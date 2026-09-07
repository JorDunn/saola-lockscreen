//! §7's outdoor temperature line — Open-Meteo, no API key, hidden entirely
//! whenever it cannot show a real number. Stage 5 of `PLAN.md`.
//!
//! Follows the established module pattern (a state struct, `view(&Theme) ->
//! Option<Element>`, `subscription()`), and copies two shapes from earlier
//! stages rather than inventing new ones:
//!
//!   - **The `Effect` return from `update`**, exactly like `modules::reveal`.
//!     This module never touches the unlock edge — it has no reason to, and
//!     nothing here can reach `Message::UnLock` — but the *reason* for the
//!     pattern still applies: `update` must return immediately (iced's loop
//!     is synchronous), and the actual network call is asynchronous work
//!     that `main.rs` hands to `iced::Task::perform`, not something this
//!     module can await itself.
//!   - **The blocking-call dispatch inside [`fetch`]**, copied from
//!     `auth::PamAuthenticator::authenticate`. `ureq` (this crate's HTTP
//!     client — see `Cargo.toml`'s comment on the survey) is a *blocking*
//!     API, not an async one, so the fetch is dispatched onto
//!     `tokio::task::spawn_blocking` the same way the PAM conversation is —
//!     one blocking-call pattern in the crate, used twice, rather than two.
//!
//! # Why the slot can only ever be "a number" or "nothing" — no error state
//!
//! Architecture is explicit: "No lat/lon in config, or any fetch/parse
//! failure → the slot renders nothing." There is deliberately no `Result`,
//! no error variant, and no retry-on-failure logic anywhere in this module —
//! [`Temperature::celsius`] is a plain `Option<f64>`, and every single thing
//! that can go wrong (unconfigured, DNS failure, TLS failure, a timeout, a
//! non-2xx HTTP status, malformed JSON, a JSON document missing the field,
//! or the field present but not a finite number) collapses to that same
//! `None`. `view` cannot tell any of these apart, on purpose: a §7 lock
//! surface has no real estate for "the weather API is down" copy, and a
//! locker's whole job is coming up correctly regardless of the network —
//! see the crate's no-panic rule (`CLAUDE.md`) applied one level down from
//! "never crash" to "never even show a broken state" for a module this
//! decorative.
//!
//! # Refresh cadence — one fetch at boot, then every 15 minutes
//!
//! Architecture: "fetch at startup and every 15 minutes." Two separate
//! mechanisms produce that, and neither depends on the other:
//!
//!   - **Boot**: `main.rs`'s `Lockscreen::boot` calls [`Temperature::boot`]
//!     once, at construction, and turns the [`Effect`] it returns into the
//!     *initial* `iced::Task` that `boot` now returns alongside the state
//!     (`iced_sessionlock`'s `IntoBoot` accepts a `(State, Task<Message>)`
//!     tuple — see that function's own doc comment). Crucially, returning a
//!     `Task` from `boot` does **not** delay the first frame: iced schedules
//!     the task on its executor and renders the initial state immediately,
//!     so the §7 surface appears at once, with the temperature slot simply
//!     empty until the fetch resolves (or forever, if it never does). This
//!     is the literal mechanism behind "failure must never delay or block
//!     lock-up" — there is no `.await` anywhere between "surface constructed"
//!     and "surface shown".
//!   - **Every 15 minutes after that**: [`Temperature::subscription`] is
//!     `iced::time::every(REFRESH_INTERVAL)` (only while coordinates are
//!     configured — `Subscription::none()` otherwise, so an unconfigured
//!     surface never even starts a timer for a fetch it will never make).
//!     Each tick produces [`Message::Tick`], which `update` turns back into
//!     the exact same [`Effect::Fetch`] the boot path used — one fetch
//!     construction site, reused by both triggers (see [`Temperature::fetch_effect`]).
//!
//! **No retry storm on failure**: a failed fetch does not schedule another
//! attempt sooner than the next ordinary 15-minute tick. There is no
//! separate "failed, try again in 30s" timer anywhere in this module —
//! Architecture asks for exactly one cadence, not a back-off ladder, and a
//! Wi-Fi-down laptop should not spend the next several minutes hammering
//! Open-Meteo every few seconds while it's locked.
//!
//! # A failed *refresh* hides the slot too, not just a failed first fetch
//!
//! [`Temperature::update`]'s `Message::Fetched` arm assigns `self.celsius =
//! celsius` unconditionally — a `None` here **replaces** a previously-shown
//! value, it does not leave stale data on screen. This is a deliberate
//! reading of "any fetch/parse failure → the slot renders nothing": a
//! 15-minutes-stale temperature that silently stopped updating (say, the
//! laptop's Wi-Fi dropped an hour into being locked) is a worse look for a
//! decorative readout than briefly disappearing, and it avoids this module
//! ever needing to reason about "how stale is too stale" (Stage 6 or a later
//! stage may reconsider this if a "keep the last good value visible" reading
//! is preferred instead — see this module's test `a_failed_refresh_hides_a_previously_shown_reading`,
//! which pins today's behaviour as an executable claim rather than a guess).

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use iced::widget::text;
use iced::{Element, Subscription};
use saola_theme::convert::{display_font, ColorExt};
use saola_theme::Theme;

/// Open-Meteo's forecast endpoint (Architecture: "outdoor temperature via
/// Open-Meteo (no API key)"). `current=temperature_2m` is the one field this
/// module reads — see [`parse_temperature`].
const ENDPOINT: &str = "https://api.open-meteo.com/v1/forecast";

/// The refresh cadence (Architecture / `PLAN.md` Stage 5: "every 15
/// minutes"). See the module doc comment's "Refresh cadence" section for how
/// this combines with the separate boot-time fetch.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// How long a single fetch attempt may run before this module gives up on
/// it. Not in Architecture's own words, but a direct consequence of its
/// "never a retry storm" and "the UI thread never blocks" rules taken
/// together: without a bound, one hung TCP connect could tie up a
/// `spawn_blocking` worker thread for the rest of the session (harmless to
/// the lock surface itself, since the UI thread never touches it, but a slow
/// leak on tokio's blocking pool over a very long uptime is still worth
/// avoiding for free). Ten seconds is generous for a same-region HTTPS GET
/// and short next to the 15-minute cadence.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Coordinates
// ---------------------------------------------------------------------------

/// A resolved lat/lon pair. Constructing one is the single gate this whole
/// module sits behind: every other piece of "is temperature configured?"
/// logic ([`Temperature::subscription`] arming a timer at all,
/// [`Temperature::fetch_effect`] ever producing [`Effect::Fetch`]) reduces to
/// "do we have a `Coordinates`", not a repeated `Option<f64>` check.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Coordinates {
    pub latitude: f64,
    pub longitude: f64,
}

impl Coordinates {
    /// `config.rs`'s `latitude`/`longitude` are each an independent
    /// `Option<f64>` (see that module's schema) — a document setting only
    /// one of the two is exactly as "unconfigured" as setting neither, since
    /// Open-Meteo's `forecast` endpoint needs both to mean anything. The `?`
    /// operator makes that the natural reading: this returns `Some` only
    /// when *both* inputs are `Some`.
    pub fn from_config(latitude: Option<f64>, longitude: Option<f64>) -> Option<Self> {
        Some(Coordinates {
            latitude: latitude?,
            longitude: longitude?,
        })
    }
}

// ---------------------------------------------------------------------------
// Message / Effect
// ---------------------------------------------------------------------------

/// The module's own message type, nested into `main.rs`'s `Message` as
/// `Message::Temperature(temperature::Message)` — the same per-module-enum
/// pattern `modules::clock` and `modules::reveal` both use.
#[derive(Debug, Clone)]
pub enum Message {
    /// The refresh timer fired ([`Temperature::subscription`]) — time to
    /// fetch again. Carries no data; the tick is purely a "do it again"
    /// signal, same shape as `modules::clock::Message::Tick`.
    Tick,
    /// A fetch attempt finished. `None` is every failure mode collapsed
    /// together (see the module doc comment's "no error state" section);
    /// `Some` is a plain celsius value, already checked finite (see
    /// [`parse_temperature`]).
    Fetched(Option<f64>),
}

/// What `main.rs` must do in response to an `update` (or the boot-time)
/// call. Mirrors `modules::reveal::Effect`'s reasoning exactly: `update`
/// itself must return synchronously, so the actual async work (here, an
/// HTTP fetch instead of a PAM conversation) is handed back as a value for
/// `main.rs` to feed to `iced::Task::perform`, rather than awaited in place.
pub enum Effect {
    /// Nothing to do — the message needed no fetch (unconfigured), or it was
    /// a `Fetched` result being folded into state.
    None,
    /// Run this future (via `Task::perform`) and route its `Option<f64>`
    /// back in as `Message::Fetched`.
    Fetch(FetchFuture),
}

/// The future a fetch attempt hands back. Boxed and dynamically dispatched
/// for the same reason as `auth::AuthFuture`: `Task::perform` just needs
/// *a* future, and there is no trait object here that would otherwise force
/// the boxing — it's kept anyway so [`fetch`]'s two internal dispatch paths
/// (with vs. without a live tokio runtime, see that function) both produce
/// the same concrete return type.
pub type FetchFuture = Pin<Box<dyn Future<Output = Option<f64>> + Send + 'static>>;

// ---------------------------------------------------------------------------
// Temperature
// ---------------------------------------------------------------------------

/// The temperature module's state: the coordinates it was configured with
/// (fixed for the process's lifetime — Architecture: no live config reload)
/// and the last successfully parsed reading, if any.
pub struct Temperature {
    coordinates: Option<Coordinates>,
    /// `None` at construction, `None` again after any failed fetch (see the
    /// module doc comment's "a failed refresh hides the slot too" section),
    /// `Some` only for the interval between one successful fetch and the
    /// next attempt's outcome.
    celsius: Option<f64>,
}

impl Temperature {
    /// Built once at boot from `config.rs`'s parsed `latitude`/`longitude` —
    /// see `main.rs`'s `Lockscreen::boot` and the Stage 3 handoff's "config
    /// is read exactly once" gotcha, which this stage now also respects for
    /// the two fields Stage 3/4 left unconsumed.
    pub fn new(coordinates: Option<Coordinates>) -> Self {
        Temperature {
            coordinates,
            celsius: None,
        }
    }

    /// The boot-time fetch trigger (Architecture: "fetch ... at startup").
    /// `main.rs`'s `Lockscreen::boot` calls this once and turns the
    /// resulting `Effect` into the initial `Task` it now returns alongside
    /// the constructed state — see the module doc comment's "Refresh
    /// cadence" section for why that does not delay the first frame.
    pub fn boot(&self) -> Effect {
        self.fetch_effect()
    }

    /// The one place that turns "we should fetch now" into an `Effect`,
    /// shared by [`Self::boot`] and `Message::Tick` below — one fetch
    /// construction site used by both triggers, per the module doc
    /// comment.
    fn fetch_effect(&self) -> Effect {
        match self.coordinates {
            Some(coordinates) => Effect::Fetch(fetch(coordinates)),
            None => Effect::None,
        }
    }

    pub fn update(&mut self, message: Message) -> Effect {
        match message {
            Message::Tick => self.fetch_effect(),
            Message::Fetched(celsius) => {
                // Unconditional assignment, including the `None` case — see
                // the module doc comment's "a failed refresh hides the slot
                // too" section. This is the hide-on-failure state
                // transition Stage 5 was asked to test.
                self.celsius = celsius;
                Effect::None
            }
        }
    }

    /// `Subscription::none()` when unconfigured — an unconfigured surface
    /// never even arms a timer for a fetch it will never make, rather than
    /// ticking forever into a no-op `fetch_effect`.
    pub fn subscription(&self) -> Subscription<Message> {
        match self.coordinates {
            Some(_) => iced::time::every(REFRESH_INTERVAL).map(|_| Message::Tick),
            None => Subscription::none(),
        }
    }

    /// `None` whenever the slot should render nothing at all (unconfigured,
    /// or no successful fetch yet/anymore) — `main.rs`'s `view` only pushes
    /// a widget into the centred `column!` when this returns `Some`, the
    /// same "absence is not a widget" shape `Lockscreen::view` already uses
    /// for the reveal stack. Styled identically to `modules::clock`'s date
    /// line (same size/font/color tokens) — see this module's doc comment
    /// and `modules::clock`'s "Type choices" section: a de-emphasized
    /// companion line, not a second focal point, and the style guide has no
    /// dedicated "temperature" row any more than it has one for "date".
    pub fn view(&self, theme: &Theme) -> Option<Element<'_, Message>> {
        let celsius = self.celsius?;
        Some(
            text(format_temperature(celsius))
                .font(display_font(theme))
                .size(theme.typography.size.panel_heading)
                .color(theme.on_ink.secondary.into_iced())
                .into(),
        )
    }
}

/// `NN°` — rounded to the nearest whole degree Celsius. `as i64` on a float
/// is a *saturating* cast in Rust (defined behaviour since 1.45, never UB,
/// never a panic) even for `NaN` (→ 0) or `Infinity` (→ `i64::MAX`), so this
/// cannot panic even if [`parse_temperature`]'s own finite-check were ever
/// bypassed — belt and braces, per the crate's no-panic rule.
fn format_temperature(celsius: f64) -> String {
    format!("{}°", celsius.round() as i64)
}

// ---------------------------------------------------------------------------
// The fetch
// ---------------------------------------------------------------------------

/// Builds the future [`Effect::Fetch`] carries: dispatch the blocking
/// `ureq` call onto a blocking-friendly thread, exactly like
/// `auth::PamAuthenticator::authenticate` dispatches the blocking PAM
/// conversation. See that function's doc comment for the fuller teaching
/// note on why `Handle::try_current()` (not the plain `spawn_blocking` free
/// function, which panics outside a runtime) with a plain-thread-plus-oneshot
/// fallback — the reasoning is identical here, just for an HTTP GET instead
/// of a PAM transaction. Any panic inside `fetch_blocking` (there should be
/// none — it is `unwrap`/`expect`-free) or a dropped sender both fold to
/// `None` here, never to a crash of the caller.
fn fetch(coordinates: Coordinates) -> FetchFuture {
    Box::pin(async move {
        let work = move || fetch_blocking(coordinates);
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle.spawn_blocking(work).await.ok().flatten(),
            Err(_) => {
                let (tx, rx) = tokio::sync::oneshot::channel();
                std::thread::spawn(move || {
                    // If the receiver is gone the value is simply dropped —
                    // nothing to clean up (unlike `auth::Password`, a
                    // temperature reading has no zeroizing to do).
                    let _ = tx.send(work());
                });
                rx.await.ok().flatten()
            }
        }
    })
}

/// The whole blocking HTTP round-trip, start to finish, on whatever thread
/// calls it — never the UI thread (see [`fetch`]). Every failure mode
/// (connect, TLS, timeout, a non-2xx status, a body read error) collapses to
/// `None` via `.ok()?`; see [`parse_temperature`] for how a *successful*
/// response can still end up `None`.
fn fetch_blocking(coordinates: Coordinates) -> Option<f64> {
    let url = format!(
        "{ENDPOINT}?latitude={}&longitude={}&current=temperature_2m",
        coordinates.latitude, coordinates.longitude
    );
    let mut response = ureq::get(&url)
        .config()
        .timeout_global(Some(FETCH_TIMEOUT))
        .build()
        .call()
        .ok()?;
    let body = response.body_mut().read_to_string().ok()?;
    parse_temperature(&body)
}

/// The pure core this module's tests actually exercise: Open-Meteo's
/// `current.temperature_2m` field, or `None` for absolutely anything wrong
/// with `body` — not valid JSON at all, valid JSON missing `current` or
/// `temperature_2m`, the field present but not a number, or a number that
/// isn't finite (`NaN`/`Infinity` — `serde_json` itself does not reject
/// those for an `f64`, so this function does). No network, no `Coordinates`,
/// nothing but a `&str` in and an `Option<f64>` out — which is what makes it
/// unit-testable with canned fixtures rather than a live endpoint.
///
/// Walked by hand via [`serde_json::Value`] rather than a
/// `#[derive(serde::Deserialize)]` struct — see `Cargo.toml`'s comment on
/// this crate's `serde_json` line, and `config.rs`'s identical choice for
/// TOML: a two-field response shape does not earn a second direct
/// dependency (`serde` itself, for the derive macro) on top of the one this
/// already takes.
fn parse_temperature(body: &str) -> Option<f64> {
    let document: serde_json::Value = serde_json::from_str(body).ok()?;
    let celsius = document.get("current")?.get("temperature_2m")?.as_f64()?;
    celsius.is_finite().then_some(celsius)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Coordinates / the unconfigured case -----------------------------

    #[test]
    fn both_coordinates_present_resolve() {
        let coordinates = Coordinates::from_config(Some(51.5074), Some(-0.1278));
        assert_eq!(
            coordinates,
            Some(Coordinates {
                latitude: 51.5074,
                longitude: -0.1278,
            })
        );
    }

    /// Neither knob set — the ordinary "no `lockscreen.toml` weather config"
    /// case.
    #[test]
    fn neither_coordinate_is_unconfigured() {
        assert_eq!(Coordinates::from_config(None, None), None);
    }

    /// A lone `latitude` with no `longitude` (or vice versa) is exactly as
    /// unconfigured as neither — see [`Coordinates::from_config`]'s doc
    /// comment.
    #[test]
    fn a_lone_coordinate_is_unconfigured() {
        assert_eq!(Coordinates::from_config(Some(51.5074), None), None);
        assert_eq!(Coordinates::from_config(None, Some(-0.1278)), None);
    }

    /// The module-level consequence of being unconfigured: `boot`, and
    /// `Message::Tick` via `update`, both produce `Effect::None` — never a
    /// fetch for coordinates that don't exist.
    #[test]
    fn unconfigured_module_never_produces_a_fetch_effect() {
        let mut temperature = Temperature::new(None);
        assert!(matches!(temperature.boot(), Effect::None));
        assert!(matches!(temperature.update(Message::Tick), Effect::None));
    }

    /// The mirror image: configured coordinates do arm a fetch, both at
    /// boot and on every subsequent tick.
    #[test]
    fn configured_module_produces_a_fetch_effect() {
        let coordinates = Coordinates {
            latitude: 51.5074,
            longitude: -0.1278,
        };
        let mut temperature = Temperature::new(Some(coordinates));
        assert!(matches!(temperature.boot(), Effect::Fetch(_)));
        assert!(matches!(
            temperature.update(Message::Tick),
            Effect::Fetch(_)
        ));
    }

    /// An unconfigured module never arms the refresh timer either — see
    /// `Temperature::subscription`'s doc comment. `Subscription` has no
    /// public way to inspect "is this none", so this asserts the one thing
    /// that is actually observable: it does not panic to construct, and a
    /// configured module's subscription is a distinct value (a real
    /// behavioural difference, even if not directly comparable in a unit
    /// test — the nested-niri smoke test is what actually proves the timer
    /// fires).
    #[test]
    fn subscription_does_not_panic_either_way() {
        let unconfigured = Temperature::new(None);
        let _ = unconfigured.subscription();

        let configured = Temperature::new(Some(Coordinates {
            latitude: 0.0,
            longitude: 0.0,
        }));
        let _ = configured.subscription();
    }

    // ---- Response parsing --------------------------------------------------

    /// The valid-response fixture: Open-Meteo's actual documented shape
    /// (trimmed to the one field this module reads — the real response has
    /// several sibling fields under `current`, e.g. `time`, `interval`,
    /// which this parser ignores rather than requiring).
    #[test]
    fn valid_response_parses() {
        let body = r#"{
            "latitude": 51.5,
            "longitude": -0.11,
            "current": {
                "time": "2026-08-02T12:00",
                "interval": 900,
                "temperature_2m": 21.3
            }
        }"#;
        assert_eq!(parse_temperature(body), Some(21.3));
    }

    /// A negative reading — the sign is not special-cased anywhere in the
    /// parser, so this pins that it survives unchanged.
    #[test]
    fn negative_reading_parses() {
        let body = r#"{"current":{"temperature_2m":-4.5}}"#;
        assert_eq!(parse_temperature(body), Some(-4.5));
    }

    /// Malformed JSON: not valid JSON syntax at all.
    #[test]
    fn malformed_json_yields_none() {
        let body = "{ this is not valid json {{{";
        assert_eq!(parse_temperature(body), None);
    }

    /// Syntactically valid JSON with no `current` object at all.
    #[test]
    fn missing_current_object_yields_none() {
        let body = r#"{"latitude": 51.5, "longitude": -0.11}"#;
        assert_eq!(parse_temperature(body), None);
    }

    /// `current` present, but without the one field this module reads
    /// (Open-Meteo returns this shape if a caller asks for a different
    /// `current` variable set than `temperature_2m`).
    #[test]
    fn missing_temperature_field_yields_none() {
        let body = r#"{"current": {"time": "2026-08-02T12:00"}}"#;
        assert_eq!(parse_temperature(body), None);
    }

    /// The field present but holding the wrong JSON type — a string instead
    /// of a number, say, from a hypothetical future API change.
    #[test]
    fn non_numeric_temperature_field_yields_none() {
        let body = r#"{"current": {"temperature_2m": "warm"}}"#;
        assert_eq!(parse_temperature(body), None);
    }

    /// An empty document is syntactically valid JSON (`{}`) but has nothing
    /// this parser can use.
    #[test]
    fn empty_object_yields_none() {
        assert_eq!(parse_temperature("{}"), None);
    }

    /// `NaN`/`Infinity` are not valid JSON literals, so `serde_json` cannot
    /// even construct them from a real Open-Meteo response — but a
    /// malicious or badly-proxied response could smuggle a huge-but-finite
    /// number, and this test exists mainly to pin that ordinary large finite
    /// numbers still parse (the finite check is not accidentally rejecting
    /// them).
    #[test]
    fn a_large_finite_reading_still_parses() {
        let body = r#"{"current": {"temperature_2m": 1.0e10}}"#;
        assert_eq!(parse_temperature(body), Some(1.0e10));
    }

    // ---- The hide-on-failure state transitions ----------------------------

    /// A successful fetch is reflected into state, and `view` starts
    /// rendering something.
    #[test]
    fn a_successful_fetch_is_shown() {
        let mut temperature = Temperature::new(Some(Coordinates {
            latitude: 0.0,
            longitude: 0.0,
        }));
        assert!(temperature.view(&Theme::saola()).is_none());

        let effect = temperature.update(Message::Fetched(Some(21.0)));
        assert!(matches!(effect, Effect::None));
        assert!(temperature.view(&Theme::saola()).is_some());
    }

    /// **The hide-on-failure transition Stage 5 was specifically asked to
    /// test**: a previously-shown reading disappears the moment a refresh
    /// fails, rather than staying on screen stale. See the module doc
    /// comment's "a failed refresh hides the slot too" section.
    #[test]
    fn a_failed_refresh_hides_a_previously_shown_reading() {
        let mut temperature = Temperature::new(Some(Coordinates {
            latitude: 0.0,
            longitude: 0.0,
        }));
        temperature.update(Message::Fetched(Some(21.0)));
        assert!(temperature.view(&Theme::saola()).is_some());

        temperature.update(Message::Fetched(None));
        assert!(temperature.view(&Theme::saola()).is_none());
    }

    /// The unconfigured module never shows anything, no matter what — there
    /// is no code path that could even deliver it a `Message::Fetched` in
    /// practice (its `subscription` never arms), but the state itself is
    /// still asserted directly here.
    #[test]
    fn unconfigured_module_never_renders() {
        let temperature = Temperature::new(None);
        assert!(temperature.view(&Theme::saola()).is_none());
    }

    // ---- Formatting ---------------------------------------------------------

    #[test]
    fn formats_with_a_degree_sign_and_no_decimal() {
        assert_eq!(format_temperature(21.3), "21°");
        assert_eq!(format_temperature(21.5), "22°");
        assert_eq!(format_temperature(-4.5), "-5°");
    }

    #[test]
    fn zero_formats_plainly() {
        assert_eq!(format_temperature(0.0), "0°");
    }

    /// Belt-and-braces (see `format_temperature`'s doc comment): even
    /// non-finite input — which `parse_temperature` should already have
    /// filtered out before this function ever sees a value — cannot panic.
    #[test]
    fn non_finite_input_never_panics() {
        let _ = format_temperature(f64::NAN);
        let _ = format_temperature(f64::INFINITY);
        let _ = format_temperature(f64::NEG_INFINITY);
    }
}
