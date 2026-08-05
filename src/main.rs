//! saola-lockscreen — the session locker for the Saola desktop.
//!
//! A single binary crate (an app, not a library — no workspace), mirroring
//! saola-panel's layout. It speaks **ext-session-lock-v1** via
//! `iced_sessionlock` (the waycrate sibling of the panel's `iced_layershell`
//! binding), authenticates through PAM, and is styled per the design
//! system's style guide §7 "Lock surface". See `PLAN.md`'s Architecture
//! section for the full state machine and the binding security rules
//! (unlock-edge, panic surface, secret hygiene) that every later stage must
//! hold to.
//!
//! # Stage 1: crate skeleton only
//!
//! Stage 1 wired up the dependency set and module layout without touching
//! Wayland at all — `main` was a stub that printed the crate version and
//! exited.
//!
//! # Stage 2: session-lock proof — ink on every output
//!
//! This stage replaces that stub with the real `iced_sessionlock`
//! application. There is still no reveal-flow UI (Stage 4) or wallpaper
//! (Stage 3): every output shows a solid ink surface, painted from
//! `saola-theme`'s own `style::container::ink_surface` helper (never a
//! hardcoded hex — see that helper's doc comment for why it's already the
//! exact "shell surface: always ink" style the panel's bar uses).
//!
//! ## How `iced_sessionlock` differs from the panel's `iced_layershell`
//!
//! Both are waycrate/exwlshelleventloop bindings for iced 0.14, but their
//! `build_pattern` shapes differ in one way worth knowing before touching
//! this file: the panel is an `iced_layershell::build_pattern::daemon`
//! (arbitrarily many named surfaces, spawned and torn down at runtime,
//! tracked in a `HashMap<window::Id, SurfaceRole>` — see saola-panel's
//! `main.rs`). A session lock has no such need: `ext-session-lock-v1`
//! surfaces are managed entirely by the underlying `sessionlockev` crate —
//! it enumerates the compositor's outputs itself and opens (or later closes,
//! on hotplug) one lock surface per output automatically, each getting its
//! own `iced::window::Id` under the hood (`sessionlockev`'s `OutputHandler`
//! impl: `new_output`/`output_destroyed`, verified in
//! `sessionlockev-0.19.1/src/lib.rs`). So `iced_sessionlock::application(..)`
//! is the *single-program, N-surfaces-for-free* builder: our `view` is
//! called once per output with that output's `window::Id`, exactly like the
//! daemon's per-surface `view`, but we never spawn or track a surface
//! ourselves — "on every output" falls out of just implementing `view`
//! once. Multi-monitor correctness for Stage 2 is therefore mostly "don't
//! assume there's only one call to `view`", which the code below already
//! satisfies by not caching or indexing on the window id at all.
//!
//! ## Scale (Jordan's 1.5-scale display)
//!
//! Also handled below the level this file operates at: `sessionlockev`
//! binds `wp_fractional_scale_v1` per surface and feeds every
//! `PreferredScale` event into `iced_sessionlock`'s own per-window `State`
//! (`iced_sessionlock-0.19.1/src/multi_window/state.rs`), which recomputes
//! the render viewport from the compositor-reported scale on every change —
//! there is no fixed/assumed 1.0 anywhere in that path. Nothing in this
//! file measures pixels or reads a scale factor itself (the ink surface is
//! `Fill`/`Fill`, not a fixed size), so it inherits that correctness for
//! free; the nested-niri test procedure below is what actually exercises it
//! against niri's own advertised scale.
//!
//! ## The unlock-edge rule (Architecture, PLAN.md — binding)
//!
//! `#[to_session_message]` (below, on [`Message`]) always appends a
//! `Message::UnLock` variant and generates
//! `impl TryInto<iced_sessionlock::actions::UnLockAction> for Message`; the
//! runtime intercepts a literal `Message::UnLock` (wherever it comes from —
//! a widget message, a subscription, a `Task`) and asks the compositor to
//! unlock *before* that message would ever reach [`Lockscreen::update`]
//! again (see `iced_sessionlock`'s `multi_window::update` and `run_action`:
//! both `match message.try_into() { Ok(action) => { *should_exit = true; ..
//! } Err(message) => .. }`). That interception is the *only* place unlock
//! actually happens; nothing in this crate calls into `sessionlockev`'s
//! unlock API directly. Our job is narrower and stricter: control which
//! code paths are even capable of producing that literal `Message::UnLock`
//! value. Today (Stage 2) there are deliberately zero such paths in a
//! default build — Stage 4 adds the first real one (PAM-ok). The only
//! *other* one, ever, is the `dev-unlock` cargo feature below: every trace
//! of it — the `Message::DevUnlockEscapePressed` variant, the subscription
//! that can produce it, and the `update` arm that turns it into
//! `Message::UnLock` — is `#[cfg(feature = "dev-unlock")]`, which is never
//! in `default-features` (see `Cargo.toml`) and must never be enabled in a
//! release build. See "Nested-niri testing" in this repo's `CLAUDE.md` for
//! how to actually exercise it.
//!
//! # Stage 3: wallpaper, clock, date
//!
//! This stage layers the §7 lock surface's "at rest" content onto Stage 2's
//! bare ink: a cover-fit wallpaper (config-driven, ink fallback when unset,
//! unreadable, or undecodable — see `wallpaper::load`) with the centred
//! clock + date (`modules::clock`) on top. The reveal flow (avatar → name →
//! password) and the temperature slot are still out of scope (Stages 4 and
//! 5).
//!
//! `view` now layers three things, back to front, with `iced::widget::
//! stack!` (see that macro's doc comment: "the first element is the base
//! layer... every consecutive element is rendered on top, on its own
//! layer"):
//!
//!   1. The Stage 2 ink container — unconditional, always the bottom layer.
//!      This is the wallpaper's fallback, not a conditional "else" branch:
//!      if the wallpaper image fails to decode, iced's own raster pipeline
//!      silently draws nothing for it (verified against
//!      `iced_tiny_skia-0.14.0/src/raster.rs`'s `Pipeline::draw`: `let
//!      Ok(image) = cache.allocate(handle) else { return; };` — no panic,
//!      no visible error, just "this layer contributed nothing"), so the
//!      ink underneath shows through automatically. This is exactly the
//!      "never an error state" fallback Architecture asks for, and it
//!      falls out of the layering rather than needing an if/else in this
//!      function.
//!   2. The wallpaper image, only when `self.wallpaper` is `Some` (config
//!      set a path *and* `wallpaper::load` decoded it at boot — see the
//!      "Post-Stage-3" section below for the full story on *when* this
//!      layer actually becomes visible, which is not necessarily the very
//!      first frame). `ContentFit::Cover` crops to fill the whole output
//!      without distorting the image (verified against
//!      `iced_core-0.14.0/src/content_fit.rs`'s `ContentFit::fit` and
//!      `iced_widget-0.14.2/src/image.rs`'s `draw`, which clips the drawn
//!      region to the widget's own layout bounds — cover-fit never bleeds
//!      into a neighboring output's surface).
//!   3. The centred clock/date column (`modules::clock`), wrapped in a
//!      `container().center_x(Fill).center_y(Fill)` — the thing that
//!      actually centers it on the surface; the module itself only lays
//!      out the two lines relative to each other (see `modules::clock`'s
//!      doc comment). **This is the temperature slot's home**: Stage 5
//!      adds `modules::temperature` as a sibling `push`ed onto the same
//!      `column!` this container wraps, once that module exists. Nothing
//!      is drawn for temperature yet — an empty slot in a `column!` isn't
//!      a widget, so "renders nothing until Stage 5" needs no placeholder
//!      code at all.
//!
//! # Post-Stage-3: why the wallpaper needed a second fix, and what it is
//!
//! Stage 3 shipped with a **known gap**: a configured wallpaper never
//! rendered — confirmed `wallpaper.is_some()` at boot, confirmed the
//! `image()` push branch executed every frame, yet the surface stayed
//! plain ink indefinitely in that stage's (short, repeatedly-restarted)
//! nested-niri tests. A follow-up diagnostic pass reproduced it live and
//! read the actual `iced_wgpu` 0.14 source (not guessed) to find two
//! separate, stacked causes, both in `iced_wgpu-0.14.0/src/image/cache.rs`:
//!
//! 1. `image::Handle::from_path`/`from_bytes` are decoded **off-thread**:
//!    the renderer's normal per-frame draw path (`load_image`, used by
//!    `measure_image` and `upload_raster`) kicks off a background
//!    `Worker::load(handle)` the first time it sees such a handle and draws
//!    *nothing* that frame — except for `Handle::Rgba`, which that same
//!    function special-cases as synchronous ("since it's very cheap").
//! 2. Independently, the GPU texture **upload** itself
//!    (`Cache::upload_raster`) is *also* asynchronous whenever the decoded
//!    RGBA buffer is ≥ 2 MiB (`MAX_SYNC_SIZE`) — true of essentially any
//!    real wallpaper, regardless of handle variant.
//!
//! A normal windowed iced app never notices either of these: it keeps
//! requesting frames continuously, so a later frame (milliseconds away)
//! picks up whatever finished decoding/uploading in the background. This
//! crate's lock surface does not — `iced_sessionlock` only requests a
//! redraw when a widget asks for one, and (before Stage 4's reveal-flow
//! listener exists) this crate's only recurring ask is the clock's
//! *minute-aligned* tick. **Confirmed live** (nested niri, screenshots —
//! see `.claude/handoffs/handoff_stage_3.md`'s addendum): switching
//! `wallpaper::load` to build `Handle::from_rgba` (fixing cause 1, the
//! decode) is what actually ships here, and it made the wallpaper render
//! *reliably* — every live test showed it appear correctly, cover-fit, no
//! corruption — but only at the *next* event, i.e. up to ~60 seconds after
//! the lock surface appears, bounded by cause 2 (the still-async GPU
//! upload) plus the clock tick being the only thing currently waking the
//! surface up. That's a large, honest improvement over Stage 3's "never"
//! but not instant, so two further fixes were tried to close the remaining
//! gap — **both tested live, neither shipped**, because neither worked:
//!
//! - Building `iced_sessionlock` with its `unconditional-rendering` feature
//!   (its docs suggest it forces continuous redraws) made **no measurable
//!   difference**: reading `multi_window.rs::handle_normal_dispatch` shows
//!   it early-returns whenever there are no pending events/messages, so the
//!   feature's "always request `NextFrame`" branch never even runs on a
//!   surface with zero input. Confirmed empirically by two independent live
//!   tests (with and without the feature, otherwise identical) both showing
//!   the wallpaper appear at the exact clock-tick boundary, never sooner.
//! - Returning an initial `Task` from `boot` that calls iced's own
//!   documented `iced::widget::image::allocate(handle)` (whose docs promise
//!   "the guarantee that using a Handle will draw... immediately in the
//!   next frame") also made **no measurable difference** live, despite
//!   being the API iced 0.14 ships specifically for this. The most likely
//!   cause, reading `iced_sessionlock-0.19.1/src/multi_window.rs`'s
//!   `run_action`: its `Action::Image::Allocate` handler resolves the
//!   `Task` by reaching into `window_manager.iter_mut().next()`, which can
//!   still be empty this early (`boot` runs before `sessionlockev` has
//!   necessarily registered any output's lock surface) — if so, the
//!   callback is silently never invoked and the `Task` never resolves, no
//!   error either. This is a plausible `iced_sessionlock` limitation worth
//!   raising upstream, not chased further here (confirming the exact
//!   internal race was out of this diagnostic's scope; the point is it does
//!   not help in practice, so it isn't shipped).
//!
//! Net result shipped in `wallpaper.rs`: `Handle::from_rgba` only. The
//! "never renders" bug is fixed; the residual "ink for up to a minute" edge
//! is real but bounded, self-healing, and — being plain ink — indistinguishable
//! from "no wallpaper configured," which is exactly the fallback Architecture
//! already asks for. Stage 4's reveal-flow listener (any click/keypress)
//! will shrink that window to "however long before the user's first
//! interaction" for free, once it lands, without this file needing to
//! change.
//!
//! **Post-Stage-7 closure of the residual gap: the warm-up ticks.** The
//! remaining "ink until the next event" window is now closed directly: when
//! `Message::WallpaperLoaded` delivers a handle, `update` arms a short-lived
//! burst of sub-second redraw ticks ([`WALLPAPER_WARMUP_FRAMES`] ×
//! [`WALLPAPER_WARMUP_INTERVAL`], via the same `iced::time::every`
//! subscription machinery the clock uses). Each tick's message wakes
//! `iced_sessionlock`'s dispatch loop — the exact mechanism the clock tick
//! was already (accidentally) providing once a minute — so the frame that
//! kicks off cause 2's async GPU upload and the frame that finally draws
//! the uploaded texture both happen within about a second of the decode
//! finishing, instead of at the next minute boundary. The burst then
//! disarms itself (the subscription is only returned while the counter is
//! non-zero), so an at-rest surface still wakes only once a minute after
//! the first second or so of its life.

//! # Stage 4: PAM authentication + the reveal flow
//!
//! The security core lands here. Almost all of it is in two new modules —
//! `auth` (the `Authenticator` trait and its PAM implementation) and
//! `modules::reveal` (the state machine) — and this file's job is only to
//! wire them to iced. Read those two modules' doc comments before this
//! section; in particular, `modules::reveal`'s explains why its `update`
//! returns a plain `Effect` value instead of an `iced::Task`.
//!
//! **The unlock edge (Architecture's binding rule).** The whole point of
//! that `Effect` design is this function, in `Lockscreen::update`:
//!
//! ```ignore
//! Effect::Unlock => Task::done(Message::UnLock),
//! ```
//!
//! That single arm is the only non-`dev-unlock` code in this crate that
//! constructs a literal `Message::UnLock`, which (per the Stage 2 section
//! above) is the only thing `iced_sessionlock`'s runtime turns into an
//! actual `ext-session-lock-v1` unlock request. It is reachable only when
//! `modules::reveal`'s state machine returns `Effect::Unlock`, which happens
//! only for `(State::Authenticating, Message::Finished(
//! Outcome::Authenticated))`, which in turn requires an
//! `auth::Outcome::Authenticated` — a value `auth::PamAuthenticator::run_pam`
//! constructs in exactly one place, after both `pam_authenticate` *and*
//! `pam_acct_mgmt` returned success. `grep -rn 'Message::UnLock' src/` shows
//! the complete list: the `TryInto` interception arm, this arm, and the
//! `#[cfg(feature = "dev-unlock")]` arm below.
//!
//! **Layering.** `view` gains one conditional layer and one conditional
//! sibling. Between the wallpaper and the centred content there is now the
//! style guide §2 scrim for "Lock / greeter awake (prompt shown)"
//! (`scrim.lock_awake`), pushed only while the prompt is up — at rest §7
//! wants the wallpaper at full strength with nothing over it. The reveal
//! stack itself is pushed into the same centred `column!` the clock lives
//! in, below the date, which is also where Stage 5's temperature line goes.
//!
//! **Subscriptions.** Both halves of the `dev-unlock` split now batch three
//! things: the clock's minute tick, the reveal flow's own idle-timeout tick
//! (present only while revealed — see `modules::reveal::Reveal::
//! subscription`), and a global event listener that turns any click, tap or
//! keypress into a `modules::reveal::Message`. That listener deliberately
//! ignores the event `Status`: iced's `text_input` *captures* Escape without
//! publishing anything, so a status-filtered listener would never see the
//! Escape that dismisses the prompt.
//!
//! One consequence worth knowing before a nested test: with `dev-unlock`
//! enabled, Escape reaches *both* listeners — it dismisses the prompt **and**
//! unlocks. That is fine for what the feature is for, and it is why the
//! real-PAM nested procedure in this stage's handoff runs without it.
//!
//! # Stage 5: the temperature line
//!
//! `modules::temperature` is the last §7 centred-stack element (Architecture:
//! "clock, date, temperature centred; nothing else at rest"). It slots in as
//! a third sibling in the same `column!` the clock's date line already lives
//! in — below the date, above the reveal stack — and only when
//! `Temperature::view` returns `Some` (unconfigured or fetch-failed both
//! mean "render nothing", per that module's doc comment).
//!
//! The one change of note here: [`Lockscreen::boot`] now returns
//! `(Self, Task<Message>)` instead of a bare `Self`. `iced_sessionlock`'s
//! `application` builder accepts either (see its `IntoBoot` trait) — a bare
//! `State` is sugar for `(State, Task::none())`. This crate needed the
//! two-element form for the first time here, to carry `modules::temperature`'s
//! boot-time fetch (Architecture: "fetch at startup") as an honest `Task`
//! rather than inventing a fake "first tick" inside the subscription, the
//! way `modules::clock`'s minute-aligned timer would have to if it, too,
//! needed an immediate first fire. See `modules::temperature`'s doc comment
//! for why returning a `Task` from `boot` does not delay the first frame.
//!
//! # Stage 7: fixes, session wiring, docs, release prep
//!
//! Stage 6's security review (`docs/REVIEW-v0.1.md`) found two must-fix
//! findings that touch this file.
//!
//! **H-1 — the wallpaper decode moves off `boot`'s synchronous path.** The
//! review traced `iced_sessionlock`'s own source and confirmed `boot()` runs
//! *before* the `ext_session_lock_manager_v1.lock` request is ever sent to
//! the compositor — so `boot`'s old synchronous `wallpaper::load(path)` call
//! (a filesystem read plus a full image decode, up to tens of MiB for a real
//! wallpaper) kept the *unlocked* desktop on screen for its entire duration,
//! not just "the lock surface was late". `boot` now constructs `Lockscreen`
//! with `wallpaper: None` (this crate's existing ink fallback — already the
//! correct "not loaded yet" visual) and returns the decode as a `Task`,
//! batched alongside the temperature module's boot-time fetch; the result
//! lands via the new `Message::WallpaperLoaded` arm below. See
//! `wallpaper::load_task`'s doc comment for the dispatch pattern (copied from
//! `auth::PamAuthenticator::authenticate`) and this file's `Message` doc
//! comment for the hand-written `Debug` this required. `Avatar::resolve` and
//! `Account::current` stay synchronous and in `boot`, deliberately — the
//! review considered moving them too and accepted leaving them (an avatar
//! file is small; `Account::current`'s NSS call is instant on this machine's
//! `files`-only `nsswitch.conf` — see the review's H-1 write-up).
//!
//! **M-1 — `dev-unlock` cannot silently reach a release build.** The
//! `compile_error!` guard below turns the prose-only "never in a release
//! build" rule (`CLAUDE.md`) into a compile failure for
//! `--release --features dev-unlock` specifically, while leaving
//! `cargo run --features dev-unlock` (the nested-niri workflow this feature
//! exists for) untouched — see the guard's own doc comment for the
//! `debug_assertions` reasoning.
//!
//! Everything else Stage 7 touched (the real PAM policy, session wiring,
//! `README.md`) lives outside `src/` — see `docs/REVIEW-v0.1.md` and this
//! stage's handoff for the full account, including the findings deliberately
//! deferred rather than fixed.

mod auth;
mod config;
mod modules;
mod wallpaper;

use std::sync::Arc;
use std::time::Instant;

use iced::widget::{column, container, image, stack, Space};
use iced::{Center, ContentFit, Element, Fill, Task};
use iced_sessionlock::application;
use iced_sessionlock::to_session_message;
use saola_theme::{style, to_iced_theme, Theme};

use modules::reveal::{Avatar, Effect, Reveal};
use modules::temperature::{Coordinates, Temperature};

// M-1 (docs/REVIEW-v0.1.md, must-fix): nothing in the type system stopped
// `cargo build --release --features dev-unlock`, which would ship a
// password-free Escape unlock — exactly the opposite of the unlock-edge
// rule this crate's whole design exists to guarantee (`CLAUDE.md`). This
// turns the old prose-only "never in a release build" rule into a compile
// failure. `debug_assertions` is on for the `dev` profile (which is what
// `cargo run`/`cargo build`/`cargo test --features dev-unlock` all use — the
// nested-niri workflow this feature exists for, see `CLAUDE.md`'s testing
// procedure) and off for `--release`, so this permits exactly the builds
// that must work and hard-fails the one that must never happen.
#[cfg(all(feature = "dev-unlock", not(debug_assertions)))]
compile_error!(
    "the dev-unlock feature adds a password-free unlock edge and must never be \
     compiled into a release build — see CLAUDE.md's unlock-edge rule"
);

/// How many post-load redraw ticks `Message::WallpaperLoaded` arms, and how
/// far apart they fire. See the module doc comment's "warm-up ticks"
/// section: the decoded wallpaper's GPU upload is asynchronous (≥ 2 MiB
/// RGBA — true of any real wallpaper), and `iced_sessionlock` only renders
/// when a message wakes it, so without these the uploaded texture sat
/// invisible until the clock's next minute tick. Ten ticks 100 ms apart is
/// deliberately generous — the upload itself takes milliseconds; the extra
/// ticks only cost a few no-op frames on a surface that just appeared —
/// and the subscription disarms itself when the counter runs out
/// (`Lockscreen::always_on_subscriptions`). The interval, not the count, is
/// what bounds how soon the image can appear after the load resolves; with
/// `wallpaper.rs`'s decoded-pixel cache making the load itself fast, that
/// bound is the dominant share of the visible delay, hence 100 ms.
const WALLPAPER_WARMUP_FRAMES: u8 = 10;
const WALLPAPER_WARMUP_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

fn main() -> iced_sessionlock::Result {
    application(Lockscreen::boot, Lockscreen::update, Lockscreen::view)
        .theme(Lockscreen::theme)
        .subscription(Lockscreen::subscription)
        .run()
}

/// The lockscreen's whole state. Stage 3 adds the wallpaper handle and the
/// (stateless) clock module; the reveal-flow state Stage 4 needs is still
/// absent. `theme` is kept on `Lockscreen` rather than read fresh in `view`
/// because Stage 7's config work (`colors { }` overrides, mirroring the
/// panel) will need to apply overrides to a theme built once at boot, the
/// same shape the panel's `Panel::theme` established.
struct Lockscreen {
    theme: Theme,
    /// The §7 wallpaper ground. Starts `None` at `Self::boot` (Stage 7,
    /// H-1: the decode must not run before the compositor is asked to
    /// lock) and is filled in later by `Message::WallpaperLoaded`, once
    /// `wallpaper::load_task`'s future resolves. `None` also covers every
    /// ordinary failure case `wallpaper::load` documents (unset,
    /// unreadable, undecodable): "draw ink instead" either way, the same
    /// no-error-state fallback Architecture asks for — `view` doesn't need
    /// to (and shouldn't) tell "not loaded yet" apart from "never going to
    /// load".
    wallpaper: Option<image::Handle>,
    /// Redraw ticks left in the post-load warm-up burst (see the
    /// [`WALLPAPER_WARMUP_FRAMES`] doc comment). Zero — the steady state —
    /// means the warm-up subscription is not armed at all.
    wallpaper_warmup: u8,
    /// The centred clock + date module (Stage 3, `modules::clock`).
    /// Stateless — see that module's doc comment — kept as a field only
    /// for the same module-uniformity reason the panel keeps its own empty
    /// `Clock` field alongside modules that do carry state.
    clock: modules::clock::Clock,
    /// The reveal flow's whole state machine (Stage 4,
    /// `modules::reveal`) — unlike the clock this one very much carries
    /// state, and it is the only thing in this crate that can authorize an
    /// unlock. See this file's Stage 4 doc section.
    reveal: Reveal,
    /// The §7 temperature line (Stage 5, `modules::temperature`). Carries
    /// its configured coordinates (or none) and the last successfully
    /// fetched reading, if any — see that module's doc comment.
    temperature: Temperature,
}

impl Lockscreen {
    /// Boot. `config::LockscreenConfig::load()` is the crate's one config
    /// read for the whole process (Architecture: no live reload) — the
    /// panel's "load before the runtime, never re-read mid-process"
    /// pattern for a locker.
    ///
    /// `wallpaper`, `avatar` (Stage 4), and — since this stage — the
    /// temperature module's `latitude`/`longitude` are now all consumed
    /// here; there is no longer a config field this function reads and then
    /// drops (see the Stage 3/4 handoffs for why that was deliberate at the
    /// time, not an oversight). Stage 5 extends *this* function rather than
    /// calling `LockscreenConfig::load()` a second time somewhere else,
    /// keeping "read once at startup" literally true.
    ///
    /// Note what is resolved here rather than lazily in `view`/`update`:
    /// the account (`getpwuid_r`), the avatar (config path → `~/.face` →
    /// initials disc), and the PAM authenticator. All three are cheap, all
    /// three touch the filesystem or libc, and none of them may run on the
    /// UI thread once the surface is up.
    ///
    /// `Theme::saola()` is the design system's built-in default,
    /// unmodified (Stage 7's `colors { }` override work is still ahead).
    ///
    /// Returns `(Self, Task<Message>)`, not a bare `Self` — see this file's
    /// Stage 5 doc section for why: `modules::temperature`'s boot-time fetch
    /// needs an honest `Task` to run, and `iced_sessionlock`'s `IntoBoot`
    /// trait is what accepts the two-element form.
    fn boot() -> (Self, Task<Message>) {
        let config = config::LockscreenConfig::load();

        let account = auth::Account::current();
        let avatar = Avatar::resolve(config.avatar.as_deref(), &account);
        // The real authenticator. Behind an `Arc<dyn Authenticator>` so
        // `modules::reveal`'s tests can put a fake in its place — the whole
        // reason `auth.rs` defines a trait (Architecture's testing
        // strategy). A greeter would build one of these per offered user.
        let authenticator = Arc::new(auth::PamAuthenticator::for_account(&account));

        let coordinates = Coordinates::from_config(config.latitude, config.longitude);
        let temperature = Temperature::new(coordinates);
        // The boot-time fetch (Architecture: "fetch ... at startup"). Built
        // from the same `Effect -> Task` translation `update` uses below
        // (`temperature_task`), so there is exactly one place that knows how
        // to turn a `temperature::Effect` into an `iced::Task`.
        let initial_fetch = temperature_task(temperature.boot());

        // Stage 7 (H-1, docs/REVIEW-v0.1.md): the wallpaper is no longer
        // decoded here, synchronously — see this file's Stage 7 doc section
        // and `wallpaper::load_task`'s doc comment for why running that
        // decode before `iced_sessionlock` has even asked the compositor to
        // lock was a real exposure window, not just a cosmetic delay. `None`
        // path configured means nothing to load, so no `Task` is scheduled
        // for it at all — matching the old `and_then`'s short-circuit.
        let wallpaper_task = match config.wallpaper {
            Some(path) => Task::perform(wallpaper::load_task(path), Message::WallpaperLoaded),
            None => Task::none(),
        };

        let lockscreen = Self {
            theme: Theme::saola(),
            wallpaper: None,
            wallpaper_warmup: 0,
            clock: modules::clock::Clock,
            reveal: Reveal::new(account, avatar, authenticator, Instant::now()),
            temperature,
        };
        (lockscreen, Task::batch([initial_fetch, wallpaper_task]))
    }

    /// Bridges our `saola_tokens::Theme` into the `iced::Theme` the
    /// renderer wants, exactly like the panel's `Panel::theme` (see that
    /// function's doc comment for the ThemeFn plumbing) — `to_iced_theme`
    /// maps `palette.ink` onto iced's `background`, which is what makes the
    /// *default* clear-to-background pass already paint ink (see
    /// `Lockscreen::view` below for why we still paint it explicitly rather
    /// than depending on that).
    fn theme(&self) -> iced::Theme {
        to_iced_theme(&self.theme)
    }

    /// `Message::UnLock` never actually reaches this function in practice —
    /// see the unlock-edge rule in this file's module doc comment: iced
    /// sessionlock's own runtime intercepts that literal variant earlier in
    /// the pipeline and asks the compositor to unlock. The arm below exists
    /// only because the match has to be exhaustive over every variant
    /// `#[to_session_message]` generates.
    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::UnLock => Task::none(),

            // THE unlock edge for nested-compositor testing, and nothing
            // else (Architecture's unlock-edge rule, PLAN.md). Gated end to
            // end: this arm is the only place in the whole crate, under
            // this feature only, that ever produces a literal
            // `Message::UnLock` — which is what the arm above intercepts,
            // per this function's doc comment, before `update` would ever
            // run again with it. Never in `default-features`; never enable
            // for a release build.
            #[cfg(feature = "dev-unlock")]
            Message::DevUnlockEscapePressed => Task::done(Message::UnLock),

            // The clock module carries no state (see `modules::clock`'s doc
            // comment) — `Tick` exists only to wake the runtime so `view`
            // re-reads `Local::now()` on its next render. Nothing to store,
            // so nothing to do here, exactly like the panel's own
            // `Message::Clock` delegation.
            Message::Clock(modules::clock::Message::Tick) => Task::none(),

            // The reveal flow (Stage 4). All of the decision-making happens
            // inside `modules::reveal`; this arm only turns the `Effect` it
            // returns into the corresponding `iced::Task`.
            //
            // `Instant::now()` is read here, not inside the state machine,
            // so the machine's 30 s idle timeout stays testable with
            // injected time (see that module's doc comment).
            Message::Reveal(message) => match self.reveal.update(message, Instant::now()) {
                Effect::None => Task::none(),

                // The password field lives on every output's surface and
                // they share one widget id, so this focuses "the password
                // field", wherever the compositor is sending keys — see
                // `modules::reveal::password_input_id`.
                Effect::Focus => {
                    iced::widget::operation::focus(modules::reveal::password_input_id())
                }

                // The PAM conversation, off the UI thread. The future
                // itself was built by the `Authenticator` and already
                // arranges its own blocking-thread dispatch (see
                // `auth::PamAuthenticator::authenticate`); all that happens
                // here is handing it to iced's executor and routing its
                // `Outcome` back into the state machine as a message.
                Effect::Authenticate(future) => Task::perform(future, |outcome| {
                    Message::Reveal(modules::reveal::Message::Finished(outcome))
                }),

                // ==================================================
                //  THE unlock edge. PAM said yes.
                //
                //  This is the *only* place outside the `dev-unlock`
                //  arm above where this crate constructs a literal
                //  `Message::UnLock` — the value `iced_sessionlock`'s
                //  runtime intercepts and turns into a real
                //  ext-session-lock-v1 unlock request (see this file's
                //  Stage 2 doc section). Nothing else in the crate may
                //  produce `Effect::Unlock`; see `modules::reveal`'s
                //  doc comment and its
                //  `unlock_is_produced_by_exactly_one_state_and_message`
                //  test, which asserts that as an executable claim.
                // ==================================================
                Effect::Unlock => Task::done(Message::UnLock),
            },

            // The temperature line (Stage 5). All of the decision-making
            // (whether to fetch at all, what to store) happens inside
            // `modules::temperature`; this arm only turns the `Effect` it
            // returns into the corresponding `iced::Task`, via the same
            // helper `Lockscreen::boot` used for the very first fetch.
            Message::Temperature(message) => temperature_task(self.temperature.update(message)),

            // Stage 7 (H-1): the decode `wallpaper::load_task` ran off the
            // UI thread has resolved — `None` here means "nothing
            // configured" or "failed to decode", and per the ink-fallback
            // contract (`wallpaper.rs`'s doc comment) that is not
            // distinguished from "hasn't loaded yet"; both just draw ink.
            Message::WallpaperLoaded(handle) => {
                // Arm the warm-up burst only when there is actually a
                // texture to upload — a `None` (nothing configured / failed
                // decode) stays ink forever, so extra frames would be pure
                // waste. See the `WALLPAPER_WARMUP_FRAMES` doc comment.
                self.wallpaper_warmup = if handle.is_some() {
                    WALLPAPER_WARMUP_FRAMES
                } else {
                    0
                };
                self.wallpaper = handle;
                Task::none()
            }

            // A warm-up tick. Like the clock's `Tick`, the message carries
            // nothing and *arriving* is its whole job — the dispatch it
            // causes is what renders a frame and lets the async GPU upload's
            // result reach the screen. All this arm does is count the burst
            // down so `always_on_subscriptions` disarms the timer.
            Message::WallpaperWarmed => {
                self.wallpaper_warmup = self.wallpaper_warmup.saturating_sub(1);
                Task::none()
            }
        }
    }

    /// Called once per output (see this file's module doc comment on why
    /// `sessionlockev` guarantees that without any surface bookkeeping
    /// here). See this file's module doc comment's "Stage 3" section for
    /// the full layering story; in short: ink base, optional cover-fit
    /// wallpaper, then the centred clock/date on top, `Fill`/`Fill` at
    /// every layer so each covers the whole output regardless of that
    /// output's resolution or scale.
    ///
    /// Teaching note (kept from Stage 2, still true): the ink layer is
    /// painted explicitly rather than leaning on the fact that
    /// `Lockscreen::theme`'s background already happens to be ink (iced
    /// clears every surface to the theme's background color before drawing
    /// — see `iced_core::theme::default`). That equivalence is real today
    /// but is an implementation detail of how `iced::Theme` derives its
    /// base style, not a contract this crate should depend on — and now
    /// it's also load-bearing rather than just defensive: the ink layer is
    /// the wallpaper's actual fallback (see the module doc comment's point
    /// 1), not a decorative background that happens to match.
    fn view(&self, _window: iced::window::Id) -> Element<'_, Message> {
        let ink = container(Space::new().width(Fill).height(Fill))
            .width(Fill)
            .height(Fill)
            .style(style::container::ink_surface(&self.theme));

        // The centred stack: clock/date always, then (Stage 5) the
        // temperature line when there is one to show, then the reveal
        // flow's avatar → name → password below both once the prompt is up.
        let mut content = column![self.clock.view(&self.theme).map(Message::Clock)]
            .align_x(Center)
            // No token names "the gap between the clock and the prompt";
            // `popover_padding` (§6's "20–22px padding") is the closest
            // content-spacing token the design system defines. See
            // `modules::reveal`'s doc comment on the size-token gaps.
            .spacing(self.theme.sizes.popover_padding);

        if let Some(temperature) = self.temperature.view(&self.theme) {
            content = content.push(temperature.map(Message::Temperature));
        }

        if self.reveal.is_awake() {
            content = content.push(self.reveal.view(&self.theme).map(Message::Reveal));
        }

        let centred = container(content)
            .width(Fill)
            .height(Fill)
            .center_x(Fill)
            .center_y(Fill);

        let mut layers = stack![ink];
        if let Some(wallpaper) = &self.wallpaper {
            layers = layers.push(
                image(wallpaper.clone())
                    .width(Fill)
                    .height(Fill)
                    .content_fit(ContentFit::Cover),
            );
        }
        if self.reveal.is_awake() {
            // Style guide §2's scrim table: "Lock / greeter awake (prompt
            // shown) — rgba(12,10,0,0.62)", i.e. the `scrim.lock_awake`
            // token. It sits above the wallpaper and below the content, so
            // the clock and the prompt both read against a dimmed image
            // rather than against whatever the wallpaper happens to be.
            // At rest there is no scrim: §7 wants the wallpaper itself.
            layers = layers.push(
                container(Space::new().width(Fill).height(Fill))
                    .width(Fill)
                    .height(Fill)
                    .style(modules::reveal::awake_scrim(&self.theme)),
            );
        }
        layers.push(centred).into()
    }

    /// The clock's minute-aligned tick (`modules::clock::Clock::
    /// subscription`) is needed unconditionally — a lock surface always
    /// shows the time, dev build or not — so it lives above the
    /// `dev-unlock` split rather than duplicated inside both halves; only
    /// the Escape listener itself is feature-gated, batched in alongside
    /// the clock's subscription under `dev-unlock` and alone without it.
    #[cfg(feature = "dev-unlock")]
    fn subscription(&self) -> iced::Subscription<Message> {
        let escape = iced::event::listen_with(|event, _status, _window| match event {
            iced::Event::Keyboard(iced::keyboard::Event::KeyPressed {
                key: iced::keyboard::Key::Named(iced::keyboard::key::Named::Escape),
                ..
            }) => Some(Message::DevUnlockEscapePressed),
            _ => None,
        });
        iced::Subscription::batch([self.always_on_subscriptions(), escape])
    }

    #[cfg(not(feature = "dev-unlock"))]
    fn subscription(&self) -> iced::Subscription<Message> {
        self.always_on_subscriptions()
    }

    /// Everything a lock surface subscribes to in *both* feature
    /// configurations, factored out so the `dev-unlock` split above stays a
    /// one-line difference (the Escape listener) rather than two copies of a
    /// growing batch that could drift apart.
    ///
    /// Three things:
    ///
    /// 1. The clock's minute-aligned tick — a lock surface always shows the
    ///    time.
    /// 2. The reveal flow's idle-timeout tick, which is
    ///    `Subscription::none()` unless the prompt is actually up (see
    ///    `modules::reveal::Reveal::subscription`), so an at-rest surface
    ///    still wakes only once a minute.
    /// 3. The wake listener: any click, tap or keypress, on any output, in
    ///    any state. `_status` is deliberately ignored — iced's `text_input`
    ///    *captures* Escape without publishing a message of its own, so a
    ///    listener that skipped captured events would never see the Escape
    ///    that dismisses the prompt.
    /// 4. (Stage 5) The temperature module's own 15-minute refresh tick,
    ///    which is `Subscription::none()` when unconfigured (see
    ///    `modules::temperature::Temperature::subscription`) — an
    ///    unconfigured surface never arms a timer for a fetch it will never
    ///    make.
    /// 5. The wallpaper's post-load warm-up burst — `Subscription::none()`
    ///    except for the ~1 s right after `Message::WallpaperLoaded`
    ///    delivers a handle (see the `WALLPAPER_WARMUP_FRAMES` doc
    ///    comment), so, like the reveal and temperature timers, it costs an
    ///    at-rest surface nothing in the steady state.
    fn always_on_subscriptions(&self) -> iced::Subscription<Message> {
        let input = iced::event::listen_with(|event, _status, _window| {
            modules::reveal::event_to_message(&event)
        });
        let warmup = if self.wallpaper_warmup > 0 {
            iced::time::every(WALLPAPER_WARMUP_INTERVAL).map(|_instant| Message::WallpaperWarmed)
        } else {
            iced::Subscription::none()
        };
        iced::Subscription::batch([
            self.clock.subscription().map(Message::Clock),
            self.reveal.subscription().map(Message::Reveal),
            self.temperature.subscription().map(Message::Temperature),
            input.map(Message::Reveal),
            warmup,
        ])
    }
}

/// Turns a `modules::temperature::Effect` into the `iced::Task` `update`
/// needs, shared by `Lockscreen::boot` (the very first fetch) and
/// `Lockscreen::update`'s `Message::Temperature` arm (every fetch after) —
/// one translation site, exactly like the reveal flow's `Effect::Authenticate`
/// arm has exactly one `Task::perform` call site. This is a free function
/// rather than a method because `Lockscreen::boot` needs it *before* a
/// `Lockscreen` value exists to call a method on.
fn temperature_task(effect: modules::temperature::Effect) -> Task<Message> {
    match effect {
        modules::temperature::Effect::None => Task::none(),
        modules::temperature::Effect::Fetch(future) => Task::perform(future, |celsius| {
            Message::Temperature(modules::temperature::Message::Fetched(celsius))
        }),
    }
}

/// The lockscreen's message enum. `#[to_session_message]` (see
/// `iced_sessionlock`'s docs) appends a `Message::UnLock` variant and the
/// `TryInto<UnLockAction>` impl the runtime needs — see this file's module
/// doc comment for exactly what that buys and does not buy.
///
/// Since Stage 4 a default build has exactly one route to `UnLock`: the
/// `Message::Reveal` arm's `Effect::Unlock` translation in `update` (see
/// this file's Stage 4 doc section). `Message::Clock` still cannot produce
/// one, and `Message::Reveal` can only do so by way of
/// `modules::reveal`'s single `PAM ok` arm. `Message::WallpaperLoaded`
/// (Stage 7) cannot either — it only ever carries image data.
///
/// `Debug` is **hand-written** below rather than derived, for two stacked
/// reasons: iced's own tracing formats messages (a derive all the way down
/// would put the user's password in the journal one keystroke at a time —
/// the same reasoning `modules::reveal::Message` and `auth::Password` give
/// for their own redacting impls), and, since Stage 7,
/// `iced_core::image::Handle` (carried by `WallpaperLoaded`) derives
/// `Clone`/`PartialEq`/`Eq` but **not** `Debug`
/// (`iced_core-0.14.0/src/image.rs`) — so a blanket `#[derive(Debug)]` on
/// this enum would no longer even compile once that variant existed.
#[to_session_message]
#[derive(Clone)]
enum Message {
    /// Escape was pressed, anywhere on any output. See
    /// `Lockscreen::subscription` and the `update` arm above.
    #[cfg(feature = "dev-unlock")]
    DevUnlockEscapePressed,
    /// A tick from `modules::clock::Clock::subscription`, nested per the
    /// per-module-message-enum pattern (see that module's doc comment).
    Clock(modules::clock::Message),
    /// The reveal flow (Stage 4): input, the idle-timeout tick, and PAM
    /// outcomes. Nested the same way as `Clock`.
    Reveal(modules::reveal::Message),
    /// The temperature line (Stage 5): the 15-minute refresh tick and fetch
    /// outcomes. Nested the same way as `Clock`/`Reveal`.
    Temperature(modules::temperature::Message),
    /// Stage 7 (H-1): `wallpaper::load_task`'s future resolved, off the UI
    /// thread. `None` means "nothing configured" or "failed to decode" —
    /// see `Lockscreen::update`'s arm for this variant.
    WallpaperLoaded(Option<image::Handle>),
    /// A post-load warm-up tick (see `WALLPAPER_WARMUP_FRAMES`). Carries
    /// nothing, exactly like the clock's `Tick` — arriving is its whole
    /// job.
    WallpaperWarmed,
}

/// Hand-written — see this enum's doc comment for why a blanket derive no
/// longer compiles once `WallpaperLoaded` carries an `image::Handle`.
/// `WallpaperLoaded` itself only ever prints whether a handle arrived, never
/// pixel data (there'd be nothing sensitive in it if it did — this is a
/// compile-time necessity, not a redaction, unlike `Password`'s).
impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "dev-unlock")]
            Message::DevUnlockEscapePressed => f.write_str("DevUnlockEscapePressed"),
            Message::Clock(message) => write!(f, "Clock({message:?})"),
            Message::Reveal(message) => write!(f, "Reveal({message:?})"),
            Message::Temperature(message) => write!(f, "Temperature({message:?})"),
            Message::WallpaperLoaded(handle) => write!(
                f,
                "WallpaperLoaded({})",
                if handle.is_some() { "Some(..)" } else { "None" }
            ),
            Message::WallpaperWarmed => f.write_str("WallpaperWarmed"),
            Message::UnLock => f.write_str("UnLock"),
        }
    }
}
