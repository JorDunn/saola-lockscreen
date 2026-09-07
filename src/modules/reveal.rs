//! The reveal flow — avatar → name → password — and the state machine that
//! governs it. **This is the security core** (Architecture, `PLAN.md`).
//!
//! ```text
//! Idle ──click/keypress──▶ Revealed ──Enter──▶ Authenticating ──PAM ok──▶ Unlock
//!   ▲                        │  ▲                    │
//!   └────Escape/timeout──────┘  └──── PAM fail ──────┘  (error copy, field cleared)
//! ```
//!
//! # The unlock-edge rule, and how this module is built to make it checkable
//!
//! `CLAUDE.md` states it as bluntly as it can be stated: *the only call site
//! of the sessionlock unlock action is the `PAM ok` edge*, plus the
//! `dev-unlock` cfg edge in `main.rs`. The design problem is that "the only
//! call site" is an easy thing to *say* and a hard thing to *keep true*
//! through refactors — so this module never constructs an
//! `iced::Task`, never names `Message::UnLock`, and in fact cannot reach
//! iced's unlock machinery at all.
//!
//! Instead [`Reveal::update`] returns a plain [`Effect`] value describing
//! what it wants done, and `main.rs` translates exactly one of those
//! variants — [`Effect::Unlock`] — into `Task::done(Message::UnLock)`. Three
//! things follow, and all three are what Stage 6's first audit item needs:
//!
//! 1. `grep -n 'Effect::Unlock' src/` enumerates the whole unlock surface of
//!    the crate: the enum declaration, the one arm that produces it, and the
//!    one arm in `main.rs` that consumes it.
//! 2. That producing arm is reachable only from
//!    `(State::Authenticating, Message::Finished(Outcome::Authenticated))` —
//!    and `Outcome::Authenticated` itself has exactly one construction site,
//!    in `auth::PamAuthenticator::run_pam`, after both `pam_authenticate`
//!    and `pam_acct_mgmt` returned success.
//! 3. Because `Effect` is an ordinary value, the claim is *testable*:
//!    [`tests::unlock_is_produced_by_exactly_one_state_and_message`] walks
//!    the entire cross product of states × messages and asserts
//!    `Effect::Unlock` appears exactly once in it.
//!
//! # Time is injected, never read
//!
//! [`Reveal::update`] takes `now: Instant` as a parameter rather than
//! calling `Instant::now()` itself, for the same reason `modules::clock`'s
//! formatters take a `DateTime` (see that module's doc comment): the 30 s
//! idle timeout is otherwise only testable by sleeping, and a test that
//! sleeps for 30 s is a test nobody runs. `main.rs` passes the real clock;
//! the tests below pass `t0 + 31s` and get a deterministic answer in
//! microseconds.
//!
//! # What this module deliberately does *not* do
//!
//! - **It does not seed the password from the key that woke it.** Pressing
//!   `h` on the idle surface reveals the prompt but does not type an `h`
//!   into it. Two reasons: iced hands key events an `Option<SmolStr>` of
//!   text this crate would have to copy into the password buffer *before*
//!   it knows the buffer exists (a copy outside [`auth::Password`]'s
//!   zeroizing discipline — see `auth.rs`'s lifetime accounting), and "any
//!   key reveals" (§7) includes keys with no sensible text at all (F1,
//!   Shift, a compose sequence). Losing the first keystroke is the
//!   conservative trade.
//! - **It does not cancel an in-flight attempt.** Escape during
//!   `Authenticating` is a no-op, not a cancel: `pam_authenticate` is a
//!   blocking C call with no cancellation point, so "cancelling" could only
//!   mean *ignoring* its answer while it keeps running. Worse, a cancel that
//!   returned to `Idle` would leave a live future whose `Outcome` arrives
//!   later — which is precisely the shape of bug that unlocks a screen the
//!   user thought they had dismissed. The stale-outcome guard in
//!   [`Reveal::update`]'s `Finished` arm closes that door from the other
//!   side as well.
//!
//! # §7 / §6 styling: everything now comes from `saola-theme`
//!
//! §7: avatar (config `avatar`, else `~/.face`, else an initials disc), the
//! GECOS display name, a password field "styled like the rosec prompt's
//! input (§6 pill, subtle-fill, primary-ivory text)", and accent-light error
//! copy on failure. `~/.config/rosec/config.toml`'s `[prompt.theme]` was
//! read for the kinship: `input_background = "#FFFFF012"` is
//! `on_ink.fill_subtle`, `input_text = "#FFFFF0"` is `on_ink.primary`,
//! `accent_color`/`border_color` are `palette.accent`.
//!
//! This module used to compose three of those looks locally, because
//! `saola-theme` v0.5.0 had no helper for them: a subtle-fill password
//! field (`field_style`), an initials disc (`disc_style`), and the §2 awake
//! scrim (`awake_scrim`). All three were then **ported upstream from this
//! file** and shipped in `saola-theme` v0.13.0, so the local copies are
//! gone and this module calls the design system instead:
//!
//! - [`style::text_input::prompt`] / [`style::text_input::prompt_rejected`]
//!   — the §6 pill over the rosec prompt's quiet `fill_subtle` recess, with
//!   the accent ring on focus and the accent-light ring in every state once
//!   a password has been rejected.
//! - [`style::container::disc`] — `style::container::tile`'s recipe at
//!   `radii.pill`, which closes a square container into a circle. Used by
//!   [`saola_theme::avatar::view`], which is itself the port of this
//!   module's old avatar arm.
//! - [`style::container::scrim`] with [`style::container::ScrimKind`] —
//!   `main.rs` layers `ScrimKind::LockAwake` under the prompt and
//!   `ScrimKind::LockRest` at rest.
//!
//! The avatar itself moved too: [`saola_theme::avatar::Avatar`] is this
//! module's old `Avatar` enum, and [`resolve_avatar`] below is the thin
//! lockscreen-side wrapper that supplies `$HOME`, this crate's decoder
//! (`wallpaper::decode`) and the stderr warning the design-system crate
//! deliberately does not emit.
//!
//! Sizes are named tokens now as well — `sizes.avatar_lock` (the avatar
//! circle), `sizes.field_lock` (the §6 60–64 px field height),
//! `sizes.lock_stack_gap` (the avatar → name → field rhythm) and
//! `typography.size.avatar_initials` — each minted upstream from the
//! derivations this file used to spell out at its use sites. There is no
//! hex and no bare number in this file.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use iced::widget::text::LineHeight;
use iced::widget::{column, text, text_input};
use iced::{Element, Length, Subscription};
use saola_theme::convert::{ui_font, ui_font_regular, ColorExt};
use saola_theme::{style, Surface, Theme};

/// §7's avatar — a decoded photo, or an initials disc. Re-exported rather
/// than re-declared: this enum *was* this module's, and `saola-theme`
/// v0.13.0 adopted it verbatim so the future greeter draws the same thing
/// (see [`saola_theme::avatar`]'s own module docs). `main.rs` keeps
/// importing it from here, because the lockscreen-side resolution wrapper
/// ([`resolve_avatar`]) lives here too.
pub use saola_theme::avatar::Avatar;

use crate::auth::{Account, AuthFuture, Authenticator, Outcome, Password};

/// How long the revealed prompt stays up with no input before folding back
/// to the at-rest clock (Architecture: "Escape or 30 s idle returns to
/// Idle"). Public so the tests below and any future config knob name the
/// same number once.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How often the idle-timeout check runs while revealed. One second is fine
/// granularity for a 30 s timeout and cheap: the subscription only exists in
/// `Revealed` (see [`Reveal::subscription`]), so an at-rest lock surface
/// still redraws only on the clock's minute tick.
const TICK: Duration = Duration::from_secs(1);

/// The widget id of the password field, used by `main.rs` to focus it.
///
/// A plain string id rather than [`iced::advanced::widget::Id::unique`]
/// because `view` runs once per output: every lock surface builds its own
/// field, and `iced_sessionlock`'s `Action::Widget` handler applies a focus
/// operation to *every* window it manages (verified in
/// `iced_sessionlock-0.19.1/src/multi_window.rs`). Sharing one id is
/// therefore the behaviour we want — "focus the password field on whichever
/// output the compositor gives keys to" — rather than a collision.
pub fn password_input_id() -> iced::advanced::widget::Id {
    iced::advanced::widget::Id::new("saola-lockscreen-password")
}

// ---------------------------------------------------------------------------
// Messages and effects
// ---------------------------------------------------------------------------

/// The reveal flow's own message type, nested into `main.rs`'s outer
/// `Message` as `Message::Reveal` — the per-module-enum pattern
/// `modules::clock` established.
#[derive(Clone)]
pub enum Message {
    /// Any click, tap or keypress anywhere on any lock surface. Wakes the
    /// prompt from `Idle`; elsewhere it is an activity signal that pushes
    /// the idle timeout back.
    Woke,
    /// Escape.
    Dismissed,
    /// The password field's contents changed.
    Changed(Password),
    /// Enter, in the password field.
    Submitted,
    /// One [`TICK`] elapsed while revealed — the idle-timeout check.
    Tick,
    /// The authenticator finished. The **only** message that can lead to
    /// [`Effect::Unlock`], and then only in [`State::Authenticating`].
    Finished(Outcome),
}

/// Hand-written rather than derived, so that `Message::Changed` cannot print
/// the password. `main.rs`'s top-level `Message` derives `Debug`, and iced's
/// own tracing formats messages — a derive here would put the user's
/// password into the journal one keystroke at a time.
///
/// ([`Password`]'s own `Debug` is already redacted; this impl is the second
/// layer, so that neither one alone is load-bearing.)
impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::Woke => f.write_str("Woke"),
            Message::Dismissed => f.write_str("Dismissed"),
            Message::Changed(_) => f.write_str("Changed(<redacted>)"),
            Message::Submitted => f.write_str("Submitted"),
            Message::Tick => f.write_str("Tick"),
            Message::Finished(outcome) => write!(f, "Finished({outcome:?})"),
        }
    }
}

/// What [`Reveal::update`] asks `main.rs` to do. See this module's doc
/// comment for why the state machine returns a value instead of an
/// `iced::Task`.
pub enum Effect {
    /// Nothing beyond the state change that already happened.
    None,
    /// Give the password field keyboard focus.
    Focus,
    /// Drive this authentication attempt off the UI thread and deliver its
    /// [`Outcome`] back as [`Message::Finished`].
    Authenticate(AuthFuture),
    /// **THE unlock edge.** PAM authenticated the user. Produced in exactly
    /// one arm of [`Reveal::update`]; consumed in exactly one arm of
    /// `main.rs`'s `update`, which is the only place in this crate that
    /// constructs `Message::UnLock`.
    Unlock,
}

/// `AuthFuture` is a boxed `dyn Future` with no `Debug`, so this is
/// hand-written. Useful in test failure output, and it also keeps `Effect`
/// out of the "accidentally printed something sensitive" category — the
/// future captures a [`Password`], and this impl never looks inside it.
impl std::fmt::Debug for Effect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Effect::None => f.write_str("None"),
            Effect::Focus => f.write_str("Focus"),
            Effect::Authenticate(_) => f.write_str("Authenticate(..)"),
            Effect::Unlock => f.write_str("Unlock"),
        }
    }
}

/// The three states of Architecture's diagram, and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// At rest: clock, date, temperature, nothing else (§7).
    Idle,
    /// The prompt is up and the field accepts input.
    Revealed,
    /// A PAM attempt is in flight. The field is **disabled** — no second
    /// submission is possible (Architecture).
    Authenticating,
}

// ---------------------------------------------------------------------------
// Avatar
// ---------------------------------------------------------------------------

/// Resolve §7's avatar for `account`, once, at boot — called from
/// `main.rs`'s `Lockscreen::boot` (which is also where the config lives —
/// see the Stage 3 handoff's "read the config once" gotcha).
///
/// A three-line wrapper over [`Avatar::resolve`], which is this module's own
/// former `resolve` after `saola-theme` v0.13.0 adopted it. The wrapper
/// exists because the design-system crate deliberately keeps three things
/// out of itself, and all three are the lockscreen's to supply:
///
/// 1. **`$HOME`.** The theme takes it as a parameter so its own precedence
///    tests never touch the environment; the read belongs to the app.
/// 2. **The decoder.** `saola-theme` has no `image` dependency and must not
///    grow one. `wallpaper::decode` is shared here rather than re-derived
///    because its `Handle::from_rgba` output is the one handle variant
///    `iced_wgpu`'s cache resolves *synchronously* (see `wallpaper.rs`'s
///    doc comment for the live-confirmed account), which matters even more
///    for the avatar than for the wallpaper: it appears at the exact moment
///    the user interacts, and a one-frame-late avatar reads as a flash.
/// 3. **The warning.** [`saola_theme::avatar::Resolution`] returns the
///    "configured path failed" case as *data* rather than writing to
///    anyone's stderr; printing it is this binary's job.
///
/// Never fails: an unreadable, oversize, non-regular-file or undecodable
/// candidate falls through to the next one, and the initials disc always
/// works.
pub fn resolve_avatar(configured: Option<&Path>, account: &Account) -> Avatar {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    resolve_avatar_from(configured, &account.display_name, home.as_deref())
}

/// [`resolve_avatar`] with `$HOME` injected instead of read, so the §7
/// precedence stays unit-testable without touching the environment — the
/// same discipline `config.rs`'s `config_dir_from` uses.
fn resolve_avatar_from(
    configured: Option<&Path>,
    display_name: &str,
    home: Option<&Path>,
) -> Avatar {
    // `MAX_BYTES_DEFAULT` (16 MiB) is the theme's recommended cap and this
    // crate has no stronger opinion: `wallpaper.rs`'s own limit is
    // `MAX_DIMENSION`, a *pixel* cap applied after decoding, so there is no
    // existing byte budget for an avatar to agree with. The cap matters
    // because every candidate path is user-controlled and read before the
    // user has authenticated — see `saola_theme::avatar`'s "Bounded read".
    let resolution = Avatar::resolve(
        configured,
        display_name,
        home,
        Avatar::MAX_BYTES_DEFAULT,
        crate::wallpaper::decode,
    );

    // Only the *explicitly configured* path is worth a warning; a missing
    // `~/.face` is the normal case for most systems and says nothing. The
    // theme applies exactly that rule when it sets the flag.
    if let Some(path) = resolution.configured_failed {
        eprintln!(
            "saola-lockscreen: avatar {} could not be loaded — falling back",
            path.display()
        );
    }

    resolution.avatar
}

// ---------------------------------------------------------------------------
// The state machine
// ---------------------------------------------------------------------------

/// The reveal flow's whole state. Held as one field on `Lockscreen`, exactly
/// like `modules::clock::Clock` — the module pattern this repo copies from
/// the panel (a state struct, a `view(&Theme)`, a `subscription()`).
pub struct Reveal {
    state: State,
    /// The live password buffer. Zeroized on every replacement and on every
    /// clear — see `auth.rs`'s password-lifetime accounting.
    password: Password,
    /// §1-compliant error copy (accent-light on ink), or `None`.
    error: Option<String>,
    /// When the last user activity happened, for the idle timeout. Only
    /// meaningful in [`State::Revealed`].
    last_activity: Instant,
    account: Account,
    avatar: Avatar,
    /// Behind an `Arc<dyn ..>` so the tests below can substitute a fake —
    /// the whole reason `auth.rs` has a trait at all (Architecture's
    /// testing strategy).
    authenticator: Arc<dyn Authenticator>,
    /// Injected so the timeout tests do not have to wait 30 seconds.
    timeout: Duration,
}

impl Reveal {
    /// Boot state: [`State::Idle`], empty buffer, no error.
    pub fn new(
        account: Account,
        avatar: Avatar,
        authenticator: Arc<dyn Authenticator>,
        now: Instant,
    ) -> Self {
        Reveal {
            state: State::Idle,
            password: Password::default(),
            error: None,
            last_activity: now,
            account,
            avatar,
            authenticator,
            timeout: IDLE_TIMEOUT,
        }
    }

    /// Whether the prompt is showing. `main.rs` uses this to decide whether
    /// to draw the reveal stack at all, and which of §2's two lock scrims to
    /// lay over the wallpaper (`LockAwake` here, `LockRest` at rest) — at
    /// rest, §7 says the surface shows the clock, date and temperature and
    /// *nothing else*.
    pub fn is_awake(&self) -> bool {
        self.state != State::Idle
    }

    /// The state machine. Every transition in Architecture's diagram lives
    /// in this one function, and nothing outside it changes `self.state`.
    ///
    /// `now` is injected rather than read — see this module's doc comment.
    pub fn update(&mut self, message: Message, now: Instant) -> Effect {
        match (self.state, message) {
            // ---- Idle ------------------------------------------------
            //
            // Any click or keypress wakes the prompt (§7). The buffer and
            // error copy are cleared on the way in, so a fresh reveal never
            // shows the previous attempt's error — the "error copy cleared
            // on next reveal" requirement.
            (State::Idle, Message::Woke) => {
                self.state = State::Revealed;
                self.clear_secret();
                self.error = None;
                self.last_activity = now;
                Effect::Focus
            }

            // ---- Revealed --------------------------------------------
            //
            // Further keypresses/clicks while revealed are activity, not
            // transitions: they push the idle timeout back so the prompt
            // does not fold away under someone who is typing.
            (State::Revealed, Message::Woke) => {
                self.last_activity = now;
                Effect::None
            }

            (State::Revealed, Message::Changed(password)) => {
                // Assigning drops the previous buffer, which zeroizes it.
                self.password = password;
                // Typing clears the previous attempt's error copy.
                self.error = None;
                self.last_activity = now;
                Effect::None
            }

            (State::Revealed, Message::Submitted) => {
                if self.password.is_empty() {
                    // Deliberately *not* an attempt. Every submission
                    // reaches `pam_faillock`, whose stock Arch policy locks
                    // the account after three failures — so an accidental
                    // Enter on an empty field would spend a third of the
                    // budget for a guess that cannot succeed. A locker's
                    // second-worst failure mode is "user locked out"
                    // (`CLAUDE.md`), and this is the cheapest place to not
                    // cause it.
                    self.last_activity = now;
                    return Effect::None;
                }
                // Move the password out of the state and into the attempt:
                // while `Authenticating`, this struct holds no secret at
                // all (asserted by
                // `password_is_out_of_state_while_authenticating`).
                let password = std::mem::take(&mut self.password);
                self.state = State::Authenticating;
                self.error = None;
                self.last_activity = now;
                Effect::Authenticate(self.authenticator.authenticate(password))
            }

            (State::Revealed, Message::Dismissed) => {
                self.return_to_idle();
                Effect::None
            }

            (State::Revealed, Message::Tick) => {
                if now.duration_since(self.last_activity) >= self.timeout {
                    self.return_to_idle();
                }
                Effect::None
            }

            // ---- Authenticating --------------------------------------
            //
            // THE unlock edge, and the only one in this crate outside
            // `main.rs`'s `dev-unlock` cfg block. Reachable only from this
            // exact (state, message) pair, with `Outcome::Authenticated` —
            // which `auth.rs` constructs in exactly one place, after both
            // `pam_authenticate` and `pam_acct_mgmt` succeeded.
            (State::Authenticating, Message::Finished(Outcome::Authenticated)) => Effect::Unlock,

            (State::Authenticating, Message::Finished(Outcome::Rejected)) => {
                self.fail(now, "Wrong password.".to_string())
            }

            (State::Authenticating, Message::Finished(Outcome::Unavailable(copy))) => {
                self.fail(now, copy)
            }

            // While `Authenticating` the field is disabled, so none of these
            // should arrive at all — they are handled explicitly rather than
            // by a catch-all so that the "no second submission" guarantee is
            // a property of this function, not of the view happening to
            // render a disabled widget.
            //
            // Escape in particular is a no-op, not a cancel: see this
            // module's doc comment.
            (State::Authenticating, _) => Effect::None,

            // ---- Everything else -------------------------------------
            //
            // Most importantly: a `Finished` arriving outside
            // `Authenticating` is *ignored*. That is the stale-outcome
            // guard — without it, an `Outcome::Authenticated` delivered
            // after the machine had already returned to `Idle` would be a
            // spurious unlock, the worst bug this crate can have.
            (State::Idle, _) | (State::Revealed, Message::Finished(_)) => Effect::None,
        }
    }

    /// Back to `Idle`, with the buffer and error copy cleared. The one place
    /// the Escape and timeout edges share.
    fn return_to_idle(&mut self) {
        self.state = State::Idle;
        self.clear_secret();
        self.error = None;
    }

    /// PAM said no (for whatever reason): show the copy, clear the field,
    /// and go back to `Revealed` with focus — Architecture's "error copy,
    /// field cleared, machine back to `Revealed`".
    fn fail(&mut self, now: Instant, copy: String) -> Effect {
        self.state = State::Revealed;
        // Already empty (the buffer was moved out on submit); clearing again
        // is free and keeps this function correct on its own terms rather
        // than by relying on the submit arm.
        self.clear_secret();
        self.error = Some(copy);
        self.last_activity = now;
        Effect::Focus
    }

    /// Replace the buffer with an empty one, zeroizing the old contents via
    /// [`Password`]'s `Drop`.
    fn clear_secret(&mut self) {
        self.password = Password::default();
    }

    /// The idle-timeout tick, and only while it can fire. `Idle` needs no
    /// timer at all, and `Authenticating` deliberately does not time out —
    /// `pam_authenticate` may legitimately take a while (a slow hash, a
    /// network module), and folding the surface away underneath a live
    /// attempt would strand its `Outcome`.
    ///
    /// The wake-on-input listener does **not** live here: it must run in
    /// every state (that is how `Idle` hears about the first keypress), so
    /// `main.rs` owns it — see [`event_to_message`].
    pub fn subscription(&self) -> Subscription<Message> {
        if self.ticks() {
            iced::time::every(TICK).map(|_instant| Message::Tick)
        } else {
            Subscription::none()
        }
    }

    /// The predicate [`Self::subscription`] branches on, split out because
    /// `iced::Subscription`'s `Debug` is opaque (`f.debug_struct(
    /// "Subscription").finish()` — it carries no recipe information), so
    /// "is the timer running?" is only assertable at this level.
    fn ticks(&self) -> bool {
        self.state == State::Revealed
    }

    /// The §7 revealed stack: avatar, display name, password field, and the
    /// error line when there is one. `main.rs` only calls this when
    /// [`Self::is_awake`]; at rest there is nothing here to draw.
    pub fn view(&self, theme: &Theme) -> Element<'_, Message> {
        // The whole avatar arm — photo cover-fit, initials on a
        // `container::disc`, the `center_x`/`center_y`-not-`Fill` gotcha —
        // now lives in `saola_theme::avatar::view`, ported from this file so
        // the greeter draws an identical badge. `sizes.avatar_lock` (88) is
        // the token minted for the diameter this module used to state as
        // `hit_target_touch * 2.0`.
        let avatar = saola_theme::avatar::view(theme, &self.avatar, theme.sizes.avatar_lock);

        // §3: "IBM Plex Sans — all interface text. Everything you scan."
        // The clock and date above are already the screen's two permitted
        // serif elements, so the name is sans by rule, not by taste.
        let name = text(&self.account.display_name)
            .font(ui_font(theme))
            .size(theme.typography.size.launcher_input)
            .color(theme.on_ink.primary.into_iced());

        // The field is disabled exactly when a PAM attempt is in flight:
        // `on_input`/`on_submit` are `None` in `Authenticating`, which is
        // what iced's `text_input` reads as "disabled" (see its
        // `on_input_maybe` doc). Belt and braces with the state machine's
        // own `(State::Authenticating, _) => Effect::None` arm — either one
        // alone would prevent a second submission.
        let accepting_input = self.state == State::Revealed;
        // `Password::displayable` is the one sanctioned read of the buffer
        // (see its doc comment); `.secure(true)` below is what the user
        // actually sees for it.
        let field = text_input("", self.password.displayable())
            .id(password_input_id())
            .secure(true)
            .font(ui_font_regular(theme))
            .size(theme.typography.size.launcher_input)
            .padding(field_padding(theme))
            .width(Length::Fixed(theme.sizes.popover_width))
            .style(field_style(theme, self.error.is_some()))
            .on_input_maybe(accepting_input.then_some(|value: String| {
                // The `String` iced hands us is moved straight into a
                // zeroizing buffer and never copied again on this side —
                // see `auth.rs`'s accounting for the copies upstream of
                // here that this crate cannot reach.
                Message::Changed(Password::new(value))
            }))
            .on_submit_maybe(accepting_input.then_some(Message::Submitted));

        let mut stack = column![avatar, name, field]
            .align_x(iced::Center)
            // `lock_stack_gap` (20) is the token minted for exactly this
            // rhythm (avatar → name → field). This module used to borrow
            // `island_gap` (10), which names the gap between free-standing
            // panel islands — a different concept that merely had a
            // plausible number.
            .spacing(theme.sizes.lock_stack_gap);

        if let Some(error) = &self.error {
            // §1: "accent-light — accent-coloured text on ink only (hints,
            // error copy, prompt highlights)". Severity is carried by the
            // wording; there is no danger colour in this system.
            stack = stack.push(
                text(error)
                    .font(ui_font_regular(theme))
                    .size(theme.typography.size.body)
                    .color(theme.palette.accent_light.into_iced()),
            );
        }

        stack.into()
    }
}

// ---------------------------------------------------------------------------
// Input routing
// ---------------------------------------------------------------------------

/// Maps a raw iced event to a reveal-flow message, or `None` to ignore it.
///
/// Split out of the subscription closure so the routing rules are a pure
/// function and can be unit-tested (the subscription itself cannot be —
/// there is no way to synthesise an `iced::Subscription`'s output without a
/// running runtime).
///
/// Note on Escape: iced's `text_input` *captures* Escape (it clears its own
/// focus without publishing a message), so this listener sees it with
/// `Status::Captured`. `main.rs`'s listener deliberately ignores the status
/// for exactly that reason — a status-filtered listener would never see the
/// Escape that dismisses the prompt.
pub fn event_to_message(event: &iced::Event) -> Option<Message> {
    use iced::keyboard::{key::Named, Event as Keyboard, Key};
    use iced::mouse::Event as Mouse;
    use iced::touch::Event as Touch;

    match event {
        iced::Event::Keyboard(Keyboard::KeyPressed {
            key: Key::Named(Named::Escape),
            ..
        }) => Some(Message::Dismissed),
        // Any other key at all — §7's "click or any key reveals".
        iced::Event::Keyboard(Keyboard::KeyPressed { .. }) => Some(Message::Woke),
        iced::Event::Mouse(Mouse::ButtonPressed(_)) => Some(Message::Woke),
        iced::Event::Touch(Touch::FingerPressed { .. }) => Some(Message::Woke),
        // Everything else — pointer motion, key *releases*, window events —
        // is not activity for this purpose. In particular, moving the mouse
        // must not wake the prompt: a nudged desk would light up the screen
        // all night.
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Size derivations the design system cannot express for us
// ---------------------------------------------------------------------------

/// Vertical padding that makes the password field `sizes.field_lock` tall.
///
/// `sizes.field_lock` (62) is the token for §6's "60–64px on lock/greeter"
/// field, and `style::text_input::prompt`'s own docs name it as the height
/// to pair the style with. iced 0.14's `text_input` has **no `.height`**,
/// though: its height is the value text's line height plus the vertical
/// padding, and nothing else (read out of `iced_widget-0.14.2`'s
/// `text_input::layout`, which computes
/// `line_height.to_absolute(text_size)` and then shrinks the limits by the
/// padding). So the only way to *adopt* the token rather than approximate
/// it is to solve for the padding that produces it.
///
/// The horizontal padding stays `sizes.popover_padding` — §6's content
/// padding, and what this field has always used.
///
/// `max(0.0)` guards the case where a future type token grows past the
/// field height: a negative padding is not a panic in iced, but it is a
/// nonsense layout, and this module has no runtime `panic!` budget to spend
/// on finding out.
fn field_padding(theme: &Theme) -> iced::Padding {
    let text_size = theme.typography.size.launcher_input;
    // `LineHeight::default()` is what `text_input` uses when the caller sets
    // none — the same default this widget is already getting.
    let line_height = LineHeight::default().to_absolute(text_size.into()).0;
    let vertical = ((theme.sizes.field_lock - line_height) / 2.0).max(0.0);

    iced::Padding::default()
        .top(vertical)
        .bottom(vertical)
        .left(theme.sizes.popover_padding)
        .right(theme.sizes.popover_padding)
}

/// The password field's style: `style::text_input::prompt`, or its
/// `prompt_rejected` sibling once an attempt has been refused.
///
/// A closure rather than a straight `if` at the call site because the two
/// helpers return *different* opaque types: they are only interchangeable
/// once both are called, which is what this wrapper arranges. Both are this
/// module's former `field_style`, ported into `saola-theme` v0.13.0 —
/// `prompt_rejected` draws the accent-light ring in every interactive
/// status, so a wrong password keeps saying so while the user retypes.
fn field_style(
    theme: &Theme,
    rejected: bool,
) -> impl Fn(&iced::Theme, text_input::Status) -> text_input::Style {
    let prompt = style::text_input::prompt(theme, Surface::Ink);
    let prompt_rejected = style::text_input::prompt_rejected(theme, Surface::Ink);

    move |iced_theme, status| {
        if rejected {
            prompt_rejected(iced_theme, status)
        } else {
            prompt(iced_theme, status)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // ---- Fakes -----------------------------------------------------------

    /// A scripted [`Authenticator`]: it counts calls and answers with the
    /// next outcome in its script (repeating the last one once exhausted).
    /// Covers all four fakes Stage 4 asks for — accept, reject,
    /// reject-then-accept, and "slow" — because *slow* is not a property of
    /// the fake at all in this design: the state machine never awaits, so
    /// "in flight" simply means "`Message::Finished` has not been delivered
    /// yet", which a test expresses by not delivering it.
    struct FakeAuthenticator {
        script: Vec<Outcome>,
        calls: Arc<AtomicUsize>,
    }

    impl FakeAuthenticator {
        fn scripted(script: Vec<Outcome>) -> (Arc<dyn Authenticator>, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            let fake = FakeAuthenticator {
                script,
                calls: Arc::clone(&calls),
            };
            (Arc::new(fake), calls)
        }
    }

    impl Authenticator for FakeAuthenticator {
        fn authenticate(&self, password: Password) -> AuthFuture {
            let index = self.calls.fetch_add(1, Ordering::SeqCst);
            let outcome = self
                .script
                .get(index)
                .or_else(|| self.script.last())
                .cloned()
                .unwrap_or(Outcome::Rejected);
            // The password is dropped (and zeroized) here — the fake has no
            // use for it, and holding it would be exactly the leak the real
            // implementation is careful to avoid.
            drop(password);
            Box::pin(async move { outcome })
        }
    }

    fn reveal_with(script: Vec<Outcome>) -> (Reveal, Arc<AtomicUsize>, Instant) {
        let (authenticator, calls) = FakeAuthenticator::scripted(script);
        let now = Instant::now();
        let account = Account {
            username: "jordan".to_string(),
            display_name: "Jordan Dunn".to_string(),
        };
        let reveal = Reveal::new(
            account,
            Avatar::Initials("JD".to_string()),
            authenticator,
            now,
        );
        (reveal, calls, now)
    }

    /// Idle → Revealed, the shape almost every test below starts from.
    fn revealed(script: Vec<Outcome>) -> (Reveal, Arc<AtomicUsize>, Instant) {
        let (mut reveal, calls, now) = reveal_with(script);
        let _ = reveal.update(Message::Woke, now);
        (reveal, calls, now)
    }

    fn typed(reveal: &mut Reveal, now: Instant, value: &str) {
        let _ = reveal.update(Message::Changed(Password::new(value.to_string())), now);
    }

    // ---- Idle → Revealed -------------------------------------------------

    /// Boot state. The lock surface comes up at rest: §7's clock/date only,
    /// no prompt.
    #[test]
    fn boots_idle() {
        let (reveal, _, _) = reveal_with(vec![]);
        assert_eq!(reveal.state, State::Idle);
        assert!(!reveal.is_awake());
    }

    /// §7's "click or any key reveals" — and the reveal focuses the field so
    /// the next keystroke lands in it.
    #[test]
    fn keypress_reveals_from_idle_and_focuses_the_field() {
        let (mut reveal, _, now) = reveal_with(vec![]);
        let effect = reveal.update(Message::Woke, now);
        assert_eq!(reveal.state, State::Revealed);
        assert!(reveal.is_awake());
        assert!(matches!(effect, Effect::Focus));
    }

    /// The routing half of "click **or** any key": both a mouse button and a
    /// key produce the same `Woke`, and pointer *motion* produces nothing.
    #[test]
    fn events_route_to_the_right_messages() {
        use iced::keyboard::{key::Named, Event as Keyboard, Key, Location, Modifiers};

        let key_event = |key: Key| {
            iced::Event::Keyboard(Keyboard::KeyPressed {
                key: key.clone(),
                modified_key: key,
                physical_key: iced::keyboard::key::Physical::Unidentified(
                    iced::keyboard::key::NativeCode::Unidentified,
                ),
                location: Location::Standard,
                modifiers: Modifiers::default(),
                text: None,
                repeat: false,
            })
        };

        assert!(matches!(
            event_to_message(&key_event(Key::Named(Named::Escape))),
            Some(Message::Dismissed)
        ));
        assert!(matches!(
            event_to_message(&key_event(Key::Character("h".into()))),
            Some(Message::Woke)
        ));
        assert!(matches!(
            event_to_message(&key_event(Key::Named(Named::Shift))),
            Some(Message::Woke)
        ));
        assert!(matches!(
            event_to_message(&iced::Event::Mouse(iced::mouse::Event::ButtonPressed(
                iced::mouse::Button::Left
            ))),
            Some(Message::Woke)
        ));
        // Motion must not wake the surface — see `event_to_message`.
        assert!(
            event_to_message(&iced::Event::Mouse(iced::mouse::Event::CursorMoved {
                position: iced::Point::ORIGIN
            }))
            .is_none()
        );
        assert!(event_to_message(&iced::Event::Mouse(iced::mouse::Event::CursorLeft)).is_none());
    }

    // ---- Revealed → Idle -------------------------------------------------

    /// Escape folds the prompt away and takes the typed password with it.
    #[test]
    fn escape_returns_to_idle_and_clears_the_buffer() {
        let (mut reveal, _, now) = revealed(vec![]);
        typed(&mut reveal, now, "hunter2");
        assert!(!reveal.password.is_empty());

        let effect = reveal.update(Message::Dismissed, now);

        assert_eq!(reveal.state, State::Idle);
        assert!(reveal.password.is_empty());
        assert!(matches!(effect, Effect::None));
    }

    /// The 30 s idle timeout — driven entirely by injected time, no sleeping.
    #[test]
    fn idle_timeout_returns_to_idle_and_clears_the_buffer() {
        let (mut reveal, _, now) = revealed(vec![]);
        typed(&mut reveal, now, "hunter2");

        let _ = reveal.update(Message::Tick, now + IDLE_TIMEOUT);

        assert_eq!(reveal.state, State::Idle);
        assert!(reveal.password.is_empty());
    }

    /// One second short of the timeout, the prompt is still up. Pins the
    /// comparison as `>=` on the *elapsed* time rather than an off-by-one on
    /// tick counts.
    #[test]
    fn tick_before_the_timeout_keeps_the_prompt_up() {
        let (mut reveal, _, now) = revealed(vec![]);
        let _ = reveal.update(Message::Tick, now + IDLE_TIMEOUT - TICK);
        assert_eq!(reveal.state, State::Revealed);
    }

    /// Typing pushes the deadline back — the prompt must not fold away under
    /// someone in the middle of a long password.
    #[test]
    fn typing_resets_the_idle_timeout() {
        let (mut reveal, _, now) = revealed(vec![]);

        // 29 s in, the user types.
        typed(&mut reveal, now + IDLE_TIMEOUT - TICK, "h");
        // The original deadline passes: still revealed, because the clock
        // restarted at the keystroke.
        let _ = reveal.update(Message::Tick, now + IDLE_TIMEOUT);
        assert_eq!(reveal.state, State::Revealed);

        // 30 s after the *keystroke*, it folds.
        let _ = reveal.update(Message::Tick, now + IDLE_TIMEOUT + IDLE_TIMEOUT);
        assert_eq!(reveal.state, State::Idle);
    }

    /// A click or keypress that is not typing is still activity.
    #[test]
    fn waking_again_resets_the_idle_timeout() {
        let (mut reveal, _, now) = revealed(vec![]);
        let _ = reveal.update(Message::Woke, now + IDLE_TIMEOUT - TICK);
        let _ = reveal.update(Message::Tick, now + IDLE_TIMEOUT);
        assert_eq!(reveal.state, State::Revealed);
    }

    // ---- Submission ------------------------------------------------------

    /// The accept path: Enter → `Authenticating`, then a successful outcome
    /// → the unlock edge. This is the one and only route to `Effect::Unlock`.
    #[test]
    fn accepting_authenticator_unlocks() {
        let (mut reveal, calls, now) = revealed(vec![Outcome::Authenticated]);
        typed(&mut reveal, now, "hunter2");

        let effect = reveal.update(Message::Submitted, now);
        assert!(matches!(effect, Effect::Authenticate(_)));
        assert_eq!(reveal.state, State::Authenticating);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let effect = reveal.update(Message::Finished(Outcome::Authenticated), now);
        assert!(matches!(effect, Effect::Unlock));
    }

    /// The reject path: error copy, cleared field, back to `Revealed` with
    /// focus — and emphatically **not** an unlock.
    #[test]
    fn rejecting_authenticator_shows_error_and_returns_to_revealed() {
        let (mut reveal, _, now) = revealed(vec![Outcome::Rejected]);
        typed(&mut reveal, now, "wrong");
        let _ = reveal.update(Message::Submitted, now);

        let effect = reveal.update(Message::Finished(Outcome::Rejected), now);

        assert_eq!(reveal.state, State::Revealed);
        assert!(reveal.password.is_empty());
        assert!(reveal.error.is_some());
        assert!(matches!(effect, Effect::Focus));
    }

    /// An `Unavailable` outcome (the missing-service-file case, among
    /// others) shows *its own* copy verbatim and never unlocks.
    #[test]
    fn unavailable_outcome_shows_its_copy_and_never_unlocks() {
        let (mut reveal, _, now) = revealed(vec![]);
        typed(&mut reveal, now, "hunter2");
        let _ = reveal.update(Message::Submitted, now);

        let effect = reveal.update(
            Message::Finished(Outcome::Unavailable("Not configured.".to_string())),
            now,
        );

        assert_eq!(reveal.state, State::Revealed);
        assert_eq!(reveal.error.as_deref(), Some("Not configured."));
        assert!(matches!(effect, Effect::Focus));
    }

    /// **No second submission while in flight** (Architecture). The "slow"
    /// authenticator case: the first attempt has not delivered its
    /// `Finished` yet, and a second Enter must not start another PAM
    /// conversation.
    #[test]
    fn second_enter_while_authenticating_is_ignored() {
        let (mut reveal, calls, now) = revealed(vec![Outcome::Authenticated]);
        typed(&mut reveal, now, "hunter2");
        let _ = reveal.update(Message::Submitted, now);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let effect = reveal.update(Message::Submitted, now);

        assert!(matches!(effect, Effect::None));
        assert_eq!(reveal.state, State::Authenticating);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a second Enter started a second PAM conversation"
        );
    }

    /// Input arriving while `Authenticating` is dropped — the field is
    /// disabled in `view`, and the state machine refuses it independently.
    #[test]
    fn input_while_authenticating_is_ignored() {
        let (mut reveal, _, now) = revealed(vec![Outcome::Rejected]);
        typed(&mut reveal, now, "hunter2");
        let _ = reveal.update(Message::Submitted, now);

        typed(&mut reveal, now, "sneaky");

        assert_eq!(reveal.state, State::Authenticating);
        assert!(reveal.password.is_empty());
    }

    /// Escape during an attempt is a no-op — not a cancel, not an unlock.
    /// See this module's doc comment for why cancelling would be the more
    /// dangerous behaviour.
    #[test]
    fn escape_during_authentication_neither_cancels_nor_unlocks() {
        let (mut reveal, _, now) = revealed(vec![Outcome::Authenticated]);
        typed(&mut reveal, now, "hunter2");
        let _ = reveal.update(Message::Submitted, now);

        let effect = reveal.update(Message::Dismissed, now);

        assert!(matches!(effect, Effect::None));
        assert_eq!(reveal.state, State::Authenticating);
    }

    /// The timeout does not fire under a live attempt.
    #[test]
    fn timeout_does_not_fire_while_authenticating() {
        let (mut reveal, _, now) = revealed(vec![Outcome::Authenticated]);
        typed(&mut reveal, now, "hunter2");
        let _ = reveal.update(Message::Submitted, now);

        let _ = reveal.update(Message::Tick, now + IDLE_TIMEOUT + IDLE_TIMEOUT);

        assert_eq!(reveal.state, State::Authenticating);
    }

    /// Reject, then accept: the machine returns to a usable prompt and the
    /// second attempt goes through. Two PAM conversations, one unlock.
    #[test]
    fn reject_then_accept_unlocks_on_the_second_attempt() {
        let (mut reveal, calls, now) = revealed(vec![Outcome::Rejected, Outcome::Authenticated]);

        typed(&mut reveal, now, "wrong");
        let _ = reveal.update(Message::Submitted, now);
        let effect = reveal.update(Message::Finished(Outcome::Rejected), now);
        assert!(matches!(effect, Effect::Focus));
        assert_eq!(reveal.state, State::Revealed);

        typed(&mut reveal, now, "right");
        let _ = reveal.update(Message::Submitted, now);
        let effect = reveal.update(Message::Finished(Outcome::Authenticated), now);

        assert!(matches!(effect, Effect::Unlock));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// An empty submission never reaches PAM — see the `Submitted` arm on
    /// `pam_faillock` and the lockout failure mode.
    #[test]
    fn empty_submission_never_reaches_the_authenticator() {
        let (mut reveal, calls, now) = revealed(vec![Outcome::Authenticated]);

        let effect = reveal.update(Message::Submitted, now);

        assert!(matches!(effect, Effect::None));
        assert_eq!(reveal.state, State::Revealed);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    /// Clearing the field back to empty and pressing Enter is the same
    /// no-attempt case — the guard is on the buffer, not on "has the user
    /// ever typed".
    #[test]
    fn cleared_field_submission_never_reaches_the_authenticator() {
        let (mut reveal, calls, now) = revealed(vec![Outcome::Authenticated]);
        typed(&mut reveal, now, "hunter2");
        typed(&mut reveal, now, "");

        let _ = reveal.update(Message::Submitted, now);

        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    /// While a PAM attempt is running, this struct holds no password at all:
    /// the buffer is *moved* into the attempt on submit rather than copied.
    /// That shrinks the window in which a secret sits in UI state to the
    /// time between keystrokes and Enter.
    #[test]
    fn password_is_out_of_state_while_authenticating() {
        let (mut reveal, _, now) = revealed(vec![Outcome::Authenticated]);
        typed(&mut reveal, now, "hunter2");
        assert!(!reveal.password.is_empty());

        let _ = reveal.update(Message::Submitted, now);

        assert!(reveal.password.is_empty());
    }

    // ---- Error copy lifetime --------------------------------------------

    #[test]
    fn error_copy_is_cleared_by_typing() {
        let (mut reveal, _, now) = revealed(vec![Outcome::Rejected]);
        typed(&mut reveal, now, "wrong");
        let _ = reveal.update(Message::Submitted, now);
        let _ = reveal.update(Message::Finished(Outcome::Rejected), now);
        assert!(reveal.error.is_some());

        typed(&mut reveal, now, "r");

        assert!(reveal.error.is_none());
    }

    #[test]
    fn error_copy_is_cleared_by_the_next_reveal() {
        let (mut reveal, _, now) = revealed(vec![Outcome::Rejected]);
        typed(&mut reveal, now, "wrong");
        let _ = reveal.update(Message::Submitted, now);
        let _ = reveal.update(Message::Finished(Outcome::Rejected), now);
        assert!(reveal.error.is_some());

        let _ = reveal.update(Message::Dismissed, now);
        assert_eq!(reveal.state, State::Idle);
        let _ = reveal.update(Message::Woke, now);

        assert_eq!(reveal.state, State::Revealed);
        assert!(reveal.error.is_none());
    }

    // ---- The unlock-edge invariant --------------------------------------

    /// A successful outcome delivered when no attempt is in flight is
    /// **ignored**. This is the stale-outcome guard: without it, an
    /// `Outcome::Authenticated` arriving after Escape had already returned
    /// the machine to `Idle` would unlock a surface the user had just
    /// dismissed.
    #[test]
    fn stale_success_outside_authenticating_never_unlocks() {
        // Delivered in Idle.
        let (mut reveal, _, now) = reveal_with(vec![]);
        let effect = reveal.update(Message::Finished(Outcome::Authenticated), now);
        assert!(matches!(effect, Effect::None));
        assert_eq!(reveal.state, State::Idle);

        // Delivered in Revealed.
        let (mut reveal, _, now) = revealed(vec![]);
        let effect = reveal.update(Message::Finished(Outcome::Authenticated), now);
        assert!(matches!(effect, Effect::None));
        assert_eq!(reveal.state, State::Revealed);
    }

    /// **The unlock-edge rule, as an executable assertion.**
    ///
    /// Walks the entire cross product of states × messages and counts how
    /// many combinations produce [`Effect::Unlock`]. Exactly one may:
    /// `(Authenticating, Finished(Authenticated))`. Any new message variant,
    /// or any new arm that reaches the unlock edge, fails this test — which
    /// is the point. (New `State`/`Message` variants must be added to the
    /// lists below; the compiler cannot enumerate them for us, so the
    /// `matches!` sweep in `every_state_and_message_pair_is_covered` pins
    /// the counts too.)
    #[test]
    fn unlock_is_produced_by_exactly_one_state_and_message() {
        let states = [State::Idle, State::Revealed, State::Authenticating];
        let messages = || {
            vec![
                ("Woke", Message::Woke),
                ("Dismissed", Message::Dismissed),
                (
                    "Changed",
                    Message::Changed(Password::new("hunter2".to_string())),
                ),
                ("Submitted", Message::Submitted),
                ("Tick", Message::Tick),
                (
                    "Finished(Authenticated)",
                    Message::Finished(Outcome::Authenticated),
                ),
                ("Finished(Rejected)", Message::Finished(Outcome::Rejected)),
                (
                    "Finished(Unavailable)",
                    Message::Finished(Outcome::Unavailable("x".to_string())),
                ),
            ]
        };

        let mut unlocking = Vec::new();
        for state in states {
            for (name, message) in messages() {
                let (mut reveal, _, now) = reveal_with(vec![Outcome::Authenticated]);
                // Drive the machine into `state` without going through the
                // message under test.
                match state {
                    State::Idle => {}
                    State::Revealed => {
                        let _ = reveal.update(Message::Woke, now);
                    }
                    State::Authenticating => {
                        let _ = reveal.update(Message::Woke, now);
                        typed(&mut reveal, now, "hunter2");
                        let _ = reveal.update(Message::Submitted, now);
                    }
                }
                assert_eq!(reveal.state, state, "test setup did not reach {state:?}");

                if matches!(reveal.update(message, now), Effect::Unlock) {
                    unlocking.push(format!("{state:?} + {name}"));
                }
            }
        }

        assert_eq!(
            unlocking,
            vec!["Authenticating + Finished(Authenticated)".to_string()],
            "the set of (state, message) pairs that unlock changed"
        );
    }

    /// The companion to the sweep above: every message, in every state,
    /// leaves the machine in a *valid* state and never panics. Cheap
    /// insurance that a future arm cannot fall through to an `unreachable!`.
    #[test]
    fn no_state_and_message_pair_panics() {
        for start in [State::Idle, State::Revealed, State::Authenticating] {
            for message in [
                Message::Woke,
                Message::Dismissed,
                Message::Changed(Password::new("x".to_string())),
                Message::Submitted,
                Message::Tick,
                Message::Finished(Outcome::Authenticated),
                Message::Finished(Outcome::Rejected),
                Message::Finished(Outcome::Unavailable("x".to_string())),
            ] {
                let (mut reveal, _, now) = reveal_with(vec![Outcome::Rejected]);
                match start {
                    State::Idle => {}
                    State::Revealed => {
                        let _ = reveal.update(Message::Woke, now);
                    }
                    State::Authenticating => {
                        let _ = reveal.update(Message::Woke, now);
                        typed(&mut reveal, now, "x");
                        let _ = reveal.update(Message::Submitted, now);
                    }
                }
                let _ = reveal.update(message, now);
                assert!(matches!(
                    reveal.state,
                    State::Idle | State::Revealed | State::Authenticating
                ));
            }
        }
    }

    // ---- Subscription ----------------------------------------------------

    /// The idle-timeout tick only exists where it can fire: not at rest
    /// (nothing to time out, and an idle lock surface should redraw only on
    /// the clock's minute tick), and not during an attempt (see the
    /// `timeout_does_not_fire_while_authenticating` case for why).
    #[test]
    fn the_timeout_tick_runs_only_while_revealed() {
        let (mut reveal, _, now) = reveal_with(vec![Outcome::Authenticated]);
        assert!(!reveal.ticks(), "Idle should not run the timeout tick");

        let _ = reveal.update(Message::Woke, now);
        assert!(reveal.ticks(), "Revealed should run the timeout tick");

        typed(&mut reveal, now, "hunter2");
        let _ = reveal.update(Message::Submitted, now);
        assert!(
            !reveal.ticks(),
            "Authenticating should not run the timeout tick"
        );
    }

    // ---- Avatar ----------------------------------------------------------
    //
    // The candidate ordering, the initials rules and the
    // configured-path-failed flag are `saola-theme`'s tests now (they were
    // ported from this file along with the code, and
    // `saola_theme::avatar`'s own test module asserts the same cases
    // verbatim). What is still this crate's to prove is the *wiring* of
    // `resolve_avatar_from`: that it passes `$HOME` through, that a bad
    // configured path still falls through rather than failing, and that the
    // initials it lands on are the account's.

    /// §7's last resort, reached through this crate's wrapper: no `$HOME`
    /// and an unreadable configured path leaves an initials disc, not a
    /// panic and not a blank.
    #[test]
    fn a_bad_configured_path_falls_through_to_initials() {
        let configured = PathBuf::from("/nonexistent/avatar.png");
        let avatar = resolve_avatar_from(Some(&configured), "Jordan Dunn", None);
        assert!(matches!(avatar, Avatar::Initials(ref i) if i == "JD"));
    }

    /// `$HOME` reaches the theme's candidate list: a home directory that
    /// does not exist contributes a `~/.face` candidate that fails, and the
    /// resolution still ends on the initials disc rather than erroring.
    #[test]
    fn a_missing_dot_face_still_resolves() {
        let avatar = resolve_avatar_from(None, "jordan", Some(Path::new("/nonexistent-home")));
        assert!(matches!(avatar, Avatar::Initials(ref i) if i == "J"));
    }

    /// A display name with nothing alphanumeric in it still produces a
    /// legible disc rather than an empty one — the case §7 cares about, kept
    /// here because it is the lockscreen's GECOS field that can be blank.
    #[test]
    fn a_blank_display_name_still_produces_a_disc() {
        let avatar = resolve_avatar_from(None, "-- --", None);
        assert!(matches!(avatar, Avatar::Initials(ref i) if i == "?"));
    }

    // ---- Size derivations ------------------------------------------------

    /// The one place this module still computes a size rather than naming a
    /// token: [`field_padding`] exists only to make the field come out
    /// `sizes.field_lock` tall, because iced 0.14's `text_input` has no
    /// `.height`. If that arithmetic drifts, §6's "60–64px on lock/greeter"
    /// silently stops holding — so it is asserted rather than trusted.
    #[test]
    fn the_password_field_is_field_lock_tall() {
        let theme = Theme::saola();
        let padding = field_padding(&theme);
        let line_height = LineHeight::default()
            .to_absolute(theme.typography.size.launcher_input.into())
            .0;

        let height = line_height + padding.top + padding.bottom;
        assert!(
            (height - theme.sizes.field_lock).abs() < 0.01,
            "field is {height}px tall, expected sizes.field_lock ({})",
            theme.sizes.field_lock
        );
    }

    /// The horizontal half of the same padding is §6's content padding,
    /// untouched by the height solve above.
    #[test]
    fn the_password_field_keeps_popover_padding_horizontally() {
        let theme = Theme::saola();
        let padding = field_padding(&theme);

        assert_eq!(padding.left, theme.sizes.popover_padding);
        assert_eq!(padding.right, theme.sizes.popover_padding);
    }

    // ---- Message hygiene -------------------------------------------------

    /// The password must not reach a log through `Debug` — `main.rs`'s
    /// `Message` derives it, and iced formats messages in its own tracing.
    #[test]
    fn message_debug_redacts_the_password() {
        let message = Message::Changed(Password::new("hunter2".to_string()));
        let rendered = format!("{message:?}");
        assert_eq!(rendered, "Changed(<redacted>)");
        assert!(!rendered.contains("hunter2"));
    }

    /// Error copy is user-facing text on the lock surface; the `Finished`
    /// message that carries it is safe to print, and this pins that it does
    /// not accidentally gain a secret later.
    #[test]
    fn message_debug_shows_outcomes() {
        assert_eq!(
            format!("{:?}", Message::Finished(Outcome::Authenticated)),
            "Finished(Authenticated)"
        );
    }
}
