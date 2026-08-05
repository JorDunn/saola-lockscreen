# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing has been tagged yet — `Cargo.toml` stays at `0.1.0-dev` until real-session
testing (see `docs/REVIEW-v0.1.md` and this stage's handoff) confirms a working PAM
round-trip. This entry covers Stage 6's security review and Stage 7's response to it;
earlier stages (crate skeleton through the temperature module) are not re-itemized here
since nothing shipped as a release before this point.

### Security

- Moved the wallpaper decode (a filesystem read plus a full image decode, up to tens of
  MiB for a real wallpaper) off `Lockscreen::boot`'s synchronous path. `boot()` runs
  *before* `iced_sessionlock` asks the compositor to lock, so that decode used to keep
  the real desktop fully visible and interactive for its entire duration — a real
  suspend-race exposure window for a fire-and-forget before-sleep hook, not just a slow
  lock surface. The decode is now an async `Task`; `boot()` starts with the ink fallback
  and fills the wallpaper in once it resolves. (`docs/REVIEW-v0.1.md` H-1)
- Shipped the real PAM policy at `contrib/pam/saola-lockscreen`, including an `account`
  stack. An earlier interim command (`auth include system-auth` only, printed by an
  earlier stage's handoff) left PAM's `account` phase with no handlers at all, which
  makes `pam_acct_mgmt()` fail for every attempt — including a correct password — and
  reports it as "Wrong password." while still spending the `pam_faillock` budget.
  **That command was never run** (verified: `/etc/pam.d/saola-lockscreen` did not exist
  on the reference machine) — this entry retracts it; only the file in this repo should
  ever be installed. (`docs/REVIEW-v0.1.md` H-2)
- Added a `compile_error!` guard (`src/main.rs`) that hard-fails
  `cargo build --release --features dev-unlock` — the `dev-unlock` feature adds a
  password-free Escape-to-unlock path for nested-compositor testing, and nothing
  previously stopped it from reaching a release build beyond a documentation rule. The
  guard is scoped to `not(debug_assertions)`, so `cargo run`/`cargo test
  --features dev-unlock` (the actual nested-niri testing workflow) are unaffected.
  (`docs/REVIEW-v0.1.md` M-1)
- An `acct_mgmt` (PAM account-phase) failure is no longer reported with the same
  "Wrong password." copy as a rejected credential — the account phase never sees a
  password, so a denial there (H-2's empty-stack bug, or any future account-phase
  module) now gets its own, honest error message instead of masquerading as a wrong
  guess. (`docs/REVIEW-v0.1.md` M-4, fixed alongside H-2)

### Added

- `contrib/pam/saola-lockscreen` — the PAM service file this crate authenticates
  against, including the rosec vault auto-unlock line (the `pam_exec` fallback form,
  since a locker only runs PAM's `auth` phase — see that file's comments for the exact
  source read for this).
- `contrib/session/` — niri session wiring: a lock-before-sleep watcher
  (`systemd-inhibit --what=sleep --mode=delay`, as a `systemd --user` unit), a suggested
  `swayidle` idle-lock snippet, and a manual `Mod+Escape` lock keybind. Scaffolding for
  the future `saola-session` package, per Architecture — nothing here installs itself.
- `README.md` — what this crate is, how to build/run/configure it, the `dev-unlock`
  feature's danger, the `lockscreen.kdl` schema, and a privacy/known-limitations section
  (the Open-Meteo fetch's coordinate + liveness disclosure, `webpki-roots`' baked-in CA
  set, no IME on the lock surface, and this crate's inability to confirm a lock actually
  succeeded).
- `docs/REVIEW-v0.1.md` — Stage 6's adversarial security review of the whole crate.

### Deferred (documented, not fixed, for v0.1)

Ranked won't-block by `docs/REVIEW-v0.1.md`; each needs a narrower trigger than the
items above, or is a documentation-only fix. Full detail and fix sketches are in that
report.

- **M-2 — multi-output password-field desync.** Every output's password field shares
  one widget id (by design, so a focus operation reaches whichever output the
  compositor sends keys to), but each output keeps its own text-cursor state, which can
  desynchronize once a user types across two outputs mid-session. Not reachable on a
  single-output machine (the only configuration this has ever run on); must be fixed
  and live-tested before a second monitor is ever attached.
- **M-3 — `Authenticating` has no timeout.** A PAM module that never returns (a network
  module against an unreachable directory, say) strands the surface with no cancel and
  no way back — deliberate today (no cancellation point exists for a blocking PAM call
  mid-flight, and a naive cancel-to-`Idle` would risk a spurious unlock from a late
  result), but this crate's current PAM stack is entirely local, so the failure mode is
  not reachable yet. Needs a bounded stopwatch + an abandon-to-`Revealed` path (not
  `Idle`) before this crate's PAM policy ever grows a network-backed module.
- **L-1 — an incomplete doc claim.** `main.rs`'s comments said `Message::UnLock`
  interception was the *only* way `iced_sessionlock` unlocks; the review found a second,
  currently-unreachable route (`iced::window::close`/`iced::exit`, via
  `WindowAction::Close`) that the doc comments and the crate's own unlock-audit grep
  list didn't mention. Corrected in the source comments; no behavior changed.
- **L-2 — empty submissions never reach PAM.** Documented as a deliberate trade (protects
  the `pam_faillock` budget from an accidental empty Enter) in this release's `README.md`
  now, including the one edge it creates: an account using PAM's `nullok` (empty password
  accepted) cannot unlock through this guard.
- **L-3 — no lock-confirmation signal.** `ext_session_lock_v1`'s `locked`/`finished`
  events are discarded by the Wayland shell binding this crate uses, so nothing in this
  crate (or watching it) can confirm a lock actually took effect. Documented in
  `README.md`'s known-limitations section and accounted for in `contrib/session/`'s
  before-sleep wiring, which uses a coarse process-liveness proxy instead.
- **L-4 — no minimum-size handling for the revealed stack.** On a very short logical
  output the password field could lay out off-screen with no scroll or shrink behavior.
  Not reproduced on Jordan's display; needs a deliberately small nested-niri output to
  verify a fix against, not just reasoning about it.
