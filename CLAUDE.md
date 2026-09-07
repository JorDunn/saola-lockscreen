# saola-lockscreen — agent instructions

Session locker for Saola, a Linux desktop environment built in Rust. Closest sibling and
convention source: [saola-panel](https://github.com/JorDunn/saola-panel) (the status
bar) — this file is derived from its `CLAUDE.md`. Themed from
[saola-theme](https://github.com/JorDunn/saola-theme). Target compositor: **niri**
(`ext-session-lock-v1`). Stack: stable iced 0.14 + `iced_sessionlock` 0.19.1 (the
waycrate sibling of the panel's `iced_layershell`), PAM via `pam-client2`.

The design source of truth is `~/Developer/saola-theme/design/SAOLA-STYLE-GUIDE.md`,
§7 "Lock surface" especially — wallpaper ground; clock, date, temperature centred;
nothing else at rest; click reveals avatar → name → password. Full context and the
decisions behind this crate live in this repo's `PLAN.md` — its **Architecture** section
is binding and every stage subagent must read it before making changes; this file is
the second required read.

## Commands

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings                    # CI gate — keep it green
cargo clippy --all-targets --features dev-unlock -- -D warnings  # same, dev-unlock cfg branch
cargo fmt --check                                             # CI gate
cargo run                                    # opens a real ext-session-lock-v1 surface — see
                                              # the nested-niri testing rule below before running this
cargo run --features dev-unlock              # nested-niri testing only — see below
```

Both feature configurations are separate compiles (the `dev-unlock` cfg branches — see the
unlock-edge rule below — mean `cargo clippy` alone does not check that code at all); run both
before considering a change to `main.rs`'s cfg-gated code done.

## Architecture

Single binary crate (an app, not a library — no workspace), mirroring saola-panel's
layout:

```
src/
├── main.rs                 # SessionLock app: state machine, update/view wiring
├── config.rs                # lockscreen.kdl: wallpaper, lat/lon, avatar override
├── auth.rs                  # Authenticator trait + PAM impl (a future greeter reuses this)
└── modules/
    ├── mod.rs
    ├── clock.rs              # Stage 3 — centred clock/date, panel's module pattern
    ├── temperature.rs        # Stage 5 — Open-Meteo, hidden on failure
    └── reveal.rs             # Stage 4 — avatar → name → password flow
```

### State machine (the security core — binding)

```
Idle ──click/keypress──▶ Revealed ──Enter──▶ Authenticating ──PAM ok──▶ Unlock
  ▲                        │  ▲                    │
  └────Escape/timeout──────┘  └──── PAM fail ──────┘  (error copy, field cleared)
```

- PAM conversation runs on a blocking thread (`spawn_blocking`); the UI thread never
  blocks. While `Authenticating`, the password field is disabled — no second submission.
- Password buffers are `zeroize`d immediately after the conversation consumes them.
- No `panic!`/`unwrap`/`expect` on any runtime path (clippy-enforced at Stage 6's
  review): errors surface as §1-compliant error copy (accent-light `#F6A06B` on ink) and
  reset the machine to `Revealed`. A locker's two failure modes, in order of severity,
  are "session exposed" and "user locked out" — niri's own failure mode (a crashed
  locker keeps the session locked, recoverable via VT switch) is the safety net this
  crate must not compromise.

### The unlock-edge rule (binding, security-critical)

**The only call site of the sessionlock unlock action is the `PAM ok` edge.** No other
code path may invoke it. The sole exception is the `dev-unlock` cargo feature (declared
in `Cargo.toml`, **never in `default-features`, never enabled in a release build**),
which may add an Escape-to-unlock path for nested-compositor testing. When used, the
feature gate (`#[cfg(feature = "dev-unlock")]`) must wrap the **entire** unlock edge —
the call itself, not just the keybind that reaches it — so a stray refactor can't leave
a dev-only path reachable without the cfg. Stage 6's review enumerates every path to the
unlock call as its first audit item; anything beyond PAM-ok and this cfg edge is a
finding.

### §7 Lock surface (binding for UI stages)

Wallpaper ground (config path, cover-fit; ink fallback `#0C0A00`). Centred stack: clock
(§3: large, tabular numerals), date, temperature — nothing else at rest. Click or any
key reveals: avatar (config override, else `~/.face`, else an initials disc), user's
display name (GECOS), password field styled like the rosec prompt's input (§6 pill,
subtle-fill `#FFFFF012`, primary-ivory text). Failed attempt: accent-light error copy,
field cleared, machine back to `Revealed`.

## Design language (binding — the theme crate is the authority)

- The lock surface is a **shell surface: always ink** (`Surface::Ink`), same rule as the
  panel's bar.
- **Zero hardcoded colors or sizes.** Every value comes from `saola_theme::tokens` and
  every widget style from `saola_theme::style` helpers. If a needed style doesn't exist,
  add it to saola-theme (its own `CLAUDE.md` governs that repo) — don't restyle locally.
- Jordan is newer to Rust: comment the non-obvious (async ownership, PAM conversation
  plumbing, sessionlock surface setup) as teaching notes; prefer explicit code over
  clever abstraction.
- Out of scope for this crate: the greeter (§7 "Greeter = Lock plus user/session
  lists" — a future binary that reuses `auth.rs`/`modules::reveal`) and session wiring
  beyond `contrib/` files (`saola-session` — a real sibling repo since 2026-08 — owns
  idle/before-sleep as a component and depends on this package; this repo's
  `contrib/session/` files remain only as the standalone fallback, see their README).

## The sudo rule (binding)

**No stage or agent working in this repo ever runs `sudo`, or any command that needs
root.** System-level files (the PAM service stack, idle/session wiring) are written
under `contrib/` in this repo and never installed directly. When such a file is ready,
print the exact `install`/`cp` command for Jordan to run and verify himself — e.g.:

```bash
sudo install -Dm644 contrib/pam/saola-lockscreen /etc/pam.d/saola-lockscreen
```

Never guess at a root-owned file's contents either — where PAM/rosec wiring is
involved, the relevant docs are read first (see Stage 7 in `PLAN.md`) and the file is
built from them, not assumed.

## The nested-niri testing rule (binding)

This crate's whole job is taking over the session's input and output. **Live testing
happens only inside a nested niri instance** — niri running windowed inside the current
session, so a bug locks a throwaway compositor, not Jordan's real one.

**Do not pass `--session`.** niri's own `--help` says that flag is for "a systemd
service started by your display manager, or when running manually as your main
compositor instance" and explicitly "do not set when running as a nested window" — it
imports the environment globally to systemd/D-Bus, which is the opposite of throwaway.
Left off, bare `niri` auto-detects an existing `WAYLAND_DISPLAY`/`DISPLAY` and starts
windowed (the `winit` backend) with no further flags needed. Verified in Stage 2 (both
against `cargo run --features dev-unlock` and the built binary directly).

Procedure:

```bash
# 1. Spawn a nested niri, windowed, with a throwaway config so it doesn't run
#    Jordan's real autostart commands twice. An empty file is a valid config
#    (every setting has a default).
touch /tmp/nested-niri.kdl
niri -c /tmp/nested-niri.kdl &

# Its own stdout/stderr (not the log file below) prints the two lines that matter:
#   listening on Wayland socket: wayland-N
#   IPC listening on: /run/user/<uid>/niri.wayland-N.<pid>.sock

# 2. GOTCHA: your shell already has NIRI_SOCKET set, pointing at the *real*,
#    outer niri (from Jordan's actual session) — `niri msg` silently talks to
#    that one, not the nested instance, unless you override it. Always pass
#    the nested socket explicitly:
export NESTED=/run/user/<uid>/niri.wayland-N.<pid>.sock
NIRI_SOCKET=$NESTED niri msg outputs   # confirm the nested output's name/scale

# 3. Jordan's laptop panel is 1.5-scale; the nested `winit` output defaults to
#    1 and won't exercise that path on its own. Force it:
NIRI_SOCKET=$NESTED niri msg output winit scale 1.5

# 4. Run the locker against the nested display only — never the real one:
WAYLAND_DISPLAY=wayland-N cargo run --features dev-unlock

# 5. Press Escape *inside the nested niri window* (click into it first so it
#    has real keyboard focus on the outer compositor) to unlock and exit.

# 6. Tear down the nested compositor:
kill %1   # or: pkill -f 'niri -c /tmp/nested-niri.kdl'
```

- There is no `niri msg` query for "is the session locked" — `ext-session-lock-v1` is
  its own protocol, separate from both layer-shell and xdg-toplevel, so locked surfaces
  never show up in `niri msg layers` or `niri msg windows`. The reliable signal is
  niri's own log line: `locking session` on lock, `unlocking session` on a clean unlock,
  or `locking session (replacing existing dead lock)` if the previous lock client died
  without unlocking (niri's safety net — see Architecture: this is expected and correct
  behavior for a crashed/killed locker, not a bug).
- `cargo run` with `dev-unlock` is the only way to get out of a nested lock without a
  real PAM round-trip; without the feature there is deliberately no unlock path before
  Stage 4.
- **Never lock the real session** to test this crate. Real-session testing happens only
  after Stage 6's security review, from a terminal Jordan drives himself, and only with
  the real PAM stack in place (Stage 7).
- Stage 2 ran this exact procedure end to end (lock, forced 1.5 scale, Escape via an
  injected key event, clean unlock) — see its handoff for the results.

## Conventions

- The `saola-theme` dependency is pinned to a release tag (currently
  `tag = "saola-theme-v0.15.0"`, with a matching `version`). Bumping it is a deliberate,
  reviewed change — never switch to `branch = "main"`. The lock-surface helpers and size
  tokens that were ported upstream *from this crate* (`avatar::{Avatar, view}`,
  `container::disc`/`scrim`, `text_input::prompt`, plus
  `sizes.avatar_lock`/`field_lock`/`lock_stack_gap`) arrived at v0.13.0/v0.14.0; v0.15.0
  is additive only (`avatar::placeholder`, `sizes.avatar_glyph`, for the greeter), and
  this crate does not use the new API. saola-panel still pins v0.5.0 as of 2026-09-06,
  so the two apps no longer read one token set until the panel bumps.
- **PAM crate: `pam-client2`.** Survey (2026-08-02) of the three live options on
  crates.io:
  - `pam` (1wilkens/pam, MIT/Apache dual license) — last published 2023-11-01.
  - `pam-client` (cg909/rust-pam-client, MPL-2.0) — last published 2022-07-30; the
    original this crate below forks.
  - `pam-client2` (LeChatP/rust-pam-client, MPL-2.0) — last published 2026-03-27, an
    actively maintained fork fixing bugs the original never addressed.
  Chosen for that activity, plus the richest API of the three: `Context::new(service,
  user, conversation)` drives `authenticate()` / `acct_mgmt()` / `open_session()`
  against a user-implemented `ConversationHandler` trait (`prompt_echo_on`,
  `prompt_echo_off`, `text_info`, `error_msg`, `radio_prompt`, `binary_prompt`) — exactly
  the shape `auth.rs` needs to feed the reveal flow's password buffer to PAM without a
  terminal. Built with `default-features = false` (drops the `cli` feature's `rpassword`
  dependency, which is for a TTY conversation handler this crate never uses). MPL-2.0 is
  file-level copyleft — it does not reach into a crate that merely depends on it, so it's
  compatible with this repo staying `MIT OR Apache-2.0`. Requires the system's PAM
  headers at build time via its `pam-sys2` dependency (present on Jordan's machine;
  flag if a future build host lacks `libpam`'s dev headers).
- **HTTP crate (Stage 5's Open-Meteo fetch): `ureq`.** Survey (2026-08-02) of the
  lightweight options, per the panel's avoid-heavyweight-deps rule:
  - `reqwest` — the default choice for most apps, but pulls hyper + h2 + tower's
    service traits and wants a full-featured tokio (`net`, `time`, `rt-multi-thread`,
    …); this crate's tokio dependency is `rt` + `sync` only, for exactly the PAM
    `spawn_blocking` case (see the `tokio` line in `Cargo.toml`). Feature unification
    would silently grow that surface for one small periodic GET.
  - `minreq` — smaller API, but its `https` feature resolves to rustls with the
    `aws-lc-rs` crypto provider, which pulls `aws-lc-sys` and needs `cmake` (and a
    C/C++ toolchain) at build time — the same "extra system build tool" shape as
    `pam-sys2` needing PAM headers, just for a feature this crate does not need a
    second time.
  - `ureq` (algesten/ureq) — chosen. **Blocking, not async**: exactly the shape
    `auth.rs` already established for PAM (a blocking call dispatched onto
    `tokio::task::spawn_blocking`), so `modules/temperature.rs`'s fetch reuses that
    one pattern instead of introducing a second concurrency model. Default features
    resolve rustls with the `ring` crypto provider (pure Rust, no `cmake`/C toolchain,
    unlike `aws-lc-rs`) and `webpki-roots` for certificate validation (no system CA
    store dependency). Actively maintained (3.x, 2026).
  Response parsing uses `serde_json::Value` with manual `.get(...)` field lookups
  (see `modules/temperature.rs`'s `parse_temperature`) rather than a
  `#[derive(serde::Deserialize)]` struct — the same "walk the parsed document by
  hand" choice `config.rs` makes for KDL, and it avoids a second direct dependency
  (`serde` itself, for the derive macro) for a two-field response shape.
  `cargo tree -e normal` (the activated dependency graph, verified 2026-08-02): 15
  real new crates beyond what was already in the tree (`ureq`, `ureq-proto`,
  `rustls`, `rustls-webpki`, `rustls-pki-types`, `ring`, `webpki-roots`, `http`,
  `httparse`, `getrandom`, `subtle`, `untrusted`, `utf8-zero`, plus `serde_json`
  itself pulling in only `zmij` new). `Cargo.lock` additionally *pins* versions for
  several of `ureq`'s other optional-feature dependencies this crate does not enable
  (`cookie_store`, `url`/`idna`, `time`, …) — normal Cargo behaviour for every
  optional dependency a crate declares, not something this crate actually compiles
  or links.
- Copy the established module pattern for new modules (read an existing one, or the
  panel's, first): a state struct, `view(&Theme) -> Element`, and a `subscription()`
  where the module needs to tick.
- No `panic!`/`unwrap`/`expect` on any runtime path — see the state-machine section
  above. This is stricter than the panel's rule because a lockscreen bug risks locking
  Jordan out, not just a cosmetic bar glitch.

## Releases

`release-plz.toml` + `CHANGELOG.md` landed in Stage 7 (mirroring the panel's setup);
`.github/workflows/ci.yml` and `release-plz.yml` are wired in (post-Stage 7). CI runs
clippy/test as a **two-entry feature matrix** (plain and `dev-unlock` — see the
commands section: they are separate compiles) plus a `release-guard` job asserting
`cargo check --release --features dev-unlock` fails at the M-1 `compile_error!` guard.
If release-guard goes red, someone loosened the cfg on the guard — that is a security
finding (the unlock-edge rule), not a build problem to fix by deleting the job.
`pkgbuild-release.yml` + `contrib/aur/PKGBUILD` (copied from the siblings' setup)
attach a filled-in Arch PKGBUILD to each GitHub release; the package installs the
binary, the PAM policy (`backup=`-protected), and licenses — saola-session's PKGBUILD
depends on this package. Both release-plz jobs carry saola-session's prerelease gate:
they no-op while `Cargo.toml`'s version has a `-dev` suffix and wake up when it comes
off — so tagging `0.1.0` is done by pushing the version change to `main`, and remains
Jordan's call. Real-session testing (lock, suspend/resume via saola-session, PAM
unlock, 20 s idle timeout twice) passed 2026-08-05.
