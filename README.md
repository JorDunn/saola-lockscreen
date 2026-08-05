# saola-lockscreen

The session locker for **Saola**, a Linux desktop environment written in Rust,
targeting the **niri** Wayland compositor via `ext-session-lock-v1`. Themed entirely
from [saola-theme](https://github.com/JorDunn/saola-theme) — the one place the Saola
look is defined; this crate hardcodes no color or size of its own. Closest sibling:
[saola-panel](https://github.com/JorDunn/saola-panel), the status bar, whose
conventions (module pattern, repo layout, PLAN.md-driven history) this crate copies.

Style guide §7 "Lock surface", the binding spec: wallpaper ground; clock, date, and
temperature centred; nothing else at rest. Click or any key reveals an avatar, the
user's display name, and a password field. Authentication is PAM, run on a blocking
thread so the UI never stalls.

<!-- screenshot: at rest — cover-fit wallpaper, centred serif clock (168px) and date,
     an optional "NN°" temperature line below, nothing else on screen -->

<!-- screenshot: revealed — the §2 dimming scrim over the wallpaper, avatar (photo or
     initials disc) → display name → password field pill, styled like the rosec
     prompt's input -->

## Running it

```bash
cargo build
cargo test
cargo run
```

`cargo run` opens a **real** `ext-session-lock-v1` surface and locks whatever session
it runs in. Do not run it directly against your real session unless you have already
confirmed a working PAM policy (see [PAM setup](#pam-setup) below) and are prepared to
recover via VT switch if something goes wrong. All development and testing happens
inside a **nested niri instance** instead — see `CLAUDE.md`'s "nested-niri testing
rule" for the exact procedure (spawn a throwaway windowed niri, run against its
`WAYLAND_DISPLAY`, never the outer session's).

### The `dev-unlock` feature — and its danger

```bash
cargo run --features dev-unlock
```

Inside a nested niri instance, this adds an Escape-to-unlock path with **no password
check at all** — the only way to get out of a locked nested compositor before a real
PAM round-trip is wired up. It is gated so it cannot reach a release build: `Cargo.toml`
never lists it in `default-features`, and `src/main.rs` carries a
`#[cfg(all(feature = "dev-unlock", not(debug_assertions)))] compile_error!(..)` guard
that hard-fails `cargo build --release --features dev-unlock` at compile time (Stage 6's
review, finding M-1) while leaving `cargo run`/`cargo test --features dev-unlock` (the
`dev` profile, used by the nested-niri workflow) untouched. **Never build or package this
crate with `dev-unlock` enabled for anything other than nested-compositor testing** — if
you're writing a PKGBUILD or any other release packaging, do not pass this feature; the
compile-time guard is the backstop, not the primary control.

### Installing on Arch

Not packaged yet — no `PKGBUILD` exists in this repo (unlike `saola-panel`'s
`contrib/aur/`). Until then, `cargo build --release` and run the resulting binary
directly, after completing [PAM setup](#pam-setup) below.

### Build dependencies

- **System PAM headers** (`pam-sys2`, via `pam-client2`) — needed at build time to link
  against `libpam`. Present on Jordan's machine; flag it if a future build host lacks
  them.
- No niri-specific build dependency: `iced_sessionlock`/`sessionlockev` speak the
  `ext-session-lock-v1` Wayland protocol directly, so this crate builds without niri
  installed. It just won't have anything to lock.

## PAM setup

`saola-lockscreen` authenticates against the PAM service `saola-lockscreen`
(`src/auth.rs`'s `SERVICE` constant → `/etc/pam.d/saola-lockscreen`). Install the real
policy from this repo (root required — this command is for you to run, this repo never
runs `sudo` itself):

```bash
sudo install -Dm644 contrib/pam/saola-lockscreen /etc/pam.d/saola-lockscreen
```

**If you previously ran an interim command from an earlier draft of this project's
setup instructions** (`printf 'auth include system-auth\n' | sudo tee
/etc/pam.d/saola-lockscreen`) — **replace it with the command above.** That interim
form has no `account` stack, which makes PAM's account check fail even for a correct
password and shows "Wrong password." forever (Stage 6's security review, finding H-2,
has the full trace). See `contrib/pam/saola-lockscreen`'s own comments for exactly why
each line is there, including the rosec `pam_exec` line's source.

`contrib/session/README.md` covers the rest of the session wiring this crate needs but
does not install itself: locking before suspend, locking on idle, and a manual lock
keybind — all `contrib/` scaffolding for a future `saola-session` package, per
Architecture's design (this crate stays focused on the lock surface itself).

## Configuring it

`~/.config/saola/lockscreen.kdl`, entirely optional — every knob has a built-in
default, and the file is read once at startup (no live reload; a locker's whole job is
coming up correctly and staying that way, not watching a config file mid-lock). The
directory resolves most-specific-first, the same chain `saola-panel`'s `panel.kdl`
uses minus its `--config-dir` flag (a locker takes no CLI arguments — niri hands it no
terminal to read flags from):

1. `$SAOLA_CONFIG_DIR` — the Saola desktop's own variable
2. `$XDG_CONFIG_HOME/saola` (the XDG base-directory spec)
3. `~/.config/saola` (the spec's own fallback for an unset `$XDG_CONFIG_HOME`)

An env var set to the empty string counts as unset, per the XDG spec's own rule.

```kdl
lockscreen {
    wallpaper "~/Pictures/wallpaper.png"
    latitude 51.5074
    longitude -0.1278
    avatar "~/Pictures/me.png"
}
```

| Knob | Default | Notes |
|---|---|---|
| `wallpaper "path"` | none — ink | §7's wallpaper ground, cover-fit. Falls back to the theme's ink surface on any unset/unreadable/undecodable path — never an error state. `~/`-prefixed paths expand against `$HOME`. |
| `latitude` / `longitude` | none | Feeds the Open-Meteo outdoor-temperature fetch (see [Privacy](#privacy--known-limitations) below). Both must be set together — a lone one is treated as neither. Either a KDL integer or a float. |
| `avatar "path"` | none | Overrides the reveal flow's avatar. Falls back to `~/.face`, then an initials disc built from your account's GECOS display name (or login name if GECOS is empty). `~/`-prefixed paths expand against `$HOME`. |

The resilience contract (this crate is stricter than the panel's here — a lockscreen
bug risks locking you out, not just a cosmetic bar glitch):

| Situation | Result |
|---|---|
| No `lockscreen.kdl` at all | Built-in defaults, silent |
| File present, not valid KDL at all | One `eprintln!` naming the file + the parse error, then the **whole file** falls back to defaults |
| One knob's value is nonsense (a `latitude` that isn't a number, say) | A warning naming that knob; **only that field** defaults, the rest of the document still applies |

## Behaviour notes

- **Empty password submissions never reach PAM.** Pressing Enter on an empty field is
  a no-op rather than an authentication attempt — a deliberate deviation from the
  Architecture state-machine diagram, to protect the `pam_faillock` budget (an accidental
  Enter should not spend a third of a stock `deny=3` policy on a guess that cannot
  succeed). The one edge this creates: an account configured with PAM's `nullok` (an
  empty password accepted) cannot unlock through this guard. Vanishingly unlikely in
  practice, and considered an acceptable trade (Stage 6's review, finding L-2).
- **The idle-timeout and Escape both return to the at-rest clock**, clearing the typed
  password and any error copy, after 30 seconds of no input on a revealed prompt.
- **A failed attempt shows accent-light error copy** (never any part of the password —
  every error string is a fixed template plus a bare PAM error-code name) and clears the
  field, per §7.

## Privacy & known limitations

- **The Open-Meteo fetch is a heartbeat, not just a one-off lookup.** Whenever
  `latitude`/`longitude` are configured, this crate makes a plaintext-DNS/TLS-SNI HTTPS
  GET to `api.open-meteo.com` at startup and every 15 minutes **for as long as the
  screen stays locked** — which publishes the configured coordinates (usually your home)
  and an "this machine is awake and locked" liveness signal to that endpoint, plus the
  hostname to anyone passively watching the local network. This is exactly what
  Architecture asked for (outdoor temperature, no API key), not a bug — just worth
  knowing before setting `latitude`/`longitude` to real coordinates.
- **`webpki-roots` bakes its CA set into the binary** rather than reading the system
  trust store. Fine for one unauthenticated weather GET; a CA distrust only reaches this
  binary on a dependency bump, not immediately.
- **IME is unavailable on the lock surface.** The password field is marked
  `input_method::Purpose::Secure`, but the underlying Wayland shell binding
  (`sessionlockev`) does not implement `text-input-v3`, so a user who needs an input
  method to type their password cannot use one here. A real constraint if this crate is
  ever used by someone other than Jordan.
- **This crate cannot confirm a lock actually succeeded.** The `ext_session_lock_v1`
  protocol's `locked`/`finished` events are discarded by the Wayland shell binding this
  crate uses (`sessionlockev`), so nothing here — nor anything watching this process —
  can distinguish "the compositor hid the desktop" from "the lock request is still
  pending" or "the lock was denied". `contrib/session/`'s before-sleep wiring documents
  its own coarse workaround (process liveness after a grace period) and its limits; see
  that directory's `README.md`.

## Design language (binding)

The lock surface is a **shell surface: always ink** — the same rule the panel's bar
follows, never toggled to paper. Every color and size comes from
[saola-theme](https://github.com/JorDunn/saola-theme)'s tokens; the code hardcodes
none. See [`docs/`](docs/) and this repo's `CLAUDE.md` for the binding style-guide
references (§1 palette, §3 typography, §6 shape, §7 the lock surface itself) and the
handful of style helpers composed locally from tokens because `saola-theme` v0.5.0
doesn't yet expose them upstream (a subtle-fill text input variant, a pill-radius disc
container, the awake scrim) — flagged in `src/modules/reveal.rs`'s doc comment as
`saola-theme` candidates, not permanent local forks.

## Docs

[`docs/REVIEW-v0.1.md`](docs/REVIEW-v0.1.md) is Stage 6's adversarial security review
of the whole crate — read it for the full trace behind every "Stage 6/7" reference
above, including what was checked and found clean, not just the findings that needed
fixing.

## Credits

- [saola-theme](https://github.com/JorDunn/saola-theme) — the design system this crate
  is themed from entirely; every color, size, and typography choice on screen traces
  back to it.
- [saola-panel](https://github.com/JorDunn/saola-panel) — the status bar this crate's
  repo layout, module pattern, and PLAN.md-driven build history are copied from.

## Contributing

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this work by you, as defined in the Apache-2.0 license, shall be dual
licensed as below, without any additional terms or conditions.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
