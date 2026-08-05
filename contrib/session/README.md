# contrib/session — niri wiring for saola-lockscreen

This directory is **files and docs only** — nothing here is installed
automatically, and nothing in this repo ever runs `sudo` or any other
root-requiring command (this repo's `CLAUDE.md`, "the sudo rule"). Every
command below is for Jordan to run and verify himself.

**Superseded for idle/before-sleep wiring:** `saola-session` exists now
(github.com/JorDunn/saola-session — the component PLAN.md's Architecture
section anticipated) and owns idle-timeout and before-sleep locking as a real
daemon; its package even lists this crate as a dependency. Sections 2 and 3
below are kept as the standalone fallback for a machine running this locker
*without* saola-session — if you run saola-session, skip them (and don't wire
both: two before-sleep paths racing to spawn the same locker is the exact
confusion §3's own note warns about). Section 1 (the PAM policy) and §4 (the
manual keybind) are not superseded and still apply either way — though the
Arch package built from `contrib/aur/PKGBUILD` installs §1's file for you.

## 1. The PAM policy (needs root)

**Retraction first.** Stage 4's handoff printed this command for Jordan to
run:

```bash
printf 'auth include system-auth\n' | sudo tee /etc/pam.d/saola-lockscreen
```

**Do not run that command.** Stage 6's security review (`docs/REVIEW-v0.1.md`,
finding H-2) found it cannot ever unlock the screen: `saola-lockscreen`'s
`auth.rs` calls both `pam_authenticate()` and `pam_acct_mgmt()`, and an
`auth`-only service file leaves the `account` stack empty, which makes
`pam_acct_mgmt()` fail even for a correct password — and the surface would
have shown "Wrong password." for it, indefinitely, while still spending the
`pam_faillock` budget on the `auth` phase's own bookkeeping. Verified before
writing this: `ls /etc/pam.d/saola-lockscreen` still reports *No such file or
directory* on this machine, so nothing has actually broken yet — Jordan
never ran the old command. Simply don't.

The real file lives at `contrib/pam/saola-lockscreen` in this repo (see that
file's own comments for the full H-2 trace and the rosec `pam_exec` line's
source). Install it with:

```bash
sudo install -Dm644 contrib/pam/saola-lockscreen /etc/pam.d/saola-lockscreen
```

Verify it landed correctly:

```bash
cat /etc/pam.d/saola-lockscreen
# Expect: auth include system-auth / account include system-auth / the
# rosec pam_exec line — three non-comment lines, no `session` or
# `password` stack (a locker never runs either phase).
```

Then follow this stage's handoff for the recommended nested-niri real-PAM
test sequence **before** ever locking a real session.

## 2. Lock before sleep (no root — a user-level systemd unit)

`contrib/session/saola-lock-before-sleep` (script) and
`saola-lock-before-sleep.service` (a `systemd --user` unit) hold a
`systemd-inhibit --what=sleep --mode=delay` lock across every suspend, so a
lid-close or `systemctl suspend` cannot complete until `saola-lockscreen` has
at least had a chance to start and ask the compositor to lock — see the
script's own header comment for the full reasoning, the H-1 review finding
it closes, and — importantly — what it **cannot** guarantee (there is no way
for this crate to confirm the lock actually succeeded; see finding L-3).

Install (all user-level; no `sudo` needed for any of this):

```bash
install -Dm755 contrib/session/saola-lock-before-sleep ~/.local/bin/saola-lock-before-sleep
install -Dm644 contrib/session/saola-lock-before-sleep.service ~/.config/systemd/user/saola-lock-before-sleep.service
systemctl --user daemon-reload
systemctl --user enable --now saola-lock-before-sleep
```

Verify it's running and holding the inhibitor correctly:

```bash
systemctl --user status saola-lock-before-sleep
systemd-inhibit --list   # should show a `sleep`/`delay` entry "who: saola-lockscreen"
```

The one manual test that actually proves this works end to end is a real
suspend/resume cycle (`systemctl suspend`, or closing the lid) with a
correctly-installed PAM policy (step 1) already in place — see this stage's
handoff for the recommended order.

## 3. Idle lock (fallback only — saola-session owns this now)

Skip this section if you run `saola-session` (see the note at the top): it
speaks `ext-idle-notify-v1` itself and spawns this locker on idle timeout,
with no external idle daemon at all. For a standalone setup without it,
`swayidle` is the recommended choice — it speaks the same `ext-idle-notify-v1`
Wayland protocol niri implements, the same protocol family this crate's own
sibling tools already assume (niri's own default config ships a suggested
`swaylock` bind in the same spirit — see `/usr/share/doc/niri/default-config.kdl`).

Install it yourself (root, not run here):

```bash
sudo pacman -S swayidle
```

Then add a `spawn-at-startup` line to `~/.config/niri/config.kdl` (the same
mechanism this machine already uses for `saola-panel` and `swaybg` — see
that file's existing `spawn-at-startup` lines):

```kdl
spawn-at-startup "swayidle" "-w" "timeout" "300" "saola-lockscreen"
```

`-w` makes `swayidle` wait for `saola-lockscreen` to be spawned before
considering the timeout handled (rather than firing it again immediately);
`300` is five minutes — adjust to taste. Deliberately **not** wiring
`swayidle`'s own `before-sleep` hook here: `saola-lock-before-sleep.service`
(section 2) already owns the suspend case with `systemd-inhibit`'s stronger
delay semantics, and adding a second before-sleep path would just be two
codepaths racing to spawn the same process (harmless — `saola-lockscreen`
would simply already be running — but confusing to debug later).

## 4. Manual lock keybind

Add to `~/.config/niri/config.kdl`'s `binds { }` block:

```kdl
Mod+Escape hotkey-overlay-title="Lock the Screen: saola-lockscreen" { spawn "saola-lockscreen"; }
```

This is unrelated to the crate's own `dev-unlock` feature's Escape handling
(that Escape is read *inside* the locked surface, by `saola-lockscreen`
itself, only in nested-niri dev builds — see the root `CLAUDE.md`'s
unlock-edge rule). `Mod+Escape` here is a normal niri keybind, read by niri
itself while unlocked, that starts the locker — the same shape as the
default config's `Super+Alt+L → swaylock` suggestion.
