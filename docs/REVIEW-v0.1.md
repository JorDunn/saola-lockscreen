# saola-lockscreen v0.1 — adversarial security review (Stage 6)

**Date:** 2026-08-02 · **Scope:** the whole crate at `src/` (`main.rs`, `auth.rs`,
`config.rs`, `wallpaper.rs`, `modules/{mod,clock,reveal,temperature}.rs`), `Cargo.toml`,
`Cargo.lock`, and the runtime behaviour of `iced_sessionlock` 0.19.1 / `sessionlockev`
0.19.1 where this crate's invariants depend on it.
**Method:** read-only. No source file was modified. Findings are for Stage 7 to fix.

A locker's failure modes, in the order of severity this review uses:

1. **Session exposed** — the desktop is visible or reachable when it should not be.
2. **User locked out** — the locker is up but no correct password can dismiss it.

Everything below is ranked against that ordering, not against generic CVSS.

---

## Verification status — read this before trusting any "live" claim

- **The real-PAM round-trip has NOT been performed.** Stage 4 printed a procedure for
  Jordan (install `/etc/pam.d/saola-lockscreen`, run nested niri, type a real password).
  As of this review that confirmation is **not recorded with the orchestrator**, and
  direct inspection confirms the file does not exist:
  `ls /etc/pam.d/saola-lockscreen` → *No such file or directory*; `/usr/lib/pam.d/`
  contains only `polkit-1`, `systemd-run0`, `systemd-user`. **No successful PAM
  authentication has ever run through this code.** Every statement in this document
  about `PamAuthenticator::run_pam`'s success path is derived from reading the code and
  `pam-client2`'s source, never from an observed unlock.
- Every live claim in Stages 2–4's handoffs (nested lock/unlock, Escape edge, 30 s
  timeout, missing-service-file error copy) is taken as reported; this review did not
  re-run them (Stage 6 is read-only and must not lock the real session).
- **Multi-output behaviour has never been exercised** (Jordan's machine has one output).
  Finding M-2 is a code-reading result, not an observed bug.
- **Stage 5's temperature line has never been rendered** — no live test, and no
  `~/.config/saola/lockscreen.kdl` exists on this machine, so the module has only ever
  run in its unconfigured (renders-nothing) state.

## Evidence run for this review

| Command | Result |
|---|---|
| `cargo clippy --all-targets -- -D warnings` | clean |
| `cargo clippy --all-targets --features dev-unlock -- -D warnings` | clean |
| `cargo test` | 100 passed, 0 failed |
| `cargo test --features dev-unlock` | 100 passed, 0 failed |
| `cargo fmt --check` | clean |
| `cargo tree -e normal -d`, `cargo tree -e normal -i {ring,url,time,cookie_store}` | see D-1/D-2 |
| `git status --porcelain` before and after | identical — no file was modified |

Green gates are the *start* of this review, not its conclusion: three of the five
findings below (H-1, H-2, M-1) are invisible to clippy and to every existing test.

---

## Findings

Severity scale: **Critical** (session exposed now) · **High** (session exposed or user
locked out under a realistic, reachable condition) · **Medium** (a real failure with a
narrower trigger, or a documented invariant that is factually wrong) · **Low** (bounded,
cosmetic, or defence-in-depth) · **Info** (recorded so a future reader does not have to
re-derive it).

### Summary

| # | Severity | Blocking? | Title |
|---|---|---|---|
| H-1 | High | **must-fix** | `Lockscreen::boot()` runs before the compositor is asked to lock — the desktop stays visible for the whole of config + wallpaper decode |
| H-2 | High | **must-fix** | Stage 4's interim PAM policy (`auth include system-auth` only) leaves the `account` stack empty, so `pam_acct_mgmt` fails and no correct password can unlock — while burning the `pam_faillock` budget |
| M-1 | Medium | **must-fix** | Nothing prevents `--release --features dev-unlock`; the binding rule is prose only |
| M-2 | Medium | won't-block | Multi-output: every surface's password field shares one widget id, and their cursors desynchronise — a password typed across two outputs is scrambled |
| M-3 | Medium | won't-block | `Authenticating` has no bound: a hung PAM module strands the surface with no timeout, no cancel and no way back |
| M-4 | Medium | won't-block | An `acct_mgmt` failure is reported with the wrong-password copy |
| L-1 | Low | won't-block | The documented "only `Message::UnLock` unlocks" invariant is incomplete — `WindowAction::Close` also unlocks |
| L-2 | Low | won't-block | Empty submissions never reach PAM — a deliberate spec deviation, but a permanent lockout for a `nullok` account |
| L-3 | Low | won't-block | The compositor's `locked` / `finished` events are ignored by the dependency; the crate cannot tell whether the lock succeeded |
| L-4 | Low | won't-block | The centred stack has no minimum-size handling; on a short logical output the password field can be laid out off-screen |
| I-1..I-6 | Info | — | Privacy of the Open-Meteo fetch, `webpki-roots`, dependency panics, uncontrollable password copies (re-verified), duplicated crates, IME |

---

### H-1 — `boot()` runs *before* the `lock` request; the unlocked desktop stays visible for its whole duration

**must-fix**

**Where:** `src/main.rs:357` (`Lockscreen::boot`), `src/wallpaper.rs:121` (`load`),
`src/modules/reveal.rs:252` (`Avatar::resolve`), `src/auth.rs:303` (`Account::current`).

**What I verified (not assumed):**

- `iced_sessionlock-0.19.1/src/multi_window.rs:82` — `let (application, task) =
  runtime.enter(|| Instance::new(program));`
- `iced_program-0.14.0/src/lib.rs:674` — `Instance::new` is `let (state, task) =
  program.boot();`, i.e. **our `Lockscreen::boot` runs here.**
- `iced_sessionlock-0.19.1/src/multi_window.rs:122–126` — *afterwards*,
  `sessionlockev::WindowState::new()…build()`.
- `sessionlockev-0.19.1/src/lib.rs:995–997` — inside that `build()`:
  `globals.bind::<ExtSessionLockManagerV1,…>()` then **`let lock = lock_manager.lock(&qh, ());`**

So the entire body of `Lockscreen::boot` executes **before the `ext_session_lock_manager_v1.lock`
request is even sent to the compositor**. Until that request lands, niri has not been
told to hide anything: the session is fully visible and fully interactive.

`boot` currently does, synchronously, on the calling thread:

1. `config::LockscreenConfig::load()` — a filesystem read.
2. `wallpaper::load(path)` — `std::fs::read` of the whole wallpaper file, then
   `image::load_from_memory` (full decode), then `to_rgba8()` (a second full-size
   allocation and copy). Stage 3's own live test used a 5000×3333 image: ~16.7 Mpx, a
   ~67 MiB RGBA buffer.
3. `auth::Account::current()` → `getpwuid_r`, which goes through NSS. On this machine
   that is `files` and instant; on any host with `sss`/`ldap` in `nsswitch.conf` it is a
   network call with no timeout that this crate controls.
4. `Avatar::resolve` — another file read plus another full image decode.

`src/wallpaper.rs`'s doc comment already discusses this cost, but frames it as a UX
trade ("a slightly slower lock beats a wallpaper that never renders") and states that
"niri does not consider the session locked until this process's first lock surface
appears". The security-relevant fact is stronger and different: **the compositor has not
been asked to lock at all yet**, so this is not "the lock surface is late", it is "the
lock has not started".

**Failure scenario (concrete):**

*Before-sleep.* Stage 7 ships `contrib/session/` idle and before-sleep wiring. A
fire-and-forget `saola-lockscreen &` on `PrepareForSleep` starts the process; the lid
closes; the kernel suspends. If suspend wins the race against `boot`'s file read +
decode, the machine suspends with the session unlocked and **resumes showing the
unlocked desktop**. This is the classic locker/suspend race that `systemd-inhibit
--what=sleep --mode=delay` exists to close, and this crate's `boot` makes the race window
larger than it needs to be by an amount proportional to the wallpaper's size and the
coldness of the page cache.

*Manual lock.* `Mod+Escape` spawns the locker; for the duration of the decode the desktop
is on screen and accepting input. Annoying rather than dangerous when the user is
present, but it is the same window.

I did **not** measure the decode time (Stage 6 may not build or run new code); the point
is that it is unbounded and user-controlled via `lockscreen.kdl`, not that it is any
particular number.

**Fix sketch for Stage 7:**

1. Make `boot` do no I/O beyond `config::load()`. Construct `Lockscreen` with
   `wallpaper: None` (the ink fallback is *already* the correct visual for "not loaded
   yet" — `src/main.rs:498`'s layering needs no change) and return, in the same
   `Task<Message>` that already carries `initial_fetch`, a `Task::perform` of a
   `spawn_blocking` closure that does `wallpaper::load(path)` and delivers
   `Message::WallpaperLoaded(handle)`.
   *Gotcha:* `iced_core::image::Handle` derives `Clone, PartialEq, Eq` but **not
   `Debug`** (`iced_core-0.14.0/src/image.rs:86`), and `main.rs`'s `Message` derives
   `Debug` — so the new variant needs a hand-written `Debug` (the same treatment
   `modules::reveal::Message` already gets), or a newtype wrapper.
2. Do the same for `Avatar::resolve`, or keep it synchronous and accept it: `~/.face` is
   small. Prefer moving it for symmetry; the initials disc is the ready fallback.
3. Keep `Account::current()` in `boot` only if you are content with NSS on the pre-lock
   path; otherwise resolve the display name asynchronously and show the login name (or
   nothing) until it arrives. On Jordan's `files`-only `nsswitch.conf` this is a
   non-issue today — document the assumption rather than engineering around it.
4. **`contrib/session/`** must not paper over this: the before-sleep unit needs
   `systemd-inhibit --what=sleep --mode=delay` (or niri's own equivalent) so the sleep is
   held until the locker is actually up. Note L-3: this crate cannot report "I am locked"
   to a wrapper, so the wrapper must use a coarse signal (process still alive after N ms,
   or niri's `locking session` log line) and the README should say so plainly.

---

### H-2 — the interim PAM policy Stage 4 told Jordan to install cannot ever unlock, and burns the faillock budget doing it

**must-fix**

**Where:** `.claude/handoffs/handoff_stage_4.md:450–454` (the command printed for
Jordan), consumed by `src/auth.rs:482` (`context.acct_mgmt(Flag::NONE)`).

Stage 4 printed this for Jordan to run as root:

```bash
printf 'auth include system-auth\n' | sudo tee /etc/pam.d/saola-lockscreen
```

`run_pam` calls **both** `pam_authenticate` *and* `pam_acct_mgmt` (`src/auth.rs:465` and
`:482`), and the doc comment there is right that skipping `acct_mgmt` would be a real
security gap. But that file gives the `saola-lockscreen` service an **`auth` stack only**
— there are no `account` rules at all.

Linux-PAM falls back to `/etc/pam.d/other` only when the *service file is absent*. Here
the file exists, so the `account` chain is simply empty, and `_pam_dispatch` with no
handlers logs `no modules loaded for 'account' service` and returns `PAM_MUST_FAIL_CODE`
(`PAM_PERM_DENIED`). Even in the alternative reading — if libpam did fall through to
`other` — `/etc/pam.d/other` on this machine is `account required pam_deny.so` (verified
by reading it). **Both readings give the same answer: `acct_mgmt` fails.**

**Failure scenario (concrete):**

1. Jordan runs the printed command, boots the locker in nested niri, types his **correct**
   password.
2. `pam_authenticate` succeeds. `pam_faillock authsucc` resets his counter.
3. `pam_acct_mgmt` returns `PERM_DENIED`.
4. `classify_failure(PERM_DENIED, service_installed = true)` → `Outcome::Rejected`
   (`src/auth.rs:556`) → `modules::reveal` shows **"Wrong password."**
   (`src/modules/reveal.rs:462`).
5. He assumes a typo and tries again. And again. Each attempt runs the full `auth` stack
   first, so `pam_faillock preauth`/`authsucc` are exercised each time — and because the
   *auth* phase keeps succeeding, the failure counter is reset each round, so he does
   *not* get locked out from this path alone. But the moment he mistypes for real, or
   `pam_systemd_home` is in play, the failures do count, and Arch's stock `deny=3`
   applies to `sudo` and his real login too (`/etc/security/faillock.conf` on this
   machine is entirely comments, i.e. all defaults).
6. Net result: **no password can unlock the screen, and the error copy actively points
   at the wrong cause.** That is squarely "user locked out", and it is the exact command
   the previous stage handed over.

The reference on this machine is `/usr/lib/pam.d/polkit-1` (polkit also runs auth +
acct_mgmt), which correctly has `auth`, `account`, `password` and `session` includes.

**Fix sketch for Stage 7:**

`contrib/pam/saola-lockscreen` must contain at minimum:

```
#%PAM-1.0
auth      include   system-auth
account   include   system-auth
```

(`password`/`session` are not needed — a locker runs neither phase. Stage 7 still owns
the rosec line; see the handoff for what is already on disk.) Stage 7 must also
**explicitly retract Stage 4's command** in the README/CHANGELOG so Jordan does not run
the old one from the handoff.

Consider also validating this at runtime: `service_file_exists` (`src/auth.rs:594`) only
checks that a file *exists*. It could cheaply also check that the file contains an
`account` line, and downgrade to `Outcome::Unavailable("…PAM policy has no account
stack")` rather than "Wrong password.". That is optional; M-4 below is the more general
version of the same fix.

---

### M-1 — nothing stops `cargo build --release --features dev-unlock`

**must-fix** (cheap, and it enforces a binding rule)

**Where:** `Cargo.toml:12` (`dev-unlock = []`), `src/main.rs:416`, `:561`, `:651`.

The good news first, all verified:

- `[features]` has **no `default` key**, so the default feature set is empty and
  `dev-unlock` is off unless explicitly asked for. ✔
- The gate wraps the *whole* edge, not just the keybind: the `Message::DevUnlockEscapePressed`
  variant (`:651`), the subscription that can emit it (`:561`), and the `update` arm that
  turns it into `Message::UnLock` (`:416`) are each `#[cfg(feature = "dev-unlock")]`. ✔
- `grep -rn 'dev-unlock' src/ Cargo.toml` shows no other site. ✔
- Both feature configurations compile clean under `clippy -D warnings` and both test
  suites pass (100/100 each) — so the cfg'd branch is genuinely checked, per `CLAUDE.md`.
  ✔

The gap is that the rule "never in a release build" lives only in prose (`CLAUDE.md`,
`PLAN.md`, three doc comments). A packaging script, an AUR `PKGBUILD`, or a tired
`cargo install --features dev-unlock` produces a binary where **Escape unlocks the
session with no password**, and nothing warns.

**Failure scenario:** Stage 7 writes the AUR `PKGBUILD`. Someone later adds
`--features dev-unlock` while debugging a packaging problem and forgets to remove it. The
shipped locker is opened by pressing Escape. Session exposed, silently, with green CI.

**Fix sketch for Stage 7:** add to `src/main.rs`, at module scope:

```rust
#[cfg(all(feature = "dev-unlock", not(debug_assertions)))]
compile_error!(
    "the dev-unlock feature adds a password-free unlock edge and must never be \
     compiled into a release build — see CLAUDE.md's unlock-edge rule"
);
```

`debug_assertions` is on for the `dev` profile and off for `release`, so this permits
`cargo run --features dev-unlock` (the nested-niri workflow, unchanged) and hard-fails
`--release --features dev-unlock`. Add a matching sentence to the README's feature
section and a `--no-default-features`-style note to the PKGBUILD.

---

### M-2 — multi-output: shared widget id, desynchronised cursors, scrambled password

won't-block (Jordan has one output today; it must be fixed before a second one)

**Where:** `src/modules/reveal.rs:137` (`password_input_id`), `:607` (the `text_input`),
`src/main.rs:440` (`Effect::Focus`).

`view` is called once per output and every surface builds a `text_input` with the *same*
id, deliberately (`password_input_id`'s doc comment), because `iced_sessionlock`'s
`Action::Widget` handler applies an operation to **every** window it manages — verified
at `iced_sessionlock-0.19.1/src/multi_window.rs:868` (`for (id, window) in
window_manager.iter_mut() { … ui.operate(…) }`). So one `Effect::Focus` focuses all of
them. That part is correct and intended.

What was not considered: each window keeps its **own** `text_input::State`, and that
state holds a cursor index. `State::focus()` sets the cursor to `usize::MAX`
(`iced_widget-0.14.2/src/text_input.rs:1511–1520` → `move_cursor_to_end`), which is
clamped to the value's length on every read — so a *freshly focused, never typed in*
field behaves as "cursor at end" and stays consistent. But the moment a surface receives
a keystroke, its editor sets a **concrete** index (`Editor::insert` → `cursor.move_right`),
and that index is now stale on every *other* surface's state, and vice versa.

**Failure scenario (concrete):** two outputs, both showing lock surfaces, both fields
focused.

1. Keyboard focus is on output A. User types `hunt` → shared buffer `hunt`, A's cursor 4,
   B's cursor still `usize::MAX` (reads as 4).
2. The user moves the pointer to output B and clicks (or the compositor moves keyboard
   focus on output change). B is now the surface receiving keys. Typing `er2` there works
   — B's cursor becomes concrete 7.
3. The user goes back to output A (a click, or the pointer crossing back) and presses
   Backspace or types one more character. **A's cursor is still 4**, so the edit lands in
   the middle of the string: `hunter2` becomes `hunt?er2` / `hun ter2`.
4. The masked field shows only bullets, so the user sees nothing wrong. Enter → "Wrong
   password." → retry → repeat. Each retry is a real `pam_faillock` failure. With Arch's
   stock `deny=3` this reaches account lockout in three rounds, affecting `sudo` and the
   real login. "User locked out", from a UI bug.

Same mechanism affects Backspace, Home/End and arrow keys, all of which are live on a
`secure` field.

**Fix sketch for Stage 7 (pick one):**

- *Cheapest and most robust:* after every `Message::Changed`, return an effect that runs
  `iced::widget::operation::text_input::move_cursor_to_end(password_input_id())`. It
  applies to all windows (same all-windows semantics as `focus`), resyncing every
  surface's cursor to the end of the shared buffer after every keystroke. The cost is that
  deliberate mid-string editing stops working — acceptable, and arguably desirable, for a
  masked password field on a lock screen.
- *More correct, more work:* give each output's field a per-`window::Id` id and only focus
  / operate on the surface that currently has keyboard focus. This needs the crate to
  track which window is focused, which today it deliberately does not do.
- Either way: **test it live on two outputs before v0.1 is tagged**, since this is
  precisely the path with no live coverage.

---

### M-3 — `Authenticating` is unbounded: a hung PAM module strands the surface with no way back

won't-block (needs a slow/hanging PAM module; Jordan's stack is local `pam_unix`)

**Where:** `src/modules/reveal.rs:477` (`(State::Authenticating, _) => Effect::None`),
`:527` (`subscription` returns `Subscription::none()` outside `Revealed`).

Three deliberate decisions compose into a trap:

- The idle-timeout tick does not run while `Authenticating` (`:539`, `ticks()`), with a
  good reason: PAM may legitimately take a while.
- Escape during `Authenticating` is a documented no-op, not a cancel (`:477`), also with a
  good reason (a cancel would leave a live future whose `Outcome` lands later — the
  spurious-unlock shape).
- The password field is disabled while `Authenticating` (`:603`).

Consequently, if `pam_authenticate` never returns, the machine can never leave
`Authenticating`. There is no watchdog, no user-visible progress state beyond the greyed
field, and no key that does anything. The clock keeps ticking, so the surface does not
*look* frozen; it is simply permanently inert.

**Failure scenario:** any PAM stack with a network module — `pam_sss`, `pam_ldap`,
`pam_krb5`, or `pam_systemd_home` against an unavailable home — plus a network partition.
`pam_authenticate` blocks for the module's own timeout, which can be minutes or (with a
misconfigured module) indefinite. During that time the user's only recovery is VT-switch +
`pkill`. That is "user locked out", the second-worst mode. Note it is *not* reachable on
this machine today: `/etc/pam.d/system-auth` is `pam_faillock` + `pam_systemd_home` +
`pam_unix`, all local. It becomes reachable the moment Stage 7 adds `pam_rosec` (a
`pam_exec` helper, per the rosec docs) or the machine joins a directory.

**Fix sketch for Stage 7:** keep the no-cancel rule, add a bound and an escape hatch:

- Re-arm the tick in `Authenticating` (`ticks()` → `self.state != State::Idle`) purely as
  a stopwatch, and after e.g. 5 s set a non-fatal hint (`"Still checking…"`) so the user
  knows the surface is alive.
- After a longer bound (e.g. 60 s), permit `Message::Dismissed` to return to `Revealed`
  (**not** to `Idle`) and mark the attempt abandoned. The existing stale-outcome guard
  (`(State::Revealed, Message::Finished(_)) => Effect::None`, `:486`) already guarantees
  the abandoned future's late `Outcome::Authenticated` is ignored, so this cannot become a
  spurious unlock — that guard is exactly what makes this safe to add.
- Do **not** add a timeout that returns to `Idle`: the reasoning in the module doc comment
  for why that is dangerous is correct and still applies.

---

### M-4 — an `acct_mgmt` failure is reported as "Wrong password."

won't-block, but fix it alongside H-2 (it is the reason H-2 is so confusing to diagnose)

**Where:** `src/auth.rs:474–484` — both the `authenticate` and the `acct_mgmt` failure
paths call the same `classify_failure(err.code(), service_file_exists(service))`.

`classify_failure` has no idea which PAM phase failed. An `acct_mgmt` returning
`PERM_DENIED` (empty account stack — H-2), or `AUTH_ERR` from a weird `account` module,
maps to `Outcome::Rejected` and the surface says **"Wrong password."** for a condition no
password can change. `ACCT_EXPIRED` is handled well; the generic codes are not.

**Failure scenario:** exactly H-2's, plus any future `account` module returning a generic
code. The user retypes a correct password indefinitely and, on stacks where the auth phase
also fails, spends the faillock budget.

**Fix sketch:** thread the phase through — `classify_failure(code, service_installed,
phase: Phase)` with `Phase::{Authenticate, Account}` — and make the `Account` phase never
produce `Outcome::Rejected`; every code there becomes
`Outcome::Unavailable("This account cannot unlock the session (…).")`. `classify_failure`
is already a pure function with exhaustive unit tests (`src/auth.rs:746–872`), so this is
a mechanical change plus a few new cases.

---

### L-1 — the documented unlock invariant is incomplete: `WindowAction::Close` also unlocks

won't-block (no code path reaches it today), but the doc comments should stop asserting
something that is not true.

**Where:** `src/main.rs:62–84` and `:398–403` state that intercepting a literal
`Message::UnLock` "is the *only* place unlock actually happens".

Verified in the dependency:

- `iced_sessionlock_macros-0.19.1/src/lib.rs` — the generated `TryInto<UnLockAction>` is
  `match self { Self::UnLock => Ok(UnLockAction), _ => Err(self) }`. **No other variant
  can convert.** ✔ (This is the part the doc comment gets right, and it is airtight.)
- `iced_sessionlock-0.19.1/src/multi_window.rs:780` (`update`) and `:824`
  (`run_action`, `Action::Output`) — both set `*should_exit = true` only on that
  conversion. ✔
- **`iced_sessionlock-0.19.1/src/multi_window.rs:874` — `WindowAction::Close(_) => {
  *should_exit = true; }`.**
- `:605` / `:675` — `if should_exit { ev.append_return_data(ReturnData::RequestUnlockAndExist) }`
- `sessionlockev-0.19.1/src/lib.rs:1198` and `:1229` — `RequestUnlockAndExist` →
  `lock.unlock_and_destroy()`.

So `iced::window::close(id)` — and anything built on it, including `iced::exit()` in
iced's own idiom (`iced_runtime-0.14.0/src/lib.rs:124`, though note that
`Action::Exit` itself falls into `run_action`'s `_ => {}` and is inert here) — is a
**second, undocumented route to a real `ext-session-lock-v1` unlock**, requiring no PAM.

Nothing in this crate produces a window action today (`grep` for `window::close`,
`iced::exit`, `Action::Window` in `src/` → no hits; the only `Task`s produced are
`Task::none`, `Task::done(Message::UnLock)`, `Task::perform`, and
`iced::widget::operation::focus`). The finding is that the crate's own audit trail tells
a future maintainer the wrong thing, and "just close the window" is a very natural thing
for someone to reach for.

**Fix sketch:** correct the doc comments in `src/main.rs` to name both routes, and add
the second one to the greppable audit list in `CLAUDE.md` (`grep -rn 'window::close\|
iced::exit\|Message::UnLock' src/` should be the enumeration, not just the last term).
Optionally add a unit-test-level guard is not possible here (it is a dependency
behaviour), so the doc + grep list is the control.

---

### L-2 — empty submissions never reach PAM: a deliberate spec deviation with one lockout edge

won't-block; document it

**Where:** `src/modules/reveal.rs:416–428`.

Architecture's diagram says `Revealed ──Enter──▶ Authenticating`. The implementation adds
a guard: an empty buffer makes Enter a no-op, to protect the `pam_faillock` budget. The
reasoning is sound and the test (`empty_submission_never_reaches_the_authenticator`) pins
it, but two things follow.

1. It is a deviation from the binding spec that is documented only in a code comment and
   Stage 4's handoff. It should be in the README and the CHANGELOG so it is a decision,
   not a surprise.
2. **`/etc/pam.d/system-auth` on this machine has `pam_unix.so try_first_pass nullok`**
   (verified by reading it). For an account with an empty password, PAM would accept an
   empty submission — and this guard makes that submission unreachable, so such an account
   can never unlock. Vanishingly unlikely for Jordan (he uses `sudo`), but it is the exact
   shape of "the locker is up and no input dismisses it".

**Fix sketch:** keep the guard (it is the right trade) and document it in the README's
behaviour section. If you want to close the `nullok` edge without giving up the faillock
protection, allow *one* empty submission per reveal (a `bool` on `Reveal`, reset in
`return_to_idle`), so a genuinely empty password works but leaning on Enter still cannot
drain the budget.

---

### L-3 — the crate cannot tell whether the lock actually succeeded

won't-block

**Where:** dependency behaviour — `sessionlockev-0.19.1/src/lib.rs:943`:
`delegate_noop!(@<T>WindowState<T>: ignore ExtSessionLockV1);`

The `ext_session_lock_v1` object's two events are `locked` (the compositor has hidden all
normal content) and `finished` (the lock was denied or revoked — e.g. another lock client
is already active). **Both are discarded.** Consequences:

- Nothing in this process, or any wrapper around it, can wait for "the session is now
  actually locked". The only signals available are niri's own log line and process
  liveness — which is why H-1's `contrib/session/` fix has to use a coarse mechanism.
- If `finished` arrives, the crate keeps running and drawing to surfaces the compositor no
  longer shows. If PAM then succeeds, `unlock_and_destroy` on a finished lock is the
  `invalid_unlock` protocol error and the compositor kills the client. The *direction* is
  safe (the session stays locked, held by whoever holds the live lock), but the behaviour
  is undefined-looking and undocumented.

**Fix sketch:** nothing to fix in this crate — record it in the README's "known
limitations" and, if it ever matters, raise it upstream with waycrate. Stage 7's session
wiring must not assume a "locked" signal exists.

---

### L-4 — no minimum-size handling for the centred stack

won't-block

**Where:** `src/main.rs:507–527`, `src/modules/reveal.rs:546–645`.

The centred `column!` stacks a 168 px clock (`typography.size.lock_clock`), a 22 px date,
an optional temperature line, an 88 px avatar (`hit_target_touch * 2.0`), a name line, a
~68 px field and an optional error line, with `popover_padding` and `island_gap` spacing —
roughly 430 logical px on the revealed state, with no scrolling and no shrink behaviour.
On Jordan's 1.5-scale panel there is plenty of room. On a short logical output (a small
external display at a high scale factor, or a projector at an odd mode), iced will lay the
column out taller than the surface and the password field can land off-screen. There is no
scroll container and no key that scrolls, so the field would be unreachable → "user locked
out".

**Fix sketch:** wrap `centred`'s content in a `scrollable`, or shrink the clock when the
available height is below a threshold. Cheap insurance; verify against a deliberately
small nested-niri output (`niri msg output winit …`) rather than by reasoning.

---

### Info

**I-1 — what leaves the machine while locked.** `src/modules/temperature.rs:326`
(`fetch_blocking`) issues `GET https://api.open-meteo.com/v1/forecast?latitude=…&longitude=…&current=temperature_2m`
at boot and every 15 minutes, *for as long as the screen is locked*. That publishes the
configured coordinates and a heartbeat of "this machine is awake and locked" to a third
party, plus `api.open-meteo.com` in plaintext DNS/SNI to anyone on the local network. It
is exactly what Architecture asked for, so it is not a finding — but the README's config
section should say it out loud, since `latitude`/`longitude` in `lockscreen.kdl` are
usually the user's home. Nothing about the request is user-controlled beyond the two
floats, and both are `f64`-formatted, so URL injection is not possible. `f64::INFINITY`
or `NaN` from KDL's `#inf`/`#nan` literals would render as `inf`/`NaN`, get a 4xx, and
fold to `None` — no panic.

**I-2 — the response side is bounded and memory-safe.** `Body::read_to_string()` has a
**default 10 MiB limit** in ureq 3 (`ureq-3.3.0/src/body/mod.rs:30`,
`const MAX_BODY_SIZE: u64 = 10 * 1024 * 1024`), so a hostile or MITM'd endpoint cannot
drive an unbounded allocation. `serde_json` parsing and the two `.get()` lookups are
memory-safe and every failure folds to `None` (`parse_temperature`, `:356`). The 10 s
`timeout_global` (`:112`) bounds the blocking-pool thread. All good.

**I-3 — the panic surface, precisely.** A per-file scan for
`unwrap()` / `.expect(` / `panic!` / `unreachable!` / `todo!` / `unimplemented!` /
`assert` **above each file's `#[cfg(test)]` line** returns **zero hits across all seven
source files**. The only non-test `unwrap_*` calls are `unwrap_or_else` /
`unwrap_or_default` (`src/auth.rs:312`, `:393`, `:532`), which do not panic. No indexing,
no slicing, no fallible arithmetic on runtime paths; the one numeric cast
(`celsius.round() as i64`, `src/modules/temperature.rs:285`) is a saturating float→int
cast and is separately tested for `NaN`/`±inf`. The crate's only `unsafe` is
`auth::passwd_entry` / `auth::owned_c_string` (`getuid` + `getpwuid_r`), each with a
correct SAFETY comment, an `ERANGE` retry loop with a 256 KiB ceiling, no borrow escaping
`buf`, and `None` on every failure path — I read it line by line and found nothing wrong.
`Cargo.toml` declares **no `[profile]` section**, so both profiles use `panic = "unwind"`;
a panic on the UI thread therefore unwinds out of `main` and the process exits *without*
unlocking, which niri treats as a dead lock and keeps the session locked. That is the
correct direction.

The *dependencies* are not panic-free, and that is the residual lockout risk this crate
cannot close: `iced_sessionlock-0.19.1` contains `expect`s on the compositor-creation and
UI-lookup paths (`multi_window.rs:126`, `:272`, `:390`, `:411`, `:416`, `:635`;
`window_manager.rs:102`; `user_interface.rs:36`), two `unreachable!`s (`event.rs:34`,
`:135`), an `unwrap()` pair in coordinate scaling (`conversion.rs:23`, `:26`, on
`TryInto<f64>` for integer coordinates — infallible for the types actually used), and one
deliberate `panic!("{error:?}")` on `SurfaceError::OutOfMemory` (`multi_window.rs:497`).
`sessionlockev-0.19.1/src/lib.rs:1200` also `expect`s a roundtrip — but that one is
*after* `unlock_and_destroy`, so it cannot strand a locked session. Every one of these
aborts the process and leaves the session locked (recoverable via VT switch), which is the
designed-for failure mode, not a bypass.

**I-4 — password lifetime: Stage 4's accounting re-verified, and it is accurate.**
`Password` is `Zeroizing<String>` (`src/auth.rs:145`); assignment drops-and-zeroes the old
buffer, and the three controlled copies (`Reveal::password`, the value moved into
`Authenticator::authenticate`, `LockConversation::password`) are each zeroed —
`forget()` is called at `src/auth.rs:472`, the tightest point `pam-client2` allows,
before `acct_mgmt` and before the context drops. `Password` implements neither `Display`
nor any serialization, and both `Password`'s and `reveal::Message`'s `Debug` are
hand-written redactions, each unit-tested. `Password` *does* derive `Clone`
(`src/auth.rs:144`) — worth knowing, but every clone is itself a `Zeroizing<String>` and
so is covered by the same `Drop`, and I found no clone site outside tests. The buffer is
*moved* out on submit, so `Reveal` holds no secret at all while `Authenticating`
(`:433`, tested). `String::push`-style realloc traps do not apply on this side: nothing
ever grows a `Password` in place — each keystroke hands us a fresh `String` from iced that
we take ownership of, and `zeroize`'s `Vec<u8>` impl wipes the full capacity, not just the
length. The uncontrollable copies Stage 4 listed (iced's per-event `Vec<char>` value, the
intermediate `String`s iced allocates while editing, `CString::new` in `prompt_echo_off`
plus `pam-client2`'s `strdup`, and whatever the PAM modules retain) are all still real and
all still outside this crate's reach; the list is complete as written. One addition worth
noting: because `view` runs **once per output**, each output's `text_input` builds its own
unzeroed `Vec<char>` copy per frame — so the number of uncontrolled transient copies
scales with the monitor count. Nothing to do about it here.
`Password::displayable()` is `pub(crate)` with exactly one caller
(`src/modules/reveal.rs:607`); tightening it further is not worth a module split.
Copy/cut are disabled for the field (`iced_widget-0.14.2/src/text_input.rs:916`, `:932`
gate them on `!is_secure`), so the typed password cannot be lifted to the clipboard;
paste *into* the field is permitted, which is fine.

**I-5 — dependency review.** `cargo tree -e normal -i` (the authoritative reverse-
dependency view) **confirms Stage 5's claim**: `url`, `time` and `cookie_store` are *not*
in the compiled graph — `cargo tree -e normal -i url` / `-i time` / `-i cookie_store` all
return *"did not match any packages"*, and a grep for `icu_*`/`zerovec`/`yoke`/`tinystr`/
`zerotrie`/`writeable` across `cargo tree -e normal` returns **0 hits**. They are
`Cargo.lock` pins for `ureq`'s unactivated optional features, exactly as described. The
TLS stack is `rustls 0.23.43` + `ring 0.17.14` + `rustls-webpki 0.103.13` +
`webpki-roots 1.0.9`: **no `native-tls`, no `openssl`, no `aws-lc-rs`/`aws-lc-sys`**
anywhere in the compiled graph (verified by grep over `cargo tree -e normal`). Note that
`webpki-roots` bakes the CA set into the binary — it does not follow the system trust
store, so a CA distrust reaches this binary only on a dependency bump; acceptable for one
unauthenticated weather GET, worth a README line. `saola-theme` is still pinned to the
**tag**, not a branch: `Cargo.toml:20` has `tag = "saola-theme-v0.5.0", version = "0.5.0"`
and `Cargo.lock` records
`git+https://github.com/JorDunn/saola-theme?tag=saola-theme-v0.5.0#b874df5c…`. ✔
`pam-client2` is `default-features = false` (drops `rpassword`). ✔
`cargo tree -e normal -d` shows **~30 duplicated crates**, essentially all of them the
known `iced`-via-`winit` versus `iced_sessionlock`-via-`sessionlockev` split
(`smithay-client-toolkit` 0.19.2 + 0.20.0, `calloop` 0.13 + 0.14,
`calloop-wayland-source` 0.3 + 0.4) plus ordinary ecosystem skew (`bitflags` 1/2,
`rustix` 0.38/1.1, `thiserror` 1/2, `syn` 2/3, `png` 0.17/0.18, `zune-jpeg` 0.4/0.5,
`getrandom` 0.2/0.3/0.4, …). Stage 1 flagged the sctk split and Stage 2 confirmed it does
not cause type-boundary friction; that still holds. It is binary bloat and duplicated
audit surface, not a correctness problem, and it is not this crate's to fix. Nothing in
the tree is obviously unmaintained; `ureq` 3.3.0, `rustls` 0.23, `kdl` 6.7.1 and
`pam-client2` 0.5.5 are all current. `cargo audit`/`cargo deny` were not run (not
installed); Stage 7 should consider wiring one into CI.

**I-6 — input assumptions.** Key events arrive through `sessionlockev`'s xkb handling, so
the compositor's keymap and layout apply and `text_input` consumes the resolved `text`
rather than a keycode — no hardcoded layout assumption anywhere in this crate.
`event_to_message` (`src/modules/reveal.rs:664`) is a pure function, unit-tested, and
correctly wakes on *any* `KeyPressed` (including modifiers, per §7's "any key") while
ignoring pointer motion and key releases — the "a nudged desk lights up the screen all
night" case is handled. Escape is routed by `main.rs`'s status-ignoring listener because
`text_input` captures it (`iced_widget-0.14.2/src/text_input.rs:1239`) — verified, and the
comment explaining it is accurate. **IME is effectively unavailable**: `text_input` sets
`input_method::Purpose::Secure` (`:435`) but `sessionlockev` does not implement
`text-input-v3`, so a user who needs an input method to type their password could not.
Irrelevant for Jordan; a real constraint for anyone else, worth a README line. Compose /
dead-key sequences depend on `waycrate_xkbkeycode`'s handling and were not tested.

---

## Checked and found clean

Absence of a finding below means the item was actually examined, with the evidence named.

**Unlock reachability (the first audit item) — clean, with L-1's caveat.**
- The generated `TryInto<UnLockAction>` accepts **only** `Self::UnLock` and returns
  `Err(self)` for every other variant — read in `iced_sessionlock_macros-0.19.1/src/lib.rs`,
  not assumed from the doc comment. There is no way for `Message::Clock`,
  `Message::Reveal`, `Message::Temperature` or a subscription-injected message to convert.
- `grep -rn 'Message::UnLock' src/` → exactly three code sites (the rest are comments):
  the exhaustiveness arm (`src/main.rs:406`), the `dev-unlock` arm (`:417`), and the PAM-ok
  arm (`:468`). `grep -rn 'Effect::Unlock' src/` → one producer
  (`src/modules/reveal.rs:459`) and one consumer (`src/main.rs:468`).
  `grep -rn 'Outcome::Authenticated' src/` → one non-test construction site
  (`src/auth.rs:486`), reached only after **both** `pam_authenticate` and `pam_acct_mgmt`
  returned `Ok`.
- Message injection via subscriptions is not a route: all three subscription sources map
  into `Message::Clock`/`Message::Reveal`/`Message::Temperature`, and subscription output
  goes through the same `Action::Output` → `try_into` funnel.
- No test-only code compiles into a non-test build: every `#[cfg(test)]` is a whole module
  at the end of its file, and no `#[cfg(any(test, …))]` or `pub(crate)` test helper exists.
- The state machine's own invariants are asserted executably and I re-read the tests
  rather than trusting their names: `unlock_is_produced_by_exactly_one_state_and_message`
  really does walk all 3 × 8 (state, message) pairs and assert the unlocking set is
  exactly `["Authenticating + Finished(Authenticated)"]`;
  `stale_success_outside_authenticating_never_unlocks` covers a late
  `Outcome::Authenticated` in both `Idle` and `Revealed`; `no_error_code_ever_authenticates`
  covers 28 `ErrorCode` variants × both probe values.
- I hand-checked `Reveal::update`'s match for exhaustiveness and for arm-order shadowing:
  the `(State::Authenticating, _)` catch-all sits **after** the three `Finished` arms, so
  it cannot swallow the unlock edge, and the final
  `(State::Idle, _) | (State::Revealed, Message::Finished(_))` arm is the stale-outcome
  guard. Nothing outside this one function mutates `self.state` (`grep 'self.state ='` →
  five sites, all inside it or its two helpers).
- At most one attempt can ever be in flight: `Effect::Authenticate` is produced only from
  `Revealed`, and the same arm moves the machine to `Authenticating`, which cannot submit.

**Panic surface — clean in this crate.** See I-3 for the full evidence, including the
zero-hit per-file scan, the `unsafe` review, and the (uncontrollable) dependency panics.
Degradation paths verified by reading each one: a missing/unreadable/undecodable/zero-
dimension wallpaper returns `None` and draws ink (`src/wallpaper.rs:121–180`, four unit
tests); a missing config file, an unreadable one, invalid KDL, and a single bad knob value
each degrade with a warning and never fail (`src/config.rs:120–180`, eleven unit tests); an
unconfigured or failing temperature fetch renders nothing, with three independent guards
(`coordinates` `None` ⇒ no timer, no `Effect::Fetch`, no `celsius`); `Account::current()`
falls through `getpwuid_r` → `$USER` → `"user"` and can neither panic nor return empty
(asserted by `current_account_is_always_populated`). No recursion anywhere; the only
unbounded-allocation candidates are the `getpwuid_r` retry loop (capped at 256 KiB) and the
HTTP body (capped at 10 MiB by ureq) — both bounded.

**Blocking on the UI thread — clean.** `Reveal::update` and `Temperature::update` are pure
state transitions returning `Effect` values; neither ever awaits, and neither constructs an
`iced::Task`. Both blocking calls (the PAM conversation and the `ureq` GET) are dispatched
off-thread by identical `Handle::try_current()` + `spawn_blocking` / thread+oneshot
fallbacks (`src/auth.rs:495–539`, `src/modules/temperature.rs:302–319`), and the free
`tokio::task::spawn_blocking` — which panics outside a runtime — is correctly avoided. The
only synchronous I/O on a hot path is in `boot`, which is H-1.
Stage 4 asked whether the never-executed `Handle::try_current()` `Err` arm should be
simplified to an `Outcome::Unavailable`: **keep it as it is.** It is small, it is
correct, it costs nothing, and replacing a working fallback with an error path would make
a hypothetical future non-tokio executor turn every unlock attempt into a hard failure —
strictly worse for the "user locked out" mode. Not a finding.

**Secret hygiene — clean.** See I-4 for the full re-verification, including the `Debug`/
`Display`/`Clone`/serialization review, the realloc-trap assessment, and the confirmation
that Stage 4's list of uncontrollable copies is still accurate and complete.
Error copy never contains secret material: every `Outcome::Unavailable` string is built
from a fixed template plus a PAM `ErrorCode` whose `Debug` is a bare enum name
(`src/auth.rs:550–586`), and `error_copy_never_contains_a_password` pins it. PAM's own
`text_info`/`error_msg` chatter is dropped rather than printed (`:662`, `:666`) — correct,
since a locker's stdout goes to the journal. Every `eprintln!` in the crate
(`src/config.rs:140`, `:279`; `src/wallpaper.rs:125`, `:136`; `src/auth.rs:313`;
`src/modules/reveal.rs:262`) was read and prints only paths, config keys, error strings
or the username. No secret reaches a log, a `Debug` impl, or the error copy.
Information disclosure in error copy is not a concern for a locker: it authenticates a
single fixed username taken from `getpwuid_r`, so "this account is not known to the
system" cannot be used for enumeration. `service_file_exists` reads two paths on every
failure — advisory only, cannot affect the decision (PAM is always asked first and always
has the final say), has no error path, and is confirmed harmless.

**Input edge cases — clean apart from M-2/M-3.** Double-Enter while `Authenticating` is
refused twice over: `view` disables `on_input`/`on_submit` (`src/modules/reveal.rs:603`)
*and* the state machine's `(State::Authenticating, _)` arm returns `Effect::None`, with
`second_enter_while_authenticating_is_ignored` asserting the authenticator call count stays
at 1. Escape during auth is a tested no-op. The 30 s timeout cannot fire during auth
(the tick subscription only exists in `Revealed` — `ticks()`, tested by
`the_timeout_tick_runs_only_while_revealed`) and cannot fold the surface away under a live
attempt (`timeout_does_not_fire_while_authenticating`). Activity (`Woke`, `Changed`) pushes
the deadline back and the comparison is on elapsed time, not tick count. Error copy is
cleared by typing and by the next reveal, both tested. Keyboard-layout, Escape-capture,
paste/copy and IME behaviour are covered in I-6.

**§7 / design-language compliance — clean.** At rest the surface renders clock, date and
(when configured) temperature and nothing else (`src/main.rs:507–521`, gated on
`reveal.is_awake()`), which is §7's requirement. The §2 `scrim.lock_awake` layer is pushed
only while awake. There is **no hardcoded colour or hex anywhere in `src/`** — I grepped;
every colour comes from a `saola_theme` token, and the three locally-composed style helpers
(`awake_scrim`, `disc_style`, `field_style`) are token compositions with the upstream gaps
documented at the site and in Stage 4's handoff. The surface is `Surface::Ink` throughout.
Size-token gaps (avatar diameter, lock field height) are derived from named tokens with the
derivation spelled out — acceptable, and already queued as saola-theme work.

**Subscription and redraw behaviour — clean.** I checked the one thing that looked
suspicious and it is fine: `Clock::subscription` recomputes `duration_until_next_minute()`
on every call, and `iced::time::every`'s recipe hash includes the duration, so the clock's
timer is torn down and recreated whenever `subscription()` is re-evaluated — which, while
`Revealed`, is every second (the reveal tick). That does not cause a missed or stale clock:
every message batch also triggers `ev.request_refresh_all(RefreshRequest::NextFrame)`
(`iced_sessionlock-0.19.1/src/multi_window.rs:662`), and `view` reads `Local::now()` fresh
on each render, so the revealed surface is *more* current, not less. `Temperature`'s
15-minute recipe uses a `const` duration and so is stable across re-evaluation. An
unconfigured temperature module and an `Idle` reveal both return `Subscription::none()`, so
an at-rest surface really does wake only once a minute.

**No source file was modified.** `git status --porcelain` is byte-identical before and
after this review (`M .gitignore`, `D LICENSE`, and the same set of untracked files that
existed at the start). The only new paths are `docs/REVIEW-v0.1.md` and
`.claude/handoffs/handoff_stage_6.attempt_1.md`.

---

## What Stage 7 must do

**Blocking (must-fix before v0.1):**

1. **H-1** — get the wallpaper (and ideally avatar) decode off the pre-lock path, and make
   `contrib/session/`'s before-sleep wiring use a delay inhibitor.
2. **H-2** — ship `contrib/pam/saola-lockscreen` with an `account` stack, and explicitly
   retract Stage 4's `auth include system-auth`-only command.
3. **M-1** — add the `compile_error!` guard against `--release --features dev-unlock`.

**Deferred (document, don't block):** M-2 (fix before a second monitor is ever attached
— and live-test it then), M-3, M-4 (do it with H-2; it is three lines), L-1, L-2, L-3,
L-4, and the README/CHANGELOG lines called for by I-1, I-5 and I-6.

**And before tagging 0.1.0:** the real-PAM round-trip named at the top of this document
still has to happen, from a terminal Jordan drives, against the *fixed* PAM policy — not
the one in Stage 4's handoff.
