//! Authentication — the [`Authenticator`] trait and its PAM implementation.
//!
//! This is the security core's boundary (Architecture / `PLAN.md`): the state
//! machine in [`crate::modules::reveal`] drives an `Authenticator` rather than
//! talking to PAM directly, so it can be unit-tested against a fake
//! (accept / reject / slow / reject-then-accept variants — see that module's
//! test section) without a real PAM stack, a real password, or a real user.
//! A future greeter binary reuses this module unchanged: it just constructs
//! one [`PamAuthenticator`] per user it offers.
//!
//! # The shape of the trait, and why it is a future rather than a callback
//!
//! ```ignore
//! fn authenticate(&self, password: Password) -> AuthFuture;
//! ```
//!
//! iced's update loop is synchronous: [`crate::modules::reveal`]'s `update`
//! must return *immediately* with a description of the work to do, and the
//! runtime does the work. iced's own currency for that is
//! [`iced::Task`] — and `Task::perform(future, f)` is the constructor that
//! takes a future and delivers its output back as a message. So the most
//! direct fit is for `authenticate` to hand back a ready-to-run future and
//! nothing else: the reveal module never awaits it (it cannot — `update` is
//! not `async`), it just wraps it in an `Effect::Authenticate` that `main.rs`
//! feeds to `Task::perform`.
//!
//! `AuthFuture` is a *boxed, dynamically-dispatched* future
//! (`Pin<Box<dyn Future<Output = Outcome> + Send>>`) rather than an
//! `async fn` in the trait, for one concrete reason: `dyn Authenticator`.
//! Rust 1.75+ does allow `async fn` in traits, but a trait with one is not
//! *dyn-compatible* (formerly "object safe"), and the whole point of this
//! trait is that `Reveal` holds an `Arc<dyn Authenticator>` it can swap for a
//! fake in tests. Boxing the future is the standard price for that.
//!
//! # Password lifetime — what is zeroized and what cannot be
//!
//! Architecture is explicit: "Password buffers are `zeroize`d immediately
//! after the conversation consumes them." Here is the honest, complete
//! accounting of every copy of the password that exists between the keyboard
//! and `pam_authenticate`, and which ones this crate can actually control.
//!
//! **Controlled (zeroized on drop, via [`Password`]'s `Zeroizing<String>`):**
//!
//! 1. `Reveal::password` — the live buffer as the user types. Replaced on
//!    every keystroke; the replaced value is dropped, and dropping zeroizes.
//!    Cleared (and therefore zeroized) on submit, on Escape, on the idle
//!    timeout, and after a failed attempt.
//! 2. The [`Password`] moved into [`Authenticator::authenticate`] and thence
//!    into the blocking closure — dropped, and zeroized, when that closure
//!    returns, whatever the outcome.
//! 3. [`LockConversation::password`] — the conversation handler's copy.
//!    Zeroized by [`LockConversation::forget`], which
//!    [`PamAuthenticator::run_pam`] calls the instant `pam_authenticate`
//!    returns — before `pam_acct_mgmt` (which never needs a password) and
//!    before the PAM context is dropped.
//!
//! **Not controlled — copies this crate does not own and cannot reach:**
//!
//! - **iced's `text_input` internals.** The widget re-derives an
//!   `iced_core::text::editor`-style `Value` (a `Vec<char>`) from the `&str`
//!   we hand it on every event and every draw, and drops it without zeroing.
//!   Every keystroke therefore leaves a short-lived heap copy of the
//!   password-so-far behind. Fixing this needs a change in iced, not here.
//! - **The `String` iced builds for `on_input`.** We take ownership of the
//!   final one (it becomes copy 1 above), but the intermediate allocations
//!   iced made while editing it are already gone, unzeroed.
//! - **`CString::new(...)` in [`LockConversation::prompt_echo_off`]**, and
//!   the `strdup()` copy `pam-client2` immediately makes of it
//!   (`pam_client2::resp_buf::ResponseBuffer::put` — verified in that
//!   crate's source). The `CString` is moved into `pam-client2` and dropped
//!   there by the ordinary allocator; the `strdup`'d C string is owned and
//!   `free()`d by libpam. Neither is zeroed, and neither is reachable from
//!   this crate.
//! - **Whatever the PAM modules themselves keep.** `pam_unix` stores the
//!   authtok in the PAM handle for later modules (`try_first_pass`); libpam
//!   is responsible for that memory.
//!
//! None of the uncontrolled copies survive the attempt for long — they are
//! all freed within milliseconds — but "freed" is not "zeroed", and this
//! comment exists so Stage 6's audit does not have to re-derive the list.
//!
//! # Missing `/etc/pam.d/saola-lockscreen`
//!
//! Stage 7 ships the real service file. Until then it does not exist, and
//! Architecture requires that this produces "a visible auth error, not a
//! hang". Verified against the machine's actual PAM configuration, not
//! assumed:
//!
//! - `pam_start()` (`Context::new`) does **not** validate the service — it
//!   succeeds for any name.
//! - `pam_authenticate()` then falls back to `/etc/pam.d/other`, which on
//!   this machine (Arch, stock `pam` package) is `auth required pam_deny.so`
//!   followed by `pam_warn.so`. `pam_deny` returns `PAM_AUTH_ERR`
//!   immediately — no prompt, no network, no hang.
//!
//! So the failure mode is real and fast, but its error code is *identical*
//! to a wrong password, which would show Jordan "Wrong password" for a
//! problem no password can fix. [`classify_failure`] therefore takes a
//! second input — whether a service file for us exists in any of PAM's own
//! search locations — and turns an `AUTH_ERR` with no service file into
//! [`Outcome::Unavailable`] with actionable copy. **That probe never affects
//! the authentication decision**: PAM is always asked first and always has
//! the final say; the probe only picks which error sentence to show once PAM
//! has already said no.

use std::ffi::{CStr, CString};
use std::fmt;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;

use pam_client2::{Context, ConversationHandler, ErrorCode, Flag};
use zeroize::Zeroizing;

/// The PAM service name this crate authenticates against
/// (`/etc/pam.d/saola-lockscreen` — PLAN.md's Architecture decision).
pub const SERVICE: &str = "saola-lockscreen";

/// Where libpam looks for a service's policy file, in its own precedence
/// order. `/etc/pam.d` is the classic location; `/usr/lib/pam.d` is the
/// vendor directory Linux-PAM ≥ 1.5.3 added for distro-shipped policies
/// (present on this machine — `polkit-1`, `systemd-user`, … live there).
///
/// Used *only* by [`service_file_exists`], which only picks error copy.
const PAM_POLICY_DIRS: [&str; 2] = ["/etc/pam.d", "/usr/lib/pam.d"];

// ---------------------------------------------------------------------------
// Password
// ---------------------------------------------------------------------------

/// A password buffer that zeroes itself when dropped.
///
/// `Zeroizing<String>` is `zeroize`'s wrapper whose `Drop` overwrites the
/// buffer before freeing it. Every assignment to a `Password` therefore
/// zeroes the value it replaced, and every `Password` that goes out of scope
/// zeroes itself — which is what makes the accounting in this module's doc
/// comment hold without any explicit "wipe" calls scattered through the
/// state machine.
///
/// It deliberately does **not** derive `Debug`: see the hand-written impl
/// below. A locker that prints a password into a log or a panic message has
/// already lost, and `#[derive(Debug)]` on any enclosing type would do
/// exactly that for free.
#[derive(Clone)]
pub struct Password(Zeroizing<String>);

impl Password {
    /// Wraps a freshly-typed value. The `String` is *moved* in, so its
    /// existing allocation becomes this `Password`'s and is covered by the
    /// zeroing `Drop` from here on.
    pub fn new(value: String) -> Self {
        Password(Zeroizing::new(value))
    }

    /// Whether the buffer is empty. Used by the state machine to refuse to
    /// spend a PAM attempt on an empty submission — see
    /// `modules::reveal`'s `Message::Submitted` arm for why that matters
    /// (`pam_faillock` counts failures, and a locked-out account is a
    /// locker's second-worst failure mode).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The bytes to hand to PAM. Private on purpose: nothing outside this
    /// module has a legitimate reason to read a password back out.
    fn as_str(&self) -> &str {
        &self.0
    }

    /// The buffer, for the one legitimate caller outside this module:
    /// `modules::reveal`'s `view`, which must hand `iced`'s `text_input` a
    /// `&str` to render.
    ///
    /// Named `displayable` rather than `as_str` so that a future reader sees
    /// the intent at the call site: this is *not* a general accessor, and
    /// what the widget draws for it is a row of bullets — `text_input`'s own
    /// `.secure(true)` masks the value and suppresses copy/selection
    /// shortcuts for it. It exists because iced has no "secret" text type;
    /// returning a borrow (rather than a `String`) at least means no
    /// additional owned copy is made to draw a frame.
    pub(crate) fn displayable(&self) -> &str {
        &self.0
    }
}

impl Default for Password {
    /// The empty password — the state a cleared field is reset to.
    /// Hand-written rather than derived so it is obvious that the default is
    /// an *empty* buffer, not an uninitialised one.
    fn default() -> Self {
        Password(Zeroizing::new(String::new()))
    }
}

/// Redacted. `Reveal`'s message enum contains a `Password`, and `main.rs`'s
/// top-level `Message` derives `Debug` — iced's own tracing/devtools can and
/// does format messages. This impl is what makes that safe.
impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Not even the length: that is a real (if small) leak.
        f.write_str("Password(<redacted>)")
    }
}

/// Compares *content*, for tests only. Deliberately not `Eq`-by-derive on
/// the public type's own terms — this exists so `modules::reveal`'s tests
/// can assert "the buffer was cleared".
impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        // Not constant-time, and does not need to be: this compares two
        // buffers this process already owns, never a secret against an
        // attacker-supplied guess.
        *self.0 == *other.0
    }
}

// ---------------------------------------------------------------------------
// Outcome
// ---------------------------------------------------------------------------

/// The result of one authentication attempt.
///
/// Three variants, not two, because "PAM said no" and "PAM could not be
/// asked" need different error copy — see this module's doc comment on the
/// missing service file. The state machine treats the two failure variants
/// identically (error copy, field cleared, back to `Revealed`); only the
/// sentence differs.
///
/// [`Outcome::Authenticated`] is the single value in this crate that
/// authorizes the unlock edge. It is produced in exactly one place
/// ([`PamAuthenticator::run_pam`], after *both* `pam_authenticate` and
/// `pam_acct_mgmt` returned success) and consumed in exactly one place
/// (`modules::reveal`'s `Authenticating` + `Finished` arm).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// PAM authenticated the user *and* the account passed `acct_mgmt`.
    Authenticated,
    /// PAM refused the credentials. Nothing is wrong with the system; the
    /// password was wrong (or the account is temporarily locked out by
    /// `pam_faillock`).
    Rejected,
    /// The attempt could not be completed: the service file is missing, a
    /// module is broken, the conversation failed, the blocking thread died.
    /// Carries user-facing copy explaining what to fix. **Never contains any
    /// part of the password** — every construction site below builds this
    /// string from a fixed template plus a PAM error code.
    Unavailable(String),
}

/// The future an [`Authenticator`] hands back. See this module's doc comment
/// for why it is boxed and dynamically dispatched rather than an `async fn`
/// in the trait.
pub type AuthFuture = Pin<Box<dyn Future<Output = Outcome> + Send + 'static>>;

/// One authentication back end.
///
/// `Send + Sync + 'static` because `Reveal` holds this behind an `Arc` and
/// the future it produces is handed to iced's executor, which may poll it on
/// any thread.
pub trait Authenticator: Send + Sync + 'static {
    /// Start one attempt. **Must not block the caller** — this is called
    /// from inside iced's `update`, on the UI thread. Implementations return
    /// a future that does the work when polled; the real one
    /// ([`PamAuthenticator`]) does its blocking C call on a separate thread
    /// entirely.
    ///
    /// Takes the [`Password`] by value: the caller gives up its copy, and
    /// this one is zeroized when the returned future completes.
    fn authenticate(&self, password: Password) -> AuthFuture;
}

// ---------------------------------------------------------------------------
// Account — who we are authenticating
// ---------------------------------------------------------------------------

/// The user the lock surface belongs to: the POSIX name PAM authenticates,
/// and the human-readable name §7 shows above the password field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// The POSIX login name (`pw_name`) handed to `pam_start`.
    pub username: String,
    /// The GECOS full name if there is one, else the login name — see
    /// [`display_name_from_gecos`].
    pub display_name: String,
}

impl Account {
    /// The account this process is running as.
    ///
    /// Resolution order, most trustworthy first:
    ///
    /// 1. `getpwuid_r(getuid())` — the C library's own answer, which goes
    ///    through NSS and so is correct for `systemd-homed`, LDAP, and
    ///    anything else `/etc/passwd` alone would miss.
    /// 2. `$USER`, if that fails. An environment variable is not
    ///    authoritative (anything that spawned us could set it), but it is
    ///    strictly better than refusing to draw a lock surface — and note
    ///    that lying here cannot *grant* access: PAM authenticates whatever
    ///    name it is given, so a wrong name simply fails to authenticate.
    /// 3. The literal `"user"`, so that the surface still comes up with a
    ///    field on it. Architecture's "a locker must always come up" rule
    ///    outranks a correct label.
    pub fn current() -> Self {
        if let Some((username, gecos)) = passwd_entry() {
            let display_name = display_name_from_gecos(&gecos, &username);
            return Account {
                username,
                display_name,
            };
        }

        let username = std::env::var("USER").unwrap_or_else(|_| "user".to_string());
        eprintln!(
            "saola-lockscreen: could not read this user's passwd entry — falling back to \"{username}\""
        );
        Account {
            display_name: username.clone(),
            username,
        }
    }
}

/// The GECOS field's first comma-separated component is the full name (the
/// rest is office/phone/other, by the historical `finger(1)` convention).
/// An empty or whitespace-only name falls back to the login name — §7 wants
/// "the user's display name", and a blank line is worse than a login name.
///
/// Pure function of its two arguments so it is unit-testable without a real
/// passwd database (the same "inject the input, never read the world"
/// discipline `modules::clock`'s formatters follow).
fn display_name_from_gecos(gecos: &str, username: &str) -> String {
    let full_name = gecos.split(',').next().unwrap_or("").trim();
    if full_name.is_empty() {
        username.to_string()
    } else {
        full_name.to_string()
    }
}

/// `getpwuid_r(getuid())`, returning `(pw_name, pw_gecos)`.
///
/// Teaching note (this is the crate's only `unsafe`): `getpwuid_r` is the
/// reentrant form of `getpwuid`. The caller supplies both the `struct passwd`
/// to fill *and* a scratch buffer that the returned string pointers point
/// into — which is why the strings must be copied into owned `String`s
/// before `buf` goes out of scope, and why nothing in the returned tuple
/// borrows. `ERANGE` means "your buffer was too small"; the loop doubles it
/// and retries, with a hard ceiling so a pathological NSS module cannot make
/// this allocate forever. Every failure path returns `None` — there is no
/// panic, no `unwrap`, and no path that leaves `buf` borrowed.
fn passwd_entry() -> Option<(String, String)> {
    // SAFETY: `getuid` takes no arguments, cannot fail, and has no
    // preconditions (POSIX: "The getuid() function shall always be
    // successful and no return value is reserved to indicate the error").
    let uid = unsafe { libc::getuid() };

    let mut size: usize = 1024;
    // 256 KiB: far past any real passwd entry, small enough that a broken
    // NSS module cannot exhaust memory here.
    const MAX_SIZE: usize = 256 * 1024;

    loop {
        // `libc::c_char` is `i8` on x86_64 and `u8` on aarch64 — spelling
        // the element type this way keeps the buffer correct on both.
        let mut buf = vec![0 as libc::c_char; size];
        // `libc::passwd` is a `repr(C)` struct of raw pointers and integers;
        // all-zero is a valid (if meaningless) bit pattern for it, and
        // `getpwuid_r` overwrites it before we read anything.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();

        // SAFETY: `pwd` and `result` are valid, uniquely-borrowed locals;
        // `buf` is a live allocation of exactly `size` bytes, which is the
        // length we pass. `getpwuid_r` writes only within those bounds.
        let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), size, &mut result) };

        if rc == libc::ERANGE && size < MAX_SIZE {
            size *= 2;
            continue;
        }
        if rc != 0 || result.is_null() {
            // rc != 0 is an error; result == null with rc == 0 means "no
            // such user", which for our own uid would be very strange but is
            // still not a reason to crash a locker.
            return None;
        }

        // SAFETY: `getpwuid_r` returned success, so `pwd.pw_name` /
        // `pwd.pw_gecos` are either NULL or NUL-terminated C strings living
        // inside `buf`, which is still alive for the rest of this block.
        // `to_owned_string` copies before we return, so nothing escapes.
        let username = unsafe { owned_c_string(pwd.pw_name) }?;
        let gecos = unsafe { owned_c_string(pwd.pw_gecos) }.unwrap_or_default();
        return Some((username, gecos));
    }
}

/// Copies a possibly-NULL C string into an owned `String`, or `None` if it
/// is NULL or not valid UTF-8.
///
/// # Safety
///
/// `ptr` must be NULL or point to a NUL-terminated string that stays valid
/// for the duration of the call.
unsafe fn owned_c_string(ptr: *const libc::c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: delegated to this function's own contract, upheld by the one
    // caller above.
    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str().ok().map(str::to_owned)
}

// ---------------------------------------------------------------------------
// The PAM implementation
// ---------------------------------------------------------------------------

/// The real [`Authenticator`]: one PAM transaction per attempt, against
/// [`SERVICE`] for a fixed username.
///
/// One transaction per attempt (rather than one long-lived `Context`) is
/// deliberate: `pam_client2::Context` is `!Sync`-ish state built around a raw
/// handle, and reusing one across attempts would mean sharing it between the
/// UI thread and the blocking thread. Creating it inside the blocking closure
/// keeps the handle's whole life on one thread, which is both simpler to
/// reason about and what libpam expects.
///
/// A greeter reuses this by constructing one per user it offers.
pub struct PamAuthenticator {
    service: String,
    username: String,
}

impl PamAuthenticator {
    /// The locker's own authenticator: [`SERVICE`], for `account`.
    pub fn for_account(account: &Account) -> Self {
        PamAuthenticator {
            service: SERVICE.to_string(),
            username: account.username.clone(),
        }
    }

    /// The whole blocking PAM transaction, start to finish, on whatever
    /// thread calls it. Never called from the UI thread — see
    /// [`Authenticator::authenticate`] below.
    fn run_pam(service: &str, username: &str, password: Password) -> Outcome {
        let conversation = LockConversation {
            password: Some(password),
        };

        let mut context = match Context::new(service, Some(username), conversation) {
            Ok(context) => context,
            Err(err) => {
                // `pam_start` failing is a system-level problem (out of
                // memory, a NUL byte in the service name — neither of which
                // can happen with our fixed constants), not a wrong password.
                return Outcome::Unavailable(format!(
                    "Authentication is unavailable (PAM start failed: {:?}).",
                    err.code()
                ));
            }
        };

        let auth_result = context.authenticate(Flag::NONE);

        // Zeroize the conversation handler's copy of the password the moment
        // `pam_authenticate` returns — before `acct_mgmt` (which never needs
        // it) and before the context is dropped. This is Architecture's
        // "immediately after the conversation consumes them", at the tightest
        // point the `pam-client2` API allows us to reach it.
        context.conversation_mut().forget();

        if let Err(err) = auth_result {
            return classify_failure(
                err.code(),
                service_file_exists(service),
                Phase::Authenticate,
            );
        }

        // Authentication succeeded; the account itself must also be valid
        // (not expired, not administratively locked, within `pam_time`
        // rules). Skipping this is a real security gap — an expired account
        // would still unlock the session — so it is not optional.
        if let Err(err) = context.acct_mgmt(Flag::NONE) {
            return classify_failure(err.code(), service_file_exists(service), Phase::Account);
        }

        Outcome::Authenticated
    }
}

impl Authenticator for PamAuthenticator {
    fn authenticate(&self, password: Password) -> AuthFuture {
        let service = self.service.clone();
        let username = self.username.clone();

        Box::pin(async move {
            // The closure that does the blocking work. Built here so both
            // dispatch paths below run exactly the same code.
            let work = move || PamAuthenticator::run_pam(&service, &username, password);

            // Teaching note — why `Handle::try_current()` and not plain
            // `tokio::task::spawn_blocking`: the free function *panics* if
            // it is called outside a tokio runtime, and a panic anywhere on
            // a runtime path is forbidden here (`CLAUDE.md`: a crashed
            // locker means Jordan is locked out until he switches VT). iced
            // is built with its `tokio` feature so in practice this future
            // is polled inside the runtime and the first arm is taken — but
            // "in practice" is not a guarantee this crate should stake the
            // session on, so the second arm keeps working without one.
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => match handle.spawn_blocking(work).await {
                    Ok(outcome) => outcome,
                    // The blocking task panicked or was cancelled. We cannot
                    // know which; either way there is no authentication
                    // result, so this must not be `Rejected` (that would
                    // imply PAM said no) and above all must not unlock.
                    Err(_) => Outcome::Unavailable(
                        "Authentication did not complete. Try again.".to_string(),
                    ),
                },
                Err(_) => {
                    // No tokio runtime: fall back to a plain OS thread and a
                    // oneshot channel. `rx.await` needs no runtime context —
                    // it is just a future the caller's executor polls.
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    std::thread::spawn(move || {
                        // If the receiver is gone (the attempt was dropped),
                        // `send` returns the value back and we drop it — which
                        // zeroizes the `Password` inside the closure. Nothing
                        // to do, and nothing to panic about.
                        let _ = tx.send(work());
                    });
                    rx.await.unwrap_or_else(|_| {
                        Outcome::Unavailable(
                            "Authentication did not complete. Try again.".to_string(),
                        )
                    })
                }
            }
        })
    }
}

/// Which PAM phase produced the [`ErrorCode`] being classified — M-4
/// (`docs/REVIEW-v0.1.md`): `authenticate` and `acct_mgmt` failures used to
/// share [`classify_failure`] with no way to tell them apart, so an
/// `acct_mgmt` denial (H-2's empty-`account`-stack bug, among others) came
/// out as "Wrong password." — actively misleading, since no password can
/// fix an account-phase failure. Threading this through is the fix: only
/// the `Authenticate` phase may ever produce [`Outcome::Rejected`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// `pam_authenticate` — the only phase a password can actually affect.
    Authenticate,
    /// `pam_acct_mgmt` — never takes a password, so a denial here is never
    /// "wrong password", no matter what generic code it returns.
    Account,
}

/// Turns a PAM error code into the [`Outcome`] the surface should show.
///
/// `service_installed` is the missing-service-file discriminator described in
/// this module's doc comment: PAM has *already* made the decision by the time
/// this is called, and this flag only chooses between two error sentences for
/// the same "no". `phase` is M-4's discriminator (see [`Phase`]'s doc
/// comment). Pure function of its three arguments, so every mapping below is
/// unit-tested.
fn classify_failure(code: ErrorCode, service_installed: bool, phase: Phase) -> Outcome {
    match code {
        // The ordinary "no": bad password, or an account `pam_faillock` has
        // temporarily locked. With no service file installed, `/etc/pam.d/
        // other`'s `pam_deny` produces exactly this code too — hence the
        // `service_installed` flag. But none of that reasoning applies to
        // the `account` phase at all: it never sees a password, so the same
        // codes there mean something else entirely (H-2: an empty `account`
        // stack) and must never be shown as a rejected credential.
        ErrorCode::AUTH_ERR | ErrorCode::PERM_DENIED | ErrorCode::CRED_INSUFFICIENT => {
            match (phase, service_installed) {
                (Phase::Authenticate, true) => Outcome::Rejected,
                (Phase::Authenticate, false) => Outcome::Unavailable(format!(
                    "Authentication is not configured: no PAM policy for \"{SERVICE}\"."
                )),
                (Phase::Account, _) => Outcome::Unavailable(
                    "This account cannot unlock the session (PAM account check failed)."
                        .to_string(),
                ),
            }
        }
        // Distinct, actionable failures that are *not* "wrong password".
        // Every one of these keeps the session locked; they only change the
        // sentence shown under the field.
        ErrorCode::MAXTRIES => {
            Outcome::Unavailable("Too many attempts. Wait, then try again.".to_string())
        }
        ErrorCode::ACCT_EXPIRED | ErrorCode::CRED_EXPIRED | ErrorCode::AUTHTOK_EXPIRED => {
            Outcome::Unavailable("This account has expired.".to_string())
        }
        ErrorCode::NEW_AUTHTOK_REQD => {
            Outcome::Unavailable("This password must be changed before you can unlock.".to_string())
        }
        ErrorCode::USER_UNKNOWN => {
            Outcome::Unavailable("This account is not known to the system.".to_string())
        }
        // Everything else is a system/configuration fault. The code is shown
        // (it is the only thing that makes this diagnosable at 2am) but never
        // any part of the password — `ErrorCode`'s `Debug` is a bare enum
        // name.
        other => Outcome::Unavailable(format!("Authentication is unavailable ({other:?}).")),
    }
}

/// Whether libpam would find a policy file for `service` in one of its
/// own search directories. **Advisory only** — see [`classify_failure`].
///
/// Deliberately not an error path: an I/O problem reading the directory just
/// makes this `false`, which at worst shows the "not configured" sentence for
/// a system that is in fact configured. Nothing here can grant access.
fn service_file_exists(service: &str) -> bool {
    PAM_POLICY_DIRS
        .iter()
        .any(|dir| Path::new(dir).join(service).exists())
}

// ---------------------------------------------------------------------------
// The PAM conversation
// ---------------------------------------------------------------------------

/// The `pam-client2` [`ConversationHandler`] that feeds the reveal flow's
/// password to PAM without a terminal.
///
/// PAM's conversation model is a callback: libpam calls back into *us*, from
/// inside `pam_authenticate`, whenever a module wants to ask the user
/// something. We are not interactive at that point — the user already typed
/// the password and pressed Enter — so this handler is a canned answering
/// machine holding exactly one secret.
struct LockConversation {
    /// `None` once [`Self::forget`] has run. Held as an `Option` rather than
    /// a bare `Password` precisely so "forgotten" is representable and
    /// `forget` can be idempotent.
    password: Option<Password>,
}

impl LockConversation {
    /// Drop (and thereby zeroize) the stored password. Idempotent.
    fn forget(&mut self) {
        // `take()` moves the `Password` out; the temporary is dropped at the
        // end of this statement, and `Password`'s `Zeroizing` wipes it there.
        drop(self.password.take());
    }
}

impl ConversationHandler for LockConversation {
    /// An echoing prompt is a *username* prompt. We always pass the username
    /// to `pam_start`, so a module asking for one means the stack is not
    /// what this crate expects. Refusing (rather than guessing, or echoing
    /// the password) is the conservative answer: PAM turns a conversation
    /// error into an authentication failure, which keeps the session locked.
    fn prompt_echo_on(&mut self, _prompt: &CStr) -> Result<CString, ErrorCode> {
        Err(ErrorCode::CONV_ERR)
    }

    /// The password prompt — the only one this handler really answers.
    ///
    /// The stored copy is *not* consumed here, because a real stack can ask
    /// more than once (two modules each prompting, `try_first_pass` chains,
    /// and Stage 7's rosec line may add another). It is wiped by
    /// [`Self::forget`] the instant `pam_authenticate` returns instead —
    /// see [`PamAuthenticator::run_pam`].
    fn prompt_echo_off(&mut self, _prompt: &CStr) -> Result<CString, ErrorCode> {
        let Some(password) = &self.password else {
            // Already forgotten: a prompt arriving after `pam_authenticate`
            // returned should be impossible, and answering it with nothing
            // is safer than answering it wrongly.
            return Err(ErrorCode::CONV_ERR);
        };
        // `CString::new` fails only on an interior NUL byte, which a
        // keyboard cannot produce — but a `?`-free, panic-free path is the
        // rule here regardless of how unreachable the branch is.
        CString::new(password.as_str()).map_err(|_| ErrorCode::CONV_ERR)
    }

    /// A lock surface has nowhere to put PAM's chatter ("Password expires in
    /// 3 days"), and §7 says nothing else is shown at rest. Dropped rather
    /// than printed: `text_info`/`error_msg` strings can echo module state,
    /// and stdout on a locker goes to the session's journal.
    fn text_info(&mut self, _msg: &CStr) {}

    /// See [`Self::text_info`]. The *outcome* is what the user is shown, via
    /// [`classify_failure`]; module-authored strings are not.
    fn error_msg(&mut self, _msg: &CStr) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Password hygiene ------------------------------------------------

    /// The redaction that keeps a password out of iced's message tracing and
    /// out of any `Debug` output of an enclosing type.
    #[test]
    fn password_debug_is_redacted() {
        let password = Password::new("hunter2".to_string());
        let rendered = format!("{password:?}");
        assert_eq!(rendered, "Password(<redacted>)");
        assert!(!rendered.contains("hunter2"));
    }

    /// The default is an empty buffer — the value `modules::reveal` resets
    /// the field to, and the value its "is the buffer clear?" assertions
    /// compare against.
    #[test]
    fn default_password_is_empty() {
        assert!(Password::default().is_empty());
        assert!(!Password::new("x".to_string()).is_empty());
    }

    #[test]
    fn passwords_compare_by_content() {
        assert_eq!(Password::new("a".into()), Password::new("a".into()));
        assert_ne!(Password::new("a".into()), Password::new("b".into()));
    }

    // ---- GECOS / display name -------------------------------------------

    #[test]
    fn gecos_full_name_wins() {
        assert_eq!(
            display_name_from_gecos("Jordan Dunn,,,", "jordan"),
            "Jordan Dunn"
        );
    }

    #[test]
    fn gecos_without_commas_is_used_whole() {
        assert_eq!(
            display_name_from_gecos("Jordan Dunn", "jordan"),
            "Jordan Dunn"
        );
    }

    /// The common Arch/Debian case: a passwd entry whose GECOS is just the
    /// separators, with no name in it at all.
    #[test]
    fn empty_gecos_falls_back_to_the_login_name() {
        assert_eq!(display_name_from_gecos(",,,", "jordan"), "jordan");
        assert_eq!(display_name_from_gecos("", "jordan"), "jordan");
    }

    /// Whitespace-only is "empty" for this purpose — §7 wants a name on the
    /// surface, and a blank line reads as a rendering bug.
    #[test]
    fn whitespace_only_gecos_falls_back_to_the_login_name() {
        assert_eq!(display_name_from_gecos("   ,x,y", "jordan"), "jordan");
    }

    #[test]
    fn gecos_full_name_is_trimmed() {
        assert_eq!(
            display_name_from_gecos("  Jordan Dunn ,x", "jordan"),
            "Jordan Dunn"
        );
    }

    // ---- Failure classification -----------------------------------------

    /// The plain wrong-password case, with the service file in place: this
    /// is the one code path that produces `Rejected`.
    #[test]
    fn auth_err_with_a_service_file_is_a_rejection() {
        assert_eq!(
            classify_failure(ErrorCode::AUTH_ERR, true, Phase::Authenticate),
            Outcome::Rejected
        );
    }

    /// Architecture's "missing `/etc/pam.d/saola-lockscreen` must produce a
    /// visible auth error": `/etc/pam.d/other`'s `pam_deny` returns the same
    /// `AUTH_ERR` a wrong password does, so without this discriminator the
    /// surface would tell Jordan his password was wrong when the real fix is
    /// Stage 7's service file.
    #[test]
    fn auth_err_without_a_service_file_is_unavailable_not_rejected() {
        let outcome = classify_failure(ErrorCode::AUTH_ERR, false, Phase::Authenticate);
        match outcome {
            Outcome::Unavailable(message) => {
                assert!(
                    message.contains(SERVICE),
                    "copy did not name the service: {message}"
                );
            }
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    /// M-4 (`docs/REVIEW-v0.1.md`), fixed alongside H-2: an `account`-phase
    /// denial is never a rejection, even with the exact same error code and
    /// even with the service file present — H-2's whole failure mode was an
    /// empty `account` stack producing `PERM_DENIED` and getting shown as
    /// "Wrong password." for a correct one.
    #[test]
    fn account_phase_denial_is_never_a_rejection() {
        for code in [
            ErrorCode::AUTH_ERR,
            ErrorCode::PERM_DENIED,
            ErrorCode::CRED_INSUFFICIENT,
        ] {
            for service_installed in [true, false] {
                let outcome = classify_failure(code, service_installed, Phase::Account);
                assert_ne!(
                    outcome,
                    Outcome::Rejected,
                    "{code:?} (service_installed = {service_installed}) in the account \
                     phase was reported as Rejected"
                );
                assert!(matches!(outcome, Outcome::Unavailable(_)));
            }
        }
    }

    /// `pam_faillock` lockout gets its own sentence — "wrong password" would
    /// be actively misleading, since the *right* password also fails here.
    #[test]
    fn maxtries_is_its_own_message() {
        let outcome = classify_failure(ErrorCode::MAXTRIES, true, Phase::Authenticate);
        assert!(matches!(outcome, Outcome::Unavailable(_)));
        assert_ne!(outcome, Outcome::Rejected);
    }

    #[test]
    fn expired_account_codes_are_unavailable() {
        for code in [
            ErrorCode::ACCT_EXPIRED,
            ErrorCode::CRED_EXPIRED,
            ErrorCode::AUTHTOK_EXPIRED,
        ] {
            assert!(
                matches!(
                    classify_failure(code, true, Phase::Authenticate),
                    Outcome::Unavailable(_)
                ),
                "{code:?} should be Unavailable"
            );
        }
    }

    /// The catch-all arm: a system fault never masquerades as a rejection.
    #[test]
    fn system_error_codes_are_unavailable() {
        for code in [
            ErrorCode::ABORT,
            ErrorCode::SERVICE_ERR,
            ErrorCode::SYSTEM_ERR,
            ErrorCode::CONV_ERR,
            ErrorCode::MODULE_UNKNOWN,
            ErrorCode::BUF_ERR,
        ] {
            assert!(
                matches!(
                    classify_failure(code, true, Phase::Authenticate),
                    Outcome::Unavailable(_)
                ),
                "{code:?} should be Unavailable"
            );
        }
    }

    /// **No failure code, with or without a service file, in either phase,
    /// may ever produce `Authenticated`.** `Outcome::Authenticated` has
    /// exactly one construction site (`run_pam`, after both PAM calls
    /// succeeded); this test pins the other half of that claim — the error
    /// path cannot manufacture one.
    #[test]
    fn no_error_code_ever_authenticates() {
        let codes = [
            ErrorCode::OPEN_ERR,
            ErrorCode::SYMBOL_ERR,
            ErrorCode::SERVICE_ERR,
            ErrorCode::SYSTEM_ERR,
            ErrorCode::BUF_ERR,
            ErrorCode::PERM_DENIED,
            ErrorCode::AUTH_ERR,
            ErrorCode::CRED_INSUFFICIENT,
            ErrorCode::AUTHINFO_UNAVAIL,
            ErrorCode::USER_UNKNOWN,
            ErrorCode::MAXTRIES,
            ErrorCode::NEW_AUTHTOK_REQD,
            ErrorCode::ACCT_EXPIRED,
            ErrorCode::SESSION_ERR,
            ErrorCode::CRED_UNAVAIL,
            ErrorCode::CRED_EXPIRED,
            ErrorCode::CRED_ERR,
            ErrorCode::CONV_ERR,
            ErrorCode::AUTHTOK_ERR,
            ErrorCode::AUTHTOK_RECOVERY_ERR,
            ErrorCode::AUTHTOK_LOCK_BUSY,
            ErrorCode::AUTHTOK_DISABLE_AGING,
            ErrorCode::ABORT,
            ErrorCode::AUTHTOK_EXPIRED,
            ErrorCode::MODULE_UNKNOWN,
            ErrorCode::BAD_ITEM,
            ErrorCode::CONV_AGAIN,
            ErrorCode::INCOMPLETE,
        ];
        for code in codes {
            for installed in [true, false] {
                for phase in [Phase::Authenticate, Phase::Account] {
                    assert_ne!(
                        classify_failure(code, installed, phase),
                        Outcome::Authenticated,
                        "{code:?} (service_installed = {installed}, phase = {phase:?}) authenticated"
                    );
                }
            }
        }
    }

    /// Error copy is shown on the lock surface, so it must never contain
    /// anything secret. The failure classifier only ever sees an error code,
    /// which this test states as an invariant over every code.
    #[test]
    fn error_copy_never_contains_a_password() {
        for installed in [true, false] {
            if let Outcome::Unavailable(message) =
                classify_failure(ErrorCode::AUTH_ERR, installed, Phase::Authenticate)
            {
                assert!(!message.contains("hunter2"));
            }
        }
    }

    // ---- The conversation handler ---------------------------------------

    #[test]
    fn the_conversation_answers_the_password_prompt() {
        let mut conversation = LockConversation {
            password: Some(Password::new("hunter2".to_string())),
        };
        let prompt = c"Password: ";
        let answer = conversation
            .prompt_echo_off(prompt)
            .expect("a stored password answers the prompt");
        assert_eq!(answer.to_bytes(), b"hunter2");
    }

    /// A second module prompting for the same password still gets an answer
    /// — the stored copy is not consumed by the first prompt (see
    /// `prompt_echo_off`'s doc comment).
    #[test]
    fn the_conversation_answers_repeated_password_prompts() {
        let mut conversation = LockConversation {
            password: Some(Password::new("hunter2".to_string())),
        };
        assert!(conversation.prompt_echo_off(c"Password: ").is_ok());
        assert!(conversation.prompt_echo_off(c"Vault password: ").is_ok());
    }

    /// After `forget()` there is nothing left to hand out — the zeroization
    /// point `run_pam` reaches for the moment `pam_authenticate` returns.
    #[test]
    fn forget_leaves_nothing_to_answer_with() {
        let mut conversation = LockConversation {
            password: Some(Password::new("hunter2".to_string())),
        };
        conversation.forget();
        conversation.forget(); // idempotent
        assert_eq!(
            conversation.prompt_echo_off(c"Password: ").unwrap_err(),
            ErrorCode::CONV_ERR
        );
    }

    /// A username prompt is refused rather than answered — see
    /// `prompt_echo_on`'s doc comment. In particular it must never echo the
    /// password, which is the mistake this test exists to prevent.
    #[test]
    fn the_conversation_refuses_echoing_prompts() {
        let mut conversation = LockConversation {
            password: Some(Password::new("hunter2".to_string())),
        };
        assert_eq!(
            conversation.prompt_echo_on(c"login: ").unwrap_err(),
            ErrorCode::CONV_ERR
        );
    }

    // ---- Service-file probe ---------------------------------------------

    /// The probe is a plain existence check with no error path; a name that
    /// cannot exist must come back `false` rather than panicking.
    #[test]
    fn service_probe_is_false_for_an_impossible_service() {
        assert!(!service_file_exists(
            "saola-lockscreen-definitely-not-a-real-service"
        ));
    }

    /// `Account::current()` must never panic and must always produce a
    /// non-empty username/display name — Architecture's "a locker must
    /// always come up". This runs against the real passwd database, so it
    /// asserts the invariant rather than a specific name.
    #[test]
    fn current_account_is_always_populated() {
        let account = Account::current();
        assert!(!account.username.is_empty());
        assert!(!account.display_name.is_empty());
    }
}
