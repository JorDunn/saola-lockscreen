//! Lock-surface modules — one file per §7 element, mirroring the panel's
//! module pattern (a state struct, `view(&Theme) -> Element`, and, where a
//! module needs to tick, a `subscription() -> Subscription<Message>`).
//!
//! Stage 1 left this empty on purpose: each module lands with the stage
//! that implements it.
//!   - `clock` (Stage 3, done): the centred clock/date, copied from the
//!     panel's minute-aligned subscription pattern.
//!   - `reveal` (Stage 4, done): the Idle → Revealed → Authenticating →
//!     Unlock state machine (Architecture's security core). Unlike the
//!     other modules it returns a plain `Effect` value from `update`
//!     rather than an `iced::Task`, so that the unlock edge is a value
//!     `main.rs` translates in exactly one place — see that module's doc
//!     comment.
//!   - `temperature` (Stage 5, done): Open-Meteo outdoor temperature,
//!     hidden entirely when unconfigured or on fetch/parse failure. Copies
//!     `reveal`'s `Effect`-return shape for the same reason (its `update`
//!     must stay synchronous) and `auth`'s blocking-call dispatch pattern
//!     for the fetch itself (`ureq` is blocking, like `pam-client2`).

pub mod clock;
pub mod reveal;
pub mod temperature;
