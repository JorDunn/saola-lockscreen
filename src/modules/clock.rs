//! The lock surface's centred clock + date (style guide §7 "Lock surface";
//! §3's "Lock clock" type row). Stage 3 of PLAN.md.
//!
//! Copies the panel's `modules::clock` pattern (stateless module struct,
//! `view(&Theme) -> Element`, a minute-aligned `subscription()`) and its
//! testability rule verbatim: `view` reads `Local::now()` once per render
//! and hands the timestamp to a pure formatting function, so the format can
//! be unit-tested without depending on the wall clock or its timezone (see
//! the panel's `clock.rs` doc comment for the fuller rationale — the
//! "teaching note" it credits this to).
//!
//! # Layout, versus the panel's clock
//!
//! The panel's clock renders one line, `"date · time"`, sized for a 48px
//! bar. Here the two are stacked instead — a big centred clock with the
//! date on its own line below (§7: "Clock, date, temperature centred") —
//! so this module owns a small [`Column`](iced::widget::Column), not a
//! single `text!`. The temperature line (Stage 5) is **not** built here:
//! `main.rs`'s `Lockscreen::view` wraps this module's column in the outer
//! `container().center_x(Fill).center_y(Fill)` that actually centers it on
//! the lock surface, and that is also where a third sibling widget lands
//! once `modules::temperature` exists — see that function's doc comment for
//! the exact slot. This module only owns the clock and date lines' layout
//! relative to each other, never their position on the screen.
//!
//! # Type choices (§3 — recorded here for the greeter, which reuses them)
//!
//! - **Clock**: `typography.size.lock_clock` (168px), the display (serif)
//!   face at its `weight.display` — the one row the style guide's own scale
//!   table names explicitly ("Lock clock | Serif 400 · 168px · -0.025em |
//!   Tabular numerals"). Tabular numerals are free: see `saola-theme`'s
//!   `docs/decisions/tabular-numerals.md` — IBM Plex's lining figures are
//!   already fixed-width, so no OpenType feature is needed (iced 0.14
//!   cannot set one regardless — same doc). The `-0.025em` letter-spacing
//!   in that row is **not applied**: `iced_core::widget::text::Text`
//!   (`iced_core-0.14.0/src/widget/text.rs`) has no letter-spacing builder
//!   method in 0.14 — a real API gap, not an oversight, left for a future
//!   iced upgrade the same way the tabular-numerals decision doc leaves
//!   `tnum` for one.
//! - **Date**: the style guide's §3 scale table has no row for a
//!   lock-screen date line — only "Lock clock" is specified there. This
//!   module picks `typography.size.panel_heading` (22px, the low end of
//!   its documented 22–30px range) in the **same display (serif) face** as
//!   the clock, at `on_ink.secondary` (de-emphasized, unlike the clock's
//!   full-emphasis `on_ink.primary`) — a quiet companion line, not a
//!   second focal point. Using serif for both stays within the guide's
//!   "the serif appears at most twice per screen" budget for the at-rest
//!   lock surface (clock + date = 2 uses) — worth re-checking if Stage 4's
//!   reveal flow wants a third serif element on the *revealed* state. Sans
//!   was the other real option here; there is no written rule forcing
//!   serif on the date line, only the absence of a dedicated "date" row to
//!   defer to. If this reads wrong once it's on screen, it is a one-line
//!   change (swap `display_font` for `saola_theme::convert::ui_font_regular`
//!   on the date `text` only), not a structural one.
//! - **Date format**: reuses the panel's exact `"%a %d %b"` pattern (see
//!   `saola-panel/src/modules/clock.rs::format_clock`) rather than
//!   inventing a new one, per this stage's instruction to reuse the
//!   panel's formatting choices. The clock line drops the panel's
//!   `"%H:%M"` format's `"date · "` prefix (the date has its own line
//!   here) but keeps the exact same 24-hour, zero-padded shape.

use std::time::Duration;

use chrono::{DateTime, Local, Timelike};
use iced::widget::{column, text};
use iced::{Center, Element};
use saola_theme::convert::{display_font, ColorExt};
use saola_theme::Theme;

/// The clock module's own message type, nested into `main.rs`'s outer
/// `Message` enum as `Message::Clock` — the same per-module-enum pattern
/// the panel's clock module doc comment explains (`main.rs` never inspects
/// `Tick` itself; it just unwraps the outer variant and falls through to
/// `Task::none()`, since this module has nothing to store — see `main.rs`'s
/// `update`).
#[derive(Debug, Clone)]
pub enum Message {
    Tick,
}

/// Clock module state. Empty, like the panel's: nothing to cache between
/// renders — every render reads the system clock fresh.
pub struct Clock;

impl Clock {
    /// The centred clock + date column (§7). See the module doc comment's
    /// "Layout" and "Type choices" sections for why the two lines are
    /// stacked here, and exactly which tokens each one uses.
    pub fn view(&self, theme: &Theme) -> Element<'_, Message> {
        let now = Local::now();
        column![
            text(format_clock(now))
                .font(display_font(theme))
                .size(theme.typography.size.lock_clock)
                .color(theme.on_ink.primary.into_iced()),
            text(format_date(now))
                .font(display_font(theme))
                .size(theme.typography.size.panel_heading)
                .color(theme.on_ink.secondary.into_iced()),
        ]
        .align_x(Center)
        .into()
    }

    /// A tick roughly once a minute, timed to land near the wall-clock
    /// minute boundary — copied verbatim from the panel's
    /// `modules::clock::Clock::subscription` (see that function's doc
    /// comment for why recomputing the duration fresh from `Local::now()`
    /// on every call is what makes the timer self-correcting, rather than
    /// needing separate first-tick / steady-state phases). The tick
    /// carries no data; its only job is to wake the runtime so `view`
    /// re-reads the clock.
    pub fn subscription(&self) -> iced::Subscription<Message> {
        iced::time::every(duration_until_next_minute()).map(|_instant| Message::Tick)
    }
}

/// Seconds remaining until the next minute boundary (e.g. :37 past the
/// minute returns 23s). Never zero — landing exactly on the boundary
/// rounds up to a full 60s rather than arming a zero-duration timer. Copied
/// verbatim from the panel's clock module.
fn duration_until_next_minute() -> Duration {
    let seconds_into_minute = Local::now().second() as u64;
    Duration::from_secs(60 - (seconds_into_minute % 60))
}

/// The big clock line: 24-hour, zero-padded `"HH:MM"` — the same time
/// shape the panel's bar clock uses, just without its `"date · "` prefix
/// (the date is [`format_date`]'s own line here, not appended to this
/// string). Pure function of `now` — no `Local::now()` call inside — which
/// is what makes it unit-testable without depending on the system clock or
/// its timezone (see the module doc comment's testability note).
fn format_clock(now: DateTime<Local>) -> String {
    now.format("%H:%M").to_string()
}

/// The date line: short weekday, zero-padded day, short month — identical
/// to the panel's own date format (`"%a %d %b"`), reused rather than
/// invented, per this stage's instruction to reuse the panel's formatting
/// choices. Pure function of `now`, for the same reason as [`format_clock`].
fn format_date(now: DateTime<Local>) -> String {
    now.format("%a %d %b").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn formats_24_hour_time_with_zero_padding() {
        let now = Local.with_ymd_and_hms(2026, 7, 26, 9, 5, 0).unwrap();
        assert_eq!(format_clock(now), "09:05");
    }

    #[test]
    fn formats_midnight_and_noon() {
        let midnight = Local.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let noon = Local.with_ymd_and_hms(2026, 1, 1, 12, 30, 0).unwrap();
        assert_eq!(format_clock(midnight), "00:00");
        assert_eq!(format_clock(noon), "12:30");
    }

    /// The clock line never carries a date — proves the panel's `"date · "`
    /// prefix was dropped deliberately (see the module doc comment), not
    /// forgotten.
    #[test]
    fn clock_line_has_no_date_prefix() {
        let now = Local.with_ymd_and_hms(2026, 7, 26, 14, 5, 0).unwrap();
        assert_eq!(format_clock(now), "14:05");
    }

    #[test]
    fn formats_short_weekday_day_and_month() {
        let now = Local.with_ymd_and_hms(2026, 7, 26, 14, 5, 0).unwrap();
        assert_eq!(format_date(now), "Sun 26 Jul");
    }

    #[test]
    fn pads_single_digit_day() {
        let now = Local.with_ymd_and_hms(2026, 1, 5, 9, 3, 0).unwrap();
        assert_eq!(format_date(now), "Mon 05 Jan");
    }
}
