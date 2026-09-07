//! `~/.config/saola/lockscreen.toml` — the locker's optional config file.
//!
//! Same resolution order and resilience posture as the panel's config
//! loader (see `saola-panel`'s `src/config.rs` and its `CLAUDE.md`), now in
//! TOML: the file is entirely optional, with built-in defaults for every
//! knob, and is read **once at startup** — live-reload is explicitly not
//! required for a locker (Architecture / PLAN.md context).
//!
//! # Why TOML, and why by hand (teaching note)
//!
//! **2026-09-07**: this module was KDL through `saola-lockscreen` v0.1.1;
//! the config-format decision (made with Jordan) moved this file to TOML,
//! matching the family standard `saola-greeter` and `saola-capture` already
//! set — see `Cargo.toml`'s `toml` dependency comment for the crate pick.
//!
//! The parsing *posture* is unchanged by the format swap: a [`toml::Table`]
//! is walked explicitly — `table.get("latitude")`, `.as_str()`, … — rather
//! than deriving `serde::Deserialize` on [`LockscreenConfig`] itself. Two
//! reasons, both from `CLAUDE.md`: a newer-to-Rust reader can trace an
//! explicit walk line by line, and a hand-written extractor can name exactly
//! *which* knob was bad (`"latitude" is not a number`) where a derive would
//! only ever report "deserialize failed" and take the whole document down
//! with it.
//!
//! # No wrapper table (a deliberate schema choice)
//!
//! The KDL schema wrapped every knob in a top-level `lockscreen { }` node,
//! mirroring the panel's `panel { }`. TOML has no reason to copy that:
//! `lockscreen.toml` is already this crate's own file and nothing else will
//! ever read it, so every knob is a **bare top-level key** — one less level
//! to walk and to hand-write, matching `saola-greeter`'s and
//! `saola-capture`'s own TOML schemas.
//!
//! # Schema
//!
//! ```toml
//! wallpaper = "~/Pictures/wallpaper.png"
//! latitude = 51.5074
//! longitude = -0.1278
//! avatar = "~/Pictures/me.png"
//! ```
//!
//! Every knob is independently optional, and so is the file itself — an
//! empty file, and a file that sets every knob to its default, both parse
//! to the exact same [`LockscreenConfig::default`]:
//!
//!   - `wallpaper = "path"` — the §7 wallpaper ground, cover-fit. Falls back
//!     to the opaque ink surface (the `saola-theme` ink token, not a
//!     hardcoded hex) when unset or unreadable. A locker must always come
//!     up, so a bad wallpaper path is a degrade, never an error state (see
//!     `main.rs`'s `load_wallpaper`).
//!   - `latitude` / `longitude` — feeds Stage 5's Open-Meteo fetch. Absent
//!     by default, which hides the temperature slot entirely.
//!   - `avatar = "path"` — overrides the reveal flow's avatar (Stage 4),
//!     which otherwise falls back to `~/.face`, then an initials disc.
//!
//! # Resilience rules (binding — mirrors the panel's `panel.kdl` loader)
//!
//! A locker must never fail to start because of a config typo — see
//! `CLAUDE.md`'s panic-surface rule, which is stricter here than the
//! panel's because a lockscreen bug risks locking Jordan out, not just a
//! cosmetic bar glitch:
//!
//! - **No file at all** → [`LockscreenConfig::default`], silently. The
//!   expected case for anyone who hasn't written a `lockscreen.toml` yet.
//! - **No `lockscreen.toml`, but a `lockscreen.kdl` sits in its place** — a
//!   pre-2026-09 config nobody has ported — → one `eprintln!` migration hint
//!   naming both paths, then defaults, same as any other missing file. See
//!   [`warn_if_stale_kdl_sibling`].
//! - **File present but not valid TOML** ("garbage") → one `eprintln!`
//!   warning naming the file and the parse error, then the whole config
//!   falls back to [`LockscreenConfig::default`] — not a partial merge
//!   (same reasoning as the panel's loader: a document that doesn't even
//!   parse gives this module nothing safe to partially trust).
//! - **File parses, but a single knob's value is nonsense** (a `latitude`
//!   that isn't a number, or a `latitude`/`longitude` that is `inf`/`nan` —
//!   TOML allows both as float literals, but Open-Meteo has no sensible
//!   reading for either) → warn on that one knob, keep the rest of the
//!   document, and default just that knob.
//! - **`wallpaper`/`avatar` present but holding a non-string value** → that
//!   one knob silently defaults (no warning) — the same behaviour
//!   `saola-greeter`'s and `saola-capture`'s identical `read_str` helper
//!   gives every string knob in the family; see [`read_str`]'s doc comment.
//!
//! Every one of these paths is unit-tested below.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

use toml::{Table, Value};

/// The fixed file name every resolved config directory is joined with.
const FILE_NAME: &str = "lockscreen.toml";

/// The whole of `lockscreen.toml`, resolved to typed values — loaded once at
/// boot (`LockscreenConfig::load`, called from `main.rs`'s `Lockscreen::
/// boot`) and never re-read (Architecture: no live reload for a locker).
///
/// Unlike the panel's `PanelConfig`, no field here has a concrete fallback
/// *value* to resolve to later — an absent `wallpaper` doesn't mean "some
/// other path", it means "draw ink instead", which is a rendering decision
/// made where the field is consumed, not a second value stored here. So
/// every field is a plain `Option`, and `Option::None` everywhere *is* the
/// default.
///
/// Derives `Debug`/`PartialEq` for the same two reasons the panel's
/// `PanelConfig` does: `assert_eq!` in the tests below needs both, and the
/// `Debug` impl is what keeps every field here "used" as far as
/// `cargo clippy -D warnings`'s dead-code lint is concerned even before
/// Stage 4/5 add real call sites for `avatar`/`latitude`/`longitude` — see
/// `main.rs`'s `Lockscreen::boot` doc comment for the fuller version of
/// that reasoning.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct LockscreenConfig {
    /// `wallpaper = "path"` — see the module doc comment's schema section.
    /// `~/` expands against `$HOME` at parse time (same minimal rule as the
    /// panel's `mark "file:~/..."` knob — see [`expand_tilde`]); the file
    /// itself is not read until `main.rs`'s `load_wallpaper` checks it.
    pub wallpaper: Option<PathBuf>,
    /// `latitude = …` — Stage 5's Open-Meteo coordinate. A plain decimal
    /// degree (TOML integer or float), not a string.
    pub latitude: Option<f64>,
    /// `longitude = …` — see [`Self::latitude`].
    pub longitude: Option<f64>,
    /// `avatar = "path"` — see the module doc comment's schema section.
    /// Tilde-expanded the same way as `wallpaper`.
    pub avatar: Option<PathBuf>,
}

/// A TOML document that failed to parse at all — the "garbage file" case.
/// Deliberately the only error this module has: once the document parses,
/// every remaining problem (a bad knob value) is handled knob-by-knob with
/// a warning, never by returning `Err` — see the module doc comment.
#[derive(Debug)]
pub struct ConfigError(toml::de::Error);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ConfigError {}

impl LockscreenConfig {
    /// Load the config at boot. Never fails — see the module doc comment's
    /// resilience rules; every error path prints a warning (via
    /// `eprintln!`, since this runs before iced's event loop exists — there
    /// is no lock surface yet to show an error on) and returns a value, not
    /// a `Result`. Called exactly once, from `main.rs`'s `Lockscreen::boot`.
    pub fn load() -> Self {
        let Some(path) = resolve_path() else {
            return Self::default();
        };
        Self::load_from(&path)
    }

    fn load_from(path: &Path) -> Self {
        let contents = match std::fs::read_to_string(path) {
            Ok(contents) => contents,
            // Covers both "the file doesn't exist" (the common case) and
            // any other I/O error (permissions, …) — both degrade to
            // defaults silently, same as the panel's loader: an I/O error
            // here is not "malformed TOML", so it does not get the parse
            // failure's stderr warning. A sibling `lockscreen.kdl` is the
            // one thing worth a word here — see `warn_if_stale_kdl_sibling`.
            Err(_) => {
                warn_if_stale_kdl_sibling(path);
                return Self::default();
            }
        };
        match Self::parse(&contents) {
            Ok(config) => config,
            Err(err) => {
                eprintln!(
                    "saola-lockscreen: {} is not valid TOML ({err}) — using defaults",
                    path.display()
                );
                Self::default()
            }
        }
    }

    /// Parse a `lockscreen.toml` document's contents into a
    /// [`LockscreenConfig`].
    ///
    /// Returns `Err` **only** if `contents` isn't valid TOML at all — every
    /// other problem (an absent knob, a `latitude`/`longitude` that isn't a
    /// finite number) resolves to that one knob's default (`None`) and is
    /// reported with `eprintln!` rather than failing the whole parse. This
    /// is the function the unit tests below exercise directly, without
    /// touching the filesystem.
    pub fn parse(contents: &str) -> Result<Self, ConfigError> {
        // No `lockscreen { }` wrapper node any more (see the module doc
        // comment's "No wrapper table" section): every knob is a bare
        // top-level key, so `body` is the parsed top-level table itself —
        // no `.get("lockscreen")` indirection like the KDL version needed.
        let body: Table = contents.parse().map_err(ConfigError)?;

        let wallpaper = read_str(&body, "wallpaper").map(expand_tilde);
        let avatar = read_str(&body, "avatar").map(expand_tilde);
        let latitude = read_number(&body, "latitude");
        let longitude = read_number(&body, "longitude");

        Ok(LockscreenConfig {
            wallpaper,
            latitude,
            longitude,
            avatar,
        })
    }
}

/// The migration hint: a `lockscreen.toml` that doesn't exist is
/// unremarkable on its own (nobody has to write one), but a **sibling
/// `lockscreen.kdl`** sitting exactly where the TOML file would go is
/// almost certainly a pre-2026-09 config nobody has ported yet. Worth one
/// `eprintln!` naming both paths so the fix is obvious, without turning it
/// into an error — defaults still apply exactly as they would for any
/// other missing file. Mirrors `saola-greeter`'s and `saola-capture`'s
/// identical helper.
///
/// Returns whether the stale file was found, which is what makes the
/// behaviour unit-testable: a bare `eprintln!` is not something a test can
/// assert on without capturing stderr.
fn warn_if_stale_kdl_sibling(toml_path: &Path) -> bool {
    let kdl_path = toml_path.with_extension("kdl");
    if !kdl_path.is_file() {
        return false;
    }
    eprintln!(
        "saola-lockscreen: found {} but no {} — the config format moved to TOML and \
         lockscreen.kdl is no longer read; copy its knobs (wallpaper, latitude, \
         longitude, avatar — same names) into {}, or delete it to stop seeing this \
         hint — using defaults for now",
        kdl_path.display(),
        toml_path.display(),
        toml_path.display()
    );
    true
}

/// Where `lockscreen.toml` lives: the resolved config **directory** joined
/// with the fixed file name. Most-specific-first, the same chain the
/// panel's `panel.kdl` uses (`PanelConfig::resolve_path`), minus the
/// panel's `--config-dir` flag — this crate takes no command-line
/// arguments at all (a session locker has no terminal to read flags from by
/// the time niri hands it the session):
///
/// 1. **`$SAOLA_CONFIG_DIR`** — the Saola desktop's own env var.
/// 2. **`$XDG_CONFIG_HOME/saola`** — the XDG base-directory spec.
/// 3. **`~/.config/saola`** — the spec's own fallback for an unset
///    `$XDG_CONFIG_HOME`.
///
/// `None` only when nothing in the chain resolves (no Saola or XDG var, and
/// no `$HOME`) — treated the same as "no file": defaults.
fn resolve_path() -> Option<PathBuf> {
    config_dir_from(
        std::env::var_os("SAOLA_CONFIG_DIR"),
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
    .map(|dir| dir.join(FILE_NAME))
}

/// The testable core of [`resolve_path`]'s directory chain: every
/// environment variable is a plain argument instead of read from the
/// process environment directly, so precedence can be unit-tested without
/// mutating (and thereby racing every other test in this binary against)
/// the real environment — the same reasoning as the panel's identical
/// helper.
///
/// An env var set to the **empty string** is treated as unset and falls
/// through to the next rung, matching the XDG spec's own rule for
/// `$XDG_CONFIG_HOME` applied uniformly to `$SAOLA_CONFIG_DIR` too.
fn config_dir_from(
    saola: Option<OsString>,
    xdg: Option<OsString>,
    home: Option<OsString>,
) -> Option<PathBuf> {
    if let Some(saola) = saola {
        if !saola.is_empty() {
            return Some(PathBuf::from(saola));
        }
    }
    if let Some(xdg) = xdg {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg).join("saola"));
        }
    }
    // Same empty-means-unset rule as the two vars above — a `HOME=""`
    // would otherwise produce the *relative* path `.config/saola`.
    home.filter(|home| !home.is_empty())
        .map(|home| PathBuf::from(home).join(".config/saola"))
}

/// A leading `~/` (or a bare `~`) expands against `$HOME`; anything else
/// passes through unchanged. Deliberately minimal — no `~user/` form, no
/// crate dependency — matching the panel's identical helper, which only
/// ever needs the common case too.
fn expand_tilde(path: &str) -> PathBuf {
    expand_tilde_with_home(path, std::env::var_os("HOME"))
}

/// The testable core of [`expand_tilde`]: `$HOME` is a plain argument
/// instead of read from the environment directly, for the same
/// test-determinism reason as [`config_dir_from`].
fn expand_tilde_with_home(path: &str, home: Option<OsString>) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = home {
            return PathBuf::from(home).join(rest);
        }
    } else if path == "~" {
        if let Some(home) = home {
            return PathBuf::from(home);
        }
    }
    PathBuf::from(path)
}

/// `table.get(name)` as a string, if the key exists and its value is a TOML
/// string. A key present but holding a non-string value falls through to
/// `None` silently — the same "absent knob" fallback path
/// `saola-greeter`'s and `saola-capture`'s identical `read_str` helper
/// gives every string knob in the family. A wrong-type `wallpaper`/`avatar`
/// does not get its own warning the way [`read_number`] does for a bad
/// `latitude`/`longitude` below — matching the rest of the TOML family
/// rather than inventing a stricter rule just for this crate.
fn read_str<'a>(table: &'a Table, name: &str) -> Option<&'a str> {
    table.get(name)?.as_str()
}

/// `latitude`/`longitude` as an `f64`, accepting either a TOML integer or a
/// float. A key present but holding a non-numeric value (a typo'd string,
/// say) warns and falls back to `None` — the per-knob resilience rule every
/// other bad value in this file gets.
///
/// TOML also allows the float literals `inf`/`-inf`/`nan`, which KDL's
/// grammar never offered a way to write. Open-Meteo has no sensible reading
/// for either, and `modules::temperature::Coordinates::from_config` does
/// not itself guard against them (it only checks that both knobs are
/// present) — so a non-finite value is rejected right here, the one place
/// every coordinate this crate uses passes through, rather than teaching
/// that module a defensive check it should never need.
fn read_number(table: &Table, name: &str) -> Option<f64> {
    let value = table.get(name)?;
    let number = match value {
        Value::Integer(i) => *i as f64,
        Value::Float(f) => *f,
        _ => {
            eprintln!(
                "saola-lockscreen: lockscreen.toml: {name} = {value} is not a number — ignored"
            );
            return None;
        }
    };
    if !number.is_finite() {
        eprintln!(
            "saola-lockscreen: lockscreen.toml: {name} = {value} is not a finite number — ignored"
        );
        return None;
    }
    Some(number)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An absent file (represented here as an empty document, which is
    /// what `LockscreenConfig::load_from` effectively sees when a real
    /// file is missing and falls back before ever calling `parse`) yields
    /// every field `None`.
    #[test]
    fn default_config_parses() {
        let config = LockscreenConfig::parse("").expect("an empty document is valid TOML");
        assert_eq!(config, LockscreenConfig::default());
    }

    /// Every knob the schema defines, set to non-default values, all land
    /// correctly. Bare top-level keys, no `lockscreen { }` wrapper node.
    #[test]
    fn full_config_parses() {
        let toml = r#"
            wallpaper = "/opt/wallpapers/dune.png"
            latitude = 51.5074
            longitude = -0.1278
            avatar = "/opt/avatars/jordan.png"
        "#;
        let config = LockscreenConfig::parse(toml).expect("well-formed TOML");

        assert_eq!(
            config.wallpaper,
            Some(PathBuf::from("/opt/wallpapers/dune.png"))
        );
        assert_eq!(config.latitude, Some(51.5074));
        assert_eq!(config.longitude, Some(-0.1278));
        assert_eq!(
            config.avatar,
            Some(PathBuf::from("/opt/avatars/jordan.png"))
        );
    }

    /// A config that only sets one knob leaves the rest at their
    /// defaults — proves knob-by-knob fallback, not "any knob present
    /// disables all defaults".
    #[test]
    fn partial_config_parses() {
        let toml = r#"
            wallpaper = "/opt/wallpapers/dune.png"
        "#;
        let config = LockscreenConfig::parse(toml).expect("well-formed TOML");

        assert_eq!(
            config.wallpaper,
            Some(PathBuf::from("/opt/wallpapers/dune.png"))
        );
        assert_eq!(config.latitude, None);
        assert_eq!(config.longitude, None);
        assert_eq!(config.avatar, None);
    }

    /// Integer-valued `latitude`/`longitude` (no decimal point) parse just
    /// as well as floats — TOML treats `51` and `51.0` as different value
    /// types, and both must resolve to the same `f64`.
    #[test]
    fn integer_coordinates_parse_as_floats() {
        let toml = r#"
            latitude = 51
            longitude = 0
        "#;
        let config = LockscreenConfig::parse(toml).expect("well-formed TOML");

        assert_eq!(config.latitude, Some(51.0));
        assert_eq!(config.longitude, Some(0.0));
    }

    /// A non-numeric `latitude` warns and defaults just that knob — the
    /// rest of the document (here, `longitude`) still loads. This is the
    /// single-bad-knob resilience rule, distinct from a whole-document
    /// parse failure below.
    #[test]
    fn non_numeric_latitude_is_ignored() {
        let toml = r#"
            latitude = "north-ish"
            longitude = -0.1278
        "#;
        let config = LockscreenConfig::parse(toml).expect("well-formed TOML");

        assert_eq!(config.latitude, None);
        assert_eq!(config.longitude, Some(-0.1278));
    }

    /// `inf`/`nan` are valid TOML float literals, but neither is a sensible
    /// coordinate — both warn and default just that knob, same as a
    /// non-numeric value. See [`read_number`]'s doc comment for why this is
    /// checked here rather than in `modules::temperature`.
    #[test]
    fn non_finite_latitude_and_longitude_are_ignored() {
        let toml = r#"
            latitude = nan
            longitude = inf
        "#;
        let config = LockscreenConfig::parse(toml).expect("well-formed TOML");

        assert_eq!(config.latitude, None);
        assert_eq!(config.longitude, None);
    }

    /// A finite negative `latitude`/`longitude` (the ordinary southern/
    /// western-hemisphere case) is not mistaken for non-finite — the finite
    /// check must not be over-eager.
    #[test]
    fn finite_negative_coordinates_still_parse() {
        let toml = r#"
            latitude = -33.8688
            longitude = -inf
        "#;
        let config = LockscreenConfig::parse(toml).expect("well-formed TOML");

        assert_eq!(config.latitude, Some(-33.8688));
        assert_eq!(config.longitude, None);
    }

    /// A non-string `wallpaper` falls back to `None` silently — no
    /// warning, matching `read_str`'s doc comment and the rest of the TOML
    /// family's identical helper.
    #[test]
    fn non_string_wallpaper_is_silently_ignored() {
        let toml = r#"
            wallpaper = 42
            avatar = "/opt/avatars/jordan.png"
        "#;
        let config = LockscreenConfig::parse(toml).expect("well-formed TOML");

        assert_eq!(config.wallpaper, None);
        assert_eq!(
            config.avatar,
            Some(PathBuf::from("/opt/avatars/jordan.png"))
        );
    }

    /// Syntactically invalid TOML is the one case `parse` itself rejects —
    /// `load_from` (not exercised here, since it touches the filesystem)
    /// is what turns this `Err` into a full-default fallback plus a
    /// warning.
    #[test]
    fn garbage_is_rejected_by_parse() {
        let result = LockscreenConfig::parse("this is not = valid [[[ toml");
        assert!(result.is_err());
    }

    /// `load_from`'s fallback path, exercised directly against a temp file
    /// so the "malformed file → full defaults" resilience rule is proven
    /// end to end, not just at the `parse` layer.
    #[test]
    fn garbage_file_falls_back_to_defaults() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "saola-lockscreen-test-garbage-{}.toml",
            std::process::id()
        ));
        std::fs::write(&path, "this is not = valid [[[ toml").unwrap();

        let config = LockscreenConfig::load_from(&path);

        std::fs::remove_file(&path).ok();
        assert_eq!(config, LockscreenConfig::default());
    }

    /// The missing-file default path (Stage 3's own instruction to cover
    /// this explicitly): a path that doesn't exist at all falls back to
    /// defaults, not an error and not a panic.
    #[test]
    fn missing_file_falls_back_to_defaults() {
        let path = std::env::temp_dir().join("saola-lockscreen-test-definitely-missing.toml");
        std::fs::remove_file(&path).ok();

        let config = LockscreenConfig::load_from(&path);

        assert_eq!(config, LockscreenConfig::default());
    }

    /// A missing `lockscreen.toml` with a stale `lockscreen.kdl` in its
    /// place still resolves to defaults (the hint is a warning, not an
    /// error), and the detector itself reports the sibling — which is the
    /// part a test can assert on without capturing stderr.
    #[test]
    fn a_stale_kdl_sibling_is_reported() {
        let dir = std::env::temp_dir().join(format!(
            "saola-lockscreen-test-stale-kdl-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let toml_path = dir.join("lockscreen.toml");
        let kdl_path = dir.join("lockscreen.kdl");
        std::fs::write(&kdl_path, "lockscreen { wallpaper \"/opt/dune.png\" }").unwrap();

        let found = warn_if_stale_kdl_sibling(&toml_path);
        let config = LockscreenConfig::load_from(&toml_path);

        std::fs::remove_dir_all(&dir).ok();
        assert!(found, "the sibling lockscreen.kdl must be detected");
        assert_eq!(config, LockscreenConfig::default());
    }

    /// No sibling, no hint — the ordinary "nobody wrote a config" case must
    /// stay silent.
    #[test]
    fn no_stale_kdl_sibling_is_not_reported() {
        let dir = std::env::temp_dir().join(format!(
            "saola-lockscreen-test-no-stale-kdl-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let toml_path = dir.join("lockscreen.toml");

        let found = warn_if_stale_kdl_sibling(&toml_path);

        std::fs::remove_dir_all(&dir).ok();
        assert!(!found);
    }

    /// A leading `~/` expands against the given `$HOME`.
    #[test]
    fn tilde_expands_against_home() {
        let expanded = expand_tilde_with_home("~/wallpaper.png", Some("/home/jordan".into()));
        assert_eq!(expanded, PathBuf::from("/home/jordan/wallpaper.png"));
    }

    /// A bare `~` (no trailing slash) also expands.
    #[test]
    fn bare_tilde_expands_to_home() {
        let expanded = expand_tilde_with_home("~", Some("/home/jordan".into()));
        assert_eq!(expanded, PathBuf::from("/home/jordan"));
    }

    /// A path with no tilde at all passes through unchanged.
    #[test]
    fn absolute_path_is_unchanged() {
        let expanded =
            expand_tilde_with_home("/opt/wallpapers/dune.png", Some("/home/jordan".into()));
        assert_eq!(expanded, PathBuf::from("/opt/wallpapers/dune.png"));
    }

    /// A `~/`-prefixed path with no `$HOME` available falls through to the
    /// literal string rather than panicking or guessing a directory.
    #[test]
    fn tilde_with_no_home_is_left_literal() {
        let expanded = expand_tilde_with_home("~/wallpaper.png", None);
        assert_eq!(expanded, PathBuf::from("~/wallpaper.png"));
    }

    /// `$SAOLA_CONFIG_DIR` wins over both `$XDG_CONFIG_HOME` and `$HOME`.
    #[test]
    fn saola_env_wins_over_xdg_and_home() {
        let dir = config_dir_from(
            Some("/saola".into()),
            Some("/xdg".into()),
            Some("/home/jordan".into()),
        );
        assert_eq!(dir, Some(PathBuf::from("/saola")));
    }

    /// `$XDG_CONFIG_HOME/saola` wins over `$HOME` when `$SAOLA_CONFIG_DIR`
    /// is unset.
    #[test]
    fn xdg_wins_over_home() {
        let dir = config_dir_from(None, Some("/xdg".into()), Some("/home/jordan".into()));
        assert_eq!(dir, Some(PathBuf::from("/xdg/saola")));
    }

    /// `~/.config/saola` is the last resort when neither env var is set.
    #[test]
    fn home_is_the_last_resort() {
        let dir = config_dir_from(None, None, Some("/home/jordan".into()));
        assert_eq!(dir, Some(PathBuf::from("/home/jordan/.config/saola")));
    }

    /// An env var set to the empty string is treated as unset, not as a
    /// literal empty path — the same rule the XDG spec states for
    /// `$XDG_CONFIG_HOME` and this loader applies uniformly to
    /// `$SAOLA_CONFIG_DIR` too.
    #[test]
    fn empty_env_var_is_treated_as_unset() {
        let dir = config_dir_from(
            Some("".into()),
            Some("".into()),
            Some("/home/jordan".into()),
        );
        assert_eq!(dir, Some(PathBuf::from("/home/jordan/.config/saola")));
    }

    /// Nothing set anywhere in the chain resolves to `None` — the "no
    /// config is possible here" case, not an error.
    #[test]
    fn nothing_set_resolves_to_none() {
        let dir = config_dir_from(None, None, None);
        assert_eq!(dir, None);
    }
}
