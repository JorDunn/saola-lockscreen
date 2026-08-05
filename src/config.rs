//! `~/.config/saola/lockscreen.kdl` — the locker's optional config file.
//!
//! Same KDL family and resolution order as the panel's `panel.kdl` (see
//! `saola-panel`'s `src/config.rs` and its `CLAUDE.md`): the file is
//! entirely optional, with built-in defaults for every knob, and is read
//! **once at startup** — live-reload is explicitly not required for a
//! locker (Architecture / PLAN.md context).
//!
//! # Schema
//!
//! ```kdl
//! lockscreen {
//!     wallpaper "~/Pictures/wallpaper.png"
//!     latitude 51.5074
//!     longitude -0.1278
//!     avatar "~/Pictures/me.png"
//! }
//! ```
//!
//! Every knob is independently optional, and so is the `lockscreen { }`
//! node itself — an empty file, a file with no `lockscreen { }` node, and a
//! file that sets every knob to its default all parse to the exact same
//! [`LockscreenConfig::default`]:
//!
//!   - `wallpaper "path"` — the §7 wallpaper ground, cover-fit. Falls back
//!     to the opaque ink surface (the `saola-theme` ink token, not a
//!     hardcoded hex) when unset or unreadable. A locker must always come
//!     up, so a bad wallpaper path is a degrade, never an error state (see
//!     `main.rs`'s `load_wallpaper`).
//!   - `latitude` / `longitude` — feeds Stage 5's Open-Meteo fetch. Absent
//!     by default, which hides the temperature slot entirely.
//!   - `avatar "path"` — overrides the reveal flow's avatar (Stage 4),
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
//!   expected case for anyone who hasn't written a `lockscreen.kdl` yet.
//! - **File present but not valid KDL** ("garbage") → one `eprintln!`
//!   warning naming the file and the parse error, then the whole config
//!   falls back to [`LockscreenConfig::default`] — not a partial merge
//!   (same reasoning as the panel's loader: a document that doesn't even
//!   parse gives this module nothing safe to partially trust).
//! - **File parses, but a single knob's value is nonsense** (a `latitude`
//!   that isn't a number, say) → warn on that one knob, keep the rest of
//!   the document, and default just that knob.
//!
//! Every one of these paths is unit-tested below.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

use kdl::{KdlDocument, KdlValue};

/// The fixed file name every resolved config directory is joined with.
const FILE_NAME: &str = "lockscreen.kdl";

/// The whole of `lockscreen.kdl`, resolved to typed values — loaded once at
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
    /// `wallpaper "path"` — see the module doc comment's schema section.
    /// `~/` expands against `$HOME` at parse time (same minimal rule as the
    /// panel's `mark "file:~/..."` knob — see [`expand_tilde`]); the file
    /// itself is not read until `main.rs`'s `load_wallpaper` checks it.
    pub wallpaper: Option<PathBuf>,
    /// `latitude "…"` — Stage 5's Open-Meteo coordinate. A plain decimal
    /// degree (KDL integer or float), not a string.
    pub latitude: Option<f64>,
    /// `longitude "…"` — see [`Self::latitude`].
    pub longitude: Option<f64>,
    /// `avatar "path"` — see the module doc comment's schema section.
    /// Tilde-expanded the same way as `wallpaper`.
    pub avatar: Option<PathBuf>,
}

/// A KDL document that failed to parse at all — the "garbage file" case.
/// Deliberately the only error this module has: once the document parses,
/// every remaining problem (a bad knob value) is handled knob-by-knob with
/// a warning, never by returning `Err` — see the module doc comment.
#[derive(Debug)]
pub struct ConfigError(kdl::KdlError);

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
            // here is not "malformed KDL", so it does not get the parse
            // failure's stderr warning.
            Err(_) => return Self::default(),
        };
        match Self::parse(&contents) {
            Ok(config) => config,
            Err(err) => {
                eprintln!(
                    "saola-lockscreen: {} is not valid KDL ({err}) — using defaults",
                    path.display()
                );
                Self::default()
            }
        }
    }

    /// Parse a `lockscreen.kdl` document's contents into a
    /// [`LockscreenConfig`].
    ///
    /// Returns `Err` **only** if `contents` isn't valid KDL at all — every
    /// other problem (no top-level `lockscreen { }` node, an absent knob, a
    /// `latitude`/`longitude` that isn't a number) resolves to that one
    /// knob's default (`None`) and is reported with `eprintln!` rather than
    /// failing the whole parse. This is the function the unit tests below
    /// exercise directly, without touching the filesystem.
    pub fn parse(contents: &str) -> Result<Self, ConfigError> {
        let document = KdlDocument::parse(contents).map_err(ConfigError)?;

        // No top-level `lockscreen { }` node at all is not "garbage" — it's
        // a config file that doesn't configure the locker (an empty file
        // is the trivial case of this). Every knob below is read through
        // this `Option`, so "no lockscreen node" and "node present but
        // every knob absent" produce the identical result:
        // `LockscreenConfig::default()`.
        let body = document.get("lockscreen").and_then(|node| node.children());

        let wallpaper = read_arg_str(body, "wallpaper").map(expand_tilde);
        let avatar = read_arg_str(body, "avatar").map(expand_tilde);
        let latitude = read_arg_number(body, "latitude");
        let longitude = read_arg_number(body, "longitude");

        Ok(LockscreenConfig {
            wallpaper,
            latitude,
            longitude,
            avatar,
        })
    }
}

/// Where `lockscreen.kdl` lives: the resolved config **directory** joined
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

/// `body.get_arg(name)` as a string, if the node exists and its first
/// positional argument is a KDL string. A node present but holding a
/// non-string value falls through to `None` — same "absent knob" fallback
/// path as the panel's identical helper, no separate error needed for
/// "wrong value type" versus "missing entirely".
fn read_arg_str<'a>(body: Option<&'a KdlDocument>, name: &str) -> Option<&'a str> {
    body?.get_arg(name)?.as_string()
}

/// `latitude`/`longitude` as an `f64`, accepting either KDL integers or
/// floats. A node present but holding a non-numeric value (a typo'd
/// string, say) warns and falls back to `None` — the per-knob resilience
/// rule every other bad value in this file gets.
fn read_arg_number(body: Option<&KdlDocument>, name: &str) -> Option<f64> {
    let value = body?.get_arg(name)?;
    match number_as_f64(value) {
        Some(n) => Some(n),
        None => {
            eprintln!(
                "saola-lockscreen: lockscreen.kdl: {name} \"{value}\" is not a number — ignored"
            );
            None
        }
    }
}

fn number_as_f64(value: &KdlValue) -> Option<f64> {
    if let Some(i) = value.as_integer() {
        return Some(i as f64);
    }
    value.as_float()
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
        let config = LockscreenConfig::parse("").expect("an empty document is valid KDL");
        assert_eq!(config, LockscreenConfig::default());
    }

    /// Every knob the schema defines, set to non-default values, all land
    /// correctly.
    #[test]
    fn full_config_parses() {
        let kdl = r##"
            lockscreen {
                wallpaper "/opt/wallpapers/dune.png"
                latitude 51.5074
                longitude -0.1278
                avatar "/opt/avatars/jordan.png"
            }
        "##;
        let config = LockscreenConfig::parse(kdl).expect("well-formed KDL");

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
        let kdl = r##"
            lockscreen {
                wallpaper "/opt/wallpapers/dune.png"
            }
        "##;
        let config = LockscreenConfig::parse(kdl).expect("well-formed KDL");

        assert_eq!(
            config.wallpaper,
            Some(PathBuf::from("/opt/wallpapers/dune.png"))
        );
        assert_eq!(config.latitude, None);
        assert_eq!(config.longitude, None);
        assert_eq!(config.avatar, None);
    }

    /// Integer-valued `latitude`/`longitude` (no decimal point) parse just
    /// as well as floats — KDL treats `51` and `51.0` as different value
    /// types, and both must resolve to the same `f64`.
    #[test]
    fn integer_coordinates_parse_as_floats() {
        let kdl = r##"
            lockscreen {
                latitude 51
                longitude 0
            }
        "##;
        let config = LockscreenConfig::parse(kdl).expect("well-formed KDL");

        assert_eq!(config.latitude, Some(51.0));
        assert_eq!(config.longitude, Some(0.0));
    }

    /// A non-numeric `latitude` warns and defaults just that knob — the
    /// rest of the document (here, `longitude`) still loads. This is the
    /// single-bad-knob resilience rule, distinct from a whole-document
    /// parse failure below.
    #[test]
    fn non_numeric_latitude_is_ignored() {
        let kdl = r##"
            lockscreen {
                latitude "north-ish"
                longitude -0.1278
            }
        "##;
        let config = LockscreenConfig::parse(kdl).expect("well-formed KDL");

        assert_eq!(config.latitude, None);
        assert_eq!(config.longitude, Some(-0.1278));
    }

    /// Syntactically invalid KDL is the one case `parse` itself rejects —
    /// `load_from` (not exercised here, since it touches the filesystem)
    /// is what turns this `Err` into a full-default fallback plus a
    /// warning.
    #[test]
    fn garbage_is_rejected_by_parse() {
        let result = LockscreenConfig::parse("lockscreen { this is not } valid kdl {{{");
        assert!(result.is_err());
    }

    /// `load_from`'s fallback path, exercised directly against a temp file
    /// so the "malformed file → full defaults" resilience rule is proven
    /// end to end, not just at the `parse` layer.
    #[test]
    fn garbage_file_falls_back_to_defaults() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "saola-lockscreen-test-garbage-{}.kdl",
            std::process::id()
        ));
        std::fs::write(&path, "lockscreen { this is not } valid kdl {{{").unwrap();

        let config = LockscreenConfig::load_from(&path);

        std::fs::remove_file(&path).ok();
        assert_eq!(config, LockscreenConfig::default());
    }

    /// The missing-file default path (Stage 3's own instruction to cover
    /// this explicitly): a path that doesn't exist at all falls back to
    /// defaults, not an error and not a panic.
    #[test]
    fn missing_file_falls_back_to_defaults() {
        let path = std::env::temp_dir().join("saola-lockscreen-test-definitely-missing.kdl");
        std::fs::remove_file(&path).ok();

        let config = LockscreenConfig::load_from(&path);

        assert_eq!(config, LockscreenConfig::default());
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
