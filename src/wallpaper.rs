//! Boot-time wallpaper decoding — the fix for Stage 3's "wallpaper never
//! renders" gap.
//!
//! # Root cause (confirmed live, nested niri, Stage "post-3" diagnostic)
//!
//! Stage 3 handed `iced::widget::image::Handle::from_path(path)` straight to
//! the `image()` widget and left decoding to iced's own renderer. That is
//! fine in a normal windowed app, which redraws continuously (every cursor
//! move, every animation frame) — but it silently fails on a **static**
//! surface like this one, for a reason specific to `iced_wgpu` 0.14's raster
//! pipeline (confirmed by reading `iced_wgpu-0.14.0/src/image/cache.rs`,
//! not guessed):
//!
//! 1. `Handle::Path`/`Handle::Bytes` are decoded **off-thread**: the first
//!    time the renderer sees the handle it kicks off a background
//!    `Worker::load(handle)` and draws *nothing* for that frame — see
//!    `load_image`'s `else if !pending.contains_key(...) { worker.load(handle) }`
//!    branch (the comment right above it — `Handle::Rgba` gets an early
//!    `Memory::load(handle)` call inline, tagged "since it's very cheap" —
//!    is the tell that `Path`/`Bytes` are deliberately treated as
//!    expensive-and-async).
//! 2. Even once decoded, the GPU texture upload itself
//!    (`Cache::upload_raster`) is *also* asynchronous whenever the decoded
//!    RGBA buffer is 2 MiB or larger (`const MAX_SYNC_SIZE: usize = 2 *
//!    1024 * 1024`) — true for essentially any real wallpaper (a modest
//!    1920×1080 RGBA buffer alone is ~8 MiB). That path, too, returns
//!    `None` for the current frame and finishes the upload on a worker
//!    thread, picked up by a later frame's `receive()` call.
//! 3. A normal iced app has a "later frame" arriving within milliseconds
//!    (the windowing backend keeps requesting frames). This crate's lock
//!    surface does not: `iced_sessionlock` only requests a redraw when a
//!    widget's `RedrawRequest` asks for one, and this crate's only
//!    recurring one is the clock's *minute-aligned* tick
//!    (`modules::clock`). So the asynchronous decode-and-upload above can
//!    sit completed-but-never-composited for up to a minute, and Stage 3's
//!    live tests (which restarted the nested compositor between short
//!    attempts, per that stage's own "prefer a fresh nested niri instance"
//!    gotcha) never ran long enough to see it resolve itself.
//!
//! # The fix (and what it does and doesn't close)
//!
//! Do the *decode* ourselves, at boot, and hand the renderer a
//! `Handle::from_rgba` instead of `Handle::from_path`. This is not just
//! "moves the CPU work earlier" — per point 1 above, `Handle::Rgba` is the
//! one handle variant `iced_wgpu`'s own cache treats as cheap enough to
//! resolve **synchronously**, skipping the background-worker decode step
//! entirely. Confirmed live (nested niri, a real 5000×3333 wallpaper,
//! screenshots — see `.claude/handoffs/handoff_stage_3.md`'s addendum and
//! `main.rs`'s module doc comment's "Post-Stage-3" section for the full
//! account): this alone turns Stage 3's "never renders" into "renders
//! reliably, every time" — a real fix, not a guess.
//!
//! It does **not** by itself close point 2 (the GPU upload staying async
//! for buffers ≥ 2 MiB, true of essentially any real wallpaper): the first
//! frame after lock-up can still show ink while that upload finishes in the
//! background, and — since this crate's only recurring redraw trigger
//! before Stage 4 is the clock's minute tick — the wallpaper's first
//! appearance can lag up to ~60 seconds behind the lock surface itself.
//! Two follow-up fixes for *that* gap were tried live and **both failed to
//! help** (`iced_sessionlock`'s `unconditional-rendering` feature, and an
//! explicit `iced::widget::image::allocate` `Task` from boot) — see
//! `main.rs`'s doc comment for why, in detail. Neither is used here as a
//! result: this module ships the decode-only fix, which is a large,
//! honest improvement over Stage 3 and keeps the crate's actual contract
//! ("ink fallback ... never an error state") intact either way, since ink
//! is indistinguishable from "no wallpaper configured."
//!
//! # Why this lives in its own module
//!
//! `main.rs`'s `Lockscreen::boot` calls [`load`] once, before the
//! `iced_sessionlock::application` runtime exists — same "read once at
//! startup, never touch it again" shape as `config::LockscreenConfig::load`.
//! Keeping the decode logic here (rather than inline in `main.rs`, where
//! Stage 3 originally put it) makes it unit-testable without dragging in
//! `iced_sessionlock`/Wayland at all: [`decode`] and
//! [`handle_from_dynamic_image`] take plain bytes/`DynamicImage`, no
//! filesystem, no renderer.
//!
//! # Fallback contract (binding — Architecture, PLAN.md)
//!
//! Every failure mode here — unreadable file, undecodable bytes, a decoded
//! image with a zero width or height — returns `None` and logs one
//! `eprintln!` explaining why, exactly like Stage 3's original
//! `load_wallpaper`. `None` reaching `main.rs`'s `Lockscreen::wallpaper`
//! field means "draw ink instead," the same fallback for every failure
//! mode; `view()` does not need to (and must not) distinguish them. A
//! locker must always come up — see `CLAUDE.md`'s panic-surface rule — so
//! nothing here panics, unwraps, or expects on a path fed by a config file
//! or a file on disk (both are attacker- and typo-controlled).
//!
//! # Boot-time cost (a deliberate trade-off, not an oversight)
//!
//! Decoding a full-resolution wallpaper (disk read + JPEG/PNG/WebP decode +
//! an RGBA copy) happens synchronously on the calling thread, before
//! `Lockscreen::boot` returns and therefore before the lock surface is
//! requested at all. For a typical desktop wallpaper (a few MB, one to a
//! few thousand pixels per side) this is comfortably sub-100ms even on
//! modest hardware — but a very large source image (e.g. an
//! unusually high-resolution panorama) would add that decode time directly
//! to "how long until the screen locks," since niri does not consider the
//! session locked until this process's first lock surface appears. That is
//! judged an acceptable trade-off here: a slightly slower lock beats a
//! wallpaper that never renders, and it only affects the moment of
//! locking, never staying locked. If this ever becomes a real problem, the
//! fix is to decode on a background thread and swap the wallpaper in after
//! the ink-only lock surface is already up, not to reach back for
//! `Handle::from_path`.

// # Stage 7 (H-1, `docs/REVIEW-v0.1.md`): the boot-time cost above is no
// longer paid before the compositor is asked to lock
//
// The "Boot-time cost" section above was written when `main.rs`'s
// `Lockscreen::boot` called [`load`] directly, synchronously, and returned.
// Stage 6's security review traced `iced_sessionlock`'s own source
// (`iced_program-0.14.0/src/lib.rs`, `iced_sessionlock-0.19.1/src/
// multi_window.rs`, `sessionlockev-0.19.1/src/lib.rs`) and found that
// `boot()` runs *before* the `ext_session_lock_manager_v1.lock` request is
// even sent — so every millisecond `boot` spent decoding a wallpaper was a
// millisecond the real desktop stayed fully visible and interactive, not
// just a millisecond of "the lock surface is late". For a `contrib/
// session/` before-sleep hook racing a real suspend, that was the whole
// exposure window (H-1's full write-up has the concrete race).
//
// The fix is [`load_task`]: `boot()` now constructs `Lockscreen` with
// `wallpaper: None` (this module's own "not loaded yet" fallback, already
// correct) and returns an `iced::Task` built from this function instead of
// calling [`load`] inline — see `main.rs`'s Stage 7 doc section for the
// `Task` wiring. The compositor's lock request goes out first; the
// wallpaper fills in via `Message::WallpaperLoaded` whenever the decode
// finishes, exactly like a failed/unset wallpaper always has.
//
// # Post-Stage-7: the decoded-pixel cache ("pre-loading")
//
// Even off the UI thread, every lock used to pay the full source decode —
// for a real wallpaper (Jordan's is a 5000×3333 JPEG) that is the dominant
// share of "how long until the image appears". Both halves of that work
// produce the exact same bytes every time, so [`load`] now caches its
// *output*: after the first successful decode, the finished RGBA pixels are
// written to `$XDG_CACHE_HOME/saola/lockscreen-wallpaper.rgba` (or
// `~/.cache/saola/`), and every later lock reads them straight into
// `Handle::from_rgba` — a plain file read, no image codec involved at all.
//
// Two design points worth knowing before touching this:
//
// - **Invalidation is by content key, not by trusting the file.** The
//   cache header stores a hash of (source path, mtime, size); [`load`]
//   recomputes it from the configured wallpaper's metadata each boot and
//   a mismatch — new wallpaper path, edited file — simply misses and
//   re-decodes. One fixed cache file plus an in-header key means a changed
//   wallpaper *replaces* the cache rather than accumulating orphans. The
//   hash is `DefaultHasher` (not guaranteed stable across Rust releases —
//   a toolchain bump may invalidate the cache once; the cost is one silent
//   re-decode, so that trade is taken for the zero-dependency hasher).
// - **The cached image is capped at [`MAX_DIMENSION`] on its longest
//   side.** `ContentFit::Cover` crops/scales at render time anyway, so
//   pixels beyond ~4K density never reach the screen — downscaling once at
//   cache-build time shrinks the cache file, the boot-time read, *and*
//   every subsequent GPU upload (the 5000×3333 source is a 66 MiB RGBA
//   buffer; capped it is ~37 MiB). The cap only ever shrinks (a smaller
//   image passes through untouched).
//
// Every cache failure mode — unreadable, truncated, wrong magic, stale
// key, impossible dimensions — falls through to the full decode path
// ([`decode_cache`] returns `None`, never an error), and a failed cache
// *write* only costs the next lock a re-decode. The fallback contract
// above is unchanged: nothing here panics, and the worst case is still
// just ink.
use std::ffi::OsString;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::SystemTime;

use iced::widget::image::Handle;
use image::DynamicImage;

/// Cache-format magic + version, the first 8 bytes of the cache file. Bump
/// the trailing digit if the header layout below ever changes — old files
/// then fail the magic check and re-decode, instead of being misread.
const CACHE_MAGIC: &[u8; 8] = b"SAOLAWP1";

/// Header layout: magic (8) + key hash (u64 LE) + width (u32 LE) + height
/// (u32 LE), then exactly `width * height * 4` RGBA bytes.
const CACHE_HEADER_LEN: usize = 24;

/// The longest side the cached wallpaper is downscaled to — see the cache
/// section of the module doc comment. 3840 matches a 4K output; Jordan's
/// panel is 2560 physical pixels wide, so this cap is quality-neutral
/// there with headroom for a denser future monitor.
const MAX_DIMENSION: u32 = 3840;

/// Loads and decodes the wallpaper at `path`, boot-time, into an RGBA
/// [`Handle`] — see the module doc comment for why `Handle::from_rgba`
/// specifically (not `Handle::from_path`) is the fix, and why every error
/// path here degrades to `None` rather than propagating a `Result`: there
/// is no caller above `main.rs`'s `Lockscreen::boot` that could do anything
/// with an `Err` except turn it into the same ink fallback, so `None` *is*
/// this function's error type.
pub fn load(path: &Path) -> Option<Handle> {
    // Metadata first, not the file contents: on a cache hit the source
    // image's bytes are never read at all — its (path, mtime, size) key is
    // all that's needed to know the cache is still current.
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) => {
            eprintln!(
                "saola-lockscreen: wallpaper {} is not readable ({err}) — falling back to ink",
                path.display()
            );
            return None;
        }
    };

    // The fast path: previously decoded pixels, read straight off disk.
    // Either `Option` being `None` (no resolvable cache dir, no usable
    // mtime) just means "this machine can't cache" — the decode below
    // still works, it's only slower.
    let key = cache_key(path, &metadata);
    let cache_path = cache_file();
    if let (Some(cache_path), Some(key)) = (&cache_path, key) {
        if let Ok(bytes) = std::fs::read(cache_path) {
            if let Some((width, height, pixels)) = decode_cache(bytes, key) {
                return Some(Handle::from_rgba(width, height, pixels));
            }
        }
    }

    // The slow path: full decode, downscale to the cap, then remember the
    // result for next time.
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!(
                "saola-lockscreen: wallpaper {} is not readable ({err}) — falling back to ink",
                path.display()
            );
            return None;
        }
    };

    let Some(image) = image::load_from_memory(&bytes).ok() else {
        eprintln!(
            "saola-lockscreen: wallpaper {} could not be decoded as an image — falling back to ink",
            path.display()
        );
        return None;
    };

    let rgba = scale_to_cap(image, MAX_DIMENSION).into_rgba8();
    let (width, height) = rgba.dimensions();
    if width == 0 || height == 0 {
        eprintln!(
            "saola-lockscreen: wallpaper {} decoded to an empty image — falling back to ink",
            path.display()
        );
        return None;
    }
    let pixels = rgba.into_raw();

    if let (Some(cache_path), Some(key)) = (cache_path, key) {
        write_cache(&cache_path, &encode_cache(key, width, height, &pixels));
    }

    Some(Handle::from_rgba(width, height, pixels))
}

/// The cache's freshness key: a hash of the source's path, mtime, and byte
/// size — the same three things `make` would look at. `None` when the
/// filesystem can't produce an mtime (some exotic mounts), which just
/// disables caching rather than failing the load. See the module doc
/// comment on why `DefaultHasher` is acceptable here.
fn cache_key(path: &Path, metadata: &std::fs::Metadata) -> Option<u64> {
    let modified = metadata.modified().ok()?;
    let nanos = modified
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()?
        .as_nanos();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    nanos.hash(&mut hasher);
    metadata.len().hash(&mut hasher);
    Some(hasher.finish())
}

/// Where the decoded-pixel cache lives: the resolved cache **directory**
/// joined with a fixed file name. `$XDG_CACHE_HOME/saola`, else
/// `~/.cache/saola` — the cache-dir mirror of `config::resolve_path`'s
/// config chain (no `$SAOLA_CONFIG_DIR` rung: that var names where to
/// *read* configuration, and pointing machine-generated cache bytes at it
/// would be a category mistake).
fn cache_file() -> Option<PathBuf> {
    cache_dir_from(std::env::var_os("XDG_CACHE_HOME"), std::env::var_os("HOME"))
        .map(|dir| dir.join("lockscreen-wallpaper.rgba"))
}

/// The testable core of [`cache_file`], same shape (and same
/// empty-means-unset rule) as `config::config_dir_from` — see that
/// function's doc comment for why the env vars are plain arguments.
fn cache_dir_from(xdg: Option<OsString>, home: Option<OsString>) -> Option<PathBuf> {
    if let Some(xdg) = xdg {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg).join("saola"));
        }
    }
    home.filter(|home| !home.is_empty())
        .map(|home| PathBuf::from(home).join(".cache/saola"))
}

/// Serializes decoded pixels into the cache-file byte layout (see
/// [`CACHE_HEADER_LEN`]). Pure, so the roundtrip is unit-testable without
/// touching a filesystem.
fn encode_cache(key: u64, width: u32, height: u32, pixels: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(CACHE_HEADER_LEN + pixels.len());
    bytes.extend_from_slice(CACHE_MAGIC);
    bytes.extend_from_slice(&key.to_le_bytes());
    bytes.extend_from_slice(&width.to_le_bytes());
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.extend_from_slice(pixels);
    bytes
}

/// Validates and unpacks a cache file's bytes: `None` for anything that
/// isn't a well-formed, current cache — wrong magic (old format), stale
/// `expected_key` (wallpaper changed), zero dimensions, or a byte count
/// that doesn't match `width × height × 4` (truncated write). All of them
/// mean "re-decode", never an error. Takes `bytes` by value so the pixel
/// payload can reuse the read buffer's allocation (`drain`) instead of
/// copying ~40 MiB.
fn decode_cache(mut bytes: Vec<u8>, expected_key: u64) -> Option<(u32, u32, Vec<u8>)> {
    let header = bytes.get(..CACHE_HEADER_LEN)?;
    if &header[..8] != CACHE_MAGIC {
        return None;
    }
    let key = u64::from_le_bytes(header[8..16].try_into().ok()?);
    if key != expected_key {
        return None;
    }
    let width = u32::from_le_bytes(header[16..20].try_into().ok()?);
    let height = u32::from_le_bytes(header[20..24].try_into().ok()?);
    if width == 0 || height == 0 {
        return None;
    }
    let expected_len = (width as usize)
        .checked_mul(height as usize)?
        .checked_mul(4)?;
    if bytes.len() - CACHE_HEADER_LEN != expected_len {
        return None;
    }
    bytes.drain(..CACHE_HEADER_LEN);
    Some((width, height, bytes))
}

/// Best-effort cache write: temp file + rename so a crash mid-write can
/// never leave a half-length file at the real path (the length check in
/// [`decode_cache`] would catch one anyway — this just avoids paying a
/// wasted read of a file that can't validate). Failure costs the next
/// lock a re-decode, nothing more, so it's logged and swallowed.
fn write_cache(path: &Path, bytes: &[u8]) {
    let result = (|| -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("rgba.tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, path)
    })();
    if let Err(err) = result {
        eprintln!(
            "saola-lockscreen: could not write the wallpaper cache {} ({err}) — the next lock will decode from scratch again",
            path.display()
        );
    }
}

/// Downscales `image` so its longest side is at most `cap`, preserving
/// aspect ratio; anything already within the cap passes through untouched
/// (this function never upscales). `CatmullRom` rather than `Lanczos3`:
/// visually equivalent at these mild ratios, meaningfully cheaper on a
/// one-time cache build; rather than `Triangle`: this output is the
/// permanent cached copy, so it's worth the better filter once.
fn scale_to_cap(image: DynamicImage, cap: u32) -> DynamicImage {
    if image.width() <= cap && image.height() <= cap {
        return image;
    }
    image.resize(cap, cap, image::imageops::FilterType::CatmullRom)
}

/// Runs [`load`] off the UI thread, for `main.rs`'s `Lockscreen::boot` to
/// hand to `iced::Task::perform` — see this module's doc comment's Stage 7
/// section for why the decode must not run inline in `boot` any more.
///
/// Dispatch pattern copied verbatim from `auth::PamAuthenticator::
/// authenticate` (see that function's teaching note for the full
/// reasoning, not repeated here): prefer `tokio::runtime::Handle::
/// spawn_blocking` when this future is polled inside a tokio runtime
/// (always true in practice — `iced` is built with its own `tokio`
/// feature), falling back to a plain OS thread plus a oneshot channel so a
/// missing runtime degrades to "the wallpaper takes a beat longer" rather
/// than a panic. Unlike the PAM case this is never security-relevant — the
/// worst outcome of every failure path here is still just the ink
/// fallback — but the crate's no-panic-on-a-runtime-path rule applies
/// uniformly regardless of stakes.
pub fn load_task(path: PathBuf) -> Pin<Box<dyn Future<Output = Option<Handle>> + Send>> {
    Box::pin(async move {
        let work = move || load(&path);
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle.spawn_blocking(work).await.unwrap_or(None),
            Err(_) => {
                let (tx, rx) = tokio::sync::oneshot::channel();
                std::thread::spawn(move || {
                    let _ = tx.send(work());
                });
                rx.await.unwrap_or(None)
            }
        }
    })
}

/// The testable core of [`load`]: decodes raw file bytes (any format the
/// `image` crate's default codecs handle — jpg/png/webp/gif/bmp/... — this
/// crate deliberately does not restrict the format list, since the
/// codecs are already compiled into the binary via iced's own `image`
/// feature; see `Cargo.toml`'s comment on the `image` dependency) into an
/// RGBA [`Handle`], or `None` on any decode failure. Split out from [`load`]
/// so the "garbage bytes" unit test below doesn't need a real file on disk.
///
/// `pub(crate)` since Stage 4: `modules::reveal::resolve_avatar` hands this
/// function to `saola_theme::avatar::Avatar::resolve` as its decoder (the
/// design-system crate has no `image` dependency and must not grow one)
/// rather than re-deriving one, because the
/// `Handle::from_rgba` choice documented above (the one handle variant
/// `iced_wgpu`'s cache resolves synchronously) matters for the avatar too —
/// it appears the instant the user interacts, where a frame's delay would
/// read as a flash.
pub(crate) fn decode(bytes: &[u8]) -> Option<Handle> {
    let image = image::load_from_memory(bytes).ok()?;
    handle_from_dynamic_image(image)
}

/// Converts an already-decoded [`DynamicImage`] into an RGBA [`Handle`],
/// rejecting a zero-width or zero-height result. Split out from [`decode`]
/// purely so the zero-dimension fallback can be unit-tested by constructing
/// a `DynamicImage` directly, without depending on whether any real codec
/// in the `image` crate actually produces a 0×0 result in practice (most
/// refuse to encode one, which would make that path untestable through
/// [`decode`] alone).
fn handle_from_dynamic_image(image: DynamicImage) -> Option<Handle> {
    let rgba = image.to_rgba8();
    let (width, height) = rgba.dimensions();

    if width == 0 || height == 0 {
        return None;
    }

    Some(Handle::from_rgba(width, height, rgba.into_raw()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A tiny (2×2) valid PNG, built in memory with the same `image` crate
    /// we're testing the decode side of — no fixture file committed to the
    /// repo, per this task's "no giant binaries committed" instruction.
    fn tiny_png_bytes() -> Vec<u8> {
        let pixels = image::RgbaImage::from_pixel(2, 2, image::Rgba([10, 20, 30, 255]));
        let mut bytes = Vec::new();
        DynamicImage::ImageRgba8(pixels)
            .write_to(&mut Cursor::new(&mut bytes), image::ImageFormat::Png)
            .expect("encoding a 2x2 RGBA buffer as PNG cannot fail");
        bytes
    }

    /// The happy path: valid, small PNG bytes decode to a `Some` handle.
    /// `Handle` has no public accessor for width/height/format (and no
    /// `Debug`/`PartialEq` — see the Stage 3 handoff's gotchas section), so
    /// `is_some()` is as far as this test can assert without reaching into
    /// iced internals; the live nested-niri screenshot is what actually
    /// proves pixels land on screen (see the Stage 3 handoff addendum).
    #[test]
    fn valid_png_decodes_to_a_handle() {
        assert!(decode(&tiny_png_bytes()).is_some());
    }

    /// Bytes that aren't any recognized image format degrade to `None`,
    /// not a panic — the "undecodable" case from this task's brief.
    #[test]
    fn garbage_bytes_fail_to_decode() {
        assert!(decode(b"not an image, just some bytes").is_none());
    }

    /// A `DynamicImage` that decoded but has a zero dimension (this task's
    /// third explicit failure mode) is rejected rather than handed to
    /// `Handle::from_rgba`, which would otherwise build a handle iced's own
    /// raster pipeline treats as `raster::Error::Empty` deeper in its
    /// pipeline (see `iced_tiny_skia`'s `Cache::allocate`) — reject it here
    /// instead, where this crate can log why.
    #[test]
    fn zero_dimension_image_is_rejected() {
        let empty = DynamicImage::ImageRgba8(image::RgbaImage::new(0, 0));
        assert!(handle_from_dynamic_image(empty).is_none());
    }

    /// A path that doesn't exist at all falls back to `None` — the
    /// "unreadable" case from this task's brief, exercised through the
    /// real filesystem (unlike the two decode tests above) since that's
    /// the one thing [`load`] adds over [`decode`].
    #[test]
    fn missing_file_falls_back_to_none() {
        let path =
            std::env::temp_dir().join("saola-lockscreen-test-wallpaper-definitely-missing.png");
        std::fs::remove_file(&path).ok();

        assert!(load(&path).is_none());
    }

    /// The cache roundtrip: what `encode_cache` writes, `decode_cache`
    /// reads back byte-identically under the same key.
    #[test]
    fn cache_roundtrips() {
        let pixels = vec![1u8, 2, 3, 4, 5, 6, 7, 8]; // 2×1 RGBA
        let encoded = encode_cache(42, 2, 1, &pixels);

        assert_eq!(decode_cache(encoded, 42), Some((2, 1, pixels)));
    }

    /// A stale key — the wallpaper file changed since the cache was
    /// written — misses rather than serving the old pixels.
    #[test]
    fn cache_with_wrong_key_misses() {
        let encoded = encode_cache(42, 1, 1, &[0, 0, 0, 255]);
        assert_eq!(decode_cache(encoded, 43), None);
    }

    /// Garbage or old-format bytes (wrong magic) miss instead of being
    /// misread as pixels.
    #[test]
    fn cache_with_wrong_magic_misses() {
        let mut encoded = encode_cache(42, 1, 1, &[0, 0, 0, 255]);
        encoded[0] = b'X';
        assert_eq!(decode_cache(encoded, 42), None);
    }

    /// A truncated payload — the length no longer matches width × height
    /// × 4 — misses; this is the crash-mid-write case `write_cache`'s
    /// rename already guards against, validated independently here.
    #[test]
    fn truncated_cache_misses() {
        let mut encoded = encode_cache(42, 1, 1, &[0, 0, 0, 255]);
        encoded.pop();
        assert_eq!(decode_cache(encoded, 42), None);
    }

    /// A file shorter than the header itself misses without panicking.
    #[test]
    fn undersized_cache_misses() {
        assert_eq!(decode_cache(vec![1, 2, 3], 42), None);
    }

    /// A header claiming zero dimensions misses — same reject rule as
    /// [`handle_from_dynamic_image`]'s, applied to the cache path.
    #[test]
    fn zero_dimension_cache_misses() {
        let encoded = encode_cache(42, 0, 0, &[]);
        assert_eq!(decode_cache(encoded, 42), None);
    }

    /// An oversized image is downscaled to the cap on its longest side,
    /// preserving aspect ratio.
    #[test]
    fn oversized_image_is_scaled_to_cap() {
        let big = DynamicImage::ImageRgba8(image::RgbaImage::new(100, 50));
        let scaled = scale_to_cap(big, 50);
        assert_eq!((scaled.width(), scaled.height()), (50, 25));
    }

    /// An image already within the cap passes through untouched — the cap
    /// never upscales.
    #[test]
    fn small_image_is_not_upscaled() {
        let small = DynamicImage::ImageRgba8(image::RgbaImage::new(30, 20));
        let scaled = scale_to_cap(small, 50);
        assert_eq!((scaled.width(), scaled.height()), (30, 20));
    }

    /// `$XDG_CACHE_HOME/saola` wins over `~/.cache/saola`, and an empty
    /// env var falls through — the same empty-means-unset rule as
    /// `config::config_dir_from`, tested the same injected-argument way.
    #[test]
    fn cache_dir_prefers_xdg_and_treats_empty_as_unset() {
        assert_eq!(
            cache_dir_from(Some("/xdg".into()), Some("/home/jordan".into())),
            Some(PathBuf::from("/xdg/saola"))
        );
        assert_eq!(
            cache_dir_from(Some("".into()), Some("/home/jordan".into())),
            Some(PathBuf::from("/home/jordan/.cache/saola"))
        );
        assert_eq!(cache_dir_from(None, None), None);
    }
}
