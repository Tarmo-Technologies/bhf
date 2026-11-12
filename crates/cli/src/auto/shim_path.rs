// SPDX-License-Identifier: Apache-2.0

//! Find libbhf_runtrace.so on disk so the auto attempt loop
//! can LD_PRELOAD it. Search order:
//!
//!   1. $BHF_RUNTRACE_SHIM (explicit override)
//!   2. Sibling of std::env::current_exe() — same target dir as
//!      cli's build.rs copied it to.
//!   3. Cargo's native sibling cdylib name from direct shim builds.
//!   4. A sibling `bhf_runtrace_shim-*` dist archive directory.
//!   5. None — the shim isn't on disk; caller falls back to
//!      audit-disabled mode with a one-line warning.
//!
//! ld.so splits `LD_PRELOAD` on spaces and colons, so a shim installed under
//! such a path (`/opt/Program Files (x86)/bhf/bin`) would never load. The
//! located shim is then staged at a path ld.so reads whole
//! ([`stage_for_preload`]), and that copy is what [`locate`] returns.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The file name a staged copy of the shim gets.
const STAGED_NAME: &str = "libbhf_runtrace_shim.so";

/// The preloadable runtrace shim: the shim found on disk, or the copy of it
/// staged at a path `LD_PRELOAD` can carry. `None` when no shim is installed,
/// or when it sits under a path with spaces or colons and no copy could be
/// staged (warned once).
pub fn locate() -> Option<PathBuf> {
    let shim = locate_on_disk()?;
    if is_preload_safe(&shim) {
        return Some(shim);
    }
    let staged = stage_for_preload(&shim, &staging_dirs(&shim));
    if staged.is_none() && UNPRELOADABLE.set(shim.clone()).is_ok() {
        bhfeprintln!(
            "bhf: warning: the runtrace shim {} is under a path with a space or colon, which \
             LD_PRELOAD cannot carry, and no copy could be staged at a path without them \
             (tried {}); running without the shim",
            shim.display(),
            staging_dirs(&shim)
                .iter()
                .map(|dir| dir.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    staged
}

/// The shim on disk, wherever it was installed.
fn locate_on_disk() -> Option<PathBuf> {
    if let Some(env_path) = std::env::var_os("BHF_RUNTRACE_SHIM") {
        let p = PathBuf::from(env_path);
        if p.is_file() {
            return Some(p);
        }
    }
    let exe = std::env::current_exe().ok()?;
    locate_next_to_exe(&exe)
}

/// The shim that was found but could not be preloaded, once [`locate`] has
/// given up on it.
static UNPRELOADABLE: OnceLock<PathBuf> = OnceLock::new();

/// The work directory of this run, whose `.bhf-runtime/` is the first place a
/// shim that needs staging is copied to.
static STAGING_WORK_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Stage a shim that needs it under `<work_dir>/.bhf-runtime/` for the rest of
/// this process (the first call wins).
pub fn set_staging_work_dir(work_dir: &Path) {
    let _ = STAGING_WORK_DIR.set(std::path::absolute(work_dir).unwrap_or_else(|_| work_dir.into()));
}

/// Whether ld.so takes `path` whole from `LD_PRELOAD`, which it splits on
/// whitespace and colons.
pub fn is_preload_safe(path: &Path) -> bool {
    !path
        .as_os_str()
        .as_encoded_bytes()
        .iter()
        .any(|byte| byte.is_ascii_whitespace() || *byte == b':')
}

/// Where a shim that needs staging is copied, in order of preference:
/// `<work_dir>/.bhf-runtime/`, then `$TMPDIR/bhf-shim-<uid>-<hash>/` (and
/// `/tmp/bhf-shim-<uid>-<hash>/` when `$TMPDIR` itself needs quoting). The
/// hash is of the shim's own path, so each installed shim keeps one staged
/// copy per user. Only a directory private to this user is used
/// ([`private_dir`]).
fn staging_dirs(shim: &Path) -> Vec<PathBuf> {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(shim.as_os_str().as_encoded_bytes());
    #[cfg(unix)]
    let user = format!("{}-", unsafe { libc::geteuid() });
    #[cfg(not(unix))]
    let user = String::new();
    let name = format!(
        "bhf-shim-{user}{}",
        digest
            .iter()
            .take(4)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let mut dirs: Vec<PathBuf> = STAGING_WORK_DIR
        .get()
        .map(|work| work.join(".bhf-runtime"))
        .into_iter()
        .collect();
    dirs.push(std::env::temp_dir().join(&name));
    #[cfg(unix)]
    dirs.push(Path::new("/tmp").join(&name));
    dirs.dedup();
    dirs
}

/// `shim` itself when `LD_PRELOAD` can carry its path; otherwise a copy of it
/// in the first of `dirs` whose path it can carry and that is private to this
/// user. A copy is reused while it is current (same size and modification
/// time as the shim) and replaced when the shim was rebuilt. `None` when no
/// directory works.
///
/// `bhf auto --jobs N` workers locate the shim from their own threads, so one
/// staging runs at a time in this process; the first makes the copy and the
/// others reuse it. Another bhf process staging the same copy at once writes
/// its own temporary file, and whichever rename lands last leaves the same
/// bytes in place.
fn stage_for_preload(shim: &Path, dirs: &[PathBuf]) -> Option<PathBuf> {
    if is_preload_safe(shim) {
        return Some(shim.to_path_buf());
    }
    static STAGING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _staging = STAGING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let source = shim.metadata().ok()?;
    dirs.iter().find_map(|dir| {
        let staged = dir.join(STAGED_NAME);
        if !is_preload_safe(&staged) || !private_dir(dir) {
            return None;
        }
        if copy_is_current(&source, &staged) {
            return Some(staged);
        }
        match copy_shim(shim, &source, dir, &staged) {
            Ok(()) => Some(staged),
            // Another process staged the same copy meanwhile.
            Err(_) if copy_is_current(&source, &staged) => Some(staged),
            Err(_) => None,
        }
    })
}

/// Create `dir` readable and writable by this user alone, or check that the
/// existing one is: a real directory (not a symbolic link) owned by this user
/// with no permissions for its group or others. Anyone else who could write
/// there could plant the library bhf preloads into every harness, or swap the
/// copy after bhf made it, so such a directory is never used.
#[cfg(unix)]
fn private_dir(dir: &Path) -> bool {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return false,
    }
    std::fs::symlink_metadata(dir).is_ok_and(|meta| {
        meta.file_type().is_dir()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o077 == 0
    })
}

/// The runtrace shim is Linux-only: nothing is staged elsewhere.
#[cfg(not(unix))]
fn private_dir(_dir: &Path) -> bool {
    false
}

/// Whether `staged` is a regular file with `source`'s size and modification
/// time.
fn copy_is_current(source: &std::fs::Metadata, staged: &Path) -> bool {
    let Ok(copy) = std::fs::symlink_metadata(staged) else {
        return false;
    };
    copy.file_type().is_file()
        && copy.len() == source.len()
        && matches!(
            (copy.modified(), source.modified()),
            (Ok(copy), Ok(source)) if copy == source
        )
}

/// Copy `shim` to `staged` through a temporary file in `dir`, so a bhf
/// process loading the copy never sees it half-written, and give the copy the
/// shim's modification time.
fn copy_shim(
    shim: &Path,
    source: &std::fs::Metadata,
    dir: &Path,
    staged: &Path,
) -> std::io::Result<()> {
    // One temporary name per copy, so no two copies ever write one file.
    static COPIES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let copy = COPIES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let partial = dir.join(format!(
        ".{STAGED_NAME}.{}.{copy}.partial",
        std::process::id()
    ));
    std::fs::copy(shim, &partial)?;
    let result = (|| {
        if let Ok(modified) = source.modified() {
            std::fs::File::options()
                .write(true)
                .open(&partial)?
                .set_modified(modified)?;
        }
        std::fs::rename(&partial, staged)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&partial);
    }
    result
}

fn locate_next_to_exe(exe: &Path) -> Option<PathBuf> {
    let dir = exe.parent()?;
    // `libbhf_runtrace.so` is the dist-named copy cli's build.rs makes from
    // the canonical cargo cdylib `libbhf_runtrace_shim.so`. Prefer the copy to
    // preserve packaging intent — BUT cli's build.rs can lag the shim by one build
    // within a single `cargo build` (its rerun-if-changed fingerprint is decided
    // before the shim rebuilds in the same invocation), leaving the copy stale.
    // Loading a stale shim silently runs old instrumentation, so when the
    // canonical artifact is strictly newer than the copy, use the fresh one.
    let dist = dir.join("libbhf_runtrace.so");
    let shim = dir.join("libbhf_runtrace_shim.so");
    match (dist.is_file(), shim.is_file()) {
        (true, true) => Some(if shim_is_strictly_newer(&shim, &dist) {
            shim
        } else {
            dist
        }),
        (true, false) => Some(dist),
        (false, true) => Some(shim),
        (false, false) => locate_in_sibling_dist_dir(dir),
    }
}

/// Whether `shim`'s mtime is strictly newer than `dist`'s. Conservative: any
/// metadata error answers `false`, so an unreadable mtime keeps the dist-name
/// preference rather than risking a spurious switch.
fn shim_is_strictly_newer(shim: &Path, dist: &Path) -> bool {
    match (
        shim.metadata().and_then(|m| m.modified()),
        dist.metadata().and_then(|m| m.modified()),
    ) {
        (Ok(shim_mtime), Ok(dist_mtime)) => shim_mtime > dist_mtime,
        _ => false,
    }
}

fn locate_in_sibling_dist_dir(dir: &Path) -> Option<PathBuf> {
    let parent = dir.parent()?;
    let mut sibling_dirs: Vec<PathBuf> = std::fs::read_dir(parent)
        .ok()?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_dir())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("bhf_runtrace_shim-"))
        })
        .collect();
    sibling_dirs.sort();

    sibling_dirs
        .into_iter()
        .map(|path| path.join("libbhf_runtrace_shim.so"))
        .find(|path| path.is_file())
}

/// Convenience: format the LD_PRELOAD value to set, optionally
/// chained behind any existing LD_PRELOAD the user has in env.
///
/// Thin wrapper around [`ld_preload_value_with`] that reads
/// `$LD_PRELOAD` from the process environment.
pub fn ld_preload_value(shim: &Path) -> String {
    ld_preload_value_with(shim, std::env::var("LD_PRELOAD").ok().as_deref())
}

/// Pure variant of [`ld_preload_value`] that takes the existing
/// `LD_PRELOAD` value as a parameter. Kept separate so tests can
/// exercise the chaining logic without touching the global env
/// (which would race under cargo's parallel test runner).
pub fn ld_preload_value_with(shim: &Path, existing: Option<&str>) -> String {
    match existing {
        Some(v) if !v.is_empty() => format!("{}:{}", shim.display(), v),
        _ => shim.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ld_preload_chains_existing_value() {
        let p = ld_preload_value_with(Path::new("/tmp/shim.so"), Some("/tmp/other.so"));
        assert_eq!(p, "/tmp/shim.so:/tmp/other.so");
    }

    #[test]
    fn ld_preload_no_chain_when_empty() {
        // Both `None` and `Some("")` should produce the bare shim path.
        let none = ld_preload_value_with(Path::new("/tmp/shim.so"), None);
        assert_eq!(none, "/tmp/shim.so");
        let empty = ld_preload_value_with(Path::new("/tmp/shim.so"), Some(""));
        assert_eq!(empty, "/tmp/shim.so");
    }

    // The shim is preloaded on Linux only; elsewhere nothing is staged.
    #[cfg(unix)]
    #[test]
    fn a_spaced_shim_path_is_staged_at_a_preloadable_path() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir
            .path()
            .join("Program Files (x86)")
            .join("bhf")
            .join("bin");
        std::fs::create_dir_all(&install).unwrap();
        let shim = install.join("libbhf_runtrace.so");
        std::fs::write(&shim, b"shim-v1").unwrap();
        let work = dir.path().join("work");
        std::fs::create_dir_all(&work).unwrap();

        let staged = stage_for_preload(&shim, &[work.join(".bhf-runtime")]).unwrap();
        let text = staged.display().to_string();
        assert!(
            !text.contains(char::is_whitespace) && !text.contains(':'),
            "{text}"
        );
        assert!(staged.starts_with(work.join(".bhf-runtime")), "{text}");
        assert_eq!(std::fs::read(&staged).unwrap(), b"shim-v1");
        // ld.so would split the original path into `.../Program` and friends.
        assert!(!is_preload_safe(&shim));
        assert!(is_preload_safe(&staged));
        assert_eq!(ld_preload_value_with(&staged, None), text);
    }

    // The shim is preloaded on Linux only; elsewhere nothing is staged.
    #[cfg(unix)]
    #[test]
    fn a_staged_copy_is_refreshed_when_the_shim_changes() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("my tools");
        std::fs::create_dir_all(&install).unwrap();
        let shim = install.join("libbhf_runtrace_shim.so");
        std::fs::write(&shim, b"old").unwrap();
        let stage = dir.path().join("stage");
        let first = stage_for_preload(&shim, std::slice::from_ref(&stage)).unwrap();
        assert_eq!(std::fs::read(&first).unwrap(), b"old");
        // Same size and mtime: the copy is reused as it is.
        std::fs::write(&first, b"cpy").unwrap();
        let mtime = shim.metadata().unwrap().modified().unwrap();
        set_mtime(&first, mtime);
        let again = stage_for_preload(&shim, std::slice::from_ref(&stage)).unwrap();
        assert_eq!(std::fs::read(&again).unwrap(), b"cpy");
        // A rebuilt shim replaces the copy.
        std::fs::write(&shim, b"newer").unwrap();
        let refreshed = stage_for_preload(&shim, std::slice::from_ref(&stage)).unwrap();
        assert_eq!(refreshed, first);
        assert_eq!(std::fs::read(&refreshed).unwrap(), b"newer");
    }

    /// A staging directory another local user could write to (pre-created
    /// world-writable, the way a planted `/tmp/bhf-shim-<hash>/` would be) is
    /// never used: a library planted there would be preloaded into every
    /// harness. The next directory, created private, is used instead.
    #[cfg(unix)]
    #[test]
    fn a_staging_dir_others_can_write_is_not_used() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("my tools");
        std::fs::create_dir_all(&install).unwrap();
        let shim = install.join("libbhf_runtrace.so");
        std::fs::write(&shim, b"genuine").unwrap();
        let planted = dir.path().join("planted");
        std::fs::create_dir_all(&planted).unwrap();
        std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o777)).unwrap();
        // A copy that looks current (same size and modification time).
        let decoy = planted.join(STAGED_NAME);
        std::fs::write(&decoy, b"planted").unwrap();
        set_mtime(&decoy, shim.metadata().unwrap().modified().unwrap());
        let private = dir.path().join("private");
        let staged = stage_for_preload(&shim, &[planted.clone(), private.clone()]).unwrap();
        assert_eq!(staged, private.join(STAGED_NAME));
        assert_eq!(std::fs::read(&staged).unwrap(), b"genuine");
        let mode = private.metadata().unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "the staging dir is private: {mode:o}");
        // With only the planted directory there is nowhere safe to stage.
        assert_eq!(
            stage_for_preload(&shim, std::slice::from_ref(&planted)),
            None
        );
    }

    /// `bhf auto --jobs N` workers locate the shim from their own threads.
    /// When they stage it at the same moment, every one of them gets the
    /// complete copy: none runs its pass without the shim, and no temporary
    /// copy is left behind.
    #[cfg(unix)]
    #[test]
    fn concurrent_stagings_all_get_the_complete_copy() {
        const WORKERS: usize = 8;
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("Program Files").join("bhf");
        std::fs::create_dir_all(&install).unwrap();
        let shim = install.join("libbhf_runtrace.so");
        // About the size of a debug build of the shim, so the copies overlap.
        let bytes: Vec<u8> = (0u32..16 << 20).map(|i| (i % 251) as u8).collect();
        std::fs::write(&shim, &bytes).unwrap();
        let stage = dir.path().join("stage");
        let expected = stage.join(STAGED_NAME);
        for round in 0..3 {
            let _ = std::fs::remove_file(&expected);
            let barrier = std::sync::Barrier::new(WORKERS);
            let staged: Vec<Option<PathBuf>> = std::thread::scope(|scope| {
                let workers: Vec<_> = (0..WORKERS)
                    .map(|_| {
                        scope.spawn(|| {
                            barrier.wait();
                            stage_for_preload(&shim, std::slice::from_ref(&stage))
                        })
                    })
                    .collect();
                workers
                    .into_iter()
                    .map(|worker| worker.join().unwrap())
                    .collect()
            });
            assert!(
                staged
                    .iter()
                    .all(|path| path.as_deref() == Some(expected.as_path())),
                "round {round}: {staged:?}"
            );
            assert!(
                std::fs::read(&expected).unwrap() == bytes,
                "round {round}: the staged copy is incomplete"
            );
            let leftovers: Vec<_> = std::fs::read_dir(&stage)
                .unwrap()
                .flatten()
                .map(|entry| entry.file_name())
                .filter(|name| name != STAGED_NAME)
                .collect();
            assert!(leftovers.is_empty(), "round {round}: {leftovers:?}");
        }
    }

    // The shim is preloaded on Linux only; elsewhere nothing is staged.
    #[cfg(unix)]
    #[test]
    fn a_shim_with_no_preloadable_staging_dir_is_not_armed() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("a b");
        std::fs::create_dir_all(&install).unwrap();
        let shim = install.join("libbhf_runtrace.so");
        std::fs::write(&shim, b"x").unwrap();
        let unsafe_dirs = [dir.path().join("c d"), dir.path().join("e:f")];
        assert_eq!(stage_for_preload(&shim, &unsafe_dirs), None);
        // A path ld.so reads whole is used where it is, never copied.
        let plain = dir.path().join("libbhf_runtrace.so");
        std::fs::write(&plain, b"x").unwrap();
        assert_eq!(stage_for_preload(&plain, &unsafe_dirs), Some(plain));
    }

    #[test]
    fn locate_next_to_exe_accepts_cargo_cdylib_name() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("bhf");
        let shim = dir.path().join("libbhf_runtrace_shim.so");
        std::fs::write(&exe, "").unwrap();
        std::fs::write(&shim, "").unwrap();

        assert_eq!(locate_next_to_exe(&exe), Some(shim));
    }

    /// Set a file's mtime so the locator's freshness comparison is deterministic
    /// (writing two files back-to-back gives unreliable mtime ordering).
    fn set_mtime(path: &Path, t: std::time::SystemTime) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(t)
            .unwrap();
    }

    #[test]
    fn locate_next_to_exe_prefers_dist_name_when_not_older() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("bhf");
        let dist_shim = dir.path().join("libbhf_runtrace.so");
        let cargo_shim = dir.path().join("libbhf_runtrace_shim.so");
        std::fs::write(&exe, "").unwrap();
        std::fs::write(&dist_shim, "").unwrap();
        std::fs::write(&cargo_shim, "").unwrap();
        // Dist copy at least as new as the cargo artifact -> dist preference holds.
        let now = std::time::SystemTime::now();
        set_mtime(&cargo_shim, now - std::time::Duration::from_secs(10));
        set_mtime(&dist_shim, now);

        assert_eq!(locate_next_to_exe(&exe), Some(dist_shim));
    }

    #[test]
    fn locate_next_to_exe_uses_fresh_cargo_artifact_over_stale_copy() {
        // The build-ordering footgun: cli's build.rs lagged, so the dist copy is
        // stale while the canonical cargo cdylib was just rebuilt. The locator
        // must load the fresh artifact, not the stale copy.
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("bhf");
        let dist_shim = dir.path().join("libbhf_runtrace.so");
        let cargo_shim = dir.path().join("libbhf_runtrace_shim.so");
        std::fs::write(&exe, "").unwrap();
        std::fs::write(&dist_shim, "").unwrap();
        std::fs::write(&cargo_shim, "").unwrap();
        let now = std::time::SystemTime::now();
        set_mtime(&dist_shim, now - std::time::Duration::from_secs(10));
        set_mtime(&cargo_shim, now);

        assert_eq!(locate_next_to_exe(&exe), Some(cargo_shim));
    }

    #[test]
    fn locate_next_to_exe_accepts_sibling_dist_archive_dir() {
        let dir = tempfile::tempdir().unwrap();
        let bhf_dir = dir.path().join("bhf-x86_64-unknown-linux-gnu");
        let shim_dir = dir
            .path()
            .join("bhf_runtrace_shim-x86_64-unknown-linux-gnu");
        std::fs::create_dir_all(&bhf_dir).unwrap();
        std::fs::create_dir_all(&shim_dir).unwrap();
        let exe = bhf_dir.join("bhf");
        let shim = shim_dir.join("libbhf_runtrace_shim.so");
        std::fs::write(&exe, "").unwrap();
        std::fs::write(&shim, "").unwrap();

        assert_eq!(locate_next_to_exe(&exe), Some(shim));
    }
}
