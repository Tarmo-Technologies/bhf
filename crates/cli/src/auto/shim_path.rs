// SPDX-License-Identifier: Apache-2.0

//! Find the runtrace shim on disk so the auto attempt loop
//! can LD_PRELOAD it. Search order:
//!
//!   1. $BHF_RUNTRACE_SHIM (explicit override)
//!   2. Cargo's cdylib `libbhf_runtrace_shim.so`, a sibling of
//!      std::env::current_exe().
//!   3. The dist-named copy `libbhf_runtrace.so` beside it, when the cdylib
//!      is not there (the copy is made from the cdylib, so it is never newer
//!      in content).
//!   4. A sibling `bhf_runtrace_shim-*` dist archive directory.
//!   5. None — the shim isn't on disk; caller falls back to
//!      audit-disabled mode with a one-line warning.
//!
//! The shim is an `LD_PRELOAD` library built for Linux only. On every other
//! platform (macOS, Windows) none is located, whatever is on disk, and
//! [`unavailable_reason`] says the platform has none.

use std::path::{Path, PathBuf};

/// The preloadable runtrace shim: the shim found on disk, or the copy of it
/// staged at a path `LD_PRELOAD` can carry. `None` when no shim is installed,
/// or when it sits under a path with spaces or colons and no copy could be
/// staged (warned once; see [`unavailable_reason`]).
///
/// ld.so splits `LD_PRELOAD` on spaces and colons, so a shim installed under
/// such a path (`/opt/Program Files (x86)/bhf/bin`) would never load: it is
/// staged at a path ld.so reads whole (`stage_for_preload`), and that copy
/// is what this returns.
pub fn locate() -> Option<PathBuf> {
    if !BUILT_FOR_THIS_PLATFORM {
        return None;
    }
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

/// Why [`locate`] found no shim, as one sentence for a warning or an error:
/// it is not installed where bhf looks, or it is installed under a path that
/// `LD_PRELOAD` cannot carry and no copy could be staged.
pub fn unavailable_reason() -> String {
    if !BUILT_FOR_THIS_PLATFORM {
        return not_built_message(std::env::consts::OS);
    }
    if let Some(shim) = UNPRELOADABLE.get() {
        return format!(
            "the runtrace shim {} is under a path with a space or colon, which LD_PRELOAD \
             cannot carry, and no copy of it could be staged at a path without them",
            shim.display()
        );
    }
    let exe = std::env::current_exe().ok();
    missing_message(
        exe.as_deref(),
        std::env::var_os("BHF_RUNTRACE_SHIM").as_deref(),
    )
}

/// Whether bhf has a runtrace shim on this platform: the shim is an
/// `LD_PRELOAD` library, built for Linux only (its crate builds an empty
/// library elsewhere, which bhf never loads).
pub(crate) const BUILT_FOR_THIS_PLATFORM: bool = cfg!(target_os = "linux");

/// [`unavailable_reason`] on a platform (`os`, as `std::env::consts::OS`
/// names it) for which no runtrace shim is built.
fn not_built_message(os: &str) -> String {
    format!(
        "the runtrace shim is built for Linux only (it is loaded with LD_PRELOAD), so on {os} \
         bhf runs native harnesses without it"
    )
}

/// The file beside a harness that records why its last builtin fuzz pass ran
/// without the runtrace shim (one line, [`unavailable_reason`]). The target's
/// fidelity reports it as `runtime_shim`.
pub(crate) const UNAVAILABLE_RECORD: &str = "runtrace_shim_unavailable.txt";

/// Record beside the harness in `harness_dir` that its fuzz pass ran without
/// the runtrace shim for `reason`, or, with `None` (the shim was loaded, or the
/// harness never takes it), remove that record. Best-effort.
pub(crate) fn record_unavailable(harness_dir: &Path, reason: Option<&str>) {
    let record = harness_dir.join(UNAVAILABLE_RECORD);
    match reason {
        Some(reason) => {
            let _ = std::fs::write(record, format!("{}\n", reason.trim()));
        }
        None => {
            let _ = std::fs::remove_file(record);
        }
    }
}

/// The reason [`record_unavailable`] recorded beside the harness in
/// `harness_dir`, or `None` when its fuzz pass had the shim (or never took it).
pub(crate) fn recorded_unavailable(harness_dir: &Path) -> Option<String> {
    std::fs::read_to_string(harness_dir.join(UNAVAILABLE_RECORD))
        .ok()
        .map(|reason| reason.trim().to_owned())
        .filter(|reason| !reason.is_empty())
}

/// [`unavailable_reason`] for a shim that is not installed, naming every
/// place [`locate`] looked: beside `exe`, a sibling dist directory, and
/// `$BHF_RUNTRACE_SHIM` (`env`) when it was set.
fn missing_message(exe: Option<&Path>, env: Option<&std::ffi::OsStr>) -> String {
    let beside = exe
        .and_then(Path::parent)
        .map(|dir| dir.display().to_string())
        .unwrap_or_else(|| "the bhf executable".to_owned());
    let env = match env {
        Some(value) if !value.is_empty() => format!(
            "BHF_RUNTRACE_SHIM={} is not a file; ",
            Path::new(value).display()
        ),
        _ => String::new(),
    };
    format!(
        "{env}the runtrace shim (libbhf_runtrace.so or libbhf_runtrace_shim.so) was not found \
         beside {beside} or in a sibling bhf_runtrace_shim directory; set \
         BHF_RUNTRACE_SHIM=<path> to use one"
    )
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
static UNPRELOADABLE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// The work directory of this run, whose `.bhf-runtime/` is the first place a
/// shim that needs staging is copied to.
static STAGING_WORK_DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Stage a shim that needs it under `<work_dir>/.bhf-runtime/` for the rest of
/// this process (the first call wins).
pub fn set_staging_work_dir(work_dir: &Path) {
    let _ = STAGING_WORK_DIR.set(std::path::absolute(work_dir).unwrap_or_else(|_| work_dir.into()));
}

/// The file name a staged copy of the shim gets.
const STAGED_NAME: &str = "libbhf_runtrace_shim.so";

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
/// user. A copy is reused only while its bytes are the shim's, and replaced
/// otherwise (a rebuilt shim, or a file with the same size and modification
/// time but other contents). `None` when no directory works.
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
        if copy_is_current(shim, &source, &staged) {
            return Some(staged);
        }
        match copy_shim(shim, &source, dir, &staged) {
            Ok(()) => Some(staged),
            // Another process staged the same copy meanwhile.
            Err(_) if copy_is_current(shim, &source, &staged) => Some(staged),
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

/// Whether `staged` is a regular file (not a symbolic link) holding exactly
/// `shim`'s bytes (`source` is `shim`'s metadata). The contents are compared,
/// not the size and modification time, which anyone who can write the file
/// can set: a staged copy is preloaded into every harness, so it is never
/// trusted unverified.
fn copy_is_current(shim: &Path, source: &std::fs::Metadata, staged: &Path) -> bool {
    let Ok(copy) = std::fs::symlink_metadata(staged) else {
        return false;
    };
    copy.file_type().is_file() && copy.len() == source.len() && same_contents(shim, staged)
}

/// Whether the files `a` and `b` hold the same bytes; `false` when either
/// cannot be read.
fn same_contents(a: &Path, b: &Path) -> bool {
    use std::io::Read;
    let (Ok(mut a), Ok(mut b)) = (std::fs::File::open(a), std::fs::File::open(b)) else {
        return false;
    };
    let mut left = vec![0u8; 64 * 1024];
    let mut right = vec![0u8; 64 * 1024];
    loop {
        let Ok(read) = read_full(&mut a, &mut left) else {
            return false;
        };
        let Ok(other) = read_full(&mut b, &mut right) else {
            return false;
        };
        if read != other || left[..read] != right[..other] {
            return false;
        }
        if read == 0 {
            return true;
        }
    }

    /// Fill `buf` from `file` until it is full or the file ends.
    fn read_full(file: &mut std::fs::File, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut filled = 0;
        while filled < buf.len() {
            match file.read(&mut buf[filled..])? {
                0 => break,
                read => filled += read,
            }
        }
        Ok(filled)
    }
}

/// Copy `shim` to `staged` through a temporary file in `dir`, so a bhf
/// process loading the copy never sees it half-written, and give the copy the
/// shim's modification time. The rename into `dir`, which only this user can
/// write, replaces whatever was there.
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
    // the canonical cargo cdylib `libbhf_runtrace_shim.so`, so with both
    // present the cdylib is the current shim: the copy can lag a shim rebuild
    // (build.rs makes it only when it reruns), and a copy written after the
    // cdylib (`cp`, an archive extract, `rsync`) can still hold an older shim
    // whatever its mtime says. Loading a stale shim silently runs old
    // instrumentation. The copy is used only when it is the only one.
    let dist = dir.join("libbhf_runtrace.so");
    let shim = dir.join("libbhf_runtrace_shim.so");
    match (dist.is_file(), shim.is_file()) {
        (_, true) => Some(shim),
        (true, false) => Some(dist),
        (false, false) => locate_in_sibling_dist_dir(dir),
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
        // A copy with the shim's size and modification time but other bytes
        // is never trusted: the shim's own bytes replace it.
        std::fs::write(&first, b"cpy").unwrap();
        let mtime = shim.metadata().unwrap().modified().unwrap();
        set_mtime(&first, mtime);
        let again = stage_for_preload(&shim, std::slice::from_ref(&stage)).unwrap();
        assert_eq!(again, first);
        assert_eq!(std::fs::read(&again).unwrap(), b"old");
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
    fn the_missing_shim_message_names_both_files_where_it_looked_and_the_override() {
        let message = missing_message(Some(Path::new("/opt/bhf/bin/bhf")), None);
        assert_eq!(
            message,
            "the runtrace shim (libbhf_runtrace.so or libbhf_runtrace_shim.so) was not found \
             beside /opt/bhf/bin or in a sibling bhf_runtrace_shim directory; set \
             BHF_RUNTRACE_SHIM=<path> to use one"
        );
        let stale = missing_message(
            Some(Path::new("/opt/bhf/bin/bhf")),
            Some(std::ffi::OsStr::new("/old/libbhf_runtrace.so")),
        );
        assert!(
            stale.starts_with("BHF_RUNTRACE_SHIM=/old/libbhf_runtrace.so is not a file; "),
            "{stale}"
        );
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

    /// The copy is made from the cargo cdylib, so with both present the cdylib
    /// is current whatever the mtimes say: a copy written after it (by `cp`,
    /// an archive extract, `rsync`) can still hold an older shim.
    #[test]
    fn locate_next_to_exe_prefers_the_cargo_shim_whatever_the_mtimes() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("bhf");
        let dist_shim = dir.path().join("libbhf_runtrace.so");
        let cargo_shim = dir.path().join("libbhf_runtrace_shim.so");
        std::fs::write(&exe, "").unwrap();
        std::fs::write(&dist_shim, "old shim").unwrap();
        std::fs::write(&cargo_shim, "current shim").unwrap();
        let now = std::time::SystemTime::now();
        set_mtime(&cargo_shim, now - std::time::Duration::from_secs(10));
        set_mtime(&dist_shim, now);

        assert_eq!(locate_next_to_exe(&exe), Some(cargo_shim));
    }

    #[test]
    fn locate_next_to_exe_uses_the_dist_name_when_it_is_alone() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("bhf");
        let dist_shim = dir.path().join("libbhf_runtrace.so");
        std::fs::write(&exe, "").unwrap();
        std::fs::write(&dist_shim, "shim").unwrap();

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

    /// Off Linux no runtrace shim is built (it is an `LD_PRELOAD` library), so
    /// the reason names the platform instead of an install path to fix.
    #[test]
    fn the_reason_off_linux_names_the_platform() {
        let message = not_built_message("macos");
        assert_eq!(
            message,
            "the runtrace shim is built for Linux only (it is loaded with LD_PRELOAD), so on \
             macos bhf runs native harnesses without it"
        );
        assert!(!message.contains("BHF_RUNTRACE_SHIM"), "{message}");
    }

    /// Where no shim is built for the platform, none is ever located, and the
    /// reason says the platform has none.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn no_shim_is_located_where_none_is_built() {
        assert_eq!(locate(), None);
        assert_eq!(
            unavailable_reason(),
            not_built_message(std::env::consts::OS)
        );
    }

    /// The record of a pass run without the shim holds the reason, and a pass
    /// with the shim removes it.
    #[test]
    fn a_pass_without_the_shim_is_recorded_beside_the_harness() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(recorded_unavailable(dir.path()), None);
        record_unavailable(dir.path(), Some("no shim here"));
        assert_eq!(
            recorded_unavailable(dir.path()).as_deref(),
            Some("no shim here")
        );
        record_unavailable(dir.path(), None);
        assert_eq!(recorded_unavailable(dir.path()), None);
        assert!(!dir.path().join(UNAVAILABLE_RECORD).exists());
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
