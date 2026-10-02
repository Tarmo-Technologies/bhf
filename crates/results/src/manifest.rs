// SPDX-License-Identifier: Apache-2.0
//! `results/manifest.json` (`bhf.results-manifest.v1`): tool identity, source
//! identity, and one entry per producer invocation.
//!
//! Source VCS identity is read from `.git` files directly. bhf scans untrusted
//! trees, and running `git status` there can execute repository-controlled
//! config (`core.fsmonitor`), so we never spawn git here. Every read is
//! bounded, refuses to follow symlinks, and refuses anything that is not a
//! plain file (so a FIFO or device planted at `.git/HEAD` cannot hang or
//! misdirect the read).

use crate::model::{Manifest, SourceInfo, ToolInfo, Vcs, MANIFEST_SCHEMA_VERSION};
use crate::{io_err, ResultsError};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

pub const MANIFEST_FILE: &str = "manifest.json";
const SENSITIVE: [&str; 4] = ["key", "token", "secret", "password"];
const SMALL_FILE_LIMIT: u64 = 4 * 1024;
const PACKED_REFS_LIMIT: u64 = 8 * 1024 * 1024;

pub fn tool_info() -> ToolInfo {
    let version = env!("CARGO_PKG_VERSION");
    ToolInfo {
        name: "bhf".to_owned(),
        version: version.to_owned(),
        build: option_env!("BHF_VERSION_FULL")
            .unwrap_or(version)
            .to_owned(),
    }
}

pub fn source_info(root: Option<&Path>) -> SourceInfo {
    SourceInfo {
        root: root.map(|r| r.to_string_lossy().into_owned()),
        vcs: root.and_then(read_vcs),
    }
}

/// HEAD commit + branch from `.git` files (worktree `gitdir:` files, loose
/// refs, `packed-refs`). `dirty` is never computed (it would need `git status`).
pub fn read_vcs(root: &Path) -> Option<Vcs> {
    let git_dir = git_dir(root)?;
    let head = read_bounded(&git_dir.join("HEAD"), SMALL_FILE_LIMIT)?;
    let head = head.trim();
    let (commit, branch) = match head.strip_prefix("ref: ") {
        Some(reference) => {
            let commit = resolve_ref(&git_dir, reference)?;
            (
                commit,
                reference.strip_prefix("refs/heads/").map(str::to_owned),
            )
        }
        None => (head.to_owned(), None),
    };
    is_object_id(&commit).then_some(Vcs {
        kind: "git".to_owned(),
        commit,
        branch,
        dirty: None,
    })
}

/// `symlink_metadata` so a `.git` that is itself a symlink to outside the
/// tree is not silently followed into a directory we did not intend to read.
fn git_dir(root: &Path) -> Option<PathBuf> {
    let dot_git = root.join(".git");
    let meta = std::fs::symlink_metadata(&dot_git).ok()?;
    if meta.is_dir() {
        return Some(dot_git);
    }
    if meta.is_file() {
        let text = read_bounded(&dot_git, SMALL_FILE_LIMIT)?;
        let target = text.trim().strip_prefix("gitdir:")?.trim();
        if is_windows_unc_or_device(target) {
            return None;
        }
        let target = Path::new(target);
        return Some(if target.is_absolute() {
            target.to_path_buf()
        } else {
            root.join(target)
        });
    }
    None
}

fn resolve_ref(git_dir: &Path, reference: &str) -> Option<String> {
    if !valid_refname(reference) {
        return None;
    }
    let common = read_bounded(&git_dir.join("commondir"), SMALL_FILE_LIMIT)
        .map(|c| c.trim().to_owned())
        .filter(|c| !is_windows_unc_or_device(c))
        .map(|c| git_dir.join(c));
    let dirs: Vec<&Path> = match &common {
        Some(common) if common != git_dir => vec![git_dir, common.as_path()],
        _ => vec![git_dir],
    };
    for dir in dirs {
        if has_symlinked_ancestor(dir, reference) {
            continue;
        }
        if let Some(text) = read_bounded(&dir.join(reference), SMALL_FILE_LIMIT) {
            return Some(text.trim().to_owned());
        }
        if let Some(packed) = read_bounded(&dir.join("packed-refs"), PACKED_REFS_LIMIT) {
            for line in packed.lines() {
                if let Some((sha, name)) = line.split_once(' ') {
                    if name.trim() == reference {
                        return Some(sha.to_owned());
                    }
                }
            }
        }
    }
    None
}

/// `O_NOFOLLOW` in [`open_regular_file`] only refuses a symlink at the final
/// path component, so a symlinked *directory* earlier in `reference` (e.g.
/// `refs/heads` pointing anywhere on disk) would otherwise still be
/// traversed and its target read. Walk every directory component between
/// `dir` and the leaf and reject if any of them is a symlink.
fn has_symlinked_ancestor(dir: &Path, reference: &str) -> bool {
    let components: Vec<&str> = reference.split('/').collect();
    let mut path = dir.to_path_buf();
    for component in &components[..components.len().saturating_sub(1)] {
        path.push(component);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
    false
}

/// A conservative check in the spirit of git's `check_refname_format`: a
/// fully-qualified ref under `refs/`, no path traversal, no control
/// characters or shell/glob metacharacters, and no trailing `.lock` (git's
/// own lockfile suffix, never a legitimate ref on disk).
fn valid_refname(reference: &str) -> bool {
    if !reference.starts_with("refs/") || reference.contains("..") || reference.contains("@{") {
        return false;
    }
    if reference.ends_with('/') || reference.ends_with(".lock") {
        return false;
    }
    if !reference.chars().all(|c| {
        !c.is_ascii_control() && !matches!(c, ' ' | '~' | '^' | ':' | '?' | '*' | '[' | '\\')
    }) {
        return false;
    }
    reference
        .split('/')
        .all(|component| !component.is_empty() && !component.starts_with('.'))
}

/// True for a UNC share (`\\server\share\...`), the explicit UNC prefix
/// (`\\?\UNC\server\share\...`), or a device-namespace path (`\\.\...`), the
/// three windows path shapes a `gitdir:`/`commondir` pointer must not be
/// allowed to redirect reads to. Written as pure string logic (not
/// `std::path::Prefix`, which only classifies on windows) so it is testable
/// on every platform; a `\\?\C:\...` verbatim disk path is left alone.
fn is_windows_unc_or_device(target: &str) -> bool {
    let normalized = target.replace('/', "\\");
    let Some(rest) = normalized.strip_prefix(r"\\") else {
        return false;
    };
    if rest.starts_with('.') {
        return true;
    }
    match rest.strip_prefix(r"?\") {
        Some(verbatim) => verbatim.to_ascii_uppercase().starts_with("UNC\\"),
        None => true,
    }
}

/// Reads at most `limit` bytes as UTF-8, refusing to follow a symlink at
/// `path` and refusing anything that is not a plain file once opened (a FIFO
/// or character/block device would otherwise hang or misdirect a read of
/// e.g. `.git/HEAD`). `.git` metadata files are always tiny except
/// `packed-refs`, which can grow in large repos.
fn read_bounded(path: &Path, limit: u64) -> Option<String> {
    let file = open_regular_file(path)?;
    let mut buf = Vec::new();
    file.take(limit).read_to_end(&mut buf).ok()?;
    String::from_utf8(buf).ok()
}

#[cfg(unix)]
fn open_regular_file(path: &Path) -> Option<File> {
    use std::os::unix::fs::OpenOptionsExt;
    // O_NONBLOCK: opening a FIFO for read never blocks waiting for a writer.
    // O_NOCTTY: never attach a controlling terminal. O_NOFOLLOW: refuse a
    // symlink at the final path component.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    file.metadata().ok()?.is_file().then_some(file)
}

#[cfg(windows)]
fn open_regular_file(path: &Path) -> Option<File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    // `symlink_metadata` never follows the final component, so this catches
    // a symlink at `path` itself before anything is opened.
    if std::fs::symlink_metadata(path)
        .ok()?
        .file_type()
        .is_symlink()
    {
        return None;
    }
    // FILE_FLAG_OPEN_REPARSE_POINT: open the reparse point itself rather
    // than transparently following it, mirroring
    // crates/continuous_daemon/src/storage_lock.rs.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(0x0020_0000)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if metadata.file_attributes() & 0x400 != 0 {
        // FILE_ATTRIBUTE_REPARSE_POINT: still a link (junction, mount point,
        // ...) even though the leaf-symlink check above passed.
        return None;
    }
    metadata.is_file().then_some(file)
}

#[cfg(not(any(unix, windows)))]
fn open_regular_file(path: &Path) -> Option<File> {
    let file = File::open(path).ok()?;
    file.metadata().ok()?.is_file().then_some(file)
}

fn is_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

pub fn redact_argv(argv: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut redact_next = false;
    for arg in argv {
        if redact_next {
            redact_next = false;
            if !arg.starts_with('-') {
                out.push("<redacted>".to_owned());
                continue;
            }
            // A sensitive flag with no value attached (e.g. a bare
            // `--api-key` immediately followed by another flag); don't
            // swallow the next flag as if it were the value.
        }
        if let Some(redacted) = redact_assignment(arg) {
            out.push(redacted);
            continue;
        }
        if arg.starts_with('-')
            && !arg.contains('=')
            && is_sensitive_name(arg.trim_start_matches('-'))
        {
            redact_next = true;
        }
        out.push(arg.clone());
    }
    out
}

fn is_sensitive_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    SENSITIVE.iter().any(|word| name.contains(word))
}

/// Redacts the value half of a `NAME=VALUE`-shaped argument when NAME looks
/// sensitive: a bare `API_TOKEN=x`, a flag `--token=abc`, or a flag whose own
/// value is itself `NAME=VALUE`-shaped (`--env=GH_TOKEN=ghp_x`). Splits only
/// on the first `=` at each level, so a value that itself contains `=`
/// (base64, `a=b`, ...) is still fully redacted rather than leaked after a
/// second `=`.
fn redact_assignment(arg: &str) -> Option<String> {
    let (lhs, value) = arg.split_once('=')?;
    if is_sensitive_name(lhs.trim_start_matches('-')) {
        return Some(format!("{lhs}=<redacted>"));
    }
    let (name, _) = value.split_once('=')?;
    is_sensitive_name(name).then(|| format!("{lhs}={name}=<redacted>"))
}

pub fn empty_manifest() -> Manifest {
    Manifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_owned(),
        tool: tool_info(),
        source: SourceInfo::default(),
        producers: Vec::new(),
    }
}

/// Load `results/manifest.json`; a missing file is empty, and a corrupt one
/// is moved aside to `manifest.json.corrupt-<unix-nanos>-<pid>` (logging the
/// parse failure to stderr so it is not silently discarded) and replaced by
/// an empty one.
///
/// Caller must hold a [`crate::lock::ResultsLock`] on `results_dir` for the
/// duration of any load-modify-save sequence; this function does not lock.
pub fn load(results_dir: &Path) -> Result<Manifest, ResultsError> {
    let path = results_dir.join(MANIFEST_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(empty_manifest()),
        Err(source) => return Err(ResultsError::Io { path, source }),
    };
    match serde_json::from_slice::<Manifest>(&bytes) {
        Ok(manifest) => Ok(manifest),
        Err(parse_error) => {
            eprintln!(
                "bhf: {} is corrupt ({parse_error}); moving aside and starting a fresh manifest",
                path.display()
            );
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let aside = results_dir.join(format!(
                "{MANIFEST_FILE}.corrupt-{stamp}-{}",
                std::process::id()
            ));
            std::fs::rename(&path, &aside).map_err(io_err(&path))?;
            Ok(empty_manifest())
        }
    }
}

/// Caller must hold a [`crate::lock::ResultsLock`] on `results_dir`.
pub fn save(results_dir: &Path, manifest: &Manifest) -> Result<(), ResultsError> {
    let path = results_dir.join(MANIFEST_FILE);
    let mut bytes = serde_json::to_vec_pretty(manifest).map_err(|source| ResultsError::Json {
        path: path.clone(),
        source,
    })?;
    bytes.push(b'\n');
    crate::rebuild::write_atomic(&path, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ProducerRecord, ProducerStatus};

    #[test]
    fn argv_redaction() {
        let argv: Vec<String> = [
            "bhf",
            "llm",
            "--api-key",
            "sk-123",
            "--token=abc",
            "--out",
            "x",
            "--private-key",
            "p.der",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            redact_argv(&argv),
            [
                "bhf",
                "llm",
                "--api-key",
                "<redacted>",
                "--token=<redacted>",
                "--out",
                "x",
                "--private-key",
                "<redacted>"
            ]
        );
    }

    #[test]
    fn argv_redaction_handles_name_value_shapes() {
        let argv: Vec<String> = [
            "API_TOKEN=x",
            "--env",
            "API_TOKEN=sk",
            "--env=GH_TOKEN=ghp_x",
            "--out",
            "x",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            redact_argv(&argv),
            [
                "API_TOKEN=<redacted>",
                "--env",
                "API_TOKEN=<redacted>",
                "--env=GH_TOKEN=<redacted>",
                "--out",
                "x"
            ]
        );
    }

    #[test]
    fn argv_redaction_does_not_swallow_a_flag_after_a_bare_sensitive_flag() {
        let argv: Vec<String> = ["--api-key", "--verbose"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(redact_argv(&argv), ["--api-key", "--verbose"]);
    }

    #[test]
    fn argv_redaction_fully_redacts_values_containing_equals() {
        let argv: Vec<String> = [
            "--api-key=abc==",
            "--env",
            "API_TOKEN=a=b",
            "--out=tokens.txt",
            "v",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            redact_argv(&argv),
            [
                "--api-key=<redacted>",
                "--env",
                "API_TOKEN=<redacted>",
                "--out=tokens.txt",
                "v"
            ]
        );
    }

    #[test]
    fn reads_git_head_without_running_git() {
        let tmp = tempfile::tempdir().unwrap();
        let git = tmp.path().join(".git");
        std::fs::create_dir_all(git.join("refs/heads")).unwrap();
        std::fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        let sha = "0123456789abcdef0123456789abcdef01234567";
        std::fs::write(git.join("refs/heads/main"), format!("{sha}\n")).unwrap();
        let vcs = read_vcs(tmp.path()).unwrap();
        assert_eq!(vcs.commit, sha);
        assert_eq!(vcs.branch.as_deref(), Some("main"));
        assert_eq!(vcs.dirty, None);
    }

    #[test]
    fn reads_packed_refs_and_detached_head() {
        let tmp = tempfile::tempdir().unwrap();
        let git = tmp.path().join(".git");
        std::fs::create_dir_all(&git).unwrap();
        let sha = "89abcdef0123456789abcdef0123456789abcdef";
        std::fs::write(git.join("HEAD"), "ref: refs/heads/dev\n").unwrap();
        std::fs::write(
            git.join("packed-refs"),
            format!("# pack-refs\n{sha} refs/heads/dev\n"),
        )
        .unwrap();
        assert_eq!(read_vcs(tmp.path()).unwrap().commit, sha);
        std::fs::write(git.join("HEAD"), format!("{sha}\n")).unwrap();
        let detached = read_vcs(tmp.path()).unwrap();
        assert_eq!(detached.branch, None);
    }

    #[test]
    fn follows_a_worktree_gitdir_file() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("realgit");
        std::fs::create_dir_all(&real).unwrap();
        let sha = "fedcba9876543210fedcba9876543210fedcba98";
        std::fs::write(real.join("HEAD"), format!("{sha}\n")).unwrap();
        let wt = tmp.path().join("wt");
        std::fs::create_dir_all(&wt).unwrap();
        std::fs::write(wt.join(".git"), format!("gitdir: {}\n", real.display())).unwrap();
        assert_eq!(read_vcs(&wt).unwrap().commit, sha);
    }

    #[test]
    fn worktree_commondir_resolves_refs_from_the_common_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let main_git = tmp.path().join("main/.git");
        std::fs::create_dir_all(main_git.join("refs/heads")).unwrap();
        let sha = "cafebabecafebabecafebabecafebabecafebabe";
        std::fs::write(main_git.join("refs/heads/feature"), format!("{sha}\n")).unwrap();
        let worktree_git_dir = main_git.join("worktrees/wt");
        std::fs::create_dir_all(&worktree_git_dir).unwrap();
        std::fs::write(worktree_git_dir.join("HEAD"), "ref: refs/heads/feature\n").unwrap();
        std::fs::write(worktree_git_dir.join("commondir"), "../..\n").unwrap();
        let wt = tmp.path().join("wt");
        std::fs::create_dir_all(&wt).unwrap();
        std::fs::write(
            wt.join(".git"),
            format!("gitdir: {}\n", worktree_git_dir.display()),
        )
        .unwrap();
        let vcs = read_vcs(&wt).unwrap();
        assert_eq!(vcs.commit, sha);
        assert_eq!(vcs.branch.as_deref(), Some("feature"));
    }

    #[test]
    fn non_repo_has_no_vcs() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(read_vcs(tmp.path()).is_none());
    }

    #[test]
    fn absolute_ref_target_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let git = tmp.path().join(".git");
        std::fs::create_dir_all(&git).unwrap();
        std::fs::write(git.join("HEAD"), "ref: /etc/hostname\n").unwrap();
        assert!(read_vcs(tmp.path()).is_none());
    }

    #[test]
    fn ref_name_with_newline_or_bracket_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let git = tmp.path().join(".git");
        std::fs::create_dir_all(&git).unwrap();
        std::fs::write(git.join("HEAD"), "ref: refs/heads/evil\nname\n").unwrap();
        assert!(read_vcs(tmp.path()).is_none());
        std::fs::write(git.join("HEAD"), "ref: refs/heads/ev[il\n").unwrap();
        assert!(read_vcs(tmp.path()).is_none());
    }

    #[test]
    fn windows_unc_and_device_paths_are_rejected() {
        assert!(is_windows_unc_or_device(r"\\server\share\x"));
        assert!(is_windows_unc_or_device(r"\\?\UNC\server\share"));
        assert!(is_windows_unc_or_device(r"\\.\PhysicalDrive0"));
        assert!(is_windows_unc_or_device("//server/share"));
        assert!(!is_windows_unc_or_device(r"\\?\C:\repo"));
        assert!(!is_windows_unc_or_device(r"C:\repo"));
        assert!(!is_windows_unc_or_device("relative/path"));
    }

    #[test]
    fn gitdir_pointer_to_a_unc_share_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join(".git"),
            "gitdir: \\\\evil-host\\share\\.git\n",
        )
        .unwrap();
        assert!(read_vcs(tmp.path()).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn fifo_head_returns_none_promptly() {
        let tmp = tempfile::tempdir().unwrap();
        let git = tmp.path().join(".git");
        std::fs::create_dir_all(&git).unwrap();
        let head = git.join("HEAD");
        let c_path = std::ffi::CString::new(head.to_str().unwrap()).unwrap();
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo failed: {}", std::io::Error::last_os_error());
        let start = std::time::Instant::now();
        assert!(read_vcs(tmp.path()).is_none());
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_head_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let git = tmp.path().join(".git");
        std::fs::create_dir_all(&git).unwrap();
        std::fs::write(
            tmp.path().join("real_head"),
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(tmp.path().join("real_head"), git.join("HEAD")).unwrap();
        assert!(read_vcs(tmp.path()).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_loose_ref_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let git = tmp.path().join(".git");
        std::fs::create_dir_all(git.join("refs/heads")).unwrap();
        std::fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(
            tmp.path().join("real_ref"),
            "0123456789abcdef0123456789abcdef01234567\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(tmp.path().join("real_ref"), git.join("refs/heads/main"))
            .unwrap();
        assert!(read_vcs(tmp.path()).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_refs_heads_dir_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let git = tmp.path().join(".git");
        std::fs::create_dir_all(git.join("refs")).unwrap();
        std::fs::write(git.join("HEAD"), "ref: refs/heads/apitoken\n").unwrap();
        let evil = tmp.path().join("evil");
        std::fs::create_dir_all(&evil).unwrap();
        std::fs::write(
            evil.join("apitoken"),
            "0123456789abcdef0123456789abcdef01234567\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(&evil, git.join("refs/heads")).unwrap();
        assert!(read_vcs(tmp.path()).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_refs_dir_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let git = tmp.path().join(".git");
        std::fs::create_dir_all(&git).unwrap();
        std::fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        let evil = tmp.path().join("evil");
        std::fs::create_dir_all(evil.join("heads")).unwrap();
        std::fs::write(
            evil.join("heads/main"),
            "0123456789abcdef0123456789abcdef01234567\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(&evil, git.join("refs")).unwrap();
        assert!(read_vcs(tmp.path()).is_none());
    }

    #[test]
    fn manifest_appends_producers_and_survives_corruption() {
        let tmp = tempfile::tempdir().unwrap();
        let results = tmp.path();
        std::fs::write(results.join("manifest.json"), "{corrupt").unwrap();
        let mut m = load(results).unwrap();
        assert!(m.producers.is_empty());
        assert!(results.read_dir().unwrap().flatten().any(|e| e
            .file_name()
            .to_string_lossy()
            .starts_with("manifest.json.corrupt-")));
        m.producers.push(ProducerRecord {
            command: "auto".into(),
            argv: vec![],
            started_at: "2026-10-01T00:00:00Z".into(),
            finished_at: "2026-10-01T00:01:00Z".into(),
            status: ProducerStatus::Complete,
            exit_code: 0,
            findings_total: 2,
        });
        save(results, &m).unwrap();
        assert_eq!(load(results).unwrap().producers.len(), 1);
    }
}
