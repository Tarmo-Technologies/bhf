// SPDX-License-Identifier: Apache-2.0
//! The one place that knows where results live under a bhf work directory.
//! Every producer and reader goes through these helpers; never spell
//! `join("findings")` by hand.

use std::path::{Path, PathBuf};

pub const RESULTS_DIR: &str = "results";
pub const FINDINGS_DIR: &str = "findings";
pub const STATIC_DIR: &str = "static";
pub const SBOM_DIR: &str = "sbom";

pub fn results_dir(work_dir: &Path) -> PathBuf {
    work_dir.join(RESULTS_DIR)
}

pub fn findings_dir(work_dir: &Path) -> PathBuf {
    results_dir(work_dir).join(FINDINGS_DIR)
}

pub fn finding_dir(work_dir: &Path, id: &str) -> PathBuf {
    findings_dir(work_dir).join(id)
}

pub fn static_dir(work_dir: &Path) -> PathBuf {
    results_dir(work_dir).join(STATIC_DIR)
}

pub fn sbom_dir(work_dir: &Path) -> PathBuf {
    results_dir(work_dir).join(SBOM_DIR)
}

/// `<work>/findings` — the bhf <= 0.2.x location, read only for migration.
pub fn legacy_findings_dir(work_dir: &Path) -> PathBuf {
    work_dir.join(FINDINGS_DIR)
}

/// Recover `<work>` from a finding directory, lexically and leniently — for
/// read-only harness/root lookup where a best guess is acceptable. Two known
/// ambiguities, by design:
/// * any `<x>/findings/<id>` returns `<x>`, even when `<x>` is not a work dir;
/// * a 0.2.x work dir literally named `results` (`results/findings/<id>`)
///   collapses the `results` segment and returns `.`.
///
/// Writers that must not guess should use [`results_work_dir_for_finding`].
pub fn work_dir_for_finding(finding_dir: &Path) -> Option<PathBuf> {
    let findings = finding_dir.parent()?;
    if findings.file_name()? != FINDINGS_DIR {
        return None;
    }
    let parent = findings.parent()?;
    let work = if parent.file_name().is_some_and(|name| name == RESULTS_DIR) {
        parent.parent()?
    } else {
        parent
    };
    Some(if work.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        work.to_path_buf()
    })
}

/// Strict results-layout work-dir recovery for writers. Unlike
/// [`work_dir_for_finding`], it accepts only the results depth
/// (`<work>/results/findings/<id>`) and requires a work-dir marker —
/// `<work>/results/manifest.json`, or a `<work>/auto` directory — so a bare
/// `<x>/results/findings/<id>` outside a real work tree is rejected.
pub fn results_work_dir_for_finding(finding_dir: &Path) -> Option<PathBuf> {
    let findings = finding_dir.parent()?;
    if findings.file_name()? != FINDINGS_DIR {
        return None;
    }
    let results = findings.parent()?;
    if results.file_name()? != RESULTS_DIR {
        return None;
    }
    let work = results.parent()?;
    let work = if work.as_os_str().is_empty() {
        Path::new(".")
    } else {
        work
    };
    let has_marker = results.join("manifest.json").is_file() || work.join("auto").is_dir();
    has_marker.then(|| work.to_path_buf())
}

/// Whether `id` is a safe single-segment finding id: `[A-Za-z0-9]` then up to
/// 127 of `[A-Za-z0-9._-]`, and never `.`/`..`. Keeps a bare id from escaping
/// its findings directory when joined as a path component.
pub fn is_valid_finding_id(id: &str) -> bool {
    if id == "." || id == ".." {
        return false;
    }
    let bytes = id.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return false;
    }
    if !bytes[0].is_ascii_alphanumeric() {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// Resolve a bare finding id against `work_dir`, preferring the results layout:
/// `<work>/results/findings/<id>`, then legacy `<work>/findings/<id>`, then the
/// cwd-relative `./results/findings/<id>` and `./findings/<id>` (pre-0.3
/// behaviour, for callers run from inside the work dir). Returns `None` for an
/// id that is not a safe single path segment.
pub fn resolve_finding_id(work_dir: &Path, id: &str) -> Option<PathBuf> {
    if !is_valid_finding_id(id) {
        return None;
    }
    [
        finding_dir(work_dir, id),
        legacy_findings_dir(work_dir).join(id),
        finding_dir(Path::new("."), id),
        PathBuf::from(FINDINGS_DIR).join(id),
    ]
    .into_iter()
    .find(|path| path.is_dir())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn results_work_dir_for_finding_accepts_only_marked_results_depth() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path();
        let finding = work.join("results/findings/F-1");
        std::fs::create_dir_all(&finding).unwrap();

        // No marker yet -> rejected.
        assert_eq!(results_work_dir_for_finding(&finding), None);

        // `<work>/auto` marker -> accepted.
        std::fs::create_dir_all(work.join("auto")).unwrap();
        assert_eq!(
            results_work_dir_for_finding(&finding),
            Some(work.to_path_buf())
        );
    }

    #[test]
    fn results_work_dir_for_finding_accepts_manifest_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path();
        let finding = work.join("results/findings/F-1");
        std::fs::create_dir_all(&finding).unwrap();
        std::fs::write(work.join("results/manifest.json"), "{}").unwrap();
        assert_eq!(
            results_work_dir_for_finding(&finding),
            Some(work.to_path_buf())
        );
    }

    #[test]
    fn results_work_dir_for_finding_rejects_legacy_and_unmarked() {
        // Legacy depth is not the results depth.
        assert_eq!(
            results_work_dir_for_finding(Path::new("/home/u/cases/findings/F-1")),
            None
        );
        // Results depth but no marker on disk.
        assert_eq!(
            results_work_dir_for_finding(Path::new("/nope/results/findings/F-1")),
            None
        );
    }

    #[test]
    fn is_valid_finding_id_accepts_ids_and_rejects_traversal() {
        assert!(is_valid_finding_id("F-0001-ab"));
        assert!(is_valid_finding_id("H.AUTO_1234"));
        assert!(!is_valid_finding_id("."));
        assert!(!is_valid_finding_id(".."));
        assert!(!is_valid_finding_id("../x"));
        assert!(!is_valid_finding_id("a/b"));
        assert!(!is_valid_finding_id(".hidden")); // must start alphanumeric
        assert!(!is_valid_finding_id(""));
        assert!(!is_valid_finding_id(&"a".repeat(129)));
    }

    #[test]
    fn resolve_finding_id_rejects_unsafe_ids() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(resolve_finding_id(tmp.path(), "../x"), None);
        assert_eq!(resolve_finding_id(tmp.path(), "a/b"), None);
    }

    #[test]
    fn results_paths_hang_off_the_work_dir() {
        let work = Path::new("/w");
        assert_eq!(results_dir(work), Path::new("/w/results"));
        assert_eq!(findings_dir(work), Path::new("/w/results/findings"));
        assert_eq!(
            finding_dir(work, "F-0001-aa"),
            Path::new("/w/results/findings/F-0001-aa")
        );
        assert_eq!(static_dir(work), Path::new("/w/results/static"));
        assert_eq!(sbom_dir(work), Path::new("/w/results/sbom"));
        assert_eq!(legacy_findings_dir(work), Path::new("/w/findings"));
    }

    #[test]
    fn work_dir_for_finding_handles_new_and_legacy_depths() {
        assert_eq!(
            work_dir_for_finding(Path::new("/w/results/findings/F-1")),
            Some(PathBuf::from("/w"))
        );
        assert_eq!(
            work_dir_for_finding(Path::new("/w/findings/F-1")),
            Some(PathBuf::from("/w"))
        );
        assert_eq!(
            work_dir_for_finding(Path::new("results/findings/F-1")),
            Some(PathBuf::from("."))
        );
        assert_eq!(work_dir_for_finding(Path::new("/w/other/F-1")), None);
    }

    #[test]
    fn resolve_finding_id_prefers_new_then_legacy() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path();
        std::fs::create_dir_all(work.join("findings/F-1")).unwrap();
        assert_eq!(
            resolve_finding_id(work, "F-1"),
            Some(work.join("findings/F-1"))
        );
        std::fs::create_dir_all(work.join("results/findings/F-1")).unwrap();
        assert_eq!(
            resolve_finding_id(work, "F-1"),
            Some(work.join("results/findings/F-1"))
        );
        assert_eq!(resolve_finding_id(work, "F-404"), None);
    }
}
