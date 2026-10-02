// SPDX-License-Identifier: Apache-2.0
//! The one place that knows where results live under a bhf work directory.
//! Every producer and reader goes through these helpers; never spell
//! `join("findings")` by hand.

use std::path::{Path, PathBuf};

pub const RESULTS_DIR: &str = "results";
pub const FINDINGS_DIR: &str = "findings";
pub const STATIC_DIR: &str = "static";
pub const SBOM_DIR: &str = "sbom";

/// Set to `1` by orchestrators (multicore workers, the continuous daemon) on
/// the `bhf` children they spawn: the child runs its command but leaves the
/// producer record and the results/ rebuild to the parent.
pub const RESULTS_DEFER_ENV: &str = "BHF_RESULTS_DEFER";

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

/// Hands out `<prefix>NNNN` finding directories under one findings dir.
/// Producers that share a family (standalone `differential` and auto's
/// post-pass, or two runs on one work dir) each hold their own allocator; the
/// leaf is made with `create_dir`, so among allocator users a name is unique
/// and exclusive: an id another writer already took is skipped, never reused.
/// The single-core fuzz emitter's `next_ordinal` is not an allocator user: it
/// picks the next `F-` ordinal by scanning and writes with `create_dir_all`,
/// so its names are not exclusive against a concurrent writer.
pub struct FamilyAllocator {
    dir: PathBuf,
    prefix: String,
    next: u64,
}

impl FamilyAllocator {
    /// Scan `findings_dir` once and start one past the highest ordinal for
    /// `prefix` (every leading digit, so `F-DIFF-10000` reads as 10000). A
    /// missing dir starts at 0; nothing is created until [`Self::create`].
    pub fn new(findings_dir: &Path, prefix: &str) -> std::io::Result<Self> {
        let entries = match std::fs::read_dir(findings_dir) {
            Ok(entries) => Some(entries),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let mut highest: Option<u64> = None;
        for entry in entries.into_iter().flatten() {
            let name = entry?.file_name();
            if let Some(ordinal) = name.to_str().and_then(|name| family_ordinal(name, prefix)) {
                highest = highest.max(Some(ordinal));
            }
        }
        Ok(Self {
            dir: findings_dir.to_path_buf(),
            prefix: prefix.to_owned(),
            next: highest.map_or(0, |highest| highest.saturating_add(1)),
        })
    }

    /// Create the next free `<prefix>NNNN` directory and return its id and path.
    pub fn create(&mut self) -> std::io::Result<(String, PathBuf)> {
        self.create_named(None)
    }

    /// As [`Self::create`], named `<prefix>NNNN-<suffix>`: with prefix `F-`
    /// and an 8-char signature, the fuzz emitter's `F-0001-1a2b3c4d`.
    pub fn create_with_suffix(&mut self, suffix: &str) -> std::io::Result<(String, PathBuf)> {
        self.create_named(Some(suffix))
    }

    /// The dir of `id` when `id` is one of this family's names and exists here
    /// as a real directory: a reservation an interrupted writer can resume
    /// into. Whether it is still unfinished is the caller's call.
    pub fn reserved_dir(&self, id: &str) -> Option<PathBuf> {
        if !is_valid_finding_id(id) || family_ordinal(id, &self.prefix).is_none() {
            return None;
        }
        let dir = self.dir.join(id);
        std::fs::symlink_metadata(&dir)
            .is_ok_and(|meta| meta.is_dir())
            .then_some(dir)
    }

    fn create_named(&mut self, suffix: Option<&str>) -> std::io::Result<(String, PathBuf)> {
        if suffix.is_some_and(|suffix| !is_valid_finding_id(suffix)) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsafe finding id suffix {suffix:?}"),
            ));
        }
        std::fs::create_dir_all(&self.dir)?;
        loop {
            let id = match suffix {
                Some(suffix) => format!("{}{:04}-{suffix}", self.prefix, self.next),
                None => format!("{}{:04}", self.prefix, self.next),
            };
            self.next = self.next.checked_add(1).ok_or_else(|| {
                std::io::Error::other(format!("{} ordinals exhausted", self.prefix))
            })?;
            let path = self.dir.join(&id);
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok((id, path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
    }
}

/// The ordinal in `<prefix><digits>...`, or `None` for another family.
fn family_ordinal(name: &str, prefix: &str) -> Option<u64> {
    let rest = name.strip_prefix(prefix)?;
    let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
    rest[..digits].parse().ok()
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

    fn create_id(allocator: &mut FamilyAllocator) -> String {
        let (id, dir) = allocator.create().unwrap();
        assert!(dir.is_dir(), "{} not created", dir.display());
        assert_eq!(dir.file_name().unwrap(), id.as_str());
        id
    }

    #[test]
    fn family_allocator_counts_up_from_zero_in_a_missing_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let findings = tmp.path().join("results/findings");
        let mut allocator = FamilyAllocator::new(&findings, "F-DIFF-").unwrap();
        assert!(!findings.exists(), "new() only scans");
        assert_eq!(create_id(&mut allocator), "F-DIFF-0000");
        assert_eq!(create_id(&mut allocator), "F-DIFF-0001");
    }

    #[test]
    fn family_allocator_continues_after_the_highest_for_its_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        for name in ["F-DIFF-0000", "F-DIFF-0007", "F-0003-abcd", "F-DIFF-x"] {
            std::fs::create_dir_all(tmp.path().join(name)).unwrap();
        }
        let mut allocator = FamilyAllocator::new(tmp.path(), "F-DIFF-").unwrap();
        assert_eq!(create_id(&mut allocator), "F-DIFF-0008");
    }

    #[test]
    fn family_allocator_reads_every_leading_digit() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("F-DIFF-9999")).unwrap();
        let mut allocator = FamilyAllocator::new(tmp.path(), "F-DIFF-").unwrap();
        assert_eq!(create_id(&mut allocator), "F-DIFF-10000");
        assert_eq!(create_id(&mut allocator), "F-DIFF-10001");
        // A second allocator sees the five-digit ordinal, not "1000".
        let mut again = FamilyAllocator::new(tmp.path(), "F-DIFF-").unwrap();
        assert_eq!(create_id(&mut again), "F-DIFF-10002");
    }

    #[test]
    fn suffixed_ids_follow_the_emitter_format_and_ignore_other_families() {
        let tmp = tempfile::tempdir().unwrap();
        for name in [
            "F-0003-abcd1234",
            "F-DIFF-0009",
            "F-STATIC-0042-x",
            "F-SCA-7",
            "H-0099",
        ] {
            std::fs::create_dir_all(tmp.path().join(name)).unwrap();
        }
        let mut allocator = FamilyAllocator::new(tmp.path(), "F-").unwrap();
        let (id, dir) = allocator.create_with_suffix("1a2b3c4d").unwrap();
        assert_eq!(id, "F-0004-1a2b3c4d");
        assert!(dir.is_dir());
        assert_eq!(
            allocator.create_with_suffix("1a2b3c4d").unwrap().0,
            "F-0005-1a2b3c4d"
        );
    }

    #[test]
    fn suffixed_ids_skip_a_name_another_writer_took() {
        let tmp = tempfile::tempdir().unwrap();
        let mut allocator = FamilyAllocator::new(tmp.path(), "F-").unwrap();
        std::fs::create_dir(tmp.path().join("F-0000-cafe")).unwrap();
        assert_eq!(
            allocator.create_with_suffix("cafe").unwrap().0,
            "F-0001-cafe"
        );
    }

    #[test]
    fn unsafe_suffixes_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let mut allocator = FamilyAllocator::new(tmp.path(), "F-").unwrap();
        for suffix in ["../x", "a/b", ""] {
            let error = allocator.create_with_suffix(suffix).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{suffix:?}");
        }
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
    }

    #[test]
    fn family_allocator_skips_an_id_another_writer_took() {
        let tmp = tempfile::tempdir().unwrap();
        let mut allocator = FamilyAllocator::new(tmp.path(), "F-DIFF-").unwrap();
        std::fs::create_dir(tmp.path().join("F-DIFF-0000")).unwrap();
        assert_eq!(create_id(&mut allocator), "F-DIFF-0001");
    }

    #[test]
    fn reserved_dir_names_only_real_dirs_of_the_family() {
        let tmp = tempfile::tempdir().unwrap();
        let mut allocator = FamilyAllocator::new(tmp.path(), "F-").unwrap();
        let (id, dir) = allocator.create_with_suffix("cafe").unwrap();
        assert_eq!(allocator.reserved_dir(&id), Some(dir));
        std::fs::create_dir(tmp.path().join("F-DIFF-0000")).unwrap();
        for other in [
            "F-DIFF-0000",
            "F-0009-none",
            "../F-0000-cafe",
            "F-0000-cafe/x",
        ] {
            assert_eq!(allocator.reserved_dir(other), None, "{other}");
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(tmp.path(), tmp.path().join("F-0001-link")).unwrap();
            assert_eq!(allocator.reserved_dir("F-0001-link"), None, "a symlink");
        }
    }

    #[test]
    fn family_allocator_propagates_unreadable_findings_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("findings");
        std::fs::write(&file, "not a dir").unwrap();
        assert!(FamilyAllocator::new(&file, "F-DIFF-").is_err());
    }

    #[test]
    fn concurrent_family_allocators_never_share_an_id() {
        let tmp = tempfile::tempdir().unwrap();
        let findings = tmp.path().join("findings");
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let findings = findings.clone();
                std::thread::spawn(move || {
                    let mut allocator = FamilyAllocator::new(&findings, "F-DIFF-").unwrap();
                    (0..50)
                        .map(|_| allocator.create().unwrap().0)
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let ids: Vec<String> = threads
            .into_iter()
            .flat_map(|t| t.join().unwrap())
            .collect();
        let unique: std::collections::BTreeSet<&String> = ids.iter().collect();
        assert_eq!(ids.len(), 400);
        assert_eq!(unique.len(), 400, "an id was handed out twice");
        assert_eq!(std::fs::read_dir(&findings).unwrap().count(), 400);
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
