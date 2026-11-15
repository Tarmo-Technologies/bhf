// SPDX-License-Identifier: Apache-2.0
//! One-time move of a bhf <= 0.2.x work dir (`<work>/findings/`) into the
//! results layout (`<work>/results/findings/`). What the old layout held that
//! `results/` replaces (its index files and reproducer scripts) is kept under
//! `results/legacy/`, with a `migration.json` record of what was moved.

use crate::lock::ResultsLock;
use crate::{io_err, layout, ResultsError};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationOutcome {
    NotNeeded,
    Migrated,
}

/// What a migration changed, for the caller to report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationReport {
    /// Finding directories moved into `results/findings/`.
    pub findings: usize,
    /// Legacy index files kept under `results/legacy/`, by their old
    /// work-dir-relative path.
    pub preserved: Vec<String>,
    /// Generated `replay.py` scripts kept under `results/legacy/findings/<id>/`.
    pub reproducers: usize,
}

/// Legacy index files; the rebuild regenerates their content under
/// `results/`, and migration keeps the old copies under `results/legacy/`.
const LEGACY_DERIVED: [&str; 3] = ["FINDINGS.md", "findings.csv", "auto/findings.csv"];

/// The directory under `results/` holding what a migrated work dir's legacy
/// layout had.
pub const LEGACY_DIR: &str = "legacy";

/// The record of a migration, in [`legacy_dir`].
pub const MIGRATION_RECORD: &str = "migration.json";

/// `<work>/results/legacy`.
pub fn legacy_dir(work_dir: &Path) -> PathBuf {
    layout::results_dir(work_dir).join(LEGACY_DIR)
}

/// Whether `work_dir` was migrated from the legacy layout (it holds a
/// [`MIGRATION_RECORD`]).
pub fn was_migrated(work_dir: &Path) -> bool {
    legacy_dir(work_dir).join(MIGRATION_RECORD).is_file()
}

enum ReclaimOutcome {
    Proceed,
    PeerMigrated,
}

/// True when a peer bhf process has already finished migrating: `legacy` is
/// gone. Within bhf the only thing that removes a confirmed-dir `legacy` is a
/// migrate rename, so its absence alone is enough — including when `legacy`
/// (and so the moved `target`) was empty to begin with. Several bhf
/// processes (e.g. a daemon's `bhf fuzz` children) can open and migrate the
/// same legacy work dir at once; this turns what would otherwise look like a
/// conflict or an I/O failure for the loser of the race into a benign no-op.
/// A genuine conflict — `legacy` still present alongside a populated
/// `target` — is unaffected: callers only consult this once `legacy` would
/// otherwise be treated as a problem.
fn peer_migrated(legacy: &Path) -> bool {
    !legacy.exists()
}

fn is_nonempty_dir(path: &Path) -> bool {
    std::fs::read_dir(path)
        .ok()
        .and_then(|mut entries| entries.next())
        .is_some()
}

/// Make room at `target` for the rename, or detect that a peer already
/// claimed it.
fn reclaim_target(legacy: &Path, target: &Path) -> Result<ReclaimOutcome, ResultsError> {
    if !target.exists() {
        return Ok(ReclaimOutcome::Proceed);
    }
    if is_nonempty_dir(target) {
        return if peer_migrated(legacy) {
            Ok(ReclaimOutcome::PeerMigrated)
        } else {
            Err(ResultsError::MigrationConflict {
                legacy: legacy.to_path_buf(),
                target: target.to_path_buf(),
            })
        };
    }
    reclaim_empty_target(legacy, target)
}

/// `target` was just observed empty; remove it so the rename below can take
/// its place. Check for a peer FIRST: an empty `target` is exactly what a
/// peer's rename of an equally-empty `legacy` leaves behind, and removing
/// that would destroy its completed migration instead of merely racing it.
/// A peer can also still populate it between this check and the removal
/// (e.g. by completing a non-empty rename into it), which fails the removal
/// with `ENOTEMPTY` rather than corrupting anything.
fn reclaim_empty_target(legacy: &Path, target: &Path) -> Result<ReclaimOutcome, ResultsError> {
    if peer_migrated(legacy) {
        return Ok(ReclaimOutcome::PeerMigrated);
    }
    match std::fs::remove_dir(target) {
        Ok(()) => Ok(ReclaimOutcome::Proceed),
        Err(source) => {
            if peer_migrated(legacy) {
                Ok(ReclaimOutcome::PeerMigrated)
            } else {
                Err(ResultsError::Io {
                    path: target.to_path_buf(),
                    source,
                })
            }
        }
    }
}

/// Rename `legacy` into `target`, or detect that a peer already did so.
fn rename_or_detect_peer(legacy: &Path, target: &Path) -> Result<MigrationOutcome, ResultsError> {
    match std::fs::rename(legacy, target) {
        Ok(()) => Ok(MigrationOutcome::Migrated),
        Err(source) => {
            if peer_migrated(legacy) {
                Ok(MigrationOutcome::NotNeeded)
            } else {
                Err(ResultsError::Io {
                    path: legacy.to_path_buf(),
                    source,
                })
            }
        }
    }
}

/// Core migration, assuming the caller has already confirmed `legacy` was a
/// real directory (not a symlink or missing) moments ago. Split out from
/// [`migrate_legacy`] so the peer-migration races below that initial check
/// are reachable from tests without threads.
fn migrate_inner(
    legacy: &Path,
    target: &Path,
    work_dir: &Path,
) -> Result<Option<MigrationReport>, ResultsError> {
    if let ReclaimOutcome::PeerMigrated = reclaim_target(legacy, target)? {
        return Ok(None);
    }

    // Keep the legacy index files BEFORE the rename: if this fails, legacy is
    // untouched and the whole migration is safely retryable.
    let kept = legacy_dir(work_dir);
    std::fs::create_dir_all(&kept).map_err(io_err(&kept))?;
    let mut preserved = Vec::new();
    for rel in LEGACY_DERIVED {
        let path = work_dir.join(rel);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_file() => {}
            // Not a file bhf wrote (a directory or a symlink): leave it alone.
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(source) => return Err(ResultsError::Io { path, source }),
        }
        let dest = kept.join(rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(io_err(parent))?;
        }
        match std::fs::rename(&path, &dest) {
            Ok(()) => preserved.push(rel.to_owned()),
            // A peer migrating the same work dir moved it first.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(ResultsError::Io { path, source }),
        }
    }

    if rename_or_detect_peer(legacy, target)? == MigrationOutcome::NotNeeded {
        return Ok(None);
    }

    // Generated reproducer scripts encode the old directory depth: the next
    // rebuild regenerates them with the current template, and the old ones
    // are kept beside the other legacy files.
    let mut findings = 0;
    let mut reproducers = 0;
    if let Ok(entries) = std::fs::read_dir(target) {
        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            findings += 1;
            let script = entry.path().join("replay.py");
            if !script.is_file() {
                continue;
            }
            let dest = kept.join(layout::FINDINGS_DIR).join(entry.file_name());
            let moved = std::fs::create_dir_all(&dest)
                .and_then(|()| std::fs::rename(&script, dest.join("replay.py")))
                .is_ok();
            if moved {
                reproducers += 1;
            } else {
                let _ = std::fs::remove_file(&script);
            }
        }
    }
    let report = MigrationReport {
        findings,
        preserved,
        reproducers,
    };
    write_record(&kept, &report)?;
    Ok(Some(report))
}

fn write_record(kept: &Path, report: &MigrationReport) -> Result<(), ResultsError> {
    let record = serde_json::json!({
        "schema_version": 1,
        "migrated_at": corpus::finding::now_rfc3339(),
        "from": "findings/",
        "to": "results/findings/",
        "findings": report.findings,
        "preserved": report.preserved,
        "reproducers": report.reproducers,
    });
    let path = kept.join(MIGRATION_RECORD);
    let bytes = serde_json::to_vec_pretty(&record).map_err(|source| ResultsError::Json {
        path: path.clone(),
        source,
    })?;
    std::fs::write(&path, bytes).map_err(io_err(&path))
}

/// Rename `<work>/findings` to `<work>/results/findings` (same filesystem, so
/// evidence is moved, never copied) and keep the legacy index files and
/// reproducer scripts under `results/legacy/`. A symlink or non-directory
/// named `findings` is not ours and is left alone. Refuses to merge when the
/// target is already populated by something other than a peer's in-flight
/// migration of the same legacy dir; a peer that finishes first anywhere along
/// the way is treated as [`MigrationOutcome::NotNeeded`], never as an error.
pub fn migrate_legacy(work_dir: &Path) -> Result<MigrationOutcome, ResultsError> {
    Ok(match migrate_legacy_report(work_dir)? {
        Some(_) => MigrationOutcome::Migrated,
        None => MigrationOutcome::NotNeeded,
    })
}

/// [`migrate_legacy`], returning what the migration changed (`None` when no
/// migration was needed).
pub fn migrate_legacy_report(work_dir: &Path) -> Result<Option<MigrationReport>, ResultsError> {
    let legacy = layout::legacy_findings_dir(work_dir);
    if !is_real_dir(&legacy)? {
        return Ok(None);
    }
    // Migrations of one work dir run one at a time, under the results lock.
    // A rename alone cannot tell racers apart on Windows: it moves the
    // directory a handle was opened on, so a racer that opened `findings/`
    // before a peer moved it then "moves" the peer's result onto itself and
    // also reports a migration.
    let results = layout::results_dir(work_dir);
    std::fs::create_dir_all(&results).map_err(io_err(&results))?;
    let _lock = ResultsLock::acquire(&results, MIGRATION_LOCK_TIMEOUT)?;
    if !is_real_dir(&legacy)? {
        return Ok(None);
    }
    let target = layout::findings_dir(work_dir);
    migrate_inner(&legacy, &target, work_dir)
}

/// How long a migration waits for a peer's migration or rebuild.
const MIGRATION_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Whether `path` is a directory itself, not a symlink to one.
fn is_real_dir(path: &Path) -> Result<bool, ResultsError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => Ok(meta.is_dir()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(ResultsError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Inputs that look damaged by the seed encoding of earlier releases, which
/// replaced every invalid UTF-8 byte of a seed with `EF BF BD` (U+FFFD).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DamagedInputs {
    /// Findings whose `testcase.bin` or `min_testcase.bin` looks damaged.
    pub findings: Vec<String>,
    /// Entries under `corpus/<id>/queue/` that look damaged.
    pub corpus_entries: usize,
    /// The corpus walk stopped at [`MAX_SCANNED_CORPUS_ENTRIES`].
    pub truncated: bool,
}

impl DamagedInputs {
    pub fn total(&self) -> usize {
        self.findings.len() + self.corpus_entries
    }
}

/// Corpus entries examined per scan; past this the result says it is partial.
pub const MAX_SCANNED_CORPUS_ENTRIES: usize = 100_000;
/// Bytes of each input examined.
const MAX_SCANNED_INPUT_BYTES: u64 = 4 * 1024 * 1024;
const REPLACEMENT: &[u8] = b"\xef\xbf\xbd";

/// Whether `bytes` holds at least two `EF BF BD` sequences: one can be a real
/// character in a text input, a run of them is what replacing the invalid
/// bytes of a binary seed leaves.
pub fn looks_damaged(bytes: &[u8]) -> bool {
    bytes
        .windows(REPLACEMENT.len())
        .filter(|window| *window == REPLACEMENT)
        .nth(1)
        .is_some()
}

/// Where `bhf auto` sets aside the corpus of a work dir from an earlier
/// release: kept, but outside `corpus/`, which every pass reseeds from.
pub const LEGACY_CORPUS_DIR: &str = "corpus-legacy";

/// The record `bhf auto` writes the first time it runs in a work dir, before
/// it writes anything else there: `decision` is [`CORPUS_FRESH`] when the work
/// dir held nothing from an earlier release, otherwise what happened to the
/// earlier corpus (`set_aside`, `reused`, or `none` when there was none).
pub const CORPUS_DECISION_RECORD: &str = "auto/legacy-corpus.json";

/// The [`CORPUS_DECISION_RECORD`] decision for a work dir this release's
/// `bhf auto` started.
pub const CORPUS_FRESH: &str = "fresh";

/// The decision a [`CORPUS_DECISION_RECORD`] holds, if there is one.
pub fn corpus_decision(work_dir: &Path) -> Option<String> {
    let bytes = std::fs::read(work_dir.join(CORPUS_DECISION_RECORD)).ok()?;
    let record: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    record
        .get("decision")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

/// Whether the work dir holds data an earlier bhf release wrote with its old
/// seed encoding: it was migrated from the legacy layout, its corpus was set
/// aside, this release's `bhf auto` found earlier-release data when it first
/// ran there, or an earlier `bhf auto` ran there and this release's has not
/// (auto state, `auto/run.json` or `auto/work-state.json`, with no
/// [`CORPUS_DECISION_RECORD`]: every run of this release writes that record
/// before anything else, even one that stops before fuzzing).
pub fn from_an_earlier_release(work_dir: &Path) -> bool {
    if was_migrated(work_dir) || work_dir.join(LEGACY_CORPUS_DIR).is_dir() {
        return true;
    }
    if work_dir.join(CORPUS_DECISION_RECORD).exists() {
        return corpus_decision(work_dir).as_deref() != Some(CORPUS_FRESH);
    }
    let auto = work_dir.join("auto");
    // A seed list is written only by a release with byte-exact seeds.
    !auto.join("seeds.json").exists()
        && (auto.join("run.json").is_file() || auto.join("work-state.json").is_file())
}

fn read_prefix(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_SCANNED_INPUT_BYTES)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(bytes)
}

/// The inputs of a work dir from an earlier release that look damaged (see
/// [`looks_damaged`]); `None` for a work dir this release wrote, or when none
/// do.
pub fn damaged_inputs(work_dir: &Path) -> Option<DamagedInputs> {
    if !from_an_earlier_release(work_dir) {
        return None;
    }
    let mut found = DamagedInputs::default();
    let findings_dir = layout::findings_dir(work_dir);
    let mut ids: Vec<String> = std::fs::read_dir(&findings_dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| entry.path().is_dir())
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    ids.sort();
    for id in ids {
        let dir = findings_dir.join(&id);
        let damaged = ["testcase.bin", "min_testcase.bin"]
            .iter()
            .filter_map(|name| read_prefix(&dir.join(name)))
            .any(|bytes| looks_damaged(&bytes));
        if damaged {
            found.findings.push(id);
        }
    }
    let mut scanned = 0usize;
    let corpus = work_dir.join("corpus");
    let mut harnesses: Vec<PathBuf> = std::fs::read_dir(&corpus)
        .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
        .unwrap_or_default();
    harnesses.sort();
    'walk: for harness in harnesses {
        let Ok(entries) = std::fs::read_dir(harness.join("queue")) else {
            continue;
        };
        for entry in entries.flatten() {
            if scanned == MAX_SCANNED_CORPUS_ENTRIES {
                found.truncated = true;
                break 'walk;
            }
            let path = entry.path();
            if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
                continue;
            }
            scanned += 1;
            if read_prefix(&path).is_some_and(|bytes| looks_damaged(&bytes)) {
                found.corpus_entries += 1;
            }
        }
    }
    (found.total() > 0).then_some(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_work() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let w = tmp.path();
        std::fs::create_dir_all(w.join("findings/F-0001-aa")).unwrap();
        std::fs::write(w.join("findings/F-0001-aa/finding.json"), "{}").unwrap();
        std::fs::write(w.join("FINDINGS.md"), "# old").unwrap();
        std::fs::write(w.join("findings.csv"), "id\n").unwrap();
        std::fs::create_dir_all(w.join("auto")).unwrap();
        std::fs::write(w.join("auto/findings.csv"), "id\n").unwrap();
        tmp
    }

    #[test]
    fn moves_legacy_findings_and_derived_files() {
        let tmp = legacy_work();
        let w = tmp.path();
        assert_eq!(migrate_legacy(w).unwrap(), MigrationOutcome::Migrated);
        assert!(w.join("results/findings/F-0001-aa/finding.json").is_file());
        assert!(!w.join("findings").exists());
        assert!(!w.join("FINDINGS.md").exists());
        assert!(!w.join("findings.csv").exists());
        assert!(!w.join("auto/findings.csv").exists());
        assert!(was_migrated(w));
    }

    /// What changed is reported to the caller.
    #[test]
    fn migration_reports_what_it_changed() {
        let tmp = legacy_work();
        let w = tmp.path();
        std::fs::write(w.join("findings/F-0001-aa/replay.py"), "old").unwrap();
        std::fs::create_dir_all(w.join("findings/F-0002-bb")).unwrap();
        let report = migrate_legacy_report(w).unwrap().expect("migrated");
        assert_eq!(
            report,
            MigrationReport {
                findings: 2,
                preserved: vec![
                    "FINDINGS.md".to_owned(),
                    "findings.csv".to_owned(),
                    "auto/findings.csv".to_owned()
                ],
                reproducers: 1,
            }
        );
        assert_eq!(migrate_legacy_report(w).unwrap(), None);
    }

    /// The legacy reports an operator may still read are kept, not deleted.
    #[test]
    fn migration_preserves_legacy_reports_under_results_legacy() {
        let tmp = legacy_work();
        let w = tmp.path();
        std::fs::write(w.join("findings/F-0001-aa/replay.py"), "old").unwrap();
        migrate_legacy(w).unwrap();
        let legacy = w.join("results/legacy");
        assert_eq!(
            std::fs::read_to_string(legacy.join("FINDINGS.md")).unwrap(),
            "# old"
        );
        assert!(legacy.join("findings.csv").is_file());
        assert!(legacy.join("auto/findings.csv").is_file());
        assert_eq!(
            std::fs::read_to_string(legacy.join("findings/F-0001-aa/replay.py")).unwrap(),
            "old"
        );
        let marker: serde_json::Value =
            serde_json::from_slice(&std::fs::read(legacy.join("migration.json")).unwrap()).unwrap();
        assert_eq!(marker["from"], "findings/");
        assert_eq!(marker["to"], "results/findings/");
        assert_eq!(marker["findings"], 1);
    }

    #[test]
    fn a_run_of_replacement_characters_looks_damaged() {
        assert!(looks_damaged(b"\x89PNG\xef\xbf\xbd\xef\xbf\xbdIHDR"));
        assert!(looks_damaged(b"a\xef\xbf\xbdb\xef\xbf\xbdc"));
        assert!(!looks_damaged("caf\u{fffd} au lait".as_bytes()));
        assert!(!looks_damaged(b"\x00\x01\xff\xfe"));
    }

    /// Only a work dir from an earlier release is scanned, and its damaged
    /// testcases and corpus entries are counted.
    #[test]
    fn damaged_inputs_are_found_in_work_dirs_from_earlier_releases() {
        let tmp = legacy_work();
        let w = tmp.path();
        std::fs::write(
            w.join("findings/F-0001-aa/testcase.bin"),
            b"\xef\xbf\xbd\xef\xbf\xbd",
        )
        .unwrap();
        let queue = w.join("corpus/H-1/queue");
        std::fs::create_dir_all(&queue).unwrap();
        std::fs::write(queue.join("a.bin"), b"\xef\xbf\xbd\xef\xbf\xbd").unwrap();
        std::fs::write(queue.join("b.bin"), b"clean").unwrap();
        assert_eq!(damaged_inputs(w), None, "a legacy dir not yet migrated");
        migrate_legacy(w).unwrap();
        assert_eq!(
            damaged_inputs(w),
            Some(DamagedInputs {
                findings: vec!["F-0001-aa".to_owned()],
                corpus_entries: 1,
                truncated: false,
            })
        );

        let fresh = tempfile::tempdir().unwrap();
        let dir = layout::findings_dir(fresh.path()).join("F-1");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("testcase.bin"), b"\xef\xbf\xbd\xef\xbf\xbd").unwrap();
        assert_eq!(
            damaged_inputs(fresh.path()),
            None,
            "a work dir this release wrote"
        );
        std::fs::create_dir_all(fresh.path().join("auto")).unwrap();
        std::fs::write(fresh.path().join("auto/run.json"), "{}").unwrap();
        assert!(
            damaged_inputs(fresh.path()).is_some(),
            "an earlier release's auto run"
        );
        std::fs::write(fresh.path().join("auto/seeds.json"), "{}").unwrap();
        assert_eq!(damaged_inputs(fresh.path()), None);
    }

    /// A `bhf auto` of this release that stopped before resolving seeds (no
    /// fuzzable target) leaves `auto/run.json` without `auto/seeds.json`, but
    /// its first write was the corpus record, so the dir is not taken for an
    /// earlier release's.
    #[test]
    fn a_work_dir_this_release_started_is_not_from_an_earlier_release() {
        let tmp = tempfile::tempdir().unwrap();
        let w = tmp.path();
        let dir = layout::findings_dir(w).join("F-1");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("testcase.bin"), b"\xef\xbf\xbd\xef\xbf\xbd").unwrap();
        std::fs::create_dir_all(w.join("auto")).unwrap();
        std::fs::write(w.join("auto/run.json"), "{}").unwrap();
        std::fs::write(w.join("auto/work-state.json"), "{}").unwrap();
        std::fs::write(
            w.join(CORPUS_DECISION_RECORD),
            r#"{"schema_version":1,"decision":"fresh"}"#,
        )
        .unwrap();
        assert!(!from_an_earlier_release(w));
        assert_eq!(damaged_inputs(w), None);
        // The record of an earlier corpus keeps the dir flagged.
        for decision in ["set_aside", "reused", "none"] {
            std::fs::write(
                w.join(CORPUS_DECISION_RECORD),
                format!(r#"{{"schema_version":1,"decision":"{decision}"}}"#),
            )
            .unwrap();
            assert!(from_an_earlier_release(w), "{decision}");
        }
        // Auto state without the record, as an earlier release left it.
        std::fs::remove_file(w.join(CORPUS_DECISION_RECORD)).unwrap();
        std::fs::remove_file(w.join("auto/run.json")).unwrap();
        assert!(from_an_earlier_release(w), "work-state.json alone");
    }

    #[test]
    fn second_run_is_a_no_op() {
        let tmp = legacy_work();
        migrate_legacy(tmp.path()).unwrap();
        assert_eq!(
            migrate_legacy(tmp.path()).unwrap(),
            MigrationOutcome::NotNeeded
        );
    }

    #[test]
    fn an_empty_results_findings_dir_is_not_a_conflict() {
        let tmp = legacy_work();
        std::fs::create_dir_all(tmp.path().join("results/findings")).unwrap();
        assert_eq!(
            migrate_legacy(tmp.path()).unwrap(),
            MigrationOutcome::Migrated
        );
        assert!(tmp
            .path()
            .join("results/findings/F-0001-aa/finding.json")
            .is_file());
    }

    #[test]
    fn migration_moves_stale_replay_scripts_out_of_the_evidence() {
        let tmp = legacy_work();
        std::fs::write(tmp.path().join("findings/F-0001-aa/replay.py"), "old").unwrap();
        migrate_legacy(tmp.path()).unwrap();
        assert!(!tmp
            .path()
            .join("results/findings/F-0001-aa/replay.py")
            .exists());
        assert!(tmp
            .path()
            .join("results/findings/F-0001-aa/finding.json")
            .is_file());
    }

    #[test]
    fn refuses_to_merge_into_existing_results() {
        let tmp = legacy_work();
        std::fs::create_dir_all(tmp.path().join("results/findings/F-9")).unwrap();
        let err = migrate_legacy(tmp.path()).unwrap_err();
        assert!(
            matches!(err, ResultsError::MigrationConflict { .. }),
            "{err}"
        );
        assert!(
            tmp.path().join("findings/F-0001-aa").is_dir(),
            "legacy left intact"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ignores_a_symlinked_findings_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), tmp.path().join("findings")).unwrap();
        assert_eq!(
            migrate_legacy(tmp.path()).unwrap(),
            MigrationOutcome::NotNeeded
        );
    }

    #[test]
    fn ignores_a_plain_file_named_findings() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("findings"), b"not a dir").unwrap();
        assert_eq!(
            migrate_legacy(tmp.path()).unwrap(),
            MigrationOutcome::NotNeeded
        );
    }

    #[test]
    fn preservation_failure_leaves_legacy_intact_and_is_retryable() {
        let tmp = legacy_work();
        let w = tmp.path();
        // results/legacy is a file, not a directory: keeping the legacy index
        // files must fail before anything moves, and leave everything as-is.
        std::fs::create_dir_all(w.join("results")).unwrap();
        std::fs::write(w.join("results/legacy"), b"not a dir").unwrap();

        let err = migrate_legacy(w).unwrap_err();
        assert!(matches!(err, ResultsError::Io { .. }), "{err}");
        assert!(
            w.join("findings/F-0001-aa").is_dir(),
            "legacy left intact for a retry"
        );
        assert!(
            w.join("FINDINGS.md").is_file(),
            "legacy index left in place"
        );
        assert!(
            !w.join("results/findings").exists(),
            "nothing was moved before the failure"
        );
        std::fs::remove_file(w.join("results/legacy")).unwrap();
        assert_eq!(migrate_legacy(w).unwrap(), MigrationOutcome::Migrated);
    }

    /// A directory named like a legacy index file is not bhf's: it stays.
    #[test]
    fn a_non_file_legacy_index_entry_is_left_alone() {
        let tmp = legacy_work();
        let w = tmp.path();
        std::fs::remove_file(w.join("FINDINGS.md")).unwrap();
        std::fs::create_dir_all(w.join("FINDINGS.md")).unwrap();
        assert_eq!(migrate_legacy(w).unwrap(), MigrationOutcome::Migrated);
        assert!(w.join("FINDINGS.md").is_dir());
        assert!(!w.join("results/legacy/FINDINGS.md").exists());
    }

    #[test]
    fn reclaim_target_treats_a_peer_populated_target_as_not_a_conflict() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path();
        // Simulate the moment after a peer's rename completed: `legacy` is
        // already gone by the time we get here, and `target` holds its
        // evidence.
        let legacy = work.join("findings");
        let target = work.join("results/findings");
        std::fs::create_dir_all(target.join("F-1")).unwrap();

        assert_eq!(migrate_inner(&legacy, &target, work).unwrap(), None);
        assert!(target.join("F-1").is_dir(), "peer's evidence left intact");
    }

    #[test]
    fn reclaim_empty_target_treats_a_peer_populated_target_as_not_a_conflict() {
        let tmp = tempfile::tempdir().unwrap();
        let legacy = tmp.path().join("findings"); // gone: a peer already renamed it away
        let target = tmp.path().join("target");
        // Non-empty, so the removal attempt fails with ENOTEMPTY exactly as
        // it would if a peer had just renamed its own evidence into it.
        std::fs::create_dir_all(target.join("F-1")).unwrap();

        match reclaim_empty_target(&legacy, &target).unwrap() {
            ReclaimOutcome::PeerMigrated => {}
            ReclaimOutcome::Proceed => panic!("expected PeerMigrated"),
        }
        assert!(target.join("F-1").is_dir());
    }

    #[test]
    fn rename_or_detect_peer_treats_a_vanished_legacy_as_not_needed() {
        let tmp = tempfile::tempdir().unwrap();
        let legacy = tmp.path().join("findings"); // gone: a peer already renamed it away
        let target = tmp.path().join("results/findings");
        std::fs::create_dir_all(target.join("F-1")).unwrap();

        assert_eq!(
            rename_or_detect_peer(&legacy, &target).unwrap(),
            MigrationOutcome::NotNeeded
        );
        assert!(target.join("F-1").is_dir());
    }

    #[test]
    fn peer_migrated_is_true_once_legacy_is_gone_even_with_an_empty_target() {
        let tmp = tempfile::tempdir().unwrap();
        let legacy = tmp.path().join("findings"); // never existed / already gone
        assert!(peer_migrated(&legacy));
    }

    #[test]
    fn reclaim_empty_target_does_not_delete_a_peers_completed_empty_migration() {
        let tmp = tempfile::tempdir().unwrap();
        let legacy = tmp.path().join("findings"); // gone: a peer renamed an EMPTY legacy away
        let target = tmp.path().join("results/findings");
        std::fs::create_dir_all(&target).unwrap(); // empty, exactly as that rename left it

        match reclaim_empty_target(&legacy, &target).unwrap() {
            ReclaimOutcome::PeerMigrated => {}
            ReclaimOutcome::Proceed => panic!("expected PeerMigrated"),
        }
        assert!(target.is_dir(), "peer's empty target must not be removed");
    }

    #[test]
    fn migrate_inner_treats_a_vanished_empty_legacy_as_not_needed() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path();
        let legacy = work.join("findings"); // gone: a peer renamed an EMPTY legacy away
        let target = work.join("results/findings");
        std::fs::create_dir_all(&target).unwrap();

        assert_eq!(migrate_inner(&legacy, &target, work).unwrap(), None);
        assert!(target.is_dir(), "peer's empty target must not be removed");
    }

    #[test]
    fn concurrent_migrations_of_an_empty_legacy_all_succeed_and_exactly_one_migrates() {
        let tmp = tempfile::tempdir().unwrap();
        let w = tmp.path();
        std::fs::create_dir_all(w.join("findings")).unwrap(); // empty legacy dir
        let work = std::sync::Arc::new(w.to_path_buf());

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let work = std::sync::Arc::clone(&work);
                std::thread::spawn(move || migrate_legacy(&work))
            })
            .collect();

        let mut migrated = 0;
        for handle in handles {
            match handle.join().unwrap() {
                Ok(MigrationOutcome::Migrated) => migrated += 1,
                Ok(MigrationOutcome::NotNeeded) => {}
                Err(error) => panic!("unexpected migration error: {error}"),
            }
        }

        assert_eq!(
            migrated, 1,
            "exactly one racer should move the (empty) evidence"
        );
        assert!(work.join("results/findings").is_dir());
        assert!(!work.join("findings").exists());
    }

    #[test]
    fn concurrent_migrations_all_succeed_and_exactly_one_moves_the_evidence() {
        let tmp = legacy_work();
        let work = std::sync::Arc::new(tmp.path().to_path_buf());

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let work = std::sync::Arc::clone(&work);
                std::thread::spawn(move || migrate_legacy(&work))
            })
            .collect();

        let mut migrated = 0;
        for handle in handles {
            match handle.join().unwrap() {
                Ok(MigrationOutcome::Migrated) => migrated += 1,
                Ok(MigrationOutcome::NotNeeded) => {}
                Err(error) => panic!("unexpected migration error: {error}"),
            }
        }

        assert_eq!(migrated, 1, "exactly one racer should move the evidence");
        assert!(work
            .join("results/findings/F-0001-aa/finding.json")
            .is_file());
        assert!(!work.join("findings").exists());
        assert!(!work.join("FINDINGS.md").exists());
        assert!(!work.join("findings.csv").exists());
        assert!(!work.join("auto/findings.csv").exists());
    }
}
