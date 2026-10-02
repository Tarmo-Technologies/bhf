// SPDX-License-Identifier: Apache-2.0
//! One-time move of a bhf <= 0.2.x work dir (`<work>/findings/`) into the
//! results layout (`<work>/results/findings/`).

use crate::{io_err, layout, ResultsError};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationOutcome {
    NotNeeded,
    Migrated,
}

/// Derived legacy index files; regenerated under `results/` by the rebuild.
const LEGACY_DERIVED: [&str; 3] = ["FINDINGS.md", "findings.csv", "auto/findings.csv"];

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
) -> Result<MigrationOutcome, ResultsError> {
    if let ReclaimOutcome::PeerMigrated = reclaim_target(legacy, target)? {
        return Ok(MigrationOutcome::NotNeeded);
    }

    // Delete derived legacy index files BEFORE the rename: if this fails,
    // legacy is untouched and the whole migration is safely retryable.
    for rel in LEGACY_DERIVED {
        let path = work_dir.join(rel);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(ResultsError::Io { path, source }),
        }
    }

    let results = layout::results_dir(work_dir);
    std::fs::create_dir_all(&results).map_err(io_err(&results))?;

    if rename_or_detect_peer(legacy, target)? == MigrationOutcome::NotNeeded {
        return Ok(MigrationOutcome::NotNeeded);
    }

    // Generated reproducer scripts encode the old directory depth; drop them so
    // the next rebuild regenerates them with the current template.
    if let Ok(entries) = std::fs::read_dir(target) {
        for entry in entries.flatten() {
            let _ = std::fs::remove_file(entry.path().join("replay.py"));
        }
    }
    Ok(MigrationOutcome::Migrated)
}

/// Rename `<work>/findings` to `<work>/results/findings` (same filesystem, so
/// evidence is moved, never copied) and delete the derived legacy index files.
/// A symlink or non-directory named `findings` is not ours and is left alone.
/// Refuses to merge when the target is already populated by something other
/// than a peer's in-flight migration of the same legacy dir; a peer that
/// finishes first anywhere along the way is treated as [`MigrationOutcome::NotNeeded`],
/// never as an error.
pub fn migrate_legacy(work_dir: &Path) -> Result<MigrationOutcome, ResultsError> {
    let legacy = layout::legacy_findings_dir(work_dir);
    match std::fs::symlink_metadata(&legacy) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Ok(MigrationOutcome::NotNeeded),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(MigrationOutcome::NotNeeded)
        }
        Err(source) => {
            return Err(ResultsError::Io {
                path: legacy,
                source,
            })
        }
    }
    let target = layout::findings_dir(work_dir);
    migrate_inner(&legacy, &target, work_dir)
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
    fn moves_legacy_findings_and_drops_derived_files() {
        let tmp = legacy_work();
        let w = tmp.path();
        assert_eq!(migrate_legacy(w).unwrap(), MigrationOutcome::Migrated);
        assert!(w.join("results/findings/F-0001-aa/finding.json").is_file());
        assert!(!w.join("findings").exists());
        assert!(!w.join("FINDINGS.md").exists());
        assert!(!w.join("findings.csv").exists());
        assert!(!w.join("auto/findings.csv").exists());
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
    fn migration_drops_stale_replay_scripts() {
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
    fn derived_file_delete_failure_leaves_legacy_intact_and_is_retryable() {
        let tmp = legacy_work();
        let w = tmp.path();
        // FINDINGS.md is a directory, not a file: the strict delete must fail
        // with something other than NotFound, and leave everything as-is.
        std::fs::remove_file(w.join("FINDINGS.md")).unwrap();
        std::fs::create_dir_all(w.join("FINDINGS.md")).unwrap();

        let err = migrate_legacy(w).unwrap_err();
        assert!(matches!(err, ResultsError::Io { .. }), "{err}");
        assert!(
            w.join("findings/F-0001-aa").is_dir(),
            "legacy left intact for a retry"
        );
        assert!(
            !w.join("results/findings").exists(),
            "nothing was moved before the failure"
        );
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

        assert_eq!(
            migrate_inner(&legacy, &target, work).unwrap(),
            MigrationOutcome::NotNeeded
        );
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

        assert_eq!(
            migrate_inner(&legacy, &target, work).unwrap(),
            MigrationOutcome::NotNeeded
        );
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
