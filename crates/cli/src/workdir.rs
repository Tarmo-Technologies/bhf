// SPDX-License-Identifier: Apache-2.0
//! Work-dir entry hook shared by every command that reads or writes findings.

use std::path::Path;

/// Migrate a legacy (<= 0.2.x) work dir into the results layout, logging once.
/// A missing work dir is fine (the command creates it).
pub fn prepare(work_dir: &Path) -> anyhow::Result<()> {
    if !work_dir.exists() {
        return Ok(());
    }
    if results::migrate::migrate_legacy(work_dir)? == results::migrate::MigrationOutcome::Migrated {
        crate::bhfeprintln!(
            "bhf: migrated legacy {}/findings/ to {}",
            work_dir.display(),
            corpus::layout::findings_dir(work_dir).display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::prepare;

    #[test]
    fn prepare_migrates_legacy_layout() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("findings/F-1")).unwrap();
        prepare(tmp.path()).unwrap();
        assert!(tmp.path().join("results/findings/F-1").is_dir());
    }

    #[test]
    fn prepare_on_missing_work_dir_is_ok() {
        let tmp = tempfile::tempdir().unwrap();
        prepare(&tmp.path().join("nope")).unwrap();
    }
}
