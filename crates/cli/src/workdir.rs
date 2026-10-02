// SPDX-License-Identifier: Apache-2.0
//! Work-dir entry and exit hooks shared by every command that reads or writes
//! findings.

use std::path::{Path, PathBuf};

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

/// Close a producer bracket: append to the manifest, rebuild results/, and
/// print the `Results:` line to stderr (stdout carries JSON for some commands).
/// A rebuild failure is a warning and never changes the command's exit code.
pub fn finish(run: results::ProducerRun, exit_code: i32, status: results::model::ProducerStatus) {
    match run.complete(exit_code, status) {
        Ok(summary) => crate::bhfeprintln!("{}", results_line(&summary)),
        Err(error) => crate::bhfeprintln!(
            "warning: results index not rebuilt: {error}; run 'bhf report' to retry"
        ),
    }
}

fn results_line(summary: &results::RebuildSummary) -> String {
    format!(
        "Results: {} ({} findings{})",
        summary.index_path.display(),
        summary.findings,
        if summary.errors > 0 {
            format!(", {} unreadable", summary.errors)
        } else {
            String::new()
        }
    )
}

/// `fs::canonicalize` (symlinks resolved, as auto's finding paths are), minus
/// Windows' verbatim disk prefix, so a recorded source root is `C:\src` like
/// the paths findings carry, not `\\?\C:\src`. Falls back to `path` when it
/// cannot be resolved.
pub fn plain_canonical(path: &Path) -> PathBuf {
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    match canonical.to_str() {
        Some(text) => PathBuf::from(strip_verbatim_disk_prefix(text)),
        None => canonical,
    }
}

/// `\\?\C:\...` becomes `C:\...`; anything else, `\\?\UNC\...` included, is
/// returned unchanged.
fn strip_verbatim_disk_prefix(path: &str) -> &str {
    let Some(rest) = path.strip_prefix(r"\\?\") else {
        return path;
    };
    match rest.as_bytes() {
        [drive, b':', ..] if drive.is_ascii_alphabetic() => rest,
        _ => path,
    }
}

/// `auto` marks a run partial in `auto/run.json`; every other producer is complete.
pub fn auto_status(work_dir: &Path) -> results::model::ProducerStatus {
    let partial = std::fs::read(work_dir.join("auto/run.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|v| v.get("partial").and_then(serde_json::Value::as_bool))
        .unwrap_or(false);
    if partial {
        results::model::ProducerStatus::Partial
    } else {
        results::model::ProducerStatus::Complete
    }
}

#[cfg(test)]
mod tests {
    use super::{
        auto_status, finish, plain_canonical, prepare, results_line, strip_verbatim_disk_prefix,
    };
    use results::model::ProducerStatus;

    #[test]
    fn verbatim_disk_prefix_is_stripped_and_nothing_else() {
        let cases = [
            (r"\\?\C:\src\demo", r"C:\src\demo"),
            (r"\\?\z:\", r"z:\"),
            (r"\\?\UNC\server\share\x", r"\\?\UNC\server\share\x"),
            (r"\\?\Volume{0}\x", r"\\?\Volume{0}\x"),
            (r"\\?\1:\x", r"\\?\1:\x"),
            (r"\\.\C:\x", r"\\.\C:\x"),
            (r"C:\src", r"C:\src"),
            ("/src/demo", "/src/demo"),
            ("", ""),
        ];
        for (input, want) in cases {
            assert_eq!(strip_verbatim_disk_prefix(input), want, "{input}");
        }
    }

    #[test]
    fn plain_canonical_resolves_or_falls_back() {
        let tmp = tempfile::tempdir().unwrap();
        let dotted = tmp.path().join("a/..");
        std::fs::create_dir_all(tmp.path().join("a")).unwrap();
        let canonical = tmp.path().canonicalize().unwrap();
        assert_eq!(
            plain_canonical(&dotted),
            std::path::PathBuf::from(strip_verbatim_disk_prefix(canonical.to_str().unwrap()))
        );
        assert!(!plain_canonical(&dotted)
            .to_string_lossy()
            .starts_with(r"\\?\"));
        let missing = tmp.path().join("nope");
        assert_eq!(plain_canonical(&missing), missing);
    }

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

    fn write_run_json(work: &std::path::Path, body: &str) {
        std::fs::create_dir_all(work.join("auto")).unwrap();
        std::fs::write(work.join("auto/run.json"), body).unwrap();
    }

    #[test]
    fn auto_status_is_partial_only_when_run_json_says_so() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(auto_status(tmp.path()), ProducerStatus::Complete);
        write_run_json(tmp.path(), r#"{"partial": true}"#);
        assert_eq!(auto_status(tmp.path()), ProducerStatus::Partial);
        write_run_json(tmp.path(), r#"{"partial": false}"#);
        assert_eq!(auto_status(tmp.path()), ProducerStatus::Complete);
        write_run_json(tmp.path(), "not json");
        assert_eq!(auto_status(tmp.path()), ProducerStatus::Complete);
    }

    #[test]
    fn results_line_names_the_index_and_counts_unreadable_records() {
        let summary = results::RebuildSummary {
            findings: 3,
            errors: 0,
            index_path: std::path::PathBuf::from("w/results/INDEX.md"),
        };
        assert_eq!(
            results_line(&summary),
            "Results: w/results/INDEX.md (3 findings)"
        );
        let summary = results::RebuildSummary {
            errors: 2,
            ..summary
        };
        assert_eq!(
            results_line(&summary),
            "Results: w/results/INDEX.md (3 findings, 2 unreadable)"
        );
    }

    #[test]
    fn finish_appends_the_producer_and_rebuilds_results() {
        let tmp = tempfile::tempdir().unwrap();
        let run =
            results::ProducerRun::begin(tmp.path(), "auto", vec!["bhf".into(), "auto".into()]);
        finish(run, 0, ProducerStatus::Partial);
        let results = tmp.path().join("results");
        assert!(results.join("INDEX.md").is_file());
        assert!(results.join("findings.json").is_file());
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(results.join("manifest.json")).unwrap()).unwrap();
        let producers = manifest["producers"].as_array().expect("producers");
        let last = producers.last().expect("one producer");
        assert_eq!(last["command"], "auto");
        assert_eq!(last["status"], "partial");
        assert_eq!(last["exit_code"], 0);
    }
}
