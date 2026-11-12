// SPDX-License-Identifier: Apache-2.0
//! Work-dir entry and exit hooks shared by every command that reads or writes
//! findings.

use std::path::{Path, PathBuf};

/// Migrate a legacy (<= 0.2.x) work dir into the results layout, saying what
/// changed. A missing work dir is fine (the command creates it).
pub fn prepare(work_dir: &Path) -> anyhow::Result<()> {
    prepare_with(work_dir, true)
}

/// [`prepare`] for a command that only reads the work dir (`bhf explain`): it
/// migrates a legacy layout but does not rebuild `results/`, and its migration
/// message ends by naming the command that does.
pub fn prepare_read_only(work_dir: &Path) -> anyhow::Result<()> {
    prepare_with(work_dir, false)
}

fn prepare_with(work_dir: &Path, rebuilds_results: bool) -> anyhow::Result<()> {
    if !work_dir.exists() {
        return Ok(());
    }
    if let Some(report) = results::migrate::migrate_legacy_report(work_dir)? {
        let mut lines = migration_lines(work_dir, &report);
        if !rebuilds_results {
            // The command comes last, quoted for a shell, so it can be pasted.
            lines.push(format!(
                "bhf:   this command does not rebuild results/; to rebuild it, run: bhf report \
                 --work-dir {}",
                crate::repro_lane::sh_word(&work_dir.to_string_lossy())
            ));
        }
        for line in lines {
            crate::bhfeprintln!("{line}");
        }
    }
    Ok(())
}

/// What a migration changed and what to do next, one line each.
fn migration_lines(work_dir: &Path, report: &results::migrate::MigrationReport) -> Vec<String> {
    let work = work_dir.display();
    let legacy = results::migrate::legacy_dir(work_dir);
    let mut lines = vec![
        format!("bhf: migrated legacy work dir {work} to the results layout:"),
        format!(
            "bhf:   moved {work}/findings/ ({} findings) to {}/",
            report.findings,
            corpus::layout::findings_dir(work_dir).display()
        ),
    ];
    if !report.preserved.is_empty() {
        lines.push(format!(
            "bhf:   kept {} under {}/ (results/INDEX.md and results/findings.{{json,csv,sarif}} replace them)",
            report.preserved.join(", "),
            legacy.display()
        ));
    }
    if report.reproducers > 0 {
        lines.push(format!(
            "bhf:   kept {} replay.py scripts under {}/findings/; the next rebuild writes current ones",
            report.reproducers,
            legacy.display()
        ));
    }
    lines.push(format!(
        "bhf:   the evidence is unchanged: migrated findings have no sanitizer.log or frames until \
         'bhf report --backfill --work-dir {work}' replays them against their harness"
    ));
    lines.push(
        "bhf:   the next 'bhf auto' sets the old corpus aside instead of reseeding it (pass \
         --reuse-legacy-corpus to keep it); a fresh work dir is cleaner"
            .to_owned(),
    );
    lines.push(
        "bhf:   the migration is one-way: bhf 0.2.x cannot read this work dir any more".to_owned(),
    );
    lines
}

/// Close a producer bracket: append to the manifest, rebuild results/, and
/// print the `Results:` line to stderr (stdout carries JSON for some commands).
/// A rebuild failure is a warning and never changes the command's exit code.
pub fn finish(run: results::ProducerRun, exit_code: i32, status: results::model::ProducerStatus) {
    match run.complete(exit_code, status) {
        Ok(summary) => {
            crate::bhfeprintln!("{}", results_line(&summary));
            warn_about_damaged_inputs(&summary);
        }
        Err(error) => crate::bhfeprintln!(
            "warning: results index not rebuilt: {error}; run 'bhf report' to retry"
        ),
    }
}

/// Repeat INDEX.md's warning about inputs an earlier release's seed encoding
/// damaged, so it is seen without opening the index.
pub fn warn_about_damaged_inputs(summary: &results::RebuildSummary) {
    if let Some(damaged) = &summary.damaged_inputs {
        crate::bhfeprintln!(
            "warning: {}",
            results::render::index_md::damaged_inputs_line(damaged).replace('`', "")
        );
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

    /// Migration says what it moved, what it kept and where, and what the
    /// operator can do next.
    #[test]
    fn migration_is_reported_line_by_line() {
        let report = results::migrate::MigrationReport {
            findings: 9,
            preserved: vec!["FINDINGS.md".to_owned(), "auto/findings.csv".to_owned()],
            reproducers: 9,
        };
        let lines = super::migration_lines(std::path::Path::new("/w"), &report);
        let text = lines.join("\n");
        for needle in [
            "migrated legacy work dir /w to the results layout",
            "moved /w/findings/ (9 findings) to /w/results/findings/",
            "kept FINDINGS.md, auto/findings.csv under /w/results/legacy/",
            "kept 9 replay.py scripts under /w/results/legacy/findings/",
            "--reuse-legacy-corpus",
            "bhf report --backfill",
            "one-way",
        ] {
            assert!(text.contains(needle), "missing {needle:?} in:\n{text}");
        }
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
            damaged_inputs: None,
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
