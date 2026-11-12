// SPDX-License-Identifier: Apache-2.0

//! `bhf report --backfill`: give C/C++ sanitizer findings that have no
//! `sanitizer.log` (findings migrated from a bhf 0.2.x work dir, or recorded
//! before bhf kept the log) the evidence a current run records. Each one is
//! replayed against its harness the way `bhf replay` replays it, and only when
//! the replay is the recorded crash (same rule, kind and sink or reported
//! site) are its `sanitizer.log`, crash frames and memory access written. The
//! finding's id and signature never change. The caller rebuilds `results/`
//! afterwards.

use crate::crash_identity;
use crate::replay::{run_c_testcase, CInput, REPLAY_TIMEOUT};
use crate::runner::{engine_for, harness_runner, HarnessEngine, SandboxModeArg};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// The `history` command name a backfill records.
const COMMAND: &str = "report --backfill";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BackfillSummary {
    pub(crate) updated: usize,
    pub(crate) skipped: usize,
    /// Findings that already had a log, or are not C/C++ sanitizer findings.
    pub(crate) not_needed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Updated { frames: usize, harness: PathBuf },
    Skipped(String),
    NotNeeded,
}

/// Backfill every finding under `<work>/results/findings/`, printing one line
/// per finding it tried and a summary.
pub(crate) fn run(work_dir: &Path) -> BackfillSummary {
    let findings_dir = corpus::layout::findings_dir(work_dir);
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&findings_dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.is_dir())
                .collect()
        })
        .unwrap_or_default();
    dirs.sort();
    let mut summary = BackfillSummary::default();
    for dir in dirs {
        let id = dir
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        match backfill_finding(&dir) {
            Outcome::Updated { frames, harness } => {
                summary.updated += 1;
                bhfeprintln!(
                    "bhf: backfill {id}: wrote sanitizer.log and {frames} crash frames from {}",
                    harness.display()
                );
            }
            Outcome::Skipped(reason) => {
                summary.skipped += 1;
                bhfeprintln!("bhf: backfill {id}: skipped, {reason}");
            }
            Outcome::NotNeeded => summary.not_needed += 1,
        }
    }
    bhfeprintln!(
        "bhf: backfill: {} updated, {} skipped, {} not needed (already have a sanitizer.log, or \
         are not C/C++ sanitizer findings)",
        summary.updated,
        summary.skipped,
        summary.not_needed
    );
    summary
}

/// Whether `raw` is a crash a C/C++ sanitizer (or an undiagnosed fatal
/// signal) reported, which a backfill can reproduce.
fn is_sanitizer_crash(raw: &Value) -> bool {
    let kind_ok = raw
        .get("finding_kind")
        .and_then(Value::as_str)
        .is_none_or(|kind| kind == corpus::finding::finding_kind::FUZZ);
    let name = raw
        .pointer("/exception/name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let sanitizer_name = ["ASAN_", "UBSAN_", "LSAN_", "MSAN_", "TSAN_"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
        || name == "FATAL_SIGNAL";
    kind_ok
        && sanitizer_name
        && raw.get("rule_id").and_then(Value::as_str).is_some()
        && raw.get("oracle").is_none()
}

fn backfill_finding(dir: &Path) -> Outcome {
    if dir.join("sanitizer.log").exists() || !dir.join("testcase.bin").is_file() {
        return Outcome::NotNeeded;
    }
    if crate::session_fuzz::is_session_finding(dir)
        || crate::collector_run::is_collector_finding(dir)
        || crate::transport_replay::is_transport_finding(dir)
        || crate::binary_fuzz::is_binary_finding(dir)
    {
        return Outcome::NotNeeded;
    }
    let path = dir.join("finding.json");
    let Some(mut raw) = std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
    else {
        return Outcome::Skipped(format!("cannot read {}", path.display()));
    };
    if !is_sanitizer_crash(&raw) {
        return Outcome::NotNeeded;
    }
    let harness = match crate::replay::recorded_harness(dir) {
        Ok(harness) => harness,
        Err(error) => return Outcome::Skipped(format!("no harness to replay against: {error}")),
    };
    let work = corpus::layout::work_dir_for_finding(dir);
    let work_dirs: Vec<&Path> = work.iter().map(PathBuf::as_path).collect();
    let detection = crate::protocol_detect::detect(&harness, &work_dirs);
    let input = if harness
        .file_name()
        .is_some_and(|name| name == "main_afl" || name == "main_afl.exe")
    {
        CInput::Stdin
    } else {
        match engine_for(detection.protocol) {
            HarnessEngine::CLibFuzzer | HarnessEngine::CAfl => CInput::ArgvFile,
            HarnessEngine::AdaStdin => {
                return Outcome::Skipped(format!(
                    "harness {} is not a C/C++ sanitizer harness ({})",
                    harness.display(),
                    detection.basis.describe()
                ))
            }
        }
    };
    let runner = harness_runner(
        harness.clone(),
        None,
        Vec::new(),
        SandboxModeArg::Auto,
        None,
        false,
    );
    let run = match run_c_testcase(
        &raw,
        &runner,
        input,
        &dir.join("testcase.bin"),
        REPLAY_TIMEOUT,
    ) {
        Ok(run) => run,
        Err(error) => return Outcome::Skipped(format!("replay failed: {error}")),
    };
    let Some(report) = run.report() else {
        return Outcome::Skipped(format!(
            "the testcase no longer crashes harness {} ({})",
            harness.display(),
            if run.timed_out {
                "timed out".to_owned()
            } else {
                exit_text(&run)
            }
        ));
    };
    let comparison = crash_identity::compare(&raw, &report);
    if !comparison.matches() {
        return Outcome::Skipped(format!(
            "harness {} now reports a different crash ({})",
            harness.display(),
            comparison.difference_lines().join("; ")
        ));
    }
    // An unsymbolized report proves neither where the crash is nor gives the
    // frames the backfill is for.
    if comparison.location_not_compared() {
        return Outcome::Skipped(format!(
            "the replay against harness {} is unsymbolized, so it gives no frames and its \
             location cannot be checked; put llvm-symbolizer on PATH or set ASAN_SYMBOLIZER_PATH \
             and run the backfill again",
            harness.display()
        ));
    }
    if let Err(error) = corpus::finding::write_sanitizer_log(dir, &run.stderr) {
        return Outcome::Skipped(format!("cannot write sanitizer.log: {error}"));
    }
    let fields = enrich(&mut raw, &report, &path);
    corpus::finding::append_history(&mut raw, COMMAND, &fields);
    let written = serde_json::to_vec_pretty(&raw)
        .map_err(std::io::Error::other)
        .and_then(|bytes| std::fs::write(&path, bytes));
    if let Err(error) = written {
        let _ = std::fs::remove_file(dir.join("sanitizer.log"));
        return Outcome::Skipped(format!("cannot update {}: {error}", path.display()));
    }
    Outcome::Updated {
        frames: report.stack.len(),
        harness,
    }
}

fn exit_text(run: &crate::replay::CRun) -> String {
    match run.status.and_then(|status| status.code()) {
        Some(code) => format!("exit status {code}"),
        None => "no crash".to_owned(),
    }
}

/// Write the replayed report's crash frames and structured evidence into the
/// record, and refresh the actionability fields that depend on them. Returns
/// the fields it set.
fn enrich(raw: &mut Value, report: &corpus::SanitizerReport, path: &Path) -> Vec<&'static str> {
    let mut fields = vec!["paths.sanitizer_log"];
    raw["paths"]["sanitizer_log"] = json!("sanitizer.log");
    if !report.stack.is_empty() {
        raw["exception"]["stack"] = json!(report.stack);
        fields.push("exception.stack");
    }
    if let Some(location) = &report.location {
        if raw.pointer("/exception/location").is_none() {
            raw["exception"]["location"] = json!(location);
            fields.push("exception.location");
        }
    }
    if let Some(check) = &report.check {
        if raw.pointer("/exception/check").is_none() {
            raw["exception"]["check"] = json!(check);
            fields.push("exception.check");
        }
    }
    if let Some(access) = &report.access {
        if raw.pointer("/exception/access").is_none() {
            raw["exception"]["access"] = json!(access);
            fields.push("exception.access");
        }
    }
    // The sink, fix location, source and explanation were derived from the
    // frames the finding lacked; recompute them from the new ones.
    if let Some(actionability) = raw.get_mut("actionability").and_then(Value::as_object_mut) {
        for key in ["sink", "fix_location", "source", "explanation"] {
            actionability.remove(key);
        }
    }
    raw["actionability"] =
        actionability::value_for_finding(actionability::RunMode::Reporting, raw, Some(path));
    fields.push("actionability");
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_sanitizer_crashes_are_backfilled() {
        let asan =
            json!({"rule_id": "BHF-201", "exception": {"name": "ASAN_HEAP_BUFFER_OVERFLOW"}});
        assert!(is_sanitizer_crash(&asan));
        let fatal = json!({"rule_id": "BHF-210", "finding_kind": "fuzz", "exception": {"name": "FATAL_SIGNAL"}});
        assert!(is_sanitizer_crash(&fatal));
        let ada = json!({"rule_id": "BHF-101", "exception": {"name": "CONSTRAINT_ERROR"}});
        assert!(!is_sanitizer_crash(&ada));
        let oracle = json!({"rule_id": "BHF-405", "oracle": {}, "exception": {"name": "ASAN_X"}});
        assert!(!is_sanitizer_crash(&oracle));
        let runtime = json!({"rule_id": "BHF-201", "finding_kind": "runtime", "exception": {"name": "ASAN_X"}});
        assert!(!is_sanitizer_crash(&runtime));
    }

    /// A finding recorded without frames gains them, its location and access,
    /// and a sink naming the function, without losing its other evidence.
    #[test]
    fn enrich_adds_frames_evidence_and_a_named_sink() {
        let report = corpus::parse_sanitizer_report(
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000031 at pc 0x1 bp 0x2 sp 0x3\n\
             WRITE of size 1 at 0x602000000031 thread T0\n\
             \x20   #0 0x1 in Widget::copy_at(char const*) /src/widget/widget.cc:12:5\n\
             \n\
             0x602000000031 is located 0 bytes after 1-byte region [0x602000000030,0x602000000031)\n\
             SUMMARY: AddressSanitizer: heap-buffer-overflow /src/widget/widget.cc:12:5 in Widget::copy_at\n",
        )
        .unwrap();
        let mut raw = json!({
            "rule_id": "BHF-201",
            "exception": {"name": "ASAN_HEAP_BUFFER_OVERFLOW", "stack": []},
            "actionability": {"mode": "reporting", "verdict": "unknown", "impact": "high",
                "confidence": "low", "prosthetics": {"used": false},
                "sink": {"function": ""}},
            "paths": {"testcase": "testcase.bin"},
        });
        let fields = enrich(&mut raw, &report, Path::new("finding.json"));
        assert_eq!(
            fields,
            [
                "paths.sanitizer_log",
                "exception.stack",
                "exception.location",
                "exception.access",
                "actionability"
            ]
        );
        assert_eq!(raw["paths"]["testcase"], "testcase.bin");
        assert_eq!(
            raw["exception"]["stack"][0]["function"],
            "Widget::copy_at(char const*)"
        );
        assert_eq!(raw["actionability"]["sink"]["function"], "Widget::copy_at");
        assert_eq!(raw["actionability"]["verdict"], "unknown", "verdict kept");
    }
}
