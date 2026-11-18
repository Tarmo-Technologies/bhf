// SPDX-License-Identifier: Apache-2.0

//! Control-flow integrity corpus replay (#297): a cast to the wrong class, a
//! virtual call through an object of another type, or a call through a function
//! pointer of the wrong type (CWE-843), which ASan and UBSan do not see.
//!
//! `-fsanitize=cfi` needs whole-program LTO and hidden visibility, which the
//! fuzzed build does not use, so `bhf auto --sanitizers cfi` builds a separate
//! binary (`make cfi`, C and C++) and replays the fuzz pass's saved corpus
//! through it. Its checks report through the UBSan runtime instead of
//! trapping, and a report at a target source becomes a finding under the rule
//! the report's check maps to (BHF-221, type confusion), which `bhf replay`
//! reproduces with the same build.
//!
//! Best-effort: a missing `make` or corpus, or a CFI build that fails (no clang,
//! no LTO linker), skips the harness and says so.

use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::auto::sanitizer_replay::{ReplayBounds, RunOutcome};

/// Cap the number of corpus inputs replayed per harness.
const MAX_INPUTS: usize = 2000;

/// What a CFI replay of a run found and could not do.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CfiReplay {
    /// Findings written.
    pub findings: usize,
    /// Harnesses whose CFI build failed: their corpus was not replayed.
    pub unbuilt: Vec<String>,
}

/// Replay every C/C++ harness's corpus through its CFI build, writing a
/// finding per distinct violation site, within `bounds`.
pub fn run_cfi_replay(work_dir: &Path, bounds: &ReplayBounds) -> CfiReplay {
    let mut replay = CfiReplay::default();
    let Ok(harnesses) = std::fs::read_dir(work_dir.join("harnesses")) else {
        return replay;
    };
    let mut index = 0usize;
    let mut harnesses: Vec<PathBuf> = harnesses.flatten().map(|entry| entry.path()).collect();
    harnesses.sort();
    for hdir in harnesses {
        let Some(harness_id) = hdir
            .file_name()
            .and_then(|n| n.to_str())
            .map(ToOwned::to_owned)
        else {
            continue;
        };
        match replay_one(work_dir, &hdir, &harness_id, &mut index, bounds) {
            Some(written) => replay.findings += written,
            None => replay.unbuilt.push(harness_id),
        }
    }
    replay
}

/// One harness's replay: the findings it wrote, or `None` when its CFI build
/// failed. A harness with no Makefile or no corpus writes none.
fn replay_one(
    work_dir: &Path,
    hdir: &Path,
    harness_id: &str,
    index: &mut usize,
    bounds: &ReplayBounds,
) -> Option<usize> {
    if !hdir.join("Makefile").is_file() {
        return Some(0);
    }
    let queue = work_dir.join("corpus").join(harness_id).join("queue");
    let Ok(inputs) = std::fs::read_dir(&queue) else {
        return Some(0);
    };
    let mut inputs: Vec<PathBuf> = inputs
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();
    if inputs.is_empty() {
        return Some(0);
    }
    inputs.sort();
    let built = crate::command_output::output_with_timeout(
        Command::new("make").arg("cfi").current_dir(hdir),
        Duration::from_secs(600),
    )
    .map(|o| o.status.success())
    .unwrap_or(false);
    let bin = crate::auto::layout::harness_exe(hdir, "main_cfi");
    if !built || !bin.is_file() {
        return None;
    }

    // Each site, with the first queue entry that showed it.
    let mut sites: BTreeMap<(String, u64), (PathBuf, String)> = BTreeMap::new();
    let started = Instant::now();
    let hdir_text = hdir.to_string_lossy().into_owned();
    for path in inputs.into_iter().take(MAX_INPUTS) {
        if started.elapsed() >= bounds.per_harness {
            break;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if bounds.is_known_hang(&bytes) {
            bounds.log_run(
                "cfi",
                harness_id,
                &path,
                Duration::ZERO,
                RunOutcome::SkippedKnownHang,
            );
            continue;
        }
        let run_started = Instant::now();
        let run = crate::command_output::output_with_timeout_flagged(
            Command::new(&bin).arg(&path).env(
                "UBSAN_OPTIONS",
                "halt_on_error=1:print_stacktrace=1:report_error_type=1",
            ),
            bounds.run_timeout,
        );
        let elapsed = run_started.elapsed();
        let out = match run {
            Ok((out, false)) => {
                bounds.log_run("cfi", harness_id, &path, elapsed, RunOutcome::Completed);
                out
            }
            Ok((_, true)) => {
                bounds.log_run("cfi", harness_id, &path, elapsed, RunOutcome::TimedOut);
                bounds.note_hang(&bytes);
                continue;
            }
            Err(_) => {
                bounds.log_run("cfi", harness_id, &path, elapsed, RunOutcome::SpawnFailed);
                continue;
            }
        };
        let stderr = String::from_utf8_lossy(&out.stderr);
        if let Some(site) = violation_site(&stderr, &hdir_text) {
            sites
                .entry(site)
                .or_insert_with(|| (path, stderr.into_owned()));
        }
    }

    let mut written = 0usize;
    let queue = crate::fuzz_lineage::ReplayedQueue::open(work_dir, harness_id);
    for ((file, line), (input, report)) in sites {
        let id = format!("F-CFI-{:04}", *index);
        *index += 1;
        let shown_by = queue.entry(&input);
        if write_cfi_finding(
            work_dir, &id, harness_id, &file, line, &input, &report, &bin, &shown_by,
        ) {
            written += 1;
        }
    }
    Some(written)
}

/// The target source and line of a control-flow-integrity report in
/// `stderr`: its `file:line:col: runtime error:` location, or, when that is
/// bhf's harness or a library, the first frame of its stack that is the
/// target's. `None` for output without a CFI report.
fn violation_site(stderr: &str, hdir: &str) -> Option<(String, u64)> {
    if !stderr.contains("control flow integrity check") {
        return None;
    }
    let report = corpus::parse_sanitizer_report(stderr)?;
    let located = report
        .location
        .iter()
        .map(|location| (location.file.clone(), u64::from(location.line)));
    let frames = report
        .stack
        .iter()
        .filter_map(|frame| Some((frame.file.clone()?, u64::from(frame.line?))));
    located
        .chain(frames)
        .find(|(file, _)| !crate::auto::msan::is_noise_frame(file, hdir))
}

/// Persist one CFI violation as a runtime finding, under the rule its UBSan
/// check maps to, with the CFI build as the fixture `bhf replay` runs.
#[allow(clippy::too_many_arguments)]
fn write_cfi_finding(
    work: &Path,
    id: &str,
    harness_id: &str,
    file: &str,
    line: u64,
    input: &Path,
    stderr: &str,
    binary: &Path,
    shown_by: &crate::fuzz_lineage::ReplayedEntry,
) -> bool {
    let Some(report) = corpus::parse_sanitizer_report(stderr) else {
        return false;
    };
    let dir = corpus::layout::finding_dir(work, id);
    if std::fs::create_dir_all(&dir).is_err() {
        return false;
    }
    let function = report
        .stack
        .iter()
        .find(|frame| {
            frame.file.as_deref() == Some(file) && frame.line.map(u64::from) == Some(line)
        })
        .map(|frame| frame.function.clone())
        .filter(|function| !function.is_empty());
    let name = function.clone().unwrap_or_else(|| {
        Path::new(file)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| file.to_owned())
    });
    let rule_id = report.rule_id;
    let cluster_key_full = hex(&Sha256::digest(
        format!("{rule_id}:cfi:{file}:{line}").as_bytes(),
    ));
    let mut evidence = vec![json!({ "key": "source", "value": format!("{file}:{line}") })];
    evidence.extend(shown_by.evidence());
    let mut record = json!({
        "id": id,
        "rule_id": rule_id,
        "classification": "unhandled",
        "severity": "high",
        "harness_id": harness_id,
        "cluster_key_full": cluster_key_full,
        "target": { "name": name, "source_path": file, "line": line },
        // As the emitter writes a sanitizer crash, so `bhf replay` compares
        // the CFI build's report with it.
        "exception": {
            "name": format!("UBSAN_{}", report.kind.to_uppercase().replace('-', "_")),
            "sanitizer": "ubsan",
            "message": report.message,
            "stack": report.stack,
        },
        "oracle": { "evidence": evidence },
        "analysis": { "engine": "bhf.dynamic.cfi.replay" },
        "actionability": { "cwe": ["CWE-843"], "verdict": "likely_reachable", "confidence": "high" },
    });
    let mut paths = serde_json::Map::new();
    paths.insert("finding".to_owned(), json!("finding.json"));
    if std::fs::copy(input, dir.join("testcase.bin")).is_ok() {
        paths.insert("testcase".to_owned(), json!("testcase.bin"));
    }
    if corpus::finding::write_sanitizer_log(&dir, stderr.as_bytes()).is_ok() {
        paths.insert("sanitizer_log".to_owned(), json!("sanitizer.log"));
    }
    record["paths"] = serde_json::Value::Object(paths);
    // Replay runs the CFI build, not the fuzzed `main`.
    record["fixture_path"] = json!(corpus::finding::stored_fixture_path(
        work,
        &binary.display().to_string()
    ));
    if let Some(format) = crate::fuzz::harness_format_for(binary, work, harness_id) {
        record["harness_format_version"] = json!(format.version);
    }
    crate::fuzz_lineage::insert(&mut record, &shown_by.lineage);
    corpus::finding::stamp_v1(&mut record, corpus::finding::finding_kind::RUNTIME);
    std::fs::write(
        dir.join("finding.json"),
        serde_json::to_vec_pretty(&record).unwrap_or_default(),
    )
    .is_ok()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str = "\
/src/shapes/area.cpp:7:22: runtime error: control flow integrity check for type 'Circle' failed during base-to-derived cast (vtable address 0x6076bfee4ce0)\n\
0x6076bfee4ce0: note: vtable is of type 'Square'\n\
    #0 0x55d1 in classify(int) /src/shapes/area.cpp:7:22\n\
    #1 0x55e2 in bhf_run_one /work/harnesses/H-X/main.cpp:40:5\n\
SUMMARY: UndefinedBehaviorSanitizer: cfi-bad-type /src/shapes/area.cpp:7:22\n";

    #[test]
    fn a_cfi_report_is_placed_at_its_target_line_under_the_type_confusion_rule() {
        assert_eq!(
            violation_site(REPORT, "/work/harnesses/H-X"),
            Some(("/src/shapes/area.cpp".to_owned(), 7))
        );
        let report = corpus::parse_sanitizer_report(REPORT).unwrap();
        assert_eq!(report.kind, "type-mismatch");
        assert_eq!(report.rule_id, "BHF-221");
        // A report in bhf's harness falls to the first target frame.
        let in_harness = REPORT.replace(
            "/src/shapes/area.cpp:7:22: runtime error",
            "/work/harnesses/H-X/main.cpp:40:5: runtime error",
        );
        assert_eq!(
            violation_site(&in_harness, "/work/harnesses/H-X"),
            Some(("/src/shapes/area.cpp".to_owned(), 7))
        );
        assert_eq!(
            violation_site("runtime error: shift exponent 40", "/w"),
            None
        );
    }
}
