// SPDX-License-Identifier: Apache-2.0

//! ThreadSanitizer corpus replay — data races (CWE-362, BHF-556) that ASan/UBSan do
//! not detect.
//!
//! TSan cannot be combined with ASan, so instead of a second fuzz loop bhf builds
//! a SEPARATE TSan-instrumented binary (`make tsan`, C only — the C++ Makefile has no
//! `tsan` target) and replays the ASan pass's saved corpus through it. An input that
//! drove a data race becomes a BHF-556 runtime finding — so it flows through the same
//! confirmation/attestation path as any fuzz crash.
//!
//! A race only surfaces when the target itself spawns threads while processing one
//! input; a single-threaded target simply reports none, so this is best-effort and,
//! like the MSan replay, FP-gated: only a report whose FAULTING frame lands in a
//! target source (not the bhf driver, the C runtime, or a system library) is
//! emitted. Missing `make`/corpus, a failed TSan build, or a C++ harness all skip
//! cleanly.

use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// Cap the number of corpus inputs replayed per harness so a huge queue can't stall
/// the run; the coverage-diverse queue front is what matters for race detection.
const MAX_INPUTS: usize = 2000;

/// Extra attempts for an unexplained abnormal exit. This preserves the existing
/// tolerance for a busy sanitizer host without repeatedly executing a target that
/// is deterministically broken.
const TSAN_RUN_RETRIES: usize = 4;

/// Executions per harness that never completed (timeout or spawn failure) before
/// the replay stops retrying them. A starved or oversubscribed host can push a
/// tiny TSan binary past its per-run timeout, and one transient stall should not
/// cost the harness its race coverage — but a target that genuinely hangs must
/// not be retried into a multi-hour replay either.
const TSAN_TIMEOUT_LIMIT: usize = 16;

/// Wall clock for one replayed input. Injectable so the timeout path can be
/// tested in milliseconds instead of costing the suite five real 30s stalls.
const TSAN_RUN_TIMEOUT: Duration = Duration::from_secs(30);

/// Consecutive explicit shadow-memory initialization failures tolerated across a
/// harness. High-entropy ASLR can make TSan fail many very fast startups in a row,
/// even immediately before the same binary runs successfully. Keep this budget
/// harness-wide so a permanently incompatible host cannot multiply it by every
/// corpus input.
const TSAN_MAPPING_FAILURE_LIMIT: usize = 256;

/// What a replay produced, and what it could not measure.
///
/// `unmeasured` exists because a corpus input whose TSan run never completed is
/// NOT evidence that the input is race-free — but the replay used to report it
/// exactly as if it were, by returning only a finding count. A silent
/// "0 races found" that actually means "0 races observed, 200 inputs never ran"
/// is the same false-clean this codebase rejects elsewhere (`stub_only`,
/// `built_not_entered`, budget cut-offs in the blocker histogram).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TsanReplay {
    /// BHF-556 findings written.
    pub findings: usize,
    /// Corpus inputs whose TSan execution never completed (timeout or spawn
    /// failure), after retries.
    pub unmeasured: usize,
    /// Inputs where ThreadSanitizer DID report a data race that could not be
    /// attributed to any source location at all, because no frame in the report
    /// carried a `file:line` locator (an unsymbolized report — no usable
    /// `llvm-symbolizer`, a stripped binary, frames that are only
    /// `module+0xoffset`).
    ///
    /// This is deliberately NOT the same as a race whose frames resolve but land
    /// only in the bhf driver, the bundled C runtime, or a system library. That
    /// one is *classified* — it is a race in the scaffolding, not in the target —
    /// and dropping it is correct and intentional (see `first_target_frame`).
    ///
    /// An unsymbolized report is not classified, it is unreadable. Dropping it
    /// silently reports the harness race-free on the strength of evidence that
    /// says the opposite, which is the same false-clean `unmeasured` exists to
    /// prevent.
    pub unattributed: usize,
}

/// Replay every C harness's corpus through its TSan build, writing a BHF-556 finding
/// per distinct data-race site.
pub fn run_tsan_replay(work_dir: &Path) -> TsanReplay {
    run_tsan_replay_with(work_dir, TSAN_RUN_TIMEOUT)
}

fn run_tsan_replay_with(work_dir: &Path, run_timeout: Duration) -> TsanReplay {
    let Ok(harnesses) = std::fs::read_dir(work_dir.join("harnesses")) else {
        return TsanReplay::default();
    };
    let mut total = TsanReplay::default();
    let mut index = 0usize;
    for entry in harnesses.flatten() {
        let hdir = entry.path();
        let Some(harness_id) = hdir
            .file_name()
            .and_then(|n| n.to_str())
            .map(ToOwned::to_owned)
        else {
            continue;
        };
        let one = replay_one(work_dir, &hdir, &harness_id, &mut index, run_timeout);
        total.findings += one.findings;
        total.unmeasured += one.unmeasured;
        total.unattributed += one.unattributed;
    }
    total
}

fn replay_one(
    work_dir: &Path,
    hdir: &Path,
    harness_id: &str,
    index: &mut usize,
    run_timeout: Duration,
) -> TsanReplay {
    if !hdir.join("Makefile").is_file() {
        return TsanReplay::default();
    }
    // Build the TSan variant. C++ harnesses have no `tsan` target -> make fails ->
    // skip. A genuine TSan build error also skips.
    let built = crate::command_output::output_with_timeout(
        Command::new("make").arg("tsan").current_dir(hdir),
        Duration::from_secs(600),
    )
    .map(|o| o.status.success())
    .unwrap_or(false);
    let bin = hdir.join("main_tsan");
    if !built || !bin.is_file() {
        return TsanReplay::default();
    }

    let queue = work_dir.join("corpus").join(harness_id).join("queue");
    let Ok(inputs) = std::fs::read_dir(&queue) else {
        return TsanReplay::default();
    };
    let mut sites: BTreeSet<(String, u64)> = BTreeSet::new();
    let mut replayed = 0usize;
    let mut consecutive_mapping_failures = 0usize;
    let mut unmeasured = 0usize;
    let mut unattributed = 0usize;
    let mut harness_timeouts = 0usize;
    'inputs: for input in inputs.flatten() {
        if replayed >= MAX_INPUTS || harness_timeouts >= TSAN_TIMEOUT_LIMIT {
            break;
        }
        let path = input.path();
        if !path.is_file() {
            continue;
        }
        replayed += 1;
        // The bhf C driver replays a single input passed as argv[1]. A clean
        // no-race run (exit 0) is a real result. Retry an unsymbolized race report
        // or unexplained abnormal exit a few times. Explicit shadow-mapping
        // initialization failures do not consume that per-input retry budget;
        // they use a larger harness-wide bound because target code never ran.
        let mut run_retries = 0usize;
        let mut never_completed = false;
        loop {
            let run = crate::command_output::output_with_timeout_flagged(
                Command::new(&bin)
                    .arg(&path)
                    .env("TSAN_OPTIONS", "halt_on_error=1:exitcode=86"),
                run_timeout,
            );
            // A killed-for-timeout run and a spawn failure mean the same thing
            // here: this input was never actually examined for races. A timeout
            // arrives as a normal non-success exit, so without the explicit flag
            // it fell into the generic abnormal-exit path, was retried, and then
            // dropped — leaving the harness reported race-free on evidence that
            // does not exist. Retry (a loaded host can push a small TSan binary
            // past 30s), bounded per input AND per harness so a target that truly
            // hangs cannot turn the replay into a multi-hour stall.
            let out = match run {
                Ok((out, false)) => out,
                Ok((_, true)) | Err(_) => {
                    harness_timeouts += 1;
                    if run_retries < TSAN_RUN_RETRIES && harness_timeouts < TSAN_TIMEOUT_LIMIT {
                        run_retries += 1;
                        continue;
                    }
                    never_completed = true;
                    break;
                }
            };
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.contains("data race") {
                consecutive_mapping_failures = 0;
                match classify_race(&stderr, hdir) {
                    RaceAttribution::Target(file, line_no) => {
                        sites.insert((file, line_no));
                        break;
                    }
                    // Retry first: a report can come back unsymbolized once and
                    // resolve on the next run, and a non-target classification can
                    // change when a different thread interleaving is caught.
                    _ if run_retries < TSAN_RUN_RETRIES => {
                        run_retries += 1;
                        continue;
                    }
                    // Readable, and it says the race is in bhf's own scaffolding
                    // rather than the target. Dropping it is the intended
                    // precision/recall trade.
                    RaceAttribution::NonTarget => break,
                    // Unreadable. TSan saw a race and we cannot say where — which
                    // is not the same as "no race". Count it so the run cannot
                    // report a clean result on evidence that says otherwise.
                    RaceAttribution::Unresolved => {
                        unattributed += 1;
                        break;
                    }
                }
            }
            // No race report: a clean exit is a genuine no-race run (stop).
            if out.status.success() {
                consecutive_mapping_failures = 0;
                break;
            }
            if is_tsan_mapping_failure(&stderr) {
                consecutive_mapping_failures += 1;
                if consecutive_mapping_failures >= TSAN_MAPPING_FAILURE_LIMIT {
                    break 'inputs;
                }
                continue;
            }
            consecutive_mapping_failures = 0;
            if run_retries >= TSAN_RUN_RETRIES {
                break;
            }
            run_retries += 1;
        }
        if never_completed {
            unmeasured += 1;
            // The timeout budget is harness-wide. Once consumed, no remaining
            // input can produce a measured replay without exceeding that bound;
            // spending another full timeout on each queue entry turns a 16-run
            // ceiling into MAX_INPUTS * timeout in the worst case.
            if harness_timeouts >= TSAN_TIMEOUT_LIMIT {
                break 'inputs;
            }
        }
    }

    let mut written = 0usize;
    for (file, line) in sites {
        let id = format!("F-TSAN-{:04}", *index);
        *index += 1;
        if write_tsan_finding(work_dir, &id, harness_id, &file, line) {
            written += 1;
        }
    }
    TsanReplay {
        findings: written,
        unmeasured,
        unattributed,
    }
}

fn is_tsan_mapping_failure(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("threadsanitizer: unexpected memory mapping")
        || lower.contains("threadsanitizer: failed to mmap")
        || lower.contains("threadsanitizer check failed")
        || lower.contains("threadsanitizer: check failed")
        || (lower.contains("threadsanitizer") && lower.contains("shadow memory"))
}

/// What a TSan data-race report could be pinned to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RaceAttribution {
    /// A frame in the target's own source. The race's real site.
    Target(String, u64),
    /// Frames resolved to source locations, but every one of them is bhf's driver,
    /// the bundled C runtime, or a system library. The report is readable and says
    /// the race is in the scaffolding rather than the target, so it is dropped on
    /// purpose.
    NonTarget,
    /// No frame carried a source locator at all. The report is unsymbolized, so
    /// nothing can be concluded about WHERE the race is — including whether it is
    /// in the target. Not the same as `NonTarget`, and must not be silent.
    Unresolved,
}

/// Classify a TSan report, separating "we know this race is not in the target"
/// from "we cannot read this report".
fn classify_race(stderr: &str, hdir: &Path) -> RaceAttribution {
    let hdir_str = hdir.to_string_lossy();
    let mut saw_locator = false;
    for line in stderr.lines() {
        let line = line.trim();
        if !line.starts_with('#') {
            continue;
        }
        let Some((file, line_no)) = line.split_whitespace().find_map(parse_locator) else {
            continue;
        };
        saw_locator = true;
        if is_noise_frame(&file, &hdir_str) {
            continue;
        }
        return RaceAttribution::Target(file, line_no);
    }
    if saw_locator {
        RaceAttribution::NonTarget
    } else {
        RaceAttribution::Unresolved
    }
}

/// Parse a `file:line:col` (or `file:line`) locator token, rejecting the
/// `(module+0xoffset)` suffix and bare symbol names. The file part must look like a
/// source path (a `/` or a `.` extension) so a module or plain word is dropped.
fn parse_locator(token: &str) -> Option<(String, u64)> {
    let token = token.trim_matches(|c| c == '(' || c == ')');
    // Try `file:line:col`.
    let mut triple = token.rsplitn(3, ':');
    let _col = triple.next();
    if let (Some(line), Some(file)) = (triple.next(), triple.next()) {
        if let Ok(line_no) = line.parse::<u64>() {
            if looks_like_source(file) {
                return Some((file.to_owned(), line_no));
            }
        }
    }
    // Try `file:line`.
    if let Some((file, line)) = token.rsplit_once(':') {
        if let Ok(line_no) = line.parse::<u64>() {
            if looks_like_source(file) {
                return Some((file.to_owned(), line_no));
            }
        }
    }
    None
}

/// Whether a token looks like a source-file path rather than a module name or a
/// bare symbol — it contains a path separator or a filename extension dot.
fn looks_like_source(file: &str) -> bool {
    file.contains('/') || file.contains('.')
}

/// Whether a frame's file is bhf scaffolding, the C runtime, or a system library
/// rather than the analysed target.
fn is_noise_frame(file: &str, hdir: &str) -> bool {
    file.starts_with(hdir)
        || file.contains("/c_runtime/")
        || file.contains("bhf_decode")
        || file.starts_with("/usr/")
        || file.starts_with("/lib")
        || file.starts_with("/build")
        || file.contains("sysdeps")
        || file.contains("csu/")
        || file == "main.c"
}

/// Persist one TSan finding as a runtime crash (`classification: unhandled`) so the
/// confirmation join + attestation treat it like any other fuzz-found defect.
fn write_tsan_finding(work: &Path, id: &str, harness_id: &str, file: &str, line: u64) -> bool {
    let dir = work.join("findings").join(id);
    if std::fs::create_dir_all(&dir).is_err() {
        return false;
    }
    let name = Path::new(file)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| file.to_owned());
    // One issue per distinct data-race site (rule + file:line), as a stable 64-hex
    // cluster key so the report collapses repeat inputs into one row.
    let cluster_key_full = hex(&Sha256::digest(format!("BHF-556:{file}:{line}").as_bytes()));
    let record = json!({
        "id": id,
        "rule_id": "BHF-556",
        "classification": "unhandled",
        "severity": "high",
        "harness_id": harness_id,
        "cluster_key_full": cluster_key_full,
        "target": { "name": name, "source_path": file, "line": line },
        "exception": {
            "name": "ThreadSanitizer",
            "message": "data race (TSan corpus replay)",
            "stack": [ { "function": "", "file": file, "line": line } ],
        },
        "oracle": { "evidence": [ { "key": "source", "value": format!("{file}:{line}") } ] },
        "analysis": { "engine": "bhf.dynamic.tsan.replay" },
        "actionability": { "cwe": ["CWE-362"], "verdict": "likely_reachable", "confidence": "high" },
    });
    std::fs::write(
        dir.join("finding.json"),
        serde_json::to_vec_pretty(&record).unwrap_or_default(),
    )
    .is_ok()
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn recovers_after_more_than_legacy_mapping_retry_streak() {
        let tmp =
            std::env::temp_dir().join(format!("bhf-tsan-mapping-retry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let work = tmp.join("work");
        let hdir = work.join("harnesses").join("H-C0001");
        let queue = work.join("corpus").join("H-C0001").join("queue");
        std::fs::create_dir_all(&hdir).unwrap();
        std::fs::create_dir_all(&queue).unwrap();
        std::fs::write(queue.join("seed"), b"input").unwrap();
        std::fs::write(hdir.join("Makefile"), "tsan:\n\tchmod +x main_tsan\n").unwrap();
        std::fs::write(
            hdir.join("main_tsan"),
            "#!/bin/sh\n\
             attempts=\"$(dirname \"$0\")/attempts\"\n\
             count=0\n\
             [ ! -f \"$attempts\" ] || count=$(cat \"$attempts\")\n\
             count=$((count + 1))\n\
             printf '%s\\n' \"$count\" > \"$attempts\"\n\
             if [ \"$count\" -le 20 ]; then\n\
               printf '%s\\n' 'FATAL: ThreadSanitizer: unexpected memory mapping 0x1-0x2' >&2\n\
               exit 66\n\
             fi\n\
             printf '%s\\n' 'WARNING: ThreadSanitizer: data race' >&2\n\
             printf '%s\\n' '    #0 worker /project/race.c:12:7 (main_tsan+0x1)' >&2\n\
             exit 86\n",
        )
        .unwrap();

        assert_eq!(run_tsan_replay(&work).findings, 1);
        assert_eq!(
            std::fs::read_to_string(hdir.join("attempts"))
                .unwrap()
                .trim(),
            "21"
        );
        let finding =
            std::fs::read_to_string(work.join("findings/F-TSAN-0000/finding.json")).unwrap();
        assert!(finding.contains("BHF-556"));
        assert!(finding.contains("race.c"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// End-to-end counterpart of `an_unsymbolized_report_is_unresolved_not_non_target`:
    /// proves the counter survives the replay loop, not just the classifier.
    ///
    /// Before this, a TSan run reporting a race with no symbolized frame left
    /// `sites` empty and incremented nothing, so the replay returned an all-zero
    /// result — reporting the harness race-free on the strength of output that
    /// says a race happened.
    #[test]
    #[cfg(unix)]
    fn a_reported_race_with_no_symbolized_frame_is_counted_not_dropped() {
        let tmp = std::env::temp_dir().join(format!(
            "bhf-tsan-unsym-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        let work = tmp.join("work");
        let hdir = work.join("harnesses").join("H-C0001");
        let queue = work.join("corpus").join("H-C0001").join("queue");
        std::fs::create_dir_all(&hdir).unwrap();
        std::fs::create_dir_all(&queue).unwrap();
        std::fs::write(queue.join("seed"), b"input").unwrap();
        std::fs::write(hdir.join("Makefile"), "tsan:\n\tchmod +x main_tsan\n").unwrap();
        // A real TSan race report whose frames carry only `module+0xoffset` — the
        // shape produced when no usable llvm-symbolizer is present.
        std::fs::write(
            hdir.join("main_tsan"),
            "#!/bin/sh\ncat >&2 <<'EOF'\n\
==================\n\
WARNING: ThreadSanitizer: data race (pid=1)\n\
  Write of size 4 at 0x7b04 by thread T1:\n\
    #0 <null> (main_tsan+0x4a1b2)\n\
  Previous read of size 4 at 0x7b04 by main thread:\n\
    #0 <null> (main_tsan+0x2000)\n\
==================\n\
EOF\nexit 86\n",
        )
        .unwrap();

        let result = run_tsan_replay_with(&work, Duration::from_secs(30));
        assert_eq!(
            result.findings, 0,
            "an unsymbolized report cannot yield a LOCATED BHF-556 finding"
        );
        assert_eq!(
            result.unattributed, 1,
            "the reported race must be counted as unattributed, not silently dropped"
        );
        assert_eq!(
            result.unmeasured, 0,
            "the run completed, so this is not an unmeasured input"
        );
        assert_ne!(
            result,
            TsanReplay::default(),
            "an all-zero result is exactly the false-clean this prevents"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    #[cfg(unix)]
    fn an_input_whose_run_never_completes_is_unmeasured_not_clean() {
        // A binary that hangs past the per-run timeout. Before this, the replay
        // dropped the input and returned a bare 0 — indistinguishable from
        // "ran fine, no race", which is a false clean on a target that was never
        // actually examined.
        let tmp = std::env::temp_dir().join(format!(
            "bhf-tsan-timeout-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        let work = tmp.join("work");
        let hdir = work.join("harnesses").join("H-C0001");
        let queue = work.join("corpus").join("H-C0001").join("queue");
        std::fs::create_dir_all(&hdir).unwrap();
        std::fs::create_dir_all(&queue).unwrap();
        std::fs::write(queue.join("seed"), b"input").unwrap();
        std::fs::write(hdir.join("Makefile"), "tsan:\n\tchmod +x main_tsan\n").unwrap();
        // Sleeps past the 30s per-run timeout; every attempt is recorded so the
        // retry bound is observable.
        std::fs::write(
            hdir.join("main_tsan"),
            "#!/bin/sh\n\
             attempts=\"$(dirname \"$0\")/attempts\"\n\
             count=0\n\
             [ ! -f \"$attempts\" ] || count=$(cat \"$attempts\")\n\
             printf '%s\\n' \"$((count + 1))\" > \"$attempts\"\n\
             sleep 5\n",
        )
        .unwrap();

        let result = run_tsan_replay_with(&work, Duration::from_millis(300));
        assert_eq!(result.findings, 0, "a hung run cannot yield a finding");
        assert_eq!(
            result.unmeasured, 1,
            "the input must be reported as unmeasured, not silently dropped"
        );
        // Retried rather than abandoned on the first stall — a loaded host is the
        // common cause — but bounded.
        let attempts: usize = std::fs::read_to_string(hdir.join("attempts"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(
            attempts,
            TSAN_RUN_RETRIES + 1,
            "expected the initial run plus its retry budget"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    #[cfg(unix)]
    fn harness_timeout_budget_stops_the_remaining_corpus() {
        let tmp = std::env::temp_dir().join(format!(
            "bhf-tsan-harness-timeout-budget-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        let work = tmp.join("work");
        let hdir = work.join("harnesses").join("H-C0001");
        let queue = work.join("corpus").join("H-C0001").join("queue");
        std::fs::create_dir_all(&hdir).unwrap();
        std::fs::create_dir_all(&queue).unwrap();
        for index in 0..(TSAN_TIMEOUT_LIMIT + 10) {
            std::fs::write(queue.join(format!("seed-{index:03}")), b"input").unwrap();
        }
        std::fs::write(hdir.join("Makefile"), "tsan:\n\tchmod +x main_tsan\n").unwrap();
        // Every run here is killed for exceeding the timeout, so the attempt
        // must be recorded before the kill lands. The original script forked
        // `dirname` and `cat` to do a read-modify-write inside a 10ms budget,
        // and on a loaded runner the kill won at some point in the middle:
        // CI saw 6 attempts recorded out of 16 actually made.
        //
        // Record with one shell builtin and an append — no forks, nothing to
        // read back — and give the spawn a budget that is not racing process
        // startup. 250ms still times out unmistakably against `sleep 5`, so
        // what the test asserts is unchanged.
        let attempts_path = hdir.join("attempts");
        std::fs::write(
            hdir.join("main_tsan"),
            format!(
                "#!/bin/sh\n\
                 printf 'x\\n' >> '{}'\n\
                 sleep 5\n",
                attempts_path.display()
            ),
        )
        .unwrap();

        let result = run_tsan_replay_with(&work, Duration::from_millis(250));
        let attempts = std::fs::read_to_string(&attempts_path)
            .unwrap()
            .lines()
            .count();
        assert_eq!(attempts, TSAN_TIMEOUT_LIMIT);
        assert_eq!(result.unmeasured, 4);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn classifies_a_target_frame_skipping_scaffolding_and_module_suffix() {
        let hdir = "/w/harnesses/H-C0001";
        // TSan frames carry a trailing `(module+0xoffset)` the parser must skip.
        let report = "\
==================\n\
WARNING: ThreadSanitizer: data race (pid=1)\n\
  Write of size 4 at 0x7b04 by thread T1:\n\
    #0 worker /proj/src/race.c:12:7 (main_tsan+0x4a1b2)\n\
    #1 bhf_run_one /w/harnesses/H-C0001/main.c:44:13 (main_tsan+0x1000)\n\
  Previous read of size 4 at 0x7b04 by main thread:\n\
    #0 main /w/harnesses/H-C0001/main.c:531:5 (main_tsan+0x2000)\n";
        assert_eq!(
            classify_race(report, Path::new(hdir)),
            RaceAttribution::Target("/proj/src/race.c".to_owned(), 12)
        );
    }

    #[test]
    fn drops_report_with_only_system_and_driver_frames() {
        let hdir = "/w/harnesses/H-C0002";
        let report = "\
WARNING: ThreadSanitizer: data race (pid=1)\n\
    #0 memcpy /usr/lib/x86_64-linux-gnu/libc.so (libc.so+0x99)\n\
    #1 bhf_run_one /w/harnesses/H-C0002/main.c:44:13 (main_tsan+0x1000)\n";
        // Readable and classified: the race is in scaffolding, not the target.
        // This drop is the intended precision/recall trade, NOT the silent one.
        assert_eq!(
            classify_race(report, Path::new(hdir)),
            RaceAttribution::NonTarget
        );
    }

    /// The regression this fixes: a report whose frames carry no `file:line` at
    /// all is unreadable, not evidence of a scaffolding race, and must be
    /// distinguishable from the deliberate `NonTarget` drop.
    #[test]
    fn an_unsymbolized_report_is_unresolved_not_non_target() {
        let hdir = "/w/harnesses/H-C0003";
        let report = "\
WARNING: ThreadSanitizer: data race (pid=1)\n\
  Write of size 4 at 0x7b04 by thread T1:\n\
    #0 <null> (main_tsan+0x4a1b2)\n\
    #1 <null> (main_tsan+0x1000)\n\
  Previous read of size 4 at 0x7b04 by main thread:\n\
    #0 <null> (main_tsan+0x2000)\n";
        assert_eq!(
            classify_race(report, Path::new(hdir)),
            RaceAttribution::Unresolved,
            "frames with only module+offset carry no source locator, so nothing \
             can be concluded about where the race is"
        );
    }

    #[test]
    fn locator_rejects_module_offset_and_bare_symbol() {
        assert_eq!(parse_locator("(main_tsan+0x4a1b2)"), None);
        assert_eq!(parse_locator("worker"), None);
        assert_eq!(
            parse_locator("/proj/src/race.c:12:7"),
            Some(("/proj/src/race.c".to_owned(), 12))
        );
        assert_eq!(
            parse_locator("/proj/src/race.c:12"),
            Some(("/proj/src/race.c".to_owned(), 12))
        );
    }

    #[test]
    fn recognizes_only_tsan_runtime_mapping_failures_for_extended_retries() {
        assert!(is_tsan_mapping_failure(
            "FATAL: ThreadSanitizer: unexpected memory mapping 0x123-0x456"
        ));
        assert!(is_tsan_mapping_failure(
            "FATAL: ThreadSanitizer: failed to mmap the shadow memory"
        ));
        assert!(is_tsan_mapping_failure(
            "FATAL: ThreadSanitizer: CHECK failed: sanitizer_allocator_primary64.h"
        ));
        assert!(!is_tsan_mapping_failure(
            "ThreadSanitizer: data race in target.c:12"
        ));
        assert!(!is_tsan_mapping_failure(
            "target process exited with code 2"
        ));
    }
}
