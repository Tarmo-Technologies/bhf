// SPDX-License-Identifier: Apache-2.0

//! RealtimeSanitizer corpus replay (#298): an allocation, a lock, a system
//! call or a sleep in a target that must not block, an interrupt handler or an
//! RTOS task entry point (CWE-1322). Such a call stalls the task, misses its
//! deadline or deadlocks on a lock the interrupted code holds, and no other
//! lane sees it: the fuzzed build never crashes on it.
//!
//! `-fsanitize=realtime` needs clang 20 or newer, so `bhf auto --sanitizers
//! realtime` builds a separate binary (`make rtsan`, with that clang as
//! `RTSAN_CC`/`RTSAN_CXX`) for each harness whose target is marked nonblocking
//! (`--nonblocking`, [`crate::generate_harness::set_nonblocking_targets`]) and
//! replays the fuzz pass's corpus through it. The harness runs the target in
//! a real-time context from its call to its return, so a report is the
//! target's, not the harness's decoding. A report at a target source is a
//! BHF-232 finding that `bhf replay` reproduces with the same build.

use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::auto::sanitizer_replay::{ReplayBounds, RunOutcome};

/// Cap the number of corpus inputs replayed per harness.
const MAX_INPUTS: usize = 2000;

/// The oldest clang with RealtimeSanitizer.
const MIN_CLANG: u32 = 20;

/// The compilers a `make rtsan` build uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtsanCompilers {
    pub cc: String,
    pub cxx: String,
}

/// What a RealtimeSanitizer replay of a run found and could not do.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RtsanReplay {
    pub findings: usize,
    /// Harnesses whose target is marked nonblocking.
    pub nonblocking: usize,
    /// Harnesses whose RTSan build failed: their corpus was not replayed.
    pub unbuilt: Vec<String>,
}

/// The major version a `clang --version` banner names.
fn clang_major(banner: &str) -> Option<u32> {
    let after = banner.split("clang version ").nth(1)?;
    after
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

/// The first of `candidates` (`(cc, cxx)` pairs) whose `cc --version` is
/// clang [`MIN_CLANG`] or newer, given how to read a version; otherwise what
/// was found, for the message.
fn pick_rtsan_compilers(
    candidates: &[(&str, &str)],
    version_of: &dyn Fn(&str) -> Option<String>,
) -> Result<RtsanCompilers, String> {
    let mut found = Vec::new();
    for (cc, cxx) in candidates {
        let Some(banner) = version_of(cc) else {
            continue;
        };
        match clang_major(&banner) {
            Some(major) if major >= MIN_CLANG => {
                return Ok(RtsanCompilers {
                    cc: (*cc).to_owned(),
                    cxx: (*cxx).to_owned(),
                })
            }
            Some(major) => found.push(format!("{cc} is clang {major}")),
            None => found.push(format!("{cc} is not clang")),
        }
    }
    Err(if found.is_empty() {
        "no clang is on PATH".to_owned()
    } else {
        found.join(", ")
    })
}

/// The clang 20+ to build the `rtsan` lane with: `clang-22` down to
/// `clang-20`, then `clang` itself.
pub fn rtsan_compilers() -> Result<RtsanCompilers, String> {
    let candidates = [
        ("clang-22", "clang++-22"),
        ("clang-21", "clang++-21"),
        ("clang-20", "clang++-20"),
        ("clang", "clang++"),
    ];
    pick_rtsan_compilers(&candidates, &|cc| {
        let out = Command::new(cc).arg("--version").output().ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    })
}

/// Whether a harness's generated main runs its target in a real-time context.
fn is_nonblocking(hdir: &Path) -> bool {
    ["main.c", "main.cpp"].iter().any(|main| {
        std::fs::read_to_string(hdir.join(main))
            .is_ok_and(|text| text.contains("#define BHF_RTSAN_NONBLOCKING"))
    })
}

/// Replay the corpus of every harness whose target is marked nonblocking
/// through its RTSan build, writing a finding per distinct site.
pub fn run_rtsan_replay(
    work_dir: &Path,
    bounds: &ReplayBounds,
    compilers: &RtsanCompilers,
) -> RtsanReplay {
    let mut replay = RtsanReplay::default();
    let Ok(harnesses) = std::fs::read_dir(work_dir.join("harnesses")) else {
        return replay;
    };
    let mut harnesses: Vec<PathBuf> = harnesses.flatten().map(|entry| entry.path()).collect();
    harnesses.sort();
    let mut index = 0usize;
    for hdir in harnesses {
        let Some(harness_id) = hdir
            .file_name()
            .and_then(|n| n.to_str())
            .map(ToOwned::to_owned)
        else {
            continue;
        };
        if !hdir.join("Makefile").is_file() || !is_nonblocking(&hdir) {
            continue;
        }
        replay.nonblocking += 1;
        match replay_one(work_dir, &hdir, &harness_id, &mut index, bounds, compilers) {
            Some(written) => replay.findings += written,
            None => replay.unbuilt.push(harness_id),
        }
    }
    replay
}

fn replay_one(
    work_dir: &Path,
    hdir: &Path,
    harness_id: &str,
    index: &mut usize,
    bounds: &ReplayBounds,
    compilers: &RtsanCompilers,
) -> Option<usize> {
    let queue = work_dir.join("corpus").join(harness_id).join("queue");
    let mut inputs: Vec<PathBuf> = std::fs::read_dir(&queue)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.is_file())
                .collect()
        })
        .unwrap_or_default();
    if inputs.is_empty() {
        return Some(0);
    }
    inputs.sort();
    let built = crate::command_output::output_with_timeout(
        Command::new("make")
            .arg("rtsan")
            .arg(format!("RTSAN_CC={}", compilers.cc))
            .arg(format!("RTSAN_CXX={}", compilers.cxx))
            .current_dir(hdir),
        Duration::from_secs(600),
    )
    .map(|o| o.status.success())
    .unwrap_or(false);
    let bin = crate::auto::layout::harness_exe(hdir, "main_rtsan");
    if !built || !bin.is_file() {
        return None;
    }
    let hdir_text = hdir.to_string_lossy().into_owned();
    let mut sites: BTreeMap<(String, u64), (PathBuf, String)> = BTreeMap::new();
    let started = Instant::now();
    for path in inputs.into_iter().take(MAX_INPUTS) {
        if started.elapsed() >= bounds.per_harness {
            break;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if bounds.is_known_hang(&bytes) {
            bounds.log_run(
                "rtsan",
                harness_id,
                &path,
                Duration::ZERO,
                RunOutcome::SkippedKnownHang,
            );
            continue;
        }
        let run_started = Instant::now();
        let run = crate::command_output::output_with_timeout_flagged(
            Command::new(&bin)
                .arg(&path)
                .env("RTSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1"),
            bounds.run_timeout,
        );
        let elapsed = run_started.elapsed();
        let out = match run {
            Ok((out, false)) => {
                bounds.log_run("rtsan", harness_id, &path, elapsed, RunOutcome::Completed);
                out
            }
            Ok((_, true)) => {
                bounds.log_run("rtsan", harness_id, &path, elapsed, RunOutcome::TimedOut);
                bounds.note_hang(&bytes);
                continue;
            }
            Err(_) => {
                bounds.log_run("rtsan", harness_id, &path, elapsed, RunOutcome::SpawnFailed);
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
    let queue = crate::fuzz_lineage::ReplayedQueue::open(work_dir, harness_id);
    let mut written = 0usize;
    for ((file, line), (input, report)) in sites {
        let id = format!("F-RTSAN-{:04}", *index);
        *index += 1;
        let shown_by = queue.entry(&input);
        if write_rtsan_finding(
            work_dir, &id, harness_id, &file, line, &input, &report, &bin, &shown_by,
        ) {
            written += 1;
        }
    }
    Some(written)
}

/// The target source and line of a RealtimeSanitizer report: the first frame
/// of its stack that is the target's (frame 0 is the intercepted library
/// call). `None` without a report or such a frame.
fn violation_site(stderr: &str, hdir: &str) -> Option<(String, u64)> {
    let report = corpus::parse_sanitizer_report(stderr)?;
    if report.sanitizer != Some(corpus::Sanitizer::RealtimeSanitizer) {
        return None;
    }
    report
        .stack
        .iter()
        .filter_map(|frame| Some((frame.file.clone()?, u64::from(frame.line?))))
        .find(|(file, _)| !crate::auto::msan::is_noise_frame(file, hdir))
}

#[allow(clippy::too_many_arguments)]
fn write_rtsan_finding(
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
    let cluster_key_full: String = Sha256::digest(format!("BHF-232:{file}:{line}").as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut evidence = vec![json!({ "key": "source", "value": format!("{file}:{line}") })];
    evidence.extend(shown_by.evidence());
    let mut record = json!({
        "id": id,
        "rule_id": report.rule_id,
        "classification": "unhandled",
        "severity": "medium",
        "harness_id": harness_id,
        "cluster_key_full": cluster_key_full,
        "target": { "name": name, "source_path": file, "line": line },
        "exception": {
            "name": format!("RTSAN_{}", report.kind.to_uppercase().replace('-', "_")),
            "sanitizer": "rtsan",
            "message": report.message,
            "stack": report.stack,
        },
        "oracle": { "evidence": evidence },
        "analysis": { "engine": "bhf.dynamic.rtsan.replay" },
        "actionability": { "cwe": ["CWE-1322"], "verdict": "likely_reachable", "confidence": "high" },
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The lane takes the first clang 20 or newer, and without one it says
    /// what it found instead of building.
    #[test]
    fn the_lane_needs_clang_20_and_says_what_it_found() {
        let banner = |version: &str| {
            format!("Ubuntu clang version {version} (0ubuntu1)\nTarget: x86_64-pc-linux-gnu\n")
        };
        let candidates = [("clang-20", "clang++-20"), ("clang", "clang++")];
        let only_18 = |cc: &str| (cc == "clang").then(|| banner("18.1.3"));
        assert_eq!(
            pick_rtsan_compilers(&candidates, &only_18).unwrap_err(),
            "clang is clang 18"
        );
        let both = |cc: &str| Some(banner(if cc == "clang-20" { "20.1.2" } else { "18.1.3" }));
        assert_eq!(
            pick_rtsan_compilers(&candidates, &both).unwrap(),
            RtsanCompilers {
                cc: "clang-20".to_owned(),
                cxx: "clang++-20".to_owned()
            }
        );
        assert_eq!(
            pick_rtsan_compilers(&candidates, &|_| None).unwrap_err(),
            "no clang is on PATH"
        );
        assert_eq!(clang_major("Apple clang version 21.0.0"), Some(21));
    }

    const REPORT: &str = "\
==31==ERROR: RealtimeSanitizer: unsafe-library-call\n\
Intercepted call to real-time unsafe function `malloc` in real-time context!\n\
    #0 0x5e4c in malloc (/w/harnesses/H-1/main_rtsan+0xc83c)\n\
    #1 0x5e4d in uart_task /src/rtos/uart.c:42:22\n\
    #2 0x5e4e in bhf_run_one /w/harnesses/H-1/main.c:90:5\n\
\n\
SUMMARY: RealtimeSanitizer: unsafe-library-call (/w/main_rtsan+0xc83c) in malloc\n";

    #[test]
    fn a_realtime_report_is_placed_at_the_targets_call() {
        assert_eq!(
            violation_site(REPORT, "/w/harnesses/H-1"),
            Some(("/src/rtos/uart.c".to_owned(), 42))
        );
        let report = corpus::parse_sanitizer_report(REPORT).unwrap();
        assert_eq!(report.rule_id, "BHF-232");
        assert_eq!(report.kind, "unsafe-library-call");
        assert!(report.message.contains("`malloc`"), "{}", report.message);
        assert_eq!(violation_site("no report here", "/w"), None);
    }
}
