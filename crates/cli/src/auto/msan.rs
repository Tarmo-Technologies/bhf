// SPDX-License-Identifier: Apache-2.0

//! MemorySanitizer corpus replay — uninitialized-memory reads (CWE-457/908, BHF-212)
//! that ASan/UBSan do not detect.
//!
//! MSan cannot be combined with ASan, so instead of a second fuzz loop bhf
//! builds a SEPARATE MSan-instrumented binary (`make msan`, C only — the C++ Makefile
//! has no `msan` target, and C++ MSan needs an instrumented libc++) and replays the
//! ASan pass's saved corpus through it. An input that drove a read of uninitialized
//! memory becomes a BHF-212 runtime finding — so it flows through the same
//! confirmation/attestation path as any fuzz crash.
//!
//! Best-effort and FP-gated: only a report whose FAULTING frame lands in a target
//! source (not the bhf driver, the C runtime, or a system library) is emitted,
//! so noise from uninstrumented libc paths is dropped. Missing `make`/corpus, a
//! failed MSan build, or a C++ harness all skip cleanly.

use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::auto::sanitizer_replay::{ReplayBounds, RunOutcome};

/// Cap the number of corpus inputs replayed per harness so a huge queue can't
/// stall the run; the coverage-diverse queue front is what matters for MSan.
const MAX_INPUTS: usize = 2000;

/// Replay every C harness's corpus through its MSan build, writing a BHF-212 finding
/// per distinct uninitialized-read site, within `bounds`. Returns the number of
/// findings written.
pub fn run_msan_replay(work_dir: &Path, bounds: &ReplayBounds) -> usize {
    let Ok(harnesses) = std::fs::read_dir(work_dir.join("harnesses")) else {
        return 0;
    };
    let mut written = 0usize;
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
        written += replay_one(work_dir, &hdir, &harness_id, &mut index, bounds);
    }
    written
}

fn replay_one(
    work_dir: &Path,
    hdir: &Path,
    harness_id: &str,
    index: &mut usize,
    bounds: &ReplayBounds,
) -> usize {
    if !hdir.join("Makefile").is_file() {
        return 0;
    }
    // Build the MSan variant. C++ harnesses have no `msan` target -> make fails ->
    // skip. A genuine MSan build error (missing instrumented dep) also skips.
    let built = crate::command_output::output_with_timeout(
        Command::new("make").arg("msan").current_dir(hdir),
        Duration::from_secs(600),
    )
    .map(|o| o.status.success())
    .unwrap_or(false);
    let bin = crate::auto::layout::harness_exe(hdir, "main_msan");
    if !built || !bin.is_file() {
        return 0;
    }

    let queue = work_dir.join("corpus").join(harness_id).join("queue");
    let Ok(inputs) = std::fs::read_dir(&queue) else {
        return 0;
    };
    // Each site, with the first queue entry that showed it.
    let mut sites: BTreeMap<(String, u64), (PathBuf, String)> = BTreeMap::new();
    let mut replayed = 0usize;
    let started = Instant::now();
    for input in inputs.flatten() {
        if replayed >= MAX_INPUTS || started.elapsed() >= bounds.per_harness {
            break;
        }
        let path = input.path();
        if !path.is_file() {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        replayed += 1;
        if bounds.is_known_hang(&bytes) {
            bounds.log_run(
                "msan",
                harness_id,
                &path,
                Duration::ZERO,
                RunOutcome::SkippedKnownHang,
            );
            continue;
        }
        // The bhf C driver replays a single input passed as argv[1]. One run:
        // an input past the run timeout hangs under MSan, and a hang is no
        // uninitialized read.
        let run_started = Instant::now();
        let run = crate::command_output::output_with_timeout_flagged(
            Command::new(&bin)
                .arg(&path)
                .env("MSAN_OPTIONS", "halt_on_error=1:exitcode=86:print_stats=0"),
            bounds.run_timeout,
        );
        let elapsed = run_started.elapsed();
        let out = match run {
            Ok((out, false)) => {
                bounds.log_run("msan", harness_id, &path, elapsed, RunOutcome::Completed);
                out
            }
            Ok((_, true)) => {
                bounds.log_run("msan", harness_id, &path, elapsed, RunOutcome::TimedOut);
                bounds.note_hang(&bytes);
                continue;
            }
            Err(_) => {
                bounds.log_run("msan", harness_id, &path, elapsed, RunOutcome::SpawnFailed);
                continue;
            }
        };
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !stderr.contains("MemorySanitizer") {
            continue;
        }
        if let Some(site) = first_target_frame(&stderr, hdir) {
            sites
                .entry(site)
                .or_insert_with(|| (path, stderr.into_owned()));
        }
    }

    let mut written = 0usize;
    if sites.is_empty() {
        return written;
    }
    let queue = crate::fuzz_lineage::ReplayedQueue::open(work_dir, harness_id);
    for ((file, line), (input, stderr)) in sites {
        let id = format!("F-MSAN-{:04}", *index);
        *index += 1;
        let shown_by = queue.entry(&input);
        let evidence = MsanEvidence {
            input: Some(input),
            report: stderr,
            binary: Some(bin.clone()),
        };
        if write_msan_finding(work_dir, &id, harness_id, &file, line, &shown_by, &evidence) {
            written += 1;
        }
    }
    written
}

/// The first stack frame in an MSan report that lands in a TARGET source — not the
/// bhf driver (`main.c` under the harness dir), the bundled C runtime, or a
/// system library. That frame is the uninitialized read's real site; if there is
/// none (the read is purely inside uninstrumented libc), the report is dropped.
fn first_target_frame(stderr: &str, hdir: &Path) -> Option<(String, u64)> {
    let hdir_str = hdir.to_string_lossy();
    for line in stderr.lines() {
        let line = line.trim();
        if !line.starts_with('#') {
            continue;
        }
        // `#N 0x... in <symbol> <file>:<line>:<col>` — take the last whitespace token
        // as the `file:line:col` locator.
        let Some(locator) = line.split_whitespace().last() else {
            continue;
        };
        let mut parts = locator.rsplitn(3, ':');
        let _col = parts.next();
        let Some(line_no) = parts.next().and_then(|l| l.parse::<u64>().ok()) else {
            continue;
        };
        let Some(file) = parts.next() else {
            continue;
        };
        if is_noise_frame(file, &hdir_str) {
            continue;
        }
        return Some((file.to_owned(), line_no));
    }
    None
}

/// Whether a frame's file is bhf scaffolding, the C runtime, or a system
/// library rather than the analysed target.
pub(crate) fn is_noise_frame(file: &str, hdir: &str) -> bool {
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

/// Persist one MSan finding as a runtime crash (`classification: unhandled`) so the
/// confirmation join + attestation treat it like any other fuzz-found defect.
/// What an MSan replay saw for one uninitialized-read site.
#[derive(Default)]
struct MsanEvidence {
    /// The corpus entry that showed the read, saved as the finding's testcase.
    input: Option<PathBuf>,
    /// MemorySanitizer's report, saved as `sanitizer.log`.
    report: String,
    /// The MSan build that ran it, which replay runs again.
    binary: Option<PathBuf>,
}

fn write_msan_finding(
    work: &Path,
    id: &str,
    harness_id: &str,
    file: &str,
    line: u64,
    shown_by: &crate::fuzz_lineage::ReplayedEntry,
    seen: &MsanEvidence,
) -> bool {
    let dir = corpus::layout::finding_dir(work, id);
    if std::fs::create_dir_all(&dir).is_err() {
        return false;
    }
    // The report as replay will parse it again, and its frame at the site.
    let report = corpus::parse_sanitizer_report(&seen.report)
        .filter(|report| report.sanitizer == Some(corpus::Sanitizer::MemorySanitizer));
    let function = report
        .as_ref()
        .and_then(|report| {
            report.stack.iter().find(|frame| {
                frame.file.as_deref() == Some(file) && frame.line.map(u64::from) == Some(line)
            })
        })
        .map(|frame| frame.function.clone())
        .filter(|function| !function.is_empty());
    let name = function.clone().unwrap_or_else(|| {
        Path::new(file)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| file.to_owned())
    });
    // One issue per distinct uninitialized-read site (rule + file:line), as a stable
    // 64-hex cluster key so the report collapses repeat inputs into one row.
    let cluster_key_full = hex(&Sha256::digest(format!("BHF-212:{file}:{line}").as_bytes()));
    let mut evidence = vec![json!({ "key": "source", "value": format!("{file}:{line}") })];
    evidence.extend(shown_by.evidence());
    let mut record = json!({
        "id": id,
        "rule_id": "BHF-212",
        "classification": "unhandled",
        "severity": "high",
        "harness_id": harness_id,
        "cluster_key_full": cluster_key_full,
        "target": { "name": name, "source_path": file, "line": line },
        "exception": {
            "name": "MemorySanitizer",
            "message": "use of uninitialized memory (MSan corpus replay)",
            "stack": [ { "function": function.clone().unwrap_or_default(), "file": file, "line": line } ],
        },
        "oracle": { "evidence": evidence },
        "analysis": { "engine": "bhf.dynamic.msan.replay" },
        "actionability": { "cwe": ["CWE-457"], "verdict": "likely_reachable", "confidence": "high" },
    });
    // The exception as the emitter writes a sanitizer crash, so `bhf replay`
    // compares the MSan build's report with it.
    if let Some(report) = &report {
        record["exception"] = json!({
            "name": format!("MSAN_{}", report.kind.to_uppercase().replace('-', "_")),
            "sanitizer": "msan",
            "message": report.message,
            "stack": report.stack,
        });
    }
    let mut paths = serde_json::Map::new();
    paths.insert("finding".to_owned(), json!("finding.json"));
    // The corpus entry that showed the read is the finding's testcase.
    if let Some(input) = &seen.input {
        if std::fs::copy(input, dir.join("testcase.bin")).is_ok() {
            paths.insert("testcase".to_owned(), json!("testcase.bin"));
        }
    }
    if !seen.report.is_empty()
        && corpus::finding::write_sanitizer_log(&dir, seen.report.as_bytes()).is_ok()
    {
        paths.insert("sanitizer_log".to_owned(), json!("sanitizer.log"));
    }
    record["paths"] = serde_json::Value::Object(paths);
    // Replay runs the MSan build, not the ASan `main`.
    if let Some(binary) = &seen.binary {
        record["fixture_path"] = json!(corpus::finding::stored_fixture_path(
            work,
            &binary.display().to_string()
        ));
        if let Some(format) = crate::fuzz::harness_format_for(binary, work, harness_id) {
            record["harness_format_version"] = json!(format.version);
        }
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
    fn parses_first_target_frame_skipping_scaffolding() {
        let hdir = "/w/harnesses/H-C0001";
        let report = "\
==1==WARNING: MemorySanitizer: use-of-uninitialized-value\n\
    #0 0x55 in classify /proj/src/uninit.c:8:5\n\
    #1 0x55 in bhf_run_one /w/harnesses/H-C0001/main.c:44:13\n\
    #2 0x55 in main /w/harnesses/H-C0001/main.c:531:5\n\
    #3 0x7f in __libc_start_main csu/../csu/libc-start.c:360:3\n";
        assert_eq!(
            first_target_frame(report, Path::new(hdir)),
            Some(("/proj/src/uninit.c".to_owned(), 8))
        );
    }

    #[test]
    fn drops_report_with_only_system_and_driver_frames() {
        let hdir = "/w/harnesses/H-C0002";
        let report = "\
==1==WARNING: MemorySanitizer: use-of-uninitialized-value\n\
    #0 0x55 in memcpy /usr/lib/x86_64-linux-gnu/libc.so\n\
    #1 0x55 in bhf_run_one /w/harnesses/H-C0002/main.c:44:13\n";
        assert_eq!(first_target_frame(report, Path::new(hdir)), None);
    }

    /// An MSan finding carries the lineage of the queue entry that showed the
    /// read, from that entry's record beside the queue, names the entry, and
    /// saves it as its testcase with MSan's report and the MSan build.
    #[test]
    #[cfg(unix)]
    fn an_msan_finding_carries_the_lineage_of_the_queue_entry_that_showed_it() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path();
        let hdir = work.join("harnesses").join("H-C0001");
        let queue = work.join("corpus").join("H-C0001").join("queue");
        std::fs::create_dir_all(&hdir).unwrap();
        std::fs::create_dir_all(&queue).unwrap();
        std::fs::write(queue.join("child.bin"), b"CHILD").unwrap();
        std::fs::write(queue.join("other.bin"), b"OTHER").unwrap();
        crate::fuzz_lineage::record_child_of_user_seed(
            work,
            "H-C0001",
            b"SEED",
            b"CHILD",
            "/seeds/seed.bin",
        );
        std::fs::write(hdir.join("Makefile"), "msan:\n\tchmod +x main_msan\n").unwrap();
        let bin = hdir.join("main_msan");
        std::fs::write(
            &bin,
            "#!/bin/sh\n\
             if grep -q CHILD \"$1\"; then\n\
               printf '%s\\n' '==1==WARNING: MemorySanitizer: use-of-uninitialized-value' \
                 '    #0 0x55 in classify /proj/src/uninit.c:8:5' >&2\n\
               exit 86\n\
             fi\n\
             exit 0\n",
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(
            run_msan_replay(work, &ReplayBounds::unbounded(Duration::from_secs(30))),
            1
        );
        let record: serde_json::Value = serde_json::from_slice(
            &std::fs::read(work.join("results/findings/F-MSAN-0000/finding.json")).unwrap(),
        )
        .unwrap();
        let lineage = &record["lineage"];
        assert_eq!(lineage["origin"], "user_seed", "{record}");
        assert_eq!(lineage["root_path"], "/seeds/seed.bin");
        assert_eq!(lineage["depth"], 1);
        let child = hex(&Sha256::digest(b"CHILD"));
        assert_eq!(lineage["parent_sha256"], hex(&Sha256::digest(b"SEED")));
        assert!(
            record["oracle"]["evidence"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["key"] == "input_sha256" && e["value"] == child.as_str()),
            "{record}"
        );
        let finding = work.join("results/findings/F-MSAN-0000");
        assert_eq!(
            std::fs::read(finding.join("testcase.bin")).unwrap(),
            b"CHILD"
        );
        assert!(finding.join("sanitizer.log").is_file());
        assert_eq!(
            record["fixture_path"], "harnesses/H-C0001/main_msan",
            "{record}"
        );
        assert_eq!(
            record["exception"]["stack"][0]["function"], "classify",
            "{record}"
        );
    }

    /// A queue entry that cannot be read back names no sha256: the finding
    /// carries no `input_sha256` evidence, and its lineage says why.
    #[test]
    fn a_finding_whose_entry_cannot_be_read_back_names_no_input_sha256() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path();
        let queue = crate::fuzz_lineage::ReplayedQueue::open(work, "H-C0001");
        let shown_by = queue.entry(&work.join("corpus/H-C0001/queue/gone.bin"));
        assert!(write_msan_finding(
            work,
            "F-MSAN-0009",
            "H-C0001",
            "/proj/src/site.c",
            8,
            &shown_by,
            &MsanEvidence::default()
        ));
        let record: serde_json::Value = serde_json::from_slice(
            &std::fs::read(work.join("results/findings/F-MSAN-0009/finding.json")).unwrap(),
        )
        .unwrap();
        let evidence = record["oracle"]["evidence"].as_array().unwrap();
        assert_eq!(
            evidence,
            &vec![serde_json::json!({"key": "source", "value": "/proj/src/site.c:8"})],
            "{record}"
        );
        assert_eq!(record["lineage"]["origin"], "unknown", "{record}");
        assert!(record["lineage"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("gone.bin")));
    }
}
