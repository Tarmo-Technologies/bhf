// SPDX-License-Identifier: Apache-2.0

//! `bhf auto --workers-per-target N` (#332): each builtin pass of a target
//! runs on N workers that share their corpus as they run, and the pass's
//! corpus and findings are the workers' merged. Needs clang and make.

use std::path::Path;
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn on_path(bin: &str) -> bool {
    let present = std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false);
    support::require_tool(present, bin)
}

/// A record parser with a few branches on its leading bytes, and an overflow
/// behind a three-byte tag.
const RECORD: &str = "#include <stddef.h>
#include <stdint.h>
#include <string.h>

int parse_record(const uint8_t *data, size_t size) {
    int kind = 0;
    if (size < 4) {
        return 0;
    }
    switch (data[0]) {
    case 'a': kind = 1; break;
    case 'b': kind = 2; break;
    case 'c': kind = 3; break;
    case 'd': kind = 4; break;
    default: break;
    }
    if (data[1] == 'W' && data[2] == 'G' && data[3] == 'T') {
        char copy[4];
        memcpy(copy, data, size);
        return copy[3] + kind;
    }
    return kind;
}
";

fn json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(
        &std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display())),
    )
    .unwrap()
}

#[test]
fn two_workers_per_target_fuzz_each_pass_and_merge_their_corpus() {
    if !on_path("clang") || !on_path("make") {
        eprintln!("skipping: needs clang and make");
        return;
    }
    let root = TestDir::new("workers-per-target");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("record.c"), RECORD).unwrap();
    let work = root.join("work");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        // One pass, so both workers start from the bootstrap seeds and each
        // finds entries the other has not.
        .args(["--per-target-time", "8", "--jobs", "1", "--single-pass"])
        .args(["--workers-per-target", "2"])
        .arg("--no-discovery-cache")
        // Sync often enough for the workers to trade entries in a short pass.
        .env("BHF_SYNC_INTERVAL_MS", "300")
        .env_remove("BHF_SYMCC")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("each target's builtin passes run on 2 workers"),
        "{stderr}"
    );
    let run = json(&work.join("auto/run.json"));
    let target = &run["targets"][0];
    let id = target["harness_id"].as_str().unwrap();
    let passes = target["outcome"]["passes"].as_array().unwrap();
    assert_eq!(passes.len(), 1, "{target:#}");

    // The pass's run summary: two workers that both fuzzed, and the pass's
    // executions are theirs together.
    let pass = json(&work.join(format!("fuzz_runs/{id}-latest.json")));
    let workers = &pass["workers"];
    assert_eq!(workers["workers"], 2, "{pass:#}");
    assert_eq!(workers["completed"], 2, "{pass:#}");
    let per_worker = workers["per_worker"].as_array().unwrap();
    assert_eq!(per_worker.len(), 2);
    let mut executions = 0;
    for worker in per_worker {
        assert!(worker["executions"].as_u64().unwrap() > 0, "{pass:#}");
        assert!(worker["queue_entries"].as_u64().unwrap() > 0, "{pass:#}");
        executions += worker["executions"].as_u64().unwrap();
    }
    assert_eq!(pass["executions"].as_u64(), Some(executions));
    assert_eq!(
        passes[0]["executions"].as_u64(),
        Some(executions),
        "{target:#}"
    );
    // They traded entries as they ran.
    let imports: u64 = per_worker
        .iter()
        .map(|worker| worker["peer_imports"].as_u64().unwrap())
        .sum();
    assert!(imports > 0, "no worker ran a peer's entry: {pass:#}");

    // The target's corpus is the workers' merged: it holds what each kept.
    let queue = std::fs::read_dir(work.join("corpus").join(id).join("queue"))
        .unwrap()
        .count() as u64;
    assert_eq!(workers["queue_entries"].as_u64(), Some(queue), "{pass:#}");
    for worker in per_worker {
        assert!(
            queue >= worker["queue_entries"].as_u64().unwrap(),
            "{pass:#}"
        );
    }
    let campaign = json(&work.join(format!("fuzz_campaigns/{id}-latest.json")));
    assert_eq!(campaign["workers_started"], 2, "{campaign:#}");
    assert_eq!(campaign["workers_completed"], 2, "{campaign:#}");

    // A worker's finding is the target's, and the workers' trees are gone.
    let findings: Vec<serde_json::Value> = std::fs::read_dir(work.join("results/findings"))
        .unwrap()
        .flatten()
        .filter_map(|entry| std::fs::read(entry.path().join("finding.json")).ok())
        .filter_map(|bytes| serde_json::from_slice(&bytes).ok())
        .collect();
    assert!(
        findings
            .iter()
            .any(|finding| finding.to_string().contains("stack-buffer-overflow")),
        "{findings:#?}\n{stderr}"
    );
    let leftovers: Vec<String> = std::fs::read_dir(&work)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("worker-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

/// `--workers-per-target 0` is refused by name.
#[test]
fn zero_workers_per_target_is_refused() {
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", ".", "--workers-per-target", "0"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--workers-per-target"), "{stderr}");
}

/// A parser that spins on a record starting with `H`.
const SPINNER: &str = "#include <stddef.h>
#include <stdint.h>

int parse_record(const uint8_t *data, size_t size) {
    volatile int spin = 1;
    if (size > 0 && data[0] == 'H') {
        while (spin) {
        }
    }
    return size > 1 ? data[1] : 0;
}
";

/// A pass on two workers reports their hangs as a pass on one does: its run
/// summary's `hangs` block holds the workers' counts summed, and run.md says
/// how many were killed and how many hung again.
#[test]
fn a_pass_on_two_workers_reports_their_hangs() {
    if !on_path("clang") || !on_path("make") {
        eprintln!("skipping: needs clang and make");
        return;
    }
    let root = TestDir::new("workers-per-target-hangs");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("spin.c"), SPINNER).unwrap();
    let work = root.join("work");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        .args(["--per-target-time", "8", "--jobs", "1", "--single-pass"])
        .args(["--timeout", "100ms", "--workers-per-target", "2"])
        .arg("--no-discovery-cache")
        .env_remove("BHF_SYMCC")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");
    let run = json(&work.join("auto/run.json"));
    let id = run["targets"][0]["harness_id"].as_str().unwrap().to_owned();
    let pass = json(&work.join(format!("fuzz_runs/{id}-latest.json")));
    // A worker that overruns the pass's grace while it re-runs hangs is
    // killed and reports nothing; the pass holds what the others reported.
    assert!(
        pass["workers"]["completed"].as_u64() >= Some(1),
        "{pass:#}\n{stderr}"
    );
    let hangs = &pass["hangs"];
    assert_eq!(hangs["timeout_ms"], 100, "{pass:#}\n{stderr}");
    let observed = hangs["observed"].as_u64().unwrap();
    let confirmed = hangs["confirmed"].as_u64().unwrap();
    assert!(observed > 0 && confirmed > 0, "{pass:#}");
    assert_eq!(
        observed,
        confirmed + hangs["cleared"].as_u64().unwrap() + hangs["not_rerun"].as_u64().unwrap(),
        "{pass:#}"
    );
    let report = std::fs::read_to_string(work.join("auto/run.md")).unwrap();
    assert!(
        report.contains(&format!("hangs={confirmed}/{observed}")),
        "{report}"
    );
    assert!(report.contains("Hangs:"), "{report}");
}
