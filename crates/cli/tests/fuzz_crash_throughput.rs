// SPDX-License-Identifier: Apache-2.0

//! The builtin loop does not symbolize the crashes it sees (#230). Every
//! crashing execution was symbolized and aborted through the kernel's core
//! pattern (most of a second each), so a target where most inputs hit a bug
//! already reported ran at a few executions a second. A crash whose
//! signature was reported is now only counted; a new one is re-run in a
//! fresh process, symbolized, and every finding keeps its symbolized stack.

#![cfg(unix)]

use std::fs;
use std::path::Path;
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn clang_runs() -> bool {
    let present = {
        Command::new("clang")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    };
    support::require_tool(present, "clang")
}

/// Two heap overflows behind one-byte gates: nearly every mutation of either
/// seed crashes in the bug its seed reaches. The buffers escape through
/// `kept`, so the compiler keeps the stores.
const TWO_BUGS: &str = "#include <stddef.h>\n#include <stdint.h>\n\
     #include <stdlib.h>\n#include <string.h>\n\
     char *volatile kept;\n\
     __attribute__((noinline)) void copy_record(const uint8_t *d, size_t n) {\n\
         char *b = malloc(4);\n\
         memcpy(b, d, n);\n\
         kept = b;\n\
         free(b);\n\
     }\n\
     __attribute__((noinline)) void store_tail(const uint8_t *d, size_t n) {\n\
         char *b = malloc(4);\n\
         b[n] = d[0];\n\
         kept = b;\n\
         free(b);\n\
     }\n\
     int bhf_run_one(const uint8_t *data, size_t size) {\n\
         if (size > 4 && data[0] == 'A') copy_record(data, size);\n\
         else if (size > 4 && data[0] == 'B') store_tail(data, size);\n\
         return 0;\n\
     }\n";

fn build_harness(work: &Path, id: &str) {
    let dir = work.join("harnesses").join(id);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("target.c"), TWO_BUGS).unwrap();
    let driver = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime/bhf_driver.c");
    let built = Command::new("clang")
        .current_dir(&dir)
        .args([
            "-O1",
            "-g",
            "-fsanitize=address",
            "-fsanitize-coverage=trace-pc-guard,trace-cmp",
            "-o",
            "main",
            "target.c",
        ])
        .arg(&driver)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
}

/// `bhf fuzz` from both seeds for `time`; its run summary.
fn fuzz(work: &Path, id: &str, time: &str, symbolize_in_loop: bool) -> serde_json::Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bhf"));
    command
        .arg("fuzz")
        .arg(work)
        .args(["--harness", id, "--time", time, "--quiet"])
        .args([
            "--seed-input",
            "AAAAAAAAAAAA",
            "--seed-input",
            "BBBBBBBBBBBB",
        ]);
    if symbolize_in_loop {
        command.env("BHF_IN_LOOP_SYMBOLIZE", "1");
    } else {
        command.env_remove("BHF_IN_LOOP_SYMBOLIZE");
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn findings(work: &Path) -> Vec<serde_json::Value> {
    fs::read_dir(work.join("results/findings"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            serde_json::from_slice(&fs::read(entry.path().join("finding.json")).ok()?).ok()
        })
        .collect()
}

fn duplicate_hits(summary: &serde_json::Value) -> u64 {
    summary["duplicate_sanitizer_hits"]
        .as_object()
        .map_or(0, |hits| hits.values().filter_map(|n| n.as_u64()).sum())
}

#[test]
fn crashes_of_reported_bugs_are_counted_and_each_finding_has_a_symbolized_stack() {
    if !clang_runs() {
        eprintln!("skipping: clang unavailable");
        return;
    }
    let root = TestDir::new("crash-throughput");
    let work = root.join("work");
    build_harness(&work, "H-TWO");
    let summary = fuzz(&work, "H-TWO", "5s", false);

    let found = findings(&work);
    let mut sinks: Vec<String> = found
        .iter()
        .map(|finding| {
            // Symbolized: the target's frame names its function, file and line.
            let top = finding["exception"]["stack"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|frame| {
                    frame["file"]
                        .as_str()
                        .is_some_and(|file| file.ends_with("target.c"))
                })
                .unwrap_or_else(|| panic!("no symbolized target frame: {finding:#}"));
            assert!(
                top["line"].as_u64().is_some_and(|line| line > 0),
                "{finding:#}"
            );
            top["function"].as_str().unwrap_or_default().to_owned()
        })
        .collect();
    sinks.sort();
    assert_eq!(sinks, ["copy_record", "store_tail"], "{summary:#}");
    // The later crashes of both were counted against them, not re-reported.
    assert!(duplicate_hits(&summary) >= 10, "{summary:#}");
}

/// Executions a second on the crash-dense target with the loop's
/// symbolization off are at least three times the rate with it on.
#[test]
#[ignore = "benchmark: two 15s campaigns; run with --ignored (the nightly does)"]
fn not_symbolizing_in_the_loop_triples_a_crash_dense_targets_throughput() {
    if !clang_runs() {
        eprintln!("skipping: clang unavailable");
        return;
    }
    let root = TestDir::new("crash-throughput-bench");
    let rate = |symbolize: bool| {
        let work = root.join(if symbolize { "on" } else { "off" });
        build_harness(&work, "H-TWO");
        fuzz(&work, "H-TWO", "15s", symbolize)["executions_per_sec"]
            .as_f64()
            .unwrap()
    };
    let symbolized = rate(true);
    let unsymbolized = rate(false);
    assert!(
        unsymbolized >= 3.0 * symbolized,
        "{unsymbolized:.1} exec/s without in-loop symbolization, {symbolized:.1} with it"
    );
}
