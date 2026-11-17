// SPDX-License-Identifier: Apache-2.0

//! Stability calibration in the persistent built-in engine (#232).
//!
//! One harness process runs input after input, so a target that keeps state
//! between calls reaches edges that depend on how many inputs ran before, not
//! on the input. `telemetry_step` calls one of 48 functions picked by a
//! static call counter: every input reaches a "new" edge on its next call.
//! The engine re-runs each entry it would keep, finds the edges that differ
//! between runs of the same input, reports the run's stability with a hint,
//! and leaves out the entries whose only news was such an edge. A target
//! whose coverage follows its input alone is 100% stable.

#![cfg(target_os = "linux")]

use serde_json::Value;
use std::fmt::Write as _;
use std::path::Path;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// The static-counter target: its coverage follows the call count.
fn stateful_target() -> String {
    let mut src = String::from("#include <stddef.h>\nstatic volatile int sink;\n");
    for case in 0..48 {
        writeln!(
            src,
            "__attribute__((noinline)) static void step_{case}(void) {{ sink = {case}; }}"
        )
        .unwrap();
    }
    src.push_str(
        "static unsigned calls;\n\
         int telemetry_step(const unsigned char *data, size_t len) {\n\
         \x20   (void)data;\n\
         \x20   if (len == 0) return 0;\n\
         \x20   switch (calls++ % 48) {\n",
    );
    for case in 0..48 {
        writeln!(src, "    case {case}: step_{case}(); break;").unwrap();
    }
    src.push_str("    }\n    return 1;\n}\n");
    src
}

/// A target whose coverage follows its input alone.
const STATELESS_TARGET: &str = "#include <stddef.h>\n\
    int parse_tag(const unsigned char *data, size_t len) {\n\
    \x20   if (len < 2) return 0;\n\
    \x20   if (data[0] == 'T') {\n\
    \x20       if (data[1] == 'A') return 2;\n\
    \x20       if (data[1] == 'G') return 3;\n\
    \x20       return 1;\n\
    \x20   }\n\
    \x20   return data[0] == 'X' ? 4 : 0;\n\
    }\n";

struct Run {
    summary: Value,
    stderr: String,
}

fn bhf(work: &Path, args: &[&str]) -> std::process::Command {
    let mut cmd = support::bhf_cargo_command();
    cmd.current_dir(work).args(args);
    cmd
}

fn fuzz(tag: &str, source: &str, target: &str) -> Run {
    let work = TestDir::new(&format!("stability-{tag}"));
    std::fs::write(work.join("target.c"), source).unwrap();
    let id = "H-STABLE";
    let generated = bhf(
        work.path(),
        &["generate-harness", "target.c", "--target", target],
    )
    .args(["--output", "generated_harnesses", "--id", id])
    .status()
    .unwrap();
    assert!(generated.success(), "generate-harness failed");
    let built = bhf(work.path(), &["build", ".", "--harness", id])
        .status()
        .unwrap();
    assert!(built.success(), "build failed");
    let out = bhf(work.path(), &["fuzz", ".", "--harness", id])
        .args([
            "--engine",
            "builtin",
            "--iterations",
            "3000",
            "--rng-seed",
            "1",
        ])
        .args(["--seed-input", "AB", "--sandbox", "none", "-q"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success() || out.status.code() == Some(1),
        "bhf fuzz: {stderr}"
    );
    let summary = std::fs::read(work.join(format!("fuzz_runs/{id}-latest.json"))).unwrap();
    Run {
        summary: serde_json::from_slice(&summary).unwrap(),
        stderr,
    }
}

#[test]
fn a_target_that_keeps_state_between_calls_reports_low_stability() {
    if !support::libfuzzer_toolchain_available("stability-stateful") {
        eprintln!("skipping: clang+make toolchain unavailable");
        return;
    }
    let run = fuzz("stateful", &stateful_target(), "telemetry_step");
    let stability = &run.summary["stability"];
    let pct = stability["stability_pct"].as_f64().expect("stability_pct");
    assert!(pct < 90.0, "{stability:#}");
    assert!(
        stability["variable_edges"].as_u64().unwrap() >= 40,
        "{stability:#}"
    );
    let dropped = stability["unstable_entries_dropped"].as_u64().unwrap();
    assert!(dropped > 0, "{stability:#}");
    // The counter's 48 edges used to make 48 corpus entries.
    let corpus_new = run.summary["corpus_new"].as_u64().unwrap();
    assert!(corpus_new < 10, "corpus_new {corpus_new}: {stability:#}");
    assert!(
        run.stderr
            .contains(&format!("bhf fuzz: stability {pct:.1}%")),
        "{}",
        run.stderr
    );
    assert!(run.stderr.contains("--no-fork-server"), "{}", run.stderr);
}

#[test]
fn a_target_whose_coverage_follows_its_input_is_fully_stable() {
    if !support::libfuzzer_toolchain_available("stability-stateless") {
        eprintln!("skipping: clang+make toolchain unavailable");
        return;
    }
    let run = fuzz("stateless", STATELESS_TARGET, "parse_tag");
    let stability = &run.summary["stability"];
    assert_eq!(stability["stability_pct"], 100.0, "{stability:#}");
    assert_eq!(stability["variable_edges"], 0, "{stability:#}");
    assert!(stability["calibrated_entries"].as_u64().unwrap() > 0);
    assert!(!run.stderr.contains("stability"), "{}", run.stderr);
}
