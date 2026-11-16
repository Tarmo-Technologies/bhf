// SPDX-License-Identifier: Apache-2.0

//! `bhf fuzz --collector auto` on Linux reads the campaign's runtrace as one
//! aggregate session. It wrote one high-confidence, clean-assurance COL
//! finding per distinct command a fuzzed `system()` ran, each with a 0-byte
//! input and its own copy of the session; one sink now gives at most one,
//! at medium confidence, with the session written once.
#![cfg(target_os = "linux")]

use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// Runs a shell command built from the input.
const TARGET: &str = "#include <stdio.h>\n#include <stdlib.h>\n#include <stddef.h>\n\
                      int run_tool(const unsigned char *data, size_t len) {\n  \
                      char cmd[96];\n  if (len < 2 || len > 40) return 0;\n  \
                      snprintf(cmd, sizeof cmd, \"echo %.*s > /dev/null\", (int)len, data);\n  \
                      return system(cmd);\n}\n";

fn bhf() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
}

const HARNESS: &str = "H-TOOL";

/// The tool target, built under `work`; returns the seed file to fuzz from.
fn build_tool(work: &TestDir) -> std::path::PathBuf {
    std::fs::write(work.join("tool.c"), TARGET).unwrap();
    for args in [
        &[
            "generate-harness",
            "tool.c",
            "--target",
            "run_tool",
            "--output",
            "generated_harnesses",
            "--id",
            HARNESS,
        ][..],
        &["build", ".", "--harness", HARNESS][..],
    ] {
        let out = bhf().current_dir(work.path()).args(args).output().unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let seed = work.join("seed");
    std::fs::write(&seed, b"hello world").unwrap();
    seed
}

/// `bhf fuzz` of the tool with `flags`, under the runtrace shim.
fn fuzz_tool(work: &TestDir, seed: &std::path::Path, flags: &[&str]) -> std::process::Output {
    let mut fuzz = bhf();
    support::configure_runtrace_shim(&mut fuzz);
    fuzz.current_dir(work.path())
        .args(["fuzz", ".", "--harness", HARNESS, "--engine", "builtin"])
        .args(flags)
        .arg("--seed-file")
        .arg(seed)
        .args([
            "--iterations",
            "400",
            "--rng-seed",
            "3",
            "--sandbox",
            "none",
        ])
        .output()
        .unwrap()
}

/// The `finding.json` of each finding under `work` whose id starts with
/// `prefix`.
fn findings(work: &TestDir, prefix: &str, stderr: &str) -> Vec<serde_json::Value> {
    std::fs::read_dir(work.join("results/findings"))
        .unwrap_or_else(|e| panic!("no findings ({e}):\n{stderr}"))
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(prefix))
        .map(|entry| {
            serde_json::from_slice(&std::fs::read(entry.path().join("finding.json")).unwrap())
                .unwrap()
        })
        .collect()
}

#[test]
fn one_system_sink_gives_at_most_one_aggregate_finding() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("skipping: no clang");
        return;
    }
    let work = TestDir::new("collector-aggregate");
    let seed = build_tool(&work);
    let out = fuzz_tool(
        &work,
        &seed,
        &["--runtime-oracles", "on", "--collector", "auto"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let collector = findings(&work, "COL-", &stderr);
    let process = collector
        .iter()
        .filter(|raw| raw["oracle"]["api"] == "execve" || raw["rule_id"] == "BHF-431")
        .count();
    assert!(process <= 1, "{collector:#?}");
    for raw in &collector {
        assert_ne!(raw["confidence"], "high", "{raw:#}");
        assert_eq!(raw["collector"]["clean_assurance"], false, "{raw:#}");
        assert_eq!(
            raw["paths"]["collector_evidence"]
                .as_str()
                .map(|p| p.starts_with("../../collector/")),
            Some(true)
        );
    }
}

/// `--collector auto` alone used to leave the runtrace shim unarmed on Linux,
/// so the collector observed nothing (`runtime_shim_not_armed`). It arms the
/// shim and observes the sink, and `--runtime-oracles off` still writes no
/// runtime-oracle finding.
#[test]
fn collector_auto_alone_arms_the_runtrace_shim() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("skipping: no clang");
        return;
    }
    let work = TestDir::new("collector-auto-alone");
    let seed = build_tool(&work);
    let out = fuzz_tool(&work, &seed, &["--collector", "auto"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let summary: serde_json::Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("summary ({e}): {stderr}"));
    let collector = &summary["collector"];
    assert_eq!(collector["observed"], true, "{collector:#}");
    assert!(
        !collector["fidelity"]["unsupported_fields"]
            .as_array()
            .is_some_and(|fields| fields.iter().any(|f| f == "runtime_shim_not_armed")),
        "{collector:#}"
    );
    assert!(
        collector["observed_event_classes"]
            .as_array()
            .is_some_and(|classes| classes.iter().any(|c| c == "process_create")),
        "{collector:#}"
    );
    let oracle: Vec<serde_json::Value> = findings(&work, "F-", &stderr)
        .into_iter()
        .filter(|raw| raw["classification"] == "oracle_hit")
        .collect();
    assert!(oracle.is_empty(), "{oracle:#?}");
    assert!(
        !findings(&work, "COL-", &stderr).is_empty(),
        "the collector reports the fuzzed system(): {collector:#}"
    );
}
