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

#[test]
fn one_system_sink_gives_at_most_one_aggregate_finding() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("skipping: no clang");
        return;
    }
    let work = TestDir::new("collector-aggregate");
    std::fs::write(work.join("tool.c"), TARGET).unwrap();
    let id = "H-TOOL";
    let ok = |cmd: &mut Command| {
        let out = cmd.current_dir(work.path()).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        out
    };
    ok(bhf()
        .args(["generate-harness", "tool.c", "--target", "run_tool"])
        .args(["--output", "generated_harnesses", "--id", id]));
    ok(bhf().args(["build", ".", "--harness", id]));
    let seed = work.join("seed");
    std::fs::write(&seed, b"hello world").unwrap();
    let mut fuzz = bhf();
    support::configure_runtrace_shim(&mut fuzz);
    let out = fuzz
        .current_dir(work.path())
        .args(["fuzz", ".", "--harness", id, "--engine", "builtin"])
        .args(["--runtime-oracles", "on", "--collector", "auto"])
        .arg("--seed-file")
        .arg(&seed)
        .args([
            "--iterations",
            "400",
            "--rng-seed",
            "3",
            "--sandbox",
            "none",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let findings = work.join("results/findings");
    let collector: Vec<serde_json::Value> = std::fs::read_dir(&findings)
        .unwrap_or_else(|e| panic!("no findings ({e}):\n{stderr}"))
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("COL-"))
        .map(|entry| {
            serde_json::from_slice(&std::fs::read(entry.path().join("finding.json")).unwrap())
                .unwrap()
        })
        .collect();
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
