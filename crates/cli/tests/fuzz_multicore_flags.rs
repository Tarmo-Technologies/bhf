// SPDX-License-Identifier: Apache-2.0

//! A multi-worker or sanitizer-matrix `bhf fuzz` dropped `--runtime-oracles`
//! and `--collector` without a word: its workers ran crash-only, so a sink
//! the runtime oracles find in a single-worker run went unreported. The
//! workers now get `--runtime-oracles`, and their oracle findings merge into
//! the campaign's; a flag whose output the merge would not carry back, such
//! as `--collector`, is refused with exit 2.

use std::path::Path;
use std::process::{Command, Output};

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn bhf() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Flags a multi-worker run does not carry out, each with the arguments that
/// set it.
const REFUSED: &[(&str, &[&str])] = &[
    ("--collector", &["--collector", "auto"]),
    ("--collector-window-ms", &["--collector-window-ms", "10"]),
    ("--extension", &["--extension", "ext.toml"]),
    ("--print-final-stats", &["--print-final-stats"]),
];

#[test]
fn a_multicore_run_refuses_each_flag_its_workers_would_ignore() {
    let work = TestDir::new("multicore-refused");
    for multicore in [
        &["--workers", "2"][..],
        &["--sanitizers", "asan", "--sanitizers", "ubsan"][..],
    ] {
        for (flag, set) in REFUSED {
            let out = bhf()
                .current_dir(work.path())
                .args(["fuzz", "bhf_work", "--harness", "h", "--iterations", "1"])
                .args(multicore)
                .args(*set)
                .output()
                .unwrap();
            let all = text(&out);
            assert_eq!(out.status.code(), Some(2), "{multicore:?} {flag}: {all}");
            assert!(
                all.contains(&format!("bhf fuzz: {flag} does not apply to")),
                "{multicore:?} {flag}: {all}"
            );
        }
    }
}

/// Runs a shell command built from the input: the runtime oracles report a
/// fuzz-controlled `system()`.
#[cfg(target_os = "linux")]
const TARGET: &str = "#include <stdio.h>\n#include <stdlib.h>\n#include <stddef.h>\n\
                      int run_tool(const unsigned char *data, size_t len) {\n  \
                      char cmd[96];\n  if (len < 2 || len > 40) return 0;\n  \
                      snprintf(cmd, sizeof cmd, \"echo %.*s > /dev/null\", (int)len, data);\n  \
                      return system(cmd);\n}\n";

#[cfg(target_os = "linux")]
#[test]
fn two_workers_with_runtime_oracles_find_the_planted_sink() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("skipping: no clang");
        return;
    }
    let work = TestDir::new("multicore-oracles");
    std::fs::write(work.join("tool.c"), TARGET).unwrap();
    let id = "H-TOOL";
    let ok = |cmd: &mut Command| {
        let out = cmd.current_dir(work.path()).output().unwrap();
        assert!(out.status.success(), "{}", text(&out));
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
    let out = ok(fuzz
        .args(["fuzz", ".", "--harness", id, "--engine", "builtin"])
        .args(["--workers", "2", "--runtime-oracles", "on"])
        .arg("--seed-file")
        .arg(&seed)
        .args(["--iterations", "200", "--sandbox", "none"]));
    let summary: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|error| panic!("summary ({error}):\n{}", text(&out)));
    assert_eq!(summary["runtime_oracles"], "on", "{summary:#}");
    let merged: Vec<&str> = summary["merged_findings"]
        .as_array()
        .unwrap_or_else(|| panic!("{summary:#}"))
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    let oracle: Vec<&str> = merged
        .iter()
        .copied()
        .filter(|id| finding(work.path(), id)["classification"] == "oracle_hit")
        .collect();
    assert!(
        !oracle.is_empty(),
        "no oracle finding merged: {summary:#}\n{}",
        text(&out)
    );
    // One sink, found by both workers, is one finding.
    let sinks: std::collections::BTreeSet<String> = oracle
        .iter()
        .map(|id| {
            let raw = finding(work.path(), id);
            format!("{}|{}", raw["rule_id"], raw["oracle"]["api"])
        })
        .collect();
    assert_eq!(sinks.len(), oracle.len(), "{oracle:?}: {sinks:?}");
}

#[cfg(target_os = "linux")]
fn finding(work: &Path, id: &str) -> serde_json::Value {
    let path = work.join("results/findings").join(id).join("finding.json");
    serde_json::from_slice(
        &std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display())),
    )
    .unwrap()
}
