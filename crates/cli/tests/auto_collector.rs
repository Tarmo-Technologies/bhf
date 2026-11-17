// SPDX-License-Identifier: Apache-2.0

//! `bhf auto --collector` (#278): after each fuzzed target's passes, its
//! retained inputs are replayed under the runtime-event collector, and
//! run.json records the observation on the target. `bhf auto` had no
//! `--collector`, and its fuzz runs left the collector off.

#![cfg(target_os = "linux")]

use serde_json::Value;
use std::path::Path;
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

fn clang_present() -> bool {
    let present = Command::new("clang")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success());
    support::require_tool(present, "clang")
}

/// `bhf auto` of the tool with `collector`; returns run.json.
fn auto(root: &Path, collector: &str) -> Value {
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("tool.c"), TARGET).unwrap();
    let work = root.join("work");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bhf"));
    support::configure_runtrace_shim(&mut cmd);
    let out = cmd
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        .args(["--per-target-time", "6", "--jobs", "1"])
        .args(["--collector", collector])
        .output()
        .unwrap();
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{log}");
    assert!(log.contains("built+fuzzed"), "{log}");
    serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap()
}

fn fuzzed(run: &Value) -> Vec<&Value> {
    run["targets"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| t["outcome"]["outcome"] == "built_and_fuzzed")
        .collect()
}

/// On Linux `--collector auto` replays each target's retained inputs under
/// the runtrace shim: every fuzzed target has one observation of real
/// testcases. `bhf auto`'s runtime oracles already report the fuzzed
/// `system()` with its input, and the collector does not report it again.
#[test]
fn each_fuzzed_target_gets_one_collector_observation_of_its_testcases() {
    if !clang_present() {
        eprintln!("skipping: no clang");
        return;
    }
    let root = TestDir::new("auto-collector");
    let run = auto(root.path(), "auto");
    let targets = fuzzed(&run);
    assert!(!targets.is_empty(), "{run:#}");
    for target in &targets {
        let collector = &target["collector"];
        if collector["active"] != true {
            eprintln!("skipping: no runtrace shim");
            return;
        }
        assert_eq!(collector["observation"], "replay", "{collector:#}");
        let replays = collector["replays"].as_array().expect("replays");
        assert!(!replays.is_empty(), "{collector:#}");
        for replay in replays {
            let testcase = replay["testcase"].as_str().unwrap();
            assert!(
                testcase.starts_with("corpus-") || testcase.starts_with("F-"),
                "a retained testcase: {replay}"
            );
            assert_eq!(replay["input_sha256"].as_str().map(str::len), Some(64));
        }
    }
    let process: Vec<std::path::PathBuf> = std::fs::read_dir(root.join("work/results/findings"))
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|dir| {
            std::fs::read(dir.join("finding.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .is_some_and(|f| f["rule_id"] == "BHF-431")
        })
        .collect();
    assert_eq!(
        process.len(),
        1,
        "one system() sink, one finding: {process:?}"
    );
    let input = std::fs::read(process[0].join("testcase.bin")).unwrap();
    assert!(
        (2..=40).contains(&input.len()),
        "the input that reached system(): {input:?}"
    );
}

/// A sidecar observes each replayed input as the process that ran it.
#[test]
fn a_sidecar_collector_observes_each_target_through_auto() {
    if !clang_present() {
        eprintln!("skipping: no clang");
        return;
    }
    let root = TestDir::new("auto-collector-sidecar");
    let run = auto(root.path(), env!("CARGO_BIN_EXE_mock_collector"));
    for target in fuzzed(&run) {
        let collector = &target["collector"];
        assert_eq!(collector["mode"], "sidecar", "{collector:#}");
        assert_eq!(collector["observed"], true, "{collector:#}");
        let replays = collector["replays"].as_array().expect("replays");
        assert!(!replays.is_empty(), "{collector:#}");
        assert!(
            replays.iter().all(|r| r["replayed_pid"].as_u64().is_some()),
            "{collector:#}"
        );
    }
}
