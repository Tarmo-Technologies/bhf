// SPDX-License-Identifier: Apache-2.0

//! Stack depth as fuzzing progress (#220).
//!
//! The `stack_depth` fixture recurses once per `[` with no depth limit, and
//! every depth runs the same edges. Edge coverage keeps none of the deeper
//! inputs, so the recursion never gets near the stack's end. With the
//! driver's stack-depth word as a novelty channel, each deeper input joins
//! the corpus, the repeat-token mutator doubles its run of `[`, and the stack
//! runs out: a BHF-207.

#![cfg(target_os = "linux")]

use serde_json::Value;
use std::path::{Path, PathBuf};

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/engine_parity/stack_depth/stack_depth.c")
}

fn bhf(work: &Path, args: &[&str]) -> std::process::Command {
    let mut cmd = support::bhf_cargo_command();
    cmd.current_dir(work).args(args);
    cmd
}

/// The rule ids of the findings of `executions` cold executions from `[]`,
/// with the stack-depth channel on or off.
fn fuzz(tag: &str, stack_depth: bool, executions: &str) -> Vec<String> {
    let work = TestDir::new(&format!("stack-depth-{tag}"));
    std::fs::copy(fixture(), work.join("stack_depth.c")).unwrap();
    let id = "H-STACK";
    let generated = bhf(
        work.path(),
        &[
            "generate-harness",
            "stack_depth.c",
            "--target",
            "stack_depth",
        ],
    )
    .args(["--output", "generated_harnesses", "--id", id])
    .status()
    .unwrap();
    assert!(generated.success(), "generate-harness failed");
    let built = bhf(work.path(), &["build", ".", "--harness", id])
        .status()
        .unwrap();
    assert!(built.success(), "build failed");

    let mut cmd = bhf(work.path(), &["fuzz", ".", "--harness", id]);
    cmd.args(["--engine", "builtin", "--iterations", executions])
        .args(["--rng-seed", "1", "--seed-input", "[]", "--sandbox", "none"]);
    if !stack_depth {
        cmd.env("BHF_DISABLE_STACK_DEPTH", "1");
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success() || out.status.code() == Some(1),
        "bhf fuzz: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let Ok(entries) = std::fs::read_dir(work.join("results/findings")) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| std::fs::read(entry.path().join("finding.json")).ok())
        .filter_map(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .map(|finding| finding["rule_id"].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// At a fixed seed and execution count the stack runs out with the depth
/// channel and not without it, and one recursion is one finding.
#[test]
fn deeper_recursion_counts_as_progress_until_the_stack_runs_out() {
    if !support::libfuzzer_toolchain_available("stack-depth") {
        eprintln!("skipping: clang+make toolchain unavailable");
        return;
    }
    let executions = "3000";
    let without = fuzz("off", false, executions);
    assert!(
        without.is_empty(),
        "BHF_DISABLE_STACK_DEPTH=1 still found {without:?} in {executions} executions"
    );
    let with = fuzz("on", true, executions);
    assert_eq!(with, ["BHF-207"], "{executions} executions");
}
