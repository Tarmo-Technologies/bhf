// SPDX-License-Identifier: Apache-2.0
//
// A Rust target whose dependency instantiates core's generics links and
// fuzzes (#409). `generic_dep_shapes` sorts its own segments through a generic
// method of `generic_dep_keysort`, so the instances of core's stable sort are
// spread over its codegen units. Built with SanitizerCoverage's
// trace-pc-guard and ASan at opt-level 1, rustc's crate-local ThinLTO left
// some of them local to one unit while another still called them, and the
// clang link of the harness staticlib failed with undefined references to
// `core::slice::sort::stable::drift::sort::<Segment, ...>`.

use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/rust_generic_dep/app")
        .canonicalize()
        .expect("canonicalize rust_generic_dep fixture")
}

fn has_cargo_nightly() -> bool {
    let present = Command::new(support::rustup_cargo())
        .args(["+nightly", "--version"])
        .output()
        .is_ok_and(|o| o.status.success());
    support::require_tool(present, "cargo nightly")
}

#[test]
fn target_whose_dependency_instantiates_core_generics_links_and_fuzzes() {
    if !has_cargo_nightly() {
        eprintln!("skip: no `cargo +nightly` toolchain (native Rust lane needs it)");
        return;
    }
    let root = TestDir::new("rust-generic-dep");
    let work = root.join("work");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args([
            "auto",
            "--run-untrusted",
            "--per-target-time",
            "10",
            "--jobs",
            "1",
            "--target",
            "parse_record",
        ])
        .arg(fixture())
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run bhf auto");
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let run: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("auto/run.json"))
            .unwrap_or_else(|e| panic!("read run.json: {e}\n{log}")),
    )
    .expect("parse run.json");
    let targets = run["targets"].as_array().expect("run.json has targets");
    let target = targets
        .iter()
        .find(|target| target["name"] == "parse_record")
        .unwrap_or_else(|| panic!("parse_record was not attempted:\n{log}"));
    let passes = target["outcome"]["passes"].as_array();
    assert!(
        passes.is_some_and(|passes| !passes.is_empty()),
        "parse_record did not link and fuzz: {target:#}\n{log}"
    );
    let findings: usize = passes
        .unwrap()
        .iter()
        .map(|pass| pass["findings"].as_array().map_or(0, Vec::len))
        .sum();
    assert!(
        findings > 0,
        "the planted out-of-bounds index behind parse_record is found: {target:#}\n{log}"
    );

    // The harness crate is the external staticlib, not an in-crate copy.
    let harness = work
        .join("harnesses")
        .join(target["harness_id"].as_str().expect("harness_id"));
    assert!(
        harness.join("rust_harness/Cargo.toml").is_file(),
        "{}",
        harness.display()
    );
}
