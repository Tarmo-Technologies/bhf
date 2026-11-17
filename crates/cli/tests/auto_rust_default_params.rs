// SPDX-License-Identifier: Apache-2.0
//
// Rust parameters that had no decoder build and fuzz (#338): an owned
// project type with `Default` is built from `T::default()`, an `Option<T>`
// decodes a flag and then `T`, and `i128`/`u128` read sixteen bytes. Each
// fixture target has a planted out-of-bounds read the run finds.

use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/rust_default_params")
        .canonicalize()
        .expect("canonicalize rust_default_params fixture")
}

fn has_cargo_nightly() -> bool {
    let present = Command::new("cargo")
        .args(["+nightly", "--version"])
        .output()
        .is_ok_and(|o| o.status.success());
    support::require_tool(present, "cargo nightly")
}

#[test]
#[cfg_attr(
    windows,
    ignore = "the Rust lane builds its harness as a Unix static archive (lib*.a, linked with \
              libpthread and libdl) and runs under WSL on Windows; see docs/site/windows.md"
)]
fn default_option_and_wide_integer_parameters_build_and_their_bugs_are_found() {
    if !has_cargo_nightly() {
        eprintln!("skip: no `cargo +nightly` toolchain (native Rust lane needs it)");
        return;
    }
    let root = TestDir::new("rust-default-params");
    let work = root.join("work");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args([
            "auto",
            "--run-untrusted",
            "--per-target-time",
            "10",
            "--jobs",
            "1",
        ])
        .args([
            "--target", "parse_at", "--target", "tag", "--target", "bucket",
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
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
    let mut found = Vec::new();
    for target in run["targets"].as_array().unwrap() {
        let name = target["name"].as_str().unwrap_or_default();
        let passes = target["outcome"]["passes"].as_array();
        assert!(
            passes.is_some_and(|passes| !passes.is_empty()),
            "{name} did not build and fuzz: {target:#}\n{log}"
        );
        let findings: usize = passes
            .unwrap()
            .iter()
            .map(|pass| pass["findings"].as_array().map_or(0, Vec::len))
            .sum();
        assert!(
            findings > 0,
            "the planted bug behind {name} is found:\n{log}"
        );
        found.push(name.to_owned());
    }
    found.sort();
    assert_eq!(found, ["bucket", "parse_at", "tag"], "{log}");

    // `parse_at`'s harness builds its `Location` rather than decoding one.
    let parse_at = run["targets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|target| target["name"] == "parse_at")
        .unwrap();
    let source = std::fs::read_to_string(
        work.join("harnesses")
            .join(parse_at["harness_id"].as_str().unwrap())
            .join("rust_harness/src/lib.rs"),
    )
    .unwrap();
    assert!(source.contains("Location::default()"), "{source}");
}
