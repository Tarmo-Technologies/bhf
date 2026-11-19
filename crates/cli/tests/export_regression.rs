// SPDX-License-Identifier: Apache-2.0

//! `bhf export regression` (#339) writes a standalone suite that fails on a
//! finding's input until its bug is fixed: the C suite rebuilds each harness
//! against the scanned tree, so fixing the tree makes it pass. The Ada suite
//! fails on the Constraint_Error input of its fixture.

#![cfg(unix)]

use std::path::Path;
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn fixture(dir: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(dir)
}

fn auto(src: &Path, work: &Path, extra: &[&str]) {
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(src)
        .arg("--work-dir")
        .arg(work)
        .args([
            "--per-target-time",
            "10",
            "--jobs",
            "1",
            "--no-discovery-cache",
        ])
        .args(extra)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn export(work: &Path, suite: &Path, lang: &str) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["export", "regression", "--lang", lang, "--work-dir"])
        .arg(work)
        .arg("--out")
        .arg(suite)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

fn run_suite(suite: &Path) -> (bool, String) {
    let output = Command::new("sh")
        .arg(suite.join("run.sh"))
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

#[test]
fn the_c_suite_fails_on_the_finding_until_the_bug_is_fixed() {
    if !support::require_tool(
        Command::new("clang").arg("--version").output().is_ok(),
        "clang",
    ) {
        eprintln!("skipping: no clang");
        return;
    }
    let root = TestDir::new("export-regression-c");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::copy(fixture("regression_c/tag.c"), src.join("tag.c")).unwrap();
    let seed = root.join("seed.bin");
    std::fs::write(&seed, b"TAAAAAAAAAAA").unwrap();
    let work = root.join("work");
    auto(
        &src,
        &work,
        &["--languages", "c", "--seed-file", seed.to_str().unwrap()],
    );

    let suite = root.join("suite");
    let summary = export(&work, &suite, "c");
    assert!(
        summary.starts_with("regression suite: 1 harness(es)"),
        "{summary}"
    );
    assert!(suite.join("c_runtime/bhf_driver.c").is_file());
    let (passed, log) = run_suite(&suite);
    assert!(!passed, "the planted overflow fails the suite: {log}");
    assert!(
        log.lines()
            .any(|line| line.starts_with("FAIL ") && line.contains("findings/F-")),
        "{log}"
    );

    // Fixed in the tree: the suite rebuilds against it and passes.
    let fixed = std::fs::read_to_string(src.join("tag.c"))
        .unwrap()
        .replace("if (len > 0 &&", "if (len > 0 && len <= sizeof tag &&");
    std::fs::write(src.join("tag.c"), fixed).unwrap();
    let (passed, log) = run_suite(&suite);
    assert!(passed, "the fixed tree passes: {log}");
    assert!(!log.contains("FAIL"), "{log}");
}

#[test]
fn the_ada_suite_fails_on_the_constraint_error_input() {
    let present = ["gnatmake", "gprbuild"]
        .iter()
        .all(|tool| Command::new(tool).arg("--version").output().is_ok());
    if !support::require_tool(present, "gnatmake and gprbuild") {
        eprintln!("skipping: no GNAT");
        return;
    }
    let root = TestDir::new("export-regression-ada");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    for name in ["words.ads", "words.adb"] {
        std::fs::copy(fixture("ada_record_params").join(name), src.join(name)).unwrap();
    }
    let work = root.join("work");
    auto(&src, &work, &["--languages", "ada", "--target", "weight"]);
    let suite = root.join("suite");
    let summary = export(&work, &suite, "ada");
    assert!(
        summary.starts_with("regression suite: 1 harness(es)"),
        "{summary}"
    );
    let (passed, log) = run_suite(&suite);
    assert!(!passed, "the index check fails the suite: {log}");
    assert!(
        log.lines()
            .any(|line| line.starts_with("FAIL ") && line.contains("findings/F-")),
        "{log}"
    );
}
