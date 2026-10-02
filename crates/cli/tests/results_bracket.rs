// SPDX-License-Identifier: Apache-2.0
//! The dispatcher's results bracket: producers record themselves in an existing
//! work dir and never conjure one from a missing or mistyped path.

use std::process::Command;

fn bhf() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
}

#[test]
fn fuzz_on_a_missing_work_dir_fails_and_creates_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("no-such-work");
    let out = bhf()
        .arg("fuzz")
        .arg(&missing)
        .args(["--harness", "H-1"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!missing.exists(), "no {}/results", missing.display());
}

#[test]
fn cartography_records_its_producer() {
    let tmp = tempfile::tempdir().unwrap();
    let work = tmp.path().join("bhf_work");
    std::fs::create_dir_all(work.join("results/findings")).unwrap();
    let out = bhf()
        .arg("cartography")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("results/manifest.json")).unwrap())
            .unwrap();
    let last = manifest["producers"].as_array().unwrap().last().unwrap();
    assert_eq!(last["command"], "cartography");
    assert_eq!(last["exit_code"], 0);
}
