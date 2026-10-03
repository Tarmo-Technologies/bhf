// SPDX-License-Identifier: Apache-2.0
//! Standalone `bhf differential` writes F-DIFF-* into <work>/results/findings and
//! rebuilds results/.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn script(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Two disagreeing harnesses and one input under `tmp`.
struct Setup {
    a: PathBuf,
    b: PathBuf,
    inputs: PathBuf,
}

fn setup(tmp: &Path) -> Setup {
    let a = tmp.join("a.sh");
    let b = tmp.join("b.sh");
    script(&a, "echo one");
    script(&b, "echo two");
    let inputs = tmp.join("inputs");
    std::fs::create_dir_all(&inputs).unwrap();
    std::fs::write(inputs.join("x"), b"x").unwrap();
    Setup { a, b, inputs }
}

fn differential(s: &Setup) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bhf"));
    cmd.args(["differential", "--harness-a"])
        .arg(&s.a)
        .arg("--harness-b")
        .arg(&s.b)
        .arg("--inputs")
        .arg(&s.inputs);
    cmd
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn finding_ids(work: &Path) -> Vec<String> {
    let mut ids: Vec<String> = std::fs::read_dir(work.join("results/findings"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    ids.sort();
    ids
}

#[test]
fn differential_writes_into_results() {
    let tmp = tempfile::tempdir().unwrap();
    let s = setup(tmp.path());
    let work = tmp.path().join("bhf_work");
    let out = differential(&s)
        .arg("--work-dir")
        .arg(&work)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let finding = work.join("results/findings/F-DIFF-0000/finding.json");
    assert!(finding.is_file(), "stderr={}", stderr(&out));
    assert!(work.join("results/INDEX.md").is_file());
    assert!(stderr(&out).contains("Results: "));
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("results/findings.json")).unwrap())
            .unwrap();
    assert!(
        doc["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == "F-DIFF-0000" && f["kind"] == "differential"),
        "{doc}"
    );
}

#[test]
fn second_run_on_one_work_dir_adds_the_next_id() {
    let tmp = tempfile::tempdir().unwrap();
    let s = setup(tmp.path());
    let work = tmp.path().join("bhf_work");
    for _ in 0..2 {
        let out = differential(&s)
            .arg("--work-dir")
            .arg(&work)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    }
    assert_eq!(finding_ids(&work), ["F-DIFF-0000", "F-DIFF-0001"]);
}

#[test]
fn missing_inputs_dir_creates_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let s = Setup {
        inputs: tmp.path().join("no-such-inputs"),
        ..setup(tmp.path())
    };
    let work = tmp.path().join("bhf_work");
    let out = differential(&s)
        .arg("--work-dir")
        .arg(&work)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        !work.exists(),
        "a failed differential must not create the work dir"
    );
}

#[test]
fn deprecated_out_is_the_work_dir_and_says_so() {
    let tmp = tempfile::tempdir().unwrap();
    let s = setup(tmp.path());
    let dir = tmp.path().join("legacy_out");
    let out = differential(&s).arg("--out").arg(&dir).output().unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let findings = dir.join("results").join("findings");
    assert!(
        stderr(&out).contains(&format!(
            "note: --out is deprecated for differential; treated as --work-dir; findings are in {}",
            findings.display()
        )),
        "{}",
        stderr(&out)
    );
    assert!(findings.join("F-DIFF-0000/finding.json").is_file());
    assert!(dir.join("results/manifest.json").is_file());
}

#[test]
fn out_and_work_dir_together_are_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let s = setup(tmp.path());
    let out = differential(&s)
        .arg("--out")
        .arg(tmp.path().join("o"))
        .arg("--work-dir")
        .arg(tmp.path().join("w"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(!tmp.path().join("o").exists() && !tmp.path().join("w").exists());
}

#[test]
fn deferred_child_writes_findings_but_leaves_the_index_to_its_parent() {
    let tmp = tempfile::tempdir().unwrap();
    let s = setup(tmp.path());
    let work = tmp.path().join("bhf_work");
    let out = differential(&s)
        .arg("--work-dir")
        .arg(&work)
        .env("BHF_RESULTS_DEFER", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(work
        .join("results/findings/F-DIFF-0000/finding.json")
        .is_file());
    assert!(
        !work.join("results/manifest.json").exists(),
        "no producer record"
    );
    assert!(!work.join("results/INDEX.md").exists(), "no rebuild");
    assert!(!stderr(&out).contains("Results: "));
}
