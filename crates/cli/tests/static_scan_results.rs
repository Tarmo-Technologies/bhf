// SPDX-License-Identifier: Apache-2.0
//! `static-scan` and `sbom` without --out write into <work>/results and rebuild it;
//! with an explicit --out they write only there (today's behaviour for scripted callers).

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

#[test]
fn static_scan_defaults_into_results() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::copy(
        repo_root().join("tests/fixtures/static_scan/weak.c"),
        src.join("weak.c"),
    )
    .unwrap();
    let work = tmp.path().join("bhf_work");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("static-scan")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(work.join("results/static/static-report.json").is_file());
    assert!(
        work.join("results/static/static-report.sarif").is_file(),
        "SARIF is always written in results mode"
    );
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("results/findings.json")).unwrap())
            .unwrap();
    assert!(doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["kind"] == "static" && f["producer"] == "static-scan"));
    assert!(
        doc["source"]["root"].as_str().is_some(),
        "static-scan records the scanned root"
    );
    let sarif: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("results/findings.sarif")).unwrap())
            .unwrap();
    assert_eq!(sarif["runs"].as_array().unwrap().len(), 1);
    assert!(!sarif["runs"][0]["results"].as_array().unwrap().is_empty());
}

#[test]
fn static_scan_explicit_out_does_not_touch_results() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::copy(
        repo_root().join("tests/fixtures/static_scan/weak.c"),
        src.join("weak.c"),
    )
    .unwrap();
    let out_dir = tmp.path().join("out");
    let work = tmp.path().join("bhf_work");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("static-scan")
        .arg(&src)
        .arg("--out")
        .arg(&out_dir)
        .arg("--sarif")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out_dir.join("static-report.sarif").is_file());
    assert!(!work.join("results").exists());
    assert!(String::from_utf8_lossy(&out.stderr).contains("results/ was not updated"));
}

#[test]
fn static_scan_of_dot_records_an_absolute_root() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::copy(
        repo_root().join("tests/fixtures/static_scan/weak.c"),
        src.join("weak.c"),
    )
    .unwrap();
    let work = tmp.path().join("bhf_work");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_bhf"))
        .current_dir(&src)
        .arg("static-scan")
        .arg(".")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("results/findings.json")).unwrap())
            .unwrap();
    assert_eq!(
        doc["source"]["root"].as_str(),
        Some(src.canonicalize().unwrap().to_str().unwrap())
    );
}
