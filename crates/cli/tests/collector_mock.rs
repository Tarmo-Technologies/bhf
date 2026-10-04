// SPDX-License-Identifier: Apache-2.0

//! End-to-end proof of the `--collector` runtime-event collector (#60) on Linux,
//! driven through the real `bhf binary-fuzz` command with the mock collector
//! sidecar standing in for a live OS provider. The mock speaks the actual
//! `bhf.collector-event.v1` JSONL wire protocol, so this exercises the whole host
//! path — spawn the sidecar, read the sink, attribute to the process tree, map to
//! the oracle registry, emit `binary_semantic` findings, store evidence, and
//! replay — without needing a native tracer.

#![cfg(unix)]

use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn bhf_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bhf"))
}

fn mock_collector() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mock_collector"))
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("bhf-collector-{name}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A target that always exits cleanly — the collector must produce findings even
/// though the crash oracle sees nothing.
fn clean_exit_target(root: &Path) -> PathBuf {
    let bin = root.join("clean.sh");
    fs::write(&bin, "#!/bin/sh\nexit 0\n").unwrap();
    let mut perms = fs::metadata(&bin).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&bin, perms).unwrap();
    bin
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

/// Run `bhf binary-fuzz` with the mock collector in `scenario` and return
/// (parsed run summary, findings dir).
fn run_collector(work_name: &str, scenario: &str) -> (Value, PathBuf) {
    let root = temp_dir(work_name);
    let target = clean_exit_target(&root);
    let work = root.join("work");
    let output = Command::new(bhf_bin())
        .args([
            "binary-fuzz",
            target.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
            "--engine",
            "builtin",
            "--iterations",
            "1",
            "--seed-input",
            "SEED",
            "--collector",
            mock_collector().to_str().unwrap(),
            "--collector-window-ms",
            "500",
        ])
        .env("BHF_MOCK_SCENARIO", scenario)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "binary-fuzz failed: exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "run summary is not JSON: {e}\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    (summary, work.join("results/findings"))
}

fn collector_findings(findings_dir: &Path) -> Vec<Value> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(findings_dir) {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with("COL-") {
                out.push(read_json(&entry.path().join("finding.json")));
            }
        }
    }
    out
}

#[test]
fn collector_three_positive_classes_emit_semantic_findings_without_a_crash() {
    let (summary, findings_dir) = run_collector("positive", "positive_all");
    assert_eq!(
        summary.pointer("/collector/active"),
        Some(&Value::Bool(true)),
        "collector must be active: {summary}"
    );

    let findings = collector_findings(&findings_dir);
    let rules: std::collections::BTreeSet<&str> = findings
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .collect();
    // process-exec (BHF-431), path-control (BHF-405), controlled-library-load (BHF-435).
    assert!(rules.contains("BHF-431"), "process-exec finding: {rules:?}");
    assert!(rules.contains("BHF-405"), "path-control finding: {rules:?}");
    assert!(
        rules.contains("BHF-435"),
        "controlled-library-load finding: {rules:?}"
    );

    for f in &findings {
        assert_eq!(f["kind"], "binary_semantic", "collector finding kind");
        assert_eq!(f["confirmation"], "collector");
        // A clean-exit semantic finding carries NO crash signal.
        assert!(f.get("crash").is_none(), "must have no crash block: {f}");
        // Provenance records the seven required fields.
        let prov = &f["collector"]["provenance"];
        for field in [
            "backend_name",
            "backend_version",
            "backend_hash",
            "process_tree_scope",
            "observation_window_ms",
            "supported_event_classes",
            "fidelity",
        ] {
            assert!(prov.get(field).is_some(), "missing provenance {field}: {f}");
        }
        assert_eq!(prov["observation_window_ms"], 500);
        // The attributing event + descendant tree are stored for audit. The tree is
        // rooted at the REAL replayed target PID the host launched under the observer
        // (#76), not a synthetic constant.
        assert!(f["collector"]["attributing_event"].is_object());
        let replayed_pid = summary["collector"]["replayed_pid"]
            .as_u64()
            .expect("the replay records the launched target PID");
        assert!(
            f["collector"]["process_tree"]
                .as_array()
                .is_some_and(|t| t.contains(&Value::from(replayed_pid))),
            "finding tree must contain the launched target PID {replayed_pid}: {f}"
        );
    }
}

#[test]
fn collector_fixed_constants_do_not_become_taint_confirmed_findings() {
    let (summary, findings_dir) = run_collector("constants", "fixed_constants");
    assert_eq!(
        summary.pointer("/collector/active"),
        Some(&Value::Bool(true))
    );
    let findings = collector_findings(&findings_dir);
    assert!(
        findings.is_empty(),
        "fixed constants must not produce taint-confirmed findings, got {} ({:?})",
        findings.len(),
        findings
            .iter()
            .map(|f| f["rule_id"].clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn collector_lossy_collection_is_never_reported_clean() {
    let (summary, findings_dir) = run_collector("lossy", "lossy");
    // The run manifest refuses a clean assurance.
    assert_eq!(
        summary.pointer("/collector/clean_assurance"),
        Some(&Value::Bool(false)),
        "a lossy run must not be reported clean: {summary}"
    );
    assert_eq!(
        summary.pointer("/collector/fidelity/permission_denied"),
        Some(&Value::Bool(true))
    );
    // Findings are still produced, each flagged degraded in its provenance.
    for f in collector_findings(&findings_dir) {
        assert_eq!(
            f["collector"]["clean_assurance"],
            Value::Bool(false),
            "per-finding clean assurance must be refused when the run was lossy: {f}"
        );
    }
}

#[test]
fn collector_replay_reproduces_the_semantic_finding_from_stored_evidence() {
    let (_summary, findings_dir) = run_collector("replay", "process_exec");
    let dir = findings_dir.join("COL-0001");
    assert!(
        dir.join("collector_session.jsonl").is_file(),
        "evidence stored"
    );

    // Replay needs no harness: it reproduces deterministically from the stored
    // CollectorSession evidence.
    let output = Command::new(bhf_bin())
        .args(["replay", dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "replay failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("MATCH"),
        "replay must report MATCH: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    // Minimize is an honest no-op for a collector finding (evidence is provider-
    // captured, not a function of the testcase bytes) and must still succeed.
    let output = Command::new(bhf_bin())
        .args(["minimize", dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "minimize failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn default_run_without_collector_is_unchanged() {
    // No --collector flag: the collector is inactive and emits no findings.
    let root = temp_dir("default");
    let target = clean_exit_target(&root);
    let work = root.join("work");
    let output = Command::new(bhf_bin())
        .args([
            "binary-fuzz",
            target.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
            "--engine",
            "builtin",
            "--iterations",
            "1",
            "--seed-input",
            "SEED",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        summary.pointer("/collector/active"),
        Some(&Value::Bool(false)),
        "collector inactive by default: {summary}"
    );
    assert!(
        collector_findings(&work.join("results/findings")).is_empty(),
        "no collector findings without --collector"
    );
}
