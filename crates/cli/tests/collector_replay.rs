// SPDX-License-Identifier: Apache-2.0

//! End-to-end proof of the #76 collector REPLAY model, driven through the real
//! `bhf binary-fuzz` command with the mock collector sidecar. The host selects a
//! retained testcase, confirms the sidecar is live via the readiness handshake,
//! and records the observation as a limited single-testcase replay with the REAL
//! triggering input retained in the finding (reproducible from it). A sidecar that
//! never acks readiness, fails its capture, or observes nothing for the testcase
//! is routed to the degraded, not-observed contract — never a clean assurance.
//!
//! This mirrors `collector_mock.rs` but focuses on the identity/readiness/degraded
//! plumbing rather than the oracle mapping.

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
    let dir = std::env::temp_dir().join(format!("bhf-replay-{name}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A target that always exits cleanly.
fn clean_exit_target(root: &Path) -> PathBuf {
    let bin = root.join("clean.sh");
    fs::write(&bin, "#!/bin/sh\nexit 0\n").unwrap();
    let mut perms = fs::metadata(&bin).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&bin, perms).unwrap();
    bin
}

/// Run `bhf binary-fuzz` with the mock collector in `scenario`, replaying `seed`,
/// and return (parsed run summary, findings dir). The run itself always succeeds
/// (a degraded collector is not a run failure).
fn run_replay(work_name: &str, scenario: &str, seed: &str) -> (Value, PathBuf) {
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
            seed,
            "--collector",
            mock_collector().to_str().unwrap(),
            "--collector-window-ms",
            "400",
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

fn collector_findings(findings_dir: &Path) -> Vec<(PathBuf, Value)> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(findings_dir) {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with("COL-") {
                let dir = entry.path();
                let f: Value =
                    serde_json::from_slice(&fs::read(dir.join("finding.json")).unwrap()).unwrap();
                out.push((dir, f));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn replayed_testcase_retains_real_input_and_is_reproducible() {
    let seed = "REPLAY-TRIGGER-INPUT";
    let (summary, findings_dir) = run_replay("retained", "positive_all", seed);

    // The collector observed a limited REPLAY of a specific retained testcase —
    // never claiming whole-campaign coverage.
    let col = &summary["collector"];
    assert_eq!(
        col["active"],
        Value::Bool(true),
        "collector active: {summary}"
    );
    assert_eq!(col["observed"], Value::Bool(true), "observed: {summary}");
    assert_eq!(col["observation"], "replay", "observation mode: {summary}");
    assert_eq!(
        col["coverage"], "single-testcase-replay",
        "limited replay coverage: {summary}"
    );

    let findings = collector_findings(&findings_dir);
    assert!(!findings.is_empty(), "replay produced collector findings");

    let (dir, f) = &findings[0];
    // The REAL triggering input is retained in the finding, byte for byte.
    let retained = fs::read(dir.join("testcase.bin")).unwrap();
    assert_eq!(
        retained,
        seed.as_bytes(),
        "the actual triggering input must be retained (not empty / not synthetic)"
    );
    assert_eq!(f["input"]["bytes"], seed.len());
    // Per-finding provenance records the limited replay scope.
    assert_eq!(f["collector"]["observation"], "replay");
    assert_eq!(f["collector"]["coverage"], "single-testcase-replay");

    // And the finding is reproducible from its stored evidence via `bhf replay`.
    let output = Command::new(bhf_bin())
        .args(["replay", dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("MATCH"),
        "replay must reproduce the finding: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn unrelated_concurrent_process_events_are_excluded() {
    let (summary, findings_dir) = run_replay("unrelated", "unrelated_excluded", "SEED");
    assert_eq!(summary["collector"]["observed"], Value::Bool(true));

    // The run's attributed process-tree scope excludes the unrelated pid 7777.
    let scope = summary["collector"]["process_tree_scope"]
        .as_array()
        .expect("process_tree_scope present");
    assert!(
        scope.iter().all(|p| p.as_u64() != Some(7777)),
        "the unrelated concurrent process (pid 7777) must be excluded from scope: {scope:?}"
    );

    let findings = collector_findings(&findings_dir);
    assert!(
        !findings.is_empty(),
        "the in-tree positive effects still fire"
    );
    for (_, f) in &findings {
        let ev_pid = f["collector"]["attributing_event"]["process"]["pid"].as_u64();
        assert_ne!(
            ev_pid,
            Some(7777),
            "no finding may be attributed to the unrelated process"
        );
        let tree = f["collector"]["process_tree"].as_array().unwrap();
        assert!(
            tree.iter().all(|p| p.as_u64() != Some(7777)),
            "the unrelated pid must not appear in a finding's process tree"
        );
    }
}

/// Every degraded sidecar outcome must record `observed: false`, refuse a clean
/// assurance, surface the reason as a fidelity limitation, and produce no findings
/// — never a clean collector assurance over a run it did not actually watch.
fn assert_degraded(scenario: &str, expected_reason: &str) {
    let (summary, findings_dir) = run_replay(scenario, scenario, "SEED");
    let col = &summary["collector"];
    assert_eq!(
        col["observed"],
        Value::Bool(false),
        "{scenario}: must not claim it observed the run: {summary}"
    );
    assert_eq!(
        col["clean_assurance"],
        Value::Bool(false),
        "{scenario}: must refuse a clean assurance: {summary}"
    );
    let unsupported = col["fidelity"]["unsupported_fields"]
        .as_array()
        .expect("unsupported_fields present");
    assert!(
        unsupported
            .iter()
            .any(|v| v.as_str() == Some(expected_reason)),
        "{scenario}: reason {expected_reason} must be recorded, got {unsupported:?}"
    );
    assert!(
        collector_findings(&findings_dir).is_empty(),
        "{scenario}: a not-observed run yields no findings"
    );
}

#[test]
fn missing_readiness_ack_is_degraded_not_clean() {
    // The sidecar never acked readiness (exited first): the host must record a
    // degraded, not-observed run rather than a clean assurance over an unwatched run.
    assert_degraded("no_ready", "collector_exited_before_ready");
}

#[test]
fn failed_capture_is_degraded_not_clean() {
    // The sidecar acked but then failed its capture (non-zero exit).
    assert_degraded("capture_failed", "collector_capture_failed_exit_7");
}

#[test]
fn unobserved_testcase_is_degraded_not_clean() {
    // The sidecar acked and ran but produced no session for the replayed testcase.
    assert_degraded("unobserved", "testcase_not_observed");
}

// ── Native positive/clean control (scaffold) ────────────────────────────────
//
// #76 native control: driving a retained testcase as a REAL replayed child under
// the live Windows ETW provider — the host spawning that child under the session
// after the readiness ack and handing off its pid — is the remaining piece and is
// NOT wired in this cut (the native sidecar observes its own window). The native
// provider's readiness ack and the degraded-vs-clean invariant it must honor are
// covered on the Windows runner by the BHF_WIN_LIVE-gated scaffold in
// `crates/bhf_collector_win/tests/live_windows.rs`
// (`replay_readiness_ack_and_clean_control_scaffold`). The identity, readiness,
// and degraded-routing plumbing those controls depend on is exercised fully above
// through the mock sidecar on this host.
