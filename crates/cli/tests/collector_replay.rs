// SPDX-License-Identifier: Apache-2.0

//! End-to-end proof of the #76 collector REPLAY model, driven through the real
//! `bhf binary-fuzz` command with the mock collector sidecar.
//!
//! The honest contract this exercises: the host selects a retained testcase, spawns
//! the collector, waits for its readiness ack, and only then LAUNCHES the target
//! with the real input UNDER the ready observer — recording the target's real PID.
//! The observation is of a process that actually ran (proved by a unique marker the
//! target writes during execution, whose PID matches the recorded `replayed_pid`),
//! the real triggering input is retained and reproducible, and unrelated concurrent
//! processes are excluded. A provider that never acks, fails its capture, observes
//! nothing, or readies-then-wedges yields a BOUNDED, degraded (not clean, not
//! observed) run — never a false replay claim and never a hang.

#![cfg(unix)]

use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

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

/// A target that records its own PID to `marker` each time it runs, then exits
/// cleanly. The collector replay launches it under the observer, so the marker
/// proves the target really ran and names the process the observer should see.
fn marker_target(root: &Path, marker: &Path) -> PathBuf {
    let bin = root.join("target.sh");
    fs::write(
        &bin,
        format!(
            "#!/bin/sh\necho \"$$\" > \"{}\"\nexit 0\n",
            marker.display()
        ),
    )
    .unwrap();
    let mut perms = fs::metadata(&bin).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&bin, perms).unwrap();
    bin
}

/// Run `bhf binary-fuzz` with the mock collector in `scenario`, replaying `seed`,
/// and return (parsed summary, findings dir, marker path, elapsed). The run itself
/// always succeeds (a degraded collector is not a run failure).
fn run_replay(work_name: &str, scenario: &str, seed: &str) -> (Value, PathBuf, PathBuf, f64) {
    let root = temp_dir(work_name);
    let marker = root.join("marker.txt");
    let target = marker_target(&root, &marker);
    let work = root.join("work");
    let started = Instant::now();
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
            "300",
        ])
        .env("BHF_MOCK_SCENARIO", scenario)
        .output()
        .unwrap();
    let elapsed = started.elapsed().as_secs_f64();
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
    (summary, work.join("results/findings"), marker, elapsed)
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
fn replay_launches_the_target_and_records_its_real_pid_and_input() {
    let seed = "REPLAY-TRIGGER-INPUT";
    let (summary, findings_dir, marker, _elapsed) = run_replay("launched", "positive_all", seed);

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
        "limited scope: {summary}"
    );

    // The target REALLY RAN under the observer: it wrote its PID to the marker.
    let marker_pid: u32 = fs::read_to_string(&marker)
        .expect("target must have run and written its marker")
        .trim()
        .parse()
        .expect("marker holds the target PID");
    // The collector recorded THAT process as the replayed PID (so the observation
    // is genuinely about the launched target, launched after the readiness ack).
    let replayed_pid = col["replayed_pid"].as_u64().expect("replayed_pid recorded");
    assert_eq!(
        replayed_pid as u32, marker_pid,
        "the recorded replayed PID must be the real launched target's PID: {summary}"
    );
    // The replayed input's content hash is recorded for auditability.
    assert!(
        col["replayed_input_sha256"]
            .as_str()
            .is_some_and(|h| h.len() == 64),
        "replayed input hash recorded: {summary}"
    );

    let findings = collector_findings(&findings_dir);
    assert!(!findings.is_empty(), "replay produced collector findings");
    let (dir, f) = &findings[0];
    // The REAL triggering input is retained, byte for byte.
    assert_eq!(
        fs::read(dir.join("testcase.bin")).unwrap(),
        seed.as_bytes(),
        "the actual triggering input must be retained (not empty / not synthetic)"
    );
    assert_eq!(f["input"]["bytes"], seed.len());
    assert_eq!(f["collector"]["observation"], "replay");
    assert_eq!(f["collector"]["coverage"], "single-testcase-replay");
    // The finding is attributed to the real launched process's tree.
    let tree = f["collector"]["process_tree"].as_array().unwrap();
    assert!(
        tree.iter().any(|p| p.as_u64() == Some(replayed_pid)),
        "the finding must be attributed to the launched target's tree: {f}"
    );

    // And it reproduces deterministically from the stored evidence.
    let out = Command::new(bhf_bin())
        .args(["replay", dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("MATCH"),
        "replay must reproduce the finding: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn unrelated_concurrent_process_events_are_excluded() {
    let (summary, findings_dir, _marker, _elapsed) =
        run_replay("unrelated", "unrelated_excluded", "SEED");
    assert_eq!(summary["collector"]["observed"], Value::Bool(true));

    let scope = summary["collector"]["process_tree_scope"]
        .as_array()
        .expect("process_tree_scope present");
    assert!(
        scope.iter().all(|p| p.as_u64() != Some(7777)),
        "the unrelated concurrent process (pid 7777) must be excluded from scope: {scope:?}"
    );
    for (_, f) in &collector_findings(&findings_dir) {
        assert_ne!(
            f["collector"]["attributing_event"]["process"]["pid"].as_u64(),
            Some(7777),
            "no finding may be attributed to the unrelated process"
        );
        assert!(
            f["collector"]["process_tree"]
                .as_array()
                .unwrap()
                .iter()
                .all(|p| p.as_u64() != Some(7777)),
            "the unrelated pid must not appear in a finding's process tree"
        );
    }
}

/// Every degraded sidecar outcome records `observed: false`, refuses a clean
/// assurance, surfaces the reason, and produces no findings — never a clean
/// assurance over a run the collector did not actually watch.
fn assert_degraded(scenario: &str, expected_reason: &str) -> f64 {
    let (summary, findings_dir, _marker, elapsed) = run_replay(scenario, scenario, "SEED");
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
    elapsed
}

#[test]
fn missing_readiness_ack_is_degraded_not_clean() {
    assert_degraded("no_ready", "collector_exited_before_ready");
}

#[test]
fn failed_capture_is_degraded_not_clean() {
    assert_degraded("capture_failed", "collector_capture_failed_exit_7");
}

#[test]
fn unobserved_testcase_is_degraded_not_clean() {
    assert_degraded("unobserved", "testcase_not_observed");
}

#[test]
fn a_provider_that_readies_then_wedges_is_bounded_not_a_hang() {
    // #76 P2: a provider that acks readiness then never finishes must be bounded by
    // the capture drain and recorded not-observed — the fuzz command must return,
    // not hang despite --collector-window-ms.
    let elapsed = assert_degraded("hang", "collector_capture_timeout");
    assert!(
        elapsed < 60.0,
        "a readies-then-wedges provider must be bounded, not hang (took {elapsed:.1}s)"
    );
}

// ── Native positive/clean control (scaffold) ────────────────────────────────
//
// Driving a retained testcase as a REAL replayed child under the live Windows ETW
// provider (host launching the child under the session after the readiness ack and
// the native sidecar rooting its observation at that child's PID via the handoff)
// needs a Windows runner and native pid-handoff wiring, so it is NOT exercised on
// this Linux host. The native readiness ack and the degraded-vs-clean invariant it
// must honor are covered on the Windows runner by the BHF_WIN_LIVE-gated scaffold in
// `crates/bhf_collector_win/tests/live_windows.rs`. Under the host replay flow a
// native sidecar that does not yet root at the handed-off PID degrades to
// not_observed (the host's "evidence must be about the launched process" invariant),
// which is honest. All of the identity/readiness/launch/bounded-drain/degraded
// plumbing is exercised fully above through the mock sidecar on this host.
