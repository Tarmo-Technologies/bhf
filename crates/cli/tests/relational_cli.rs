// SPDX-License-Identifier: Apache-2.0
//! End-to-end `bhf relational` tests driving the real binary with a real,
//! process-spawning executor against the issue's toy viewer/administrator
//! launcher repro.
//!
//! The launcher is a POSIX-sh mock: it emits the `bhf.*` runtime-trace JSONL that
//! an instrumented target would produce (so the test is deterministic and needs
//! no prebuilt LD_PRELOAD shim — the shim is disabled via `BHF_RUNTRACE_SHIM=off`,
//! which also keeps the sh process's own `grep` out of the trace). Both roles exit
//! 0 and print identical stdout, so the only signal distinguishing an escape is
//! the effect event — exactly what a crash/output-diff oracle cannot see.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bhf_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bhf"))
}

fn tempdir(tag: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("bhf-relational-{tag}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Write the toy launcher. `viewer` may launch only `viewer-helper`;
/// `administrator` launches `administrator-helper` too. A bug lets `viewer` launch
/// `administrator-helper` when the mutated input contains the marker byte `z`.
/// Both roles exit 0 with identical stdout.
fn write_launcher(dir: &Path) -> PathBuf {
    let path = dir.join("launcher.sh");
    let script = r#"#!/bin/sh
role="$1"
log="$BHF_RUNTRACE_LOG"
inp="$BHF_RELATIONAL_INPUT"
# Every role launches its own helper.
printf '{"e":"exec","a":"execve","p":"%s-helper"}\n' "$role" >> "$log"
if [ "$role" = administrator ]; then
    # Declared, expected: administrator may launch administrator-helper.
    printf '{"e":"exec","a":"execve","p":"administrator-helper"}\n' >> "$log"
elif [ "$role" = viewer ]; then
    if grep -q z "$inp" 2>/dev/null; then
        # The bug: viewer reaches the forbidden target on a crafted input.
        printf '{"e":"exec","a":"execve","p":"administrator-helper"}\n' >> "$log"
        # A resolved secret would ride along on the privileged launch command.
        if [ -n "$TOKEN" ]; then
            printf '{"e":"system","c":"login --token %s"}\n' "$TOKEN" >> "$log"
        fi
    fi
fi
# Identical stdout + exit status for every role: no output-diff signal.
printf 'ok\n'
exit 0
"#;
    fs::write(&path, script).unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).unwrap();
    path
}

fn write_config(dir: &Path, launcher: &Path, viewer_allowlist: &str) -> PathBuf {
    let path = dir.join("relational.toml");
    let launcher = launcher.display();
    let config = format!(
        r#"schema = "bhf.relational.v1"

[status_map]
allowed = [0]
denied = [77]

[[profiles]]
name = "administrator"
runner = "/bin/sh"
args = ["{launcher}", "administrator"]
allowlist = ["administrator-helper", "viewer-helper"]
collector = "runtrace"
[profiles.env]
TOKEN = "lab:admin-token"

[[profiles]]
name = "viewer"
runner = "/bin/sh"
args = ["{launcher}", "viewer"]
allowlist = [{viewer_allowlist}]
collector = "runtrace"
[profiles.env]
TOKEN = "lab:viewer-token"

[[predicates]]
rule = "viewer spawned targets must be a subset of its allowlist"
require = {{ kind = "subset", set = "viewer.spawned", of = "viewer.allowlist" }}
"#
    );
    fs::write(&path, config).unwrap();
    path
}

fn write_seeds(dir: &Path, contents: &[&[u8]]) -> PathBuf {
    let seeds = dir.join("seeds");
    fs::create_dir_all(&seeds).unwrap();
    for (i, bytes) in contents.iter().enumerate() {
        fs::write(seeds.join(format!("s{i}")), bytes).unwrap();
    }
    seeds
}

fn finding_dirs(work: &Path) -> Vec<PathBuf> {
    let root = work.join("results/findings");
    let mut dirs: Vec<PathBuf> = match fs::read_dir(&root) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_dir())
            .collect(),
        Err(_) => Vec::new(),
    };
    dirs.sort();
    dirs
}

#[test]
fn relational_viewer_escape_is_found_persisted_replayed_and_minimized() {
    let dir = tempdir("escape");
    let launcher = write_launcher(&dir);
    let config = write_config(&dir, &launcher, r#""viewer-helper""#);
    // Seeds do NOT contain the marker byte; the campaign must reach it by mutation.
    let seeds = write_seeds(&dir, &[b"aaaa", b"bbbb"]);
    let work = dir.join("out");

    let out = Command::new(bhf_bin())
        .args([
            "relational",
            "run",
            "--config",
            config.to_str().unwrap(),
            "--seeds",
            seeds.to_str().unwrap(),
            "--out",
            work.to_str().unwrap(),
            "--max-execs",
            "100000",
            "--max-findings",
            "1",
            "--seed",
            "1",
            "--timeout-secs",
            "5",
        ])
        .env("BHF_RUNTRACE_SHIM", "off")
        .env("BHF_SECRET_VIEWER_TOKEN", "s3cr3t-viewer")
        .env("BHF_SECRET_ADMIN_TOKEN", "s3cr3t-admin")
        .output()
        .expect("spawn bhf relational run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a finding exits 1; stderr={stderr}"
    );

    // Exactly one finding (coverage-guided search stops at the first escape).
    let findings = finding_dirs(&work);
    assert_eq!(findings.len(), 1, "exactly one finding; stderr={stderr}");
    let finding_dir = &findings[0];
    let text = fs::read_to_string(finding_dir.join("finding.json")).unwrap();
    let finding: serde_json::Value = serde_json::from_str(&text).unwrap();

    // Acceptance #1/#2: the authorization-policy finding fired on the forbidden
    // target even though both roles exit 0 with identical stdout.
    assert_eq!(finding["rule_id"], "BHF-309");
    assert_eq!(finding["kind"], "allowlist_escape");
    assert_eq!(finding["classification"], "relational_violation");
    assert_eq!(finding["finding_kind"], "differential");
    assert_eq!(
        finding["profiles"].as_array().unwrap(),
        &vec![serde_json::json!("viewer")],
        "only viewer violates its allowlist"
    );
    let evidence = finding["evidence_events"].as_array().unwrap();
    assert!(
        evidence
            .iter()
            .any(|e| e["target"] == "administrator-helper"),
        "the forbidden launch is the evidence: {text}"
    );
    assert!(
        finding["profile_hashes"].get("viewer").is_some()
            && !finding["policy_hash"].as_str().unwrap().is_empty(),
        "finding records policy + per-profile hashes"
    );

    // Acceptance #8: no cross-profile contamination — the finding carries only
    // viewer's observation; administrator's events never leaked in.
    assert!(finding["observations"].get("administrator").is_none());
    assert!(finding["observations"].get("viewer").is_some());

    // Acceptance #9: the resolved secret is redacted everywhere it could appear;
    // the stable reference id remains in the persisted policy.
    assert!(
        !text.contains("s3cr3t-viewer") && !text.contains("s3cr3t-admin"),
        "resolved secret leaked into finding.json: {text}"
    );
    let policy = fs::read_to_string(work.join("results/relational-policy.toml")).unwrap();
    assert!(policy.contains("lab:viewer-token") && !policy.contains("s3cr3t"));

    // The unified index rebuilt and carries the relational finding.
    let doc: serde_json::Value =
        serde_json::from_slice(&fs::read(work.join("results/findings.json")).unwrap()).unwrap();
    assert!(doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["rule"]["id"] == "BHF-309" || f["rule_id"] == "BHF-309"));

    // Acceptance #5: replay re-runs every required profile and re-confirms.
    let replay = Command::new(bhf_bin())
        .args([
            "relational",
            "replay",
            "--finding",
            finding_dir.to_str().unwrap(),
        ])
        .env("BHF_RUNTRACE_SHIM", "off")
        .env("BHF_SECRET_VIEWER_TOKEN", "s3cr3t-viewer")
        .env("BHF_SECRET_ADMIN_TOKEN", "s3cr3t-admin")
        .output()
        .expect("spawn bhf relational replay");
    assert_eq!(
        replay.status.code(),
        Some(0),
        "replay reproduces; stderr={}",
        String::from_utf8_lossy(&replay.stderr)
    );
    let replay_json: serde_json::Value =
        serde_json::from_slice(&fs::read(finding_dir.join("replay.json")).unwrap()).unwrap();
    assert_eq!(replay_json["reproduced"], true);
    assert_eq!(
        replay_json["executed_profiles"].as_array().unwrap(),
        &vec![serde_json::json!("viewer")],
        "replay executes exactly the finding's required profiles"
    );
    // The replay bundle never carries a resolved secret.
    let replay_text = fs::read_to_string(finding_dir.join("replay.json")).unwrap();
    assert!(!replay_text.contains("s3cr3t"));

    // Acceptance #6: minimize preserves the smallest violating testcase and the
    // minimal required profile set.
    let original_len = fs::read(finding_dir.join("testcase.bin")).unwrap().len();
    let minimize = Command::new(bhf_bin())
        .args([
            "relational",
            "minimize",
            "--finding",
            finding_dir.to_str().unwrap(),
        ])
        .env("BHF_RUNTRACE_SHIM", "off")
        .env("BHF_SECRET_VIEWER_TOKEN", "s3cr3t-viewer")
        .env("BHF_SECRET_ADMIN_TOKEN", "s3cr3t-admin")
        .output()
        .expect("spawn bhf relational minimize");
    assert_eq!(
        minimize.status.code(),
        Some(0),
        "minimize ok; stderr={}",
        String::from_utf8_lossy(&minimize.stderr)
    );
    let min_json: serde_json::Value =
        serde_json::from_slice(&fs::read(finding_dir.join("minimize.json")).unwrap()).unwrap();
    assert_eq!(
        min_json["profiles"].as_array().unwrap(),
        &vec![serde_json::json!("viewer")],
        "the required profile set reduces to just viewer"
    );
    let min_bytes = fs::read(finding_dir.join("testcase.min.bin")).unwrap();
    assert!(min_bytes.len() <= original_len && !min_bytes.is_empty());
    assert!(
        min_bytes.contains(&b'z'),
        "the minimized testcase still carries the triggering marker"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn relational_declared_allowed_launch_is_not_a_finding() {
    let dir = tempdir("declared");
    let launcher = write_launcher(&dir);
    // viewer's allowlist now INCLUDES administrator-helper: launching it is a
    // declared, expected difference and must NOT become a finding.
    let config = write_config(
        &dir,
        &launcher,
        r#""viewer-helper", "administrator-helper""#,
    );
    // Seed already carries the marker, so viewer DOES launch administrator-helper
    // on the very first run — but it is declared in viewer's allowlist, so it must
    // stay compliant. Deterministic in a couple of execs.
    let seeds = write_seeds(&dir, &[b"zzzz"]);
    let work = dir.join("out");

    let out = Command::new(bhf_bin())
        .args([
            "relational",
            "run",
            "--config",
            config.to_str().unwrap(),
            "--seeds",
            seeds.to_str().unwrap(),
            "--out",
            work.to_str().unwrap(),
            "--max-execs",
            "5",
            "--seed",
            "1",
            "--timeout-secs",
            "5",
        ])
        // No secrets provided: the launcher skips the privileged-login line, so
        // viewer's spawned set is exactly {viewer-helper, administrator-helper} —
        // both declared in its allowlist here.
        .env("BHF_RUNTRACE_SHIM", "off")
        .output()
        .expect("spawn bhf relational run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "no findings => exit 0; {stderr}"
    );
    assert!(finding_dirs(&work).is_empty(), "no finding dirs: {stderr}");
    assert!(stderr.contains("violation=0"), "summary: {stderr}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn relational_missing_runner_is_setup_failure_not_a_finding() {
    let dir = tempdir("setup");
    let seeds = write_seeds(&dir, &[b"aaaa"]);
    let work = dir.join("out");
    // A viewer whose runner does not exist: the spawn fails, which must surface as
    // a distinct setup-failure outcome, never a policy finding or silent pass.
    let config_path = dir.join("relational.toml");
    fs::write(
        &config_path,
        r#"schema = "bhf.relational.v1"
[[profiles]]
name = "viewer"
runner = "/nonexistent/launcher-binary"
args = ["viewer"]
allowlist = ["viewer-helper"]
collector = "runtrace"
[[predicates]]
rule = "viewer spawned targets must be a subset of its allowlist"
require = { kind = "subset", set = "viewer.spawned", of = "viewer.allowlist" }
"#,
    )
    .unwrap();

    let out = Command::new(bhf_bin())
        .args([
            "relational",
            "run",
            "--config",
            config_path.to_str().unwrap(),
            "--seeds",
            seeds.to_str().unwrap(),
            "--out",
            work.to_str().unwrap(),
            "--max-execs",
            "5",
            "--seed",
            "1",
        ])
        .env("BHF_RUNTRACE_SHIM", "off")
        .output()
        .expect("spawn bhf relational run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "setup failure is not a finding; {stderr}"
    );
    assert!(finding_dirs(&work).is_empty());
    assert!(
        stderr.contains("setup=") && !stderr.contains("setup=0"),
        "setup failures are counted as their own distinct outcome: {stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn relational_help_lists_the_three_subcommands() {
    let out = Command::new(bhf_bin())
        .args(["relational", "--help"])
        .output()
        .expect("spawn bhf relational --help");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("run"), "help: {text}");
    assert!(text.contains("replay"), "help: {text}");
    assert!(text.contains("minimize"), "help: {text}");
}
