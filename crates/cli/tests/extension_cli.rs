// SPDX-License-Identifier: Apache-2.0

//! End-to-end CLI proof of the `bhf.extension.v1` out-of-process extension host
//! (#57), driven through the real `bhf extension` command and `bhf fuzz
//! --extension` with the `bhf_ext_mock` sidecar standing in for a trusted
//! extension. The mock speaks the actual length-framed JSON wire protocol, so
//! this exercises the whole host path — explicit manifest load (the trust
//! boundary), spawn, handshake + capability negotiation, `oracle.evaluate`,
//! finding emission with stable identity + provenance, and bounded fault
//! handling — without any private extension.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use cli::run_from;
use serde_json::Value;

fn bhf_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bhf"))
}

fn mock_extension() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bhf_ext_mock"))
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("bhf-extension-{name}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Write a `bhf.extension-manifest.v1` manifest into `dir` pointing at the mock
/// extension in `mode`, requiring `required_caps`.
fn write_manifest(dir: &Path, mode: &str, required_caps: &[&str]) -> PathBuf {
    let caps = required_caps
        .iter()
        .map(|c| format!("{c:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    let manifest = format!(
        "schema = \"bhf.extension-manifest.v1\"\n\
         id = \"mock-extension\"\n\
         executable = {exe:?}\n\
         args = [\"--mode\", {mode:?}]\n\
         required-capabilities = [{caps}]\n\
         allow-external-paths = true\n\
         \n\
         [limits]\n\
         call-timeout-ms = 5000\n",
        exe = mock_extension().to_str().unwrap(),
    );
    let path = dir.join("extension.toml");
    fs::write(&path, manifest).unwrap();
    path
}

/// Run `bhf extension <args...>` as a subprocess, returning the finished output.
fn run_extension(args: &[&str]) -> std::process::Output {
    Command::new(bhf_bin())
        .arg("extension")
        .args(args)
        .output()
        .unwrap()
}

/// Every `finding.json` under `<work>/results/findings/`.
fn findings(work: &Path) -> Vec<Value> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(work.join("results/findings")) {
        for entry in entries.flatten() {
            let finding = entry.path().join("finding.json");
            if finding.is_file() {
                out.push(serde_json::from_slice(&fs::read(&finding).unwrap()).unwrap());
            }
        }
    }
    out
}

fn extension_findings(work: &Path) -> Vec<Value> {
    findings(work)
        .into_iter()
        .filter(|f| f["confirmation"] == "extension")
        .collect()
}

// ── validate ─────────────────────────────────────────────────────────────

#[test]
fn extension_validate_negotiates_and_prints_caps_and_hashes() {
    let dir = temp_dir("validate-ok");
    let manifest = write_manifest(&dir, "well-behaved", &["oracle.evaluate"]);

    let output = run_extension(&["validate", "--manifest", manifest.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "validate failed: {:?}\n{stdout}\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    // The negotiated protocol version, the required + negotiated capability, and a
    // 64-hex executable sha256 are all reported.
    assert!(stdout.contains("bhf.extension.v1"), "protocol: {stdout}");
    assert!(stdout.contains("oracle.evaluate"), "capability: {stdout}");
    assert!(
        stdout.contains("executable sha256:"),
        "executable hash: {stdout}"
    );
}

#[test]
fn extension_validate_json_reports_hashes_and_negotiated_caps() {
    let dir = temp_dir("validate-json");
    let manifest = write_manifest(&dir, "well-behaved", &["oracle.evaluate"]);

    let output = run_extension(&[
        "validate",
        "--manifest",
        manifest.to_str().unwrap(),
        "--json",
    ]);
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["protocol_version"], "bhf.extension.v1");
    assert_eq!(report["negotiated_capabilities"][0], "oracle.evaluate");
    assert_eq!(report["required_capabilities"][0], "oracle.evaluate");
    let exe_hash = report["executable_sha256"].as_str().unwrap();
    assert_eq!(exe_hash.len(), 64, "executable sha256 is 64 hex chars");
    assert!(exe_hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn extension_validate_exits_nonzero_on_unsatisfied_required_cap() {
    let dir = temp_dir("validate-missing-cap");
    // The mock in `no-cap` mode advertises only `codec.decode`, so a manifest that
    // requires `oracle.evaluate` must fail negotiation up front.
    let manifest = write_manifest(&dir, "no-cap", &["oracle.evaluate"]);

    let output = run_extension(&["validate", "--manifest", manifest.to_str().unwrap()]);
    assert!(
        !output.status.success(),
        "must reject a missing required cap"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("oracle.evaluate"),
        "error must name the missing cap: {stderr}"
    );
    // No campaign/work artifacts are produced by validate.
    assert!(!dir.join("results").exists());
}

#[test]
fn extension_validate_refuses_without_explicit_manifest() {
    // No `--manifest`: clap rejects it (never auto-discovers an extension).
    let output = run_extension(&["validate"]);
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(2), "clap usage error");
}

// ── evaluate ─────────────────────────────────────────────────────────────

/// Drive `bhf extension evaluate` on `input_bytes` through the mock in `mode`,
/// returning (exit code, work dir).
fn run_evaluate(name: &str, mode: &str, input_bytes: &[u8]) -> (i32, PathBuf) {
    let dir = temp_dir(name);
    let manifest = write_manifest(&dir, mode, &["oracle.evaluate"]);
    let input = dir.join("input.bin");
    fs::write(&input, input_bytes).unwrap();
    let work = dir.join("work");
    let output = run_extension(&[
        "evaluate",
        "--manifest",
        manifest.to_str().unwrap(),
        "--input",
        input.to_str().unwrap(),
        "--work",
        work.to_str().unwrap(),
    ]);
    (output.status.code().unwrap_or(-1), work)
}

#[test]
fn extension_evaluate_emits_finding_for_clean_exit_violation() {
    // "../etc/passwd" is a clean-exit semantic violation (a crash-only fuzzer
    // cannot see it) — the oracle flags it as a finding.
    let (code, work) = run_evaluate("evaluate-finding", "well-behaved", b"../etc/passwd");
    assert_eq!(code, 1, "a finding must use the finding exit code");

    let ext = extension_findings(&work);
    assert_eq!(ext.len(), 1, "exactly one extension finding");
    let finding = &ext[0];
    assert_eq!(finding["confirmation"], "extension");
    assert_eq!(finding["classification"], "extension_oracle");
    assert_eq!(finding["rule_id"], "oracle.path-escape");
    // Provenance records the executable/config hashes, protocol version, and caps.
    let prov = &finding["extension"];
    assert_eq!(prov["protocol_version"], "bhf.extension.v1");
    assert_eq!(prov["negotiated_caps"][0], "oracle.evaluate");
    assert_eq!(prov["executable_sha256"].as_str().unwrap().len(), 64);
    assert!(prov["config_sha256"].is_string(), "config hash recorded");

    // The run-level provenance file records the same session facts + the result.
    let run: Value =
        serde_json::from_slice(&fs::read(work.join("extension.json")).unwrap()).unwrap();
    assert_eq!(run["result"], "finding");
    assert_eq!(run["findings"], 1);
    assert_eq!(run["provenance"]["protocol_version"], "bhf.extension.v1");
    assert_eq!(
        run["provenance"]["executable_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
}

#[test]
fn extension_evaluate_benign_input_is_clean() {
    let (code, work) = run_evaluate("evaluate-clean", "well-behaved", b"a-safe-relative-path");
    assert_eq!(code, 0, "a benign input exits clean");
    assert!(
        extension_findings(&work).is_empty(),
        "no finding for a benign input"
    );
    let run: Value =
        serde_json::from_slice(&fs::read(work.join("extension.json")).unwrap()).unwrap();
    assert_eq!(run["result"], "ok");
    assert_eq!(run["findings"], 0);
}

#[test]
fn extension_evaluate_reemits_same_stable_signature() {
    // The same violation evaluated twice yields the identical finding signature —
    // the property replay and minimize rely on.
    let (_c1, w1) = run_evaluate("evaluate-sig-a", "well-behaved", b"../etc/passwd");
    let (_c2, w2) = run_evaluate("evaluate-sig-b", "well-behaved", b"../etc/passwd");
    let s1 = extension_findings(&w1)[0]["signature"]
        .as_str()
        .unwrap()
        .to_owned();
    let s2 = extension_findings(&w2)[0]["signature"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        s1, s2,
        "identical violations must reproduce the same signature"
    );
    assert_eq!(s1.len(), 64);
}

#[test]
fn extension_fault_is_not_a_target_finding() {
    // The extension crashes mid-evaluate: a bounded infrastructure result, NEVER a
    // target finding, with an exit code distinct from clean and from finding.
    let (code, work) = run_evaluate("evaluate-crash", "crash", b"../etc/passwd");
    assert_ne!(code, 0, "a fault is not clean");
    assert_ne!(code, 1, "a fault is not a finding");
    assert!(
        extension_findings(&work).is_empty(),
        "an extension crash must not produce a target finding"
    );
    let run: Value =
        serde_json::from_slice(&fs::read(work.join("extension.json")).unwrap()).unwrap();
    assert_eq!(run["findings"], 0);
    assert!(
        run["result"]
            .as_str()
            .unwrap()
            .contains("infrastructure_error"),
        "result records the bounded fault: {}",
        run["result"]
    );
    // A terminal crash with no restart budget is recorded as a loss event.
    assert!(run["provenance"]["loss_count"].as_u64().unwrap() >= 1);
}

#[test]
fn extension_malformed_response_is_infrastructure_not_finding() {
    let (code, work) = run_evaluate("evaluate-malformed", "malformed", b"../etc/passwd");
    assert_ne!(code, 0);
    assert_ne!(code, 1);
    assert!(extension_findings(&work).is_empty());
}

#[test]
fn extension_tampered_case_identity_is_rejected() {
    // The mock echoes a DIFFERENT worker in the response; the host must reject the
    // case-identity mismatch as infrastructure, never a finding — the guard that
    // keeps two workers from ever mixing test-case identity.
    let (code, work) = run_evaluate("evaluate-tamper", "tamper-case", b"../etc/passwd");
    assert_ne!(code, 1, "a case mismatch is not a finding");
    assert!(extension_findings(&work).is_empty());
}

/// The release-build round-trip the dedicated per-PR `--release` CI step targets.
#[test]
fn release_profile_mock_oracle_end_to_end() {
    let (code, work) = run_evaluate("release-e2e", "well-behaved", b"../../secret/key");
    assert_eq!(code, 1);
    let ext = extension_findings(&work);
    assert_eq!(ext.len(), 1);
    assert_eq!(ext[0]["confirmation"], "extension");
    assert_eq!(ext[0]["rule_id"], "oracle.path-escape");
    assert!(work.join("extension.json").is_file());
}

// ── bhf fuzz --extension ───────────────────────────────────────────────────

fn install_fake_harness(work_dir: &Path, harness_id: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let harness = PathBuf::from(env!("CARGO_BIN_EXE_cli_fake_harness"));
    let target = work_dir
        .join("build")
        .join(harness_id)
        .join("obj")
        .join("main");
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::copy(&harness, &target).unwrap();
    let mut perms = fs::metadata(&target).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&target, perms).unwrap();
    target
}

#[test]
fn fuzz_with_extension_drives_evaluate_on_retained_inputs() {
    let dir = temp_dir("fuzz-extension");
    let work_dir = dir.join("bhf_work");
    let harness_id = "H-TEST";
    install_fake_harness(&work_dir, harness_id);
    // The fake harness only crashes on inputs containing "crash"; "../etc/passwd"
    // is benign to the harness (no crash finding) but is a clean-exit semantic
    // violation the extension oracle flags.
    let manifest = write_manifest(&dir, "well-behaved", &["oracle.evaluate"]);

    let fuzz_exit = run_from(vec![
        "bhf".to_string(),
        "fuzz".to_string(),
        work_dir.to_str().unwrap().to_string(),
        "--harness".to_string(),
        harness_id.to_string(),
        "--iterations".to_string(),
        "1".to_string(),
        "--seed-input".to_string(),
        "../etc/passwd".to_string(),
        "--extension".to_string(),
        manifest.to_str().unwrap().to_string(),
    ]);
    assert_eq!(fuzz_exit, 0, "an extension fault never aborts the campaign");

    // The run summary carries the additive extension block.
    let summary: Value =
        serde_json::from_slice(&fs::read(work_dir.join("fuzz_runs/H-TEST-latest.json")).unwrap())
            .unwrap();
    assert_eq!(summary["schema_version"], 1, "summary schema is unchanged");
    assert_eq!(summary["extension"]["active"], true, "{summary}");
    assert!(
        summary["extension"]["evaluated"].as_u64().unwrap() >= 1,
        "retained inputs were evaluated: {summary}"
    );
    assert_eq!(summary["extension"]["findings"], 1, "{summary}");
    assert_eq!(summary["extension"]["protocol_version"], "bhf.extension.v1");

    // A replayable extension finding was emitted, distinct from any crash finding.
    let ext = extension_findings(&work_dir);
    assert_eq!(ext.len(), 1, "one extension finding");
    assert_eq!(ext[0]["rule_id"], "oracle.path-escape");
    assert_eq!(ext[0]["extension"]["protocol_version"], "bhf.extension.v1");
}

#[test]
fn fuzz_extension_fault_never_aborts_campaign_nor_becomes_a_finding() {
    let dir = temp_dir("fuzz-extension-fault");
    let work_dir = dir.join("bhf_work");
    let harness_id = "H-TEST";
    install_fake_harness(&work_dir, harness_id);
    let manifest = write_manifest(&dir, "crash", &["oracle.evaluate"]);

    let fuzz_exit = run_from(vec![
        "bhf".to_string(),
        "fuzz".to_string(),
        work_dir.to_str().unwrap().to_string(),
        "--harness".to_string(),
        harness_id.to_string(),
        "--iterations".to_string(),
        "1".to_string(),
        "--seed-input".to_string(),
        "../etc/passwd".to_string(),
        "--extension".to_string(),
        manifest.to_str().unwrap().to_string(),
    ]);
    assert_eq!(
        fuzz_exit, 0,
        "an extension crash must not abort the campaign"
    );
    assert!(
        extension_findings(&work_dir).is_empty(),
        "an extension fault never becomes a target finding"
    );
}
