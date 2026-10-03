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

// ── session (codec / mutator / scenario / lifecycle) ────────────────────────

/// Drive `bhf extension session` with the full capability surface, returning
/// (exit code, work dir, the run's `extension.json`).
fn run_session(name: &str, input_bytes: &[u8], extra: &[&str]) -> (i32, PathBuf, Value) {
    let dir = temp_dir(name);
    // The session caps are requested as optional by the command, so the manifest
    // need only require `oracle.evaluate`.
    let manifest = write_manifest(&dir, "well-behaved", &["oracle.evaluate"]);
    let input = dir.join("input.bin");
    fs::write(&input, input_bytes).unwrap();
    let work = dir.join("work");
    let mut args = vec![
        "session",
        "--manifest",
        manifest.to_str().unwrap(),
        "--input",
        input.to_str().unwrap(),
        "--work",
        work.to_str().unwrap(),
        "--json",
    ];
    args.extend_from_slice(extra);
    let output = run_extension(&args);
    let run: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    (output.status.code().unwrap_or(-1), work, run)
}

#[test]
fn extension_session_binds_open_handle_into_write_and_flags_escape() {
    // The scenario drives OPEN(path) then WRITE(handle, data): the target returns
    // a handle for OPEN, the extension binds it into WRITE, and the clean-exit
    // escape is a finding.
    let (code, work, run) = run_session("session-escape", b"../etc/passwd", &[]);
    assert_eq!(code, 1, "a session escape is a finding: {run}");

    let ext = extension_findings(&work);
    assert_eq!(ext.len(), 1, "exactly one session finding");
    assert_eq!(ext[0]["rule_id"], "oracle.path-escape");
    assert_eq!(ext[0]["extension"]["protocol_version"], "bhf.extension.v1");

    // The session record proves the OPEN handle reached the WRITE: the target
    // resolved the WRITE's handle back to the OPEN path (so the write lands
    // outside root). A failed binding would leave `wrote_outside_root` false.
    let session = &run["session"];
    assert_eq!(session["messages_sent"], 2, "OPEN then WRITE: {run}");
    let target = &session["target"];
    assert_eq!(target["all_frames_valid"], true, "{run}");
    assert_eq!(target["writes"], 1);
    assert_eq!(
        target["wrote_outside_root"], true,
        "the bound WRITE handle resolved to the escaping OPEN path: {run}"
    );
    // The WRITE step is labelled and used a real handle (not the unbound "0").
    let write = session["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["label"] == "WRITE")
        .expect("a WRITE step");
    assert_eq!(write["step"], 1);
    assert_ne!(
        target["write_paths"][0]["handle"], "0",
        "the handle was bound from the OPEN response: {run}"
    );
}

#[test]
fn extension_session_benign_path_is_clean_no_finding() {
    let (code, work, run) = run_session("session-clean", b"logs/run-01.txt", &[]);
    assert_eq!(code, 0, "a benign path exits clean: {run}");
    assert!(extension_findings(&work).is_empty());
    assert_eq!(run["session"]["target"]["wrote_outside_root"], false);
}

#[test]
fn extension_session_repairs_mutated_frame_before_it_reaches_target() {
    // With mutation but NO repair, the target sees malformed frames.
    let (_c, _w, no_repair) = run_session(
        "session-norepair",
        b"logs/run.txt",
        &["--mutate", "153", "--repair", "false"],
    );
    assert_eq!(no_repair["session"]["mutated"], true, "{no_repair}");
    assert_eq!(no_repair["session"]["repaired"], false);
    assert_eq!(
        no_repair["session"]["target"]["all_frames_valid"], false,
        "an unrepaired mutation corrupts the frame at the target: {no_repair}"
    );

    // With repair on, every mutated frame reaches the target well-formed.
    let (_c2, _w2, repaired) = run_session(
        "session-repair",
        b"logs/run.txt",
        &["--mutate", "153", "--repair", "true"],
    );
    assert_eq!(repaired["session"]["mutated"], true);
    assert_eq!(repaired["session"]["repaired"], true, "{repaired}");
    assert_eq!(
        repaired["session"]["target"]["all_frames_valid"], true,
        "repair makes the mutated frame well-formed at the target: {repaired}"
    );
}

#[test]
fn extension_session_reemits_same_stable_signature() {
    // The session finding replays/minimizes to the same stable signature: the same
    // violation evaluated again yields the identical signature (and it equals the
    // standalone `evaluate` signature for the same path — the minimization
    // predicate re-check).
    let (_c1, w1, _r1) = run_session("session-sig-a", b"../etc/passwd", &[]);
    let (_c2, w2, _r2) = run_session("session-sig-b", b"../etc/passwd", &[]);
    let s1 = extension_findings(&w1)[0]["signature"]
        .as_str()
        .unwrap()
        .to_owned();
    let s2 = extension_findings(&w2)[0]["signature"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(s1, s2, "session findings replay to the same signature");

    let (_c3, w3) = run_evaluate("session-sig-eval", "well-behaved", b"../etc/passwd");
    let s3 = extension_findings(&w3)[0]["signature"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        s1, s3,
        "the session finding and the oracle predicate agree on the signature"
    );
}

#[test]
fn extension_session_crash_is_bounded_not_a_finding() {
    let dir = temp_dir("session-crash");
    let manifest = write_manifest(&dir, "crash", &["oracle.evaluate"]);
    let input = dir.join("input.bin");
    fs::write(&input, b"../etc/passwd").unwrap();
    let work = dir.join("work");
    let output = run_extension(&[
        "session",
        "--manifest",
        manifest.to_str().unwrap(),
        "--input",
        input.to_str().unwrap(),
        "--work",
        work.to_str().unwrap(),
    ]);
    let code = output.status.code().unwrap_or(-1);
    assert_ne!(code, 1, "a crash is not a finding");
    assert!(
        extension_findings(&work).is_empty(),
        "an extension crash never becomes a target finding"
    );
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

    // The fuzz pass negotiated `codec.repair`; a raw (non-frame) corpus entry is
    // `reject`ed by the extension and evaluated verbatim (0 repaired), so the host
    // stays codec-agnostic over arbitrary corpora.
    assert_eq!(
        summary["extension"]["codec_repair_available"], true,
        "{summary}"
    );
    assert_eq!(summary["extension"]["repaired"], 0, "{summary}");
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
