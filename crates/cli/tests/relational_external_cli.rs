// SPDX-License-Identifier: Apache-2.0
//! End-to-end `bhf relational` tests for the **external-comparator** predicate
//! (#61): a relational config whose `external` predicate names a trusted
//! `bhf.extension.v1` comparator extension (the dependency-free
//! `bhf_relational_comparator_ext` reference fixture). The driver spawns and
//! negotiates the comparator, serializes the secret-redacted cross-profile
//! observation bundle, and drives `oracle.evaluate`:
//!
//! * a `finding` verdict over a policy-violating bundle becomes a real relational
//!   finding (`BHF-312`) carrying the comparator's signature/classification and
//!   the trusted-extension provenance;
//! * an `unsupported`/undecidable verdict maps to `PolicyUnknown` — not a finding,
//!   not compliant;
//! * a comparator manifest that does not load fails the run up front.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bhf_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bhf"))
}

fn comparator_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bhf_relational_comparator_ext"))
}

fn tempdir(tag: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("bhf-relational-ext-{tag}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A `bhf.extension-manifest.v1` manifest pointing at the reference comparator.
fn write_manifest(dir: &Path) -> PathBuf {
    let path = dir.join("comparator.toml");
    let manifest = format!(
        "schema = \"bhf.extension-manifest.v1\"\n\
         id = \"relational-comparator\"\n\
         executable = {exe:?}\n\
         required-capabilities = [\"oracle.evaluate\"]\n\
         allow-external-paths = true\n\
         \n\
         [limits]\n\
         call-timeout-ms = 5000\n",
        exe = comparator_bin().to_str().unwrap(),
    );
    fs::write(&path, manifest).unwrap();
    path
}

/// The issue's toy launcher: `viewer` reaches the forbidden `administrator-helper`
/// only on a crafted input (contains the marker byte `z`); both roles exit 0 with
/// identical stdout, so the only signal is the effect event in the bundle.
fn write_launcher(dir: &Path) -> PathBuf {
    let path = dir.join("launcher.sh");
    let script = r#"#!/bin/sh
role="$1"
log="$BHF_RUNTRACE_LOG"
inp="$BHF_RELATIONAL_INPUT"
printf '{"e":"exec","a":"execve","p":"%s-helper"}\n' "$role" >> "$log"
if [ "$role" = administrator ]; then
    printf '{"e":"exec","a":"execve","p":"administrator-helper"}\n' >> "$log"
elif [ "$role" = viewer ]; then
    if grep -q z "$inp" 2>/dev/null; then
        printf '{"e":"exec","a":"execve","p":"administrator-helper"}\n' >> "$log"
    fi
fi
printf 'ok\n'
exit 0
"#;
    fs::write(&path, script).unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).unwrap();
    path
}

fn write_seed(dir: &Path, bytes: &[u8]) -> PathBuf {
    let seeds = dir.join("seeds");
    fs::create_dir_all(&seeds).unwrap();
    fs::write(seeds.join("s0"), bytes).unwrap();
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

/// The comparator flags viewer's forbidden reach into `administrator-helper` as a
/// `finding` → a real relational finding (`BHF-312`) carrying the comparator's
/// signature/classification and the trusted-extension provenance.
#[test]
fn relational_external_comparator_finding_is_persisted_with_provenance() {
    let dir = tempdir("finding");
    let launcher = write_launcher(&dir);
    let manifest = write_manifest(&dir);
    let config = dir.join("relational.toml");
    fs::write(
        &config,
        format!(
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

[[profiles]]
name = "viewer"
runner = "/bin/sh"
args = ["{launcher}", "viewer"]
allowlist = ["viewer-helper"]
collector = "runtrace"

[[predicates]]
rule = "a trusted comparator decides the cross-profile relation"
require = {{ kind = "external", comparator = "{manifest}" }}
"#,
            launcher = launcher.display(),
            manifest = manifest.display(),
        ),
    )
    .unwrap();
    // The seed already carries the marker, so viewer reaches the forbidden target
    // on the very first exec.
    let seeds = write_seed(&dir, b"zzzz");
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
            "--max-findings",
            "1",
            "--seed",
            "1",
            "--timeout-secs",
            "5",
        ])
        .env("BHF_RUNTRACE_SHIM", "off")
        .output()
        .expect("spawn bhf relational run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a finding exits 1; stderr={stderr}"
    );

    let findings = finding_dirs(&work);
    assert_eq!(
        findings.len(),
        1,
        "exactly one external finding; stderr={stderr}"
    );
    let text = fs::read_to_string(findings[0].join("finding.json")).unwrap();
    let finding: serde_json::Value = serde_json::from_str(&text).unwrap();

    assert_eq!(finding["rule_id"], "BHF-312");
    assert_eq!(finding["kind"], "external_comparator");
    assert_eq!(finding["classification"], "relational_violation");
    assert_eq!(finding["finding_kind"], "differential");

    // The comparator's own verdict rode into the relational finding.
    let ext = &finding["external"];
    assert_eq!(ext["classification"], "relational_external");
    assert!(
        ext["signature"].as_str().map(|s| s.len()) == Some(64),
        "comparator signature is a 64-hex sha256: {text}"
    );
    assert_eq!(ext["comparator"], manifest.display().to_string());
    // Trusted-extension provenance: protocol version + a 64-hex executable hash.
    let prov = &ext["provenance"];
    assert_eq!(prov["protocol_version"], "bhf.extension.v1");
    assert_eq!(prov["executable_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(prov["negotiated_caps"][0], "oracle.evaluate");

    // Both profiles are recorded as involved (the comparator saw the whole bundle).
    let profiles = finding["profiles"].as_array().unwrap();
    assert!(profiles.contains(&serde_json::json!("viewer")));
    assert!(profiles.contains(&serde_json::json!("administrator")));

    // The unified index resolved the new BHF-312 rule.
    let doc: serde_json::Value =
        serde_json::from_slice(&fs::read(work.join("results/findings.json")).unwrap()).unwrap();
    assert!(doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["rule"]["id"] == "BHF-312" || f["rule_id"] == "BHF-312"));

    assert!(stderr.contains("violation=1"), "summary: {stderr}");
    let _ = fs::remove_dir_all(&dir);
}

/// An `unsupported`/undecidable comparator verdict maps to `PolicyUnknown`: not a
/// finding and not compliant. The viewer exits an unmapped code, so its status is
/// `unknown` and the comparator declines to decide.
#[test]
fn relational_external_comparator_unknown_maps_to_policy_unknown() {
    let dir = tempdir("unknown");
    let manifest = write_manifest(&dir);
    let config = dir.join("relational.toml");
    fs::write(
        &config,
        format!(
            r#"schema = "bhf.relational.v1"
[status_map]
allowed = [0]
denied = [77]

[[profiles]]
name = "administrator"
runner = "/bin/sh"
args = ["-c", "exit 0"]
collector = "none"

[[profiles]]
name = "viewer"
runner = "/bin/sh"
args = ["-c", "exit 9"]
collector = "none"

[[predicates]]
rule = "a trusted comparator decides the cross-profile relation"
require = {{ kind = "external", comparator = "{manifest}" }}
"#,
            manifest = manifest.display(),
        ),
    )
    .unwrap();
    let seeds = write_seed(&dir, b"aaaa");
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
            "3",
            "--seed",
            "1",
            "--timeout-secs",
            "5",
        ])
        .env("BHF_RUNTRACE_SHIM", "off")
        .output()
        .expect("spawn bhf relational run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "unknown is not a finding; {stderr}"
    );
    assert!(finding_dirs(&work).is_empty(), "no finding dirs: {stderr}");
    // The undecidable verdict is counted as its own distinct outcome, never as a
    // violation and never as compliance.
    assert!(
        stderr.contains("unknown=") && !stderr.contains("unknown=0"),
        "policy-unknown is counted distinctly: {stderr}"
    );
    assert!(stderr.contains("violation=0"), "no violation: {stderr}");
    let _ = fs::remove_dir_all(&dir);
}

/// A comparator manifest that does not load fails the run up front (the
/// explicit-load trust boundary), rather than silently skipping the predicate.
#[test]
fn relational_external_bad_comparator_manifest_fails_fast() {
    let dir = tempdir("bad-manifest");
    let config = dir.join("relational.toml");
    fs::write(
        &config,
        r#"schema = "bhf.relational.v1"
[[profiles]]
name = "viewer"
runner = "/bin/sh"
args = ["-c", "exit 0"]
collector = "none"
[[predicates]]
rule = "a trusted comparator decides the cross-profile relation"
require = { kind = "external", comparator = "/nonexistent/comparator.toml" }
"#,
    )
    .unwrap();
    let seeds = write_seed(&dir, b"aaaa");
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
            "1",
        ])
        .env("BHF_RUNTRACE_SHIM", "off")
        .output()
        .expect("spawn bhf relational run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a bad comparator manifest fails the run: {stderr}"
    );
    assert!(
        stderr.contains("comparator") || stderr.contains("manifest"),
        "the error names the unloadable comparator: {stderr}"
    );
    assert!(finding_dirs(&work).is_empty());
    let _ = fs::remove_dir_all(&dir);
}
