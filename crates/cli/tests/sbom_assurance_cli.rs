// SPDX-License-Identifier: Apache-2.0
//! Exercise inventory review and exit-code contracts through the real CLI.
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    out: PathBuf,
    db: PathBuf,
}

impl Fixture {
    fn new(version: &str, severity: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("source");
        let out = temp.path().join("reports");
        let db = temp.path().join("advisories.json");
        fs::create_dir(&root).unwrap();
        write_json(&root.join("component.json"), json!({
            "name": "example", "version": version, "ecosystem": "npm",
            "type": "library", "purl": format!("pkg:npm/example@{version}")
        }));
        write_json(&db, json!({"vulnerabilities": [{
            "id": "CVE-2026-TEST", "severity": severity, "summary": "test advisory",
            "package": {"ecosystem": "npm", "name": "example"},
            "affected_versions": [version],
            "fixed_versions": ["1.5.9", "2.4.3"], "patched_version": "3.0.0"
        }]}));
        Self { _temp: temp, root, out, db }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_bhf"))
            .arg("sbom").arg(&self.root).arg("--out").arg(&self.out)
            .arg("--vuln-db").arg(&self.db).args(args)
            .output().expect("run bhf sbom")
    }

    fn read(&self, name: &str) -> Value {
        serde_json::from_slice(&fs::read(self.out.join(name)).unwrap()).unwrap()
    }
}

fn write_json(path: &Path, value: Value) {
    fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}

fn assert_exit(output: &Output, expected: i32) {
    assert_eq!(output.status.code(), Some(expected), "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}

#[test]
fn default_reports_preserve_advisory_matches_without_unsupported_clearance() {
    let f = Fixture::new("2.4.2", "high");
    assert_exit(&f.run(&[]), 0);
    let queue = f.read("vex-review.json");
    assert_eq!(queue["counts"]["matches"], 1);
    assert_eq!(queue["counts"]["requiring_review"], 1);
    let entry = &queue["entries"][0];
    assert_eq!(entry["id"], "CVE-2026-TEST");
    assert_eq!(entry["product_id"], "pkg:npm/example@2.4.2");
    assert_eq!(entry["advisory_fixed_versions"], json!(["1.5.9", "2.4.3", "3.0.0"]));
    assert!(!entry["next_action"].as_str().unwrap().is_empty());
    let openvex = f.read("openvex.json");
    assert_eq!(openvex["statements"][0]["status"], "under_investigation");
    assert!(openvex["statements"][0].get("justification").is_none());
    assert_eq!(f.read("cyclonedx.json")["vulnerabilities"][0]["analysis"]["state"], "in_triage");
}

#[test]
fn review_gate_blocks_low_severity_even_when_severity_gate_would_pass() {
    let f = Fixture::new("2.4.2", "low");
    assert_exit(&f.run(&["--fail-on", "critical"]), 0);
    let output = f.run(&["--fail-on", "critical", "--fail-on-unreviewed"]);
    assert_exit(&output, 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("review gate blocked"));
    assert_eq!(f.read("vex-review.json")["entries"].as_array().unwrap().len(), 1);
    assert!(f.out.join("sbom.json").is_file());
}

#[test]
fn severity_gate_still_blocks_without_the_new_review_flag() {
    let f = Fixture::new("2.4.2", "high");
    assert_exit(&f.run(&["--fail-on", "high"]), 1);
}

#[test]
fn review_gate_forces_queue_with_an_otherwise_narrow_emit_set() {
    let f = Fixture::new("2.4.2", "low");
    assert_exit(&f.run(&["--emit", "sbom", "--fail-on-unreviewed"]), 1);
    assert!(f.out.join("sbom.json").is_file());
    assert!(f.out.join("vex-review.json").is_file());
    assert!(!f.out.join("openvex.json").exists());
    assert_eq!(fs::read_dir(&f.out).unwrap().count(), 2);
}

#[test]
fn review_only_selection_is_independent_and_deterministic() {
    let f = Fixture::new("2.4.2", "low");
    assert_exit(&f.run(&["--emit", "vex-review"]), 0);
    let before = fs::read(f.out.join("vex-review.json")).unwrap();
    assert_exit(&f.run(&["--emit", "vex-review"]), 0);
    assert_eq!(before, fs::read(f.out.join("vex-review.json")).unwrap());
    assert_eq!(fs::read_dir(&f.out).unwrap().count(), 1);
}

#[test]
fn review_gate_requires_an_explicit_advisory_database() {
    let f = Fixture::new("2.4.2", "low");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("sbom").arg(&f.root).arg("--out").arg(&f.out)
        .arg("--fail-on-unreviewed").output().unwrap();
    assert_exit(&output, 2);
    assert!(String::from_utf8_lossy(&output.stderr).contains("--vuln-db"));
    assert!(!f.out.join("vex-review.json").exists());
}

#[test]
fn valid_empty_database_yields_a_scoped_empty_queue_not_a_safety_claim() {
    let f = Fixture::new("2.4.2", "low");
    write_json(&f.db, json!({"vulnerabilities": []}));
    assert_exit(&f.run(&["--fail-on-unreviewed"]), 0);
    let queue = f.read("vex-review.json");
    assert_eq!(queue["counts"]["requiring_review"], 0);
    assert_eq!(queue["assessment_scope"], "matched_advisories_only");
}

#[test]
fn malformed_database_cannot_masquerade_as_a_successful_empty_review() {
    for db in [json!({}), json!({"vulnerabilities": {}}),
        json!({"vulnerabilities": [null]}), json!({"vulnerabilities": [{}]}),
        json!({"vulnerabilities": [{"id": "CVE-X", "package": {"name": "example", "ecosystem": "npm"}, "affected_versions": "2.4.2"}]})] {
        let f = Fixture::new("2.4.2", "low");
        write_json(&f.db, db);
        assert_exit(&f.run(&["--fail-on-unreviewed"]), 1);
        assert!(!f.out.join("vex-review.json").exists());
    }
}

#[test]
fn missing_or_invalid_json_database_is_an_error_not_a_clean_scan() {
    let f = Fixture::new("2.4.2", "low");
    fs::remove_file(&f.db).unwrap();
    assert_exit(&f.run(&["--fail-on-unreviewed"]), 1);
    fs::write(&f.db, b"{not json").unwrap();
    assert_exit(&f.run(&["--fail-on-unreviewed"]), 1);
}

#[test]
fn prerelease_version_does_not_inherit_a_final_release_fix() {
    let f = Fixture::new("3.0.0-rc1", "high");
    assert_exit(&f.run(&["--fail-on-unreviewed"]), 1);
    assert_eq!(f.read("openvex.json")["statements"][0]["status"], "under_investigation");
    assert!(f.read("vex-review.json")["entries"][0]["status_notes"].as_str().unwrap().contains("not a verified fix"));
}
