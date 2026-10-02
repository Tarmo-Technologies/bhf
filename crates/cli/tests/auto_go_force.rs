// SPDX-License-Identifier: Apache-2.0
//
// `auto --force` on the Go lane. Feed needs a receiver and skips without the
// flag. Render takes raw bytes plus a data-only map and is now driven by a
// length-prefixed raw field followed by a JSON field without force.
//
// Forced Feed is called on a synthesized zero receiver. Its findings must be
// marked `forced` and floored to `low`; Render stays an unforced campaign.
//
// Skips cleanly when no `go` toolchain is installed (the GNAT-less rule).

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/go_force")
        .canonicalize()
        .expect("canonicalize go_force fixture")
}

fn bhf_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe path");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("bhf")
}

fn have_go() -> bool {
    Command::new("go")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run(tag: &str, force: bool) -> (PathBuf, serde_json::Value) {
    let src = std::env::temp_dir().join(format!("bhf_goforce_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&src);
    copy_dir(&fixture(), &src).expect("copy go fixture module");
    let work = std::env::temp_dir().join(format!("bhf_goforce_w_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);

    let mut cmd = Command::new(bhf_bin());
    cmd.args([
        "auto",
        "--per-target-time",
        "8",
        "--single-pass",
        "--jobs",
        "1",
        "--work-dir",
        work.to_str().unwrap(),
        src.to_str().unwrap(),
    ]);
    if force {
        cmd.arg("--force");
    }
    // The exit status is not asserted: a run where NOTHING fuzzed exits non-zero by
    // design, and the unforced arm is exactly that run. What is under test is the
    // recorded outcome, so read run.json either way.
    let out = cmd.output().expect("run bhf auto");
    assert!(
        work.join("auto/run.json").is_file(),
        "no run.json written: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).expect("run.json"))
            .expect("parse run.json");
    let _ = std::fs::remove_dir_all(&src);
    (work, json)
}

#[test]
fn unforced_go_method_skips_while_data_map_fuzzes() {
    if !have_go() {
        eprintln!("skipping: no go toolchain on PATH (GNAT-less rule)");
        return;
    }
    let (work, json) = run("plain", false);
    assert_eq!(
        json["summary"]["unsupported_params"], 1,
        "only the receiver still needs --force: {json}"
    );
    assert_eq!(json["summary"]["built_and_fuzzed"], 1);
    let reasons = json["targets"].to_string();
    assert!(
        reasons.contains("needs a receiver value"),
        "the method must say what is missing: {reasons}"
    );
    let render = json["targets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|target| target["name"] == "Render")
        .unwrap();
    assert_eq!(render["outcome"]["outcome"], "built_and_fuzzed");
    assert!(
        render["outcome"]["passes"][0]["coverage_edges"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );
    assert_eq!(
        render["outcome"]["passes"][0]["target_entry_observed"],
        true
    );
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn forced_go_targets_build_fuzz_and_are_marked_forced() {
    if !have_go() {
        eprintln!("skipping: no go toolchain on PATH (GNAT-less rule)");
        return;
    }
    let (work, json) = run("forced", true);
    assert_eq!(
        json["summary"]["built_and_fuzzed"], 2,
        "both targets fuzz once forced: {json}"
    );
    // Only Feed used a synthesized receiver; Render's map came from input.
    assert_eq!(json["summary"]["forced"], 1, "{json}");

    // The synthesized value is recorded on the target, naming what was fabricated.
    let targets = json["targets"].to_string();
    assert!(
        targets.contains("forced_synthetic_params"),
        "the forced synthesis must be on the repair ledger: {targets}"
    );
    assert!(
        targets.contains("receiver tgt.Decoder"),
        "the receiver synthesis must name the type: {targets}"
    );

    // The planted CWE-125 read in Feed is found. Its finding is flagged forced
    // and floored to `low` with the forced caveat; an unforced Render finding
    // need not be floored. A finding names its harness, not the target, so map
    // Feed to its harness through run.json.
    let feed_harness = json["targets"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|target| target["name"] == "Feed")
        .and_then(|target| target["harness_id"].as_str())
        .unwrap_or_else(|| panic!("run.json must list the Feed target: {json}"));
    let doc = results_doc(&work);
    let mut forced_findings = 0usize;
    for finding in doc["findings"].as_array().into_iter().flatten() {
        if finding["fuzz"]["harness_id"] != feed_harness {
            continue;
        }
        forced_findings += 1;
        assert_eq!(
            finding["fidelity"]["forced"], true,
            "a forced finding must be flagged forced: {finding}"
        );
        assert_eq!(
            finding["severity"], "low",
            "a forced finding must be low-severity: {finding}"
        );
        assert_eq!(
            finding["confidence"]["level"], "low",
            "a forced finding must be low-confidence: {finding}"
        );
        assert!(
            finding.to_string().contains("stub artifact"),
            "a forced finding must carry the caveat note: {finding}"
        );
    }
    assert!(
        forced_findings > 0,
        "the forced Feed panic must be found:\n{doc:#}"
    );
    assert!(
        has_cwe(&doc, 125),
        "expected a CWE-125 index-out-of-bounds finding:\n{doc:#}"
    );
    let _ = std::fs::remove_dir_all(&work);
}

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let dest = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &dest)?;
        } else {
            std::fs::copy(entry.path(), &dest)?;
        }
    }
    Ok(())
}

fn results_doc(work: &std::path::Path) -> serde_json::Value {
    let bytes = std::fs::read(work.join("results/findings.json")).unwrap_or_default();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

fn has_cwe(doc: &serde_json::Value, cwe: u64) -> bool {
    doc["findings"].as_array().into_iter().flatten().any(|f| {
        f["cwe"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|c| c.as_u64() == Some(cwe))
    })
}
