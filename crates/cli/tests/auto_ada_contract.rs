// SPDX-License-Identifier: Apache-2.0
//! Ada 2012 contracts as fuzzing oracles: `bhf auto` builds Ada targets with
//! -gnata, so a violated Pre/Post/Type_Invariant raises Assertion_Error, which the
//! exception oracle reports as a contract violation (BHF-557 / CWE-617).
//!
//! The fixture's `Parsed_Length` has an off-by-one (returns Data'Length + 1) that its
//! postcondition (`Result <= Data'Length`) catches on every call — so any input,
//! including the empty one, trips it. This drives the real `bhf auto` and asserts
//! a BHF-557 finding is recorded. Gated on the Ada toolchain; skipped otherwise.
//!
//! `bhf auto`'s minimize pass minimizes the finding as it does a C one
//! (#281): its `min_testcase.bin` holds an input that still trips it, no
//! longer than the one the fuzzer found. The pass skipped Ada findings.

use std::path::{Path, PathBuf};

mod support;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root")
}

fn have_ada_toolchain() -> bool {
    let present = { which::which("gnatmake").is_ok() && which::which("gprbuild").is_ok() };
    support::require_tool(present, "ada toolchain")
}

fn copy_ada_sources(fixture: &Path, dest: &Path) {
    for entry in std::fs::read_dir(fixture).expect("read fixture dir") {
        let path = entry.expect("dir entry").path();
        let is_ada = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e == "ads" || e == "adb");
        if is_ada {
            std::fs::copy(&path, dest.join(path.file_name().unwrap())).expect("copy ada source");
        }
    }
}

/// The directory of a finding of `rule_id`, if there is one.
fn finding_with_rule(work_dir: &Path, rule_id: &str) -> Option<PathBuf> {
    let findings = work_dir.join("results").join("findings");
    std::fs::read_dir(&findings)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .find(|dir| {
            std::fs::read_to_string(dir.join("finding.json"))
                .is_ok_and(|json| json.contains(rule_id))
        })
}

#[test]
fn ada_contract_violation_reports_bhf557() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }

    let tmp = tempfile::Builder::new()
        .prefix("bhf-ada-contract-")
        .tempdir()
        .expect("tempdir");
    let srcroot = tmp.path().join("srcroot");
    std::fs::create_dir_all(&srcroot).expect("mkdir srcroot");

    let fixture = repo_root().join("tests/fixtures/ada_contract");
    copy_ada_sources(&fixture, &srcroot);

    let work_dir = srcroot.join("bhf_work");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&srcroot)
        .arg("--work-dir")
        .arg(&work_dir)
        .arg("--per-target-time")
        .arg("5")
        .output()
        .expect("spawn bhf auto");

    let finding = finding_with_rule(&work_dir, "BHF-557").unwrap_or_else(|| {
        panic!(
            "expected a BHF-557 Ada contract-violation finding under {}; bhf auto exit={:?}\nstderr=\n{}",
            work_dir.join("results").join("findings").display(),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr),
        )
    });
    let minimized = std::fs::read(finding.join("min_testcase.bin")).unwrap_or_else(|error| {
        panic!(
            "the minimize pass left no min_testcase.bin in {} ({error}); stderr=\n{}",
            finding.display(),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let original = std::fs::read(finding.join("testcase.bin")).unwrap();
    assert!(
        minimized.len() <= original.len(),
        "{minimized:?} {original:?}"
    );
    let record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(finding.join("finding.json")).unwrap())
            .unwrap();
    assert_eq!(
        record["minimal_reproducer"], "min_testcase.bin",
        "{record:#}"
    );
    assert_eq!(record["minimization"]["strategy"], "bytes", "{record:#}");
}
