// SPDX-License-Identifier: Apache-2.0
//
// A browser-oriented JS module references `window`, `document` or `navigator`,
// and under Node it did not load ("navigator is not defined"): 28 targets of the
// 500-project sweep were skipped so (JS-2). The driver now stands in for the
// browser globals Node lacks when a module needs them, as it loads or when it
// is called, and records which it stood in for. The target's findings carry
// that in their fidelity caveat. A module that only tests `typeof window` gets
// no stand-ins.

use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/js_browser_globals")
        .canonicalize()
        .expect("canonicalize js_browser_globals fixture")
}

fn have_node() -> bool {
    let present = Command::new("node")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    support::require_tool(present, "node")
}

/// The record of the harness whose launcher fuzzes `export`, if it has one;
/// `None` when no harness does.
fn record_for(work: &Path, export: &str) -> Option<Option<String>> {
    let harnesses = std::fs::read_dir(work.join("harnesses")).ok()?;
    harnesses.flatten().find_map(|entry| {
        let launcher = std::fs::read_to_string(entry.path().join("main")).ok()?;
        launcher
            .contains(&format!("BHF_JS_EXPORT=\"{export}\""))
            .then(|| std::fs::read_to_string(entry.path().join("browser-globals.txt")).ok())
    })
}

#[test]
fn a_module_reading_a_browser_global_as_it_loads_gets_stand_ins_and_its_bug_is_found() {
    if !have_node() {
        eprintln!("skipping: no node runtime on PATH");
        return;
    }
    // Copy outside the repo: discovery excludes `tests/` unless it is the root.
    let src = TestDir::new("js_browser_globals");
    for entry in std::fs::read_dir(fixture()).unwrap().flatten() {
        std::fs::copy(entry.path(), src.join(entry.file_name())).unwrap();
    }
    let work_guard = TestDir::new("js_browser_globals_w");
    let work = work_guard.join("work");
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(src.path())
        .args(["--per-target-time", "6", "--single-pass", "--jobs", "1"])
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run bhf auto");
    let log = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!log.contains("location is not defined"), "{log}");

    let index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("results/findings.json"))
            .unwrap_or_else(|error| panic!("{error}\n{log}")),
    )
    .unwrap();
    let finding = index["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding.to_string().contains("parseHeader"))
        .unwrap_or_else(|| panic!("the planted bug is not found: {index:#}\n{log}"));
    let id = finding["id"].as_str().unwrap();
    let record: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("results/findings").join(id).join("finding.json")).unwrap(),
    )
    .unwrap();
    let caveat = record["fidelity_caveat"].as_str().unwrap_or_default();
    assert!(
        caveat.contains("browser globals") && caveat.contains("location"),
        "{record:#}"
    );
    assert!(
        record["fidelity"]["environment_shim"]
            .as_str()
            .is_some_and(|shim| shim.contains("location")),
        "{record:#}"
    );

    // Stood in for as it loaded, when called, and not at all.
    let loaded = record_for(&work, "parseHeader").expect("a parseHeader harness");
    assert!(
        loaded
            .as_deref()
            .is_some_and(|names| names.contains("location")),
        "{loaded:?}"
    );
    let called = record_for(&work, "widthFor").expect("a widthFor harness");
    assert!(
        called
            .as_deref()
            .is_some_and(|names| names.contains("window")),
        "{called:?}\n{log}"
    );
    let guarded = record_for(&work, "describe").expect("a describe harness");
    assert_eq!(guarded, None, "{log}");
}

/// A global that is neither Node's nor a browser's (`hostApp`, injected by the
/// host the module was written for) stops every call before the input is used
/// (#398). When every input bhf tries before fuzzing raises the same
/// `ReferenceError` (the starting inputs, a seed file included, and inputs
/// built from the target's literals), it is the target's environment: the
/// target is built but not entered, naming the global, and no finding is
/// written. A `ReferenceError` that some input avoids is a bug in the target
/// and stays a finding: past a length check (`decodeRecord`), past a header
/// that is one of the target's literals (`parseFrame`), or past a format only
/// the seed file shows (`parseRange`).
#[test]
fn an_undefined_global_on_every_input_is_not_entered_and_an_input_dependent_one_is_a_finding() {
    if !have_node() {
        eprintln!("skipping: no node runtime on PATH");
        return;
    }
    let fixture = fixture().join("../js_host_globals");
    let src = TestDir::new("js_host_globals");
    for entry in std::fs::read_dir(&fixture).unwrap().flatten() {
        std::fs::copy(entry.path(), src.join(entry.file_name())).unwrap();
    }
    let work_guard = TestDir::new("js_host_globals_w");
    let work = work_guard.join("work");
    // A sample of parseRange's format, which none of its literals spells.
    let seed = work_guard.join("range.seed");
    std::fs::write(&seed, "12-34").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(src.path())
        .args(["--per-target-time", "6", "--single-pass", "--jobs", "1"])
        .arg("--seed-file")
        .arg(&seed)
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run bhf auto");
    let log = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let run: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("auto/run.json")).unwrap_or_else(|e| panic!("{e}\n{log}")),
    )
    .unwrap();
    let target = |name: &str| {
        run["targets"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|target| target["name"] == name)
            .unwrap_or_else(|| panic!("{name} was not attempted: {run:#}\n{log}"))
            .clone()
    };
    let upload = target("readUpload");
    assert_eq!(
        upload["outcome"]["outcome"], "built_not_entered",
        "{upload:#}\n{log}"
    );
    assert_eq!(
        upload["outcome"]["entry_miss"], "target_environment",
        "{upload:#}"
    );
    let reason = upload["outcome"]["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("`hostApp`") && reason.contains("ReferenceError"),
        "the reason must name the missing global: {reason}"
    );
    for name in ["decodeRecord", "parseFrame", "parseRange"] {
        let fuzzed = target(name);
        assert_eq!(
            fuzzed["outcome"]["outcome"], "built_and_fuzzed",
            "{name}: some input gets past its ReferenceError: {fuzzed:#}\n{log}"
        );
    }

    let index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("results/findings.json"))
            .unwrap_or_else(|error| panic!("{error}\n{log}")),
    )
    .unwrap();
    let findings = index["findings"].as_array().cloned().unwrap_or_default();
    for global in ["recordCodec", "legacyFrames", "rangeTable"] {
        assert!(
            findings.iter().any(|finding| finding
                .to_string()
                .contains(&format!("{global} is not defined"))),
            "the input-dependent ReferenceError for {global} must be a finding: {index:#}\n{log}"
        );
    }
    assert!(
        !findings
            .iter()
            .any(|finding| finding.to_string().contains("hostApp")),
        "the missing host global must not be a finding: {index:#}"
    );
    // Not a row for bhf's maintainer: the target's environment stopped it.
    let bug_report = std::fs::read_to_string(work.join("auto/bug-report.md")).unwrap_or_default();
    assert!(
        !bug_report.contains("hostApp"),
        "the target's environment is not a bhf issue: {bug_report}"
    );
}
