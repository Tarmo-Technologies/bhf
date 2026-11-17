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
#[cfg_attr(
    windows,
    ignore = "JavaScript runs under WSL on Windows; see docs/site/windows.md"
)]
fn a_navigator_module_loads_with_stand_ins_and_its_bug_is_found() {
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
    assert!(!log.contains("navigator is not defined"), "{log}");

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
        caveat.contains("browser globals") && caveat.contains("navigator"),
        "{record:#}"
    );
    assert!(
        record["fidelity"]["environment_shim"]
            .as_str()
            .is_some_and(|shim| shim.contains("navigator")),
        "{record:#}"
    );

    // Stood in for as it loaded, when called, and not at all.
    let loaded = record_for(&work, "parseHeader").expect("a parseHeader harness");
    assert!(
        loaded
            .as_deref()
            .is_some_and(|names| names.contains("navigator")),
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
