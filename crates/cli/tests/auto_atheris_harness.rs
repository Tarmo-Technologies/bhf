// SPDX-License-Identifier: Apache-2.0
//
// Atheris harnesses are provided harnesses: `bhf auto` finds the function a
// project's Python file registers with `atheris.Setup`, runs it under bhf's
// driver with a stand-in for the `atheris` module (Atheris itself need not be
// installed), starts it from its seed corpus with its dictionary, and reports
// every exception it lets escape as a finding, as Atheris does.
//
// The `atheris_harness` fixture's TestOneInput decodes a record kind and a
// payload with a FuzzedDataProvider and calls recordlib.parse_record, whose
// planted bug raises KeyError for a flagged record of kind 2 or 3: an
// exception bhf's generated Python harnesses take for an input rejection,
// and Atheris takes for a crash. Its corpus keeps a kind-2 record one byte
// from the bug, and its dictionary the flag byte.
//
// Skips cleanly when no `python3` is installed (the GNAT-less rule).

use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/atheris_harness")
        .canonicalize()
        .expect("canonicalize atheris_harness fixture")
}

fn have_python3() -> bool {
    let present = Command::new("python3")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    support::require_tool(present, "python3")
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &dest);
        } else {
            std::fs::copy(entry.path(), &dest).unwrap();
        }
    }
}

#[test]
fn auto_runs_an_atheris_harness_from_its_corpus_and_finds_its_planted_exception() {
    if !have_python3() {
        eprintln!("skipping: no python3 on PATH (GNAT-less rule)");
        return;
    }
    let tmp = TestDir::new("atheris-harness");
    let src = tmp.join("src");
    copy_dir(&fixture(), &src);
    let src = src.canonicalize().unwrap();
    let work = tmp.join("work");
    let _serial = support::fuzz_serial_guard();
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args([
            "auto",
            "--languages",
            "python",
            "--per-target-time",
            "20",
            "--single-pass",
            "--jobs",
            "1",
            "--max-targets",
            "1",
            "--work-dir",
        ])
        .arg(&work)
        .arg(&src)
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "bhf auto failed: {stderr}");
    assert!(
        stderr.contains("provided harnesses: 1 the project ships (1 Atheris harness(s))"),
        "the run names the harness it found: {stderr}"
    );
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
    assert_eq!(run["summary"]["provided_harnesses"], 1, "{run:#}");
    let target = run["targets"]
        .as_array()
        .expect("run.json targets")
        .iter()
        .find(|target| target["name"] == "TestOneInput")
        .unwrap_or_else(|| panic!("no TestOneInput target in run.json: {run:#}"));
    assert_eq!(
        target["outcome"]["outcome"], "built_and_fuzzed",
        "{target:#}"
    );
    let provided = &target["provided_harness"];
    assert_eq!(provided["origin"], "atheris", "{target:#}");
    assert_eq!(provided["entry"], "TestOneInput");
    assert_eq!(
        provided["source"],
        serde_json::json!(src.join("fuzz/fuzz_records.py"))
    );
    assert_eq!(provided["seeds"], 1, "{provided:#}");
    assert_eq!(
        provided["seed_sources"],
        serde_json::json!([src.join("fuzz/corpus/fuzz_records")])
    );
    assert_eq!(
        provided["dictionaries"],
        serde_json::json!([src.join("fuzz/fuzz_records.dict")])
    );
    assert_eq!(provided["dictionary_tokens"], 2);
    let id = target["harness_id"].as_str().unwrap();
    assert!(id.starts_with("H-P"), "{id}");
    let harness = work.join("harnesses").join(id);
    assert_eq!(
        provided_seeds(&harness),
        [b"\x02REC1abc".to_vec()],
        "the corpus file, as it is"
    );
    let dictionary = std::fs::read_to_string(harness.join("dictionary.txt")).unwrap();
    assert!(
        dictionary.contains("\"REC\"") && dictionary.contains("\"!\""),
        "{dictionary}"
    );

    // The planted KeyError, which only Atheris's rule makes a finding.
    let findings: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("results/findings.json")).unwrap())
            .unwrap();
    let found: Vec<&serde_json::Value> = findings["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|finding| finding["fuzz"]["harness_id"] == id)
        .collect();
    let key_error = found
        .iter()
        .find(|finding| {
            finding["message"]
                .as_str()
                .is_some_and(|m| m.contains("KeyError"))
        })
        .unwrap_or_else(|| {
            panic!("the planted KeyError was not found through TestOneInput: {findings:#}")
        });
    // Located in the library code that raised it, not at the harness's call.
    let location = &key_error["location"];
    assert_eq!(location["function"], "parse_record", "{key_error:#}");
    assert!(
        location["file"]
            .as_str()
            .is_some_and(|file| file.ends_with("recordlib/__init__.py")),
        "{key_error:#}"
    );
    assert_eq!(location["line"], 20, "{key_error:#}");
    // The harness file is fuzzed, so the note on what discovery skipped by
    // default does not count it.
    assert!(
        !stderr.contains("fuzz/ ("),
        "the harness's dir is named as skipped: {stderr}"
    );

    let summary = std::fs::read_to_string(work.join("auto/summary.txt")).unwrap();
    assert!(
        summary.contains(&format!(
            "{id} TestOneInput [atheris]: built+fuzzed, 1 seed(s)"
        )),
        "{summary}"
    );
    // The scanned tree was not written to.
    assert!(!src.join("fuzz/__pycache__").exists());
    assert!(!src.join("recordlib/__pycache__").exists());
}

/// The starting inputs bhf copied into a provided harness's dir.
fn provided_seeds(harness: &Path) -> Vec<Vec<u8>> {
    let mut seeds: Vec<Vec<u8>> = std::fs::read_dir(harness.join("provided-seeds"))
        .unwrap()
        .map(|entry| std::fs::read(entry.unwrap().path()).unwrap())
        .collect();
    seeds.sort();
    seeds
}
