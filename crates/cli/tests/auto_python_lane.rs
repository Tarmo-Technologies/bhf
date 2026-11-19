// SPDX-License-Identifier: Apache-2.0
//
// M3.1 native Python lane: the `python_lane` fixture is discovered + ranked by
// `bhf auto`, built into a framed CPython launcher, fuzzed by the builtin
// engine, and the planted uncontrolled-recursion bug surfaces as a CWE-674
// finding. The end-to-end portion skips cleanly when no `python3` is installed
// (the GNAT-less rule).

use std::path::{Path, PathBuf};
use std::process::Command;

use cli::auto::candidate::Lang;
use cli::auto::discovery::discover;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/python_lane")
        .canonicalize()
        .expect("canonicalize python_lane fixture")
}

/// The `bhf` binary cargo built for these tests (`bhf.exe` on Windows).
fn bhf_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bhf"))
}

fn have_python() -> bool {
    // As the lane looks for one: `python3`, else `python` (Windows' name).
    let present = ["python3", "python"].iter().any(|python| {
        Command::new(python)
            .arg("--version")
            .output()
            .is_ok_and(|output| {
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout)
                        .trim_start()
                        .starts_with("Python 3")
            })
    });
    support::require_tool(present, "python")
}

#[test]
fn discovers_and_ranks_python_targets() {
    let candidates = discover(&fixture()).expect("discover python_lane fixture");
    let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();

    assert!(
        candidates.iter().all(|c| c.lang == Lang::Python),
        "every candidate from the Python fixture is tagged Lang::Python: {names:?}"
    );
    assert!(
        names.contains(&"parse_record"),
        "public byte-channel entry `parse_record` discovered: {names:?}"
    );
    assert!(
        !names.contains(&"_walk"),
        "private helper `_walk` must be dropped by the ranker: {names:?}"
    );

    let parse = candidates
        .iter()
        .find(|c| c.name == "parse_record")
        .expect("parse_record discovered");
    assert!(
        parse.harness_id.starts_with("H-P"),
        "Python harness id prefix is H-P: {}",
        parse.harness_id
    );
}

#[test]
fn auto_builds_fuzzes_and_finds_recursion_cwe674() {
    if !have_python() {
        eprintln!("skipping: no python3 on PATH (GNAT-less rule)");
        return;
    }
    // Run from a temp copy OUTSIDE the repo so project-root detection doesn't
    // escape upward into the workspace.
    let src = TestDir::new("pylane_it");
    std::fs::copy(
        fixture().join("recordparser.py"),
        src.join("recordparser.py"),
    )
    .unwrap();
    let work_guard = TestDir::new("pylane_itwork");
    let work = work_guard.join("work");

    let out = Command::new(bhf_bin())
        .args([
            "auto",
            "--per-target-time",
            "10",
            "--work-dir",
            work.to_str().unwrap(),
            src.to_str().unwrap(),
        ])
        .output()
        .expect("run bhf auto");
    assert!(
        out.status.success(),
        "bhf auto exited non-zero: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let doc = results_doc(&work);
    assert!(
        has_cwe(&doc, 674),
        "expected a CWE-674 uncontrolled-recursion finding in results/findings.json:\n{doc:#}"
    );
    assert!(
        doc.to_string().contains("parse_record"),
        "the finding should point at parse_record:\n{doc:#}"
    );
    let _ = std::fs::remove_dir_all(&src);
    let _ = std::fs::remove_dir_all(&work);
}

/// #286: an instance method whose class takes constructor arguments is
/// fuzzed: `Parser(limit)` is built from a decoded `int`, and the
/// out-of-range index the limit reaches is found. Such a method was skipped
/// ("only no-arg-constructible receivers").
#[test]
fn auto_builds_a_receiver_from_its_init_arguments_and_finds_the_bug() {
    if !have_python() {
        eprintln!("skipping: no python3 on PATH (GNAT-less rule)");
        return;
    }
    let src = TestDir::new("pylane_ctor");
    std::fs::write(
        src.join("fieldparser.py"),
        "class Parser:\n\
         \x20   def __init__(self, limit: int):\n\
         \x20       self.limit = limit\n\
         \n\
         \x20   def parse(self, data: bytes):\n\
         \x20       fields = data.split(b\",\")\n\
         \x20       if self.limit >= 16:\n\
         \x20           return fields[0]\n\
         \x20       return fields[self.limit]\n",
    )
    .unwrap();
    let work_guard = TestDir::new("pylane_ctorwork");
    let work = work_guard.join("work");
    let out = Command::new(bhf_bin())
        .args([
            "auto",
            "--target",
            "Parser.parse",
            "--per-target-time",
            "10",
        ])
        .args(["--work-dir", work.to_str().unwrap(), src.to_str().unwrap()])
        .output()
        .expect("run bhf auto");
    let log = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{log}");
    assert!(log.contains("1 built+fuzzed"), "{log}");
    let harness = std::fs::read_dir(work.join("harnesses"))
        .unwrap()
        .map(|entry| entry.unwrap().path().join("bhfgen/harness.py"))
        .find(|path| path.exists())
        .unwrap_or_else(|| panic!("no generated harness:\n{log}"));
    let harness = std::fs::read_to_string(harness).unwrap();
    assert!(harness.contains("_recv = _t.Parser(r0)"), "{harness}");
    let doc = results_doc(&work);
    assert!(
        has_cwe(&doc, 125) && doc.to_string().contains("Parser.parse"),
        "expected an out-of-bounds read in Parser.parse:\n{doc:#}\n{log}"
    );
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
