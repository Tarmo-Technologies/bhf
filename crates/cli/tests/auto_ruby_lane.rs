// SPDX-License-Identifier: Apache-2.0
//
// M3.9 native Ruby lane: the `ruby_lane` fixture is discovered, built into a framed
// `ruby` launcher (TracePoint edge coverage), fuzzed by the builtin engine, and the
// planted divide-by-zero surfaces as a CWE-369 finding. The end-to-end portion skips
// cleanly when no `ruby` is installed (the GNAT-less rule).

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
        .join("../../tests/fixtures/ruby_lane")
        .canonicalize()
        .expect("canonicalize ruby_lane fixture")
}

/// The `bhf` binary cargo built for these tests (`bhf.exe` on Windows).
fn bhf_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bhf"))
}

fn have_ruby() -> bool {
    let present = {
        Command::new("ruby")
            .arg("-e")
            .arg("1")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };
    support::require_tool(present, "ruby")
}

#[test]
fn discovers_ruby_methods() {
    let candidates = discover(&fixture()).expect("discover ruby_lane fixture");
    let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
    assert!(
        candidates.iter().all(|c| c.lang == Lang::Ruby),
        "every candidate is Lang::Ruby: {names:?}"
    );
    assert!(
        names.contains(&"RecordParser.parse_record"),
        "module self-method discovered with receiver qualification: {names:?}"
    );
    let p = candidates
        .iter()
        .find(|c| c.name == "RecordParser.parse_record")
        .expect("parse_record discovered");
    assert!(
        p.harness_id.starts_with("H-U"),
        "Ruby id prefix H-U: {}",
        p.harness_id
    );
}

#[test]
fn auto_builds_fuzzes_and_finds_divide_by_zero_cwe369() {
    if !have_ruby() {
        eprintln!("skipping: no ruby on PATH (GNAT-less rule)");
        return;
    }
    let src = TestDir::new("rubylane_it");
    std::fs::copy(
        fixture().join("record_parser.rb"),
        src.join("record_parser.rb"),
    )
    .unwrap();
    let work_guard = TestDir::new("rubylane_w");
    let work = work_guard.join("work");

    let out = Command::new(bhf_bin())
        .args([
            "auto",
            "--per-target-time",
            "20",
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
        has_cwe(&doc, 369),
        "expected a CWE-369 arithmetic finding in results/findings.json:\n{doc:#}"
    );
    let _ = std::fs::remove_dir_all(&src);
    let _ = std::fs::remove_dir_all(&work);
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
