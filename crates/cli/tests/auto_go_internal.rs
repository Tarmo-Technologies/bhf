// SPDX-License-Identifier: Apache-2.0
//
// A Go target under `internal/` is reachable. Go decides "outside the internal
// tree" from the IMPORT PATH, so a harness module named `bhfharness` was
// outside every project and could not import such a package at all — `use of
// internal package … not allowed`, reported as a failed BUILD rather than as the
// naming problem it was. Eight targets in three of the 500-project sweep's Go
// repos, and `internal/` is where a great deal of real Go code lives.
//
// The fixture is the `go_lane` parser moved under `internal/`, so the planted
// index-out-of-range panic (CWE-125) proves the harness both COMPILED against
// the internal package and ran it.

use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/go_internal")
        .canonicalize()
        .expect("canonicalize go_internal fixture")
}

/// The `bhf` binary cargo built for these tests (`bhf.exe` on Windows).
fn bhf_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bhf"))
}

fn have_go() -> bool {
    let present = {
        Command::new("go")
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };
    support::require_tool(present, "go")
}

#[test]
fn a_target_under_internal_builds_and_fuzzes() {
    if !have_go() {
        eprintln!("skipping: no go toolchain on PATH (GNAT-less rule)");
        return;
    }
    let src_guard = TestDir::new("gointernal_it");
    let src = src_guard.join("src");
    copy_dir(&fixture(), &src).expect("copy go fixture module");
    let work_guard = TestDir::new("gointernal_w");
    let work = work_guard.join("work");

    let out = Command::new(bhf_bin())
        .args([
            "auto",
            "--per-target-time",
            "8",
            "--work-dir",
            work.to_str().unwrap(),
            src.to_str().unwrap(),
        ])
        .output()
        .expect("run bhf auto");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !combined.contains("use of internal package"),
        "the harness module must be inside the tree that may import it:\n{combined}"
    );

    let doc = results_doc(&work);
    assert!(
        has_cwe(&doc, 125),
        "expected a CWE-125 finding from the internal package:\n{doc:#}\n{combined}"
    );
    assert!(
        doc.to_string().contains("ParseRecord"),
        "the finding should point at ParseRecord:\n{doc:#}"
    );
    let _ = std::fs::remove_dir_all(&src);
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
            std::fs::copy(entry.path(), dest)?;
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
