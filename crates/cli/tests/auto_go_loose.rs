// SPDX-License-Identifier: Apache-2.0
//
// A Go target outside every module is fuzzed (#237). The harness imports the
// target through a module `replace`, which needs a dir holding a `go.mod`, so a
// GOPATH-era package or a loose directory of `.go` files was skipped. bhf now
// copies the package into a module of its own, and renames a `package main`
// in the copy so it can be imported at all.
//
// The fixture has neither a go.mod nor a parent that holds one: a library
// package with a planted index-out-of-range (CWE-125), and a command with a
// planted divide-by-zero (CWE-369). Each finding names the project's file and
// line, not the copy's.

use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/go_loose")
        .canonicalize()
        .expect("canonicalize go_loose fixture")
}

fn have_go() -> bool {
    let present = Command::new("go")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success());
    support::require_tool(present, "go")
}

#[test]
fn packages_outside_every_module_build_and_their_bugs_are_found() {
    if !have_go() {
        eprintln!("skipping: no go toolchain on PATH (GNAT-less rule)");
        return;
    }
    let root = TestDir::new("goloose_it");
    let src = root.join("src");
    copy_dir(&fixture(), &src).expect("copy go_loose fixture");
    let work = root.join("work");

    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        .args(["--per-target-time", "8", "--jobs", "1"])
        .output()
        .expect("run bhf auto");
    let log = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!log.contains("not inside a Go module"), "{log}");

    let doc: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("results/findings.json")).unwrap_or_default(),
    )
    .unwrap_or(serde_json::Value::Null);
    let findings = doc["findings"].as_array().cloned().unwrap_or_default();
    let located = |cwe: u64| {
        findings.iter().find_map(|finding| {
            finding["cwe"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|c| c.as_u64() == Some(cwe))
                .then(|| {
                    let location = &finding["location"];
                    (
                        location["file"].as_str().unwrap_or_default().to_owned(),
                        location["line"].as_u64(),
                    )
                })
        })
    };
    assert_eq!(
        located(125),
        Some(("recordparser/parser.go".to_owned(), Some(14))),
        "the library package's out-of-bounds read:\n{doc:#}\n{log}"
    );
    assert_eq!(
        located(369),
        Some(("cmd/rsum/main.go".to_owned(), Some(22))),
        "the command's divide by zero:\n{doc:#}\n{log}"
    );
    // The scanned tree is not written to: the go.mod is the copy's.
    assert!(!src.join("recordparser/go.mod").exists());
    assert!(!src.join("cmd/rsum/go.mod").exists());
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
