// SPDX-License-Identifier: Apache-2.0

//! The Fortran lane fuzzes a `bind(C)` procedure that takes an assumed-size
//! `c_char` buffer (#235). Such a dummy is a bare C pointer, but the lane
//! sent every character array to its descriptor wrapper, which supports one
//! form only, and skipped `parse_rec`: the most C-callable Fortran shape was
//! not fuzzed, and `--force` did not change that.

#![cfg(target_os = "linux")]

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn runs(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/fortran_bindc/recs.f90")
}

#[test]
fn a_bind_c_buffer_procedure_is_fuzzed_and_its_overread_found() {
    if !runs("gfortran") || !runs("clang") {
        eprintln!("skipping: gfortran or clang unavailable");
        return;
    }
    let root = TestDir::new("auto-fortran-bindc");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::copy(fixture(), src.join("recs.f90")).unwrap();
    let work = root.join("work");
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--per-target-time", "15", src.to_str().unwrap()])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("PARSE_REC → built+fuzzed"), "{stderr}");

    let findings: Vec<Value> = std::fs::read_dir(work.join("results/findings"))
        .expect("findings")
        .flatten()
        .filter_map(|entry| std::fs::read(entry.path().join("finding.json")).ok())
        .filter_map(|bytes| serde_json::from_slice(&bytes).ok())
        .collect();
    let overread = findings
        .iter()
        .find(|finding| finding["rule_id"] == "BHF-201")
        .unwrap_or_else(|| panic!("no BHF-201 finding: {findings:#?}\n{stderr}"));
    assert!(
        overread.to_string().contains("recs.f90"),
        "the overread is in the target: {overread:#}"
    );
}
