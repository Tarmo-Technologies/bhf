// SPDX-License-Identifier: Apache-2.0

//! `bhf auto --engine afl++` beyond C/C++: the lanes whose harness bhf
//! builds with its C Makefile run under AFL++ too (#302), and each run finds
//! its fixture's bug. Every test needs AFL++ and the lane's toolchain;
//! `BHF_REQUIRE_TOOLS=1` makes a missing one a failure.

use std::path::Path;
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn on_path(bin: &str) -> bool {
    let present = std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false);
    support::require_tool(present, bin)
}

fn afl_present() -> bool {
    on_path("afl-fuzz") && on_path("afl-clang-fast")
}

/// Run `bhf auto --engine afl++` on `src` and return run.json's one target
/// and the findings, after checking AFL++ alone fuzzed it.
fn auto_afl(
    root: &TestDir,
    src: &Path,
    extra: &[&str],
) -> (serde_json::Value, Vec<serde_json::Value>, String) {
    let work = root.join("work");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(src)
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--engine",
            "afl++",
            "--per-target-time",
            "20",
            "--jobs",
            "1",
        ])
        .arg("--no-discovery-cache")
        .args(extra)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
    let target = run["targets"][0].clone();
    assert_eq!(
        target["lanes"]["afl"]["built"], true,
        "{target:#}\n{stderr}"
    );
    let passes = target["outcome"]["passes"].as_array().unwrap();
    assert!(
        !passes.is_empty() && passes.iter().all(|pass| pass["engine"] == "afl++"),
        "AFL++ alone fuzzed it: {target:#}\n{stderr}"
    );
    let findings = std::fs::read_dir(work.join("results/findings"))
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|entry| std::fs::read(entry.path().join("finding.json")).ok())
                .filter_map(|bytes| serde_json::from_slice(&bytes).ok())
                .collect()
        })
        .unwrap_or_default();
    (target, findings, stderr)
}

fn found_by_afl(finding: &serde_json::Value) -> bool {
    finding["lineage"]["reason"]
        .as_str()
        .is_some_and(|reason| reason.contains("found by AFL++"))
}

/// The COBOL ref-mod fixture: `BUF(IDX:1)` with `IDX` = 200 when the input
/// starts with `Z`, at line 11 of `parseit.cob`.
const PARSEIT: &str = "       IDENTIFICATION DIVISION.\n\
     \x20      PROGRAM-ID. PARSEIT.\n\
     \x20      DATA DIVISION.\n\
     \x20      WORKING-STORAGE SECTION.\n\
     \x20      01 IDX PIC 9(4).\n\
     \x20      LINKAGE SECTION.\n\
     \x20      01 BUF PIC X(8).\n\
     \x20      PROCEDURE DIVISION USING BUF.\n\
     \x20          IF BUF(1:1) = \"Z\"\n\
     \x20              MOVE 200 TO IDX\n\
     \x20              DISPLAY BUF(IDX:1)\n\
     \x20          END-IF\n\
     \x20          GOBACK.\n";

#[test]
fn afl_fuzzes_a_cobol_program_and_finds_its_out_of_bounds_reference() {
    if !afl_present() || !on_path("cobc") {
        eprintln!("skipping: needs AFL++ and cobc");
        return;
    }
    let root = TestDir::new("afl-cobol");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("parseit.cob"), PARSEIT).unwrap();
    let (_, findings, stderr) = auto_afl(&root, &src, &["--languages", "cobol"]);
    let finding = findings
        .iter()
        .find(|finding| finding["exception"]["name"] == "COBOL_RUNTIME_ERROR")
        .unwrap_or_else(|| panic!("no COBOL runtime error: {findings:#?}\n{stderr}"));
    assert!(found_by_afl(finding), "{finding:#}");
    assert_eq!(finding["cobol_source"]["line"], 11, "{finding:#}");
}

#[test]
fn afl_fuzzes_a_fortran_routine_and_finds_its_overflow() {
    if !afl_present() || !on_path("gfortran") {
        eprintln!("skipping: needs AFL++ and gfortran");
        return;
    }
    let root = TestDir::new("afl-fortran");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/fortran_bindc/recs.f90"),
        src.join("recs.f90"),
    )
    .unwrap();
    let (_, findings, stderr) = auto_afl(&root, &src, &["--languages", "fortran"]);
    let finding = findings
        .iter()
        .find(|finding| finding["rule_id"] == "BHF-201")
        .unwrap_or_else(|| panic!("no BHF-201 finding: {findings:#?}\n{stderr}"));
    assert!(found_by_afl(finding), "{finding:#}");
    assert!(
        finding.to_string().contains("recs.f90"),
        "located in the Fortran source: {finding:#}"
    );
}

fn cargo_nightly() -> bool {
    let present = Command::new("cargo")
        .args(["+nightly", "--version"])
        .output()
        .is_ok_and(|output| output.status.success());
    support::require_tool(present, "cargo +nightly")
}

/// #303: the Rust lane's staticlib links with afl-clang-fast, as cargo-afl
/// links a crate, and AFL++ finds the fixture's out-of-bounds index behind
/// its `AB` magic.
#[test]
fn afl_fuzzes_a_rust_function_and_finds_its_out_of_bounds_index() {
    if !afl_present() || !cargo_nightly() {
        eprintln!("skipping: needs AFL++ and a nightly cargo");
        return;
    }
    let root = TestDir::new("afl-rust");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/rust_fuzz");
    let (target, findings, stderr) = auto_afl(
        &root,
        &fixture,
        &["--run-untrusted", "--target", "parse_packet"],
    );
    let id = target["harness_id"].as_str().unwrap();
    let harness = root.join("work/harnesses").join(id);
    assert!(harness.join("main_afl_cmplog").is_file(), "{target:#}");
    assert!(
        !harness.join("rust_harness/target-afl").exists(),
        "the AFL++ build's target tree is removed"
    );
    let finding = findings
        .iter()
        .find(|finding| finding["rule_id"] == "BHF-201")
        .unwrap_or_else(|| panic!("no BHF-201 finding: {findings:#?}\n{stderr}"));
    assert!(found_by_afl(finding), "{finding:#}");
    assert!(
        finding.to_string().contains("src/lib.rs"),
        "located in the crate: {finding:#}"
    );
}
