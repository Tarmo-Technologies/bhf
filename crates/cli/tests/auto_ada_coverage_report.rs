// SPDX-License-Identifier: Apache-2.0

//! Ada per-subprogram coverage (#310): GNAT instruments with trace-pc and no
//! coverage mapping, so the replay records each edge's PC, places it with
//! addr2line and the instrumented copies' line maps on the original Ada line,
//! and writes the C/C++ report's `lcov.info` and per-subprogram table to
//! `results/coverage/<id>/`.

use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

#[test]
fn an_ada_target_gets_a_report_of_its_subprograms() {
    let present = ["gnatmake", "gprbuild", "objdump"]
        .iter()
        .all(|tool| which::which(tool).is_ok())
        && (which::which("addr2line").is_ok()
            || which::which("llvm-symbolizer").is_ok()
            || which::which("llvm-symbolizer-18").is_ok());
    if !support::require_tool(present, "GNAT, objdump and addr2line") {
        eprintln!("SKIP: gnatmake/gprbuild/objdump/addr2line not installed — Ada lane unavailable");
        return;
    }
    let root = TestDir::new("ada-coverage-report");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("checks.ads"),
        "package Checks is\n\
         \x20  function Classify (Input : String) return Integer;\n\
         \x20  function Unused (N : Integer) return Integer;\n\
         end Checks;\n",
    )
    .unwrap();
    std::fs::write(
        src.join("checks.adb"),
        "package body Checks is\n\
         \x20  function Classify (Input : String) return Integer is\n\
         \x20     Total : Integer := 0;\n\
         \x20  begin\n\
         \x20     for C of Input loop\n\
         \x20        Total := Total + Character'Pos (C);\n\
         \x20     end loop;\n\
         \x20     return Total;\n\
         \x20  end Classify;\n\
         \n\
         \x20  function Unused (N : Integer) return Integer is\n\
         \x20  begin\n\
         \x20     return N - 1;\n\
         \x20  end Unused;\n\
         end Checks;\n",
    )
    .unwrap();
    let work = root.join("work");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        .args(["--target", "Classify"])
        .args(["--per-target-time", "3", "--jobs", "1"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");

    let report = std::fs::read_dir(work.join("results/coverage"))
        .unwrap_or_else(|e| panic!("no results/coverage ({e}):\n{stderr}"))
        .flatten()
        .map(|entry| entry.path())
        .next()
        .expect("one harness's report");
    let functions: serde_json::Value =
        serde_json::from_slice(&std::fs::read(report.join("functions.json")).unwrap()).unwrap();
    let row = |name: &str| {
        functions
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["function"] == name)
            .unwrap_or_else(|| panic!("{name} missing: {functions:#}"))
            .clone()
    };
    let classify = row("checks.classify");
    // The original file and its lines, not the instrumented copy's.
    let file = classify["file"].as_str().unwrap();
    assert!(file.ends_with("src/checks.adb"), "{classify:#}");
    assert!(!file.contains("src_instrumented"), "{classify:#}");
    assert!(
        (2..=9).contains(&classify["line"].as_u64().unwrap()),
        "{classify:#}"
    );
    assert!(
        classify["lines_covered"].as_u64().unwrap() > 0,
        "{classify:#}"
    );
    assert!(classify["calls"].is_null(), "{classify:#}");
    let unused = row("checks.unused");
    assert_eq!(unused["lines_covered"], 0, "{unused:#}");
    assert!(
        unused["lines_instrumented"].as_u64().unwrap() > 0,
        "{unused:#}"
    );
    assert!(
        (11..=14).contains(&unused["line"].as_u64().unwrap()),
        "{unused:#}"
    );

    let table = std::fs::read_to_string(report.join("functions.txt")).unwrap();
    assert!(
        table.contains("checks.classify") && table.contains("checks.unused"),
        "{table}"
    );
    let lcov = std::fs::read_to_string(report.join("lcov.info")).unwrap();
    assert!(
        lcov.contains("FN:") && lcov.contains("SF:") && lcov.contains("end_of_record"),
        "{lcov}"
    );
    assert!(
        !lcov.contains("main.adb"),
        "the harness is not in the report: {lcov}"
    );
    assert!(stderr.contains("line coverage"), "{stderr}");
}
