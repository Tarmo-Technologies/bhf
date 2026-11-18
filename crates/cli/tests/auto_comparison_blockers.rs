// SPDX-License-Identifier: Apache-2.0

//! Reached-but-stuck comparisons (#309): `bhf auto` lists, per target, the
//! comparisons its corpus reached and never passed, with the operand each
//! wants and where it is, in `results/coverage/<id>/blockers.{json,txt}`.

#![cfg(unix)]

use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

#[test]
fn an_unsolved_magic_compare_is_listed_as_a_blocker() {
    let present = which::which("clang").is_ok()
        && (which::which("llvm-cov").is_ok() || which::which("llvm-cov-18").is_ok())
        && (which::which("llvm-symbolizer").is_ok() || which::which("llvm-symbolizer-18").is_ok());
    if !support::require_tool(present, "clang, llvm-cov and llvm-symbolizer") {
        eprintln!("skipping: clang, llvm-cov or llvm-symbolizer unavailable");
        return;
    }
    let root = TestDir::new("comparison-blockers");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    // The input is multiplied before the compare, so its bytes never hold the
    // constant: splicing the operand into the input does not solve it.
    std::fs::write(
        src.join("magic.c"),
        "#include <stddef.h>\n#include <stdint.h>\n\
         int parse_magic(const uint8_t *data, size_t len) {\n\
         \x20   if (len < 4)\n\
         \x20       return -1;\n\
         \x20   uint32_t word = (uint32_t)data[0] | ((uint32_t)data[1] << 8) |\n\
         \x20                   ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);\n\
         \x20   if (word * 2654435761u == 0x5AFEC0DEu)\n\
         \x20       return 1;\n\
         \x20   return 0;\n\
         }\n",
    )
    .unwrap();
    let work = root.join("work");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        .args(["--target", "parse_magic"])
        .args(["--per-target-time", "3", "--jobs", "1"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("comparison(s) reached but never passed"),
        "{stderr}"
    );

    let report = std::fs::read_dir(work.join("results/coverage"))
        .unwrap_or_else(|e| panic!("no results/coverage ({e}):\n{stderr}"))
        .flatten()
        .map(|entry| entry.path())
        .next()
        .expect("one harness's report");
    let blockers: serde_json::Value =
        serde_json::from_slice(&std::fs::read(report.join("blockers.json")).unwrap()).unwrap();
    let blocker = blockers
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["line"] == 8)
        .unwrap_or_else(|| panic!("the compare on line 8 is not listed: {blockers:#}"));
    assert!(
        blocker["file"].as_str().unwrap().ends_with("magic.c"),
        "{blocker:#}"
    );
    assert_eq!(blocker["function"], "parse_magic", "{blocker:#}");
    // 0x5AFEC0DE, little-endian.
    assert_eq!(blocker["wants"], "dec0fe5a", "{blocker:#}");
    assert!(
        blocker["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k == "int"),
        "{blocker:#}"
    );
    assert_eq!(blocker["branches_not_taken"], 1, "{blocker:#}");
    let text = std::fs::read_to_string(report.join("blockers.txt")).unwrap();
    assert!(
        text.contains("magic.c:8  parse_magic  int  wants dec0fe5a"),
        "{text}"
    );
}
