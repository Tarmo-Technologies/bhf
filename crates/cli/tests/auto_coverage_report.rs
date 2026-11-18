// SPDX-License-Identifier: Apache-2.0

//! The coverage report a C target gets (#308): `bhf auto` replays the corpus
//! through the source-coverage build and writes `results/coverage/<id>/` with
//! an lcov file, an HTML report and a per-function table, all of them about
//! the project's file and none about bhf's harness or runtime.

#![cfg(unix)]

use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

#[test]
fn a_one_file_target_gets_lcov_html_and_a_function_table() {
    let present = which::which("clang").is_ok()
        && (which::which("llvm-cov").is_ok() || which::which("llvm-cov-18").is_ok());
    if !support::require_tool(present, "clang and llvm-cov") {
        eprintln!("skipping: clang or llvm-cov unavailable");
        return;
    }
    let root = TestDir::new("coverage-report");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    // `scale` is reached from the target; `unused` never is.
    std::fs::write(
        src.join("checksum.c"),
        "#include <stddef.h>\n#include <stdint.h>\n\
         static int scale(int value) {\n\
         \x20   return value * 3;\n\
         }\n\
         int unused(int value) {\n\
         \x20   return value - 1;\n\
         }\n\
         int checksum(const uint8_t *data, size_t len) {\n\
         \x20   int total = 0;\n\
         \x20   for (size_t i = 0; i < len; i++) {\n\
         \x20       if (data[i] == 'Z') total += scale(data[i]);\n\
         \x20       else total += data[i];\n\
         \x20   }\n\
         \x20   return total;\n\
         }\n",
    )
    .unwrap();
    let work = root.join("work");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        .args(["--target", "checksum"])
        .args(["--per-target-time", "3", "--jobs", "1"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(stderr.contains("reports in results/coverage/"), "{stderr}");

    let reports: Vec<_> = std::fs::read_dir(work.join("results/coverage"))
        .unwrap_or_else(|e| panic!("no results/coverage ({e}):\n{stderr}"))
        .flatten()
        .map(|entry| entry.path())
        .collect();
    assert_eq!(reports.len(), 1, "{reports:?}");
    let report = &reports[0];

    let lcov = std::fs::read_to_string(report.join("lcov.info")).unwrap();
    let files: Vec<&str> = lcov.lines().filter_map(|l| l.strip_prefix("SF:")).collect();
    assert_eq!(files.len(), 1, "only the project's file: {lcov}");
    assert!(files[0].ends_with("checksum.c"), "{lcov}");
    assert!(lcov.contains("end_of_record"), "{lcov}");

    let html = report.join("html/index.html");
    let index = std::fs::read_to_string(&html).unwrap_or_else(|e| panic!("{html:?}: {e}"));
    assert!(
        index.contains("checksum.c"),
        "the HTML index names the file"
    );
    assert!(
        !index.contains("main.c"),
        "the harness is not in the report"
    );

    let table = std::fs::read_to_string(report.join("functions.txt")).unwrap();
    for function in ["checksum", "scale", "unused"] {
        assert!(table.contains(function), "{function} missing:\n{table}");
    }
    let functions: serde_json::Value =
        serde_json::from_slice(&std::fs::read(report.join("functions.json")).unwrap()).unwrap();
    let row = |name: &str| {
        functions
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["function"].as_str().is_some_and(|f| f.ends_with(name)))
            .unwrap_or_else(|| panic!("{name} missing: {functions:#}"))
            .clone()
    };
    let checksum = row("checksum");
    assert!(checksum["calls"].as_u64().unwrap() > 0, "{checksum:#}");
    assert!(
        checksum["lines_covered"].as_u64().unwrap() > 0,
        "{checksum:#}"
    );
    let unused = row("unused");
    assert_eq!(unused["calls"], 0, "{unused:#}");
    assert_eq!(unused["lines_covered"], 0, "{unused:#}");
    assert!(
        unused["lines_instrumented"].as_u64().unwrap() > 0,
        "{unused:#}"
    );
}
