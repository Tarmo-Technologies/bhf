// SPDX-License-Identifier: Apache-2.0

//! Line coverage counts the project's lines, and the summary's edge figure
//! says what it is (#243). `covered-lines.txt` listed bhf's runtime headers
//! (`bhf_decode.h`, `bhf_trace.h`) and the generated `main.c` beside the
//! target's lines, and the summary printed the most edges any one target
//! reached as a bare "Coverage: N edges".

#![cfg(unix)]

use std::path::Path;
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

#[test]
fn covered_lines_are_the_projects_and_the_edge_figure_is_labelled() {
    let present = ["clang", "llvm-cov"]
        .iter()
        .all(|tool| which::which(tool).is_ok())
        || (which::which("clang").is_ok() && which::which("llvm-cov-18").is_ok());
    if !support::require_tool(present, "clang and llvm-cov") {
        eprintln!("skipping: clang or llvm-cov unavailable");
        return;
    }
    let root = TestDir::new("coverage-scope");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("checksum.c"),
        "#include <stddef.h>\n#include <stdint.h>\n\
         int checksum(const uint8_t *data, size_t len) {\n\
         \x20   int total = 0;\n\
         \x20   for (size_t i = 0; i < len; i++) {\n\
         \x20       if (data[i] == 'Z') total += 7;\n\
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
        .args(["--per-target-time", "3", "--jobs", "1"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");

    let covered: Vec<String> = std::fs::read_dir(work.join("harnesses"))
        .unwrap()
        .flatten()
        .filter_map(|entry| std::fs::read_to_string(entry.path().join("covered-lines.txt")).ok())
        .flat_map(|text| text.lines().map(str::to_owned).collect::<Vec<_>>())
        .collect();
    assert!(!covered.is_empty(), "no covered-lines.txt:\n{stderr}");
    let src = src.canonicalize().unwrap();
    for line in &covered {
        let file = line
            .rsplit_once(':')
            .map_or(line.as_str(), |(file, _)| file);
        let file = Path::new(file);
        assert!(
            file.starts_with(&src) || file.canonicalize().is_ok_and(|real| real.starts_with(&src)),
            "{line} is not a project line: {covered:?}"
        );
    }
    let all = format!("{stdout}{stderr}");
    assert!(
        all.contains("edges (the most any one target reached)"),
        "{all}"
    );
}
