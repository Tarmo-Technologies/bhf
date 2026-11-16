// SPDX-License-Identifier: Apache-2.0

//! `bhf fuzz` prints a progress line on stderr while it runs (#231): it
//! printed nothing until the end, so a long run looked hung. `--quiet` prints
//! none.

#![cfg(unix)]

use std::fs;
use std::path::Path;
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn clang_runs() -> bool {
    let present = {
        Command::new("clang")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    };
    support::require_tool(present, "clang")
}

/// Reads its input and never fails.
const TARGET: &str = "#include <stddef.h>\n#include <stdint.h>\n\
     static volatile unsigned total;\n\
     int bhf_run_one(const uint8_t *data, size_t size) {\n\
         for (size_t i = 0; i < size; i++) total += data[i];\n\
         if (size > 2 && data[0] == 'P' && data[1] == 'R') total ^= 7;\n\
         return 0;\n\
     }\n";

fn build_harness(work: &Path, id: &str) {
    let dir = work.join("harnesses").join(id);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("target.c"), TARGET).unwrap();
    let driver = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime/bhf_driver.c");
    let built = Command::new("clang")
        .current_dir(&dir)
        .args([
            "-O1",
            "-g",
            "-fsanitize=address",
            "-fsanitize-coverage=trace-pc-guard,trace-cmp",
            "-o",
            "main",
            "target.c",
        ])
        .arg(&driver)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
}

/// `bhf fuzz` for five seconds; its stderr.
fn fuzz_for_five_seconds(work: &Path, id: &str, extra: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("fuzz")
        .arg(work)
        .args(["--harness", id, "--time", "5s", "--seed-input", "PR seed"])
        .args(extra)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");
    stderr
}

fn progress_lines(stderr: &str) -> Vec<&str> {
    stderr
        .lines()
        .filter(|line| line.starts_with("bhf: fuzz: "))
        .collect()
}

#[test]
fn a_five_second_run_prints_progress_and_quiet_prints_none() {
    if !clang_runs() {
        eprintln!("skipping: clang unavailable");
        return;
    }
    let root = TestDir::new("fuzz-progress");
    let work = root.join("work");
    build_harness(&work, "H-PROGRESS");

    let stderr = fuzz_for_five_seconds(&work, "H-PROGRESS", &[]);
    let lines = progress_lines(&stderr);
    assert!(!lines.is_empty(), "no progress line:\n{stderr}");
    let first = lines[0];
    for field in [
        "execs (",
        "/s) | corpus: ",
        " | findings: 0 | edges: ",
        " | elapsed: ",
    ] {
        assert!(first.contains(field), "{first}");
    }
    let execs: usize = first["bhf: fuzz: ".len()..]
        .split(' ')
        .next()
        .and_then(|count| count.parse().ok())
        .unwrap_or_else(|| panic!("no exec count: {first}"));
    assert!(execs > 0, "{first}");
    // Two seconds in, then again after as long as the run has taken: a
    // five-second run prints at 2s and 4s, not every 500ms sample.
    assert!(lines.len() <= 3, "{stderr}");

    let quiet = fuzz_for_five_seconds(&work, "H-PROGRESS", &["--quiet"]);
    assert!(progress_lines(&quiet).is_empty(), "{quiet}");
}
