// SPDX-License-Identifier: Apache-2.0

//! An uninitialized-memory finding from the MSan corpus replay ships what it
//! takes to reproduce it: the queue entry as `testcase.bin`, MSan's report,
//! the frame's function and the `main_msan` build. It used to carry only
//! `finding.json`, so `bhf replay` ran the ASan `main` and MISMATCHed, and
//! replay.py "passed" on an input that did not exist because the driver
//! exited 0 when it could not open its input.
#![cfg(target_os = "linux")]

use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// Branches on an uninitialized heap field when the first byte is zero.
const TARGET: &str = "#include <stddef.h>\n#include <stdio.h>\n#include <stdlib.h>\n\
                      int parse_record(const unsigned char *data, size_t len) {\n  \
                      int *fields = malloc(4 * sizeof *fields);\n  \
                      int large = 0;\n  \
                      if (!fields || len < 1) {\n    free(fields);\n    return 0;\n  }\n  \
                      if (data[0] != 0) fields[1] = data[0];\n  \
                      if (fields[1] > 3) {\n    puts(\"large record\");\n    large = 1;\n  }\n  \
                      free(fields);\n  \
                      return large;\n}\n";

#[test]
fn an_msan_finding_replays_as_a_match_from_its_own_testcase() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("skipping: no clang for the MemorySanitizer build");
        return;
    }
    let root = TestDir::new("msan-finding-replay");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("rec.c"), TARGET).unwrap();
    let work = root.join("work");
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--jobs", "1", "--per-target-time", "5"])
        .arg(&src)
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let finding = work.join("results/findings/F-MSAN-0000");
    assert!(
        finding.join("finding.json").is_file(),
        "the MSan replay finds the read:\n{stderr}"
    );
    for file in ["testcase.bin", "sanitizer.log"] {
        assert!(finding.join(file).is_file(), "{file} is saved");
    }
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(finding.join("finding.json")).unwrap()).unwrap();
    assert!(
        raw["fixture_path"]
            .as_str()
            .is_some_and(|path| path.ends_with("/main_msan")),
        "{raw:#}"
    );
    assert_eq!(raw["exception"]["stack"][0]["function"], "parse_record");
    assert_eq!(raw["exception"]["sanitizer"], "msan");

    let replay = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["replay", "--finding"])
        .arg(&finding)
        .output()
        .expect("run bhf replay");
    let replayed = String::from_utf8_lossy(&replay.stdout);
    assert!(
        replay.status.success() && replayed.starts_with("MATCH"),
        "{replayed}\n{}",
        String::from_utf8_lossy(&replay.stderr)
    );

    let script = Command::new("python3")
        .arg(finding.join("replay.py"))
        .output()
        .expect("run replay.py");
    let script_out = String::from_utf8_lossy(&script.stdout);
    assert!(
        !script.status.success() && script_out.contains("MemorySanitizer"),
        "replay.py reproduces the read: {script_out}"
    );

    // The driver says so, and fails, when it cannot open its input.
    let harness_id = raw["harness_id"].as_str().unwrap();
    let missing = Command::new(work.join("harnesses").join(harness_id).join("main"))
        .arg(root.join("no-such-input.bin"))
        .output()
        .expect("run the harness");
    assert_ne!(missing.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("cannot open input"),
        "{}",
        String::from_utf8_lossy(&missing.stderr)
    );
}
