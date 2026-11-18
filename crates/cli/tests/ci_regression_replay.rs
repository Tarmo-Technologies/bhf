// SPDX-License-Identifier: Apache-2.0

//! `bhf ci` replays the findings an earlier run stored before it judges this
//! one (#318): a finding that still reproduces fails the gate, and once the
//! bug is fixed it passes and is reported fixed. A work dir restored from a
//! CI cache keeps its last findings in `regressions/`.

#![cfg(unix)]

use std::path::Path;
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const BUGGY: &str = "#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n\n\
                     int parse_tag(const uint8_t *data, size_t len) {\n  char tag[4];\n  \
                     if (len > 0 && data[0] == 'T') {\n    memcpy(tag, data, len);\n    \
                     return tag[1];\n  }\n  return 0;\n}\n";

const FIXED: &str = "#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n\n\
                     int parse_tag(const uint8_t *data, size_t len) {\n  char tag[4];\n  \
                     if (len >= 2 && len <= sizeof tag && data[0] == 'T') {\n    \
                     memcpy(tag, data, len);\n    return tag[1];\n  }\n  return 0;\n}\n";

fn ci(src: &Path, work: &Path, json: &Path) -> (i32, serde_json::Value, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("ci")
        .arg(src)
        .arg("--work-dir")
        .arg(work)
        .args(["--languages", "c", "--per-target-time", "10"])
        .arg("--ci-json")
        .arg(json)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let doc = serde_json::from_slice(&std::fs::read(json).unwrap_or_default())
        .unwrap_or_else(|error| panic!("{} ({error}): {stderr}", json.display()));
    (output.status.code().unwrap_or(-1), doc, stderr)
}

#[test]
fn a_stored_finding_fails_the_gate_until_it_is_fixed() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("skipping: no clang");
        return;
    }
    let root = TestDir::new("ci-regression");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("tag.c"), BUGGY).unwrap();
    let work = root.join("work");

    let (exit, first, stderr) = ci(&src, &work, &root.join("first.json"));
    assert_eq!(
        exit, 1,
        "the planted overflow fails the gate: {first:#}\n{stderr}"
    );
    assert!(first["total_findings"].as_u64().unwrap() >= 1, "{first:#}");
    assert_eq!(first["regressions"]["replayed"], 0, "{first:#}");

    // The same tree again: the stored finding is replayed, and reproduces.
    let (exit, second, stderr) = ci(&src, &work, &root.join("second.json"));
    assert_eq!(exit, 1, "{second:#}\n{stderr}");
    let reproduced = second["regressions"]["reproduced"].as_array().unwrap();
    assert!(!reproduced.is_empty(), "{second:#}\n{stderr}");
    assert!(stderr.contains("still reproduces"), "{stderr}");
    let id = reproduced[0].as_str().unwrap().to_owned();
    assert!(work.join("regressions").join(&id).is_dir(), "{second:#}");

    // Fixed: the stored finding no longer reproduces, and the gate passes.
    std::fs::write(src.join("tag.c"), FIXED).unwrap();
    let (exit, third, stderr) = ci(&src, &work, &root.join("third.json"));
    assert_eq!(exit, 0, "{third:#}\n{stderr}");
    assert_eq!(third["total_findings"], 0, "{third:#}");
    let fixed = third["regressions"]["fixed"].as_array().unwrap();
    assert!(
        fixed.iter().any(|fixed| fixed == id.as_str()),
        "{third:#}\n{stderr}"
    );
    assert_eq!(
        third["regressions"]["reproduced"].as_array().map(Vec::len),
        Some(0),
        "{third:#}"
    );
}
