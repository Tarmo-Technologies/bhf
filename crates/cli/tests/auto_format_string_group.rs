// SPDX-License-Identifier: Apache-2.0

//! One input-controlled `snprintf` format is one bug. It used to come out as
//! a location-less CWE-134 oracle finding, a NULL dereference and a wild
//! access inside the C library, and a format-string capability finding, each
//! its own root-cause group; it is now one CWE-134 group at the call.
#![cfg(unix)]

use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const TARGET: &str = "#include <stdio.h>\n#include <stddef.h>\n#include <string.h>\n\n\
                      int log_message(const char *msg) {\n  char buf[64];\n  \
                      snprintf(buf, sizeof buf, msg);\n  return (int)strlen(buf);\n}\n";

#[test]
fn a_format_string_bug_is_one_cwe_134_group_at_the_call() {
    if Command::new("cc").arg("--version").output().is_err() {
        eprintln!("skipping: no C compiler on PATH");
        return;
    }
    let root = TestDir::new("format-string-group");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("fmt.c"), TARGET).unwrap();
    let work = root.join("work");
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--jobs", "1", "--per-target-time", "10"])
        .arg(&src)
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("results/findings.json")).unwrap())
            .unwrap();
    let findings = doc["findings"].as_array().unwrap();
    assert!(
        findings.len() >= 2,
        "the oracle and a crash are both found:\n{doc:#}\n{stderr}"
    );
    let groups = doc["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1, "{doc:#}");
    let representative = findings
        .iter()
        .find(|f| f["id"] == groups[0]["representative"])
        .unwrap();
    // The whole document and bhf's log go with each failure: the line a
    // finding is placed at depends on its report being symbolized.
    assert_eq!(representative["cwe"][0], 134, "{doc:#}\n{stderr}");
    assert_eq!(
        representative["location"]["file"], "fmt.c",
        "{doc:#}\n{stderr}"
    );
    assert_eq!(representative["location"]["line"], 7, "{doc:#}\n{stderr}");
    // Every finding is the format-string bug: the crashes and an MSan read
    // of a garbage argument lead with CWE-134, and the capability finding is
    // the format reaching the call.
    for finding in findings {
        assert!(
            finding["cwe"][0] == 134 || finding["rule"]["id"] == "BHF-668",
            "every finding is the format-string bug: {finding:#}"
        );
    }
}
