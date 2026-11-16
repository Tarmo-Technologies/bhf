// SPDX-License-Identifier: Apache-2.0

//! GitHub code scanning drops a SARIF result with no location. A format-string
//! oracle finding (BHF-408) has no crash frame of its own, and both
//! results/findings.sarif and results/findings.json gave it none; it now points
//! at the format's call site (from a crash of the same bug), else at the
//! fuzzed target's source line.
#![cfg(unix)]

use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const TARGET: &str = "#include <stdio.h>\n#include <stddef.h>\n#include <string.h>\n\
                      int log_line(const char *msg) {\n  char buf[64];\n  \
                      snprintf(buf, sizeof buf, msg);\n  return (int)strlen(buf);\n}\n";

#[test]
fn every_result_of_a_run_has_a_location_and_the_oracle_one_names_the_target() {
    if Command::new("cc").arg("--version").output().is_err() {
        eprintln!("skipping: no C compiler on PATH");
        return;
    }
    let root = TestDir::new("sarif-locations");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("fmt.c"), TARGET).unwrap();
    let work = root.join("work");
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--jobs", "1", "--per-target-time", "5"])
        .arg(&src)
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let read = |name: &str| -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(work.join("results").join(name)).unwrap())
            .unwrap_or_else(|e| panic!("results/{name}: {e}\n{stderr}"))
    };

    let sarif = read("findings.sarif");
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert!(
        results.iter().any(|r| r["ruleId"] == "BHF-408"),
        "the planted format string is found:\n{sarif:#}\n{stderr}"
    );
    for result in results {
        let locations = result["locations"].as_array().unwrap();
        assert!(!locations.is_empty(), "no location: {result:#}");
    }
    // The oracle finding has no stack; a crash of the same bug gives the call.
    let findings = read("findings.json");
    let oracle_id = findings["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| {
            f["rule"]["id"] == "BHF-408"
                && f["kind"] == "fuzz"
                && f["stack"] == serde_json::json!([])
        })
        .and_then(|f| f["id"].as_str())
        .map(str::to_owned)
        .expect("the format-string oracle finding, which has no stack");
    for row in findings["findings"].as_array().unwrap() {
        if row["rule"]["id"] != "BHF-408" {
            continue;
        }
        assert_eq!(row["location"]["file"], "fmt.c", "{row:#}");
        let line = row["location"]["line"].as_u64().unwrap();
        assert!(line == 4 || line == 6, "the function or the call: {row:#}");
    }
    let oracle = results
        .iter()
        .find(|r| r["properties"]["bhfFindingId"] == oracle_id.as_str())
        .unwrap();
    let physical = &oracle["locations"][0]["physicalLocation"];
    assert_eq!(physical["artifactLocation"]["uri"], "fmt.c", "{oracle:#}");
    let line = physical["region"]["startLine"].as_u64().unwrap();
    assert!(line == 4 || line == 6, "{oracle:#}");
}
