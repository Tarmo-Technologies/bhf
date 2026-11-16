// SPDX-License-Identifier: Apache-2.0

//! `bhf replay` confirms the findings that are not sanitizer crashes from
//! what the replay did: a failed assertion (BHF-415), a fuzz-controlled
//! format string (BHF-408), an input-triggered capability (BHF-668), and a
//! crash `bhf auto` filed as the format-string bug. It used to decide only
//! from a sanitizer report, so each of them replayed as MISMATCH (an
//! assertion as `no crash: signal 6 (SIGABRT)`).
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const TARGET: &str = "#include <assert.h>\n#include <stdio.h>\n#include <stddef.h>\n\
                      #include <string.h>\n\n\
                      int log_message(const char *msg) {\n  char buf[64];\n  \
                      snprintf(buf, sizeof buf, msg);\n  return (int)strlen(buf);\n}\n\n\
                      int check_header(const unsigned char *data, size_t len) {\n  \
                      if (len < 2) return 0;\n  assert(data[0] != 'Z');\n  \
                      return data[1];\n}\n";

fn record(finding: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(finding.join("finding.json")).unwrap()).unwrap()
}

fn replay(finding: &Path) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["replay", "--finding"])
        .arg(finding)
        .output()
        .expect("run bhf replay");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    (
        out.status.success() && stdout.starts_with("MATCH"),
        format!("{stdout}\n{}", String::from_utf8_lossy(&out.stderr)),
    )
}

#[test]
fn oracle_assertion_and_capability_findings_replay_as_a_match() {
    if Command::new("cc").arg("--version").output().is_err() {
        eprintln!("skipping: no C compiler on PATH");
        return;
    }
    let root = TestDir::new("replay-oracle-findings");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("fmt.c"), TARGET).unwrap();
    let work = root.join("work");
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--jobs", "1", "--per-target-time", "8"])
        .arg(&src)
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let findings: Vec<PathBuf> = std::fs::read_dir(work.join("results/findings"))
        .unwrap_or_else(|e| panic!("no findings dir ({e}):\n{stderr}"))
        .flatten()
        .map(|entry| entry.path())
        .filter(|dir| dir.join("finding.json").is_file())
        .collect();
    let find = |rule: &str, classification: &str| {
        findings
            .iter()
            .find(|dir| {
                let raw = record(dir);
                raw["rule_id"] == rule && raw["classification"] == classification
            })
            .unwrap_or_else(|| panic!("no {classification} {rule} finding:\n{stderr}"))
    };

    let assertion = find("BHF-415", "oracle_hit");
    let (matched, shown) = replay(assertion);
    assert!(matched, "{shown}");
    assert!(shown.contains("expression data[0] != 'Z'"), "{shown}");

    let format_string = find("BHF-408", "oracle_hit");
    let (matched, shown) = replay(format_string);
    assert!(matched, "{shown}");
    assert!(shown.contains("api snprintf"), "{shown}");

    let capability = find("BHF-668", "capability");
    assert!(
        capability.join("testcase.bin").is_file(),
        "the capability finding ships an input that reaches it"
    );
    let (matched, shown) = replay(capability);
    assert!(matched, "{shown}");

    // The crashes filed as the format-string bug, however each one replays.
    for crash in findings
        .iter()
        .filter(|dir| record(dir)["format_string"]["crash_rule_id"].is_string())
    {
        let (matched, shown) = replay(crash);
        assert!(matched, "{shown}");
    }
}
