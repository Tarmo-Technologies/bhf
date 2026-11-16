// SPDX-License-Identifier: Apache-2.0

//! Oracle, assertion and capability findings minimize and package like
//! crashes. `bhf minimize` held every reduction to a sanitizer crash, so they
//! never minimized, and `bhf capsule` skipped the oracle findings and left
//! the capability ones out of its count.
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

/// The number `text` prints right before `marker`.
fn count_before(text: &str, marker: &str) -> usize {
    text.find(marker)
        .and_then(|at| text[..at].split_whitespace().last()?.parse().ok())
        .unwrap_or(0)
}

#[test]
fn oracle_and_capability_findings_minimize_and_are_all_packaged() {
    if Command::new("cc").arg("--version").output().is_err() {
        eprintln!("skipping: no C compiler on PATH");
        return;
    }
    let root = TestDir::new("oracle-minimize-capsule");
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

    for finding in [find("BHF-415", "oracle_hit"), find("BHF-408", "oracle_hit")] {
        let _ = std::fs::remove_file(finding.join("min_testcase.bin"));
        let minimize = Command::new(env!("CARGO_BIN_EXE_bhf"))
            .args(["minimize", "--finding"])
            .arg(finding)
            .output()
            .expect("run bhf minimize");
        let shown = String::from_utf8_lossy(&minimize.stdout);
        assert!(
            minimize.status.success() && shown.contains("MINIMIZED"),
            "{shown}\n{}",
            String::from_utf8_lossy(&minimize.stderr)
        );
        let minimized = std::fs::read(finding.join("min_testcase.bin")).unwrap();
        let original = std::fs::read(finding.join("testcase.bin")).unwrap();
        assert!(minimized.len() <= original.len());
    }
    // The assertion fails on its first byte alone.
    let assertion = find("BHF-415", "oracle_hit");
    assert_eq!(
        std::fs::read(assertion.join("min_testcase.bin")).unwrap()[0],
        b'Z'
    );

    let capsule = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["capsule", "--work-dir"])
        .arg(&work)
        .output()
        .expect("run bhf capsule");
    let stdout = String::from_utf8_lossy(&capsule.stdout);
    let capsule_err = String::from_utf8_lossy(&capsule.stderr);
    let written = count_before(&stdout, "capsule(s) written");
    let skipped = count_before(&stdout, "finding(s) skipped");
    let failed = count_before(&stdout, "failed)");
    assert_eq!(
        written + skipped + failed,
        findings.len(),
        "every finding is written or skipped:\n{stdout}\n{capsule_err}"
    );
    let capsules = work.join("capsules");
    for (rule, classification) in [
        ("BHF-415", "oracle_hit"),
        ("BHF-408", "oracle_hit"),
        ("BHF-668", "capability"),
    ] {
        let id = record(find(rule, classification))["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let manifest: serde_json::Value = serde_json::from_slice(
            &std::fs::read(capsules.join(format!("capsule_{id}/manifest.json")))
                .unwrap_or_else(|e| panic!("{id} is packaged ({e}):\n{stdout}\n{capsule_err}")),
        )
        .unwrap();
        assert_eq!(manifest["reproduced"], true, "{manifest:#}");
        assert_eq!(manifest["oracle_comparison"]["verdict"], "match");
        let verify = Command::new(env!("CARGO_BIN_EXE_bhf"))
            .arg("verify-poc")
            .arg(capsules.join(format!("capsule_{id}")))
            .output()
            .expect("run bhf verify-poc");
        let verified = String::from_utf8_lossy(&verify.stdout);
        assert!(
            verify.status.success() && verified.contains("verify-poc: PASS"),
            "{verified}"
        );
    }
}
