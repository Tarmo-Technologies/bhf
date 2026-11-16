// SPDX-License-Identifier: Apache-2.0

//! An out-of-memory finding (BHF-209) records the `--rss-limit-mb` its input
//! ran past, and `bhf replay` runs it under that limit. Replay used to run it
//! with no cap at all, so the testcase really allocated (gigabytes, for a
//! real finding) and then reported MISMATCH because nothing crashed.
#![cfg(target_os = "linux")]

use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// Allocates and touches `data[0]` × 64 MiB.
const TARGET: &str = "#include <stdlib.h>\n#include <string.h>\n#include <stddef.h>\n\
                      int read_blob(const unsigned char *data, size_t len) {\n  \
                      if (len < 2) return 0;\n  \
                      size_t n = (size_t)data[0] * 64u * 1024u * 1024u;\n  \
                      char *p = malloc(n);\n  \
                      if (!p) return -1;\n  \
                      memset(p, 1, n);\n  \
                      int r = p[n / 2];\n  \
                      free(p);\n  \
                      return r;\n}\n";

#[test]
fn an_rss_finding_records_its_limit_and_replays_as_a_match_under_it() {
    if Command::new("cc").arg("--version").output().is_err() {
        eprintln!("skipping: no C compiler on PATH");
        return;
    }
    let root = TestDir::new("rss-limit-replay");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("blob.c"), TARGET).unwrap();
    let work = root.join("work");
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--jobs", "1", "--per-target-time", "5", "--single-pass"])
        .args(["--rss-limit-mb", "200"])
        .arg(&src)
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);

    let findings = work.join("results/findings");
    let finding = std::fs::read_dir(&findings)
        .unwrap_or_else(|e| panic!("no findings dir ({e}):\n{stderr}"))
        .flatten()
        .map(|entry| entry.path())
        .find(|dir| {
            std::fs::read_to_string(dir.join("finding.json"))
                .is_ok_and(|text| text.contains("\"BHF-209\""))
        })
        .unwrap_or_else(|| panic!("no BHF-209 finding:\n{stderr}"));
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(finding.join("finding.json")).unwrap()).unwrap();
    assert_eq!(raw["rss_limit_mb"], 200, "{raw:#}");

    let replay = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["replay", "--finding"])
        .arg(&finding)
        .output()
        .expect("run bhf replay");
    let stdout = String::from_utf8_lossy(&replay.stdout);
    let replay_err = String::from_utf8_lossy(&replay.stderr);
    assert!(
        replay.status.success() && stdout.starts_with("MATCH"),
        "{stdout}\n{replay_err}"
    );
}
