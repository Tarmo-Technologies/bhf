// SPDX-License-Identifier: Apache-2.0

//! A Java target in an IntelliJ-default `org.example` package builds and is
//! fuzzed: the javac fallback compiles the target's own package tree even when
//! a package segment is named like example or test code.

use std::path::Path;
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("-version")
        .output()
        .is_ok_and(|output| output.status.success())
}

#[test]
fn a_target_in_org_example_builds_and_its_bug_is_found() {
    if !have("javac") || !have("java") {
        eprintln!("skipping: no JDK");
        return;
    }
    let dir = TestDir::new("java-org-example");
    let tree = dir.join("tree");
    let package = tree.join("src/main/java/org/example");
    std::fs::create_dir_all(&package).unwrap();
    std::fs::write(
        package.join("RecordParser.java"),
        "package org.example;\n\n\
         public class RecordParser {\n\
         \x20   public static int parseRecord(byte[] data) {\n\
         \x20       if (data.length > 2 && data[0] == 'R') {\n\
         \x20           return data[data.length];\n\
         \x20       }\n\
         \x20       return data.length;\n\
         \x20   }\n\
         }\n",
    )
    .unwrap();
    let work = dir.join("work");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto"])
        .arg(&tree)
        .args(["--per-target-time", "10", "--jobs", "1", "--work-dir"])
        .arg(&work)
        .env("RAYON_NUM_THREADS", "1")
        .output()
        .expect("run bhf auto");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!text.contains("no .java sources"), "{text}");
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
    let attempt = run["targets"]
        .as_array()
        .or_else(|| run["attempts"].as_array())
        .unwrap()
        .iter()
        .find(|attempt| {
            attempt["name"]
                .as_str()
                .is_some_and(|n| n.ends_with("parseRecord"))
        })
        .unwrap_or_else(|| panic!("parseRecord not attempted: {text}"));
    assert!(
        attempt["outcome"]["passes"]
            .as_array()
            .is_some_and(|p| !p.is_empty()),
        "parseRecord did not build and fuzz: {attempt}\n{text}"
    );
    let findings = std::fs::read_dir(work.join("results/findings"))
        .map(|entries| entries.count())
        .unwrap_or(0);
    assert!(
        findings >= 1,
        "the planted out-of-bounds read is not found: {text}"
    );
    assert!(Path::new(&work).is_dir());
}
