// SPDX-License-Identifier: Apache-2.0
//
// A Java target that takes a JDK collection is fuzzed (#236). The harness
// declared every local with `var`, which infers the wrong element type for a
// collection built from the input, so `List<String>`, `Map<String, Object>`
// and the like were skipped as unsupported. A collection local is now
// declared with its parsed type, spelled fully qualified, and filled with a
// fuzzed number of decoded elements.
//
// Every target of the `java_generics` fixture takes a different collection
// shape (a map, a set, a sorted map, a nested collection, a wildcard, an
// `int[]`), so each harness compiling proves the declared spelling. The
// planted ArrayIndexOutOfBoundsException in `widths(List<String>)` is found.

use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/java_generics")
        .canonicalize()
        .expect("canonicalize java_generics fixture")
}

fn has_jdk() -> bool {
    let present = Command::new("javac").arg("-version").output().is_ok()
        && Command::new("java").arg("-version").output().is_ok();
    support::require_tool(present, "jdk")
}

const TARGETS: &[&str] = &[
    "widths",
    "fieldCount",
    "total",
    "distinct",
    "firstBlobLength",
    "groupCount",
    "totalChars",
];

#[test]
fn collection_parameters_build_and_a_list_of_strings_finds_the_planted_bug() {
    if !has_jdk() {
        eprintln!("skip: no JDK (native Java lane needs javac/java)");
        return;
    }
    let tmp = TestDir::new("java-generics");
    let work = tmp.join("work");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(fixture())
        .args(["--per-target-time", "6", "--jobs", "1", "--work-dir"])
        .arg(&work)
        .output()
        .expect("run bhf auto");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!text.contains("unsupported type"), "{text}");

    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
    let attempts = run["targets"]
        .as_array()
        .or_else(|| run["attempts"].as_array())
        .unwrap();
    for target in TARGETS {
        let attempt = attempts
            .iter()
            .find(|attempt| {
                attempt["name"]
                    .as_str()
                    .is_some_and(|name| name.ends_with(&format!(".{target}")) || name == *target)
            })
            .unwrap_or_else(|| panic!("{target} was not attempted:\n{text}"));
        assert!(
            attempt["outcome"]["passes"]
                .as_array()
                .is_some_and(|passes| !passes.is_empty()),
            "{target} did not build and fuzz: {attempt:#}\n{text}"
        );
    }

    let found = std::fs::read_dir(work.join("results/findings"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| std::fs::read_to_string(entry.path().join("finding.json")).ok())
        .any(|finding| finding.contains("ArrayIndexOutOfBounds") && finding.contains("widths"));
    assert!(
        found,
        "the planted out-of-bounds write in widths(List<String>) is not found:\n{text}"
    );
}
