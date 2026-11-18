// SPDX-License-Identifier: Apache-2.0

//! `--sanitizers hwasan` (#333): on an AArch64 host the fuzzed harness is
//! built with HWAddressSanitizer in place of ASan, and a heap overflow is a
//! HWASan finding under the heap-overflow rule. On any other host the run is
//! refused before it builds. The AArch64 test needs clang with its HWASan
//! runtime; `BHF_REQUIRE_TOOLS=1` (the ARM64 CI job) makes a missing one a
//! failure.

#![cfg(unix)]

use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// A record's name copied into an 8-byte heap buffer without a length check.
const OVERFLOW: &str = "\
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int parse_record(const unsigned char *data, size_t len) {
    if (len < 2 || data[0] != 'R') {
        return 0;
    }
    char *name = malloc(8);
    memcpy(name, data + 1, len - 1);
    int first = name[0];
    free(name);
    return first;
}
";

fn auto_with_hwasan(root: &TestDir) -> std::process::Output {
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("record.c"), OVERFLOW).unwrap();
    let seed = root.join("seed.bin");
    std::fs::write(&seed, b"RAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
    Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(root.join("work"))
        .args(["--languages", "c", "--per-target-time", "20", "--jobs", "1"])
        .args([
            "--sanitizers",
            "hwasan,ubsan",
            "--no-discovery-cache",
            "--seed-file",
        ])
        .arg(&seed)
        .output()
        .unwrap()
}

#[cfg(target_arch = "aarch64")]
fn clang_links_hwasan() -> bool {
    let dir = TestDir::new("hwasan-probe");
    let source = dir.join("probe.c");
    std::fs::write(&source, "int main(void) { return 0; }\n").unwrap();
    let exe = dir.join("probe");
    Command::new("clang")
        .args(["-fsanitize=hwaddress", "-o"])
        .arg(&exe)
        .arg(&source)
        .status()
        .is_ok_and(|status| status.success())
        && Command::new(&exe)
            .status()
            .is_ok_and(|status| status.success())
}

#[cfg(target_arch = "aarch64")]
#[test]
fn a_heap_overflow_is_a_hwasan_finding() {
    if !support::require_tool(clang_links_hwasan(), "clang with its HWASan runtime") {
        eprintln!("skipping: clang cannot build and run a HWASan program here");
        return;
    }
    let root = TestDir::new("hwasan-auto");
    let output = auto_with_hwasan(&root);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let work = root.join("work");
    let findings: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("results/findings.json")).unwrap())
            .unwrap();
    let findings = findings["findings"].as_array().unwrap();
    let overflow = findings
        .iter()
        .find(|finding| finding["rule"]["id"] == "BHF-201")
        .unwrap_or_else(|| panic!("no heap overflow finding: {findings:#?}\n{stderr}"));
    let text = overflow.to_string();
    assert!(text.contains("HWASAN_HEAP_BUFFER_OVERFLOW"), "{overflow:#}");
    assert!(text.contains("HWAddressSanitizer"), "{overflow:#}");
    assert!(text.contains("record.c"), "{overflow:#}");
}

#[cfg(not(target_arch = "aarch64"))]
#[test]
fn hwasan_is_refused_off_aarch64_before_anything_builds() {
    let root = TestDir::new("hwasan-refused");
    let output = auto_with_hwasan(&root);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("--sanitizers hwasan needs an AArch64 host"),
        "{stderr}"
    );
    assert!(
        !root.join("work/harnesses").exists(),
        "no harness is built: {stderr}"
    );
}
