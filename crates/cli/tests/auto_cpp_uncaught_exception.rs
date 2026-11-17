// SPDX-License-Identifier: Apache-2.0

//! An exception that leaves a C++ target is an uncaught-exception finding
//! (#242, BHF-231, CWE-248). The C++ harness caught every exception with
//! `catch (...)` and returned, so `std::out_of_range` from `vector::at` on
//! an input-derived index was never reported. An exception type listed as
//! expected (`--cxx-expected-exception`) is the target rejecting the input.

#![cfg(unix)]

use std::path::Path;
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// `net::Decoder::decode` indexes a four-element vector with `.at()` past its
/// end when the record starts with `E`.
const DECODER: &str = "#include <cstddef>\n#include <cstdint>\n#include <vector>\n\
     namespace net {\n\
     class Decoder {\n\
     public:\n\
     \x20   int decode(const std::uint8_t *data, std::size_t len) {\n\
     \x20       std::vector<int> v = {1, 2, 3, 4};\n\
     \x20       if (len > 3 && data[0] == 'E') return v.at(data[1] + 100);\n\
     \x20       return v.at(0);\n\
     \x20   }\n\
     };\n\
     }\n";

fn uncaught(work: &Path, extra: &[&str]) -> Vec<serde_json::Value> {
    let root = work.parent().unwrap();
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("decoder.cpp"), DECODER).unwrap();
    let seed = root.join("seed.bin");
    std::fs::write(&seed, b"E\x01\x02\x03").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(work)
        .args(["--per-target-time", "5", "--jobs", "1", "--seed-file"])
        .arg(&seed)
        .args(extra)
        .output()
        .unwrap();
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{log}");
    assert!(log.contains("built+fuzzed"), "{log}");
    std::fs::read_dir(work.join("results/findings"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            serde_json::from_slice::<serde_json::Value>(
                &std::fs::read(entry.path().join("finding.json")).ok()?,
            )
            .ok()
        })
        .filter(|finding| finding["rule_id"] == "BHF-231")
        .collect()
}

fn clang_runs() -> bool {
    let present = {
        Command::new("clang++")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    };
    support::require_tool(present, "clang++")
}

#[test]
fn an_out_of_range_from_vector_at_is_an_uncaught_exception_finding() {
    if !clang_runs() {
        eprintln!("skipping: clang++ unavailable");
        return;
    }
    let root = TestDir::new("cpp-uncaught");
    let found = uncaught(&root.join("work"), &[]);
    assert_eq!(found.len(), 1, "{found:#?}");
    let finding = &found[0];
    let text = finding.to_string();
    assert!(text.contains("std::out_of_range"), "{finding:#}");
    assert!(text.contains("CWE-248"), "{finding:#}");
}

#[test]
fn an_expected_exception_type_is_not_a_finding() {
    if !clang_runs() {
        eprintln!("skipping: clang++ unavailable");
        return;
    }
    let root = TestDir::new("cpp-expected");
    let found = uncaught(
        &root.join("work"),
        &["--cxx-expected-exception", "std::out_of_range"],
    );
    assert!(found.is_empty(), "{found:#?}");
}
