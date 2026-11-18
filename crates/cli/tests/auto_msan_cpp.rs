// SPDX-License-Identifier: Apache-2.0

//! The MSan corpus replay covers C++ (#323): with `BHF_MSAN_LIBCXX` naming
//! an MSan-instrumented libc++ (the full image builds one), a C++ harness
//! builds `main_msan` against it, and a read of memory the target never
//! wrote is a BHF-212 finding that replays. Without one the test skips;
//! `BHF_REQUIRE_TOOLS=1` makes a missing one a failure.
#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// Copies the input into a `std::string` (libc++ code MSan must see as
/// instrumented), then branches on a heap field it never wrote when the
/// first byte is zero.
const TARGET: &str = "#include <cstddef>\n#include <cstdio>\n#include <string>\n\
                      int parse_record(const unsigned char *data, size_t len) {\n  \
                      if (len < 1) return 0;\n  \
                      std::string tag(reinterpret_cast<const char *>(data), len);\n  \
                      int *fields = new int[4];\n  \
                      int large = 0;\n  \
                      if (tag[0] != 0) fields[1] = tag[0];\n  \
                      if (fields[1] > 3) {\n    std::puts(\"large record\");\n    large = 1;\n  }\n  \
                      delete[] fields;\n  \
                      return large;\n}\n";

/// The MSan-instrumented libc++ prefix, if `BHF_MSAN_LIBCXX` names one.
fn msan_libcxx() -> Option<PathBuf> {
    let prefix = PathBuf::from(std::env::var_os("BHF_MSAN_LIBCXX")?);
    (prefix.join("include/c++/v1").is_dir() && prefix.join("lib").is_dir()).then_some(prefix)
}

#[test]
fn a_cpp_uninitialized_read_is_an_msan_finding_that_replays() {
    let have_clang = Command::new("clang++").arg("--version").output().is_ok();
    if !support::require_tool(
        have_clang && msan_libcxx().is_some(),
        "clang++ and BHF_MSAN_LIBCXX (an MSan-instrumented libc++)",
    ) {
        eprintln!("skipping: no BHF_MSAN_LIBCXX for the C++ MemorySanitizer build");
        return;
    }
    let root = TestDir::new("msan-cpp");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("rec.cpp"), TARGET).unwrap();
    let work = root.join("work");
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--jobs", "1", "--per-target-time", "5"])
        .arg(&src)
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let finding = work.join("results/findings/F-MSAN-0000");
    assert!(
        finding.join("finding.json").is_file(),
        "the MSan replay finds the C++ read:\n{stderr}"
    );
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(finding.join("finding.json")).unwrap()).unwrap();
    assert_eq!(raw["exception"]["sanitizer"], "msan");
    let top = raw["exception"]["stack"][0]["function"]
        .as_str()
        .unwrap_or_default();
    assert!(top.contains("parse_record"), "{raw:#}");
    let log = std::fs::read_to_string(finding.join("sanitizer.log")).unwrap();
    assert!(log.contains("use-of-uninitialized-value"), "{log}");
    // The report is at the planted read, not in the std::string copy.
    assert!(log.contains("rec.cpp"), "{log}");

    let replay = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["replay", "--finding"])
        .arg(&finding)
        .output()
        .expect("run bhf replay");
    let replayed = String::from_utf8_lossy(&replay.stdout);
    assert!(
        replay.status.success() && replayed.starts_with("MATCH"),
        "{replayed}\n{}",
        String::from_utf8_lossy(&replay.stderr)
    );
}
