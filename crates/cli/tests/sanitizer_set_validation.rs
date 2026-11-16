// SPDX-License-Identifier: Apache-2.0

//! `--sanitizers msan,asan` was accepted, so every target then failed to build
//! (clang refuses `-fsanitize=address,memory`) and the failures were filed as
//! bhf code-generation bugs; `--dry-run` also accepted `--engine bogus`. Both
//! are refused with exit 2 before anything runs, the dry run included.

use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn bhf(dir: &std::path::Path, args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn incompatible_sanitizers_and_unknown_engines_exit_2() {
    let work = TestDir::new("sanitizer-set");
    std::fs::create_dir_all(work.join("src")).unwrap();
    for set in ["msan,asan", "tsan,ubsan"] {
        let (code, stderr) = bhf(work.path(), &["auto", "src", "--sanitizers", set]);
        assert_eq!(code, Some(2), "auto {set}: {stderr}");
        assert!(stderr.contains("cannot be combined with"), "{stderr}");
        let (code, stderr) = bhf(
            work.path(),
            &["fuzz", "bhf_work", "--harness", "h", "--sanitizers", set],
        );
        assert_eq!(code, Some(2), "fuzz {set}: {stderr}");
        assert!(stderr.contains("cannot be combined with"), "{stderr}");
    }
    let (code, stderr) = bhf(
        work.path(),
        &["auto", "src", "--dry-run", "--engine", "bogus"],
    );
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("unknown fuzz engine 'bogus'"), "{stderr}");
    let (code, stderr) = bhf(
        work.path(),
        &["auto", "src", "--dry-run", "--sanitizers", "asan,ubsan"],
    );
    assert_ne!(code, Some(2), "a compatible set still plans: {stderr}");
}
