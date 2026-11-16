// SPDX-License-Identifier: Apache-2.0

//! The docs write `--timeout 500ms`, which `bhf fuzz` and `bhf auto` refused:
//! their duration parser took whole seconds, minutes or hours only. Durations
//! now take milliseconds and fractions.

use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn bhf(args: &[&str], dir: &std::path::Path) -> (Option<i32>, String) {
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
fn millisecond_and_fractional_durations_are_accepted() {
    let work = TestDir::new("duration-flags");
    std::fs::create_dir_all(work.join("src")).unwrap();
    for timeout in ["500ms", "0.5s"] {
        let (code, stderr) = bhf(
            &["auto", "src", "--dry-run", "--timeout", timeout],
            work.path(),
        );
        assert!(!stderr.contains("invalid duration"), "{timeout}: {stderr}");
        assert_ne!(code, Some(2), "{timeout}: {stderr}");
        // No harness to fuzz: the run gets past the flags to the lookup.
        let (_, stderr) = bhf(
            &["fuzz", "bhf_work", "--harness", "h", "--timeout", timeout],
            work.path(),
        );
        assert!(!stderr.contains("invalid duration"), "{timeout}: {stderr}");
    }
    let (code, stderr) = bhf(
        &["fuzz", "bhf_work", "--harness", "h", "--timeout", "5x"],
        work.path(),
    );
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("invalid duration '5x'"), "{stderr}");
}
