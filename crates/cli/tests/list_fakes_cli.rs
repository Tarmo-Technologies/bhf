// SPDX-License-Identifier: Apache-2.0

//! End-to-end check that `bhf auto --list-fakes` prints the
//! manifest as a table.

use std::process::Command;

fn bhf_bin() -> std::path::PathBuf {
    let path = env!("CARGO_BIN_EXE_bhf");
    std::path::PathBuf::from(path)
}

#[test]
fn bhf_auto_list_fakes_prints_known_plugins() {
    let output = Command::new(bhf_bin())
        .args(["auto", ".", "--list-fakes"])
        .output()
        .expect("spawn bhf auto --list-fakes");
    assert!(
        output.status.success(),
        "bhf auto --list-fakes exit={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    for name in ["env", "net", "fs", "dl", "dlsym", "identity"] {
        assert!(
            stdout.contains(name),
            "missing {name} in --list-fakes output: {stdout}"
        );
    }
    assert!(stdout.contains("BHF_FAKE_IDENTITY"));
    assert!(stdout.contains("env-gated"));
    assert!(stdout.contains("always-on"));
}
