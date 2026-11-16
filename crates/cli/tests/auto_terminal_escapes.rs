// SPDX-License-Identifier: Apache-2.0

//! A target's exception message reaches the operator's terminal in `bhf
//! auto`'s top findings. Printed raw, an escape sequence in it could retitle
//! the window or clear the screen (#211): every control character other than
//! tab and line breaks is printed as an escape.

use std::path::PathBuf;
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn have_node() -> bool {
    let present = {
        Command::new("node")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    };
    support::require_tool(present, "node")
}

#[test]
#[cfg_attr(
    windows,
    ignore = "JavaScript runs under WSL on Windows; see docs/site/windows.md"
)]
fn a_target_s_escape_sequences_are_printed_escaped() {
    if !have_node() {
        eprintln!("skipping: no node runtime on PATH");
        return;
    }
    let src = TestDir::new("auto-escapes-src");
    std::fs::write(
        src.join("codec.js"),
        "'use strict';\n\
         function decodeRecord(data) {\n\
           if (data.length > 0) {\n\
             throw new Error('bad record \\u001b]0;pwned\\u0007\\u001b[2J\\u009b31m end');\n\
           }\n\
           return 0;\n\
         }\n\
         module.exports = { decodeRecord };\n",
    )
    .unwrap();
    let work = TestDir::new("auto-escapes-work");
    let out = Command::new(PathBuf::from(env!("CARGO_BIN_EXE_bhf")))
        .args(["auto", src.to_str().unwrap()])
        .args(["--per-target-time", "5", "--single-pass", "--jobs", "1"])
        .arg("--work-dir")
        .arg(work.join("work"))
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stderr.contains("bhf auto: top findings"),
        "the planted throw is found and listed:\n{stderr}"
    );
    assert!(
        stderr.contains("bad record \\x1b]0;pwned\\x07\\x1b[2J\\u{9b}31m end"),
        "the message is shown, escaped:\n{stderr}"
    );
    for (name, text) in [("stderr", &stderr), ("stdout", &stdout)] {
        assert!(
            !text.contains(['\u{1b}', '\u{7}', '\u{9b}']),
            "a raw control character reached {name}:\n{text}"
        );
    }
}
