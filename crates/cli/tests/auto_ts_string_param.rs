// SPDX-License-Identifier: Apache-2.0

//! A TypeScript parameter's annotation decides what the driver passes it. A
//! `decode(data: string)` read as byte-like from its name alone got a `Buffer`,
//! whose missing `trim` threw a suppressed `TypeError` on every input, so the
//! bug past it was never reached. With the annotation honoured it gets a
//! string and the planted throw is reported.
#![cfg(unix)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const TARGET: &str = "export function decode(data: string): number {\n  \
                      const body = data.trim();\n  \
                      if (body.startsWith('{') && !body.endsWith('}')) {\n    \
                      throw new Error('unterminated object');\n  \
                      }\n  \
                      return body.length;\n}\n";

fn have(tool: &str) -> bool {
    let present = { which::which(tool).is_ok() };
    support::require_tool(present, tool)
}

#[test]
fn a_string_annotated_data_param_gets_a_string_and_its_planted_throw_is_found() {
    if !have("node") || !have("esbuild") {
        eprintln!("skipping: node or esbuild unavailable");
        return;
    }
    let root = TestDir::new("ts-string-param");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("decoder.ts"), TARGET).unwrap();
    let work: PathBuf = root.join("work");

    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--languages", "typescript", "--max-targets", "1"])
        .args(["--jobs", "1", "--per-target-time", "10", "--single-pass"])
        .arg(&src)
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);

    let findings = fs::read_to_string(work.join("results/findings.json")).unwrap_or_default();
    assert!(
        findings.contains("decode") && findings.contains("unterminated object"),
        "the planted throw behind `data.trim()` must be found:\n{findings}\n{stderr}"
    );
}
