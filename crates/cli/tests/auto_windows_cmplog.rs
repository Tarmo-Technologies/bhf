// SPDX-License-Identifier: Apache-2.0
// Windows only: the runtime cmplog of a native Windows harness.
#![cfg(windows)]

//! The C driver compiled its runtime cmplog out on Windows, so a Windows
//! harness recorded no comparison operands and `bhf auto` wrote no learned
//! dictionary for it. The driver now appends the same records to the run's
//! log through a FILE_APPEND_DATA handle: a string-gated target's learned
//! dictionary holds the gate token.

use std::fs;
use std::path::{Path, PathBuf};

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const GATED_C: &str = "#include <stddef.h>\n#include <string.h>\n\
                       int check_token(const char *s) {\n\
                           if (strcmp(s, \"WIDGETMAGIC\") == 0) return 1;\n\
                           return 0;\n\
                       }\n";

fn files_named(root: &Path, name: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().is_some_and(|n| n == name) {
                out.push(path);
            }
        }
    }
    out
}

#[test]
fn a_string_gate_reaches_the_learned_dictionary_on_windows() {
    if !support::libfuzzer_toolchain_available("windows-cmplog") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }
    let root = TestDir::new("auto-windows-cmplog");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("gate.c"), GATED_C).unwrap();
    let work = root.join("work");
    let out = support::bhf_cargo_command()
        .current_dir(root.path())
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--per-target-time", "6", src.to_str().unwrap()])
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() || out.status.code() == Some(1),
        "{stderr}"
    );
    let records: String = files_named(&work, "cmplog.jsonl")
        .iter()
        .map(|path| fs::read_to_string(path).unwrap())
        .collect();
    let token_hex: String = "WIDGETMAGIC".bytes().map(|b| format!("{b:02x}")).collect();
    assert!(
        records.contains(&token_hex),
        "no cmplog record of the gate's comparison:\n{records}\n{stderr}"
    );
    let dictionaries: String = files_named(&work, "learned_dictionary.txt")
        .iter()
        .map(|path| fs::read_to_string(path).unwrap())
        .collect();
    assert!(
        dictionaries.contains("\"WIDGETMAGIC\""),
        "the learned dictionary lacks the gate token:\n{dictionaries}\n{stderr}"
    );
}
