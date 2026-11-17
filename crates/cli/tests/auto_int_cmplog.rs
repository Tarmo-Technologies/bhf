// SPDX-License-Identifier: Apache-2.0

//! Integer comparison constants in the runtime cmplog (#221).
//!
//! `check_key` compares its input with `mix(0x1234)`, a constant the compiler
//! folds into the comparison and no source literal spells, so the mined
//! dictionary cannot hold it. The driver logs an integer comparison's
//! constant as an `"int"` record, so a run's learned dictionary, which later
//! runs and the AFL++ and WinAFL lanes load, holds it in both byte orders.
//! A trivial constant (at most 0xff, or all ones) is not logged.

#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const TARGET: &str = "#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n\
                      static uint32_t mix(uint32_t x) {\n\
                          x ^= x >> 16;\n    x *= 0x7feb352du;\n    x ^= x >> 15;\n    return x;\n}\n\
                      int check_key(const unsigned char *data, size_t len) {\n\
                          uint32_t key;\n\
                          if (len < 4) return 0;\n\
                          memcpy(&key, data, sizeof key);\n\
                          if (key == 0xffffffffu) return -1;\n\
                          return key == mix(0x1234);\n\
                      }\n";

/// The C `mix`, so the test knows the constant the compiler folded.
fn mix(mut x: u32) -> u32 {
    x ^= x >> 16;
    x = x.wrapping_mul(0x7feb_352d);
    x ^= x >> 15;
    x
}

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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A dictionary line's token as the AFL++ format escapes it.
fn dictionary_line(token: &[u8]) -> String {
    let mut line = String::from("\"");
    for byte in token {
        match *byte {
            b'\\' => line.push_str("\\\\"),
            b'"' => line.push_str("\\\""),
            0x20..=0x7e => line.push(char::from(*byte)),
            other => line.push_str(&format!("\\x{other:02x}")),
        }
    }
    line.push('"');
    line
}

#[test]
fn a_folded_integer_constant_reaches_the_learned_dictionary() {
    if !support::libfuzzer_toolchain_available("auto-int-cmplog") {
        eprintln!("skipping: clang toolchain unavailable");
        return;
    }
    let root = TestDir::new("auto-int-cmplog");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("key.c"), TARGET).unwrap();
    let work = root.join("work");
    let out = support::bhf_cargo_command()
        .current_dir(root.path())
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--per-target-time", "4", src.to_str().unwrap()])
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() || out.status.code() == Some(1),
        "{stderr}"
    );

    let key = mix(0x1234).to_le_bytes();
    let records: Vec<serde_json::Value> = files_named(&work, "cmplog.jsonl")
        .iter()
        .flat_map(|path| {
            fs::read_to_string(path)
                .unwrap()
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect::<Vec<serde_json::Value>>()
        })
        .collect();
    let ints: Vec<&str> = records
        .iter()
        .filter(|record| record["k"] == "int")
        .filter_map(|record| record["a"].as_str())
        .collect();
    assert!(
        ints.contains(&hex(&key).as_str()),
        "no int record of mix(0x1234) = {:#x}: {ints:?}\n{stderr}",
        mix(0x1234)
    );
    for trivial in ["0400000000000000", "ffffffff"] {
        assert!(
            !ints.contains(&trivial),
            "trivial constant {trivial} logged"
        );
    }

    let dictionaries: String = files_named(&work, "learned_dictionary.txt")
        .iter()
        .map(|path| fs::read_to_string(path).unwrap())
        .collect();
    let mut big_endian = key;
    big_endian.reverse();
    for token in [key, big_endian] {
        let line = dictionary_line(&token);
        assert!(
            dictionaries.lines().any(|l| l == line),
            "the learned dictionary lacks {line}:\n{dictionaries}"
        );
    }
}
