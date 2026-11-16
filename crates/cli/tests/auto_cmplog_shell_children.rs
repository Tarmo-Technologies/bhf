// SPDX-License-Identifier: Apache-2.0
// Linux only: the comparison records come from the LD_PRELOAD runtrace shim.
#![cfg(target_os = "linux")]

//! A target that runs a shell through `popen` filled its `cmplog.jsonl` with
//! the shell's own comparisons (its keyword table: `elif`, `until`, `jobs`),
//! which then reached the mutator's dictionary. bhf names the harness image in
//! `BHF_TARGET_EXE` and the shim records only there, so the shell's
//! comparisons are gone and the harness's fork-server children still record
//! the target's.

use std::fs;
use std::path::{Path, PathBuf};

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// Words of the shell's keyword and builtin tables that the target's source
/// does not hold, so no input bhf mines from it is one (`esac` is in its
/// `popen` command, and a fuzz input of it is the target's to compare).
const SHELL_KEYWORDS: &[&str] = &["elif", "until", "jobs"];

const TARGET: &str = "#include <stdio.h>\n\
                      #include <string.h>\n\
                      int check_tag(const unsigned char *d, unsigned long n) {\n\
                          FILE *shell;\n\
                          char line[64];\n\
                          if (n < 4) return 0;\n\
                          shell = popen(\"for w in alpha beta; do case $w in alpha) : ;; *) : ;; esac; done\", \"r\");\n\
                          if (shell) {\n\
                              while (fgets(line, sizeof line, shell)) {}\n\
                              pclose(shell);\n\
                          }\n\
                          return memcmp(d, \"PHAS\", 4) == 0;\n\
                      }\n";

/// Every file named `name` under `root`.
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

fn hex(text: &str) -> String {
    text.bytes().map(|b| format!("{b:02x}")).collect()
}

/// The hex operands of a cmplog record line.
fn operands(record: &str) -> [String; 2] {
    ["a", "b"].map(|key| {
        let open = format!("\"{key}\":\"");
        record
            .find(&open)
            .map(|at| {
                let rest = &record[at + open.len()..];
                rest[..rest.find('"').unwrap_or(rest.len())].to_owned()
            })
            .unwrap_or_default()
    })
}

#[test]
fn a_shell_the_target_runs_adds_no_comparisons() {
    if !support::libfuzzer_toolchain_available("cmplog-shell") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }
    let root = TestDir::new("auto-cmplog-shell");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("tag.c"), TARGET).unwrap();
    let out = support::bhf_cargo_command()
        .current_dir(root.path())
        .args(["auto", src.to_str().unwrap(), "--per-target-time", "3"])
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() || out.status.code() == Some(1),
        "{stderr}"
    );
    let logs = files_named(root.path(), "cmplog.jsonl");
    assert!(!logs.is_empty(), "no cmplog.jsonl: {stderr}");
    let records: Vec<String> = logs
        .iter()
        .flat_map(|log| {
            fs::read_to_string(log)
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect();
    let keywords: Vec<String> = SHELL_KEYWORDS.iter().map(|k| hex(k)).collect();
    let from_shell: Vec<&String> = records
        .iter()
        .filter(|record| operands(record).iter().any(|op| keywords.contains(op)))
        .collect();
    assert!(
        from_shell.is_empty(),
        "the shell's comparisons: {from_shell:?}"
    );
    // The fork-server children ran the target's comparison.
    assert!(
        records
            .iter()
            .any(|record| operands(record).iter().any(|op| *op == hex("PHAS"))),
        "the target's memcmp is not recorded: {records:?}"
    );
    for dictionary in files_named(root.path(), "learned_dictionary.txt") {
        let text = fs::read_to_string(&dictionary).unwrap();
        for keyword in SHELL_KEYWORDS {
            assert!(
                !text.contains(&format!("\"{keyword}\"")),
                "{}: {text}",
                dictionary.display()
            );
        }
    }
}
