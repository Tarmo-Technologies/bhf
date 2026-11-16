// SPDX-License-Identifier: Apache-2.0
// Linux only: the command events and their taint come from the LD_PRELOAD
// runtrace shim.
#![cfg(target_os = "linux")]

//! End to end: a target that runs a constant shell command full of shell
//! syntax gets no BHF-304 command-injection finding, and one whose command
//! carries its input bytes still does. Both commands are inert (`echo` to
//! `/dev/null`); the controlled fixture embeds the input inside single quotes
//! and rejects quote and control bytes.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

/// A fresh scratch directory for one test, under Cargo's per-target temp dir.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join("constant-shell-command")
            .join(format!("{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src")).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Every `finding.json` under `root`.
fn findings(root: &Path) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for path in entries.flatten().map(|entry| entry.path()) {
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().is_some_and(|name| name == "finding.json") {
                if let Ok(value) = serde_json::from_slice(&fs::read(&path).unwrap()) {
                    out.push(value);
                }
            }
        }
    }
    out
}

/// Run `bhf auto` over the scratch `src/` and return its findings and output.
fn run_auto(scratch: &Scratch) -> (Vec<serde_json::Value>, String) {
    let work = scratch.0.join("work");
    let mut command = Command::new(env!("CARGO_BIN_EXE_bhf"));
    support::configure_runtrace_shim(&mut command);
    let output = command
        .current_dir(&scratch.0)
        .arg("auto")
        .arg(scratch.0.join("src"))
        .arg("--work-dir")
        .arg(&work)
        .args(["--per-target-time", "3"])
        .output()
        .expect("run bhf auto");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // auto exits 1 when it reports findings.
    assert!(
        output.status.success() || output.status.code() == Some(1),
        "{text}"
    );
    (findings(&work), text)
}

#[test]
fn constant_shell_command_is_not_command_injection() {
    if !support::libfuzzer_toolchain_available("constant-shell-command") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }
    let scratch = Scratch::new("constant");
    fs::write(
        scratch.0.join("src/report.c"),
        "#include <stdio.h>\n\
         int print_report(const unsigned char *d, unsigned long n) {\n\
             FILE *p;\n\
             if (n < 1) return 0;\n\
             p = popen(\"if [ -n \\\"$HOME\\\" ]; then case x in x) echo ok;; esac; fi > /dev/null\", \"r\");\n\
             if (p) pclose(p);\n\
             return d[0];\n\
         }\n",
    )
    .unwrap();

    let (findings, output) = run_auto(&scratch);
    let commands: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| matches!(f["rule_id"].as_str(), Some("BHF-304" | "BHF-431")))
        .collect();
    assert!(
        commands.is_empty(),
        "a constant command is not command injection: {commands:#?}"
    );
    assert!(
        output.contains("shell metacharacters ran without fuzz-input bytes in them"),
        "{output}"
    );
}

#[test]
fn input_derived_shell_command_is_command_injection() {
    if !support::libfuzzer_toolchain_available("input-shell-command") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }
    let scratch = Scratch::new("controlled");
    fs::write(
        scratch.0.join("src/runner.c"),
        "#include <stdlib.h>\n\
         #include <stdio.h>\n\
         #include <string.h>\n\
         int run_cmd(const unsigned char *d, unsigned long n) {\n\
             char arg[256];\n\
             char cmd[512];\n\
             unsigned long i;\n\
             if (n < 4 || n >= sizeof(arg)) return 0;\n\
             for (i = 0; i < n; i++) {\n\
                 if (d[i] == '\\'' || d[i] < 0x20 || d[i] > 0x7e) return 0;\n\
             }\n\
             memcpy(arg, d, n);\n\
             arg[n] = 0;\n\
             snprintf(cmd, sizeof(cmd), \"echo 'bhf_%s' > /dev/null\", arg);\n\
             system(cmd);\n\
             return (int)n;\n\
         }\n",
    )
    .unwrap();

    let (findings, _) = run_auto(&scratch);
    let heuristic = findings
        .iter()
        .find(|f| f["rule_id"] == "BHF-304")
        .unwrap_or_else(|| panic!("expected a BHF-304 finding: {findings:#?}"));
    assert!(
        findings.iter().any(|f| f["rule_id"] == "BHF-431"),
        "the taint-confirmed BHF-431 is beside it: {findings:#?}"
    );
    assert_eq!(heuristic["oracle"]["name"], "command-injection");
    assert_eq!(heuristic["exception"]["name"], "ORACLE_COMMAND_INJECTION");
    let evidence = heuristic["oracle"]["evidence"].as_array().unwrap();
    assert!(
        evidence.iter().any(|e| e["key"] == "taint_path"
            && e["value"].as_str().is_some_and(
                |path| path.starts_with("fuzz_input[") && path.ends_with("→ system(command)")
            )),
        "{evidence:?}"
    );
}
