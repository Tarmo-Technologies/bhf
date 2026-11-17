// SPDX-License-Identifier: Apache-2.0

//! The runtrace shim's sink oracles in the Python and Perl lanes (#300).
//!
//! The shim was never preloaded into an interpreter launcher, so a Python or
//! Perl target that opened a path or ran a command its input controlled was
//! never reported. It is now, recording only from target entry (the
//! interpreter's own start-up is not the target's), with the driver writing
//! each input where the shim can match it against a sink's argument.

#![cfg(target_os = "linux")]

use serde_json::Value;
use std::path::Path;
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn have(program: &str) -> bool {
    let present = Command::new(program)
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success());
    support::require_tool(present, program)
}

/// `bhf auto` over `file` (named `name`); the rule ids of its findings.
fn auto_rules(root: &Path, name: &str, file: &str) -> Vec<String> {
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join(name), file).unwrap();
    let work = root.join("work");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bhf"));
    support::configure_runtrace_shim(&mut cmd);
    let out = cmd
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        .args(["--per-target-time", "8", "--jobs", "1"])
        .output()
        .unwrap();
    let log = String::from_utf8_lossy(&out.stderr);
    assert!(log.contains("built+fuzzed"), "{log}");
    let Ok(entries) = std::fs::read_dir(work.join("results/findings")) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| std::fs::read(entry.path().join("finding.json")).ok())
        .filter_map(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .map(|finding| finding["rule_id"].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// A path built from the input reaches `open`: BHF-405 (CWE-22).
#[test]
fn a_python_target_opening_an_input_path_is_a_path_finding() {
    if !have("python3") {
        eprintln!("skipping: no python3");
        return;
    }
    let root = TestDir::new("py-sink-open");
    let rules = auto_rules(
        root.path(),
        "docs.py",
        "import os\n\n\ndef read_doc(name: str) -> int:\n    \
         path = os.path.join(\"/tmp\", \"bhf-docs\", name)\n    try:\n        \
         with open(path, \"rb\") as handle:\n            return len(handle.read())\n    \
         except OSError:\n        return -1\n",
    );
    assert!(rules.iter().any(|rule| rule == "BHF-405"), "{rules:?}");
}

/// A command built from the input reaches a shell: BHF-431 (CWE-78).
#[test]
fn a_perl_target_running_an_input_command_is_a_command_finding() {
    if !have("perl") {
        eprintln!("skipping: no perl");
        return;
    }
    let root = TestDir::new("pl-sink-system");
    let rules = auto_rules(
        root.path(),
        "Tool.pm",
        "package Tool;\nuse strict;\nuse warnings;\n\nsub run_tool {\n    \
         my ($arg) = @_;\n    return 0 if length($arg) > 40;\n    \
         return system(\"echo $arg > /dev/null\");\n}\n\n1;\n",
    );
    assert!(rules.iter().any(|rule| rule == "BHF-431"), "{rules:?}");
}

/// The interpreter's start-up (imports, the driver's own files) is not the
/// target's: a target with no sink has no finding.
#[test]
fn a_clean_python_target_has_no_findings() {
    if !have("python3") {
        eprintln!("skipping: no python3");
        return;
    }
    let root = TestDir::new("py-sink-clean");
    let rules = auto_rules(
        root.path(),
        "nums.py",
        "def parse_pair(text: str) -> int:\n    parts = text.split(\",\")\n    \
         if len(parts) != 2:\n        return 0\n    try:\n        \
         return int(parts[0]) + int(parts[1])\n    except ValueError:\n        return -1\n",
    );
    assert!(rules.is_empty(), "{rules:?}");
}
