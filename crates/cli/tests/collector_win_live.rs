// SPDX-License-Identifier: Apache-2.0
#![cfg(windows)]

//! The native Windows ETW collector end to end, under `bhf binary fuzz
//! --collector auto`: the host launches the target under the ready sidecar
//! and hands it the target's PID, and the sidecar attributes what that
//! process tree did. The sidecar ignored the handoff, rooted at PID 0 and
//! slept a fixed window, so every replay was `replayed_process_not_observed`.
//!
//! Positive control: a target that runs `cmd.exe` through ShellExecuteEx with
//! its input in the command line has a controlled-process-execution finding
//! (BHF-431, taint-confirmed). Clean control: the same with a constant command
//! line, free of shell syntax (which the BHF-304 heuristic flags whoever
//! wrote it), is observed and has none. Like the crate's other live ETW tests
//! these need an elevated Windows host and run only with BHF_WIN_LIVE=1.

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const TOOL_C: &str = r#"#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#pragma comment(lib, "shell32.lib")
int main(void) {
    char input[64];
    char params[160];
    size_t n = fread(input, 1, sizeof input - 1, stdin);
    SHELLEXECUTEINFOA run = { sizeof run };
    input[n] = 0;
#ifdef CONSTANT_COMMAND
    snprintf(params, sizeof params, "/c echo fixed-widget-command");
#else
    snprintf(params, sizeof params, "/c echo %s", input);
#endif
    run.fMask = SEE_MASK_NOCLOSEPROCESS;
    run.lpVerb = "open";
    run.lpFile = "cmd.exe";
    run.lpParameters = params;
    run.nShow = SW_HIDE;
    if (ShellExecuteExA(&run) && run.hProcess) {
        WaitForSingleObject(run.hProcess, 10000);
        CloseHandle(run.hProcess);
    }
    return 0;
}
"#;

fn live_enabled() -> bool {
    std::env::var("BHF_WIN_LIVE").as_deref() == Ok("1")
}

/// The sidecar beside the test's bhf, built if it is not there yet.
fn collector_sidecar() -> PathBuf {
    let bhf = PathBuf::from(env!("CARGO_BIN_EXE_bhf"));
    let sidecar = bhf.with_file_name("bhf-collector-win.exe");
    if !sidecar.is_file() {
        let status = Command::new(env!("CARGO"))
            .args(["build", "-p", "bhf_collector_win"])
            .status()
            .unwrap();
        assert!(status.success(), "build bhf-collector-win");
    }
    assert!(sidecar.is_file(), "{}", sidecar.display());
    sidecar
}

fn build_tool(dir: &Path, constant: bool) -> PathBuf {
    let source = dir.join("tool.c");
    std::fs::write(&source, TOOL_C).unwrap();
    let exe = dir.join(if constant {
        "tool_constant.exe"
    } else {
        "tool.exe"
    });
    let mut clang = Command::new("clang");
    clang.arg(&source).arg("-o").arg(&exe);
    if constant {
        clang.arg("-DCONSTANT_COMMAND");
    }
    let out = clang.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    exe
}

/// `bhf binary fuzz` of `exe` under the ETW collector, replaying one seed;
/// the run's collector provenance and its COL findings.
fn collect(dir: &Path, exe: &Path) -> (serde_json::Value, Vec<serde_json::Value>) {
    let work = dir.join(format!(
        "work-{}",
        exe.file_stem().unwrap().to_string_lossy()
    ));
    let seed = dir.join("seed");
    std::fs::write(&seed, b"widget-4c7e91").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .env("BHF_COLLECTOR_WIN", collector_sidecar())
        .args(["binary", "fuzz"])
        .arg(exe)
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--collector",
            "auto",
            "--input-mode",
            "stdin",
            "--iterations",
            "1",
        ])
        .arg("--seed-file")
        .arg(&seed)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let summary: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|error| panic!("summary ({error}):\n{stdout}\n{stderr}"));
    let findings = std::fs::read_dir(work.join("results/findings"))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("COL-"))
        .map(|entry| {
            serde_json::from_slice(&std::fs::read(entry.path().join("finding.json")).unwrap())
                .unwrap()
        })
        .collect();
    (summary["collector"].clone(), findings)
}

#[test]
#[ignore = "requires BHF_WIN_LIVE=1 on an elevated Windows host"]
fn shell_execute_of_the_input_is_found_and_a_constant_command_is_not() {
    if !live_enabled() {
        return;
    }
    let dir = TestDir::new("collector-win-live");
    let (positive, found) = collect(dir.path(), &build_tool(dir.path(), false));
    assert_eq!(positive["observed"], true, "{positive:#}");
    assert!(
        !positive["fidelity"]["unsupported_fields"]
            .as_array()
            .is_some_and(|fields| fields
                .iter()
                .any(|f| f == "replayed_process_not_observed" || f == "target_pid_not_received")),
        "{positive:#}"
    );
    let rules = |findings: &[serde_json::Value]| -> Vec<String> {
        findings
            .iter()
            .map(|raw| format!("{} {}", raw["rule_id"], raw["oracle"]["api"]))
            .collect()
    };
    assert!(
        found.iter().any(|raw| raw["rule_id"] == "BHF-431"),
        "the input-controlled command has no BHF-431 finding: {:?}\n{positive:#}",
        rules(&found)
    );

    let (clean, none) = collect(dir.path(), &build_tool(dir.path(), true));
    assert_eq!(clean["observed"], true, "{clean:#}");
    assert!(
        none.is_empty(),
        "the constant command is a finding: {:?}",
        rules(&none)
    );
}
