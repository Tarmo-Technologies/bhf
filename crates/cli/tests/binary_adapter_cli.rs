// SPDX-License-Identifier: Apache-2.0

use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

#[test]
fn binary_adapter_normalizes_mock_contract_and_error_reports() {
    let root = temp_dir("mock");
    let target = root.join("sample.elf");
    write_elf64_x86_64(&target);
    let mock = root.join("mock-adapter.json");
    fs::write(
        &mock,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "bhf.binary.adapter.mock.v1",
            "adapter": "mock-disasm",
            "status": "ok",
            "functions": [{ "name": "parse", "address": "0x1000", "signature": "int parse(char *)" }],
            "call_graph": [{ "caller": "main", "callee": "parse" }],
            "strings": [{ "address": "0x2000", "value": "usage: legacy" }],
            "xrefs": [{ "from": "0x1000", "to": "0x2000", "kind": "data" }]
        }))
        .unwrap(),
    )
    .unwrap();

    let out = root.join("out-ok");
    assert_success(
        Command::new(bhf_bin())
            .args([
                "binary-adapter",
                target.to_str().unwrap(),
                "--adapter",
                "mock",
                "--mock-output",
                mock.to_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    let report = read_json(&out.join("binary-adapter-report.json"));
    assert_eq!(report["schema_version"], "bhf.binary.adapter.v1");
    assert_eq!(report["evidence_kind"], "adapter_derived");
    assert_eq!(report["adapter"]["kind"], "mock");
    assert_eq!(report["functions"][0]["name"], "parse");
    assert_eq!(report["call_graph"][0]["callee"], "parse");
    assert_eq!(report["strings"][0]["value"], "usage: legacy");
    assert_eq!(report["xrefs"][0]["kind"], "data");

    let mock_error = root.join("mock-error.json");
    fs::write(
        &mock_error,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "bhf.binary.adapter.mock.v1",
            "adapter": "mock-disasm",
            "status": "error",
            "error": "adapter timeout"
        }))
        .unwrap(),
    )
    .unwrap();
    let out_error = root.join("out-error");
    let output = Command::new(bhf_bin())
        .args([
            "binary-adapter",
            target.to_str().unwrap(),
            "--adapter",
            "mock",
            "--mock-output",
            mock_error.to_str().unwrap(),
            "--out",
            out_error.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let error_report = read_json(&out_error.join("binary-adapter-report.json"));
    assert_eq!(error_report["status"], "error");
    assert_eq!(error_report["errors"][0]["message"], "adapter timeout");
}

#[test]
fn binary_adapter_blocks_real_adapters_by_default_and_skips_missing_tools_when_opted_in() {
    let root = temp_dir("policy");
    let target = root.join("sample.elf");
    write_elf64_x86_64(&target);
    let missing_tool = root.join("missing-rizin").to_string_lossy().into_owned();

    let blocked = Command::new(bhf_bin())
        .args([
            "binary-adapter",
            target.to_str().unwrap(),
            "--adapter",
            "rizin",
            "--tool",
            &missing_tool,
            "--out",
            root.join("blocked").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(blocked.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("not allowed"));

    let out = root.join("skipped");
    let skipped = Command::new(bhf_bin())
        .args([
            "--profile",
            "external-tools",
            "binary-adapter",
            target.to_str().unwrap(),
            "--adapter",
            "rizin",
            "--tool",
            &missing_tool,
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    // A missing tool is an error, not a successful run.
    assert_eq!(skipped.status.code(), Some(1));
    let report = read_json(&out.join("binary-adapter-report.json"));
    assert_eq!(report["adapter"]["kind"], "rizin");
    assert_eq!(report["status"], "skipped");
    assert_eq!(report["errors"][0]["reason"], "tool_not_found");
}

/// `bhf --profile external-tools binary adapter <target> --adapter <kind>
/// --tool <tool>`: its exit code and report.
#[cfg(unix)]
fn run_adapter(root: &Path, kind: &str, tool: &Path) -> (Option<i32>, serde_json::Value) {
    let target = root.join("sample.elf");
    write_elf64_x86_64(&target);
    let out = root.join(format!("out-{kind}"));
    let output = Command::new(bhf_bin())
        .args(["--profile", "external-tools", "binary", "adapter"])
        .arg(&target)
        .args(["--adapter", kind, "--tool"])
        .arg(tool)
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    (
        output.status.code(),
        read_json(&out.join("binary-adapter-report.json")),
    )
}

/// A script that exits `code` whatever it is asked.
#[cfg(unix)]
fn fake_tool(root: &Path, name: &str, code: i32) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = root.join(name);
    fs::write(
        &path,
        format!("#!/bin/sh\necho {name} 1.2.3\nexit {code}\n"),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// The Rizin, Ghidra and angr adapters run no analysis: with their tool they
/// say so (exit 3), without it they are skipped (exit 1). They wrote empty
/// arrays as a successful `smoke_tested` analysis, and angr's ran
/// `python3 --version`, which succeeds without angr.
#[cfg(unix)]
#[test]
fn each_real_adapter_is_not_implemented_with_its_tool_and_skipped_without() {
    for kind in ["rizin", "ghidra", "angr"] {
        let root = temp_dir(&format!("real-{kind}"));
        let present = fake_tool(&root, &format!("{kind}-tool"), 0);
        let (code, report) = run_adapter(&root, kind, &present);
        assert_eq!(code, Some(3), "{kind}: {report:#}");
        assert_eq!(report["status"], "not_implemented", "{kind}");
        assert_eq!(report["errors"][0]["reason"], "not_implemented", "{kind}");
        assert_eq!(report["functions"], json!([]), "{kind}");

        let (code, report) = run_adapter(&root, kind, &root.join("no-such-tool"));
        assert_eq!(code, Some(1), "{kind}: {report:#}");
        assert_eq!(report["status"], "skipped", "{kind}");
        assert_eq!(report["errors"][0]["reason"], "tool_not_found", "{kind}");
    }
    // A Python that cannot import angr is no angr.
    let root = temp_dir("real-angr-missing");
    let python_without_angr = fake_tool(&root, "python-no-angr", 1);
    let (code, report) = run_adapter(&root, "angr", &python_without_angr);
    assert_eq!(code, Some(1), "{report:#}");
    assert_eq!(report["errors"][0]["reason"], "tool_not_found");
}

#[test]
fn the_adapter_help_does_not_claim_an_analysis() {
    let output = Command::new(bhf_bin())
        .args(["binary", "--help"])
        .output()
        .unwrap();
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(
        !help.contains("Analyze a binary via external adapters"),
        "{help}"
    );
    assert!(
        help.contains("no analysis through them is implemented yet"),
        "{help}"
    );
}

fn assert_success(output: std::process::Output) {
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn write_elf64_x86_64(path: &Path) {
    let mut bytes = vec![0u8; 64];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    fs::write(path, bytes).unwrap();
}

fn bhf_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bhf"))
}

fn temp_dir(name: &str) -> TestDir {
    TestDir::new(&format!("binary-adapter-{name}"))
}
