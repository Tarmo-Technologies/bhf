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

/// The adapters that run an external analyzer.
#[cfg(unix)]
const ANALYZERS: &[&str] = &["rizin", "ghidra"];

/// A tool that answers its probe and writes, or prints, the analysis its real
/// counterpart recorded for `tests/fixtures/binary_adapter/legacy.c`: rizin
/// prints it, `analyzeHeadless` and angr's Python write it where the bundled
/// script would.
#[cfg(unix)]
fn recording_tool(root: &Path, kind: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let recorded = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/binary_adapter/testdata");
    let script = match kind {
        "rizin" => format!(
            "#!/bin/sh\n[ \"$1\" = -v ] && {{ echo 'rizin 0.9.1 @ linux-x86-64'; exit 0; }}\n\
             cat '{}'\n",
            recorded.join("rizin-legacy.out").display()
        ),
        // analyzeHeadless <project> <name> -import <binary> -scriptPath <dir>
        //   -postScript BhfExport.java <export> <limit> -deleteProject
        "ghidra" => format!(
            "#!/bin/sh\nscripts=$6\n[ \"$7 $8\" = '-postScript BhfExport.java' ] || exit 9\n\
             grep -q 'class BhfExport' \"$scripts/BhfExport.java\" || exit 9\n\
             cp '{}' \"$9\"\n",
            recorded.join("ghidra-legacy.json").display()
        ),
        other => panic!("{other}"),
    };
    let path = root.join(format!("{kind}-recording"));
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// Each real adapter maps what its tool exports into the report: the
/// functions at the binary's own addresses, the call graph, the strings and
/// the xrefs, `ok` and exit 0. They used to run only the tool's `--version`
/// and write empty arrays.
#[cfg(unix)]
#[test]
fn each_real_adapter_reports_the_analysis_its_tool_exports() {
    for &kind in ANALYZERS {
        let root = temp_dir(&format!("recorded-{kind}"));
        let (code, report) = run_adapter(&root, kind, &recording_tool(&root, kind));
        assert_eq!(code, Some(0), "{kind}: {report:#}");
        assert_eq!(report["status"], "ok", "{kind}");
        assert_eq!(report["errors"], json!([]), "{kind}");
        assert_eq!(report["truncated"], json!([]), "{kind}");
        let parse_header = report["functions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|function| function["name"] == "parse_header")
            .unwrap_or_else(|| panic!("{kind}: {report:#}"));
        assert_eq!(parse_header["address"], "0x1169", "{kind}");
        assert!(
            report["call_graph"]
                .as_array()
                .unwrap()
                .contains(&json!({ "caller": "handle", "callee": "parse_header" })),
            "{kind}: {report:#}"
        );
        assert!(
            report["strings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|string| string["value"] == "LEGACY/1.0"),
            "{kind}"
        );
        assert!(
            report["xrefs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|xref| xref["kind"] == "call" && xref["to"] == "0x1169"),
            "{kind}"
        );
    }
}

/// A tool that prints no analysis is an error, a tool that is not there is
/// skipped, and so is a Python that cannot import angr: exit 1 each time.
#[cfg(unix)]
#[test]
fn a_real_adapter_without_an_analysis_is_an_error_or_skipped() {
    for &kind in ANALYZERS {
        let root = temp_dir(&format!("real-{kind}"));
        let present = fake_tool(&root, &format!("{kind}-tool"), 0);
        let (code, report) = run_adapter(&root, kind, &present);
        assert_eq!(code, Some(1), "{kind}: {report:#}");
        assert_eq!(report["status"], "error", "{kind}");
        assert_eq!(report["errors"][0]["reason"], "bad_output", "{kind}");
        assert_eq!(report["functions"], json!([]), "{kind}");

        let (code, report) = run_adapter(&root, kind, &root.join("no-such-tool"));
        assert_eq!(code, Some(1), "{kind}: {report:#}");
        assert_eq!(report["status"], "skipped", "{kind}");
        assert_eq!(report["errors"][0]["reason"], "tool_not_found", "{kind}");
    }
    let root = temp_dir("real-angr-missing");
    let python_without_angr = fake_tool(&root, "python-no-angr", 1);
    let (code, report) = run_adapter(&root, "angr", &python_without_angr);
    assert_eq!(code, Some(1), "{report:#}");
    assert_eq!(report["status"], "skipped");
    assert_eq!(report["errors"][0]["reason"], "tool_not_found");
}

/// The adapters that find their tool but run no analysis yet.
#[cfg(unix)]
const NOT_YET: &[&str] = &["angr"];

/// An adapter whose analysis bhf does not run yet says so with its tool
/// (exit 3).
#[cfg(unix)]
#[test]
fn an_adapter_with_no_analysis_yet_says_so() {
    for &kind in NOT_YET {
        let root = temp_dir(&format!("unimplemented-{kind}"));
        let present = fake_tool(&root, &format!("{kind}-tool"), 0);
        let (code, report) = run_adapter(&root, kind, &present);
        assert_eq!(code, Some(3), "{kind}: {report:#}");
        assert_eq!(report["status"], "not_implemented", "{kind}");
        assert_eq!(report["errors"][0]["reason"], "not_implemented", "{kind}");
        assert_eq!(report["functions"], json!([]), "{kind}");
    }
}

#[test]
fn the_adapter_help_names_the_analyzers_it_runs() {
    let output = Command::new(bhf_bin())
        .args(["binary", "--help"])
        .output()
        .unwrap();
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(
        help.contains(
            "with Rizin or Ghidra headless, run as subprocesses (angr: no analysis yet, exit 3)"
        ),
        "{help}"
    );
    assert!(
        !help.contains("no analysis through them is implemented"),
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
