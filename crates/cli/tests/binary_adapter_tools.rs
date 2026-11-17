// SPDX-License-Identifier: Apache-2.0

//! `bhf binary adapter` against the real Rizin and Ghidra (#264, #265), on
//! `tests/fixtures/binary_adapter/legacy.c` built with `cc -O0`.
//!
//! These run where `BHF_BINARY_ANALYZERS=1`: the nightly's binary-analyzers
//! job installs the pinned tools and sets it, with `BHF_REQUIRE_TOOLS=1`, so
//! a missing tool fails the test there. The tools are `BHF_RIZIN` and
//! `BHF_GHIDRA_HEADLESS` (Ghidra's `support/analyzeHeadless`, with a JDK 25
//! on `PATH` or in `JAVA_HOME`), else `rizin` and `analyzeHeadless` on
//! `PATH`.

#![cfg(target_os = "linux")]

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// The analyzer `kind` runs, if this run tests the analyzers and it is there.
fn analyzer(kind: &str, variable: &str, default: &str) -> Option<PathBuf> {
    if std::env::var_os("BHF_BINARY_ANALYZERS").is_none_or(|value| value != "1") {
        eprintln!("skip binary_adapter_tools: set BHF_BINARY_ANALYZERS=1");
        return None;
    }
    let tool = std::env::var_os(variable)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default));
    let present = match kind {
        "rizin" => Command::new(&tool)
            .arg("-v")
            .stdin(Stdio::null())
            .output()
            .is_ok_and(|output| output.status.success()),
        _ => which::which(&tool).is_ok(),
    };
    support::require_tool(present, kind).then_some(tool)
}

/// The fixture, built, and its symbols' addresses as `nm` gives them.
fn legacy_binary(root: &Path) -> (PathBuf, Vec<(String, String)>) {
    let binary = root.join("legacy");
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/binary_adapter/legacy.c");
    let built = Command::new("cc")
        .args(["-O0", "-o"])
        .arg(&binary)
        .arg(source)
        .status()
        .expect("run cc");
    assert!(built.success(), "cc legacy.c");
    let nm = Command::new("nm").arg(&binary).output().expect("run nm");
    let symbols = String::from_utf8_lossy(&nm.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let address = fields.next()?;
            let kind = fields.next()?;
            let name = fields.next()?;
            (kind == "T").then(|| {
                (
                    name.to_owned(),
                    format!("{:#x}", u64::from_str_radix(address, 16).unwrap()),
                )
            })
        })
        .collect();
    (binary, symbols)
}

/// Run the adapter on the fixture and check its report: the fixture's
/// functions at the addresses `nm` gives, its call edges, its magic string and
/// the call xref to `parse_header`.
fn analyze_legacy(kind: &str, tool: &Path) {
    let root = TestDir::new(&format!("binary-analyzer-{kind}"));
    let (binary, symbols) = legacy_binary(root.path());
    let out = root.join("out");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["--profile", "external-tools", "binary", "adapter"])
        .arg(&binary)
        .args(["--adapter", kind, "--tool"])
        .arg(tool)
        .arg("--out")
        .arg(&out)
        .args(["--timeout-secs", "600"])
        .output()
        .expect("run bhf binary adapter");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let report: Value =
        serde_json::from_slice(&std::fs::read(out.join("binary-adapter-report.json")).unwrap())
            .unwrap();
    assert_eq!(output.status.code(), Some(0), "{stderr}\n{report:#}");
    assert_eq!(report["status"], "ok", "{report:#}");
    assert!(report["tool"]["version"].is_string(), "{report:#}");

    let functions = report["functions"].as_array().unwrap();
    for name in ["main", "handle", "parse_header"] {
        let expected = &symbols
            .iter()
            .find(|(symbol, _)| symbol == name)
            .unwrap_or_else(|| panic!("nm has no {name}: {symbols:?}"))
            .1;
        let function = functions
            .iter()
            .find(|function| function["name"] == name)
            .unwrap_or_else(|| panic!("{kind} found no {name}: {functions:#?}"));
        assert_eq!(&function["address"], expected, "{kind}: {name}");
    }
    for (caller, callee) in [("main", "handle"), ("handle", "parse_header")] {
        assert!(
            report["call_graph"]
                .as_array()
                .unwrap()
                .contains(&json!({ "caller": caller, "callee": callee })),
            "{kind}: {caller} -> {callee}: {:#}",
            report["call_graph"]
        );
    }
    assert!(
        report["strings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|string| string["value"] == "LEGACY/1.0"),
        "{kind}: {:#}",
        report["strings"]
    );
    let parse_header = &symbols
        .iter()
        .find(|(name, _)| name == "parse_header")
        .unwrap()
        .1;
    assert!(
        report["xrefs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|xref| xref["kind"] == "call" && &xref["to"] == parse_header),
        "{kind}: no call xref to parse_header"
    );
}

#[test]
fn rizin_finds_the_fixtures_functions_and_call_edges() {
    if let Some(rizin) = analyzer("rizin", "BHF_RIZIN", "rizin") {
        analyze_legacy("rizin", &rizin);
    }
}

#[test]
fn ghidra_headless_finds_the_fixtures_functions_and_call_edges() {
    if let Some(headless) = analyzer("ghidra", "BHF_GHIDRA_HEADLESS", "analyzeHeadless") {
        analyze_legacy("ghidra", &headless);
    }
}
