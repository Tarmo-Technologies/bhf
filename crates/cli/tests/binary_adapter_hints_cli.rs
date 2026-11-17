// SPDX-License-Identifier: Apache-2.0

//! `--adapter-report` on `bhf binary fuzz` and `bhf binary scan` (#267): a
//! recorded `bhf binary adapter` report seeds the mutation dictionary with
//! the strings the binary's code references, and ranks its functions as fuzz
//! entry points. Nothing read the report before.

#![cfg(unix)]

use serde_json::Value;
use sha2::Digest;
use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// A stdin target that aborts on the legacy header anywhere in its input:
/// ten exact bytes no blind byte mutation of `hello` reaches.
const TARGET: &str = r#"
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(void) {
    char buf[4096];
    ssize_t n = read(0, buf, sizeof buf);
    if (n > 0 && memmem(buf, (size_t)n, "LEGACY/1.0", 10)) abort();
    return 0;
}
"#;

fn bhf() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
}

/// The target, built, or `None` with no C compiler.
fn build_target(root: &Path) -> Option<PathBuf> {
    let source = root.join("legacy_stdin.c");
    std::fs::write(&source, TARGET).unwrap();
    let binary = root.join("legacy_stdin");
    Command::new("cc")
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .status()
        .is_ok_and(|status| status.success())
        .then_some(binary)
}

/// The recorded rizin report of `tests/fixtures/binary_adapter/legacy.c`,
/// recorded as a report of `binary`.
fn report_for(root: &Path, binary: &Path) -> PathBuf {
    let recorded = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/binary_adapter/legacy-rizin-report.json");
    let mut report: Value = serde_json::from_slice(&std::fs::read(recorded).unwrap()).unwrap();
    let digest = sha2::Sha256::digest(std::fs::read(binary).unwrap());
    report["target_sha256"] =
        Value::String(digest.iter().map(|byte| format!("{byte:02x}")).collect());
    let path = root.join("binary-adapter-report.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    path
}

fn fuzz(binary: &Path, work: &Path, report: Option<&Path>) -> Value {
    let mut command = bhf();
    command
        .args(["binary", "fuzz"])
        .arg(binary)
        .arg("--work-dir")
        .arg(work)
        .args(["--engine", "builtin", "--input-mode", "stdin"])
        .args([
            "--seed-input",
            "hello",
            "--iterations",
            "3000",
            "--rng-seed",
            "7",
        ]);
    if let Some(report) = report {
        command.arg("--adapter-report").arg(report);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn a_recorded_report_seeds_the_dictionary_and_the_ranking() {
    let root = TestDir::new("adapter-hints");
    let Some(binary) = build_target(root.path()) else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let report = report_for(root.path(), &binary);

    let blind = fuzz(&binary, &root.join("blind"), None);
    assert_eq!(blind["findings"], serde_json::json!([]), "{blind:#}");
    assert!(blind["adapter_report"].is_null(), "{blind:#}");

    let seeded = fuzz(&binary, &root.join("seeded"), Some(&report));
    assert!(
        !seeded["findings"].as_array().unwrap().is_empty(),
        "the header from the report's strings reaches the abort: {seeded:#}"
    );
    let hints = &seeded["adapter_report"];
    assert_eq!(hints["adapter"], "rizin", "{seeded:#}");
    assert_eq!(hints["dictionary_tokens"], 2);
    assert_eq!(hints["ranking"][0]["name"], "parse_header");
    assert_eq!(hints["persistent_candidate"]["address"], "0x1169");

    // The scan puts the ranking in the binary's inventory entry.
    let out = root.join("scan");
    let scan = bhf()
        .args(["binary", "scan"])
        .arg(&binary)
        .arg("--out")
        .arg(&out)
        .arg("--adapter-report")
        .arg(&report)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&scan.stdout);
    assert!(
        scan.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&scan.stderr)
    );
    assert!(stdout.contains("first parse_header at 0x1169"), "{stdout}");
    let inventory: Value =
        serde_json::from_slice(&std::fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();
    let adapter = &inventory["binaries"][0]["adapter"];
    assert_eq!(
        adapter["ranking"][0]["name"], "parse_header",
        "{inventory:#}"
    );
    assert!(
        adapter["ranking"][0]["reasons"]
            .as_array()
            .unwrap()
            .contains(&Value::String("calls strncmp".to_owned())),
        "{adapter:#}"
    );

    // A report of another binary is refused.
    let other = root.join("other");
    std::fs::copy("/bin/true", &other).unwrap();
    let refused = bhf()
        .args(["binary", "scan"])
        .arg(&other)
        .arg("--out")
        .arg(root.join("scan-other"))
        .arg("--adapter-report")
        .arg(&report)
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("which this scan did not inventory"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
}
