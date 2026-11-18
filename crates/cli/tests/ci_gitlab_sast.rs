// SPDX-License-Identifier: Apache-2.0

//! `bhf ci --gitlab-sast` and `bhf report --gitlab-sast` write a GitLab SAST
//! report of the run's findings (#320): one vulnerability per finding, its
//! bhf rule first among its identifiers, at the finding's source line.
//! `scripts/ci/tests/test_gitlab_sast.py` validates the format against
//! GitLab's schema; when Python's `jsonschema` is installed this test also
//! validates the report it gets.

#![cfg(unix)]

use std::path::Path;
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const TARGET: &str = "#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n\n\
                      int parse_tag(const uint8_t *data, size_t len) {\n  char tag[4];\n  \
                      if (len > 0 && data[0] == 'T') {\n    memcpy(tag, data, len);\n    \
                      return tag[1];\n  }\n  return 0;\n}\n";

fn validates_with_jsonschema(report: &Path) -> Option<bool> {
    let schema = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/gitlab/sast-report-format.json");
    let check = "import json,sys,jsonschema\n\
                 schema=json.load(open(sys.argv[1]));doc=json.load(open(sys.argv[2]))\n\
                 cls=jsonschema.validators.validator_for(schema)\n\
                 errors=list(cls(schema).iter_errors(doc))\n\
                 [print(e.message) for e in errors]\n\
                 sys.exit(1 if errors else 0)\n";
    let output = Command::new("python3")
        .args(["-c", "import jsonschema"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let run = Command::new("python3")
        .args(["-c", check])
        .arg(&schema)
        .arg(report)
        .output()
        .ok()?;
    eprintln!("{}", String::from_utf8_lossy(&run.stdout));
    Some(run.status.success())
}

#[test]
fn a_finding_is_a_gitlab_sast_vulnerability() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("skipping: no clang");
        return;
    }
    let root = TestDir::new("ci-gitlab-sast");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("tag.c"), TARGET).unwrap();
    let work = root.join("work");
    let report = root.join("gl-sast-report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("ci")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--languages",
            "c",
            "--per-target-time",
            "10",
            "--gitlab-sast",
        ])
        .arg(&report)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "the finding fails the gate: {stderr}"
    );
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
    assert_eq!(doc["version"], "15.2.1", "{doc:#}");
    assert_eq!(doc["scan"]["type"], "sast", "{doc:#}");
    let vulnerability = doc["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["location"]["file"] == "tag.c")
        .unwrap_or_else(|| panic!("no vulnerability in tag.c: {doc:#}"));
    let primary = &vulnerability["identifiers"][0];
    assert_eq!(primary["type"], "bhf_rule", "{vulnerability:#}");
    assert!(
        primary["value"]
            .as_str()
            .is_some_and(|rule| rule.starts_with("BHF-")),
        "{vulnerability:#}"
    );
    assert!(
        vulnerability["location"]["start_line"].as_u64().is_some(),
        "{vulnerability:#}"
    );
    if let Some(valid) = validates_with_jsonschema(&report) {
        assert!(
            valid,
            "the report validates against GitLab's schema: {doc:#}"
        );
    }

    // `bhf report` writes the same report into results/.
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("report")
        .arg("--work-dir")
        .arg(&work)
        .arg("--gitlab-sast")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("GITLAB_SAST "), "{stdout}");
    let rebuilt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("results/gl-sast-report.json")).unwrap())
            .unwrap();
    assert_eq!(rebuilt["vulnerabilities"], doc["vulnerabilities"]);
}
