// SPDX-License-Identifier: Apache-2.0

//! `bhf ci` replays the findings an earlier run stored before it judges this
//! one (#318): a finding that still reproduces fails the gate, and once the
//! bug is fixed it passes and is reported fixed. A work dir restored from a
//! CI cache keeps its last findings in `regressions/`.

#![cfg(unix)]

use std::path::Path;
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const BUGGY: &str = "#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n\n\
                     int parse_tag(const uint8_t *data, size_t len) {\n  char tag[4];\n  \
                     if (len > 0 && data[0] == 'T') {\n    memcpy(tag, data, len);\n    \
                     return tag[1];\n  }\n  return 0;\n}\n";

const FIXED: &str = "#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n\n\
                     int parse_tag(const uint8_t *data, size_t len) {\n  char tag[4];\n  \
                     if (len >= 2 && len <= sizeof tag && data[0] == 'T') {\n    \
                     memcpy(tag, data, len);\n    return tag[1];\n  }\n  return 0;\n}\n";

fn ci(src: &Path, work: &Path, json: &Path) -> (i32, serde_json::Value, String) {
    ci_with(src, work, json, &[])
}

fn ci_with(
    src: &Path,
    work: &Path,
    json: &Path,
    extra: &[&std::ffi::OsStr],
) -> (i32, serde_json::Value, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("ci")
        .arg(src)
        .arg("--work-dir")
        .arg(work)
        .args(["--languages", "c", "--per-target-time", "10"])
        .arg("--ci-json")
        .arg(json)
        .args(extra)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let doc = serde_json::from_slice(&std::fs::read(json).unwrap_or_default())
        .unwrap_or_else(|error| panic!("{} ({error}): {stderr}", json.display()));
    (output.status.code().unwrap_or(-1), doc, stderr)
}

#[test]
fn a_stored_finding_fails_the_gate_until_it_is_fixed() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("skipping: no clang");
        return;
    }
    let root = TestDir::new("ci-regression");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("tag.c"), BUGGY).unwrap();
    let work = root.join("work");

    let (exit, first, stderr) = ci(&src, &work, &root.join("first.json"));
    assert_eq!(
        exit, 1,
        "the planted overflow fails the gate: {first:#}\n{stderr}"
    );
    assert!(first["total_findings"].as_u64().unwrap() >= 1, "{first:#}");
    assert_eq!(first["regressions"]["replayed"], 0, "{first:#}");

    // The same tree again: the stored finding is replayed, and reproduces.
    let (exit, second, stderr) = ci(&src, &work, &root.join("second.json"));
    assert_eq!(exit, 1, "{second:#}\n{stderr}");
    let reproduced = second["regressions"]["reproduced"].as_array().unwrap();
    assert!(!reproduced.is_empty(), "{second:#}\n{stderr}");
    assert!(stderr.contains("still reproduces"), "{stderr}");
    let id = reproduced[0].as_str().unwrap().to_owned();
    assert!(work.join("regressions").join(&id).is_dir(), "{second:#}");

    // Fixed: the stored finding no longer reproduces, and the gate passes.
    std::fs::write(src.join("tag.c"), FIXED).unwrap();
    let (exit, third, stderr) = ci(&src, &work, &root.join("third.json"));
    assert_eq!(exit, 0, "{third:#}\n{stderr}");
    assert_eq!(third["total_findings"], 0, "{third:#}");
    let fixed = third["regressions"]["fixed"].as_array().unwrap();
    assert!(
        fixed.iter().any(|fixed| fixed == id.as_str()),
        "{third:#}\n{stderr}"
    );
    assert_eq!(
        third["regressions"]["reproduced"].as_array().map(Vec::len),
        Some(0),
        "{third:#}"
    );
}

/// A `--policy` gate is one gate among those the run applies (#448): a
/// passing policy does not hide a failing `--fail-on` or a stored finding that
/// still reproduces, and the run passes only when every gate passes. The
/// summary names each gate's result.
#[test]
fn a_passing_policy_does_not_hide_a_failing_gate() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("skipping: no clang");
        return;
    }
    let root = TestDir::new("ci-policy-gates");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("tag.c"), BUGGY).unwrap();
    let work = root.join("work");
    // A policy that fails on no finding.
    let policy = root.join("policy.json");
    std::fs::write(
        &policy,
        r#"{"schema_version":"bhf.policy.v1","policy_id":"report-only","ci":{"fail_on_severity":"none"}}"#,
    )
    .unwrap();
    let summary = |name: &str| root.join(format!("{name}.md"));
    let args = |name: &str, more: &[&str]| -> Vec<std::ffi::OsString> {
        let mut args: Vec<std::ffi::OsString> = vec![
            "--policy".into(),
            policy.clone().into(),
            "--summary-file".into(),
            summary(name).into(),
        ];
        args.extend(more.iter().map(Into::into));
        args
    };
    let run = |name: &str, more: &[&str]| {
        let extra = args(name, more);
        let extra: Vec<&std::ffi::OsStr> = extra.iter().map(|arg| arg.as_os_str()).collect();
        let (exit, doc, stderr) = ci_with(&src, &work, &root.join(format!("{name}.json")), &extra);
        let markdown = std::fs::read_to_string(summary(name)).unwrap_or_default();
        (exit, doc, format!("{stderr}\n{markdown}"), markdown)
    };

    // The policy passes the planted overflow; `--fail-on any` fails on it.
    let (exit, first, log, markdown) = run("fail-on", &["--fail-on", "any"]);
    assert!(first["total_findings"].as_u64().unwrap() >= 1, "{first:#}");
    assert_eq!(exit, 1, "{first:#}\n{log}");
    assert_eq!(first["exit_code"], 1, "{first:#}");
    assert!(markdown.contains("`--fail-on any`: **failed**"), "{log}");
    assert!(markdown.contains("`--policy`: passed"), "{log}");

    // The same tree again with only the policy: the stored finding still
    // reproduces, which fails the run. The default `--fail-on any` is not
    // applied beside the policy.
    let (exit, second, log, markdown) = run("regression", &[]);
    assert!(
        !second["regressions"]["reproduced"]
            .as_array()
            .unwrap()
            .is_empty(),
        "{second:#}\n{log}"
    );
    assert_eq!(exit, 1, "{second:#}\n{log}");
    assert!(markdown.contains("regression replay: **failed**"), "{log}");
    assert!(!markdown.contains("`--fail-on"), "{log}");

    // Fixed: no finding, the stored one is fixed and the policy passes, so
    // every gate passes.
    std::fs::write(src.join("tag.c"), FIXED).unwrap();
    let (exit, third, log, markdown) = run("fixed", &["--fail-on", "any"]);
    assert_eq!(third["total_findings"], 0, "{third:#}\n{log}");
    assert_eq!(exit, 0, "{third:#}\n{log}");
    assert_eq!(third["exit_code"], 0, "{third:#}");
    for gate in [
        "`--fail-on any`: passed",
        "regression replay: passed",
        "`--policy`: passed",
    ] {
        assert!(markdown.contains(gate), "{gate}: {log}");
    }
}
