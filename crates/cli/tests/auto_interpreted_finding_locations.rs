// SPDX-License-Identifier: Apache-2.0

//! A Perl, Ruby or PHP finding is located at the target line that raised it,
//! in results/findings.json, results/findings.sarif and INDEX.md. The Perl
//! driver stripped the `at FILE line N` from the die message and the Ruby and
//! PHP drivers printed no backtrace, so these findings had no location.

use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn have(program: &str, args: &[&str]) -> bool {
    let present = {
        Command::new(program)
            .args(args)
            .output()
            .is_ok_and(|out| out.status.success())
    };
    support::require_tool(present, program)
}

/// Fuzz `file` from fixture `dir` with `language`, and check its divide by
/// zero is located at `line` of that file.
fn located(language: &str, dir: &str, file: &str, line: u64) {
    let root = TestDir::new(&format!("{language}-finding-location"));
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::copy(fixtures().join(dir).join(file), src.join(file)).unwrap();
    let work = root.join("work");
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--languages", language, "--jobs", "1", "--single-pass"])
        .args(["--per-target-time", "20"])
        .arg(&src)
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let read = |name: &str| -> serde_json::Value {
        let path = work.join("results").join(name);
        serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|e| {
            panic!("{} ({e}):\n{stderr}", path.display());
        }))
        .unwrap()
    };

    let doc = read("findings.json");
    let finding = doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["cwe"][0] == 369)
        .unwrap_or_else(|| panic!("{language}: no CWE-369 finding:\n{doc:#}\n{stderr}"));
    assert_eq!(finding["location"]["file"], file, "{language}: {finding:#}");
    assert_eq!(finding["location"]["line"], line, "{language}: {finding:#}");

    let sarif = read("findings.sarif");
    let result = sarif["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|result| result["properties"]["bhfFindingId"] == finding["id"])
        .unwrap_or_else(|| panic!("{language}: no SARIF result:\n{sarif:#}"));
    let physical = &result["locations"][0]["physicalLocation"];
    assert_eq!(physical["artifactLocation"]["uri"], file, "{result:#}");
    assert_eq!(physical["region"]["startLine"], line, "{result:#}");

    let index = std::fs::read_to_string(work.join("results/INDEX.md")).unwrap();
    assert!(
        index.contains(&format!("Location: `{file}`:{line}")),
        "{language}: INDEX.md names {file}:{line}:\n{index}"
    );
}

#[test]
fn a_perl_finding_is_located_at_its_die() {
    if !have("perl", &["-e", "1"]) {
        eprintln!("skipping: no perl on PATH");
        return;
    }
    located("perl", "perl_lane", "RecordParser.pm", 15);
}

#[test]
fn a_ruby_finding_is_located_at_its_raise() {
    if !have("ruby", &["-e", "1"]) {
        eprintln!("skipping: no ruby on PATH");
        return;
    }
    located("ruby", "ruby_lane", "record_parser.rb", 9);
}

#[test]
fn a_php_finding_is_located_at_its_throw() {
    if !have("php", &["-r", "exit(0);"]) {
        eprintln!("skipping: no php on PATH");
        return;
    }
    located("php", "php_lane", "parser.php", 10);
}
