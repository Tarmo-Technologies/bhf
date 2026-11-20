// SPDX-License-Identifier: Apache-2.0

//! `bhf minimize --strategy grammar` (#369): a grammar finding is minimized
//! on its derivation tree, parsed from the testcase with `--grammar`, so the
//! minimized input is a smaller sentence of the grammar that still
//! reproduces, where `--strategy bytes` cuts it down to bytes that are none.
//! Driven against the event-log fake harness, whose planted bug fires on any
//! input holding `BHFMAGIC`.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const HARNESS: &str = "H-TEST";

/// Bracketed words and parenthesized groups of them.
const GRAMMAR: &str = r#"{"START": ["{LIST}"], "LIST": ["{ITEM}", "{ITEM},{LIST}"],
    "ITEM": ["[{WORD}]", "({LIST})"], "WORD": ["alpha", "beta", "BHFMAGIC", "gamma"]}"#;

const TESTCASE: &[u8] = b"[alpha],([beta],([gamma],[BHFMAGIC])),[gamma]";

/// A work dir with the fake harness installed as `H-TEST`, and its path.
fn work_with_harness(dir: &Path) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let work = dir.join("bhf_work");
    let target = work.join("build").join(HARNESS).join("obj").join("main");
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_cli_fake_harness"), &target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
    (work, target)
}

fn bhf(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(args)
        .output()
        .expect("run bhf")
}

fn text(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The finding of the planted `magic.adb` bug that `testcase` raises,
/// recorded by a one-execution `bhf fuzz` of it.
fn magic_finding(dir: &Path, testcase: &[u8]) -> (PathBuf, PathBuf) {
    let (work, harness) = work_with_harness(dir);
    let seed = dir.join("seed");
    fs::write(&seed, testcase).unwrap();
    let output = bhf(&[
        "fuzz",
        work.to_str().unwrap(),
        "--harness",
        HARNESS,
        "--iterations",
        "1",
        "--seed-file",
        seed.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "{}", text(&output));
    let finding = fs::read_dir(work.join("results/findings"))
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .find(|path| {
            fs::read(path.join("finding.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .is_some_and(|finding| {
                    finding["exception"]["message"]
                        .as_str()
                        .is_some_and(|message| message.contains("magic.adb"))
                })
        })
        .expect("the magic finding");
    assert_eq!(fs::read(finding.join("testcase.bin")).unwrap(), testcase);
    (finding, harness)
}

/// Whether `input` raises the finding's signature again: `bhf replay` of a
/// copy of the finding whose testcase is `input`.
fn reproduces(finding: &Path, harness: &Path, input: &[u8], scratch: &Path) -> bool {
    fs::create_dir_all(scratch).unwrap();
    fs::copy(finding.join("finding.json"), scratch.join("finding.json")).unwrap();
    fs::write(scratch.join("testcase.bin"), input).unwrap();
    bhf(&[
        "replay",
        scratch.to_str().unwrap(),
        "--harness",
        harness.to_str().unwrap(),
    ])
    .status
    .success()
}

#[test]
fn a_grammar_finding_minimizes_to_a_smaller_valid_sentence_that_still_reproduces() {
    let dir = TestDir::new("minimize-grammar");
    let grammar = dir.join("list.json");
    fs::write(&grammar, GRAMMAR).unwrap();
    let (finding, harness) = magic_finding(dir.path(), TESTCASE);

    let output = bhf(&[
        "minimize",
        finding.to_str().unwrap(),
        "--strategy",
        "grammar",
        "--grammar",
        grammar.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "{}", text(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("strategy=grammar"),
        "{}",
        text(&output)
    );
    let minimized = fs::read(finding.join("min_testcase.bin")).unwrap();
    assert_eq!(
        minimized, b"[BHFMAGIC]",
        "the smallest sentence holding the magic"
    );
    assert!(minimized.len() < TESTCASE.len());
    assert!(
        reproduces(&finding, &harness, &minimized, &dir.join("replay-min")),
        "the minimized sentence still reproduces"
    );
    let record: Value =
        serde_json::from_slice(&fs::read(finding.join("finding.json")).unwrap()).unwrap();
    let minimization = &record["minimization"];
    assert_eq!(minimization["strategy"], "grammar", "{record:#}");
    assert_eq!(minimization["minimized_len"], minimized.len(), "{record:#}");
    assert!(
        minimization["grammar"]["nodes_after"].as_u64()
            < minimization["grammar"]["nodes_before"].as_u64(),
        "{record:#}"
    );
    assert!(!finding.join("minimize_tmp").exists());

    // Byte-wise, the same finding is cut to bytes the grammar does not
    // derive: a grammar minimization of that result is refused.
    let output = bhf(&["minimize", finding.to_str().unwrap()]);
    assert!(output.status.success(), "{}", text(&output));
    let bytes = fs::read(finding.join("min_testcase.bin")).unwrap();
    assert_eq!(bytes, b"BHFMAGIC");
    let (unstructured, _) = magic_finding(&dir.join("bytes"), &bytes);
    let output = bhf(&[
        "minimize",
        unstructured.to_str().unwrap(),
        "--strategy",
        "grammar",
        "--grammar",
        grammar.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    assert!(
        text(&output).contains("not a sentence of the grammar")
            && text(&output).contains("--strategy bytes"),
        "{}",
        text(&output)
    );
}

#[test]
fn the_grammar_strategy_needs_a_grammar_and_the_grammar_needs_the_strategy() {
    let dir = TestDir::new("minimize-grammar-args");
    let grammar = dir.join("list.json");
    fs::write(&grammar, GRAMMAR).unwrap();
    let (finding, _) = magic_finding(dir.path(), TESTCASE);

    let output = bhf(&[
        "minimize",
        finding.to_str().unwrap(),
        "--strategy",
        "grammar",
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", text(&output));
    assert!(text(&output).contains("--grammar"), "{}", text(&output));

    let output = bhf(&[
        "minimize",
        finding.to_str().unwrap(),
        "--grammar",
        grammar.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    assert!(
        text(&output).contains("--strategy bytes does not use it"),
        "{}",
        text(&output)
    );
    assert!(!finding.join("min_testcase.bin").exists());
}
