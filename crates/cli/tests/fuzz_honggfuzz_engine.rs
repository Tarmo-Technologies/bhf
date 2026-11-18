// SPDX-License-Identifier: Apache-2.0
//
// #295: `bhf fuzz --engine honggfuzz` runs honggfuzz in persistent mode on
// the harness's honggfuzz build, building `main_honggfuzz` with `make
// honggfuzz` when there is none, and records the crash it saves as a finding
// that `bhf replay` reproduces. Needs honggfuzz on PATH or in
// `BHF_HONGGFUZZ_PATH`; `BHF_REQUIRE_TOOLS=1` makes a missing one a failure.
#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn have_honggfuzz() -> bool {
    let present = std::env::var_os("BHF_HONGGFUZZ_PATH")
        .map(PathBuf::from)
        .is_some_and(|dir| dir.join("honggfuzz").is_file())
        || which::which("honggfuzz").is_ok();
    support::require_tool(present, "honggfuzz")
}

fn bhf(args: &[&str]) -> std::process::Output {
    Command::new(PathBuf::from(env!("CARGO_BIN_EXE_bhf")))
        .args(args)
        .output()
        .expect("run bhf")
}

#[test]
fn the_honggfuzz_engine_finds_the_overflow_and_its_finding_replays() {
    if !have_honggfuzz() {
        eprintln!("SKIP: honggfuzz is not installed");
        return;
    }
    let scratch = TestDir::new("honggfuzz-engine");
    let source = scratch.join("rec.c");
    std::fs::write(
        &source,
        "#include <string.h>\n\
         int parse_rec(const unsigned char *buf, unsigned long len) {\n\
         \x20   char tmp[8];\n\
         \x20   if (len < 2 || buf[0] != 'R')\n\
         \x20       return -1;\n\
         \x20   memcpy(tmp, buf, len);\n\
         \x20   return tmp[1];\n\
         }\n",
    )
    .unwrap();
    let work = scratch.join("work");
    let generated = bhf(&[
        "generate-harness",
        source.to_str().unwrap(),
        "--target",
        "parse_rec",
        "--output",
        work.join("harnesses").to_str().unwrap(),
        "--id",
        "H-HF",
    ]);
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let out = bhf(&[
        "fuzz",
        work.to_str().unwrap(),
        "--harness",
        "H-HF",
        "--engine",
        "honggfuzz",
        "--time",
        "15s",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("make honggfuzz"), "{stderr}");
    let summary: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(summary["engine"], "honggfuzz", "{summary:#}");
    assert!(
        summary["executions"].as_u64().unwrap_or(0) > 0,
        "{summary:#}"
    );
    let id = summary["findings"][0]
        .as_str()
        .unwrap_or_else(|| panic!("no finding: {summary:#}\n{stderr}"))
        .to_owned();
    let finding = work.join("results/findings").join(&id);
    let record = std::fs::read_to_string(finding.join("finding.json")).unwrap();
    assert!(record.contains("found by honggfuzz"), "{record}");

    let replay = bhf(&["replay", finding.to_str().unwrap()]);
    let replayed = String::from_utf8_lossy(&replay.stdout);
    assert!(
        replayed.contains("MATCH") && !replayed.contains("MISMATCH"),
        "{replayed}\n{}",
        String::from_utf8_lossy(&replay.stderr)
    );
}
