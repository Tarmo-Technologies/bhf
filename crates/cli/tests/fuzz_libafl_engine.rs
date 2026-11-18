// SPDX-License-Identifier: Apache-2.0
//
// #296: `bhf fuzz --engine libafl`, in a bhf built with the `libafl-engine`
// feature, runs a LibAFL campaign over the harness's `main`, with the edge
// bitmap the harness writes as LibAFL's map, and records the crash it finds as
// a finding that `bhf replay` reproduces. Without the feature the engine is
// refused with the rebuild it needs.
#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn bhf(args: &[&str]) -> std::process::Output {
    Command::new(PathBuf::from(env!("CARGO_BIN_EXE_bhf")))
        .args(args)
        .output()
        .expect("run bhf")
}

fn harness_work(scratch: &TestDir) -> PathBuf {
    let source = scratch.join("rec.c");
    // The overflow sits behind a four-byte magic, which havoc alone does not
    // guess in the budget: the run finds it with the harness's dictionary,
    // which holds the magic mined from the source.
    std::fs::write(
        &source,
        "#include <string.h>\n\
         int parse_rec(const unsigned char *buf, unsigned long len) {\n\
         \x20   char tmp[8];\n\
         \x20   if (len < 4 || memcmp(buf, \"REC!\", 4) != 0)\n\
         \x20       return -1;\n\
         \x20   memcpy(tmp, buf, len);\n\
         \x20   return tmp[2];\n\
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
        "H-LA",
    ]);
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let built = bhf(&["build", work.to_str().unwrap(), "--harness", "H-LA"]);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    work
}

#[cfg(feature = "libafl-engine")]
#[test]
fn the_libafl_engine_finds_the_overflow_and_its_finding_replays() {
    let scratch = TestDir::new("libafl-engine");
    let work = harness_work(&scratch);
    let out = bhf(&[
        "fuzz",
        work.to_str().unwrap(),
        "--harness",
        "H-LA",
        "--engine",
        "libafl",
        "--time",
        "20s",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let summary: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(summary["engine"], "libafl", "{summary:#}");
    assert!(
        summary["executions"].as_u64().unwrap_or(0) > 0,
        "{summary:#}"
    );
    // The seed and the input that matched the magic stay in the corpus.
    assert!(
        summary["corpus_persisted"].as_u64().unwrap_or(0) >= 2,
        "{summary:#}"
    );
    let id = summary["findings"][0]
        .as_str()
        .unwrap_or_else(|| panic!("no finding: {summary:#}\n{stderr}"))
        .to_owned();
    let finding = work.join("results/findings").join(&id);
    let record = std::fs::read_to_string(finding.join("finding.json")).unwrap();
    assert!(record.contains("found by LibAFL"), "{record}");

    let replay = bhf(&["replay", finding.to_str().unwrap()]);
    let replayed = String::from_utf8_lossy(&replay.stdout);
    assert!(
        replayed.contains("MATCH") && !replayed.contains("MISMATCH"),
        "{replayed}\n{}",
        String::from_utf8_lossy(&replay.stderr)
    );
}

#[cfg(not(feature = "libafl-engine"))]
#[test]
fn without_the_feature_the_libafl_engine_names_the_rebuild_it_needs() {
    let scratch = TestDir::new("libafl-engine-off");
    let work = harness_work(&scratch);
    let out = bhf(&[
        "fuzz",
        work.to_str().unwrap(),
        "--harness",
        "H-LA",
        "--engine",
        "libafl",
        "--time",
        "1s",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_ne!(out.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("--features libafl-engine"), "{stderr}");
    assert!(
        out.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}
