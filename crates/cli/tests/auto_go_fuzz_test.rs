// SPDX-License-Identifier: Apache-2.0
//
// Go native fuzz tests are provided harnesses: `bhf auto` finds the project's
// `func FuzzXxx(f *testing.F)` tests in its `_test.go` files, builds each as a
// harness the builtin engine drives, starts it from its `f.Add` seeds and its
// `testdata/fuzz/<Name>` corpus, and reports it in run.json as a provided
// harness.
//
// The `go_fuzz_test` fixture has three: FuzzParse, an internal test whose
// target is unexported (so no generated harness reaches it) and calls a
// helper another test file defines, with a planted index-out-of-range panic;
// FuzzFieldLen, an external (`package codec_test`) test of two arguments
// that fails through t.Fatalf rather than a panic; and FuzzParseRecord, an
// external test that reaches an unexported parser through the name its
// package's export_test.go gives it, with a planted divide by zero.
//
// Skips cleanly when no `go` toolchain is installed (the GNAT-less rule).

use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/go_fuzz_test")
        .canonicalize()
        .expect("canonicalize go_fuzz_test fixture")
}

fn have_go() -> bool {
    let present = Command::new("go")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    support::require_tool(present, "go")
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &dest);
        } else {
            std::fs::copy(entry.path(), &dest).unwrap();
        }
    }
}

fn target<'a>(run: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    run["targets"]
        .as_array()
        .expect("run.json targets")
        .iter()
        .find(|target| target["name"] == name)
        .unwrap_or_else(|| panic!("no target {name} in run.json: {run:#}"))
}

/// The findings `bhf auto` recorded for harness `id`, as findings.json lists them.
fn findings_of<'a>(doc: &'a serde_json::Value, id: &str) -> Vec<&'a serde_json::Value> {
    doc["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|finding| finding["fuzz"]["harness_id"] == id)
        .collect()
}

#[test]
fn auto_fuzzes_go_native_fuzz_tests_from_their_seeds_and_finds_their_bugs() {
    if !have_go() {
        eprintln!("skipping: no go toolchain on PATH (GNAT-less rule)");
        return;
    }
    let tmp = TestDir::new("go-fuzz-test");
    let src = tmp.join("src");
    copy_dir(&fixture(), &src);
    let work = tmp.join("work");
    let _serial = support::fuzz_serial_guard();
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args([
            "auto",
            "--languages",
            "go",
            "--per-target-time",
            "10",
            "--single-pass",
            "--jobs",
            "1",
            "--work-dir",
        ])
        .arg(&work)
        .arg(&src)
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "bhf auto failed: {stderr}");
    assert!(
        stderr.contains("provided harnesses: 3 the project ships (3 Go native fuzz test(s))"),
        "the run names the fuzz tests it found: {stderr}"
    );
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
    assert_eq!(run["summary"]["provided_harnesses"], 3, "{run:#}");
    let findings: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("results/findings.json")).unwrap())
            .unwrap();

    // FuzzParse: built from its _test.go, started from its f.Add seed and its
    // corpus file, and its planted index-out-of-range panic found.
    let parse = target(&run, "FuzzParse");
    assert_eq!(parse["outcome"]["outcome"], "built_and_fuzzed", "{parse:#}");
    let provided = &parse["provided_harness"];
    assert_eq!(provided["origin"], "go-fuzz-test", "{parse:#}");
    assert_eq!(provided["entry"], "FuzzParse");
    assert_eq!(provided["seeds"], 2, "the f.Add seed and the corpus file");
    let corpus = src.join("parser/testdata/fuzz/FuzzParse");
    assert_eq!(
        provided["seed_sources"],
        serde_json::json!([corpus.canonicalize().unwrap()])
    );
    let parse_id = parse["harness_id"].as_str().unwrap();
    assert!(parse_id.starts_with("H-G"), "{parse_id}");
    let harness = work.join("harnesses").join(parse_id);
    let mut seeds: Vec<Vec<u8>> = std::fs::read_dir(harness.join("provided-seeds"))
        .unwrap()
        .map(|entry| std::fs::read(entry.unwrap().path()).unwrap())
        .collect();
    seeds.sort();
    assert_eq!(seeds, [b"BHF\x01".to_vec(), b"hello".to_vec()]);
    let found = findings_of(&findings, parse_id);
    assert!(
        found.iter().any(|finding| {
            finding["cwe"]
                .as_array()
                .is_some_and(|cwe| cwe.contains(&serde_json::json!(125)))
                && finding["location"]["function"] == "example.com/widget/parser.parseHeader"
        }),
        "the planted panic in parseHeader was not found through FuzzParse: {findings:#}"
    );

    // FuzzFieldLen: an external test of two arguments whose check fails
    // through t.Fatalf, on the regression input its corpus keeps.
    let field_len = target(&run, "FuzzFieldLen");
    assert_eq!(
        field_len["outcome"]["outcome"], "built_and_fuzzed",
        "{field_len:#}"
    );
    assert_eq!(field_len["provided_harness"]["origin"], "go-fuzz-test");
    assert_eq!(field_len["provided_harness"]["seeds"], 2);
    let field_len_id = field_len["harness_id"].as_str().unwrap();
    // f.Add([]byte("WA"), 2): a length byte and the bytes, then 8 bytes of int.
    let seed = std::fs::read(
        work.join("harnesses")
            .join(field_len_id)
            .join("provided-seeds/add-0000"),
    )
    .unwrap();
    assert_eq!(seed, [&[2, b'W', b'A'][..], &2u64.to_le_bytes()].concat());
    // The corpus file's two values, `[]byte("WX")` and `int(0)`, the same way.
    let regression = std::fs::read(
        work.join("harnesses")
            .join(field_len_id)
            .join("provided-seeds/corpus-regression_wx"),
    )
    .unwrap();
    assert_eq!(
        regression,
        [&[2, b'W', b'X'][..], &0u64.to_le_bytes()].concat()
    );
    let found = findings_of(&findings, field_len_id);
    assert!(
        found.iter().any(|finding| {
            finding["message"]
                .as_str()
                .is_some_and(|m| m.contains("fuzz target FuzzFieldLen failed: FieldLen took"))
                && finding["location"]["function"]
                    .as_str()
                    .is_some_and(|f| f.contains("FuzzFieldLen"))
        }),
        "the fuzz target's t.Fatalf was not reported at the fuzz test: {findings:#}"
    );

    // FuzzParseRecord: `package record_test` calls record.ParseRecord, which
    // only the package's own export_test.go declares, as `go test` builds it.
    let record = target(&run, "FuzzParseRecord");
    assert_eq!(
        record["outcome"]["outcome"], "built_and_fuzzed",
        "{record:#}"
    );
    let record_id = record["harness_id"].as_str().unwrap();
    let found = findings_of(&findings, record_id);
    assert!(
        found
            .iter()
            .any(|finding| finding["location"]["function"]
                == "example.com/widget/record.parseRecord"),
        "the planted divide by zero in parseRecord was not found through \
         FuzzParseRecord: {findings:#}"
    );

    // The summary lists all three as provided harnesses.
    let summary = std::fs::read_to_string(work.join("auto/summary.txt")).unwrap();
    assert!(summary.contains("Provided harnesses (3)"), "{summary}");
    assert!(
        summary.contains(&format!(
            "{parse_id} FuzzParse [go-fuzz-test]: built+fuzzed, 2 seed(s)"
        )),
        "{summary}"
    );
    // The scanned tree was not written to.
    assert!(!src.join("parser/bhf_fuzztest_parse.go").exists());
    assert!(!src.join("record/bhf_fuzztest_export.go").exists());
}
