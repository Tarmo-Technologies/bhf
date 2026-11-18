// SPDX-License-Identifier: Apache-2.0

//! An Ada record parameter whose components are a constrained `String`
//! subtype, an enumeration and an integer (#418), as whitakers-words declares
//! its dictionary entries. Each component is decoded as its own type, so the
//! `in` record's harness builds and the input reaches the planted index check
//! behind the enumeration; the `out` record is declared without an
//! initializer. Gated on the Ada toolchain; `BHF_REQUIRE_TOOLS=1` makes a
//! missing one a failure.

use std::path::Path;
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn have_ada_toolchain() -> bool {
    let present = which::which("gnatmake").is_ok() && which::which("gprbuild").is_ok();
    support::require_tool(present, "ada toolchain")
}

#[test]
fn record_parameters_build_with_each_component_decoded_as_its_type() {
    if !have_ada_toolchain() {
        eprintln!("skipping: gnatmake/gprbuild not installed");
        return;
    }
    let root = TestDir::new("ada-record-params");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/ada_record_params");
    for name in ["words.ads", "words.adb"] {
        std::fs::copy(fixture.join(name), src.join(name)).unwrap();
    }
    let work = root.join("work");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--languages",
            "ada",
            "--per-target-time",
            "10",
            "--jobs",
            "1",
        ])
        .arg("--no-discovery-cache")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");

    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
    let targets = run["targets"].as_array().unwrap();
    assert_eq!(targets.len(), 2, "{run:#}");
    for target in targets {
        assert_eq!(
            target["outcome"]["outcome"], "built_and_fuzzed",
            "{target:#}\n{stderr}"
        );
        let id = target["harness_id"].as_str().unwrap();
        let main =
            std::fs::read_to_string(work.join("harnesses").join(id).join("main.adb")).unwrap();
        if main.contains("Words.Get (") {
            assert!(main.contains("P : Words.Ewds_Record;"), "{main}");
        } else {
            assert!(
                main.contains("Pofs => Words.Part_Of_Speech_Type'Val ("),
                "the enumeration is decoded: {main}"
            );
            assert!(
                main.contains("W => (others => Character'Val ("),
                "the String subtype is decoded: {main}"
            );
        }
    }
    let findings: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("results/findings.json")).unwrap())
            .unwrap();
    assert!(
        findings["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["message"]
                .as_str()
                .is_some_and(|message| message.contains("words.adb:20 index check failed"))),
        "the index check behind `Pofs = Adj` is reached: {findings:#}\n{stderr}"
    );
}
