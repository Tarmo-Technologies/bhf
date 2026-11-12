// SPDX-License-Identifier: Apache-2.0
//! A target that compiles only after the repair loop fabricates a macro value
//! the build context should have supplied (`FRAME_SLOTS`, normally a `-D`).
//! With the fabricated `0`, the target's buffer is one byte, so the fuzzer
//! finds an overflow the real build may not have. Every report must say the
//! finding came from fabricated build context: `finding.json` and `run.json`
//! carry the record, the normalized finding is low confidence with the caveat,
//! INDEX.md and findings.csv show it, and the console summary calls it out.

use std::process::Command;

#[test]
fn findings_from_fabricated_macro_values_are_marked() {
    if which::which("clang").is_err() || which::which("make").is_err() {
        eprintln!("skipping: clang/make not on PATH");
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("tree");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(
        source.join("frame.c"),
        "#include <stddef.h>\n#include <stdlib.h>\n\
         int parse_frame(const unsigned char *data, size_t len) {\n\
             unsigned char *slots = malloc(FRAME_SLOTS + 1);\n\
             if (!slots) return 0;\n\
             if (len > 1 && data[0] == 'F') slots[1] = data[1];\n\
             free(slots);\n\
             return 0;\n\
         }\n",
    )
    .unwrap();
    let work = temp.path().join("work");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&source)
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--jobs",
            "1",
            "--max-targets",
            "1",
            "--per-target-time",
            "3",
        ])
        .args(["--languages", "c", "--no-discovery-cache"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let read = |path: &str| -> serde_json::Value {
        serde_json::from_slice(
            &std::fs::read(work.join(path))
                .unwrap_or_else(|error| panic!("{path}: {error}\n{stderr}")),
        )
        .unwrap()
    };
    let run = read("auto/run.json");
    assert_eq!(run["summary"]["built_and_fuzzed"], 1, "{stderr}");
    assert_eq!(run["summary"]["fabricated_build_context"], 1, "{stderr}");
    let fabricated = run["targets"][0]["build_fidelity"]["fabricated"]
        .as_array()
        .unwrap_or_else(|| panic!("no build_fidelity: {}", run["targets"][0]));
    assert!(
        fabricated.iter().any(|input| input["kind"] == "macro"
            && input["name"] == "FRAME_SLOTS"
            && input["value"] == "0"),
        "{fabricated:?}"
    );
    assert!(
        stderr.contains("⚠ Build context: 1 target(s)") && stderr.contains("macro FRAME_SLOTS=0"),
        "the console summary names it:\n{stderr}"
    );

    let findings = read("results/findings.json");
    let finding = findings["findings"]
        .as_array()
        .and_then(|all| all.iter().find(|f| f["kind"] == "fuzz"))
        .unwrap_or_else(|| panic!("no fuzz finding:\n{stderr}"));
    assert_eq!(finding["confidence"]["level"], "low", "{finding}");
    assert_eq!(
        finding["reproduce"]["build"]["fidelity"]["level"],
        "reduced"
    );
    let id = finding["id"].as_str().unwrap();
    let raw = read(&format!("results/findings/{id}/finding.json"));
    assert_eq!(
        raw["build"]["fidelity"]["fabricated"][0]["name"],
        "FRAME_SLOTS"
    );
    let index = std::fs::read_to_string(work.join("results/INDEX.md")).unwrap();
    assert!(
        index.contains("Caveat: built with inputs bhf supplied")
            && index.contains("FRAME\\_SLOTS=0"),
        "{index}"
    );
    // The `build_fidelity` column, wherever later columns put it.
    let csv = std::fs::read_to_string(work.join("results/findings.csv")).unwrap();
    assert!(
        csv.lines().any(|row| row.starts_with(id)
            && (row.ends_with(",reduced: macro FRAME_SLOTS=0")
                || row.contains(",reduced: macro FRAME_SLOTS=0,"))),
        "{csv}"
    );
}

/// A C++ target whose only gap is a header it never included (`cerr` without
/// `<iostream>`) is repaired by including that real header, not by a
/// fabricated `void *` type: the build keeps full fidelity, and run.json and
/// run.md list the header bhf included.
#[test]
fn a_cpp_target_missing_only_a_standard_header_keeps_full_fidelity() {
    if which::which("clang++").is_err() || which::which("make").is_err() {
        eprintln!("skipping: clang++/make not on PATH");
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("tree");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(
        source.join("widget.cpp"),
        "#include <cstddef>\n#include <string>\n\
         using namespace std;\n\
         namespace demo {\n\
         int parse_widget(const unsigned char *data, size_t len) {\n\
         \x20   if (len > 2 && data[0] == 'W') cerr << \"widget \" << data[1] << \"\\n\";\n\
         \x20   return len ? data[0] : 0;\n\
         }\n\
         }\n",
    )
    .unwrap();
    let work = temp.path().join("work");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&source)
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--jobs",
            "1",
            "--max-targets",
            "1",
            "--per-target-time",
            "3",
        ])
        .args(["--languages", "cpp", "--no-discovery-cache"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let run: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("auto/run.json"))
            .unwrap_or_else(|error| panic!("run.json: {error}\n{stderr}")),
    )
    .unwrap();
    assert_eq!(run["summary"]["built_and_fuzzed"], 1, "{stderr}");
    let target = &run["targets"][0];
    assert!(
        target["outcome"]["repairs"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|repair| repair["kind"] == "type_placeholder"
                && repair["type_name"] == "cerr"
                && repair["resolved_header"] == "<iostream>"),
        "the cerr repair records the header it included: {target}"
    );
    assert!(
        target.get("build_fidelity").is_none(),
        "a real header is no fabricated input: {target}"
    );
    assert_eq!(
        run["summary"]["fabricated_build_context"]
            .as_u64()
            .unwrap_or(0),
        0,
        "{stderr}"
    );
    assert_eq!(
        target["real_headers_included"][0], "type cerr: real header included (<iostream>)",
        "{target}"
    );
    assert!(!stderr.contains("⚠ Build context"), "{stderr}");
    let run_md = std::fs::read_to_string(work.join("auto/run.md")).unwrap();
    assert!(
        run_md.contains("type cerr: real header included (<iostream>)")
            && !run_md.contains("## Fabricated build context"),
        "{run_md}"
    );
}
