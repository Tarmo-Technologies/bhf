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
    let csv = std::fs::read_to_string(work.join("results/findings.csv")).unwrap();
    assert!(
        csv.lines()
            .any(|row| row.starts_with(id) && row.ends_with("reduced: macro FRAME_SLOTS=0")),
        "{csv}"
    );
}
