// SPDX-License-Identifier: Apache-2.0
//! A built harness whose every fuzz pass fails must not report a successful run.
#[cfg(unix)]
mod support;

#[cfg(unix)]
#[test]
fn every_input_rejected_is_a_runtime_failure() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let work = temporary.path().join("work");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(
        source.join("parser.c"),
        "#include <stddef.h>\n#include <stdlib.h>\n\
         int parse_packet(const unsigned char *data, size_t len) {\n\
         (void)data; (void)len; exit(2); return 0;\n}\n",
    )
    .unwrap();
    let output = support::bhf_cargo_command()
        .args([
            "auto",
            source.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
            "--jobs",
            "1",
            "--max-targets",
            "1",
            "--per-target-time",
            "1",
        ])
        .output()
        .expect("run owned rejection fixture");
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).expect("durable report"))
            .unwrap();
    let diagnostics = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{diagnostics}");
    assert_eq!(report["summary"]["built_and_fuzzed"], 0, "{diagnostics}");
    assert_eq!(
        report["summary"]["unrecoverable_runtime"], 1,
        "{diagnostics}"
    );
    assert!(
        report["targets"][0]["outcome"]["reason"]
            .as_str()
            .unwrap()
            .contains("rejected all"),
        "{diagnostics}"
    );
}
