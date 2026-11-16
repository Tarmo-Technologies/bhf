// SPDX-License-Identifier: Apache-2.0

//! One out-of-bounds read in `tlv_decode`, reached directly by one harness and
//! through `parse_message` by another, and reported by AddressSanitizer and by
//! UndefinedBehaviorSanitizer: three findings. Each had its own stack and
//! sanitizer cluster, so `results/` counted three root-cause groups. The root
//! cause is one sink, the first project frame and its bug family: one group,
//! with the two call stacks as its observations.

use std::path::Path;
use std::time::Duration;

fn asan(frames: &[(&str, &str, u32)]) -> String {
    let mut stack = String::new();
    for (index, (function, file, line)) in frames.iter().enumerate() {
        stack.push_str(&format!(
            "    #{index} 0x5b4db87ef4{index:02} in {function} /src/widget/{file}:{line}:10\n"
        ));
    }
    format!(
        "=================================================================\n\
         ==547304==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000088 at pc 0x5b4db87ef463 bp 0x7ffdcd3d0460 sp 0x7ffdcd3d0458\n\
         READ of size 1 at 0x502000000088 thread T0\n\
         {stack}\n\
         0x502000000088 is located 0 bytes after 8-byte region [0x502000000080,0x502000000088)\n\
         SUMMARY: AddressSanitizer: heap-buffer-overflow /src/widget/tlv.c:12:10 in tlv_decode\n\
         ==547304==ABORTING\n"
    )
}

fn ubsan(frames: &[(&str, &str, u32)]) -> String {
    let mut stack = String::new();
    for (index, (function, file, line)) in frames.iter().enumerate() {
        stack.push_str(&format!(
            "    #{index} 0x5b4db87ef4{index:02} in {function} /src/widget/{file}:{line}:10\n"
        ));
    }
    format!(
        "/src/widget/tlv.c:12:10: runtime error: index 8 out of bounds for type 'unsigned char[8]'\n\
         {stack}\n\
         SUMMARY: UndefinedBehaviorSanitizer: out-of-bounds-index /src/widget/tlv.c:12:10\n"
    )
}

fn emit(work: &Path, harness: &str, stderr: &str) -> String {
    let report = corpus::parse_sanitizer_report(stderr).expect("a sanitizer report");
    corpus::finding::FindingEmitter::with_metadata(
        work.to_path_buf(),
        harness.to_owned(),
        "c".to_owned(),
        String::new(),
    )
    .emit_sanitizer_crash_with_log(stderr.as_bytes(), &report, Some(stderr.as_bytes()))
    .unwrap()
    .0
}

#[test]
fn one_sink_reached_two_ways_is_one_group_with_two_observations() {
    let work = tempfile::tempdir().unwrap();
    let direct = [
        ("tlv_decode", "tlv.c", 12),
        ("bhf_run_one", "harness/main.c", 40),
    ];
    let through_message = [
        ("tlv_decode", "tlv.c", 12),
        ("parse_message", "message.c", 30),
        ("bhf_run_one", "harness/main.c", 40),
    ];
    let a = emit(work.path(), "H-C0001-1A2B3C4D", &asan(&direct));
    let b = emit(work.path(), "H-C0002-5E6F7A8B", &asan(&through_message));
    let c = emit(work.path(), "H-C0001-1A2B3C4D", &ubsan(&direct));
    results::rebuild(
        work.path(),
        &results::RebuildOptions {
            tool: results::model::ToolInfo {
                name: "bhf".into(),
                version: "0.0.0-test".into(),
                build: "test".into(),
            },
            now: Some("2026-11-15T12:00:00Z".into()),
            generate_reproducers: false,
            lock_timeout: Duration::from_secs(5),
        },
    )
    .unwrap();

    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.path().join("results/findings.json")).unwrap())
            .unwrap();
    let groups = doc["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1, "{groups:#?}");
    let group = &groups[0];
    let mut members: Vec<&str> = group["members"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    members.sort_unstable();
    let mut ids = vec![a.as_str(), b.as_str(), c.as_str()];
    ids.sort_unstable();
    assert_eq!(members, ids);
    let observations = group["observations"].as_array().unwrap();
    assert_eq!(observations.len(), 2, "{group:#}");
    let stack_of = |id: &str| {
        observations
            .iter()
            .position(|observation| {
                observation["members"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|m| m == id)
            })
            .unwrap()
    };
    assert_eq!(
        stack_of(&a),
        stack_of(&c),
        "ASan and UBSan through one stack"
    );
    assert_ne!(stack_of(&a), stack_of(&b));
    for finding in doc["findings"].as_array().unwrap() {
        assert_eq!(finding["group"], group["key"], "{finding:#}");
    }
    let index = std::fs::read_to_string(work.path().join("results/INDEX.md")).unwrap();
    assert!(
        index.contains("**3 findings** in 1 root-cause groups"),
        "{index}"
    );
    assert!(
        index.contains("- Reached through 2 call stacks:"),
        "{index}"
    );
}
