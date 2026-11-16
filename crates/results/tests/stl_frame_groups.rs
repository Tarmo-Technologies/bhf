// SPDX-License-Identifier: Apache-2.0

//! Two independent out-of-bounds reads through one C++ standard-library
//! accessor, in two project files, are two root-cause groups in `results/`.
//! The reports are the ones clang 18 with libstdc++ 14 prints for a
//! `vector<unique_ptr<Item>>` read past its end in `users.cpp:8` and in
//! `groups.cpp:9` (paths shortened).

use std::path::Path;
use std::time::Duration;

const UNIQUE_PTR_H: &str =
    "/usr/bin/../lib/gcc/x86_64-linux-gnu/14/../../../../include/c++/14/bits/unique_ptr.h";

fn report(function: &str, file: &str, line: u32) -> String {
    format!(
        "=================================================================\n\
         ==547304==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000088 at pc 0x5b4db87ef463 bp 0x7ffdcd3d0460 sp 0x7ffdcd3d0458\n\
         READ of size 8 at 0x502000000088 thread T0\n\
         \x20   #0 0x5b4db87ef462 in std::__uniq_ptr_impl<Item, std::default_delete<Item>>::_M_ptr() const {UNIQUE_PTR_H}:193:51\n\
         \x20   #1 0x5b4db87ef424 in std::unique_ptr<Item, std::default_delete<Item>>::get() const {UNIQUE_PTR_H}:464:21\n\
         \x20   #2 0x5b4db87ed2b4 in std::unique_ptr<Item, std::default_delete<Item>>::operator->() const {UNIQUE_PTR_H}:457:9\n\
         \x20   #3 0x5b4db87ef59e in {function}(unsigned char const*) /src/widget/{file}:{line}:10\n\
         \x20   #4 0x5b4db87ecd54 in main /src/widget/main.cpp:7:74\n\
         \n\
         0x502000000088 is located 8 bytes after 16-byte region [0x502000000070,0x502000000080)\n\
         SUMMARY: AddressSanitizer: heap-buffer-overflow {UNIQUE_PTR_H}:193:51 in std::__uniq_ptr_impl<Item, std::default_delete<Item>>::_M_ptr() const\n\
         ==547304==ABORTING\n"
    )
}

fn emit(work: &Path, harness: &str, stderr: &str) -> String {
    let report = corpus::parse_sanitizer_report(stderr).expect("an ASan report");
    corpus::finding::FindingEmitter::with_metadata(
        work.to_path_buf(),
        harness.to_owned(),
        "cpp".to_owned(),
        String::new(),
    )
    .emit_sanitizer_crash_with_log(b"x", &report, Some(stderr.as_bytes()))
    .unwrap()
    .0
}

#[test]
fn two_file_stl_fixture_yields_two_root_cause_groups() {
    let work = tempfile::tempdir().unwrap();
    let users = emit(
        work.path(),
        "H-X0008-1A2B3C4D",
        &report("user_lookup", "users.cpp", 8),
    );
    let groups = emit(
        work.path(),
        "H-X0009-5E6F7A8B",
        &report("group_lookup", "groups.cpp", 9),
    );
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
    let groups_doc = doc["groups"].as_array().unwrap();
    assert_eq!(groups_doc.len(), 2, "{groups_doc:#?}");
    for id in [&users, &groups] {
        assert!(
            groups_doc
                .iter()
                .any(|group| group["members"] == serde_json::json!([id])),
            "{id} is alone in its group: {groups_doc:#?}"
        );
    }
    let index = std::fs::read_to_string(work.path().join("results/INDEX.md")).unwrap();
    assert!(
        index.contains("**2 findings** in 2 root-cause groups"),
        "{index}"
    );
    assert!(index.contains("user_lookup"), "{index}");
    assert!(index.contains("group_lookup"), "{index}");
}
