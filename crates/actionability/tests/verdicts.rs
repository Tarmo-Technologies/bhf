// SPDX-License-Identifier: Apache-2.0

use actionability::{
    backfill_actionability, existing_actionability_or_backfill, ActionabilityConfidence, RunMode,
    Verdict,
};
use serde_json::json;

#[test]
fn real_reachable_requires_entry_failure_fix_and_no_prosthetics() {
    let raw = json!({
        "id": "F-real",
        "rule_id": "BHF-201",
        "harness_id": "H-real",
        "exception": {
            "stack": [
                { "function": "__asan_report_load4", "file": null, "line": null },
                { "function": "parse", "file": "src/parse.c", "line": 12 }
            ]
        },
        "replay": { "status": "reproduced" }
    });

    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-real/finding.json"),
    );

    assert_eq!(record.verdict, Verdict::RealReachable);
    assert!(!record.prosthetics.used);
}

#[test]
fn rust_std_alloc_only_leak_is_lab_only() {
    // G5: a LeakSanitizer report whose entire stack is Rust std alloc plumbing
    // (no target-crate frame) is the harness-dropped Vec/arena — lab-only noise.
    let raw = json!({
        "id": "F-leak", "rule_id": "BHF-208", "harness_id": "H-r",
        "exception": {
            "sanitizer": "lsan", "name": "memory-leak",
            "stack": [
                { "function": "malloc" },
                { "function": "<alloc::raw_vec::RawVecInner>::with_capacity_in" },
                { "function": "<alloc::vec::Vec<u8>>::with_capacity_in" }
            ]
        },
        "replay": { "status": "reproduced" }
    });
    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-leak/finding.json"),
    );
    assert_eq!(record.verdict, Verdict::LabOnly);
}

#[test]
fn leak_with_a_target_frame_is_not_demoted() {
    // A leak WITH a real target-crate frame (parson process_string) is a genuine
    // finding and must keep its normal verdict — G5 must not over-suppress.
    let raw = json!({
        "id": "F-realleak", "rule_id": "BHF-208", "harness_id": "H-p",
        "exception": {
            "sanitizer": "lsan", "name": "memory-leak",
            "stack": [
                { "function": "malloc" },
                { "function": "process_string", "file": "parson.c", "line": 898 }
            ]
        },
        "replay": { "status": "reproduced" }
    });
    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-realleak/finding.json"),
    );
    assert_ne!(record.verdict, Verdict::LabOnly);
}

#[test]
fn harness_cleanup_double_free_is_lab_only() {
    // A double-free whose ENTIRE fault stack is the generated harness's own
    // cleanup (bhf_run_one freeing the pointer fields it fabricated for a
    // by-pointer struct param, e.g. a tomlc99 `eat_token(context_t*, …)`
    // internal) plus libc — no target frame. bhf manufactured the crash, so
    // even though the fuzzed entry is flagged attacker-reachable it must NOT read
    // as a real/likely-reachable critical vulnerability. Surfaced as lab-only.
    let raw = json!({
        "id": "F-art", "rule_id": "BHF-201", "harness_id": "H-C0",
        "input_reachability": "attacker_reachable",
        "exception": {
            "name": "ASAN_ATTEMPTING",
            "message": "ERROR: AddressSanitizer: attempting double-free on 0x502000000070 in thread T0:",
            "stack": [
                { "function": "free", "file": null, "line": null },
                { "function": "bhf_run_one", "file": "/w/auto/H-C0/main.c", "line": 64 },
                { "function": "bhf_run_file", "file": "/w/auto/H-C0/main.c", "line": 479 },
                { "function": "main", "file": "/w/auto/H-C0/main.c", "line": 545 }
            ]
        },
        "replay": { "status": "reproduced" }
    });
    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-art/finding.json"),
    );
    assert_eq!(record.verdict, Verdict::LabOnly);
}

#[test]
fn double_free_with_a_target_frame_is_not_demoted() {
    // The contrast: a double-free whose top fault frame is TARGET code (the
    // target itself frees twice) is a genuine ownership bug — it must keep its
    // normal reachable verdict. The harness-artifact demotion must not swallow it.
    let raw = json!({
        "id": "F-real-df", "rule_id": "BHF-201", "harness_id": "H-C1",
        "input_reachability": "attacker_reachable",
        "exception": {
            "name": "ASAN_ATTEMPTING",
            "message": "ERROR: AddressSanitizer: attempting double-free on 0x502 in thread T0:",
            "stack": [
                { "function": "free", "file": null, "line": null },
                { "function": "toml_free_table", "file": "toml.c", "line": 1421 },
                { "function": "bhf_run_one", "file": "/w/auto/H-C1/main.c", "line": 64 }
            ]
        },
        "replay": { "status": "reproduced" }
    });
    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-real-df/finding.json"),
    );
    assert_ne!(record.verdict, Verdict::LabOnly);
}

#[test]
fn go_must_function_panic_is_lab_only() {
    // A recovered Go panic whose panicking frame is a `Must*` function
    // (fastjson `MustParse`): by Go convention `MustX` is a panic-on-error
    // wrapper around `X`, so panicking on bad input is its documented contract,
    // not a bug — and `X` (which returns an error) is fuzzed separately. Demote.
    let raw = json!({
        "id": "F-must", "rule_id": "BHF-210", "harness_id": "H-G0",
        "input_reachability": "attacker_reachable",
        "exception": {
            "name": "ASAN_GO_PANIC",
            "message": "Go panic: cannot parse JSON: cannot parse empty string",
            "stack": [
                { "function": "github.com/valyala/fastjson.MustParse", "file": "parser.go", "line": 60 }
            ]
        },
        "replay": { "status": "reproduced" }
    });
    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-must/finding.json"),
    );
    assert_eq!(record.verdict, Verdict::LabOnly);
}

#[test]
fn go_panic_in_non_must_function_is_not_demoted() {
    // The contrast: a Go panic whose top frame is an ordinary (`Parse`) function
    // is a genuine finding — the Must* demotion must be precise.
    let raw = json!({
        "id": "F-parse", "rule_id": "BHF-210", "harness_id": "H-G1",
        "input_reachability": "attacker_reachable",
        "exception": {
            "name": "ASAN_GO_PANIC",
            "message": "Go panic: runtime error: index out of range [3] with length 2",
            "stack": [
                { "function": "github.com/x/y.Parse", "file": "parse.go", "line": 12 }
            ]
        },
        "replay": { "status": "reproduced" }
    });
    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-parse/finding.json"),
    );
    assert_ne!(record.verdict, Verdict::LabOnly);
}

#[test]
fn relational_contract_assert_panic_is_lab_only() {
    // G6: bytes::Bytes::slice_ref asserts subset is contained in self; the
    // auto-harness builds them independently so any input trips the contract.
    let raw = json!({
        "id": "F-sr", "rule_id": "BHF-201", "harness_id": "H-b",
        "exception": {
            "name": "panic",
            "message": "subset is out of bounds: self = (0x1, 10), subset = (0x2, 3)",
            "stack": [ { "function": "slice_ref", "file": "src/bytes.rs", "line": 432 } ]
        },
        "replay": { "status": "reproduced" }
    });
    let record =
        backfill_actionability(RunMode::Attacking, &raw, Some("findings/F-sr/finding.json"));
    assert_eq!(record.verdict, Verdict::LabOnly);
}

#[test]
fn stdlib_index_oob_panic_is_not_demoted() {
    // A genuine standard-library bounds panic must NOT be demoted by G6 — it can
    // be a real OOB in target code.
    let raw = json!({
        "id": "F-oob", "rule_id": "BHF-201", "harness_id": "H-x",
        "exception": {
            "name": "panic",
            "message": "index out of bounds: the len is 3 but the index is 5",
            "stack": [ { "function": "parse", "file": "src/parse.rs", "line": 12 } ]
        },
        "replay": { "status": "reproduced" }
    });
    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-oob/finding.json"),
    );
    assert_ne!(record.verdict, Verdict::LabOnly);
}

#[test]
fn byteorder_fixed_width_slice_read_panic_is_lab_only() {
    // #467: ByteOrder::read_u128(buf: &[u8]) reads a fixed `&buf[..16]` prefix and
    // panics when the fuzzed slice is shorter — a documented length precondition
    // ("Panics if buf.len() < 16"), not a memory-safety bug. The `range end index
    // {primitive-width}` form (NOT the computed `the index is Y` form) marks it.
    for (n, m) in [(16u32, 0u32), (4, 0), (8, 3), (2, 1)] {
        let raw = json!({
            "id": "F-bo", "rule_id": "BHF-201", "harness_id": "H-bo",
            "exception": {
                "sanitizer": "asan",
                "name": "ASAN_RUST_PANIC_INDEX_OUT_OF_BOUNDS",
                "message": format!("Rust panic: range end index {n} out of range for slice of length {m}"),
                "stack": [ { "function": "<rust panic>", "file": "src/lib.rs", "line": 1908 } ]
            },
            "replay": { "status": "reproduced" }
        });
        let record =
            backfill_actionability(RunMode::Attacking, &raw, Some("findings/F-bo/finding.json"));
        assert_eq!(
            record.verdict,
            Verdict::LabOnly,
            "fixed-width read of a too-short slice (end {n}, len {m}) is lab-only"
        );
    }
}

#[test]
fn variable_length_slice_read_panic_is_not_demoted() {
    // A parser that reads a length field then over-indexes lands on an ARBITRARY
    // end index (here 257), never a primitive integer width — that can be a real
    // OOB and must NOT be masked by the #467 byteorder carve-out.
    let raw = json!({
        "id": "F-var", "rule_id": "BHF-201", "harness_id": "H-var",
        "exception": {
            "name": "panic",
            "message": "range end index 257 out of range for slice of length 12",
            "stack": [ { "function": "parse_record", "file": "src/parse.rs", "line": 88 } ]
        },
        "replay": { "status": "reproduced" }
    });
    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-var/finding.json"),
    );
    assert_ne!(record.verdict, Verdict::LabOnly);
}

#[test]
fn prosthetic_evidence_disqualifies_real_reachable() {
    let raw = json!({
        "id": "F-lab",
        "rule_id": "BHF-201",
        "harness_id": "H-lab",
        "build": { "deps": { "stubbed": ["Missing.Driver"] } },
        "exception": {
            "stack": [
                { "function": "parse", "file": "src/parse.c", "line": 12 }
            ]
        },
        "replay": { "status": "reproduced" }
    });

    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-lab/finding.json"),
    );

    assert_eq!(record.verdict, Verdict::LabOnly);
    assert!(record.prosthetics.used);
    assert_eq!(record.prosthetics.items[0].kind, "stubbed_dependency");
}

#[test]
fn existing_real_actionability_is_downgraded_when_raw_prosthetics_are_present() {
    let raw = json!({
        "id": "F-stale-real",
        "rule_id": "BHF-201",
        "harness_id": "H-lab",
        "build": { "deps": { "stubbed": ["Missing.Driver"] } },
        "exception": {
            "stack": [
                { "function": "parse", "file": "src/parse.c", "line": 12 }
            ]
        },
        "replay": { "status": "reproduced" },
        "actionability": {
            "mode": "attacking",
            "verdict": "real_reachable",
            "impact": "high",
            "confidence": "high",
            "entry_path": {
                "kind": "harness",
                "source": "testcase.bin",
                "target": "H-lab"
            },
            "fix_location": {
                "path": "src/parse.c",
                "line": 12,
                "reason": "sanitizer_stack_frame"
            },
            "replay": { "status": "reproduced" },
            "prosthetics": { "used": false, "items": [] }
        }
    });

    let record = existing_actionability_or_backfill(
        RunMode::Attacking,
        &raw,
        Some(std::path::Path::new("findings/F-stale-real/finding.json")),
    );

    assert_eq!(record.verdict, Verdict::LabOnly);
    assert!(record.prosthetics.used);
    assert_eq!(record.prosthetics.items[0].kind, "stubbed_dependency");
}

#[test]
fn blocked_resource_evidence_yields_blocked_when_no_prosthetic_was_used() {
    let raw = json!({
        "id": "F-blocked",
        "rule_id": "BHF-304",
        "harness_id": "H-blocked",
        "runtrace_events": [
            { "kind": "network_unreachable", "address": "10.0.0.5:443" }
        ]
    });

    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-blocked/finding.json"),
    );

    assert_eq!(record.verdict, Verdict::Blocked);
}

#[test]
fn explicit_blocked_resources_yield_blocked_when_no_prosthetic_was_used() {
    let raw = json!({
        "id": "F-blocked-resource",
        "rule_id": "BHF-304",
        "harness_id": "H-blocked",
        "blocked_resources": [
            { "kind": "file_missing", "path": "/etc/app/config" }
        ]
    });

    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-blocked-resource/finding.json"),
    );

    assert_eq!(record.verdict, Verdict::Blocked);
}

#[test]
fn fallback_finding_json_location_does_not_make_reproduced_finding_real() {
    let raw = json!({
        "id": "F-metadata-only",
        "rule_id": "BHF-201",
        "harness_id": "H-metadata",
        "replay": { "status": "reproduced" }
    });

    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-metadata-only/finding.json"),
    );

    assert_ne!(record.verdict, Verdict::RealReachable);
    assert_eq!(record.confidence, ActionabilityConfidence::Low);
    // With no stack to resolve, there is no fix location at all — and never the
    // generated finding.json path.
    assert!(record.fix_location.is_none());
}

#[test]
fn unknown_runtrace_event_does_not_block_reproduced_real_finding() {
    let raw = json!({
        "id": "F-real-runtrace",
        "rule_id": "BHF-201",
        "harness_id": "H-real",
        "exception": {
            "stack": [
                { "function": "__asan_report_load4", "file": null, "line": null },
                { "function": "parse", "file": "src/parse.c", "line": 12 }
            ]
        },
        "replay": { "status": "reproduced" },
        "runtrace_events": [
            { "kind": "unknown", "raw": "resource probe did something unclassified" }
        ]
    });

    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-real-runtrace/finding.json"),
    );

    assert_eq!(record.verdict, Verdict::RealReachable);
}

#[test]
fn strong_static_evidence_without_replay_is_likely_reachable() {
    let raw = json!({
        "id": "F-likely",
        "rule_id": "BHF-205",
        "harness_id": "H-likely",
        "exception": {
            "stack": [
                { "function": "size_calc", "file": "src/parse.c", "line": 30 }
            ]
        }
    });

    let record = backfill_actionability(
        RunMode::Reporting,
        &raw,
        Some("findings/F-likely/finding.json"),
    );

    assert_eq!(record.verdict, Verdict::LikelyReachable);
}

#[test]
fn insufficient_evidence_is_unknown() {
    let raw = json!({ "id": "F-unknown" });

    let record = backfill_actionability(
        RunMode::Reporting,
        &raw,
        Some("findings/F-unknown/finding.json"),
    );

    assert_eq!(record.verdict, Verdict::Unknown);
}

#[test]
fn unproven_reachability_entry_is_lab_only_even_when_reproduced() {
    // The harness drove an internal function directly (e.g. a write_* serializer
    // whose buffer is caller-controlled): a clean reproduce does not make it
    // attacker-reachable, so the verdict is lab_only and the confidence cannot
    // read as high.
    let raw = json!({
        "id": "F-internal",
        "rule_id": "BHF-201",
        "harness_id": "H-internal",
        "input_reachability": "reachability_unproven",
        "exception": {
            "stack": [
                { "function": "__asan_report_load4", "file": null, "line": null },
                { "function": "write_uint24", "file": "src/enc.c", "line": 20 }
            ]
        },
        "replay": { "status": "reproduced" }
    });

    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-internal/finding.json"),
    );

    assert_eq!(record.verdict, Verdict::LabOnly);
    assert_eq!(
        record.entry_path.as_ref().unwrap().attacker_reachable,
        Some(false)
    );
    assert_ne!(record.confidence, ActionabilityConfidence::High);
}

#[test]
fn output_serializer_reachability_is_also_lab_only() {
    let raw = json!({
        "id": "F-serializer",
        "rule_id": "BHF-201",
        "harness_id": "H-serializer",
        "input_reachability": "output_serializer",
        "exception": {
            "stack": [
                { "function": "encode_frame", "file": "src/enc.c", "line": 8 }
            ]
        },
        "replay": { "status": "reproduced" }
    });

    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-serializer/finding.json"),
    );

    assert_eq!(record.verdict, Verdict::LabOnly);
    assert_eq!(
        record.entry_path.as_ref().unwrap().attacker_reachable,
        Some(false)
    );
}

#[test]
fn attacker_reachable_entry_stays_real_reachable() {
    let raw = json!({
        "id": "F-public",
        "rule_id": "BHF-201",
        "harness_id": "H-public",
        "input_reachability": "attacker_reachable",
        "exception": {
            "stack": [
                { "function": "__asan_report_load4", "file": null, "line": null },
                { "function": "parse", "file": "src/parse.c", "line": 12 }
            ]
        },
        "replay": { "status": "reproduced" }
    });

    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-public/finding.json"),
    );

    assert_eq!(record.verdict, Verdict::RealReachable);
    assert_eq!(
        record.entry_path.as_ref().unwrap().attacker_reachable,
        Some(true)
    );
    assert_eq!(record.confidence, ActionabilityConfidence::High);
}

#[test]
fn attacker_reachable_static_only_is_likely_reachable() {
    let raw = json!({
        "id": "F-public-static",
        "rule_id": "BHF-205",
        "harness_id": "H-public-static",
        "input_reachability": "attacker_reachable",
        "exception": {
            "stack": [
                { "function": "size_calc", "file": "src/parse.c", "line": 30 }
            ]
        }
    });

    let record = backfill_actionability(
        RunMode::Reporting,
        &raw,
        Some("findings/F-public-static/finding.json"),
    );

    assert_eq!(record.verdict, Verdict::LikelyReachable);
}

#[test]
fn empty_harness_id_does_not_create_entry_path_evidence() {
    let raw = json!({
        "id": "F-empty-harness",
        "rule_id": "BHF-201",
        "harness_id": "   "
    });

    let record = backfill_actionability(
        RunMode::Reporting,
        &raw,
        Some("findings/F-empty-harness/finding.json"),
    );

    assert!(record.entry_path.is_none());
    assert_ne!(record.verdict, Verdict::LikelyReachable);
}

#[test]
fn native_assertion_enum_domain_precondition_is_lab_only() {
    // #39: tinycbor cbor_encode_floating_point asserts its fpType discriminator is
    // one of the Half/Float/Double enum members. The auto-harness fuzzes fpType out
    // of domain, so the assert trips on a harness-supplied parameter — demote to
    // lab-only (still surfaced), not a real CWE-617 finding.
    let raw = json!({
        "id": "F-fp",
        "rule_id": "BHF-415",
        "harness_id": "H-tinycbor",
        "classification": "oracle_hit",
        "oracle": {
            "name": "native-assertion-contract",
            "api": "__assert_fail",
            "evidence": [
                { "key": "expression", "value": "fpType == CborHalfFloatType || fpType == CborFloatType || fpType == CborDoubleType" }
            ]
        },
        "exception": { "name": "oracle", "message": "native assertion contract failed" }
    });
    let record = backfill_actionability(RunMode::Attacking, &raw, None);
    assert_eq!(record.verdict, Verdict::LabOnly);
}

#[test]
fn genuine_relational_assertion_still_surfaces_not_demoted() {
    // #39 guard: a genuine relational invariant (`len < cap`) is NOT a discriminator
    // domain precondition — it must keep its normal (non-lab-only) verdict so a real
    // reachable assertion is never hidden.
    let raw = json!({
        "id": "F-real-assert",
        "rule_id": "BHF-415",
        "harness_id": "H-x",
        "classification": "oracle_hit",
        "oracle": {
            "name": "native-assertion-contract",
            "api": "__assert_fail",
            "evidence": [ { "key": "expression", "value": "len < cap" } ]
        },
        "exception": { "name": "oracle", "message": "native assertion contract failed" }
    });
    let record = backfill_actionability(RunMode::Attacking, &raw, None);
    assert_ne!(record.verdict, Verdict::LabOnly);
}

#[test]
fn single_value_enum_assertion_is_not_demoted() {
    // #39 guard: a single `state == ACTIVE` precondition (one allowed value) is not
    // a multi-member domain check — keep it (too tight to demote safely).
    let raw = json!({
        "id": "F-one",
        "rule_id": "BHF-415",
        "harness_id": "H-y",
        "classification": "oracle_hit",
        "oracle": {
            "name": "native-assertion-contract",
            "api": "__assert_fail",
            "evidence": [ { "key": "expression", "value": "state == ACTIVE" } ]
        },
        "exception": { "name": "oracle", "message": "native assertion contract failed" }
    });
    let record = backfill_actionability(RunMode::Attacking, &raw, None);
    assert_ne!(record.verdict, Verdict::LabOnly);
}

/// A generated harness source with `statement` at line 76 of `main.c` in a
/// fresh directory, and the path of that file.
fn generated_main(tag: &str, statements: &[&str]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("bhf-actionability-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut lines = vec![
        "/* SPDX-License-Identifier: Apache-2.0 */".to_owned(),
        "/* generated_harnesses/H-C0001/main.c */".to_owned(),
        "/* bhf harness format 2 */".to_owned(),
    ];
    while lines.len() < 72 {
        lines.push(String::new());
    }
    lines.push("int bhf_run_one(const uint8_t *Data, size_t Size) {".to_owned());
    lines.push("    BHF_PUBLISH_INPUT(Data, Size);".to_owned());
    lines.push("    bhf_cursor Cur = bhf_open(Data, Size);".to_owned());
    for statement in statements {
        lines.push(format!("    {statement}"));
    }
    lines.push("    return 0;".to_owned());
    lines.push("}".to_owned());
    let path = dir.join("main.c");
    std::fs::write(&path, lines.join("\n")).unwrap();
    path
}

/// A heap overflow of a buffer allocated at `alloc_function` in `alloc_file`
/// (line `line`), on an entry whose signature takes a byte buffer.
fn harness_sized_overflow_at(
    alloc_function: &str,
    alloc_file: &str,
    line: u64,
) -> serde_json::Value {
    json!({
        "id": "F-pre", "rule_id": "BHF-201", "harness_id": "H-C0001",
        "input_reachability": "attacker_reachable",
        "exception": {
            "name": "ASAN_HEAP_BUFFER_OVERFLOW", "sanitizer": "asan",
            "message": "heap-buffer-overflow READ of size 4",
            "stack": [{ "function": "copy_at", "file": "/src/widget/copy.c", "line": 7 }],
            "access": {
                "direction": "read", "size": 4,
                "region": { "kind": "heap", "size": 1, "offset": 1, "relation": "after", "distance": 0 },
                "alloc_stack": [
                    { "function": "malloc", "file": "/llvm/compiler-rt/lib/asan/asan_malloc_linux.cpp", "line": 68 },
                    { "function": alloc_function, "file": alloc_file, "line": line },
                    { "function": "bhf_run_one", "file": "/w/harnesses/H-C0001/main.c", "line": 106 }
                ]
            }
        }
    })
}

/// The statement a generated harness emits for a lone `const unsigned char *`
/// parameter: a copy of the whole input, sized by the harness.
const LENGTHLESS_COPY: &str = "size_t _bhf_cap_tag = (size_t)Size + 1; if (_bhf_cap_tag < 8) _bhf_cap_tag = 8; const unsigned char * tag = (const unsigned char *)malloc(_bhf_cap_tag); if (tag) { memset((void *)tag, 0, _bhf_cap_tag); if (Size) memcpy((void *)tag, Data, Size); ((char *)tag)[Size] = '\\0'; };";

/// A heap overflow of a buffer the generated harness allocated for a pointer
/// parameter it passes without a length (a decoded C string, or a copy of the
/// input sized by the harness) is precondition-dependent, not reachable from
/// input, even on an entry whose signature takes a byte buffer.
#[test]
fn overflow_of_a_harness_sized_buffer_is_precondition_dependent() {
    let main = generated_main("lengthless", &[LENGTHLESS_COPY, "int R = read_tag(tag);"]);
    let main = main.to_str().unwrap().to_owned();
    for (function, file, line, buffer) in [
        (
            "bhf_c_string",
            "/w/harnesses/H-C0001/bhf_decode.h",
            195,
            None,
        ),
        ("bhf_run_one", main.as_str(), 76, Some("`tag`")),
    ] {
        let raw = harness_sized_overflow_at(function, file, line);
        assert!(
            actionability::is_harness_sized_buffer_overflow(&raw),
            "{function}"
        );
        let record = backfill_actionability(
            RunMode::Reporting,
            &raw,
            Some("findings/F-pre/finding.json"),
        );
        assert_eq!(record.verdict, Verdict::LabOnly, "{function}");
        let mut stamped = raw.clone();
        stamped["actionability"] = serde_json::to_value(&record).unwrap();
        let text = actionability::reachability_statement(&stamped, Some("read_tag"));
        assert!(text.starts_with("precondition-dependent"), "{text}");
        assert!(text.contains("passed without a length"), "{text}");
        if let Some(buffer) = buffer {
            assert!(text.contains(buffer), "{text}");
        }
        assert!(!text.contains("attacker-reachable"), "{text}");
    }
}

/// The generated harness also allocates the buffer of a `(buf, len)` pair,
/// an output buffer with its capacity, and a NUL-terminated copy passed with
/// a length. Those come with their length, so an overflow past it is the
/// target's and keeps its reachability verdict.
#[test]
fn overflow_of_a_harness_buffer_passed_with_its_length_stays_reachable() {
    for (tag, statements) in [
        (
            "pair",
            [
                "size_t _bhf_cap_buf = Size <= (1024 * 1024) ? (size_t)Size : (1024 * 1024); uint8_t * buf = (uint8_t *)malloc(_bhf_cap_buf ? _bhf_cap_buf : 1); if (buf && _bhf_cap_buf) memcpy(buf, Data, _bhf_cap_buf);",
                "size_t len = (size_t)(buf ? _bhf_cap_buf : 0);",
                "int R = parse_frame(buf, len);",
            ],
        ),
        (
            "output",
            [
                "size_t _bhf_cap_out = Size < (1024 * 1024) ? Size + 65536 : (1024 * 1024 + 65536); char * out = (char *)malloc(_bhf_cap_out ? _bhf_cap_out : 1);",
                "size_t _bhf_out_cap = (size_t)(out ? _bhf_cap_out : 0); size_t *cap = &_bhf_out_cap;",
                "int R = render_widget(out, cap);",
            ],
        ),
        (
            "nul-copy",
            [
                "size_t _bhf_ntlen_str = Size <= (1024 * 1024) ? (size_t)Size : (1024 * 1024); char *_bhf_ntbuf_str = (char *)malloc(_bhf_ntlen_str + 1); if (_bhf_ntbuf_str) { if (_bhf_ntlen_str) memcpy(_bhf_ntbuf_str, Data, _bhf_ntlen_str); _bhf_ntbuf_str[_bhf_ntlen_str] = 0; } const char * str = (const char *)_bhf_ntbuf_str;",
                "size_t len = (size_t)(_bhf_ntbuf_str ? _bhf_ntlen_str : 0);",
                "int R = scan_text(str, len, 1);",
            ],
        ),
    ] {
        let main = generated_main(tag, &statements);
        let raw = harness_sized_overflow_at("bhf_run_one", main.to_str().unwrap(), 76);
        assert!(
            !actionability::is_harness_sized_buffer_overflow(&raw),
            "{tag}"
        );
        let record = backfill_actionability(
            RunMode::Reporting,
            &raw,
            Some("findings/F-pre/finding.json"),
        );
        assert_eq!(record.verdict, Verdict::LikelyReachable, "{tag}");
        let mut stamped = raw.clone();
        stamped["actionability"] = serde_json::to_value(&record).unwrap();
        let text = actionability::reachability_statement(&stamped, Some("parse_frame"));
        assert!(!text.contains("precondition"), "{tag}: {text}");
    }
}

#[test]
fn overflow_of_a_project_or_driver_buffer_is_not_precondition_dependent() {
    // The project allocated it, or it is the driver's input buffer (which the
    // harness passes together with its length), or a harness whose source is
    // not a generated one or cannot be read: nothing shows a length-less
    // parameter.
    let custom =
        std::env::temp_dir().join(format!("bhf-actionability-custom-{}", std::process::id()));
    std::fs::create_dir_all(&custom).unwrap();
    let mut source = vec![String::new(); 75];
    source.push("    char *s = malloc(size + 1);".to_owned());
    std::fs::write(custom.join("main.c"), source.join("\n")).unwrap();
    let custom_main = custom.join("main.c");
    for (function, file, line) in [
        ("parse_record", "/src/widget/parse.c", 195),
        ("bhf_run_file", "/opt/bhf/c_runtime/bhf_driver.c", 660),
        ("bhf_run_one", custom_main.to_str().unwrap(), 76),
        ("bhf_run_one", "/nonexistent/harnesses/H-C0001/main.c", 76),
    ] {
        let raw = harness_sized_overflow_at(function, file, line);
        let raw = if function == "bhf_run_file" {
            let mut raw = raw;
            raw["exception"]["access"]["alloc_stack"] = json!([
                { "function": "malloc" },
                { "function": "bhf_run_file", "file": file, "line": 660 },
                { "function": "main", "file": file, "line": 744 }
            ]);
            raw
        } else {
            raw
        };
        assert!(
            !actionability::is_harness_sized_buffer_overflow(&raw),
            "{function} {file}"
        );
        let record = backfill_actionability(
            RunMode::Reporting,
            &raw,
            Some("findings/F-pre/finding.json"),
        );
        assert_ne!(record.verdict, Verdict::LabOnly, "{function} {file}");
    }
}

/// The reachability wording names its evidence: a signature-shape inference
/// says so, and an unassessed entry reads as not assessed, never as
/// attacker-reachable.
#[test]
fn reachability_statement_names_its_basis() {
    let statement = |verdict: &str, reachability: Option<&str>| {
        let mut raw = json!({ "harness_id": "H-C0001", "actionability": { "verdict": verdict } });
        if let Some(label) = reachability {
            raw["input_reachability"] = json!(label);
        }
        actionability::reachability_statement(&raw, Some("parse_record"))
    };
    let inferred = statement("likely_reachable", Some("attacker_reachable"));
    assert!(
        inferred.starts_with(
            "the signature of the entry `parse_record` matches an input-taking shape, so likely \
             reachable from input; not proven"
        ),
        "{inferred}"
    );
    // The signature-based classifier also accepts a parser taking one byte,
    // so the wording never claims a byte buffer.
    assert!(!inferred.contains("byte buffer"), "{inferred}");
    let unassessed = statement("likely_reachable", None);
    assert!(
        unassessed.starts_with("reachability not assessed"),
        "{unassessed}"
    );
    let unproven = statement("lab_only", Some("reachability_unproven"));
    assert!(unproven.contains("unproven"), "{unproven}");
    // Without a recorded basis nothing says whether typedefs were resolved,
    // and the wording never says no parameter is a byte buffer.
    assert!(
        unproven.contains(
            "the signature of the entry `parse_record` does not match an input-taking shape"
        ),
        "{unproven}"
    );
    assert!(!unproven.contains("as spelled"), "{unproven}");
    assert!(!unproven.contains("no parameter"), "{unproven}");
    assert_eq!(statement("", None), "not assessed");
    for text in [inferred, unassessed, unproven] {
        assert!(!text.contains("attacker-reachable"), "{text}");
    }

    // With the basis the classifier recorded, the verdict names the
    // parameter and its type as spelled and resolved.
    let with_basis = |verdict: &str, label: &str, basis: serde_json::Value| {
        let raw = json!({ "harness_id": "H-C0001", "actionability": { "verdict": verdict },
            "input_reachability": label, "input_reachability_basis": basis });
        actionability::reachability_statement(&raw, Some("parse_record"))
    };
    let named = with_basis(
        "likely_reachable",
        "attacker_reachable",
        json!({"rule": "const_byte_buffer", "param": "buf", "spelled_type": "const u8_t *",
               "resolved_type": "const uint8_t *", "typedefs_resolved": true}),
    );
    assert!(
        named.contains(
            "matches an input-taking shape because parameter `buf` (`const u8_t *`, resolves to \
             `const uint8_t *`) is a read-only byte buffer, so likely reachable from input; not \
             proven"
        ),
        "{named}"
    );
    let resolved_unproven = with_basis(
        "lab_only",
        "reachability_unproven",
        json!({"rule": "no_input_shape", "typedefs_resolved": true}),
    );
    assert!(
        resolved_unproven.contains(
            "the signature of the entry `parse_record`, with its typedefs resolved, does not \
             match an input-taking shape"
        ),
        "{resolved_unproven}"
    );
    let internal = with_basis(
        "lab_only",
        "reachability_unproven",
        json!({"rule": "internal_linkage", "param": "buf", "spelled_type": "const uint8_t *"}),
    );
    assert!(
        internal.contains("`parse_record` has internal linkage (`static`)"),
        "{internal}"
    );
}

/// An input that is empty or all zero bytes, or a method run on an object
/// bhf's harness built, is a state real callers may never produce: each gets
/// its own caveat. A plain function on a non-zero input gets none.
#[test]
fn constructed_states_get_a_caveat() {
    let plain = json!({"rule_id": "BHF-201", "harness_id": "H-C0001"});
    assert!(actionability::harness_state_caveats(&plain, Some(b"\x01\x02")).is_empty());
    assert!(actionability::harness_state_caveats(&plain, None).is_empty());
    for input in [&b""[..], &b"\x00\x00\x00\x00"[..]] {
        let caveats = actionability::harness_state_caveats(&plain, Some(input));
        assert_eq!(caveats.len(), 1, "{caveats:?}");
        assert!(
            caveats[0].contains(
                "a real caller may never pass all-zero arguments; check that one can before \
                 treating this as reachable"
            ),
            "{caveats:?}"
        );
    }
    let method = json!({"rule_id": "BHF-201", "harness_id": "H-X0001", "decoded_args": [
        {"name": "receiver", "type": "Widget", "role": "receiver", "decoder": "default constructor"},
        {"name": "n", "type": "int", "role": "param", "value": "3", "span": [0, 4]}
    ]});
    let caveats = actionability::harness_state_caveats(&method, Some(b"\x03\x00\x00\x00"));
    assert_eq!(
        caveats,
        vec![
            "the method ran on an object bhf's harness constructed (default constructor); real \
             callers may never put the object in that state"
                .to_owned()
        ]
    );
}
