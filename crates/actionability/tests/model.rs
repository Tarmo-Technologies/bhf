// SPDX-License-Identifier: Apache-2.0

use actionability::{
    backfill_actionability, ActionabilityConfidence, ActionabilityRecord, EntryPath, FixLocation,
    Impact, Prosthetics, ReplayEvidence, RunMode, Verdict,
};
use serde_json::json;

#[test]
fn oracle_finding_backfills_cwe_from_rule_id() {
    // M22 campaign fix: an ORACLE_* behavioral/assertion finding has no bug-class
    // CWE, so it used to emit a blank CWE in auto/findings.csv. The actionability
    // backfill must fall back to the matched rule's CWE (BHF-415 -> CWE-617) so the
    // "every finding carries a CWE in every format" contract holds on the auto path.
    let raw = json!({
        "rule_id": "BHF-415",
        "classification": "ORACLE_NATIVE_ASSERT",
        "exception": { "name": "oracle", "message": "native assertion contract violated" }
    });
    let rec = backfill_actionability(RunMode::Reporting, &raw, None);
    assert_eq!(rec.cwe, vec!["CWE-617".to_string()]);
    assert!(rec.cwe_name.is_some());
}

#[test]
fn temporal_stack_use_after_return_maps_to_cwe_562_not_121() {
    // #29: a stack-use-after-return is a TEMPORAL stale-pointer bug (CWE-562 with
    // CWE-825 secondary), NOT the spatial stack-buffer-overflow CWE-121 that the
    // old BHF-203 rule fallback produced.
    let raw = json!({
        "rule_id": "BHF-211",
        "exception": {
            "name": "ASAN_STACK_USE_AFTER_RETURN",
            "sanitizer": "asan",
            "message": "AddressSanitizer: stack-use-after-return on address 0x7f"
        }
    });
    let rec = backfill_actionability(RunMode::Reporting, &raw, None);
    assert_eq!(rec.cwe, vec!["CWE-562".to_string(), "CWE-825".to_string()]);
    assert!(!rec.cwe.contains(&"CWE-121".to_string()));
    assert!(
        !rec.patch_hints.is_empty(),
        "temporal stack needs a patch hint"
    );
    assert!(rec
        .explanation
        .unwrap()
        .to_lowercase()
        .contains("stale stack"));
}

#[test]
fn temporal_stack_use_after_scope_maps_to_cwe_825() {
    let raw = json!({
        "rule_id": "BHF-211",
        "exception": {
            "name": "ASAN_STACK_USE_AFTER_SCOPE",
            "sanitizer": "asan",
            "message": "AddressSanitizer: stack-use-after-scope on address 0x7f"
        }
    });
    let rec = backfill_actionability(RunMode::Reporting, &raw, None);
    assert_eq!(rec.cwe, vec!["CWE-825".to_string(), "CWE-562".to_string()]);
}

#[test]
fn segv_near_null_subpage_address_is_cwe_476_null_deref() {
    // #30: a near-null deref (null base + small field offset) faults at a sub-page
    // address, not exactly zero; classify it as a NULL deref (CWE-476), not a wild
    // SEGV (CWE-787/125).
    let raw = json!({
        "rule_id": "BHF-206",
        "exception": {
            "name": "ASAN_SEGV",
            "sanitizer": "asan",
            "message": "AddressSanitizer: SEGV on unknown address 0x000000000010 (READ memory access)"
        }
    });
    let rec = backfill_actionability(RunMode::Reporting, &raw, None);
    assert_eq!(rec.cwe, vec!["CWE-476".to_string()]);
}

#[test]
fn segv_wild_read_with_direction_is_cwe_125_not_787() {
    // #30: a non-null wild SEGV whose captured direction is a READ is an
    // out-of-bounds READ (CWE-125), not the default OOB WRITE (CWE-787).
    let read = json!({
        "rule_id": "BHF-206",
        "exception": {
            "name": "ASAN_SEGV",
            "sanitizer": "asan",
            "message": "AddressSanitizer: SEGV on unknown address 0x00007f1200001234 (READ memory access)"
        }
    });
    assert_eq!(
        backfill_actionability(RunMode::Reporting, &read, None).cwe,
        vec!["CWE-125".to_string()]
    );
    let write = json!({
        "rule_id": "BHF-206",
        "exception": {
            "name": "ASAN_SEGV",
            "sanitizer": "asan",
            "message": "AddressSanitizer: SEGV on unknown address 0x00007f1200001234 (WRITE memory access)"
        }
    });
    assert_eq!(
        backfill_actionability(RunMode::Reporting, &write, None).cwe,
        vec!["CWE-787".to_string()]
    );
}

#[test]
fn serializes_actionability_record_in_spec_shape() {
    let record = ActionabilityRecord {
        mode: RunMode::Attacking,
        verdict: Verdict::RealReachable,
        impact: Impact::High,
        confidence: ActionabilityConfidence::High,
        entry_path: Some(EntryPath {
            kind: "cli".to_owned(),
            source: "stdin".to_owned(),
            target: "Pkg.Parse".to_owned(),
            evidence: Vec::new(),
            attacker_reachable: None,
            reachability_basis: None,
        }),
        fix_location: Some(FixLocation {
            path: "src/pkg.adb".to_owned(),
            line: Some(42),
            col: None,
            reason: "explicit_raise_site".to_owned(),
        }),
        source: None,
        sink: None,
        explanation: None,
        cwe: Vec::new(),
        cwe_name: None,
        replay: Some(ReplayEvidence {
            status: "reproduced".to_owned(),
        }),
        prosthetics: Prosthetics::default(),
        patch_hints: Vec::new(),
        next_steps: Vec::new(),
    };

    let value = serde_json::to_value(record).unwrap();

    assert_eq!(value["mode"], "attacking");
    assert_eq!(value["verdict"], "real_reachable");
    assert_eq!(value["impact"], "high");
    assert_eq!(value["confidence"], "high");
    assert_eq!(value["entry_path"]["source"], "stdin");
    assert_eq!(value["fix_location"]["path"], "src/pkg.adb");
    assert_eq!(value["fix_location"]["reason"], "explicit_raise_site");
    assert_eq!(value["prosthetics"]["used"], false);
}

#[test]
fn lsan_leak_maps_to_cwe_401() {
    // A LeakSanitizer finding (nanosvg-style) maps to CWE-401.
    let raw = json!({
        "exception": {
            "name": "LSAN_MEMORY_LEAK",
            "sanitizer": "lsan",
            "message": "==1==ERROR: LeakSanitizer: detected memory leaks",
        }
    });
    let record = backfill_actionability(RunMode::Reporting, &raw, None);
    assert_eq!(record.cwe, vec!["CWE-401".to_owned()]);
    assert_eq!(
        record.cwe_name.as_deref(),
        Some("Missing Release of Memory after Effective Lifetime")
    );

    let value = serde_json::to_value(&record).unwrap();
    assert_eq!(value["cwe"][0], "CWE-401");
    assert_eq!(
        value["cwe_name"],
        "Missing Release of Memory after Effective Lifetime"
    );
}

#[test]
fn cwe_mapping_covers_core_bug_classes() {
    let case = |name: &str, msg: &str, sanitizer: &str| {
        backfill_actionability(
            RunMode::Reporting,
            &json!({
                "exception": { "name": name, "message": msg, "sanitizer": sanitizer }
            }),
            None,
        )
        .cwe
    };

    // heap-buffer-overflow READ -> CWE-122 primary + CWE-125 secondary.
    assert_eq!(
        case("heap-buffer-overflow", "READ of size 4", "asan"),
        vec!["CWE-122".to_owned(), "CWE-125".to_owned()]
    );
    // heap-buffer-overflow WRITE -> CWE-122 + CWE-787.
    assert_eq!(
        case("heap-buffer-overflow", "WRITE of size 8", "asan"),
        vec!["CWE-122".to_owned(), "CWE-787".to_owned()]
    );
    assert_eq!(
        case("stack-buffer-overflow", "WRITE of size 1", "asan"),
        vec!["CWE-121".to_owned()]
    );
    assert_eq!(
        case("heap-use-after-free", "READ of size 4", "asan"),
        vec!["CWE-416".to_owned()]
    );
    assert_eq!(case("double-free", "", "asan"), vec!["CWE-415".to_owned()]);
    assert_eq!(
        case("SEGV", "SEGV on unknown address 0x000000000000", "asan"),
        vec!["CWE-476".to_owned()]
    );
    assert_eq!(
        case("signed-integer-overflow", "", "ubsan"),
        vec!["CWE-190".to_owned()]
    );
    // A shift is its own weakness (CWE-1335), not "Incorrect Calculation".
    assert_eq!(
        case("shift-exponent", "shift exponent too large", "ubsan"),
        vec!["CWE-1335".to_owned()]
    );
    assert_eq!(
        case("timeout", "timeout after 60s", ""),
        vec!["CWE-834".to_owned(), "CWE-400".to_owned()]
    );
    assert_eq!(
        case(
            "out-of-memory",
            "out-of-memory: requested allocation size",
            ""
        ),
        vec!["CWE-789".to_owned(), "CWE-400".to_owned()]
    );
    // Unknown / non-memory-safety: no CWE.
    assert!(case("Constraint_Error", "range check failed", "").is_empty());
}

#[test]
fn cwe_mapping_covers_non_memory_fault_classes() {
    let record = |name: &str, msg: &str, sanitizer: &str| {
        backfill_actionability(
            RunMode::Reporting,
            &json!({
                "exception": { "name": name, "message": msg, "sanitizer": sanitizer }
            }),
            None,
        )
    };

    // SIGABRT / assert -> Reachable Assertion (CWE-617).
    let abort = record("SIGABRT", "Assertion failed: idx < len", "");
    assert_eq!(abort.cwe, vec!["CWE-617".to_owned()]);
    assert_eq!(abort.cwe_name.as_deref(), Some("Reachable Assertion"));

    // SIGFPE / divide-by-zero -> CWE-369 (NOT generic UB), even under UBSan.
    let fpe = record("SIGFPE", "division by zero", "ubsan");
    assert_eq!(fpe.cwe, vec!["CWE-369".to_owned()]);
    assert_eq!(fpe.cwe_name.as_deref(), Some("Divide By Zero"));

    // Stack exhaustion from recursion -> CWE-674 (NOT stack-buffer-overflow).
    let recursion = record(
        "stack-exhaustion",
        "uncontrolled recursion depth exceeded",
        "",
    );
    assert_eq!(recursion.cwe, vec!["CWE-674".to_owned()]);
    assert_eq!(
        recursion.cwe_name.as_deref(),
        Some("Uncontrolled Recursion")
    );

    // Uncaught managed-runtime exception -> CWE-248.
    let uncaught = record(
        "jvm-uncaught-throwable",
        "Uncaught exception: java.lang.IllegalStateException",
        "",
    );
    assert_eq!(uncaught.cwe, vec!["CWE-248".to_owned()]);
    assert_eq!(uncaught.cwe_name.as_deref(), Some("Uncaught Exception"));
}

#[test]
fn rust_index_out_of_bounds_panic_maps_to_oob_cwe() {
    // A Rust bounds-checked panic must carry a memory-safety CWE (it was empty/None
    // before) — a DETECTED out-of-bounds access. Read direction defaults to CWE-125
    // (Out-of-bounds Read); a write context flips it to CWE-787 (Out-of-bounds Write).
    let record = |name: &str, msg: &str| {
        backfill_actionability(
            RunMode::Attacking,
            &json!({
                "exception": { "name": name, "message": msg, "sanitizer": "asan" }
            }),
            None,
        )
    };

    // The byteorder campaign shape: name + slice-range message, no read/write word.
    let bo = record(
        "ASAN_RUST_PANIC_INDEX_OUT_OF_BOUNDS",
        "Rust panic: range end index 8 out of range for slice of length 0",
    );
    assert!(
        !bo.cwe.is_empty(),
        "a Rust index-out-of-bounds panic must carry a CWE, got none"
    );
    assert_eq!(bo.cwe[0], "CWE-125");
    assert_eq!(bo.cwe_name.as_deref(), Some("Out-of-bounds Read"));

    // The classic indexing form also classifies (was Unknown -> no CWE before).
    let idx = record(
        "panic",
        "index out of bounds: the len is 3 but the index is 5",
    );
    assert_eq!(idx.cwe[0], "CWE-125");

    // A write context (`copy_from_slice` into the buffer) makes it CWE-787 primary.
    let write = record(
        "ASAN_RUST_PANIC_INDEX_OUT_OF_BOUNDS",
        "Rust panic: range end index 16 out of range for slice of length 0 in copy_from_slice",
    );
    assert_eq!(write.cwe[0], "CWE-787");
    assert_eq!(write.cwe_name.as_deref(), Some("Out-of-bounds Write"));
}

/// A UBSan finding as the emitter writes it: the per-check exception name, the
/// UBSan report line (location prefix included) and the check name.
fn ubsan_finding(kind: &str, rule: &str, message: &str) -> serde_json::Value {
    json!({
        "rule_id": rule,
        "harness_id": "H-C0001",
        "paths": { "testcase": "testcase.bin" },
        "exception": {
            "name": format!("UBSAN_{}", kind.to_ascii_uppercase().replace('-', "_")),
            "sanitizer": "ubsan",
            "message": format!("/src/widget/w.cc:7:9: runtime error: {message}"),
            "stack": [{ "function": "parse_record(unsigned char const*)", "file": "/src/widget/w.cc", "line": 7 }]
        }
    })
}

const UBSAN_KINDS: &[(&str, &str, &str, &[&str])] = &[
    ("signed-integer-overflow", "BHF-205", "signed integer overflow: 2147483647 + 5 cannot be represented in type 'int'", &["CWE-190"]),
    ("null-pointer-dereference", "BHF-206", "load of null pointer of type 'int'", &["CWE-476"]),
    ("out-of-bounds-access", "BHF-220", "index 10 out of bounds for type 'int[4]'", &["CWE-129", "CWE-125", "CWE-787"]),
    ("invalid-vla-bound", "BHF-220", "variable length array bound evaluates to non-positive value -1", &["CWE-129"]),
    ("division-by-zero", "BHF-222", "division by zero", &["CWE-369"]),
    ("invalid-shift", "BHF-215", "shift exponent 40 is too large for 32-bit type 'int'", &["CWE-1335"]),
    ("missing-return", "BHF-214", "execution reached the end of a value-returning function without returning a value", &["CWE-758"]),
    ("unreachable", "BHF-216", "execution reached an unreachable program point", &["CWE-758"]),
    ("invalid-value-load", "BHF-217", "load of value 7, which is not a valid value for type 'bool'", &["CWE-758"]),
    ("float-cast-overflow", "BHF-218", "1e+20 is outside the range of representable values of type 'int'", &["CWE-681"]),
    ("implicit-conversion", "BHF-218", "implicit conversion from type 'long long' of value 1099511627776 (64-bit, signed) to type 'int' changed the value to 0 (32-bit, signed)", &["CWE-681", "CWE-197"]),
    ("pointer-overflow", "BHF-219", "pointer index expression with base 0x7fffffffffff overflowed to 0x80000000fffe", &["CWE-823", "CWE-119"]),
    ("misaligned-access", "BHF-213", "load of misaligned address 0x7c3938b00021 for type 'int', which requires 4 byte alignment", &["CWE-758"]),
    ("insufficient-object-size", "BHF-201", "store to address 0x7ffc with insufficient space for an object of type 'int'", &["CWE-787"]),
    ("type-mismatch", "BHF-221", "call to function parse_record through pointer to incorrect function type 'int (*)(void)'", &["CWE-843"]),
    ("invalid-builtin-use", "BHF-213", "passing zero to __builtin_ctz(), which is not a valid argument", &["CWE-758"]),
    ("undefined-behavior", "BHF-213", "a check this release does not name", &["CWE-758"]),
];

/// Each UBSan check kind gets its own CWE, explanation and fix hint; none of
/// them is the arithmetic-overflow narrative except the overflow itself.
#[test]
fn every_ubsan_kind_gets_its_own_cwe_explanation_and_fix_hint() {
    let mut explanations = std::collections::BTreeSet::new();
    let mut hints = std::collections::BTreeSet::new();
    for (kind, rule, message, cwes) in UBSAN_KINDS {
        let raw = ubsan_finding(kind, rule, message);
        let rec = backfill_actionability(RunMode::Reporting, &raw, None);
        let want: Vec<String> = cwes.iter().map(|c| (*c).to_owned()).collect();
        assert_eq!(rec.cwe, want, "{kind}");
        let name = rec.cwe_name.clone().unwrap_or_default();
        assert!(
            !name.is_empty() && name != "Uncategorized Weakness",
            "{kind}: {name}"
        );
        assert_ne!(name, "Incorrect Calculation", "{kind}");
        let explanation = rec.explanation.clone().unwrap();
        if *kind != "signed-integer-overflow" {
            assert!(!explanation.contains("overflows"), "{kind}: {explanation}");
        }
        let hint = rec
            .patch_hints
            .first()
            .map(|h| h.guidance.clone())
            .unwrap_or_default();
        if ![
            "signed-integer-overflow",
            "null-pointer-dereference",
            "division-by-zero",
        ]
        .contains(kind)
        {
            assert!(
                !hint.contains("overflow before the arithmetic"),
                "{kind}: {hint}"
            );
        }
        explanations.insert(explanation.split(':').next().unwrap().to_owned());
        hints.insert(hint);
    }
    assert_eq!(explanations.len(), UBSAN_KINDS.len(), "{explanations:#?}");
    assert_eq!(hints.len(), UBSAN_KINDS.len(), "{hints:#?}");

    let missing_return = backfill_actionability(
        RunMode::Reporting,
        &ubsan_finding("missing-return", "BHF-214", UBSAN_KINDS[6].2),
        None,
    );
    assert_eq!(
        missing_return.cwe_name.as_deref(),
        Some("Reliance on Undefined, Unspecified, or Implementation-Defined Behavior")
    );
    assert!(missing_return.patch_hints[0].guidance.contains("return"));
    let shift = backfill_actionability(
        RunMode::Reporting,
        &ubsan_finding("invalid-shift", "BHF-215", UBSAN_KINDS[5].2),
        None,
    );
    assert_eq!(
        shift.cwe_name.as_deref(),
        Some("Incorrect Bitwise Shift of Integer")
    );
}

/// Records written before the per-check kinds carry the generic
/// `UBSAN_UNDEFINED_BEHAVIOR` name, or a NULL/index kind whose UBSan origin
/// used to short-circuit to "Incorrect Calculation"; the report text after the
/// location still names the check.
#[test]
fn older_ubsan_records_are_classified_from_their_report_text() {
    let generic = json!({
        "rule_id": "BHF-210",
        "exception": {
            "name": "UBSAN_UNDEFINED_BEHAVIOR",
            "sanitizer": "ubsan",
            "message": "/src/widget/classify.cc:3:5: runtime error: execution reached the end of a value-returning function without returning a value",
            "stack": []
        }
    });
    let rec = backfill_actionability(RunMode::Reporting, &generic, None);
    assert_eq!(rec.cwe, vec!["CWE-758".to_owned()]);
    assert!(rec.patch_hints[0].guidance.contains("return"));
    for (name, rule, message, cwe) in [
        (
            "UBSAN_NULL_POINTER_DEREFERENCE",
            "BHF-206",
            "load of null pointer of type 'int'",
            "CWE-476",
        ),
        (
            "UBSAN_OUT_OF_BOUNDS_ACCESS",
            "BHF-201",
            "index 65 out of bounds for type 'int[4]'",
            "CWE-129",
        ),
    ] {
        let raw = json!({
            "rule_id": rule,
            "exception": {
                "name": name,
                "sanitizer": "ubsan",
                "message": format!("/src/widget/two.cc:9:3: runtime error: {message}"),
                "stack": [{ "function": "index_arr", "file": "/src/widget/two.cc", "line": 9 }]
            }
        });
        let rec = backfill_actionability(RunMode::Reporting, &raw, None);
        assert_eq!(rec.cwe[0], cwe, "{name}");
        assert_ne!(
            rec.cwe_name.as_deref(),
            Some("Incorrect Calculation"),
            "{name}"
        );
    }
}

/// The source path a report starts with never decides the bug class: a path
/// segment containing `oom`, `timeout` or `division_by_zero` is not an
/// out-of-memory, hang or divide-by-zero finding.
#[test]
fn source_path_substrings_never_reclassify_a_finding() {
    for path in [
        "/src/zoomlib/Scale.cpp",
        "/src/bloom/room.cc",
        "/src/timeout/retry.c",
        "/src/division_by_zero/math.c",
        "/src/out_of_memory/alloc.c",
    ] {
        let raw = json!({
            "rule_id": "BHF-205",
            "exception": {
                "name": "UBSAN_SIGNED_INTEGER_OVERFLOW",
                "sanitizer": "ubsan",
                "message": format!("{path}:5:24: runtime error: signed integer overflow: 1094795585 * 1094795585 cannot be represented in type 'int'"),
                "stack": [{ "function": "zoom_scale", "file": path, "line": 5 }]
            }
        });
        let rec = backfill_actionability(RunMode::Reporting, &raw, None);
        assert_eq!(rec.cwe, vec!["CWE-190".to_owned()], "{path}");
        assert!(
            rec.explanation.unwrap().contains("integer overflow"),
            "{path}"
        );
    }
    // GNAT's `file.adb:NN message` form (a line number followed by a space,
    // not a colon): the unit's file name decides nothing either, so a unit
    // named `timeout_ctl` or `oom_check` classifies like any other.
    let gnat = |message: &str| {
        let raw = json!({
            "rule_id": "BHF-101",
            "exception": {"name": "CONSTRAINT_ERROR", "message": message}
        });
        let rec = backfill_actionability(RunMode::Reporting, &raw, None);
        (rec.cwe, rec.cwe_name)
    };
    let control = gnat("parser.adb:17 range check failed");
    for message in [
        "timeout_ctl.adb:42 index check failed",
        "oom_check.adb:17 range check failed",
        "timeout_ctl.adb:42:7 index check failed",
        "zoom_out_of_memory.ads:9 range check failed",
    ] {
        assert_eq!(gnat(message), control, "{message}");
    }
    // A real out-of-memory and a real timeout are still recognised.
    let oom = json!({"rule_id": "BHF-209", "exception": {"name": "OUT_OF_MEMORY", "message": "harness exceeded the configured RSS limit (--rss-limit-mb)"}});
    assert_eq!(
        backfill_actionability(RunMode::Reporting, &oom, None).cwe[0],
        "CWE-789"
    );
    let leak_named_oom = json!({"exception": {"name": "LIBFUZZER_OOM", "message": "out-of-memory (malloc(2147483648))"}});
    assert_eq!(
        backfill_actionability(RunMode::Reporting, &leak_named_oom, None).cwe[0],
        "CWE-789"
    );
}

fn segv_record(rule: &str, message: &str, access: Option<serde_json::Value>) -> serde_json::Value {
    let mut raw = json!({
        "rule_id": rule,
        "exception": { "name": "ASAN_SEGV", "sanitizer": "asan", "message": message }
    });
    if let Some(access) = access {
        raw["exception"]["access"] = access;
    }
    raw
}

/// SEGV direction is ASan's READ/WRITE token, not a substring of the message;
/// no direction, or a non-canonical address whose READ is not a direction,
/// maps to CWE-119 instead of defaulting to an out-of-bounds write.
#[test]
fn segv_direction_is_a_token_and_unknown_maps_to_cwe_119() {
    let wild =
        "ERROR: AddressSanitizer: SEGV on unknown address 0x7f0000001000 (pc 0x1 bp 0x2 sp 0x3 T0)";
    let cwe = |raw: &serde_json::Value| backfill_actionability(RunMode::Reporting, raw, None).cwe;
    assert_eq!(
        cwe(&segv_record(
            "BHF-223",
            wild,
            Some(json!({"direction": "read"}))
        )),
        ["CWE-125"]
    );
    assert_eq!(
        cwe(&segv_record(
            "BHF-223",
            wild,
            Some(json!({"direction": "write"}))
        )),
        ["CWE-787"]
    );
    assert_eq!(
        cwe(&segv_record(
            "BHF-223",
            wild,
            Some(json!({"direction": "unknown"}))
        )),
        ["CWE-119"]
    );
    assert_eq!(
        cwe(&segv_record(
            "BHF-223",
            "ERROR: AddressSanitizer: SEGV on unknown address (pc 0x1 bp 0x2 sp 0x3 T0) (READ memory access)",
            Some(json!({"direction": "read", "address_hint": "high-value-address"}))
        )),
        ["CWE-119"]
    );
    // Older records: the direction folded into the message, or none at all.
    assert_eq!(
        cwe(&segv_record(
            "BHF-206",
            &format!("{wild} (READ memory access)"),
            None
        )),
        ["CWE-125"]
    );
    assert_eq!(cwe(&segv_record("BHF-206", wild, None)), ["CWE-119"]);
    // "thread" is not a READ.
    let global = json!({
        "rule_id": "BHF-201",
        "exception": {
            "name": "ASAN_GLOBAL_BUFFER_OVERFLOW",
            "sanitizer": "asan",
            "message": "ERROR: AddressSanitizer: global-buffer-overflow on address 0x1 at pc 0x2 bp 0x3 sp 0x4 (WRITE of size 4 at 0x1 thread T0)"
        }
    });
    assert_eq!(cwe(&global), ["CWE-787"]);
}

/// A wild-address SEGV is its own rule and class, never a NULL dereference.
#[test]
fn wild_address_segv_is_not_a_null_dereference() {
    let wild = segv_record(
        "BHF-223",
        "ERROR: AddressSanitizer: SEGV on unknown address 0x4141414141414141 (pc 0x1 bp 0x2 sp 0x3 T0)",
        Some(json!({"direction": "write", "address": "0x4141414141414141"})),
    );
    let rec = backfill_actionability(RunMode::Reporting, &wild, None);
    assert_ne!(rec.cwe[0], "CWE-476");
    assert!(rec.explanation.unwrap().contains("invalid-memory access"));
    let null = segv_record(
        "BHF-206",
        "ERROR: AddressSanitizer: SEGV on unknown address 0x000000000010 (pc 0x1 bp 0x2 sp 0x3 T0)",
        Some(
            json!({"direction": "write", "address": "0x000000000010", "address_hint": "zero-page"}),
        ),
    );
    assert_eq!(
        backfill_actionability(RunMode::Reporting, &null, None).cwe,
        ["CWE-476"]
    );
}
