// SPDX-License-Identifier: Apache-2.0

//! Every AddressSanitizer report kind maps to its own rule. The banners are
//! the reports compiler-rt prints: the Linux ones were captured from clang 18
//! builds of small programs (paths shortened), the Windows ones follow the
//! format the Windows runtime prints, which names the exception instead of a
//! signal.

use corpus::sanitizer::{legacy_kind, legacy_rule_id, parse_sanitizer_report, rule_matches};
use corpus::FindingEmitter;

/// A Linux report: `error` (the text after `AddressSanitizer: `), the frame
/// it faulted in, and the summary.
fn linux(error: &str, function: &str, summary: &str) -> String {
    format!(
        "AddressSanitizer:DEADLYSIGNAL\n\
         =================================================================\n\
         ==546742==ERROR: AddressSanitizer: {error}\n\
         \x20   #0 0x5c309f29cd09 in {function} /src/widget/records.c:9:60\n\
         \x20   #1 0x5c309f29cd0d in parse_record /src/widget/records.c:21:43\n\
         \x20   #2 0x7fcb36c2a1c9 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16\n\
         \n\
         AddressSanitizer can not provide additional info.\n\
         SUMMARY: AddressSanitizer: {summary}\n\
         ==546742==ABORTING\n"
    )
}

/// A Windows report of `kind`, which the Windows runtime prints for an
/// exception as `<kind> on unknown address`.
fn windows(kind: &str) -> String {
    format!(
        "==7020==ERROR: AddressSanitizer: {kind} on unknown address 0x7ff7a1b21234 \
         (pc 0x7ff7a1b21234 bp 0x00c2d0aff7a0 sp 0x00c2d0aff6f0 T0)\n\
         \x20   #0 0x7ff7a1b21234 in copy_at C:\\src\\widget\\records.c:5\n\
         \x20   #1 0x7ff7a1b25678 in parse_record C:\\src\\widget\\records.c:21\n\
         \n\
         SUMMARY: AddressSanitizer: {kind} C:\\src\\widget\\records.c:5 in copy_at\n\
         ==7020==ABORTING\n"
    )
}

const STACK_OVERFLOW: &str = "stack-overflow on address 0x7fff203c2ff8 (pc 0x5c309f29cd09 bp 0x7fff203c3020 sp 0x7fff203c3000 T0)";
const FPE: &str = "FPE on unknown address 0x617e248b6d3e (pc 0x617e248b6d3e bp 0x7ffed4a1bdb0 sp 0x7ffed4a1bdb0 T0)";
const MEMCPY_OVERLAP: &str = "memcpy-param-overlap: memory ranges [0x7e6395200030,0x7e639520003a) and [0x7e6395200032, 0x7e639520003c) overlap";
const STRCPY_OVERLAP: &str = "strcpy-param-overlap: memory ranges [0x7d5e49e00051,0x7d5e49e00058) and [0x7d5e49e00050, 0x7d5e49e00057) overlap";
const CALLOC_OVERFLOW: &str = "calloc parameters overflow: count * size (9223372036854775807 * 4) cannot be represented in type size_t (thread T0)";
const TOO_BIG: &str = "requested allocation size 0x3fffffffffffffff (0x4000000000001000 after adjustments for alignment, red zones etc.) exceeds maximum supported size of 0x10000000000 (thread T0)";
const OUT_OF_MEMORY: &str = "out of memory: allocator is trying to allocate 0x8000000000 bytes";
const BUS: &str =
    "BUS on unknown address (pc 0x5f49148f3be0 bp 0x7ffce2784dd0 sp 0x7ffce2784d00 T0)";
const ILL: &str = "ILL on unknown address 0x59cc5b476b04 (pc 0x59cc5b476b04 bp 0x7ffc9ec74580 sp 0x7ffc9ec744a0 T0)";
const ABRT: &str = "ABRT on unknown address 0x03e80008584b (pc 0x7ef107c9ebec bp 0x7ffd77bf13d0 sp 0x7ffd77bf1390 T0)";
const TRAP: &str = "TRAP on unknown address 0x000000000000 (pc 0x5fffbf064b23 bp 0x7ffeee189bd0 sp 0x7ffeee189b00 T0)";

/// `(report, kind, rule)` for every report kind that has a rule of its own.
fn reports() -> Vec<(String, &'static str, &'static str)> {
    vec![
        (
            linux(
                STACK_OVERFLOW,
                "depth_of",
                "stack-overflow /src/widget/records.c:9:60 in depth_of",
            ),
            "stack-overflow",
            "BHF-207",
        ),
        (
            linux(FPE, "divide", "FPE /src/widget/records.c:9:60 in divide"),
            "FPE",
            "BHF-222",
        ),
        (
            linux(
                MEMCPY_OVERLAP,
                "shift_buffer",
                "memcpy-param-overlap (/src/widget/records+0xc4ee4)",
            ),
            "memcpy-param-overlap",
            "BHF-229",
        ),
        (
            linux(
                STRCPY_OVERLAP,
                "copy_name",
                "strcpy-param-overlap (/src/widget/records+0xc4ee4)",
            ),
            "strcpy-param-overlap",
            "BHF-229",
        ),
        (
            linux(
                CALLOC_OVERFLOW,
                "alloc_matrix",
                "calloc-overflow (/src/widget/records+0xc739d)",
            ),
            "calloc-overflow",
            "BHF-209",
        ),
        (
            linux(
                TOO_BIG,
                "read_blob",
                "allocation-size-too-big (/src/widget/records+0xc71b3)",
            ),
            "allocation-size-too-big",
            "BHF-209",
        ),
        (
            linux(
                OUT_OF_MEMORY,
                "read_blob",
                "out-of-memory (/src/widget/records+0xc71b3)",
            ),
            "out-of-memory",
            "BHF-209",
        ),
        (
            linux(BUS, "copy_at", "BUS /src/widget/records.c:9:60 in copy_at"),
            "BUS",
            "BHF-210",
        ),
        (
            linux(ILL, "copy_at", "ILL /src/widget/records.c:9:60 in copy_at"),
            "ILL",
            "BHF-210",
        ),
        (
            linux(
                ABRT,
                "__pthread_kill_implementation",
                "ABRT nptl/pthread_kill.c:44:76 in __pthread_kill_implementation",
            ),
            "ABRT",
            "BHF-210",
        ),
        (
            linux(
                TRAP,
                "copy_at",
                "TRAP /src/widget/records.c:9:60 in copy_at",
            ),
            "TRAP",
            "BHF-210",
        ),
        (windows("stack-overflow"), "stack-overflow", "BHF-207"),
        (
            windows("int-divide-by-zero"),
            "int-divide-by-zero",
            "BHF-222",
        ),
        (
            windows("flt-divide-by-zero"),
            "flt-divide-by-zero",
            "BHF-222",
        ),
        (
            windows("illegal-instruction"),
            "illegal-instruction",
            "BHF-210",
        ),
        (windows("priv-instruction"), "priv-instruction", "BHF-210"),
        (windows("breakpoint"), "breakpoint", "BHF-210"),
    ]
}

/// Each kind is read from the `ERROR:` line, by phrase where ASan names it
/// with one, and reports under its own rule; none of them is a heap overflow.
#[test]
fn asan_kind_maps_to_its_rule() {
    for (stderr, kind, rule) in reports() {
        let report = parse_sanitizer_report(&stderr).expect("an ASan report");
        assert_eq!(
            (report.kind.as_str(), report.rule_id),
            (kind, rule),
            "{stderr}"
        );
        assert!(
            report.message.starts_with("ERROR: AddressSanitizer: "),
            "{}",
            report.message
        );
        let rule = finding_rules::by_id(report.rule_id).expect("a catalog rule");
        assert_ne!(rule.cwe, "CWE-787", "{kind}");
    }
}

/// The stack of an unbounded recursion is the recursing function, and the
/// finding carries the uncontrolled-recursion rule and its CWE.
#[test]
fn stack_overflow_is_uncontrolled_recursion() {
    let report = parse_sanitizer_report(&linux(
        STACK_OVERFLOW,
        "depth_of",
        "stack-overflow /src/widget/records.c:9:60 in depth_of",
    ))
    .unwrap();
    assert_eq!(report.stack[0].function, "depth_of");
    assert_eq!(finding_rules::by_id(report.rule_id).unwrap().cwe, "CWE-674");

    let work = tempfile::tempdir().unwrap();
    let id = FindingEmitter::new(work.path().to_path_buf())
        .emit_sanitizer_crash(b"[[[[", &report)
        .unwrap();
    let record: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            work.path()
                .join("results/findings")
                .join(&id.0)
                .join("finding.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        record["actionability"]["cwe"],
        serde_json::json!(["CWE-674"])
    );
    let explanation = record["actionability"]["explanation"].as_str().unwrap();
    assert!(explanation.contains("recursion"), "{explanation}");
    assert!(!explanation.contains("past the end"), "{explanation}");
}

/// An overlapping `memcpy` is BHF-229, CWE-475, in the rule catalog and in
/// the finding bhf writes for it.
#[test]
fn memcpy_param_overlap_is_bhf229_cwe475() {
    let report = parse_sanitizer_report(&linux(
        MEMCPY_OVERLAP,
        "shift_buffer",
        "memcpy-param-overlap (/src/widget/records+0xc4ee4)",
    ))
    .unwrap();
    assert_eq!(report.rule_id, "BHF-229");
    assert_eq!(report.kind, "memcpy-param-overlap");
    let rule = finding_rules::by_id("BHF-229").expect("BHF-229 is registered");
    assert_eq!(rule.cwe, "CWE-475");
    assert_eq!(rule.slug, "bhf.c/overlapping-copy-arguments");

    let work = tempfile::tempdir().unwrap();
    let emitter = FindingEmitter::new(work.path().to_path_buf());
    let id = emitter.emit_sanitizer_crash(b"seed", &report).unwrap();
    let record: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            work.path()
                .join("results/findings")
                .join(&id.0)
                .join("finding.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(record["rule_id"], "BHF-229");
    assert_eq!(record["exception"]["name"], "ASAN_MEMCPY_PARAM_OVERLAP");
    assert_eq!(
        record["actionability"]["cwe"],
        serde_json::json!(["CWE-475"])
    );
    let explanation = record["actionability"]["explanation"].as_str().unwrap();
    assert!(explanation.contains("overlap"), "{explanation}");
    assert!(explanation.contains("shift_buffer"), "{explanation}");
}

/// A kind bhf has no rule for, a known one (`unknown-crash`,
/// `odr-violation`, Windows' `datatype-misalignment`) or one a later
/// compiler-rt adds, is a reachable crash, never a heap overflow.
#[test]
fn unknown_asan_kind_is_not_heap_buffer_overflow() {
    let reports = [
        linux(
            "unknown-crash on address 0x602000000014 at pc 0x55d1 bp 0x7ffd sp 0x7ffc",
            "copy_at",
            "unknown-crash /src/widget/records.c:9:60 in copy_at",
        ),
        linux(
            "odr-violation (0x55d1b2c3d4e0):",
            "copy_at",
            "odr-violation: global 'table' at /src/widget/records.c:3:12",
        ),
        linux(
            "frobnicated-pointer on address 0x602000000014 at pc 0x55d1 bp 0x7ffd sp 0x7ffc",
            "copy_at",
            "frobnicated-pointer /src/widget/records.c:9:60 in copy_at",
        ),
        windows("datatype-misalignment"),
        windows("flt-invalid-operation"),
    ];
    for stderr in &reports {
        let report = parse_sanitizer_report(stderr).expect("an ASan report");
        assert_eq!(report.rule_id, "BHF-210", "{stderr}");
        assert_ne!(report.rule_id, "BHF-201", "{stderr}");
    }
}

/// Earlier releases filed every kind above under BHF-201, and took the kind
/// from the first word of the `ERROR:` line: a replay of such a finding still
/// matches its rule and kind.
#[test]
fn earlier_heap_overflow_rule_is_the_legacy_rule() {
    for (stderr, kind, _) in reports() {
        let report = parse_sanitizer_report(&stderr).unwrap();
        assert_eq!(legacy_rule_id(&report), Some("BHF-201"), "{kind}");
        assert!(rule_matches("BHF-201", &report), "{kind}");
        assert!(rule_matches(report.rule_id, &report), "{kind}");
        assert!(!rule_matches("BHF-202", &report), "{kind}");
    }
    let kind_of = |error: &str| {
        let report = parse_sanitizer_report(&linux(error, "read_blob", "x")).unwrap();
        (report.kind.clone(), legacy_kind(&report))
    };
    assert_eq!(
        kind_of(OUT_OF_MEMORY),
        ("out-of-memory".to_owned(), Some("out".to_owned()))
    );
    assert_eq!(
        kind_of(CALLOC_OVERFLOW),
        ("calloc-overflow".to_owned(), Some("calloc".to_owned()))
    );
    assert_eq!(
        kind_of(TOO_BIG),
        (
            "allocation-size-too-big".to_owned(),
            Some("requested".to_owned())
        )
    );
    assert_eq!(
        kind_of(MEMCPY_OVERLAP),
        (
            "memcpy-param-overlap".to_owned(),
            Some("memcpy-param-overlap:".to_owned())
        )
    );
    assert_eq!(kind_of(STACK_OVERFLOW), ("stack-overflow".to_owned(), None));

    // Kinds whose rule did not change have no legacy rule.
    let heap = parse_sanitizer_report(&linux(
        "heap-buffer-overflow on address 0x602000000014 at pc 0x55d1 bp 0x7ffd sp 0x7ffc",
        "copy_at",
        "heap-buffer-overflow /src/widget/records.c:9:60 in copy_at",
    ))
    .unwrap();
    assert_eq!(heap.rule_id, "BHF-201");
    assert_eq!(legacy_rule_id(&heap), None);
    assert_eq!(legacy_kind(&heap), None);
    let poisoned = parse_sanitizer_report(&linux(
        "use-after-poison on address 0x602000000014 at pc 0x55d1 bp 0x7ffd sp 0x7ffc",
        "copy_at",
        "use-after-poison /src/widget/records.c:9:60 in copy_at",
    ))
    .unwrap();
    assert_eq!(poisoned.rule_id, "BHF-201");
    assert_eq!(legacy_rule_id(&poisoned), None);
}

/// A language lane's finding is tagged AddressSanitizer too; it never takes
/// the heap-overflow rule as its earlier one.
#[test]
fn language_lane_findings_have_no_legacy_heap_overflow_rule() {
    let python = parse_sanitizer_report(
        "== bhf python finding: KeyError: 'name'\nTraceback (most recent call last):\n",
    )
    .unwrap();
    assert_eq!(python.rule_id, "BHF-210");
    assert_eq!(legacy_rule_id(&python), None);
    assert!(!rule_matches("BHF-201", &python));
    assert_eq!(legacy_kind(&python), None);
}

/// A finding an earlier release wrote for an ASan out-of-memory report, under
/// the heap-overflow rule and the kind `out`, is in the root-cause group of
/// the same crash found now, under BHF-209 `out-of-memory`.
#[test]
fn earlier_heap_overflow_finding_groups_with_the_same_crash_found_now() {
    let stderr = linux(
        OUT_OF_MEMORY,
        "read_blob",
        "out-of-memory (/src/widget/records+0xc71b3)",
    );
    let now = parse_sanitizer_report(&stderr).unwrap();
    let mut earlier = now.clone();
    earlier.rule_id = "BHF-201";
    earlier.kind = "out".to_owned();

    let work = tempfile::tempdir().unwrap();
    let emitter = FindingEmitter::new(work.path().to_path_buf());
    let earlier_id = emitter.emit_sanitizer_crash(b"earlier", &earlier).unwrap();
    let now_id = emitter.emit_sanitizer_crash(b"now", &now).unwrap();
    let findings = work.path().join("results/findings");
    let record = |id: &corpus::FindingId| -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(findings.join(&id.0).join("finding.json")).unwrap())
            .unwrap()
    };
    let (earlier_record, now_record) = (record(&earlier_id), record(&now_id));
    assert_eq!(earlier_record["exception"]["name"], "ASAN_OUT");
    assert_ne!(
        earlier_record["cluster_key_full"],
        now_record["cluster_key_full"]
    );

    let rekeyed = corpus::cluster::legacy_fallback_cluster_key(&earlier_record)
        .expect("the earlier record takes this release's key");
    assert_eq!(
        serde_json::json!(rekeyed.full),
        now_record["cluster_key_full"]
    );
    assert_eq!(rekeyed.frames, ["read_blob", "parse_record"]);
    assert!(corpus::cluster::legacy_fallback_cluster_key(&now_record).is_none());

    let out = tempfile::tempdir().unwrap();
    let document = report::build_report(&report::ReportOptions::new(
        findings,
        out.path().to_path_buf(),
    ))
    .unwrap();
    assert_eq!(document.findings.len(), 2);
    assert_eq!(document.clusters.len(), 1, "{:#?}", document.clusters);
    assert_eq!(document.clusters[0].member_count, 2);
}
