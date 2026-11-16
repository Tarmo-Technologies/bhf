// SPDX-License-Identifier: Apache-2.0

//! The findings of the interpreted lanes are classified by what happened:
//! stack exhaustion in a JavaScript or PHP target is uncontrolled recursion,
//! not a buffer overflow, and a command injection the JavaScript driver
//! stopped is not described as a crash. Each finding is written by the
//! emitter from the stderr the lane prints.

use corpus::sanitizer::{parse_sanitizer_report, Sanitizer, SanitizerReport};
use corpus::FindingEmitter;
use serde_json::Value;

/// The finding bhf writes for `report`, found by harness `harness_id`.
fn emit(harness_id: &str, report: &SanitizerReport) -> Value {
    let work = tempfile::tempdir().unwrap();
    let emitter = FindingEmitter::with_metadata(
        work.path().to_path_buf(),
        harness_id.to_owned(),
        "unknown".to_owned(),
        format!("{}/auto/{harness_id}/main", work.path().display()),
    );
    let id = emitter.emit_sanitizer_crash(b"((((", report).unwrap();
    serde_json::from_slice(
        &std::fs::read(
            work.path()
                .join("results/findings")
                .join(&id.0)
                .join("finding.json"),
        )
        .unwrap(),
    )
    .unwrap()
}

fn explanation(record: &Value) -> &str {
    record["actionability"]["explanation"].as_str().unwrap()
}

/// What the Node driver prints for `RangeError: Maximum call stack size
/// exceeded`: the stack V8 printed when the recursion ran out inside the
/// `Buffer` length getter, a builtin with no source file.
const JS_RECURSION: &str =
    "== bhf js finding: BHF-207: RangeError: Maximum call stack size exceeded\n\
RangeError: Maximum call stack size exceeded\n\
\x20   at get length [as length] (<anonymous>)\n\
\x20   at nest (/srv/app/lib/nest.js:1:34)\n\
\x20   at nest (/srv/app/lib/nest.js:1:78)\n\
\x20   at nest (/srv/app/lib/nest.js:1:78)\n\
\x20   at nest (/srv/app/lib/nest.js:1:78)\n";

#[test]
fn js_range_error_is_uncontrolled_recursion() {
    let report = parse_sanitizer_report(JS_RECURSION).expect("a js finding");
    assert_eq!(
        (report.rule_id, report.kind.as_str()),
        ("BHF-207", "js-stack-overflow")
    );
    let record = emit("H-N0001-1A2B3C4D", &report);
    let actionability = &record["actionability"];
    assert_eq!(actionability["cwe"], serde_json::json!(["CWE-674"]));
    assert_eq!(actionability["cwe_name"], "Uncontrolled Recursion");
    // The builtin frame V8 names `<anonymous>` is not where the bug is.
    assert_eq!(actionability["sink"]["function"], "nest");
    assert_eq!(actionability["sink"]["file"], "/srv/app/lib/nest.js");
    assert_eq!(
        actionability["fix_location"]["path"],
        "/srv/app/lib/nest.js"
    );
    let text = explanation(&record);
    assert!(text.contains("recursion"), "{text}");
    assert!(text.contains("`nest`"), "{text}");
    assert!(!text.contains("past the end of a buffer"), "{text}");
    assert!(!text.contains("attacker-controlled code"), "{text}");
}

/// PHP 8.3 has no stack limit by default: deep recursion overflows the
/// interpreter's own C stack and the kernel kills `php` with SIGSEGV, with
/// nothing on stderr. The fuzz loop records that as a fatal signal.
#[test]
fn php_recursion_segv_is_not_cwe_119() {
    let report = SanitizerReport {
        sanitizer: None,
        kind: "fatal-signal".to_owned(),
        rule_id: "BHF-210",
        message: "harness crashed with SIGSEGV and no sanitizer report — a reachable crash"
            .to_owned(),
        check: Some("SIGSEGV".to_owned()),
        ..Default::default()
    };
    let record = emit("H-W0003-5E6F7A8B", &report);
    let actionability = &record["actionability"];
    assert_ne!(actionability["cwe"], serde_json::json!(["CWE-119"]));
    assert_eq!(actionability["cwe"], serde_json::json!(["CWE-674"]));
    let text = explanation(&record);
    assert!(text.contains("PHP interpreter"), "{text}");
    assert!(text.contains("recursion"), "{text}");
    assert!(!text.contains("pointer"), "{text}");
    let hints = actionability["patch_hints"].as_array().unwrap();
    assert!(
        hints.iter().any(|hint| hint["guidance"]
            .as_str()
            .is_some_and(|text| text.contains("recursion depth"))),
        "{hints:?}"
    );

    // The same signal in a native harness stays an invalid-memory access.
    let native = emit("H-C0003-5E6F7A8B", &report);
    assert_eq!(
        native["actionability"]["cwe"],
        serde_json::json!(["CWE-119"])
    );
}

/// The Node driver stops a fuzz-controlled `child_process` command before it
/// runs and reports it (BHF-431) with one line: nothing crashed. The command
/// is the fuzz input's, so its words (`SEGV`, `abort`) are not evidence.
#[test]
fn command_injection_explanation_does_not_describe_a_crash() {
    let report = parse_sanitizer_report(
        "== bhf js finding: BHF-431: CommandInjection: execSync: convert x; kill -SEGV 1; abort out.png\n",
    )
    .expect("a js finding");
    assert_eq!(report.rule_id, "BHF-431");
    let record = emit("H-N0002-1A2B3C4D", &report);
    let actionability = &record["actionability"];
    assert_eq!(actionability["cwe"], serde_json::json!(["CWE-78"]));
    let text = explanation(&record);
    for crash_word in ["crash", "fault", "stopped", "segmentation"] {
        assert!(!text.contains(crash_word), "{crash_word}: {text}");
    }
    assert!(text.contains("command"), "{text}");
    assert!(
        actionability["patch_hints"][0]["guidance"]
            .as_str()
            .is_some_and(|hint| hint.contains("argument")),
        "{}",
        actionability["patch_hints"]
    );
}

/// A runtime oracle's command-injection finding is explained the same way.
#[test]
fn command_injection_oracle_explanation_does_not_describe_a_crash() {
    let work = tempfile::tempdir().unwrap();
    let emitter = FindingEmitter::new(work.path().to_path_buf());
    let hit = finding_rules::oracle_sdk::OracleHit {
        oracle_name: "command-controlled-runtime".to_owned(),
        rule_id: "BHF-431".to_owned(),
        category: "logic".to_owned(),
        api: "system".to_owned(),
        message: "fuzz-controlled command reached a shell-execution API during fuzz execution"
            .to_owned(),
        evidence: vec![finding_rules::oracle_sdk::OracleEvidence::new(
            "command",
            "echo 'bhf_x; abort' > /dev/null",
        )],
    };
    let id = emitter.emit_oracle_hit(b"x; abort", &hit).unwrap();
    let record: Value = serde_json::from_slice(
        &std::fs::read(
            work.path()
                .join("results/findings")
                .join(&id.0)
                .join("finding.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let text = explanation(&record);
    for crash_word in ["crash", "fault", "stopped", "assertion"] {
        assert!(!text.contains(crash_word), "{crash_word}: {text}");
    }
    assert!(text.contains("command"), "{text}");
}

/// A memory-safe lane's own stack-depth errors, named by kind, are
/// uncontrolled recursion as well.
#[test]
fn managed_stack_overflow_kinds_are_uncontrolled_recursion() {
    for (harness, kind) in [
        ("H-G0001-1A2B3C4D", "go-stack-overflow"),
        ("H-S0001-1A2B3C4D", "csharp-stack-overflow"),
    ] {
        let report = SanitizerReport {
            sanitizer: Some(Sanitizer::AddressSanitizer),
            kind: kind.to_owned(),
            rule_id: "BHF-207",
            message: "runtime: goroutine stack exceeds 1000000000-byte limit".to_owned(),
            ..Default::default()
        };
        let record = emit(harness, &report);
        assert_eq!(
            record["actionability"]["cwe"],
            serde_json::json!(["CWE-674"]),
            "{kind}"
        );
    }
}
