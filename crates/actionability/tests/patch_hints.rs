// SPDX-License-Identifier: Apache-2.0

use actionability::patch_hints_for_finding;
use serde_json::json;

#[test]
fn command_injection_gets_conservative_argv_guidance() {
    let hints = patch_hints_for_finding(&json!({ "rule_id": "BHF-304" }));

    assert_eq!(hints.len(), 1);
    assert_eq!(hints[0].rule_id, "BHF-304");
    assert!(hints[0].guidance.contains("argv"));
    assert!(hints[0].diff.is_none());
}

#[test]
fn integer_overflow_gets_bounds_guidance() {
    let hints = patch_hints_for_finding(&json!({ "rule_id": "BHF-205" }));

    assert_eq!(hints[0].rule_id, "BHF-205");
    assert!(hints[0].guidance.contains("bounds"));
}

#[test]
fn unknown_rule_gets_no_patch_hint() {
    let hints = patch_hints_for_finding(&json!({ "rule_id": "BHF-999" }));

    assert!(hints.is_empty());
}

/// UBSan reports a missing return at the function's own line, while frame #0
/// is where the input fell off the end of its body. The hint names the
/// function and cites the reported line as its declaration, and mentions
/// frame #0's line only as where the input reached the end.
#[test]
fn missing_return_hint_cites_the_function_line_not_the_body_line_as_the_function() {
    let raw = json!({
        "rule_id": "BHF-214",
        "exception": {
            "name": "UBSAN_MISSING_RETURN",
            "kind": "missing-return",
            "sanitizer": "ubsan",
            "message": "/src/widget/util.cpp:2:5: runtime error: execution reached the end of a value-returning function without returning a value",
            "stack": [
                { "function": "classify_code(int)", "file": "/src/widget/util.cpp", "line": 4 },
                { "function": "parse_record(unsigned char const*)", "file": "/src/widget/parse.cpp", "line": 11 }
            ]
        }
    });
    let hints = patch_hints_for_finding(&raw);
    let guidance = &hints.first().expect("a hint").guidance;
    assert!(
        guidance.starts_with(
            "Return a value on every path out of `classify_code` (declared at `/src/widget/util.cpp:2`)"
        ),
        "{guidance}"
    );
    assert!(
        guidance
            .contains("the input reached the end of the function from `/src/widget/util.cpp:4`"),
        "{guidance}"
    );
    assert!(
        !guidance.contains("reported line is the function"),
        "{guidance}"
    );
    assert!(
        !guidance.contains("function at `/src/widget/util.cpp:4`"),
        "{guidance}"
    );

    // Without frames the report's own line is all there is: no second line.
    let mut frameless = raw.clone();
    frameless["exception"]["stack"] = json!([]);
    let hints = patch_hints_for_finding(&frameless);
    let guidance = &hints.first().expect("a hint").guidance;
    assert!(
        guidance.contains("(declared at `/src/widget/util.cpp:2`)"),
        "{guidance}"
    );
    assert!(
        !guidance.contains("reached the end of the function from"),
        "{guidance}"
    );
}
