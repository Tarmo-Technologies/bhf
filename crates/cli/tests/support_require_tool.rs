// SPDX-License-Identifier: Apache-2.0

//! `support::require_tool` is how a test's check for a tool it needs answers:
//! it skips the test without `BHF_REQUIRE_TOOLS=1` and fails it with the
//! variable, so a local run cannot pass by skipping what the nightly runs
//! (#360). No per-file tool helper may bypass it.

use std::path::Path;

mod support;

#[test]
fn require_tool_skips_without_env() {
    assert!(support::require_tool_with(true, "clang", false));
    assert!(!support::require_tool_with(false, "clang", false));
}

#[test]
#[should_panic(expected = "BHF_REQUIRE_TOOLS=1 and the test's tool `gnatmake` is not available")]
fn require_tool_panics_with_env() {
    support::require_tool_with(false, "gnatmake", true);
}

#[test]
fn require_tool_passes_a_present_tool_with_env() {
    assert!(support::require_tool_with(true, "gnatmake", true));
}

/// Every function in the integration tests that looks for a tool (its name
/// says so and its body runs or locates a program) answers through
/// `support::require_tool`.
#[test]
fn no_tool_helper_bypasses_require_tool() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut bypassing = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        for (name, body) in tool_helpers(&text) {
            let probes = ["Command::new(", "which::which", "split_paths"]
                .iter()
                .any(|probe| body.contains(probe));
            if probes && !body.contains("support::require_tool") {
                bypassing.push(format!(
                    "{}: fn {name}",
                    path.file_name().unwrap().to_string_lossy()
                ));
            }
        }
    }
    assert!(
        bypassing.is_empty(),
        "tool helpers that skip without support::require_tool: {bypassing:#?}"
    );
}

/// `(name, body)` of each `fn <name>(...) -> bool` whose name marks a tool
/// check: `have*`, `which`, `*_available`, `*_present`, `has_*`, `*_runs`,
/// `*_installed`.
fn tool_helpers(text: &str) -> Vec<(String, String)> {
    let mut helpers = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("fn ") {
        let after = &rest[at + 3..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        rest = &after[name.len()..];
        let tool_name = name.starts_with("have")
            || name == "which"
            || name.ends_with("_available")
            || name.ends_with("_present")
            || name.starts_with("has_")
            || name.ends_with("_runs")
            || name.ends_with("_installed");
        let Some(open) = rest.find('{') else { break };
        let signature = &rest[..open];
        if !tool_name || !signature.contains("-> bool") || signature.contains(';') {
            continue;
        }
        let mut depth = 0usize;
        let mut end = open;
        for (offset, c) in rest[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + offset;
                        break;
                    }
                }
                _ => {}
            }
        }
        helpers.push((name, rest[open + 1..end].to_owned()));
        rest = &rest[end..];
    }
    helpers
}
