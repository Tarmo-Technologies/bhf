// SPDX-License-Identifier: Apache-2.0

//! The angr adapter: the tool is a Python that imports angr, and it runs the
//! bundled `angr_export.py` (CFGFast over the main object), whose JSON export
//! is mapped into the report's arrays. angr maps a PIE at `0x400000`;
//! addresses are moved back to the binary's own base.

use super::{int_at, read_export, run_analyzer, AdapterError, Analysis, MAX_XREFS};
use serde_json::Value;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// The export script, written beside its export for each run.
const EXPORT_SCRIPT: &str = include_str!("angr_export.py");

pub(super) fn analyze(
    python: &Path,
    target: &Path,
    timeout: Duration,
) -> Result<Analysis, AdapterError> {
    let work = tempfile::Builder::new()
        .prefix("bhf-angr-")
        .tempdir()
        .map_err(|error| AdapterError::new("tool_error", format!("create a work dir: {error}")))?;
    let script = work.path().join("angr_export.py");
    let export = work.path().join("export.json");
    std::fs::write(&script, EXPORT_SCRIPT).map_err(|error| {
        AdapterError::new("tool_error", format!("write the export script: {error}"))
    })?;
    let mut command = Command::new(python);
    command
        .arg(&script)
        .arg(target)
        .arg(&export)
        // One past the largest cap, so a list cut there is seen as cut.
        .arg((MAX_XREFS + 1).to_string());
    let log = run_analyzer(&mut command, timeout)?;
    map(&read_export(&export, &log)?)
}

/// Map the export `angr_export.py` wrote into an analysis.
fn map(export: &Value) -> Result<Analysis, AdapterError> {
    let mapped_base = int_at(export, "mapped_base")
        .ok_or_else(|| AdapterError::new("bad_output", "the export has no mapped_base"))?;
    let linked_base = int_at(export, "linked_base").unwrap_or(mapped_base);
    let rebase = |address: u64| address.wrapping_sub(mapped_base).wrapping_add(linked_base);
    let list = |key: &str| -> Result<&Vec<Value>, AdapterError> {
        export
            .get(key)
            .and_then(Value::as_array)
            .ok_or_else(|| AdapterError::new("bad_output", format!("the export has no {key} list")))
    };

    let mut analysis = Analysis::default();
    for function in list("functions")? {
        let (Some(name), Some(entry)) = (
            function.get("name").and_then(Value::as_str),
            int_at(function, "entry"),
        ) else {
            continue;
        };
        analysis.function(
            name,
            rebase(entry),
            int_at(function, "size"),
            None,
            function.get("plt").and_then(Value::as_bool) == Some(true),
        );
        for callee in function
            .get("calls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            analysis.call(name, callee);
        }
    }
    for string in list("strings")? {
        let (Some(address), Some(value)) = (
            int_at(string, "address"),
            string.get("value").and_then(Value::as_str),
        ) else {
            continue;
        };
        analysis.string(
            rebase(address),
            value,
            string.get("section").and_then(Value::as_str),
        );
    }
    for xref in list("xrefs")? {
        let (Some(from), Some(to), Some(kind)) = (
            int_at(xref, "from"),
            int_at(xref, "to"),
            xref.get("type").and_then(Value::as_str),
        ) else {
            continue;
        };
        // angr's `offset`, `read` and `write` are data references.
        let kind = match kind {
            "call" => "call",
            "offset" | "read" | "write" => "data",
            other => other,
        };
        analysis.xref(rebase(from), rebase(to), kind);
    }
    Ok(analysis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// `angr_export.py`'s export of `tests/fixtures/binary_adapter/legacy.c`
    /// (`cc -O0`, a PIE) from angr 10.0.7.
    const RECORDED: &str = include_str!("testdata/angr-legacy.json");

    #[test]
    fn a_recorded_angr_export_maps_at_the_binarys_own_addresses() {
        let export: Value = serde_json::from_str(RECORDED).unwrap();
        assert_eq!(export["mapped_base"], 0x400000);
        let analysis = map(&export).unwrap();
        let function = |name: &str| {
            analysis
                .functions
                .iter()
                .find(|function| function["name"] == name)
                .unwrap_or_else(|| panic!("{name}: {:#?}", analysis.functions))
                .clone()
        };
        assert_eq!(function("parse_header")["address"], "0x1169");
        assert_eq!(function("parse_header")["size"], 61);
        assert_eq!(function("main")["address"], "0x11de");
        assert_eq!(function("puts")["imported"], true);
        assert_eq!(function("puts")["address"], "0x1070");
        for (caller, callee) in [
            ("main", "handle"),
            ("handle", "parse_header"),
            ("handle", "puts"),
            ("parse_header", "strncmp"),
        ] {
            assert!(
                analysis
                    .call_graph
                    .contains(&json!({ "caller": caller, "callee": callee })),
                "{caller} -> {callee}: {:#?}",
                analysis.call_graph
            );
        }
        assert!(
            !analysis
                .call_graph
                .iter()
                .any(|edge| edge["callee"].as_str().unwrap().starts_with("Unresolvable")),
            "{:#?}",
            analysis.call_graph
        );
        let values: Vec<&str> = analysis
            .strings
            .iter()
            .filter(|string| string["section"] == ".rodata")
            .map(|string| string["value"].as_str().unwrap())
            .collect();
        assert_eq!(values, ["LEGACY/1.0", "usage: legacy"]);
        assert!(analysis
            .xrefs
            .contains(&json!({ "from": "0x11bd", "to": "0x1169", "kind": "call" })));
        assert!(analysis.xrefs.iter().any(|xref| xref["kind"] == "data"));
    }

    #[test]
    fn an_export_without_its_lists_is_bad_output() {
        let error = map(&json!({ "mapped_base": 0, "functions": [], "strings": [] })).unwrap_err();
        assert_eq!(error.reason, "bad_output");
        assert!(error.message.contains("xrefs"), "{}", error.message);
    }
}
