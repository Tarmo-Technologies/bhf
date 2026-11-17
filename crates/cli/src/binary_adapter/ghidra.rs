// SPDX-License-Identifier: Apache-2.0

//! The Ghidra adapter: `analyzeHeadless` imports and analyzes the binary in a
//! throwaway project, then the bundled `BhfExport.java` post-script writes its
//! functions, calls, strings and references as JSON, mapped into the report's
//! arrays. Ghidra loads a PIE at `0x100000`; addresses are moved back to the
//! binary's own base.

use super::{int_at, read_export, run_analyzer, AdapterError, Analysis, MAX_XREFS};
use serde_json::Value;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// The post-script, written into the project's script dir for each run.
const EXPORT_SCRIPT: &str = include_str!("BhfExport.java");
const EXPORT_SCRIPT_NAME: &str = "BhfExport.java";

/// The Ghidra version of the install `analyze_headless` (its
/// `support/analyzeHeadless`) is in, from `Ghidra/application.properties`.
pub(super) fn version(analyze_headless: &Path) -> Option<String> {
    let install = analyze_headless
        .canonicalize()
        .ok()?
        .parent()?
        .parent()?
        .to_path_buf();
    let properties = std::fs::read_to_string(install.join("Ghidra/application.properties")).ok()?;
    properties
        .lines()
        .find_map(|line| line.strip_prefix("application.version="))
        .map(|version| format!("Ghidra {}", version.trim()))
}

pub(super) fn analyze(
    tool: &Path,
    target: &Path,
    timeout: Duration,
) -> Result<Analysis, AdapterError> {
    let work = tempfile::Builder::new()
        .prefix("bhf-ghidra-")
        .tempdir()
        .map_err(|error| {
            AdapterError::new("tool_error", format!("create a project dir: {error}"))
        })?;
    let scripts = work.path().join("scripts");
    let project = work.path().join("project");
    let export = work.path().join("export.json");
    for dir in [&scripts, &project] {
        std::fs::create_dir_all(dir).map_err(|error| {
            AdapterError::new("tool_error", format!("create {}: {error}", dir.display()))
        })?;
    }
    std::fs::write(scripts.join(EXPORT_SCRIPT_NAME), EXPORT_SCRIPT).map_err(|error| {
        AdapterError::new("tool_error", format!("write the export script: {error}"))
    })?;
    let mut command = Command::new(tool);
    command
        .arg(&project)
        .arg("bhf")
        .arg("-import")
        .arg(target)
        .arg("-scriptPath")
        .arg(&scripts)
        .arg("-postScript")
        .arg(EXPORT_SCRIPT_NAME)
        .arg(&export)
        // One past the largest cap, so a list cut there is seen as cut.
        .arg((MAX_XREFS + 1).to_string())
        .arg("-deleteProject");
    let log = run_analyzer(&mut command, timeout)?;
    map(&read_export(&export, &log)?)
}

/// Map the export `BhfExport.java` wrote into an analysis.
fn map(export: &Value) -> Result<Analysis, AdapterError> {
    let image_base = int_at(export, "image_base")
        .ok_or_else(|| AdapterError::new("bad_output", "the export has no image_base"))?;
    // An ELF's own base; Ghidra loads other formats at theirs.
    let linked_base = int_at(export, "linked_base").unwrap_or(image_base);
    let rebase = |address: u64| address.wrapping_sub(image_base).wrapping_add(linked_base);
    let list = |key: &str| -> Result<&Vec<Value>, AdapterError> {
        export
            .get(key)
            .and_then(Value::as_array)
            .ok_or_else(|| AdapterError::new("bad_output", format!("the export has no {key} list")))
    };

    let mut analysis = Analysis::default();
    // An import's own function in Ghidra's EXTERNAL block is left out: its
    // PLT thunk, in the binary, is the import.
    let functions: Vec<&Value> = list("functions")?
        .iter()
        .filter(|function| function.get("external").and_then(Value::as_bool) != Some(true))
        .collect();
    for function in &functions {
        let (Some(name), Some(entry)) = (
            function.get("name").and_then(Value::as_str),
            int_at(function, "entry"),
        ) else {
            continue;
        };
        let thunk = function.get("thunk").and_then(Value::as_bool) == Some(true);
        analysis.function(
            name,
            rebase(entry),
            int_at(function, "size"),
            function.get("signature").and_then(Value::as_str),
            thunk,
        );
        // A thunk's one call is to the import it stands for.
        if thunk {
            continue;
        }
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
        if string.get("loaded").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        let (Some(address), Some(value)) = (
            int_at(string, "address"),
            string.get("value").and_then(Value::as_str),
        ) else {
            continue;
        };
        analysis.string(
            rebase(address),
            value,
            string.get("block").and_then(Value::as_str),
        );
    }
    for reference in list("references")? {
        let (Some(from), Some(to), Some(kind)) = (
            int_at(reference, "from"),
            int_at(reference, "to"),
            reference.get("type").and_then(Value::as_str),
        ) else {
            continue;
        };
        analysis.xref(rebase(from), rebase(to), &reference_kind(kind));
    }
    Ok(analysis)
}

/// A Ghidra `RefType` name as the report's xref kind: `call`, `code` (a jump
/// or other flow), `data`, or the name itself, lowercase.
fn reference_kind(name: &str) -> String {
    if name.contains("CALL") {
        "call".to_owned()
    } else if name.contains("JUMP") || name.contains("FLOW") || name.contains("TERMINATOR") {
        "code".to_owned()
    } else if ["DATA", "READ", "WRITE"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
        || matches!(name, "PARAM" | "INDIRECTION")
    {
        "data".to_owned()
    } else {
        name.to_ascii_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// `BhfExport.java`'s export of `tests/fixtures/binary_adapter/legacy.c`
    /// (`cc -O0`, a PIE) from Ghidra 12.2.
    const RECORDED: &str = include_str!("testdata/ghidra-legacy.json");

    #[test]
    fn a_recorded_ghidra_export_maps_at_the_binarys_own_addresses() {
        let export: Value = serde_json::from_str(RECORDED).unwrap();
        assert_eq!(export["image_base"], "0x100000");
        let analysis = map(&export).unwrap();
        let function = |name: &str| {
            analysis
                .functions
                .iter()
                .filter(|function| function["name"] == name)
                .cloned()
                .collect::<Vec<_>>()
        };
        // The addresses Rizin and the ELF headers give, not Ghidra's.
        assert_eq!(function("parse_header")[0]["address"], "0x1169");
        assert_eq!(function("parse_header")[0]["size"], 61);
        assert_eq!(function("main")[0]["address"], "0x11de");
        // An import is its PLT thunk, once.
        let strncmp = function("strncmp");
        assert_eq!(strncmp.len(), 1, "{strncmp:?}");
        assert_eq!(strncmp[0]["imported"], true);
        assert_eq!(strncmp[0]["address"], "0x1060");

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
                .any(|edge| edge["caller"] == edge["callee"]),
            "no thunk calls itself: {:#?}",
            analysis.call_graph
        );

        let rodata: Vec<&Value> = analysis
            .strings
            .iter()
            .filter(|string| string["section"] == ".rodata")
            .collect();
        assert_eq!(rodata[0]["value"], "LEGACY/1.0");
        assert_eq!(rodata[0]["address"], "0x2004");
        assert!(
            analysis
                .strings
                .iter()
                .all(|string| ![".dynstr", ".strtab", ".shstrtab", ".comment"]
                    .contains(&string["section"].as_str().unwrap())),
            "symbol names and unloaded sections are left out: {:#?}",
            analysis.strings
        );

        assert!(analysis
            .xrefs
            .contains(&json!({ "from": "0x11bd", "to": "0x1169", "kind": "call" })));
        assert!(analysis.xrefs.iter().any(|xref| xref["kind"] == "data"));
        assert!(analysis.xrefs.iter().any(|xref| xref["kind"] == "code"));
    }

    #[test]
    fn an_export_without_its_lists_is_bad_output() {
        let error = map(&json!({ "image_base": "0x0", "functions": [] })).unwrap_err();
        assert_eq!(error.reason, "bad_output");
        assert!(error.message.contains("strings"), "{}", error.message);
        let error = map(&json!({})).unwrap_err();
        assert!(error.message.contains("image_base"), "{}", error.message);
    }

    #[test]
    fn reference_types_map_to_xref_kinds() {
        for (name, kind) in [
            ("UNCONDITIONAL_CALL", "call"),
            ("COMPUTED_CALL_TERMINATOR", "call"),
            ("CONDITIONAL_JUMP", "code"),
            ("DATA", "data"),
            ("READ_WRITE", "data"),
            ("PARAM", "data"),
            ("EXTERNAL_REF", "external_ref"),
        ] {
            assert_eq!(reference_kind(name), kind, "{name}");
        }
    }
}
