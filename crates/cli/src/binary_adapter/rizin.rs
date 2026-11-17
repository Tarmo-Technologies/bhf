// SPDX-License-Identifier: Apache-2.0

//! The Rizin adapter: `rizin -q -c 'aaa; aflj; axlj; izj' <binary>`, each
//! listing after a marker line, mapped into the report's arrays.

use super::{int_at, run_analyzer, AdapterError, Analysis};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// The marker line before each listing in the output.
const SECTION: &str = "BHF_SECTION ";

/// The commands Rizin runs: analyze everything, then list the functions
/// (with their call refs), every xref and the strings of the data sections.
const SCRIPT: &str = "aaa; echo BHF_SECTION functions; aflj; echo BHF_SECTION xrefs; axlj; \
                      echo BHF_SECTION strings; izj";

pub(super) fn analyze(
    tool: &Path,
    target: &Path,
    timeout: Duration,
) -> Result<Analysis, AdapterError> {
    let mut command = Command::new(tool);
    command
        .args([
            "-q",
            "-e",
            "scr.color=0",
            "-e",
            "scr.interactive=false",
            "-c",
        ])
        .arg(SCRIPT)
        .arg(target);
    map(&run_analyzer(&mut command, timeout)?)
}

/// Map Rizin's output, as [`SCRIPT`] prints it, into an analysis.
fn map(output: &str) -> Result<Analysis, AdapterError> {
    let sections = split_sections(output);
    let listing = |name: &str| -> Result<Vec<Value>, AdapterError> {
        let Some(text) = sections.get(name) else {
            return Err(AdapterError::new(
                "bad_output",
                format!("rizin printed no {name} listing"),
            ));
        };
        if text.trim().is_empty() {
            return Ok(Vec::new());
        }
        match serde_json::from_str(text) {
            Ok(Value::Array(items)) => Ok(items),
            Ok(_) => Err(AdapterError::new(
                "bad_output",
                format!("rizin's {name} listing is not a JSON array"),
            )),
            Err(error) => Err(AdapterError::new(
                "bad_output",
                format!("parse rizin's {name} listing: {error}"),
            )),
        }
    };
    let functions = listing("functions")?;
    let xrefs = listing("xrefs")?;
    let strings = listing("strings")?;

    let mut analysis = Analysis::default();
    let mut names = HashMap::new();
    for function in &functions {
        let (Some(address), Some(raw)) = (
            int_at(function, "offset").or_else(|| int_at(function, "addr")),
            function.get("name").and_then(Value::as_str),
        ) else {
            continue;
        };
        let (name, imported) = symbol_name(raw);
        names.insert(address, name.clone());
        analysis.function(
            &name,
            address,
            int_at(function, "size"),
            function.get("signature").and_then(Value::as_str),
            imported,
        );
    }
    for function in &functions {
        let Some(caller) = int_at(function, "offset")
            .or_else(|| int_at(function, "addr"))
            .and_then(|address| names.get(&address))
        else {
            continue;
        };
        for call in function
            .get("callrefs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|call| call.get("type").and_then(Value::as_str) == Some("CALL"))
        {
            let Some(to) = int_at(call, "to").or_else(|| int_at(call, "addr")) else {
                continue;
            };
            let callee = names.get(&to).cloned().unwrap_or_else(|| super::hex(to));
            analysis.call(caller, &callee);
        }
    }
    for xref in &xrefs {
        let (Some(from), Some(to)) = (int_at(xref, "from"), int_at(xref, "to")) else {
            continue;
        };
        let kind = xref
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_ascii_lowercase();
        analysis.xref(from, to, &kind);
    }
    for string in &strings {
        let (Some(address), Some(value)) = (
            int_at(string, "vaddr"),
            string.get("string").and_then(Value::as_str),
        ) else {
            continue;
        };
        analysis.string(
            address,
            value,
            string.get("section").and_then(Value::as_str),
        );
    }
    Ok(analysis)
}

/// The text after each `BHF_SECTION <name>` line, up to the next.
fn split_sections(output: &str) -> HashMap<&str, String> {
    let mut sections: HashMap<&str, String> = HashMap::new();
    let mut current = None;
    for line in output.lines() {
        if let Some(name) = line.trim().strip_prefix(SECTION) {
            current = Some(name.trim());
            sections.entry(name.trim()).or_default();
        } else if let Some(name) = current {
            let text = sections.entry(name).or_default();
            text.push_str(line);
            text.push('\n');
        }
    }
    sections
}

/// A Rizin flag name as the symbol it names, and whether it is an import:
/// `sym.imp.puts` is the import `puts`, `sym.parse_header` and
/// `dbg.parse_header` are `parse_header`; `main`, `entry0` and
/// `fcn.00001050` are as they are.
fn symbol_name(raw: &str) -> (String, bool) {
    if let Some(name) = raw.strip_prefix("sym.imp.") {
        return (name.to_owned(), true);
    }
    let name = raw
        .strip_prefix("sym.")
        .or_else(|| raw.strip_prefix("dbg."))
        .unwrap_or(raw);
    (name.to_owned(), false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Rizin 0.9.1's output for `tests/fixtures/binary_adapter/legacy.c`
    /// (`cc -O0`), as [`SCRIPT`] prints it.
    const RECORDED: &str = include_str!("testdata/rizin-legacy.out");

    #[test]
    fn recorded_rizin_output_maps_to_functions_calls_strings_and_xrefs() {
        let analysis = map(RECORDED).unwrap();
        let function = |name: &str| {
            analysis
                .functions
                .iter()
                .find(|function| function["name"] == name)
                .unwrap_or_else(|| panic!("{name}: {:#?}", analysis.functions))
                .clone()
        };
        let parse_header = function("parse_header");
        assert_eq!(parse_header["address"], "0x1169");
        assert_eq!(parse_header["size"], 61);
        assert_eq!(parse_header["imported"], false);
        assert!(parse_header["signature"]
            .as_str()
            .unwrap()
            .contains("const char *"));
        assert_eq!(function("strncmp")["imported"], true);
        assert_eq!(function("main")["address"], "0x11de");

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

        let values: Vec<&str> = analysis
            .strings
            .iter()
            .map(|string| string["value"].as_str().unwrap())
            .collect();
        assert_eq!(
            values,
            ["LEGACY/1.0", "usage: legacy"],
            "the .dynstr names are left out"
        );
        assert_eq!(analysis.strings[0]["section"], ".rodata");
        assert_eq!(analysis.strings[0]["address"], "0x2004");

        let call = analysis
            .xrefs
            .iter()
            .find(|xref| xref["kind"] == "call" && xref["to"] == "0x1169")
            .expect("a call xref to parse_header");
        assert!(call["from"].as_str().unwrap().starts_with("0x11"));
        assert!(analysis.xrefs.iter().any(|xref| xref["kind"] == "data"));
    }

    #[test]
    fn a_missing_or_malformed_listing_is_bad_output() {
        let missing = map("BHF_SECTION functions\n[]\n").unwrap_err();
        assert_eq!(missing.reason, "bad_output");
        assert!(missing.message.contains("xrefs"), "{}", missing.message);
        let malformed =
            map("BHF_SECTION functions\n[{\n BHF_SECTION xrefs\n[]\nBHF_SECTION strings\n[]\n")
                .unwrap_err();
        assert!(
            malformed.message.contains("functions"),
            "{}",
            malformed.message
        );
        // An empty listing is an empty array.
        let empty =
            map("BHF_SECTION functions\n\nBHF_SECTION xrefs\nBHF_SECTION strings\n[]\n").unwrap();
        assert!(empty.functions.is_empty() && empty.xrefs.is_empty());
    }

    #[test]
    fn flag_names_are_the_symbols_they_name() {
        assert_eq!(symbol_name("sym.imp.puts"), ("puts".to_owned(), true));
        assert_eq!(
            symbol_name("sym.parse_header"),
            ("parse_header".to_owned(), false)
        );
        assert_eq!(symbol_name("dbg.handle"), ("handle".to_owned(), false));
        assert_eq!(
            symbol_name("fcn.00001050"),
            ("fcn.00001050".to_owned(), false)
        );
        assert_eq!(symbol_name("main"), ("main".to_owned(), false));
    }
}
