// SPDX-License-Identifier: Apache-2.0

//! Build fidelity: which inputs a C/C++ harness build had to fabricate.
//!
//! When the build context (a compile database, the Visual Studio project
//! import, or nothing at all) leaves a header, a macro value or a type
//! undefined, the repair loop writes a placeholder so the target still
//! compiles: an empty header, `#define NAME 0`, `typedef void *T`. The harness
//! then runs code compiled against values the project's real build never
//! uses, so a finding from it can be false, or need an input the real build
//! rejects. This module names those inputs so every report can say so.

use std::collections::BTreeMap;
use std::path::Path;

use crate::auto::repair::{Repair, AUTO_DEFINES_FILE};
use results::model::{BuildFidelity, FabricatedInput};

/// The fabricated inputs of one harness build, from its repair ledger and the
/// `repairs/auto_defines.h` the macro repairs wrote. `None` when nothing was
/// fabricated.
pub(crate) fn for_target(repairs: &[Repair], harness_dir: &Path) -> Option<BuildFidelity> {
    let defines = written_defines(&harness_dir.join("repairs").join(AUTO_DEFINES_FILE));
    let mut fabricated: Vec<FabricatedInput> = Vec::new();
    let mut push = |kind: &str, name: &str, value: Option<String>| {
        if !fabricated
            .iter()
            .any(|input| input.kind == kind && input.name == name)
        {
            fabricated.push(FabricatedInput {
                kind: kind.to_owned(),
                name: name.to_owned(),
                value,
            });
        }
    };
    for repair in repairs {
        match repair {
            Repair::MacroDefine { name, .. } => {
                push("macro", name, defines.get(name.as_str()).cloned());
            }
            Repair::ConfigGuardDefine { name, value } => {
                push("macro", name, Some(value.clone()));
            }
            Repair::HeaderPlaceholder { virtual_path }
            | Repair::ConfigHeaderSynth { virtual_path } => {
                push("header", virtual_path, None);
            }
            // A real header included for the type is no fabrication.
            Repair::TypePlaceholder {
                resolved_header: Some(_),
                ..
            } => {}
            Repair::TypePlaceholder { type_name, .. } => {
                push("type", type_name, Some("void *".to_owned()));
            }
            Repair::ConfigTypeAlias {
                type_name,
                underlying,
                ..
            } => {
                push("type", type_name, Some(underlying.clone()));
            }
            _ => {}
        }
    }
    if fabricated.is_empty() {
        return None;
    }
    Some(BuildFidelity {
        level: "reduced".to_owned(),
        context: build_context_provenance(&harness_dir.join("Makefile")),
        fabricated,
    })
}

/// The types a build's repairs resolved by including their real header
/// instead of fabricating them, as `type NAME: real header included
/// (<header>)` lines: listed beside the build's fidelity, never counted
/// against it.
pub(crate) fn real_headers_included(repairs: &[Repair]) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for repair in repairs {
        if let Repair::TypePlaceholder {
            type_name,
            resolved_header: Some(header),
        } = repair
        {
            let line = format!("type {type_name}: real header included ({header})");
            if !lines.contains(&line) {
                lines.push(line);
            }
        }
    }
    lines
}

/// `NAME -> replacement` for each `#define` in a repair defines file. A
/// function-like macro is keyed by its name and keeps its parameter list in
/// the value (`(...) 0`).
fn written_defines(path: &Path) -> BTreeMap<String, String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    let mut defines = BTreeMap::new();
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("#define ") else {
            continue;
        };
        let rest = rest.trim();
        let name_end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        let (name, value) = rest.split_at(name_end);
        if name.is_empty() {
            continue;
        }
        defines.insert(name.to_owned(), value.trim().to_owned());
    }
    defines
}

/// The `BUILD_CONTEXT_PROVENANCE` a generated harness Makefile records.
fn build_context_provenance(makefile: &Path) -> Option<String> {
    let text = std::fs::read_to_string(makefile).ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("BUILD_CONTEXT_PROVENANCE ="))
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Whether the harness had a recovered build context (a compile database or
/// a project import) and still needed fabricated headers: the context is
/// incomplete, which is worth saying louder than a plain placeholder.
pub(crate) fn incomplete_context_headers(fidelity: &BuildFidelity) -> Vec<&str> {
    if matches!(fidelity.context.as_deref(), None | Some("none")) {
        return Vec::new();
    }
    fidelity
        .fabricated
        .iter()
        .filter(|input| input.kind == "header")
        .map(|input| input.name.as_str())
        .collect()
}

/// Stamp `build.fidelity` onto every `finding.json` produced by a harness in
/// `by_harness`. Like the forced floor, the record is a fact of the build the
/// finding came from: a later run only ever adds it.
pub(crate) fn annotate_findings(work_dir: &Path, by_harness: &BTreeMap<String, BuildFidelity>) {
    if by_harness.is_empty() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(corpus::layout::findings_dir(work_dir)) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path().join("finding.json");
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(mut raw) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        let harness = raw
            .get("harness_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let Some(fidelity) = by_harness.get(&harness) else {
            continue;
        };
        let Ok(value) = serde_json::to_value(fidelity) else {
            continue;
        };
        let before = raw.clone();
        let Some(object) = raw.as_object_mut() else {
            continue;
        };
        let build = object
            .entry("build")
            .or_insert_with(|| serde_json::json!({}));
        if !build.is_object() {
            *build = serde_json::json!({});
        }
        if let Some(build) = build.as_object_mut() {
            build.insert("fidelity".to_owned(), value);
        }
        if raw == before {
            continue;
        }
        corpus::finding::append_history(&mut raw, "auto", &["build.fidelity"]);
        if let Ok(serialized) = serde_json::to_vec_pretty(&raw) {
            if let Err(error) = crate::auto::report::atomic_write(&path, &serialized) {
                bhfeprintln!(
                    "warning: failed to record build fidelity on {}: {error}",
                    path.display()
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fabricated_inputs_are_named_with_the_values_written() {
        let temp = tempfile::tempdir().unwrap();
        let repairs_dir = temp.path().join("repairs");
        std::fs::create_dir_all(&repairs_dir).unwrap();
        std::fs::write(
            repairs_dir.join(AUTO_DEFINES_FILE),
            "#define WIDGET_SLOTS 0\n#define WIDGET_LOG(...) (0)\n#define WIDGET_API\n",
        )
        .unwrap();
        std::fs::write(
            temp.path().join("Makefile"),
            "BUILD_CONTEXT_PROVENANCE = exact_tu_compile_database\nCOMPILE_DB_FLAGS = \n",
        )
        .unwrap();
        let repairs = vec![
            Repair::MacroDefine {
                name: "WIDGET_SLOTS".to_owned(),
                as_value: true,
                function_like: false,
            },
            Repair::MacroDefine {
                name: "WIDGET_LOG".to_owned(),
                as_value: true,
                function_like: true,
            },
            Repair::MacroDefine {
                name: "WIDGET_API".to_owned(),
                as_value: false,
                function_like: false,
            },
            Repair::ConfigGuardDefine {
                name: "WIDGET_DEPTH".to_owned(),
                value: "8".to_owned(),
            },
            Repair::HeaderPlaceholder {
                virtual_path: "tables.h".to_owned(),
            },
            Repair::TypePlaceholder {
                type_name: "widget_ctx".to_owned(),
                resolved_header: None,
            },
            Repair::StubBlind {
                symbol: "widget_log".to_owned(),
            },
        ];
        let fidelity = for_target(&repairs, temp.path()).expect("fabricated");
        assert_eq!(fidelity.level, "reduced");
        assert_eq!(
            fidelity.context.as_deref(),
            Some("exact_tu_compile_database")
        );
        let named: Vec<(String, String, Option<String>)> = fidelity
            .fabricated
            .iter()
            .map(|input| (input.kind.clone(), input.name.clone(), input.value.clone()))
            .collect();
        assert_eq!(
            named,
            vec![
                ("macro".into(), "WIDGET_SLOTS".into(), Some("0".into())),
                (
                    "macro".into(),
                    "WIDGET_LOG".into(),
                    Some("(...) (0)".into())
                ),
                ("macro".into(), "WIDGET_API".into(), Some(String::new())),
                ("macro".into(), "WIDGET_DEPTH".into(), Some("8".into())),
                ("header".into(), "tables.h".into(), None),
                ("type".into(), "widget_ctx".into(), Some("void *".into())),
            ],
            "stubs are tracked separately and are not build-context inputs"
        );
        assert_eq!(incomplete_context_headers(&fidelity), vec!["tables.h"]);
        assert!(for_target(&[Repair::StubBlind { symbol: "x".into() }], temp.path()).is_none());
    }

    /// A type the repair resolved by including its real header (`cerr` from
    /// `<iostream>`) was not fabricated: it leaves the build at full fidelity
    /// and is listed as a real header, while a `void *` stand-in still
    /// reduces it.
    #[test]
    fn a_type_resolved_to_its_real_header_is_not_fabricated() {
        let temp = tempfile::tempdir().unwrap();
        let resolved = |name: &str, header: &str| Repair::TypePlaceholder {
            type_name: name.to_owned(),
            resolved_header: Some(header.to_owned()),
        };
        let only_real = [
            resolved("cerr", "<iostream>"),
            resolved("istream", "<istream>"),
        ];
        assert!(
            for_target(&only_real, temp.path()).is_none(),
            "real headers alone keep the build at full fidelity"
        );
        assert_eq!(
            real_headers_included(&only_real),
            vec![
                "type cerr: real header included (<iostream>)".to_owned(),
                "type istream: real header included (<istream>)".to_owned(),
            ]
        );
        let mixed = [
            resolved("cerr", "<iostream>"),
            Repair::TypePlaceholder {
                type_name: "widget_ctx".to_owned(),
                resolved_header: None,
            },
        ];
        let fidelity = for_target(&mixed, temp.path()).expect("one type was fabricated");
        assert_eq!(fidelity.level, "reduced");
        assert_eq!(fidelity.fabricated.len(), 1);
        assert_eq!(fidelity.fabricated[0].name, "widget_ctx");
        assert_eq!(fidelity.fabricated[0].value.as_deref(), Some("void *"));
    }
}
