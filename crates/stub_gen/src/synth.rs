// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use crate::{StubNeed, StubNeedKind, StubOp};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StubFile {
    pub path: PathBuf,
    pub content: String,
}

pub fn synth_stub(need: &StubNeed, output_root: &Path) -> StubFile {
    match &need.kind {
        StubNeedKind::PackageSpec { decls } => {
            synth_package_spec(&need.unit_name, decls, output_root)
        }
        StubNeedKind::PackageBody { ops } => synth_package_body(&need.unit_name, ops, output_root),
        StubNeedKind::Identifier { unit, symbol } => {
            synth_package_spec(unit, std::slice::from_ref(symbol), output_root)
        }
        StubNeedKind::Visibility { unit, symbol } => {
            synth_package_spec(unit, std::slice::from_ref(symbol), output_root)
        }
    }
}

pub fn synth_all(needs: &[StubNeed], output_root: &Path) -> Vec<StubFile> {
    let mut files = Vec::new();
    for need in needs {
        files.push(synth_stub(need, output_root));
        if let StubNeedKind::PackageSpec { decls } = &need.kind {
            if !decls.is_empty() {
                let body_need = package_body_need_from_spec(need, decls);
                files.push(synth_stub(&body_need, output_root));
            }
        }
    }
    files
}

fn synth_package_spec(unit_name: &str, decls: &[String], output_root: &Path) -> StubFile {
    let mut content = String::new();
    content.push_str("--  SPDX-License-Identifier: Apache-2.0\n");
    content.push_str("--  Auto-stubbed by bhf from compiler diagnostics.\n");
    content.push_str(&format!("package {unit_name} is\n"));
    content.push_str("   pragma Preelaborate;\n");
    content.push_str("   --  Auto-stubbed: declarations referenced from real code\n");
    for decl in unique_decl_names(decls) {
        content.push_str(&format!("   procedure {decl};\n"));
    }
    content.push_str(&format!("end {unit_name};\n"));

    StubFile {
        path: output_root.join(format!("{}.ads", unit_file_stem(unit_name))),
        content,
    }
}

fn synth_package_body(unit_name: &str, ops: &[StubOp], output_root: &Path) -> StubFile {
    synth_package_body_with_mode(unit_name, ops, output_root, false)
}

/// HDF-6 deliverable 1 (Ada): the fuzz-driven counterpart of [`synth_package_body`].
/// A stubbed `Integer`/`Natural`-returning function draws its result from the LIVE
/// FUZZ INPUT — keyed by its own symbol name — via the runtrace shim's C export
/// `bhf_shim_fuzz_stub_value`, instead of the constant `0`. Every other shape
/// (procedures, `Boolean`/`String`/record returns, `Positive` which cannot take a
/// masked-to-zero value) keeps its constant neutral body. Strictly opt-in:
/// [`synth_package_body`]/[`synth_all`] are byte-for-byte unchanged, mirroring how
/// the C fuzz-driven stub mode is a separate entry point.
pub fn synth_fuzz_driven_package_body(
    unit_name: &str,
    ops: &[StubOp],
    output_root: &Path,
) -> StubFile {
    synth_package_body_with_mode(unit_name, ops, output_root, true)
}

fn synth_package_body_with_mode(
    unit_name: &str,
    ops: &[StubOp],
    output_root: &Path,
    fuzz_driven: bool,
) -> StubFile {
    let mut content = String::new();
    content.push_str("--  SPDX-License-Identifier: Apache-2.0\n");
    content.push_str("--  Auto-stubbed by bhf from compiler diagnostics.\n");
    let mut context_units = ada_context_units_for_ops(unit_name, ops);
    // A fuzz-driven body imports the shim reader and builds its per-symbol key, so
    // it always needs Interfaces / Interfaces.C / System regardless of the profile.
    if fuzz_driven && ops.iter().any(op_is_fuzz_drivable) {
        context_units.insert("Interfaces".to_owned());
        context_units.insert("Interfaces.C".to_owned());
        context_units.insert("System".to_owned());
    }
    for context_unit in &context_units {
        content.push_str(&format!("with {context_unit};\n"));
    }
    if !context_units.is_empty() {
        content.push('\n');
    }
    content.push_str(&format!("package body {unit_name} is\n\n"));
    for op in ops {
        match op.kind {
            crate::StubOpKind::Procedure => push_procedure_body(&mut content, op),
            crate::StubOpKind::Function if fuzz_driven && op_is_fuzz_drivable(op) => {
                push_fuzz_driven_function_body(&mut content, op)
            }
            crate::StubOpKind::Function => push_function_body(&mut content, op),
        }
    }
    content.push_str(&format!("end {unit_name};\n"));

    StubFile {
        path: output_root.join(format!("{}.adb", unit_file_stem(unit_name))),
        content,
    }
}

/// Whether an op is a function whose return type can safely take a fuzz-driven,
/// masked-nonnegative value: `Integer` or `Natural` (both admit 0). `Positive`
/// (min 1), `Boolean`, `String`, and record/access returns are excluded.
fn op_is_fuzz_drivable(op: &StubOp) -> bool {
    matches!(op.kind, crate::StubOpKind::Function)
        && op
            .return_type
            .as_deref()
            .is_some_and(|rt| matches_ada_name(rt, &["Integer", "Natural"]))
}

fn push_fuzz_driven_function_body(content: &mut String, op: &StubOp) {
    let return_type = op.return_type.as_deref().unwrap_or("Integer");
    let profile = render_profile(&op.params);
    // Ada symbol names are case-insensitive; the shim keys on the exact bytes it is
    // handed, so pass the operation's own name as the channel key.
    content.push_str(&format!(
        "   function {name}{profile} return {return_type} is\n\
         \x20     function Bhf_Fuzz_Stub_Value (Sym : System.Address) \
         return Interfaces.Unsigned_64;\n\
         \x20     pragma Import (C, Bhf_Fuzz_Stub_Value, \"bhf_shim_fuzz_stub_value\");\n\
         \x20     Bhf_Sym : constant Interfaces.C.char_array := \
         Interfaces.C.To_C (\"{name}\");\n\
         \x20  begin\n\
         \x20     return {return_type}\n\
         \x20       (Bhf_Fuzz_Stub_Value (Bhf_Sym'Address)\n\
         \x20        and Interfaces.Unsigned_64 (Integer'Last));  -- fuzz-driven return\n\
         \x20  end {name};\n\n",
        name = op.name,
        profile = profile,
        return_type = return_type,
    ));
}

pub fn ada_context_units_for_ops(unit_name: &str, ops: &[StubOp]) -> BTreeSet<String> {
    let mut units = BTreeSet::new();
    for type_name in ops.iter().flat_map(|op| {
        op.params
            .iter()
            .map(|param| param.type_name.as_str())
            .chain(op.return_type.iter().map(String::as_str))
    }) {
        for token in type_name.split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '_' | '.'))
        }) {
            let Some((context_unit, _)) = token.rsplit_once('.') else {
                continue;
            };
            if !context_unit.is_empty()
                && !context_unit.eq_ignore_ascii_case(unit_name)
                && !unit_name
                    .strip_prefix(context_unit)
                    .is_some_and(|suffix| suffix.starts_with('.'))
            {
                units.insert(context_unit.to_owned());
            }
        }
    }
    units
}

/// GNAT's crunched file stem for an Ada unit: lowercased with `.` → `-`.
///
/// The unit name is captured verbatim from compiler diagnostics, i.e. untrusted
/// child-process output. A legitimate Ada unit name contains only letters,
/// digits, `_`, and `.`, so any other character — in particular `/` or a leading
/// `/` from a crafted `unit "/tmp/evil" needed…` diagnostic — is replaced with
/// `_`. That keeps every real unit name byte-identical while ensuring the stem
/// can never contain a path separator or `..`, so `output_root.join(stem)` can
/// never escape the work dir (path-traversal defense; security review).
fn unit_file_stem(unit_name: &str) -> String {
    let stem: String = unit_name
        .to_ascii_lowercase()
        .chars()
        .map(|c| match c {
            '.' => '-',
            'a'..='z' | '0'..='9' | '_' | '-' => c,
            _ => '_',
        })
        .collect();
    if stem.is_empty() {
        "stub".to_owned()
    } else {
        stem
    }
}

fn package_body_need_from_spec(need: &StubNeed, decls: &[String]) -> StubNeed {
    StubNeed {
        unit_name: need.unit_name.clone(),
        kind: StubNeedKind::PackageBody {
            ops: unique_decl_names(decls)
                .into_iter()
                .map(|decl| StubOp {
                    name: decl.to_owned(),
                    kind: crate::StubOpKind::Procedure,
                    return_type: None,
                    params: Vec::new(),
                })
                .collect(),
        },
    }
}

fn push_procedure_body(content: &mut String, op: &StubOp) {
    let profile = render_profile(&op.params);
    content.push_str(&format!(
        "   procedure {}{profile} is\n   begin\n      null;  -- auto-stubbed\n   end {};\n\n",
        op.name, op.name
    ));
}

fn push_function_body(content: &mut String, op: &StubOp) {
    let return_type = op.return_type.as_deref().unwrap_or("Integer");
    let profile = render_profile(&op.params);
    content.push_str(&format!(
        "   function {}{profile} return {return_type} is\n",
        op.name
    ));
    match neutral_default(return_type) {
        Some(value) => {
            content.push_str("   begin\n");
            content.push_str(&format!(
                "      return {value};  -- auto-stubbed neutral default\n"
            ));
        }
        None => {
            // A bare `raise Program_Error` is not a return statement, so GNAT
            // rejects the function body before it can serve as a dependency
            // stub. A null access-to-result dereference is type-correct for a
            // named scalar, record, private, class-wide, or unconstrained result
            // type and raises Constraint_Error immediately if this fallback is
            // actually executed.
            content.push_str(&format!(
                "      type Bhf_Result_Access is access {return_type};\n\
                 \x20     Bhf_Result : constant Bhf_Result_Access := null;\n\
                 \x20  begin\n\
                 \x20     return Bhf_Result.all;  -- auto-stubbed exceptional default\n"
            ));
        }
    }
    content.push_str(&format!("   end {};\n\n", op.name));
}

fn render_profile(params: &[crate::StubParam]) -> String {
    if params.is_empty() {
        return String::new();
    }
    let rendered = params
        .iter()
        .map(|param| {
            let mut rendered = match param.mode.as_deref().filter(|mode| !mode.is_empty()) {
                Some(mode) => format!("{} : {mode} {}", param.name, param.type_name),
                None => format!("{} : {}", param.name, param.type_name),
            };
            if let Some(default) = param.default.as_deref() {
                rendered.push_str(" := ");
                rendered.push_str(default);
            }
            rendered
        })
        .collect::<Vec<_>>()
        .join("; ");
    format!(" ({rendered})")
}

fn neutral_default(return_type: &str) -> Option<&'static str> {
    if matches_ada_name(return_type, &["Integer", "Natural", "Positive"]) {
        Some("0")
    } else if return_type.eq_ignore_ascii_case("Boolean") {
        Some("False")
    } else if return_type.eq_ignore_ascii_case("String") {
        Some(r#""""#)
    } else {
        None
    }
}

fn matches_ada_name(value: &str, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

fn unique_decl_names(decls: &[String]) -> Vec<&str> {
    let mut names = Vec::new();
    for decl in decls {
        if !names.iter().any(|name| *name == decl) {
            names.push(decl.as_str());
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::{synth_all, synth_stub, StubNeed, StubNeedKind, StubOp, StubOpKind};

    #[test]
    fn synth_package_spec_matches_expected_snapshot() {
        let stub = synth_stub(
            &package_spec_need(vec!["Process", "Reset"]),
            Path::new("/tmp/stubs"),
        );

        assert_eq!(
            stub.content,
            "--  SPDX-License-Identifier: Apache-2.0\n--  Auto-stubbed by bhf from compiler diagnostics.\npackage External_Lib is\n   pragma Preelaborate;\n   --  Auto-stubbed: declarations referenced from real code\n   procedure Process;\n   procedure Reset;\nend External_Lib;\n"
        );
    }

    // Regression (security review, MEDIUM): the Ada unit name comes from untrusted
    // compiler diagnostics, so the derived file stem must never carry a path
    // separator or `..` that would let `output_root.join(..)` escape the work dir.
    #[test]
    fn unit_file_stem_neutralizes_path_traversal_from_untrusted_diagnostics() {
        use super::unit_file_stem;
        // Legitimate unit names are unchanged (lowercased, '.' -> '-').
        assert_eq!(unit_file_stem("Foo.Bar_Baz"), "foo-bar_baz");
        // Crafted names from compiler stderr must stay inside the work dir.
        let root = Path::new("/work/dir");
        for evil in ["/tmp/evil", "../../etc/passwd", "a/b/c", "..", "/abs"] {
            let stem = unit_file_stem(evil);
            assert!(!stem.contains('/'), "stem kept a '/': {stem:?}");
            assert!(!stem.contains(".."), "stem kept a '..': {stem:?}");
            let joined = root.join(format!("{stem}.ads"));
            assert!(
                joined.starts_with(root),
                "path escaped output_root: {joined:?}"
            );
        }
        assert_eq!(unit_file_stem(""), "stub");
    }

    #[test]
    fn synth_package_spec_emits_pragma_preelaborate() {
        let stub = synth_stub(&package_spec_need(Vec::new()), Path::new("/tmp/stubs"));

        assert!(stub.content.contains("   pragma Preelaborate;"));
    }

    #[test]
    fn synth_package_spec_includes_unit_name_in_declaration() {
        let stub = synth_stub(&package_spec_need(Vec::new()), Path::new("/tmp/stubs"));

        assert!(stub.content.contains("package External_Lib is"));
        assert!(stub.content.contains("end External_Lib;"));
    }

    #[test]
    fn synth_package_spec_emits_decl_for_each_referenced_symbol() {
        let stub = synth_stub(
            &package_spec_need(vec!["Process", "Reset"]),
            Path::new("/tmp/stubs"),
        );

        assert!(stub.content.contains("   procedure Process;"));
        assert!(stub.content.contains("   procedure Reset;"));
    }

    #[test]
    fn synth_package_spec_dedupes_repeated_referenced_symbols() {
        let stub = synth_stub(
            &package_spec_need(vec!["Process", "Process"]),
            Path::new("/tmp/stubs"),
        );

        assert_eq!(stub.content.matches("procedure Process;").count(), 1);
    }

    #[test]
    fn synth_package_spec_output_path_uses_lowercase_filename() {
        let stub = synth_stub(&package_spec_need(Vec::new()), Path::new("/tmp/stubs"));

        assert_eq!(stub.path, PathBuf::from("/tmp/stubs/external_lib.ads"));
    }

    #[test]
    fn synth_package_spec_includes_spdx_header() {
        let stub = synth_stub(&package_spec_need(Vec::new()), Path::new("/tmp/stubs"));

        assert!(stub
            .content
            .starts_with("--  SPDX-License-Identifier: Apache-2.0\n"));
    }

    #[test]
    fn synth_package_spec_output_parses_via_ada_parser() {
        let stub = synth_stub(&package_spec_need(vec!["Process"]), Path::new("/tmp/stubs"));

        ada_parser::reconcile::build_structural_ast(&stub.content, None, &stub.path)
            .expect("generated package spec parses");
    }

    #[test]
    fn synth_all_generates_package_body_for_package_spec_decls() {
        let files = synth_all(
            &[package_spec_need(vec!["Process"])],
            Path::new("/tmp/stubs"),
        );

        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path, PathBuf::from("/tmp/stubs/external_lib.ads"));
        assert_eq!(files[1].path, PathBuf::from("/tmp/stubs/external_lib.adb"));
        assert!(files[1].content.contains("   procedure Process is"));
    }

    #[test]
    fn synth_package_body_emits_one_subprogram_per_op() {
        let stub = synth_stub(&package_body_need(), Path::new("/tmp/stubs"));

        assert!(stub.content.contains("   procedure Process is"));
        assert!(stub
            .content
            .contains("   function Get_Count return Integer is"));
    }

    #[test]
    fn synth_package_body_procedure_returns_null() {
        let stub = synth_stub(&package_body_need(), Path::new("/tmp/stubs"));

        assert!(stub.content.contains("      null;  -- auto-stubbed"));
    }

    #[test]
    fn synth_package_body_function_returns_neutral_for_integer() {
        let stub = synth_stub(&package_body_need(), Path::new("/tmp/stubs"));

        assert!(stub
            .content
            .contains("      return 0;  -- auto-stubbed neutral default"));
    }

    #[test]
    fn synth_package_body_preserves_operation_parameter_profiles() {
        let stub = synth_stub(
            &StubNeed {
                unit_name: "External_Lib".to_owned(),
                kind: StubNeedKind::PackageBody {
                    ops: vec![StubOp {
                        name: "Score".to_owned(),
                        kind: StubOpKind::Function,
                        return_type: Some("Integer".to_owned()),
                        params: vec![crate::StubParam {
                            name: "N".to_owned(),
                            mode: None,
                            type_name: "Natural".to_owned(),
                            default: Some("10".to_owned()),
                        }],
                    }],
                },
            },
            Path::new("/tmp/stubs"),
        );

        assert!(stub
            .content
            .contains("function Score (N : Natural := 10) return Integer is"));
    }

    #[test]
    fn synthesized_stubs_inherit_project_dialect_for_in_out_functions() {
        let stub = synth_stub(
            &StubNeed {
                unit_name: "External_Lib".to_owned(),
                kind: StubNeedKind::PackageBody {
                    ops: vec![StubOp {
                        name: "Final_Round".to_owned(),
                        kind: StubOpKind::Function,
                        return_type: Some("Integer".to_owned()),
                        params: vec![crate::StubParam {
                            name: "This".to_owned(),
                            mode: Some("in out".to_owned()),
                            type_name: "State".to_owned(),
                            default: None,
                        }],
                    }],
                },
            },
            Path::new("/tmp/stubs"),
        );

        assert!(!stub.content.contains("pragma Ada_"));
        assert!(stub
            .content
            .contains("function Final_Round (This : in out State) return Integer is"));
    }

    #[test]
    fn package_body_adds_context_for_qualified_profile_types() {
        let stub = synth_stub(
            &StubNeed {
                unit_name: "PolyORB_HI.Output_Low_Level".to_owned(),
                kind: StubNeedKind::PackageBody {
                    ops: vec![StubOp {
                        name: "C_Write".to_owned(),
                        kind: StubOpKind::Procedure,
                        return_type: None,
                        params: vec![
                            crate::StubParam {
                                name: "Fd".to_owned(),
                                mode: None,
                                type_name: "Interfaces.C.Int".to_owned(),
                                default: None,
                            },
                            crate::StubParam {
                                name: "P".to_owned(),
                                mode: None,
                                type_name: "System.Address".to_owned(),
                                default: None,
                            },
                        ],
                    }],
                },
            },
            Path::new("/tmp/stubs"),
        );

        assert!(stub.content.starts_with(
            "--  SPDX-License-Identifier: Apache-2.0\n\
             --  Auto-stubbed by bhf from compiler diagnostics.\n\
             with Interfaces.C;\n\
             with System;\n\n\
             package body PolyORB_HI.Output_Low_Level is\n"
        ));
    }

    #[test]
    fn synth_package_body_function_defaults_are_case_insensitive() {
        let stub = synth_stub(
            &StubNeed {
                unit_name: "External_Lib".to_owned(),
                kind: StubNeedKind::PackageBody {
                    ops: vec![StubOp {
                        name: "Get_Count".to_owned(),
                        kind: StubOpKind::Function,
                        return_type: Some("integer".to_owned()),
                        params: Vec::new(),
                    }],
                },
            },
            Path::new("/tmp/stubs"),
        );

        assert!(stub
            .content
            .contains("      return 0;  -- auto-stubbed neutral default"));
    }

    #[test]
    fn synth_package_body_function_uses_typed_exceptional_default_for_unknown_type() {
        let stub = synth_stub(&package_body_need(), Path::new("/tmp/stubs"));

        assert!(stub
            .content
            .contains("type Bhf_Result_Access is access Widget;"));
        assert!(stub.content.contains("return Bhf_Result.all;"));
    }

    #[test]
    fn synth_package_body_matches_expected_snapshot() {
        let stub = synth_stub(&package_body_need(), Path::new("/tmp/stubs"));

        assert_eq!(
            stub.content,
            "--  SPDX-License-Identifier: Apache-2.0\n--  Auto-stubbed by bhf from compiler diagnostics.\npackage body External_Lib is\n\n   procedure Process is\n   begin\n      null;  -- auto-stubbed\n   end Process;\n\n   function Get_Count return Integer is\n   begin\n      return 0;  -- auto-stubbed neutral default\n   end Get_Count;\n\n   function Find return Widget is\n      type Bhf_Result_Access is access Widget;\n      Bhf_Result : constant Bhf_Result_Access := null;\n   begin\n      return Bhf_Result.all;  -- auto-stubbed exceptional default\n   end Find;\n\nend External_Lib;\n"
        );
    }

    #[test]
    fn synth_package_body_output_parses_via_ada_parser() {
        let stub = synth_stub(&package_body_need(), Path::new("/tmp/stubs"));

        ada_parser::reconcile::build_structural_ast(&stub.content, None, &stub.path)
            .expect("generated package body parses");
    }

    // ---- HDF-6 D1 (Ada): fuzz-driven function bodies -------------------------

    #[test]
    fn fuzz_driven_integer_function_draws_return_from_shim() {
        let stub = super::synth_fuzz_driven_package_body(
            "External_Lib",
            &[StubOp {
                name: "Read_Sensor".to_owned(),
                kind: StubOpKind::Function,
                return_type: Some("Integer".to_owned()),
                params: Vec::new(),
            }],
            Path::new("/tmp/stubs"),
        );
        // Imports the shim reader, keys it by the op name, and masks to a
        // nonnegative Integer.
        assert!(
            stub.content
                .contains("pragma Import (C, Bhf_Fuzz_Stub_Value, \"bhf_shim_fuzz_stub_value\");"),
            "{}",
            stub.content
        );
        assert!(
            stub.content.contains("Interfaces.C.To_C (\"Read_Sensor\")"),
            "{}",
            stub.content
        );
        assert!(
            stub.content
                .contains("and Interfaces.Unsigned_64 (Integer'Last)"),
            "{}",
            stub.content
        );
        // Needs the C-interfacing context units.
        assert!(
            stub.content.contains("with Interfaces.C;"),
            "{}",
            stub.content
        );
        assert!(stub.content.contains("with System;"), "{}", stub.content);
        // And the whole unit is valid Ada.
        ada_parser::reconcile::build_structural_ast(&stub.content, None, &stub.path)
            .expect("generated fuzz-driven package body parses");
    }

    #[test]
    fn fuzz_driven_mode_keeps_constant_body_for_non_integer_returns() {
        // Boolean/Positive/record returns cannot safely take a masked-to-zero value,
        // so fuzz-driven mode leaves their constant neutral body untouched and does
        // not import the shim reader.
        let stub = super::synth_fuzz_driven_package_body(
            "External_Lib",
            &[
                StubOp {
                    name: "Is_Ready".to_owned(),
                    kind: StubOpKind::Function,
                    return_type: Some("Boolean".to_owned()),
                    params: Vec::new(),
                },
                StubOp {
                    name: "Reset".to_owned(),
                    kind: StubOpKind::Procedure,
                    return_type: None,
                    params: Vec::new(),
                },
            ],
            Path::new("/tmp/stubs"),
        );
        assert!(stub.content.contains("return False;"), "{}", stub.content);
        assert!(
            stub.content.contains("null;  -- auto-stubbed"),
            "{}",
            stub.content
        );
        assert!(
            !stub.content.contains("bhf_shim_fuzz_stub_value"),
            "no fuzz-driven body for these shapes: {}",
            stub.content
        );
        ada_parser::reconcile::build_structural_ast(&stub.content, None, &stub.path)
            .expect("generated package body parses");
    }

    fn package_spec_need(decls: Vec<&str>) -> StubNeed {
        StubNeed {
            unit_name: "External_Lib".to_owned(),
            kind: StubNeedKind::PackageSpec {
                decls: decls.into_iter().map(str::to_owned).collect(),
            },
        }
    }

    fn package_body_need() -> StubNeed {
        StubNeed {
            unit_name: "External_Lib".to_owned(),
            kind: StubNeedKind::PackageBody {
                ops: vec![
                    StubOp {
                        name: "Process".to_owned(),
                        kind: StubOpKind::Procedure,
                        return_type: None,
                        params: Vec::new(),
                    },
                    StubOp {
                        name: "Get_Count".to_owned(),
                        kind: StubOpKind::Function,
                        return_type: Some("Integer".to_owned()),
                        params: Vec::new(),
                    },
                    StubOp {
                        name: "Find".to_owned(),
                        kind: StubOpKind::Function,
                        return_type: Some("Widget".to_owned()),
                        params: Vec::new(),
                    },
                ],
            },
        }
    }
}
