// SPDX-License-Identifier: Apache-2.0

use crate::rewriter::{LineMap, SourceRewriter};
use crate::{breadcrumbs, context_clauses, handlers, raises, Breadcrumb, InstrumenterError};
use ada_parser::ast::{AdaStandard, StructuralAst};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub struct InstrumentArgs<'a> {
    pub source: &'a str,
    pub ast: &'a StructuralAst,
    pub source_path: &'a Path,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InstrumentedFile {
    pub rewritten_source: String,
    pub breadcrumbs: Vec<Breadcrumb>,
    /// Maps instrumented-output line numbers back to the original source lines,
    /// so the reporter can show developers the line they wrote rather than the
    /// post-instrumentation line GNAT embeds in runtime exception messages.
    #[serde(default)]
    pub line_map: LineMap,
}

/// Serializable sidecar pairing a unit's [`LineMap`] anchors with its original
/// source path, written next to the instrumented copy and consumed by the
/// reporter to rewrite `<file>:<line>` references back to the original source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LineMapSidecar {
    pub source_path: String,
    /// `(instrumented_line, original_line)` anchors, 1-based, sorted.
    pub anchors: Vec<(u32, u32)>,
}

pub fn line_map_sidecar_json(
    source_path: &str,
    line_map: &LineMap,
) -> Result<String, InstrumenterError> {
    Ok(serde_json::to_string(&LineMapSidecar {
        source_path: source_path.to_owned(),
        anchors: line_map.anchors().to_vec(),
    })?)
}

pub type BreadcrumbSidecar = BTreeMap<String, Breadcrumb>;

/// The probe package a unit of `dialect` names in its instrumented calls.
/// Ada 83 has no child units, so an Ada 83 unit cannot `with`
/// `AdaFuzz.Probe`; it names the runtime's library-level
/// `AdaFuzz_Probe83`, which renames the probe's subprograms (#284).
pub fn probe_package(dialect: AdaStandard) -> &'static str {
    if dialect == AdaStandard::Ada83 {
        "AdaFuzz_Probe83"
    } else {
        "AdaFuzz.Probe"
    }
}

pub fn instrument_unit(args: InstrumentArgs<'_>) -> Result<InstrumentedFile, InstrumenterError> {
    let mut rewriter = SourceRewriter::new(args.source);
    let dialect = args
        .ast
        .units
        .first()
        .map(|unit| unit.ada_standard)
        .unwrap_or(AdaStandard::Ada2022);
    let probe = probe_package(dialect);
    let breadcrumbs = breadcrumbs::collect_breadcrumb_insertions(
        args.ast,
        args.source,
        args.source_path,
        probe,
        &mut rewriter,
    )?;
    // A handler probe binds the exception occurrence (`when E : others`) and
    // reads it through Ada.Exceptions, neither of which Ada 83 has.
    let handler_insertions = if dialect == AdaStandard::Ada83 {
        0
    } else {
        handlers::collect_handler_rewrites(args.ast, args.source, args.source_path, &mut rewriter)?
    };
    let raise_insertions = raises::collect_raise_insertions(
        args.ast,
        args.source,
        args.source_path,
        probe,
        &mut rewriter,
    )?;
    let needs_probe = !breadcrumbs.is_empty() || handler_insertions > 0 || raise_insertions > 0;
    let needs_ada_exceptions = handler_insertions > 0;
    let tokens = ada_parser::lexer::lex(args.source, dialect);
    context_clauses::collect_context_clause_insertions(
        args.source,
        args.ast,
        &tokens,
        probe,
        needs_probe,
        needs_ada_exceptions,
        &mut rewriter,
    )?;
    let (rewritten_source, line_map) = rewriter.apply_with_line_map()?;

    Ok(InstrumentedFile {
        rewritten_source,
        breadcrumbs,
        line_map,
    })
}

pub fn breadcrumbs_sidecar_json(breadcrumbs: &[Breadcrumb]) -> Result<String, InstrumenterError> {
    Ok(serde_json::to_string_pretty(&breadcrumbs_sidecar(
        breadcrumbs,
    ))?)
}

pub fn parse_breadcrumbs_sidecar_json(json: &str) -> Result<BreadcrumbSidecar, InstrumenterError> {
    Ok(serde_json::from_str(json)?)
}

fn breadcrumbs_sidecar(breadcrumbs: &[Breadcrumb]) -> BreadcrumbSidecar {
    breadcrumbs
        .iter()
        .map(|breadcrumb| (breadcrumb.id.to_string(), breadcrumb.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        breadcrumbs_sidecar_json, instrument_unit, parse_breadcrumbs_sidecar_json, InstrumentArgs,
    };
    use crate::Breadcrumb;
    use std::path::Path;

    fn instrument(source: &str) -> super::InstrumentedFile {
        let path = Path::new("src.adb");
        let ast = ada_parser::reconcile::build_structural_ast(source, None, path).unwrap();

        instrument_unit(InstrumentArgs {
            source,
            ast: &ast,
            source_path: path,
        })
        .unwrap()
    }

    /// #284: an Ada 83 unit cannot `with` a child unit, so its calls name the
    /// library-level bridge, and its handlers are left as written: their
    /// probe binds the occurrence, which Ada 83 cannot.
    #[test]
    fn an_ada83_unit_names_the_library_level_probe_and_keeps_its_handlers() {
        let source = "pragma Ada_83;\n\
                      package body P is\n\
                      \x20  Bad : exception;\n\
                      \x20  procedure Q (N : Integer) is\n\
                      \x20  begin\n\
                      \x20     if N = 0 then\n\
                      \x20        raise Bad;\n\
                      \x20     end if;\n\
                      \x20  exception\n\
                      \x20     when Constraint_Error => null;\n\
                      \x20  end Q;\n\
                      end P;\n";
        let result = instrument(source);
        let out = &result.rewritten_source;
        assert!(
            out.contains("with AdaFuzz_Probe83;\npackage body P"),
            "{out}"
        );
        assert!(out.contains("AdaFuzz_Probe83.Breadcrumb (1);"), "{out}");
        assert!(out.contains("AdaFuzz_Probe83.On_Explicit_Raise"), "{out}");
        assert!(
            out.contains("Breadcrumb     => AdaFuzz_Probe83.Last_Breadcrumb"),
            "{out}"
        );
        assert!(!out.contains("AdaFuzz.Probe"), "{out}");
        assert!(!out.contains("Ada.Exceptions"), "{out}");
        assert!(out.contains("when Constraint_Error => null;"), "{out}");
    }

    #[test]
    fn instrument_empty_body_returns_source_unchanged() {
        let source = "package P is end P;";

        let result = instrument(source);

        assert_eq!(result.rewritten_source, source);
        assert!(result.breadcrumbs.is_empty());
    }

    #[test]
    fn instrument_simple_procedure_inserts_breadcrumbs_handlers_raises() {
        let source =
            "procedure P is begin raise Constraint_Error; exception when others => return; end P;";

        let result = instrument(source);

        assert!(result
            .rewritten_source
            .contains("AdaFuzz.Probe.Breadcrumb (1);"));
        assert!(result
            .rewritten_source
            .contains("AdaFuzz.Probe.On_Handler_Entry"));
        assert!(result
            .rewritten_source
            .contains("AdaFuzz.Probe.On_Explicit_Raise"));
    }

    #[test]
    fn instrument_preserves_byte_for_byte_outside_injection_points() {
        let source = "-- header\nprocedure P is\nbegin\n   A;\nend P;\n";

        let result = instrument(source);

        assert!(result
            .rewritten_source
            .starts_with("-- header\nwith AdaFuzz.Probe;\nprocedure P is\nbegin\n   "));
        assert!(result.rewritten_source.ends_with("A;\nend P;\n"));
    }

    #[test]
    fn instrument_returns_breadcrumbs_in_id_order() {
        let source = "procedure P is begin A; B; end P;";

        let result = instrument(source);

        assert_eq!(
            result
                .breadcrumbs
                .iter()
                .map(|breadcrumb| breadcrumb.id)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn sidecar_serializes_to_valid_json() {
        let breadcrumbs = vec![breadcrumb(1)];

        let json = breadcrumbs_sidecar_json(&breadcrumbs).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(value.is_object());
    }

    #[test]
    fn sidecar_keys_are_breadcrumb_ids_as_strings() {
        let breadcrumbs = vec![breadcrumb(7)];

        let json = breadcrumbs_sidecar_json(&breadcrumbs).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(value.get("7").is_some());
    }

    #[test]
    fn sidecar_round_trips_through_serde() {
        let breadcrumbs = vec![breadcrumb(1), breadcrumb(2)];

        let json = breadcrumbs_sidecar_json(&breadcrumbs).unwrap();
        let decoded = parse_breadcrumbs_sidecar_json(&json).unwrap();

        assert_eq!(decoded.get("1"), Some(&breadcrumb(1)));
        assert_eq!(decoded.get("2"), Some(&breadcrumb(2)));
    }

    fn breadcrumb(id: u32) -> Breadcrumb {
        Breadcrumb {
            id,
            file: Path::new("src.adb").to_path_buf(),
            line: id,
            col: 3,
            subprogram: "parse".to_owned(),
            depth: 0,
            idx: id - 1,
        }
    }
}
