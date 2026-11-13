// SPDX-License-Identifier: Apache-2.0
//! `results/findings.csv`: one row per finding, for spreadsheets.

use crate::model::FindingsDocument;

/// Columns after `evidence_dir` were added later; they stay at the end so a
/// reader that addresses columns by position keeps working.
pub const CSV_HEADER: &str = "id,kind,severity,confidence,confirmation,rule_id,cwe,title,file,line,function,group,occurrences,verdict,vuln_id,purl,first_seen,evidence_dir,access,access_size,region_size,region_offset,input_to_state,input_to_state_input,arguments,access_parameter,build_fidelity,input_to_state_status";

/// Longest `arguments` cell, in characters.
pub const ARGUMENTS_CELL_MAX: usize = 200;
/// Buffer bytes shown in an `arguments` cell's preview.
const ARGUMENT_PREVIEW_BYTES: usize = 8;

pub fn render_csv(doc: &FindingsDocument) -> String {
    let mut out = String::from(CSV_HEADER);
    out.push('\n');
    for f in &doc.findings {
        let loc = f.location.as_ref();
        let cwe = f
            .cwe
            .iter()
            .map(|c| format!("CWE-{c}"))
            .collect::<Vec<_>>()
            .join(";");
        let sca = f.sca.as_ref();
        let access = f.fuzz.as_ref().and_then(|fuzz| fuzz.access.as_ref());
        let region = access.and_then(|a| a.region.as_ref());
        let number = |n: Option<String>| n.unwrap_or_default();
        let row = [
            f.id.clone(),
            f.kind.as_str().to_owned(),
            f.severity.as_str().to_owned(),
            f.confidence.level.clone(),
            f.confirmation.level.as_str().to_owned(),
            f.rule.id.clone().unwrap_or_default(),
            cwe,
            f.title.clone(),
            loc.map(|l| l.file.clone()).unwrap_or_default(),
            loc.and_then(|l| l.line)
                .map(|n| n.to_string())
                .unwrap_or_default(),
            loc.and_then(|l| l.function.clone()).unwrap_or_default(),
            f.group.clone().unwrap_or_default(),
            f.occurrences.to_string(),
            f.verdict.clone().unwrap_or_default(),
            sca.map(|s| s.vuln_id.clone()).unwrap_or_default(),
            sca.and_then(|s| s.component.purl.clone())
                .unwrap_or_default(),
            f.first_seen.clone().unwrap_or_default(),
            f.evidence
                .as_ref()
                .map(|e| e.dir.clone())
                .unwrap_or_default(),
            access.map(|a| a.direction.clone()).unwrap_or_default(),
            number(access.and_then(|a| a.size).map(|n| n.to_string())),
            number(region.and_then(|r| r.size).map(|n| n.to_string())),
            number(region.and_then(|r| r.offset).map(|n| n.to_string())),
            input_to_state_cell(f),
            f.fuzz
                .as_ref()
                .and_then(|fuzz| fuzz.input_to_state_input.clone())
                .unwrap_or_default(),
            f.fuzz
                .as_ref()
                .and_then(|fuzz| fuzz.arguments.as_deref())
                .map(arguments_cell)
                .unwrap_or_default(),
            access
                .and_then(|a| a.parameter.as_ref())
                .map(|p| p.name.clone())
                .unwrap_or_default(),
            build_fidelity_cell(f),
            f.fuzz
                .as_ref()
                .and_then(|fuzz| fuzz.input_to_state_status.clone())
                .unwrap_or_default(),
        ];
        out.push_str(&row.iter().map(|v| cell(v)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

/// `reduced: macro NAME=VALUE, header NAME` for a finding whose harness was
/// built with inputs bhf fabricated; empty otherwise.
fn build_fidelity_cell(f: &crate::model::Finding) -> String {
    f.reproduce
        .as_ref()
        .and_then(|reproduce| reproduce.build.fidelity.as_ref())
        .map(|fidelity| format!("{}: {}", fidelity.level, fidelity.summary()))
        .unwrap_or_default()
}

/// `offset:len:cmp_kind:operand_hex` per comparison-evidence entry,
/// `;`-separated.
fn input_to_state_cell(f: &crate::model::Finding) -> String {
    f.fuzz
        .as_ref()
        .and_then(|fuzz| fuzz.input_to_state.as_ref())
        .map(|gates| {
            gates
                .iter()
                .map(|g| format!("{}:{}:{}:{}", g.offset, g.len, g.cmp_kind, g.operand_hex))
                .collect::<Vec<_>>()
                .join(";")
        })
        .unwrap_or_default()
}

/// The decoded arguments, compactly: `name=value` per argument, `;`-separated.
/// A buffer or string is `len N`, with `hex <first 8 bytes>` when it has a
/// preview; an output whose value changed shows `before->after`. A `;` in a
/// name or value reads as `,` so the separator stays unambiguous, and the
/// cell stops at [`ARGUMENTS_CELL_MAX`] characters with `...`.
pub(crate) fn arguments_cell(arguments: &[crate::model::Argument]) -> String {
    let clean = |text: &str| text.replace(';', ",");
    let mut cell = arguments
        .iter()
        .map(|arg| {
            let value = match (&arg.value, arg.len) {
                (Some(value), _) => clean(value),
                (None, Some(len)) => match arg.preview_hex.as_deref().filter(|h| !h.is_empty()) {
                    Some(hex) => {
                        let shown: String = hex.chars().take(ARGUMENT_PREVIEW_BYTES * 2).collect();
                        let more = if shown.len() < hex.len() { "..." } else { "" };
                        format!("len {len} hex {shown}{more}")
                    }
                    None => format!("len {len}"),
                },
                (None, None) => "?".to_owned(),
            };
            let after = arg
                .after_call_value
                .as_deref()
                .filter(|after| Some(*after) != arg.value.as_deref())
                .map(|after| format!("->{}", clean(after)))
                .unwrap_or_default();
            format!("{}={value}{after}", clean(&arg.name))
        })
        .collect::<Vec<_>>()
        .join(";");
    if cell.chars().count() > ARGUMENTS_CELL_MAX {
        cell = cell.chars().take(ARGUMENTS_CELL_MAX - 3).collect();
        cell.push_str("...");
    }
    cell
}

/// RFC 4180 escaping plus spreadsheet formula neutralization (OWASP CSV
/// injection): a leading `= + - @ \t \r` gets a `'` prefix. Comma-delimited
/// only: a spreadsheet opening this file with a `;` list-separator locale is
/// out of scope.
pub(crate) fn cell(value: &str) -> String {
    let guarded = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> crate::model::FindingsDocument {
        serde_json::from_str(include_str!(
            "../../../../schemas/examples/findings.v1.example.json"
        ))
        .unwrap()
    }

    #[test]
    fn header_and_rows() {
        let out = render_csv(&example());
        let mut lines = out.lines();
        assert_eq!(lines.next(), Some(CSV_HEADER));
        let fuzz = lines.next().unwrap();
        assert!(
            fuzz.starts_with("F-0000-1a2b3c4d,fuzz,high,high,sanitizer_crash,BHF-201,CWE-122,"),
            "{fuzz}"
        );
        assert!(fuzz.contains(",src/parse.c,42,parse_header,"));
        assert!(
            fuzz.ends_with(
                ",findings/F-0000-1a2b3c4d,read,4,12,12,0:4:memcmp:48445231,min_testcase.bin,\
                 data=len 12 hex 48445231;flags=7,data,,recorded"
            ),
            "{fuzz}"
        );
        assert!(CSV_HEADER.ends_with(",build_fidelity,input_to_state_status"));
        let sca = lines.next().unwrap();
        assert!(
            sca.contains(",CVE-2026-0001,pkg:npm/example@2.4.2,"),
            "{sca}"
        );
        assert!(
            sca.ends_with(",,,,,,,,,,"),
            "no fuzz columns for SCA: {sca}"
        );
        assert_eq!(lines.next(), None);
    }

    /// The arguments cell lists `name=value`, a buffer as its length and a
    /// short hex preview, an output's value after the call, and is bounded.
    #[test]
    fn arguments_cell_is_compact_and_bounded() {
        let arg = |name: &str, value: Option<&str>, len: Option<u64>, preview: Option<&str>| {
            crate::model::Argument {
                name: name.to_owned(),
                type_: "t".to_owned(),
                value: value.map(str::to_owned),
                len,
                span: None,
                preview_hex: preview.map(str::to_owned),
                role: "param".to_owned(),
                after_call_value: None,
            }
        };
        let mut out = arg("n", Some("3"), None, None);
        out.role = "out".to_owned();
        out.after_call_value = Some("9".to_owned());
        let args = vec![
            arg("bit_index", Some("2124921448"), None, None),
            arg("data", None, Some(50718), Some("68baa77e0f0102030405")),
            arg("empty", None, Some(0), None),
            out,
            arg("odd;name", Some("a=b;c"), None, None),
        ];
        assert_eq!(
            arguments_cell(&args),
            "bit_index=2124921448;data=len 50718 hex 68baa77e0f010203...;empty=len 0;n=3->9;\
             odd,name=a=b,c"
        );
        let many: Vec<_> = (0..100)
            .map(|i| arg(&format!("p{i}"), Some("123456789"), None, None))
            .collect();
        let cell = arguments_cell(&many);
        assert!(cell.chars().count() <= ARGUMENTS_CELL_MAX, "{cell}");
        assert!(cell.ends_with("..."), "{cell}");
    }

    /// The last column names what bhf fabricated for the harness build, so a
    /// spreadsheet sort by it separates findings from an exact build.
    #[test]
    fn a_fabricated_build_context_fills_the_build_fidelity_column() {
        let mut doc = example();
        doc.findings[0].reproduce.as_mut().unwrap().build.fidelity =
            Some(crate::model::BuildFidelity {
                level: "reduced".to_owned(),
                context: Some("none".to_owned()),
                fabricated: vec![
                    crate::model::FabricatedInput {
                        kind: "macro".to_owned(),
                        name: "WIDGET_SLOTS".to_owned(),
                        value: Some("0".to_owned()),
                    },
                    crate::model::FabricatedInput {
                        kind: "header".to_owned(),
                        name: "tables.h".to_owned(),
                        value: None,
                    },
                ],
            });
        let out = render_csv(&doc);
        let fuzz = out.lines().nth(1).unwrap();
        assert!(
            fuzz.ends_with(",\"reduced: macro WIDGET_SLOTS=0, header tables.h\",recorded"),
            "{fuzz}"
        );
        assert_eq!(
            CSV_HEADER.split(',').count(),
            fuzz.matches(',').count(),
            "one column per header field (the cell's own comma is quoted): {fuzz}"
        );
    }

    #[test]
    fn neutralizes_formula_injection_and_quotes() {
        assert_eq!(cell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(cell("-1"), "'-1");
        assert_eq!(cell("a,b"), "\"a,b\"");
        assert_eq!(cell("plain"), "plain");
    }

    #[test]
    fn neutralizes_additional_formula_prefixes_and_embedded_newline() {
        assert_eq!(cell("@SUM(A1)"), "'@SUM(A1)");
        assert_eq!(cell("+1"), "'+1");
        assert_eq!(cell("\t=x"), "'\t=x");
        assert_eq!(cell("a\nb"), "\"a\nb\"");
    }
}
