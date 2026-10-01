// SPDX-License-Identifier: Apache-2.0
//! `results/findings.csv`: one row per finding, for spreadsheets.

use crate::model::FindingsDocument;

pub const CSV_HEADER: &str = "id,kind,severity,confidence,confirmation,rule_id,cwe,title,file,line,function,group,occurrences,verdict,vuln_id,purl,first_seen,evidence_dir";

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
        ];
        out.push_str(&row.iter().map(|v| cell(v)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
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
        assert!(fuzz.ends_with(",findings/F-0000-1a2b3c4d"));
        let sca = lines.next().unwrap();
        assert!(
            sca.contains(",CVE-2026-0001,pkg:npm/example@2.4.2,"),
            "{sca}"
        );
        assert_eq!(lines.next(), None);
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
