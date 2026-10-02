// SPDX-License-Identifier: Apache-2.0
//! `results/INDEX.md`: the human entry point. A summary, then one section per
//! root-cause group, most severe first.
//!
//! Finding content (titles, messages, component names, ...) comes from
//! producers reading untrusted source trees, so every value interpolated
//! into the Markdown is escaped: [`md_text`] for free inline prose,
//! [`md_code`] for values placed inside a backtick span.

use crate::model::{Finding, FindingsDocument, Kind, Severity};
use std::collections::HashMap;
use std::fmt::Write;

const MAX_PRODUCERS_SHOWN: usize = 10;

/// Extra context the document itself does not carry.
#[derive(Debug, Default, Clone)]
pub struct IndexContext {
    /// One line summarizing `auto/run.json`, when a campaign ran.
    pub campaign: Option<String>,
    pub has_static_dir: bool,
    pub has_sbom_dir: bool,
    /// Root-cause groups whose representative was not minimized in budget.
    pub unminimized_groups: usize,
}

pub fn render_index(doc: &FindingsDocument, ctx: &IndexContext) -> String {
    let mut out = String::from("# BHF results\n\n");
    let source = match (&doc.source.root, &doc.source.vcs) {
        (Some(root), Some(vcs)) => {
            let commit = vcs.commit.get(..7).unwrap_or(&vcs.commit);
            let branch = vcs
                .branch
                .as_deref()
                .map(|b| format!(" (`{}`)", md_code(b)))
                .unwrap_or_default();
            format!(
                " · source `{}` @ `{}`{branch}",
                md_code(root),
                md_code(commit)
            )
        }
        (Some(root), None) => format!(" · source `{}`", md_code(root)),
        _ => String::new(),
    };
    let _ = writeln!(out, "- bhf {}{source}", doc.tool.version);
    let severities = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ]
    .iter()
    .map(|s| {
        format!(
            "{} {}",
            s.as_str(),
            doc.counts.by_severity.get(s.as_str()).copied().unwrap_or(0)
        )
    })
    .collect::<Vec<_>>()
    .join(" · ");
    let _ = writeln!(
        out,
        "- **{} findings** in {} root-cause groups — {severities}",
        doc.counts.total,
        doc.groups.len()
    );
    let kinds = Kind::ALL
        .iter()
        .filter_map(|k| {
            doc.counts
                .by_kind
                .get(k.as_str())
                .map(|n| format!("{} {n}", k.as_str()))
        })
        .collect::<Vec<_>>();
    if !kinds.is_empty() {
        let _ = writeln!(out, "- By kind: {}", kinds.join(" · "));
    }
    if !doc.producers.is_empty() {
        let total = doc.producers.len();
        let visible = &doc.producers[total.saturating_sub(MAX_PRODUCERS_SHOWN)..];
        let mut producers = visible
            .iter()
            .map(|p| {
                let exit = if p.exit_code == 0 {
                    String::new()
                } else {
                    format!(", exit {}", p.exit_code)
                };
                format!(
                    "{} ({}{exit}, {})",
                    md_text(&p.command),
                    status_word(p.status),
                    p.finished_at
                )
            })
            .collect::<Vec<_>>()
            .join(" · ");
        if total > visible.len() {
            let _ = write!(
                producers,
                " · … {} more in manifest.json",
                total - visible.len()
            );
        }
        let _ = writeln!(out, "- Producers: {producers}");
    }
    if let Some(campaign) = &ctx.campaign {
        let _ = writeln!(
            out,
            "- Campaign: {campaign} — details in [`../auto/run.md`](../auto/run.md)"
        );
    }
    let _ = writeln!(
        out,
        "- Machine-readable: [`findings.json`](findings.json) · [`findings.csv`](findings.csv) · [`findings.sarif`](findings.sarif)"
    );
    let mut native = Vec::new();
    if ctx.has_static_dir {
        native.push("[`static/`](static/)");
    }
    if ctx.has_sbom_dir {
        native.push("[`sbom/`](sbom/)");
    }
    if !native.is_empty() {
        let _ = writeln!(out, "- Native reports: {}", native.join(" · "));
    }
    if !doc.errors.is_empty() {
        let _ = writeln!(
            out,
            "- ⚠ {} problem(s) while building results — see `errors` in findings.json.",
            doc.errors.len()
        );
    }
    if ctx.unminimized_groups > 0 {
        let _ = writeln!(
            out,
            "- ⚠ {} root-cause group(s) were not minimized within the time budget; run `bhf minimize` on them.",
            ctx.unminimized_groups
        );
    }
    out.push('\n');

    if doc.findings.is_empty() {
        out.push_str(
            "No findings. This is not a coverage guarantee; review `../auto/run.md` for targets that \
             were skipped, failed to build, or were not entered.\n",
        );
        return out;
    }

    let by_id: HashMap<&str, &Finding> = doc.findings.iter().map(|f| (f.id.as_str(), f)).collect();
    for (index, group) in doc.groups.iter().enumerate() {
        let Some(rep) = by_id.get(group.representative.as_str()) else {
            continue;
        };
        let _ = writeln!(
            out,
            "## {}. [{}] {}\n",
            index + 1,
            rep.severity.as_str().to_ascii_uppercase(),
            md_text(&rep.title)
        );
        debug_assert!(
            is_safe_relative_path(&rep.id),
            "finding id must be a safe path component: {}",
            rep.id
        );
        let _ = writeln!(
            out,
            "- Finding: `{}` ({})",
            md_code(&rep.id),
            rep.kind.as_str()
        );
        if let Some(rule) = &rep.rule.id {
            let _ = writeln!(out, "- Rule: `{}`", md_code(rule));
        }
        let _ = writeln!(
            out,
            "- Evidence: {} · confidence {}{}",
            rep.confirmation.level.as_str(),
            md_text(&rep.confidence.level),
            rep.verdict
                .as_deref()
                .map(|v| format!(" · verdict {}", md_text(v)))
                .unwrap_or_default()
        );
        let _ = writeln!(
            out,
            "- CWE: {}",
            rep.cwe
                .iter()
                .map(|c| format!("CWE-{c}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        if let Some(loc) = &rep.location {
            let _ = writeln!(
                out,
                "- Location: `{}`{}{}",
                md_code(&loc.file),
                loc.line.map(|l| format!(":{l}")).unwrap_or_default(),
                loc.function
                    .as_deref()
                    .map(|f| format!(" in `{}`", md_code(f)))
                    .unwrap_or_default()
            );
        }
        if let Some(sca) = &rep.sca {
            let package = sca
                .component
                .purl
                .clone()
                .unwrap_or_else(|| sca.component.name.clone());
            let fixed = if sca.fixed_versions.is_empty() {
                String::new()
            } else {
                let versions = sca
                    .fixed_versions
                    .iter()
                    .map(|v| md_text(v))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(" · fixed in {versions}")
            };
            let _ = writeln!(out, "- Component: `{}`{fixed}", md_code(&package));
        }
        if group.members.len() > 1 {
            let _ = writeln!(out, "- Collapsed observations: {}", group.members.len());
        }
        if rep.fidelity.forced || !rep.fidelity.caveats.is_empty() {
            let _ = writeln!(
                out,
                "- Caveat: {}",
                md_text(&rep.fidelity.caveats.join("; "))
            );
        }
        if let Some(fix) = &rep.remediation {
            let _ = writeln!(out, "- Suggested fix: {}", md_text(fix));
        }
        if let Some(evidence) = &rep.evidence {
            if is_safe_relative_path(&evidence.dir) {
                let _ = writeln!(
                    out,
                    "- Evidence bundle: [`{}/`]({}/)",
                    md_code(&evidence.dir),
                    evidence.dir
                );
            } else {
                let _ = writeln!(out, "- Evidence bundle: `{}/`", md_code(&evidence.dir));
            }
        } else if let Some(raw) = &rep.raw_ref {
            if is_safe_relative_path(raw) {
                let _ = writeln!(out, "- Source: [`{}`]({})", md_code(raw), raw);
            } else {
                let _ = writeln!(out, "- Source: `{}`", md_code(raw));
            }
        }
        if let Some(command) = rep.reproduce.as_ref().and_then(|r| r.command.as_deref()) {
            let _ = writeln!(out, "- Reproduce: `{}`", md_code(command));
        }
        out.push('\n');
    }
    out
}

fn status_word(status: crate::model::ProducerStatus) -> &'static str {
    match status {
        crate::model::ProducerStatus::Complete => "complete",
        crate::model::ProducerStatus::Partial => "partial",
    }
}

/// bhf builds `evidence.dir`/`raw_ref` itself from a finding id and a fixed
/// set of filenames, so this is a defense-in-depth assertion, not sanitization.
fn is_safe_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains("..")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'/' | b'.'))
}

/// For a value placed inside a backtick code span: collapses newlines to a
/// space, replaces an embedded backtick (which would otherwise close the
/// span early) with a plain quote, and drops control characters and bidi
/// override characters that could visually reorder the rendered line.
fn md_code(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\r' | '\n' => out.push(' '),
            '`' => out.push('\''),
            '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => {}
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out.trim().to_owned()
}

/// For free inline text: backslash-escapes Markdown/HTML metacharacters so a
/// producer-controlled string (a finding title, a remediation hint, ...)
/// cannot inject raw HTML, close out of the current line, or start a new
/// Markdown block; also collapses newlines and drops control/bidi characters.
fn md_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\r' | '\n' => out.push(' '),
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '|' | '~' | '&' => {
                out.push('\\');
                out.push(c)
            }
            '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => {}
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out.trim().to_owned()
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
    fn summary_then_groups_by_severity() {
        let md = render_index(&example(), &IndexContext::default());
        assert!(md.starts_with("# BHF results\n"));
        assert!(md.contains("bhf 0.3.0"));
        assert!(md.contains("`0123456` (`main`)"));
        assert!(md.contains("**2 findings** in 2 root-cause groups"));
        assert!(md.contains("By kind: fuzz 1 · sca 1"));
        assert!(md.contains("## 1. [HIGH]"));
        assert!(md.contains(
            "- Evidence bundle: [`findings/F-0000-1a2b3c4d/`](findings/F-0000-1a2b3c4d/)"
        ));
        assert!(md.contains("- Reproduce: `python3 findings/F-0000-1a2b3c4d/replay.py`"));
        assert!(md.contains("- Component: `pkg:npm/example@2.4.2` · fixed in 2.4.3"));
    }

    #[test]
    fn empty_and_error_banners() {
        let mut doc = example();
        doc.findings.clear();
        doc.groups.clear();
        doc.errors.push(crate::model::LoadError {
            path: "findings/F-9/finding.json".into(),
            reason: "bad".into(),
        });
        let md = render_index(&doc, &IndexContext::default());
        assert!(md.contains("No findings."));
        assert!(
            md.contains("- ⚠ 1 problem(s) while building results — see `errors` in findings.json."),
            "{md}"
        );
    }

    #[test]
    fn hostile_title_is_escaped_not_raw() {
        let mut doc = example();
        doc.findings[0].title = "x`<img src=x>[a](javascript:1)\n## y".to_owned();
        let md = render_index(&doc, &IndexContext::default());
        // Escaped, so it cannot render as a live tag or link: the raw,
        // unescaped tag text is absent, and the escaped form (backslash
        // kept) is what shows up instead.
        assert!(!md.contains("<img src=x>"), "{md}");
        assert!(md.contains(r"\<img"), "{md}");
        assert!(md.contains(r"\[a\]"), "{md}");
        // The embedded newline became a space, not a new heading line.
        assert!(!md.lines().any(|l| l == "## y"), "{md}");
    }

    #[test]
    fn hostile_branch_stays_inside_its_code_span() {
        let mut doc = example();
        doc.source.vcs.as_mut().unwrap().branch = Some("evil`with`backticks\n# h4x".to_owned());
        let md = render_index(&doc, &IndexContext::default());
        // The embedded backtick must not close the span early (it becomes a
        // plain quote), and the embedded newline must not start a new line,
        // so "# h4x" never becomes a real heading outside the code span.
        assert!(md.contains("(`evil'with'backticks # h4x`)"), "{md}");
        assert!(!md.lines().any(|l| l == "# h4x"), "{md}");
    }

    #[test]
    fn only_the_last_ten_producers_are_shown() {
        let mut doc = example();
        doc.producers = (0..15)
            .map(|i| crate::model::ProducerRecord {
                command: format!("p{i}"),
                argv: vec![],
                started_at: "2026-10-01T00:00:00Z".into(),
                finished_at: "2026-10-01T00:01:00Z".into(),
                status: crate::model::ProducerStatus::Complete,
                exit_code: 0,
                findings_total: 0,
            })
            .collect();
        let md = render_index(&doc, &IndexContext::default());
        assert!(md.contains("p14"));
        assert!(!md.contains("p0 ("));
        assert!(md.contains("… 5 more in manifest.json"));
    }

    #[test]
    fn unsafe_evidence_dir_renders_without_a_link() {
        let mut doc = example();
        doc.findings[0].evidence.as_mut().unwrap().dir = "../../etc/passwd".to_owned();
        let md = render_index(&doc, &IndexContext::default());
        assert!(!md.contains("](../../etc/passwd/)"), "{md}");
        assert!(
            md.contains("- Evidence bundle: `../../etc/passwd/`"),
            "{md}"
        );
    }

    #[test]
    fn unsafe_raw_ref_renders_without_a_link() {
        let mut doc = example();
        doc.findings[1].evidence = None;
        doc.findings[1].raw_ref = Some("../outside.json".to_owned());
        let md = render_index(&doc, &IndexContext::default());
        assert!(!md.contains("](../outside.json)"), "{md}");
        assert!(md.contains("- Source: `../outside.json`"), "{md}");
    }

    #[test]
    fn confidence_level_and_verdict_are_escaped() {
        let mut doc = example();
        doc.findings[0].confidence.level = "high`<b>".to_owned();
        doc.findings[0].verdict = Some("real`<i>".to_owned());
        let md = render_index(&doc, &IndexContext::default());
        assert!(md.contains(r"high\`\<b\>"), "{md}");
        assert!(md.contains(r"verdict real\`\<i\>"), "{md}");
    }
}
