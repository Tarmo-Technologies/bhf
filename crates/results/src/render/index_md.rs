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
    /// Inputs of a work dir from an earlier release that look damaged.
    pub damaged_inputs: Option<crate::migrate::DamagedInputs>,
}

/// Most finding ids the damaged-input warning names.
const MAX_DAMAGED_FINDINGS_SHOWN: usize = 20;

/// The warning about inputs an earlier release's seed encoding damaged.
pub fn damaged_inputs_line(damaged: &crate::migrate::DamagedInputs) -> String {
    let mut parts = Vec::new();
    if !damaged.findings.is_empty() {
        let mut ids = damaged
            .findings
            .iter()
            .take(MAX_DAMAGED_FINDINGS_SHOWN)
            .map(|id| format!("`{}`", md_code(id)))
            .collect::<Vec<_>>()
            .join(", ");
        if damaged.findings.len() > MAX_DAMAGED_FINDINGS_SHOWN {
            let _ = write!(
                ids,
                " and {} more",
                damaged.findings.len() - MAX_DAMAGED_FINDINGS_SHOWN
            );
        }
        parts.push(format!("the testcases of {ids}"));
    }
    if damaged.corpus_entries > 0 {
        parts.push(format!(
            "{} corpus {} under the work dir's `corpus/`{}",
            damaged.corpus_entries,
            if damaged.corpus_entries == 1 {
                "entry"
            } else {
                "entries"
            },
            if damaged.truncated {
                " (the first entries scanned)"
            } else {
                ""
            }
        ));
    }
    let total = damaged.total();
    format!(
        "{total} {} runs of `EF BF BD` (U+FFFD, the UTF-8 replacement character): {}. \
         This work dir holds data from an earlier bhf release, whose seed encoding replaced every \
         invalid UTF-8 byte of a seed with it, so these are likely damaged copies of binary seeds \
         rather than real inputs. Re-run `bhf auto` into a fresh work dir to fuzz from the \
         original seeds.",
        if total == 1 {
            "input contains"
        } else {
            "inputs contain"
        },
        parts.join(" and ")
    )
}

/// On Windows a sanitized harness needs the sanitizer runtime DLL's directory
/// on PATH; replay.py adds it (a direct `main.exe` run needs the same).
const REPRODUCE_PLATFORM_NOTE: &str = if cfg!(windows) {
    " (it puts the sanitizer runtime DLL directory on PATH; set the same PATH to run the harness directly)"
} else {
    ""
};

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
    if let Some(damaged) = &ctx.damaged_inputs {
        let _ = writeln!(out, "- ⚠ {}", damaged_inputs_line(damaged));
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
        if let Some(access) = rep.fuzz.as_ref().and_then(|fuzz| fuzz.access.as_ref()) {
            let _ = writeln!(
                out,
                "- Memory access: {}{}",
                md_text(&access_text(access)),
                access_parameter_text(access)
            );
        }
        if let Some(gates) = rep
            .fuzz
            .as_ref()
            .and_then(|fuzz| fuzz.input_to_state.as_deref())
            .filter(|gates| !gates.is_empty())
        {
            let shown = gates
                .iter()
                .take(MAX_GATES_SHOWN)
                .map(|g| {
                    let site = g
                        .site_location
                        .as_ref()
                        .map(|l| match l.line {
                            Some(line) => format!(" at `{}:{line}`", md_code(&l.file)),
                            None => format!(" at `{}`", md_code(&l.file)),
                        })
                        .unwrap_or_default();
                    format!(
                        "bytes {}..{} → {}{site}",
                        g.offset,
                        g.offset + g.len,
                        md_text(&g.cmp_kind)
                    )
                })
                .collect::<Vec<_>>()
                .join(" · ");
            let more = if gates.len() > MAX_GATES_SHOWN {
                format!(" · … {} more", gates.len() - MAX_GATES_SHOWN)
            } else {
                String::new()
            };
            let input = rep
                .fuzz
                .as_ref()
                .and_then(|fuzz| fuzz.input_to_state_input.as_deref())
                .map(|name| format!(" (offsets in `{}`)", md_code(name)))
                .unwrap_or_default();
            let _ = writeln!(out, "- Input bytes compared{input}: {shown}{more}");
        } else if let Some(fuzz) = rep
            .fuzz
            .as_ref()
            .filter(|fuzz| fuzz.input_to_state_status.is_some())
        {
            // A capture ran (or could not): say why it has no evidence.
            let what = if fuzz.input_to_state.is_some() {
                "none"
            } else {
                "not recorded"
            };
            let why = fuzz
                .input_to_state_reason
                .as_deref()
                .map(|reason| format!(" ({})", md_text(reason)))
                .unwrap_or_default();
            let _ = writeln!(out, "- Input bytes compared: {what}{why}");
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
            let _ = writeln!(
                out,
                "- Reproduce: `{}`{}",
                md_code(command),
                REPRODUCE_PLATFORM_NOTE
            );
        }
        out.push('\n');
    }
    out
}

/// Comparison-evidence entries listed per group before `… N more`.
const MAX_GATES_SHOWN: usize = 4;

/// `read of 4 byte(s), 0 byte(s) after a 12-byte heap region`.
fn access_text(access: &crate::model::MemoryAccess) -> String {
    let mut text = match access.direction.as_str() {
        "read" | "write" => access.direction.clone(),
        _ => "unknown-direction access".to_owned(),
    };
    if let Some(size) = access.size {
        let _ = write!(text, " of {size} byte(s)");
    }
    if let Some(region) = &access.region {
        let object = match region.size {
            Some(size) => format!("{size}-byte {} object", region.kind),
            None => format!("{} object", region.kind),
        };
        match (region.distance, region.relation.as_deref()) {
            (Some(distance), Some(relation)) => {
                let _ = write!(text, ", {distance} byte(s) {relation} a {object}");
            }
            _ => {
                let _ = write!(text, ", in a {object}");
            }
        }
    }
    text
}

/// ` (the buffer of parameter `data`, at offset 12)`: the harness parameter
/// the access hit, as Markdown, or nothing when none was named.
fn access_parameter_text(access: &crate::model::MemoryAccess) -> String {
    let Some(parameter) = &access.parameter else {
        return String::new();
    };
    let name = md_code(&parameter.name);
    let offset = parameter
        .offset
        .map(|offset| offset.to_string())
        .unwrap_or_else(|| "?".to_owned());
    match parameter.basis.as_str() {
        "region_start" => format!(" (the buffer of parameter `{name}`, at offset {offset})"),
        "region_interior" => {
            format!(" (in the buffer parameter `{name}` points into, {offset} byte(s) from it)")
        }
        _ => format!(" ({offset} byte(s) past parameter `{name}`)"),
    }
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

    /// The warning names the damaged testcases and counts corpus entries.
    #[test]
    fn index_warns_about_damaged_inputs() {
        let ctx = IndexContext {
            damaged_inputs: Some(crate::migrate::DamagedInputs {
                findings: vec!["F-0001-aaaaaaaa".to_owned()],
                corpus_entries: 3,
                truncated: false,
            }),
            ..IndexContext::default()
        };
        let md = render_index(&example(), &ctx);
        assert!(
            md.contains("- ⚠ 4 inputs contain runs of `EF BF BD`"),
            "{md}"
        );
        assert!(
            md.contains("the testcases of `F-0001-aaaaaaaa` and 3 corpus entries"),
            "{md}"
        );
        assert!(md.contains("likely damaged"), "{md}");
        let single = damaged_inputs_line(&crate::migrate::DamagedInputs {
            findings: Vec::new(),
            corpus_entries: 1,
            truncated: true,
        });
        assert!(single.starts_with("1 input contains"), "{single}");
        assert!(single.contains("1 corpus entry"), "{single}");
        assert!(single.contains("first entries scanned"), "{single}");
        assert!(!render_index(&example(), &IndexContext::default()).contains("EF BF BD"));
    }

    /// A fuzz finding whose capture found no comparison evidence says why.
    #[test]
    fn a_finding_without_comparison_evidence_says_why() {
        let mut doc = example();
        let fuzz = doc.findings[0].fuzz.as_mut().unwrap();
        fuzz.input_to_state = Some(Vec::new());
        fuzz.input_to_state_status = Some("no_input_comparisons".to_owned());
        fuzz.input_to_state_reason = Some(
            "4 comparison(s) recorded; no operand followed a change of the input bytes".to_owned(),
        );
        let md = render_index(&doc, &IndexContext::default());
        assert!(
            md.contains(
                "- Input bytes compared: none (4 comparison(s) recorded; no operand followed a \
                 change of the input bytes)"
            ),
            "{md}"
        );
        let fuzz = doc.findings[0].fuzz.as_mut().unwrap();
        fuzz.input_to_state = None;
        fuzz.input_to_state_status = Some("unavailable".to_owned());
        fuzz.input_to_state_reason = Some("the harness binary was not found".to_owned());
        let md = render_index(&doc, &IndexContext::default());
        assert!(
            md.contains("- Input bytes compared: not recorded (the harness binary was not found)"),
            "{md}"
        );
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
        assert!(
            md.contains(
                "- Memory access: read of 4 byte(s), 0 byte(s) after a 12-byte heap object \
                 (the buffer of parameter `data`, at offset 12)\n"
            ),
            "{md}"
        );
        assert!(
            md.contains(
                "- Input bytes compared (offsets in `min_testcase.bin`): bytes 0..4 → memcmp at \
                 `src/parse.c:31`\n"
            ),
            "{md}"
        );
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
