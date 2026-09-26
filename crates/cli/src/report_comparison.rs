// SPDX-License-Identifier: Apache-2.0
//! Offline campaign comparison. Observational absence is never a fixed verdict.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FINDINGS: usize = 100_000;
const NOTICE: &str = "Not observed means absent from this report, not fixed or unreachable. Compare equivalent projects and campaign scopes; no coverage equivalence is inferred.";

type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Deserialize)]
pub struct Snapshot {
    schema_version: String,
    run: Run,
    counts: Counts,
    findings: Vec<Finding>,
}
#[derive(Debug, Deserialize)]
struct Run {
    id: String,
    #[serde(default)]
    source_root: Option<String>,
}
#[derive(Debug, Deserialize)]
struct Counts {
    findings: usize,
}
#[derive(Debug, Deserialize)]
struct Finding {
    id: String,
    severity: String,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    cluster_key_full: Option<String>,
    #[serde(default)]
    cluster_fallback: bool,
    #[serde(default)]
    rule_id: Option<String>,
    #[serde(default)]
    classification: Option<String>,
    #[serde(default)]
    target: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    issue_key: String,
    status: ReviewStatus,
    owner: String,
    reason: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReviewStatus {
    Open,
    Investigating,
    AcceptedRisk,
    FalsePositive,
    Fixed,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TriageDocument {
    schema_version: String,
    decisions: Vec<Decision>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Issue {
    issue_key: String,
    identity_kind: String,
    rule_id: String,
    classification: String,
    target: String,
    severity: String,
    finding_ids: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct Entry {
    issue_key: String,
    state: &'static str,
    severity_increased: Option<bool>,
    review_needed: bool,
    review_status: String,
    decision: Option<Decision>,
    baseline: Option<Issue>,
    current: Option<Issue>,
}
#[derive(Debug, Serialize)]
pub struct Comparison {
    schema_version: &'static str,
    baseline_run: String,
    current_run: String,
    notice: &'static str,
    warnings: Vec<String>,
    counts: BTreeMap<String, usize>,
    unmatched_triage_keys: Vec<String>,
    issues: Vec<Entry>,
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("expected a regular report file: {}", path.display()));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("report input is not a regular file".to_owned());
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("comparison input exceeds 64 MiB".to_owned());
    }
    Ok(bytes)
}

pub fn load_snapshot(path: &Path) -> Result<Snapshot> {
    parse_snapshot(&read_bounded(path)?)
}

fn parse_snapshot(bytes: &[u8]) -> Result<Snapshot> {
    let snapshot: Snapshot = serde_json::from_slice(bytes).map_err(|e| format!("invalid report: {e}"))?;
    if snapshot.schema_version != "bhf.report.v2" {
        return Err("baseline comparison requires bhf.report.v2".to_owned());
    }
    if snapshot.run.id.trim().is_empty() || snapshot.counts.findings != snapshot.findings.len() {
        return Err("report has an empty run ID or inconsistent finding count".to_owned());
    }
    if snapshot.findings.len() > MAX_FINDINGS {
        return Err("comparison exceeds 100,000 findings".to_owned());
    }
    let mut ids = BTreeSet::new();
    for finding in &snapshot.findings {
        if finding.id.trim().is_empty() || finding.severity.trim().is_empty() || !ids.insert(&finding.id) {
            return Err("report has an empty ID/severity or duplicate finding ID".to_owned());
        }
    }
    Ok(snapshot)
}

pub fn load_triage(path: Option<&Path>) -> Result<BTreeMap<String, Decision>> {
    let Some(path) = path else { return Ok(BTreeMap::new()); };
    let document: TriageDocument = serde_json::from_slice(&read_bounded(path)?)
        .map_err(|e| format!("invalid triage document: {e}"))?;
    if document.schema_version != "bhf.triage.v1" || document.decisions.len() > MAX_FINDINGS {
        return Err("unsupported or oversized triage document".to_owned());
    }
    let mut decisions = BTreeMap::new();
    for decision in document.decisions {
        let valid_key = decision.issue_key.strip_prefix("bhf-issue-v1:")
            .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        if !valid_key || decision.owner.trim().is_empty() || decision.reason.trim().is_empty() {
            return Err("triage entries require a valid issue key, owner, and reason".to_owned());
        }
        if decisions.insert(decision.issue_key.clone(), decision).is_some() {
            return Err("duplicate triage issue key".to_owned());
        }
    }
    Ok(decisions)
}

fn nonempty(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|s| !s.trim().is_empty())
}
fn severity_rank(value: &str) -> Option<u8> {
    match value {
        "critical" => Some(4), "high" => Some(3), "medium" => Some(2),
        "low" => Some(1), "info" | "informational" | "note" => Some(0), _ => None,
    }
}
fn canonical_severity(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => "critical", "high" => "high", "medium" => "medium",
        "low" => "low", "info" | "informational" | "note" => "info", _ => "unknown",
    }.to_owned()
}
fn strongest(a: &str, b: &str) -> String {
    match (severity_rank(a), severity_rank(b)) {
        (Some(x), Some(y)) => (if x >= y { a } else { b }).to_owned(),
        // Unknown evidence must not be quietly replaced with a reassuring rank.
        _ => "unknown".to_owned(),
    }
}

fn group(snapshot: &Snapshot, side: &str) -> BTreeMap<String, Issue> {
    let mut issues: BTreeMap<String, Issue> = BTreeMap::new();
    for finding in &snapshot.findings {
        let target = ["qualified_name", "symbol", "function", "name"].iter()
            .find_map(|k| finding.target.get(k).and_then(Value::as_str))
            .or_else(|| finding.target.as_str()).unwrap_or("");
        let rule = finding.rule_id.as_deref().unwrap_or("");
        let class = finding.classification.as_deref().unwrap_or("");
        let (kind, signal) = if !finding.cluster_fallback && nonempty(&finding.cluster_key_full).is_some() {
            ("cluster", nonempty(&finding.cluster_key_full).unwrap().to_owned())
        } else if let Some(signature) = nonempty(&finding.signature) {
            ("signature", signature.to_owned())
        } else {
            // IDs alone can be local counters. Never link unrelated crashes on
            // that basis, even when both runs are named "last".
            ("unmatched", format!("{side}:{}:{}", snapshot.run.id, finding.id))
        };
        let identity = json!([kind, signal, rule, class, target]).to_string();
        let key = format!("bhf-issue-v1:{:x}", Sha256::digest(identity.as_bytes()));
        let severity = canonical_severity(&finding.severity);
        let entry = issues.entry(key.clone()).or_insert_with(|| Issue {
            issue_key: key, identity_kind: kind.to_owned(), rule_id: rule.to_owned(),
            classification: class.to_owned(), target: target.to_owned(), severity: severity.clone(),
            finding_ids: Vec::new(),
        });
        entry.severity = strongest(&entry.severity, &severity);
        entry.finding_ids.push(finding.id.clone());
    }
    for issue in issues.values_mut() { issue.finding_ids.sort(); }
    issues
}

pub fn compare(baseline: &Snapshot, current: &Snapshot, decisions: &BTreeMap<String, Decision>) -> Comparison {
    let old = group(baseline, "baseline");
    let new = group(current, "current");
    let keys: BTreeSet<_> = old.keys().chain(new.keys()).cloned().collect();
    let mut counts: BTreeMap<String, usize> = ["new", "persistent", "not_observed", "reopened", "review_needed", "severity_increased"]
        .into_iter().map(|s| (s.to_owned(), 0)).collect();
    let mut entries = Vec::new();
    let mut applied_decisions = BTreeSet::new();
    for key in &keys {
        let before = old.get(key);
        let after = new.get(key);
        let state = match (before, after) {
            (None, Some(_)) => "new", (Some(_), None) => "not_observed", _ => "persistent",
        };
        let increase = before.zip(after).and_then(|(a, b)| severity_rank(&a.severity).zip(severity_rank(&b.severity)))
            .map(|(a, b)| b > a);
        // A run-local fallback key is not safe for carrying decisions between
        // later runs named "last" which may reuse local finding counters.
        let matchable = after.or(before).is_some_and(|i| i.identity_kind != "unmatched");
        let decision = decisions.get(key).filter(|_| matchable).cloned();
        if decision.is_some() { applied_decisions.insert(key.clone()); }
        let reopened = after.is_some() && decision.as_ref().is_some_and(|d| d.status == ReviewStatus::Fixed);
        let severity_changed = before.zip(after).is_some_and(|(a, b)| a.severity != b.severity);
        let unresolved = decision.as_ref().is_some_and(|d| matches!(d.status, ReviewStatus::Open | ReviewStatus::Investigating));
        let review_needed = after.is_some() && (decision.is_none() || unresolved || reopened || increase == Some(true)
            || (severity_changed && increase.is_none()));
        let review_status = if reopened { "reopened".to_owned() }
            else if let Some(d) = &decision { serde_json::to_value(d.status).unwrap().as_str().unwrap().to_owned() }
            else { "unreviewed".to_owned() };
        *counts.get_mut(state).unwrap() += 1;
        if reopened { *counts.get_mut("reopened").unwrap() += 1; }
        if review_needed { *counts.get_mut("review_needed").unwrap() += 1; }
        if increase == Some(true) { *counts.get_mut("severity_increased").unwrap() += 1; }
        entries.push(Entry { issue_key: key.clone(), state, severity_increased: increase, review_needed,
            review_status, decision, baseline: before.cloned(), current: after.cloned() });
    }
    let mut warnings = vec![NOTICE.to_owned()];
    if baseline.run.source_root != current.run.source_root || baseline.run.source_root.is_none() {
        warnings.push("Source roots differ or are unavailable; the operator must confirm project identity.".to_owned());
    }
    if old.values().chain(new.values()).any(|i| i.identity_kind == "unmatched") {
        warnings.push("Some findings have no full cluster key or signature and are intentionally not matched across runs; their run-local keys cannot carry triage decisions.".to_owned());
    }
    Comparison { schema_version: "bhf.report.comparison.v1", baseline_run: baseline.run.id.clone(),
        current_run: current.run.id.clone(), notice: NOTICE, warnings, counts,
        unmatched_triage_keys: decisions.keys().filter(|k| !applied_decisions.contains(*k)).cloned().collect(), issues: entries }
}

fn escape(s: &str) -> String {
    s.chars().map(|c| match c {
        '&' => "&amp;".to_owned(), '<' => "&lt;".to_owned(), '>' => "&gt;".to_owned(),
        '"' => "&quot;".to_owned(), '\'' => "&#39;".to_owned(),
        c if c.is_control() => " ".to_owned(), c => c.to_string(),
    }).collect()
}
fn md(s: &str) -> String {
    escape(s).replace('|', "&#124;").replace('`', "&#96;")
        .replace('\\', "&#92;").replace('[', "&#91;").replace(']', "&#93;")
        .replace('!', "&#33;").replace('*', "&#42;").replace('_', "&#95;")
}

fn markdown(report: &Comparison) -> String {
    let mut out = format!("# BHF campaign comparison\n\n{} → {}\n\n{}\n\n", md(&report.baseline_run), md(&report.current_run), NOTICE);
    for (name, count) in &report.counts { out.push_str(&format!("{name}: {count}  \n")); }
    out.push_str("\n| State | Severity (before → after) | Target | Review | Owner | Issue key |\n|---|---|---|---|---|---|\n");
    for entry in &report.issues {
        let issue = entry.current.as_ref().or(entry.baseline.as_ref()).unwrap();
        out.push_str(&format!("| {} | {} → {} | {} | {}{} | {} | {} |\n", entry.state,
            md(entry.baseline.as_ref().map(|i| i.severity.as_str()).unwrap_or("—")),
            md(entry.current.as_ref().map(|i| i.severity.as_str()).unwrap_or("—")), md(&issue.target),
            md(&entry.review_status), if entry.review_needed { " (review needed)" } else { "" },
            md(entry.decision.as_ref().map(|d| d.owner.as_str()).unwrap_or("")), entry.issue_key));
    }
    for warning in &report.warnings { out.push_str(&format!("\nNote: {}\n", md(warning))); }
    if !report.unmatched_triage_keys.is_empty() { out.push_str("\nUnmatched triage keys (retained, not applied):\n"); }
    for key in &report.unmatched_triage_keys { out.push_str(&format!("\n{}\n", md(key))); }
    out
}

fn html(report: &Comparison) -> String {
    let mut out = String::from("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>BHF campaign comparison</title><style>body{font:16px system-ui,sans-serif;max-width:1100px;margin:2em auto;padding:0 1em;line-height:1.5}article{border:1px solid #bbb;padding:1em;margin:1em 0;overflow-wrap:anywhere}code{font-size:.8em}summary{cursor:pointer}dt{font-weight:bold}dd{margin-bottom:.6em}nav{display:flex;gap:1em;flex-wrap:wrap}</style><h1>BHF campaign comparison</h1>");
    out.push_str(&format!("<p>{} → {}</p><p>{}</p><nav>", escape(&report.baseline_run), escape(&report.current_run), NOTICE));
    for (name, count) in &report.counts { out.push_str(&format!("<span>{}: <strong>{count}</strong></span>", escape(name))); }
    out.push_str("</nav>");
    for state in ["new", "persistent", "not_observed"] {
        out.push_str(&format!("<h2>{}</h2>", escape(state)));
        for entry in report.issues.iter().filter(|i| i.state == state) {
            let issue = entry.current.as_ref().or(entry.baseline.as_ref()).unwrap();
            out.push_str(&format!("<article><h3>{} {}</h3><p>{} · {}{}</p><code>{}</code><details><summary>Finding evidence and triage</summary><dl>",
                escape(&issue.rule_id), escape(&issue.target), escape(&issue.severity), escape(&entry.review_status),
                if entry.review_needed { " · Review needed" } else { "" }, entry.issue_key));
            for (label, value) in [("Classification", issue.classification.as_str()), ("Identity", issue.identity_kind.as_str()),
                ("Owner", entry.decision.as_ref().map(|d| d.owner.as_str()).unwrap_or("Unassigned")),
                ("Reason", entry.decision.as_ref().map(|d| d.reason.as_str()).unwrap_or("No recorded decision"))] {
                out.push_str(&format!("<dt>{label}</dt><dd>{}</dd>", escape(value)));
            }
            for (label, item) in [("Baseline IDs", &entry.baseline), ("Current IDs", &entry.current)] {
                let ids = item.as_ref().map(|i| i.finding_ids.join(", ")).unwrap_or_default();
                out.push_str(&format!("<dt>{label}</dt><dd>{}</dd>", escape(&ids)));
            }
            out.push_str("</dl></details></article>");
        }
    }
    out.push_str("<h2>Comparison limitations</h2>");
    for warning in &report.warnings { out.push_str(&format!("<p>{}</p>", escape(warning))); }
    if !report.unmatched_triage_keys.is_empty() { out.push_str("<h2>Unmatched triage keys</h2>"); }
    for key in &report.unmatched_triage_keys { out.push_str(&format!("<p><code>{}</code></p>", escape(key))); }
    out.push_str("</html>\n"); out
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    temp.write_all(bytes).map_err(|e| e.to_string())?;
    temp.as_file().sync_all().map_err(|e| e.to_string())?;
    temp.persist(path).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn write(report: &Comparison, current_json: &Path) -> Result<Vec<PathBuf>> {
    let outputs = vec![current_json.with_extension("comparison.json"), current_json.with_extension("comparison.md"),
        current_json.with_extension("comparison.html")];
    let bytes = serde_json::to_vec_pretty(report).map_err(|e| e.to_string())?;
    atomic_write(&outputs[0], &bytes)?;
    atomic_write(&outputs[1], markdown(report).as_bytes())?;
    atomic_write(&outputs[2], html(report).as_bytes())?;
    Ok(outputs)
}

#[cfg(test)]
#[path = "report_comparison_tests.rs"]
mod tests;
