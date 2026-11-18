// SPDX-License-Identifier: Apache-2.0
//! A GitLab SAST security report (`gl-sast-report.json`, #320) of a
//! `FindingsDocument`, in GitLab's security report format 15.2.1, for a
//! pipeline's `artifacts:reports:sast`.
//!
//! Each finding is one vulnerability. Its primary identifier is its bhf rule,
//! then its CWEs; its location is where the finding is placed (the source
//! file, relative to the scanned root, and the line), and its id is the
//! finding's fingerprint, stable across runs, so GitLab tracks the same
//! vulnerability from pipeline to pipeline. A finding with no source location
//! (a binary finding) is left out: GitLab requires one.

use crate::model::{Finding, FindingsDocument, Severity};
use serde_json::{json, Value};

/// The report format version written, and its schema.
pub const GITLAB_SAST_VERSION: &str = "15.2.1";
const GITLAB_SAST_SCHEMA: &str = "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/v15.2.1/dist/sast-report-format.json";

/// The GitLab SAST report of `doc`, its scan started at `start_time` and
/// ended at `end_time` (RFC 3339 times, as bhf records them).
pub fn render_gitlab_sast(doc: &FindingsDocument, start_time: &str, end_time: &str) -> Value {
    let tool = json!({
        "id": "bhf",
        "name": "bhf",
        "version": doc.tool.version,
        "vendor": { "name": "bhf" },
    });
    let vulnerabilities: Vec<Value> = doc.findings.iter().filter_map(vulnerability).collect();
    json!({
        "version": GITLAB_SAST_VERSION,
        "schema": GITLAB_SAST_SCHEMA,
        "scan": {
            "analyzer": tool,
            "scanner": tool,
            "type": "sast",
            "start_time": gitlab_time(start_time),
            "end_time": gitlab_time(end_time),
            "status": "success",
        },
        "vulnerabilities": vulnerabilities,
    })
}

fn vulnerability(finding: &Finding) -> Option<Value> {
    let location = finding
        .location
        .as_ref()
        .filter(|location| !location.file.is_empty())?;
    let mut place = json!({ "file": location.file });
    if let Some(line) = location.line.filter(|line| *line > 0) {
        place["start_line"] = json!(line);
        place["end_line"] = json!(line);
    }
    if let Some(function) = location.function.as_deref().filter(|f| !f.is_empty()) {
        place["method"] = json!(function);
    }
    let rule = finding
        .rule
        .id
        .clone()
        .unwrap_or_else(|| finding.producer.clone());
    let mut identifiers = vec![json!({
        "type": "bhf_rule",
        "name": match &finding.rule.name {
            Some(name) => format!("{rule} {name}"),
            None => rule.clone(),
        },
        "value": rule,
    })];
    identifiers.extend(finding.cwe.iter().map(|cwe| {
        json!({
            "type": "cwe",
            "name": format!("CWE-{cwe}"),
            "value": cwe.to_string(),
            "url": format!("https://cwe.mitre.org/data/definitions/{cwe}.html"),
        })
    }));
    let mut vulnerability = json!({
        "id": finding.fingerprint.primary,
        "name": finding.title,
        "description": finding.explanation.clone().unwrap_or_else(|| finding.message.clone()),
        "severity": severity(finding.severity),
        "identifiers": identifiers,
        "location": place,
    });
    if let Some(remediation) = finding.remediation.as_deref().filter(|r| !r.is_empty()) {
        vulnerability["solution"] = json!(remediation);
    }
    Some(vulnerability)
}

fn severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "Info",
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    }
}

/// `time` in GitLab's format, `yyyy-mm-ddThh:mm:ss` UTC: an RFC 3339 time's
/// date and time to the second.
fn gitlab_time(time: &str) -> String {
    match time.parse::<jiff::Timestamp>() {
        Ok(parsed) => parsed.strftime("%Y-%m-%dT%H:%M:%S").to_string(),
        Err(_) => time.chars().take(19).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_are_utc_to_the_second() {
        assert_eq!(
            gitlab_time("2026-11-18T07:33:42.952Z"),
            "2026-11-18T07:33:42"
        );
        assert_eq!(
            gitlab_time("2026-11-18T09:33:42+02:00"),
            "2026-11-18T07:33:42"
        );
    }
}
