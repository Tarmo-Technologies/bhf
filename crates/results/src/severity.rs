// SPDX-License-Identifier: Apache-2.0
//! The single severity every renderer, the `ci` gate and importers read.
//! Precedence: actionability impact (unless unknown) -> the record's own
//! `severity` -> the rule catalog default -> medium. `forced` floors to low.

use crate::model::Severity;
use serde_json::Value;
use std::path::Path;

pub fn parse(value: &str) -> Option<Severity> {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" | "moderate" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "info" | "informational" | "note" | "none" => Some(Severity::Info),
        _ => None,
    }
}

pub fn resolve(
    impact: Option<&str>,
    record_severity: Option<&str>,
    rule_id: Option<&str>,
    forced: bool,
) -> Severity {
    let base = impact
        .and_then(parse)
        .or_else(|| record_severity.and_then(parse))
        .or_else(|| {
            rule_id
                .and_then(finding_rules::by_id)
                .and_then(|rule| parse(rule.default_severity.as_str()))
        })
        .unwrap_or(Severity::Medium);
    if forced {
        base.min(Severity::Low)
    } else {
        base
    }
}

/// Resolve straight from an on-disk `finding.json` (used by `ci`).
pub fn resolve_raw(raw: &Value, finding_path: Option<&Path>) -> Severity {
    let record = actionability::existing_actionability_or_backfill(
        actionability::RunMode::Reporting,
        raw,
        finding_path,
    );
    resolve(
        Some(record.impact.as_str()),
        raw.get("severity").and_then(Value::as_str),
        raw.get("rule_id").and_then(Value::as_str),
        raw.get("forced").and_then(Value::as_bool).unwrap_or(false),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity::*;

    #[test]
    fn precedence_table() {
        // (impact, record severity, rule id, forced) -> expected
        let cases = [
            (Some("critical"), Some("low"), None, false, Critical),
            (Some("unknown"), Some("low"), None, false, Low),
            (None, Some("HIGH"), None, false, High),
            (None, Some("moderate"), None, false, Medium),
            (None, None, Some("BHF-201"), false, rule_default("BHF-201")),
            (None, None, Some("NOPE-1"), false, Medium),
            (None, None, None, false, Medium),
            (Some("high"), None, None, true, Low),
            (Some("info"), None, None, true, Info),
        ];
        for (impact, record, rule, forced, want) in cases {
            assert_eq!(
                resolve(impact, record, rule, forced),
                want,
                "{impact:?} {record:?} {rule:?} {forced}"
            );
        }
    }

    #[test]
    fn resolve_raw_reads_impact_then_severity_then_forced() {
        let raw = serde_json::json!({"severity": "high", "rule_id": "BHF-201", "forced": true});
        assert_eq!(resolve_raw(&raw, None), Low);
    }

    fn rule_default(id: &str) -> crate::model::Severity {
        parse(
            finding_rules::by_id(id)
                .expect("catalog rule")
                .default_severity
                .as_str(),
        )
        .expect("catalog severities parse")
    }
}
