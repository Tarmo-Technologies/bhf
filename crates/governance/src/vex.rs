// SPDX-License-Identifier: Apache-2.0

//! Evidence-conservative automatic VEX assessment.
//!
//! Component discovery, loading and fuzz coverage describe use, not whether a
//! particular vulnerability is exploitable. Missing observations do not prove
//! absence or unreachability. Generic version ordering is not an ecosystem- or
//! release-branch-aware proof of a fix. Preserve these facts for analyst review
//! without automatically suppressing or confirming a CVE.

use sbom_ingest::EvidenceKind;
use serde_json::{json, Value};

/// The only verdict supported by component-level evidence alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VexStatus {
    UnderInvestigation,
}

impl VexStatus {
    pub fn openvex(self) -> &'static str {
        match self {
            Self::UnderInvestigation => "under_investigation",
        }
    }

    pub fn cyclonedx_state(self) -> &'static str {
        match self {
            Self::UnderInvestigation => "in_triage",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VexAssessment {
    pub status: VexStatus,
    pub justification: Option<&'static str>,
    /// Retained in the native JSON for compatibility; also emitted as the
    /// OpenVEX status_notes field. It describes uncertainty, not non-impact.
    pub impact_statement: String,
}

pub struct AssessmentContext<'a> {
    pub top_rung: Option<EvidenceKind>,
    /// A validated campaign observation exists; this does not establish that
    /// every relevant target, dependency or vulnerable path was exercised.
    pub campaign_ran: bool,
    pub advisory_fixed_versions: &'a [String],
    pub resolved_version: Option<&'a str>,
    pub product_id: &'a str,
    pub evidence_summary: &'a str,
    pub harnesses: &'a [String],
}

pub fn assess(ctx: &AssessmentContext<'_>) -> VexAssessment {
    let rung = ctx.top_rung.map_or("no-evidence", EvidenceKind::as_str);
    let campaign = if ctx.campaign_ran {
        "validated campaign evidence is present; its coverage is not proof of CVE applicability"
    } else {
        "no validated campaign evidence is available"
    };
    let mut detail = format!(
        "component {} (top evidence rung {}; reported version {}); {}; vulnerability-specific evidence is required to determine affected, not_affected or fixed status",
        ctx.product_id, rung, ctx.resolved_version.unwrap_or("unknown"), campaign,
    );
    if !ctx.evidence_summary.is_empty() {
        detail.push_str(&format!("; evidence: {}", ctx.evidence_summary));
    }
    if !ctx.harnesses.is_empty() {
        detail.push_str(&format!("; harnesses: {}", ctx.harnesses.join(", ")));
    }
    if !ctx.advisory_fixed_versions.is_empty() {
        detail.push_str(&format!(
            "; advisory fixed-version hints: {} (not a verified fix; validate package identity, version scheme and affected release branch)",
            ctx.advisory_fixed_versions.join(", "),
        ));
    }
    VexAssessment {
        status: VexStatus::UnderInvestigation,
        justification: None,
        impact_statement: detail,
    }
}

pub fn openvex_statement(cve: &str, product_id: &str, assessment: &VexAssessment) -> Value {
    json!({
        "vulnerability": { "name": cve },
        "products": [ { "@id": product_id } ],
        "status": assessment.status.openvex(),
        "status_notes": assessment.impact_statement,
        // Compatibility field, never paired with a not_affected verdict.
        "impact_statement": assessment.impact_statement,
    })
}

pub fn render_openvex(id: &str, timestamp: &str, statements: Vec<Value>) -> Value {
    json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": id,
        "author": "bhf",
        "timestamp": timestamp,
        "version": 1,
        "statements": statements,
    })
}

pub fn cyclonedx_analysis(assessment: &VexAssessment) -> Value {
    json!({
        "state": assessment.status.cyclonedx_state(),
        "detail": assessment.impact_statement,
    })
}

/// Machine-readable work queue. Missing or malformed assessment metadata must
/// not silently remove a matched vulnerability from review.
pub fn review_queue(report: &Value) -> Value {
    let matches = report.get("matches").and_then(Value::as_array);
    let entries = matches.into_iter().flatten().filter(|finding| {
        finding.pointer("/vex/review_required").and_then(Value::as_bool) != Some(false)
            || !matches!(finding.pointer("/vex/status").and_then(Value::as_str),
                Some("affected" | "not_affected" | "fixed"))
    }).map(|finding| json!({
        "id": finding.get("id"),
        "component_ref": finding.get("component_ref"),
        "component": finding.get("component"),
        "product_id": finding.pointer("/vex/product_id"),
        "severity": finding.get("severity"),
        "match_confidence": finding.get("match_confidence"),
        "matching_method": finding.get("matching_method"),
        "evidence": finding.get("evidence"),
        "reachability": finding.get("reachability"),
        "status": "under_investigation",
        "reason": "vulnerability_specific_evidence_missing",
        "status_notes": finding.pointer("/vex/impact_statement"),
        "advisory_fixed_versions": finding.pointer("/vex/advisory_fixed_versions"),
        "next_action": "Validate the advisory match, affected version range and vulnerable path for the identified product; retain reviewer evidence before issuing a definitive VEX statement.",
    })).collect::<Vec<_>>();
    json!({
        "schema_version": "bhf.vex.review_queue.v1",
        "assessment_scope": "matched_advisories_only",
        "counts": {
            "matches": matches.map_or(0, Vec::len),
            "requiring_review": entries.len(),
        },
        "entries": entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context<'a>(rung: Option<EvidenceKind>, campaign: bool,
        versions: &'a [String], harnesses: &'a [String]) -> AssessmentContext<'a> {
        AssessmentContext {
            top_rung: rung, campaign_ran: campaign, advisory_fixed_versions: versions,
            resolved_version: Some("2.0.0-rc1"), product_id: "pkg:generic/example@2.0.0-rc1",
            evidence_summary: "inventory", harnesses,
        }
    }

    #[test]
    fn every_component_rung_and_campaign_state_requires_vulnerability_review() {
        for rung in [None, Some(EvidenceKind::Declared), Some(EvidenceKind::Resolved),
            Some(EvidenceKind::SourceObserved), Some(EvidenceKind::Linked),
            Some(EvidenceKind::RuntimeLoaded), Some(EvidenceKind::FuzzReached)] {
            for campaign in [false, true] {
                let assessment = assess(&context(rung, campaign, &[], &[]));
                assert_eq!(assessment.status.openvex(), "under_investigation");
                assert!(assessment.justification.is_none());
                assert!(assessment.impact_statement.contains("vulnerability-specific evidence"));
            }
        }
    }

    #[test]
    fn even_matching_or_older_fixed_version_hints_never_prove_fixed() {
        for version in ["1.0.0", "2.0.0", "2.0.0-rc1", "2.0.0+build", "1.0.0-r2", "unknown"] {
            let versions = vec![version.to_owned()];
            let assessment = assess(&context(Some(EvidenceKind::Resolved), false, &versions, &[]));
            assert_eq!(assessment.status.openvex(), "under_investigation");
            assert!(assessment.impact_statement.contains(version));
            assert!(assessment.impact_statement.contains("not a verified fix"));
        }
    }

    #[test]
    fn multiple_fixed_branches_are_preserved_for_review_without_ordering() {
        let versions = vec!["1.5.9".to_owned(), "2.4.3".to_owned()];
        let assessment = assess(&context(Some(EvidenceKind::FuzzReached), true, &versions, &[]));
        assert!(assessment.impact_statement.contains("1.5.9, 2.4.3"));
        assert_eq!(assessment.status.openvex(), "under_investigation");
    }

    #[test]
    fn notes_keep_product_rung_campaign_and_harness_evidence() {
        let harnesses = vec!["H-1".to_owned()];
        let assessment = assess(&context(Some(EvidenceKind::FuzzReached), true, &[], &harnesses));
        for expected in ["pkg:generic/example", "validated campaign evidence is present", "H-1", "inventory"] {
            assert!(assessment.impact_statement.contains(expected));
        }
    }

    #[test]
    fn missing_campaign_data_does_not_claim_that_no_campaign_ran() {
        let assessment = assess(&context(None, false, &[], &[]));
        assert!(assessment.impact_statement.contains("no validated campaign evidence"));
        assert!(!assessment.impact_statement.contains("no fuzz campaign ran"));
    }

    #[test]
    fn openvex_exports_status_notes_without_nonimpact_justification() {
        let assessment = assess(&context(Some(EvidenceKind::Declared), false, &[], &[]));
        let value = openvex_statement("CVE-example", "pkg:generic/example@1", &assessment);
        assert_eq!(value["status"], "under_investigation");
        assert_eq!(value["status_notes"], assessment.impact_statement);
        assert!(value.get("justification").is_none());
        assert_eq!(value["vulnerability"]["name"], "CVE-example");
        assert_eq!(value["products"][0]["@id"], "pkg:generic/example@1");
    }

    #[test]
    fn cyclonedx_never_turns_component_loading_into_exploitability() {
        let assessment = assess(&context(Some(EvidenceKind::RuntimeLoaded), true, &[], &[]));
        let value = cyclonedx_analysis(&assessment);
        assert_eq!(value["state"], "in_triage");
        assert!(value.get("justification").is_none());
        assert!(!value["detail"].as_str().unwrap().is_empty());
    }

    #[test]
    fn empty_review_queue_is_scoped_to_matches_not_a_safety_verdict() {
        let queue = review_queue(&json!({"matches": []}));
        assert_eq!(queue["counts"]["requiring_review"], 0);
        assert_eq!(queue["assessment_scope"], "matched_advisories_only");
        assert!(queue.get("safe").is_none());
    }

    #[test]
    fn missing_or_malformed_assessments_remain_in_review() {
        for vex in [Value::Null, json!({}), json!({"review_required": "false"}),
            json!({"review_required": false, "status": "unknown"}),
            json!({"review_required": false, "status": "under_investigation"})] {
            let queue = review_queue(&json!({"matches": [{"id": "CVE-example", "vex": vex}]}));
            assert_eq!(queue["counts"]["requiring_review"], 1);
        }
    }

    #[test]
    fn review_queue_preserves_separate_products_for_the_same_cve() {
        let queue = review_queue(&json!({"matches": [
            {"id": "CVE-example", "component_ref": "a", "vex": {"product_id": "pkg:generic/a@1"}},
            {"id": "CVE-example", "component_ref": "b", "vex": {"product_id": "pkg:generic/b@1"}}
        ]}));
        assert_eq!(queue["counts"]["requiring_review"], 2);
        assert_ne!(queue["entries"][0]["product_id"], queue["entries"][1]["product_id"]);
    }

    #[test]
    fn openvex_document_keeps_existing_format_and_supplied_timestamp() {
        let value = render_openvex("bhf:test", "2026-09-25T00:00:00Z", vec![]);
        assert_eq!(value["@context"], "https://openvex.dev/ns/v0.2.0");
        assert_eq!(value["timestamp"], "2026-09-25T00:00:00Z");
        assert_eq!(value["version"], 1);
        assert_eq!(value["statements"], json!([]));
    }
}
