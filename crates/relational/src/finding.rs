// SPDX-License-Identifier: Apache-2.0

//! The relational finding record and its stable signature.
//!
//! A [`RelationFinding`] records a violated relation: the human rule label, the
//! involved profiles, each profile's normalized [`Observation`], the testcase
//! hash, the evidence events, the policy hash and per-profile hashes. Its
//! [`RelationFinding::signature`] is a stable, dedupable SHA-256 over
//! `(kind, sorted profile names, policy_hash, canonical relation, testcase_sha)`.
//!
//! The persisted shape mirrors the existing finding layout consumed by SARIF /
//! vulnerability-management importers: `id` (`F-{ordinal:04}-{sha8}`),
//! `signature`, `rule_id`, `classification`, `paths { testcase, finding }`,
//! with `testcase.bin` written beside `finding.json` by the driver.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::observation::{EffectEvent, Observation};
use crate::predicate::Violation;
use crate::schema::{Predicate, RelationalConfig};

/// The classification string stamped on every relational finding.
pub const CLASSIFICATION: &str = "relational_violation";

/// The category of a relational violation. The `kind → rule_id` mapping is kept
/// here and must be reconciled with the finding-rules table (added separately).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// An operation that policy required denied was observed allowed.
    UnexpectedAllow,
    /// A profile reached a target outside its declared allowlist.
    AllowlistEscape,
    /// Selectors that policy required to differ were observed equal.
    UnexpectedEquivalence,
    /// Selectors that policy required equal were observed to differ.
    UnexpectedDivergence,
    /// A trusted external comparator reported a cross-profile policy violation
    /// over the serialized observation bundle.
    ExternalComparator,
}

impl FindingKind {
    /// The stable rule id for this kind.
    #[must_use]
    pub fn rule_id(self) -> &'static str {
        rule_id_for_kind(self)
    }

    /// A short machine slug for this kind.
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            FindingKind::UnexpectedAllow => "unexpected_allow",
            FindingKind::AllowlistEscape => "allowlist_escape",
            FindingKind::UnexpectedEquivalence => "unexpected_equivalence",
            FindingKind::UnexpectedDivergence => "unexpected_divergence",
            FindingKind::ExternalComparator => "external_comparator",
        }
    }
}

/// The `kind → rule_id` table. These ids (`BHF-308..312`) are reconciled with
/// the finding-rules `RULES` table; this crate needs a stable, total mapping so
/// every emitted finding carries a catalog-resolvable rule id.
#[must_use]
pub fn rule_id_for_kind(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::UnexpectedAllow => "BHF-308",
        FindingKind::AllowlistEscape => "BHF-309",
        FindingKind::UnexpectedEquivalence => "BHF-310",
        FindingKind::UnexpectedDivergence => "BHF-311",
        FindingKind::ExternalComparator => "BHF-312",
    }
}

/// Provenance for an external-comparator finding: which trusted extension
/// decided it. Mirrors the extension host's finding-provenance block but is a
/// pure relational type (so this crate stays free of any extension dependency),
/// carried verbatim into the persisted relational finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalProvenance {
    /// SHA-256 of the comparator extension executable.
    pub executable_sha256: String,
    /// SHA-256 of the comparator extension manifest/config, if one was used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_sha256: Option<String>,
    /// The negotiated extension protocol version.
    pub protocol_version: String,
    /// The capabilities negotiated with the comparator extension.
    #[serde(default)]
    pub negotiated_caps: Vec<String>,
}

/// The comparator's verdict payload for a cross-profile external finding. Its
/// `signature` and `classification` are the comparator's own stable identity;
/// `provenance` records the trusted extension that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalFinding {
    /// The named comparator (an extension manifest path) that decided the relation.
    pub comparator: String,
    /// The comparator's stable, dedupable signature for this finding.
    pub signature: String,
    /// The comparator's classification label.
    pub classification: String,
    /// Optional human-readable detail from the comparator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The trusted-extension provenance of the comparator that decided this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ExternalProvenance>,
}

/// The persisted file paths of a finding bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingPaths {
    /// The testcase file, relative to the finding dir.
    pub testcase: String,
    /// The finding JSON file, relative to the finding dir.
    pub finding: String,
}

impl Default for FindingPaths {
    fn default() -> Self {
        Self {
            testcase: "testcase.bin".to_string(),
            finding: "finding.json".to_string(),
        }
    }
}

/// A relational finding: a violated relation with full evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationFinding {
    /// `F-{ordinal:04}-{sha8}`.
    pub id: String,
    /// Stable SHA-256 signature (hex).
    pub signature: String,
    /// The rule id from the `kind → rule_id` table.
    pub rule_id: String,
    /// Always [`CLASSIFICATION`].
    pub classification: String,
    /// The violation category.
    pub kind: FindingKind,
    /// The human rule label from the violated predicate.
    pub rule_label: String,
    /// The involved profile names, sorted.
    pub profiles: Vec<String>,
    /// The violated predicate (the relation that failed).
    pub relation: Predicate,
    /// Each involved profile's normalized observation.
    pub observations: BTreeMap<String, Observation>,
    /// SHA-256 of the testcase bytes.
    pub testcase_sha: String,
    /// The evidence events proving the violation.
    pub evidence_events: Vec<EffectEvent>,
    /// The policy hash at the time of the finding.
    pub policy_hash: String,
    /// Per-profile hashes for the involved profiles.
    pub profile_hashes: BTreeMap<String, String>,
    /// For an external-comparator violation, the comparator's verdict payload
    /// (its signature, classification and trusted-extension provenance). `None`
    /// for every built-in relation kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external: Option<ExternalFinding>,
    /// The persisted file paths.
    pub paths: FindingPaths,
}

impl RelationFinding {
    /// Build a finding from a [`Violation`], the config, the per-profile
    /// observations and the testcase bytes. `ordinal` orders findings in a run.
    #[must_use]
    pub fn from_violation(
        ordinal: u32,
        violation: &Violation,
        config: &RelationalConfig,
        observations: &BTreeMap<String, Observation>,
        testcase_sha: &str,
    ) -> Self {
        let mut profiles = violation.profiles.clone();
        profiles.sort();
        profiles.dedup();

        let policy_hash = config.policy_hash();

        let mut profile_hashes = BTreeMap::new();
        let mut obs = BTreeMap::new();
        for name in &profiles {
            if let Some(h) = config.profile_hash(name) {
                profile_hashes.insert(name.clone(), h);
            }
            if let Some(o) = observations.get(name) {
                obs.insert(name.clone(), o.clone());
            }
        }

        let external_signature = violation.external.as_ref().map(|e| e.signature.as_str());
        let signature = signature(
            violation.kind,
            &profiles,
            &policy_hash,
            &violation.predicate,
            testcase_sha,
            external_signature,
        );
        let short: String = signature.chars().take(8).collect();
        let id = format!("F-{ordinal:04}-{short}");

        RelationFinding {
            id,
            signature,
            rule_id: violation.kind.rule_id().to_string(),
            classification: CLASSIFICATION.to_string(),
            kind: violation.kind,
            rule_label: violation.rule_label.clone(),
            profiles,
            relation: violation.predicate.clone(),
            observations: obs,
            testcase_sha: testcase_sha.to_string(),
            evidence_events: violation.evidence.clone(),
            policy_hash,
            profile_hashes,
            external: violation.external.clone(),
            paths: FindingPaths::default(),
        }
    }
}

/// Compute a stable, dedupable finding signature.
///
/// `external_signature` is the comparator's own signature for an
/// external-comparator finding; it is folded in only when present, so every
/// built-in relation kind hashes exactly as before (the key is absent).
#[must_use]
pub fn signature(
    kind: FindingKind,
    sorted_profiles: &[String],
    policy_hash: &str,
    relation: &Predicate,
    testcase_sha: &str,
    external_signature: Option<&str>,
) -> String {
    // Canonicalize the relation via JSON so logically-equal relations hash equal.
    let relation_json = serde_json::to_string(relation).expect("relation serializes");
    let mut canonical = serde_json::Map::new();
    canonical.insert("kind".to_string(), kind.slug().into());
    canonical.insert("profiles".to_string(), sorted_profiles.into());
    canonical.insert("policy_hash".to_string(), policy_hash.into());
    canonical.insert("relation".to_string(), relation_json.into());
    canonical.insert("testcase_sha".to_string(), testcase_sha.into());
    // Two distinct comparator verdicts on the same relation+testcase must not
    // collide, so fold the comparator signature in when the relation is external.
    if let Some(sig) = external_signature {
        canonical.insert("external".to_string(), sig.into());
    }
    crate::sha256_hex(serde_json::Value::Object(canonical).to_string().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::{EffectEvent, Observation, ProfileStatus};
    use crate::schema::RelationalConfig;

    fn config() -> RelationalConfig {
        let src = r#"
schema = "bhf.relational.v1"
[status_map]
allowed = [0]
denied = [77]
[[profiles]]
name = "admin"
allowlist = ["admin-helper", "viewer-helper"]
[[profiles]]
name = "viewer"
allowlist = ["viewer-helper"]
[[predicates]]
rule = "viewer spawned subset of allowlist"
require = { kind = "subset", set = "viewer.spawned", of = "viewer.allowlist" }
"#;
        RelationalConfig::parse(src).unwrap()
    }

    fn sample_violation(cfg: &RelationalConfig) -> Violation {
        Violation {
            kind: FindingKind::AllowlistEscape,
            rule_label: "viewer spawned subset of allowlist".to_string(),
            profiles: vec!["viewer".to_string()],
            evidence: vec![EffectEvent::process_exec("execve", "administrator-helper")],
            predicate: cfg.predicates[0].clone(),
            external: None,
        }
    }

    #[test]
    fn finding_records_all_required_fields_and_is_stable() {
        let cfg = config();
        let mut obs = BTreeMap::new();
        obs.insert(
            "viewer".to_string(),
            Observation::ready("viewer", ProfileStatus::Allowed).with_events(vec![
                EffectEvent::process_exec("execve", "administrator-helper"),
            ]),
        );
        let v = sample_violation(&cfg);
        let f = RelationFinding::from_violation(1, &v, &cfg, &obs, "abc123");

        // Required fields present.
        assert_eq!(f.classification, CLASSIFICATION);
        assert_eq!(f.rule_id, "BHF-309");
        assert_eq!(f.kind, FindingKind::AllowlistEscape);
        assert_eq!(f.rule_label, "viewer spawned subset of allowlist");
        assert_eq!(f.profiles, vec!["viewer".to_string()]);
        assert_eq!(f.testcase_sha, "abc123");
        assert_eq!(f.evidence_events.len(), 1);
        assert!(!f.policy_hash.is_empty());
        assert!(f.profile_hashes.contains_key("viewer"));
        assert!(f.observations.contains_key("viewer"));
        assert_eq!(f.paths.testcase, "testcase.bin");
        assert!(f.id.starts_with("F-0001-"));

        // Signature stable across identical violations.
        let f2 = RelationFinding::from_violation(2, &v, &cfg, &obs, "abc123");
        assert_eq!(
            f.signature, f2.signature,
            "same violation => same signature"
        );

        // Signature differs when the testcase differs.
        let f3 = RelationFinding::from_violation(1, &v, &cfg, &obs, "different");
        assert_ne!(f.signature, f3.signature);

        // Signature differs when the kind differs.
        let mut v_other = v.clone();
        v_other.kind = FindingKind::UnexpectedAllow;
        let f4 = RelationFinding::from_violation(1, &v_other, &cfg, &obs, "abc123");
        assert_ne!(f.signature, f4.signature);
    }

    #[test]
    fn finding_round_trips_through_json() {
        let cfg = config();
        let obs = BTreeMap::new();
        let v = sample_violation(&cfg);
        let f = RelationFinding::from_violation(7, &v, &cfg, &obs, "deadbeef");
        let json = serde_json::to_string(&f).unwrap();
        let back: RelationFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
        // The persisted shape carries the importer-facing fields.
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value.get("id").is_some());
        assert!(value.get("signature").is_some());
        assert_eq!(value["rule_id"], "BHF-309");
        assert_eq!(value["classification"], CLASSIFICATION);
        assert_eq!(value["paths"]["testcase"], "testcase.bin");
    }

    #[test]
    fn external_comparator_finding_carries_signature_classification_and_provenance() {
        // An external-comparator violation carries the comparator's own signature,
        // classification and trusted-extension provenance into the relational
        // finding, and the comparator signature is folded into the relational
        // signature so two distinct verdicts on the same relation do not collide.
        let src = r#"
schema = "bhf.relational.v1"
[[profiles]]
name = "viewer"
[[profiles]]
name = "admin"
[[predicates]]
rule = "external comparator decides"
require = { kind = "external", comparator = "ext/comparator.toml" }
"#;
        let cfg = RelationalConfig::parse(src).unwrap();
        let ext = crate::finding::ExternalFinding {
            comparator: "ext/comparator.toml".to_string(),
            signature: "c0ffee".to_string(),
            classification: "relational_external".to_string(),
            detail: Some("viewer escaped under admin equivalence".to_string()),
            provenance: Some(crate::finding::ExternalProvenance {
                executable_sha256: "a".repeat(64),
                config_sha256: Some("b".repeat(64)),
                protocol_version: "bhf.extension.v1".to_string(),
                negotiated_caps: vec!["oracle.evaluate".to_string()],
            }),
        };
        let v = Violation {
            kind: FindingKind::ExternalComparator,
            rule_label: "external comparator decides".to_string(),
            profiles: vec!["admin".to_string(), "viewer".to_string()],
            evidence: Vec::new(),
            predicate: cfg.predicates[0].clone(),
            external: Some(ext.clone()),
        };
        let obs = BTreeMap::new();
        let f = RelationFinding::from_violation(1, &v, &cfg, &obs, "tc-sha");
        assert_eq!(f.rule_id, "BHF-312");
        assert_eq!(f.kind, FindingKind::ExternalComparator);
        let carried = f.external.as_ref().expect("external block carried");
        assert_eq!(carried.signature, "c0ffee");
        assert_eq!(carried.classification, "relational_external");
        assert_eq!(
            carried.provenance.as_ref().unwrap().protocol_version,
            "bhf.extension.v1"
        );

        // Folding the comparator signature in disambiguates distinct verdicts.
        let mut v2 = v.clone();
        v2.external = Some(ExternalFinding {
            signature: "d1ffff".to_string(),
            ..ext.clone()
        });
        let f2 = RelationFinding::from_violation(1, &v2, &cfg, &obs, "tc-sha");
        assert_ne!(
            f.signature, f2.signature,
            "different comparator signatures must not collide"
        );

        // The persisted JSON carries the comparator block (importer-facing).
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
        assert_eq!(json["external"]["signature"], "c0ffee");
        assert_eq!(
            json["external"]["provenance"]["protocol_version"],
            "bhf.extension.v1"
        );
    }

    #[test]
    fn every_kind_maps_to_a_distinct_rule_id() {
        let kinds = [
            FindingKind::UnexpectedAllow,
            FindingKind::AllowlistEscape,
            FindingKind::UnexpectedEquivalence,
            FindingKind::UnexpectedDivergence,
            FindingKind::ExternalComparator,
        ];
        let mut ids: Vec<&str> = kinds.iter().map(|k| k.rule_id()).collect();
        for id in &ids {
            assert!(id.starts_with("BHF-"), "rule id {id} not in BHF band");
        }
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total, "rule ids collided");
    }
}
