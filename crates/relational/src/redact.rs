// SPDX-License-Identifier: Apache-2.0

//! Secret redaction.
//!
//! Profiles reference secrets by a stable id ([`EnvValue::SecretRef`]); the pure
//! crate never holds a *resolved* value. A downstream driver resolves references
//! from a local source, then — before anything is persisted into a finding or a
//! replay bundle — runs the recorded command/env/evidence through this module.
//! Every occurrence of a resolved value is replaced by a stable placeholder that
//! names the reference id, so the reference survives while the value never does.

use std::collections::BTreeMap;

use crate::finding::RelationFinding;
use crate::observation::{EffectEvent, Observation};
use crate::schema::EnvValue;

/// A map from secret reference id to its resolved value, held only transiently
/// by the driver. Values are consumed here to scrub them out of persisted data.
#[derive(Debug, Clone, Default)]
pub struct SecretResolution {
    map: BTreeMap<String, String>,
}

impl SecretResolution {
    /// An empty resolution.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that reference `reference` resolved to `value`.
    pub fn insert(&mut self, reference: impl Into<String>, value: impl Into<String>) {
        self.map.insert(reference.into(), value.into());
    }

    /// The resolved value for a reference, if known.
    #[must_use]
    pub fn resolve(&self, reference: &str) -> Option<&str> {
        self.map.get(reference).map(String::as_str)
    }

    /// Reference ids known to this resolution.
    #[must_use]
    pub fn references(&self) -> Vec<String> {
        self.map.keys().cloned().collect()
    }

    /// `(reference, value)` pairs sorted by value length (longest first), so a
    /// value that contains another value is scrubbed first and no partial
    /// fragment leaks.
    fn ordered(&self) -> Vec<(&str, &str)> {
        let mut pairs: Vec<(&str, &str)> = self
            .map
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        pairs.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(b.0)));
        pairs
    }
}

/// The stable placeholder a resolved secret is replaced with. It carries the
/// reference id so the stable id remains legible after redaction.
#[must_use]
pub fn placeholder(reference: &str) -> String {
    format!("<secret:{reference}>")
}

/// Redact every resolved secret value from `text`, replacing it with
/// [`placeholder`] of its reference id.
#[must_use]
pub fn redact_text(text: &str, resolution: &SecretResolution) -> String {
    let mut out = text.to_string();
    for (reference, value) in resolution.ordered() {
        if out.contains(value) {
            out = out.replace(value, &placeholder(reference));
        }
    }
    out
}

/// Redact a recorded command vector.
#[must_use]
pub fn redact_command(command: &[String], resolution: &SecretResolution) -> Vec<String> {
    command
        .iter()
        .map(|arg| redact_text(arg, resolution))
        .collect()
}

/// Redact an environment overlay. Literal values are scrubbed; secret-ref values
/// already carry only the reference id and are kept verbatim.
#[must_use]
pub fn redact_env(
    env: &BTreeMap<String, EnvValue>,
    resolution: &SecretResolution,
) -> BTreeMap<String, EnvValue> {
    env.iter()
        .map(|(k, v)| {
            let redacted = match v {
                EnvValue::Literal(s) => EnvValue::Literal(redact_text(s, resolution)),
                EnvValue::SecretRef(id) => EnvValue::SecretRef(id.clone()),
            };
            (k.clone(), redacted)
        })
        .collect()
}

/// Redact effect-event strings in place.
pub fn redact_events(events: &mut [EffectEvent], resolution: &SecretResolution) {
    for e in events.iter_mut() {
        e.api = redact_text(&e.api, resolution);
        e.target = redact_text(&e.target, resolution);
    }
}

fn redact_observation(obs: &mut Observation, resolution: &SecretResolution) {
    redact_events(&mut obs.events, resolution);
    if let Some(d) = &obs.response_digest {
        obs.response_digest = Some(redact_text(d, resolution));
    }
    for hit in &mut obs.semantic_hits {
        hit.detail = redact_text(&hit.detail, resolution);
    }
}

/// Scrub every resolved secret from a finding before it is persisted or replayed.
/// The reference ids remain (they live in the config, not in resolved values).
pub fn redact_finding(finding: &mut RelationFinding, resolution: &SecretResolution) {
    redact_events(&mut finding.evidence_events, resolution);
    finding.rule_label = redact_text(&finding.rule_label, resolution);
    for obs in finding.observations.values_mut() {
        redact_observation(obs, resolution);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{FindingKind, RelationFinding};
    use crate::observation::{EffectEvent, Observation, ProfileStatus};
    use crate::predicate::Violation;
    use crate::schema::{EnvValue, RelationalConfig};

    fn resolution() -> SecretResolution {
        let mut r = SecretResolution::new();
        r.insert("lab:admin", "s3cr3t");
        r
    }

    #[test]
    fn redaction_scrubs_resolved_secret_keeps_reference() {
        let res = resolution();

        // Command vector carrying the resolved value.
        let cmd = vec![
            "/bin/login".to_string(),
            "--token".to_string(),
            "s3cr3t".to_string(),
        ];
        let redacted = redact_command(&cmd, &res);
        assert!(!redacted.iter().any(|a| a.contains("s3cr3t")));
        assert!(redacted.iter().any(|a| a.contains("lab:admin")));

        // Env overlay holds only the reference id by construction.
        let mut env = BTreeMap::new();
        env.insert("TOKEN".to_string(), EnvValue::SecretRef("lab:admin".into()));
        let redacted_env = redact_env(&env, &res);
        let serialized = serde_json::to_string(&redacted_env).unwrap();
        assert!(!serialized.contains("s3cr3t"));
        assert!(serialized.contains("lab:admin"));

        // Evidence string carrying the resolved value.
        let mut events = vec![EffectEvent::process_exec("execve", "helper --token s3cr3t")];
        redact_events(&mut events, &res);
        assert_eq!(events[0].target, "helper --token <secret:lab:admin>");
    }

    #[test]
    fn finding_serialized_through_redaction_has_no_resolved_value() {
        let src = r#"
schema = "bhf.relational.v1"
[[profiles]]
name = "viewer"
allowlist = ["viewer-helper"]
[[predicates]]
rule = "viewer spawned subset of allowlist"
require = { kind = "subset", set = "viewer.spawned", of = "viewer.allowlist" }
"#;
        let cfg = RelationalConfig::parse(src).unwrap();
        let mut obs = BTreeMap::new();
        obs.insert(
            "viewer".to_string(),
            Observation::ready("viewer", ProfileStatus::Allowed)
                .with_events(vec![EffectEvent::process_exec(
                    "execve",
                    "launch s3cr3t helper",
                )])
                .with_response_digest("prefix-s3cr3t-suffix"),
        );
        let v = Violation {
            kind: FindingKind::AllowlistEscape,
            rule_label: "spawned s3cr3t".to_string(),
            profiles: vec!["viewer".to_string()],
            evidence: vec![EffectEvent::process_exec("execve", "launch s3cr3t helper")],
            predicate: cfg.predicates[0].clone(),
        };
        let mut finding = RelationFinding::from_violation(1, &v, &cfg, &obs, "abc");

        let res = resolution();
        redact_finding(&mut finding, &res);
        let json = serde_json::to_string(&finding).unwrap();
        assert!(
            !json.contains("s3cr3t"),
            "resolved secret leaked into finding"
        );
        assert!(json.contains("lab:admin") || json.contains("<secret:lab:admin>"));
    }

    #[test]
    fn longest_value_redacted_first_leaves_no_fragment() {
        let mut res = SecretResolution::new();
        res.insert("lab:short", "abc");
        res.insert("lab:long", "abcdef");
        let out = redact_text("value=abcdef", &res);
        assert!(!out.contains("abcdef"));
        assert!(!out.contains("abc</"));
        assert_eq!(out, "value=<secret:lab:long>");
    }
}
