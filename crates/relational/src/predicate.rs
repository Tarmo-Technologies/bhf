// SPDX-License-Identifier: Apache-2.0

//! The declarative relational predicate evaluator.
//!
//! Given a [`RelationalConfig`] and the per-profile [`Observation`]s for one
//! testcase, [`evaluate`] produces an [`Evaluation`] per predicate. Each maps to
//! exactly one [`RelationOutcome`]:
//!
//! * run-level states — [`RelationOutcome::SetupFailure`],
//!   [`RelationOutcome::AuthFailure`] — when an involved profile never produced a
//!   usable observation;
//! * [`RelationOutcome::MissingObservation`] when a required stream was not
//!   collected (absence is never silently treated as compliance);
//! * [`RelationOutcome::PolicyUnknown`] when the policy question is genuinely
//!   undecidable (e.g. a status that could not be classified);
//! * [`RelationOutcome::Compliant`] when the relation holds (or its guard is not
//!   met);
//! * [`RelationOutcome::Violation`] when the relation is broken;
//! * [`RelationOutcome::Inconclusive`] for the external-comparator seam.
//!
//! The six run/eval outcomes stay mutually distinct (acceptance: setup / auth /
//! missing-observation / policy-unknown / compliance / violation).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::finding::FindingKind;
use crate::observation::{EffectEvent, Observation, ProfileStatus, Stream};
use crate::schema::{Cond, Field, Predicate, RelationalConfig, Require, Selector};

/// A tri-state the external comparator seam would return once wired. Until then
/// [`Require::External`] evaluates to [`RelationOutcome::Inconclusive`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalVerdict {
    /// The comparator found no violation.
    Clean,
    /// The comparator found a violation.
    Finding,
    /// The comparator could not decide.
    Unknown,
}

/// A violated relation, with everything needed to build a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    /// The violation category.
    pub kind: FindingKind,
    /// The human rule label.
    pub rule_label: String,
    /// The involved profile names.
    pub profiles: Vec<String>,
    /// The evidence events proving the violation (may be empty for value-only
    /// divergence/equivalence violations).
    pub evidence: Vec<EffectEvent>,
    /// The violated predicate.
    pub predicate: Predicate,
}

/// The outcome of evaluating one predicate for one testcase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RelationOutcome {
    /// An involved profile could not be launched.
    SetupFailure {
        /// The failing profile.
        profile: String,
    },
    /// An involved profile failed its auth/session bootstrap.
    AuthFailure {
        /// The failing profile.
        profile: String,
    },
    /// A required observation stream was not collected.
    MissingObservation {
        /// The profile whose stream was missing.
        profile: String,
        /// The missing stream name.
        stream: String,
    },
    /// The policy question is undecidable for this testcase.
    PolicyUnknown {
        /// Why the evaluation was inconclusive.
        reason: String,
    },
    /// The relation holds (or its guard is not met).
    Compliant,
    /// The relation is broken.
    Violation(Violation),
    /// The external comparator seam is not yet wired.
    Inconclusive {
        /// The extension/comparator awaited.
        awaiting_extension: String,
    },
}

impl RelationOutcome {
    /// A stable discriminant label, used to assert outcome distinctness.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            RelationOutcome::SetupFailure { .. } => "setup_failure",
            RelationOutcome::AuthFailure { .. } => "auth_failure",
            RelationOutcome::MissingObservation { .. } => "missing_observation",
            RelationOutcome::PolicyUnknown { .. } => "policy_unknown",
            RelationOutcome::Compliant => "compliant",
            RelationOutcome::Violation(_) => "violation",
            RelationOutcome::Inconclusive { .. } => "inconclusive",
        }
    }

    /// The contained [`Violation`], if this is a violation.
    #[must_use]
    pub fn as_violation(&self) -> Option<&Violation> {
        match self {
            RelationOutcome::Violation(v) => Some(v),
            _ => None,
        }
    }
}

/// One predicate's evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    /// The predicate's index in the config.
    pub predicate_index: usize,
    /// The predicate's human rule label.
    pub rule_label: String,
    /// The outcome.
    pub outcome: RelationOutcome,
}

/// Evaluate every predicate in `config` against `observations`.
#[must_use]
pub fn evaluate(
    config: &RelationalConfig,
    observations: &BTreeMap<String, Observation>,
) -> Vec<Evaluation> {
    config
        .predicates
        .iter()
        .enumerate()
        .map(|(i, pred)| Evaluation {
            predicate_index: i,
            rule_label: pred.rule.clone(),
            outcome: evaluate_one(config, pred, observations),
        })
        .collect()
}

/// Evaluate a single predicate against `observations`.
#[must_use]
pub fn evaluate_one(
    config: &RelationalConfig,
    predicate: &Predicate,
    observations: &BTreeMap<String, Observation>,
) -> RelationOutcome {
    // 1. Run-state gating: any involved profile that never produced a usable
    //    observation short-circuits to its distinct run-level outcome.
    for prof in predicate.involved_profiles() {
        match observations.get(&prof) {
            None => {
                return RelationOutcome::MissingObservation {
                    profile: prof,
                    stream: "status".to_string(),
                };
            }
            Some(obs) => match obs.run_state {
                crate::observation::RunState::SetupFailure => {
                    return RelationOutcome::SetupFailure { profile: prof };
                }
                crate::observation::RunState::AuthFailure => {
                    return RelationOutcome::AuthFailure { profile: prof };
                }
                crate::observation::RunState::Ready => {}
            },
        }
    }

    // 2. Guard: if present and not met, the relation is not required => compliant.
    if let Some(cond) = &predicate.when {
        if !guard_met(cond, observations) {
            return RelationOutcome::Compliant;
        }
    }

    // 3. Evaluate the relation.
    match &predicate.require {
        Require::StatusRelation { profile, status } => {
            eval_status_relation(predicate, profile, *status, observations)
        }
        Require::Subset { set, of } => eval_subset(config, predicate, set, of, observations),
        Require::Equal { selectors } => {
            eval_equal_differ(config, predicate, selectors, true, observations)
        }
        Require::Differ { selectors } => {
            eval_equal_differ(config, predicate, selectors, false, observations)
        }
        Require::External { comparator } => RelationOutcome::Inconclusive {
            awaiting_extension: comparator.clone(),
        },
    }
}

/// Whether a `when` guard is satisfied. A guard that references a Ready profile
/// compares its status; an unmet guard means the relation is not required.
fn guard_met(cond: &Cond, observations: &BTreeMap<String, Observation>) -> bool {
    match cond {
        Cond::Always => true,
        Cond::StatusIs { profile, status } => observations
            .get(profile)
            .is_some_and(|o| o.status == *status),
    }
}

fn eval_status_relation(
    predicate: &Predicate,
    profile: &str,
    required: ProfileStatus,
    observations: &BTreeMap<String, Observation>,
) -> RelationOutcome {
    let obs = observations
        .get(profile)
        .expect("involved profile present after gating");
    if !obs.has_stream(Stream::Status) {
        return RelationOutcome::MissingObservation {
            profile: profile.to_string(),
            stream: "status".to_string(),
        };
    }
    if obs.status == required {
        return RelationOutcome::Compliant;
    }
    if obs.status == ProfileStatus::Unknown {
        return RelationOutcome::PolicyUnknown {
            reason: format!("{profile} status could not be classified"),
        };
    }
    // A definite status that contradicts the policy requirement.
    let kind = predicate.kind.unwrap_or(FindingKind::UnexpectedAllow);
    RelationOutcome::Violation(Violation {
        kind,
        rule_label: predicate.rule.clone(),
        profiles: predicate.involved_profiles(),
        evidence: obs.events.clone(),
        predicate: predicate.clone(),
    })
}

fn eval_subset(
    config: &RelationalConfig,
    predicate: &Predicate,
    set: &Selector,
    of: &Selector,
    observations: &BTreeMap<String, Observation>,
) -> RelationOutcome {
    let (set_targets, set_events) = match resolve_targets(config, set, observations) {
        Ok(v) => v,
        Err(fail) => return fail.into_outcome(),
    };
    let (of_targets, _) = match resolve_targets(config, of, observations) {
        Ok(v) => v,
        Err(fail) => return fail.into_outcome(),
    };

    let escapes: Vec<String> = set_targets
        .iter()
        .filter(|t| !of_targets.contains(*t))
        .cloned()
        .collect();
    if escapes.is_empty() {
        return RelationOutcome::Compliant;
    }
    let evidence: Vec<EffectEvent> = set_events
        .into_iter()
        .filter(|e| escapes.contains(&e.target))
        .collect();
    let kind = predicate.kind.unwrap_or(FindingKind::AllowlistEscape);
    RelationOutcome::Violation(Violation {
        kind,
        rule_label: predicate.rule.clone(),
        profiles: predicate.involved_profiles(),
        evidence,
        predicate: predicate.clone(),
    })
}

fn eval_equal_differ(
    config: &RelationalConfig,
    predicate: &Predicate,
    selectors: &[Selector],
    want_equal: bool,
    observations: &BTreeMap<String, Observation>,
) -> RelationOutcome {
    let mut values = Vec::with_capacity(selectors.len());
    for sel in selectors {
        match resolve_value(config, sel, observations) {
            Ok(v) => values.push(v),
            Err(fail) => return fail.into_outcome(),
        }
    }
    let all_equal = values.windows(2).all(|w| w[0] == w[1]);
    let violated = if want_equal { !all_equal } else { all_equal };
    if !violated {
        return RelationOutcome::Compliant;
    }
    let default_kind = if want_equal {
        FindingKind::UnexpectedDivergence
    } else {
        FindingKind::UnexpectedEquivalence
    };
    let kind = predicate.kind.unwrap_or(default_kind);
    // Evidence: the involved profiles' events, for context.
    let mut evidence = Vec::new();
    for sel in selectors {
        if let Some(o) = observations.get(&sel.profile) {
            evidence.extend(o.events.iter().cloned());
        }
    }
    RelationOutcome::Violation(Violation {
        kind,
        rule_label: predicate.rule.clone(),
        profiles: predicate.involved_profiles(),
        evidence,
        predicate: predicate.clone(),
    })
}

/// A selector-resolution failure. Deliberately small (never carries a
/// [`Violation`]) so the resolver helpers do not return a large `Err` variant;
/// callers convert it to the corresponding [`RelationOutcome`].
enum ResolveFail {
    Missing { profile: String, stream: String },
    Unknown { reason: String },
}

impl ResolveFail {
    fn into_outcome(self) -> RelationOutcome {
        match self {
            ResolveFail::Missing { profile, stream } => {
                RelationOutcome::MissingObservation { profile, stream }
            }
            ResolveFail::Unknown { reason } => RelationOutcome::PolicyUnknown { reason },
        }
    }
}

/// Resolve a selector to a set of targets (for subset predicates). `Spawned`
/// reads the effect-event stream (missing => [`ResolveFail::Missing`]);
/// `Allowlist` reads the declared config allowlist.
fn resolve_targets(
    config: &RelationalConfig,
    sel: &Selector,
    observations: &BTreeMap<String, Observation>,
) -> Result<(Vec<String>, Vec<EffectEvent>), ResolveFail> {
    match sel.field {
        Field::Spawned => {
            let obs = observations
                .get(&sel.profile)
                .ok_or_else(|| ResolveFail::Missing {
                    profile: sel.profile.clone(),
                    stream: "effects".to_string(),
                })?;
            if !obs.has_stream(Stream::Effects) {
                return Err(ResolveFail::Missing {
                    profile: sel.profile.clone(),
                    stream: "effects".to_string(),
                });
            }
            Ok((obs.target_set(), obs.events.clone()))
        }
        Field::Allowlist => {
            let profile = config
                .profile(&sel.profile)
                .ok_or_else(|| ResolveFail::Unknown {
                    reason: format!("unknown profile {} in selector", sel.profile),
                })?;
            let mut list = profile.allowlist.clone();
            list.sort();
            list.dedup();
            Ok((list, Vec::new()))
        }
        other => Err(ResolveFail::Unknown {
            reason: format!("selector field {other:?} is not a target set"),
        }),
    }
}

/// Resolve a selector to a canonical comparable string (for equal/differ).
fn resolve_value(
    config: &RelationalConfig,
    sel: &Selector,
    observations: &BTreeMap<String, Observation>,
) -> Result<String, ResolveFail> {
    let obs = observations.get(&sel.profile);
    match sel.field {
        Field::Status => {
            let obs = obs.ok_or_else(|| ResolveFail::Missing {
                profile: sel.profile.clone(),
                stream: "status".to_string(),
            })?;
            Ok(format!("{:?}", obs.status))
        }
        Field::Response => {
            let obs = obs.ok_or_else(|| ResolveFail::Missing {
                profile: sel.profile.clone(),
                stream: "status".to_string(),
            })?;
            obs.response_digest
                .clone()
                .ok_or_else(|| ResolveFail::Missing {
                    profile: sel.profile.clone(),
                    stream: "response".to_string(),
                })
        }
        Field::Edges => {
            let obs = obs.ok_or_else(|| ResolveFail::Missing {
                profile: sel.profile.clone(),
                stream: "coverage".to_string(),
            })?;
            Ok(obs.edges.to_string())
        }
        Field::Spawned | Field::Allowlist => {
            let (targets, _) = resolve_targets(config, sel, observations)?;
            Ok(targets.join(","))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::{EffectEvent, Observation, ProfileStatus, RunState, Stream};
    use crate::schema::RelationalConfig;

    fn cfg_status() -> RelationalConfig {
        let src = r#"
schema = "bhf.relational.v1"
[status_map]
allowed = [0]
denied = [77]
[[profiles]]
name = "admin"
[[profiles]]
name = "viewer"
[[predicates]]
rule = "viewer must stay denied when admin is allowed"
require = { kind = "status_relation", profile = "viewer", status = "denied" }
when = { kind = "status_is", profile = "admin", status = "allowed" }
"#;
        RelationalConfig::parse(src).unwrap()
    }

    fn cfg_subset() -> RelationalConfig {
        let src = r#"
schema = "bhf.relational.v1"
[[profiles]]
name = "viewer"
allowlist = ["viewer-helper"]
[[predicates]]
rule = "viewer spawned subset of allowlist"
require = { kind = "subset", set = "viewer.spawned", of = "viewer.allowlist" }
"#;
        RelationalConfig::parse(src).unwrap()
    }

    fn obs_set(items: Vec<Observation>) -> BTreeMap<String, Observation> {
        items.into_iter().map(|o| (o.profile.clone(), o)).collect()
    }

    #[test]
    fn status_relation_flags_unexpected_allow() {
        let cfg = cfg_status();
        // admin allowed (guard true), viewer allowed (should be denied).
        let obs = obs_set(vec![
            Observation::ready("admin", ProfileStatus::Allowed),
            Observation::ready("viewer", ProfileStatus::Allowed),
        ]);
        let out = evaluate_one(&cfg, &cfg.predicates[0], &obs);
        let v = out.as_violation().expect("violation");
        assert_eq!(v.kind, FindingKind::UnexpectedAllow);
        assert!(v.profiles.contains(&"viewer".to_string()));
        assert!(v.profiles.contains(&"admin".to_string()));
    }

    #[test]
    fn status_relation_compliant_when_denied() {
        let cfg = cfg_status();
        let obs = obs_set(vec![
            Observation::ready("admin", ProfileStatus::Allowed),
            Observation::ready("viewer", ProfileStatus::Denied),
        ]);
        assert_eq!(
            evaluate_one(&cfg, &cfg.predicates[0], &obs),
            RelationOutcome::Compliant
        );
    }

    #[test]
    fn expected_difference_is_not_a_finding() {
        // Guard false: admin is NOT allowed, so "viewer must be denied" is not
        // required even though viewer is allowed. This is a declared, expected
        // difference and must NOT become a finding.
        let cfg = cfg_status();
        let obs = obs_set(vec![
            Observation::ready("admin", ProfileStatus::Denied),
            Observation::ready("viewer", ProfileStatus::Allowed),
        ]);
        assert_eq!(
            evaluate_one(&cfg, &cfg.predicates[0], &obs),
            RelationOutcome::Compliant
        );
    }

    #[test]
    fn status_relation_unknown_is_policy_unknown_not_compliant() {
        let cfg = cfg_status();
        let obs = obs_set(vec![
            Observation::ready("admin", ProfileStatus::Allowed),
            Observation::ready("viewer", ProfileStatus::Unknown),
        ]);
        let out = evaluate_one(&cfg, &cfg.predicates[0], &obs);
        assert_eq!(out.label(), "policy_unknown");
        assert_ne!(out, RelationOutcome::Compliant);
    }

    #[test]
    fn subset_flags_allowlist_escape() {
        let cfg = cfg_subset();
        let obs = obs_set(vec![Observation::ready("viewer", ProfileStatus::Allowed)
            .with_events(vec![
                EffectEvent::process_exec("execve", "viewer-helper"),
                EffectEvent::process_exec("execve", "administrator-helper"),
            ])]);
        let out = evaluate_one(&cfg, &cfg.predicates[0], &obs);
        let v = out.as_violation().expect("violation");
        assert_eq!(v.kind, FindingKind::AllowlistEscape);
        // Evidence is exactly the escaping event.
        assert_eq!(v.evidence.len(), 1);
        assert_eq!(v.evidence[0].target, "administrator-helper");
    }

    #[test]
    fn identical_stdout_does_not_suppress_effect_violation() {
        // Two observations with equal status, edges and response digest; only the
        // effect stream distinguishes them. A forbidden spawn must still fire.
        let cfg = cfg_subset();
        let viewer = Observation::ready("viewer", ProfileStatus::Allowed)
            .with_edges(5)
            .with_response_digest("same-digest")
            .with_events(vec![EffectEvent::process_exec(
                "execve",
                "administrator-helper",
            )]);
        let obs = obs_set(vec![viewer]);
        let out = evaluate_one(&cfg, &cfg.predicates[0], &obs);
        assert_eq!(
            out.as_violation().map(|v| v.kind),
            Some(FindingKind::AllowlistEscape)
        );
    }

    #[test]
    fn missing_observation_is_not_compliant() {
        // Subset predicate but the effects stream was never collected.
        let cfg = cfg_subset();
        let viewer =
            Observation::ready("viewer", ProfileStatus::Allowed).without_stream(Stream::Effects);
        let obs = obs_set(vec![viewer]);
        let out = evaluate_one(&cfg, &cfg.predicates[0], &obs);
        assert_eq!(out.label(), "missing_observation");
        assert_ne!(out, RelationOutcome::Compliant);
    }

    #[test]
    fn setup_and_auth_failures_short_circuit() {
        let cfg = cfg_subset();
        let setup = obs_set(vec![Observation::failed("viewer", RunState::SetupFailure)]);
        assert_eq!(
            evaluate_one(&cfg, &cfg.predicates[0], &setup).label(),
            "setup_failure"
        );
        let authf = obs_set(vec![Observation::failed("viewer", RunState::AuthFailure)]);
        assert_eq!(
            evaluate_one(&cfg, &cfg.predicates[0], &authf).label(),
            "auth_failure"
        );
    }

    #[test]
    fn equal_selectors_flag_divergence_and_differ_flag_equivalence() {
        let src = r#"
schema = "bhf.relational.v1"
[[profiles]]
name = "a"
[[profiles]]
name = "b"
[[predicates]]
rule = "responses must be equal"
require = { kind = "equal", selectors = ["a.response", "b.response"] }
[[predicates]]
rule = "responses must differ"
require = { kind = "differ", selectors = ["a.response", "b.response"] }
"#;
        let cfg = RelationalConfig::parse(src).unwrap();

        // Different responses: equal-predicate => divergence; differ-predicate ok.
        let diff = obs_set(vec![
            Observation::ready("a", ProfileStatus::Allowed).with_response_digest("x"),
            Observation::ready("b", ProfileStatus::Allowed).with_response_digest("y"),
        ]);
        assert_eq!(
            evaluate_one(&cfg, &cfg.predicates[0], &diff)
                .as_violation()
                .map(|v| v.kind),
            Some(FindingKind::UnexpectedDivergence)
        );
        assert_eq!(
            evaluate_one(&cfg, &cfg.predicates[1], &diff),
            RelationOutcome::Compliant
        );

        // Equal responses: differ-predicate => equivalence; equal-predicate ok.
        let same = obs_set(vec![
            Observation::ready("a", ProfileStatus::Allowed).with_response_digest("x"),
            Observation::ready("b", ProfileStatus::Allowed).with_response_digest("x"),
        ]);
        assert_eq!(
            evaluate_one(&cfg, &cfg.predicates[1], &same)
                .as_violation()
                .map(|v| v.kind),
            Some(FindingKind::UnexpectedEquivalence)
        );
        assert_eq!(
            evaluate_one(&cfg, &cfg.predicates[0], &same),
            RelationOutcome::Compliant
        );
    }

    #[test]
    fn external_comparator_is_inconclusive() {
        let src = r#"
schema = "bhf.relational.v1"
[[profiles]]
name = "a"
[[predicates]]
rule = "external check"
require = { kind = "external", comparator = "diff-tool" }
"#;
        let cfg = RelationalConfig::parse(src).unwrap();
        let obs = obs_set(vec![Observation::ready("a", ProfileStatus::Allowed)]);
        let out = evaluate_one(&cfg, &cfg.predicates[0], &obs);
        assert_eq!(
            out,
            RelationOutcome::Inconclusive {
                awaiting_extension: "diff-tool".to_string()
            }
        );
    }
}
