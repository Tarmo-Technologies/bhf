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
//! * [`RelationOutcome::Violation`] when the relation is broken.
//!
//! The six run/eval outcomes stay mutually distinct (acceptance: setup / auth /
//! missing-observation / policy-unknown / compliance / violation).
//!
//! The [`Require::External`] relation is decided by an injected
//! [`ExternalComparator`]: its [`ComparatorVerdict`] maps `Clean → Compliant`,
//! `Finding → Violation` (carrying the comparator's signature/classification into
//! the finding) and `Unknown → PolicyUnknown`. The crate is pure; the real,
//! process-spawning comparator lives in the driver and is passed in at the seam.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::finding::{ExternalFinding, FindingKind};
use crate::observation::{EffectEvent, Observation, ProfileStatus, RunState, Stream};
use crate::schema::{Cond, Field, Predicate, RelationalConfig, Require, Selector};

/// The verdict a [`ExternalComparator`] returns for one relation's cross-profile
/// observation bundle. `Finding` carries the comparator's own stable identity so
/// it can be folded into the relational finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComparatorVerdict {
    /// The comparator found no violation → [`RelationOutcome::Compliant`].
    Clean,
    /// The comparator found a violation → [`RelationOutcome::Violation`].
    Finding(ExternalFinding),
    /// The comparator could not decide → [`RelationOutcome::PolicyUnknown`].
    Unknown {
        /// Why the comparator could not decide (e.g. an unsupported/bounded
        /// infrastructure result from the extension).
        reason: String,
    },
}

/// Decides the [`Require::External`] relation over a cross-profile observation
/// bundle. Implemented by the driver with a real (process-spawning) extension;
/// the crate stays pure and never performs I/O itself.
pub trait ExternalComparator {
    /// Compare the full cross-profile observation `bundle` for an `External`
    /// predicate whose named `comparator` selects the trusted comparator.
    fn compare(
        &mut self,
        comparator: &str,
        bundle: &BTreeMap<String, Observation>,
    ) -> ComparatorVerdict;
}

/// A comparator for when none is wired: every `External` predicate is undecidable
/// ([`RelationOutcome::PolicyUnknown`]) rather than silently compliant. Used by
/// the no-comparator [`evaluate`]/[`evaluate_one`] convenience entry points.
pub struct NoComparator;

impl ExternalComparator for NoComparator {
    fn compare(
        &mut self,
        comparator: &str,
        _bundle: &BTreeMap<String, Observation>,
    ) -> ComparatorVerdict {
        ComparatorVerdict::Unknown {
            reason: format!("no external comparator wired for {comparator:?}"),
        }
    }
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
    /// divergence/equivalence violations, and for an external-comparator finding
    /// it is the involved profiles' events as context).
    pub evidence: Vec<EffectEvent>,
    /// The violated predicate.
    pub predicate: Predicate,
    /// For a [`Require::External`] violation, the comparator's verdict payload
    /// (signature, classification, trusted-extension provenance). `None` for
    /// every built-in relation kind.
    pub external: Option<ExternalFinding>,
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
    /// The relation is broken. Boxed so the large payload (which embeds the
    /// violated predicate and, for an external finding, the comparator verdict)
    /// does not bloat the whole enum.
    Violation(Box<Violation>),
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
        }
    }

    /// The contained [`Violation`], if this is a violation.
    #[must_use]
    pub fn as_violation(&self) -> Option<&Violation> {
        match self {
            RelationOutcome::Violation(v) => Some(&**v),
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

/// Evaluate every predicate in `config` against `observations`, with no external
/// comparator wired (every [`Require::External`] predicate is undecidable).
#[must_use]
pub fn evaluate(
    config: &RelationalConfig,
    observations: &BTreeMap<String, Observation>,
) -> Vec<Evaluation> {
    evaluate_with(config, observations, &mut NoComparator)
}

/// Evaluate every predicate in `config` against `observations`, deciding any
/// [`Require::External`] predicate with `comparator`.
#[must_use]
pub fn evaluate_with(
    config: &RelationalConfig,
    observations: &BTreeMap<String, Observation>,
    comparator: &mut dyn ExternalComparator,
) -> Vec<Evaluation> {
    config
        .predicates
        .iter()
        .enumerate()
        .map(|(i, pred)| Evaluation {
            predicate_index: i,
            rule_label: pred.rule.clone(),
            outcome: evaluate_one_with(config, pred, observations, comparator),
        })
        .collect()
}

/// Evaluate a single predicate against `observations`, with no external
/// comparator wired (an [`Require::External`] predicate is undecidable).
#[must_use]
pub fn evaluate_one(
    config: &RelationalConfig,
    predicate: &Predicate,
    observations: &BTreeMap<String, Observation>,
) -> RelationOutcome {
    evaluate_one_with(config, predicate, observations, &mut NoComparator)
}

/// Evaluate a single predicate against `observations`, deciding a
/// [`Require::External`] predicate with `comparator`.
#[must_use]
pub fn evaluate_one_with(
    config: &RelationalConfig,
    predicate: &Predicate,
    observations: &BTreeMap<String, Observation>,
    comparator: &mut dyn ExternalComparator,
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
        Require::External { comparator: name } => {
            eval_external(predicate, name, observations, comparator)
        }
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
    RelationOutcome::Violation(Box::new(Violation {
        kind,
        rule_label: predicate.rule.clone(),
        profiles: predicate.involved_profiles(),
        evidence: obs.events.clone(),
        predicate: predicate.clone(),
        external: None,
    }))
}

/// Decide an [`Require::External`] predicate via the injected comparator.
///
/// A profile in the bundle that never produced a usable observation
/// (setup/auth failure) short-circuits to that distinct run-level outcome first —
/// a context that never launched cannot participate in a cross-profile
/// comparison. Otherwise the comparator's [`ComparatorVerdict`] maps to real
/// outcomes: `Clean → Compliant`, `Unknown → PolicyUnknown`, and `Finding →
/// Violation` carrying the comparator's signature/classification/provenance. The
/// finding's involved profiles are every profile in the bundle (the comparator
/// sees the whole cross-profile bundle), so replay re-runs them all.
fn eval_external(
    predicate: &Predicate,
    comparator_name: &str,
    observations: &BTreeMap<String, Observation>,
    comparator: &mut dyn ExternalComparator,
) -> RelationOutcome {
    // Gate run-level failures (sorted, deterministic) before asking the
    // comparator, keeping setup/auth failures distinct from a policy verdict.
    for (name, obs) in observations {
        match obs.run_state {
            RunState::SetupFailure => {
                return RelationOutcome::SetupFailure {
                    profile: name.clone(),
                };
            }
            RunState::AuthFailure => {
                return RelationOutcome::AuthFailure {
                    profile: name.clone(),
                };
            }
            RunState::Ready => {}
        }
    }

    match comparator.compare(comparator_name, observations) {
        ComparatorVerdict::Clean => RelationOutcome::Compliant,
        ComparatorVerdict::Unknown { reason } => RelationOutcome::PolicyUnknown { reason },
        ComparatorVerdict::Finding(external) => {
            let kind = predicate.kind.unwrap_or(FindingKind::ExternalComparator);
            let profiles: Vec<String> = observations.keys().cloned().collect();
            let evidence: Vec<EffectEvent> = observations
                .values()
                .flat_map(|o| o.events.iter().cloned())
                .collect();
            RelationOutcome::Violation(Box::new(Violation {
                kind,
                rule_label: predicate.rule.clone(),
                profiles,
                evidence,
                predicate: predicate.clone(),
                external: Some(external),
            }))
        }
    }
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
    RelationOutcome::Violation(Box::new(Violation {
        kind,
        rule_label: predicate.rule.clone(),
        profiles: predicate.involved_profiles(),
        evidence,
        predicate: predicate.clone(),
        external: None,
    }))
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
    RelationOutcome::Violation(Box::new(Violation {
        kind,
        rule_label: predicate.rule.clone(),
        profiles: predicate.involved_profiles(),
        evidence,
        predicate: predicate.clone(),
        external: None,
    }))
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

    /// A mock comparator scripted with a fixed verdict, recording the comparator
    /// name and bundle size it was asked about.
    struct MockComparator {
        verdict: ComparatorVerdict,
        saw_comparator: Option<String>,
        saw_profiles: usize,
    }

    impl MockComparator {
        fn new(verdict: ComparatorVerdict) -> Self {
            Self {
                verdict,
                saw_comparator: None,
                saw_profiles: 0,
            }
        }
    }

    impl ExternalComparator for MockComparator {
        fn compare(
            &mut self,
            comparator: &str,
            bundle: &BTreeMap<String, Observation>,
        ) -> ComparatorVerdict {
            self.saw_comparator = Some(comparator.to_string());
            self.saw_profiles = bundle.len();
            self.verdict.clone()
        }
    }

    fn cfg_external() -> RelationalConfig {
        let src = r#"
schema = "bhf.relational.v1"
[[profiles]]
name = "admin"
[[profiles]]
name = "viewer"
[[predicates]]
rule = "external comparator decides the cross-profile relation"
require = { kind = "external", comparator = "ext/diff.toml" }
"#;
        RelationalConfig::parse(src).unwrap()
    }

    fn external_finding() -> ExternalFinding {
        ExternalFinding {
            comparator: "ext/diff.toml".to_string(),
            signature: "f00dcafe".to_string(),
            classification: "relational_external".to_string(),
            detail: Some("viewer diverged from admin".to_string()),
            provenance: None,
        }
    }

    /// Clean → Compliant, Finding → Violation (carrying the comparator's
    /// signature/classification), Unknown → PolicyUnknown — all distinct, and the
    /// comparator is handed the whole cross-profile bundle.
    #[test]
    fn external_comparator_maps_each_verdict_to_a_distinct_outcome() {
        let cfg = cfg_external();
        let obs = obs_set(vec![
            Observation::ready("admin", ProfileStatus::Allowed),
            Observation::ready("viewer", ProfileStatus::Allowed),
        ]);

        // Clean → Compliant.
        let mut clean = MockComparator::new(ComparatorVerdict::Clean);
        assert_eq!(
            evaluate_one_with(&cfg, &cfg.predicates[0], &obs, &mut clean),
            RelationOutcome::Compliant
        );
        assert_eq!(clean.saw_comparator.as_deref(), Some("ext/diff.toml"));
        assert_eq!(clean.saw_profiles, 2, "comparator sees the whole bundle");

        // Finding → Violation carrying the comparator's identity.
        let mut finder = MockComparator::new(ComparatorVerdict::Finding(external_finding()));
        let out = evaluate_one_with(&cfg, &cfg.predicates[0], &obs, &mut finder);
        let v = out.as_violation().expect("violation");
        assert_eq!(v.kind, FindingKind::ExternalComparator);
        let ext = v.external.as_ref().expect("external payload carried");
        assert_eq!(ext.signature, "f00dcafe");
        assert_eq!(ext.classification, "relational_external");
        // Both profiles are recorded as involved (replay re-runs the whole bundle).
        assert_eq!(v.profiles, vec!["admin".to_string(), "viewer".to_string()]);

        // Unknown → PolicyUnknown (never compliant, never a finding).
        let mut unknown = MockComparator::new(ComparatorVerdict::Unknown {
            reason: "comparator could not decide".to_string(),
        });
        let out = evaluate_one_with(&cfg, &cfg.predicates[0], &obs, &mut unknown);
        assert_eq!(out.label(), "policy_unknown");
        assert_ne!(out, RelationOutcome::Compliant);
        assert!(out.as_violation().is_none());

        // The three outcomes are mutually distinct.
        assert_ne!(
            evaluate_one_with(
                &cfg,
                &cfg.predicates[0],
                &obs,
                &mut MockComparator::new(ComparatorVerdict::Clean)
            )
            .label(),
            "policy_unknown"
        );
    }

    /// An external finding stays distinct from the run-level setup/auth outcomes:
    /// a profile that never launched short-circuits before the comparator runs.
    #[test]
    fn external_profile_setup_failure_short_circuits_before_comparator() {
        let cfg = cfg_external();
        let obs = obs_set(vec![
            Observation::ready("admin", ProfileStatus::Allowed),
            Observation::failed("viewer", RunState::SetupFailure),
        ]);
        // Even a comparator that would "find" is never consulted.
        let mut finder = MockComparator::new(ComparatorVerdict::Finding(external_finding()));
        let out = evaluate_one_with(&cfg, &cfg.predicates[0], &obs, &mut finder);
        assert_eq!(out.label(), "setup_failure");
        assert!(finder.saw_comparator.is_none(), "comparator must not run");
    }

    /// With no comparator wired, an External predicate is undecidable
    /// (PolicyUnknown), never silently compliant.
    #[test]
    fn external_without_comparator_is_policy_unknown() {
        let cfg = cfg_external();
        let obs = obs_set(vec![
            Observation::ready("admin", ProfileStatus::Allowed),
            Observation::ready("viewer", ProfileStatus::Allowed),
        ]);
        let out = evaluate_one(&cfg, &cfg.predicates[0], &obs);
        assert_eq!(out.label(), "policy_unknown");
        assert_ne!(out, RelationOutcome::Compliant);
    }
}
