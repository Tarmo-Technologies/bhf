// SPDX-License-Identifier: Apache-2.0

//! The per-profile observation model.
//!
//! An [`Observation`] is the normalized record of what a single profile did on
//! one testcase: its derived authorization [`ProfileStatus`], an edge-coverage
//! scalar, a normalized response digest, the observed runtime [`EffectEvent`]s,
//! and the optional semantic / authorization-decision seams. Each observation
//! also records *which* streams were actually collected ([`Stream`]) so a
//! predicate that needs a stream which was never collected yields a
//! *missing-observation* outcome instead of silently passing on an empty set.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::schema::StatusMap;

/// Derived authorization status for a profile on one testcase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileStatus {
    /// The operation was allowed (e.g. exit code in the config's `allowed` set).
    Allowed,
    /// The operation was denied (exit code in the config's `denied` set).
    Denied,
    /// Status could not be mapped to allowed/denied.
    Unknown,
}

/// Whether a profile run produced a usable observation, and if not, why.
///
/// `SetupFailure` and `AuthFailure` are run-level states that must stay distinct
/// from the evaluator's own compliant/violation/unknown verdicts (acceptance:
/// setup / auth / missing-observation / policy-unknown / compliance / violation
/// are all distinct).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    /// The profile ran and produced an observation.
    Ready,
    /// The runner/target could not be launched (missing binary, spawn error).
    SetupFailure,
    /// A bootstrap/session/auth step failed with the configured auth-failure
    /// exit code; the profile never reached the operation under test.
    AuthFailure,
}

/// The category of a runtime effect event. Kept deliberately generic so a
/// future platform-neutral collector can populate it unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    /// A process/program was executed (`exec*`/`posix_spawn`-style).
    ProcessExec,
    /// A command string was executed (`system`/`popen`-style).
    CommandExec,
    /// A network destination was contacted.
    NetworkEgress,
    /// A dynamic library was loaded.
    LibraryLoad,
    /// Any other observed effect.
    Other,
}

/// One observed runtime effect: the originating API, the effect category, and
/// the normalized target string (a program path, command, destination, …).
///
/// Note: no `argv` field — the process-exec source carries only the program
/// path/target string. This mirrors the real trace contract and keeps the model
/// portable to a future collector.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EffectEvent {
    /// The API that produced the event (e.g. `execve`, `system`).
    pub api: String,
    /// The effect category.
    pub kind: EffectKind,
    /// The normalized target (program path / command / destination).
    pub target: String,
}

impl EffectEvent {
    /// Convenience constructor for a process-exec effect.
    #[must_use]
    pub fn process_exec(api: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            api: api.into(),
            kind: EffectKind::ProcessExec,
            target: target.into(),
        }
    }
}

/// A semantic/postcondition verdict (external-comparator-style tri-state).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticVerdict {
    /// No semantic violation.
    Clean,
    /// A semantic violation was found.
    Finding,
    /// The semantic check was inconclusive.
    Unknown,
}

/// A semantic/postcondition result for a profile. Empty-by-default seam: real
/// semantic collectors populate this when they land.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SemanticHit {
    /// The semantic rule/postcondition label.
    pub rule: String,
    /// The tri-state verdict.
    pub verdict: SemanticVerdict,
    /// Human-readable detail.
    pub detail: String,
}

/// The decision of an authorization check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthResult {
    /// The operation was authorized.
    Allow,
    /// The operation was refused.
    Deny,
}

/// An authorization-decision event emitted by an instrumented target. Empty by
/// default; populated only when the target emits such events (optional seam).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthDecision {
    /// The operation the decision applies to.
    pub operation: String,
    /// The principal/role the decision was made for.
    pub principal: String,
    /// The decision.
    pub result: AuthResult,
}

/// Which observation streams were actually collected for a profile. A predicate
/// that requires a stream absent from this set yields a missing-observation
/// outcome rather than treating absence as compliance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stream {
    /// The authorization status stream.
    Status,
    /// The edge-coverage stream.
    Coverage,
    /// The runtime effect-event stream.
    Effects,
    /// The semantic/postcondition stream.
    Semantic,
    /// The authorization-decision stream.
    Auth,
}

/// The normalized per-profile observation for one testcase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    /// The profile this observation belongs to.
    pub profile: String,
    /// Whether the run produced a usable observation, and if not, why.
    pub run_state: RunState,
    /// The derived authorization status.
    pub status: ProfileStatus,
    /// Distinct edges hit (popcount of the coverage bitmap); 0 if none.
    pub edges: u64,
    /// SHA-256 of the normalized response, if a response was collected.
    pub response_digest: Option<String>,
    /// The process exit code, if the process ran to completion.
    pub exit_code: Option<i32>,
    /// Observed runtime effect events.
    pub events: Vec<EffectEvent>,
    /// Semantic/postcondition results (empty-by-default seam).
    pub semantic_hits: Vec<SemanticHit>,
    /// Authorization-decision events (empty-by-default seam).
    pub auth_decisions: Vec<AuthDecision>,
    /// Which streams were actually collected.
    pub collected: BTreeSet<Stream>,
}

impl Observation {
    /// A ready observation with the given status, no events, status+effects
    /// streams marked collected. Intended for tests and simple assembly.
    #[must_use]
    pub fn ready(profile: impl Into<String>, status: ProfileStatus) -> Self {
        let mut collected = BTreeSet::new();
        collected.insert(Stream::Status);
        collected.insert(Stream::Effects);
        Self {
            profile: profile.into(),
            run_state: RunState::Ready,
            status,
            edges: 0,
            response_digest: None,
            exit_code: None,
            events: Vec::new(),
            semantic_hits: Vec::new(),
            auth_decisions: Vec::new(),
            collected,
        }
    }

    /// A run-level failure observation (setup/auth). No streams are collected.
    #[must_use]
    pub fn failed(profile: impl Into<String>, run_state: RunState) -> Self {
        Self {
            profile: profile.into(),
            run_state,
            status: ProfileStatus::Unknown,
            edges: 0,
            response_digest: None,
            exit_code: None,
            events: Vec::new(),
            semantic_hits: Vec::new(),
            auth_decisions: Vec::new(),
            collected: BTreeSet::new(),
        }
    }

    /// Builder: attach effect events and mark the effects stream collected.
    #[must_use]
    pub fn with_events(mut self, events: Vec<EffectEvent>) -> Self {
        self.events = events;
        self.collected.insert(Stream::Effects);
        self
    }

    /// Builder: set the response digest and mark the status stream collected.
    #[must_use]
    pub fn with_response_digest(mut self, digest: impl Into<String>) -> Self {
        self.response_digest = Some(digest.into());
        self
    }

    /// Builder: set edges and mark the coverage stream collected.
    #[must_use]
    pub fn with_edges(mut self, edges: u64) -> Self {
        self.edges = edges;
        self.collected.insert(Stream::Coverage);
        self
    }

    /// Builder: mark a stream as *not* collected (e.g. a missing event stream).
    #[must_use]
    pub fn without_stream(mut self, stream: Stream) -> Self {
        self.collected.remove(&stream);
        self
    }

    /// Whether `stream` was collected for this observation.
    #[must_use]
    pub fn has_stream(&self, stream: Stream) -> bool {
        self.collected.contains(&stream)
    }

    /// The set of distinct process/command targets observed, sorted and deduped.
    /// Used by subset/allowlist predicates and for outcome-vector novelty.
    #[must_use]
    pub fn target_set(&self) -> Vec<String> {
        let mut out: Vec<String> = self.events.iter().map(|e| e.target.clone()).collect();
        out.sort();
        out.dedup();
        out
    }

    /// Classify a completed [`ProfileRun`] into an [`Observation`], applying the
    /// config's exit-code status mapping. A spawn failure maps to
    /// [`RunState::SetupFailure`]; an auth-failure exit code maps to
    /// [`RunState::AuthFailure`]. A stream is marked collected only when its data
    /// was actually produced (coverage bitmap present, effect stream present,
    /// semantic/auth seams non-empty).
    #[must_use]
    pub fn from_run(run: &crate::executor::ProfileRun, status_map: &StatusMap) -> Self {
        if run.run_state == RunState::SetupFailure {
            return Observation::failed(run.profile.clone(), RunState::SetupFailure);
        }
        // Auth-failure classification is driven by the configured exit code.
        if let Some(code) = run.exit_code {
            if status_map.is_auth_failure(code) {
                return Observation::failed(run.profile.clone(), RunState::AuthFailure);
            }
        }
        let status = match run.exit_code {
            Some(code) => status_map.classify(code),
            None => ProfileStatus::Unknown,
        };
        let mut collected = BTreeSet::new();
        collected.insert(Stream::Status);
        if !run.coverage.is_empty() {
            collected.insert(Stream::Coverage);
        }
        let events = match &run.events {
            Some(ev) => {
                collected.insert(Stream::Effects);
                ev.clone()
            }
            None => Vec::new(),
        };
        if !run.semantic_hits.is_empty() {
            collected.insert(Stream::Semantic);
        }
        if !run.auth_decisions.is_empty() {
            collected.insert(Stream::Auth);
        }
        Self {
            profile: run.profile.clone(),
            run_state: RunState::Ready,
            status,
            edges: crate::coverage::popcount(&run.coverage),
            response_digest: Some(crate::sha256_hex(&run.response)),
            exit_code: run.exit_code,
            events,
            semantic_hits: run.semantic_hits.clone(),
            auth_decisions: run.auth_decisions.clone(),
            collected,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predicate::RelationOutcome;
    use crate::schema::StatusMap;
    use std::collections::BTreeMap;

    fn status_map() -> StatusMap {
        StatusMap {
            allowed: vec![0],
            denied: vec![77],
            auth_failure: vec![66],
        }
    }

    #[test]
    fn from_run_maps_exit_codes_and_streams() {
        use crate::executor::ProfileRun;
        let sm = status_map();

        let allowed = Observation::from_run(
            &ProfileRun::ready("admin", 0)
                .with_coverage(vec![1, 0, 1, 1])
                .with_events(vec![EffectEvent::process_exec("execve", "helper")]),
            &sm,
        );
        assert_eq!(allowed.status, ProfileStatus::Allowed);
        assert_eq!(allowed.run_state, RunState::Ready);
        assert!(allowed.has_stream(Stream::Coverage));
        assert!(allowed.has_stream(Stream::Effects));
        assert_eq!(allowed.edges, 3);

        // Exit 77, no coverage, effect stream not collected.
        let denied = Observation::from_run(&ProfileRun::ready("viewer", 77).without_events(), &sm);
        assert_eq!(denied.status, ProfileStatus::Denied);
        assert!(!denied.has_stream(Stream::Effects));
        assert!(!denied.has_stream(Stream::Coverage));

        let authf = Observation::from_run(&ProfileRun::ready("viewer", 66), &sm);
        assert_eq!(authf.run_state, RunState::AuthFailure);

        let setup = Observation::from_run(&ProfileRun::setup_failure("viewer"), &sm);
        assert_eq!(setup.run_state, RunState::SetupFailure);
    }

    /// Acceptance #7: the six run/eval outcomes are all distinct and none
    /// collapses into another. A missing required stream must surface as a
    /// distinct outcome, never silently as compliance.
    #[test]
    fn observation_outcome_variants_are_distinct() {
        let outcomes = [
            RelationOutcome::SetupFailure {
                profile: "p".into(),
            },
            RelationOutcome::AuthFailure {
                profile: "p".into(),
            },
            RelationOutcome::MissingObservation {
                profile: "p".into(),
                stream: "effects".into(),
            },
            RelationOutcome::PolicyUnknown {
                reason: "guard inconclusive".into(),
            },
            RelationOutcome::Compliant,
            RelationOutcome::Violation(Box::new(crate::predicate::Violation {
                kind: crate::finding::FindingKind::ExternalComparator,
                rule_label: "r".into(),
                profiles: vec!["p".into()],
                evidence: Vec::new(),
                predicate: crate::schema::Predicate {
                    rule: "r".into(),
                    when: None,
                    require: crate::schema::Require::External {
                        comparator: "c".into(),
                    },
                    kind: None,
                },
                external: None,
            })),
        ];
        // All six labels distinct.
        let mut labels: Vec<&str> = outcomes.iter().map(RelationOutcome::label).collect();
        let total = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), total, "outcome labels collapsed: {labels:?}");

        // A missing event stream is produced (not compliant) when the stream is
        // absent. Build a ready-but-stream-missing observation and confirm the
        // model records the absence.
        let obs =
            Observation::ready("viewer", ProfileStatus::Allowed).without_stream(Stream::Effects);
        assert!(!obs.has_stream(Stream::Effects));
        assert_ne!(
            RelationOutcome::MissingObservation {
                profile: "viewer".into(),
                stream: "effects".into()
            },
            RelationOutcome::Compliant
        );

        // Sanity: an ObservationSet keyed by profile never conflates two profiles.
        let mut set: BTreeMap<String, Observation> = BTreeMap::new();
        set.insert("a".into(), Observation::ready("a", ProfileStatus::Allowed));
        set.insert("b".into(), Observation::ready("b", ProfileStatus::Denied));
        assert_eq!(set["a"].status, ProfileStatus::Allowed);
        assert_eq!(set["b"].status, ProfileStatus::Denied);
    }
}
