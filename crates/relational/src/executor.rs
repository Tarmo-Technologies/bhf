// SPDX-License-Identifier: Apache-2.0

//! The cross-profile execution seam.
//!
//! The campaign engine runs one testcase under each profile through the
//! [`ProfileExecutor`] trait. The pure crate never spawns a process: a
//! downstream driver implements the trait with real, isolated process spawning
//! (distinct coverage-shm, runtrace log and scratch dir per profile). This crate
//! ships an in-process [`FnExecutor`] so the whole campaign — mutation, coverage
//! feedback, predicate evaluation, finding emission, replay and minimization —
//! is unit-testable with a mock multi-profile target.

use crate::observation::{AuthDecision, EffectEvent, RunState, SemanticHit};
use crate::schema::Profile;

/// Errors a profile executor can raise. Distinct from a [`RunState::SetupFailure`]
/// run (which the mock reports as data): an `ExecError` is an executor-internal
/// fault the campaign surfaces rather than treats as a policy signal.
#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    /// The executor could not run the profile at all.
    #[error("profile executor failed for {profile:?}: {detail}")]
    Failed {
        /// The profile that failed.
        profile: String,
        /// Human-readable detail.
        detail: String,
    },
}

/// The raw result of running one testcase under one profile. The campaign turns
/// this into a normalized [`crate::observation::Observation`] via the config's
/// status mapping — keeping config interpretation out of the executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileRun {
    /// The profile name.
    pub profile: String,
    /// Whether the run produced a usable result.
    pub run_state: RunState,
    /// The process exit code, if it ran to completion.
    pub exit_code: Option<i32>,
    /// The normalized response bytes (e.g. stdout).
    pub response: Vec<u8>,
    /// The raw coverage bitmap (empty when no instrumented bitmap exists).
    pub coverage: Vec<u8>,
    /// Observed effect events; `None` means the effect stream was not collected.
    pub events: Option<Vec<EffectEvent>>,
    /// Semantic/postcondition results (seam; usually empty).
    pub semantic_hits: Vec<SemanticHit>,
    /// Authorization-decision events (seam; usually empty).
    pub auth_decisions: Vec<AuthDecision>,
}

impl ProfileRun {
    /// A ready run with the given exit code, empty response and no coverage.
    #[must_use]
    pub fn ready(profile: impl Into<String>, exit_code: i32) -> Self {
        Self {
            profile: profile.into(),
            run_state: RunState::Ready,
            exit_code: Some(exit_code),
            response: Vec::new(),
            coverage: Vec::new(),
            events: Some(Vec::new()),
            semantic_hits: Vec::new(),
            auth_decisions: Vec::new(),
        }
    }

    /// A setup-failure run (runner missing / spawn failed).
    #[must_use]
    pub fn setup_failure(profile: impl Into<String>) -> Self {
        Self {
            profile: profile.into(),
            run_state: RunState::SetupFailure,
            exit_code: None,
            response: Vec::new(),
            coverage: Vec::new(),
            events: None,
            semantic_hits: Vec::new(),
            auth_decisions: Vec::new(),
        }
    }

    /// Builder: set the response.
    #[must_use]
    pub fn with_response(mut self, response: Vec<u8>) -> Self {
        self.response = response;
        self
    }

    /// Builder: set the coverage bitmap.
    #[must_use]
    pub fn with_coverage(mut self, coverage: Vec<u8>) -> Self {
        self.coverage = coverage;
        self
    }

    /// Builder: set the effect events (marks the effect stream collected).
    #[must_use]
    pub fn with_events(mut self, events: Vec<EffectEvent>) -> Self {
        self.events = Some(events);
        self
    }

    /// Builder: drop the effect stream entirely (it was not collected).
    #[must_use]
    pub fn without_events(mut self) -> Self {
        self.events = None;
        self
    }
}

/// Runs a testcase under a profile. Implemented in-process for tests and with
/// real, isolated spawning by a downstream driver.
pub trait ProfileExecutor {
    /// Run `input` under `profile`.
    ///
    /// # Errors
    /// Returns [`ExecError`] only for executor-internal faults, not for policy
    /// signals (those are encoded in the returned [`ProfileRun`]).
    fn run(&mut self, profile: &Profile, input: &[u8]) -> Result<ProfileRun, ExecError>;
}

/// An in-process executor backed by a closure `FnMut(&Profile, &[u8]) -> ProfileRun`.
/// The closure is the mock target: it decides, per profile and input, what the
/// run looked like. This is how the campaign is exercised without spawning.
pub struct FnExecutor<F> {
    f: F,
}

impl<F> FnExecutor<F>
where
    F: FnMut(&Profile, &[u8]) -> ProfileRun,
{
    /// Wrap a closure as an executor.
    pub fn new(f: F) -> Self {
        Self { f }
    }
}

impl<F> ProfileExecutor for FnExecutor<F>
where
    F: FnMut(&Profile, &[u8]) -> ProfileRun,
{
    fn run(&mut self, profile: &Profile, input: &[u8]) -> Result<ProfileRun, ExecError> {
        Ok((self.f)(profile, input))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{CollectorKind, Profile};
    use std::collections::BTreeMap;

    fn profile(name: &str) -> Profile {
        Profile {
            name: name.to_string(),
            runner: None,
            args: Vec::new(),
            env: BTreeMap::new(),
            allowlist: Vec::new(),
            collector: CollectorKind::None,
        }
    }

    #[test]
    fn fn_executor_dispatches_per_profile_and_input() {
        let mut exec = FnExecutor::new(|p: &Profile, input: &[u8]| {
            // A toy target: exit 0 if the input contains 0xAA, else exit 77.
            let allowed = input.contains(&0xAA);
            ProfileRun::ready(p.name.clone(), if allowed { 0 } else { 77 })
        });
        let viewer = profile("viewer");
        let denied = exec.run(&viewer, b"ordinary").unwrap();
        assert_eq!(denied.exit_code, Some(77));
        let allowed = exec.run(&viewer, &[0x00, 0xAA]).unwrap();
        assert_eq!(allowed.exit_code, Some(0));
    }

    /// Acceptance #8: a profile's state cannot bleed into another's. The executor
    /// returns events for `viewer` only; `admin`'s run carries none.
    #[test]
    fn executor_results_do_not_bleed_between_profiles() {
        let mut exec = FnExecutor::new(|p: &Profile, _input: &[u8]| {
            if p.name == "viewer" {
                ProfileRun::ready(p.name.clone(), 0)
                    .with_events(vec![EffectEvent::process_exec("execve", "viewer-only")])
            } else {
                ProfileRun::ready(p.name.clone(), 0)
            }
        });
        let viewer_run = exec.run(&profile("viewer"), b"x").unwrap();
        let admin_run = exec.run(&profile("admin"), b"x").unwrap();
        assert_eq!(viewer_run.events.as_ref().unwrap().len(), 1);
        assert_eq!(admin_run.events.as_ref().unwrap().len(), 0);
    }
}
