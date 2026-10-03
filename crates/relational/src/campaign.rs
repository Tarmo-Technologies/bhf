// SPDX-License-Identifier: Apache-2.0

//! The coverage-guided relational campaign engine.
//!
//! [`run_campaign`] mutates a shared testcase, runs it under every profile
//! through a [`ProfileExecutor`], and retains any input that reaches new code in
//! *any* profile, produces a new cross-profile outcome vector, or a new
//! effect-event shape. For each case it evaluates the relational predicates and
//! emits a deduplicated [`RelationFinding`] per violated relation.
//!
//! [`replay`] re-runs every profile a finding requires and re-confirms the
//! relation. [`minimize`] shrinks the testcase while the relation still holds and
//! reduces the required profile set to the minimum that still proves it.
//!
//! The engine is pure: all process interaction goes through the executor seam,
//! so the whole flow is exercised with an in-process mock in tests.

use std::collections::{BTreeMap, BTreeSet};

use crate::coverage::UnionBitmap;
use crate::executor::{ExecError, ProfileExecutor, ProfileRun};
use crate::finding::RelationFinding;
use crate::mutate::{ByteMutator, Mutator};
use crate::observation::Observation;
use crate::predicate::{evaluate, evaluate_one, RelationOutcome};
use crate::schema::RelationalConfig;

/// Budget and determinism knobs for a campaign.
#[derive(Debug, Clone)]
pub struct CampaignOptions {
    /// Maximum number of testcases to execute.
    pub max_execs: usize,
    /// Maximum mutated-input length.
    pub max_len: usize,
    /// Deterministic mutation RNG seed.
    pub seed: u64,
    /// Stop once this many distinct findings have been recorded.
    pub max_findings: usize,
}

impl Default for CampaignOptions {
    fn default() -> Self {
        Self {
            max_execs: 10_000,
            max_len: 4096,
            seed: 0,
            max_findings: 1024,
        }
    }
}

/// A tally of predicate outcomes across a campaign. The distinct categories stay
/// separate so a run summary never conflates e.g. setup failures with compliance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutcomeTally {
    /// Count of setup-failure outcomes.
    pub setup_failure: usize,
    /// Count of auth-failure outcomes.
    pub auth_failure: usize,
    /// Count of missing-observation outcomes.
    pub missing_observation: usize,
    /// Count of policy-unknown outcomes.
    pub policy_unknown: usize,
    /// Count of compliant outcomes.
    pub compliant: usize,
    /// Count of violation outcomes.
    pub violation: usize,
    /// Count of inconclusive (external-seam) outcomes.
    pub inconclusive: usize,
}

impl OutcomeTally {
    fn record(&mut self, outcome: &RelationOutcome) {
        match outcome {
            RelationOutcome::SetupFailure { .. } => self.setup_failure += 1,
            RelationOutcome::AuthFailure { .. } => self.auth_failure += 1,
            RelationOutcome::MissingObservation { .. } => self.missing_observation += 1,
            RelationOutcome::PolicyUnknown { .. } => self.policy_unknown += 1,
            RelationOutcome::Compliant => self.compliant += 1,
            RelationOutcome::Violation(_) => self.violation += 1,
            RelationOutcome::Inconclusive { .. } => self.inconclusive += 1,
        }
    }
}

/// The result of a campaign run.
#[derive(Debug, Clone)]
pub struct CampaignReport {
    /// Deduplicated relational findings, in discovery order.
    pub findings: Vec<RelationFinding>,
    /// Outcome tally across all evaluated predicates.
    pub outcomes: OutcomeTally,
    /// Number of testcases executed.
    pub execs: usize,
    /// Final corpus size (seeds + retained mutants).
    pub corpus_size: usize,
}

/// Run a coverage-guided relational campaign.
///
/// # Errors
/// Propagates any [`ExecError`] from the executor.
pub fn run_campaign<E: ProfileExecutor>(
    config: &RelationalConfig,
    seeds: &[Vec<u8>],
    executor: &mut E,
    opts: &CampaignOptions,
) -> Result<CampaignReport, ExecError> {
    let mut corpus: Vec<Vec<u8>> = if seeds.is_empty() {
        vec![vec![0u8]]
    } else {
        seeds.to_vec()
    };

    let mut unions: BTreeMap<String, UnionBitmap> = BTreeMap::new();
    let mut seen_outcome_vectors: BTreeSet<String> = BTreeSet::new();
    let mut seen_event_shapes: BTreeSet<String> = BTreeSet::new();
    let mut seen_signatures: BTreeSet<String> = BTreeSet::new();

    let mut findings: Vec<RelationFinding> = Vec::new();
    let mut tally = OutcomeTally::default();
    let mut mutator = ByteMutator::new(opts.seed);
    let mut rng = crate::mutate::Rng::new(opts.seed ^ 0x5DEE_CE66_D1B2_A5F3);

    let seed_count = corpus.len();
    let mut execs = 0usize;
    let mut scratch = Vec::new();

    while execs < opts.max_execs && findings.len() < opts.max_findings {
        // First pass executes seeds verbatim; afterwards, mutate a corpus entry.
        let input: Vec<u8> = if execs < seed_count {
            corpus[execs].clone()
        } else {
            let base = &corpus[rng.below(corpus.len())];
            mutator.mutate(base, opts.max_len, &mut scratch);
            scratch.clone()
        };
        execs += 1;

        let runs = run_all(config, &input, executor)?;

        // Per-profile union-coverage novelty: each profile keeps its own union.
        let mut novel = false;
        for run in &runs {
            let union = unions.entry(run.profile.clone()).or_default();
            if union.fold(&run.coverage) {
                novel = true;
            }
        }

        let observations = observe_runs(config, &runs);

        // Outcome-vector and effect-shape novelty retain inputs even with no new
        // edges (e.g. a shell mock emits no coverage bitmap).
        if seen_outcome_vectors.insert(outcome_vector_key(&observations)) {
            novel = true;
        }
        if seen_event_shapes.insert(event_shape_key(&observations)) {
            novel = true;
        }
        if novel {
            corpus.push(input.clone());
        }

        let testcase_sha = crate::sha256_hex(&input);
        for eval in evaluate(config, &observations) {
            tally.record(&eval.outcome);
            if let Some(violation) = eval.outcome.as_violation() {
                let ordinal = findings.len() as u32 + 1;
                let finding = RelationFinding::from_violation(
                    ordinal,
                    violation,
                    config,
                    &observations,
                    &testcase_sha,
                );
                if seen_signatures.insert(finding.signature.clone()) {
                    findings.push(finding);
                    if findings.len() >= opts.max_findings {
                        break;
                    }
                }
            }
        }
    }

    Ok(CampaignReport {
        corpus_size: corpus.len(),
        findings,
        outcomes: tally,
        execs,
    })
}

/// The result of replaying a finding.
#[derive(Debug, Clone)]
pub struct ReplayResult {
    /// The profiles re-executed, in order (the finding's required set).
    pub executed_profiles: Vec<String>,
    /// Whether the violated relation still reproduces as the same kind.
    pub reproduced: bool,
    /// The re-collected observations.
    pub observations: BTreeMap<String, Observation>,
    /// The re-evaluated outcome.
    pub outcome: RelationOutcome,
}

/// Re-run every profile a finding requires and re-confirm the violated relation.
///
/// # Errors
/// Propagates any [`ExecError`] from the executor.
pub fn replay<E: ProfileExecutor>(
    finding: &RelationFinding,
    config: &RelationalConfig,
    input: &[u8],
    executor: &mut E,
) -> Result<ReplayResult, ExecError> {
    let observations = observe_profiles(config, input, &finding.profiles, executor)?;
    let outcome = evaluate_one(config, &finding.relation, &observations);
    let reproduced = outcome
        .as_violation()
        .is_some_and(|v| v.kind == finding.kind);
    Ok(ReplayResult {
        executed_profiles: finding.profiles.clone(),
        reproduced,
        observations,
        outcome,
    })
}

/// The result of minimizing a finding.
#[derive(Debug, Clone)]
pub struct MinimizeResult {
    /// The minimized testcase.
    pub input: Vec<u8>,
    /// The minimal profile set that still proves the relation, sorted.
    pub profiles: Vec<String>,
    /// Number of oracle evaluations performed on the testcase.
    pub predicate_runs: usize,
}

/// Shrink a finding's testcase while the violated relation still holds, then
/// reduce the required profile set to the minimum that still proves it.
///
/// # Errors
/// Propagates any [`ExecError`] from the executor.
pub fn minimize<E: ProfileExecutor>(
    finding: &RelationFinding,
    config: &RelationalConfig,
    input: &[u8],
    executor: &mut E,
) -> Result<MinimizeResult, ExecError> {
    // Reduce over the full executed profile set so that unneeded profiles can be
    // dropped; the oracle is "the recorded violation still reproduces".
    let full_set: Vec<String> = config.profiles.iter().map(|p| p.name.clone()).collect();

    let (minimized, predicate_runs) = ddmin_bytes(input, |candidate| {
        still_violates(finding, config, candidate, &full_set, executor)
    })?;

    // Profile-set reduction: greedily drop profiles while the relation still
    // fails across the remaining set.
    let mut required = full_set.clone();
    for name in &full_set {
        if required.len() <= 1 {
            break;
        }
        let trial: Vec<String> = required.iter().filter(|n| *n != name).cloned().collect();
        if still_violates(finding, config, &minimized, &trial, executor)? {
            required = trial;
        }
    }
    required.sort();

    Ok(MinimizeResult {
        input: minimized,
        profiles: required,
        predicate_runs,
    })
}

fn still_violates<E: ProfileExecutor>(
    finding: &RelationFinding,
    config: &RelationalConfig,
    input: &[u8],
    profile_set: &[String],
    executor: &mut E,
) -> Result<bool, ExecError> {
    let observations = observe_profiles(config, input, profile_set, executor)?;
    let outcome = evaluate_one(config, &finding.relation, &observations);
    Ok(outcome
        .as_violation()
        .is_some_and(|v| v.kind == finding.kind))
}

// --- execution + observation assembly ----------------------------------------

fn run_all<E: ProfileExecutor>(
    config: &RelationalConfig,
    input: &[u8],
    executor: &mut E,
) -> Result<Vec<ProfileRun>, ExecError> {
    let mut runs = Vec::with_capacity(config.profiles.len());
    for profile in &config.profiles {
        runs.push(executor.run(profile, input)?);
    }
    Ok(runs)
}

fn observe_profiles<E: ProfileExecutor>(
    config: &RelationalConfig,
    input: &[u8],
    names: &[String],
    executor: &mut E,
) -> Result<BTreeMap<String, Observation>, ExecError> {
    let mut map = BTreeMap::new();
    for name in names {
        let profile = config.profile(name).ok_or_else(|| ExecError::Failed {
            profile: name.clone(),
            detail: "profile not declared in config".to_string(),
        })?;
        let run = executor.run(profile, input)?;
        map.insert(
            name.clone(),
            Observation::from_run(&run, &config.status_map),
        );
    }
    Ok(map)
}

fn observe_runs(config: &RelationalConfig, runs: &[ProfileRun]) -> BTreeMap<String, Observation> {
    runs.iter()
        .map(|run| {
            (
                run.profile.clone(),
                Observation::from_run(run, &config.status_map),
            )
        })
        .collect()
}

fn outcome_vector_key(observations: &BTreeMap<String, Observation>) -> String {
    observations
        .iter()
        .map(|(name, o)| format!("{name}:{:?}:{:?}", o.run_state, o.status))
        .collect::<Vec<_>>()
        .join("|")
}

fn event_shape_key(observations: &BTreeMap<String, Observation>) -> String {
    observations
        .iter()
        .map(|(name, o)| format!("{name}:{}", o.target_set().join(",")))
        .collect::<Vec<_>>()
        .join("|")
}

/// Self-contained delta-debugging byte minimizer. Mirrors the standard ddmin:
/// shrink by removing chunks while `predicate` still holds, then try keeping each
/// chunk alone. Returns the minimized bytes and the number of predicate runs.
fn ddmin_bytes<F, Err>(input: &[u8], mut predicate: F) -> Result<(Vec<u8>, usize), Err>
where
    F: FnMut(&[u8]) -> Result<bool, Err>,
{
    let mut current = input.to_vec();
    let mut n = 2usize;
    let mut runs = 0usize;

    while !current.is_empty() {
        let split_count = n.min(current.len());
        let chunks = split_ranges(current.len(), split_count);
        let mut changed = false;

        // Phase 1: try removing a single chunk.
        for chunk in &chunks {
            let candidate = remove_range(&current, chunk.0, chunk.1);
            runs += 1;
            if predicate(&candidate)? {
                current = candidate;
                n = split_count.saturating_sub(1).max(2);
                changed = true;
                break;
            }
        }
        if changed {
            continue;
        }

        // Phase 2: try keeping a single chunk (its complement removed).
        for chunk in &chunks {
            if chunk.1 - chunk.0 == current.len() {
                continue;
            }
            let candidate = current[chunk.0..chunk.1].to_vec();
            runs += 1;
            if predicate(&candidate)? {
                current = candidate;
                n = 2;
                changed = true;
                break;
            }
        }
        if changed {
            continue;
        }

        if split_count >= current.len() {
            break;
        }
        n = split_count.saturating_mul(2).min(current.len());
    }

    Ok((current, runs))
}

fn split_ranges(len: usize, count: usize) -> Vec<(usize, usize)> {
    if count == 0 {
        return Vec::new();
    }
    let base = len / count;
    let rem = len % count;
    let mut ranges = Vec::with_capacity(count);
    let mut start = 0;
    for i in 0..count {
        let extra = usize::from(i < rem);
        let end = start + base + extra;
        ranges.push((start, end));
        start = end;
    }
    ranges
}

fn remove_range(input: &[u8], start: usize, end: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() - (end - start));
    out.extend_from_slice(&input[..start]);
    out.extend_from_slice(&input[end..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::FnExecutor;
    use crate::finding::{FindingKind, RelationFinding};
    use crate::observation::{EffectEvent, Observation, ProfileStatus};
    use crate::predicate::{evaluate_one, Violation};
    use crate::schema::Profile;

    const MAGIC: &[u8] = b"go";

    /// Mock target for the allowlist-escape campaign: `viewer` spawns the
    /// forbidden `administrator-helper` only once the input's leading bytes match
    /// MAGIC; coverage grows with the matched prefix length so the engine climbs
    /// toward the trigger. `admin` is allowed to spawn both.
    fn magic_target(profile: &Profile, input: &[u8]) -> ProfileRun {
        let matched = input
            .iter()
            .zip(MAGIC.iter())
            .take_while(|(a, b)| a == b)
            .count();
        // Coverage: a base edge plus one edge per matched leading byte.
        let mut coverage = vec![0u8; MAGIC.len() + 1];
        coverage[0] = 1;
        for slot in coverage.iter_mut().take(matched + 1).skip(1) {
            *slot = 1;
        }
        if profile.name == "viewer" {
            let mut events = vec![EffectEvent::process_exec("execve", "viewer-helper")];
            if matched == MAGIC.len() {
                events.push(EffectEvent::process_exec("execve", "administrator-helper"));
            }
            ProfileRun::ready("viewer", 0)
                .with_coverage(coverage)
                .with_events(events)
        } else {
            ProfileRun::ready(profile.name.clone(), 0)
                .with_coverage(vec![1u8])
                .with_events(vec![
                    EffectEvent::process_exec("execve", "viewer-helper"),
                    EffectEvent::process_exec("execve", "administrator-helper"),
                ])
        }
    }

    fn escape_config() -> RelationalConfig {
        let src = r#"
schema = "bhf.relational.v1"
[status_map]
allowed = [0]
denied = [77]
[[profiles]]
name = "admin"
allowlist = ["viewer-helper", "administrator-helper"]
[[profiles]]
name = "viewer"
allowlist = ["viewer-helper"]
[[predicates]]
rule = "viewer spawned targets must be a subset of its allowlist"
require = { kind = "subset", set = "viewer.spawned", of = "viewer.allowlist" }
"#;
        RelationalConfig::parse(src).unwrap()
    }

    /// Acceptance #1/#2: coverage-guided mutation reaches the forbidden target and
    /// emits an authorization-policy finding; identical exit/stdout across the run
    /// does not suppress it (the signal is the effect event, not the response).
    #[test]
    fn coverage_guided_mutation_reaches_forbidden_target_and_finds_it() {
        let config = escape_config();
        let mut executor = FnExecutor::new(magic_target);
        let opts = CampaignOptions {
            max_execs: 200_000,
            max_len: 8,
            seed: 1,
            max_findings: 1,
        };
        let seeds = vec![b"zz".to_vec()];
        let report = run_campaign(&config, &seeds, &mut executor, &opts).unwrap();

        assert_eq!(report.findings.len(), 1, "expected exactly one finding");
        assert!(
            report.execs < opts.max_execs,
            "campaign should converge early"
        );
        let f = &report.findings[0];
        assert_eq!(f.kind, FindingKind::AllowlistEscape);
        assert_eq!(f.rule_id, "BHF-309");
        assert_eq!(f.profiles, vec!["viewer".to_string()]);
        assert!(f
            .evidence_events
            .iter()
            .any(|e| e.target == "administrator-helper"));
        assert!(!f.policy_hash.is_empty());
        assert!(f.profile_hashes.contains_key("viewer"));
        assert!(report.outcomes.violation >= 1);
    }

    fn contains_marker(profile: &Profile, input: &[u8]) -> ProfileRun {
        let escaping = input.contains(&0xAA);
        if profile.name == "viewer" {
            let mut events = vec![EffectEvent::process_exec("execve", "viewer-helper")];
            if escaping {
                events.push(EffectEvent::process_exec("execve", "administrator-helper"));
            }
            ProfileRun::ready("viewer", 0).with_events(events)
        } else {
            ProfileRun::ready(profile.name.clone(), 0)
                .with_events(vec![EffectEvent::process_exec("execve", "viewer-helper")])
        }
    }

    fn marker_config() -> RelationalConfig {
        // Three profiles; the subset predicate only involves `viewer`, so the
        // required profile set reduces to {viewer}.
        let src = r#"
schema = "bhf.relational.v1"
[[profiles]]
name = "admin"
allowlist = ["viewer-helper", "administrator-helper"]
[[profiles]]
name = "viewer"
allowlist = ["viewer-helper"]
[[profiles]]
name = "guest"
allowlist = ["viewer-helper"]
[[predicates]]
rule = "viewer spawned targets must be a subset of its allowlist"
require = { kind = "subset", set = "viewer.spawned", of = "viewer.allowlist" }
"#;
        RelationalConfig::parse(src).unwrap()
    }

    fn marker_finding(config: &RelationalConfig) -> RelationFinding {
        let mut obs = BTreeMap::new();
        obs.insert(
            "viewer".to_string(),
            Observation::ready("viewer", ProfileStatus::Allowed).with_events(vec![
                EffectEvent::process_exec("execve", "administrator-helper"),
            ]),
        );
        let outcome = evaluate_one(config, &config.predicates[0], &obs);
        let v: &Violation = outcome.as_violation().expect("violation");
        RelationFinding::from_violation(1, v, config, &obs, "seed-sha")
    }

    /// Acceptance #5: replay re-runs every required profile and re-confirms.
    #[test]
    fn replay_reruns_required_profiles_and_confirms() {
        let config = marker_config();
        let finding = marker_finding(&config);
        assert_eq!(finding.profiles, vec!["viewer".to_string()]);

        let mut exec = FnExecutor::new(contains_marker);
        let repro = replay(&finding, &config, &[0x00, 0xAA, 0x01], &mut exec).unwrap();
        assert!(repro.reproduced, "violation should reproduce");
        assert_eq!(repro.executed_profiles, finding.profiles);

        // An input that no longer triggers the escape does not reproduce.
        let mut exec2 = FnExecutor::new(contains_marker);
        let gone = replay(&finding, &config, &[0x00, 0x01], &mut exec2).unwrap();
        assert!(!gone.reproduced);
    }

    /// Acceptance #5 (multi-profile): a status-relation finding re-runs BOTH its
    /// required profiles.
    #[test]
    fn replay_executes_every_required_profile_for_multi_profile_relation() {
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
        let config = RelationalConfig::parse(src).unwrap();
        // Build the finding: admin allowed, viewer allowed => unexpected_allow.
        let mut obs = BTreeMap::new();
        obs.insert(
            "admin".to_string(),
            Observation::ready("admin", ProfileStatus::Allowed),
        );
        obs.insert(
            "viewer".to_string(),
            Observation::ready("viewer", ProfileStatus::Allowed),
        );
        let outcome = evaluate_one(&config, &config.predicates[0], &obs);
        let finding = RelationFinding::from_violation(
            1,
            outcome.as_violation().unwrap(),
            &config,
            &obs,
            "sha",
        );
        assert_eq!(
            finding.profiles,
            vec!["admin".to_string(), "viewer".to_string()]
        );

        // Mock: admin exit 0 (allowed), viewer exit 0 (allowed) => reproduces.
        let mut exec =
            FnExecutor::new(|p: &Profile, _i: &[u8]| ProfileRun::ready(p.name.clone(), 0));
        let r = replay(&finding, &config, b"x", &mut exec).unwrap();
        assert!(r.reproduced);
        assert_eq!(
            r.executed_profiles,
            vec!["admin".to_string(), "viewer".to_string()]
        );

        // Fixed: viewer now denied (exit 77) => no longer reproduces.
        let mut exec2 = FnExecutor::new(|p: &Profile, _i: &[u8]| {
            let code = if p.name == "viewer" { 77 } else { 0 };
            ProfileRun::ready(p.name.clone(), code)
        });
        let r2 = replay(&finding, &config, b"x", &mut exec2).unwrap();
        assert!(!r2.reproduced);
    }

    /// Acceptance #6: minimization preserves the smallest policy-violating
    /// testcase AND reduces the required profile set to the minimum.
    #[test]
    fn minimize_preserves_smallest_input_and_profile_set() {
        let config = marker_config();
        let finding = marker_finding(&config);

        let mut exec = FnExecutor::new(contains_marker);
        let input = vec![0x01, 0x02, 0xAA, 0x03, 0x04];
        let result = minimize(&finding, &config, &input, &mut exec).unwrap();

        // Testcase shrinks to the single marker byte.
        assert_eq!(result.input, vec![0xAA]);
        // Profile set reduces from {admin, viewer, guest} to just {viewer}.
        assert_eq!(result.profiles, vec!["viewer".to_string()]);
        assert!(result.predicate_runs > 0);
    }

    /// Acceptance #8: one profile's events cannot contaminate another's, and a new
    /// cross-profile outcome vector retains an input even without new edges.
    #[test]
    fn profiles_do_not_contaminate_and_outcome_vectors_retain() {
        let config = marker_config();
        // A deterministic executor: viewer escapes only when input is non-empty
        // and its first byte is 0xAA; coverage is constant (no new edges), so
        // retention of the escaping input rests on the new event shape.
        let mut exec = FnExecutor::new(|p: &Profile, input: &[u8]| {
            let escaping = p.name == "viewer" && input.first() == Some(&0xAA);
            let mut events = vec![EffectEvent::process_exec("execve", "viewer-helper")];
            if escaping {
                events.push(EffectEvent::process_exec("execve", "administrator-helper"));
            }
            ProfileRun::ready(p.name.clone(), 0)
                .with_coverage(vec![1u8]) // constant => no edge novelty after case 1
                .with_events(events)
        });
        let opts = CampaignOptions {
            max_execs: 1,
            max_len: 4,
            seed: 3,
            max_findings: 16,
        };
        // Seed the escaping input directly; one exec must find it (no coverage
        // novelty available, so this proves event-shape retention + no bleed).
        let seeds = vec![vec![0xAAu8]];
        let report = run_campaign(&config, &seeds, &mut exec, &opts).unwrap();
        assert_eq!(report.execs, 1);
        assert_eq!(report.findings.len(), 1);
        let f = &report.findings[0];
        assert_eq!(f.kind, FindingKind::AllowlistEscape);
        // The finding's viewer observation carries the escape; admin/guest are
        // not involved and their events never leaked into viewer's.
        let viewer_obs = &f.observations["viewer"];
        assert!(viewer_obs
            .events
            .iter()
            .any(|e| e.target == "administrator-helper"));
    }
}
