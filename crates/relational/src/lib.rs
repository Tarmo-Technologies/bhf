// SPDX-License-Identifier: Apache-2.0

//! Coverage-guided relational policy fuzzing — pure core.
//!
//! This crate is the self-contained, I/O-free core for a *relational* fuzzing
//! campaign: one generated testcase is run across several named launch/session
//! **profiles** (differing in runner, args, environment, entitlements,
//! allowlists and secret references) and a set of declarative **relational
//! predicates** is evaluated over each profile's observed behaviour. The
//! evaluator catches both unexpected *divergence* and unexpected *equivalence*
//! against an explicit policy, and maps relation violations to stable-signature
//! relational [`RelationFinding`]s.
//!
//! Scope and seams (deliberate):
//!
//! * The crate performs **no I/O, no subprocess spawning, no clock reads and no
//!   coverage-shm access**. Cross-profile execution is abstracted behind the
//!   [`ProfileExecutor`] trait; the crate ships an in-process [`FnExecutor`] for
//!   tests and leaves the real (process-spawning, LD_PRELOAD-collecting) executor
//!   to a downstream driver.
//! * The observation model defines its **own** minimal effect-event / semantic /
//!   authorization types ([`EffectEvent`], [`SemanticHit`], [`AuthDecision`]) so
//!   the crate does not depend on any collector or oracle crate. A downstream
//!   driver adapts its real event source (e.g. a process-exec trace) into
//!   [`EffectEvent`] at the seam.
//! * `semantic_hits` and `auth_decisions` are optional, empty-by-default seams:
//!   they are populated by downstream semantic/authorization collectors when
//!   those land. The [`Require::External`] predicate is the external-comparator
//!   seam and evaluates to [`RelationOutcome::Inconclusive`] until a comparator
//!   is wired, rather than fabricating a verdict.
//!
//! Downstream consumers (importers / SARIF / vulnerability-management tooling)
//! are referred to only generically; no product name appears anywhere.

pub mod campaign;
pub mod coverage;
pub mod executor;
pub mod finding;
pub mod mutate;
pub mod observation;
pub mod predicate;
pub mod redact;
pub mod schema;

pub use campaign::{
    minimize, replay, run_campaign, CampaignOptions, CampaignReport, MinimizeResult, OutcomeTally,
    ReplayResult,
};
pub use coverage::{popcount, UnionBitmap};
pub use executor::{ExecError, FnExecutor, ProfileExecutor, ProfileRun};
pub use finding::{rule_id_for_kind, FindingKind, FindingPaths, RelationFinding};
pub use mutate::{ByteMutator, Rng};
pub use observation::{
    AuthDecision, AuthResult, EffectEvent, EffectKind, Observation, ProfileStatus, RunState,
    SemanticHit, SemanticVerdict, Stream,
};
pub use predicate::{
    evaluate, evaluate_one, Evaluation, ExternalVerdict, RelationOutcome, Violation,
};
pub use schema::{
    CollectorKind, Cond, EnvValue, Field, Predicate, Profile, RelationalConfig, Require,
    SchemaError, Selector, StatusMap, SCHEMA_V1,
};

/// Stable crate identifier, handy for diagnostics and log lines.
#[must_use]
pub fn crate_name() -> &'static str {
    "relational"
}

/// SHA-256 of `bytes`, lowercase hex. Shared helper for testcase/policy hashing.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
