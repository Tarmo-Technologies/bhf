// SPDX-License-Identifier: Apache-2.0

//! The relational campaign config/schema (`bhf.relational.v1`).
//!
//! A [`RelationalConfig`] declares named launch/session [`Profile`]s — each
//! differing in runner, args, environment (literal or [`EnvValue::SecretRef`]),
//! declared target allowlist and collector — plus a set of relational
//! [`Predicate`]s. Secret references use a configurable prefix (default `lab:`);
//! the config never holds a *resolved* secret, only the stable reference id.
//!
//! The config is pure data: [`RelationalConfig::policy_hash`] and
//! [`RelationalConfig::profile_hash`] produce stable SHA-256 digests over the
//! canonical JSON serialization, used in relational findings.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};

use crate::finding::FindingKind;
use crate::observation::ProfileStatus;

/// The one schema string this crate accepts.
pub const SCHEMA_V1: &str = "bhf.relational.v1";

/// The default secret-reference prefix.
pub const DEFAULT_SECRET_PREFIX: &str = "lab:";

/// Errors from parsing/validating a [`RelationalConfig`].
#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    /// The TOML did not parse.
    #[error("relational config TOML parse error: {0}")]
    Parse(#[from] toml::de::Error),
    /// The `schema` field was not the supported value.
    #[error("unsupported schema {found:?}; expected {expected:?}")]
    UnsupportedSchema {
        /// The schema string found in the config.
        found: String,
        /// The schema string this crate supports.
        expected: &'static str,
    },
    /// Two profiles share a name.
    #[error("duplicate profile name {0:?}")]
    DuplicateProfile(String),
    /// A predicate/selector references a profile that is not declared.
    #[error("predicate references unknown profile {0:?}")]
    UnknownProfile(String),
    /// A selector string was malformed (not `profile.field`, or unknown field).
    #[error("invalid selector {0:?}")]
    InvalidSelector(String),
    /// The config declared no profiles.
    #[error("relational config declares no profiles")]
    NoProfiles,
}

/// How an environment value is supplied to a profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvValue {
    /// A literal value.
    Literal(String),
    /// A reference to a secret resolved by the driver at run time. The stored
    /// string is the stable reference id (including its prefix, e.g.
    /// `lab:admin-token`); the resolved value never appears here.
    SecretRef(String),
}

impl EnvValue {
    /// Classify a raw TOML env string into literal or secret-ref by prefix.
    fn classify(raw: &str, secret_prefix: &str) -> Self {
        if raw.starts_with(secret_prefix) {
            EnvValue::SecretRef(raw.to_string())
        } else {
            EnvValue::Literal(raw.to_string())
        }
    }

    /// The stable reference id if this is a secret reference.
    #[must_use]
    pub fn secret_ref(&self) -> Option<&str> {
        match self {
            EnvValue::SecretRef(id) => Some(id.as_str()),
            EnvValue::Literal(_) => None,
        }
    }
}

/// The event collector to use for a profile. A seam for a future
/// platform-neutral collector; the pure crate does not act on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorKind {
    /// Auto-select a collector.
    #[default]
    Auto,
    /// Use the runtime trace collector.
    Runtrace,
    /// Collect no effect events.
    None,
}

/// A named launch/session profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Profile {
    /// The profile's unique name.
    pub name: String,
    /// Optional runner prefix (e.g. an interpreter or wrapper).
    pub runner: Option<String>,
    /// Arguments passed to the runner/target.
    pub args: Vec<String>,
    /// Environment overlay (literal or secret-ref), key-ordered.
    pub env: BTreeMap<String, EnvValue>,
    /// Declared process/target allowlist for subset predicates.
    pub allowlist: Vec<String>,
    /// The collector to use (seam).
    pub collector: CollectorKind,
}

/// Exit-code → status mapping. Anything unmapped is [`ProfileStatus::Unknown`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StatusMap {
    /// Exit codes meaning the operation was allowed.
    #[serde(default)]
    pub allowed: Vec<i32>,
    /// Exit codes meaning the operation was denied.
    #[serde(default)]
    pub denied: Vec<i32>,
    /// Exit codes meaning a bootstrap/session/auth step failed.
    #[serde(default)]
    pub auth_failure: Vec<i32>,
}

impl StatusMap {
    /// Map an exit code to a [`ProfileStatus`].
    #[must_use]
    pub fn classify(&self, exit: i32) -> ProfileStatus {
        if self.allowed.contains(&exit) {
            ProfileStatus::Allowed
        } else if self.denied.contains(&exit) {
            ProfileStatus::Denied
        } else {
            ProfileStatus::Unknown
        }
    }

    /// Whether an exit code denotes an auth/session-bootstrap failure.
    #[must_use]
    pub fn is_auth_failure(&self, exit: i32) -> bool {
        self.auth_failure.contains(&exit)
    }
}

/// A field of a profile's observation that a selector can reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    /// The set of process/command targets observed.
    Spawned,
    /// The profile's declared allowlist (from config).
    Allowlist,
    /// The derived authorization status.
    Status,
    /// The normalized response digest.
    Response,
    /// The edge-coverage scalar.
    Edges,
}

impl Field {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "spawned" => Field::Spawned,
            "allowlist" => Field::Allowlist,
            "status" => Field::Status,
            "response" => Field::Response,
            "edges" => Field::Edges,
            _ => return None,
        })
    }

    fn as_str(self) -> &'static str {
        match self {
            Field::Spawned => "spawned",
            Field::Allowlist => "allowlist",
            Field::Status => "status",
            Field::Response => "response",
            Field::Edges => "edges",
        }
    }
}

/// A `profile.field` reference into an observation, e.g. `viewer.spawned`.
/// Serializes to/from the dotted string form for ergonomic TOML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selector {
    /// The profile the selector reads from.
    pub profile: String,
    /// The field read.
    pub field: Field,
}

impl Selector {
    /// Parse `profile.field`.
    fn parse(s: &str) -> Result<Self, SchemaError> {
        let (profile, field) = s
            .split_once('.')
            .ok_or_else(|| SchemaError::InvalidSelector(s.to_string()))?;
        if profile.is_empty() {
            return Err(SchemaError::InvalidSelector(s.to_string()));
        }
        let field =
            Field::parse(field).ok_or_else(|| SchemaError::InvalidSelector(s.to_string()))?;
        Ok(Selector {
            profile: profile.to_string(),
            field,
        })
    }

    /// The dotted string form.
    #[must_use]
    pub fn dotted(&self) -> String {
        format!("{}.{}", self.profile, self.field.as_str())
    }
}

impl Serialize for Selector {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.dotted())
    }
}

impl<'de> Deserialize<'de> for Selector {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Selector::parse(&s).map_err(D::Error::custom)
    }
}

/// The relation a predicate requires to hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Require {
    /// `profile`'s status must equal `status` (e.g. "viewer must be denied").
    StatusRelation {
        /// The profile whose status is constrained.
        profile: String,
        /// The required status.
        status: ProfileStatus,
    },
    /// The `set` selector's values must be a subset of `of`'s (allowlist check).
    Subset {
        /// The observed set (e.g. `viewer.spawned`).
        set: Selector,
        /// The declared superset (e.g. `viewer.allowlist`).
        of: Selector,
    },
    /// All `selectors` must observe equal values (unexpected divergence if not).
    Equal {
        /// The selectors that must be equal.
        selectors: Vec<Selector>,
    },
    /// All `selectors` must differ (unexpected equivalence if they are equal).
    Differ {
        /// The selectors that must differ.
        selectors: Vec<Selector>,
    },
    /// An external comparator decides (seam). Evaluates to inconclusive until a
    /// comparator is wired, rather than fabricating a verdict.
    External {
        /// The named external comparator.
        comparator: String,
    },
}

/// A guard controlling whether a predicate's relation is required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Cond {
    /// Always required.
    Always,
    /// Required only when `profile` has `status`.
    StatusIs {
        /// The guard profile.
        profile: String,
        /// The guard status.
        status: ProfileStatus,
    },
}

/// A declarative relational predicate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Predicate {
    /// Human label, carried verbatim into any finding.
    pub rule: String,
    /// Optional guard; absent means always required.
    #[serde(default)]
    pub when: Option<Cond>,
    /// The relation that must hold.
    pub require: Require,
    /// Optional explicit finding kind; defaults are derived from `require`.
    #[serde(default)]
    pub kind: Option<FindingKind>,
}

impl Predicate {
    /// The set of profiles this predicate reads from (via `require` and `when`).
    #[must_use]
    pub fn involved_profiles(&self) -> Vec<String> {
        let mut set: BTreeSet<String> = BTreeSet::new();
        match &self.require {
            Require::StatusRelation { profile, .. } => {
                set.insert(profile.clone());
            }
            Require::Subset { set: s, of } => {
                set.insert(s.profile.clone());
                set.insert(of.profile.clone());
            }
            Require::Equal { selectors } | Require::Differ { selectors } => {
                for sel in selectors {
                    set.insert(sel.profile.clone());
                }
            }
            Require::External { .. } => {}
        }
        if let Some(Cond::StatusIs { profile, .. }) = &self.when {
            set.insert(profile.clone());
        }
        set.into_iter().collect()
    }
}

/// A parsed, validated relational campaign configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RelationalConfig {
    /// The schema string (always [`SCHEMA_V1`] once parsed).
    pub schema: String,
    /// The declared profiles.
    pub profiles: Vec<Profile>,
    /// The relational predicates.
    pub predicates: Vec<Predicate>,
    /// Exit-code → status mapping.
    pub status_map: StatusMap,
    /// The secret-reference prefix in effect.
    pub secret_prefix: String,
}

// --- raw (pre-validation) deserialization shapes ------------------------------

#[derive(Deserialize)]
struct RawProfile {
    name: String,
    #[serde(default)]
    runner: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    allowlist: Vec<String>,
    #[serde(default)]
    collector: CollectorKind,
}

#[derive(Deserialize)]
struct RawConfig {
    schema: String,
    #[serde(default)]
    profiles: Vec<RawProfile>,
    #[serde(default)]
    predicates: Vec<Predicate>,
    #[serde(default)]
    status_map: StatusMap,
    #[serde(default)]
    secret_prefix: Option<String>,
}

impl RelationalConfig {
    /// Parse and validate a `bhf.relational.v1` TOML config.
    ///
    /// # Errors
    /// Returns a [`SchemaError`] for a bad schema string, duplicate profile
    /// names, predicates that reference unknown profiles, malformed selectors or
    /// an empty profile set.
    pub fn parse(toml_src: &str) -> Result<Self, SchemaError> {
        let raw: RawConfig = toml::from_str(toml_src)?;
        if raw.schema != SCHEMA_V1 {
            return Err(SchemaError::UnsupportedSchema {
                found: raw.schema,
                expected: SCHEMA_V1,
            });
        }
        if raw.profiles.is_empty() {
            return Err(SchemaError::NoProfiles);
        }
        let secret_prefix = raw
            .secret_prefix
            .unwrap_or_else(|| DEFAULT_SECRET_PREFIX.to_string());

        let mut names: BTreeSet<String> = BTreeSet::new();
        let mut profiles = Vec::with_capacity(raw.profiles.len());
        for rp in raw.profiles {
            if !names.insert(rp.name.clone()) {
                return Err(SchemaError::DuplicateProfile(rp.name));
            }
            let env = rp
                .env
                .into_iter()
                .map(|(k, v)| (k, EnvValue::classify(&v, &secret_prefix)))
                .collect();
            profiles.push(Profile {
                name: rp.name,
                runner: rp.runner,
                args: rp.args,
                env,
                allowlist: rp.allowlist,
                collector: rp.collector,
            });
        }

        // Validate that every profile referenced by a predicate exists.
        for pred in &raw.predicates {
            for prof in pred.involved_profiles() {
                if !names.contains(&prof) {
                    return Err(SchemaError::UnknownProfile(prof));
                }
            }
        }

        Ok(RelationalConfig {
            schema: raw.schema,
            profiles,
            predicates: raw.predicates,
            status_map: raw.status_map,
            secret_prefix,
        })
    }

    /// Look up a profile by name.
    #[must_use]
    pub fn profile(&self, name: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.name == name)
    }

    /// Stable SHA-256 over the canonical JSON of the whole policy. Contains only
    /// secret *references*, never resolved values, so it is safe to persist.
    #[must_use]
    pub fn policy_hash(&self) -> String {
        let json = serde_json::to_vec(self).expect("config serializes");
        crate::sha256_hex(&json)
    }

    /// Stable SHA-256 over the canonical JSON of one profile. Returns `None` if
    /// the profile is not declared.
    #[must_use]
    pub fn profile_hash(&self, name: &str) -> Option<String> {
        let profile = self.profile(name)?;
        let json = serde_json::to_vec(profile).expect("profile serializes");
        Some(crate::sha256_hex(&json))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
schema = "bhf.relational.v1"

[status_map]
allowed = [0]
denied = [77]
auth_failure = [66]

[[profiles]]
name = "admin"
runner = "/bin/sh"
args = ["launcher.sh", "admin"]
allowlist = ["admin-helper", "viewer-helper"]
collector = "runtrace"
[profiles.env]
ROLE = "admin"
TOKEN = "lab:admin-token"

[[profiles]]
name = "viewer"
runner = "/bin/sh"
args = ["launcher.sh", "viewer"]
allowlist = ["viewer-helper"]
collector = "runtrace"
[profiles.env]
ROLE = "viewer"

[[predicates]]
rule = "viewer must stay denied when admin is allowed"
require = { kind = "status_relation", profile = "viewer", status = "denied" }
when = { kind = "status_is", profile = "admin", status = "allowed" }

[[predicates]]
rule = "viewer spawned targets must be a subset of its allowlist"
require = { kind = "subset", set = "viewer.spawned", of = "viewer.allowlist" }
"#;

    #[test]
    fn parses_v1_profiles_and_predicates() {
        let cfg = RelationalConfig::parse(EXAMPLE).expect("parses");
        assert_eq!(cfg.profiles.len(), 2);
        assert_eq!(cfg.predicates.len(), 2);

        let admin = cfg.profile("admin").expect("admin present");
        assert_eq!(admin.runner.as_deref(), Some("/bin/sh"));
        assert_eq!(
            admin.env.get("TOKEN"),
            Some(&EnvValue::SecretRef("lab:admin-token".into()))
        );
        assert_eq!(
            admin.env.get("ROLE"),
            Some(&EnvValue::Literal("admin".into()))
        );

        // Subset predicate parsed its dotted selectors.
        match &cfg.predicates[1].require {
            Require::Subset { set, of } => {
                assert_eq!(set.dotted(), "viewer.spawned");
                assert_eq!(of.dotted(), "viewer.allowlist");
            }
            other => panic!("expected subset, got {other:?}"),
        }

        // Status map round-trips.
        assert_eq!(cfg.status_map.classify(0), ProfileStatus::Allowed);
        assert_eq!(cfg.status_map.classify(77), ProfileStatus::Denied);
        assert!(cfg.status_map.is_auth_failure(66));
    }

    #[test]
    fn rejects_wrong_schema() {
        let src = r#"schema = "bhf.relational.v0"
[[profiles]]
name = "a"
"#;
        let err = RelationalConfig::parse(src).unwrap_err();
        assert!(matches!(err, SchemaError::UnsupportedSchema { .. }));
    }

    #[test]
    fn rejects_unknown_profile_in_predicate() {
        let src = r#"schema = "bhf.relational.v1"
[[profiles]]
name = "viewer"
[[predicates]]
rule = "r"
require = { kind = "status_relation", profile = "ghost", status = "denied" }
"#;
        let err = RelationalConfig::parse(src).unwrap_err();
        assert!(matches!(err, SchemaError::UnknownProfile(p) if p == "ghost"));
    }

    #[test]
    fn rejects_duplicate_profile() {
        let src = r#"schema = "bhf.relational.v1"
[[profiles]]
name = "dup"
[[profiles]]
name = "dup"
"#;
        let err = RelationalConfig::parse(src).unwrap_err();
        assert!(matches!(err, SchemaError::DuplicateProfile(p) if p == "dup"));
    }

    #[test]
    fn hashes_are_stable_and_profile_scoped() {
        let cfg = RelationalConfig::parse(EXAMPLE).expect("parses");
        let cfg2 = RelationalConfig::parse(EXAMPLE).expect("parses");
        assert_eq!(cfg.policy_hash(), cfg2.policy_hash());
        let admin_hash = cfg.profile_hash("admin").unwrap();
        let viewer_hash = cfg.profile_hash("viewer").unwrap();
        assert_ne!(admin_hash, viewer_hash);
        assert!(cfg.profile_hash("ghost").is_none());
    }

    #[test]
    fn secret_values_never_appear_in_policy_hash_source() {
        // The config holds only the reference id; the canonical JSON used for
        // the policy hash must contain the ref but never a resolved value.
        let cfg = RelationalConfig::parse(EXAMPLE).expect("parses");
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("lab:admin-token"));
        assert!(!json.contains("s3cr3t"));
    }
}
