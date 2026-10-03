// SPDX-License-Identifier: Apache-2.0

//! The provenance record written for every project run and stamped onto every
//! finding, replay bundle, and run summary.
//!
//! It ties a finding back to the exact project/target identity, the manifest
//! hash, and every asset's SHA-256, so importers (SARIF / vulnerability-
//! management tooling) can reconstruct precisely what produced a result.
//! Secret values are never serialized — only their `${secret:NAME}` handle is
//! recorded.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::warning::Warning;

/// What a hashed asset is, for the provenance record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssetKind {
    /// The harness source/binary for a native engine.
    Harness,
    /// The target binary for the `binary` engine.
    Binary,
    /// A seed file or directory (directories hashed by sorted walk).
    Seed,
    /// One declared dictionary layer, hashed as-is.
    Dictionary,
    /// The merged, de-duplicated dictionary actually materialized.
    MergedDictionary,
    /// A structured-input grammar descriptor.
    Grammar,
    /// An explicitly-trusted out-of-process extension executable.
    Extension,
}

/// One asset's manifest-relative path and content hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetHash {
    pub kind: AssetKind,
    /// The path as declared in the manifest (relative), for stable provenance.
    pub path: String,
    /// Lower-case hex SHA-256.
    pub sha256: String,
}

/// The authoritative provenance record for a resolved target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Provenance {
    pub schema: String,
    pub project_id: String,
    pub project_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_bhf: Option<String>,
    pub manifest_sha256: String,
    pub target_id: String,
    pub engine: String,
    pub input_mode: String,
    pub assets: Vec<AssetHash>,
    /// Resolved launch command: the resolved harness/binary path. The full
    /// per-execution argv (runner prefix + fixed target args + the `@@` input
    /// position, #47) is recorded by the binary engine in each finding.
    pub resolved_command: Vec<String>,
    /// Env in redacted form: literals verbatim, handles as `${env:NAME}` /
    /// `${secret:NAME}` with the value omitted.
    pub redacted_env: BTreeMap<String, String>,
    /// The running bhf version (injected by the caller).
    pub bhf_version: String,
    /// Best-effort build target triple of this bhf (injected by the caller).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub toolchain: Option<String>,
    pub warnings: Vec<Warning>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::warning::{Warning, WarningKind};

    fn sample() -> Provenance {
        Provenance {
            schema: "bhf.project.v1".to_owned(),
            project_id: "demo".to_owned(),
            project_version: "1.0.0".to_owned(),
            requires_bhf: Some(">=0.2.0".to_owned()),
            manifest_sha256: "a".repeat(64),
            target_id: "alpha".to_owned(),
            engine: "builtin".to_owned(),
            input_mode: "framed".to_owned(),
            assets: vec![AssetHash {
                kind: AssetKind::Harness,
                path: "prebuilt/harness".to_owned(),
                sha256: "b".repeat(64),
            }],
            resolved_command: vec!["prebuilt/harness".to_owned()],
            redacted_env: BTreeMap::from([
                ("PROFILE".to_owned(), "release".to_owned()),
                ("TOKEN".to_owned(), "${secret:API_TOKEN}".to_owned()),
            ]),
            bhf_version: "0.2.34".to_owned(),
            toolchain: Some("x86_64-unknown-linux-gnu".to_owned()),
            warnings: vec![Warning::new(
                WarningKind::GrammarUnsupportedByEngine,
                "example",
            )],
        }
    }

    #[test]
    fn provenance_serializes_stable_json() {
        let p = sample();
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["schema"], "bhf.project.v1");
        assert_eq!(json["project_id"], "demo");
        assert_eq!(json["project_version"], "1.0.0");
        assert_eq!(json["requires_bhf"], ">=0.2.0");
        assert_eq!(json["target_id"], "alpha");
        assert_eq!(json["bhf_version"], "0.2.34");
        assert_eq!(json["manifest_sha256"].as_str().unwrap().len(), 64);
        assert_eq!(json["assets"][0]["kind"], "harness");
        assert_eq!(json["assets"][0]["path"], "prebuilt/harness");
        assert_eq!(json["assets"][0]["sha256"].as_str().unwrap().len(), 64);
        assert_eq!(json["warnings"][0]["kind"], "grammar-unsupported-by-engine");
        // Round-trips.
        let back: Provenance = serde_json::from_value(json).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn provenance_redacts_secret_values() {
        let p = sample();
        let json = serde_json::to_string(&p).unwrap();
        // The handle is recorded; the value never is.
        assert!(json.contains("${secret:API_TOKEN}"));
        assert!(!json.contains("s3cr3t"));
    }
}
