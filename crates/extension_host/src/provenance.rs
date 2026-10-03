// SPDX-License-Identifier: Apache-2.0

//! Provenance accounting for an extension session.
//!
//! Every finding and every run that involves an extension records *where it came
//! from*: the sha256 of the extension executable and its config/manifest, the
//! negotiated protocol version and capabilities, the resource limits applied,
//! and the restart/loss events observed. Secrets are never recorded: the
//! environment is reduced to an explicit allowlist before the child is spawned,
//! and only the **names** (never the values) of passed/dropped variables are
//! retained.

use crate::Result;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

/// The resource limits applied to the child (recorded for audit; `None` fields
/// mean "not constrained on this platform / by this policy").
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ProvLimits {
    /// `RLIMIT_AS` applied to the child, in bytes (unix only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_space_bytes: Option<u64>,
    /// `RLIMIT_CPU` applied to the child, in seconds (unix only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_seconds: Option<u64>,
    /// The negotiated maximum frame size, in bytes.
    pub max_frame_bytes: u64,
    /// The per-call timeout, in milliseconds.
    pub call_timeout_ms: u64,
}

/// The result of reducing an environment to an explicit allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedEnv {
    /// The variables (name -> value) that passed the allowlist and will be set
    /// on the child.
    pub passed: BTreeMap<String, String>,
    /// The **names** of the variables that were dropped (values never retained).
    pub redacted: Vec<String>,
}

/// Reduce `source` to only the variables whose name is in `allowlist`.
///
/// Returns the passed variables (name -> value) and the sorted list of dropped
/// variable **names** (never their values). This is the single chokepoint that
/// keeps host secrets out of both the child environment and provenance.
pub fn redact_env(allowlist: &[String], source: &BTreeMap<String, String>) -> RedactedEnv {
    let mut passed = BTreeMap::new();
    let mut redacted = Vec::new();
    for (name, value) in source {
        if allowlist.iter().any(|a| a == name) {
            passed.insert(name.clone(), value.clone());
        } else {
            redacted.push(name.clone());
        }
    }
    redacted.sort();
    RedactedEnv { passed, redacted }
}

/// Compute the lowercase-hex sha256 of a file's contents.
pub fn hash_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)?;
    Ok(hash_bytes(&bytes))
}

/// Compute the lowercase-hex sha256 of a byte slice.
pub fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The provenance record for one extension session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExtensionProvenance {
    /// sha256 of the extension executable.
    pub executable_sha256: String,
    /// sha256 of the extension config/manifest, if one was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_sha256: Option<String>,
    /// The negotiated protocol identifier.
    pub protocol_version: String,
    /// The negotiated capabilities (sorted).
    pub negotiated_caps: Vec<String>,
    /// The **names** of the environment variables passed through to the child
    /// (values never recorded).
    pub env_allowlist: Vec<String>,
    /// The **names** of the environment variables that were dropped.
    pub redacted_env: Vec<String>,
    /// The resource limits applied to the child.
    pub resource_limits: ProvLimits,
    /// The number of restarts performed over the session.
    pub restart_count: u32,
    /// The number of terminal loss events over the session.
    pub loss_count: u32,
}

impl ExtensionProvenance {
    /// Build the compact `extension` block stamped into a finding record.
    ///
    /// The key order is deterministic (serde_json's `Map` is sorted) so the
    /// block a finding carries and the full provenance record always agree.
    pub fn finding_block(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert(
            "executable_sha256".to_string(),
            serde_json::Value::String(self.executable_sha256.clone()),
        );
        map.insert(
            "config_sha256".to_string(),
            match &self.config_sha256 {
                Some(h) => serde_json::Value::String(h.clone()),
                None => serde_json::Value::Null,
            },
        );
        map.insert(
            "protocol_version".to_string(),
            serde_json::Value::String(self.protocol_version.clone()),
        );
        map.insert(
            "negotiated_caps".to_string(),
            serde_json::Value::Array(
                self.negotiated_caps
                    .iter()
                    .map(|c| serde_json::Value::String(c.clone()))
                    .collect(),
            ),
        );
        serde_json::Value::Object(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(contents: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        f.write_all(contents).expect("write");
        f.flush().expect("flush");
        f
    }

    fn sample() -> ExtensionProvenance {
        ExtensionProvenance {
            executable_sha256: "a".repeat(64),
            config_sha256: Some("b".repeat(64)),
            protocol_version: crate::PROTOCOL.to_string(),
            negotiated_caps: vec!["oracle.evaluate".to_string()],
            env_allowlist: vec!["ACME_MODE".to_string()],
            redacted_env: vec!["SECRET_TOKEN".to_string()],
            resource_limits: ProvLimits {
                address_space_bytes: Some(1 << 30),
                cpu_seconds: Some(30),
                max_frame_bytes: 4096,
                call_timeout_ms: 5000,
            },
            restart_count: 1,
            loss_count: 0,
        }
    }

    #[test]
    fn provenance_records_exe_and_config_sha256() {
        let exe = write_temp(b"executable-bytes");
        let cfg = write_temp(b"config-bytes");
        let exe_hash = hash_file(exe.path()).expect("exe hash");
        let cfg_hash = hash_file(cfg.path()).expect("cfg hash");
        // Known sha256 of "executable-bytes" vs "config-bytes" differ and are
        // 64 hex chars.
        assert_eq!(exe_hash.len(), 64);
        assert_ne!(exe_hash, cfg_hash);
        assert!(exe_hash.chars().all(|c| c.is_ascii_hexdigit()));

        let prov = ExtensionProvenance {
            executable_sha256: exe_hash.clone(),
            config_sha256: Some(cfg_hash.clone()),
            ..sample()
        };
        let json = serde_json::to_value(&prov).expect("serialize");
        assert_eq!(json["executable_sha256"], serde_json::json!(exe_hash));
        assert_eq!(json["config_sha256"], serde_json::json!(cfg_hash));
        assert_eq!(json["protocol_version"], serde_json::json!(crate::PROTOCOL));
    }

    #[test]
    fn hash_bytes_matches_known_vector() {
        // sha256("") is the well-known empty-string digest.
        assert_eq!(
            hash_bytes(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn env_redaction_passes_only_allowlisted_vars() {
        let mut full = BTreeMap::new();
        full.insert("ACME_MODE".to_string(), "strict".to_string());
        full.insert("SECRET_TOKEN".to_string(), "hunter2".to_string());
        full.insert("AWS_SECRET_ACCESS_KEY".to_string(), "nope".to_string());

        let redacted = redact_env(&["ACME_MODE".to_string()], &full);
        assert_eq!(redacted.passed.len(), 1);
        assert_eq!(
            redacted.passed.get("ACME_MODE"),
            Some(&"strict".to_string())
        );
        // Dropped NAMES are recorded, values are not present anywhere.
        assert_eq!(
            redacted.redacted,
            vec![
                "AWS_SECRET_ACCESS_KEY".to_string(),
                "SECRET_TOKEN".to_string()
            ]
        );
        // The dropped values never appear in the redacted-name list.
        assert!(!redacted.redacted.iter().any(|n| n.contains("hunter2")));
    }

    #[test]
    fn provenance_serialises_restart_and_loss_events() {
        let prov = ExtensionProvenance {
            restart_count: 3,
            loss_count: 2,
            ..sample()
        };
        let json = serde_json::to_value(&prov).expect("serialize");
        assert_eq!(json["restart_count"], serde_json::json!(3));
        assert_eq!(json["loss_count"], serde_json::json!(2));
        // Resource limits are recorded, but no raw env values leak.
        assert_eq!(
            json["resource_limits"]["call_timeout_ms"],
            serde_json::json!(5000)
        );
        let serialized = serde_json::to_string(&json).unwrap();
        assert!(!serialized.contains("hunter2"));
    }

    #[test]
    fn provenance_finding_block_has_stable_key_order() {
        let prov = sample();
        let block = prov.finding_block();
        // Deterministic: the same inputs always serialize to identical bytes,
        // whatever `serde_json::Map`'s backing order is. This is what makes the
        // block a finding carries and the full provenance record always agree.
        let s1 = serde_json::to_string(&block).unwrap();
        let s2 = serde_json::to_string(&prov.finding_block()).unwrap();
        let s3 = serde_json::to_string(&sample().finding_block()).unwrap();
        assert_eq!(s1, s2, "finding block must serialize deterministically");
        assert_eq!(s1, s3, "equal provenance must serialize identically");

        // The four stamped keys are present with the expected values, and no
        // raw env values leak into the finding block.
        let obj = block.as_object().expect("object");
        assert_eq!(obj.len(), 4, "exactly four stamped keys");
        assert_eq!(obj["executable_sha256"], serde_json::json!("a".repeat(64)));
        assert_eq!(obj["config_sha256"], serde_json::json!("b".repeat(64)));
        assert_eq!(obj["protocol_version"], serde_json::json!(crate::PROTOCOL));
        assert_eq!(
            obj["negotiated_caps"],
            serde_json::json!(["oracle.evaluate"])
        );
    }
}
