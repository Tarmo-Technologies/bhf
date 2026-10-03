// SPDX-License-Identifier: Apache-2.0

//! The standalone `bhf.extension-manifest.v1` trust manifest.
//!
//! An extension is **never** auto-discovered or implicitly executed: the
//! operator must point bhf at an explicit manifest describing the trusted
//! executable, the capabilities it must satisfy, and the limited environment it
//! runs under. The manifest is strict (unknown keys are rejected), resolves the
//! executable relative to its own directory, refuses to escape that directory
//! unless explicitly opted in, and fails closed on a `requires-bhf` version
//! bound this bhf does not meet.
//!
//! This is a minimal, self-contained trust gate. It is intentionally shaped so a
//! future external project-profile format can grow an `[[extension]]` section
//! that reuses these field names.

use crate::handshake::WireLimits;
use crate::limits::Limits;
use crate::provenance::ProvLimits;
use crate::restart::RestartPolicy;
use crate::{ExtensionError, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

/// The only manifest schema identifier this host accepts.
pub const MANIFEST_SCHEMA: &str = "bhf.extension-manifest.v1";

/// A parsed, validated extension trust manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ExtensionManifest {
    /// Must equal [`MANIFEST_SCHEMA`].
    pub schema: String,
    /// An optional operator-facing identifier.
    #[serde(default)]
    pub id: Option<String>,
    /// An optional extension version string (diagnostic only).
    #[serde(default)]
    pub version: Option<String>,
    /// An optional `>=X.Y[.Z]` bound on the bhf version required to run this
    /// extension. Fails closed if this bhf is older.
    #[serde(default)]
    pub requires_bhf: Option<String>,
    /// The extension executable, resolved relative to the manifest directory.
    pub executable: String,
    /// Fixed arguments passed to the executable.
    #[serde(default)]
    pub args: Vec<String>,
    /// Capabilities that MUST be negotiated or the campaign aborts.
    #[serde(default)]
    pub required_capabilities: Vec<String>,
    /// Capabilities used opportunistically if provided.
    #[serde(default)]
    pub optional_capabilities: Vec<String>,
    /// Explicit environment variables to set on the child (name -> value). The
    /// child's environment is cleared first; it sees only these plus any
    /// allow-listed passthrough names.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Names of host environment variables to forward to the child. Only the
    /// names are ever recorded in provenance, never the values.
    #[serde(default)]
    pub env_passthrough: Vec<String>,
    /// The preferred wire format (only `json` is supported today).
    #[serde(default)]
    pub format: Option<String>,
    /// Opt-in to an executable path that is absolute or escapes the manifest
    /// directory. Off by default (fail-safe).
    #[serde(default)]
    pub allow_external_paths: bool,
    /// Optional resource/limit overrides.
    #[serde(default)]
    pub limits: Option<ManifestLimits>,
}

/// Optional limit overrides from a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ManifestLimits {
    /// Maximum framed message size, in bytes.
    #[serde(default)]
    pub max_frame_bytes: Option<u64>,
    /// Per-call deadline, in milliseconds.
    #[serde(default)]
    pub call_timeout_ms: Option<u64>,
    /// Maximum concurrently outstanding requests.
    #[serde(default)]
    pub max_outstanding: Option<usize>,
    /// Child `RLIMIT_AS`, in bytes (unix only).
    #[serde(default)]
    pub address_space_bytes: Option<u64>,
    /// Child `RLIMIT_CPU`, in seconds (unix only).
    #[serde(default)]
    pub cpu_seconds: Option<u64>,
    /// Maximum restarts before a fault is terminal.
    #[serde(default)]
    pub max_restarts: Option<u32>,
}

impl ExtensionManifest {
    /// Parse and validate a manifest from TOML text.
    pub fn from_toml_str(text: &str) -> Result<Self> {
        let manifest: ExtensionManifest = toml::from_str(text)
            .map_err(|e| ExtensionError::manifest(format!("could not parse manifest: {e}")))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Load and validate a manifest from an explicit path. Never auto-discovered.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            ExtensionError::manifest(format!("could not read manifest {}: {e}", path.display()))
        })?;
        Self::from_toml_str(&text)
    }

    /// Validate the schema identifier and the `requires-bhf` gate against this
    /// bhf's version.
    fn validate(&self) -> Result<()> {
        if self.schema != MANIFEST_SCHEMA {
            return Err(ExtensionError::manifest(format!(
                "unsupported manifest schema {:?} (expected {MANIFEST_SCHEMA:?})",
                self.schema
            )));
        }
        if self.executable.trim().is_empty() {
            return Err(ExtensionError::manifest(
                "manifest `executable` must not be empty",
            ));
        }
        if let Some(fmt) = &self.format {
            if fmt != "json" {
                return Err(ExtensionError::manifest(format!(
                    "unsupported wire format {fmt:?} (this host speaks only \"json\")"
                )));
            }
        }
        if let Some(req) = &self.requires_bhf {
            let actual = env!("CARGO_PKG_VERSION");
            if !bhf_version_satisfies(req, actual)? {
                return Err(ExtensionError::manifest(format!(
                    "this bhf is version {actual}, which does not satisfy the extension's \
                     requires-bhf = {req:?}"
                )));
            }
        }
        Ok(())
    }

    /// Resolve the executable path against the manifest's directory, refusing an
    /// absolute path or a parent-directory escape unless `allow-external-paths`.
    pub fn resolve_executable(&self, manifest_dir: &Path) -> Result<PathBuf> {
        let exe = Path::new(&self.executable);
        if !self.allow_external_paths {
            if exe.is_absolute() {
                return Err(ExtensionError::manifest(format!(
                    "executable {:?} is an absolute path; set allow-external-paths = true to permit it",
                    self.executable
                )));
            }
            if exe.components().any(|c| matches!(c, Component::ParentDir)) {
                return Err(ExtensionError::manifest(format!(
                    "executable {:?} escapes the manifest directory; set allow-external-paths = true to permit it",
                    self.executable
                )));
            }
        }
        Ok(manifest_dir.join(exe))
    }

    /// The wire limits proposed by the host, folding in any manifest overrides.
    pub fn wire_limits(&self) -> WireLimits {
        let defaults = Limits::default();
        let (max_frame, timeout_ms) = match &self.limits {
            Some(l) => (
                l.max_frame_bytes.unwrap_or(defaults.max_frame_bytes as u64),
                l.call_timeout_ms
                    .unwrap_or(defaults.call_timeout.as_millis() as u64),
            ),
            None => (
                defaults.max_frame_bytes as u64,
                defaults.call_timeout.as_millis() as u64,
            ),
        };
        WireLimits {
            max_frame_bytes: max_frame,
            call_timeout_ms: timeout_ms,
        }
    }

    /// The host-side outstanding cap from the manifest (defaults to 1).
    pub fn max_outstanding(&self) -> usize {
        self.limits
            .as_ref()
            .and_then(|l| l.max_outstanding)
            .unwrap_or(1)
            .max(1)
    }

    /// The restart policy from the manifest (defaults to [`RestartPolicy::default`]).
    pub fn restart_policy(&self) -> RestartPolicy {
        let mut policy = RestartPolicy::default();
        if let Some(max) = self.limits.as_ref().and_then(|l| l.max_restarts) {
            policy.max_restarts = max;
        }
        policy
    }

    /// The child resource caps recorded in provenance (unix only; `None` means
    /// unconstrained).
    pub fn prov_limits(&self) -> ProvLimits {
        let wire = self.wire_limits();
        ProvLimits {
            address_space_bytes: self.limits.as_ref().and_then(|l| l.address_space_bytes),
            cpu_seconds: self.limits.as_ref().and_then(|l| l.cpu_seconds),
            max_frame_bytes: wire.max_frame_bytes,
            call_timeout_ms: wire.call_timeout_ms,
        }
    }
}

/// Compare a `>=X.Y[.Z]` bound against an actual `major.minor.patch` version.
///
/// A hand-rolled dotted-integer comparator kept deliberately simple: only the
/// `>=` operator is supported, so no `semver` dependency is pulled in.
fn bhf_version_satisfies(requirement: &str, actual: &str) -> Result<bool> {
    let bound = requirement.trim();
    let rest = bound.strip_prefix(">=").ok_or_else(|| {
        ExtensionError::manifest(format!(
            "unsupported requires-bhf constraint {requirement:?} (only \">=X.Y[.Z]\" is supported)"
        ))
    })?;
    let want = parse_version(rest.trim(), "requires-bhf bound")?;
    let have = parse_version(actual, "this bhf version")?;
    Ok(have >= want)
}

/// Parse a dotted-integer version into a `(major, minor, patch)` tuple; a
/// missing patch defaults to 0. Pre-release/build suffixes are not supported.
fn parse_version(text: &str, context: &str) -> Result<(u64, u64, u64)> {
    let mut parts = text.split('.');
    let mut next = |field: &str| -> Result<u64> {
        match parts.next() {
            Some(p) => p.parse::<u64>().map_err(|_| {
                ExtensionError::manifest(format!("{context}: {field} {p:?} is not an integer"))
            }),
            None => Ok(0),
        }
    };
    let major = next("major")?;
    let minor = next("minor")?;
    let patch = next("patch")?;
    if parts.next().is_some() {
        return Err(ExtensionError::manifest(format!(
            "{context}: {text:?} has too many version components"
        )));
    }
    Ok((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
schema = "bhf.extension-manifest.v1"
executable = "./ext"
required-capabilities = ["oracle.evaluate"]
"#;

    #[test]
    fn manifest_parses_minimal_and_resolves_paths_against_manifest_dir() {
        let manifest = ExtensionManifest::from_toml_str(MINIMAL).expect("parse minimal");
        assert_eq!(manifest.schema, MANIFEST_SCHEMA);
        assert_eq!(manifest.required_capabilities, vec!["oracle.evaluate"]);

        let dir = Path::new("/opt/ext-pkg");
        let resolved = manifest.resolve_executable(dir).expect("resolve");
        assert_eq!(resolved, Path::new("/opt/ext-pkg/ext"));
    }

    #[test]
    fn manifest_rejects_unknown_keys() {
        let text = format!("{MINIMAL}\nunexpected-key = true\n");
        let err = ExtensionManifest::from_toml_str(&text).expect_err("unknown key must fail");
        assert!(matches!(err, ExtensionError::Manifest(_)));
    }

    #[test]
    fn manifest_requires_schema_and_executable() {
        let no_schema = r#"executable = "./ext""#;
        assert!(ExtensionManifest::from_toml_str(no_schema).is_err());

        let no_exe = r#"schema = "bhf.extension-manifest.v1""#;
        let err = ExtensionManifest::from_toml_str(no_exe).expect_err("missing executable");
        assert!(matches!(err, ExtensionError::Manifest(_)));

        let wrong_schema = r#"
schema = "bhf.extension-manifest.v99"
executable = "./ext"
"#;
        let err = ExtensionManifest::from_toml_str(wrong_schema).expect_err("wrong schema");
        assert!(err.to_string().contains("unsupported manifest schema"));
    }

    #[test]
    fn manifest_rejects_parent_dir_escape_without_opt_in() {
        let text = r#"
schema = "bhf.extension-manifest.v1"
executable = "../../bin/x"
"#;
        let manifest = ExtensionManifest::from_toml_str(text).expect("parse");
        let err = manifest
            .resolve_executable(Path::new("/opt/ext-pkg"))
            .expect_err("parent escape must be refused");
        assert!(err.to_string().contains("allow-external-paths"));

        // With the opt-in, the same path resolves.
        let opted = format!("{text}allow-external-paths = true\n");
        let manifest = ExtensionManifest::from_toml_str(&opted).expect("parse opted");
        let resolved = manifest
            .resolve_executable(Path::new("/opt/ext-pkg"))
            .expect("opted resolve");
        assert_eq!(resolved, Path::new("/opt/ext-pkg/../../bin/x"));
    }

    #[test]
    fn manifest_rejects_absolute_path_without_opt_in() {
        let text = r#"
schema = "bhf.extension-manifest.v1"
executable = "/usr/bin/evil"
"#;
        let manifest = ExtensionManifest::from_toml_str(text).expect("parse");
        assert!(manifest
            .resolve_executable(Path::new("/opt/ext-pkg"))
            .is_err());
    }

    #[test]
    fn requires_bhf_gate_fails_closed_on_older_bhf() {
        let text = r#"
schema = "bhf.extension-manifest.v1"
executable = "./ext"
requires-bhf = ">=9.9"
"#;
        let err = ExtensionManifest::from_toml_str(text).expect_err("future bhf must fail closed");
        assert!(err.to_string().contains("requires-bhf"));

        // A bound this bhf satisfies parses fine.
        let ok = r#"
schema = "bhf.extension-manifest.v1"
executable = "./ext"
requires-bhf = ">=0.1"
"#;
        ExtensionManifest::from_toml_str(ok).expect("satisfied bound parses");
    }

    #[test]
    fn version_comparator_handles_two_and_three_components() {
        assert!(bhf_version_satisfies(">=0.2", "0.2.34").unwrap());
        assert!(bhf_version_satisfies(">=0.2.34", "0.2.34").unwrap());
        assert!(!bhf_version_satisfies(">=0.2.35", "0.2.34").unwrap());
        assert!(!bhf_version_satisfies(">=1.0", "0.2.34").unwrap());
        // Unsupported operator is a descriptive error, not a silent pass.
        assert!(bhf_version_satisfies("^0.2", "0.2.34").is_err());
    }
}
