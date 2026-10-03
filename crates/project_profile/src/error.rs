// SPDX-License-Identifier: Apache-2.0

//! The single error type for manifest loading, validation, resolution, and
//! lowering. Every failure is a descriptive, typed variant — this crate never
//! returns a bare `None` or a stringly-typed error on failure.

use std::path::PathBuf;

use thiserror::Error;

/// All the ways a `bhf.project.v1` manifest can fail to load, validate, or
/// resolve.
#[derive(Debug, Error)]
pub enum ProjectError {
    /// TOML did not parse, or a declared field had the wrong type / a genuine
    /// unknown-field typo (via `deny_unknown_fields`).
    #[error("failed to parse manifest: {0}")]
    Parse(#[from] toml::de::Error),

    /// The `schema` string was not `bhf.project.v1`.
    #[error("unsupported manifest schema '{found}' (this bhf understands '{expected}')")]
    UnsupportedSchema { found: String, expected: String },

    /// Two targets share an `id`.
    #[error("duplicate target id '{0}'")]
    DuplicateTargetId(String),

    /// A target's `engine` is not one of the known engines.
    #[error("target '{target}': unknown engine '{engine}' (expected builtin, afl++, or binary)")]
    UnknownEngine { target: String, engine: String },

    /// A required field for the selected engine was absent.
    #[error("target '{target}': missing required field '{field}'")]
    MissingField { target: String, field: &'static str },

    /// The named target id was not found in the manifest.
    #[error("no target with id '{0}' in manifest")]
    UnknownTarget(String),

    /// The manifest's `requires-bhf` is not satisfied by the running bhf.
    #[error("manifest requires bhf '{requires}', but this bhf is '{current}'")]
    UnsupportedBhfVersion { requires: String, current: String },

    /// A version literal (the `current` version, or a req's version text) was
    /// malformed.
    #[error("malformed version '{value}': {detail}")]
    MalformedVersion { value: String, detail: String },

    /// The `requires-bhf` requirement string itself was malformed.
    #[error("malformed requires-bhf requirement '{value}': {detail}")]
    MalformedVersionReq { value: String, detail: String },

    /// A relative asset path escaped the manifest directory via `..`.
    #[error("path '{0}' escapes the manifest directory (use --allow-external-paths to permit)")]
    PathEscape(String),

    /// An absolute asset path was used without opting in.
    #[error("absolute path '{0}' not allowed (use --allow-external-paths to permit)")]
    AbsolutePathNotAllowed(String),

    /// A referenced asset (seed, binary, dictionary, grammar) does not exist.
    #[error("asset not found: {0}")]
    MissingAsset(PathBuf),

    /// A value mixed literal text with an interpolation handle, or used a
    /// handle shape other than `${env:NAME}` / `${secret:NAME}`.
    #[error("unsafe interpolation in value '{value}': {detail}")]
    UnsafeInterpolation { value: String, detail: String },

    /// An `${env:NAME}` handle referenced an unset environment variable.
    #[error("environment variable '{0}' referenced by an ${{env:...}} handle is not set")]
    UndefinedEnvHandle(String),

    /// A `${secret:NAME}` handle had no corresponding `BHF_SECRET_<NAME>`.
    #[error("secret '{name}' is not set (expected environment variable '{env_var}')")]
    UndefinedSecret { name: String, env_var: String },

    /// A manifest field belongs to an engine feature not available in this bhf.
    #[error(
        "target '{target}': field '{field}' requires feature {issue} (not available in this bhf)"
    )]
    GatedFeature {
        target: String,
        field: &'static str,
        issue: &'static str,
    },

    /// The engine and `input-mode` are incompatible.
    #[error("target '{target}': {detail}")]
    InputModeMismatch { target: String, detail: String },

    /// A dictionary file was not valid UTF-8 or exceeded the safety limit.
    #[error("dictionary '{path}': {detail}")]
    InvalidDictionary { path: PathBuf, detail: String },

    /// An underlying I/O failure (reading an asset, walking a seed directory).
    #[error("io error on '{path}': {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    /// A `[[extension]]` entry was malformed (empty executable, unsupported wire
    /// format, …).
    #[error("extension{}: {detail}", id.as_ref().map(|i| format!(" '{i}'")).unwrap_or_default())]
    InvalidExtension { id: Option<String>, detail: String },
}
