// SPDX-License-Identifier: Apache-2.0

//! Serde types for the `bhf.project.v1` manifest.
//!
//! The manifest is a TOML document that declares a project and one or more
//! fuzzing *targets*, each composing a private harness (source or prebuilt
//! binary) with its corpora, layered dictionaries, grammar, and launch
//! settings — all kept outside the bhf source tree. The manifest is only ever
//! loaded through an explicit path (the trust boundary), never auto-discovered.
//!
//! `#[serde(deny_unknown_fields)]` rejects genuine typos (e.g. `seedz`). Fields
//! that belong to engine features not yet available in this bhf
//! (`runner`, `runner-args`, `target-args`, `arguments`, `runtime-oracles`,
//! `postcondition`) are declared here as `Option<_>` so the manifest still
//! *parses* — they are then rejected during validation with a precise
//! "requires feature #NN" diagnostic rather than a generic serde "unknown
//! field" error. This keeps the on-disk format stable and fail-closed while the
//! owning issues land.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The only schema string this bhf understands.
pub const SCHEMA_V1: &str = "bhf.project.v1";

/// Top-level `bhf.project.v1` manifest.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Manifest {
    /// Must equal [`SCHEMA_V1`]; any other value is rejected on load.
    pub schema: String,
    /// Project-level identity and compatibility metadata.
    pub project: Project,
    /// The declared targets. TOML array-of-tables key is `target`.
    #[serde(default, rename = "target")]
    pub targets: Vec<Target>,
    /// Explicitly-trusted out-of-process extensions (`bhf.extension.v1`). TOML
    /// array-of-tables key is `extension`. A project-level `[[extension]]`
    /// declares an extension `bhf project run` loads for its native-engine
    /// campaigns — the convergence of the standalone `bhf.extension-manifest.v1`
    /// onto the project profile.
    #[serde(default, rename = "extension")]
    pub extensions: Vec<Extension>,
}

/// A `[[extension]]` entry: an explicitly-trusted extension executable and the
/// capabilities/limits it runs under. The field set mirrors the standalone
/// `bhf.extension-manifest.v1` so the two trust surfaces converge.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Extension {
    /// An optional operator-facing identifier.
    #[serde(default)]
    pub id: Option<String>,
    /// The extension executable, resolved relative to the manifest directory.
    pub executable: PathBuf,
    /// Fixed arguments passed to the executable.
    #[serde(default)]
    pub args: Vec<String>,
    /// Capabilities that MUST be negotiated or the campaign aborts.
    #[serde(default)]
    pub required_capabilities: Vec<String>,
    /// Capabilities used opportunistically if provided.
    #[serde(default)]
    pub optional_capabilities: Vec<String>,
    /// Explicit environment variables to set on the child.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Names of host environment variables to forward to the child.
    #[serde(default)]
    pub env_passthrough: Vec<String>,
    /// The preferred wire format (only `json` is supported today).
    #[serde(default)]
    pub format: Option<String>,
    /// Optional resource/limit overrides.
    #[serde(default)]
    pub limits: Option<ExtensionLimits>,
}

/// Optional `[extension.limits]` overrides, mirroring the standalone manifest's
/// `[limits]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ExtensionLimits {
    /// Maximum framed message size, in bytes.
    #[serde(default)]
    pub max_frame_bytes: Option<u64>,
    /// Per-call deadline, in milliseconds.
    #[serde(default)]
    pub call_timeout_ms: Option<u64>,
    /// Maximum concurrently outstanding requests.
    #[serde(default)]
    pub max_outstanding: Option<u64>,
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

/// Project identity and bhf-version compatibility.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Project {
    /// Stable project identifier (recorded in provenance).
    pub id: String,
    /// Project version string (recorded in provenance, not interpreted).
    pub version: String,
    /// Optional bhf-version requirement, e.g. `">=0.2.0"` or `"^0.2.34"`.
    /// Checked against the running bhf during validation (fail-closed).
    #[serde(default)]
    pub requires_bhf: Option<String>,
}

/// A single fuzzing target.
///
/// `engine` and `input-mode` are kept as free strings in the schema so that
/// validation can emit a precise "unknown engine 'x'" / input-mode diagnostic
/// rather than a generic serde enum-variant error.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Target {
    /// Stable, project-unique target identifier.
    pub id: String,
    /// Engine selector: `builtin`, `afl++`, or `binary`.
    pub engine: String,
    /// Path to the harness source/binary (native engines) or the target binary
    /// (`binary` engine). Resolved relative to the manifest directory.
    #[serde(default)]
    pub binary: Option<PathBuf>,
    /// Input contract: `framed` (native engines, the default), or `stdin` /
    /// `file` (the `binary` engine). Cross-engine mismatches are rejected.
    #[serde(default)]
    pub input_mode: Option<String>,
    /// Trusted build command (argv form). Executed only by `run`, never by
    /// `validate`/`list`. Not interpreted by this pure crate.
    #[serde(default)]
    pub build_command: Option<Vec<String>>,
    /// Seed files and/or directories, resolved relative to the manifest dir.
    #[serde(default)]
    pub seeds: Vec<PathBuf>,
    /// Layered AFL-format dictionaries, merged in declared order.
    #[serde(default)]
    pub dictionaries: Vec<PathBuf>,
    /// Structured-input grammar descriptor (the JSON format `bhf fuzz
    /// --grammar` consumes). A builtin-mutator feature; see fidelity warnings.
    #[serde(default)]
    pub grammar: Option<PathBuf>,

    // --- Engine / resource knobs (engine-neutral; lowered per engine). ---
    /// AFL++ binary-only mode: `native` (default), `qemu`, or `frida`.
    #[serde(default)]
    pub afl_mode: Option<String>,
    /// AFL++ instrumentation range scope (passed through to the engine env).
    #[serde(default)]
    pub afl_inst_ranges: Option<String>,
    /// Override path to the AFL++ toolchain root.
    #[serde(default)]
    pub afl_path: Option<PathBuf>,
    /// Wall-clock budget, e.g. `"60s"`, `"5m"`.
    #[serde(default)]
    pub time: Option<String>,
    /// Per-execution timeout for native engines (string form, engine-parsed).
    #[serde(default)]
    pub timeout: Option<String>,
    /// Per-execution timeout in milliseconds for the `binary` engine.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Maximum input length (`"auto"` or a byte count), native engines.
    #[serde(default)]
    pub max_len: Option<String>,
    /// RSS limit in MiB for native engines.
    #[serde(default)]
    pub rss_limit_mb: Option<u64>,
    /// Child-process memory limit in MiB for the `binary` engine.
    #[serde(default)]
    pub mem_mb: Option<u64>,
    /// Sandbox toggle for native engines.
    #[serde(default)]
    pub sandbox: Option<bool>,
    /// Extra environment for the harness. Values may be literals or
    /// `${env:NAME}` / `${secret:NAME}` handles (resolved, with secrets
    /// redacted from provenance).
    #[serde(default)]
    pub env: BTreeMap<String, String>,

    // --- Gated fields: parse but are rejected in validation (fail-closed). ---
    /// Binary runner / argv wrapper (e.g. a PE loader). Requires issue #47.
    #[serde(default)]
    pub runner: Option<String>,
    /// Runner arguments. Requires issue #47.
    #[serde(default)]
    pub runner_args: Option<Vec<String>>,
    /// Target argv. Requires issue #47.
    #[serde(default)]
    pub target_args: Option<Vec<String>>,
    /// Target argument template. Requires issue #47.
    #[serde(default)]
    pub arguments: Option<Vec<String>>,
    /// Runtime sink oracles. Requires issue #59.
    #[serde(default)]
    pub runtime_oracles: Option<Vec<String>>,
    /// Postcondition / lifecycle hooks. Requires issue #55.
    #[serde(default)]
    pub postcondition: Option<toml::Value>,
}
