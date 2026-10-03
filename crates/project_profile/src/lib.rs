// SPDX-License-Identifier: Apache-2.0

//! `project_profile` — parse, validate, resolve, hash, and lower a
//! `bhf.project.v1` external project/target-profile manifest.
//!
//! This crate is **pure**: it never spawns a process, runs a campaign, or
//! executes a manifest's build command, and it never depends on the CLI. It
//! turns an explicitly-loaded manifest (TOML) into an engine-neutral launch
//! plan plus a redacted provenance record, so the whole surface is unit-testable
//! on every platform and the CLI (a separate crate) can wire it onto the
//! existing fuzzing engines without any new execution path.
//!
//! The manifest composes a private harness (source or prebuilt binary) with its
//! corpora, layered dictionaries, grammar, and launch settings — all kept
//! outside the bhf source tree — under one or more stable target ids. The
//! resolved provenance (manifest hash + every asset's SHA-256 + the resolved,
//! redacted launch) lets importers (SARIF / vulnerability-management tooling)
//! tie findings, replay, and run summaries back to an exact project/target.
//!
//! ## Pipeline
//!
//! 1. [`load`] — parse TOML and gate the `schema` string.
//! 2. [`validate`] — structural checks + `requires-bhf` gate + gated-field
//!    rejection (the caller supplies the running bhf version).
//! 3. [`resolve`] — resolve+hash every asset, merge dictionaries, interpolate
//!    env (secrets redacted), and assemble the [`Provenance`] for one target.

mod dictionary;
mod error;
mod hash;
mod interpolate;
mod lower;
mod paths;
mod provenance;
mod schema;
mod validate;
mod version_req;
mod warning;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub use dictionary::{merge as merge_dictionaries, MergedDictionary, MAX_DICTIONARY_BYTES};
pub use error::ProjectError;
pub use hash::{sha256_asset, sha256_bytes, sha256_file, sha256_seed_dir};
pub use interpolate::{EnvSource, InterpolatedValue, ProcessEnv, ResolvedValue};
pub use lower::{
    lower_target, AflMode, BinaryEngine, BinaryInput, BinaryLaunch, LoweredLaunch, NativeEngine,
    NativeLaunch,
};
pub use paths::{resolve_asset, ResolveOptions};
pub use provenance::{AssetHash, AssetKind, Provenance};
pub use schema::{Extension, ExtensionLimits, Manifest, Project, Target, SCHEMA_V1};
pub use validate::{check_bhf_version, validate};
pub use version_req::satisfied_by;
pub use warning::{Warning, WarningKind};

/// Parse a manifest from TOML text and gate the schema string.
///
/// Rejects a genuine unknown-field typo (via `deny_unknown_fields`) and any
/// `schema` other than [`SCHEMA_V1`]. Gated engine-feature fields still parse
/// here; they are rejected later in [`validate`] / [`resolve`].
pub fn load(text: &str) -> Result<Manifest, ProjectError> {
    let manifest: Manifest = toml::from_str(text)?;
    if manifest.schema != SCHEMA_V1 {
        return Err(ProjectError::UnsupportedSchema {
            found: manifest.schema,
            expected: SCHEMA_V1.to_owned(),
        });
    }
    Ok(manifest)
}

/// The fully-resolved result for one target: the engine-neutral launch plan,
/// the resolved (absolute) asset paths, the merged dictionary, the resolved env
/// (real values, for the process), and the redacted [`Provenance`].
#[derive(Debug, Clone)]
pub struct Resolved {
    /// The engine-neutral launch plan (declared, manifest-relative paths).
    pub launch: LoweredLaunch,
    /// Resolved absolute path to the harness source/binary (native) or target
    /// binary (binary engine).
    pub resolved_binary: PathBuf,
    /// Resolved absolute seed paths, in declared order.
    pub resolved_seeds: Vec<PathBuf>,
    /// Resolved absolute dictionary paths, in layering order.
    pub resolved_dictionaries: Vec<PathBuf>,
    /// Resolved absolute grammar path, if any.
    pub resolved_grammar: Option<PathBuf>,
    /// The merged, de-duplicated dictionary (ready to materialize).
    pub merged_dictionary: MergedDictionary,
    /// The resolved env with **real** values, for handing to the process. Not
    /// serialized into provenance; secrets live here but never in
    /// [`Provenance::redacted_env`].
    pub resolved_env: Vec<(String, String)>,
    /// The redacted provenance record.
    pub provenance: Provenance,
    /// The project-level trusted extension to load for this run, if the manifest
    /// declares one (`[[extension]]`). Native-engine runs load it via
    /// `bhf.extension.v1`; the executable is resolved + hashed into provenance.
    pub resolved_extension: Option<ResolvedExtension>,
    /// Fidelity / compatibility warnings collected during lowering + resolution.
    pub warnings: Vec<Warning>,
}

/// A resolved `[[extension]]`: the absolute executable path plus the fields the
/// CLI needs to materialize a `bhf.extension-manifest.v1` and load it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedExtension {
    /// An optional operator-facing identifier.
    pub id: Option<String>,
    /// The resolved, absolute extension executable path.
    pub resolved_executable: PathBuf,
    /// Fixed arguments passed to the executable.
    pub args: Vec<String>,
    /// Capabilities that MUST be negotiated.
    pub required_capabilities: Vec<String>,
    /// Capabilities used opportunistically.
    pub optional_capabilities: Vec<String>,
    /// Explicit environment to set on the child.
    pub env: BTreeMap<String, String>,
    /// Host environment variable names to forward.
    pub env_passthrough: Vec<String>,
    /// The preferred wire format, if declared.
    pub format: Option<String>,
    /// Resource/limit overrides, if declared.
    pub limits: Option<ExtensionLimits>,
}

/// Inputs the caller injects into [`resolve`] that this crate must not fabricate
/// itself (the running bhf version and build toolchain).
#[derive(Debug, Clone, Copy)]
pub struct RunContext<'a> {
    /// The running bhf version (the `bhf` package's `CARGO_PKG_VERSION`), used
    /// both for the `requires-bhf` gate and recorded in provenance.
    pub bhf_version: &'a str,
    /// Best-effort build target triple of this bhf, recorded in provenance.
    pub toolchain: Option<&'a str>,
}

/// Resolve a single target end to end: validate, lower, resolve+hash every
/// asset, merge dictionaries, interpolate env, and build the provenance record.
///
/// * `manifest` / `manifest_text` — the parsed manifest and its original bytes
///   (hashed verbatim into provenance).
/// * `manifest_dir` — the directory every relative asset path resolves against.
/// * `target_id` — which target to resolve.
/// * `opts` — path-safety options (`allow_external`).
/// * `ctx` — caller-injected bhf version + toolchain.
/// * `env` — the environment / secret source for interpolation.
pub fn resolve(
    manifest: &Manifest,
    manifest_text: &str,
    manifest_dir: &Path,
    target_id: &str,
    opts: &ResolveOptions,
    ctx: &RunContext<'_>,
    env: &dyn EnvSource,
) -> Result<Resolved, ProjectError> {
    // Whole-manifest gates first (fail-closed on version / duplicate ids).
    check_bhf_version(manifest, ctx.bhf_version)?;
    ensure_unique_ids(manifest)?;

    let target = manifest
        .targets
        .iter()
        .find(|t| t.id == target_id)
        .ok_or_else(|| ProjectError::UnknownTarget(target_id.to_owned()))?;

    let (launch, mut warnings) = lower_target(target)?;

    let mut assets = Vec::new();

    // Harness / target binary.
    let (binary_decl, binary_kind) = match &launch {
        LoweredLaunch::Native(n) => (n.binary.clone(), AssetKind::Harness),
        LoweredLaunch::Binary(b) => (b.binary.clone(), AssetKind::Binary),
    };
    let resolved_binary = resolve_and_record(
        manifest_dir,
        &binary_decl,
        opts,
        binary_kind,
        &mut assets,
        &mut warnings,
    )?;

    // Seeds (files and/or directories).
    let seed_decls: &[PathBuf] = match &launch {
        LoweredLaunch::Native(n) => &n.seeds,
        LoweredLaunch::Binary(b) => &b.seeds,
    };
    let mut resolved_seeds = Vec::with_capacity(seed_decls.len());
    for seed in seed_decls {
        resolved_seeds.push(resolve_and_record(
            manifest_dir,
            seed,
            opts,
            AssetKind::Seed,
            &mut assets,
            &mut warnings,
        )?);
    }

    // Dictionaries (native only) — hash each layer, then merge + hash merged.
    let mut resolved_dictionaries = Vec::new();
    let mut merged_dictionary = MergedDictionary::default();
    if let LoweredLaunch::Native(n) = &launch {
        for dict in &n.dictionaries {
            resolved_dictionaries.push(resolve_and_record(
                manifest_dir,
                dict,
                opts,
                AssetKind::Dictionary,
                &mut assets,
                &mut warnings,
            )?);
        }
        merged_dictionary = merge_dictionaries(&resolved_dictionaries)?;
        if !resolved_dictionaries.is_empty() {
            assets.push(AssetHash {
                kind: AssetKind::MergedDictionary,
                path: "<merged>".to_owned(),
                sha256: sha256_bytes(merged_dictionary.to_afl_format().as_bytes()),
            });
        }
    }

    // Grammar (native only).
    let resolved_grammar = match &launch {
        LoweredLaunch::Native(n) => match &n.grammar {
            Some(g) => Some(resolve_and_record(
                manifest_dir,
                g,
                opts,
                AssetKind::Grammar,
                &mut assets,
                &mut warnings,
            )?),
            None => None,
        },
        LoweredLaunch::Binary(_) => None,
    };

    // Env resolution: real values for the launch, handles for provenance.
    let env_entries = match &launch {
        LoweredLaunch::Native(n) => &n.env,
        LoweredLaunch::Binary(b) => &b.env,
    };
    let mut resolved_env = Vec::with_capacity(env_entries.len());
    let mut redacted_env = BTreeMap::new();
    for (key, classified) in env_entries {
        let resolved = interpolate::resolve_classified(classified, env)?;
        redacted_env.insert(key.clone(), resolved.redacted_display());
        resolved_env.push((key.clone(), resolved.value));
    }

    // Project-level trusted extension (`[[extension]]`): resolve + hash its
    // executable so provenance records exactly which extension a run loads.
    let resolved_extension = resolve_extension(manifest, manifest_dir, opts, &mut assets)?;

    let provenance = Provenance {
        schema: manifest.schema.clone(),
        project_id: manifest.project.id.clone(),
        project_version: manifest.project.version.clone(),
        requires_bhf: manifest.project.requires_bhf.clone(),
        manifest_sha256: sha256_bytes(manifest_text.as_bytes()),
        target_id: target.id.clone(),
        engine: target.engine.clone(),
        input_mode: input_mode_label(&launch),
        assets,
        resolved_command: vec![resolved_binary.display().to_string()],
        redacted_env,
        bhf_version: ctx.bhf_version.to_owned(),
        toolchain: ctx.toolchain.map(str::to_owned),
        warnings: warnings.clone(),
    };

    Ok(Resolved {
        launch,
        resolved_binary,
        resolved_seeds,
        resolved_dictionaries,
        resolved_grammar,
        merged_dictionary,
        resolved_env,
        provenance,
        resolved_extension,
        warnings,
    })
}

/// Validate and resolve the project-level `[[extension]]`, if any, hashing its
/// executable into `assets`. Only the first entry is loaded today (a project
/// declares a single trusted extension); additional entries are validated but a
/// warning is not emitted here (the CLI loads the first).
fn resolve_extension(
    manifest: &Manifest,
    manifest_dir: &Path,
    opts: &ResolveOptions,
    assets: &mut Vec<AssetHash>,
) -> Result<Option<ResolvedExtension>, ProjectError> {
    let Some(extension) = manifest.extensions.first() else {
        return Ok(None);
    };
    validate_extension(extension)?;
    let resolved_executable = resolve_asset(manifest_dir, &extension.executable, opts)?;
    assets.push(AssetHash {
        kind: AssetKind::Extension,
        path: extension.executable.display().to_string(),
        sha256: sha256_asset(&resolved_executable)?,
    });
    Ok(Some(ResolvedExtension {
        id: extension.id.clone(),
        resolved_executable,
        args: extension.args.clone(),
        required_capabilities: extension.required_capabilities.clone(),
        optional_capabilities: extension.optional_capabilities.clone(),
        env: extension.env.clone(),
        env_passthrough: extension.env_passthrough.clone(),
        format: extension.format.clone(),
        limits: extension.limits.clone(),
    }))
}

/// Structural checks for a `[[extension]]` entry (fail-closed, descriptive).
pub fn validate_extension(extension: &Extension) -> Result<(), ProjectError> {
    if extension.executable.as_os_str().is_empty() {
        return Err(ProjectError::InvalidExtension {
            id: extension.id.clone(),
            detail: "`executable` must not be empty".to_owned(),
        });
    }
    if let Some(format) = &extension.format {
        if format != "json" {
            return Err(ProjectError::InvalidExtension {
                id: extension.id.clone(),
                detail: format!("unsupported wire format {format:?} (only \"json\" is supported)"),
            });
        }
    }
    Ok(())
}

fn ensure_unique_ids(manifest: &Manifest) -> Result<(), ProjectError> {
    let mut seen = std::collections::BTreeSet::new();
    for t in &manifest.targets {
        if !seen.insert(t.id.as_str()) {
            return Err(ProjectError::DuplicateTargetId(t.id.clone()));
        }
    }
    Ok(())
}

/// Resolve one declared asset path, hash it, record an [`AssetHash`] under its
/// *declared* (manifest-relative) path, and emit an external-path warning when
/// the operator opted a path outside the manifest dir in.
fn resolve_and_record(
    manifest_dir: &Path,
    declared: &Path,
    opts: &ResolveOptions,
    kind: AssetKind,
    assets: &mut Vec<AssetHash>,
    warnings: &mut Vec<Warning>,
) -> Result<PathBuf, ProjectError> {
    let resolved = resolve_asset(manifest_dir, declared, opts)?;
    if opts.allow_external && is_external(declared) {
        warnings.push(Warning::new(
            WarningKind::ExternalPath,
            format!(
                "asset '{}' resolves outside the manifest directory (permitted by \
                 --allow-external-paths)",
                declared.display()
            ),
        ));
    }
    assets.push(AssetHash {
        kind,
        path: declared.display().to_string(),
        sha256: sha256_asset(&resolved)?,
    });
    Ok(resolved)
}

fn is_external(declared: &Path) -> bool {
    use std::path::Component;
    declared.components().any(|c| {
        matches!(
            c,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    })
}

fn input_mode_label(launch: &LoweredLaunch) -> String {
    match launch {
        LoweredLaunch::Native(_) => "framed".to_owned(),
        LoweredLaunch::Binary(b) => match b.input_mode {
            BinaryInput::Stdin => "stdin".to_owned(),
            BinaryInput::File => "file".to_owned(),
        },
    }
}
