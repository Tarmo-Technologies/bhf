// SPDX-License-Identifier: Apache-2.0

//! `bhf project <validate|list|run>` — define, validate, and run an external
//! project/target-profile manifest (`bhf.project.v1`) kept entirely outside the
//! bhf source tree.
//!
//! This module is the only bridge between the pure [`project_profile`] crate
//! (parse / validate / resolve+hash / lower) and the existing fuzzing engines
//! (`bhf fuzz` for `builtin`/`afl++`, `bhf binary fuzz` for `binary`). It adds
//! **no new execution path**: `run` materializes an isolated work directory from
//! a resolved target and dispatches to the same `fuzz::run` / `binary_fuzz::run`
//! entry points a hand-driven run would use, then records provenance (the
//! manifest hash + every asset's SHA-256 + the resolved, redacted launch) so
//! findings, replay, minimization, and run summaries retain project/target
//! identity for importers (SARIF / vulnerability-management tooling).
//!
//! The manifest is only ever loaded through an explicit `--manifest` path — that
//! explicitness **is** the trust boundary. `validate`/`list` never execute a
//! target's build command; `run` does (explicit load = trusted), unless
//! `--skip-build` reuses a prebuilt binary. There is no auto-discovery path, so
//! an untrusted manifest's code never runs.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::Subcommand;
use serde_json::json;

use project_profile::{
    check_bhf_version, load as load_text, lower_target, resolve, validate as validate_manifest,
    AflMode as PpAflMode, BinaryEngine as PpBinaryEngine, BinaryInput, BinaryLaunch, LoweredLaunch,
    Manifest, NativeEngine as PpNativeEngine, NativeLaunch, ProcessEnv, ResolveOptions, Resolved,
    ResolvedExtension, RunContext, RuntimeOraclesMode as PpRuntimeOraclesMode,
};

use crate::binary_fuzz::{self, BinaryFuzzArgs, BinaryFuzzEngine, BinaryInputMode};
use crate::fuzz::{self, AflMode, FuzzArgs, FuzzEngine, StructuredInputMode};
use crate::runner::SandboxModeArg;
use crate::runtime_oracles::RuntimeOracleMode;

/// The running bhf version. The CLI package is `bhf`, so its
/// `CARGO_PKG_VERSION` is the bhf version the pure crate must gate against — the
/// pure crate never reads it from `env!` itself (it takes it as a parameter).
const BHF_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Best-effort build target triple of this bhf, captured at build time
/// (`crates/cli/build.rs`). `None` on a build where it was unavailable; v1 does
/// not attempt to detect a prebuilt harness's own compiler.
fn toolchain() -> Option<&'static str> {
    option_env!("BHF_TARGET")
}

/// `bhf project <validate|list|run>` — define, validate, and run an external
/// project/target-profile manifest kept outside the bhf source tree.
#[derive(Debug, clap::Args)]
pub struct ProjectArgs {
    #[command(subcommand)]
    command: ProjectCommand,
}

#[derive(Debug, Subcommand)]
pub enum ProjectCommand {
    /// Resolve and hash every referenced asset, type-check each target's launch, and report problems (missing assets, duplicate ids, unsupported schema/bhf version, invalid relative paths, unsafe secret interpolation) WITHOUT running a campaign or the build command
    Validate(ValidateArgs),
    /// List the targets declared in the manifest with their engine, input mode, and a summary of declared seeds/dictionaries/grammar
    List(ListArgs),
    /// Materialize an isolated work directory from a target, resolve+hash its assets, write provenance, and run its campaign on the configured engine (builtin/afl++ or binary)
    Run(RunArgs),
}

#[derive(Debug, clap::Args)]
pub struct ValidateArgs {
    /// Path to the `bhf.project.v1` manifest (TOML). Explicit load is the trust
    /// boundary; this is never auto-discovered.
    #[arg(long)]
    manifest: PathBuf,
    /// Validate only this target (default: every declared target).
    #[arg(long)]
    target: Option<String>,
    /// Permit assets outside the manifest directory (absolute paths / `..`
    /// escapes). Off by default; a path escape is otherwise rejected.
    #[arg(long = "allow-external-paths")]
    allow_external_paths: bool,
    /// Emit a machine-readable JSON report instead of human-readable lines.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, clap::Args)]
pub struct ListArgs {
    /// Path to the `bhf.project.v1` manifest (TOML).
    #[arg(long)]
    manifest: PathBuf,
    /// Emit a machine-readable JSON summary instead of human-readable lines.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, clap::Args)]
pub struct RunArgs {
    /// Path to the `bhf.project.v1` manifest (TOML). Explicit load is the trust
    /// boundary: `run` executes this target's build command because the manifest
    /// was named explicitly.
    #[arg(long)]
    manifest: PathBuf,
    /// Which target to run (required).
    #[arg(long)]
    target: String,
    /// Isolated work directory. Default:
    /// `./bhf_work_project/<project-id>/<target-id>`.
    #[arg(long = "work-dir")]
    work_dir: Option<PathBuf>,
    /// Permit assets outside the manifest directory (absolute paths / `..`
    /// escapes).
    #[arg(long = "allow-external-paths")]
    allow_external_paths: bool,
    /// Reuse a prebuilt binary; do NOT run the manifest's trusted build command.
    #[arg(long = "skip-build")]
    skip_build: bool,
    /// Emit the resolved provenance as JSON on stdout before the run starts.
    #[arg(long)]
    json: bool,
}

/// Dispatch a `bhf project` invocation, returning a process exit code.
pub fn run(args: ProjectArgs) -> i32 {
    match args.command {
        ProjectCommand::Validate(a) => code_for(run_validate(&a)),
        ProjectCommand::List(a) => code_for(run_list(&a)),
        ProjectCommand::Run(a) => match run_run(&a) {
            Ok(code) => code,
            Err(error) => {
                bhfeprintln!("error: {error:#}");
                2
            }
        },
    }
}

/// Map a unit-returning handler's result to an exit code: 0 on success, 2 on a
/// manifest/validation error (a user-input problem, mirroring clap's usage
/// exit code).
fn code_for(result: Result<()>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(error) => {
            bhfeprintln!("error: {error:#}");
            2
        }
    }
}

/// Load + parse a manifest, returning it, its verbatim text (hashed into
/// provenance), and the directory every relative asset path resolves against.
fn load_manifest(path: &Path) -> Result<(Manifest, String, PathBuf)> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read manifest '{}'", path.display()))?;
    let manifest = load_text(&text)?;
    let manifest_dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    Ok((manifest, text, manifest_dir))
}

fn run_validate(a: &ValidateArgs) -> Result<()> {
    let (manifest, text, manifest_dir) = load_manifest(&a.manifest)?;
    // Structural validation across every target (schema already gated at load):
    // duplicate ids, version floor, unknown engine, missing fields, input-mode
    // compatibility, gated-feature rejection, unsafe secret interpolation. No FS
    // access, no build command.
    validate_manifest(&manifest, BHF_VERSION)?;

    let opts = ResolveOptions {
        allow_external: a.allow_external_paths,
    };
    let ctx = RunContext {
        bhf_version: BHF_VERSION,
        toolchain: toolchain(),
    };
    let env = ProcessEnv;

    // Resolving each target hashes its assets, which is where a missing asset or
    // an invalid relative path is detected — still without spawning anything.
    let target_ids: Vec<String> = match &a.target {
        Some(id) => vec![id.clone()],
        None => manifest.targets.iter().map(|t| t.id.clone()).collect(),
    };
    let mut provenances = Vec::with_capacity(target_ids.len());
    for id in &target_ids {
        let resolved = resolve(&manifest, &text, &manifest_dir, id, &opts, &ctx, &env)?;
        provenances.push(resolved.provenance);
    }

    if a.json {
        let report = json!({
            "ok": true,
            "schema": manifest.schema,
            "project": { "id": manifest.project.id, "version": manifest.project.version },
            "targets": provenances,
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "manifest '{}' valid: project '{}' v{} ({} target(s) checked)",
            a.manifest.display(),
            manifest.project.id,
            manifest.project.version,
            provenances.len()
        );
        for p in &provenances {
            println!(
                "  target '{}' [{}/{}] — {} asset(s), manifest {}…",
                p.target_id,
                p.engine,
                p.input_mode,
                p.assets.len(),
                &p.manifest_sha256[..12.min(p.manifest_sha256.len())]
            );
            for w in &p.warnings {
                bhfeprintln!("  warning: {}", w.message);
            }
        }
    }
    Ok(())
}

fn run_list(a: &ListArgs) -> Result<()> {
    let (manifest, _text, _dir) = load_manifest(&a.manifest)?;
    if a.json {
        let targets: Vec<_> = manifest
            .targets
            .iter()
            .map(|t| {
                json!({
                    "id": t.id,
                    "engine": t.engine,
                    "input_mode": t.input_mode,
                    "seeds": t.seeds.len(),
                    "dictionaries": t.dictionaries.len(),
                    "grammar": t.grammar.is_some(),
                })
            })
            .collect();
        let report = json!({
            "project": { "id": manifest.project.id, "version": manifest.project.version },
            "targets": targets,
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "project '{}' v{} — {} target(s):",
            manifest.project.id,
            manifest.project.version,
            manifest.targets.len()
        );
        for t in &manifest.targets {
            println!(
                "  {} [engine={}, input-mode={}] seeds={} dictionaries={} grammar={}",
                t.id,
                t.engine,
                t.input_mode.as_deref().unwrap_or("(default)"),
                t.seeds.len(),
                t.dictionaries.len(),
                if t.grammar.is_some() { "yes" } else { "no" },
            );
        }
    }
    Ok(())
}

fn run_run(a: &RunArgs) -> Result<i32> {
    let (manifest, text, manifest_dir) = load_manifest(&a.manifest)?;

    // Pre-build soundness of the SELECTED target only (no asset resolution, no
    // build): the version floor plus lowering (engine / input-mode / gated-field
    // rejection). This fails closed BEFORE any build command runs, so a
    // malformed or forward-looking target never triggers execution. A sibling
    // target being forward-looking does not block a sound one.
    check_bhf_version(&manifest, BHF_VERSION)?;
    let target = manifest
        .targets
        .iter()
        .find(|t| t.id == a.target)
        .ok_or_else(|| anyhow!("no target with id '{}' in manifest", a.target))?;
    lower_target(target)?;

    // Isolated work directory.
    let work_dir = match &a.work_dir {
        Some(dir) => dir.clone(),
        None => std::env::current_dir()
            .context("determine current directory for the default work dir")?
            .join("bhf_work_project")
            .join(&manifest.project.id)
            .join(&target.id),
    };
    std::fs::create_dir_all(&work_dir)
        .with_context(|| format!("create work dir '{}'", work_dir.display()))?;
    let work_dir = std::fs::canonicalize(&work_dir)
        .with_context(|| format!("canonicalize work dir '{}'", work_dir.display()))?;

    // Trusted build command (explicit load = trusted). `--skip-build` reuses a
    // prebuilt binary and never runs it.
    if !a.skip_build {
        if let Some(cmd) = &target.build_command {
            run_build_command(cmd, &manifest_dir)?;
        }
    }

    // Resolve + hash every asset (the binary now exists, whether prebuilt or
    // just produced by the build command) and assemble the redacted provenance.
    let opts = ResolveOptions {
        allow_external: a.allow_external_paths,
    };
    let ctx = RunContext {
        bhf_version: BHF_VERSION,
        toolchain: toolchain(),
    };
    let env = ProcessEnv;
    let resolved = resolve(
        &manifest,
        &text,
        &manifest_dir,
        &target.id,
        &opts,
        &ctx,
        &env,
    )?;

    // Write the authoritative provenance, co-existing with unified results.
    let results_dir = ::corpus::layout::results_dir(&work_dir);
    std::fs::create_dir_all(&results_dir)
        .with_context(|| format!("create results dir '{}'", results_dir.display()))?;
    let provenance_json = serde_json::to_string_pretty(&resolved.provenance)?;
    std::fs::write(results_dir.join("project.json"), &provenance_json)
        .context("write results/project.json")?;

    if a.json {
        println!("{provenance_json}");
    } else {
        println!(
            "project '{}' target '{}' [{}]: running in {}",
            manifest.project.id,
            target.id,
            resolved.provenance.engine,
            work_dir.display()
        );
        for w in &resolved.warnings {
            bhfeprintln!("warning: {}", w.message);
        }
    }

    // Materialize the work dir for the chosen lane and dispatch to the existing
    // engine. The engine writes findings under `results/findings/<id>/`.
    let is_native = matches!(resolved.launch, LoweredLaunch::Native(_));
    let exit = match &resolved.launch {
        LoweredLaunch::Native(launch) => {
            materialize_native(launch, &target.id, &work_dir, &resolved)?;
            let seed_files = expand_seed_files(&resolved.resolved_seeds)?;
            let mut fuzz_args = plan_to_fuzz_args(
                launch,
                &target.id,
                &work_dir,
                seed_files,
                resolved.resolved_grammar.clone(),
                resolved.resolved_env.clone(),
            )?;
            // A project-level `[[extension]]` is materialized as a trusted
            // `bhf.extension-manifest.v1` in the work dir and loaded by the run,
            // converging the standalone manifest onto the project profile.
            if let Some(extension) = &resolved.resolved_extension {
                let manifest_path = materialize_extension_manifest(extension, &work_dir)?;
                fuzz_args.extension = Some(manifest_path);
            }
            fuzz::run(fuzz_args)
        }
        LoweredLaunch::Binary(launch) => {
            if resolved.resolved_extension.is_some() {
                bhfeprintln!(
                    "warning: [[extension]] is loaded only on native-engine runs; \
                     the binary lane ignores it"
                );
            }
            let seed_files = expand_seed_files(&resolved.resolved_seeds)?;
            let binary_args = plan_to_binary_fuzz_args(
                launch,
                &resolved.resolved_binary,
                &work_dir,
                seed_files,
                resolved.resolved_env.clone(),
            )?;
            binary_fuzz::run(binary_args)
        }
    };

    // Stamp project/target identity onto every finding (and, for the native
    // lane, the run-summary dir) so replay/minimize carry it forward.
    stamp_provenance(&work_dir, &provenance_json, is_native)?;

    Ok(exit)
}

/// Materialize a resolved `[[extension]]` as a standalone
/// `bhf.extension-manifest.v1` TOML in the work dir and return its path, so the
/// run loads it through the same trusted-extension path as `bhf fuzz
/// --extension`. The executable is written as its resolved absolute path with
/// `allow-external-paths = true`, so load-time path resolution accepts it.
fn materialize_extension_manifest(
    extension: &ResolvedExtension,
    work_dir: &Path,
) -> Result<PathBuf> {
    /// A serializable view matching the `bhf.extension-manifest.v1` schema.
    #[derive(serde::Serialize)]
    #[serde(rename_all = "kebab-case")]
    struct Doc<'a> {
        schema: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: &'a Option<String>,
        executable: String,
        allow_external_paths: bool,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        args: &'a Vec<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        required_capabilities: &'a Vec<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        optional_capabilities: &'a Vec<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        env_passthrough: &'a Vec<String>,
        #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
        env: &'a std::collections::BTreeMap<String, String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        format: &'a Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        limits: &'a Option<project_profile::ExtensionLimits>,
    }

    let doc = Doc {
        schema: "bhf.extension-manifest.v1",
        id: &extension.id,
        executable: extension.resolved_executable.display().to_string(),
        allow_external_paths: true,
        args: &extension.args,
        required_capabilities: &extension.required_capabilities,
        optional_capabilities: &extension.optional_capabilities,
        env_passthrough: &extension.env_passthrough,
        env: &extension.env,
        format: &extension.format,
        limits: &extension.limits,
    };
    let text = toml::to_string(&doc).context("serialize materialized extension manifest")?;
    let path = work_dir.join("extension.toml");
    std::fs::write(&path, text)
        .with_context(|| format!("write materialized extension manifest '{}'", path.display()))?;
    Ok(path)
}

/// Run a target's trusted build command (argv form) with the manifest directory
/// as its working directory. A non-zero exit is a hard error.
fn run_build_command(cmd: &[String], cwd: &Path) -> Result<()> {
    let (program, rest) = cmd
        .split_first()
        .ok_or_else(|| anyhow!("build-command is empty"))?;
    let status = std::process::Command::new(program)
        .args(rest)
        .current_dir(cwd)
        .status()
        .with_context(|| format!("spawn build-command '{program}'"))?;
    if !status.success() {
        return Err(anyhow!("build-command '{program}' failed: {status}"));
    }
    Ok(())
}

/// Copy the resolved harness binary to the exact path `find_harness_executable`
/// probes first (`<work>/build/<id>/main[_afl]`) and write the merged dictionary
/// where `find_generated_dictionary` looks (`<work>/build/<id>/dictionary.txt`),
/// so the engine auto-loads both with the operator copying nothing.
fn materialize_native(
    launch: &NativeLaunch,
    target_id: &str,
    work_dir: &Path,
    resolved: &Resolved,
) -> Result<()> {
    let build_dir = work_dir.join("build").join(target_id);
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("create harness build dir '{}'", build_dir.display()))?;

    let main_name = match launch.engine {
        PpNativeEngine::AflPlusPlus => "main_afl",
        PpNativeEngine::Builtin => "main",
    };
    let dest = build_dir.join(main_name);
    std::fs::copy(&resolved.resolved_binary, &dest).with_context(|| {
        format!(
            "materialize harness '{}' to '{}'",
            resolved.resolved_binary.display(),
            dest.display()
        )
    })?;
    make_executable(&dest)?;

    if !resolved.merged_dictionary.tokens.is_empty() {
        std::fs::write(
            build_dir.join("dictionary.txt"),
            resolved.merged_dictionary.to_afl_format(),
        )
        .context("materialize merged dictionary")?;
    }
    Ok(())
}

/// Write the provenance sidecar into every finding directory, and — on the
/// native lane — the run-summary directory. `bhf minimize` edits a finding dir
/// in place and `bhf replay` only reads, so neither prunes this sidecar.
fn stamp_provenance(work_dir: &Path, provenance_json: &str, native: bool) -> Result<()> {
    let findings = ::corpus::layout::findings_dir(work_dir);
    if findings.is_dir() {
        for entry in std::fs::read_dir(&findings)
            .with_context(|| format!("read findings dir '{}'", findings.display()))?
        {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                std::fs::write(
                    entry.path().join("project-provenance.json"),
                    provenance_json,
                )
                .with_context(|| format!("stamp provenance onto '{}'", entry.path().display()))?;
            }
        }
    }
    if native {
        let runs = work_dir.join("fuzz_runs");
        if runs.is_dir() {
            std::fs::write(runs.join("project-provenance.json"), provenance_json)
                .context("stamp provenance onto the run-summary dir")?;
        }
    }
    Ok(())
}

/// Expand resolved seed paths into concrete seed files: a directory becomes its
/// files (recursive, sorted, matching the provenance hash walk), a file passes
/// through. The engines read each `--seed-file` as a single file.
fn expand_seed_files(resolved_seeds: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for seed in resolved_seeds {
        if seed.is_dir() {
            collect_files_sorted(seed, &mut out)
                .with_context(|| format!("enumerate seed dir '{}'", seed.display()))?;
        } else {
            out.push(seed.clone());
        }
    }
    Ok(out)
}

fn collect_files_sorted(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_files_sorted(&path, out)?;
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

/// Lower a native launch plan onto `FuzzArgs`. Pure over its inputs (no FS), so
/// it is unit-tested directly. There is no `Default` for `FuzzArgs`, so every
/// field is spelled out; manifest-unset fields take the defaults clap would
/// apply, which means a future field added to `FuzzArgs` fails this to compile
/// until it is mapped — a welcome compile-time tripwire.
fn plan_to_fuzz_args(
    launch: &NativeLaunch,
    harness_id: &str,
    work_dir: &Path,
    seed_files: Vec<PathBuf>,
    grammar_file: Option<PathBuf>,
    extra_env: Vec<(String, String)>,
) -> Result<FuzzArgs> {
    Ok(FuzzArgs {
        work_dir: work_dir.to_path_buf(),
        harness: harness_id.to_owned(),
        engine: match launch.engine {
            PpNativeEngine::Builtin => FuzzEngine::Builtin,
            PpNativeEngine::AflPlusPlus => FuzzEngine::AflPlusPlus,
        },
        afl_mode: match launch.afl_mode {
            PpAflMode::Native => AflMode::Native,
            PpAflMode::Qemu => AflMode::Qemu,
            PpAflMode::Frida => AflMode::Frida,
        },
        afl_path: launch.afl_path.clone(),
        // A single manifest range maps to one repeatable `--afl-inst-range`.
        afl_inst_ranges: launch.afl_inst_ranges.clone().into_iter().collect(),
        workers: None,
        iterations: None,
        time: resolve_duration(&launch.time)?,
        max_len: resolve_max_len(&launch.max_len)?,
        len_control: crate::fuzz::DEFAULT_LEN_CONTROL,
        timeout: resolve_duration(&launch.timeout)?,
        deadline: None,
        print_final_stats: false,
        rss_limit_mb: launch.rss_limit_mb.unwrap_or(0) as usize,
        fork_server: false,
        no_fork_server: false,
        seed_inputs: Vec::new(),
        seed_files,
        sanitizers: Vec::new(),
        symbolic_seed_sources: Vec::new(),
        rng_seed: 0x4756_4655_5a5a,
        // A manifest `sandbox = true` opts into the best available sandbox;
        // unset / `false` runs direct (`None`), not clap's `Auto`, so an
        // explicit opt-out is honored.
        sandbox: if launch.sandbox {
            SandboxModeArg::Auto
        } else {
            SandboxModeArg::None
        },
        mode: actionability::RunMode::Reporting,
        sandbox_tool: None,
        sandbox_strict: false,
        extra_env,
        runtime_oracles: map_runtime_oracles(launch.runtime_oracles),
        cmplog_log: None,
        grammar_file,
        structured_inputs: StructuredInputMode::Auto,
        bhf_bin: None,
        stop_after_findings: None,
        target_transport: None,
        transport_coverage_map: None,
        protocol_profile: None,
        session_transport: None,
        session_reset: crate::session_fuzz::SessionResetMode::Reconnect,
        max_session_messages: 64,
        collector: crate::collector_run::CollectorSpec::Off,
        collector_window_ms: crate::collector_run::DEFAULT_WINDOW_MS,
        // A project-level `[[extension]]`, when declared, is materialized and
        // wired in by `run_run` right after this plan is built (it is not part of
        // the pure lowering). Default to none here.
        extension: None,
    })
}

/// Lower a binary launch plan onto `BinaryFuzzArgs`. Pure over its inputs.
fn plan_to_binary_fuzz_args(
    launch: &BinaryLaunch,
    binary: &Path,
    work_dir: &Path,
    seed_files: Vec<PathBuf>,
    env: Vec<(String, String)>,
) -> Result<BinaryFuzzArgs> {
    Ok(BinaryFuzzArgs {
        binary: binary.to_path_buf(),
        work_dir: work_dir.to_path_buf(),
        input_mode: match launch.input_mode {
            BinaryInput::Stdin => BinaryInputMode::Stdin,
            BinaryInput::File => BinaryInputMode::File,
        },
        iterations: 256,
        seed_inputs: Vec::new(),
        seed_files,
        timeout_ms: launch.timeout_ms.unwrap_or(10_000),
        mem_mb: launch
            .mem_mb
            .map(|m| m.to_string())
            .unwrap_or_else(|| "none".to_owned()),
        env: env.into_iter().map(|(k, v)| format!("{k}={v}")).collect(),
        runner: launch.runner.clone(),
        runner_args: launch.runner_args.clone(),
        target_args: launch.target_args.clone(),
        sandbox: SandboxModeArg::Auto,
        engine: match launch.engine {
            PpBinaryEngine::Builtin => BinaryFuzzEngine::Builtin,
            PpBinaryEngine::AflQemu => BinaryFuzzEngine::AflQemu,
            PpBinaryEngine::Auto => BinaryFuzzEngine::Auto,
        },
        time: launch.time.clone(),
        runtime_oracles: map_runtime_oracles(launch.runtime_oracles),
        setup_command: launch.setup_command.clone(),
        oracle_command: launch.oracle_command.clone(),
        reset_command: launch.reset_command.clone(),
        collector: crate::collector_run::CollectorSpec::Off,
        collector_window_ms: crate::collector_run::DEFAULT_WINDOW_MS,
    })
}

/// Map the pure crate's engine-neutral runtime-oracle mode (#59) onto the CLI's
/// own `RuntimeOracleMode`, shared by the native and binary lanes.
fn map_runtime_oracles(mode: PpRuntimeOraclesMode) -> RuntimeOracleMode {
    match mode {
        PpRuntimeOraclesMode::Auto => RuntimeOracleMode::Auto,
        PpRuntimeOraclesMode::On => RuntimeOracleMode::On,
        PpRuntimeOraclesMode::Off => RuntimeOracleMode::Off,
    }
}

/// Resolve an optional manifest duration string (e.g. `"60s"`, `"5m"`) with the
/// same parser `bhf fuzz --time`/`--timeout` use.
fn resolve_duration(spec: &Option<String>) -> Result<Option<Duration>> {
    match spec {
        None => Ok(None),
        Some(s) => crate::fuzz::parse_duration(s)
            .map(Some)
            .map_err(|e| anyhow!("invalid duration '{s}': {e}")),
    }
}

/// Resolve the manifest `max-len` (`"auto"` or a byte count) to the engine's
/// `usize`. Unset or `"auto"` keeps the built-in mutator's adaptive default.
fn resolve_max_len(max_len: &Option<String>) -> Result<usize> {
    match max_len.as_deref() {
        None | Some("auto") => Ok(crate::fuzz::DEFAULT_MAX_LEN),
        Some(n) => n
            .parse::<usize>()
            .map_err(|_| anyhow!("invalid max-len '{n}' (expected 'auto' or a byte count)")),
    }
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .with_context(|| format!("stat '{}'", path.display()))?
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)
        .with_context(|| format!("set +x on '{}'", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native(engine: PpNativeEngine) -> NativeLaunch {
        NativeLaunch {
            engine,
            afl_mode: PpAflMode::Frida,
            afl_inst_ranges: Some("libfoo.so".to_owned()),
            afl_path: Some(PathBuf::from("/opt/afl")),
            binary: PathBuf::from("prebuilt/harness"),
            seeds: vec![],
            dictionaries: vec![],
            grammar: Some(PathBuf::from("grammar/a.json")),
            env: vec![],
            time: Some("30s".to_owned()),
            timeout: None,
            max_len: Some("4096".to_owned()),
            rss_limit_mb: Some(512),
            sandbox: true,
            runtime_oracles: PpRuntimeOraclesMode::Off,
        }
    }

    /// A minimal binary launch with no composition wrappers, for per-field tests.
    fn binary_launch() -> BinaryLaunch {
        BinaryLaunch {
            engine: PpBinaryEngine::Auto,
            input_mode: BinaryInput::Stdin,
            binary: PathBuf::from("prebuilt/target"),
            seeds: vec![],
            env: vec![],
            timeout_ms: None,
            mem_mb: None,
            time: None,
            runner: None,
            runner_args: Vec::new(),
            target_args: Vec::new(),
            runtime_oracles: PpRuntimeOraclesMode::Off,
            setup_command: None,
            oracle_command: None,
            reset_command: None,
        }
    }

    #[test]
    fn native_plan_maps_to_fuzz_args() {
        let launch = native(PpNativeEngine::AflPlusPlus);
        let args = plan_to_fuzz_args(
            &launch,
            "alpha",
            Path::new("/w"),
            vec![PathBuf::from("/seeds/a"), PathBuf::from("/seeds/b")],
            Some(PathBuf::from("/g/a.json")),
            vec![("PROFILE".to_owned(), "release".to_owned())],
        )
        .unwrap();

        assert_eq!(args.harness, "alpha");
        assert_eq!(args.work_dir, PathBuf::from("/w"));
        assert!(matches!(args.engine, FuzzEngine::AflPlusPlus));
        assert!(matches!(args.afl_mode, AflMode::Frida));
        assert_eq!(args.afl_inst_ranges, vec!["libfoo.so".to_owned()]);
        assert_eq!(args.afl_path, Some(PathBuf::from("/opt/afl")));
        assert_eq!(
            args.seed_files,
            vec![PathBuf::from("/seeds/a"), PathBuf::from("/seeds/b")]
        );
        assert_eq!(args.grammar_file, Some(PathBuf::from("/g/a.json")));
        assert_eq!(
            args.extra_env,
            vec![("PROFILE".to_owned(), "release".to_owned())]
        );
        assert_eq!(args.time, Some(Duration::from_secs(30)));
        assert_eq!(args.max_len, 4096);
        assert_eq!(args.rss_limit_mb, 512);
        // sandbox = true opts into the best available sandbox.
        assert!(matches!(args.sandbox, SandboxModeArg::Auto));
        // No runtime oracles declared → off (crash-only), the native default.
        assert!(matches!(args.runtime_oracles, RuntimeOracleMode::Off));
    }

    #[test]
    fn native_plan_maps_runtime_oracles() {
        let mut launch = native(PpNativeEngine::Builtin);
        launch.runtime_oracles = PpRuntimeOraclesMode::On;
        let args = plan_to_fuzz_args(&launch, "a", Path::new("/w"), vec![], None, vec![]).unwrap();
        assert!(matches!(args.runtime_oracles, RuntimeOracleMode::On));
    }

    #[test]
    fn native_unset_sandbox_runs_direct() {
        let mut launch = native(PpNativeEngine::Builtin);
        launch.sandbox = false;
        let args = plan_to_fuzz_args(&launch, "a", Path::new("/w"), vec![], None, vec![]).unwrap();
        assert!(matches!(args.sandbox, SandboxModeArg::None));
        assert!(matches!(args.engine, FuzzEngine::Builtin));
    }

    #[test]
    fn binary_plan_maps_to_binary_fuzz_args() {
        let mut launch = binary_launch();
        launch.input_mode = BinaryInput::File;
        launch.timeout_ms = Some(5000);
        launch.mem_mb = Some(256);
        launch.time = Some("1m".to_owned());
        let args = plan_to_binary_fuzz_args(
            &launch,
            Path::new("/abs/target"),
            Path::new("/w"),
            vec![PathBuf::from("/seeds/s0")],
            vec![("K".to_owned(), "V".to_owned())],
        )
        .unwrap();

        assert_eq!(args.binary, PathBuf::from("/abs/target"));
        assert_eq!(args.work_dir, PathBuf::from("/w"));
        assert!(matches!(args.input_mode, BinaryInputMode::File));
        assert!(matches!(args.engine, BinaryFuzzEngine::Auto));
        assert_eq!(args.timeout_ms, 5000);
        assert_eq!(args.mem_mb, "256");
        assert_eq!(args.seed_files, vec![PathBuf::from("/seeds/s0")]);
        assert_eq!(args.env, vec!["K=V".to_owned()]);
        assert_eq!(args.time, Some("1m".to_owned()));
        // No composition wrappers declared → defaults.
        assert!(args.runner.is_none());
        assert!(args.runner_args.is_empty());
        assert!(args.target_args.is_empty());
        assert!(matches!(args.runtime_oracles, RuntimeOracleMode::Off));
        assert!(args.oracle_command.is_none());
    }

    #[test]
    fn binary_plan_maps_runner_target_args_and_postcondition() {
        // The composed binary launch (#47/#59/#55) maps every field onto the
        // real `BinaryFuzzArgs`, so `bhf project run` drives a runner + fixed
        // argv + semantic-oracle hooks + runtime oracles.
        let mut launch = binary_launch();
        launch.engine = PpBinaryEngine::Builtin;
        launch.input_mode = BinaryInput::File;
        launch.runner = Some("wine".to_owned());
        launch.runner_args = vec!["--mode".to_owned(), "fuzz".to_owned()];
        launch.target_args = vec!["@@".to_owned()];
        launch.runtime_oracles = PpRuntimeOraclesMode::Auto;
        launch.setup_command = Some("./prepare-case".to_owned());
        launch.oracle_command = Some("./check-postcondition".to_owned());
        launch.reset_command = Some("./reset-case".to_owned());

        let args = plan_to_binary_fuzz_args(
            &launch,
            Path::new("/abs/target"),
            Path::new("/w"),
            vec![],
            vec![],
        )
        .unwrap();

        assert!(matches!(args.engine, BinaryFuzzEngine::Builtin));
        assert_eq!(args.runner.as_deref(), Some("wine"));
        assert_eq!(
            args.runner_args,
            vec!["--mode".to_owned(), "fuzz".to_owned()]
        );
        assert_eq!(args.target_args, vec!["@@".to_owned()]);
        assert!(matches!(args.runtime_oracles, RuntimeOracleMode::Auto));
        assert_eq!(args.setup_command.as_deref(), Some("./prepare-case"));
        assert_eq!(
            args.oracle_command.as_deref(),
            Some("./check-postcondition")
        );
        assert_eq!(args.reset_command.as_deref(), Some("./reset-case"));
    }

    #[test]
    fn binary_plan_defaults_mem_and_timeout() {
        let launch = binary_launch();
        let args =
            plan_to_binary_fuzz_args(&launch, Path::new("/t"), Path::new("/w"), vec![], vec![])
                .unwrap();
        assert_eq!(args.timeout_ms, 10_000);
        assert_eq!(args.mem_mb, "none");
        assert!(matches!(args.input_mode, BinaryInputMode::Stdin));
    }

    #[test]
    fn max_len_auto_keeps_default() {
        assert_eq!(
            resolve_max_len(&Some("auto".to_owned())).unwrap(),
            crate::fuzz::DEFAULT_MAX_LEN
        );
        assert_eq!(
            resolve_max_len(&None).unwrap(),
            crate::fuzz::DEFAULT_MAX_LEN
        );
        assert_eq!(resolve_max_len(&Some("8192".to_owned())).unwrap(), 8192);
        assert!(resolve_max_len(&Some("huge".to_owned())).is_err());
    }
}
