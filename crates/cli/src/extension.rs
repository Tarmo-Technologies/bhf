// SPDX-License-Identifier: Apache-2.0

//! `bhf extension <validate|evaluate>` — drive an explicitly-trusted,
//! out-of-process extension speaking the versioned `bhf.extension.v1` protocol.
//!
//! An extension is **never** auto-discovered or implicitly executed: the operator
//! names an explicit `--manifest` path, and that explicitness **is** the trust
//! boundary (mirroring `bhf project`). `validate` spawns the extension, performs
//! the handshake + capability negotiation, and reports the negotiated protocol
//! version, capabilities, and the executable/config hashes — without driving any
//! case. `evaluate` drives `oracle.evaluate` over one input so a clean-exit
//! semantic violation becomes a stable, replayable finding; every extension
//! crash, timeout, oversized/malformed response, or unsupported reply is a
//! **bounded infrastructure result** that can never masquerade as a target bug.
//!
//! The same `oracle.evaluate` path is reused by `bhf fuzz --extension` via
//! [`drive_fuzz_extension`], which evaluates a campaign's retained corpus after
//! the run (never in the hot mutation loop).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use serde_json::{json, Value};

use corpus::{ExtensionFinding, FindingEmitter};
use extension_host::{
    CaseId, EvaluateOutcome, ExtensionClient, ExtensionManifest, FindingResult, InfraFailure,
};

/// Clean: the input was evaluated and is benign (no finding, no fault).
const EXIT_OK: i32 = 0;
/// At least one semantic finding was emitted.
const EXIT_FINDING: i32 = 1;
/// A manifest / usage / setup problem (mirrors clap's usage exit code).
const EXIT_USAGE: i32 = 2;
/// A bounded extension-side infrastructure failure (crash/timeout/oversize/
/// malformed/unsupported). Deliberately distinct from clean and from finding so a
/// fault is never confused with a target result.
const EXIT_INFRA: i32 = 4;

/// `bhf extension <validate|evaluate>`.
#[derive(Debug, clap::Args)]
pub struct ExtensionArgs {
    #[command(subcommand)]
    command: ExtensionCommand,
}

#[derive(Debug, Subcommand)]
pub enum ExtensionCommand {
    /// Load an explicitly-trusted extension manifest, spawn the extension, negotiate the bhf.extension.v1 protocol + capabilities, and print the negotiated protocol version, required/negotiated capabilities, and executable/config SHA-256 — WITHOUT driving any case
    Validate(ValidateArgs),
    /// Drive oracle.evaluate over one input through a trusted extension: a clean-exit semantic violation becomes a replayable finding; a crash/timeout/oversized/malformed/unsupported reply is a bounded infrastructure result, never a target finding
    Evaluate(EvaluateArgs),
}

#[derive(Debug, clap::Args)]
pub struct ValidateArgs {
    /// Path to the `bhf.extension-manifest.v1` manifest (TOML). Explicit load is
    /// the trust boundary; an extension is never auto-discovered.
    #[arg(long)]
    manifest: PathBuf,
    /// Emit a machine-readable JSON report instead of human-readable lines.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, clap::Args)]
pub struct EvaluateArgs {
    /// Path to the `bhf.extension-manifest.v1` manifest (TOML). Explicit load is
    /// the trust boundary; an extension is never auto-discovered.
    #[arg(long)]
    manifest: PathBuf,
    /// File whose raw bytes are the test input handed to `oracle.evaluate`.
    #[arg(long)]
    input: PathBuf,
    /// Work directory a finding (and the run's `extension.json` provenance) is
    /// written under (`<work>/results/findings/…`).
    #[arg(long = "work")]
    work: PathBuf,
    /// Emit a machine-readable JSON report instead of human-readable lines.
    #[arg(long)]
    json: bool,
}

/// Dispatch a `bhf extension` invocation, returning a process exit code.
pub fn run(args: ExtensionArgs) -> i32 {
    match args.command {
        ExtensionCommand::Validate(a) => run_validate(&a),
        ExtensionCommand::Evaluate(a) => run_evaluate(&a),
    }
}

/// Load + validate the manifest, then spawn and handshake with the extension.
/// Any failure here (bad manifest, failed spawn, unsupported protocol, missing
/// required capability) aborts *before* any case is driven — that is the point of
/// validate/negotiate-first.
fn load_and_spawn(manifest_path: &Path) -> Result<(ExtensionManifest, ExtensionClient), String> {
    let manifest = ExtensionManifest::load(manifest_path).map_err(|e| e.to_string())?;
    let client =
        ExtensionClient::from_manifest(&manifest, manifest_path).map_err(|e| e.to_string())?;
    Ok((manifest, client))
}

fn run_validate(a: &ValidateArgs) -> i32 {
    let (manifest, client) = match load_and_spawn(&a.manifest) {
        Ok(pair) => pair,
        Err(error) => {
            bhfeprintln!("error: extension validation failed: {error}");
            return EXIT_USAGE;
        }
    };
    let negotiated = client.negotiated();
    let provenance = client.provenance();

    if a.json {
        let report = json!({
            "ok": true,
            "manifest": a.manifest.display().to_string(),
            "protocol_version": negotiated.protocol,
            "required_capabilities": manifest.required_capabilities,
            "negotiated_capabilities": negotiated.caps,
            "executable_sha256": provenance.executable_sha256,
            "config_sha256": provenance.config_sha256,
            "extension_name": negotiated.extension_name,
            "extension_version": negotiated.extension_version,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("extension manifest '{}' valid", a.manifest.display());
        println!("  protocol: {}", negotiated.protocol);
        if let Some(name) = &negotiated.extension_name {
            let version = negotiated.extension_version.as_deref().unwrap_or("?");
            println!("  extension: {name} v{version}");
        }
        println!(
            "  required capabilities: {}",
            join_caps(&manifest.required_capabilities)
        );
        println!("  negotiated capabilities: {}", join_caps(&negotiated.caps));
        println!("  executable sha256: {}", provenance.executable_sha256);
        if let Some(config) = &provenance.config_sha256 {
            println!("  config sha256: {config}");
        }
    }
    EXIT_OK
}

fn run_evaluate(a: &EvaluateArgs) -> i32 {
    let input = match std::fs::read(&a.input) {
        Ok(bytes) => bytes,
        Err(error) => {
            bhfeprintln!(
                "error: could not read input '{}': {error}",
                a.input.display()
            );
            return EXIT_USAGE;
        }
    };
    if let Err(error) = crate::workdir::prepare(&a.work) {
        bhfeprintln!(
            "error: could not prepare work dir '{}': {error:#}",
            a.work.display()
        );
        return EXIT_USAGE;
    }
    // `workdir::prepare` is a no-op for a missing dir (it only migrates an existing
    // one), so create the work dir here — the run's `extension.json` provenance is
    // written even when no finding is emitted.
    if let Err(error) = std::fs::create_dir_all(&a.work) {
        bhfeprintln!(
            "error: could not create work dir '{}': {error}",
            a.work.display()
        );
        return EXIT_USAGE;
    }

    let (_manifest, mut client) = match load_and_spawn(&a.manifest) {
        Ok(pair) => pair,
        Err(error) => {
            bhfeprintln!("error: extension setup failed: {error}");
            return EXIT_USAGE;
        }
    };

    let case = CaseId::new(campaign_id(&a.work), "0", testcase_id(&a.input, &input));
    // The finding-provenance block (executable/config hashes, protocol version,
    // negotiated caps) is stable across the session, so capture it once.
    let finding_block = client.provenance().finding_block();

    let outcome = match client.evaluate(&case, &input) {
        Ok(outcome) => outcome,
        Err(error) => {
            // A setup/transport error raised as `ExtensionError` (not a bounded
            // per-call fault) — report and exit as a usage/setup problem.
            bhfeprintln!("error: extension evaluate failed: {error}");
            return EXIT_USAGE;
        }
    };

    let mut emitted = 0usize;
    let (code, result_label) = match &outcome {
        EvaluateOutcome::Ok => (EXIT_OK, "ok".to_string()),
        EvaluateOutcome::Reject { .. } => (EXIT_OK, "reject".to_string()),
        EvaluateOutcome::Finding(finding) => {
            let emitter = FindingEmitter::new(a.work.clone());
            match emitter.emit_extension_finding(
                &input,
                &extension_finding_from(finding, finding_block.clone()),
            ) {
                Ok(id) => {
                    emitted = 1;
                    if !a.json {
                        println!("extension finding emitted: {}", id.0);
                    }
                    (EXIT_FINDING, "finding".to_string())
                }
                Err(error) => {
                    bhfeprintln!("error: could not write extension finding: {error}");
                    return EXIT_USAGE;
                }
            }
        }
        EvaluateOutcome::Unsupported { detail } => {
            (EXIT_INFRA, infra_label("unsupported", detail.as_deref()))
        }
        EvaluateOutcome::Infrastructure(failure) => (EXIT_INFRA, infra_failure_label(failure)),
    };

    // Record run-level provenance so a consumer can audit which trusted extension
    // ran, what it negotiated, and whether it suffered restart/loss events.
    let provenance = client.provenance();
    let run_record = json!({
        "schema_version": EXTENSION_RUN_SCHEMA,
        "manifest": a.manifest.display().to_string(),
        "result": result_label,
        "findings": emitted,
        "provenance": provenance,
    });
    if let Err(error) = write_run_provenance(&a.work, &run_record) {
        bhfeprintln!("warning: could not write extension run provenance: {error}");
    }

    if a.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&run_record).unwrap_or_else(|_| "{}".to_string())
        );
    } else if emitted == 0 {
        println!("extension evaluate: {result_label} (no finding)");
    }
    code
}

/// The schema identifier of the run-level `extension.json` provenance record.
const EXTENSION_RUN_SCHEMA: &str = "bhf.extension-run.v1";

/// Drive `oracle.evaluate` over a campaign's retained inputs after a fuzz run.
///
/// Reuses the same trusted-manifest load, client, finding emitter, and bounded
/// fault handling as `bhf extension evaluate` — an extension fault NEVER aborts
/// the campaign nor becomes a target finding. Returns an optional additive
/// `extension` block for the fuzz run summary (never changes its
/// `schema_version`). Findings are deduplicated at the DEFECT level within the
/// pass so one defect re-triggered on many inputs emits a single finding.
pub(crate) fn drive_fuzz_extension<'a, I>(
    manifest_path: &Path,
    emitter: &FindingEmitter,
    campaign: &str,
    inputs: I,
) -> Value
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let (_manifest, mut client) = match load_and_spawn(manifest_path) {
        Ok(pair) => pair,
        Err(error) => {
            // A failed trusted load/handshake is bounded infrastructure, not a
            // target bug: record it and leave the campaign's findings untouched.
            return json!({
                "active": true,
                "manifest": manifest_path.display().to_string(),
                "error": error,
                "evaluated": 0,
                "findings": 0,
                "infrastructure_errors": 1,
            });
        }
    };

    let finding_block = client.provenance().finding_block();
    let negotiated_protocol = client.negotiated().protocol.clone();
    let negotiated_caps = client.negotiated().caps.clone();

    let mut evaluated = 0usize;
    let mut findings = 0usize;
    let mut infrastructure_errors = 0usize;
    let mut seen_defects: HashSet<String> = HashSet::new();

    for (index, input) in inputs.into_iter().enumerate() {
        evaluated += 1;
        let case = CaseId::new(
            campaign,
            "ext-0",
            format!("{index}-{}", short_digest(input)),
        );
        match client.evaluate(&case, input) {
            Ok(EvaluateOutcome::Finding(finding)) => {
                let defect = format!("{}|{}", finding.rule, finding.classification);
                if seen_defects.insert(defect)
                    && emitter
                        .emit_extension_finding(
                            input,
                            &extension_finding_from(&finding, finding_block.clone()),
                        )
                        .is_ok()
                {
                    findings += 1;
                }
            }
            Ok(EvaluateOutcome::Ok | EvaluateOutcome::Reject { .. }) => {}
            Ok(EvaluateOutcome::Unsupported { .. } | EvaluateOutcome::Infrastructure(_)) => {
                infrastructure_errors += 1;
            }
            Err(_) => {
                // A hard transport/setup error ends the pass; it is bounded
                // infrastructure, never a target finding.
                infrastructure_errors += 1;
                break;
            }
        }
    }

    let provenance = client.provenance();
    json!({
        "active": true,
        "manifest": manifest_path.display().to_string(),
        "protocol_version": negotiated_protocol,
        "negotiated_capabilities": negotiated_caps,
        "evaluated": evaluated,
        "findings": findings,
        "infrastructure_errors": infrastructure_errors,
        "provenance": provenance,
    })
}

fn extension_finding_from(finding: &FindingResult, provenance: Value) -> ExtensionFinding {
    ExtensionFinding {
        rule: finding.rule.clone(),
        classification: finding.classification.clone(),
        signature_inputs: finding.signature_inputs.clone(),
        evidence: finding
            .evidence
            .iter()
            .map(|e| (e.key.clone(), e.value.clone()))
            .collect(),
        min_predicate: finding.min_predicate.clone(),
        provenance,
    }
}

fn join_caps(caps: &[String]) -> String {
    if caps.is_empty() {
        "(none)".to_string()
    } else {
        caps.join(", ")
    }
}

fn infra_label(kind: &str, detail: Option<&str>) -> String {
    match detail {
        Some(detail) => format!("{kind}: {detail}"),
        None => kind.to_string(),
    }
}

fn infra_failure_label(failure: &InfraFailure) -> String {
    match failure {
        InfraFailure::Timeout { after } => format!("infrastructure_error: timeout after {after:?}"),
        InfraFailure::Crashed { status, signal } => format!(
            "infrastructure_error: extension crashed (status={status:?}, signal={signal:?})"
        ),
        InfraFailure::FrameTooLarge { declared, cap } => {
            format!("infrastructure_error: oversized frame (declared={declared}, cap={cap})")
        }
        InfraFailure::Protocol { detail } => format!("infrastructure_error: protocol: {detail}"),
        InfraFailure::CaseMismatch { .. } => {
            "infrastructure_error: response case identity did not match the request".to_string()
        }
        InfraFailure::ExtensionReported { detail } => {
            infra_label("infrastructure_error", detail.as_deref())
        }
    }
}

/// Write the run-level `extension.json` provenance next to the work dir.
fn write_run_provenance(work: &Path, record: &Value) -> std::io::Result<()> {
    std::fs::write(
        work.join("extension.json"),
        serde_json::to_vec_pretty(record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
    )
}

/// A stable campaign id for a standalone `evaluate` (the work dir's name).
fn campaign_id(work: &Path) -> String {
    work.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "extension-evaluate".to_string())
}

/// A testcase id for a standalone `evaluate` (the input file name, plus a short
/// content digest to disambiguate).
fn testcase_id(path: &Path, bytes: &[u8]) -> String {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "input".to_string());
    format!("{name}-{}", short_digest(bytes))
}

/// A short (16 hex chars) sha256 of `bytes`, for case-id disambiguation.
fn short_digest(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
        .chars()
        .take(16)
        .collect()
}
