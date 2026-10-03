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
    CaseId, CodecOutcome, EvaluateOutcome, ExtensionClient, ExtensionManifest, FindingResult,
    InfraFailure, SessionDriver, SessionOptions, SessionTarget,
};

/// The session capability surface requested (as optional) by `bhf extension
/// session` and `bhf fuzz --extension`, so an extension that provides them is
/// driven even when the manifest listed only `oracle.evaluate` as required.
const SESSION_CAPS: &[&str] = &[
    "codec.decode",
    "codec.encode",
    "codec.repair",
    "mutator.mutate",
    "scenario.next",
    "scenario.observe-response",
    "lifecycle.setup",
    "lifecycle.reset",
    "lifecycle.teardown",
];

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
    /// Drive a full multi-message session through a trusted extension: lifecycle.reset a fresh root, pull each scenario.next message, optionally extension-mutate and codec.repair it before it reaches the target, bind each response (scenario.observe-response) into a later message, then oracle.evaluate the clean-exit outcome. Every extension fault stays a bounded infrastructure result
    Session(SessionCmdArgs),
    /// Minimize an emitted extension-oracle finding by delta-debugging its testcase through oracle.evaluate, accepting a candidate only when it reproduces the SAME stable signature (same rule + signature inputs). Writes min_testcase.bin and records the minimization without ever changing the finding's signature
    Minimize(MinimizeCmdArgs),
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

#[derive(Debug, clap::Args)]
pub struct SessionCmdArgs {
    /// Path to the `bhf.extension-manifest.v1` manifest (TOML). Explicit load is
    /// the trust boundary; an extension is never auto-discovered.
    #[arg(long)]
    manifest: PathBuf,
    /// File whose raw bytes seed the session (e.g. the OPEN path the scenario
    /// drives). The oracle judges this testcase on the clean-exit outcome.
    #[arg(long)]
    input: PathBuf,
    /// Work directory a finding (and the run's `extension.json` provenance) is
    /// written under; the fresh per-case root lives at `<work>/session-root`.
    #[arg(long = "work")]
    work: PathBuf,
    /// Enable extension mutation of each scenario message with this seed
    /// (requires the extension to provide `mutator.mutate`).
    #[arg(long)]
    mutate: Option<u64>,
    /// Repair each (possibly mutated) message's computed fields via
    /// `codec.repair` before it reaches the target (on by default when the
    /// extension provides `codec.repair`).
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    repair: bool,
    /// Emit a machine-readable JSON report instead of human-readable lines.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, clap::Args)]
pub struct MinimizeCmdArgs {
    /// Path to the `bhf.extension-manifest.v1` manifest (TOML) whose oracle judged
    /// the finding. Explicit load is the trust boundary; re-driving the oracle to
    /// minimize is never implicit.
    #[arg(long)]
    manifest: PathBuf,
    /// The extension-oracle finding directory to minimize (holds `finding.json` +
    /// `testcase.bin`); `min_testcase.bin` is written alongside it.
    #[arg(long)]
    finding: PathBuf,
    /// Emit a machine-readable JSON report instead of human-readable lines.
    #[arg(long)]
    json: bool,
}

/// Dispatch a `bhf extension` invocation, returning a process exit code.
pub fn run(args: ExtensionArgs) -> i32 {
    match args.command {
        ExtensionCommand::Validate(a) => run_validate(&a),
        ExtensionCommand::Evaluate(a) => run_evaluate(&a),
        ExtensionCommand::Session(a) => run_session(&a),
        ExtensionCommand::Minimize(a) => run_minimize(&a),
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

fn run_session(a: &SessionCmdArgs) -> i32 {
    let seed = match std::fs::read(&a.input) {
        Ok(bytes) => bytes,
        Err(error) => {
            bhfeprintln!(
                "error: could not read input '{}': {error}",
                a.input.display()
            );
            return EXIT_USAGE;
        }
    };
    if let Err(error) = std::fs::create_dir_all(&a.work) {
        bhfeprintln!(
            "error: could not create work dir '{}': {error}",
            a.work.display()
        );
        return EXIT_USAGE;
    }
    // A fresh per-case root the extension's `lifecycle.reset` anchors on.
    let root = a.work.join("session-root");
    let _ = std::fs::remove_dir_all(&root);
    if let Err(error) = std::fs::create_dir_all(&root) {
        bhfeprintln!(
            "error: could not create session root '{}': {error}",
            root.display()
        );
        return EXIT_USAGE;
    }

    let manifest = match ExtensionManifest::load(&a.manifest) {
        Ok(manifest) => manifest,
        Err(error) => {
            bhfeprintln!("error: extension manifest invalid: {error}");
            return EXIT_USAGE;
        }
    };
    let mut client =
        match ExtensionClient::from_manifest_with_optional(&manifest, &a.manifest, SESSION_CAPS) {
            Ok(client) => client,
            Err(error) => {
                bhfeprintln!("error: extension setup failed: {error}");
                return EXIT_USAGE;
            }
        };

    let finding_block = client.provenance().finding_block();
    let negotiated_protocol = client.negotiated().protocol.clone();
    let negotiated_caps = client.negotiated().caps.clone();
    let case = CaseId::new(
        campaign_id(&a.work),
        "session-0",
        testcase_id(&a.input, &seed),
    );

    let mut target = ToyFileTarget::new(&root);
    let driver = SessionDriver::new(SessionOptions {
        mutate_seed: a.mutate,
        repair: a.repair,
        max_steps: 64,
    });
    let outcome = match driver.run(&mut client, &mut target, &case, &root, &seed) {
        Ok(outcome) => outcome,
        Err(error) => {
            bhfeprintln!("error: extension session failed: {error}");
            return EXIT_USAGE;
        }
    };

    let mut emitted = 0usize;
    let (code, result_label) = if let Some(failure) = &outcome.infrastructure {
        (EXIT_INFRA, infra_failure_label(failure))
    } else if let Some(finding) = &outcome.finding {
        let emitter = FindingEmitter::new(a.work.clone());
        match emitter.emit_extension_finding(
            &seed,
            &extension_finding_from(finding, finding_block.clone()),
        ) {
            Ok(id) => {
                emitted = 1;
                if !a.json {
                    println!("extension session finding emitted: {}", id.0);
                }
                (EXIT_FINDING, "finding".to_string())
            }
            Err(error) => {
                bhfeprintln!("error: could not write extension finding: {error}");
                return EXIT_USAGE;
            }
        }
    } else {
        (EXIT_OK, "ok".to_string())
    };

    let steps: Vec<Value> = outcome
        .steps
        .iter()
        .map(|s| {
            json!({
                "step": s.step,
                "label": s.label,
                "mutated": s.mutated,
                "repaired": s.repaired,
            })
        })
        .collect();
    let run_record = json!({
        "schema_version": EXTENSION_RUN_SCHEMA,
        "mode": "session",
        "manifest": a.manifest.display().to_string(),
        "result": result_label,
        "findings": emitted,
        "session": {
            "messages_sent": outcome.steps.len(),
            "steps": steps,
            "mutated": outcome.any_mutated(),
            "repaired": outcome.any_repaired(),
            "oracle_ran": outcome.oracle_ran,
            "target": target.summary(),
        },
        "protocol_version": negotiated_protocol,
        "negotiated_capabilities": negotiated_caps,
        "provenance": client.provenance(),
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
        println!("extension session: {result_label} (no finding)");
    }
    code
}

/// Re-drive `oracle.evaluate` over `bytes` and return the finding's stable
/// signature, or `None` if the input is not (any longer) a finding. The signature
/// is computed exactly as [`FindingEmitter::emit_extension_finding`] does (via the
/// shared `corpus::finding::extension_signature`), so a match means byte-for-byte
/// finding-identity equality.
fn reevaluate_signature(
    client: &mut ExtensionClient,
    campaign: &str,
    testcase_path: &Path,
    bytes: &[u8],
) -> Option<String> {
    let case = CaseId::new(campaign, "min-0", testcase_id(testcase_path, bytes));
    match client.evaluate(&case, bytes) {
        Ok(EvaluateOutcome::Finding(finding)) => Some(corpus::finding::extension_signature(
            &finding.signature_inputs,
        )),
        _ => None,
    }
}

/// `bhf extension minimize`: delta-debug an emitted extension-oracle finding's
/// testcase, accepting a candidate only when it re-drives the oracle to the SAME
/// stable signature (so finding identity — rule + signature inputs — is preserved
/// through minimization, satisfying issue #57's "emitted, replayed, AND minimized
/// with the same stable signature"). The recorded `signature` is never rewritten.
fn run_minimize(a: &MinimizeCmdArgs) -> i32 {
    let finding_dir = a.finding.as_path();
    let finding_json = finding_dir.join("finding.json");
    let record: Value = match std::fs::read(&finding_json) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(error) => {
                bhfeprintln!("error: could not parse {}: {error}", finding_json.display());
                return EXIT_USAGE;
            }
        },
        Err(error) => {
            bhfeprintln!("error: could not read {}: {error}", finding_json.display());
            return EXIT_USAGE;
        }
    };

    // Only an extension-oracle finding can be re-driven through oracle.evaluate.
    if record.get("confirmation").and_then(Value::as_str) != Some("extension") {
        bhfeprintln!(
            "error: {} is not an extension-oracle finding (confirmation != \"extension\")",
            finding_json.display()
        );
        return EXIT_USAGE;
    }
    let Some(recorded_sig) = record
        .get("signature")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        bhfeprintln!("error: finding has no `signature` to preserve across minimize");
        return EXIT_USAGE;
    };
    let testcase_name = record
        .get("paths")
        .and_then(|p| p.get("testcase"))
        .and_then(Value::as_str)
        .unwrap_or("testcase.bin");
    let testcase_path = finding_dir.join(testcase_name);
    let original = match std::fs::read(&testcase_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            bhfeprintln!(
                "error: could not read testcase '{}': {error}",
                testcase_path.display()
            );
            return EXIT_USAGE;
        }
    };

    let (_manifest, mut client) = match load_and_spawn(&a.manifest) {
        Ok(pair) => pair,
        Err(error) => {
            bhfeprintln!("error: extension setup failed: {error}");
            return EXIT_USAGE;
        }
    };

    let campaign = campaign_id(finding_dir);

    // Baseline: the recorded testcase must still reproduce the recorded signature,
    // or there is nothing honest to minimize against.
    match reevaluate_signature(&mut client, &campaign, &testcase_path, &original) {
        Some(sig) if sig == recorded_sig => {}
        _ => {
            bhfeprintln!(
                "error: finding {} no longer reproduces its recorded signature through the \
                 extension oracle; refusing to minimize",
                finding_dir.display()
            );
            return EXIT_INFRA;
        }
    }

    let result = replay_min::ddmin_bytes(&original, |candidate: &[u8]| -> Result<bool, String> {
        Ok(
            reevaluate_signature(&mut client, &campaign, &testcase_path, candidate).as_deref()
                == Some(recorded_sig.as_str()),
        )
    });
    let minimized = match result {
        Ok(result) => result.minimized,
        Err(error) => {
            bhfeprintln!("error: minimize failed: {error}");
            return EXIT_INFRA;
        }
    };

    // The 1-minimal candidate must still reproduce the signature (ddmin preserves
    // the predicate, but re-confirm so a reported minimization is never a lie).
    let final_sig = reevaluate_signature(&mut client, &campaign, &testcase_path, &minimized);
    if final_sig.as_deref() != Some(recorded_sig.as_str()) {
        bhfeprintln!("error: minimized input did not reproduce the recorded signature");
        return EXIT_INFRA;
    }

    let removed = original.len().saturating_sub(minimized.len());
    let reduced = removed > 0;
    let min_path = finding_dir.join("min_testcase.bin");
    if let Err(error) = std::fs::write(&min_path, &minimized) {
        bhfeprintln!(
            "error: could not write minimized testcase '{}': {error}",
            min_path.display()
        );
        return EXIT_USAGE;
    }
    if let Err(error) = update_extension_minimized(
        finding_dir,
        original.len(),
        minimized.len(),
        removed,
        reduced,
    ) {
        bhfeprintln!("warning: could not update finding record: {error}");
    }

    if a.json {
        let report = json!({
            "strategy": "bytes",
            "predicate": "extension-oracle-signature",
            "signature": recorded_sig,
            "original_len": original.len(),
            "minimized_len": minimized.len(),
            "removed_bytes": removed,
            "reduced": reduced,
            "path": "min_testcase.bin",
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!(
            "EXTENSION-MINIMIZED signature={recorded_sig} original_len={} minimized_len={} \
             removed_bytes={removed} reduced={reduced} path=min_testcase.bin",
            original.len(),
            minimized.len()
        );
    }
    EXIT_OK
}

/// Record the minimization on `finding.json` WITHOUT touching its `signature`
/// (minimize preserves finding identity): point `paths.minimized` /
/// `minimal_reproducer` at `min_testcase.bin` and stamp a `minimization` block.
fn update_extension_minimized(
    finding_dir: &Path,
    original_len: usize,
    minimized_len: usize,
    removed: usize,
    reduced: bool,
) -> std::io::Result<()> {
    let path = finding_dir.join("finding.json");
    let bytes = std::fs::read(&path)?;
    let mut value: Value = serde_json::from_slice(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if let Some(obj) = value.as_object_mut() {
        let paths = obj.entry("paths").or_insert_with(|| json!({}));
        if let Some(paths) = paths.as_object_mut() {
            paths.insert("minimized".to_string(), json!("min_testcase.bin"));
        }
        obj.insert("minimal_reproducer".to_string(), json!("min_testcase.bin"));
        obj.insert(
            "minimization".to_string(),
            json!({
                "strategy": "bytes",
                "predicate": "extension-oracle-signature",
                "original_len": original_len,
                "minimized_len": minimized_len,
                "removed_bytes": removed,
                "reduced": reduced,
            }),
        );
    }
    corpus::finding::append_history(
        &mut value,
        "minimize",
        &["paths.minimized", "minimal_reproducer", "minimization"],
    );
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&value)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
    )
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
    let client = ExtensionManifest::load(manifest_path).and_then(|manifest| {
        ExtensionClient::from_manifest_with_optional(&manifest, manifest_path, SESSION_CAPS)
    });
    let mut client = match client {
        Ok(client) => client,
        Err(error) => {
            // A failed trusted load/handshake is bounded infrastructure, not a
            // target bug: record it and leave the campaign's findings untouched.
            return json!({
                "active": true,
                "manifest": manifest_path.display().to_string(),
                "error": error.to_string(),
                "evaluated": 0,
                "findings": 0,
                "infrastructure_errors": 1,
            });
        }
    };

    let finding_block = client.provenance().finding_block();
    let negotiated_protocol = client.negotiated().protocol.clone();
    let negotiated_caps = client.negotiated().caps.clone();
    let repair_available = client.supports(extension_host::capability::CODEC_REPAIR);

    let mut evaluated = 0usize;
    let mut findings = 0usize;
    let mut repaired = 0usize;
    let mut infrastructure_errors = 0usize;
    let mut seen_defects: HashSet<String> = HashSet::new();

    for (index, input) in inputs.into_iter().enumerate() {
        evaluated += 1;
        let case = CaseId::new(
            campaign,
            "ext-0",
            format!("{index}-{}", short_digest(input)),
        );
        // When the extension owns the target's codec, repair a (structurally
        // valid but computed-field-stale) frame before the oracle sees it. The
        // extension `reject`s any input it does not recognize as its format, so a
        // raw corpus entry is evaluated verbatim — the host stays codec-agnostic.
        let owned;
        let eval_input: &[u8] = if repair_available {
            match client.repair(&case, input) {
                Ok(CodecOutcome::Bytes(bytes)) => {
                    repaired += 1;
                    owned = bytes;
                    owned.as_slice()
                }
                Ok(_) => input,
                Err(_) => {
                    infrastructure_errors += 1;
                    input
                }
            }
        } else {
            input
        };
        match client.evaluate(&case, eval_input) {
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
        "repaired": repaired,
        "codec_repair_available": repair_available,
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

// ── The toy target: the issue's `[u16 BE len][payload][u32 BE CRC-32]` ───────
// protocol with `OPEN(path) -> handle` and `WRITE(handle, data)`. It is the
// concrete `SessionTarget` the extension's scenario/codec drives; the host never
// speaks this protocol itself. Writes are modelled, not performed on disk — the
// target records whether a WRITE would land outside its sandbox root.

/// A received-frame record for provenance.
struct TargetWrite {
    handle: String,
    path: String,
    outside_root: bool,
}

/// An in-process toy file target: validates each frame's length+CRC, returns a
/// handle for OPEN, and records WRITE destinations (and whether they escape root).
struct ToyFileTarget {
    next_handle: u32,
    handles: std::collections::HashMap<String, String>,
    received: usize,
    received_valid: usize,
    writes: Vec<TargetWrite>,
}

impl ToyFileTarget {
    fn new(_root: &Path) -> Self {
        Self {
            next_handle: 1,
            handles: std::collections::HashMap::new(),
            received: 0,
            received_valid: 0,
            writes: Vec::new(),
        }
    }

    fn summary(&self) -> Value {
        json!({
            "frames_received": self.received,
            "frames_valid": self.received_valid,
            "all_frames_valid": self.received == self.received_valid,
            "writes": self.writes.len(),
            "wrote_outside_root": self.writes.iter().any(|w| w.outside_root),
            "write_paths": self
                .writes
                .iter()
                .map(|w| json!({ "handle": w.handle, "path": w.path, "outside_root": w.outside_root }))
                .collect::<Vec<_>>(),
        })
    }
}

/// A path escapes the sandbox root if it is absolute or lexically pops above it.
fn escapes_root(path: &str) -> bool {
    path.starts_with('/') || path.split('/').any(|seg| seg == "..")
}

impl SessionTarget for ToyFileTarget {
    fn exchange(
        &mut self,
        _step: u32,
        _label: Option<&str>,
        message: &[u8],
    ) -> std::io::Result<Vec<u8>> {
        self.received += 1;
        let (payload, valid) = match toy_parse(message) {
            Some(parsed) => parsed,
            None => return Ok(toy_frame(b"ERR badframe")),
        };
        if !valid {
            return Ok(toy_frame(b"ERR badcrc"));
        }
        self.received_valid += 1;
        let text = String::from_utf8_lossy(&payload).into_owned();
        let mut parts = text.splitn(3, ' ');
        match parts.next() {
            Some("OPEN") => {
                let path = parts.next().unwrap_or("").to_string();
                let handle = self.next_handle.to_string();
                self.next_handle += 1;
                self.handles.insert(handle.clone(), path);
                Ok(toy_frame(format!("OPENOK {handle}").as_bytes()))
            }
            Some("WRITE") => {
                let handle = parts.next().unwrap_or("").to_string();
                let path = self.handles.get(&handle).cloned().unwrap_or_default();
                let outside_root = escapes_root(&path);
                self.writes.push(TargetWrite {
                    handle,
                    path,
                    outside_root,
                });
                Ok(toy_frame(b"WRITEOK"))
            }
            _ => Ok(toy_frame(b"ERR unknownop")),
        }
    }
}

fn toy_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 6);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&toy_crc32(payload).to_be_bytes());
    out
}

/// Parse a frame into `(payload, crc_valid)`.
fn toy_parse(frame: &[u8]) -> Option<(Vec<u8>, bool)> {
    if frame.len() < 6 {
        return None;
    }
    let declared = u16::from_be_bytes([frame[0], frame[1]]) as usize;
    let payload = frame[2..frame.len() - 4].to_vec();
    let crc = u32::from_be_bytes([
        frame[frame.len() - 4],
        frame[frame.len() - 3],
        frame[frame.len() - 2],
        frame[frame.len() - 1],
    ]);
    let valid = declared == payload.len() && crc == toy_crc32(&payload);
    Some((payload, valid))
}

/// CRC-32/ISO-HDLC (zlib), matching the extensions' CRC.
fn toy_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}
