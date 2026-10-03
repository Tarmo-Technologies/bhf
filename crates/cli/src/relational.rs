// SPDX-License-Identifier: Apache-2.0
//! `bhf relational` — coverage-guided relational policy fuzzing across profiles.
//!
//! One generated testcase is run under several named launch/session **profiles**
//! (differing in runner, args, environment, declared target allowlist and secret
//! references) and a set of declarative relational **predicates** is evaluated
//! over each profile's observed behaviour. The campaign retains any input that
//! reaches new code in any profile, produces a new semantic observation, a new
//! cross-profile outcome vector, or a new effect-event shape, and emits a finding
//! when a policy relation is violated — catching both unexpected *divergence* and
//! unexpected *equivalence*.
//!
//! The campaign engine, mutator, coverage novelty, predicate evaluator, finding
//! model, replay and minimize all live in the pure `relational` crate behind the
//! [`relational::ProfileExecutor`] seam. This module supplies the **real**
//! executor: it spawns each profile with per-profile isolated state (a distinct
//! coverage-shm file, a distinct runtime-trace log and a distinct scratch dir),
//! resolves `lab:`-style secret references from a local source, and maps the real
//! per-profile observations — edge coverage (`BHF_COV_SHM`), runtime effect events
//! (the runtrace collector, with the platform-neutral `bhf.collector-event.v1`
//! source adapted at the same seam) and runtime-oracle semantic results — onto the
//! crate's observation types. Resolved secrets are redacted before anything is
//! persisted into a finding or a replay bundle; only the stable reference id
//! survives.
//!
//! Findings are written through the unified `results/` layout
//! (`results/findings/F-REL-NNNN/`), so SARIF / vulnerability-management importers
//! read them with the same reader as every other finding kind.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use serde_json::json;

use relational::redact::{self, SecretResolution};
use relational::{
    minimize_with as rel_minimize, replay_with as rel_replay, run_campaign_with, sha256_hex,
    CampaignOptions, CollectorKind, ComparatorVerdict, EffectEvent, EffectKind, EnvValue,
    ExecError, ExternalComparator, ExternalFinding, ExternalProvenance, Observation, Profile,
    ProfileExecutor, ProfileRun, RelationFinding, RelationalConfig, Require, RunState, SemanticHit,
    SemanticVerdict,
};

use extension_host::{
    CaseId, EvaluateOutcome, ExtensionClient, ExtensionManifest, FindingResult, InfraFailure,
};

use crate::auto::runtrace::{self, RuntraceEvent};
use crate::auto::shim_path;

/// Coverage bitmap size: one byte per edge, matching the bhf-driver harness
/// convention (`fuzz.rs::BHF_COV_BITS`).
const COV_BITS: usize = 1 << 16;

/// The persisted policy file name, kept in the run's `results/` dir so `replay`
/// and `minimize` can reconstruct the profiles without `--config`. It holds only
/// secret *references*, never resolved values.
const POLICY_FILE: &str = "relational-policy.toml";

/// Finding-id family prefix for relational findings in the unified layout.
const FINDING_PREFIX: &str = "F-REL-";

/// `bhf relational <run|replay|minimize>` — coverage-guided relational policy
/// fuzzing across named launch/session profiles.
#[derive(Debug, Args)]
pub struct RelationalArgs {
    #[command(subcommand)]
    command: RelationalCommand,
}

#[derive(Debug, Subcommand)]
enum RelationalCommand {
    /// Coverage-guided relational campaign: mutate a shared testcase, run it under every named role/session profile, retain inputs that reach new code or a new cross-profile outcome, and emit a finding when a declarative policy relation is violated
    Run(RunArgs),
    /// Re-run every profile required by a relational finding and re-confirm the violated relation (secret values stay redacted)
    Replay(ReplayArgs),
    /// Shrink a relational finding's testcase while the violated relation still holds, preserving the minimal required profile set
    Minimize(MinimizeArgs),
}

#[derive(Debug, Args)]
struct RunArgs {
    /// TOML policy file (schema = "bhf.relational.v1") declaring profiles and relational predicates.
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
    /// Directory of seed inputs for the shared testcase mutator.
    #[arg(long, value_name = "DIR")]
    seeds: PathBuf,
    /// Findings output / work directory; findings go to <out>/results/findings/F-REL-*.
    #[arg(long, value_name = "DIR", default_value = "findings_relational")]
    out: PathBuf,
    /// Maximum number of testcases to execute.
    #[arg(long, default_value_t = 10_000)]
    max_execs: usize,
    /// Per-profile per-case timeout in seconds.
    #[arg(long, default_value_t = 5)]
    timeout_secs: u64,
    /// Deterministic mutation RNG seed.
    #[arg(long, default_value_t = 0)]
    seed: u64,
    /// Maximum mutated input length.
    #[arg(long, default_value_t = 4096)]
    max_len: usize,
    /// Stop once this many distinct findings have been recorded.
    #[arg(long, default_value_t = 1024)]
    max_findings: usize,
}

#[derive(Debug, Args)]
struct ReplayArgs {
    /// A finding id or a finding directory (containing finding.json + testcase.bin).
    #[arg(long, value_name = "ID_OR_DIR")]
    finding: String,
    /// TOML policy file; defaults to the policy persisted beside the finding.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Work directory used to resolve a bare finding id.
    #[arg(
        long = "work-dir",
        value_name = "DIR",
        default_value = "findings_relational"
    )]
    work_dir: PathBuf,
    /// Per-profile timeout in seconds.
    #[arg(long, default_value_t = 5)]
    timeout_secs: u64,
}

#[derive(Debug, Args)]
struct MinimizeArgs {
    /// A finding id or a finding directory (containing finding.json + testcase.bin).
    #[arg(long, value_name = "ID_OR_DIR")]
    finding: String,
    /// TOML policy file; defaults to the policy persisted beside the finding.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Work directory used to resolve a bare finding id.
    #[arg(
        long = "work-dir",
        value_name = "DIR",
        default_value = "findings_relational"
    )]
    work_dir: PathBuf,
    /// Per-profile timeout in seconds.
    #[arg(long, default_value_t = 5)]
    timeout_secs: u64,
}

/// Dispatch a `bhf relational` invocation, returning a process exit code.
pub fn run(args: RelationalArgs) -> i32 {
    let result = match args.command {
        RelationalCommand::Run(a) => run_campaign_cmd(a),
        RelationalCommand::Replay(a) => replay_cmd(a),
        RelationalCommand::Minimize(a) => minimize_cmd(a),
    };
    match result {
        Ok(code) => code,
        Err(error) => {
            crate::bhfeprintln!("error: {error:#}");
            2
        }
    }
}

// ---------------------------------------------------------------------------
// `bhf relational run`
// ---------------------------------------------------------------------------

fn run_campaign_cmd(a: RunArgs) -> Result<i32> {
    let config_src = fs::read_to_string(&a.config)
        .with_context(|| format!("read relational config {}", a.config.display()))?;
    let config = RelationalConfig::parse(&config_src)
        .map_err(|error| anyhow!("parse relational config {}: {error}", a.config.display()))?;
    let seeds = load_seeds(&a.seeds)?;

    let work_dir = a.out.clone();
    fs::create_dir_all(&work_dir)
        .with_context(|| format!("create work dir {}", work_dir.display()))?;
    crate::workdir::prepare(&work_dir)?;

    // Persist the policy (references only) so replay/minimize can reconstruct the
    // profiles without --config.
    let results_dir = corpus::layout::results_dir(&work_dir);
    fs::create_dir_all(&results_dir)
        .with_context(|| format!("create results dir {}", results_dir.display()))?;
    fs::write(results_dir.join(POLICY_FILE), &config_src).context("persist relational policy")?;

    let scratch = work_dir.join(".relational-scratch");
    let _ = fs::remove_dir_all(&scratch);
    fs::create_dir_all(&scratch).context("create relational scratch dir")?;
    // Remove the campaign scratch root on every exit — success, a propagated
    // campaign error, or an unwinding panic — so an errored/interrupted run does
    // not leave it behind. Per-case scratch is cleaned promptly inside each run
    // (see `ScratchGuard` in `SpawnExecutor::run`), so this root is normally empty
    // by the time the guard fires.
    let _scratch_guard = ScratchGuard::new(scratch.clone());

    let mut executor = SpawnExecutor::new(
        &scratch,
        Duration::from_secs(a.timeout_secs),
        config.secret_prefix.clone(),
    );
    // The External-predicate comparator: spawn + negotiate every trusted
    // comparator extension up front so a bad manifest fails the run here (the
    // explicit-load trust boundary), then reuse the live clients across cases.
    let mut comparator = ExtensionComparator::new(&config, campaign_name(&work_dir));
    comparator.preflight(&config)?;

    let opts = CampaignOptions {
        max_execs: a.max_execs,
        max_len: a.max_len,
        seed: a.seed,
        max_findings: a.max_findings,
    };

    let producer = results::ProducerRun::begin(&work_dir, "relational", std::env::args().collect());

    let report = run_campaign_with(&config, &seeds, &mut executor, &mut comparator, &opts)
        .map_err(|error| anyhow!("relational campaign failed: {error}"))?;

    let resolution = executor.secret_resolution();
    let written = persist_findings(&work_dir, report.findings, &resolution, &executor)?;

    let o = &report.outcomes;
    crate::bhfeprintln!(
        "relational: {} execs, {} corpus, {} findings | outcomes setup={} auth={} missing={} unknown={} compliant={} violation={}",
        report.execs,
        report.corpus_size,
        written,
        o.setup_failure,
        o.auth_failure,
        o.missing_observation,
        o.policy_unknown,
        o.compliant,
        o.violation,
    );

    let exit_code = i32::from(written > 0);
    crate::workdir::finish(
        producer,
        exit_code,
        results::model::ProducerStatus::Complete,
    );
    // `_scratch_guard` removes the scratch root here as it drops.
    Ok(exit_code)
}

/// Write each relational finding into the unified `results/` layout, redacting
/// every resolved secret first. Returns the number of findings written.
fn persist_findings(
    work_dir: &Path,
    findings: Vec<RelationFinding>,
    resolution: &SecretResolution,
    bytes: &dyn TestcaseBytes,
) -> Result<usize> {
    let findings_root = corpus::layout::findings_dir(work_dir);
    fs::create_dir_all(&findings_root)
        .with_context(|| format!("create findings dir {}", findings_root.display()))?;
    let mut ids = corpus::layout::FamilyAllocator::new(&findings_root, FINDING_PREFIX)?;

    let mut written = 0usize;
    for mut finding in findings {
        // Scrub every resolved secret value before the finding touches disk; the
        // stable reference id (held in the persisted policy) is what survives.
        redact::redact_finding(&mut finding, resolution);
        let testcase = bytes
            .testcase_for(&finding.testcase_sha)
            .unwrap_or_default();

        let (id, dir) = ids.create()?;
        finding.id = id;
        fs::write(dir.join("testcase.bin"), &testcase)
            .with_context(|| format!("write testcase for {}", finding.signature))?;

        let mut record = serde_json::to_value(&finding).context("serialize relational finding")?;
        // Relational findings are a cross-execution relation oracle in the
        // differential family; the BHF-308..311 rule ids carry the precise kind.
        corpus::finding::stamp_v1(&mut record, corpus::finding::finding_kind::DIFFERENTIAL);
        fs::write(
            dir.join("finding.json"),
            serde_json::to_vec_pretty(&record)?,
        )
        .context("write finding.json")?;
        written += 1;
    }
    Ok(written)
}

// ---------------------------------------------------------------------------
// `bhf relational replay`
// ---------------------------------------------------------------------------

fn replay_cmd(a: ReplayArgs) -> Result<i32> {
    let loaded = load_finding(&a.finding, &a.work_dir)?;
    let config = load_config_for_finding(a.config.as_deref(), &loaded.dir)?;

    let scratch = scratch_under(&loaded.dir, "replay");
    let _scratch_guard = ScratchGuard::new(scratch.clone());
    let mut executor = SpawnExecutor::new(
        &scratch,
        Duration::from_secs(a.timeout_secs),
        config.secret_prefix.clone(),
    );
    // Lazily reuses any trusted comparator the finding's relation references; a
    // comparator that no longer loads yields a bounded Unknown (not reproduced),
    // never a fabricated verdict.
    let mut comparator = ExtensionComparator::new(&config, campaign_name(&loaded.dir));
    let result = rel_replay(
        &loaded.finding,
        &config,
        &loaded.input,
        &mut executor,
        &mut comparator,
    )
    .map_err(|error| anyhow!("relational replay failed: {error}"))?;

    // Build a redacted replay bundle (no resolved secret ever persisted).
    let resolution = executor.secret_resolution();
    let mut observations = result.observations.clone();
    for obs in observations.values_mut() {
        redact::redact_events(&mut obs.events, &resolution);
    }
    let bundle = json!({
        "reproduced": result.reproduced,
        "executed_profiles": result.executed_profiles,
        "outcome": result.outcome.label(),
        "observations": observations,
    });
    fs::write(
        loaded.dir.join("replay.json"),
        serde_json::to_vec_pretty(&bundle)?,
    )
    .context("write replay.json")?;
    // `_scratch_guard` removes the replay scratch here (and on any error above).

    crate::bhfeprintln!(
        "relational replay: profiles={:?} reproduced={} outcome={}",
        result.executed_profiles,
        result.reproduced,
        result.outcome.label(),
    );
    Ok(i32::from(!result.reproduced))
}

// ---------------------------------------------------------------------------
// `bhf relational minimize`
// ---------------------------------------------------------------------------

fn minimize_cmd(a: MinimizeArgs) -> Result<i32> {
    let loaded = load_finding(&a.finding, &a.work_dir)?;
    let config = load_config_for_finding(a.config.as_deref(), &loaded.dir)?;

    let scratch = scratch_under(&loaded.dir, "minimize");
    let _scratch_guard = ScratchGuard::new(scratch.clone());
    let mut executor = SpawnExecutor::new(
        &scratch,
        Duration::from_secs(a.timeout_secs),
        config.secret_prefix.clone(),
    );
    let mut comparator = ExtensionComparator::new(&config, campaign_name(&loaded.dir));
    let result = rel_minimize(
        &loaded.finding,
        &config,
        &loaded.input,
        &mut executor,
        &mut comparator,
    )
    .map_err(|error| anyhow!("relational minimize failed: {error}"))?;

    fs::write(loaded.dir.join("testcase.min.bin"), &result.input)
        .context("write minimized testcase")?;
    let summary = json!({
        "input_len": result.input.len(),
        "original_len": loaded.input.len(),
        "profiles": result.profiles,
        "predicate_runs": result.predicate_runs,
    });
    fs::write(
        loaded.dir.join("minimize.json"),
        serde_json::to_vec_pretty(&summary)?,
    )
    .context("write minimize.json")?;
    // `_scratch_guard` removes the minimize scratch here (and on any error above).

    crate::bhfeprintln!(
        "relational minimize: {} -> {} bytes, required profiles={:?}",
        loaded.input.len(),
        result.input.len(),
        result.profiles,
    );
    Ok(0)
}

// ---------------------------------------------------------------------------
// Finding / config loading
// ---------------------------------------------------------------------------

struct LoadedFinding {
    dir: PathBuf,
    finding: RelationFinding,
    input: Vec<u8>,
}

fn load_finding(finding: &str, work_dir: &Path) -> Result<LoadedFinding> {
    let dir = resolve_finding_dir(finding, work_dir)?;
    let json = fs::read(dir.join("finding.json"))
        .with_context(|| format!("read finding.json in {}", dir.display()))?;
    let finding: RelationFinding =
        serde_json::from_slice(&json).context("parse relational finding.json")?;
    let input = fs::read(dir.join(&finding.paths.testcase)).with_context(|| {
        format!(
            "read testcase {} in {}",
            finding.paths.testcase,
            dir.display()
        )
    })?;
    Ok(LoadedFinding {
        dir,
        finding,
        input,
    })
}

fn resolve_finding_dir(finding: &str, work_dir: &Path) -> Result<PathBuf> {
    let direct = Path::new(finding);
    if direct.is_dir() {
        return Ok(direct.to_path_buf());
    }
    corpus::layout::resolve_finding_id(work_dir, finding).ok_or_else(|| {
        anyhow!(
            "finding {finding:?} not found as a directory or as an id under {}",
            work_dir.display()
        )
    })
}

fn load_config_for_finding(
    explicit: Option<&Path>,
    finding_dir: &Path,
) -> Result<RelationalConfig> {
    let src = match explicit {
        Some(path) => fs::read_to_string(path)
            .with_context(|| format!("read relational config {}", path.display()))?,
        None => {
            // <results>/findings/<id> -> <results>/<POLICY_FILE>
            let policy = finding_dir
                .parent()
                .and_then(Path::parent)
                .map(|results| results.join(POLICY_FILE));
            match policy {
                Some(path) if path.is_file() => fs::read_to_string(&path)
                    .with_context(|| format!("read persisted policy {}", path.display()))?,
                _ => bail!(
                    "no --config given and no persisted {POLICY_FILE} found beside the finding; pass --config"
                ),
            }
        }
    };
    RelationalConfig::parse(&src).map_err(|error| anyhow!("parse relational config: {error}"))
}

fn load_seeds(dir: &Path) -> Result<Vec<Vec<u8>>> {
    let entries = fs::read_dir(dir).with_context(|| format!("read seeds dir {}", dir.display()))?;
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file())
        .collect();
    paths.sort();
    let mut seeds = Vec::with_capacity(paths.len());
    for path in paths {
        seeds.push(fs::read(&path).with_context(|| format!("read seed {}", path.display()))?);
    }
    Ok(seeds)
}

fn scratch_under(finding_dir: &Path, tag: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    finding_dir.join(format!(".relational-{tag}-{nonce}"))
}

// ---------------------------------------------------------------------------
// The real External-predicate comparator (trusted extension over the bundle)
// ---------------------------------------------------------------------------

/// A stable campaign id for a relational run (the work/finding dir's name).
fn campaign_name(dir: &Path) -> String {
    dir.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "relational".to_string())
}

/// The driver-side [`ExternalComparator`]. For an `External` predicate whose
/// `comparator` names a trusted `bhf.extension-manifest.v1` manifest, it spawns
/// and negotiates the extension (explicit load = the trust boundary) and drives
/// `oracle.evaluate` with the serialized, secret-redacted cross-profile
/// observation bundle. `ok → Clean`, `finding → Finding`, and
/// `reject`/`unsupported`/bounded-infrastructure → `Unknown`. The comparator exe
/// + config hashes and the protocol version are recorded in the finding.
struct ExtensionComparator {
    campaign: String,
    /// Resolved secret values, used ONLY to redact the bundle before it is sent;
    /// never persisted and never transmitted.
    secrets: SecretResolution,
    /// One supervised extension per distinct comparator manifest path, spawned on
    /// first use and reused across cases. `Err` caches a spawn/handshake failure
    /// so a broken comparator yields a bounded `Unknown`, not repeated spawns.
    clients: BTreeMap<String, Result<ExtensionClient, String>>,
    case_counter: u64,
}

impl ExtensionComparator {
    fn new(config: &RelationalConfig, campaign: String) -> Self {
        // Resolve the declared secret refs once from the local lab source so the
        // bundle can be scrubbed before it is handed to the comparator. This is a
        // read-only redaction aid: resolved values are never sent or persisted.
        let mut secrets = SecretResolution::new();
        for profile in &config.profiles {
            for value in profile.env.values() {
                if let EnvValue::SecretRef(reference) = value {
                    if let Some(resolved) = resolve_secret(reference, &config.secret_prefix) {
                        secrets.insert(reference.clone(), resolved);
                    }
                }
            }
        }
        Self {
            campaign,
            secrets,
            clients: BTreeMap::new(),
            case_counter: 0,
        }
    }

    /// The distinct comparator manifest paths the config's External predicates name.
    fn comparator_paths(config: &RelationalConfig) -> Vec<String> {
        let mut set = std::collections::BTreeSet::new();
        for pred in &config.predicates {
            if let Require::External { comparator } = &pred.require {
                set.insert(comparator.clone());
            }
        }
        set.into_iter().collect()
    }

    /// Eagerly load + spawn every comparator the config references so a bad
    /// manifest fails the command up front (the explicit-load trust boundary).
    fn preflight(&mut self, config: &RelationalConfig) -> Result<()> {
        for path in Self::comparator_paths(config) {
            self.client_for(&path)
                .map_err(|reason| anyhow!("load external comparator {path:?}: {reason}"))?;
        }
        Ok(())
    }

    /// Get-or-spawn the supervised client for `comparator`. Caches success and
    /// failure alike.
    fn client_for(
        &mut self,
        comparator: &str,
    ) -> std::result::Result<&mut ExtensionClient, String> {
        if !self.clients.contains_key(comparator) {
            let spawned = spawn_comparator(comparator).map_err(|e| e.to_string());
            self.clients.insert(comparator.to_string(), spawned);
        }
        match self.clients.get_mut(comparator).expect("inserted above") {
            Ok(client) => Ok(client),
            Err(reason) => Err(reason.clone()),
        }
    }
}

impl ExternalComparator for ExtensionComparator {
    fn compare(
        &mut self,
        comparator: &str,
        bundle: &BTreeMap<String, Observation>,
    ) -> ComparatorVerdict {
        // Redact every resolved secret from the bundle before it leaves bhf.
        let input = match redacted_bundle_bytes(bundle, &self.secrets) {
            Ok(bytes) => bytes,
            Err(error) => {
                return ComparatorVerdict::Unknown {
                    reason: format!("serialize observation bundle: {error}"),
                };
            }
        };
        let digest: String = sha256_hex(&input).chars().take(16).collect();
        let case = CaseId::new(
            self.campaign.clone(),
            "relational",
            format!("{:010}-{digest}", self.case_counter),
        );
        self.case_counter += 1;

        let client = match self.client_for(comparator) {
            Ok(client) => client,
            Err(reason) => {
                return ComparatorVerdict::Unknown {
                    reason: format!("external comparator {comparator:?} unavailable: {reason}"),
                };
            }
        };
        // Capture provenance (exe/config hash + protocol version) before the call.
        let provenance = external_provenance(client);
        let outcome = match client.evaluate(&case, &input) {
            Ok(outcome) => outcome,
            Err(error) => {
                return ComparatorVerdict::Unknown {
                    reason: format!("external comparator transport error: {error}"),
                };
            }
        };
        match outcome {
            EvaluateOutcome::Ok => ComparatorVerdict::Clean,
            EvaluateOutcome::Finding(finding) => {
                ComparatorVerdict::Finding(external_finding_from(comparator, &finding, provenance))
            }
            EvaluateOutcome::Reject { detail } => ComparatorVerdict::Unknown {
                reason: format!(
                    "comparator rejected the bundle: {}",
                    detail.unwrap_or_default()
                ),
            },
            EvaluateOutcome::Unsupported { detail } => ComparatorVerdict::Unknown {
                reason: format!("comparator unsupported: {}", detail.unwrap_or_default()),
            },
            EvaluateOutcome::Infrastructure(failure) => ComparatorVerdict::Unknown {
                reason: format!(
                    "comparator infrastructure fault: {}",
                    infra_reason(&failure)
                ),
            },
        }
    }
}

/// Load the named comparator manifest (explicit-load trust boundary) and spawn +
/// handshake the extension.
fn spawn_comparator(comparator: &str) -> extension_host::Result<ExtensionClient> {
    let manifest_path = Path::new(comparator);
    let manifest = ExtensionManifest::load(manifest_path)?;
    ExtensionClient::from_manifest(&manifest, manifest_path)
}

/// Snapshot the comparator extension's provenance for the relational finding.
fn external_provenance(client: &ExtensionClient) -> ExternalProvenance {
    let p = client.provenance();
    ExternalProvenance {
        executable_sha256: p.executable_sha256.clone(),
        config_sha256: p.config_sha256.clone(),
        protocol_version: p.protocol_version.clone(),
        negotiated_caps: p.negotiated_caps.clone(),
    }
}

/// Fold an extension `FindingResult` into the relational [`ExternalFinding`]. The
/// comparator signature mirrors the host's stable extension-finding signature
/// (sha256 over the ordered `signature_inputs`, 0x1f-separated, "extension"-tagged)
/// so an identical comparator verdict reproduces the identical signature.
fn external_finding_from(
    comparator: &str,
    finding: &FindingResult,
    provenance: ExternalProvenance,
) -> ExternalFinding {
    let mut buf = b"extension".to_vec();
    for part in &finding.signature_inputs {
        buf.push(0x1f);
        buf.extend_from_slice(part.as_bytes());
    }
    let detail = finding
        .evidence
        .iter()
        .find(|e| e.key == "reason")
        .map(|e| e.value.clone())
        .or_else(|| {
            finding
                .evidence
                .first()
                .map(|e| format!("{}={}", e.key, e.value))
        });
    ExternalFinding {
        comparator: comparator.to_string(),
        signature: sha256_hex(&buf),
        classification: finding.classification.clone(),
        detail,
        provenance: Some(provenance),
    }
}

/// Serialize the cross-profile observation bundle with every resolved secret
/// scrubbed first, so nothing sensitive is ever handed to the comparator.
fn redacted_bundle_bytes(
    bundle: &BTreeMap<String, Observation>,
    secrets: &SecretResolution,
) -> Result<Vec<u8>> {
    let mut redacted = bundle.clone();
    for obs in redacted.values_mut() {
        redact::redact_events(&mut obs.events, secrets);
        if let Some(digest) = &obs.response_digest {
            obs.response_digest = Some(redact::redact_text(digest, secrets));
        }
        for hit in &mut obs.semantic_hits {
            hit.detail = redact::redact_text(&hit.detail, secrets);
        }
    }
    Ok(serde_json::to_vec(&redacted)?)
}

/// A compact human reason for a bounded extension infrastructure fault.
fn infra_reason(failure: &InfraFailure) -> String {
    match failure {
        InfraFailure::Timeout { after } => format!("timeout after {after:?}"),
        InfraFailure::Crashed { status, signal } => {
            format!("extension crashed (status={status:?}, signal={signal:?})")
        }
        InfraFailure::FrameTooLarge { declared, cap } => {
            format!("oversized frame (declared={declared}, cap={cap})")
        }
        InfraFailure::Protocol { detail } => format!("protocol: {detail}"),
        InfraFailure::CaseMismatch { .. } => "response case identity mismatch".to_string(),
        InfraFailure::ExtensionReported { detail } => detail
            .clone()
            .unwrap_or_else(|| "extension-reported error".to_string()),
    }
}

// ---------------------------------------------------------------------------
// The real, isolated, process-spawning executor
// ---------------------------------------------------------------------------

/// A lookup from a testcase SHA-256 to the bytes that produced it. The executor
/// records every input it runs so a finding (which carries only `testcase_sha`)
/// can be persisted with its `testcase.bin`.
trait TestcaseBytes {
    fn testcase_for(&self, sha: &str) -> Option<Vec<u8>>;
}

/// Removes a scratch directory when it drops. Used for both the per-(profile,
/// case) scratch and a command's scratch root, so neither a long campaign (which
/// would otherwise accumulate a dir per run) nor an error / interrupt that unwinds
/// through a run leaves scratch behind. Every byte a finding needs is folded into
/// the returned [`ProfileRun`] before the per-case guard drops, so nothing a
/// finding references lives under a guarded dir. Cleanup is best-effort: a failed
/// removal is ignored rather than masking the real result.
struct ScratchGuard {
    dir: PathBuf,
}

impl ScratchGuard {
    fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
}

impl Drop for ScratchGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// A [`relational::ProfileExecutor`] that spawns each profile in isolation.
struct SpawnExecutor {
    scratch: PathBuf,
    timeout: Duration,
    secret_prefix: String,
    shim: Option<PathBuf>,
    counter: u64,
    seen_inputs: BTreeMap<String, Vec<u8>>,
    secrets: SecretResolution,
}

impl SpawnExecutor {
    fn new(scratch: &Path, timeout: Duration, secret_prefix: String) -> Self {
        Self {
            scratch: scratch.to_path_buf(),
            timeout,
            secret_prefix,
            shim: locate_shim(),
            counter: 0,
            seen_inputs: BTreeMap::new(),
            secrets: SecretResolution::new(),
        }
    }

    fn secret_resolution(&self) -> SecretResolution {
        self.secrets.clone()
    }
}

impl TestcaseBytes for SpawnExecutor {
    fn testcase_for(&self, sha: &str) -> Option<Vec<u8>> {
        self.seen_inputs.get(sha).cloned()
    }
}

impl ProfileExecutor for SpawnExecutor {
    fn run(&mut self, profile: &Profile, input: &[u8]) -> Result<ProfileRun, ExecError> {
        self.seen_inputs
            .entry(sha256_hex(input))
            .or_insert_with(|| input.to_vec());

        let case = self.counter;
        self.counter += 1;
        // Per-(profile, case) isolation: a distinct scratch dir, coverage-shm file
        // and runtime-trace/collector log per run, so one profile's coverage or
        // events can never contaminate another's.
        let case_dir = self
            .scratch
            .join(format!("{case:010}-{}", sanitize(&profile.name)));
        // Clean this case's scratch (input.bin + cov.shm + runtrace.jsonl +
        // collector.jsonl) as soon as the run returns — on success, a setup
        // failure, an error or a panic — so a long campaign never accumulates
        // per-case dirs and an interrupt leaks at most the one in flight. Declared
        // before the dir is created so even a bail during setup is covered; the
        // coverage/events/stdout it reads are all folded into the `ProfileRun`
        // before this drops.
        let _scratch = ScratchGuard::new(case_dir.clone());
        fs::create_dir_all(&case_dir).map_err(|e| failed(profile, format!("scratch dir: {e}")))?;
        let input_path = case_dir.join("input.bin");
        fs::write(&input_path, input).map_err(|e| failed(profile, format!("write input: {e}")))?;
        let cov_shm = case_dir.join("cov.shm");
        arm_cov_shm(&cov_shm).map_err(|e| failed(profile, format!("arm coverage shm: {e}")))?;
        let runtrace_log = case_dir.join("runtrace.jsonl");
        fs::write(&runtrace_log, b"")
            .map_err(|e| failed(profile, format!("init runtrace: {e}")))?;
        let collector_log = case_dir.join("collector.jsonl");

        let Some(mut cmd) = build_command(profile) else {
            return Ok(ProfileRun::setup_failure(profile.name.clone()));
        };

        // Resolve secret references in the environment overlay from a local source
        // and record them so they can be redacted out of persisted artifacts.
        for (key, value) in &profile.env {
            match value {
                EnvValue::Literal(literal) => {
                    cmd.env(key, literal);
                }
                EnvValue::SecretRef(reference) => {
                    if let Some(resolved) = resolve_secret(reference, &self.secret_prefix) {
                        self.secrets.insert(reference.clone(), resolved.clone());
                        cmd.env(key, resolved);
                    }
                    // An unresolved reference is left unset; the profile's own
                    // bootstrap decides whether that is an auth/setup failure.
                }
            }
        }

        cmd.env("BHF_COV_SHM", &cov_shm)
            .env("BHF_RUNTRACE_LOG", &runtrace_log)
            .env("BHF_RUNTRACE_MODE", "reporting")
            .env("BHF_COLLECTOR_LOG", &collector_log)
            .env("BHF_RELATIONAL_INPUT", &input_path)
            .current_dir(&case_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(shim) = &self.shim {
            cmd.env("LD_PRELOAD", shim_path::ld_preload_value(shim));
        }

        let Some(outcome) = spawn_capture(cmd, input, self.timeout) else {
            return Ok(ProfileRun::setup_failure(profile.name.clone()));
        };

        let coverage = read_cov_shm(&cov_shm);
        let (events, semantic_hits) = collect_observations(profile, &runtrace_log, &collector_log);

        Ok(ProfileRun {
            profile: profile.name.clone(),
            run_state: RunState::Ready,
            exit_code: outcome.exit_code,
            response: outcome.stdout,
            coverage,
            events,
            semantic_hits,
            auth_decisions: Vec::new(),
        })
    }
}

fn failed(profile: &Profile, detail: String) -> ExecError {
    ExecError::Failed {
        profile: profile.name.clone(),
        detail,
    }
}

/// Build the spawn command from the profile's runner/args (feature #47 surface).
fn build_command(profile: &Profile) -> Option<Command> {
    match (&profile.runner, profile.args.as_slice()) {
        (Some(runner), args) => {
            let mut cmd = Command::new(runner);
            cmd.args(args);
            Some(cmd)
        }
        (None, [program, rest @ ..]) => {
            let mut cmd = Command::new(program);
            cmd.args(rest);
            Some(cmd)
        }
        (None, []) => None,
    }
}

struct RunOutcome {
    exit_code: Option<i32>,
    stdout: Vec<u8>,
}

/// Spawn `cmd`, feed `input` on stdin, enforce `timeout`, and capture stdout +
/// exit code. Returns `None` when the process could not be spawned at all (a
/// setup failure). A timeout yields `exit_code: None`.
///
/// stdin is fed and stdout/stderr are drained on dedicated threads that run
/// concurrently with the wait loop, so the child can never deadlock the parent
/// against a full pipe: a target that streams more than a pipe buffer of output,
/// or that never reads its stdin, keeps making progress instead of blocking until
/// `timeout`. On timeout (or a wait error) the child is killed; closing its pipe
/// ends unblocks the feed/drain threads, which are then joined so no per-case
/// thread lingers. Per-(profile, case) isolation is unchanged — each call owns its
/// own child and its own pipes.
fn spawn_capture(mut cmd: Command, input: &[u8], timeout: Duration) -> Option<RunOutcome> {
    let mut child = cmd.spawn().ok()?;

    // Hand each stdio end to its own thread *before* the wait loop, so writing a
    // large stdin and draining a large stdout/stderr happen in parallel with the
    // child's own progress — the sequential "write all stdin, then poll, then read
    // stdout" shape deadlocked whenever either pipe filled.
    let stdin_feeder = child.stdin.take().map(|mut stdin| {
        let payload = input.to_vec();
        std::thread::spawn(move || {
            // A target that ignores or short-circuits stdin makes this fail with
            // EPIPE once its read end closes; that is expected, not an error.
            let _ = stdin.write_all(&payload);
            // Dropping `stdin` here closes it so the child sees EOF.
        })
    });
    let stdout_drain = child.stdout.take().map(|mut out| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = out.read_to_end(&mut buf);
            buf
        })
    });
    let stderr_drain = child.stderr.take().map(|mut err| {
        std::thread::spawn(move || {
            let mut sink = Vec::new();
            let _ = err.read_to_end(&mut sink);
        })
    });

    let start = Instant::now();
    let mut timed_out = false;
    let mut errored = false;
    let mut exit_status = None;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_status = Some(status);
                break;
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                errored = true;
                break;
            }
        }
    }

    // The child has exited or been killed, so every pipe end is now closed: the
    // feed/drain threads observe EOF/EPIPE and finish. Join them to collect the
    // captured stdout and to guarantee no per-case thread outlives the run.
    if let Some(feeder) = stdin_feeder {
        let _ = feeder.join();
    }
    let stdout = stdout_drain
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    if let Some(drain) = stderr_drain {
        let _ = drain.join();
    }

    let exit_code = if timed_out || errored {
        None
    } else {
        exit_status.and_then(|status| status.code())
    };
    Some(RunOutcome { exit_code, stdout })
}

/// Read the coverage bitmap back (byte-per-edge, non-zero == hit), capped at the
/// bitmap size — the same convention `fuzz.rs::coverage_from_env` reads.
fn read_cov_shm(path: &Path) -> Vec<u8> {
    let Ok(file) = fs::File::open(path) else {
        return Vec::new();
    };
    let mut buf = Vec::new();
    let _ = file.take(COV_BITS as u64).read_to_end(&mut buf);
    buf
}

fn arm_cov_shm(path: &Path) -> std::io::Result<()> {
    let file = fs::File::create(path)?;
    // A freshly-created/truncated file of this length is all-zero (no edges yet),
    // and it is distinct per (profile, case), so no edge bleeds across profiles.
    file.set_len(COV_BITS as u64)?;
    Ok(())
}

/// Assemble a profile's effect events and semantic hits from the per-profile
/// runtime-trace log and platform collector log. A profile whose collector is
/// `none` reports its effect stream as *not collected* (`None`), so a predicate
/// that needs it yields a missing-observation outcome rather than silent
/// compliance.
fn collect_observations(
    profile: &Profile,
    runtrace_log: &Path,
    collector_log: &Path,
) -> (Option<Vec<EffectEvent>>, Vec<SemanticHit>) {
    if profile.collector == CollectorKind::None {
        return (None, Vec::new());
    }

    let mut rt_events = runtrace::parse_log(runtrace_log).unwrap_or_default();
    runtrace::dedupe_in_place(&mut rt_events);

    let mut events: Vec<EffectEvent> = rt_events
        .iter()
        .filter_map(runtrace_event_to_effect)
        .collect();

    // The platform-neutral collector (#60) feeds the SAME effect-event seam. On a
    // platform where the collector is active it writes `bhf.collector-event.v1`
    // JSONL to BHF_COLLECTOR_LOG; here we adapt whatever it produced onto the
    // crate's EffectEvent so the executor is source-agnostic.
    events.extend(collector_events(collector_log));

    // Runtime-oracle / postcondition semantic results (#55/#59) are an optional
    // evidence seam on the observation; map each runtime-oracle hit onto a
    // SemanticHit. Predicates never key on these (they enrich the finding only),
    // so an empty result never changes a verdict.
    let semantic_hits = runtrace::oracle_hits_from_events(&rt_events)
        .iter()
        .map(oracle_hit_to_semantic)
        .collect();

    (Some(events), semantic_hits)
}

/// Parse any `bhf.collector-event.v1` JSONL the platform collector wrote and map
/// each real event onto the crate's [`EffectEvent`].
fn collector_events(log: &Path) -> Vec<EffectEvent> {
    let Ok(text) = fs::read_to_string(log) else {
        return Vec::new();
    };
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<runtime_collector::CollectorEvent>(line).ok())
        .filter_map(|event| collector_event_to_effect(&event))
        .collect()
}

fn runtrace_event_to_effect(event: &RuntraceEvent) -> Option<EffectEvent> {
    Some(match event {
        RuntraceEvent::ProcessExec { api, program, .. } => EffectEvent {
            api: api.clone(),
            kind: EffectKind::ProcessExec,
            target: program.clone(),
        },
        RuntraceEvent::CommandExecuted { api, command, .. } => EffectEvent {
            api: api.clone(),
            kind: EffectKind::CommandExec,
            target: command.clone(),
        },
        RuntraceEvent::NetworkEgress { api, address, .. } => EffectEvent {
            api: api.clone(),
            kind: EffectKind::NetworkEgress,
            target: address.clone(),
        },
        RuntraceEvent::LibraryLoad { api, library, .. } => EffectEvent {
            api: api.clone(),
            kind: EffectKind::LibraryLoad,
            target: library.clone(),
        },
        _ => return None,
    })
}

fn collector_event_to_effect(event: &runtime_collector::CollectorEvent) -> Option<EffectEvent> {
    use runtime_collector::{EventKind, EventPhase};
    // Begin/End are session markers, not effects.
    if event.phase != EventPhase::Event {
        return None;
    }
    let image = event.process.image.clone().unwrap_or_default();
    let (kind, api, target) = match &event.kind {
        EventKind::ProcessCreate => (
            EffectKind::ProcessExec,
            "CreateProcess",
            command_string(event, &image),
        ),
        EventKind::ShellExecute => (
            EffectKind::CommandExec,
            "ShellExecute",
            command_string(event, &image),
        ),
        EventKind::Network => (
            EffectKind::NetworkEgress,
            "connect",
            event.address.clone().or_else(|| event.path.clone())?,
        ),
        EventKind::ModuleLoad => (EffectKind::LibraryLoad, "LoadLibrary", event.path.clone()?),
        _ => return None,
    };
    Some(EffectEvent {
        api: api.to_string(),
        kind,
        target,
    })
}

/// `[verb] image args...` joined by spaces, mirroring the collector oracle map.
fn command_string(event: &runtime_collector::CollectorEvent, image: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(verb) = &event.verb {
        parts.push(verb.clone());
    }
    let subject = if image.is_empty() {
        event.path.clone().unwrap_or_default()
    } else {
        image.to_string()
    };
    if !subject.is_empty() {
        parts.push(subject);
    }
    parts.extend(event.args.iter().cloned());
    parts.join(" ")
}

fn oracle_hit_to_semantic(hit: &finding_rules::oracle_sdk::OracleHit) -> SemanticHit {
    SemanticHit {
        rule: hit.rule_id.clone(),
        verdict: SemanticVerdict::Finding,
        detail: hit.message.clone(),
    }
}

/// Resolve a `<prefix><name>` secret reference from a local lab source: the env
/// var `BHF_SECRET_<NAME>` (name upper-cased, non-alphanumerics mapped to `_`),
/// mirroring `bhf project`'s `${secret:NAME}` scheme. bhf never stores the
/// resolved value — only the stable reference id is persisted.
fn resolve_secret(reference: &str, prefix: &str) -> Option<String> {
    let name = reference.strip_prefix(prefix).unwrap_or(reference);
    let env_name: String = format!(
        "BHF_SECRET_{}",
        name.chars()
            .map(|c| if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            })
            .collect::<String>()
    );
    std::env::var(env_name)
        .ok()
        .filter(|value| !value.is_empty())
}

/// Locate the runtime-trace shim to preload, unless disabled. A target that
/// emits its own `bhf.collector-event.v1`/runtrace stream (or one that must not
/// be instrumented) sets `BHF_RUNTRACE_SHIM=off` to skip the LD_PRELOAD shim.
fn locate_shim() -> Option<PathBuf> {
    match std::env::var("BHF_RUNTRACE_SHIM").as_deref() {
        Ok("off") | Ok("none") | Ok("") => None,
        _ => shim_path::locate(),
    }
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests;
