// SPDX-License-Identifier: Apache-2.0

//! Host harness for the platform-neutral runtime-event collector (#60).
//!
//! A *collector* observes the process, filesystem, and module-load effects a
//! target performs while a testcase runs — including effects a target performs on
//! a **clean exit** (no crash) — and emits the versioned `bhf.collector-event.v1`
//! JSONL contract (see the `runtime_collector` crate). This module resolves the
//! `--collector` spec, runs the resolved provider for a testcase, attributes the
//! observed events to the testcase's descendant process tree, and feeds them
//! through the SAME bug-oracle registry the LD_PRELOAD runtime oracles (#59) use,
//! so a clean-exit semantic violation becomes a `binary_semantic` finding. The
//! raw [`CollectorSession`] evidence is stored next to the finding so replay can
//! reproduce it deterministically and a reviewer can audit the attribution.
//!
//! Providers are decoupled from this host by the JSONL wire format: a native
//! Windows ETW provider, an out-of-tree sidecar, or the dependency-free mock all
//! satisfy the same contract. `--collector auto` resolves to the native
//! `bhf-collector-win` ETW sidecar on Windows and to the in-process LD_PRELOAD
//! runtrace adapter on Linux (the `runtrace → collector` seam in
//! `crate::auto::runtrace`), so a clean-exit semantic violation becomes a
//! `binary_semantic` finding on either platform. Where no built-in provider
//! exists (no shim on a non-Windows host), `auto` stays inactive rather than
//! fabricating a clean observation; an external provider is always available
//! through `--collector <PATH>`.

use anyhow::{anyhow, Context};
use finding_rules::oracle_registry::ORACLE_REGISTRY;
use finding_rules::oracle_sdk::OracleHit;
use runtime_collector::{
    attribute, BackendInfo, CollectorProvenance, CollectorSession, CollectorSessionSet,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The default bounded post-exit observation window, in milliseconds.
pub const DEFAULT_WINDOW_MS: u64 = 250;

/// Event classes the Linux built-in (runtrace→collector) provider can observe at
/// all — its *declared* coverage (AC7), independent of what fires on any one run.
/// This is exactly the set [`crate::auto::runtrace::to_collector_event`] can
/// produce from the LD_PRELOAD shim's event vocabulary. The shim cannot observe
/// `shell_execute`/`registry`, nor the create/write/rename file sub-kinds, so
/// declaring those would overstate coverage and mislead a blind-spot audit.
pub const RUNTRACE_SUPPORTED_CLASSES: &[&str] = &[
    "file_delete",
    "file_open",
    "module_load",
    "network",
    "process_create",
];

/// Event classes the native Windows ETW provider (`bhf-collector-win`) can
/// observe — the process, file-I/O, and image-load kernel providers it
/// subscribes to. It does not subscribe to a network or registry provider, so
/// those are deliberately absent.
pub const WINDOWS_SUPPORTED_CLASSES: &[&str] = &[
    "file_create",
    "file_delete",
    "file_open",
    "file_rename",
    "file_write",
    "module_load",
    "process_create",
    "shell_execute",
];

/// How `--collector` resolves a provider.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum CollectorSpec {
    /// No collector (default): behaviour is unchanged (crash-only / #59 oracles).
    #[default]
    Off,
    /// The built-in provider for this platform (Windows ETW; inactive elsewhere).
    Auto,
    /// An external sidecar executable that speaks the collector JSONL protocol.
    Sidecar(PathBuf),
}

/// clap value parser for `--collector <auto|none|PATH>`.
pub fn parse_collector_spec(value: &str) -> Result<CollectorSpec, String> {
    match value {
        "none" | "off" => Ok(CollectorSpec::Off),
        "auto" => Ok(CollectorSpec::Auto),
        path if !path.is_empty() => Ok(CollectorSpec::Sidecar(PathBuf::from(path))),
        _ => Err("expected `auto`, `none`, or a path to a collector sidecar".to_owned()),
    }
}

/// How a resolved collector actually observes a testcase.
#[derive(Debug, Clone)]
enum CollectorSource {
    /// An external sidecar executable spawned per observation (Windows ETW
    /// `bhf-collector-win`, or any `--collector <PATH>` provider).
    Sidecar(PathBuf),
    /// The Linux built-in provider: the LD_PRELOAD runtrace shim. The host runs
    /// the target under this shim and feeds the captured events to the collector
    /// through the `runtrace → collector` adapter, so `--collector auto` works on
    /// Linux without a native sidecar. Carries the resolved shim so the host can
    /// arm a target execution with it.
    Runtrace(crate::runtime_oracles::RuntimeOracles),
}

/// A resolved, runnable collector provider.
#[derive(Debug, Clone)]
pub struct ResolvedCollector {
    source: CollectorSource,
    window_ms: u64,
    backend: BackendInfo,
}

/// Locate the native Windows collector sidecar next to the running `bhf`
/// executable, honoring the `BHF_COLLECTOR_WIN` override first. Only consulted on
/// Windows (see [`resolve_auto`]): on a non-Windows host the built-in provider is
/// the runtrace adapter, and a Linux-built `bhf-collector-win` cannot observe
/// anyway (it exits non-zero), so `auto` never selects it there — an explicit
/// `--collector <PATH>` is the escape hatch for a custom non-Windows sidecar.
fn locate_windows_sidecar() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("BHF_COLLECTOR_WIN") {
        let p = PathBuf::from(explicit);
        if p.is_file() {
            return Some(p);
        }
    }
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    for name in ["bhf-collector-win", "bhf-collector-win.exe"] {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Resolve `spec` into a runnable provider, or `None` when the collector is off
/// or no built-in provider exists for this platform.
///
/// `auto` resolves to the native `bhf-collector-win` ETW sidecar on Windows and
/// to the in-process LD_PRELOAD runtrace adapter on Linux (the built-in provider
/// for each platform). On a non-Windows host where the runtrace shim is
/// unavailable it stays inactive (no fabricated clean run); an explicit
/// `--collector <PATH>` sidecar is always available and hard-errors if the path
/// is not an executable file.
pub fn resolve(spec: &CollectorSpec, window_ms: u64) -> anyhow::Result<Option<ResolvedCollector>> {
    match spec {
        CollectorSpec::Off => Ok(None),
        CollectorSpec::Auto => resolve_auto(window_ms),
        CollectorSpec::Sidecar(path) => {
            if !path.is_file() {
                return Err(anyhow!(
                    "--collector {}: not an executable file",
                    path.display()
                ));
            }
            Ok(Some(resolved_for(path.clone(), window_ms)?))
        }
    }
}

/// Resolve `--collector auto` to the built-in provider for this platform: the
/// native Windows ETW sidecar on Windows, the LD_PRELOAD runtrace adapter on a
/// non-Windows host (inactive when its shim is unavailable). The `cfg!(windows)`
/// branch keeps both paths compiled on every platform (so neither helper is
/// platform-dead) while selecting the right one at runtime.
fn resolve_auto(window_ms: u64) -> anyhow::Result<Option<ResolvedCollector>> {
    if cfg!(windows) {
        match locate_windows_sidecar() {
            // The auto-resolved Windows sidecar is the known native ETW provider,
            // so it declares the ETW-observable classes (AC7). An arbitrary
            // `--collector <PATH>` sidecar cannot be assumed to, and declares none.
            Some(path) => {
                let mut resolved = resolved_for(path, window_ms)?;
                resolved.backend = resolved
                    .backend
                    .with_supported_classes(WINDOWS_SUPPORTED_CLASSES.iter().copied());
                Ok(Some(resolved))
            }
            None => Err(anyhow!(
                "--collector auto: the native Windows collector (bhf-collector-win) \
                 was not found next to bhf; build it (`cargo build -p bhf_collector_win`) \
                 or set BHF_COLLECTOR_WIN to its path"
            )),
        }
    } else {
        match crate::runtime_oracles::RuntimeOracles::resolve(
            crate::runtime_oracles::RuntimeOracleMode::Auto,
            "reporting",
        )? {
            Some(shim) => Ok(Some(resolved_runtrace(shim, window_ms))),
            // No runtrace shim on this host: stay inactive rather than fabricate a
            // clean run.
            None => Ok(None),
        }
    }
}

fn resolved_for(sidecar: PathBuf, window_ms: u64) -> anyhow::Result<ResolvedCollector> {
    let bytes = std::fs::read(&sidecar)
        .with_context(|| format!("read collector sidecar {}", sidecar.display()))?;
    let name = sidecar
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("sidecar")
        .to_owned();
    let backend = BackendInfo::new(name, "sidecar", format!("{:x}", Sha256::digest(&bytes)));
    Ok(ResolvedCollector {
        source: CollectorSource::Sidecar(sidecar),
        window_ms,
        backend,
    })
}

/// Build the Linux built-in (runtrace-backed) collector. The backend hash is the
/// shim's own SHA-256, so a collector finding audits back to the exact shim.
fn resolved_runtrace(
    shim: crate::runtime_oracles::RuntimeOracles,
    window_ms: u64,
) -> ResolvedCollector {
    let backend = BackendInfo::new(
        "runtrace",
        env!("CARGO_PKG_VERSION"),
        shim.shim_sha256().to_owned(),
    )
    .with_supported_classes(RUNTRACE_SUPPORTED_CLASSES.iter().copied());
    ResolvedCollector {
        source: CollectorSource::Runtrace(shim),
        window_ms,
        backend,
    }
}

/// What a lane hands the collector for one observation.
pub struct CollectorRunParams<'a> {
    pub testcase: String,
    pub worker: u32,
    pub root: String,
    pub root_pid: u32,
    pub root_image: String,
    pub input: &'a [u8],
    pub tmp_dir: PathBuf,
}

/// One collector-sourced semantic finding ready to be written.
#[derive(Debug, Clone)]
pub struct CollectorFinding {
    pub hit: OracleHit,
    pub signature: String,
    pub provenance: CollectorProvenance,
    pub root: String,
    pub attributing_event: Value,
    pub process_tree: Vec<u32>,
    pub session_jsonl: String,
}

/// The result of one collector observation: the deduplicated findings plus the
/// run-manifest provenance block.
pub struct CollectorOutcome {
    pub findings: Vec<CollectorFinding>,
    pub run_provenance: Value,
}

impl ResolvedCollector {
    fn backend(&self) -> &BackendInfo {
        &self.backend
    }

    /// The run-manifest `mode` label for this provider's source.
    fn source_label(&self) -> &'static str {
        match &self.source {
            CollectorSource::Sidecar(_) => "sidecar",
            CollectorSource::Runtrace(_) => "runtrace",
        }
    }

    /// The resolved runtrace shim when this is the Linux built-in provider, else
    /// `None` (a sidecar provider). The host uses it to arm a target execution so
    /// the collector can observe the run's effects through the shim.
    pub fn runtrace_shim(&self) -> Option<&crate::runtime_oracles::RuntimeOracles> {
        match &self.source {
            CollectorSource::Runtrace(shim) => Some(shim),
            CollectorSource::Sidecar(_) => None,
        }
    }

    /// Evaluate a raw `bhf.collector-event.v1` JSONL stream (for example the one
    /// the `runtrace → collector` adapter produced from a run's shim events) and
    /// return the deduplicated findings plus run provenance — the same evaluation
    /// the sidecar path performs on the sink it reads.
    pub fn evaluate_jsonl(&self, jsonl: &str, root: &str) -> CollectorOutcome {
        let set = CollectorSessionSet::from_jsonl(jsonl);
        self.evaluate(&set, root)
    }

    /// Run the sidecar for one testcase and return the raw JSONL sink it wrote.
    fn observe(&self, params: &CollectorRunParams<'_>) -> anyhow::Result<String> {
        let sidecar = match &self.source {
            CollectorSource::Sidecar(path) => path,
            CollectorSource::Runtrace(_) => {
                return Err(anyhow!(
                    "the runtrace-backed collector is driven by the host (it observes the \
                     target under the LD_PRELOAD shim), not spawned as a sidecar"
                ));
            }
        };
        std::fs::create_dir_all(&params.tmp_dir)
            .with_context(|| format!("create {}", params.tmp_dir.display()))?;
        let sink = params.tmp_dir.join("collector.jsonl");
        let input_path = params.tmp_dir.join("collector_input.bin");
        std::fs::write(&input_path, params.input)
            .with_context(|| format!("write {}", input_path.display()))?;
        // Truncate any prior sink so a failed provider is never mistaken for a
        // prior clean run.
        let _ = std::fs::remove_file(&sink);

        let status = Command::new(sidecar)
            .env("BHF_COLLECTOR_TESTCASE", &params.testcase)
            .env("BHF_COLLECTOR_WORKER", params.worker.to_string())
            .env("BHF_COLLECTOR_ROOT", &params.root)
            .env("BHF_COLLECTOR_ROOT_PID", params.root_pid.to_string())
            .env("BHF_COLLECTOR_ROOT_IMAGE", &params.root_image)
            .env("BHF_COLLECTOR_WINDOW_MS", self.window_ms.to_string())
            .env("BHF_COLLECTOR_INPUT", &input_path)
            .env("BHF_COLLECTOR_LOG", &sink)
            .status()
            .with_context(|| format!("spawn collector sidecar {}", sidecar.display()))?;
        if !status.success() {
            return Err(anyhow!(
                "collector sidecar {} exited with {} (it could not observe; refusing to treat \
                 this as a clean run)",
                sidecar.display(),
                status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".to_owned())
            ));
        }
        std::fs::read_to_string(&sink)
            .with_context(|| format!("read collector sink {}", sink.display()))
    }

    /// Observe a testcase, attribute the events, and evaluate the oracle registry
    /// over them, returning deduplicated findings plus run provenance.
    pub fn run_once(&self, params: &CollectorRunParams<'_>) -> anyhow::Result<CollectorOutcome> {
        let jsonl = self.observe(params)?;
        let set = CollectorSessionSet::from_jsonl(&jsonl);
        Ok(self.evaluate(&set, &params.root))
    }

    /// Pure evaluation step (no I/O): attribute each session and run the oracle
    /// registry over its events. Deduplicated by oracle signature.
    pub fn evaluate(&self, set: &CollectorSessionSet, root: &str) -> CollectorOutcome {
        let mut findings = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut run_fidelity = runtime_collector::schema::Fidelity::default();
        let mut tree_scope: BTreeSet<u32> = BTreeSet::new();
        let mut run_observed: BTreeSet<String> = BTreeSet::new();

        for session in &set.sessions {
            run_fidelity.merge(&session.fidelity);
            let session_jsonl = session_to_jsonl(session);
            let attributed = attribute(session, self.window_ms);
            for pid in &attributed.tree_pids {
                tree_scope.insert(*pid);
            }
            // The classes that actually FIRED this session (AC7: observed, kept
            // distinct from the backend's declared coverage in provenance).
            let observed = observed_classes(session);
            run_observed.extend(observed.iter().cloned());
            let provenance = CollectorProvenance::from_attributed(
                self.backend(),
                &attributed,
                self.window_ms,
                observed,
                session.fidelity.clone(),
            );

            for ev in attributed.attributed.iter().copied() {
                let Some(oracle_ev) = runtime_collector::to_oracle_event(ev, root) else {
                    continue;
                };
                for oracle in ORACLE_REGISTRY.iter() {
                    let Some(hit) = oracle.evaluate(&oracle_ev) else {
                        continue;
                    };
                    let signature = crate::runtime_oracles::oracle_signature(&hit);
                    if !seen.insert(signature.clone()) {
                        continue;
                    }
                    findings.push(CollectorFinding {
                        hit,
                        signature,
                        provenance: provenance.clone(),
                        root: root.to_owned(),
                        attributing_event: serde_json::to_value(ev).unwrap_or(Value::Null),
                        process_tree: attributed.tree_pids.iter().copied().collect(),
                        session_jsonl: session_jsonl.clone(),
                    });
                }
            }
        }

        let run_provenance = json!({
            "mode": self.source_label(),
            "active": true,
            // The collector actually observed this run (events were collected and
            // evaluated). Contrast `not_observed`, where a resolved collector could
            // not observe at all and must never be read as a clean assurance (AC6).
            "observed": true,
            "backend": {
                "name": self.backend.name,
                "version": self.backend.version,
                "hash": self.backend.hash,
            },
            "window_ms": self.window_ms,
            "process_tree_scope": tree_scope.into_iter().collect::<Vec<_>>(),
            // AC7: declared backend coverage vs the subset that fired this run.
            "supported_event_classes": self.backend.supported_event_classes.clone(),
            "observed_event_classes": run_observed.into_iter().collect::<Vec<_>>(),
            "clean_assurance": set.clean_assurance_ok(),
            "fidelity": {
                "lost": run_fidelity.lost,
                "permission_denied": run_fidelity.permission_denied,
                "unsupported_fields": run_fidelity.unsupported_fields,
            },
        });

        CollectorOutcome {
            findings,
            run_provenance,
        }
    }

    /// Provenance for a *resolved-but-not-observed* collector run: the provider
    /// was active (successfully resolved) but could not actually observe this run,
    /// so there is no event stream to evaluate. The Linux runtrace built-in hits
    /// this when it relies on the fuzz loop's shim log and the loop did not arm the
    /// shim (`--runtime-oracles off`): the shim never ran, so nothing was observed.
    ///
    /// Such a run is recorded DEGRADED — `observed: false`, `clean_assurance:
    /// false`, with the reason captured as a fidelity limitation — and never
    /// presents crash-only coverage as a clean collector assurance (#60 AC6). It
    /// yields no findings (there was nothing to evaluate).
    pub fn not_observed(&self, reason: impl Into<String>) -> CollectorOutcome {
        let reason = reason.into();
        let run_provenance = json!({
            "mode": self.source_label(),
            "active": true,
            "observed": false,
            "backend": {
                "name": self.backend.name,
                "version": self.backend.version,
                "hash": self.backend.hash,
            },
            "window_ms": self.window_ms,
            "process_tree_scope": Vec::<u32>::new(),
            "supported_event_classes": self.backend.supported_event_classes.clone(),
            "observed_event_classes": Vec::<String>::new(),
            // Nothing was observed: a clean assurance is impossible, not merely
            // absent. The reason is recorded as an unsupported-observation signal.
            "clean_assurance": false,
            "fidelity": {
                "lost": 0,
                "permission_denied": false,
                "unsupported_fields": [reason],
            },
        });
        CollectorOutcome {
            findings: Vec::new(),
            run_provenance,
        }
    }
}

/// Run-manifest provenance when the collector is inactive (off, or no built-in
/// provider on this platform), so a crash-only run is distinguishable from an
/// observed one.
pub fn inactive_run_provenance(spec: &CollectorSpec) -> Value {
    json!({
        "mode": match spec {
            CollectorSpec::Off => "none",
            CollectorSpec::Auto => "auto",
            CollectorSpec::Sidecar(_) => "sidecar",
        },
        "active": false,
    })
}

/// Serialize a session back to JSONL for stored evidence.
fn session_to_jsonl(session: &CollectorSession) -> String {
    let mut out = String::new();
    for ev in &session.events {
        out.push_str(&ev.to_jsonl_line());
        out.push('\n');
    }
    out
}

/// The distinct event classes observed in a session (the classes the provider
/// demonstrably emitted), for provenance.
fn observed_classes(session: &CollectorSession) -> Vec<String> {
    let mut classes: BTreeSet<String> = BTreeSet::new();
    for ev in &session.events {
        classes.insert(ev.kind.as_str().to_owned());
    }
    classes.into_iter().collect()
}

/// Build the `collector` provenance block embedded in a finding.
fn collector_block(finding: &CollectorFinding) -> Value {
    json!({
        "provenance": finding.provenance,
        "root": finding.root,
        "evidence": EVIDENCE_FILE,
        "attributing_event": finding.attributing_event,
        "process_tree": finding.process_tree,
        "clean_assurance": finding.provenance.clean_assurance_ok(),
    })
}

/// Name of the stored collector-session evidence file next to a finding.
pub const EVIDENCE_FILE: &str = "collector_session.jsonl";

/// Allocate the next collector finding id (`COL-NNNN`) in `findings_dir`. A
/// dedicated prefix keeps collector findings from colliding with a lane's own id
/// scheme (crash `BF-` / source `F-`).
pub fn next_collector_finding_id(findings_dir: &Path) -> anyhow::Result<String> {
    let mut max_id = 0usize;
    if findings_dir.is_dir() {
        for entry in std::fs::read_dir(findings_dir)
            .with_context(|| format!("read {}", findings_dir.display()))?
        {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                if let Some(n) = name
                    .strip_prefix("COL-")
                    .and_then(|v| v.parse::<usize>().ok())
                {
                    max_id = max_id.max(n);
                }
            }
        }
    }
    Ok(format!("COL-{next:04}", next = max_id + 1))
}

/// Write a collector-sourced `binary_semantic` finding to `dir`, reusing the
/// semantic finding shape (#59) and adding the `collector` provenance block plus
/// the stored session evidence used for deterministic replay.
///
/// `target` is the lane-specific command/target descriptor (binary path + argv,
/// or harness identity) spliced into the finding so a reviewer can see what ran.
pub fn write_finding(
    dir: &Path,
    id: &str,
    target: Value,
    finding: &CollectorFinding,
    input: &[u8],
) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    std::fs::write(dir.join("testcase.bin"), input)
        .with_context(|| format!("write {}", dir.join("testcase.bin").display()))?;
    std::fs::write(dir.join(EVIDENCE_FILE), finding.session_jsonl.as_bytes())
        .with_context(|| format!("write {}", dir.join(EVIDENCE_FILE).display()))?;

    let evidence: serde_json::Map<String, Value> = finding
        .hit
        .evidence
        .iter()
        .map(|e| (e.key.clone(), Value::String(e.value.clone())))
        .collect();

    let doc = json!({
        "id": id,
        "kind": "binary_semantic",
        "rule_id": finding.hit.rule_id,
        "classification": "oracle_hit",
        "confirmation": "collector",
        "severity": "high",
        "confidence": "high",
        "message": finding.hit.message,
        "target": target,
        "input": {
            "bytes": input.len(),
            "testcase": "testcase.bin"
        },
        "oracle": {
            "name": finding.hit.oracle_name,
            "category": finding.hit.category,
            "api": finding.hit.api,
            "message": finding.hit.message,
            "evidence": evidence,
            "signature": finding.signature
        },
        "collector": collector_block(finding),
        "paths": {
            "testcase": "testcase.bin",
            "collector_evidence": EVIDENCE_FILE
        },
        "triage": {
            "replay": format!("bhf replay {id}")
        }
    });
    std::fs::write(dir.join("finding.json"), serde_json::to_vec_pretty(&doc)?)
        .with_context(|| format!("write {}", dir.join("finding.json").display()))?;
    Ok(())
}

/// A finding is collector-sourced when its `finding.json` carries a `collector`
/// provenance block. Replay/minimize route on this independently of the harness,
/// since a collector finding reproduces from its stored evidence, not a re-run.
pub fn is_collector_finding(finding_dir: &Path) -> bool {
    std::fs::read(finding_dir.join("finding.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .map(|v| {
            v.get("collector").is_some()
                && v.get("kind").and_then(Value::as_str) == Some("binary_semantic")
        })
        .unwrap_or(false)
}

/// Re-evaluate the oracle registry over a finding's stored collector evidence and
/// return every oracle signature it reproduces, plus the attributed sessions (for
/// surfacing the process tree).
fn replayed_signatures(finding: &Value, evidence: &str, root: &str, window_ms: u64) -> Vec<String> {
    let set = CollectorSessionSet::from_jsonl(evidence);
    let mut sigs = Vec::new();
    for session in &set.sessions {
        let attributed = attribute(session, window_ms);
        for ev in attributed.attributed.iter().copied() {
            if let Some(oracle_ev) = runtime_collector::to_oracle_event(ev, root) {
                for oracle in ORACLE_REGISTRY.iter() {
                    if let Some(hit) = oracle.evaluate(&oracle_ev) {
                        sigs.push(crate::runtime_oracles::oracle_signature(&hit));
                    }
                }
            }
        }
    }
    let _ = finding;
    sigs
}

fn finding_root(finding: &Value) -> String {
    finding
        .pointer("/collector/root")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

fn finding_window_ms(finding: &Value) -> u64 {
    finding
        .pointer("/collector/provenance/observation_window_ms")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_WINDOW_MS)
}

/// Replay a collector-sourced finding deterministically from its stored evidence:
/// re-run the oracle evaluation over the recorded `CollectorSession` and confirm
/// the SAME oracle signature fires, surfacing the attributing event and the
/// descendant process tree so the attribution can be audited. A live collector is
/// not re-run (live process trees are non-deterministic and out of replay scope).
pub fn replay_collector_finding(finding_dir: &Path) -> i32 {
    match replay_collector_finding_inner(finding_dir) {
        Ok(true) => {
            let _ = corpus::finding::touch_last_seen(finding_dir, "replay");
            println!("MATCH");
            0
        }
        Ok(false) => {
            bhfeprintln!("MISMATCH collector semantic signature not reproduced from evidence");
            3
        }
        Err(error) => {
            bhfeprintln!("error: {error:#}");
            1
        }
    }
}

fn replay_collector_finding_inner(finding_dir: &Path) -> anyhow::Result<bool> {
    let finding = read_finding_json(finding_dir)?;
    let want = finding
        .pointer("/oracle/signature")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("collector finding is missing oracle.signature"))?
        .to_owned();
    let evidence_path = finding_dir.join(EVIDENCE_FILE);
    let evidence = std::fs::read_to_string(&evidence_path)
        .with_context(|| format!("read collector evidence {}", evidence_path.display()))?;
    let root = finding_root(&finding);
    let window_ms = finding_window_ms(&finding);
    let sigs = replayed_signatures(&finding, &evidence, &root, window_ms);

    // Surface the attributing event + descendant process tree for the auditor.
    if let Some(ev) = finding.pointer("/collector/attributing_event") {
        if !ev.is_null() {
            println!(
                "attributing event: {}",
                serde_json::to_string(ev).unwrap_or_default()
            );
        }
    }
    if let Some(tree) = finding.pointer("/collector/process_tree") {
        println!("descendant process tree: {tree}");
    }
    Ok(sigs.iter().any(|s| s == &want))
}

/// Minimize a collector-sourced finding. The stored evidence is captured by the
/// provider independently of the testcase bytes, so there is nothing to reduce
/// under deterministic replay: re-confirm the finding still reproduces from its
/// evidence and leave the reproducer unchanged (an honest no-op rather than a
/// misleading zero-byte "minimum").
pub fn minimize_collector_finding(finding_dir: &Path) -> anyhow::Result<CollectorMinimizeSummary> {
    let finding = read_finding_json(finding_dir)?;
    let want = finding
        .pointer("/oracle/signature")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("collector finding is missing oracle.signature"))?
        .to_owned();
    let evidence = std::fs::read_to_string(finding_dir.join(EVIDENCE_FILE))
        .with_context(|| "read collector evidence")?;
    let root = finding_root(&finding);
    let window_ms = finding_window_ms(&finding);
    let reproduced = replayed_signatures(&finding, &evidence, &root, window_ms)
        .iter()
        .any(|s| s == &want);
    if !reproduced {
        return Err(anyhow!(
            "collector finding no longer reproduces from its stored evidence; refusing to minimize"
        ));
    }
    let original_len = std::fs::read(finding_dir.join("testcase.bin"))
        .map(|b| b.len())
        .unwrap_or(0);
    Ok(CollectorMinimizeSummary {
        original_len,
        reduced: false,
    })
}

/// Summary of a collector-finding minimize attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorMinimizeSummary {
    pub original_len: usize,
    pub reduced: bool,
}

fn read_finding_json(finding_dir: &Path) -> anyhow::Result<Value> {
    let path = finding_dir.join("finding.json");
    serde_json::from_slice(
        &std::fs::read(&path).with_context(|| format!("read {}", path.display()))?,
    )
    .with_context(|| format!("parse {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtime_collector::mock::MockCollector;
    use runtime_collector::{Collector, CollectorContext};

    fn mock_resolved(window_ms: u64) -> ResolvedCollector {
        ResolvedCollector {
            source: CollectorSource::Sidecar(PathBuf::from("mock")),
            window_ms,
            backend: BackendInfo::new("mock", "test", "deadbeef"),
        }
    }

    /// A runtrace-shaped resolved collector (sidecar source, but a backend that
    /// declares the runtrace coverage) for exercising provenance class reporting.
    fn declaring_resolved(window_ms: u64) -> ResolvedCollector {
        ResolvedCollector {
            source: CollectorSource::Sidecar(PathBuf::from("mock")),
            window_ms,
            backend: BackendInfo::new("mock", "test", "deadbeef")
                .with_supported_classes(RUNTRACE_SUPPORTED_CLASSES.iter().copied()),
        }
    }

    fn sessions(mock: &MockCollector, testcase: &str, worker: u32) -> CollectorSessionSet {
        let ctx = CollectorContext::new(testcase, worker, "/srv/sandbox", 250);
        CollectorSessionSet::from_jsonl(&mock.observe(&ctx).unwrap())
    }

    #[test]
    fn parses_collector_spec_variants() {
        assert_eq!(parse_collector_spec("none").unwrap(), CollectorSpec::Off);
        assert_eq!(parse_collector_spec("off").unwrap(), CollectorSpec::Off);
        assert_eq!(parse_collector_spec("auto").unwrap(), CollectorSpec::Auto);
        assert_eq!(
            parse_collector_spec("/opt/probe").unwrap(),
            CollectorSpec::Sidecar(PathBuf::from("/opt/probe"))
        );
    }

    #[test]
    fn off_spec_resolves_to_inactive() {
        assert!(resolve(&CollectorSpec::Off, 250).unwrap().is_none());
    }

    #[test]
    fn three_positive_classes_each_emit_a_finding_without_a_crash() {
        let collector = mock_resolved(250);
        let mut set = sessions(&MockCollector::process_exec(), "tc", 0);
        set.sessions
            .extend(sessions(&MockCollector::path_control(), "tc", 1).sessions);
        set.sessions
            .extend(sessions(&MockCollector::controlled_library_load(), "tc", 2).sessions);
        let outcome = collector.evaluate(&set, "/srv/sandbox");
        let rules: BTreeSet<String> = outcome
            .findings
            .iter()
            .map(|f| f.hit.rule_id.clone())
            .collect();
        assert!(rules.contains("BHF-431"), "process-exec finding: {rules:?}");
        assert!(rules.contains("BHF-405"), "path-control finding: {rules:?}");
        assert!(
            rules.contains("BHF-435"),
            "controlled-library-load finding: {rules:?}"
        );
    }

    #[test]
    fn fixed_constants_produce_no_taint_confirmed_finding() {
        let collector = mock_resolved(250);
        let set = sessions(&MockCollector::fixed_constants(), "tc", 0);
        let outcome = collector.evaluate(&set, "/srv/sandbox");
        for taint_rule in ["BHF-431", "BHF-405", "BHF-435"] {
            assert!(
                !outcome.findings.iter().any(|f| f.hit.rule_id == taint_rule),
                "a fixed constant must never be taint-confirmed, but {taint_rule} fired"
            );
        }
    }

    #[test]
    fn lossy_run_provenance_refuses_clean_assurance() {
        let collector = mock_resolved(250);
        let mock =
            MockCollector::process_exec().with_fidelity(runtime_collector::schema::Fidelity {
                lost: 2,
                permission_denied: true,
                unsupported_fields: vec!["process.token".into()],
            });
        let set = sessions(&mock, "tc", 0);
        let outcome = collector.evaluate(&set, "/srv/sandbox");
        assert_eq!(
            outcome.run_provenance.pointer("/clean_assurance"),
            Some(&Value::Bool(false)),
            "a lossy run must not be reported clean"
        );
        // The per-finding provenance also refuses the clean claim.
        assert!(outcome
            .findings
            .iter()
            .all(|f| !f.provenance.clean_assurance_ok()));
    }

    #[test]
    fn not_observed_run_is_degraded_never_clean() {
        // #60 AC6: a resolved collector that could not observe (shim not armed)
        // must record a degraded, not-observed run — never a clean assurance over
        // an unobserved stream — and emit no findings.
        let collector = declaring_resolved(250);
        let outcome = collector.not_observed("runtime_shim_not_armed");
        assert!(outcome.findings.is_empty(), "no findings without observation");
        assert_eq!(
            outcome.run_provenance.pointer("/active"),
            Some(&Value::Bool(true)),
            "the collector was resolved/active"
        );
        assert_eq!(
            outcome.run_provenance.pointer("/observed"),
            Some(&Value::Bool(false)),
            "but it observed nothing"
        );
        assert_eq!(
            outcome.run_provenance.pointer("/clean_assurance"),
            Some(&Value::Bool(false)),
            "an unobserved run must never be reported clean"
        );
        let unsupported = outcome
            .run_provenance
            .pointer("/fidelity/unsupported_fields")
            .and_then(Value::as_array)
            .expect("unsupported_fields present");
        assert!(
            unsupported
                .iter()
                .any(|v| v.as_str() == Some("runtime_shim_not_armed")),
            "the not-observed reason is recorded as a fidelity limitation"
        );
        // Declared backend coverage is still reported even with nothing observed.
        assert_eq!(
            outcome
                .run_provenance
                .pointer("/supported_event_classes")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(RUNTRACE_SUPPORTED_CLASSES.len())
        );
        assert_eq!(
            outcome
                .run_provenance
                .pointer("/observed_event_classes")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );
    }

    #[test]
    fn run_provenance_separates_declared_coverage_from_observed_classes() {
        // #60 AC7: supported_event_classes is the backend's declared coverage;
        // observed_event_classes is the subset that fired this run.
        let collector = declaring_resolved(250);
        let set = sessions(&MockCollector::process_exec(), "tc", 0);
        let outcome = collector.evaluate(&set, "/srv/sandbox");

        let supported: Vec<String> = outcome
            .run_provenance
            .pointer("/supported_event_classes")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        let observed: Vec<String> = outcome
            .run_provenance
            .pointer("/observed_event_classes")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();

        assert_eq!(
            supported,
            RUNTRACE_SUPPORTED_CLASSES
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
            "supported = backend-declared coverage, verbatim"
        );
        // observed = what the mock actually emitted this run (process_create
        // boundaries + a shell_execute effect) — reported verbatim, NOT clamped to
        // the declared set, and distinct from it.
        assert!(observed.contains(&"shell_execute".to_owned()));
        assert_ne!(observed, supported, "declared coverage != this run's hits");
        // The per-finding provenance carries the same declared coverage.
        for f in &outcome.findings {
            assert_eq!(f.provenance.supported_event_classes, supported);
        }
    }

    #[test]
    fn replay_reproduces_finding_from_stored_evidence() {
        let dir = std::env::temp_dir().join(format!(
            "bhf-collector-replay-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let collector = mock_resolved(250);
        let set = sessions(&MockCollector::path_control(), "tc", 0);
        let outcome = collector.evaluate(&set, "/srv/sandbox");
        let finding = &outcome.findings[0];
        write_finding(&dir, "BF-0001", json!({"kind": "test"}), finding, b"seed").unwrap();

        assert!(is_collector_finding(&dir));
        // Deterministic replay from stored evidence reproduces the signature.
        assert_eq!(replay_collector_finding(&dir), 0);

        // Tamper with the stored signature: replay must MISMATCH, never falsely MATCH.
        let path = dir.join("finding.json");
        let mut doc: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        doc["oracle"]["signature"] = json!("oracle:BHF-000:nope:none");
        std::fs::write(&path, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
        assert_eq!(replay_collector_finding(&dir), 3);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
