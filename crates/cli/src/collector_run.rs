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
//! satisfy the same contract. On a platform with no built-in provider, `auto`
//! stays inactive rather than fabricating a clean observation; an external
//! provider is always available through `--collector <PATH>`.

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

/// A resolved, runnable collector provider.
#[derive(Debug, Clone)]
pub struct ResolvedCollector {
    sidecar: PathBuf,
    window_ms: u64,
    backend: BackendInfo,
}

/// Locate the native Windows collector sidecar next to the running `bhf`
/// executable, honoring the `BHF_COLLECTOR_WIN` override first.
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
/// `auto` on Windows resolves to the native `bhf-collector-win` ETW sidecar; on
/// any other platform it stays inactive (no fabricated clean run) — a Linux or
/// cross target gets runtime coverage through the `--runtime-oracles` LD_PRELOAD
/// path (#59) or an explicit `--collector <PATH>` sidecar. An explicit sidecar
/// path hard-errors if it is not an executable file.
pub fn resolve(spec: &CollectorSpec, window_ms: u64) -> anyhow::Result<Option<ResolvedCollector>> {
    match spec {
        CollectorSpec::Off => Ok(None),
        CollectorSpec::Auto => match locate_windows_sidecar() {
            Some(path) => Ok(Some(resolved_for(path, window_ms)?)),
            None => {
                if cfg!(windows) {
                    Err(anyhow!(
                        "--collector auto: the native Windows collector (bhf-collector-win) \
                         was not found next to bhf; build it (`cargo build -p bhf_collector_win`) \
                         or set BHF_COLLECTOR_WIN to its path"
                    ))
                } else {
                    // No built-in native provider on this platform. Stay inactive
                    // rather than pretend to have observed a clean run.
                    Ok(None)
                }
            }
        },
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
        sidecar,
        window_ms,
        backend,
    })
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

    /// Run the sidecar for one testcase and return the raw JSONL sink it wrote.
    fn observe(&self, params: &CollectorRunParams<'_>) -> anyhow::Result<String> {
        std::fs::create_dir_all(&params.tmp_dir)
            .with_context(|| format!("create {}", params.tmp_dir.display()))?;
        let sink = params.tmp_dir.join("collector.jsonl");
        let input_path = params.tmp_dir.join("collector_input.bin");
        std::fs::write(&input_path, params.input)
            .with_context(|| format!("write {}", input_path.display()))?;
        // Truncate any prior sink so a failed provider is never mistaken for a
        // prior clean run.
        let _ = std::fs::remove_file(&sink);

        let status = Command::new(&self.sidecar)
            .env("BHF_COLLECTOR_TESTCASE", &params.testcase)
            .env("BHF_COLLECTOR_WORKER", params.worker.to_string())
            .env("BHF_COLLECTOR_ROOT", &params.root)
            .env("BHF_COLLECTOR_ROOT_PID", params.root_pid.to_string())
            .env("BHF_COLLECTOR_ROOT_IMAGE", &params.root_image)
            .env("BHF_COLLECTOR_WINDOW_MS", self.window_ms.to_string())
            .env("BHF_COLLECTOR_INPUT", &input_path)
            .env("BHF_COLLECTOR_LOG", &sink)
            .status()
            .with_context(|| format!("spawn collector sidecar {}", self.sidecar.display()))?;
        if !status.success() {
            return Err(anyhow!(
                "collector sidecar {} exited with {} (it could not observe; refusing to treat \
                 this as a clean run)",
                self.sidecar.display(),
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

        for session in &set.sessions {
            run_fidelity.merge(&session.fidelity);
            let session_jsonl = session_to_jsonl(session);
            let attributed = attribute(session, self.window_ms);
            for pid in &attributed.tree_pids {
                tree_scope.insert(*pid);
            }
            let classes = observed_classes(session);
            let provenance = CollectorProvenance::from_attributed(
                self.backend(),
                &attributed,
                self.window_ms,
                classes,
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
            "mode": "sidecar",
            "active": true,
            "backend": {
                "name": self.backend.name,
                "version": self.backend.version,
                "hash": self.backend.hash,
            },
            "window_ms": self.window_ms,
            "process_tree_scope": tree_scope.into_iter().collect::<Vec<_>>(),
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
            sidecar: PathBuf::from("mock"),
            window_ms,
            backend: BackendInfo::new("mock", "test", "deadbeef"),
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
