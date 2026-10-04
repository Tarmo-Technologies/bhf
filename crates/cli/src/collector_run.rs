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
use std::time::{Duration, Instant};

/// The default bounded post-exit observation window, in milliseconds.
pub const DEFAULT_WINDOW_MS: u64 = 250;

/// How long the host waits for a sidecar to signal it is live and watching (the
/// readiness ack) before giving up and recording a degraded, not-observed run. A
/// sidecar that never readies is bounded by this timeout rather than blocking the
/// run or being mistaken for a clean observation.
pub const READINESS_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on how long the replayed target itself may run under the observer
/// before it is killed (the replay is a single bounded execution, not a campaign).
pub const REPLAY_TARGET_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound on how long the host waits for the observer to finish writing its
/// sink after the replay completes. A provider that readies then wedges is killed
/// at this bound and recorded not-observed, so it can never hang the fuzz command
/// despite `--collector-window-ms` (#76 P2).
pub const CAPTURE_DRAIN: Duration = Duration::from_secs(3);

/// How the collector observed this run, recorded in provenance so a reviewer never
/// reads a limited observation as whole-campaign coverage (#76).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationMode {
    /// A specific retained testcase replayed under the collector. Coverage is
    /// limited to that one replayed execution — NOT the whole campaign.
    Replay,
    /// The Linux runtrace built-in re-expressing the campaign's aggregate shim log
    /// as collector events. Coverage is campaign-level/aggregate, not a per-testcase
    /// replay, so per-case identity is never fabricated for it.
    Aggregate,
}

impl ObservationMode {
    /// Short provenance label.
    pub fn label(self) -> &'static str {
        match self {
            ObservationMode::Replay => "replay",
            ObservationMode::Aggregate => "aggregate",
        }
    }

    /// The coverage scope this observation honestly represents.
    pub fn coverage(self) -> &'static str {
        match self {
            ObservationMode::Replay => "single-testcase-replay",
            ObservationMode::Aggregate => "whole-campaign-aggregate",
        }
    }

    /// Stamp `observation`/`coverage` onto a run-provenance JSON object, so the run
    /// manifest states which (limited) scope was observed.
    pub fn stamp(self, provenance: &mut Value) {
        if let Some(obj) = provenance.as_object_mut() {
            obj.insert("observation".to_owned(), json!(self.label()));
            obj.insert("coverage".to_owned(), json!(self.coverage()));
        }
    }
}

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
    pub root_image: String,
    pub input: &'a [u8],
    pub tmp_dir: PathBuf,
    /// Launches the retained target to replay, UNDER the already-ready observer,
    /// and returns the spawned child. The host calls this only AFTER the sidecar
    /// has acked readiness, so the observer is watching when the target runs, and
    /// records the child's real PID. `None` means there is no target to launch on
    /// this host (for example the sidecar path with no wired launch): the run is
    /// then recorded `not_observed`, never claimed as a replay that did not run
    /// (#76). The observer is still spawned and supervised so a readiness-but-hang
    /// provider is bounded rather than hanging the command.
    pub launch: Option<ReplayLauncher<'a>>,
}

/// Spawns the retained replay target and returns it [`LaunchedReplay`]. Called by
/// the host after the readiness ack. The launcher returns IMMEDIATELY: any stdin
/// input is delivered on a background thread, so a target that does not drain
/// stdin cannot block the supervising thread before its bounded wait begins (#76
/// re-review).
pub type ReplayLauncher<'a> = Box<dyn Fn() -> anyhow::Result<LaunchedReplay> + 'a>;

/// A launched replay target plus its background stdin-delivery thread (if any).
pub struct LaunchedReplay {
    /// The running target. The supervisor bounded-waits and reaps it.
    pub child: std::process::Child,
    /// Joins the thread writing the retained input to the target's stdin, so the
    /// supervisor can reap it after the target exits or is killed (the closed pipe
    /// unblocks any pending write). `None` for non-stdin input modes. A benign
    /// `BrokenPipe` here is expected when the target finishes (crashes/exits)
    /// before draining all input — that is the target's behavior, not a failure.
    pub delivery: Option<std::thread::JoinHandle<std::io::Result<()>>>,
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

/// The outcome of spawning the sidecar, launching the target under it, and
/// draining the capture — all bounded.
enum ObserveOutcome {
    /// The observer acked readiness, the target was launched under it and ran, and
    /// the observer wrote a sink. Carries the raw JSONL and the launched target's
    /// real PID (so the caller can confirm the evidence is about THAT process).
    Observed { jsonl: String, replayed_pid: u32 },
    /// The run could not be observed as a replay (no readiness ack, no target to
    /// launch, the capture timed out, a failed capture, or no sink). Carries a
    /// degrade reason routed to [`ResolvedCollector::not_observed`] — never a clean
    /// assurance, and never a false replay claim.
    NotObserved(String),
}

/// A retained campaign testcase chosen to replay under the collector: real bytes,
/// a real testcase id, the worker that replays it, and the input's content hash —
/// never a synthetic `testcase:"fuzz"` / empty input (#76).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayTestcase {
    pub testcase: String,
    pub worker: u32,
    pub input: Vec<u8>,
    /// SHA-256 of `input`, recorded in provenance so the replayed input is
    /// identifiable and the selection is auditable.
    pub input_sha256: String,
}

/// SHA-256 of `bytes` as lowercase hex.
fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Does this crash finding belong to `harness_id`'s campaign? A multi-target work
/// dir shares one `results/findings/` tree, so a replay must only adopt THIS
/// target's retained evidence — never another target's input/ID (#76 P2). The
/// association is read from the finding's recorded target identity.
fn finding_matches_harness(finding_dir: &Path, harness_id: &str) -> bool {
    let Ok(bytes) = std::fs::read(finding_dir.join("finding.json")) else {
        return false;
    };
    let Ok(doc) = serde_json::from_slice::<Value>(&bytes) else {
        return false;
    };
    // The identity a lane records for its target: the binary path (binary-fuzz) or
    // the harness id (harness lanes). Match any of the known locations exactly.
    for ptr in [
        "/target/binary/path",
        "/target/harness",
        "/harness_id",
        "/harness",
    ] {
        if doc.pointer(ptr).and_then(Value::as_str) == Some(harness_id) {
            return true;
        }
    }
    false
}

/// Select a retained testcase to replay under the collector: a crash finding's
/// stored `testcase.bin` **from this harness's campaign** first (the most
/// interesting retained input), else a persisted coverage-corpus input (already
/// stored per-harness). Returns `None` when this campaign retained nothing to
/// replay — the caller then records a degraded, not-observed run rather than
/// fabricating a synthetic observation. Deterministic (lowest id / name first) so
/// a replayed finding is reproducible, and the selected input's hash is recorded.
///
/// Collector findings (`COL-` ids) are skipped: they are what this pass writes,
/// and are not themselves campaign testcases. Crash findings whose recorded target
/// does not match `harness_id` are skipped so a sibling target's input is never
/// adopted.
pub fn select_replay_testcase(work_dir: &Path, harness_id: &str) -> Option<ReplayTestcase> {
    // 1) This harness's crash findings: results/findings/<id>/testcase.bin.
    let findings_dir = corpus::layout::findings_dir(work_dir);
    if let Ok(entries) = std::fs::read_dir(&findings_dir) {
        let mut crash_ids: Vec<(String, PathBuf, PathBuf)> = entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_str()?.to_owned();
                if name.starts_with("COL-") {
                    return None; // collector's own findings, not a campaign testcase
                }
                let dir = e.path();
                let tc = dir.join("testcase.bin");
                // Only this harness's findings — never a sibling target's input.
                (tc.is_file() && finding_matches_harness(&dir, harness_id))
                    .then_some((name, dir, tc))
            })
            .collect();
        crash_ids.sort_by(|a, b| a.0.cmp(&b.0));
        if let Some((id, _dir, tc)) = crash_ids.first() {
            if let Ok(bytes) = std::fs::read(tc) {
                let input_sha256 = sha256_hex(&bytes);
                return Some(ReplayTestcase {
                    testcase: id.clone(),
                    worker: 0,
                    input: bytes,
                    input_sha256,
                });
            }
        }
    }

    // 2) Persisted coverage corpus: corpus/<harness_id>/queue/<sha>.bin. This path
    //    is already scoped to the harness, so it cannot adopt a sibling's input.
    let queue = work_dir.join("corpus").join(harness_id).join("queue");
    if let Ok(entries) = std::fs::read_dir(&queue) {
        let mut inputs: Vec<(String, PathBuf)> = entries
            .flatten()
            .filter_map(|e| {
                let p = e.path();
                let stem = p.file_stem()?.to_str()?.to_owned();
                (p.extension().and_then(|x| x.to_str()) == Some("bin")).then_some((stem, p))
            })
            .collect();
        inputs.sort_by(|a, b| a.0.cmp(&b.0));
        if let Some((stem, path)) = inputs.first() {
            if let Ok(bytes) = std::fs::read(path) {
                let input_sha256 = sha256_hex(&bytes);
                return Some(ReplayTestcase {
                    testcase: format!("corpus-{stem}"),
                    worker: 0,
                    input: bytes,
                    input_sha256,
                });
            }
        }
    }

    None
}

/// Wait for `child` to exit, but no later than `deadline`. Returns its exit
/// status if it exited in time, or `None` after killing and reaping it on
/// timeout. Guarantees a bounded wait (no unbounded `child.wait()`).
fn wait_child_until(
    child: &mut std::process::Child,
    deadline: Instant,
) -> Option<std::process::ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
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

    /// Spawn the sidecar, LAUNCH the retained target under it once it is ready,
    /// observe through the target's exit plus the post-exit window, and return the
    /// sink — all bounded. This is the honest replay: a real target process runs,
    /// under the ready observer, with its real PID handed to the observer; the
    /// result carries that PID so the caller can confirm the evidence is about it.
    ///
    /// Any failure to genuinely replay-and-observe — no readiness ack, no target to
    /// launch, the capture timing out, a failed capture, or a sink with no session
    /// — routes to [`ObserveOutcome::NotObserved`], never a false replay claim.
    fn observe(&self, params: &CollectorRunParams<'_>) -> anyhow::Result<ObserveOutcome> {
        let sidecar = match &self.source {
            CollectorSource::Sidecar(path) => path,
            CollectorSource::Runtrace(_) => {
                return Err(anyhow!(
                    "the runtrace-backed collector is driven by the host (it observes the \
                     target under the LD_PRELOAD shim), not spawned as a sidecar"
                ));
            }
        };

        // No retained target to launch under the observer on this host: do not
        // spawn an observer that watches nothing, and never claim a replay that did
        // not run. The caller records a degraded, not-observed run.
        let Some(launch) = params.launch.as_ref() else {
            return Ok(ObserveOutcome::NotObserved("no_replay_target".to_owned()));
        };

        std::fs::create_dir_all(&params.tmp_dir)
            .with_context(|| format!("create {}", params.tmp_dir.display()))?;
        let sink = params.tmp_dir.join("collector.jsonl");
        let input_path = params.tmp_dir.join("collector_input.bin");
        let ready_path = params.tmp_dir.join("collector.ready");
        let pid_path = params.tmp_dir.join("collector.target_pid");
        let done_path = params.tmp_dir.join("collector.done");
        std::fs::write(&input_path, params.input)
            .with_context(|| format!("write {}", input_path.display()))?;
        // Clear prior sink / handshake markers so a stale one is never mistaken for
        // this run's.
        for stale in [&sink, &ready_path, &pid_path, &done_path] {
            let _ = std::fs::remove_file(stale);
        }

        let mut child = Command::new(sidecar)
            .env("BHF_COLLECTOR_TESTCASE", &params.testcase)
            .env("BHF_COLLECTOR_WORKER", params.worker.to_string())
            .env("BHF_COLLECTOR_ROOT", &params.root)
            .env("BHF_COLLECTOR_ROOT_IMAGE", &params.root_image)
            .env("BHF_COLLECTOR_WINDOW_MS", self.window_ms.to_string())
            .env("BHF_COLLECTOR_INPUT", &input_path)
            .env("BHF_COLLECTOR_LOG", &sink)
            .env("BHF_COLLECTOR_READY", &ready_path)
            .env("BHF_COLLECTOR_TARGET_PID", &pid_path)
            .env("BHF_COLLECTOR_DONE", &done_path)
            .spawn()
            .with_context(|| format!("spawn collector sidecar {}", sidecar.display()))?;

        // 1. Wait for the readiness ack, the child exiting first, or the timeout.
        let ready_deadline = Instant::now() + READINESS_TIMEOUT;
        let mut readied = false;
        let mut exited_before_ready = false;
        while Instant::now() < ready_deadline {
            if ready_path.exists() {
                readied = true;
                break;
            }
            match child.try_wait() {
                Ok(Some(_status)) => {
                    exited_before_ready = true;
                    break;
                }
                Ok(None) => {}
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(anyhow!("collector sidecar {}: {error}", sidecar.display()));
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if !readied {
            if !exited_before_ready {
                let _ = child.kill();
            }
            let _ = child.wait();
            let reason = if exited_before_ready {
                "collector_exited_before_ready"
            } else {
                "collector_no_readiness_ack"
            };
            return Ok(ObserveOutcome::NotObserved(reason.to_owned()));
        }

        // 2. Launch the retained target UNDER the ready observer, record its PID.
        //    The launcher returns IMMEDIATELY (stdin is delivered on a background
        //    thread), so the whole launch/delivery/wait lifecycle below runs under
        //    the bounded deadline rather than blocking on an unbounded stdin write
        //    that a target which never drains stdin could stall forever (#76).
        let launched = match (launch)() {
            Ok(launched) => launched,
            Err(error) => {
                // Killing the sidecar PROCESS never stops an ETW session it owns
                // (that is the sidecar's own teardown) — we only ever kill it, we
                // never issue a control STOP on a session we do not own (#77).
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.context("launch the replay target under the collector"));
            }
        };
        let mut target = launched.child;
        let delivery = launched.delivery;
        let replayed_pid = target.id();

        // 3. Hand the real PID to the observer so it attributes to our launched
        //    process (a system-wide tracer may instead observe the PID directly).
        let _ = std::fs::write(&pid_path, replayed_pid.to_string());

        // 4. Bounded-wait the target. A target that does NOT exit within the bound —
        //    e.g. one that never drains the delivered input and hangs — is killed
        //    and reaped here; the sidecar is reaped too, and the run degrades to
        //    not-observed rather than being attributed an incompletely-delivered
        //    replay. Then reap the stdin-delivery thread (the target's exit/kill
        //    closed the pipe, so a pending write unblocks).
        let target_status = wait_child_until(&mut target, Instant::now() + REPLAY_TARGET_TIMEOUT);
        if let Some(handle) = delivery {
            let _ = handle.join();
        }
        if target_status.is_none() {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(ObserveOutcome::NotObserved(
                "collector_replay_target_timeout".to_owned(),
            ));
        }

        // Hold for the post-exit observation window.
        let window_end = Instant::now() + Duration::from_millis(self.window_ms);
        while Instant::now() < window_end {
            std::thread::sleep(Duration::from_millis(10));
        }

        // 5. Tell the observer the replay completed so it can stop and emit.
        let _ = std::fs::write(&done_path, b"done");

        // 6. Bounded-wait the observer to finish writing its sink (#76 P2): a
        //    provider that readies then wedges is killed here, never hangs the run.
        let Some(status) = wait_child_until(&mut child, Instant::now() + CAPTURE_DRAIN) else {
            return Ok(ObserveOutcome::NotObserved(
                "collector_capture_timeout".to_owned(),
            ));
        };
        if !status.success() {
            return Ok(ObserveOutcome::NotObserved(format!(
                "collector_capture_failed_exit_{}",
                status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".to_owned())
            )));
        }

        // 7. Read the sink the observer wrote.
        match std::fs::read_to_string(&sink) {
            Ok(jsonl) => Ok(ObserveOutcome::Observed {
                jsonl,
                replayed_pid,
            }),
            Err(_) => Ok(ObserveOutcome::NotObserved(
                "collector_sink_missing".to_owned(),
            )),
        }
    }

    /// Replay a retained testcase under the collector, attribute the events, and
    /// evaluate the oracle registry over them, returning deduplicated findings plus
    /// run provenance.
    ///
    /// A run that was not genuinely replayed-and-observed (no readiness ack, no
    /// target to launch, a timed-out/failed capture, a sink with no session for the
    /// replayed testcase/worker, or evidence NOT rooted at the launched PID) yields
    /// the degraded [`Self::not_observed`] contract — never a clean assurance, and
    /// never a replay claim for a target that did not actually run (#76).
    pub fn run_once(&self, params: &CollectorRunParams<'_>) -> anyhow::Result<CollectorOutcome> {
        match self.observe(params)? {
            ObserveOutcome::NotObserved(reason) => Ok(self.not_observed(reason)),
            ObserveOutcome::Observed {
                jsonl,
                replayed_pid,
            } => {
                let set = CollectorSessionSet::from_jsonl(&jsonl);
                let Some(session) = set.session(&params.testcase, params.worker) else {
                    // The observer produced no session for the replayed
                    // testcase/worker: nothing honest to evaluate.
                    return Ok(self.not_observed("testcase_not_observed"));
                };
                // Honesty invariant: the evidence must be about the process we
                // actually launched. If the observer's session is not rooted at the
                // replayed PID, it did not observe our target — degrade rather than
                // claim a replay of it.
                if session.root_pid() != Some(replayed_pid) {
                    return Ok(self.not_observed("replayed_process_not_observed"));
                }
                let mut outcome = self.evaluate(&set, &params.root);
                if let Some(obj) = outcome.run_provenance.as_object_mut() {
                    obj.insert("replayed_pid".to_owned(), json!(replayed_pid));
                }
                Ok(outcome)
            }
        }
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

/// Build the `collector` provenance block embedded in a finding. `observation`
/// records the (limited) scope the collector actually watched, so a reviewer never
/// reads a single-testcase replay as whole-campaign coverage (#76).
fn collector_block(finding: &CollectorFinding, observation: ObservationMode) -> Value {
    json!({
        "provenance": finding.provenance,
        "root": finding.root,
        "evidence": EVIDENCE_FILE,
        "attributing_event": finding.attributing_event,
        "process_tree": finding.process_tree,
        "clean_assurance": finding.provenance.clean_assurance_ok(),
        "observation": observation.label(),
        "coverage": observation.coverage(),
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
    observation: ObservationMode,
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
        "collector": collector_block(finding, observation),
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
        assert!(
            outcome.findings.is_empty(),
            "no findings without observation"
        );
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
        write_finding(
            &dir,
            "BF-0001",
            json!({"kind": "test"}),
            finding,
            b"seed",
            ObservationMode::Replay,
        )
        .unwrap();

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

    fn unique_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bhf-select-replay-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Write a crash finding dir with a `testcase.bin` and a `finding.json` whose
    /// recorded target binary path is `harness`, so selection can scope it.
    fn write_crash_finding(work: &Path, id: &str, harness: &str, input: &[u8]) {
        let dir = corpus::layout::findings_dir(work).join(id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("testcase.bin"), input).unwrap();
        std::fs::write(
            dir.join("finding.json"),
            serde_json::to_vec(&json!({ "target": { "binary": { "path": harness } } })).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn select_replay_prefers_crash_finding_then_corpus_then_none() {
        let work = unique_dir("sel");
        let hid = "harness-x";

        // Nothing retained yet: the caller must degrade, not replay a synthetic id.
        assert_eq!(select_replay_testcase(&work, hid), None);

        // A persisted coverage-corpus input is a valid (fallback) replay source.
        let queue = work.join("corpus").join(hid).join("queue");
        std::fs::create_dir_all(&queue).unwrap();
        std::fs::write(queue.join("aaaa.bin"), b"corpus-bytes").unwrap();
        let picked = select_replay_testcase(&work, hid).expect("corpus input selected");
        assert_eq!(picked.input, b"corpus-bytes");
        assert_eq!(picked.testcase, "corpus-aaaa");
        assert_eq!(picked.worker, 0);
        assert_eq!(picked.input_sha256, sha256_hex(b"corpus-bytes"));

        // This harness's crash finding outranks the corpus (most interesting).
        write_crash_finding(&work, "BF-0001", hid, b"CRASH-INPUT");
        // A collector finding (COL-) is NOT a campaign testcase and is skipped.
        let col = corpus::layout::findings_dir(&work).join("COL-0001");
        std::fs::create_dir_all(&col).unwrap();
        std::fs::write(col.join("testcase.bin"), b"not-a-source").unwrap();

        let picked = select_replay_testcase(&work, hid).expect("crash testcase selected");
        assert_eq!(
            picked.input, b"CRASH-INPUT",
            "crash testcase outranks corpus"
        );
        assert_eq!(picked.testcase, "BF-0001");
        assert_eq!(picked.input_sha256, sha256_hex(b"CRASH-INPUT"));

        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn select_replay_never_adopts_a_sibling_targets_input() {
        // #76 P2: a multi-target work dir shares one findings tree. Each target must
        // select ONLY its own retained evidence, never a sibling's input/ID.
        let work = unique_dir("multi");
        let harness_a = "/targets/alpha";
        let harness_b = "/targets/bravo";

        // Alpha crashes first (lexicographically-lowest id) with ITS input; bravo's
        // crash is a different finding with a different input.
        write_crash_finding(&work, "BF-0001", harness_a, b"ALPHA-INPUT");
        write_crash_finding(&work, "BF-0002", harness_b, b"BRAVO-INPUT");

        // Each harness selects only its own crash testcase, despite the shared tree
        // and alpha's finding sorting first.
        let a = select_replay_testcase(&work, harness_a).expect("alpha selects its own");
        assert_eq!(a.testcase, "BF-0001");
        assert_eq!(a.input, b"ALPHA-INPUT");

        let b = select_replay_testcase(&work, harness_b).expect("bravo selects its own");
        assert_eq!(
            b.testcase, "BF-0002",
            "bravo must not adopt alpha's lower-id finding"
        );
        assert_eq!(b.input, b"BRAVO-INPUT");

        // A third harness with no retained evidence anywhere gets nothing (not a
        // sibling's input).
        assert_eq!(select_replay_testcase(&work, "/targets/charlie"), None);

        let _ = std::fs::remove_dir_all(&work);
    }
}
