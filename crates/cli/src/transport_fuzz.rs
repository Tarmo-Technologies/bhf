// SPDX-License-Identifier: Apache-2.0

//! HDF-1b: wire the `target_transport` seam into a runnable fuzz loop.
//!
//! HDF-1 landed the `TargetTransport`/`TargetSession` seam and its backends
//! (agent, gdb-remote, full-system) plus HDF-2's [`crate::transport_fault`]
//! finding seam, but nothing on the engine/CLI side consumed them — the crate
//! was tested-but-dead (roadmap CC-2, "no consumer"). This module is that
//! consumer: it adds a `--target-transport` option to `bhf fuzz` and drives a
//! coverage-guided fuzz loop through the transport, reusing the builtin engine's
//! machinery (the [`MutatorSuite`], the [`PowerScheduler`], and [`CoverageProxy`]
//! coverage folding) and turning a [`RunOutcome`] fault/crash into a written
//! finding via [`crate::transport_fault::outcome_finding`].
//!
//! # Additive by construction
//!
//! The loop is a SEPARATE code path, reached only when `--target-transport` is
//! set (see [`should_use_transport`] and the dispatch in [`crate::fuzz::run`]).
//! When the flag is absent, `bhf fuzz` runs the existing host libFuzzer/AFL path
//! byte-for-byte as before; nothing here touches the hot host loop.
//!
//! # In-tree vs gated
//!
//! The spec parser, the transport builder, and the fuzz loop are pure software
//! and are proven end-to-end against the in-crate [`target_transport::testsupport`]
//! mocks (an [`AgentTransport`] over `duplex()` + a scripted `MockAgent`). The
//! *live* backends the parser can build — an on-target agent over TCP/serial, a
//! gdbstub over TCP, a `qemu-system` QMP+gdbstub — dial real resources in their
//! connect closures and are DEPENDENCY-gated (hardware / emulator), exactly as
//! HDF-1 records. Building the transport is pure; only [`TargetTransport::arm`]
//! reaches out, so the parser/builder are fully testable with no hardware.
//!
//! # Spec grammar
//!
//! `--target-transport <spec>`:
//! * `agent:tcp:HOST:PORT`   — [`AgentTransport`] over a TCP socket.
//! * `agent:serial:PATH`     — [`AgentTransport`] over a serial device / file.
//! * `gdb:HOST:PORT`         — [`GdbRemoteTransport`]; needs `--transport-coverage-map`.
//! * `qemu-system:qmp=HOST:PORT,gdb=HOST:PORT[,snapshot=TAG]` — [`FullSystemTransport`];
//!   needs `--transport-coverage-map`.
//!
//! `--transport-coverage-map input=<addr>,ring=<addr>,write=<addr>,wrapped=<addr>,cap=<n>`
//! (each `<addr>` is decimal or `0x`-hex) locates the coverage ring in target
//! memory for the memory-read backends (gdb / qemu-system). The agent backend
//! carries coverage over its protocol and rejects a coverage map.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use corpus::{CorpusError, FindingEmitter};
use event_log::Testcase;
use fuzz_engine_builtin::{
    CoverageFeedback, CoverageInput, CoverageProxy, Dictionary, MutationInput, MutationRng,
    MutatorConfig, MutatorSuite, PowerScheduler,
};
use serde::Serialize;
use target_transport::{
    AgentTransport, ExitKind, FullSystemTransport, GdbMemoryMap, GdbRemoteTransport, RunOutcome,
    TargetTransport, TransportError,
};

use crate::fuzz::FuzzArgs;

/// The default coverage-corpus seed used when the caller supplies none, so the
/// mutator always has non-empty material to derive from.
const DEFAULT_SEED: &[u8] = b"BHF-transport-seed";

/// The default `qemu-system` baseline snapshot tag when the spec omits one.
const DEFAULT_SNAPSHOT_TAG: &str = "bhf-baseline";

/// True when `bhf fuzz` should take the transport-driven path instead of the
/// host libFuzzer/AFL path: exactly when `--target-transport` is set. When it is
/// `None`, the default flow is byte-for-byte unchanged.
pub(crate) fn should_use_transport(args: &FuzzArgs) -> bool {
    args.target_transport.is_some()
}

// ---------------------------------------------------------------------------
// Spec parsing (pure, fully testable)
// ---------------------------------------------------------------------------

/// A parsed, validated `--target-transport` spec. Kept separate from the built
/// [`TargetTransport`] so the parse is inspectable and testable without dialing
/// any live resource (construction of the live transport happens in
/// [`TransportPlan::into_transport`], and the connection only in `arm`).
#[derive(Debug, Clone)]
pub(crate) enum TransportPlan {
    /// On-target agent over a TCP socket.
    AgentTcp { host: String, port: u16 },
    /// On-target agent over a serial device / file.
    AgentSerial { path: PathBuf },
    /// Debug-probe / emulator gdbstub over TCP, reading the coverage ring by
    /// memory access described by `map`.
    Gdb {
        host: String,
        port: u16,
        map: GdbMemoryMap,
    },
    /// Full-system `qemu-system` guest driven by QMP (snapshot lifecycle) + a
    /// gdbstub (input + coverage-ring readback).
    QemuSystem {
        qmp_host: String,
        qmp_port: u16,
        gdb_host: String,
        gdb_port: u16,
        map: GdbMemoryMap,
        snapshot_tag: String,
    },
}

/// A descriptive failure parsing a `--target-transport` / `--transport-coverage-map`
/// spec, or building the transport. Never a silent `None`.
#[derive(Debug, thiserror::Error)]
pub(crate) enum TransportSpecError {
    #[error(
        "empty --target-transport spec; expected one of \
         agent:tcp:HOST:PORT, agent:serial:PATH, gdb:HOST:PORT, \
         qemu-system:qmp=HOST:PORT,gdb=HOST:PORT"
    )]
    Empty,

    #[error(
        "unknown --target-transport backend {backend:?}; supported: \
         agent:tcp, agent:serial, gdb, qemu-system"
    )]
    UnknownBackend { backend: String },

    #[error("malformed {backend} spec {spec:?}: {reason}")]
    Malformed {
        backend: &'static str,
        spec: String,
        reason: String,
    },

    #[error(
        "the {backend} backend requires --transport-coverage-map \
         (input=<addr>,ring=<addr>,write=<addr>,wrapped=<addr>,cap=<n>)"
    )]
    MissingCoverageMap { backend: &'static str },

    #[error(
        "--transport-coverage-map is not used by the agent backend \
         (coverage arrives over the agent protocol); remove it"
    )]
    UnexpectedCoverageMap,

    #[error(
        "malformed --transport-coverage-map field {field}={value:?}: \
         expected a decimal or 0x-hex integer"
    )]
    Field { field: String, value: String },

    #[error("--transport-coverage-map is missing required key {key:?} (need input,ring,write,wrapped,cap)")]
    MissingMapKey { key: &'static str },

    #[error(
        "--transport-coverage-map has unknown key {key:?} (allowed: input,ring,write,wrapped,cap)"
    )]
    UnknownMapKey { key: String },

    #[error("coverage ring capacity {cap} is not representable as a host-sized length")]
    CapTooLarge { cap: u64 },

    /// A transport constructor rejected the spec (e.g. an unsafe snapshot tag).
    #[error(transparent)]
    Transport(#[from] TransportError),
}

impl TransportPlan {
    /// Parse a `--target-transport` spec plus the optional
    /// `--transport-coverage-map` into an inspectable plan.
    pub(crate) fn parse(
        spec: &str,
        coverage_map: Option<&str>,
    ) -> Result<Self, TransportSpecError> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err(TransportSpecError::Empty);
        }

        if let Some(rest) = spec.strip_prefix("agent:tcp:") {
            reject_coverage_map(coverage_map)?;
            let (host, port) = parse_host_port("agent:tcp", spec, rest)?;
            return Ok(Self::AgentTcp { host, port });
        }

        if let Some(rest) = spec.strip_prefix("agent:serial:") {
            reject_coverage_map(coverage_map)?;
            if rest.trim().is_empty() {
                return Err(TransportSpecError::Malformed {
                    backend: "agent:serial",
                    spec: spec.to_owned(),
                    reason: "device path is empty".to_owned(),
                });
            }
            return Ok(Self::AgentSerial {
                path: PathBuf::from(rest),
            });
        }

        if let Some(rest) = spec.strip_prefix("agent:") {
            let sub = rest.split(':').next().unwrap_or(rest);
            return Err(TransportSpecError::Malformed {
                backend: "agent",
                spec: spec.to_owned(),
                reason: format!(
                    "unknown agent channel {sub:?}; expected agent:tcp:HOST:PORT \
                     or agent:serial:PATH"
                ),
            });
        }

        if let Some(rest) = spec.strip_prefix("gdb:") {
            let map = require_coverage_map("gdb", coverage_map)?;
            let (host, port) = parse_host_port("gdb", spec, rest)?;
            return Ok(Self::Gdb { host, port, map });
        }

        if let Some(rest) = spec.strip_prefix("qemu-system:") {
            let map = require_coverage_map("qemu-system", coverage_map)?;
            return parse_qemu_system(spec, rest, map);
        }

        Err(TransportSpecError::UnknownBackend {
            backend: spec.split(':').next().unwrap_or(spec).to_owned(),
        })
    }

    /// Build the live [`TargetTransport`] this plan describes. Pure: the
    /// connect closures dial their resource only when [`TargetTransport::arm`]
    /// is called, so this never touches hardware/emulator/socket by itself.
    pub(crate) fn into_transport(self) -> Result<Box<dyn TargetTransport>, TransportSpecError> {
        match self {
            Self::AgentTcp { host, port } => Ok(Box::new(AgentTransport::new(move || {
                std::net::TcpStream::connect((host.as_str(), port)).map_err(TransportError::from)
            }))),
            Self::AgentSerial { path } => Ok(Box::new(AgentTransport::new(move || {
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&path)
                    .map_err(TransportError::from)
            }))),
            Self::Gdb { host, port, map } => Ok(Box::new(GdbRemoteTransport::new(
                move || {
                    std::net::TcpStream::connect((host.as_str(), port))
                        .map_err(TransportError::from)
                },
                map,
            ))),
            Self::QemuSystem {
                qmp_host,
                qmp_port,
                gdb_host,
                gdb_port,
                map,
                snapshot_tag,
            } => {
                let transport = FullSystemTransport::new(
                    move || {
                        std::net::TcpStream::connect((qmp_host.as_str(), qmp_port))
                            .map_err(TransportError::from)
                    },
                    move || {
                        std::net::TcpStream::connect((gdb_host.as_str(), gdb_port))
                            .map_err(TransportError::from)
                    },
                    map,
                    snapshot_tag,
                )?;
                Ok(Box::new(transport))
            }
        }
    }

    /// A short human label for the run summary / finding metadata.
    fn label(&self) -> String {
        match self {
            Self::AgentTcp { host, port } => format!("agent:tcp:{host}:{port}"),
            Self::AgentSerial { path } => format!("agent:serial:{}", path.display()),
            Self::Gdb { host, port, .. } => format!("gdb:{host}:{port}"),
            Self::QemuSystem {
                qmp_host,
                qmp_port,
                gdb_host,
                gdb_port,
                ..
            } => format!("qemu-system:qmp={qmp_host}:{qmp_port},gdb={gdb_host}:{gdb_port}"),
        }
    }
}

fn reject_coverage_map(coverage_map: Option<&str>) -> Result<(), TransportSpecError> {
    if coverage_map.is_some_and(|m| !m.trim().is_empty()) {
        return Err(TransportSpecError::UnexpectedCoverageMap);
    }
    Ok(())
}

fn require_coverage_map(
    backend: &'static str,
    coverage_map: Option<&str>,
) -> Result<GdbMemoryMap, TransportSpecError> {
    let map = coverage_map
        .filter(|m| !m.trim().is_empty())
        .ok_or(TransportSpecError::MissingCoverageMap { backend })?;
    parse_coverage_map(map)
}

fn parse_qemu_system(
    spec: &str,
    rest: &str,
    map: GdbMemoryMap,
) -> Result<TransportPlan, TransportSpecError> {
    let mut qmp: Option<(String, u16)> = None;
    let mut gdb: Option<(String, u16)> = None;
    let mut snapshot_tag = DEFAULT_SNAPSHOT_TAG.to_owned();

    for part in rest.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| TransportSpecError::Malformed {
                backend: "qemu-system",
                spec: spec.to_owned(),
                reason: format!("expected key=value in {part:?}"),
            })?;
        match key.trim() {
            "qmp" => qmp = Some(parse_host_port("qemu-system", spec, value.trim())?),
            "gdb" => gdb = Some(parse_host_port("qemu-system", spec, value.trim())?),
            "snapshot" => snapshot_tag = value.trim().to_owned(),
            other => {
                return Err(TransportSpecError::Malformed {
                    backend: "qemu-system",
                    spec: spec.to_owned(),
                    reason: format!("unknown key {other:?}; allowed: qmp, gdb, snapshot"),
                })
            }
        }
    }

    let (qmp_host, qmp_port) = qmp.ok_or_else(|| TransportSpecError::Malformed {
        backend: "qemu-system",
        spec: spec.to_owned(),
        reason: "missing required key qmp=HOST:PORT".to_owned(),
    })?;
    let (gdb_host, gdb_port) = gdb.ok_or_else(|| TransportSpecError::Malformed {
        backend: "qemu-system",
        spec: spec.to_owned(),
        reason: "missing required key gdb=HOST:PORT".to_owned(),
    })?;

    Ok(TransportPlan::QemuSystem {
        qmp_host,
        qmp_port,
        gdb_host,
        gdb_port,
        map,
        snapshot_tag,
    })
}

fn parse_host_port(
    backend: &'static str,
    spec: &str,
    hostport: &str,
) -> Result<(String, u16), TransportSpecError> {
    let malformed = |reason: String| TransportSpecError::Malformed {
        backend,
        spec: spec.to_owned(),
        reason,
    };
    let (host, port) = hostport
        .rsplit_once(':')
        .ok_or_else(|| malformed(format!("expected HOST:PORT, got {hostport:?}")))?;
    if host.is_empty() {
        return Err(malformed(format!("host is empty in {hostport:?}")));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| malformed(format!("port {port:?} is not a valid 1..=65535 value")))?;
    if port == 0 {
        return Err(malformed("port 0 is not a valid port".to_owned()));
    }
    Ok((host.to_owned(), port))
}

fn parse_coverage_map(spec: &str) -> Result<GdbMemoryMap, TransportSpecError> {
    let mut input = None;
    let mut ring = None;
    let mut write = None;
    let mut wrapped = None;
    let mut cap = None;

    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| TransportSpecError::Field {
                field: part.to_owned(),
                value: String::new(),
            })?;
        let key = key.trim();
        match key {
            "input" => input = Some(parse_int(key, value)?),
            "ring" => ring = Some(parse_int(key, value)?),
            "write" => write = Some(parse_int(key, value)?),
            "wrapped" => wrapped = Some(parse_int(key, value)?),
            "cap" => cap = Some(parse_int(key, value)?),
            other => {
                return Err(TransportSpecError::UnknownMapKey {
                    key: other.to_owned(),
                })
            }
        }
    }

    let cap = cap.ok_or(TransportSpecError::MissingMapKey { key: "cap" })?;
    let ring_capacity =
        usize::try_from(cap).map_err(|_| TransportSpecError::CapTooLarge { cap })?;

    Ok(GdbMemoryMap {
        input_address: input.ok_or(TransportSpecError::MissingMapKey { key: "input" })?,
        ring_address: ring.ok_or(TransportSpecError::MissingMapKey { key: "ring" })?,
        ring_write_address: write.ok_or(TransportSpecError::MissingMapKey { key: "write" })?,
        ring_wrapped_address: wrapped
            .ok_or(TransportSpecError::MissingMapKey { key: "wrapped" })?,
        ring_capacity,
    })
}

/// Parse a decimal or `0x`-hex unsigned integer.
fn parse_int(field: &str, value: &str) -> Result<u64, TransportSpecError> {
    let trimmed = value.trim();
    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        trimmed.parse::<u64>()
    };
    parsed.map_err(|_| TransportSpecError::Field {
        field: field.to_owned(),
        value: value.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// The transport-driven fuzz loop
// ---------------------------------------------------------------------------

/// Inputs to [`run_transport_campaign`], decoupled from clap so the loop is
/// testable against a mock transport in a temp dir.
#[derive(Debug, Clone)]
pub(crate) struct TransportFuzzConfig {
    pub work_dir: PathBuf,
    pub harness_id: String,
    /// Human label of the transport (for the summary + finding metadata).
    pub transport_label: String,
    /// Initial corpus seeds.
    pub seeds: Vec<Vec<u8>>,
    /// Total execution cap (bounded work — never unbounded).
    pub iterations: usize,
    /// Optional wall-clock budget.
    pub time_budget: Option<Duration>,
    /// Ceiling on a generated input's length.
    pub max_len: usize,
    /// Deterministic mutation RNG seed.
    pub rng_seed: u64,
    /// Stop as soon as this many DISTINCT findings are emitted.
    pub stop_after_findings: Option<usize>,
    /// Actionability profile for the emitted findings.
    pub mode: actionability::RunMode,
}

/// The JSON summary a transport-driven run reports (mirrors the shape of the
/// host lane's summary, restricted to what the transport path measures).
#[derive(Debug, Clone, Serialize)]
pub(crate) struct TransportFuzzSummary {
    pub schema_version: u32,
    pub harness_id: String,
    pub engine: String,
    pub transport: String,
    pub seeds: usize,
    pub executions: usize,
    /// Mutated inputs retained for reaching new coverage.
    pub corpus_new: usize,
    /// Distinct edge-transition bits observed (from the builtin coverage fold).
    pub coverage_edges: usize,
    /// Distinct block/hit-count bits observed.
    pub coverage_blocks: usize,
    /// Total crash/timeout outcomes seen (before dedup).
    pub crashes: usize,
    /// Distinct finding ids written to `<work_dir>/findings/`.
    pub findings: Vec<String>,
    pub elapsed_secs: f64,
}

/// A failure running a transport-driven campaign.
#[derive(Debug, thiserror::Error)]
pub(crate) enum TransportFuzzError {
    #[error("target transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("writing finding: {0}")]
    Finding(#[from] CorpusError),
}

/// Fold one run's coverage edges into the builtin [`CoverageProxy`], reusing the
/// engine's exact edge/hit-count-bucket model. The transport's `coverage_edges`
/// map directly onto the breadcrumb (`crumbs`) channel a host testcase carries.
fn fold_coverage(coverage: &mut CoverageProxy, edges: &[u32]) -> CoverageFeedback {
    let testcase = Testcase {
        testcase_id: 0,
        target_id: 0,
        target_entered: false,
        crumbs: edges.to_vec(),
        handlers: Vec::new(),
        raises: Vec::new(),
        top_level: None,
        end: None,
        mocks: Vec::new(),
    };
    coverage.record(CoverageInput::new(&testcase, &[]))
}

/// Whether the loop should stop now: hit the iteration cap, the time budget, or
/// the distinct-finding target. Checked before every `run_input` so the loop
/// never runs unbounded and never runs one execution past its budget.
fn should_stop(
    executions: usize,
    iterations: usize,
    start: Instant,
    time_budget: Option<Duration>,
    distinct_findings: usize,
    stop_after_findings: Option<usize>,
) -> bool {
    if executions >= iterations {
        return true;
    }
    if let Some(budget) = time_budget {
        if start.elapsed() >= budget {
            return true;
        }
    }
    if let Some(target) = stop_after_findings {
        if distinct_findings >= target {
            return true;
        }
    }
    false
}

/// Drive a coverage-guided fuzz loop through `transport`, reusing the builtin
/// engine's mutator + power scheduler + coverage folding, and writing each
/// transport-reported fault as a finding via [`crate::transport_fault::outcome_finding`].
///
/// Bounded by `config.iterations` / `config.time_budget` / `config.stop_after_findings`.
/// Returns the run summary; propagates a transport or finding-write failure as a
/// descriptive error (never a silent `None`).
pub(crate) fn run_transport_campaign(
    transport: &dyn TargetTransport,
    config: &TransportFuzzConfig,
) -> Result<TransportFuzzSummary, TransportFuzzError> {
    let start = Instant::now();
    let mut session = transport.arm()?;

    let mut coverage = CoverageProxy::default();
    let mut scheduler = PowerScheduler::default();
    let mutator = MutatorSuite::new(MutatorConfig {
        max_len: config.max_len.max(1),
        ..MutatorConfig::default()
    });
    let mut rng = MutationRng::new(config.rng_seed);
    let dictionary = Dictionary::from_tokens(std::iter::empty::<Vec<u8>>());

    let emitter = FindingEmitter::with_metadata(
        config.work_dir.clone(),
        config.harness_id.clone(),
        "transport".to_owned(),
        config.transport_label.clone(),
    )
    .with_mode(config.mode);

    let mut executions = 0usize;
    let mut corpus_new = 0usize;
    let mut crashes = 0usize;
    let mut finding_ids: Vec<String> = Vec::new();
    // Dedup findings on the same key the on-disk finding signature is built from
    // (rule_id | kind; the transport lane carries no stack frames), so one fault
    // class yields one finding regardless of how many inputs reach it.
    let mut seen_findings: std::collections::HashSet<String> = std::collections::HashSet::new();

    // --- seed phase: run every seed once; seeds are always corpus members. ---
    let seed_count = config.seeds.len();
    for seed in &config.seeds {
        if should_stop(
            executions,
            config.iterations,
            start,
            config.time_budget,
            finding_ids.len(),
            config.stop_after_findings,
        ) {
            break;
        }
        let outcome = session.run_input(seed)?;
        executions += 1;
        let feedback = fold_coverage(&mut coverage, &outcome.coverage_edges);
        scheduler.insert_with_feedback(seed.clone(), feedback.to_schedule_feedback());
        handle_outcome(
            &outcome,
            seed,
            &emitter,
            &mut seen_findings,
            &mut finding_ids,
            &mut crashes,
        )?;
    }

    // --- mutation phase: scheduler-driven, coverage-guided. ---
    'outer: loop {
        if should_stop(
            executions,
            config.iterations,
            start,
            config.time_budget,
            finding_ids.len(),
            config.stop_after_findings,
        ) {
            break;
        }
        let Some(scheduled) = scheduler.select_next() else {
            // No corpus (no seeds and none retained) — nothing to mutate.
            break;
        };
        // The scheduler's power schedule sets how many children this seed earns.
        let children = scheduled.energy.max(1);
        for _ in 0..children {
            if should_stop(
                executions,
                config.iterations,
                start,
                config.time_budget,
                finding_ids.len(),
                config.stop_after_findings,
            ) {
                break 'outer;
            }
            let input = match mutator
                .mutate(&MutationInput::new(&scheduled.bytes, &dictionary), &mut rng)
            {
                Some(result) => result.bytes,
                None => scheduled.bytes.clone(),
            };
            let outcome = session.run_input(&input)?;
            executions += 1;
            let feedback = fold_coverage(&mut coverage, &outcome.coverage_edges);
            // Retain a clean input that reached new coverage as a new corpus
            // seed, feeding its novelty back into the power schedule. A crashing
            // input becomes a finding (below), not a corpus seed.
            if outcome.exit == ExitKind::Ok
                && (feedback.new_bitmap_bits() > 0 || feedback.new_exception_signatures > 0)
            {
                scheduler.insert_with_feedback(input.clone(), feedback.to_schedule_feedback());
                corpus_new += 1;
            }
            handle_outcome(
                &outcome,
                &input,
                &emitter,
                &mut seen_findings,
                &mut finding_ids,
                &mut crashes,
            )?;
        }
    }

    let snapshot = coverage.snapshot();
    Ok(TransportFuzzSummary {
        schema_version: 1,
        harness_id: config.harness_id.clone(),
        engine: "transport".to_owned(),
        transport: config.transport_label.clone(),
        seeds: seed_count,
        executions,
        corpus_new,
        coverage_edges: snapshot.edge_bits,
        coverage_blocks: snapshot.breadcrumb_bits,
        crashes,
        findings: finding_ids,
        elapsed_secs: start.elapsed().as_secs_f64(),
    })
}

/// Turn one run outcome into a finding when it crashed/timed out, deduped by
/// fault class, and count crash outcomes. A clean outcome is a no-op.
fn handle_outcome(
    outcome: &RunOutcome,
    input: &[u8],
    emitter: &FindingEmitter,
    seen: &mut std::collections::HashSet<String>,
    finding_ids: &mut Vec<String>,
    crashes: &mut usize,
) -> Result<(), CorpusError> {
    let Some(report) = crate::transport_fault::outcome_finding(outcome) else {
        return Ok(());
    };
    *crashes += 1;
    let dedup_key = format!("{}|{}", report.rule_id, report.kind);
    if !seen.insert(dedup_key) {
        return Ok(());
    }
    let id = emitter.emit_sanitizer_crash(input, &report)?;
    finding_ids.push(id.0);
    Ok(())
}

// ---------------------------------------------------------------------------
// CLI entry
// ---------------------------------------------------------------------------

/// `bhf fuzz --target-transport <spec>` entry point. Parses the spec, builds the
/// transport, loads seeds, runs the campaign, and prints the JSON summary.
pub(crate) fn run(args: FuzzArgs) -> i32 {
    match run_inner(args) {
        Ok(summary) => match serde_json::to_string_pretty(&summary) {
            Ok(json) => {
                println!("{json}");
                0
            }
            Err(error) => {
                crate::bhfeprintln!("failed to render transport-fuzz summary: {error}");
                1
            }
        },
        Err(code) => code,
    }
}

fn run_inner(args: FuzzArgs) -> Result<TransportFuzzSummary, i32> {
    let spec = args
        .target_transport
        .as_deref()
        .expect("run() is only reached when --target-transport is set");

    let plan =
        TransportPlan::parse(spec, args.transport_coverage_map.as_deref()).map_err(|error| {
            crate::bhfeprintln!("bhf fuzz --target-transport: {error}");
            2
        })?;
    let transport_label = plan.label();
    let transport = plan.into_transport().map_err(|error| {
        crate::bhfeprintln!("bhf fuzz --target-transport: {error}");
        2
    })?;

    let seeds = load_seeds(&args).map_err(|error| {
        crate::bhfeprintln!("bhf fuzz --target-transport: {error}");
        3
    })?;

    let config = TransportFuzzConfig {
        work_dir: args.work_dir.clone(),
        harness_id: args.harness.clone(),
        transport_label,
        seeds,
        iterations: args.effective_iterations(),
        time_budget: args.time,
        max_len: args.max_len,
        rng_seed: args.rng_seed,
        stop_after_findings: args.stop_after_findings,
        mode: args.mode,
    };

    run_transport_campaign(transport.as_ref(), &config).map_err(|error| {
        crate::bhfeprintln!("bhf fuzz --target-transport: {error}");
        1
    })
}

/// Load seeds from `--seed-input` / `--seed-file`, bounding each to `--max-len`,
/// and fall back to a single default seed so the mutator always has material.
fn load_seeds(args: &FuzzArgs) -> Result<Vec<Vec<u8>>, String> {
    let cap = args.max_len.max(1);
    let mut seeds: Vec<Vec<u8>> = args
        .seed_inputs
        .iter()
        .map(|s| truncate(s.as_bytes().to_vec(), cap))
        .collect();
    for path in &args.seed_files {
        let (bytes, _len) = crate::fuzz::read_seed_file_prefix(path, cap)
            .map_err(|error| format!("read seed file '{}': {error}", path.display()))?;
        seeds.push(bytes);
    }
    if seeds.is_empty() {
        seeds.push(truncate(DEFAULT_SEED.to_vec(), cap));
    }
    Ok(seeds)
}

fn truncate(mut bytes: Vec<u8>, cap: usize) -> Vec<u8> {
    bytes.truncate(cap);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use target_transport::testsupport::{duplex, MockAgent, ScriptedResponse};
    use target_transport::{AgentTransport, Fault, FaultKind, TransportError};

    // --- regression: the flag is opt-in; the default flow is untouched -------

    // `FuzzArgs` is a `clap::Args` group; wrap it in a `Parser` to parse a
    // `bhf fuzz`-style argument vector in isolation.
    #[derive(clap::Parser)]
    struct FuzzArgsHarness {
        #[command(flatten)]
        fuzz: FuzzArgs,
    }

    #[test]
    fn transport_path_is_off_by_default_and_opt_in() {
        use clap::Parser;

        // Omitting --target-transport leaves the field None, so `bhf fuzz` takes
        // the existing host libFuzzer/AFL path (should_use_transport == false).
        let default = FuzzArgsHarness::parse_from(["fuzz", "workdir", "--harness", "H-1"]).fuzz;
        assert!(default.target_transport.is_none());
        assert!(default.transport_coverage_map.is_none());
        assert!(
            !should_use_transport(&default),
            "the default flow must not route through the transport path"
        );

        // Passing it opts in.
        let with_transport = FuzzArgsHarness::parse_from([
            "fuzz",
            "workdir",
            "--harness",
            "H-1",
            "--target-transport",
            "agent:tcp:127.0.0.1:9999",
        ])
        .fuzz;
        assert_eq!(
            with_transport.target_transport.as_deref(),
            Some("agent:tcp:127.0.0.1:9999")
        );
        assert!(should_use_transport(&with_transport));
    }

    // --- spec-parser tests ---------------------------------------------------

    #[test]
    fn parses_agent_tcp_spec() {
        let plan = TransportPlan::parse("agent:tcp:127.0.0.1:9999", None).unwrap();
        match plan {
            TransportPlan::AgentTcp { host, port } => {
                assert_eq!(host, "127.0.0.1");
                assert_eq!(port, 9999);
            }
            other => panic!("expected AgentTcp, got {other:?}"),
        }
    }

    #[test]
    fn parses_agent_serial_spec() {
        let plan = TransportPlan::parse("agent:serial:/dev/ttyUSB0", None).unwrap();
        match plan {
            TransportPlan::AgentSerial { path } => {
                assert_eq!(path, PathBuf::from("/dev/ttyUSB0"));
            }
            other => panic!("expected AgentSerial, got {other:?}"),
        }
    }

    #[test]
    fn parses_gdb_spec_with_coverage_map() {
        let map_spec = "input=0x1000,ring=0x4000,write=0x5000,wrapped=0x5100,cap=65536";
        let plan = TransportPlan::parse("gdb:127.0.0.1:1234", Some(map_spec)).unwrap();
        match plan {
            TransportPlan::Gdb { host, port, map } => {
                assert_eq!(host, "127.0.0.1");
                assert_eq!(port, 1234);
                assert_eq!(map.input_address, 0x1000);
                assert_eq!(map.ring_address, 0x4000);
                assert_eq!(map.ring_write_address, 0x5000);
                assert_eq!(map.ring_wrapped_address, 0x5100);
                assert_eq!(map.ring_capacity, 65536);
            }
            other => panic!("expected Gdb, got {other:?}"),
        }
    }

    #[test]
    fn parses_qemu_system_spec_with_default_and_explicit_snapshot() {
        let map_spec = "input=4096,ring=16384,write=20480,wrapped=20736,cap=32";
        // Default snapshot tag.
        let plan = TransportPlan::parse(
            "qemu-system:qmp=127.0.0.1:4444,gdb=127.0.0.1:1234",
            Some(map_spec),
        )
        .unwrap();
        match plan {
            TransportPlan::QemuSystem {
                qmp_host,
                qmp_port,
                gdb_host,
                gdb_port,
                map,
                snapshot_tag,
            } => {
                assert_eq!(qmp_host, "127.0.0.1");
                assert_eq!(qmp_port, 4444);
                assert_eq!(gdb_host, "127.0.0.1");
                assert_eq!(gdb_port, 1234);
                assert_eq!(map.input_address, 4096);
                assert_eq!(map.ring_capacity, 32);
                assert_eq!(snapshot_tag, DEFAULT_SNAPSHOT_TAG);
            }
            other => panic!("expected QemuSystem, got {other:?}"),
        }
        // Explicit snapshot tag is honored.
        let plan = TransportPlan::parse(
            "qemu-system:qmp=h:1,gdb=h:2,snapshot=my-baseline",
            Some(map_spec),
        )
        .unwrap();
        match plan {
            TransportPlan::QemuSystem { snapshot_tag, .. } => {
                assert_eq!(snapshot_tag, "my-baseline");
            }
            other => panic!("expected QemuSystem, got {other:?}"),
        }
    }

    #[test]
    fn empty_spec_is_a_descriptive_error() {
        let error = TransportPlan::parse("", None).unwrap_err();
        assert!(matches!(error, TransportSpecError::Empty), "{error}");
        assert!(error.to_string().contains("empty"));
    }

    #[test]
    fn whitespace_only_spec_is_empty_error() {
        assert!(matches!(
            TransportPlan::parse("   ", None).unwrap_err(),
            TransportSpecError::Empty
        ));
    }

    #[test]
    fn unknown_agent_channel_is_descriptive() {
        let error = TransportPlan::parse("agent:bogus", None).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("unknown agent channel") && message.contains("bogus"),
            "message: {message}"
        );
    }

    #[test]
    fn unknown_backend_is_descriptive() {
        let error = TransportPlan::parse("carrierpigeon:host:1", None).unwrap_err();
        match error {
            TransportSpecError::UnknownBackend { backend } => assert_eq!(backend, "carrierpigeon"),
            other => panic!("expected UnknownBackend, got {other}"),
        }
    }

    #[test]
    fn agent_tcp_missing_port_is_descriptive() {
        let error = TransportPlan::parse("agent:tcp:localhost", None).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("HOST:PORT"), "message: {message}");
    }

    #[test]
    fn agent_tcp_zero_port_is_rejected() {
        let error = TransportPlan::parse("agent:tcp:localhost:0", None).unwrap_err();
        assert!(error.to_string().contains("port"), "{error}");
    }

    #[test]
    fn agent_serial_empty_path_is_descriptive() {
        let error = TransportPlan::parse("agent:serial:", None).unwrap_err();
        assert!(
            error.to_string().contains("device path is empty"),
            "{error}"
        );
    }

    #[test]
    fn gdb_without_coverage_map_is_descriptive() {
        let error = TransportPlan::parse("gdb:127.0.0.1:1234", None).unwrap_err();
        match error {
            TransportSpecError::MissingCoverageMap { backend } => assert_eq!(backend, "gdb"),
            other => panic!("expected MissingCoverageMap, got {other}"),
        }
    }

    #[test]
    fn agent_with_coverage_map_is_rejected() {
        let error = TransportPlan::parse(
            "agent:tcp:h:1",
            Some("input=0,ring=0,write=0,wrapped=0,cap=1"),
        )
        .unwrap_err();
        assert!(
            matches!(error, TransportSpecError::UnexpectedCoverageMap),
            "{error}"
        );
    }

    #[test]
    fn coverage_map_bad_integer_is_descriptive() {
        let error = TransportPlan::parse(
            "gdb:h:1",
            Some("input=notanumber,ring=0,write=0,wrapped=0,cap=1"),
        )
        .unwrap_err();
        match error {
            TransportSpecError::Field { field, value } => {
                assert_eq!(field, "input");
                assert_eq!(value, "notanumber");
            }
            other => panic!("expected Field error, got {other}"),
        }
    }

    #[test]
    fn coverage_map_missing_key_is_descriptive() {
        // No `cap`.
        let error =
            TransportPlan::parse("gdb:h:1", Some("input=0,ring=0,write=0,wrapped=0")).unwrap_err();
        match error {
            TransportSpecError::MissingMapKey { key } => assert_eq!(key, "cap"),
            other => panic!("expected MissingMapKey, got {other}"),
        }
    }

    #[test]
    fn coverage_map_unknown_key_is_descriptive() {
        let error = TransportPlan::parse(
            "gdb:h:1",
            Some("input=0,ring=0,write=0,wrapped=0,cap=1,bogus=2"),
        )
        .unwrap_err();
        match error {
            TransportSpecError::UnknownMapKey { key } => assert_eq!(key, "bogus"),
            other => panic!("expected UnknownMapKey, got {other}"),
        }
    }

    #[test]
    fn qemu_missing_qmp_key_is_descriptive() {
        let error = TransportPlan::parse(
            "qemu-system:gdb=h:2",
            Some("input=0,ring=0,write=0,wrapped=0,cap=1"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("qmp"), "{error}");
    }

    // --- transport builder tests (pure; no live connection) ------------------

    #[test]
    fn agent_tcp_builds_a_transport() {
        // Construction is pure — the socket is only dialed on arm(), which we
        // never call here, so this needs no listener.
        let plan = TransportPlan::parse("agent:tcp:127.0.0.1:1", None).unwrap();
        assert!(plan.into_transport().is_ok());
    }

    #[test]
    fn qemu_system_rejects_unsafe_snapshot_tag_at_build_time() {
        // A snapshot tag with a space would be spliced into an HMP command line;
        // FullSystemTransport::new must reject it, surfacing as a Transport error.
        let map_spec = "input=0,ring=0,write=0,wrapped=0,cap=1";
        let plan = TransportPlan::parse(
            "qemu-system:qmp=h:1,gdb=h:2,snapshot=bad tag",
            Some(map_spec),
        )
        .unwrap();
        let error = match plan.into_transport() {
            Ok(_) => panic!("an unsafe snapshot tag must be rejected"),
            Err(error) => error,
        };
        assert!(
            matches!(error, TransportSpecError::Transport(_)),
            "expected a Transport error, got {error}"
        );
        assert!(error.to_string().contains("snapshot tag"), "{error}");
    }

    // --- end-to-end loop tests against the mock agent ------------------------

    /// Build an [`AgentTransport`] over an in-memory `duplex()` whose target end
    /// is served by a `MockAgent` running the given script. Returns the transport
    /// and the shared `received` log of delivered inputs.
    fn mock_agent_transport(
        script: Vec<ScriptedResponse>,
    ) -> (Box<dyn TargetTransport>, Arc<Mutex<Vec<Vec<u8>>>>) {
        let received = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let received_for_factory = Arc::clone(&received);
        // arm() is called once; hand out the single host end via a slot.
        let (host_end, target_end) = duplex();
        let slot = Mutex::new(Some(host_end));
        let agent = MockAgent::new(target_end, script, received_for_factory);
        thread::spawn(move || {
            let _ = agent.serve();
        });
        let transport = AgentTransport::new(move || {
            slot.lock().unwrap().take().ok_or_else(|| {
                TransportError::Protocol("mock connect invoked more than once".to_owned())
            })
        });
        (Box::new(transport), received)
    }

    fn tmp_work_dir(tag: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        dir.push(format!("bhf-transport-fuzz-{tag}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn config(work_dir: PathBuf, seeds: Vec<Vec<u8>>, iterations: usize) -> TransportFuzzConfig {
        TransportFuzzConfig {
            work_dir,
            harness_id: "H-transport".to_owned(),
            transport_label: "mock-agent".to_owned(),
            seeds,
            iterations,
            time_budget: None,
            max_len: 4096,
            rng_seed: 0x4756_4655_5a5a,
            stop_after_findings: None,
            mode: actionability::RunMode::Reporting,
        }
    }

    #[test]
    fn loop_folds_coverage_retains_new_edge_seed_and_writes_a_fault_finding() {
        // The mock serves responses positionally (one per delivered input), so
        // coverage is controlled by execution index regardless of mutated bytes:
        //   exec 0 (seed):     edges [10, 11]        -> baseline coverage
        //   exec 1 (mutation): edges [10, 11, 12]    -> NEW coverage, retained
        //   exec 2 (mutation): crash with a fault    -> a written finding
        let fault = Fault {
            kind: FaultKind::MemoryProtection,
            address: Some(0x2000_4000),
            detail: "MPU region 3".to_owned(),
        };
        let script = vec![
            ScriptedResponse::ok(vec![10, 11]),
            ScriptedResponse::ok(vec![10, 11, 12]),
            ScriptedResponse::crash(vec![10, 11, 12], fault),
        ];
        let (transport, received) = mock_agent_transport(script);

        let work_dir = tmp_work_dir("e2e");
        // 1 seed + 2 mutations == 3 scripted responses.
        let config = config(work_dir.clone(), vec![b"seed".to_vec()], 3);

        let summary = run_transport_campaign(transport.as_ref(), &config).unwrap();

        // (c) terminates on budget: exactly `iterations` executions, no more.
        assert_eq!(summary.executions, 3, "must stop at the iteration budget");

        // (a) coverage was folded across all three runs, and a new-edge input was
        // retained as a corpus seed.
        assert!(
            summary.coverage_blocks >= 3,
            "blocks 10,11,12 must all be folded: {summary:?}"
        );
        assert!(
            summary.coverage_edges >= 2,
            "edges 10->11 and 11->12 must be folded: {summary:?}"
        );
        assert_eq!(
            summary.corpus_new, 1,
            "exactly the new-edge mutation (exec 1) is retained: {summary:?}"
        );

        // (b) the scripted fault became a written finding on disk.
        assert_eq!(summary.crashes, 1, "one crash outcome seen");
        assert_eq!(
            summary.findings.len(),
            1,
            "one finding emitted: {summary:?}"
        );
        let finding_id = &summary.findings[0];
        let finding_json = work_dir
            .join("findings")
            .join(finding_id)
            .join("finding.json");
        assert!(
            finding_json.exists(),
            "finding.json must be written to the work dir: {}",
            finding_json.display()
        );
        // It is classified through the HDF-2 seam: an MPU trap at a non-null
        // address maps to the BHF-210 memory-bounds family.
        let record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&finding_json).unwrap()).unwrap();
        assert_eq!(record["rule_id"], "BHF-210", "{record}");

        // All three inputs were actually delivered over the transport.
        assert_eq!(received.lock().unwrap().len(), 3);

        std::fs::remove_dir_all(&work_dir).ok();
    }

    #[test]
    fn loop_terminates_immediately_on_a_zero_time_budget() {
        // A zero wall-clock budget stops before any execution — the time-budget
        // branch of should_stop, exercised deterministically (no run_input call,
        // so the mock needs no script entries).
        let (transport, received) = mock_agent_transport(vec![]);
        let work_dir = tmp_work_dir("zero-budget");
        let mut config = config(work_dir.clone(), vec![b"seed".to_vec()], 1_000);
        config.time_budget = Some(Duration::from_secs(0));

        let summary = run_transport_campaign(transport.as_ref(), &config).unwrap();

        assert_eq!(summary.executions, 0, "zero-budget run does nothing");
        assert!(summary.findings.is_empty());
        assert!(received.lock().unwrap().is_empty());

        std::fs::remove_dir_all(&work_dir).ok();
    }

    #[test]
    fn loop_stops_after_the_requested_distinct_finding_count() {
        // Two crashes of the SAME fault class dedup to one finding; the run keeps
        // going. Give distinct classes and cap at one distinct finding.
        let script = vec![
            ScriptedResponse::crash(vec![1], Fault::new(FaultKind::StackOverflow)),
            ScriptedResponse::crash(vec![2], Fault::new(FaultKind::CpuException)),
        ];
        let (transport, _received) = mock_agent_transport(script);
        let work_dir = tmp_work_dir("stop-after");
        let mut config = config(work_dir.clone(), vec![b"seed".to_vec()], 2);
        config.stop_after_findings = Some(1);

        let summary = run_transport_campaign(transport.as_ref(), &config).unwrap();

        // The seed run (exec 0) crashes -> first distinct finding -> stop_after
        // reached, so the loop halts before a second execution.
        assert_eq!(summary.findings.len(), 1, "{summary:?}");
        assert_eq!(summary.executions, 1, "stops as soon as the target is met");

        std::fs::remove_dir_all(&work_dir).ok();
    }

    #[test]
    fn duplicate_fault_classes_collapse_to_one_finding() {
        // Two crashes of the same class over two executions -> one finding.
        let script = vec![
            ScriptedResponse::crash(vec![1], Fault::new(FaultKind::StackOverflow)),
            ScriptedResponse::crash(vec![2], Fault::new(FaultKind::StackOverflow)),
        ];
        let (transport, _received) = mock_agent_transport(script);
        let work_dir = tmp_work_dir("dedup");
        let config = config(work_dir.clone(), vec![b"seed".to_vec()], 2);

        let summary = run_transport_campaign(transport.as_ref(), &config).unwrap();

        assert_eq!(summary.executions, 2);
        assert_eq!(summary.crashes, 2, "both crash outcomes are counted");
        assert_eq!(
            summary.findings.len(),
            1,
            "same fault class -> one finding: {summary:?}"
        );

        std::fs::remove_dir_all(&work_dir).ok();
    }
}
