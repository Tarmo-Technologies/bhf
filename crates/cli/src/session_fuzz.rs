// SPDX-License-Identifier: Apache-2.0

//! HDF-7: wire the pure `protocol_session` crate into a runnable `bhf fuzz` lane.
//!
//! `protocol_session` parses a versioned protocol profile, lowers each message
//! onto the reused `binframe` descriptor, projects the legal message ordering
//! onto the reused `ada_state_machine` graph, and drives / replays / minimizes a
//! response-dependent, multi-message session over a [`SessionTransport`] seam —
//! but it is deliberately hardware-free: it owns no sockets and no process
//! spawn. This module is the consumer that supplies the live side: a real TCP
//! [`TcpSessionTransport`], a bounded seed+mutation campaign loop, and the
//! finding emission + replay/minimize wiring, all reusing the existing
//! `results/` finding layout `bhf fuzz` already writes.
//!
//! # Additive by construction
//!
//! The lane is a SEPARATE code path, reached only when `--protocol-profile` is
//! set (see [`should_use_session`] and the dispatch in [`crate::fuzz::run`]).
//! Without it, `bhf fuzz` runs the existing host/transport paths byte-for-byte.
//!
//! # Two novelty channels, reported separately
//!
//! Scheduling folds a CAPPED protocol-state/transition novelty contribution into
//! the shared scheduler's breadcrumb channel, but the run summary keeps the code-
//! coverage channel (`coverage_edges` / `coverage_blocks`) and the state channel
//! (`states_covered` / `transitions_covered`) in distinct fields — never merged
//! into one number. A plain request/response transport reports no code edges, so
//! the code channel is honestly zero on such targets while the state channel
//! carries the novelty.
//!
//! Nothing here names a downstream consumer: a finding is emitted for importers /
//! SARIF / vulnerability-management tools to read.

use std::collections::{BTreeSet, HashSet};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use corpus::{CorpusError, FindingEmitter};
use finding_rules::oracle_sdk::{OracleEvidence, OracleHit};
use fuzz_engine_builtin::{MutationRng, PowerScheduler, ScheduleFeedback};
use protocol_session::{
    mutate_fields, mutate_sequence, BoundValue, CodeCoverageNovelty, FieldRole, Profile,
    ProtocolModel, SessionRun, SessionRunner, SessionTestcase, SessionTransport, SessionVerdict,
    StateNovelty, StateNoveltyDelta, TransportError,
};
use serde::{Deserialize, Serialize};

use crate::fuzz::FuzzArgs;

/// The versioned name of the per-finding session artifact sidecar.
const SESSION_ARTIFACT_SCHEMA: &str = "bhf.session-artifact.v1";
/// The `session.json` artifact a session finding carries in its finding dir.
const SESSION_ARTIFACT: &str = "session.json";
/// The self-contained replay/minimize metadata sidecar (profile + transport).
const SESSION_META: &str = "session_meta.json";
/// Upper bound on a single framed reply we will read off a socket, so a
/// misbehaving peer cannot drive an unbounded allocation.
const MAX_REPLY_BYTES: usize = 1 << 20;
/// Per-request socket read/write timeout, so a silent peer cannot hang a run.
const SESSION_IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Cap on the state-novelty contribution folded into the shared scheduler's
/// breadcrumb channel, so protocol novelty can never dominate code coverage.
const STATE_NOVELTY_CAP: usize = 8;

/// How a session is reset between testcases. Recorded as the run's reset
/// fidelity so a finding states exactly how its session state was re-established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum SessionResetMode {
    /// A fresh connection per testcase: new per-session target state (a new
    /// handle / id / nonce is captured each run). The default.
    #[default]
    Reconnect,
    /// Keep one connection across testcases: per-session target state persists.
    None,
}

impl SessionResetMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SessionResetMode::Reconnect => "reconnect",
            SessionResetMode::None => "none",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "reconnect" => Ok(SessionResetMode::Reconnect),
            "none" => Ok(SessionResetMode::None),
            other => Err(format!(
                "unknown session reset mode {other:?}; expected reconnect or none"
            )),
        }
    }
}

/// True when `bhf fuzz` should take the session-driven lane instead of the host
/// / transport paths: exactly when `--protocol-profile` is set. When it is
/// `None`, the default flow is byte-for-byte unchanged.
pub(crate) fn should_use_session(args: &FuzzArgs) -> bool {
    args.protocol_profile.is_some()
}

// ---------------------------------------------------------------------------
// Transport spec parsing (pure, fully testable)
// ---------------------------------------------------------------------------

/// A parsed, validated `--session-transport` spec. Kept separate from the built
/// transport so the parse is inspectable without dialing any socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionTransportPlan {
    /// A TCP request/response backend: one socket connected per session.
    Tcp { host: String, port: u16 },
}

/// A descriptive failure parsing a `--session-transport` spec. Never a silent
/// `None`.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SessionSpecError {
    #[error("empty --session-transport spec; expected tcp:HOST:PORT")]
    Empty,
    #[error("unknown --session-transport backend {backend:?}; supported: tcp")]
    UnknownBackend { backend: String },
    #[error("malformed {backend} spec {spec:?}: {reason}")]
    Malformed {
        backend: &'static str,
        spec: String,
        reason: String,
    },
}

impl SessionTransportPlan {
    /// Parse a `--session-transport` spec into an inspectable plan.
    pub(crate) fn parse(spec: &str) -> Result<Self, SessionSpecError> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err(SessionSpecError::Empty);
        }
        if let Some(rest) = spec.strip_prefix("tcp:") {
            let (host, port) = parse_host_port("tcp", spec, rest)?;
            return Ok(Self::Tcp { host, port });
        }
        Err(SessionSpecError::UnknownBackend {
            backend: spec.split(':').next().unwrap_or(spec).to_owned(),
        })
    }

    /// A short human label for the run summary / finding metadata.
    fn label(&self) -> String {
        match self {
            Self::Tcp { host, port } => format!("tcp:{host}:{port}"),
        }
    }

    /// The transport kind, for the reset-fidelity string.
    fn kind(&self) -> &'static str {
        match self {
            Self::Tcp { .. } => "tcp",
        }
    }

    /// Build the live transport this plan describes. The socket is dialed lazily
    /// on the first [`SessionTransport::reset`], so this itself touches nothing.
    fn into_transport(self, reset: SessionResetMode) -> TcpSessionTransport {
        match self {
            Self::Tcp { host, port } => TcpSessionTransport::new(host, port, reset),
        }
    }
}

fn parse_host_port(
    backend: &'static str,
    spec: &str,
    hostport: &str,
) -> Result<(String, u16), SessionSpecError> {
    let malformed = |reason: String| SessionSpecError::Malformed {
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

// ---------------------------------------------------------------------------
// The live TCP request/response backend
// ---------------------------------------------------------------------------

/// A real TCP [`SessionTransport`]. Each request is length-prefixed
/// (`[u16 BE len][frame]`) and the reply is read the same way, with a bounded
/// read (`MAX_REPLY_BYTES`) and a read/write timeout so neither a huge reply nor
/// a silent peer can wedge a campaign.
pub(crate) struct TcpSessionTransport {
    host: String,
    port: u16,
    reset: SessionResetMode,
    stream: Option<TcpStream>,
}

impl TcpSessionTransport {
    fn new(host: String, port: u16, reset: SessionResetMode) -> Self {
        Self {
            host,
            port,
            reset,
            stream: None,
        }
    }

    fn connect(&mut self) -> Result<(), TransportError> {
        self.stream = None;
        let stream = TcpStream::connect((self.host.as_str(), self.port)).map_err(|e| {
            TransportError::new(format!("connect {}:{}: {e}", self.host, self.port))
        })?;
        stream.set_read_timeout(Some(SESSION_IO_TIMEOUT)).ok();
        stream.set_write_timeout(Some(SESSION_IO_TIMEOUT)).ok();
        // Disable Nagle: a request/response session sends one small frame then
        // blocks on the reply, so Nagle + delayed-ACK would add a ~40ms stall per
        // round-trip. We frame explicitly, so coalescing buys nothing.
        stream.set_nodelay(true).ok();
        self.stream = Some(stream);
        Ok(())
    }
}

impl SessionTransport for TcpSessionTransport {
    fn send_request(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        if request.len() > u16::MAX as usize {
            return Err(TransportError::new(format!(
                "request frame is {} bytes, exceeding the {} wire-length cap",
                request.len(),
                u16::MAX
            )));
        }
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| TransportError::new("tcp session is not connected; reset first"))?;
        let len = (request.len() as u16).to_be_bytes();
        stream
            .write_all(&len)
            .and_then(|()| stream.write_all(request))
            .and_then(|()| stream.flush())
            .map_err(|e| TransportError::new(format!("session write: {e}")))?;

        let mut len_buf = [0u8; 2];
        stream
            .read_exact(&mut len_buf)
            .map_err(|e| TransportError::new(format!("session read reply length: {e}")))?;
        let reply_len = usize::from(u16::from_be_bytes(len_buf));
        if reply_len > MAX_REPLY_BYTES {
            return Err(TransportError::new(format!(
                "reply length {reply_len} exceeds the {MAX_REPLY_BYTES}-byte cap"
            )));
        }
        let mut reply = vec![0u8; reply_len];
        stream
            .read_exact(&mut reply)
            .map_err(|e| TransportError::new(format!("session read reply body: {e}")))?;
        Ok(reply)
    }

    fn reset(&mut self) -> Result<(), TransportError> {
        // Reconnect establishes fresh per-session target state; `none` keeps the
        // one connection alive after the first dial.
        if self.stream.is_none() || matches!(self.reset, SessionResetMode::Reconnect) {
            self.connect()?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Seed synthesis
// ---------------------------------------------------------------------------

/// Synthesize the campaign's valid seed session(s) from the profile: a single
/// legal walk from the start state that covers each message type once, emitting a
/// message only once every back-reference it carries has a producer earlier in
/// the walk. For the OPEN/WRITE slice this yields the ordinary valid
/// `OPEN,WRITE` session (a non-escaping path) the campaign then mutates.
fn seed_sessions(model: &ProtocolModel) -> Vec<SessionTestcase> {
    let graph = model.graph();
    let total = model.messages().len();
    if total == 0 {
        return Vec::new();
    }
    let cap = model.max_messages().min(2 * total + 2).max(1);

    let mut produced: BTreeSet<String> = BTreeSet::new();
    let mut covered: BTreeSet<String> = BTreeSet::new();
    let mut messages = Vec::new();
    let mut cur = graph.initial();

    while covered.len() < total && messages.len() < cap {
        let choice = graph
            .open_entries(cur)
            .iter()
            .find(|name| !covered.contains(name.as_str()) && refs_satisfied(model, name, &produced))
            .cloned();
        let Some(name) = choice else { break };
        let Some(compiled) = model.message(&name) else {
            break;
        };
        messages.push(protocol_session::MessageInstance::from_seed(compiled));
        produced.insert(name.clone());
        covered.insert(name.clone());
        match graph.next_state(cur, &name) {
            Some(next) => cur = next,
            None => break,
        }
    }

    if messages.is_empty() {
        Vec::new()
    } else {
        vec![SessionTestcase::from_messages(
            model.profile_sha256(),
            messages,
        )]
    }
}

/// Whether every back-reference field of `message` has a producer already in the
/// `produced` set.
fn refs_satisfied(model: &ProtocolModel, message: &str, produced: &BTreeSet<String>) -> bool {
    let Some(compiled) = model.message(message) else {
        return false;
    };
    compiled.fields.iter().all(|field| match &field.role {
        FieldRole::Ref { source, .. } => produced.contains(source.split('.').next().unwrap_or("")),
        _ => true,
    })
}

/// A small, generic boundary-token dictionary spliced into bytes-typed fields.
/// `..` is the universal path-escape token; keeping it makes a bounded, fixed-
/// seed campaign deterministically reach a sandbox-escape boundary. No token is
/// consumer-specific.
fn boundary_dictionary() -> Vec<Vec<u8>> {
    vec![b"..".to_vec()]
}

// ---------------------------------------------------------------------------
// Campaign configuration / summary / errors
// ---------------------------------------------------------------------------

/// Inputs to [`run_session_campaign`], decoupled from clap so the loop is
/// testable against an in-memory transport in a temp dir.
#[derive(Debug, Clone)]
pub(crate) struct SessionFuzzConfig {
    pub work_dir: PathBuf,
    pub harness_id: String,
    /// SHA-256 of the driving profile (recorded on the run and every finding).
    pub profile_sha256: String,
    /// The full profile TOML, embedded in each finding's metadata so a finding
    /// replays/minimizes self-contained.
    pub profile_toml: String,
    /// The transport spec, used as the `transport` summary field and to rebuild
    /// the backend for replay/minimize.
    pub transport_label: String,
    /// The transport kind, for the reset-fidelity string.
    pub transport_kind: String,
    /// How a session is reset between testcases.
    pub reset: SessionResetMode,
    /// Bounded cap on messages per session.
    pub max_messages: usize,
    /// The valid seed session(s) the campaign mutates.
    pub seeds: Vec<SessionTestcase>,
    /// Total execution cap (bounded work — never unbounded).
    pub iterations: usize,
    /// Optional wall-clock budget.
    pub time_budget: Option<Duration>,
    /// Deterministic mutation RNG seed.
    pub rng_seed: u64,
    /// Stop as soon as this many DISTINCT findings are emitted.
    pub stop_after_findings: Option<usize>,
    /// Actionability profile for the emitted findings.
    pub mode: actionability::RunMode,
}

impl SessionFuzzConfig {
    fn reset_fidelity(&self) -> String {
        format!("{};reset={}", self.transport_kind, self.reset.as_str())
    }
}

/// The JSON summary a session-driven run reports. The code-coverage channel
/// (`coverage_edges` / `coverage_blocks`) and the protocol-state channel
/// (`states_covered` / `transitions_covered`) are DISTINCT fields, never merged.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct SessionFuzzSummary {
    pub schema_version: u32,
    pub harness_id: String,
    pub engine: String,
    pub profile_sha256: String,
    pub transport: String,
    pub reset_fidelity: String,
    pub seeds: usize,
    pub executions: usize,
    pub corpus_new: usize,
    /// Code-coverage channel (distinct edge bits). Zero on a transport that
    /// reports no edges; still present and reported separately.
    pub coverage_edges: usize,
    /// Code-coverage channel (block/hit-count bits).
    pub coverage_blocks: usize,
    /// Protocol-state channel: distinct states visited.
    pub states_covered: usize,
    /// Protocol-state channel: distinct transitions walked.
    pub transitions_covered: usize,
    /// Crash outcomes (always 0 on this lane — findings are clean-exit).
    pub crashes: usize,
    /// Distinct finding ids written to `<work_dir>/results/findings/`.
    pub findings: Vec<String>,
    pub elapsed_secs: f64,
}

/// A failure running a session-driven campaign. Every variant is descriptive.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SessionFuzzError {
    #[error("session transport error: {0}")]
    Transport(TransportError),
    #[error("serializing session testcase: {0}")]
    Serialize(serde_json::Error),
    #[error("writing finding: {0}")]
    Finding(#[from] CorpusError),
    #[error("writing session artifact {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
}

/// The self-contained replay/minimize sidecar written next to a session finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionArtifactMeta {
    schema: String,
    profile_sha256: String,
    /// The full driving profile, embedded so replay/minimize is self-contained.
    profile_toml: String,
    /// The `--session-transport` spec to rebuild the backend.
    transport: String,
    transport_kind: String,
    /// `reconnect` | `none`.
    reset: String,
    reset_fidelity: String,
    rule_id: Option<String>,
    oracle: String,
}

// ---------------------------------------------------------------------------
// The session campaign loop
// ---------------------------------------------------------------------------

/// Whether the loop should stop now: hit the iteration cap, the time budget, or
/// the distinct-finding target. Checked before every drive so the loop never
/// runs unbounded and never runs one execution past its budget.
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

/// Turn a capped state-novelty delta into scheduler feedback. The state
/// contribution rides the breadcrumb channel (weighted by the scheduler's
/// `breadcrumb_bit_bonus`) and is clamped so it cannot dominate code coverage.
fn schedule_feedback(delta: StateNoveltyDelta) -> ScheduleFeedback {
    let bits = (delta.new_states + delta.new_transitions).min(STATE_NOVELTY_CAP) as u32;
    ScheduleFeedback {
        new_exception_signatures: 0,
        new_breadcrumb_bits: bits,
    }
}

/// Apply one bounded, graph-legal mutation: mostly field-value mutation (which
/// discovers the field-level boundary), occasionally a structural sequence edit.
fn mutate_one(
    parent: &SessionTestcase,
    model: &ProtocolModel,
    rng: &mut MutationRng,
    dictionary: &[Vec<u8>],
    max_messages: usize,
) -> SessionTestcase {
    if rng.next_u64().is_multiple_of(8) {
        mutate_sequence(parent, model, rng, max_messages)
    } else {
        mutate_fields(parent, model, rng, dictionary)
    }
}

/// Drive one candidate against the transport, folding both novelty channels and
/// emitting a finding (deduped by rule|oracle) on a clean-exit violation.
/// Returns the state-novelty delta and whether a NEW finding was emitted.
///
/// A transport error aborts the campaign (the connection is broken); a
/// candidate-specific drive error (illegal transition, encode/response failure)
/// is skipped so the loop keeps exploring.
#[allow(clippy::too_many_arguments)]
fn drive_candidate(
    candidate: &SessionTestcase,
    runner: &SessionRunner,
    transport: &mut dyn SessionTransport,
    state_novelty: &mut StateNovelty,
    code_novelty: &mut CodeCoverageNovelty,
    emitter: &FindingEmitter,
    config: &SessionFuzzConfig,
    seen: &mut HashSet<String>,
    finding_ids: &mut Vec<String>,
) -> Result<(StateNoveltyDelta, bool), SessionFuzzError> {
    let run = match runner.drive(&candidate.messages, transport) {
        Ok(run) => run,
        Err(protocol_session::RunnerError::Transport(error)) => {
            return Err(SessionFuzzError::Transport(error))
        }
        // Candidate-specific error (should not occur for a graph-legal mutant):
        // skip it rather than aborting the campaign.
        Err(_) => return Ok((StateNoveltyDelta::default(), false)),
    };

    let delta = state_novelty.observe(&run.state_ids, &run.transitions);
    // The session seam carries no code-coverage edges; fold an empty set so the
    // code channel stays present (and honestly zero) alongside the state channel.
    code_novelty.observe(&[]);

    let mut new_finding = false;
    if let SessionVerdict::Finding {
        oracle,
        rule_id,
        message,
        detail,
    } = &run.verdict
    {
        let dedup = format!(
            "{}|{}",
            rule_id.as_deref().unwrap_or("HDF7-SESSION"),
            oracle
        );
        if seen.insert(dedup) {
            let id = emit_session_finding(
                emitter,
                &run,
                oracle,
                rule_id.as_deref(),
                message,
                detail,
                config,
            )?;
            finding_ids.push(id);
            new_finding = true;
        }
    }
    Ok((delta, new_finding))
}

/// Drive a bounded, coverage- and state-guided session campaign against
/// `transport`, reusing the builtin [`PowerScheduler`] for seed selection and
/// `protocol_session`'s graph-gated structured mutation. Returns the run summary;
/// a transport or finding-write failure propagates as a descriptive error.
pub(crate) fn run_session_campaign(
    model: &ProtocolModel,
    transport: &mut dyn SessionTransport,
    config: &SessionFuzzConfig,
) -> Result<SessionFuzzSummary, SessionFuzzError> {
    let start = Instant::now();
    let runner = SessionRunner::new(model);
    let dictionary = boundary_dictionary();
    let mut rng = MutationRng::new(config.rng_seed);
    let mut scheduler = PowerScheduler::default();
    let mut state_novelty = StateNovelty::new();
    let mut code_novelty = CodeCoverageNovelty::new();

    let emitter = FindingEmitter::with_metadata(
        config.work_dir.clone(),
        config.harness_id.clone(),
        "session".to_owned(),
        config.transport_label.clone(),
    )
    .with_mode(config.mode);

    let mut executions = 0usize;
    let mut corpus_new = 0usize;
    let mut finding_ids: Vec<String> = Vec::new();
    let mut seen_findings: HashSet<String> = HashSet::new();

    // --- seed phase: drive every seed once; seeds are always corpus members. ---
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
        let serialized = seed.to_json().map_err(SessionFuzzError::Serialize)?;
        let (delta, _) = drive_candidate(
            seed,
            &runner,
            transport,
            &mut state_novelty,
            &mut code_novelty,
            &emitter,
            config,
            &mut seen_findings,
            &mut finding_ids,
        )?;
        executions += 1;
        scheduler.insert_with_feedback(serialized.into_bytes(), schedule_feedback(delta));
    }

    // --- mutation phase: scheduler-driven structured mutation. ---
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
            break; // no corpus — nothing to mutate
        };
        let Ok(parent) = std::str::from_utf8(&scheduled.bytes)
            .map_err(|_| ())
            .and_then(|json| SessionTestcase::from_json(json).map_err(|_| ()))
        else {
            continue; // a corpus seed that is not valid session JSON — skip
        };

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
            let candidate = mutate_one(&parent, model, &mut rng, &dictionary, config.max_messages);
            let serialized = candidate.to_json().map_err(SessionFuzzError::Serialize)?;
            let (delta, _) = drive_candidate(
                &candidate,
                &runner,
                transport,
                &mut state_novelty,
                &mut code_novelty,
                &emitter,
                config,
                &mut seen_findings,
                &mut finding_ids,
            )?;
            executions += 1;
            if delta.is_novel() {
                scheduler.insert_with_feedback(serialized.into_bytes(), schedule_feedback(delta));
                corpus_new += 1;
            }
        }
    }

    Ok(SessionFuzzSummary {
        schema_version: 1,
        harness_id: config.harness_id.clone(),
        engine: "session".to_owned(),
        profile_sha256: config.profile_sha256.clone(),
        transport: config.transport_label.clone(),
        reset_fidelity: config.reset_fidelity(),
        seeds: seed_count,
        executions,
        corpus_new,
        coverage_edges: code_novelty.edges_covered(),
        coverage_blocks: 0,
        states_covered: state_novelty.states_covered(),
        transitions_covered: state_novelty.transitions_covered(),
        crashes: 0,
        findings: finding_ids,
        elapsed_secs: start.elapsed().as_secs_f64(),
    })
}

/// Emit one clean-exit session finding: build an [`OracleHit`] from the profile
/// oracle verdict, write it through the existing finding emitter (testcase.bin =
/// the serialized session), then write the `session.json` artifact and the
/// self-contained `session_meta.json` sidecar into the finding dir.
#[allow(clippy::too_many_arguments)]
fn emit_session_finding(
    emitter: &FindingEmitter,
    run: &SessionRun,
    oracle: &str,
    rule_id: Option<&str>,
    message: &str,
    detail: &str,
    config: &SessionFuzzConfig,
) -> Result<String, SessionFuzzError> {
    let serialized = run
        .testcase
        .to_json()
        .map_err(SessionFuzzError::Serialize)?;

    let mut evidence = vec![
        OracleEvidence::new("state_path", run.testcase.state_path.join(" -> ")),
        OracleEvidence::new("messages", run.testcase.messages.len().to_string()),
        OracleEvidence::new("detail", detail.to_owned()),
    ];
    for (source, value) in run.testcase.bindings.iter() {
        evidence.push(OracleEvidence::new(source.clone(), format_bound(value)));
    }

    let hit = OracleHit {
        oracle_name: oracle.to_owned(),
        rule_id: rule_id.unwrap_or("HDF7-SESSION").to_owned(),
        category: "logic-bug".to_owned(),
        api: message.to_owned(),
        message: format!("protocol session reached a clean-exit violation: {detail}"),
        evidence,
    };

    let id = emitter.emit_oracle_hit(serialized.as_bytes(), &hit)?;
    let finding_dir = corpus::layout::finding_dir(&config.work_dir, &id.0);

    write_artifact(&finding_dir.join(SESSION_ARTIFACT), serialized.as_bytes())?;

    let meta = SessionArtifactMeta {
        schema: SESSION_ARTIFACT_SCHEMA.to_owned(),
        profile_sha256: config.profile_sha256.clone(),
        profile_toml: config.profile_toml.clone(),
        transport: config.transport_label.clone(),
        transport_kind: config.transport_kind.clone(),
        reset: config.reset.as_str().to_owned(),
        reset_fidelity: config.reset_fidelity(),
        rule_id: rule_id.map(str::to_owned),
        oracle: oracle.to_owned(),
    };
    let meta_bytes = serde_json::to_vec_pretty(&meta).map_err(SessionFuzzError::Serialize)?;
    write_artifact(&finding_dir.join(SESSION_META), &meta_bytes)?;

    Ok(id.0)
}

fn write_artifact(path: &Path, bytes: &[u8]) -> Result<(), SessionFuzzError> {
    std::fs::write(path, bytes).map_err(|source| SessionFuzzError::Io {
        path: path.display().to_string(),
        source,
    })
}

fn format_bound(value: &BoundValue) -> String {
    match value {
        BoundValue::Int { value } => format!("0x{value:x}"),
        BoundValue::Enum { symbol, code } => format!("{symbol}(0x{code:x})"),
        BoundValue::Bytes { value } => format!("{} bytes", value.len()),
    }
}

// ---------------------------------------------------------------------------
// Replay / minimize of a session finding
// ---------------------------------------------------------------------------

/// Whether a finding directory carries a session artifact (so `bhf replay` /
/// `bhf minimize` take the session path automatically, leaving opaque-input
/// findings untouched).
pub(crate) fn is_session_finding(finding_dir: &Path) -> bool {
    finding_dir.join(SESSION_ARTIFACT).is_file()
}

/// Load a session finding's recorded testcase, its profile-derived model, and a
/// freshly-built transport from the self-contained metadata sidecar.
fn load_session_finding(
    finding_dir: &Path,
) -> Result<(SessionTestcase, ProtocolModel, SessionArtifactMeta), String> {
    let artifact = finding_dir.join(SESSION_ARTIFACT);
    let testcase_json = std::fs::read_to_string(&artifact)
        .map_err(|e| format!("read {}: {e}", artifact.display()))?;
    let testcase = SessionTestcase::from_json(&testcase_json)
        .map_err(|e| format!("parse {}: {e}", artifact.display()))?;

    let meta_path = finding_dir.join(SESSION_META);
    let meta_json = std::fs::read_to_string(&meta_path)
        .map_err(|e| format!("read {}: {e}", meta_path.display()))?;
    let meta: SessionArtifactMeta = serde_json::from_str(&meta_json)
        .map_err(|e| format!("parse {}: {e}", meta_path.display()))?;

    let profile = Profile::from_toml(&meta.profile_toml)
        .map_err(|e| format!("rebuild profile from finding metadata: {e}"))?;
    let model =
        ProtocolModel::from_profile(&profile).map_err(|e| format!("compile profile model: {e}"))?;

    Ok((testcase, model, meta))
}

fn build_live_transport(meta: &SessionArtifactMeta) -> Result<TcpSessionTransport, String> {
    let plan = SessionTransportPlan::parse(&meta.transport).map_err(|e| e.to_string())?;
    let reset = SessionResetMode::parse(&meta.reset)?;
    Ok(plan.into_transport(reset))
}

/// `bhf replay` of a session finding: re-drive the recorded session against a
/// freshly reset transport (re-capturing a fresh handle) and report whether it
/// still reaches the oracle verdict.
pub(crate) fn replay_session_finding(finding_dir: &Path) -> i32 {
    match replay_session_inner(finding_dir) {
        Ok(true) => {
            let _ = corpus::finding::touch_last_seen(finding_dir, "replay");
            println!("MATCH");
            0
        }
        Ok(false) => {
            bhfeprintln!("MISMATCH: the recorded session no longer reaches the oracle verdict");
            3
        }
        Err(error) => {
            bhfeprintln!("error: {error}");
            1
        }
    }
}

fn replay_session_inner(finding_dir: &Path) -> Result<bool, String> {
    let (testcase, model, meta) = load_session_finding(finding_dir)?;
    let mut transport = build_live_transport(&meta)?;
    replay_reproduces(&model, &testcase, &meta, &mut transport)
}

/// Whether `verdict` reproduces the SAME oracle finding that the metadata
/// recorded, by both oracle name and `rule_id`.
///
/// Replay and minimize must not accept *any* oracle firing as a reproduction:
/// under a multi-oracle profile (`[[oracle]]` is a list) a session recorded for
/// oracle `O1` can re-drive into a finding for a different oracle `O2`, which
/// would falsely "confirm" `O1` — or, in minimize, let delta-debugging shrink
/// away the very structure that triggered `O1` because a smaller sequence still
/// trips `O2`. Gating on the recorded oracle keeps each finding honest to the
/// oracle it was emitted for.
fn verdict_reproduces(verdict: &SessionVerdict, meta: &SessionArtifactMeta) -> bool {
    match verdict {
        SessionVerdict::Finding {
            oracle, rule_id, ..
        } => *oracle == meta.oracle && *rule_id == meta.rule_id,
        SessionVerdict::Clean => false,
    }
}

/// Re-drive `testcase` against `transport` and report whether it reproduces the
/// recorded oracle finding (not merely *some* finding).
fn replay_reproduces(
    model: &ProtocolModel,
    testcase: &SessionTestcase,
    meta: &SessionArtifactMeta,
    transport: &mut dyn SessionTransport,
) -> Result<bool, String> {
    let runner = SessionRunner::new(model);
    let run = runner
        .replay(testcase, transport)
        .map_err(|e| format!("replay session: {e}"))?;
    Ok(verdict_reproduces(&run.verdict, meta))
}

/// `bhf minimize` of a session finding: shrink the message sequence and the
/// bytes fields via the crate's minimizer (re-repairing computed fields and
/// re-resolving bindings on every candidate), keeping the finding reproducing,
/// then rewrite the smaller `session.json`.
pub(crate) fn minimize_session_finding(finding_dir: &Path) -> i32 {
    match minimize_session_inner(finding_dir) {
        Ok((original, minimized, reproduces)) => {
            println!(
                "SESSION-MINIMIZED original_messages={original} minimized_messages={minimized} reduced={} reproduces={reproduces} path={SESSION_ARTIFACT}",
                minimized < original
            );
            0
        }
        Err(error) => {
            bhfeprintln!("error: {error}");
            1
        }
    }
}

fn minimize_session_inner(finding_dir: &Path) -> Result<(usize, usize, bool), String> {
    let (testcase, model, meta) = load_session_finding(finding_dir)?;
    let (original_len, run, reproduces) =
        minimize_session_core(&model, &testcase, &meta, || build_live_transport(&meta))?;
    let minimized_len = run.testcase.messages.len();

    let serialized = run
        .testcase
        .to_json()
        .map_err(|e| format!("serialize minimized session: {e}"))?;
    let artifact = finding_dir.join(SESSION_ARTIFACT);
    std::fs::write(&artifact, serialized.as_bytes())
        .map_err(|e| format!("write {}: {e}", artifact.display()))?;
    // Keep the finding's primary testcase in step with the minimized repro.
    let testcase_bin = finding_dir.join("testcase.bin");
    if testcase_bin.exists() {
        std::fs::write(&testcase_bin, serialized.as_bytes())
            .map_err(|e| format!("write {}: {e}", testcase_bin.display()))?;
    }

    Ok((original_len, minimized_len, reproduces))
}

/// Shrink `testcase` while it keeps reproducing the recorded oracle finding,
/// then drive the minimized sequence once more for fresh evidence. Returns the
/// original message count, that final [`SessionRun`], and whether the minimized
/// sequence still reproduces the recorded oracle.
///
/// `make_transport` yields a *freshly reset* transport per drive, so the
/// dynamic binding is re-resolved and the computed fields re-repaired on every
/// candidate. Factoring the transport out keeps the oracle-gating logic
/// testable against an in-memory transport instead of a live socket.
fn minimize_session_core<T, F>(
    model: &ProtocolModel,
    testcase: &SessionTestcase,
    meta: &SessionArtifactMeta,
    mut make_transport: F,
) -> Result<(usize, SessionRun, bool), String>
where
    T: SessionTransport,
    F: FnMut() -> Result<T, String>,
{
    let runner = SessionRunner::new(model);
    let original_len = testcase.messages.len();

    // Baseline: the recorded session must still reproduce the SAME recorded
    // oracle before we minimize it.
    {
        let mut transport = make_transport()?;
        let run = runner
            .replay(testcase, &mut transport)
            .map_err(|e| format!("baseline replay: {e}"))?;
        if !verdict_reproduces(&run.verdict, meta) {
            return Err(
                "the recorded session no longer reproduces; refusing to minimize".to_owned(),
            );
        }
    }

    // Each predicate candidate re-drives on a fresh transport (fresh handle),
    // and only a finding for the RECORDED oracle counts as still reproducing —
    // a smaller sequence that trips a different oracle must not be accepted.
    let predicate = |candidate: &SessionTestcase| -> bool {
        let Ok(mut transport) = make_transport() else {
            return false;
        };
        runner
            .replay(candidate, &mut transport)
            .map(|run| verdict_reproduces(&run.verdict, meta))
            .unwrap_or(false)
    };
    let minimized = runner.minimize(testcase, predicate);

    // Re-drive the minimized testcase once to capture its fresh evidence.
    let mut transport = make_transport()?;
    let run = runner
        .replay(&minimized, &mut transport)
        .map_err(|e| format!("drive minimized session: {e}"))?;
    let reproduces = verdict_reproduces(&run.verdict, meta);
    Ok((original_len, run, reproduces))
}

// ---------------------------------------------------------------------------
// CLI entry
// ---------------------------------------------------------------------------

/// `bhf fuzz --protocol-profile <PATH>` entry point. Loads and compiles the
/// profile, builds the transport, synthesizes the valid seed session, runs the
/// bounded campaign, and prints the JSON summary.
pub(crate) fn run(args: FuzzArgs) -> i32 {
    match run_inner(args) {
        Ok(summary) => match serde_json::to_string_pretty(&summary) {
            Ok(json) => {
                println!("{json}");
                0
            }
            Err(error) => {
                crate::bhfeprintln!("failed to render session-fuzz summary: {error}");
                1
            }
        },
        Err(code) => code,
    }
}

fn run_inner(args: FuzzArgs) -> Result<SessionFuzzSummary, i32> {
    let profile_path = args
        .protocol_profile
        .as_deref()
        .expect("run() is only reached when --protocol-profile is set");

    let profile_toml = std::fs::read_to_string(profile_path).map_err(|error| {
        crate::bhfeprintln!(
            "bhf fuzz --protocol-profile: read {}: {error}",
            profile_path.display()
        );
        3
    })?;
    let profile = Profile::from_toml(&profile_toml).map_err(|error| {
        crate::bhfeprintln!("bhf fuzz --protocol-profile: {error}");
        2
    })?;
    let model = ProtocolModel::from_profile(&profile).map_err(|error| {
        crate::bhfeprintln!("bhf fuzz --protocol-profile: {error}");
        2
    })?;

    let spec = args.session_transport.as_deref().ok_or_else(|| {
        crate::bhfeprintln!(
            "bhf fuzz --protocol-profile requires --session-transport <SPEC> (e.g. tcp:HOST:PORT)"
        );
        2
    })?;
    let plan = SessionTransportPlan::parse(spec).map_err(|error| {
        crate::bhfeprintln!("bhf fuzz --session-transport: {error}");
        2
    })?;
    let transport_label = plan.label();
    let transport_kind = plan.kind().to_owned();
    let mut transport = plan.into_transport(args.session_reset);

    let seeds = seed_sessions(&model);
    if seeds.is_empty() {
        crate::bhfeprintln!(
            "bhf fuzz --protocol-profile: the profile has no legal seed session (no message is \
             reachable from the start state)"
        );
        return Err(2);
    }

    let config = SessionFuzzConfig {
        work_dir: args.work_dir.clone(),
        harness_id: args.harness.clone(),
        profile_sha256: model.profile_sha256().to_owned(),
        profile_toml,
        transport_label,
        transport_kind,
        reset: args.session_reset,
        max_messages: args.max_session_messages,
        seeds,
        iterations: args.effective_iterations(),
        time_budget: args.time,
        rng_seed: args.rng_seed,
        stop_after_findings: args.stop_after_findings,
        mode: args.mode,
    };

    run_session_campaign(&model, &mut transport, &config).map_err(|error| {
        crate::bhfeprintln!("bhf fuzz --protocol-profile: {error}");
        1
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuzz_engine_builtin::crc32;

    const TOY: &str = include_str!("../../protocol_session/tests/fixtures/toy-open-write.toml");

    fn toy_model() -> ProtocolModel {
        ProtocolModel::from_profile(&Profile::from_toml(TOY).expect("parse")).expect("compile")
    }

    // --- an in-memory toy OPEN/WRITE service behind the transport seam -------
    // Mirrors the real vertical-slice service: OPEN issues a fresh per-session
    // handle (different after every reset); a WRITE through a handle whose OPEN
    // path escaped the sandbox ("..") returns the boundary status 0xEF.
    struct ToyService {
        session: u32,
        current_handle: Option<u32>,
        tainted: bool,
        open_count: u32,
    }

    impl ToyService {
        fn new() -> Self {
            Self {
                session: 0,
                current_handle: None,
                tainted: false,
                open_count: 0,
            }
        }

        fn base(&self) -> u32 {
            self.session
                .wrapping_mul(0x0100_0000)
                .wrapping_add(0x00AB_CD01)
        }
    }

    fn be16(buf: &[u8], at: usize) -> Option<usize> {
        let s = buf.get(at..at + 2)?;
        Some(usize::from(u16::from_be_bytes([s[0], s[1]])))
    }

    fn be32(buf: &[u8], at: usize) -> Option<u32> {
        let s = buf.get(at..at + 4)?;
        Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    impl SessionTransport for ToyService {
        fn send_request(&mut self, req: &[u8]) -> Result<Vec<u8>, TransportError> {
            let reject = || Ok(vec![0x01]);
            let Some(&op) = req.first() else {
                return reject();
            };
            match op {
                1 => {
                    let Some(len) = be16(req, 2) else {
                        return reject();
                    };
                    let path_end = 4 + len;
                    let crc_end = path_end + 4;
                    if req.len() < crc_end {
                        return reject();
                    }
                    if be32(req, path_end).unwrap() != crc32(&req[0..path_end]) {
                        return Ok(vec![0, 0, 0, 0]);
                    }
                    self.tainted = req[4..path_end].windows(2).any(|w| w == b"..");
                    let handle = self.base().wrapping_add(self.open_count);
                    self.open_count = self.open_count.wrapping_add(1);
                    self.current_handle = Some(handle);
                    Ok(handle.to_be_bytes().to_vec())
                }
                2 => {
                    let Some(handle) = be32(req, 1) else {
                        return reject();
                    };
                    let Some(len) = be16(req, 5) else {
                        return reject();
                    };
                    let data_end = 7 + len;
                    let crc_end = data_end + 4;
                    if req.len() < crc_end {
                        return reject();
                    }
                    if be32(req, data_end).unwrap() != crc32(&req[0..data_end]) {
                        return reject();
                    }
                    if self.current_handle == Some(handle) {
                        if self.tainted {
                            Ok(vec![0xEF])
                        } else {
                            Ok(vec![0x00])
                        }
                    } else {
                        Ok(vec![0x01])
                    }
                }
                _ => reject(),
            }
        }

        fn reset(&mut self) -> Result<(), TransportError> {
            self.session = self.session.wrapping_add(1);
            self.current_handle = None;
            self.tainted = false;
            self.open_count = 0;
            Ok(())
        }
    }

    fn tmp_work_dir(tag: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        dir.push(format!("bhf-session-fuzz-{tag}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn config(model: &ProtocolModel, work_dir: PathBuf, iterations: usize) -> SessionFuzzConfig {
        SessionFuzzConfig {
            work_dir,
            harness_id: "H-session".to_owned(),
            profile_sha256: model.profile_sha256().to_owned(),
            profile_toml: TOY.to_owned(),
            transport_label: "scripted".to_owned(),
            transport_kind: "scripted".to_owned(),
            reset: SessionResetMode::Reconnect,
            max_messages: 64,
            seeds: seed_sessions(model),
            iterations,
            time_budget: None,
            rng_seed: 0x00C0_FFEE_D00D,
            stop_after_findings: None,
            mode: actionability::RunMode::Reporting,
        }
    }

    // `FuzzArgs` is a `clap::Args` group; wrap it in a `Parser` to parse a
    // `bhf fuzz`-style argument vector in isolation.
    #[derive(clap::Parser)]
    struct FuzzArgsHarness {
        #[command(flatten)]
        fuzz: FuzzArgs,
    }

    #[test]
    fn session_path_is_off_by_default_and_opt_in() {
        use clap::Parser;

        let default = FuzzArgsHarness::parse_from(["fuzz", "workdir", "--harness", "H-1"]).fuzz;
        assert!(default.protocol_profile.is_none());
        assert!(
            !should_use_session(&default),
            "the default flow must not route through the session lane"
        );

        let with_profile = FuzzArgsHarness::parse_from([
            "fuzz",
            "workdir",
            "--harness",
            "H-1",
            "--protocol-profile",
            "/some/profile.toml",
        ])
        .fuzz;
        assert_eq!(
            with_profile.protocol_profile.as_deref(),
            Some(Path::new("/some/profile.toml"))
        );
        assert!(should_use_session(&with_profile));
        // The reset default is reconnect and the message cap defaults to 64.
        assert_eq!(with_profile.session_reset, SessionResetMode::Reconnect);
        assert_eq!(with_profile.max_session_messages, 64);
    }

    #[test]
    fn parses_tcp_transport_spec() {
        let plan = SessionTransportPlan::parse("tcp:127.0.0.1:9000").unwrap();
        assert_eq!(
            plan,
            SessionTransportPlan::Tcp {
                host: "127.0.0.1".to_owned(),
                port: 9000
            }
        );
        assert_eq!(plan.label(), "tcp:127.0.0.1:9000");
        assert_eq!(plan.kind(), "tcp");
    }

    #[test]
    fn transport_spec_errors_are_descriptive() {
        assert!(matches!(
            SessionTransportPlan::parse("   ").unwrap_err(),
            SessionSpecError::Empty
        ));
        match SessionTransportPlan::parse("carrierpigeon:host:1").unwrap_err() {
            SessionSpecError::UnknownBackend { backend } => assert_eq!(backend, "carrierpigeon"),
            other => panic!("expected UnknownBackend, got {other}"),
        }
        assert!(SessionTransportPlan::parse("tcp:localhost")
            .unwrap_err()
            .to_string()
            .contains("HOST:PORT"));
        assert!(SessionTransportPlan::parse("tcp:localhost:0")
            .unwrap_err()
            .to_string()
            .contains("port"));
    }

    #[test]
    fn seed_session_is_a_legal_ref_satisfying_walk() {
        let model = toy_model();
        let seeds = seed_sessions(&model);
        assert_eq!(seeds.len(), 1);
        // The synthesized seed is the ordinary valid OPEN,WRITE session: OPEN
        // produces the handle WRITE references, in a legal order.
        assert_eq!(seeds[0].message_names(), vec!["OPEN", "WRITE"]);
    }

    #[test]
    fn loop_reports_code_and_state_coverage_separately() {
        // Seed with just OPEN (one transition); the campaign's structural
        // mutation discovers a second transition, so the STATE channel grows
        // while the CODE channel stays an honestly-reported, distinct zero.
        let model = toy_model();
        let work_dir = tmp_work_dir("separate-novelty");
        let mut cfg = config(&model, work_dir.clone(), 3000);
        cfg.seeds = vec![SessionTestcase::from_messages(
            model.profile_sha256(),
            vec![protocol_session::MessageInstance::from_seed(
                model.message("OPEN").unwrap(),
            )],
        )];

        let mut service = ToyService::new();
        let summary = run_session_campaign(&model, &mut service, &cfg).unwrap();

        assert!(
            summary.transitions_covered >= 2,
            "structural mutation must reach a new transition: {summary:?}"
        );
        assert!(summary.states_covered >= 2, "start + opened visited");
        // Two DISTINCT channels: the code channel is present and (for this
        // edge-less transport) honestly zero, never merged into the state one.
        assert_eq!(summary.coverage_edges, 0);
        assert_eq!(summary.coverage_blocks, 0);

        std::fs::remove_dir_all(&work_dir).ok();
    }

    #[test]
    fn summary_records_profile_hash_and_reset_fidelity() {
        let model = toy_model();
        let work_dir = tmp_work_dir("hash-fidelity");
        let cfg = config(&model, work_dir.clone(), 200);

        let mut service = ToyService::new();
        let summary = run_session_campaign(&model, &mut service, &cfg).unwrap();

        assert_eq!(summary.profile_sha256, model.profile_sha256());
        assert_eq!(summary.reset_fidelity, "scripted;reset=reconnect");
        assert_eq!(summary.transport, "scripted");
        assert_eq!(summary.engine, "session");

        std::fs::remove_dir_all(&work_dir).ok();
    }

    #[test]
    fn loop_is_bounded_by_time_and_findings() {
        let model = toy_model();

        // A zero-time budget stops before any execution.
        let work_dir = tmp_work_dir("zero-budget");
        let mut cfg = config(&model, work_dir.clone(), 10_000);
        cfg.time_budget = Some(Duration::from_secs(0));
        let mut service = ToyService::new();
        let summary = run_session_campaign(&model, &mut service, &cfg).unwrap();
        assert_eq!(summary.executions, 0, "zero-budget run does nothing");
        assert!(summary.findings.is_empty());
        std::fs::remove_dir_all(&work_dir).ok();

        // Stop as soon as the first distinct finding lands.
        let work_dir = tmp_work_dir("stop-after");
        let mut cfg = config(&model, work_dir.clone(), 10_000);
        cfg.stop_after_findings = Some(1);
        let mut service = ToyService::new();
        let summary = run_session_campaign(&model, &mut service, &cfg).unwrap();
        assert_eq!(
            summary.findings.len(),
            1,
            "exactly one finding: {summary:?}"
        );
        std::fs::remove_dir_all(&work_dir).ok();
    }

    #[test]
    fn campaign_reaches_boundary_and_writes_session_artifact() {
        // AC1/AC2 over the in-memory service: a fixed-seed, bounded campaign from
        // the ordinary valid OPEN,WRITE seed reaches the clean-exit boundary via
        // field mutation of the path, and the written finding carries the AC2
        // evidence plus the replay/minimize metadata sidecar.
        let model = toy_model();
        let work_dir = tmp_work_dir("artifact");
        let mut cfg = config(&model, work_dir.clone(), 8000);
        cfg.transport_label = "tcp:127.0.0.1:0".to_owned();
        cfg.transport_kind = "tcp".to_owned();
        cfg.stop_after_findings = Some(1);

        let mut service = ToyService::new();
        let summary = run_session_campaign(&model, &mut service, &cfg).unwrap();
        assert_eq!(
            summary.findings.len(),
            1,
            "the bounded campaign reached the boundary: {summary:?}"
        );
        assert_eq!(
            summary.crashes, 0,
            "the violation is clean-exit, not a crash"
        );

        let finding_dir = corpus::layout::finding_dir(&work_dir, &summary.findings[0]);
        assert!(is_session_finding(&finding_dir));

        let artifact =
            std::fs::read_to_string(finding_dir.join(SESSION_ARTIFACT)).expect("session.json");
        let testcase = SessionTestcase::from_json(&artifact).expect("parse session.json");
        assert!(testcase.messages.len() >= 2, "AC2: >= 2 messages");
        assert!(!testcase.state_path.is_empty(), "AC2: state path");
        assert!(
            testcase.captured_responses.iter().all(|r| !r.is_empty()),
            "AC2: captured replies"
        );
        assert!(
            testcase.bindings.contains("OPEN.response.handle"),
            "AC2: response-derived handle binding"
        );
        assert_eq!(testcase.profile_sha256, model.profile_sha256());

        let meta_json =
            std::fs::read_to_string(finding_dir.join(SESSION_META)).expect("session_meta.json");
        let meta: SessionArtifactMeta = serde_json::from_str(&meta_json).unwrap();
        assert_eq!(meta.schema, SESSION_ARTIFACT_SCHEMA);
        assert_eq!(meta.reset_fidelity, "tcp;reset=reconnect");
        assert_eq!(meta.profile_sha256, model.profile_sha256());
        // The metadata is self-contained: the profile round-trips.
        assert!(Profile::from_toml(&meta.profile_toml).is_ok());

        std::fs::remove_dir_all(&work_dir).ok();
    }

    // --- multi-oracle replay/minimize must honor the RECORDED oracle ---------
    //
    // A profile with two oracles over the same WRITE reply: O1 (status 0xE1) is
    // the real bug and only fires when a BUMP sits between OPEN and WRITE; O2
    // (status 0xE2) fires on a bare OPEN,WRITE. Replay/minimize of an O1 finding
    // must not treat an O2 firing as a reproduction.
    const MULTI_ORACLE: &str = r#"
schema = "bhf.protocol.v1"
start = "start"
transport = "tcp:127.0.0.1:0"

[[message]]
name = "OPEN"
[[message.field]]
name = "op"
type = "u8"
value = 1
[message.response]
[[message.response.capture]]
name = "ostatus"
type = "u8"
at = 0

[[message]]
name = "BUMP"
[[message.field]]
name = "op"
type = "u8"
value = 2
[message.response]
[[message.response.capture]]
name = "bstatus"
type = "u8"
at = 0

[[message]]
name = "WRITE"
[[message.field]]
name = "op"
type = "u8"
value = 3
[message.response]
[[message.response.capture]]
name = "wstatus"
type = "u8"
at = 0

[[transition]]
from = "start"
send = "OPEN"
to = "opened"
[[transition]]
from = "opened"
send = "BUMP"
to = "opened"
[[transition]]
from = "opened"
send = "WRITE"
to = "opened"

[[oracle]]
name = "O1"
rule_id = "R1"
message = "WRITE"
response_field = "wstatus"
equals = 225

[[oracle]]
name = "O2"
rule_id = "R2"
message = "WRITE"
response_field = "wstatus"
equals = 226
"#;

    /// An in-memory service for the multi-oracle profile. A WRITE returns the
    /// O1 status (0xE1) only when a BUMP preceded it this session; otherwise it
    /// returns the O2 status (0xE2). OPEN/BUMP return non-oracle status bytes.
    struct MultiOracleService {
        bumped: bool,
    }

    impl MultiOracleService {
        fn new() -> Self {
            Self { bumped: false }
        }
    }

    impl SessionTransport for MultiOracleService {
        fn send_request(&mut self, req: &[u8]) -> Result<Vec<u8>, TransportError> {
            match req.first().copied() {
                Some(1) => Ok(vec![0x10]),
                Some(2) => {
                    self.bumped = true;
                    Ok(vec![0x20])
                }
                Some(3) => Ok(vec![if self.bumped { 0xE1 } else { 0xE2 }]),
                _ => Ok(vec![0x01]),
            }
        }

        fn reset(&mut self) -> Result<(), TransportError> {
            self.bumped = false;
            Ok(())
        }
    }

    fn multi_oracle_model() -> ProtocolModel {
        ProtocolModel::from_profile(&Profile::from_toml(MULTI_ORACLE).expect("parse"))
            .expect("compile")
    }

    fn multi_oracle_meta(
        model: &ProtocolModel,
        oracle: &str,
        rule_id: &str,
    ) -> SessionArtifactMeta {
        SessionArtifactMeta {
            schema: SESSION_ARTIFACT_SCHEMA.to_owned(),
            profile_sha256: model.profile_sha256().to_owned(),
            profile_toml: MULTI_ORACLE.to_owned(),
            transport: "scripted".to_owned(),
            transport_kind: "scripted".to_owned(),
            reset: "reconnect".to_owned(),
            reset_fidelity: "scripted;reset=reconnect".to_owned(),
            rule_id: Some(rule_id.to_owned()),
            oracle: oracle.to_owned(),
        }
    }

    fn instance(model: &ProtocolModel, name: &str) -> protocol_session::MessageInstance {
        protocol_session::MessageInstance::from_seed(model.message(name).expect(name))
    }

    fn session_of(model: &ProtocolModel, names: &[&str]) -> SessionTestcase {
        SessionTestcase::from_messages(
            model.profile_sha256(),
            names.iter().map(|n| instance(model, n)).collect(),
        )
    }

    #[test]
    fn replay_requires_the_recorded_oracle_not_just_any_finding() {
        let model = multi_oracle_model();
        let meta = multi_oracle_meta(&model, "O1", "R1");

        // Recorded as O1, but re-driven without the BUMP the WRITE trips O2.
        // A different oracle firing must NOT count as reproducing the O1 finding.
        let drifted = session_of(&model, &["OPEN", "WRITE"]);
        let mut svc = MultiOracleService::new();
        assert!(
            !replay_reproduces(&model, &drifted, &meta, &mut svc).unwrap(),
            "O2 firing must not falsely confirm an O1 finding"
        );

        // Control: the O1-triggering sequence does still reproduce O1.
        let faithful = session_of(&model, &["OPEN", "BUMP", "WRITE"]);
        let mut svc = MultiOracleService::new();
        assert!(
            replay_reproduces(&model, &faithful, &meta, &mut svc).unwrap(),
            "the recorded O1 sequence must still reproduce O1"
        );

        // And if the recorded oracle really were O2, the drifted sequence is a
        // faithful reproduction — the gate is on identity, not strictness.
        let meta_o2 = multi_oracle_meta(&model, "O2", "R2");
        let mut svc = MultiOracleService::new();
        assert!(
            replay_reproduces(&model, &drifted, &meta_o2, &mut svc).unwrap(),
            "OPEN,WRITE legitimately reproduces an O2 finding"
        );
    }

    #[test]
    fn minimize_preserves_the_recorded_oracles_structure() {
        let model = multi_oracle_model();
        let meta = multi_oracle_meta(&model, "O1", "R1");

        // The O1 repro depends on the BUMP between OPEN and WRITE. Dropping it
        // leaves OPEN,WRITE, which trips O2 — an any-finding predicate would
        // happily shrink the BUMP away. Gating on the recorded oracle keeps it.
        let recorded = session_of(&model, &["OPEN", "BUMP", "WRITE"]);

        let (original_len, run, reproduces) =
            minimize_session_core(&model, &recorded, &meta, || {
                Ok::<_, String>(MultiOracleService::new())
            })
            .unwrap();

        assert_eq!(original_len, 3);
        assert!(reproduces, "the minimized sequence still reproduces O1");
        assert_eq!(
            run.testcase.message_names(),
            vec!["OPEN", "BUMP", "WRITE"],
            "minimize must keep the BUMP O1 depends on, not collapse to the O2 sequence"
        );
        assert!(
            matches!(&run.verdict, SessionVerdict::Finding { oracle, .. } if oracle == "O1"),
            "the preserved reproduction must be O1, got {:?}",
            run.verdict
        );
    }

    #[test]
    fn minimize_refuses_when_the_recorded_oracle_no_longer_reproduces() {
        let model = multi_oracle_model();
        // Recorded as O1, but the only sequence we hand minimize reproduces O2.
        let meta = multi_oracle_meta(&model, "O1", "R1");
        let drifted = session_of(&model, &["OPEN", "WRITE"]);
        let err = minimize_session_core(&model, &drifted, &meta, || {
            Ok::<_, String>(MultiOracleService::new())
        })
        .unwrap_err();
        assert!(
            err.contains("no longer reproduces"),
            "baseline must refuse to minimize a non-reproducing O1 finding, got {err:?}"
        );
    }
}
