// SPDX-License-Identifier: Apache-2.0

//! The supervised extension client.
//!
//! [`ExtensionClient`] spawns a trusted extension executable with a cleared,
//! explicitly allow-listed environment (plus `cfg(unix)` `setrlimit` hardening),
//! performs the handshake, and then drives `oracle.evaluate` with a per-call
//! deadline. Every crash, timeout, oversized/malformed response, mismatched case
//! identity, or `unsupported` reply is mapped to a bounded
//! [`EvaluateOutcome::Infrastructure`] / [`EvaluateOutcome::Unsupported`] — it is
//! impossible for such a fault to be reported as a target finding. A crash or
//! timeout triggers the [`RestartPolicy`]; once the restart budget is exhausted
//! the loss is terminal and a loss event is recorded in provenance.

use crate::codec::{self, DecodePayload, EncodePayload, RepairPayload};
use crate::envelope::{CaseId, FindingResult, Request, Response, ResultClass};
use crate::handshake::{negotiate, ExtHello, HostHello, Negotiated, WireLimits};
use crate::lifecycle::LifecyclePayload;
use crate::limits::{Limits, OutstandingGuard};
use crate::manifest::ExtensionManifest;
use crate::mutator::MutatePayload;
use crate::oracle::EvaluatePayload;
use crate::provenance::{
    hash_bytes, hash_file, redact_env, ExtensionProvenance, ProvLimits, RedactedEnv,
};
use crate::restart::{RestartPolicy, RestartState};
use crate::scenario::{NextValue, ObserveResponsePayload, ScenarioNextPayload};
use crate::wire::{read_frame, write_frame};
use crate::{capability, ExtensionError, Result, PROTOCOL};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

/// Child resource caps applied on unix via `setrlimit` in a `pre_exec` hook.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceLimits {
    /// `RLIMIT_AS` (address space) cap in bytes. `None` leaves it unconstrained.
    pub address_space_bytes: Option<u64>,
    /// `RLIMIT_CPU` cap in seconds. `None` leaves it unconstrained.
    pub cpu_seconds: Option<u64>,
}

/// Everything needed to spawn and supervise one extension.
#[derive(Debug, Clone)]
pub struct SpawnSpec {
    /// The resolved executable path.
    pub program: PathBuf,
    /// Fixed arguments.
    pub args: Vec<String>,
    /// Explicit environment to set (name -> value); the child's environment is
    /// cleared first.
    pub env: BTreeMap<String, String>,
    /// Host environment variable names to forward (values never recorded).
    pub env_passthrough: Vec<String>,
    /// Capabilities that MUST be negotiated.
    pub required_capabilities: Vec<String>,
    /// Capabilities used opportunistically.
    pub optional_capabilities: Vec<String>,
    /// Host-side wire/time/outstanding limits (the hard safety bound).
    pub limits: Limits,
    /// The crash/timeout restart policy.
    pub restart: RestartPolicy,
    /// Child resource caps (unix).
    pub resource_limits: ResourceLimits,
    /// The config/manifest path to hash into provenance, if any.
    pub config_path: Option<PathBuf>,
}

impl SpawnSpec {
    /// A spec for `program` with sane defaults (requires `oracle.evaluate`).
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
            env_passthrough: Vec::new(),
            required_capabilities: vec![capability::ORACLE_EVALUATE.to_string()],
            optional_capabilities: Vec::new(),
            limits: Limits::default(),
            restart: RestartPolicy::default(),
            resource_limits: ResourceLimits::default(),
            config_path: None,
        }
    }
}

/// A bounded extension-side failure. None of these can ever be reported as a
/// target finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InfraFailure {
    /// The extension did not respond within the per-call deadline; the child was
    /// killed.
    Timeout {
        /// The deadline that elapsed.
        after: Duration,
    },
    /// The extension process exited/crashed instead of responding.
    Crashed {
        /// The exit code, if the child exited normally with one.
        status: Option<i32>,
        /// The terminating signal, if any (unix).
        signal: Option<i32>,
    },
    /// The extension declared a frame larger than the host's hard cap; rejected
    /// before allocation and the child killed.
    FrameTooLarge {
        /// The declared length.
        declared: u64,
        /// The host's cap.
        cap: usize,
    },
    /// The response was not a valid envelope (bad framing, non-JSON, wrong
    /// schema, wrong protocol identifier).
    Protocol {
        /// A human-readable detail.
        detail: String,
    },
    /// The response echoed a case identity different from the request's. This is
    /// the guard that keeps two workers from ever mixing test-case identity.
    /// (Boxed to keep [`InfraFailure`] small.)
    CaseMismatch {
        /// The case the host sent.
        expected: Box<CaseId>,
        /// The case the extension echoed back.
        got: Box<CaseId>,
    },
    /// The extension explicitly returned `result: "infrastructure_error"`.
    ExtensionReported {
        /// The detail the extension supplied, if any.
        detail: Option<String>,
    },
}

/// The outcome of a single `oracle.evaluate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluateOutcome {
    /// The input was evaluated and is benign.
    Ok,
    /// The extension rejected the input (e.g. undecodable); drop it.
    Reject {
        /// The reason the extension gave, if any.
        detail: Option<String>,
    },
    /// The input triggered a semantic violation.
    Finding(Box<FindingResult>),
    /// The extension does not support the capability for this input/mode.
    Unsupported {
        /// The detail the extension supplied, if any.
        detail: Option<String>,
    },
    /// A bounded extension-side failure (never a target finding).
    Infrastructure(InfraFailure),
}

impl EvaluateOutcome {
    /// Whether this outcome is a bounded infrastructure/unsupported result (i.e.
    /// not a target-truth `ok`/`reject`/`finding`).
    pub fn is_infrastructure(&self) -> bool {
        matches!(
            self,
            EvaluateOutcome::Infrastructure(_) | EvaluateOutcome::Unsupported { .. }
        )
    }
}

/// The capability-generic outcome of a single request/response exchange. Every
/// typed capability method ([`ExtensionClient::evaluate`], [`decode`](ExtensionClient::decode),
/// [`mutate`](ExtensionClient::mutate), …) is a thin mapping over this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallOutcome {
    /// The call succeeded; `value` is the capability-specific output payload
    /// (`None` for capabilities that return no structured value, e.g. an oracle
    /// `ok`).
    Ok {
        /// The response `value` payload, if any.
        value: Option<serde_json::Value>,
    },
    /// The extension rejected the input for this capability (e.g. undecodable).
    Reject {
        /// The reason the extension gave, if any.
        detail: Option<String>,
    },
    /// A semantic finding (only `oracle.evaluate` produces this).
    Finding(Box<FindingResult>),
    /// The capability is not supported for this input/mode (bounded).
    Unsupported {
        /// The detail the extension supplied, if any.
        detail: Option<String>,
    },
    /// A bounded extension-side failure (never a target finding).
    Infrastructure(InfraFailure),
}

/// The outcome of a `codec.decode` / `codec.encode` / `codec.repair` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecOutcome {
    /// `codec.decode` succeeded: the extension-defined structured value.
    Decoded(serde_json::Value),
    /// `codec.encode` / `codec.repair` succeeded: the raw output bytes.
    Bytes(Vec<u8>),
    /// The extension could not decode/repair this input; drop it.
    Reject {
        /// The reason, if any.
        detail: Option<String>,
    },
    /// The capability is unsupported for this input (bounded).
    Unsupported {
        /// The detail, if any.
        detail: Option<String>,
    },
    /// A bounded extension-side failure (never a target finding).
    Infrastructure(InfraFailure),
}

/// The outcome of a `mutator.mutate` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutateOutcome {
    /// The extension produced a mutated input.
    Mutated(Vec<u8>),
    /// The extension declined to mutate this input; keep the original.
    Reject {
        /// The reason, if any.
        detail: Option<String>,
    },
    /// Mutation is unsupported for this input (bounded).
    Unsupported {
        /// The detail, if any.
        detail: Option<String>,
    },
    /// A bounded extension-side failure (never a target finding).
    Infrastructure(InfraFailure),
}

/// One message yielded by `scenario.next`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioMessage {
    /// The raw bytes to send to the target.
    pub bytes: Vec<u8>,
    /// An optional diagnostic label (e.g. `OPEN`, `WRITE`).
    pub label: Option<String>,
}

/// The outcome of a `scenario.next` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScenarioStep {
    /// The next message to send.
    Message(ScenarioMessage),
    /// The session has no further messages.
    Done,
    /// The extension rejected this step (bounded).
    Reject {
        /// The reason, if any.
        detail: Option<String>,
    },
    /// `scenario.next` is unsupported (bounded).
    Unsupported {
        /// The detail, if any.
        detail: Option<String>,
    },
    /// A bounded extension-side failure (never a target finding).
    Infrastructure(InfraFailure),
}

/// The outcome of a `scenario.observe-response` or `lifecycle.*` acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckOutcome {
    /// The extension acknowledged the call.
    Ok,
    /// The call is unsupported (bounded).
    Unsupported {
        /// The detail, if any.
        detail: Option<String>,
    },
    /// A bounded extension-side failure (never a target finding).
    Infrastructure(InfraFailure),
}

impl AckOutcome {
    /// Whether this is a bounded, non-success result.
    pub fn is_infrastructure(&self) -> bool {
        matches!(
            self,
            AckOutcome::Infrastructure(_) | AckOutcome::Unsupported { .. }
        )
    }
}

/// A live child + its frame reader thread.
struct Session {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<FrameEvent>,
    reader: Option<JoinHandle<()>>,
}

/// An event produced by the background frame reader.
enum FrameEvent {
    Frame(Vec<u8>),
    Closed,
    Error(ExtensionError),
}

/// What a bounded receive produced.
enum Received {
    Frame(Vec<u8>),
    Closed,
    Wire(ExtensionError),
    Timeout,
}

impl Session {
    fn recv(&self, timeout: Duration) -> Received {
        match self.rx.recv_timeout(timeout) {
            Ok(FrameEvent::Frame(bytes)) => Received::Frame(bytes),
            Ok(FrameEvent::Closed) => Received::Closed,
            Ok(FrameEvent::Error(err)) => Received::Wire(err),
            Err(RecvTimeoutError::Timeout) => Received::Timeout,
            Err(RecvTimeoutError::Disconnected) => Received::Closed,
        }
    }
}

impl Drop for Session {
    /// Best-effort reap so a dropped `Session` can never leak its child. This is
    /// the single kill+reap path — [`ExtensionClient::teardown_session`] drops the
    /// session to invoke it, and it also fires on a `Session` dropped via `?`
    /// (e.g. a failed re-handshake in [`ExtensionClient::restart_child`], or a
    /// failed handshake in [`ExtensionClient::spawn`]), which `std::process::Child`
    /// would otherwise leave running/unreaped (its own `Drop` neither kills nor
    /// waits). Reaping an already-reaped child (the crash path already called
    /// `wait`) is harmless: `std` caches the exit status, so a second `wait` never
    /// reaps a reused PID, and `kill` of an exited child errors benignly.
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
    }
}

/// A supervised, out-of-process extension speaking `bhf.extension.v1`.
pub struct ExtensionClient {
    spec: SpawnSpec,
    negotiated: Negotiated,
    limits: Limits,
    restart: RestartState,
    outstanding: OutstandingGuard,
    provenance: ExtensionProvenance,
    redacted: RedactedEnv,
    session: Option<Session>,
    last_digest: Option<String>,
    /// Set once the session is unrecoverably lost: a respawn/re-handshake failed,
    /// or the restart budget was exhausted. The session can never be
    /// re-established, so every subsequent call short-circuits to the terminal
    /// bounded infrastructure result instead of spawning another child per
    /// remaining restart slot (one failed re-handshake must not leak
    /// `max_restarts` more children).
    lost: bool,
}

impl ExtensionClient {
    /// Spawn and handshake with an extension from a fully-specified [`SpawnSpec`].
    pub fn spawn(spec: SpawnSpec) -> Result<Self> {
        let host_env: BTreeMap<String, String> = std::env::vars().collect();
        let redacted = redact_env(&spec.env_passthrough, &host_env);

        let executable_sha256 = hash_file(&spec.program)?;
        let config_sha256 = match &spec.config_path {
            Some(path) => Some(hash_file(path)?),
            None => None,
        };

        let mut session = spawn_session(&spec, &redacted)?;
        let host_hello = host_hello_from(&spec);
        let negotiated =
            handshake_over_session(&mut session, &host_hello, spec.limits.call_timeout)?;

        let provenance = ExtensionProvenance {
            executable_sha256,
            config_sha256,
            protocol_version: negotiated.protocol.clone(),
            negotiated_caps: negotiated.caps.clone(),
            env_allowlist: redacted.passed.keys().cloned().collect(),
            redacted_env: redacted.redacted.clone(),
            resource_limits: ProvLimits {
                address_space_bytes: spec.resource_limits.address_space_bytes,
                cpu_seconds: spec.resource_limits.cpu_seconds,
                max_frame_bytes: negotiated.limits.max_frame_bytes,
                call_timeout_ms: negotiated.limits.call_timeout_ms,
            },
            restart_count: 0,
            loss_count: 0,
        };

        let outstanding = OutstandingGuard::new(spec.limits.max_outstanding);
        let restart = RestartState::new(spec.restart);

        Ok(Self {
            limits: spec.limits,
            spec,
            negotiated,
            restart,
            outstanding,
            provenance,
            redacted,
            session: Some(session),
            last_digest: None,
            lost: false,
        })
    }

    /// Spawn and handshake from a loaded, validated trust manifest. The manifest
    /// path is hashed into provenance as the config hash.
    pub fn from_manifest(manifest: &ExtensionManifest, manifest_path: &Path) -> Result<Self> {
        Self::from_manifest_with_optional(manifest, manifest_path, &[])
    }

    /// Like [`from_manifest`](Self::from_manifest), but additionally requests
    /// `extra_optional` capabilities. The manifest's `required_capabilities`
    /// remain the hard gate; these are merely offered so a capability the
    /// extension provides is negotiated even if the manifest did not list it. A
    /// session-driving caller passes the session capability set here.
    pub fn from_manifest_with_optional(
        manifest: &ExtensionManifest,
        manifest_path: &Path,
        extra_optional: &[&str],
    ) -> Result<Self> {
        let manifest_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
        let program = manifest.resolve_executable(manifest_dir)?;
        let limits = Limits::from_wire(manifest.wire_limits(), manifest.max_outstanding());
        let resource_limits = ResourceLimits {
            address_space_bytes: manifest.limits.as_ref().and_then(|l| l.address_space_bytes),
            cpu_seconds: manifest.limits.as_ref().and_then(|l| l.cpu_seconds),
        };
        let mut optional_capabilities = manifest.optional_capabilities.clone();
        for cap in extra_optional {
            let cap = cap.to_string();
            if !manifest.required_capabilities.contains(&cap)
                && !optional_capabilities.contains(&cap)
            {
                optional_capabilities.push(cap);
            }
        }
        let spec = SpawnSpec {
            program,
            args: manifest.args.clone(),
            env: manifest.env.clone(),
            env_passthrough: manifest.env_passthrough.clone(),
            required_capabilities: manifest.required_capabilities.clone(),
            optional_capabilities,
            limits,
            restart: manifest.restart_policy(),
            resource_limits,
            config_path: Some(manifest_path.to_path_buf()),
        };
        Self::spawn(spec)
    }

    /// The negotiated session parameters.
    pub fn negotiated(&self) -> &Negotiated {
        &self.negotiated
    }

    /// The provenance record accumulated so far (restart/loss counts update as
    /// faults occur).
    pub fn provenance(&self) -> &ExtensionProvenance {
        &self.provenance
    }

    /// The per-case digest of the most recent response (result + finding +
    /// detail), used by replay to flag output divergence.
    pub fn last_case_digest(&self) -> Option<&str> {
        self.last_digest.as_deref()
    }

    /// Whether a capability was negotiated with the extension.
    pub fn supports(&self, capability: &str) -> bool {
        self.negotiated.caps.iter().any(|c| c == capability)
    }

    /// Evaluate one test input against the extension oracle, restarting a
    /// crashed/timed-out child within the restart budget.
    pub fn evaluate(&mut self, case: &CaseId, input: &[u8]) -> Result<EvaluateOutcome> {
        let payload = EvaluatePayload::from_input(input).to_value();
        Ok(evaluate_outcome_from(self.call(
            capability::ORACLE_EVALUATE,
            case,
            payload,
        )?))
    }

    /// `codec.decode`: turn a raw frame into the extension's structured value.
    pub fn decode(&mut self, case: &CaseId, raw: &[u8]) -> Result<CodecOutcome> {
        let out = self.call(
            capability::CODEC_DECODE,
            case,
            DecodePayload::from_input(raw).to_value(),
        )?;
        Ok(match out {
            CallOutcome::Ok { value } => match require_value(value, "codec.decode")
                .and_then(|v| crate::codec::DecodedValue::from_value(&v))
            {
                Ok(decoded) => CodecOutcome::Decoded(decoded.decoded),
                Err(err) => CodecOutcome::Infrastructure(InfraFailure::Protocol {
                    detail: err.to_string(),
                }),
            },
            other => codec_fault(other, "codec.decode"),
        })
    }

    /// `codec.encode`: turn a structured value back into raw bytes.
    pub fn encode(&mut self, case: &CaseId, decoded: serde_json::Value) -> Result<CodecOutcome> {
        let out = self.call(
            capability::CODEC_ENCODE,
            case,
            EncodePayload::new(decoded).to_value(),
        )?;
        Ok(self.codec_bytes_outcome(out, "codec.encode"))
    }

    /// `codec.repair`: recompute a (mutated) frame's computed fields.
    pub fn repair(&mut self, case: &CaseId, raw: &[u8]) -> Result<CodecOutcome> {
        let out = self.call(
            capability::CODEC_REPAIR,
            case,
            RepairPayload::from_input(raw).to_value(),
        )?;
        Ok(self.codec_bytes_outcome(out, "codec.repair"))
    }

    /// `mutator.mutate`: ask the extension for a structure-aware mutation.
    pub fn mutate(&mut self, case: &CaseId, raw: &[u8], seed: u64) -> Result<MutateOutcome> {
        let out = self.call(
            capability::MUTATOR_MUTATE,
            case,
            MutatePayload::from_input(raw, seed).to_value(),
        )?;
        Ok(match out {
            CallOutcome::Ok { value } => {
                match require_value(value, "mutator.mutate")
                    .and_then(|v| codec::output_bytes_from_value(&v))
                {
                    Ok(bytes) => MutateOutcome::Mutated(bytes),
                    Err(err) => MutateOutcome::Infrastructure(InfraFailure::Protocol {
                        detail: err.to_string(),
                    }),
                }
            }
            CallOutcome::Reject { detail } => MutateOutcome::Reject { detail },
            CallOutcome::Unsupported { detail } => MutateOutcome::Unsupported { detail },
            CallOutcome::Infrastructure(f) => MutateOutcome::Infrastructure(f),
            CallOutcome::Finding(_) => MutateOutcome::Infrastructure(InfraFailure::Protocol {
                detail: "mutator.mutate returned a finding".to_string(),
            }),
        })
    }

    /// `scenario.next`: get the next message in a multi-message session.
    pub fn scenario_next(&mut self, case: &CaseId, step: u32) -> Result<ScenarioStep> {
        self.scenario_next_payload(case, ScenarioNextPayload::new(step))
    }

    /// `scenario.next` carrying the session seed (first step), so the testcase
    /// drives the session content.
    pub fn scenario_next_seeded(
        &mut self,
        case: &CaseId,
        step: u32,
        seed: &[u8],
    ) -> Result<ScenarioStep> {
        self.scenario_next_payload(case, ScenarioNextPayload::with_seed(step, seed))
    }

    fn scenario_next_payload(
        &mut self,
        case: &CaseId,
        payload: ScenarioNextPayload,
    ) -> Result<ScenarioStep> {
        let out = self.call(capability::SCENARIO_NEXT, case, payload.to_value())?;
        Ok(match out {
            CallOutcome::Ok { value } => {
                match require_value(value, "scenario.next").and_then(|v| parse_next_value(&v)) {
                    Ok(step) => step,
                    Err(err) => ScenarioStep::Infrastructure(InfraFailure::Protocol {
                        detail: err.to_string(),
                    }),
                }
            }
            CallOutcome::Reject { detail } => ScenarioStep::Reject { detail },
            CallOutcome::Unsupported { detail } => ScenarioStep::Unsupported { detail },
            CallOutcome::Infrastructure(f) => ScenarioStep::Infrastructure(f),
            CallOutcome::Finding(_) => ScenarioStep::Infrastructure(InfraFailure::Protocol {
                detail: "scenario.next returned a finding".to_string(),
            }),
        })
    }

    /// `scenario.observe-response`: feed the target's response bytes back so the
    /// extension can bind a response-derived value into a later message.
    pub fn scenario_observe_response(
        &mut self,
        case: &CaseId,
        step: u32,
        response: &[u8],
    ) -> Result<AckOutcome> {
        let out = self.call(
            capability::SCENARIO_OBSERVE_RESPONSE,
            case,
            ObserveResponsePayload::new(step, response).to_value(),
        )?;
        Ok(ack_from(out, "scenario.observe-response"))
    }

    /// `lifecycle.setup`: set the session up before the first case.
    pub fn lifecycle_setup(&mut self, case: &CaseId, root: Option<&Path>) -> Result<AckOutcome> {
        let out = self.call(capability::LIFECYCLE_SETUP, case, lifecycle_payload(root))?;
        Ok(ack_from(out, "lifecycle.setup"))
    }

    /// `lifecycle.reset`: reset state with a fresh root between cases.
    pub fn lifecycle_reset(&mut self, case: &CaseId, root: &Path) -> Result<AckOutcome> {
        let out = self.call(
            capability::LIFECYCLE_RESET,
            case,
            LifecyclePayload::with_root(root).to_value(),
        )?;
        Ok(ack_from(out, "lifecycle.reset"))
    }

    /// `lifecycle.teardown`: tear the session down at the end.
    pub fn lifecycle_teardown(&mut self, case: &CaseId) -> Result<AckOutcome> {
        let out = self.call(
            capability::LIFECYCLE_TEARDOWN,
            case,
            LifecyclePayload::empty().to_value(),
        )?;
        Ok(ack_from(out, "lifecycle.teardown"))
    }

    /// Map an `ok`/bytes-bearing codec response into a [`CodecOutcome::Bytes`].
    fn codec_bytes_outcome(&self, out: CallOutcome, capability: &str) -> CodecOutcome {
        match out {
            CallOutcome::Ok { value } => {
                match require_value(value, capability)
                    .and_then(|v| codec::output_bytes_from_value(&v))
                {
                    Ok(bytes) => CodecOutcome::Bytes(bytes),
                    Err(err) => CodecOutcome::Infrastructure(InfraFailure::Protocol {
                        detail: err.to_string(),
                    }),
                }
            }
            other => codec_fault(other, capability),
        }
    }

    /// Drive one capability request/response exchange, restarting a
    /// crashed/timed-out child within the restart budget. The capability-generic
    /// core shared by every typed method.
    pub fn call(
        &mut self,
        capability: &str,
        case: &CaseId,
        payload: serde_json::Value,
    ) -> Result<CallOutcome> {
        let request = Request {
            protocol: self.negotiated.protocol.clone(),
            capability: capability.to_string(),
            case: case.clone(),
            payload,
        };

        loop {
            if self.lost {
                // A prior fault was terminal (restart budget exhausted, or a
                // respawn/re-handshake that could not recover). The session can
                // never come back, so short-circuit without spawning yet another
                // child: a persistently-failing re-handshake must leak at most one
                // child total, not one per remaining restart slot across the whole
                // evaluate loop.
                return Ok(terminal_crash());
            }
            if self.session.is_none() {
                if self.restart.should_restart() {
                    if self.restart_child().is_err() {
                        // A respawn / re-handshake failure during a permitted
                        // restart is TERMINAL: it is a bounded infrastructure
                        // result (a crash the host could not recover), never a
                        // target finding and never a hard error a caller would
                        // misclassify as a usage/setup problem. Record the loss,
                        // mark the session lost so no further respawn is attempted,
                        // and surface it as infrastructure.
                        self.lost = true;
                        self.restart.record_loss();
                        self.provenance.loss_count = self.restart.losses();
                        return Ok(terminal_crash());
                    }
                } else {
                    // No live session and no restart budget: terminal.
                    self.lost = true;
                    return Ok(terminal_crash());
                }
            }

            let outcome = self.try_call_once(&request)?;
            match &outcome {
                CallOutcome::Infrastructure(failure) if is_transport_fault(failure) => {
                    self.teardown_session();
                    if self.restart.should_restart() {
                        // Loop around; the top will record the restart + respawn
                        // and the same request is retried on the fresh child.
                        continue;
                    }
                    // Budget exhausted: this transport fault is terminal.
                    self.lost = true;
                    self.restart.record_loss();
                    self.provenance.loss_count = self.restart.losses();
                    return Ok(outcome);
                }
                _ => return Ok(outcome),
            }
        }
    }

    /// Explicitly tear down the child (also done on drop).
    pub fn shutdown(mut self) {
        self.teardown_session();
    }

    fn try_call_once(&mut self, request: &Request) -> Result<CallOutcome> {
        self.outstanding.acquire()?;
        let result = self.call_inner(request);
        self.outstanding.release();
        result
    }

    fn call_inner(&mut self, request: &Request) -> Result<CallOutcome> {
        let timeout = self.limits.call_timeout;
        let session = self
            .session
            .as_mut()
            .expect("call_inner called without a live session");

        let bytes = serde_json::to_vec(request)?;
        if write_frame(&mut session.stdin, &bytes).is_err() {
            // A broken pipe means the child died before/while reading.
            let infra = crash_from_child(&mut session.child);
            return Ok(CallOutcome::Infrastructure(infra));
        }

        match session.recv(timeout) {
            Received::Frame(frame) => {
                classify_response(request, &frame, &self.negotiated).map(|(outcome, digest)| {
                    self.last_digest = digest;
                    outcome
                })
            }
            Received::Closed => {
                let infra = crash_from_child(&mut session.child);
                Ok(CallOutcome::Infrastructure(infra))
            }
            Received::Wire(ExtensionError::FrameTooLarge { declared, cap }) => {
                let _ = session.child.kill();
                Ok(CallOutcome::Infrastructure(InfraFailure::FrameTooLarge {
                    declared,
                    cap,
                }))
            }
            Received::Wire(err) => {
                let _ = session.child.kill();
                Ok(CallOutcome::Infrastructure(InfraFailure::Protocol {
                    detail: err.to_string(),
                }))
            }
            Received::Timeout => {
                let _ = session.child.kill();
                Ok(CallOutcome::Infrastructure(InfraFailure::Timeout {
                    after: timeout,
                }))
            }
        }
    }

    /// Record a restart, wait the backoff, and respawn + re-handshake.
    fn restart_child(&mut self) -> Result<()> {
        let backoff = self.restart.record_restart();
        self.provenance.restart_count = self.restart.restarts();
        if !backoff.is_zero() {
            std::thread::sleep(backoff);
        }
        let mut session = spawn_session(&self.spec, &self.redacted)?;
        let host_hello = host_hello_from(&self.spec);
        // Re-handshake; a fresh child must still satisfy the required caps.
        let _ = handshake_over_session(&mut session, &host_hello, self.limits.call_timeout)?;
        self.session = Some(session);
        Ok(())
    }

    fn teardown_session(&mut self) {
        // Dropping the `Session` kills + reaps the child and joins the reader; see
        // `impl Drop for Session`. Keeping that logic in one place means a session
        // dropped on any path (teardown here, or a `?` early-return) is reaped the
        // same way.
        self.session = None;
    }
}

/// The terminal, bounded infrastructure outcome for a session that cannot be
/// recovered (no status/signal is available for a loss the host synthesizes).
fn terminal_crash() -> CallOutcome {
    CallOutcome::Infrastructure(InfraFailure::Crashed {
        status: None,
        signal: None,
    })
}

impl Drop for ExtensionClient {
    fn drop(&mut self) {
        self.teardown_session();
    }
}

/// Transport faults warrant a restart (the stream/child is unusable); an
/// extension-reported infrastructure error does not (the child is healthy).
fn is_transport_fault(failure: &InfraFailure) -> bool {
    matches!(
        failure,
        InfraFailure::Timeout { .. }
            | InfraFailure::Crashed { .. }
            | InfraFailure::FrameTooLarge { .. }
            | InfraFailure::Protocol { .. }
            | InfraFailure::CaseMismatch { .. }
    )
}

fn host_hello_from(spec: &SpawnSpec) -> HostHello {
    HostHello {
        protocol: PROTOCOL.to_string(),
        required_capabilities: spec.required_capabilities.clone(),
        optional_capabilities: spec.optional_capabilities.clone(),
        formats: vec!["json".to_string()],
        limits: WireLimits {
            max_frame_bytes: spec.limits.max_frame_bytes as u64,
            call_timeout_ms: spec.limits.call_timeout.as_millis() as u64,
        },
    }
}

/// Classify a response frame, returning the outcome and (for a well-formed
/// response) the per-case digest used for replay-divergence checks.
fn classify_response(
    request: &Request,
    bytes: &[u8],
    negotiated: &Negotiated,
) -> Result<(CallOutcome, Option<String>)> {
    let response: Response = match serde_json::from_slice(bytes) {
        Ok(response) => response,
        Err(err) => {
            return Ok((
                CallOutcome::Infrastructure(InfraFailure::Protocol {
                    detail: format!("response was not a valid envelope: {err}"),
                }),
                None,
            ));
        }
    };

    if response.protocol != negotiated.protocol {
        return Ok((
            CallOutcome::Infrastructure(InfraFailure::Protocol {
                detail: format!(
                    "response protocol {:?} does not match negotiated {:?}",
                    response.protocol, negotiated.protocol
                ),
            }),
            None,
        ));
    }

    if response.case != request.case {
        return Ok((
            CallOutcome::Infrastructure(InfraFailure::CaseMismatch {
                expected: Box::new(request.case.clone()),
                got: Box::new(response.case.clone()),
            }),
            None,
        ));
    }

    let digest = response_digest(&response);
    let outcome = match response.result {
        ResultClass::Ok => CallOutcome::Ok {
            value: response.value,
        },
        ResultClass::Reject => CallOutcome::Reject {
            detail: response.detail,
        },
        ResultClass::Unsupported => CallOutcome::Unsupported {
            detail: response.detail,
        },
        ResultClass::InfrastructureError => {
            CallOutcome::Infrastructure(InfraFailure::ExtensionReported {
                detail: response.detail,
            })
        }
        ResultClass::Finding => match response.finding {
            Some(finding) => CallOutcome::Finding(Box::new(finding)),
            None => CallOutcome::Infrastructure(InfraFailure::Protocol {
                detail: "result was \"finding\" but no finding payload was attached".to_string(),
            }),
        },
    };
    Ok((outcome, Some(digest)))
}

/// A stable digest of the response's *content* (result class, finding, value,
/// detail), independent of the request-specific case identity.
fn response_digest(response: &Response) -> String {
    let content = serde_json::json!({
        "result": response.result,
        "finding": response.finding,
        "value": response.value,
        "detail": response.detail,
    });
    hash_bytes(&serde_json::to_vec(&content).unwrap_or_default())
}

/// Map the capability-generic [`CallOutcome`] onto the oracle-specific
/// [`EvaluateOutcome`] (an oracle `ok` carries no `value`).
fn evaluate_outcome_from(outcome: CallOutcome) -> EvaluateOutcome {
    match outcome {
        CallOutcome::Ok { .. } => EvaluateOutcome::Ok,
        CallOutcome::Reject { detail } => EvaluateOutcome::Reject { detail },
        CallOutcome::Finding(finding) => EvaluateOutcome::Finding(finding),
        CallOutcome::Unsupported { detail } => EvaluateOutcome::Unsupported { detail },
        CallOutcome::Infrastructure(failure) => EvaluateOutcome::Infrastructure(failure),
    }
}

/// Require an `ok` response to carry a `value` payload, surfacing a bounded
/// protocol error if it did not.
fn require_value(value: Option<serde_json::Value>, capability: &str) -> Result<serde_json::Value> {
    value.ok_or_else(|| {
        ExtensionError::protocol(format!("{capability} ok response carried no value payload"))
    })
}

/// Map a non-`ok` [`CallOutcome`] to a [`CodecOutcome`] fault.
fn codec_fault(outcome: CallOutcome, capability: &str) -> CodecOutcome {
    match outcome {
        CallOutcome::Reject { detail } => CodecOutcome::Reject { detail },
        CallOutcome::Unsupported { detail } => CodecOutcome::Unsupported { detail },
        CallOutcome::Infrastructure(failure) => CodecOutcome::Infrastructure(failure),
        CallOutcome::Finding(_) => CodecOutcome::Infrastructure(InfraFailure::Protocol {
            detail: format!("{capability} returned a finding"),
        }),
        CallOutcome::Ok { .. } => CodecOutcome::Infrastructure(InfraFailure::Protocol {
            detail: format!("{capability} ok handled elsewhere"),
        }),
    }
}

/// Map a [`CallOutcome`] to an [`AckOutcome`] (for observe-response / lifecycle).
fn ack_from(outcome: CallOutcome, capability: &str) -> AckOutcome {
    match outcome {
        CallOutcome::Ok { .. } => AckOutcome::Ok,
        CallOutcome::Reject { detail } => AckOutcome::Unsupported { detail },
        CallOutcome::Unsupported { detail } => AckOutcome::Unsupported { detail },
        CallOutcome::Infrastructure(failure) => AckOutcome::Infrastructure(failure),
        CallOutcome::Finding(_) => AckOutcome::Infrastructure(InfraFailure::Protocol {
            detail: format!("{capability} returned a finding"),
        }),
    }
}

/// Build a `lifecycle.setup` payload (optional root).
fn lifecycle_payload(root: Option<&Path>) -> serde_json::Value {
    match root {
        Some(root) => LifecyclePayload::with_root(root).to_value(),
        None => LifecyclePayload::empty().to_value(),
    }
}

/// Parse a `scenario.next` response `value` into a [`ScenarioStep`].
fn parse_next_value(value: &serde_json::Value) -> Result<ScenarioStep> {
    let next: NextValue = serde_json::from_value(value.clone()).map_err(|e| {
        ExtensionError::protocol(format!("scenario.next value was not a NextValue: {e}"))
    })?;
    if next.done {
        return Ok(ScenarioStep::Done);
    }
    let encoded = next.message_b64.ok_or_else(|| {
        ExtensionError::protocol("scenario.next was not done but carried no message_b64")
    })?;
    let bytes = crate::b64::decode(&encoded).map_err(|e| {
        ExtensionError::protocol(format!(
            "scenario.next message_b64 was not valid base64: {e}"
        ))
    })?;
    Ok(ScenarioStep::Message(ScenarioMessage {
        bytes,
        label: next.label,
    }))
}

fn spawn_session(spec: &SpawnSpec, redacted: &RedactedEnv) -> Result<Session> {
    let mut command = Command::new(&spec.program);
    command.args(&spec.args);
    command.env_clear();
    for (name, value) in &spec.env {
        command.env(name, value);
    }
    for (name, value) in &redacted.passed {
        command.env(name, value);
    }
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::inherit());

    #[cfg(unix)]
    apply_rlimits(&mut command, spec.resource_limits);

    let mut child = command.spawn().map_err(|source| ExtensionError::Spawn {
        program: spec.program.display().to_string(),
        source,
    })?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| ExtensionError::protocol("extension child stdin was not captured"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ExtensionError::protocol("extension child stdout was not captured"))?;

    let (tx, rx) = mpsc::channel();
    let cap = spec.limits.max_frame_bytes;
    let reader = std::thread::Builder::new()
        .name("extension-reader".to_string())
        .spawn(move || reader_loop(stdout, cap, tx))
        .map_err(ExtensionError::Io)?;

    Ok(Session {
        child,
        stdin,
        rx,
        reader: Some(reader),
    })
}

fn reader_loop(mut stdout: impl Read, cap: usize, tx: Sender<FrameEvent>) {
    loop {
        match read_frame(&mut stdout, cap) {
            Ok(Some(frame)) => {
                if tx.send(FrameEvent::Frame(frame)).is_err() {
                    break;
                }
            }
            Ok(None) => {
                let _ = tx.send(FrameEvent::Closed);
                break;
            }
            Err(err) => {
                let _ = tx.send(FrameEvent::Error(err));
                break;
            }
        }
    }
}

fn handshake_over_session(
    session: &mut Session,
    host_hello: &HostHello,
    timeout: Duration,
) -> Result<Negotiated> {
    let bytes = serde_json::to_vec(host_hello)?;
    write_frame(&mut session.stdin, &bytes)
        .map_err(|err| ExtensionError::Handshake(format!("failed to send host hello: {err}")))?;

    match session.recv(timeout) {
        Received::Frame(frame) => {
            let ext: ExtHello = serde_json::from_slice(&frame).map_err(|err| {
                ExtensionError::Handshake(format!(
                    "extension hello was not a valid ExtHello: {err}"
                ))
            })?;
            negotiate(host_hello, &ext)
        }
        Received::Closed => Err(ExtensionError::Handshake(
            "extension closed the connection before sending its hello".to_string(),
        )),
        Received::Wire(err) => Err(ExtensionError::Handshake(format!(
            "wire error during handshake: {err}"
        ))),
        Received::Timeout => Err(ExtensionError::Handshake(
            "extension did not send its hello within the timeout".to_string(),
        )),
    }
}

fn crash_from_child(child: &mut Child) -> InfraFailure {
    match child.wait() {
        Ok(status) => {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                InfraFailure::Crashed {
                    status: status.code(),
                    signal: status.signal(),
                }
            }
            #[cfg(not(unix))]
            {
                InfraFailure::Crashed {
                    status: status.code(),
                    signal: None,
                }
            }
        }
        Err(_) => InfraFailure::Crashed {
            status: None,
            signal: None,
        },
    }
}

#[cfg(unix)]
fn apply_rlimits(command: &mut Command, limits: ResourceLimits) {
    use std::os::unix::process::CommandExt;

    if limits.address_space_bytes.is_none() && limits.cpu_seconds.is_none() {
        return;
    }
    let address_space_bytes = limits.address_space_bytes;
    let cpu_seconds = limits.cpu_seconds;

    // SAFETY: `pre_exec` runs in the forked child before `exec`. The closure
    // only calls `setrlimit`, which is async-signal-safe, and reads values
    // copied into the closure; it performs no allocation and touches no shared
    // state, so it is sound to run between fork and exec. The resource constant
    // is passed directly so its type is inferred per libc flavour (glibc/musl).
    unsafe {
        command.pre_exec(move || {
            if let Some(bytes) = address_space_bytes {
                let limit = libc::rlimit {
                    rlim_cur: bytes as libc::rlim_t,
                    rlim_max: bytes as libc::rlim_t,
                };
                if libc::setrlimit(libc::RLIMIT_AS, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if let Some(seconds) = cpu_seconds {
                let limit = libc::rlimit {
                    rlim_cur: seconds as libc::rlim_t,
                    rlim_max: seconds as libc::rlim_t,
                };
                if libc::setrlimit(libc::RLIMIT_CPU, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}
