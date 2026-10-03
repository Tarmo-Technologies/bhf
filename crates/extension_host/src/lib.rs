// SPDX-License-Identifier: Apache-2.0

//! Host for the `bhf.extension.v1` versioned out-of-process extension protocol.
//!
//! This crate lets bhf start an *explicitly trusted*, out-of-process extension
//! executable, negotiate a protocol version and a set of capabilities before
//! any fuzzing work is driven across the wire, and then exchange length-framed
//! JSON request/response envelopes that each carry campaign/worker/testcase
//! identity. Every extension crash, timeout, oversized/malformed response, or
//! unsupported capability is turned into a **bounded infrastructure result**
//! that can never masquerade as a target vulnerability, and executable/config
//! hashes plus the negotiated capabilities are recorded in provenance.
//!
//! The crate is deliberately self-contained: it names no downstream consumer,
//! depends only on `serde`/`serde_json`/`sha2`/`thiserror`/`toml` (plus `libc`
//! on unix for child resource-limit hardening), and speaks a wire protocol that
//! can be re-implemented in any language (see the reference extension fixture).
//!
//! The full `bhf.extension.v1` capability surface is implemented here:
//! [`capability::ORACLE_EVALUATE`], the `codec.*` family
//! ([`capability::CODEC_DECODE`]/[`CODEC_ENCODE`](capability::CODEC_ENCODE)/
//! [`CODEC_REPAIR`](capability::CODEC_REPAIR)), [`capability::MUTATOR_MUTATE`],
//! the `scenario.*` family
//! ([`SCENARIO_NEXT`](capability::SCENARIO_NEXT)/[`SCENARIO_OBSERVE_RESPONSE`](capability::SCENARIO_OBSERVE_RESPONSE)),
//! and the `lifecycle.*` family
//! ([`LIFECYCLE_SETUP`](capability::LIFECYCLE_SETUP)/[`LIFECYCLE_RESET`](capability::LIFECYCLE_RESET)/[`LIFECYCLE_TEARDOWN`](capability::LIFECYCLE_TEARDOWN)).
//! Capability negotiation advertises the full set; an extension that declares
//! only a subset still works — the host drives exactly the capabilities both
//! sides agreed on. CBOR remains an optional, negotiated-but-unused wire format;
//! the host speaks JSON only.

pub mod client;
pub mod codec;
pub mod envelope;
pub mod handshake;
pub mod lifecycle;
pub mod limits;
pub mod manifest;
pub mod mutator;
pub mod oracle;
pub mod provenance;
pub mod restart;
pub mod scenario;
pub mod session;
pub mod wire;

mod b64;

pub use client::{
    AckOutcome, CallOutcome, CodecOutcome, EvaluateOutcome, ExtensionClient, InfraFailure,
    MutateOutcome, ResourceLimits, ScenarioMessage, ScenarioStep, SpawnSpec,
};
pub use codec::{DecodePayload, DecodedValue, EncodePayload, RepairPayload};
pub use envelope::{CaseId, Evidence, FindingResult, Request, Response, ResultClass};
pub use handshake::{negotiate, ExtHello, Format, HostHello, Negotiated, WireLimits};
pub use lifecycle::LifecyclePayload;
pub use limits::{Limits, OutstandingGuard};
pub use manifest::ExtensionManifest;
pub use mutator::MutatePayload;
pub use provenance::{hash_file, redact_env, ExtensionProvenance, RedactedEnv};
pub use restart::{RestartPolicy, RestartState};
pub use scenario::{ObserveResponsePayload, ScenarioNextPayload};
pub use session::{
    SessionDriver, SessionOptions, SessionOutcome, SessionStepRecord, SessionTarget,
};

/// The wire protocol identifier negotiated by this host.
pub const PROTOCOL: &str = "bhf.extension.v1";

/// Capability identifiers understood by this host.
pub mod capability {
    /// Evaluate a (clean-exiting) test input against a private semantic oracle.
    pub const ORACLE_EVALUATE: &str = "oracle.evaluate";
    /// Decode a raw frame into a structured value.
    pub const CODEC_DECODE: &str = "codec.decode";
    /// Encode a structured value back into a raw frame.
    pub const CODEC_ENCODE: &str = "codec.encode";
    /// Repair a (mutated) raw frame's computed fields (length, checksum).
    pub const CODEC_REPAIR: &str = "codec.repair";
    /// Produce a custom mutation of a decoded test input.
    pub const MUTATOR_MUTATE: &str = "mutator.mutate";
    /// Yield the next message in a multi-message session.
    pub const SCENARIO_NEXT: &str = "scenario.next";
    /// Feed a target's response bytes back so the extension can bind a
    /// response-derived value into a later message.
    pub const SCENARIO_OBSERVE_RESPONSE: &str = "scenario.observe-response";
    /// Set a session up before the first case.
    pub const LIFECYCLE_SETUP: &str = "lifecycle.setup";
    /// Reset state (e.g. a fresh temp root) between cases.
    pub const LIFECYCLE_RESET: &str = "lifecycle.reset";
    /// Tear a session down at the end.
    pub const LIFECYCLE_TEARDOWN: &str = "lifecycle.teardown";

    /// Every capability this host can drive, in a stable order (used to build the
    /// host hello's optional-capability set so a subset-declaring extension still
    /// negotiates cleanly).
    pub const ALL: &[&str] = &[
        ORACLE_EVALUATE,
        CODEC_DECODE,
        CODEC_ENCODE,
        CODEC_REPAIR,
        MUTATOR_MUTATE,
        SCENARIO_NEXT,
        SCENARIO_OBSERVE_RESPONSE,
        LIFECYCLE_SETUP,
        LIFECYCLE_RESET,
        LIFECYCLE_TEARDOWN,
    ];
}

/// The crate's fallible result alias.
pub type Result<T> = std::result::Result<T, ExtensionError>;

/// A failure while loading a manifest, spawning an extension, negotiating the
/// protocol, or exchanging frames.
///
/// Per-call faults that must stay *bounded* (a crash, a timeout, an oversized or
/// malformed response, an `unsupported` reply) are **not** modelled here — they
/// surface as an [`crate::client::EvaluateOutcome::Infrastructure`] /
/// [`crate::client::EvaluateOutcome::Unsupported`] so they can never be confused
/// with a target finding. This type is for setup/handshake errors that abort
/// before any case is driven.
#[derive(Debug, thiserror::Error)]
pub enum ExtensionError {
    /// An underlying byte channel (a subprocess pipe) failed.
    #[error("extension I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A framed message violated the wire protocol (truncated field, wrong
    /// framing, non-JSON body).
    #[error("extension protocol error: {0}")]
    Protocol(String),

    /// A declared frame length exceeded the configured cap. Reported *before*
    /// any allocation so a malformed oversized length cannot drive bhf
    /// out-of-memory.
    #[error(
        "declared frame length {declared} exceeds configured cap {cap} \
         (frame rejected before allocation)"
    )]
    FrameTooLarge {
        /// The length the extension declared in the frame header.
        declared: u64,
        /// The cap the reader was configured with.
        cap: usize,
    },

    /// A JSON payload failed to (de)serialize against the envelope schema.
    #[error("extension JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// The extension offered a protocol identifier the host does not speak.
    #[error("protocol version mismatch: host speaks {expected}, extension offered {got}")]
    ProtocolVersion {
        /// The protocol identifier this host speaks.
        expected: String,
        /// The identifier the extension offered during the handshake.
        got: String,
    },

    /// The extension did not advertise one or more *required* capabilities, so
    /// the campaign must not start.
    #[error("extension is missing required capabilities: {}", .missing.join(", "))]
    CapabilityUnsatisfied {
        /// The required capabilities the extension failed to provide, sorted.
        missing: Vec<String>,
    },

    /// The host and the extension share no common wire format.
    #[error("no common wire format (host offered [{}], extension offered [{}])", .host.join(", "), .ext.join(", "))]
    NoCommonFormat {
        /// The formats the host advertised.
        host: Vec<String>,
        /// The formats the extension advertised.
        ext: Vec<String>,
    },

    /// More requests were issued concurrently than the negotiated outstanding
    /// cap permits.
    #[error("too many outstanding extension requests (cap {max})")]
    OutstandingLimit {
        /// The configured outstanding-request cap.
        max: usize,
    },

    /// An extension trust manifest was malformed, incomplete, unsafe, or failed
    /// its `requires-bhf` version gate.
    #[error("extension manifest error: {0}")]
    Manifest(String),

    /// The extension executable could not be spawned.
    #[error("failed to spawn extension executable {program}: {source}")]
    Spawn {
        /// The program path the host attempted to execute.
        program: String,
        /// The underlying spawn error.
        source: std::io::Error,
    },

    /// The handshake exchange failed before a usable session was established.
    #[error("extension handshake failed: {0}")]
    Handshake(String),
}

impl ExtensionError {
    /// Build an [`ExtensionError::Protocol`] from any displayable value.
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }

    /// Build an [`ExtensionError::Manifest`] from any displayable value.
    pub fn manifest(message: impl Into<String>) -> Self {
        Self::Manifest(message.into())
    }
}
