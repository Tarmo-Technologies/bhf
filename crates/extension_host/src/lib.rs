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
//! The capability surface shipped here is [`capability::ORACLE_EVALUATE`]. The
//! `codec.*`, `mutator.mutate`, `scenario.*`, and `lifecycle.*` capabilities are
//! negotiated-but-deferred to follow-up work.

pub mod client;
pub mod envelope;
pub mod handshake;
pub mod limits;
pub mod manifest;
pub mod oracle;
pub mod provenance;
pub mod restart;
pub mod wire;

mod b64;

pub use client::{EvaluateOutcome, ExtensionClient, InfraFailure, ResourceLimits, SpawnSpec};
pub use envelope::{CaseId, Evidence, FindingResult, Request, Response, ResultClass};
pub use handshake::{negotiate, ExtHello, Format, HostHello, Negotiated, WireLimits};
pub use limits::{Limits, OutstandingGuard};
pub use manifest::ExtensionManifest;
pub use provenance::{hash_file, redact_env, ExtensionProvenance, RedactedEnv};
pub use restart::{RestartPolicy, RestartState};

/// The wire protocol identifier negotiated by this host.
pub const PROTOCOL: &str = "bhf.extension.v1";

/// Capability identifiers understood by this host.
pub mod capability {
    /// Evaluate a (clean-exiting) test input against a private semantic oracle.
    /// This is the only capability a host built from this crate drives today.
    pub const ORACLE_EVALUATE: &str = "oracle.evaluate";
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
