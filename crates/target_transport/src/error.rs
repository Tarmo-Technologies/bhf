// SPDX-License-Identifier: Apache-2.0

//! Error type for the target-transport seam.
//!
//! Every fallible path returns a descriptive [`TransportError`]; nothing in
//! this crate signals failure with a bare `None` or a silently-empty result.

use std::io;

/// Convenience alias for the crate's fallible results.
pub type Result<T> = std::result::Result<T, TransportError>;

/// A failure while arming a target, running an input, or decoding a coverage
/// or debug-protocol stream.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// An underlying byte channel (socket, pipe, serial line, subprocess pipe)
    /// failed.
    #[error("target transport I/O error: {0}")]
    Io(#[from] io::Error),

    /// A framed message violated the protocol (bad status word, unexpected
    /// framing byte, truncated field, non-UTF-8 detail string, …).
    #[error("target transport protocol error: {0}")]
    Protocol(String),

    /// A length field on the wire exceeded the configured cap. Reported
    /// *before* any allocation so a malformed oversized length cannot drive an
    /// out-of-memory condition.
    #[error(
        "declared {field} length {declared} exceeds configured cap {cap} \
         (raise the limit only for a trusted channel)"
    )]
    LengthCap {
        /// Which field carried the oversized length (for diagnosis).
        field: &'static str,
        /// The length the peer declared.
        declared: u64,
        /// The cap the reader was configured with.
        cap: usize,
    },

    /// The `BHF_EVENTS` coverage/event stream failed to decode.
    #[error(transparent)]
    Event(#[from] event_log::EventReadError),

    /// The GDB remote serial protocol framing or exchange was malformed.
    #[error("gdb remote serial protocol error: {0}")]
    Gdb(String),

    /// The target (agent or gdbstub) returned a well-formed error response.
    #[error("target reported error: {0}")]
    TargetError(String),
}

impl TransportError {
    /// Build a [`TransportError::Protocol`] from any displayable value.
    pub(crate) fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }

    /// Build a [`TransportError::Gdb`] from any displayable value.
    pub(crate) fn gdb(message: impl Into<String>) -> Self {
        Self::Gdb(message.into())
    }
}
