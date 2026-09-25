// SPDX-License-Identifier: Apache-2.0

//! Backend-neutral result of running one input against a target.
//!
//! [`RunOutcome`] is what every [`crate::TargetSession`] returns, regardless of
//! whether the target ran as a host child process, an on-target agent over a
//! serial/TCP link, or an emulator/debug-probe. The [`Fault`] taxonomy here is
//! a deliberately minimal placeholder: HDF-2 replaces [`FaultKind`] with the
//! full CPU-exception / MMU / watchdog taxonomy. New variants must extend
//! [`FaultKind`] (and its wire mapping in [`FaultKind::from_wire`] /
//! [`FaultKind::to_wire`]) without repurposing the reserved codes `0..=5`.

/// How a single execution terminated.
///
/// This is intentionally coarse. Fine-grained fault classification lives in
/// [`Fault`] / [`FaultKind`] so that the exit signal (did it crash at all?) is
/// decoupled from *why* it crashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitKind {
    /// The target completed the input without a fault.
    Ok,
    /// The target faulted (host signal, on-target CPU exception, sanitizer
    /// abort, …). The accompanying [`RunOutcome::fault`] carries detail when
    /// the backend can supply it.
    Crash,
    /// The target did not complete within the backend's per-input deadline.
    Timeout,
}

/// A minimal, backend-neutral fault classification.
///
/// The wire codes are stable and shared with the on-target agent protocol
/// (see [`crate::agent`]). Codes `0..=5` are reserved for the variants below;
/// any other code round-trips through [`FaultKind::Other`] so an unrecognized
/// fault is never silently dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    /// A CPU exception vector fired (undefined instruction, illegal op, …).
    CpuException,
    /// An MMU/MPU access-protection trap.
    MemoryProtection,
    /// A watchdog or reset controller tripped.
    Watchdog,
    /// A language-level assertion, panic, or `abort()`.
    AssertionPanic,
    /// A stack-overflow or guard-region violation.
    StackOverflow,
    /// The execution exceeded a hard real-time / watchdog deadline.
    Timeout,
    /// A fault code outside the reserved range, preserved verbatim so HDF-2 can
    /// classify it later without losing information.
    Other(u32),
}

impl FaultKind {
    /// Decode a fault kind from its 32-bit wire code.
    pub fn from_wire(code: u32) -> Self {
        match code {
            0 => Self::CpuException,
            1 => Self::MemoryProtection,
            2 => Self::Watchdog,
            3 => Self::AssertionPanic,
            4 => Self::StackOverflow,
            5 => Self::Timeout,
            other => Self::Other(other),
        }
    }

    /// Encode a fault kind to its 32-bit wire code. Inverse of
    /// [`FaultKind::from_wire`] for every value.
    pub fn to_wire(self) -> u32 {
        match self {
            Self::CpuException => 0,
            Self::MemoryProtection => 1,
            Self::Watchdog => 2,
            Self::AssertionPanic => 3,
            Self::StackOverflow => 4,
            Self::Timeout => 5,
            Self::Other(code) => code,
        }
    }
}

/// A structured fault report.
///
/// `address` is `Some` when the backend can attribute a faulting address (the
/// on-target agent protocol always carries an address word; host-signal
/// backends generally cannot and report `None`). `detail` is free-form context
/// (a signal name, an exception mnemonic, a decoded register snapshot summary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    /// The fault classification.
    pub kind: FaultKind,
    /// The faulting address, if the backend attributed one.
    pub address: Option<u64>,
    /// Human-readable context; may be empty.
    pub detail: String,
}

impl Fault {
    /// Construct a fault with the given kind and no address/detail.
    pub fn new(kind: FaultKind) -> Self {
        Self {
            kind,
            address: None,
            detail: String::new(),
        }
    }
}

/// The result of one [`crate::TargetSession::run_input`] execution.
///
/// `coverage_edges` are `u32` edge ids matching BHF's existing edge model
/// (breadcrumb ids from the instrumentation; see [`crate::coverage`]).
/// `stdout` is populated by backends that own a stdout channel (the host child
/// backend); channel-only backends such as the agent protocol leave it empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutcome {
    /// How the execution terminated.
    pub exit: ExitKind,
    /// Coverage edge ids observed on this execution, in emission order.
    pub coverage_edges: Vec<u32>,
    /// A structured fault, when one was detected.
    pub fault: Option<Fault>,
    /// Captured stdout, for backends that expose one.
    pub stdout: Vec<u8>,
}

impl RunOutcome {
    /// A clean run with the given coverage and no fault or stdout.
    pub fn clean(coverage_edges: Vec<u32>) -> Self {
        Self {
            exit: ExitKind::Ok,
            coverage_edges,
            fault: None,
            stdout: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_kind_wire_round_trips_named_variants() {
        for kind in [
            FaultKind::CpuException,
            FaultKind::MemoryProtection,
            FaultKind::Watchdog,
            FaultKind::AssertionPanic,
            FaultKind::StackOverflow,
            FaultKind::Timeout,
        ] {
            assert_eq!(FaultKind::from_wire(kind.to_wire()), kind);
        }
    }

    #[test]
    fn fault_kind_preserves_unknown_wire_code() {
        // A code outside the reserved range must survive the round trip
        // verbatim, not collapse to a catch-all sentinel.
        assert_eq!(FaultKind::from_wire(9), FaultKind::Other(9));
        assert_eq!(FaultKind::Other(9).to_wire(), 9);
        assert_eq!(FaultKind::from_wire(u32::MAX), FaultKind::Other(u32::MAX));
    }

    #[test]
    fn reserved_codes_never_decode_to_other() {
        for code in 0..=5u32 {
            assert!(!matches!(FaultKind::from_wire(code), FaultKind::Other(_)));
        }
    }
}
