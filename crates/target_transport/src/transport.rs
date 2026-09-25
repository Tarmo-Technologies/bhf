// SPDX-License-Identifier: Apache-2.0

//! The backend-agnostic execution seam.
//!
//! [`TargetTransport::arm`] prepares a target for a fuzzing session;
//! [`TargetSession::run_input`] delivers one input, triggers exactly one
//! execution, and returns coverage + status + faults as a [`RunOutcome`].
//!
//! The engine loop is factored so that the "run once + read coverage delta +
//! classify" span sits behind [`TargetSession::run_input`]. The existing
//! host/fork-server path can adopt this trait later (its `mmap`/`waitpid`
//! implementation moving verbatim into a `HostChildTransport`); new backends —
//! the on-target [`crate::agent`] protocol and the [`crate::gdb`] debug-probe
//! bridge — implement the same two methods and stay interchangeable.

use crate::error::Result;
use crate::outcome::RunOutcome;

/// A target that can be armed for fuzzing.
///
/// Arming is the once-per-session setup: connect the socket/serial link, attach
/// the debug probe, or record the child-spawn recipe. It yields a
/// [`TargetSession`] that runs individual inputs.
pub trait TargetTransport {
    /// Prepare a fresh session against the target.
    fn arm(&self) -> Result<Box<dyn TargetSession>>;
}

/// A live session against an armed target.
///
/// A session persists across inputs (like a fork server or a long-lived
/// on-target agent): each [`TargetSession::run_input`] is one execution and one
/// coverage round-trip.
pub trait TargetSession {
    /// Deliver `input`, run the target once, and return the outcome.
    fn run_input(&mut self, input: &[u8]) -> Result<RunOutcome>;
}
