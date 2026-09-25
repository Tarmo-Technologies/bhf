// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

//! Backend-agnostic target-execution seam for BHF (HDF-1, "the back half").
//!
//! BHF's engine loop is: publish an input, run the target once, read the
//! coverage delta, classify. Today that span is hardcoded to a host child
//! process (`command.spawn()`, stdin/stdout pipes, `mmap(BHF_COV_SHM)`,
//! `waitpid`), so a VxWorks image, a Cortex-M board, or a `qemu-system` guest
//! cannot be fuzzed with feedback. This crate factors "run once + read coverage
//! + classify" behind a single trait so the engine stays backend-neutral.
//!
//! # The seam
//!
//! * [`TargetTransport::arm`] prepares a session; [`TargetSession::run_input`]
//!   delivers one input and returns a [`RunOutcome`] (`exit`, `coverage_edges`,
//!   `fault`, `stdout`).
//!
//! # Backends in this crate
//!
//! * [`agent::AgentTransport`] — an on-target agent over a framed protocol on
//!   any `Read + Write` channel (TCP / serial / stdio).
//! * [`gdb::GdbRemoteTransport`] — a GDB remote serial protocol client for a
//!   debug probe / emulator gdbstub, reading the coverage ring back out of
//!   target memory.
//! * [`fullsystem::FullSystemTransport`] (HDF-4) — a full-system / snapshot
//!   backend over `qemu-system-*`: a [`fullsystem::QmpClient`] drives the
//!   snapshot lifecycle (`qmp_capabilities`, `stop`, `savevm`/`loadvm`) while
//!   the [`gdb::GdbClient`] delivers input, runs, and reads the coverage ring.
//! * [`host::HostChildTransport`] (Unix) — a self-contained reference host
//!   backend (spawn child, feed stdin, map exit/signal). It collects no
//!   coverage; adopting the production `mmap`/fork-server coverage path is a
//!   separate supervised follow-up.
//!
//! # Coverage readers
//!
//! [`coverage::SemihostingReader`] and [`coverage::MemoryBufferReader`] decode
//! the `BHF_EVENTS` tag-length edge/event stream that the existing Ada runtime
//! emitters already produce (`ada_runtime/adafuzz-probe-{semihosting,memory_buffer}.adb`),
//! reusing [`event_log`]'s reader as the wire-format source of truth.
//!
//! # Test support
//!
//! [`testsupport`] provides in-process mocks ([`testsupport::MockAgent`],
//! [`testsupport::MockGdbStub`], an in-memory [`testsupport::duplex`]) so every
//! backend is exercised end-to-end with no hardware.

pub mod agent;
pub mod coverage;
pub mod error;
pub mod fullsystem;
pub mod gdb;
pub mod outcome;
pub mod testsupport;
pub mod transport;
mod wire;

#[cfg(unix)]
pub mod host;

pub use agent::{AgentLimits, AgentSession, AgentTransport};
pub use coverage::{edges_from_events, MemoryBufferReader, SemihostingReader};
pub use error::{Result, TransportError};
pub use fullsystem::{FullSystemSession, FullSystemTransport, QmpClient, QmpLimits};
pub use gdb::{
    read_coverage_ring, GdbClient, GdbConnection, GdbMemoryMap, GdbRemoteTransport, GdbSession,
    StopReply,
};
pub use outcome::{ExitKind, Fault, FaultKind, RunOutcome};
pub use transport::{TargetSession, TargetTransport};

#[cfg(unix)]
pub use host::HostChildTransport;
