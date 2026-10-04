// SPDX-License-Identifier: Apache-2.0

//! Full-system / snapshot transport over `qemu-system-*` (HDF-4).
//!
//! HDF-4 fuzzes code that only runs meaningfully in a privileged / full-system
//! context — RTOS images, BSPs, drivers, ISRs — by driving a `qemu-system-*`
//! guest with snapshot/reset between iterations. [`FullSystemTransport`] is the
//! [`crate::TargetTransport`] impl for that lane; it composes two links QEMU
//! already exposes:
//!
//! * a **QMP client** ([`QmpClient`]) — QEMU Machine Protocol, line-delimited
//!   JSON over a socket. Used for the snapshot lifecycle: the `qmp_capabilities`
//!   handshake, `stop` (quiesce the vCPUs so a restore is coherent), and
//!   `human-monitor-command` running `savevm`/`loadvm` to save the baseline and
//!   reset to it each iteration.
//! * the existing **GDB remote client** ([`crate::gdb::GdbClient`]) — used for
//!   run control (`c` → a stop reply that classifies the run) and for reading
//!   the coverage ring back out of guest memory via
//!   [`crate::gdb::read_coverage_ring`] / [`crate::coverage::MemoryBufferReader`],
//!   and for staging the input into a guest memory region.
//!
//! # The snapshot/reset state machine
//!
//! ```text
//! arm():   QMP connect + qmp_capabilities
//!          GDB attach
//!          QMP stop                       (quiesce before the baseline)
//!          QMP savevm <tag>               (baseline snapshot)
//!
//! run_input(input):
//!          QMP stop                       (pause vCPUs for a coherent restore)
//!          QMP loadvm <tag>               (reset to the baseline — THE reset;
//!                                          replaces gdb's unreliable `R`)
//!          GDB write_memory(input_addr, input)   (deliver the input)
//!          GDB c                          (run to the harness end breakpoint)
//!          GDB read coverage ring         (MemoryBufferReader → edges)
//!          classify (stop reply → ExitKind + coarse Fault)
//! ```
//!
//! Determinism follows from the snapshot reset: every iteration starts from the
//! identical baseline, so the same input yields the same coverage.
//!
//! # Bounding
//!
//! Every QMP read is bounded ([`QmpLimits`]): a message line is capped before it
//! can grow without limit, and the number of asynchronous events skipped while
//! waiting for a command response is capped, so a hostile or wedged monitor is a
//! descriptive error, never an allocation bomb or an unbounded spin. The GDB
//! memory reads are bounded by [`crate::gdb::GdbClient::read_memory`].
//!
//! # What is gated
//!
//! The live path — an actual `qemu-system-*` process with a QMP socket and a
//! gdbstub, restoring a real image snapshot — is a DEPENDENCY (emulator + a
//! lawfully-obtained image) and is **not** run in CI. Everything in this module
//! is unit-tested against the in-process scripted QMP + gdbstub mocks in
//! [`crate::testsupport`] ([`crate::testsupport::MockQmpServer`],
//! [`crate::testsupport::MockGdbStub`]); the live emulator run is unproven until
//! executed against the real resource (roadmap HDF-4 gated acceptance).
//!
//! # Renode (documented follow-up)
//!
//! A Renode board is a `.resc` script that instantiates the platform and can
//! expose a GDB server (`machine StartGdbServer`), so the *same* [`GdbClient`] +
//! [`MemoryBufferReader`](crate::coverage::MemoryBufferReader) read the coverage
//! ring, and Renode's `Save`/`Load` state serialization plays the snapshot role
//! that `savevm`/`loadvm` play here. What differs is the control channel:
//! Renode's monitor is a line-oriented telnet CLI, **not** QMP, so a
//! `RenodeTransport` needs a small monitor adapter in place of [`QmpClient`]
//! (`Save @snap`, `Load @snap` instead of `savevm`/`loadvm`). That adapter is a
//! deliberate follow-up rather than part of this change: shipping it without a
//! Renode instance to test against would be untested integration, which the
//! roadmap forbids. The transport seam and the coverage reader it would reuse
//! are already in place, so the follow-up is additive.

use crate::error::{Result, TransportError};
use crate::gdb::{read_coverage_ring, ContStop, GdbClient, GdbMemoryMap};
use crate::outcome::{ExitKind, Fault, FaultKind, RunOutcome};
use crate::transport::{TargetSession, TargetTransport};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

/// Bounds on inbound QMP reads, enforced before any large allocation or an
/// unbounded wait.
#[derive(Debug, Clone, Copy)]
pub struct QmpLimits {
    /// Cap on a single QMP message (one JSON line). A message longer than this
    /// is a descriptive error, reported *before* the buffer can grow further.
    pub max_message_bytes: usize,
    /// Cap on how many asynchronous events may be skipped while waiting for a
    /// command's `return`/`error`. A monitor that only ever emits events is a
    /// descriptive error rather than an infinite loop.
    pub max_events_before_response: usize,
}

impl Default for QmpLimits {
    fn default() -> Self {
        Self {
            // 1 MiB is far larger than any real QMP control message (savevm /
            // loadvm returns are tiny) yet still a hard ceiling.
            max_message_bytes: 1024 * 1024,
            max_events_before_response: 4096,
        }
    }
}

/// A QMP (QEMU Machine Protocol) client over any byte channel.
///
/// QMP frames are complete JSON objects, one per line, terminated by `\r\n` (a
/// bare `\n` is also accepted). The server opens with a greeting object carrying
/// a top-level `"QMP"` key; [`QmpClient::connect`] consumes it and negotiates
/// `qmp_capabilities` before any other command is legal.
pub struct QmpClient<C> {
    channel: C,
    limits: QmpLimits,
}

impl<C: Read + Write> QmpClient<C> {
    /// Wrap a channel with default [`QmpLimits`].
    pub fn new(channel: C) -> Self {
        Self {
            channel,
            limits: QmpLimits::default(),
        }
    }

    /// Wrap a channel with explicit limits.
    pub fn with_limits(channel: C, limits: QmpLimits) -> Self {
        Self { channel, limits }
    }

    /// Read one byte, distinguishing a clean EOF (`Ok(None)`) from a live byte.
    fn read_byte(&mut self) -> Result<Option<u8>> {
        let mut buf = [0_u8; 1];
        match self.channel.read(&mut buf)? {
            0 => Ok(None),
            _ => Ok(Some(buf[0])),
        }
    }

    /// Read one `\n`-terminated line, bounded by `max_message_bytes`, with the
    /// trailing `\r?\n` stripped. A clean EOF before any byte is a descriptive
    /// error (the monitor closed the link).
    fn read_line(&mut self) -> Result<Vec<u8>> {
        let mut line = Vec::new();
        loop {
            match self.read_byte()? {
                None => {
                    if line.is_empty() {
                        return Err(TransportError::protocol(
                            "QMP link closed while awaiting a message",
                        ));
                    }
                    return Err(TransportError::protocol(
                        "QMP link closed mid-message (no line terminator)",
                    ));
                }
                Some(b'\n') => {
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                    return Ok(line);
                }
                Some(byte) => {
                    if line.len() >= self.limits.max_message_bytes {
                        return Err(TransportError::protocol(format!(
                            "QMP message exceeded {} byte cap",
                            self.limits.max_message_bytes
                        )));
                    }
                    line.push(byte);
                }
            }
        }
    }

    /// Read and JSON-parse one QMP message.
    fn read_message(&mut self) -> Result<Value> {
        let line = self.read_line()?;
        serde_json::from_slice(&line).map_err(|error| {
            TransportError::protocol(format!(
                "QMP message is not valid JSON ({error}): {:?}",
                String::from_utf8_lossy(&line)
            ))
        })
    }

    /// Serialize and send one QMP request object, newline-terminated.
    fn send(&mut self, request: &Value) -> Result<()> {
        let mut bytes = serde_json::to_vec(request).map_err(|error| {
            TransportError::protocol(format!("failed to encode QMP request: {error}"))
        })?;
        bytes.push(b'\n');
        self.channel.write_all(&bytes)?;
        self.channel.flush()?;
        Ok(())
    }

    /// Perform the QMP handshake: consume the greeting, then negotiate
    /// `qmp_capabilities`. Must be called once before any other command.
    pub fn connect(&mut self) -> Result<()> {
        let greeting = self.read_message()?;
        if greeting.get("QMP").is_none() {
            return Err(TransportError::protocol(format!(
                "QMP greeting is missing its \"QMP\" object: {greeting}"
            )));
        }
        self.execute("qmp_capabilities", None)?;
        Ok(())
    }

    /// Execute a QMP command and return its `return` value.
    ///
    /// Asynchronous `event` messages that arrive before the response are skipped
    /// (bounded by [`QmpLimits::max_events_before_response`]); an `error` object
    /// becomes a [`TransportError::TargetError`].
    pub fn execute(&mut self, command: &str, arguments: Option<Value>) -> Result<Value> {
        let mut request = json!({ "execute": command });
        if let Some(arguments) = arguments {
            request["arguments"] = arguments;
        }
        self.send(&request)?;

        let mut events_skipped = 0_usize;
        loop {
            let message = self.read_message()?;
            if message.get("event").is_some() {
                events_skipped += 1;
                if events_skipped > self.limits.max_events_before_response {
                    return Err(TransportError::protocol(format!(
                        "QMP emitted more than {} events without a response to {command:?}",
                        self.limits.max_events_before_response
                    )));
                }
                continue;
            }
            if let Some(error) = message.get("error") {
                let desc = error
                    .get("desc")
                    .and_then(Value::as_str)
                    .unwrap_or("(no desc)");
                return Err(TransportError::TargetError(format!(
                    "QMP command {command:?} failed: {desc}"
                )));
            }
            if let Some(value) = message.get("return") {
                return Ok(value.clone());
            }
            return Err(TransportError::protocol(format!(
                "QMP response to {command:?} has neither \"return\" nor \"error\": {message}"
            )));
        }
    }

    /// `stop`: pause the vCPUs (idempotent; required for a coherent `loadvm`).
    pub fn stop(&mut self) -> Result<()> {
        self.execute("stop", None).map(|_| ())
    }

    /// `cont`: resume the vCPUs. Provided for callers that drive run control over
    /// QMP; the [`FullSystemSession`] loop instead steps the guest through the
    /// GDB `c` path so it gets a deterministic stop reply.
    pub fn cont(&mut self) -> Result<()> {
        self.execute("cont", None).map(|_| ())
    }

    /// Run a human-monitor (HMP) command line and return its text output.
    pub fn human_monitor_command(&mut self, command_line: &str) -> Result<String> {
        let value = self.execute(
            "human-monitor-command",
            Some(json!({ "command-line": command_line })),
        )?;
        match value {
            Value::String(text) => Ok(text),
            other => Err(TransportError::protocol(format!(
                "human-monitor-command returned a non-string result: {other}"
            ))),
        }
    }

    /// `savevm <tag>` via HMP. A non-empty HMP result is the human-readable
    /// error text, surfaced as a [`TransportError::TargetError`].
    pub fn savevm(&mut self, tag: &str) -> Result<()> {
        let output = self.human_monitor_command(&format!("savevm {tag}"))?;
        expect_empty_hmp("savevm", &output)
    }

    /// `loadvm <tag>` via HMP. A non-empty HMP result is surfaced as an error.
    pub fn loadvm(&mut self, tag: &str) -> Result<()> {
        let output = self.human_monitor_command(&format!("loadvm {tag}"))?;
        expect_empty_hmp("loadvm", &output)
    }
}

/// A successful `savevm`/`loadvm` prints nothing; any output is an error string.
fn expect_empty_hmp(operation: &str, output: &str) -> Result<()> {
    if output.trim().is_empty() {
        Ok(())
    } else {
        Err(TransportError::TargetError(format!(
            "{operation} failed: {}",
            output.trim()
        )))
    }
}

/// Validate a snapshot tag before it is interpolated into an HMP command line.
///
/// The tag is spliced into `savevm <tag>` / `loadvm <tag>`, so a tag carrying
/// whitespace or control characters could smuggle a second monitor command.
/// Restrict it to a conservative identifier alphabet.
fn validate_snapshot_tag(tag: &str) -> Result<()> {
    if tag.is_empty() {
        return Err(TransportError::protocol("snapshot tag must not be empty"));
    }
    if let Some(bad) = tag
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
    {
        return Err(TransportError::protocol(format!(
            "snapshot tag {tag:?} contains disallowed character {bad:?}; \
             use only [A-Za-z0-9._-] (it is spliced into an HMP command line)"
        )));
    }
    Ok(())
}

/// An explicit firmware fault-status contract in guest memory.
///
/// A target whose fault handler routes back through the harness completion
/// breakpoint — as a Cortex-M `HardFault_Handler` that calls the "done" symbol
/// commonly does — reports a benign `SIGTRAP` at that breakpoint, so the fault
/// is invisible in the GDB stop reply (#72). When the firmware also records the
/// fault in a known memory word, this contract lets the session read that word
/// as a separate evidence channel and classify the run as a crash independently
/// of the completion trap. It is a deliberate, caller-declared location — never
/// an inference from a particular coverage edge id.
#[derive(Debug, Clone)]
pub struct GuestFaultStatus {
    /// Address of the little-endian fault-status word in guest memory.
    pub address: u64,
    /// Width of the status word in bytes (`1..=8`).
    pub width: usize,
    /// The value meaning "no fault" (typically `0`); any other value is a fault.
    pub clear_value: u64,
}

impl GuestFaultStatus {
    /// Build a contract, validating `width` is in `1..=8` bytes.
    pub fn new(address: u64, width: usize, clear_value: u64) -> Result<Self> {
        if !(1..=8).contains(&width) {
            return Err(TransportError::protocol(format!(
                "fault-status word width {width} must be 1..=8 bytes"
            )));
        }
        Ok(Self {
            address,
            width,
            clear_value,
        })
    }
}

/// Read the firmware fault-status word. Returns `Ok(Some(word))` when it differs
/// from the contract's `clear_value` (a fault was recorded), `Ok(None)` when it
/// is clear. The read is bounded by [`GdbClient::read_memory`].
fn read_fault_status<C: Read + Write>(
    gdb: &mut GdbClient<C>,
    status: &GuestFaultStatus,
) -> Result<Option<u64>> {
    let bytes = gdb.read_memory(status.address, status.width)?;
    let mut word = 0_u64;
    for (i, byte) in bytes.iter().enumerate() {
        word |= u64::from(*byte) << (8 * i);
    }
    Ok((word != status.clear_value).then_some(word))
}

/// A full-system transport over a `qemu-system-*` guest driven by QMP + GDB.
///
/// `connect_qmp` dials a fresh QMP socket and `connect_gdb` a fresh gdbstub
/// socket per [`TargetTransport::arm`]. `map` locates the input staging region
/// and the coverage ring in guest memory; `snapshot_tag` names the baseline
/// snapshot saved on arm and restored each iteration.
pub struct FullSystemTransport<FQ, FG> {
    connect_qmp: FQ,
    connect_gdb: FG,
    map: GdbMemoryMap,
    snapshot_tag: String,
    harness_breakpoint: Option<(u64, u32)>,
    fault_status: Option<GuestFaultStatus>,
    exec_deadline: Option<Duration>,
}

impl<FQ, FG> FullSystemTransport<FQ, FG> {
    /// Build a transport. The `snapshot_tag` is validated up front because it is
    /// spliced into an HMP command line each iteration.
    pub fn new(
        connect_qmp: FQ,
        connect_gdb: FG,
        map: GdbMemoryMap,
        snapshot_tag: impl Into<String>,
    ) -> Result<Self> {
        let snapshot_tag = snapshot_tag.into();
        validate_snapshot_tag(&snapshot_tag)?;
        Ok(Self {
            connect_qmp,
            connect_gdb,
            map,
            snapshot_tag,
            harness_breakpoint: None,
            fault_status: None,
            exec_deadline: None,
        })
    }

    /// Set the absolute per-input execution deadline (#70). A run whose `continue`
    /// does not reach the harness-completion stop within this wall-clock bound is
    /// a target-execution timeout (a hang), surfaced as an [`ExitKind::Timeout`]
    /// outcome rather than blocking on the gdbstub read timeout alone. `None` (the
    /// default) relies on the connection read timeout and the packet/byte caps.
    pub fn with_exec_deadline(mut self, deadline: Option<Duration>) -> Self {
        self.exec_deadline = deadline;
        self
    }

    /// Plant a gdbstub software breakpoint at `address` (RSP `kind`, e.g. `2` for
    /// ARM Thumb) at [`TargetTransport::arm`] time, right after the GDB attach.
    ///
    /// This is required for full-system Cortex-M targets: the harness cannot
    /// self-halt to the debugger with a `bkpt` instruction (with halting-debug
    /// disabled under the QEMU gdbstub, `bkpt` escalates to a HardFault rather
    /// than stopping), so the run-control loop's `c` would never return. Planting
    /// a breakpoint at the harness "done" symbol makes each
    /// [`TargetSession::run_input`] `c` stop with a real stop reply. QEMU keeps
    /// gdbstub breakpoints across a snapshot restore, so one insert on `arm`
    /// covers every iteration. Leave it unset (the default) for targets whose
    /// harness already traps back to the debugger.
    pub fn with_harness_breakpoint(mut self, address: u64, kind: u32) -> Self {
        self.harness_breakpoint = Some((address, kind));
        self
    }

    /// Declare a firmware fault-status word ([`GuestFaultStatus`]) read after
    /// each run. When the GDB stop reply is benign (e.g. a `SIGTRAP` at the
    /// completion breakpoint) but the firmware recorded a fault — a Cortex-M
    /// `HardFault_Handler` that returns through the "done" symbol — a set status
    /// word upgrades the outcome to a crash with a structured fault, so the
    /// crash is not reported as a silent clean pass (#72). Leave it unset (the
    /// default) for targets that surface faults directly in the stop reply.
    pub fn with_fault_status(mut self, status: GuestFaultStatus) -> Self {
        self.fault_status = Some(status);
        self
    }
}

impl<FQ, FG, CQ, CG> TargetTransport for FullSystemTransport<FQ, FG>
where
    FQ: Fn() -> Result<CQ>,
    FG: Fn() -> Result<CG>,
    CQ: Read + Write + 'static,
    CG: Read + Write + 'static,
{
    fn arm(&self) -> Result<Box<dyn TargetSession>> {
        let mut qmp = QmpClient::new((self.connect_qmp)()?);
        qmp.connect()?;

        let mut gdb = GdbClient::new((self.connect_gdb)()?);
        gdb.attach()?;

        // Plant the harness "done" breakpoint before the baseline snapshot so it
        // is in place for the very first iteration (QEMU keeps gdbstub
        // breakpoints across `loadvm`, so one insert covers the whole session).
        if let Some((address, kind)) = self.harness_breakpoint {
            gdb.insert_sw_breakpoint(address, kind)?;
        }

        // Quiesce the vCPUs, then snapshot the clean baseline every iteration
        // restores to.
        qmp.stop()?;
        qmp.savevm(&self.snapshot_tag)?;

        Ok(Box::new(FullSystemSession {
            qmp,
            gdb,
            map: self.map,
            snapshot_tag: self.snapshot_tag.clone(),
            fault_status: self.fault_status.clone(),
            exec_deadline: self.exec_deadline,
        }))
    }
}

/// A live full-system session: restore the baseline, deliver input, run, read
/// coverage — once per [`TargetSession::run_input`].
pub struct FullSystemSession<CQ, CG> {
    qmp: QmpClient<CQ>,
    gdb: GdbClient<CG>,
    map: GdbMemoryMap,
    snapshot_tag: String,
    fault_status: Option<GuestFaultStatus>,
    exec_deadline: Option<Duration>,
}

impl<CQ: Read + Write, CG: Read + Write> TargetSession for FullSystemSession<CQ, CG> {
    fn run_input(&mut self, input: &[u8]) -> Result<RunOutcome> {
        // Reset to the baseline snapshot. loadvm needs paused vCPUs, so stop
        // first (idempotent). This is the per-iteration reset — it replaces the
        // GDB `R` restart, which qemu-system does not implement reliably.
        self.qmp.stop()?;
        self.qmp.loadvm(&self.snapshot_tag)?;

        // Deliver the input into the guest staging region, then run to the
        // harness end breakpoint and collect the stop reply. The run control is
        // bounded by the absolute per-input deadline (#70): a guest that never
        // reaches the completion stop is a first-class Timeout outcome (a hang)
        // with a structured fault, distinct from a lost link — not an unbounded
        // wait and not a silent clean pass. Coverage is not read from a hung guest.
        self.gdb.write_memory(self.map.input_address, input)?;
        let deadline = self.exec_deadline.map(|budget| Instant::now() + budget);
        let (stop, stdout) = match self.gdb.cont_until(deadline)? {
            (ContStop::Stopped(stop), stdout) => (stop, stdout),
            (ContStop::DeadlineExceeded, stdout) => {
                let detail = match self.exec_deadline {
                    Some(budget) => format!(
                        "no completion stop within the per-input execution deadline {}ms",
                        budget.as_millis()
                    ),
                    None => "no completion stop within the per-input execution deadline".to_owned(),
                };
                return Ok(RunOutcome {
                    exit: ExitKind::Timeout,
                    coverage_edges: Vec::new(),
                    fault: Some(Fault {
                        kind: FaultKind::Timeout,
                        address: None,
                        detail,
                    }),
                    stdout,
                    coverage_incomplete: Some(
                        "guest hung: coverage ring not read after an execution timeout".to_owned(),
                    ),
                });
            }
        };

        // Classify the stop reply FIRST (#74: a later readback failure must not
        // erase an already-observed crash).
        let mut exit = stop.to_exit_kind();
        let mut fault = fault_from_stop(&stop);
        let mut coverage_incomplete: Option<String> = None;

        // Explicit firmware fault-status channel (#72). A target whose fault
        // handler returns through the completion breakpoint reports a benign
        // SIGTRAP, hiding the crash in the stop reply. Read the declared status
        // word (before the next loadvm reset) and, when the stop itself was not
        // already a crash, let a recorded fault upgrade the outcome. This is a
        // separate evidence channel from coverage: a coverage edge id is never
        // reinterpreted as a fault.
        if let Some(status) = &self.fault_status {
            match read_fault_status(&mut self.gdb, status) {
                Ok(Some(word)) if exit != ExitKind::Crash => {
                    exit = ExitKind::Crash;
                    fault = Some(Fault {
                        kind: FaultKind::CpuException,
                        address: None,
                        detail: format!("firmware fault-status {word:#x} at {:#x}", status.address),
                    });
                }
                Ok(_) => {}
                Err(err) => {
                    coverage_incomplete = Some(format!("fault-status read failed: {err}"));
                }
            }
        }

        // Harvest coverage from the in-guest ring, best-effort (#74).
        let coverage_edges = match read_coverage_ring(&mut self.gdb, &self.map) {
            Ok(edges) => edges,
            Err(err) => {
                coverage_incomplete.get_or_insert_with(|| err.to_string());
                Vec::new()
            }
        };

        Ok(RunOutcome {
            exit,
            coverage_edges,
            fault,
            stdout,
            coverage_incomplete,
        })
    }
}

/// Coarse fault classification from a GDB stop reply.
///
/// This is intentionally minimal: the full CPU-exception / MMU / watchdog
/// taxonomy is HDF-2's job. Here a crash-classified stop reply is given a
/// best-effort [`FaultKind`] from its signal so the finding is not empty; a
/// clean exit or a benign breakpoint stop carries no fault.
fn fault_from_stop(stop: &crate::gdb::StopReply) -> Option<Fault> {
    use crate::gdb::{gdb_signal, is_fatal_signal, StopReply};
    // Produce a fault exactly when `to_exit_kind` classifies a crash, so the
    // coarse exit and the detailed fault never disagree: a fatal `Sxx`/`Txx`
    // signal, or any `Xxx` termination-by-signal. A benign `SIGTRAP`, "no
    // signal", or a clean exit carries no fault.
    let signal = match stop {
        StopReply::Signal(signal) if is_fatal_signal(*signal) => *signal,
        StopReply::Terminated(signal) => *signal,
        StopReply::Signal(_) | StopReply::Exited(_) => return None,
    };
    // GDB-protocol signal numbers (see `gdb::gdb_signal`), NOT host POSIX ones —
    // in particular SIGBUS is 10 and SIGEMT is 7.
    let kind = match signal {
        gdb_signal::SEGV | gdb_signal::BUS => FaultKind::MemoryProtection,
        gdb_signal::ILL | gdb_signal::FPE | gdb_signal::EMT => FaultKind::CpuException,
        gdb_signal::ABRT => FaultKind::AssertionPanic,
        other => FaultKind::Other(u32::from(other)),
    };
    Some(Fault {
        kind,
        address: None,
        detail: format!("qemu-system stop reply reported GDB signal {signal}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gdb::StopReply;
    use crate::outcome::ExitKind;
    use crate::testsupport::{
        duplex, encode_event_stream, simulate_ring, DuplexStream, MockGdbStub, MockQmpServer,
    };
    use event_log::Event;
    use std::sync::{Arc, Mutex};
    use std::thread;

    /// A ring image of three breadcrumbs and its control words, small enough for
    /// a test but exercising the real reader.
    fn scripted_ring(edges: &[u32], capacity: usize) -> (Vec<u8>, u32, bool) {
        let events: Vec<Event> = edges.iter().map(|&id| Event::Crumb { id }).collect();
        let stream = encode_event_stream(&events);
        simulate_ring(&stream, capacity)
    }

    /// Build a `FullSystemTransport` wired to a fresh scripted QMP server and a
    /// fresh scripted gdbstub, plus the shared logs to assert against.
    ///
    /// The connect factories hand out a single pre-built channel each (the mock
    /// pair is spawned here); a real backend would dial a socket instead.
    #[allow(clippy::type_complexity)]
    fn wired_transport(
        edges: &[u32],
        stop_reply: Vec<u8>,
        ring_capacity: usize,
    ) -> (
        FullSystemTransport<impl Fn() -> Result<DuplexStream>, impl Fn() -> Result<DuplexStream>>,
        Arc<Mutex<Vec<String>>>,
        Arc<Mutex<Vec<String>>>,
    ) {
        let (image, write, wrapped) = scripted_ring(edges, ring_capacity);
        let map = GdbMemoryMap {
            input_address: 0x1000,
            ring_address: 0x4000,
            ring_write_address: 0x5000,
            ring_wrapped_address: 0x5100,
            ring_capacity,
        };

        // GDB stub thread.
        let gdb_log = Arc::new(Mutex::new(Vec::<String>::new()));
        let (gdb_client_end, gdb_stub_end) = duplex();
        let stub = MockGdbStub::new(gdb_stub_end, Arc::clone(&gdb_log))
            .with_stop_reply(stop_reply)
            .with_region(map.input_address, vec![0_u8; 64])
            .with_region(map.ring_address, image)
            .with_region(map.ring_write_address, write.to_le_bytes().to_vec())
            .with_region(map.ring_wrapped_address, vec![u8::from(wrapped)]);
        thread::spawn(move || {
            let _ = stub.serve();
        });

        // QMP server thread.
        let qmp_log = Arc::new(Mutex::new(Vec::<String>::new()));
        let (qmp_client_end, qmp_server_end) = duplex();
        let server = MockQmpServer::new(qmp_server_end, Arc::clone(&qmp_log));
        thread::spawn(move || {
            let _ = server.serve();
        });

        let gdb_slot = Mutex::new(Some(gdb_client_end));
        let qmp_slot = Mutex::new(Some(qmp_client_end));
        let transport =
            FullSystemTransport::new(
                move || {
                    qmp_slot.lock().unwrap().take().ok_or_else(|| {
                        TransportError::protocol("qmp connect invoked more than once")
                    })
                },
                move || {
                    gdb_slot.lock().unwrap().take().ok_or_else(|| {
                        TransportError::protocol("gdb connect invoked more than once")
                    })
                },
                map,
                "bhf-baseline",
            )
            .unwrap();

        (transport, qmp_log, gdb_log)
    }

    #[test]
    fn arm_performs_qmp_handshake_gdb_attach_and_baseline_snapshot() {
        let (transport, qmp_log, gdb_log) = wired_transport(&[1, 2, 3], b"S05".to_vec(), 64);
        let _session = transport.arm().unwrap();

        let qmp = qmp_log.lock().unwrap();
        assert!(
            qmp.iter().any(|c| c == "qmp_capabilities"),
            "arm must negotiate capabilities: {qmp:?}"
        );
        assert!(qmp.iter().any(|c| c == "stop"), "arm must stop: {qmp:?}");
        assert!(
            qmp.iter().any(|c| c == "hmp:savevm bhf-baseline"),
            "arm must snapshot the baseline: {qmp:?}"
        );

        let gdb = gdb_log.lock().unwrap();
        assert!(gdb.iter().any(|p| p == "!"), "arm must attach (!): {gdb:?}");
        assert!(
            gdb.iter().any(|p| p == "?"),
            "arm must query stop (?): {gdb:?}"
        );
    }

    #[test]
    fn run_input_loads_snapshot_delivers_input_and_reads_ring_coverage() {
        let (transport, qmp_log, gdb_log) = wired_transport(&[11, 22, 33], b"W00".to_vec(), 64);
        let mut session = transport.arm().unwrap();
        let outcome = session.run_input(b"radar-frame").unwrap();

        assert_eq!(outcome.exit, ExitKind::Ok, "W00 is a clean exit");
        assert_eq!(outcome.coverage_edges, vec![11, 22, 33]);
        assert!(outcome.fault.is_none());

        // The reset (loadvm) was issued this iteration.
        let qmp = qmp_log.lock().unwrap();
        assert!(
            qmp.iter().any(|c| c == "hmp:loadvm bhf-baseline"),
            "run_input must restore the baseline: {qmp:?}"
        );
        // The input was written into the staging region, and the ring was read.
        let gdb = gdb_log.lock().unwrap();
        assert!(
            gdb.iter().any(|p| p.starts_with("M1000,")),
            "run_input must write the input: {gdb:?}"
        );
        assert!(
            gdb.iter().any(|p| p.starts_with("m4000,")),
            "run_input must read the ring image: {gdb:?}"
        );
    }

    #[test]
    fn run_input_resets_and_delivers_input_every_iteration() {
        let (transport, qmp_log, gdb_log) = wired_transport(&[7], b"S05".to_vec(), 64);
        let mut session = transport.arm().unwrap();
        for input in [b"a".as_slice(), b"bb".as_slice(), b"ccc".as_slice()] {
            session.run_input(input).unwrap();
        }

        let loadvms = qmp_log
            .lock()
            .unwrap()
            .iter()
            .filter(|c| *c == "hmp:loadvm bhf-baseline")
            .count();
        assert_eq!(loadvms, 3, "one snapshot restore per iteration");

        let input_writes = gdb_log
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.starts_with("M1000,"))
            .count();
        assert_eq!(input_writes, 3, "one input delivery per iteration");
    }

    #[test]
    fn same_input_twice_is_deterministic() {
        let (transport, _qmp_log, _gdb_log) = wired_transport(&[3, 1, 4], b"S05".to_vec(), 64);
        let mut session = transport.arm().unwrap();
        let first = session.run_input(b"same").unwrap();
        let second = session.run_input(b"same").unwrap();
        assert_eq!(first, second, "snapshot reset makes runs reproducible");
        assert_eq!(first.coverage_edges, vec![3, 1, 4]);
    }

    #[test]
    fn crash_stop_reply_is_classified_and_faulted() {
        // SIGSEGV (11 == 0x0b) must classify as a memory-protection crash.
        let (transport, _qmp_log, _gdb_log) = wired_transport(&[9], b"S0b".to_vec(), 64);
        let mut session = transport.arm().unwrap();
        let outcome = session.run_input(b"boom").unwrap();

        assert_eq!(outcome.exit, ExitKind::Crash);
        let fault = outcome.fault.expect("a crash must carry a fault");
        assert_eq!(fault.kind, FaultKind::MemoryProtection);
    }

    /// Build a full-system session whose ring region is shorter than the map's
    /// declared capacity, so the post-stop coverage readback fails with a
    /// bounded `memory read` error. `stop_reply` controls how the run itself
    /// terminated.
    fn short_ring_session(stop_reply: &[u8]) -> Box<dyn TargetSession> {
        let map = GdbMemoryMap {
            input_address: 0x1000,
            ring_address: 0x4000,
            ring_write_address: 0x5000,
            ring_wrapped_address: 0x5100,
            ring_capacity: 64,
        };
        let gdb_log = Arc::new(Mutex::new(Vec::<String>::new()));
        let (gdb_client_end, gdb_stub_end) = duplex();
        let stub = MockGdbStub::new(gdb_stub_end, gdb_log)
            .with_stop_reply(stop_reply.to_vec())
            .with_region(map.input_address, vec![0_u8; 64])
            .with_region(map.ring_address, vec![0_u8; 16]) // too short for cap=64
            .with_region(map.ring_write_address, 4_u32.to_le_bytes().to_vec())
            .with_region(map.ring_wrapped_address, vec![0_u8]);
        thread::spawn(move || {
            let _ = stub.serve();
        });

        let qmp_log = Arc::new(Mutex::new(Vec::<String>::new()));
        let (qmp_client_end, qmp_server_end) = duplex();
        let server = MockQmpServer::new(qmp_server_end, qmp_log);
        thread::spawn(move || {
            let _ = server.serve();
        });

        let gdb_slot = Mutex::new(Some(gdb_client_end));
        let qmp_slot = Mutex::new(Some(qmp_client_end));
        let transport = FullSystemTransport::new(
            move || {
                qmp_slot
                    .lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| TransportError::protocol("q"))
            },
            move || {
                gdb_slot
                    .lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| TransportError::protocol("g"))
            },
            map,
            "bhf-baseline",
        )
        .unwrap();
        transport.arm().unwrap()
    }

    #[test]
    fn clean_stop_with_failed_readback_is_retained_as_coverage_incomplete() {
        // A benign stop (S05) whose coverage read fails must NOT be presented as
        // a fully observed clean run: the outcome stays Ok but is flagged
        // incomplete with a descriptive diagnostic, so a coverage/infrastructure
        // failure is distinguishable from complete clean coverage (#74).
        let mut session = short_ring_session(b"S05");
        let outcome = session.run_input(b"x").unwrap();
        assert_eq!(outcome.exit, ExitKind::Ok);
        assert!(outcome.coverage_edges.is_empty());
        let diag = outcome
            .coverage_incomplete
            .expect("a failed readback must be recorded, not silently dropped");
        assert!(
            diag.contains("memory read"),
            "expected a descriptive coverage diagnostic, got: {diag}"
        );
    }

    #[test]
    fn crash_stop_survives_a_failed_coverage_readback() {
        // A SIGSEGV stop (S0b) followed by a coverage-ring read failure must
        // retain the crash classification and fault rather than erroring out
        // and losing the already-observed crash (#74).
        let mut session = short_ring_session(b"S0b");
        let outcome = session.run_input(b"boom").unwrap();
        assert_eq!(outcome.exit, ExitKind::Crash);
        assert_eq!(
            outcome.fault.expect("the crash must be retained").kind,
            FaultKind::MemoryProtection
        );
        assert!(
            outcome.coverage_incomplete.is_some(),
            "the readback failure must be recorded alongside the retained crash"
        );
    }

    /// Build a full-system session with a valid coverage ring, a benign stop
    /// reply (`S05`, as a completion-breakpoint trap), and a fault-status word
    /// region holding `status_word`, so the fault-status channel can be tested
    /// in isolation from the stop reply.
    fn fault_status_session(status_word: u32) -> Box<dyn TargetSession> {
        const STATUS_ADDR: u64 = 0x6000;
        let (image, write, wrapped) = scripted_ring(&[7], 64);
        let map = GdbMemoryMap {
            input_address: 0x1000,
            ring_address: 0x4000,
            ring_write_address: 0x5000,
            ring_wrapped_address: 0x5100,
            ring_capacity: 64,
        };
        let (gdb_client_end, gdb_stub_end) = duplex();
        let stub = MockGdbStub::new(gdb_stub_end, Arc::new(Mutex::new(Vec::new())))
            .with_stop_reply(b"S05".to_vec()) // benign completion trap
            .with_region(map.input_address, vec![0_u8; 64])
            .with_region(map.ring_address, image)
            .with_region(map.ring_write_address, write.to_le_bytes().to_vec())
            .with_region(map.ring_wrapped_address, vec![u8::from(wrapped)])
            .with_region(STATUS_ADDR, status_word.to_le_bytes().to_vec());
        thread::spawn(move || {
            let _ = stub.serve();
        });

        let (qmp_client_end, qmp_server_end) = duplex();
        let server = MockQmpServer::new(qmp_server_end, Arc::new(Mutex::new(Vec::new())));
        thread::spawn(move || {
            let _ = server.serve();
        });

        let gdb_slot = Mutex::new(Some(gdb_client_end));
        let qmp_slot = Mutex::new(Some(qmp_client_end));
        let transport = FullSystemTransport::new(
            move || {
                qmp_slot
                    .lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| TransportError::protocol("q"))
            },
            move || {
                gdb_slot
                    .lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| TransportError::protocol("g"))
            },
            map,
            "bhf-baseline",
        )
        .unwrap()
        .with_fault_status(GuestFaultStatus::new(STATUS_ADDR, 4, 0).unwrap());
        transport.arm().unwrap()
    }

    #[test]
    fn benign_stop_with_set_fault_status_is_a_crash() {
        // The run completes at the benign SIGTRAP completion breakpoint (S05)
        // but the firmware recorded a fault word — the outcome must be a
        // classified crash, not a silent clean pass (#72).
        let mut session = fault_status_session(0xDEAD_FA11);
        let outcome = session.run_input(b"fault").unwrap();
        assert_eq!(outcome.exit, ExitKind::Crash);
        let fault = outcome.fault.expect("a recorded fault must surface");
        assert_eq!(fault.kind, FaultKind::CpuException);
        assert!(
            fault.detail.contains("deadfa11"),
            "fault detail must carry the raw status word: {}",
            fault.detail
        );
        // Coverage is a separate channel and is still harvested normally.
        assert_eq!(outcome.coverage_edges, vec![7]);
    }

    #[test]
    fn benign_stop_with_clear_fault_status_stays_clean() {
        // A clean completion with a cleared fault word stays Ok with no fault:
        // the fault-status channel must not fabricate a crash (#72).
        let mut session = fault_status_session(0);
        let outcome = session.run_input(b"ok").unwrap();
        assert_eq!(outcome.exit, ExitKind::Ok);
        assert!(outcome.fault.is_none());
    }

    #[test]
    fn fault_status_width_is_validated() {
        assert!(GuestFaultStatus::new(0x6000, 0, 0).is_err());
        assert!(GuestFaultStatus::new(0x6000, 9, 0).is_err());
        assert!(GuestFaultStatus::new(0x6000, 4, 0).is_ok());
    }

    #[test]
    fn run_input_reports_timeout_when_execution_deadline_elapses() {
        // A 1ns per-input deadline elapses before the completion stop can be read:
        // the session reports a first-class Timeout outcome (a hang) with a Timeout
        // fault — not a crash, not a propagated error — and does not read coverage
        // from the hung guest (#70).
        let (transport, _qmp_log, _gdb_log) = wired_transport(&[7], b"W00".to_vec(), 64);
        let transport = transport.with_exec_deadline(Some(Duration::from_nanos(1)));
        let mut session = transport.arm().unwrap();
        let outcome = session.run_input(b"hang").unwrap();
        assert_eq!(outcome.exit, ExitKind::Timeout);
        assert_eq!(
            outcome.fault.expect("a hang carries a Timeout fault").kind,
            FaultKind::Timeout
        );
        assert!(
            outcome.coverage_incomplete.is_some(),
            "a hung guest's coverage ring is not presented as complete"
        );
    }

    // ------------------------------------------------------------------
    // QMP client unit tests (crafted-byte and mock-server)
    // ------------------------------------------------------------------

    /// A QMP client whose reads come from `bytes` and whose writes are dropped,
    /// for decode-path testing.
    fn client_over_scripted(bytes: &[u8]) -> QmpClient<DuplexStream> {
        let (client_end, mut peer) = duplex();
        peer.write_all(bytes).unwrap();
        drop(peer);
        QmpClient::new(client_end)
    }

    const GREETING: &[u8] =
        b"{\"QMP\":{\"version\":{\"qemu\":{\"major\":8,\"minor\":2,\"micro\":0}},\"capabilities\":[]}}\n";

    #[test]
    fn qmp_connects_and_runs_snapshot_commands_against_mock() {
        let log = Arc::new(Mutex::new(Vec::<String>::new()));
        let (client_end, server_end) = duplex();
        let server = MockQmpServer::new(server_end, Arc::clone(&log));
        let handle = thread::spawn(move || server.serve());

        let mut client = QmpClient::new(client_end);
        client.connect().unwrap();
        client.stop().unwrap();
        client.cont().unwrap();
        client.savevm("bhf-baseline").unwrap();
        client.loadvm("bhf-baseline").unwrap();
        drop(client);
        handle.join().unwrap().unwrap();

        let log = log.lock().unwrap();
        assert_eq!(
            *log,
            vec![
                "qmp_capabilities".to_string(),
                "stop".to_string(),
                "cont".to_string(),
                "hmp:savevm bhf-baseline".to_string(),
                "hmp:loadvm bhf-baseline".to_string(),
            ]
        );
    }

    #[test]
    fn qmp_connect_rejects_greeting_without_qmp_key() {
        let mut client = client_over_scripted(b"{\"not\":\"a greeting\"}\n");
        let error = client.connect().unwrap_err();
        assert!(
            matches!(error, TransportError::Protocol(ref m) if m.contains("greeting")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn qmp_oversized_message_is_descriptive_error_not_alloc_bomb() {
        // A 4 KiB line against a 16-byte cap must error before growing further,
        // and long before an attacker-declared length could exhaust memory.
        let mut flood = vec![b'{'; 4096];
        flood.push(b'\n');
        let (client_end, mut peer) = duplex();
        peer.write_all(&flood).unwrap();
        drop(peer);
        let mut client = QmpClient::with_limits(
            client_end,
            QmpLimits {
                max_message_bytes: 16,
                ..QmpLimits::default()
            },
        );
        let error = client.connect().unwrap_err();
        assert!(
            matches!(error, TransportError::Protocol(ref m) if m.contains("16 byte cap")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn qmp_malformed_json_is_descriptive_error() {
        let mut client = client_over_scripted(b"this is not json\n");
        let error = client.connect().unwrap_err();
        assert!(
            matches!(error, TransportError::Protocol(ref m) if m.contains("not valid JSON")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn qmp_error_response_maps_to_target_error() {
        let mut script = Vec::new();
        script.extend_from_slice(GREETING);
        script.extend_from_slice(b"{\"return\":{}}\n"); // qmp_capabilities ok
        script.extend_from_slice(
            b"{\"error\":{\"class\":\"GenericError\",\"desc\":\"no such snapshot\"}}\n",
        );
        let mut client = client_over_scripted(&script);
        client.connect().unwrap();
        let error = client.loadvm("missing").unwrap_err();
        assert!(
            matches!(error, TransportError::TargetError(ref m) if m.contains("no such snapshot")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn qmp_skips_async_events_before_a_response() {
        let mut script = Vec::new();
        script.extend_from_slice(GREETING);
        script.extend_from_slice(b"{\"return\":{}}\n"); // qmp_capabilities ok
        script.extend_from_slice(b"{\"event\":\"STOP\",\"timestamp\":{}}\n");
        script.extend_from_slice(b"{\"event\":\"RESUME\",\"timestamp\":{}}\n");
        script.extend_from_slice(b"{\"return\":{}}\n"); // stop's actual return
        let mut client = client_over_scripted(&script);
        client.connect().unwrap();
        client.stop().unwrap(); // must skip the two events and see the return
    }

    #[test]
    fn qmp_event_flood_without_response_is_bounded() {
        let mut script = Vec::new();
        script.extend_from_slice(GREETING);
        // qmp_capabilities: flood events, never a return.
        for _ in 0..10 {
            script.extend_from_slice(b"{\"event\":\"X\",\"timestamp\":{}}\n");
        }
        let (client_end, mut peer) = duplex();
        peer.write_all(&script).unwrap();
        drop(peer);
        let mut client = QmpClient::with_limits(
            client_end,
            QmpLimits {
                max_events_before_response: 3,
                ..QmpLimits::default()
            },
        );
        let error = client.connect().unwrap_err();
        assert!(
            matches!(error, TransportError::Protocol(ref m) if m.contains("without a response")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn qmp_savevm_nonempty_hmp_output_is_target_error() {
        let mut script = Vec::new();
        script.extend_from_slice(GREETING);
        script.extend_from_slice(b"{\"return\":{}}\n"); // qmp_capabilities ok
        script.extend_from_slice(b"{\"return\":\"Error: no block device\"}\n");
        let mut client = client_over_scripted(&script);
        client.connect().unwrap();
        let error = client.savevm("bhf-baseline").unwrap_err();
        assert!(
            matches!(error, TransportError::TargetError(ref m) if m.contains("savevm failed") && m.contains("no block device")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn snapshot_tag_validation_rejects_injection() {
        let map = GdbMemoryMap {
            input_address: 0,
            ring_address: 0,
            ring_write_address: 0,
            ring_wrapped_address: 0,
            ring_capacity: 0,
        };
        let make = |tag: &str| {
            FullSystemTransport::new(
                || Err::<DuplexStream, _>(TransportError::protocol("unused")),
                || Err::<DuplexStream, _>(TransportError::protocol("unused")),
                map,
                tag,
            )
        };
        // A tag that would smuggle a second HMP command is rejected.
        assert!(make("baseline; quit").is_err());
        assert!(make("").is_err());
        // A conservative identifier is accepted.
        assert!(make("bhf-baseline.v1").is_ok());
    }

    #[test]
    fn fault_from_stop_uses_gdb_signal_numbers_and_ignores_clean_exit() {
        use crate::gdb::gdb_signal;
        assert!(fault_from_stop(&StopReply::Exited(0)).is_none());
        assert!(fault_from_stop(&StopReply::Signal(gdb_signal::TRAP)).is_none()); // benign trap
        assert!(fault_from_stop(&StopReply::Signal(0)).is_none());
        assert_eq!(
            fault_from_stop(&StopReply::Signal(gdb_signal::SEGV))
                .unwrap()
                .kind,
            FaultKind::MemoryProtection
        );
        // SIGBUS is GDB signal 10 (not the host POSIX 7): a memory-protection
        // fault that was previously misclassified as Other(10) and reported Ok.
        assert_eq!(
            fault_from_stop(&StopReply::Signal(gdb_signal::BUS))
                .unwrap()
                .kind,
            FaultKind::MemoryProtection
        );
        // GDB signal 7 is SIGEMT (an emulator/CPU trap), not SIGBUS.
        assert_eq!(
            fault_from_stop(&StopReply::Signal(gdb_signal::EMT))
                .unwrap()
                .kind,
            FaultKind::CpuException
        );
        assert_eq!(
            fault_from_stop(&StopReply::Signal(gdb_signal::ILL))
                .unwrap()
                .kind,
            FaultKind::CpuException
        );
        assert_eq!(
            fault_from_stop(&StopReply::Terminated(gdb_signal::ABRT))
                .unwrap()
                .kind,
            FaultKind::AssertionPanic
        );
    }

    #[test]
    fn bus_error_stop_reply_is_a_crash_through_the_session() {
        // GDB signal 10 (`S0a`) is a bus error. Routed through the session it
        // must be a retained memory-protection crash, not a clean outcome.
        let (transport, _qmp_log, _gdb_log) = wired_transport(&[9], b"S0a".to_vec(), 64);
        let mut session = transport.arm().unwrap();
        let outcome = session.run_input(b"bus").unwrap();
        assert_eq!(outcome.exit, ExitKind::Crash);
        assert_eq!(
            outcome.fault.expect("a crash must carry a fault").kind,
            FaultKind::MemoryProtection
        );
    }
}
