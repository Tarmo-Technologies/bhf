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
use crate::gdb::{read_coverage_ring, GdbClient, GdbMemoryMap};
use crate::outcome::{Fault, FaultKind, RunOutcome};
use crate::transport::{TargetSession, TargetTransport};
use serde_json::{json, Value};
use std::io::{Read, Write};

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
        })
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
}

impl<CQ: Read + Write, CG: Read + Write> TargetSession for FullSystemSession<CQ, CG> {
    fn run_input(&mut self, input: &[u8]) -> Result<RunOutcome> {
        // Reset to the baseline snapshot. loadvm needs paused vCPUs, so stop
        // first (idempotent). This is the per-iteration reset — it replaces the
        // GDB `R` restart, which qemu-system does not implement reliably.
        self.qmp.stop()?;
        self.qmp.loadvm(&self.snapshot_tag)?;

        // Deliver the input into the guest staging region, then run to the
        // harness end breakpoint and collect the stop reply.
        self.gdb.write_memory(self.map.input_address, input)?;
        let stop = self.gdb.cont()?;

        // Harvest coverage from the in-guest ring.
        let coverage_edges = read_coverage_ring(&mut self.gdb, &self.map)?;

        let exit = stop.to_exit_kind();
        Ok(RunOutcome {
            exit,
            coverage_edges,
            fault: fault_from_stop(&stop),
            stdout: Vec::new(),
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
    use crate::gdb::StopReply;
    let signal = match stop {
        StopReply::Signal(signal) => *signal,
        StopReply::Terminated(signal) => *signal,
        StopReply::Exited(_) => return None,
    };
    let kind = match signal {
        // SIGSEGV(11), SIGBUS(7): memory-protection faults.
        11 | 7 => FaultKind::MemoryProtection,
        // SIGILL(4), SIGFPE(8): CPU exceptions.
        4 | 8 => FaultKind::CpuException,
        // SIGABRT(6): assertion / abort.
        6 => FaultKind::AssertionPanic,
        // A non-fatal signal is not a crash (to_exit_kind agrees); no fault.
        0 | 5 => return None,
        other => FaultKind::Other(other as u32),
    };
    Some(Fault {
        kind,
        address: None,
        detail: format!("qemu-system stop reply reported signal {signal}"),
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

    #[test]
    fn short_ring_memory_read_is_a_descriptive_error_not_a_panic() {
        // The map claims a 64-byte ring but the stub only serves 16 bytes at the
        // ring base, so the bounded gdb read cannot satisfy the request.
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
            .with_region(map.input_address, vec![0_u8; 64])
            .with_region(map.ring_address, vec![0_u8; 16]) // too short
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

        let mut session = transport.arm().unwrap();
        let error = session.run_input(b"x").unwrap_err();
        assert!(
            matches!(error, TransportError::TargetError(ref m) if m.contains("memory read")),
            "expected a descriptive memory-read error, got: {error}"
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
    fn fault_from_stop_maps_signals_and_ignores_clean_exit() {
        assert!(fault_from_stop(&StopReply::Exited(0)).is_none());
        assert!(fault_from_stop(&StopReply::Signal(5)).is_none()); // benign trap
        assert_eq!(
            fault_from_stop(&StopReply::Signal(11)).unwrap().kind,
            FaultKind::MemoryProtection
        );
        assert_eq!(
            fault_from_stop(&StopReply::Terminated(6)).unwrap().kind,
            FaultKind::AssertionPanic
        );
    }
}
