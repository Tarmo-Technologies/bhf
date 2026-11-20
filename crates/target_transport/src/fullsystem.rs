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
//! # The persistent loop (`reset=persistent`)
//!
//! A `loadvm` per input costs milliseconds even on a small guest and grows with
//! its RAM. [`FullSystemReset::Persistent`] restores only when it must, for a
//! firmware whose completion function returns into a loop that reads the next
//! input from the staging region:
//!
//! ```text
//! run_input(input), the last run clean (the guest parked at `done`):
//!          GDB z0 / s / Z0                (step off the done breakpoint; until
//!                                          the loop is proven, a `g` on either
//!                                          side shows the step left done)
//!          GDB write ring cursor + wrapped = 0, and put back the staging
//!              bytes a longer previous input left past this one
//!          stage, GDB c, read, classify    (as above)
//! run_input(input), otherwise (first input, or after a crash, a hang, an
//! inconclusive run or an error):
//!          QMP stop + loadvm, then as above
//! ```
//!
//! Every other byte of guest state carries over from one clean input to the
//! next, as in any persistent-mode fuzzer. A continuation that comes back to
//! `done` cleanly with coverage proves the loop. Until one has, any other
//! continuation is run again from the snapshot and that run reported, so a
//! firmware that does not loop neither hides a fault nor makes a false one; a
//! step off `done` that changes no register (a `done` that branches to itself)
//! is refused at once, and three continuations that do not show they ran their
//! input stop the session with an error.
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
//! # Renode
//!
//! [`crate::renode::RenodeTransport`] is the same lane for a Renode board:
//! Renode's telnet monitor ([`crate::renode::RenodeMonitor`]) plays QMP's
//! part, with `Save @path` / `Load @path` for `savevm` / `loadvm`, and the
//! run itself is [`run_from_baseline`], shared with this module.

use crate::error::{Result, TransportError};
use crate::gdb::{ContStop, GdbClient, GdbMemoryMap};
use crate::outcome::{ExitKind, Fault, FaultKind, RunOutcome};
use crate::transport::{TargetSession, TargetTransport};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

/// Persistent continuations between two QMP commands. QEMU reports each stop
/// and resume of the guest as a QMP event, and a continuation is two of each
/// (the step off `done` and the run), so a monitor nobody reads would hold an
/// ever-growing backlog, past [`QmpLimits::max_events_before_response`] by the
/// time a restore reads it. A `query-status` this often keeps it to 512.
const QMP_DRAIN_INTERVAL: usize = 128;

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

/// Let the firmware fault-status word (#72) classify a run: a recorded fault
/// upgrades a benign stop to a crash; a failed read after a crash stop is
/// incomplete evidence, and after a benign stop makes the run inconclusive.
/// Shared by [`FullSystemTransport`] and [`crate::gdb::GdbRemoteTransport`].
pub(crate) fn classify_fault_status<C: Read + Write>(
    gdb: &mut GdbClient<C>,
    status: &GuestFaultStatus,
    exit: &mut ExitKind,
    fault: &mut Option<Fault>,
    coverage_incomplete: &mut Option<String>,
    inconclusive: &mut Option<String>,
) {
    match read_fault_status(gdb, status) {
        Ok(Some(word)) if *exit != ExitKind::Crash => {
            *exit = ExitKind::Crash;
            *fault = Some(Fault {
                kind: FaultKind::CpuException,
                address: None,
                detail: format!("firmware fault-status {word:#x} at {:#x}", status.address),
            });
        }
        Ok(_) => {}
        Err(err) if *exit == ExitKind::Crash => {
            // The stop itself is already a crash; the fault-status word
            // would only add detail, so a failed read does not erase the
            // known crash — note it as incomplete evidence (#74) and keep
            // the authoritative Crash classification.
            *coverage_incomplete = Some(format!(
                "fault-status read failed after a crash stop: {err}"
            ));
        }
        Err(err) => {
            // A benign completion stop whose fault-status word could NOT be
            // read is INCONCLUSIVE (#72 re-review): that word is the only
            // thing distinguishing a clean completion from a fault that
            // returned through the `done` breakpoint, so we must not count
            // this as a clean pass nor invent a crash — mark it inconclusive
            // and retain the reason.
            *inconclusive = Some(format!(
                "firmware fault-status read failed on a benign completion stop: {err} \
                     — cannot distinguish a clean completion from a returned-through-done fault"
            ));
        }
    }
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
    snapshot_tag: String,
    harness_breakpoint: Option<(u64, u32)>,
    reset: FullSystemReset,
    run: RunSettings,
}

/// How a [`FullSystemSession`] brings the guest back before each input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FullSystemReset {
    /// Restore the baseline snapshot (`loadvm`) before every input.
    #[default]
    Loadvm,
    /// Leave a guest that ran its input cleanly parked at the completion
    /// breakpoint and continue its own input loop with the next input; restore
    /// the snapshot only before the first input and after a crash, a hang or an
    /// inconclusive run.
    ///
    /// The firmware's completion function (the breakpoint
    /// [`FullSystemTransport::with_harness_breakpoint`] plants, which this mode
    /// requires) must return, into a loop that reads the staging region again
    /// and records the run's coverage:
    ///
    /// ```c
    /// __attribute__((noinline)) void harness_done(void) { __asm volatile(""); }
    /// for (;;) { run_one(bhf_input); harness_done(); }
    /// ```
    ///
    /// A continuation that comes back to `done` cleanly with coverage proves
    /// the loop; until one has, every other continuation is run again from
    /// the snapshot. A `done` that branches to itself (`for (;;) {}` built
    /// with optimization) is refused, and so is a firmware whose
    /// continuations keep failing to show they ran their input.
    ///
    /// Before each continuation the session empties the coverage ring and puts
    /// back the staging bytes a longer previous input left, so a run's coverage
    /// and input are its own; the rest of the guest's state is the firmware's
    /// to reset. A fault handler should record the fault in the
    /// [`GuestFaultStatus`] word: a fault that looks like a clean stop at `done`
    /// would be continued.
    Persistent,
}

/// What one run from a restored baseline needs: where the input and the
/// coverage live, and what is read around the run. Shared by
/// [`FullSystemTransport`] and [`crate::renode::RenodeTransport`], which
/// differ only in how they save and restore the baseline.
#[derive(Debug, Clone)]
pub(crate) struct RunSettings {
    pub(crate) map: GdbMemoryMap,
    pub(crate) fault_status: Option<GuestFaultStatus>,
    pub(crate) exec_deadline: Option<Duration>,
    pub(crate) input_contract: Option<crate::gdb::InputContract>,
    pub(crate) cycle_counter: Option<crate::cycles::CycleCounter>,
    pub(crate) task_id_address: Option<u64>,
    pub(crate) cmplog: Option<crate::cmplog::CmpLogRegion>,
    pub(crate) semihosting_coverage: bool,
    /// Names the emulator in a fault's detail (`qemu-system`, `renode`).
    pub(crate) backend: &'static str,
}

impl RunSettings {
    pub(crate) fn new(map: GdbMemoryMap, backend: &'static str) -> Self {
        Self {
            map,
            fault_status: None,
            exec_deadline: None,
            input_contract: None,
            cycle_counter: None,
            task_id_address: None,
            cmplog: None,
            semihosting_coverage: false,
            backend,
        }
    }
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
            snapshot_tag,
            harness_breakpoint: None,
            reset: FullSystemReset::Loadvm,
            run: RunSettings::new(map, "qemu-system"),
        })
    }

    /// Choose how the guest is brought back before each input (`reset=`).
    pub fn with_reset(mut self, reset: FullSystemReset) -> Self {
        self.reset = reset;
        self
    }

    /// Read the 32-bit task identity word at `address` after each run and
    /// report it in [`RunOutcome::target`] (#252).
    pub fn with_task_id(mut self, address: Option<u64>) -> Self {
        self.run.task_id_address = address;
        self
    }

    /// Read `counter` around each run and report the cycles it took in
    /// [`RunOutcome::target`] (#251).
    pub fn with_cycle_counter(mut self, counter: Option<crate::cycles::CycleCounter>) -> Self {
        self.run.cycle_counter = counter;
        self
    }

    /// Clear the firmware's CmpLog record in `region` before each run and
    /// report the comparisons it holds after it in [`RunOutcome::target`]
    /// (#386).
    pub fn with_cmplog(mut self, region: Option<crate::cmplog::CmpLogRegion>) -> Self {
        self.run.cmplog = region;
        self
    }

    /// Decode each run's coverage from the event stream the target writes to
    /// its semihosting channel ([`crate::gdb::SEMIHOSTING_COVERAGE_FD`]) in
    /// place of the coverage ring (#292).
    pub fn with_semihosting_coverage(mut self, semihosting: bool) -> Self {
        self.run.semihosting_coverage = semihosting;
        self
    }

    /// Stage each input under `contract`: cut to the guest staging region's
    /// capacity, with its length word written first when the firmware reads one.
    pub fn with_input_contract(mut self, contract: Option<crate::gdb::InputContract>) -> Self {
        self.run.input_contract = contract;
        self
    }

    /// Set the absolute per-input execution deadline (#70). A run whose `continue`
    /// does not reach the harness-completion stop within this wall-clock bound is
    /// a target-execution timeout (a hang), surfaced as an [`ExitKind::Timeout`]
    /// outcome rather than blocking on the gdbstub read timeout alone. `None` (the
    /// default) relies on the connection read timeout and the packet/byte caps.
    pub fn with_exec_deadline(mut self, deadline: Option<Duration>) -> Self {
        self.run.exec_deadline = deadline;
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
        self.run.fault_status = Some(status);
        self
    }
}

impl<FQ, FG, CQ, CG> TargetTransport for FullSystemTransport<FQ, FG>
where
    FQ: Fn() -> Result<CQ>,
    FG: Fn() -> Result<CG>,
    CQ: Read + Write + 'static,
    // The gdb channel drives the bounded `continue`, so it must be able to set a
    // read deadline (#70 re-review); the QMP channel does not.
    CG: Read + Write + crate::gdb::ReadDeadline + 'static,
{
    fn arm(&self) -> Result<Box<dyn TargetSession>> {
        // A continuation steps the parked guest off its completion breakpoint,
        // so the persistent loop needs one.
        let persistent = match (self.reset, self.harness_breakpoint) {
            (FullSystemReset::Loadvm, _) => None,
            (FullSystemReset::Persistent, Some(done)) => Some(PersistentLoop::new(done)),
            (FullSystemReset::Persistent, None) => {
                return Err(TransportError::protocol(
                    "reset=persistent needs the completion breakpoint (done=): the guest \
                     parks there between inputs",
                ))
            }
        };

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
            snapshot_tag: self.snapshot_tag.clone(),
            run: self.run.clone(),
            persistent,
        }))
    }
}

/// A live full-system session: restore the baseline (or, under
/// [`FullSystemReset::Persistent`], continue the guest's own input loop),
/// deliver input, run, read coverage — once per [`TargetSession::run_input`].
pub struct FullSystemSession<CQ, CG> {
    qmp: QmpClient<CQ>,
    gdb: GdbClient<CG>,
    snapshot_tag: String,
    run: RunSettings,
    /// The guest's input loop under [`FullSystemReset::Persistent`]; `None`
    /// restores the snapshot before every input.
    persistent: Option<PersistentLoop>,
}

/// Continuations that failed to show the guest ran their input, before one
/// did: each crashed or hung where the same input run from the snapshot did
/// not, came back to `done` with no coverage, or did not step off `done`
/// with a trap. That many is a firmware whose `done` does not return into an
/// input loop.
const UNPROVEN_DIVERGENCE_LIMIT: usize = 3;

/// The largest staging-region read: QEMU's gdbstub answers `m` for at most
/// 2 KiB.
const STAGING_READ_CHUNK: usize = 1024;

/// What a [`FullSystemReset::Persistent`] session knows of the guest's loop.
#[derive(Debug)]
struct PersistentLoop {
    /// The completion breakpoint `(address, RSP kind)` a parked guest is
    /// stepped off.
    done: (u64, u32),
    /// The last input ran cleanly, so the guest waits at `done` for the next.
    parked: bool,
    /// `done` was removed for a step that did not finish putting it back. A
    /// `loadvm` keeps the gdbstub's breakpoints as they are, so the next
    /// restore plants it again.
    lifted: bool,
    /// A continuation has come back to `done` cleanly with coverage: the
    /// guest loops, and runs the input it is given.
    proven: bool,
    /// Continuations that failed to prove the loop before one did (see
    /// [`UNPROVEN_DIVERGENCE_LIMIT`]).
    diverged: usize,
    /// Continuations since the monitor was last read ([`QMP_DRAIN_INTERVAL`]).
    since_qmp: usize,
    staging: StagingTail,
}

impl PersistentLoop {
    fn new(done: (u64, u32)) -> Self {
        Self {
            done,
            parked: false,
            lifted: false,
            proven: false,
            diverged: 0,
            since_qmp: 0,
            staging: StagingTail::default(),
        }
    }

    /// Run `input` on `session`: continue the guest's loop when the last run
    /// left it parked, else restore the snapshot first. Only a guest that ran
    /// its input cleanly is left where it stopped; a crash, a hang or an
    /// inconclusive run is followed by a restore, and so is a run that failed
    /// part way, which leaves the guest's state unknown.
    fn run<CQ: Read + Write, CG: Read + Write + crate::gdb::ReadDeadline>(
        &mut self,
        session: &mut FullSystemSession<CQ, CG>,
        input: &[u8],
    ) -> Result<RunOutcome> {
        let parked = std::mem::replace(&mut self.parked, false);
        let outcome = if parked {
            self.run_continuation(session, input)?
        } else {
            self.run_restored(session, input)?
        };
        self.parked = outcome.exit == ExitKind::Ok && outcome.inconclusive.is_none();
        Ok(outcome)
    }

    /// Run `input` as a continuation of the parked guest's loop, and judge it.
    ///
    /// A continuation that comes back to `done` cleanly with coverage proves
    /// that the guest loops and runs its input. Until one has, any other
    /// continuation may be a guest that never left `done`, or left it for
    /// somewhere other than its input loop, so the input is run from the
    /// snapshot too and that run is the one reported, with its own time in
    /// [`crate::outcome::TargetObservation::host_run_time`]. So is a
    /// continuation whose step off `done` did not trap, at any time.
    fn run_continuation<CQ: Read + Write, CG: Read + Write + crate::gdb::ReadDeadline>(
        &mut self,
        session: &mut FullSystemSession<CQ, CG>,
        input: &[u8],
    ) -> Result<RunOutcome> {
        let continued = match self.run_continued(session, input)? {
            Some(outcome) if self.proven => return Ok(outcome),
            Some(outcome) if proves_the_loop(&outcome) => {
                self.proven = true;
                return Ok(outcome);
            }
            other => other,
        };
        let started = Instant::now();
        let mut restored = self.run_restored(session, input)?;
        restored.target.host_run_time = Some(started.elapsed());
        let unfaithful = continued.as_ref().is_none_or(|continued| {
            continued.exit != restored.exit
                || (continued.exit == ExitKind::Ok && continued.coverage_edges.is_empty())
        });
        if !self.proven && unfaithful {
            self.diverged += 1;
            if self.diverged >= UNPROVEN_DIVERGENCE_LIMIT {
                return Err(TransportError::protocol(format!(
                    "reset=persistent: {} continuations of the guest's input loop did not show \
                     that the guest ran their input (each crashed or hung where the same input \
                     run from the snapshot did not, came back to done= with no coverage, or did \
                     not step off done=), and none has come back to done= cleanly with coverage: \
                     the firmware's done function must return into a loop that runs the next \
                     input from the staging region (use reset=loadvm for a firmware that does \
                     not loop or records no coverage)",
                    self.diverged
                )));
            }
        }
        Ok(restored)
    }

    /// Restore the snapshot and run `input` from it.
    fn run_restored<CQ: Read + Write, CG: Read + Write + crate::gdb::ReadDeadline>(
        &mut self,
        session: &mut FullSystemSession<CQ, CG>,
        input: &[u8],
    ) -> Result<RunOutcome> {
        session.restore()?;
        self.staging.restored();
        if self.lifted {
            let (address, kind) = self.done;
            session.gdb.insert_sw_breakpoint(address, kind)?;
            self.lifted = false;
        }
        // stop and loadvm read the monitor's event backlog.
        self.since_qmp = 0;
        let len = session.staged_len(input);
        self.staging
            .prepare(&mut session.gdb, session.run.map.input_address, len)?;
        run_from_baseline(&mut session.gdb, &session.run, input)
    }

    /// Continue the parked guest's input loop with `input`: step it off `done`,
    /// put the coverage ring and the staging region back as a restore would
    /// leave them, and run. `None` when the step did not stop with a trap,
    /// which leaves the guest's state unknown.
    ///
    /// Until the loop is proven, the step must also change a register: a
    /// `done` that branches to itself (`b .`) does not, the guest stays at
    /// `done`, and a `c` would stop there at once with an empty ring. That
    /// firmware cannot loop, so it is refused at once.
    fn run_continued<CQ: Read + Write, CG: Read + Write + crate::gdb::ReadDeadline>(
        &mut self,
        session: &mut FullSystemSession<CQ, CG>,
        input: &[u8],
    ) -> Result<Option<RunOutcome>> {
        self.since_qmp += 1;
        if self.since_qmp >= QMP_DRAIN_INTERVAL {
            session.qmp.execute("query-status", None)?;
            self.since_qmp = 0;
        }
        // A `c` from the breakpoint would stop there again at once. Step off
        // it with it removed, as gdb does.
        let (address, kind) = self.done;
        let gdb = &mut session.gdb;
        let parked = if self.proven {
            None
        } else {
            Some(gdb.read_registers()?)
        };
        gdb.remove_sw_breakpoint(address, kind)?;
        self.lifted = true;
        let step = gdb.step()?;
        gdb.insert_sw_breakpoint(address, kind)?;
        self.lifted = false;
        if step != crate::gdb::StopReply::Signal(crate::gdb::gdb_signal::TRAP) {
            return Ok(None);
        }
        if let Some(parked) = parked {
            if gdb.read_registers()? == parked {
                return Err(TransportError::protocol(format!(
                    "reset=persistent: the step off done= at {address:#x} changed no register, \
                     so the done function branches to itself (`for (;;) {{}}` built with \
                     optimization is `b .`) and never returns into the firmware's input loop: \
                     use reset=loadvm, or make done a function that returns"
                )));
            }
        }
        // The ring still holds the last run's coverage.
        let map = &session.run.map;
        if !session.run.semihosting_coverage {
            gdb.write_memory(map.ring_write_address, &0_u32.to_le_bytes())?;
            gdb.write_memory(map.ring_wrapped_address, &[0])?;
        }
        let len = session.staged_len(input);
        self.staging
            .prepare(&mut session.gdb, session.run.map.input_address, len)?;
        run_from_baseline(&mut session.gdb, &session.run, input).map(Some)
    }
}

/// Whether a continuation shows that the guest loops and ran its input: it
/// came back to `done` cleanly, and the input's run recorded coverage.
fn proves_the_loop(outcome: &RunOutcome) -> bool {
    outcome.exit == ExitKind::Ok
        && outcome.inconclusive.is_none()
        && !outcome.coverage_edges.is_empty()
}

/// The staging region's bytes as the snapshot holds them, so a continuation
/// can put back what a longer previous input left past a shorter one: each
/// input then meets the region it would after a restore.
///
/// Past `dirty` the region holds its baseline (a restore, or the last put-back,
/// left it so), and `dirty` never passes `baseline.len()`, so a byte read past
/// `baseline.len()` is a baseline byte.
#[derive(Debug, Default)]
struct StagingTail {
    /// The baseline of the region's first `baseline.len()` bytes.
    baseline: Vec<u8>,
    /// The bytes the last staged input covers.
    dirty: usize,
}

impl StagingTail {
    /// Before `len` input bytes are staged at `address`: keep the baseline of
    /// any byte this input is the first to cover, and put back the baseline
    /// bytes the last input left past `len`.
    fn prepare<C: Read + Write>(
        &mut self,
        gdb: &mut GdbClient<C>,
        address: u64,
        len: usize,
    ) -> Result<()> {
        while self.baseline.len() < len {
            let start = self.baseline.len();
            let chunk = (len - start).min(STAGING_READ_CHUNK);
            self.baseline
                .extend(gdb.read_memory(address + start as u64, chunk)?);
        }
        if self.dirty > len {
            gdb.write_memory(address + len as u64, &self.baseline[len..self.dirty])?;
        }
        self.dirty = len;
        Ok(())
    }

    /// The snapshot was restored: the whole region holds its baseline.
    fn restored(&mut self) {
        self.dirty = 0;
    }
}

impl<CQ: Read + Write, CG: Read + Write + crate::gdb::ReadDeadline> FullSystemSession<CQ, CG> {
    /// Reset to the baseline snapshot. loadvm needs paused vCPUs, so stop first
    /// (idempotent). This replaces the GDB `R` restart, which qemu-system does
    /// not implement reliably.
    fn restore(&mut self) -> Result<()> {
        self.qmp.stop()?;
        self.qmp.loadvm(&self.snapshot_tag)
    }

    /// The bytes of `input` the staging region takes.
    fn staged_len(&self, input: &[u8]) -> usize {
        self.run
            .input_contract
            .as_ref()
            .map_or(input.len(), |contract| contract.clamp(input).len())
    }
}

impl<CQ: Read + Write, CG: Read + Write + crate::gdb::ReadDeadline> TargetSession
    for FullSystemSession<CQ, CG>
{
    fn run_input(&mut self, input: &[u8]) -> Result<RunOutcome> {
        // The loop state is taken out for the run so it can drive the session.
        let Some(mut state) = self.persistent.take() else {
            self.restore()?;
            return run_from_baseline(&mut self.gdb, &self.run, input);
        };
        let outcome = state.run(self, input);
        self.persistent = Some(state);
        outcome
    }
}

/// Run one input on a target restored to its baseline, or parked at `done` in
/// its own input loop: stage the input, run to the completion stop within the
/// deadline, classify the stop, and read the fault-status word, the cycle
/// counter, the task id, the CmpLog record and the coverage. Shared by
/// [`FullSystemSession`] and [`crate::renode::RenodeSession`].
pub(crate) fn run_from_baseline<CG: Read + Write + crate::gdb::ReadDeadline>(
    gdb: &mut GdbClient<CG>,
    run: &RunSettings,
    input: &[u8],
) -> Result<RunOutcome> {
    // Deliver the input into the guest staging region, then run to the
    // harness end breakpoint and collect the stop reply. The run control is
    // bounded by the absolute per-input deadline (#70): a guest that never
    // reaches the completion stop is a first-class Timeout outcome (a hang)
    // with a structured fault, distinct from a lost link — not an unbounded
    // wait and not a silent clean pass. Coverage is not read from a hung guest.
    crate::gdb::stage_input(
        gdb,
        run.map.input_address,
        run.input_contract.as_ref(),
        input,
    )?;
    // The snapshot holds the record as it was at arm: start it empty.
    if let Some(region) = &run.cmplog {
        crate::cmplog::clear(gdb, region)?;
    }
    gdb.take_semihosting_output();
    // The cycle counter starts last, so it measures the run, not the setup.
    let cycles_start = match &run.cycle_counter {
        Some(counter) => Some(counter.start(gdb)?),
        None => None,
    };
    let deadline = run.exec_deadline.map(|budget| Instant::now() + budget);
    let (stop, stdout) = match gdb.cont_until(deadline)? {
        (ContStop::Stopped(stop), stdout) => (stop, stdout),
        (ContStop::DeadlineExceeded, mut stdout) => {
            let written = gdb.take_semihosting_output();
            if !run.semihosting_coverage {
                stdout.extend_from_slice(&written);
            }
            let detail = match run.exec_deadline {
                Some(budget) => format!(
                    "no completion stop within the per-input execution deadline {}ms",
                    budget.as_millis()
                ),
                None => "no completion stop within the per-input execution deadline".to_owned(),
            };
            return Ok(RunOutcome {
                target: Default::default(),
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
                inconclusive: None,
            });
        }
    };

    // Classify the stop reply FIRST (#74: a later readback failure must not
    // erase an already-observed crash).
    let mut exit = stop.to_exit_kind();
    let mut fault = fault_from_stop(&stop, run.backend);
    let mut coverage_incomplete: Option<String> = None;
    let mut inconclusive: Option<String> = None;

    // Explicit firmware fault-status channel (#72). A target whose fault
    // handler returns through the completion breakpoint reports a benign
    // SIGTRAP, hiding the crash in the stop reply. Read the declared status
    // word (before the next loadvm reset) and, when the stop itself was not
    // already a crash, let a recorded fault upgrade the outcome. This is a
    // separate evidence channel from coverage: a coverage edge id is never
    // reinterpreted as a fault.
    if let Some(status) = &run.fault_status {
        classify_fault_status(
            gdb,
            status,
            &mut exit,
            &mut fault,
            &mut coverage_incomplete,
            &mut inconclusive,
        );
    }

    // The cycles the run took (#251), best-effort like coverage: a failed
    // read leaves the classification alone.
    let mut target = crate::outcome::TargetObservation::default();
    if let (Some(counter), Some(start)) = (&run.cycle_counter, cycles_start) {
        match counter.elapsed(gdb, start) {
            Ok(cycles) => target.cycles = Some(cycles),
            Err(err) => {
                coverage_incomplete.get_or_insert_with(|| format!("cycle counter: {err}"));
            }
        }
    }
    if let Some(address) = run.task_id_address {
        match crate::gdb::read_u32(gdb, address) {
            Ok(id) => target.task_id = Some(u64::from(id)),
            Err(err) => {
                coverage_incomplete.get_or_insert_with(|| format!("task id: {err}"));
            }
        }
    }
    if let Some(region) = &run.cmplog {
        match crate::cmplog::read(gdb, region) {
            Ok(comparisons) => target.comparisons = comparisons,
            Err(err) => {
                coverage_incomplete.get_or_insert_with(|| format!("cmplog: {err}"));
            }
        }
    }

    // Harvest coverage from the in-guest ring or the semihosting
    // channel, best-effort (#74).
    let mut stdout = stdout;
    let coverage_edges =
        match crate::gdb::collect_coverage(gdb, &run.map, run.semihosting_coverage, &mut stdout) {
            Ok(edges) => edges,
            Err(err) => {
                coverage_incomplete.get_or_insert_with(|| err.to_string());
                Vec::new()
            }
        };

    Ok(RunOutcome {
        target,
        exit,
        coverage_edges,
        fault,
        stdout,
        coverage_incomplete,
        inconclusive,
    })
}

/// Coarse fault classification from a GDB stop reply.
///
/// This is intentionally minimal: the full CPU-exception / MMU / watchdog
/// taxonomy is HDF-2's job. Here a crash-classified stop reply is given a
/// best-effort [`FaultKind`] from its signal so the finding is not empty; a
/// clean exit or a benign breakpoint stop carries no fault.
fn fault_from_stop(stop: &crate::gdb::StopReply, backend: &str) -> Option<Fault> {
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
        detail: format!("{backend} stop reply reported GDB signal {signal}"),
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
        assert!(
            outcome.inconclusive.is_none(),
            "a successful fault-status read is conclusive"
        );
    }

    #[test]
    fn benign_stop_with_unreadable_fault_status_is_inconclusive() {
        // #72 re-review: a benign completion stop (S05) whose CONFIGURED firmware
        // fault-status word cannot be read is INCONCLUSIVE — that word is the only
        // thing distinguishing a clean completion from a fault that returned
        // through the `done` breakpoint. The run must NOT be presented as a clean
        // pass (nor a fabricated crash); the benign exit stays, with the reason
        // retained in `inconclusive`.
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
            // The fault-status region is only 2 bytes, but the contract reads 4,
            // so the read fails — the fault channel could not be observed.
            .with_region(STATUS_ADDR, vec![0_u8; 2]);
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
        let mut session = transport.arm().unwrap();
        let outcome = session.run_input(b"x").unwrap();

        assert_eq!(
            outcome.exit,
            ExitKind::Ok,
            "the benign stop classification is left intact, not upgraded to a crash"
        );
        assert!(outcome.fault.is_none(), "no crash is invented");
        let reason = outcome
            .inconclusive
            .expect("a failed fault-status read on a benign stop is inconclusive, not clean");
        assert!(
            reason.contains("fault-status"),
            "the inconclusive reason is retained: {reason}"
        );
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
        assert!(fault_from_stop(&StopReply::Exited(0), "qemu-system").is_none());
        assert!(fault_from_stop(&StopReply::Signal(gdb_signal::TRAP), "qemu-system").is_none()); // benign trap
        assert!(fault_from_stop(&StopReply::Signal(0), "qemu-system").is_none());
        assert_eq!(
            fault_from_stop(&StopReply::Signal(gdb_signal::SEGV), "qemu-system")
                .unwrap()
                .kind,
            FaultKind::MemoryProtection
        );
        // SIGBUS is GDB signal 10 (not the host POSIX 7): a memory-protection
        // fault that was previously misclassified as Other(10) and reported Ok.
        assert_eq!(
            fault_from_stop(&StopReply::Signal(gdb_signal::BUS), "qemu-system")
                .unwrap()
                .kind,
            FaultKind::MemoryProtection
        );
        // GDB signal 7 is SIGEMT (an emulator/CPU trap), not SIGBUS.
        assert_eq!(
            fault_from_stop(&StopReply::Signal(gdb_signal::EMT), "qemu-system")
                .unwrap()
                .kind,
            FaultKind::CpuException
        );
        assert_eq!(
            fault_from_stop(&StopReply::Signal(gdb_signal::ILL), "qemu-system")
                .unwrap()
                .kind,
            FaultKind::CpuException
        );
        assert_eq!(
            fault_from_stop(&StopReply::Terminated(gdb_signal::ABRT), "qemu-system")
                .unwrap()
                .kind,
            FaultKind::AssertionPanic
        );
    }

    // ------------------------------------------------------------------
    // reset=persistent: the guest's own input loop between clean runs
    // ------------------------------------------------------------------

    const DONE: u64 = 0x2000;
    const STATUS: u64 = 0x6000;
    const LOADVM: &str = "hmp:loadvm bhf-baseline";

    fn scripted_map() -> GdbMemoryMap {
        GdbMemoryMap {
            input_address: 0x1000,
            ring_address: 0x4000,
            ring_write_address: 0x5000,
            ring_wrapped_address: 0x5100,
            ring_capacity: 64,
        }
    }

    /// A gdbstub for a guest that writes `edges` to its ring on every run,
    /// whose staging region holds `staging` at the baseline, whose
    /// fault-status word stays clear, and whose successive `c`s answer `stops`
    /// (an empty one never stops).
    fn scripted_stub<C: Read + Write>(
        channel: C,
        log: Arc<Mutex<Vec<String>>>,
        edges: &[u32],
        stops: Vec<Vec<u8>>,
        staging: Vec<u8>,
    ) -> MockGdbStub<C> {
        let (image, write, wrapped) = scripted_ring(edges, 64);
        let map = scripted_map();
        MockGdbStub::new(channel, log)
            .with_stop_sequence(stops)
            .with_region(map.input_address, staging)
            .with_region(map.ring_address, image)
            .with_region(map.ring_write_address, write.to_le_bytes().to_vec())
            .with_region(map.ring_wrapped_address, vec![u8::from(wrapped)])
            .with_region(STATUS, vec![0; 4])
            .with_run_write(map.ring_write_address, write.to_le_bytes().to_vec())
            .with_run_write(map.ring_wrapped_address, vec![u8::from(wrapped)])
    }

    /// A transport over `gdb` (the client end of a served stub) and a fresh
    /// mock QMP monitor, with the completion breakpoint at [`DONE`], the
    /// fault-status word at [`STATUS`] and `reset`.
    #[allow(clippy::type_complexity)]
    fn scripted_transport<CG: Read + Write + Send + 'static>(
        gdb: CG,
        reset: FullSystemReset,
    ) -> (
        FullSystemTransport<impl Fn() -> Result<DuplexStream>, impl Fn() -> Result<CG>>,
        Arc<Mutex<Vec<String>>>,
    ) {
        let qmp_log = Arc::new(Mutex::new(Vec::<String>::new()));
        let (qmp_client_end, qmp_server_end) = duplex();
        let server = MockQmpServer::new(qmp_server_end, Arc::clone(&qmp_log));
        thread::spawn(move || {
            let _ = server.serve();
        });
        let qmp_slot = Mutex::new(Some(qmp_client_end));
        let gdb_slot = Mutex::new(Some(gdb));
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
            scripted_map(),
            "bhf-baseline",
        )
        .unwrap()
        .with_harness_breakpoint(DONE, 2)
        .with_fault_status(GuestFaultStatus::new(STATUS, 4, 0).unwrap())
        .with_reset(reset);
        (transport, qmp_log)
    }

    /// [`scripted_transport`] over an in-memory gdb channel.
    #[allow(clippy::type_complexity)]
    fn duplex_transport(
        stops: Vec<Vec<u8>>,
        staging: Vec<u8>,
        reset: FullSystemReset,
    ) -> (
        FullSystemTransport<impl Fn() -> Result<DuplexStream>, impl Fn() -> Result<DuplexStream>>,
        Arc<Mutex<Vec<String>>>,
        Arc<Mutex<Vec<String>>>,
    ) {
        let gdb_log = Arc::new(Mutex::new(Vec::<String>::new()));
        let (client, stub_end) = duplex();
        let stub = scripted_stub(stub_end, Arc::clone(&gdb_log), &[7], stops, staging);
        thread::spawn(move || {
            let _ = stub.serve();
        });
        let (transport, qmp_log) = scripted_transport(client, reset);
        (transport, qmp_log, gdb_log)
    }

    /// [`scripted_transport`] over loopback TCP, whose read deadline lets a
    /// stop that never comes end as a hang.
    #[allow(clippy::type_complexity)]
    fn tcp_transport(
        stops: Vec<Vec<u8>>,
    ) -> (
        FullSystemTransport<
            impl Fn() -> Result<DuplexStream>,
            impl Fn() -> Result<std::net::TcpStream>,
        >,
        Arc<Mutex<Vec<String>>>,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            // Small packets each way: Nagle's delay would add tens of ms to
            // every round trip, past the times a test compares.
            stream.set_nodelay(true).unwrap();
            let stub = scripted_stub(
                stream,
                Arc::new(Mutex::new(Vec::new())),
                &[7],
                stops,
                vec![0; 64],
            );
            let _ = stub.serve();
        });
        let client = std::net::TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        client.set_nodelay(true).unwrap();
        let (transport, qmp_log) = scripted_transport(client, FullSystemReset::Persistent);
        (
            transport.with_exec_deadline(Some(Duration::from_millis(300))),
            qmp_log,
        )
    }

    fn count(log: &Arc<Mutex<Vec<String>>>, entry: &str) -> usize {
        log.lock().unwrap().iter().filter(|e| *e == entry).count()
    }

    fn stops(replies: &[&[u8]]) -> Vec<Vec<u8>> {
        replies.iter().map(|reply| reply.to_vec()).collect()
    }

    #[test]
    fn persistent_reset_restores_the_snapshot_only_after_a_fault() {
        // Clean, clean, crash (S0b), clean, clean: the guest is restored before
        // the first input and after the crash, and continues its own loop for
        // the other three.
        let (transport, qmp_log, gdb_log) = duplex_transport(
            stops(&[b"S05", b"S05", b"S0b", b"S05", b"S05"]),
            vec![0; 64],
            FullSystemReset::Persistent,
        );
        let mut session = transport.arm().unwrap();
        let mut exits = Vec::new();
        let mut restores = Vec::new();
        for input in [b"a", b"b", b"c", b"d", b"e"] {
            let outcome = session.run_input(input).unwrap();
            assert_eq!(outcome.coverage_edges, vec![7], "{outcome:?}");
            exits.push(outcome.exit);
            restores.push(count(&qmp_log, LOADVM));
        }
        use ExitKind::{Crash, Ok};
        assert_eq!(exits, vec![Ok, Ok, Crash, Ok, Ok]);
        assert_eq!(
            restores,
            vec![1, 1, 1, 2, 2],
            "a loadvm before the first input and after the crash only"
        );
        assert_eq!(count(&gdb_log, "s"), 3, "each continuation steps off done");
    }

    #[test]
    fn loadvm_reset_restores_before_every_input_and_never_steps() {
        let (transport, qmp_log, gdb_log) = duplex_transport(
            stops(&[b"S05", b"S05", b"S05"]),
            vec![0; 64],
            FullSystemReset::Loadvm,
        );
        let mut session = transport.arm().unwrap();
        for input in [b"a", b"b", b"c"] {
            assert_eq!(session.run_input(input).unwrap().exit, ExitKind::Ok);
        }
        assert_eq!(count(&qmp_log, LOADVM), 3);
        let gdb = gdb_log.lock().unwrap();
        assert!(!gdb.iter().any(|p| p == "s"), "{gdb:?}");
        assert!(
            !gdb.iter().any(|p| p.starts_with("m1000,")),
            "the staging region is not read: {gdb:?}"
        );
    }

    #[test]
    fn a_persistent_continuation_steps_off_done_and_empties_the_ring_first() {
        let (transport, _qmp_log, gdb_log) = duplex_transport(
            stops(&[b"S05", b"S05"]),
            vec![0; 64],
            FullSystemReset::Persistent,
        );
        let mut session = transport.arm().unwrap();
        session.run_input(b"a").unwrap();
        let first = gdb_log.lock().unwrap().len();
        session.run_input(b"b").unwrap();
        let gdb = gdb_log.lock().unwrap()[first..].to_vec();
        // gdb steps off a breakpoint with it removed, and so does bhf; until
        // the loop is proven, the registers on either side of the step show
        // that it left done.
        assert_eq!(
            gdb[..5],
            ["g", "z0,2000,2", "s", "Z0,2000,2", "g"],
            "{gdb:?}"
        );
        let position = |packet: &str| {
            gdb.iter()
                .position(|p| p == packet)
                .unwrap_or_else(|| panic!("{packet} missing: {gdb:?}"))
        };
        let run = position("c");
        assert!(position("M5000,4:00000000") < run, "{gdb:?}");
        assert!(position("M5100,1:00") < run, "{gdb:?}");
        assert!(position("M1000,1:62") < run, "{gdb:?}");
    }

    #[test]
    fn a_persistent_continuation_puts_back_the_staging_bytes_a_longer_input_left() {
        // After a restore the region holds the baseline past the input; a
        // continuation after a longer input must look the same to the guest.
        let (transport, _qmp_log, gdb_log) = duplex_transport(
            stops(&[b"S05", b"S05", b"S05"]),
            vec![0xAA; 8],
            FullSystemReset::Persistent,
        );
        let mut session = transport.arm().unwrap();
        session.run_input(b"1234").unwrap();
        let first = gdb_log.lock().unwrap().len();
        session.run_input(b"z").unwrap();
        let second = gdb_log.lock().unwrap().len();
        session.run_input(b"zz").unwrap();
        let gdb = gdb_log.lock().unwrap().clone();
        let tail = gdb[first..second]
            .iter()
            .position(|p| p == "M1001,3:aaaaaa")
            .unwrap_or_else(|| panic!("the stale tail is not put back: {gdb:?}"));
        let input = gdb[first..second]
            .iter()
            .position(|p| p == "M1000,1:7a")
            .expect("the input is staged");
        assert!(tail < input, "{gdb:?}");
        assert!(
            !gdb[second..].iter().any(|p| p.starts_with("M1002,")),
            "nothing is left past a longer input: {gdb:?}"
        );
    }

    #[test]
    fn persistent_reset_needs_the_completion_breakpoint() {
        let map = scripted_map();
        let transport = FullSystemTransport::new(
            || Err::<DuplexStream, _>(TransportError::protocol("unused")),
            || Err::<DuplexStream, _>(TransportError::protocol("unused")),
            map,
            "bhf-baseline",
        )
        .unwrap()
        .with_reset(FullSystemReset::Persistent);
        let error = transport.arm().err().expect("no done breakpoint");
        assert!(
            error.to_string().contains("completion breakpoint"),
            "{error}"
        );
    }

    #[test]
    fn a_continuation_that_fails_is_followed_by_a_restore() {
        // The 16-byte input does not fit the 8-byte staging region, so its
        // continuation fails part way: the guest's state is unknown, and the
        // next input must not continue from it.
        let (transport, qmp_log, _gdb_log) = duplex_transport(
            stops(&[b"S05", b"S05"]),
            vec![0; 8],
            FullSystemReset::Persistent,
        );
        let mut session = transport.arm().unwrap();
        assert_eq!(session.run_input(b"a").unwrap().exit, ExitKind::Ok);
        session
            .run_input(&[0x41; 16])
            .expect_err("the input overruns the staging region");
        assert_eq!(session.run_input(b"b").unwrap().exit, ExitKind::Ok);
        assert_eq!(
            count(&qmp_log, LOADVM),
            2,
            "a loadvm after the failed continuation"
        );
    }

    #[test]
    fn a_failed_step_off_done_puts_the_breakpoint_back_with_the_restore() {
        // The step fails with the breakpoint removed for it, and a loadvm
        // keeps QEMU's breakpoints as they are: the restore after the failure
        // plants it again, or no later run would stop at done.
        let gdb_log = Arc::new(Mutex::new(Vec::<String>::new()));
        let (client, stub_end) = duplex();
        let stub = scripted_stub(
            stub_end,
            Arc::clone(&gdb_log),
            &[7],
            stops(&[b"S05", b"S05"]),
            vec![0; 64],
        )
        .with_step_reply(b"E01");
        thread::spawn(move || {
            let _ = stub.serve();
        });
        let (transport, qmp_log) = scripted_transport(client, FullSystemReset::Persistent);
        let mut session = transport.arm().unwrap();
        assert_eq!(session.run_input(b"a").unwrap().exit, ExitKind::Ok);
        session.run_input(b"b").expect_err("the step fails");
        assert_eq!(session.run_input(b"c").unwrap().exit, ExitKind::Ok);
        assert_eq!(count(&qmp_log, LOADVM), 2);
        let inserted = count(&gdb_log, "Z0,2000,2");
        let removed = count(&gdb_log, "z0,2000,2");
        assert_eq!(
            inserted,
            removed + 1,
            "done is planted for the run after the restore: {:?}",
            gdb_log.lock().unwrap()
        );
    }

    #[test]
    fn before_the_loop_comes_back_a_crashing_continuation_is_rerun_from_the_snapshot() {
        // r2's continuation crashes, but the input runs clean from the
        // snapshot: the guest may not have looped, so the snapshot run is the
        // one reported. r3's continuation comes back clean, which proves the
        // loop, so r4's crash is a crash, and a loadvm follows it.
        let (transport, qmp_log, _gdb_log) = duplex_transport(
            stops(&[b"S05", b"S0b", b"S05", b"S05", b"S0b", b"S05"]),
            vec![0; 64],
            FullSystemReset::Persistent,
        );
        let mut session = transport.arm().unwrap();
        let mut exits = Vec::new();
        let mut restores = Vec::new();
        for input in [b"a", b"b", b"c", b"d", b"e"] {
            exits.push(session.run_input(input).unwrap().exit);
            restores.push(count(&qmp_log, LOADVM));
        }
        use ExitKind::{Crash, Ok};
        assert_eq!(exits, vec![Ok, Ok, Ok, Crash, Ok]);
        assert_eq!(restores, vec![1, 2, 2, 2, 3]);
    }

    #[test]
    fn an_input_that_crashes_from_the_snapshot_too_is_a_crash() {
        let (transport, qmp_log, _gdb_log) = duplex_transport(
            stops(&[b"S05", b"S0b", b"S0b", b"S05"]),
            vec![0; 64],
            FullSystemReset::Persistent,
        );
        let mut session = transport.arm().unwrap();
        assert_eq!(session.run_input(b"a").unwrap().exit, ExitKind::Ok);
        let crash = session.run_input(b"b").unwrap();
        assert_eq!(crash.exit, ExitKind::Crash);
        assert_eq!(
            crash.fault.expect("a crash carries a fault").kind,
            FaultKind::MemoryProtection
        );
        assert_eq!(session.run_input(b"c").unwrap().exit, ExitKind::Ok);
        assert_eq!(
            count(&qmp_log, LOADVM),
            3,
            "the crash is followed by a loadvm"
        );
    }

    #[test]
    fn a_guest_that_never_comes_back_to_done_from_its_loop_is_refused() {
        // Every continuation crashes where the same input runs clean from the
        // snapshot: the firmware's done returns into nothing.
        let (transport, _qmp_log, _gdb_log) = duplex_transport(
            stops(&[b"S05", b"S0b", b"S05", b"S0b", b"S05", b"S0b", b"S05"]),
            vec![0; 64],
            FullSystemReset::Persistent,
        );
        let mut session = transport.arm().unwrap();
        for input in [b"a", b"b", b"c"] {
            assert_eq!(session.run_input(input).unwrap().exit, ExitKind::Ok);
        }
        let error = session.run_input(b"d").unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("reset=persistent") && message.contains("loop"),
            "{message}"
        );
    }

    #[test]
    fn a_hang_on_a_proven_loop_is_a_timeout_and_the_next_input_restores() {
        let (transport, qmp_log) = tcp_transport(stops(&[b"S05", b"S05", b"", b"S05"]));
        let mut session = transport.arm().unwrap();
        assert_eq!(session.run_input(b"a").unwrap().exit, ExitKind::Ok);
        assert_eq!(session.run_input(b"b").unwrap().exit, ExitKind::Ok);
        let hang = session.run_input(b"c").unwrap();
        assert_eq!(hang.exit, ExitKind::Timeout);
        assert_eq!(count(&qmp_log, LOADVM), 1);
        assert_eq!(session.run_input(b"d").unwrap().exit, ExitKind::Ok);
        assert_eq!(
            count(&qmp_log, LOADVM),
            2,
            "the hang is followed by a loadvm"
        );
    }

    #[test]
    fn before_the_loop_comes_back_a_hanging_continuation_is_rerun_from_the_snapshot() {
        let (transport, qmp_log) = tcp_transport(stops(&[b"S05", b"", b"S05"]));
        let mut session = transport.arm().unwrap();
        assert_eq!(session.run_input(b"a").unwrap().exit, ExitKind::Ok);
        let rerun = session.run_input(b"b").unwrap();
        assert_eq!(rerun.exit, ExitKind::Ok, "{rerun:?}");
        assert_eq!(rerun.coverage_edges, vec![7]);
        assert_eq!(count(&qmp_log, LOADVM), 2);
    }

    /// [`duplex_transport`] with the stub adjusted by `adjust` before it
    /// serves.
    #[allow(clippy::type_complexity)]
    fn adjusted_transport(
        stops: Vec<Vec<u8>>,
        adjust: impl FnOnce(MockGdbStub<DuplexStream>) -> MockGdbStub<DuplexStream>,
    ) -> (
        FullSystemTransport<impl Fn() -> Result<DuplexStream>, impl Fn() -> Result<DuplexStream>>,
        Arc<Mutex<Vec<String>>>,
        Arc<Mutex<Vec<String>>>,
    ) {
        let gdb_log = Arc::new(Mutex::new(Vec::<String>::new()));
        let (client, stub_end) = duplex();
        let stub = adjust(scripted_stub(
            stub_end,
            Arc::clone(&gdb_log),
            &[7],
            stops,
            vec![0; 64],
        ));
        thread::spawn(move || {
            let _ = stub.serve();
        });
        let (transport, qmp_log) = scripted_transport(client, FullSystemReset::Persistent);
        (transport, qmp_log, gdb_log)
    }

    #[test]
    fn a_step_that_leaves_the_guest_at_done_is_refused_and_does_not_park_it() {
        // A done that branches to itself (`for (;;) {}` built -O1 is `b .`):
        // the step off it lands on it again, so a `c` would stop there at
        // once with an empty ring and every input would read as clean.
        let (transport, qmp_log, gdb_log) =
            adjusted_transport(stops(&[b"S05", b"S05", b"S05"]), |stub| {
                stub.with_step_in_place()
            });
        let mut session = transport.arm().unwrap();
        assert_eq!(session.run_input(b"a").unwrap().exit, ExitKind::Ok);
        let runs = count(&gdb_log, "c");
        let message = session
            .run_input(b"b")
            .expect_err("a done that spins in place is refused")
            .to_string();
        assert!(
            message.contains("reset=persistent")
                && message.contains("0x2000")
                && message.contains("reset=loadvm"),
            "{message}"
        );
        assert_eq!(
            count(&gdb_log, "c"),
            runs,
            "the input is not run on a guest that did not leave done"
        );
        // The guest was not left parked: the next input runs from the snapshot.
        let next = session.run_input(b"c").unwrap();
        assert_eq!((next.exit, next.coverage_edges), (ExitKind::Ok, vec![7]));
        assert_eq!(count(&qmp_log, LOADVM), 2);
    }

    #[test]
    fn a_continuation_that_comes_back_without_running_is_rerun_from_the_snapshot() {
        // The step leaves done, but the guest comes straight back to it with
        // an empty ring: nothing shows the input ran. It runs from the
        // snapshot, where it crashes, and that crash is what is reported.
        let (transport, qmp_log, _gdb_log) =
            adjusted_transport(stops(&[b"S05", b"S05", b"S0b", b"S05"]), |stub| {
                stub.with_runs_that_write(vec![true, false])
            });
        let mut session = transport.arm().unwrap();
        assert_eq!(session.run_input(b"a").unwrap().exit, ExitKind::Ok);
        let crash = session.run_input(b"b").unwrap();
        assert_eq!(crash.exit, ExitKind::Crash, "{crash:?}");
        assert_eq!(crash.coverage_edges, vec![7]);
        assert!(
            crash.target.host_run_time.is_some(),
            "the snapshot run's own time is reported: {crash:?}"
        );
        assert_eq!(count(&qmp_log, LOADVM), 2);
        assert_eq!(session.run_input(b"c").unwrap().exit, ExitKind::Ok);
        assert_eq!(count(&qmp_log, LOADVM), 3, "a loadvm after the crash");
    }

    #[test]
    fn continuations_that_never_record_coverage_are_refused() {
        // Each continuation comes back to done with an empty ring where the
        // same input from the snapshot records coverage: the loop never
        // proves itself, and the third such continuation is refused.
        let (transport, qmp_log, _gdb_log) = adjusted_transport(Vec::new(), |stub| {
            stub.with_runs_that_write(vec![true, false, true, false, true, false, true])
        });
        let mut session = transport.arm().unwrap();
        for input in [b"a", b"b", b"c"] {
            let outcome = session.run_input(input).unwrap();
            assert_eq!(
                (outcome.exit, outcome.coverage_edges),
                (ExitKind::Ok, vec![7])
            );
        }
        let message = session.run_input(b"d").unwrap_err().to_string();
        assert!(
            message.contains("reset=persistent") && message.contains("coverage"),
            "{message}"
        );
        assert_eq!(count(&qmp_log, LOADVM), 4, "each was run from the snapshot");
    }

    #[test]
    fn a_step_off_done_that_does_not_trap_is_rerun_from_the_snapshot() {
        let (transport, qmp_log, gdb_log) =
            adjusted_transport(Vec::new(), |stub| stub.with_step_reply(b"S0b"));
        let mut session = transport.arm().unwrap();
        assert_eq!(session.run_input(b"a").unwrap().exit, ExitKind::Ok);
        let rerun = session.run_input(b"b").unwrap();
        assert_eq!((rerun.exit, rerun.coverage_edges), (ExitKind::Ok, vec![7]));
        assert_eq!(count(&qmp_log, LOADVM), 2);
        assert_eq!(
            count(&gdb_log, "c"),
            2,
            "no run from the failed step: {:?}",
            gdb_log.lock().unwrap()
        );
        assert_eq!(
            count(&gdb_log, "Z0,2000,2"),
            count(&gdb_log, "z0,2000,2") + 1,
            "done is planted again after the step"
        );
    }

    #[test]
    fn once_the_loop_is_proven_a_continuation_reads_no_registers() {
        // The step check costs two register reads; the loop it guards does
        // not change once a continuation has come back with coverage.
        let (transport, _qmp_log, gdb_log) =
            duplex_transport(Vec::new(), vec![0; 64], FullSystemReset::Persistent);
        let mut session = transport.arm().unwrap();
        for input in [b"a", b"b", b"c", b"d"] {
            assert_eq!(session.run_input(input).unwrap().exit, ExitKind::Ok);
        }
        assert_eq!(count(&gdb_log, "s"), 3);
        assert_eq!(count(&gdb_log, "g"), 2, "{:?}", gdb_log.lock().unwrap());
    }

    #[test]
    fn a_hanging_continuation_rerun_from_the_snapshot_reports_the_rerun_time() {
        // The hung continuation took the whole 300 ms deadline; the reported
        // run is the one from the snapshot, and a deadline oracle must judge
        // that run's time, not the hang's.
        let (transport, _qmp_log) = tcp_transport(stops(&[b"S05", b"", b"S05"]));
        let mut session = transport.arm().unwrap();
        assert_eq!(
            session.run_input(b"a").unwrap().target.host_run_time,
            None,
            "a run from a restore is the whole call"
        );
        let rerun = session.run_input(b"b").unwrap();
        assert_eq!(rerun.exit, ExitKind::Ok, "{rerun:?}");
        let time = rerun.target.host_run_time.expect("the rerun's own time");
        assert!(time < Duration::from_millis(300), "{time:?}");
    }

    #[test]
    fn persistent_reset_reads_the_monitor_while_the_loop_runs() {
        // The guest stops and resumes through gdb, and QEMU reports each as a
        // QMP event; a periodic command keeps that backlog bounded.
        let runs = 1 + QMP_DRAIN_INTERVAL;
        let (transport, qmp_log, _gdb_log) =
            duplex_transport(Vec::new(), vec![0; 64], FullSystemReset::Persistent);
        let mut session = transport.arm().unwrap();
        for _ in 0..runs {
            assert_eq!(session.run_input(b"a").unwrap().exit, ExitKind::Ok);
        }
        assert_eq!(count(&qmp_log, LOADVM), 1);
        assert_eq!(count(&qmp_log, "query-status"), 1);
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
