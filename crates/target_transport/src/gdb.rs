// SPDX-License-Identifier: Apache-2.0

//! GDB Remote Serial Protocol (RSP) client for the debug-probe / emulator
//! bridge.
//!
//! Enough of RSP to drive a fuzzing loop over OpenOCD / gdbserver / a QEMU
//! gdbstub: framed `$...#xx` packets with checksums, `+`/`-` acknowledgements,
//! the `m`/`M` memory read/write packets, `g` register read, `c` continue, and
//! a reset sequence between iterations. [`GdbRemoteTransport`] composes these
//! with [`crate::coverage::MemoryBufferReader`] to read the on-target coverage
//! ring back out of memory.
//!
//! The client logic here is exercised against the in-crate mock gdbstub
//! ([`crate::testsupport::MockGdbStub`]) in unit tests, and against a REAL
//! `qemu-<arch>` / `qemu-system-arm` gdbstub in the gated live integration
//! tests (`crates/target_transport/tests/live_gdb.rs`,
//! `crates/target_transport/tests/live_fullsystem.rs`) that only run when the
//! emulator + cross toolchains are present.
//!
//! Run-length-encoded responses (which real gdbserver / OpenOCD — and QEMU for
//! some dumps — emit to compress repeated bytes) are **expanded** per the RSP
//! rule (`<byte>*<count>` repeats the preceding byte `count - 29` more times;
//! this was the HDF-4 live-path follow-up and is now implemented). The expansion
//! is bounded by [`MAX_PACKET_BYTES`] so a hostile run-length header cannot drive
//! an unbounded allocation.

use crate::coverage::MemoryBufferReader;
use crate::error::{Result, TransportError};
use crate::outcome::{ExitKind, Fault, FaultKind, RunOutcome};
use crate::transport::{TargetSession, TargetTransport};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

/// A byte channel that can bound how long a single subsequent read may block.
///
/// [`GdbClient::cont_until`] uses this to re-arm each blocking read with the
/// REMAINING absolute per-input budget, so neither the `continue` send/ack nor
/// any one packet — even one dribbled a byte at a time — can push the total past
/// the deadline. A channel that cannot enforce a read deadline returns `false`;
/// such a channel is acceptable only when it cannot block indefinitely (the
/// in-memory test pipe), and the GDB transport's live channel is always a
/// `TcpStream`, which can.
pub trait ReadDeadline {
    /// Set the maximum time a single subsequent read may block (`None` clears the
    /// bound). Returns `false` if the channel cannot enforce one.
    fn set_read_deadline(&self, timeout: Option<Duration>) -> bool;
}

impl ReadDeadline for std::net::TcpStream {
    fn set_read_deadline(&self, timeout: Option<Duration>) -> bool {
        self.set_read_timeout(timeout).is_ok()
    }
}

/// RSP escape byte (`}`); the following byte is the real byte XOR 0x20.
const ESCAPE: u8 = 0x7d;
/// RSP run-length-encoding marker (`*`).
const RUN_LENGTH: u8 = 0x2a;
/// Upper bound on a received packet's data length (unbounded-read guard).
const MAX_PACKET_BYTES: usize = 2 * 1024 * 1024;
/// Upper bound on a single `m` memory read length.
const MAX_MEMORY_READ: usize = 1024 * 1024;
/// Retransmit attempts on a `-` (NAK) before giving up.
const MAX_RETRANSMITS: usize = 3;
/// Max intermediate `O` console-output packets accepted between a `c` and the
/// terminal stop reply before giving up, so a chatty or wedged target cannot
/// stream forever (an absolute execution deadline is enforced by the campaign).
const MAX_CONSOLE_PACKETS: usize = 100_000;
/// Max total decoded console-output bytes retained while awaiting a stop reply.
const MAX_CONSOLE_BYTES: usize = 1024 * 1024;

/// The RSP checksum: the low byte of the sum of the packet data bytes.
pub fn rsp_checksum(data: &[u8]) -> u8 {
    data.iter().fold(0_u8, |acc, &byte| acc.wrapping_add(byte))
}

/// Frame packet `data` as `$<data>#<cc>` with a two-hex-digit checksum.
pub fn encode_packet(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 4);
    out.push(b'$');
    out.extend_from_slice(data);
    out.push(b'#');
    out.extend_from_slice(hex_byte(rsp_checksum(data)).as_bytes());
    out
}

/// Decode a `$<data>#<cc>` frame: verify the checksum and un-escape the data.
///
/// Errors on a missing `$`/`#`, a truncated or mismatched checksum, or a
/// run-length-encoded body (unsupported; see the module docs).
pub fn decode_packet(frame: &[u8]) -> Result<Vec<u8>> {
    if frame.first() != Some(&b'$') {
        return Err(TransportError::gdb("packet does not start with '$'"));
    }
    let hash = frame
        .iter()
        .position(|&byte| byte == b'#')
        .ok_or_else(|| TransportError::gdb("packet has no '#' terminator"))?;
    let data = &frame[1..hash];
    let checksum_hex = frame
        .get(hash + 1..hash + 3)
        .ok_or_else(|| TransportError::gdb("packet checksum is truncated"))?;
    let given = parse_hex_byte(checksum_hex)?;
    let want = rsp_checksum(data);
    if given != want {
        return Err(TransportError::gdb(format!(
            "checksum mismatch: frame carries {given:02x}, computed {want:02x}"
        )));
    }
    unescape(data)
}

/// Un-escape RSP `}`-escaped data and expand run-length-encoded runs.
///
/// RSP compresses a run of identical bytes as `<byte>*<count>`, where the byte to
/// repeat has already been emitted and `count` is the character *following* the
/// `*`; the preceding byte is repeated `count - 29` **additional** times (gdb's
/// `repeat = c - ' ' + 3`). Real gdbserver / OpenOCD (and QEMU, for some dumps)
/// emit this for large register/memory reads, so the live path must expand it.
/// The expansion is bounded by [`MAX_PACKET_BYTES`] so a malicious run-length
/// header cannot drive an unbounded allocation.
fn unescape(data: &[u8]) -> Result<Vec<u8>> {
    /// RSP run-length count offset: a count character `c` encodes `c - 29`.
    const RLE_OFFSET: i32 = 29;
    let mut out = Vec::with_capacity(data.len());
    let mut iter = data.iter().copied();
    while let Some(byte) = iter.next() {
        match byte {
            ESCAPE => {
                let escaped = iter
                    .next()
                    .ok_or_else(|| TransportError::gdb("dangling '}' escape at end of packet"))?;
                out.push(escaped ^ 0x20);
            }
            RUN_LENGTH => {
                let count_char = iter.next().ok_or_else(|| {
                    TransportError::gdb("dangling '*' run-length marker at end of packet")
                })?;
                let &last = out.last().ok_or_else(|| {
                    TransportError::gdb("run-length '*' with no preceding byte to repeat")
                })?;
                let repeat = count_char as i32 - RLE_OFFSET;
                if repeat < 0 {
                    return Err(TransportError::gdb(format!(
                        "invalid run-length count byte {count_char:#04x} (decodes to {repeat})"
                    )));
                }
                let repeat = repeat as usize;
                if out.len() + repeat > MAX_PACKET_BYTES {
                    return Err(TransportError::gdb(format!(
                        "run-length expansion would exceed the {MAX_PACKET_BYTES} byte cap"
                    )));
                }
                out.extend(std::iter::repeat_n(last, repeat));
            }
            other => out.push(other),
        }
    }
    Ok(out)
}

fn hex_byte(value: u8) -> String {
    format!("{value:02x}")
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push_str(&hex_byte(byte));
    }
    out
}

fn parse_hex_byte(pair: &[u8]) -> Result<u8> {
    let text =
        std::str::from_utf8(pair).map_err(|_| TransportError::gdb("non-ASCII in a hex byte"))?;
    u8::from_str_radix(text, 16)
        .map_err(|error| TransportError::gdb(format!("invalid hex byte {text:?}: {error}")))
}

// `as_chunks::<2>()` would avoid the remainder check but is not stable at our
// MSRV; `chunks_exact(2)` is equivalent and clear here.
#[allow(clippy::chunks_exact_to_as_chunks)]
fn from_hex(bytes: &[u8]) -> Result<Vec<u8>> {
    if !bytes.len().is_multiple_of(2) {
        return Err(TransportError::gdb(format!(
            "hex payload has odd length {}",
            bytes.len()
        )));
    }
    bytes.chunks_exact(2).map(parse_hex_byte).collect()
}

/// How the target stopped, decoded from a `S`/`T`/`W`/`X` stop reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReply {
    /// Stopped with a signal (`Sxx` / `Txx...`).
    Signal(u8),
    /// Exited normally with a code (`Wxx`).
    Exited(u8),
    /// Terminated by a signal (`Xxx`).
    Terminated(u8),
}

/// GDB remote-protocol signal numbers.
///
/// RSP stop replies (`Sxx` / `Txx`) carry GDB's own `gdb_signal` enum values,
/// **not** the host platform's POSIX signal numbers. The two namespaces
/// diverge: notably GDB numbers `SIGBUS` as 10 and `SIGEMT` as 7, whereas Linux
/// uses 7 for `SIGBUS`. Classifying an RSP reply with host constants therefore
/// mislabels a bus error and never fires for a real `SIGBUS`. These are the
/// protocol values from GDB's `include/gdb/signals.def`.
pub mod gdb_signal {
    /// Illegal instruction.
    pub const ILL: u8 = 4;
    /// Trace/breakpoint trap — benign (a planted breakpoint or single-step stop).
    pub const TRAP: u8 = 5;
    /// Abort / `abort()`.
    pub const ABRT: u8 = 6;
    /// Emulator trap.
    pub const EMT: u8 = 7;
    /// Floating-point / arithmetic exception.
    pub const FPE: u8 = 8;
    /// Bus error (GDB numbers this 10, not the Linux POSIX 7).
    pub const BUS: u8 = 10;
    /// Segmentation fault / invalid memory access.
    pub const SEGV: u8 = 11;
}

/// True for a GDB-protocol signal that denotes a target fault (a crash), as
/// opposed to a benign stop such as `SIGTRAP` (a breakpoint) or "no signal" (0).
///
/// Shared by [`StopReply::to_exit_kind`] and the full-system fault classifier so
/// the coarse crash decision and the detailed fault taxonomy stay in agreement.
pub fn is_fatal_signal(signal: u8) -> bool {
    use gdb_signal::*;
    matches!(signal, ILL | ABRT | EMT | FPE | BUS | SEGV)
}

impl StopReply {
    /// Parse a stop-reply packet body.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let (&tag, rest) = body
            .split_first()
            .ok_or_else(|| TransportError::gdb("empty stop reply"))?;
        let code =
            parse_hex_byte(rest.get(0..2).ok_or_else(|| {
                TransportError::gdb("stop reply is missing its two-hex-digit code")
            })?)?;
        match tag {
            b'S' | b'T' => Ok(Self::Signal(code)),
            b'W' => Ok(Self::Exited(code)),
            b'X' => Ok(Self::Terminated(code)),
            other => Err(TransportError::gdb(format!(
                "unexpected stop-reply tag {:?}",
                other as char
            ))),
        }
    }

    /// Coarse HDF-1 mapping to [`ExitKind`]. The full signal-to-fault taxonomy
    /// is HDF-2; here only the fatal GDB-protocol signals count as a crash so a
    /// benign `SIGTRAP` breakpoint stop is not mislabeled. Signal numbers are
    /// GDB's, not the host's — see [`gdb_signal`] and [`is_fatal_signal`].
    pub fn to_exit_kind(&self) -> ExitKind {
        match self {
            Self::Exited(_) => ExitKind::Ok,
            // `Xxx` always denotes termination by a signal: a crash.
            Self::Terminated(_) => ExitKind::Crash,
            Self::Signal(signal) if is_fatal_signal(*signal) => ExitKind::Crash,
            Self::Signal(_) => ExitKind::Ok,
        }
    }
}

/// The result of a bounded [`GdbClient::cont_until`]: the target reached a stop
/// within its per-input execution deadline, or the deadline elapsed first.
///
/// `DeadlineExceeded` is a *target-execution* timeout (a hang) — distinct from a
/// setup/control I/O failure, which the caller sees as an `Err` from the setup
/// packets, and from a lost link. The session turns it into a first-class
/// [`ExitKind::Timeout`] outcome rather than a propagated I/O error, so a hang is
/// never misreported as a lost transport or a clean run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContStop {
    /// The target stopped (a real stop reply) before the deadline.
    Stopped(StopReply),
    /// The absolute per-input execution deadline elapsed with no stop reply.
    DeadlineExceeded,
}

/// True for an I/O error that is a read/write timeout (the per-input budget
/// elapsed), as opposed to a framing or connection-drop failure.
fn is_timeout_err(err: &TransportError) -> bool {
    matches!(
        err,
        TransportError::Io(io)
            if matches!(
                io.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            )
    )
}

/// Low-level framed RSP connection over any byte channel.
pub struct GdbConnection<C> {
    channel: C,
}

impl<C: Read + Write> GdbConnection<C> {
    /// Wrap a byte channel.
    pub fn new(channel: C) -> Self {
        Self { channel }
    }

    fn read_byte(&mut self) -> Result<Option<u8>> {
        let mut buf = [0_u8; 1];
        match self.channel.read(&mut buf)? {
            0 => Ok(None),
            _ => Ok(Some(buf[0])),
        }
    }

    fn read_byte_required(&mut self, context: &str) -> Result<u8> {
        self.read_byte()?
            .ok_or_else(|| TransportError::gdb(format!("stream closed while awaiting {context}")))
    }

    /// Send a command packet and consume the peer's `+` acknowledgement,
    /// retransmitting on `-`.
    pub fn send_packet(&mut self, data: &[u8]) -> Result<()> {
        let frame = encode_packet(data);
        for _ in 0..MAX_RETRANSMITS {
            self.channel.write_all(&frame)?;
            self.channel.flush()?;
            match self.read_byte_required("packet acknowledgement")? {
                b'+' => return Ok(()),
                b'-' => continue,
                other => {
                    return Err(TransportError::gdb(format!(
                        "expected '+'/'-' ack, got {:?}",
                        other as char
                    )))
                }
            }
        }
        Err(TransportError::gdb(
            "peer NAKed the packet past the retransmit limit",
        ))
    }

    /// Receive a response packet, verify its checksum, and send `+`.
    pub fn recv_packet(&mut self) -> Result<Vec<u8>> {
        self.recv_packet_opt()?
            .ok_or_else(|| TransportError::gdb("stream closed while awaiting a packet"))
    }

    /// Like [`GdbConnection::recv_packet`] but returns `Ok(None)` on a clean EOF
    /// at the packet boundary (the peer closed the link between packets). Used
    /// by the mock stub's serve loop to terminate.
    pub fn recv_packet_opt(&mut self) -> Result<Option<Vec<u8>>> {
        // Skip to the packet start, tolerating stray acks; clean EOF -> None.
        loop {
            match self.read_byte()? {
                None => return Ok(None),
                Some(b'$') => break,
                Some(b'+') | Some(b'-') => continue,
                Some(other) => {
                    return Err(TransportError::gdb(format!(
                        "expected packet start '$', got {:?}",
                        other as char
                    )))
                }
            }
        }
        let mut data = Vec::new();
        loop {
            let byte = self.read_byte_required("packet body")?;
            if byte == b'#' {
                break;
            }
            data.push(byte);
            if data.len() > MAX_PACKET_BYTES {
                return Err(TransportError::gdb(format!(
                    "response packet exceeded {MAX_PACKET_BYTES} byte cap"
                )));
            }
        }
        let checksum = [
            self.read_byte_required("checksum digit 1")?,
            self.read_byte_required("checksum digit 2")?,
        ];
        let given = parse_hex_byte(&checksum)?;
        let want = rsp_checksum(&data);
        if given != want {
            self.channel.write_all(b"-")?;
            self.channel.flush()?;
            return Err(TransportError::gdb(format!(
                "response checksum mismatch: got {given:02x}, computed {want:02x}"
            )));
        }
        self.channel.write_all(b"+")?;
        self.channel.flush()?;
        Ok(Some(unescape(&data)?))
    }
}

impl<C: Read + Write + ReadDeadline> GdbConnection<C> {
    /// Bound the next blocking read(s) by the REMAINING time until `deadline`, so
    /// the absolute per-input budget is enforced read-by-read (#70 re-review). A
    /// `None` deadline leaves the channel's standing timeout unchanged. A minimum
    /// of 1ms is armed even once the budget is spent, so the next read returns
    /// promptly (rather than with a zero/forever timeout) and the caller observes
    /// the deadline. Channels that cannot set a read deadline are a no-op here;
    /// the GDB transport's live channel is a `TcpStream`, which can.
    fn arm_read_budget(&mut self, deadline: Option<Instant>) {
        if let Some(deadline) = deadline {
            let remaining = deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1));
            let _ = self.channel.set_read_deadline(Some(remaining));
        }
    }
}

/// Higher-level RSP client: attach, memory access, continue, reset.
pub struct GdbClient<C> {
    connection: GdbConnection<C>,
}

impl<C: Read + Write> GdbClient<C> {
    /// Wrap a byte channel as a client.
    pub fn new(channel: C) -> Self {
        Self {
            connection: GdbConnection::new(channel),
        }
    }

    fn command(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        self.connection.send_packet(packet)?;
        self.connection.recv_packet()
    }

    fn expect_ok(&mut self, response: &[u8], context: &str) -> Result<()> {
        match response {
            b"OK" => Ok(()),
            body if body.first() == Some(&b'E') => Err(TransportError::TargetError(format!(
                "{context}: {}",
                String::from_utf8_lossy(body)
            ))),
            other => Err(TransportError::gdb(format!(
                "{context}: expected OK, got {:?}",
                String::from_utf8_lossy(other)
            ))),
        }
    }

    /// Attach: enable extended mode (`!`) then query the initial stop state
    /// (`?`). Some stubs answer `!` with an empty packet; both are accepted.
    pub fn attach(&mut self) -> Result<StopReply> {
        let extended = self.command(b"!")?;
        if !extended.is_empty() && extended != b"OK" {
            return Err(TransportError::gdb(format!(
                "unexpected reply to extended-mode '!': {:?}",
                String::from_utf8_lossy(&extended)
            )));
        }
        let stop = self.command(b"?")?;
        StopReply::parse(&stop)
    }

    /// Read `length` bytes of target memory at `address` via `m addr,length`.
    pub fn read_memory(&mut self, address: u64, length: usize) -> Result<Vec<u8>> {
        if length > MAX_MEMORY_READ {
            return Err(TransportError::gdb(format!(
                "memory read length {length} exceeds {MAX_MEMORY_READ} byte cap"
            )));
        }
        let response = self.command(format!("m{address:x},{length:x}").as_bytes())?;
        if is_error_reply(&response) {
            return Err(TransportError::TargetError(format!(
                "memory read at {address:#x}: {}",
                String::from_utf8_lossy(&response)
            )));
        }
        let bytes = from_hex(&response)?;
        if bytes.len() != length {
            return Err(TransportError::gdb(format!(
                "memory read returned {} bytes, requested {length}",
                bytes.len()
            )));
        }
        Ok(bytes)
    }

    /// Write `data` to target memory at `address` via `M addr,len:hex`.
    pub fn write_memory(&mut self, address: u64, data: &[u8]) -> Result<()> {
        let packet = format!(
            "M{address:x},{len:x}:{hex}",
            len = data.len(),
            hex = to_hex(data)
        );
        let response = self.command(packet.as_bytes())?;
        self.expect_ok(&response, "memory write")
    }

    /// Read the general register block via `g`.
    pub fn read_registers(&mut self) -> Result<Vec<u8>> {
        let response = self.command(b"g")?;
        if is_error_reply(&response) {
            return Err(TransportError::TargetError(format!(
                "register read: {}",
                String::from_utf8_lossy(&response)
            )));
        }
        from_hex(&response)
    }
}

/// The `continue`-family run-control, split out because it bounds each blocking
/// read by the remaining absolute per-input budget (#70 re-review) and therefore
/// needs a channel that can set a read deadline ([`ReadDeadline`]).
impl<C: Read + Write + ReadDeadline> GdbClient<C> {
    /// Continue execution via `c`, draining any intermediate `O<hex>` console
    /// -output packets (semihosting / serial writes the target emits while it
    /// runs) until the terminal stop reply. Returns the stop together with the
    /// decoded console output, which the session surfaces as
    /// [`RunOutcome::stdout`].
    ///
    /// Per the RSP specification a debugger must keep reading after an `O`
    /// packet and wait for the real stop or exit; parsing the first frame as
    /// the stop reply (a single send/recv) aborts any run that prints. An
    /// unsupported intermediate frame is surfaced as an explicit error rather
    /// than interpreted as a completed clean execution, and the retained output
    /// is bounded by byte and packet counts so a continuous stream cannot run
    /// unbounded.
    pub fn cont(&mut self) -> Result<(StopReply, Vec<u8>)> {
        match self.cont_until(None)? {
            (ContStop::Stopped(stop), output) => Ok((stop, output)),
            // With no deadline supplied the loop never yields DeadlineExceeded;
            // guard it explicitly rather than panic so the invariant is visible.
            (ContStop::DeadlineExceeded, _) => Err(TransportError::gdb(
                "cont() reported a deadline with no deadline configured",
            )),
        }
    }

    /// Like [`GdbClient::cont`] but bounded by an absolute per-input execution
    /// `deadline` (#70). When the target reaches a stop first, returns
    /// [`ContStop::Stopped`]; when the deadline elapses (or a read times out with
    /// a deadline configured — the read timeout IS the per-input budget), returns
    /// [`ContStop::DeadlineExceeded`] with whatever console output was drained so
    /// far, so the session can record a target-execution timeout (a hang) instead
    /// of blocking forever or misreading the hang as a lost link. `None` restores
    /// the unbounded behavior (bounded only by the socket read timeout and the
    /// packet/byte caps), for callers with no per-input deadline.
    pub fn cont_until(&mut self, deadline: Option<Instant>) -> Result<(ContStop, Vec<u8>)> {
        // Arm the `c` send + its ack read with the remaining budget, then send.
        self.connection.arm_read_budget(deadline);
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Ok((ContStop::DeadlineExceeded, Vec::new()));
        }
        self.connection.send_packet(b"c")?;
        let mut output = Vec::new();
        for _ in 0..MAX_CONSOLE_PACKETS {
            if deadline.is_some_and(|d| Instant::now() >= d) {
                return Ok((ContStop::DeadlineExceeded, output));
            }
            // Re-arm every read with the REMAINING absolute budget, so no single
            // packet — even one dribbled a byte at a time — can push the total past
            // the deadline (a fixed per-read socket timeout could be restarted
            // indefinitely by partial progress).
            self.connection.arm_read_budget(deadline);
            let frame = match self.connection.recv_packet() {
                Ok(frame) => frame,
                // A read timeout while a per-input deadline is in force is the
                // budget elapsing on a silent (hung) target during execution —
                // a target timeout, not a lost link. With no deadline the timeout
                // is a genuine I/O failure and propagates unchanged.
                Err(err) if deadline.is_some() && is_timeout_err(&err) => {
                    return Ok((ContStop::DeadlineExceeded, output));
                }
                Err(err) => return Err(err),
            };
            match frame.split_first() {
                Some((&b'O', payload)) => {
                    let decoded = from_hex(payload)?;
                    if output.len() + decoded.len() > MAX_CONSOLE_BYTES {
                        return Err(TransportError::gdb(format!(
                            "console output exceeded {MAX_CONSOLE_BYTES} bytes before a stop reply"
                        )));
                    }
                    output.extend_from_slice(&decoded);
                }
                // A terminal stop reply. Reject it as a hang if it only arrived
                // AFTER the deadline — a late stop is not a normal in-budget stop.
                _ => {
                    if deadline.is_some_and(|d| Instant::now() >= d) {
                        return Ok((ContStop::DeadlineExceeded, output));
                    }
                    return Ok((ContStop::Stopped(StopReply::parse(&frame)?), output));
                }
            }
        }
        Err(TransportError::gdb(format!(
            "received more than {MAX_CONSOLE_PACKETS} console-output packets before a stop reply"
        )))
    }
}

impl<C: Read + Write> GdbClient<C> {
    /// Reset the target between iterations: enable extended mode, then issue
    /// the `R` restart packet (which, per RSP, has no reply).
    pub fn reset(&mut self) -> Result<()> {
        let extended = self.command(b"!")?;
        if !extended.is_empty() && extended != b"OK" {
            return Err(TransportError::gdb(format!(
                "unexpected reply to extended-mode '!': {:?}",
                String::from_utf8_lossy(&extended)
            )));
        }
        // `R XX` restarts; the argument is ignored by the stub and there is no
        // response packet, only the framing ack that send_packet consumes.
        self.connection.send_packet(b"R00")
    }

    /// Insert a software breakpoint at `address` via `Z0,addr,kind`.
    ///
    /// `kind` is the RSP breakpoint "kind" — for ARM Thumb it is the instruction
    /// size in bytes (`2`), for ARM (A32) `4`. On a full-system Cortex-M target a
    /// harness cannot self-halt back to the debugger with a `bkpt` instruction:
    /// with halting-debug disabled (the default under a QEMU gdbstub), `bkpt`
    /// escalates to a HardFault instead of stopping to the debugger. The host
    /// therefore plants a breakpoint at the harness "done" symbol so that
    /// [`GdbClient::cont`] returns a real stop reply when the run completes. QEMU
    /// implements `Z0`/`z0` as gdbstub-side breakpoints that survive a snapshot
    /// restore (`loadvm`), so a single insert covers every iteration.
    pub fn insert_sw_breakpoint(&mut self, address: u64, kind: u32) -> Result<()> {
        let response = self.command(format!("Z0,{address:x},{kind:x}").as_bytes())?;
        self.expect_ok(&response, "insert software breakpoint")
    }

    /// Remove a software breakpoint at `address` via `z0,addr,kind`.
    pub fn remove_sw_breakpoint(&mut self, address: u64, kind: u32) -> Result<()> {
        let response = self.command(format!("z0,{address:x},{kind:x}").as_bytes())?;
        self.expect_ok(&response, "remove software breakpoint")
    }
}

/// Target memory layout the [`GdbRemoteTransport`] uses to inject input and
/// read the coverage ring back out.
#[derive(Debug, Clone, Copy)]
pub struct GdbMemoryMap {
    /// Address of the input staging region the harness reads from.
    pub input_address: u64,
    /// Address of the `adafuzz_probe_memory_buffer` ring.
    pub ring_address: u64,
    /// Address of `adafuzz_probe_memory_buffer_write` (little-endian `u32`).
    pub ring_write_address: u64,
    /// Address of `adafuzz_probe_memory_buffer_wrapped` (`u8`).
    pub ring_wrapped_address: u64,
    /// Ring capacity in bytes (length to read back).
    pub ring_capacity: usize,
}

/// A transport that drives a target over the GDB remote protocol.
///
/// `connect` dials a fresh RSP channel per [`TargetTransport::arm`] (a TCP
/// connection to OpenOCD / gdbserver / a QEMU gdbstub).
pub struct GdbRemoteTransport<F> {
    connect: F,
    map: GdbMemoryMap,
    exec_deadline: Option<Duration>,
}

impl<F> GdbRemoteTransport<F> {
    /// Build a transport with the given connection factory and memory map.
    pub fn new(connect: F, map: GdbMemoryMap) -> Self {
        Self {
            connect,
            map,
            exec_deadline: None,
        }
    }

    /// Set the absolute per-input execution deadline (#70). A run whose `continue`
    /// does not reach a stop within this wall-clock bound is a target-execution
    /// timeout (a hang), surfaced as an [`ExitKind::Timeout`] outcome rather than
    /// blocking on the socket read timeout alone. `None` (the default) relies on
    /// the connection's read timeout and the packet/byte caps.
    pub fn with_exec_deadline(mut self, deadline: Option<Duration>) -> Self {
        self.exec_deadline = deadline;
        self
    }
}

impl<F, C> TargetTransport for GdbRemoteTransport<F>
where
    F: Fn() -> Result<C>,
    C: Read + Write + ReadDeadline + 'static,
{
    fn arm(&self) -> Result<Box<dyn TargetSession>> {
        let mut client = GdbClient::new((self.connect)()?);
        client.attach()?;
        Ok(Box::new(GdbSession {
            client,
            map: self.map,
            exec_deadline: self.exec_deadline,
        }))
    }
}

/// Read the coverage ring control words and image out of target memory and
/// reconstruct the coverage edges.
///
/// Reads `adafuzz_probe_memory_buffer_write` (little-endian `u32`),
/// `_wrapped` (`u8`), and the ring image, then hands them to
/// [`MemoryBufferReader`] which honors the wrap. Shared by [`GdbSession`] and by
/// the HDF-4 [`crate::fullsystem::FullSystemTransport`] so the coverage read is
/// defined once. Every read is length-bounded by [`GdbClient::read_memory`].
pub fn read_coverage_ring<C: Read + Write>(
    client: &mut GdbClient<C>,
    map: &GdbMemoryMap,
) -> Result<Vec<u32>> {
    let write_bytes = client.read_memory(map.ring_write_address, 4)?;
    let write = u32::from_le_bytes([
        write_bytes[0],
        write_bytes[1],
        write_bytes[2],
        write_bytes[3],
    ]);
    let wrapped = client.read_memory(map.ring_wrapped_address, 1)?[0] != 0;
    let image = client.read_memory(map.ring_address, map.ring_capacity)?;
    MemoryBufferReader::new(image, write, wrapped)?.read_edges()
}

/// A live GDB-driven session.
pub struct GdbSession<C> {
    client: GdbClient<C>,
    map: GdbMemoryMap,
    exec_deadline: Option<Duration>,
}

impl<C: Read + Write + ReadDeadline> TargetSession for GdbSession<C> {
    fn run_input(&mut self, input: &[u8]) -> Result<RunOutcome> {
        // SETUP phase: reset + input injection. A failure here — including an I/O
        // timeout — is a control/infrastructure error, NOT a target-execution
        // hang, so it propagates (the caller halts without inventing a false
        // target-timing finding) rather than being classed as a target timeout.
        self.client.reset()?;
        self.client.write_memory(self.map.input_address, input)?;

        // EXECUTION phase: bounded by the absolute per-input deadline (#70). A
        // target that never reaches its stop within the deadline is a first-class
        // Timeout outcome (a hang) with a structured fault, distinct from a setup
        // failure or a lost link. Coverage is not read from a hung target.
        let deadline = self.exec_deadline.map(|budget| Instant::now() + budget);
        let (stop, stdout) = match self.client.cont_until(deadline)? {
            (ContStop::Stopped(stop), stdout) => (stop, stdout),
            (ContStop::DeadlineExceeded, stdout) => {
                let detail = match self.exec_deadline {
                    Some(budget) => format!(
                        "no stop within the per-input execution deadline {}ms",
                        budget.as_millis()
                    ),
                    None => "no stop within the per-input execution deadline".to_owned(),
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
                        "target hung: coverage ring not read after an execution timeout".to_owned(),
                    ),
                    inconclusive: None,
                });
            }
        };

        // COLLECTION phase: classify the stop reply FIRST, then collect coverage.
        // A coverage-readback failure must not erase an already-known stop (#74):
        // keep the exit classification and record the read failure as a diagnostic
        // instead of propagating an error that loses the crash.
        let exit = stop.to_exit_kind();
        let (coverage_edges, coverage_incomplete) =
            match read_coverage_ring(&mut self.client, &self.map) {
                Ok(edges) => (edges, None),
                Err(err) => (Vec::new(), Some(err.to_string())),
            };
        Ok(RunOutcome {
            exit,
            coverage_edges,
            // Fault classification over the debug-probe path is HDF-2.
            fault: None,
            stdout,
            coverage_incomplete,
            inconclusive: None,
        })
    }
}

/// True for an RSP `Exx` error reply (uppercase `E` + two hex digits).
fn is_error_reply(response: &[u8]) -> bool {
    response.len() == 3
        && response[0] == b'E'
        && response[1..].iter().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::{duplex, encode_event_stream, simulate_ring, MockGdbStub};
    use event_log::Event;
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn checksum_matches_known_values() {
        assert_eq!(rsp_checksum(b"OK"), 0x9a);
        assert_eq!(rsp_checksum(b""), 0x00);
        // wrapping add: 0xff + 0x01 = 0x00
        assert_eq!(rsp_checksum(&[0xff, 0x01]), 0x00);
    }

    #[test]
    fn encode_then_decode_round_trips_packet() {
        let frame = encode_packet(b"m1000,10");
        assert_eq!(frame.first(), Some(&b'$'));
        assert_eq!(decode_packet(&frame).unwrap(), b"m1000,10");
    }

    #[test]
    fn encode_produces_expected_checksummed_frame() {
        assert_eq!(encode_packet(b"OK"), b"$OK#9a");
    }

    #[test]
    fn decode_rejects_checksum_mismatch() {
        let error = decode_packet(b"$OK#00").unwrap_err();
        assert!(
            error.to_string().contains("checksum mismatch"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn decode_unescapes_escaped_bytes() {
        // '}' 0x03^0x20 == 0x23 ('#'); a literal '#' inside data must be escaped.
        let mut data = vec![b'X'];
        data.push(ESCAPE);
        data.push(b'#' ^ 0x20);
        let frame = encode_packet(&data);
        assert_eq!(decode_packet(&frame).unwrap(), vec![b'X', b'#']);
    }

    #[test]
    fn decode_expands_run_length_encoding() {
        // RSP: `<byte>*<count>` repeats the preceding byte `count - 29` more
        // times. Space (0x20) => 0x20 - 29 = 3, so `0* ` is `0` + 3 more = four
        // `0` bytes — the canonical example from the gdb RSP documentation.
        let frame = encode_packet(&[b'0', RUN_LENGTH, b' ']);
        assert_eq!(decode_packet(&frame).unwrap(), vec![b'0', b'0', b'0', b'0']);

        // A memory-style hex payload with a longer zero run: `00` then `*` then
        // '2' (0x32 => 21 more) reconstructs 22 `0` chars = 11 zero bytes.
        let mut data = vec![b'0', b'0', RUN_LENGTH, b'2'];
        data.extend_from_slice(b"ff");
        let expanded = decode_packet(&encode_packet(&data)).unwrap();
        assert_eq!(expanded.len(), 2 + 21 + 2);
        assert!(expanded[..23].iter().all(|&b| b == b'0'));
        assert_eq!(&expanded[23..], b"ff");
    }

    #[test]
    fn decode_rejects_run_length_marker_with_no_preceding_byte() {
        let frame = encode_packet(&[RUN_LENGTH, b' ']);
        let error = decode_packet(&frame).unwrap_err();
        assert!(
            error.to_string().contains("no preceding byte"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn stop_reply_parses_signal_exit_and_terminate_tags() {
        assert_eq!(StopReply::parse(b"S05").unwrap(), StopReply::Signal(5));
        assert_eq!(StopReply::parse(b"S0a").unwrap(), StopReply::Signal(10));
        assert_eq!(StopReply::parse(b"S0b").unwrap(), StopReply::Signal(11));
        // A `T` reply carries the same signal in its first two hex digits, then
        // register/thread fields the coarse decoder ignores.
        assert_eq!(
            StopReply::parse(b"T0b20:0000;thread:1;").unwrap(),
            StopReply::Signal(11)
        );
        assert_eq!(StopReply::parse(b"W00").unwrap(), StopReply::Exited(0));
        assert_eq!(StopReply::parse(b"X0b").unwrap(), StopReply::Terminated(11));
    }

    #[test]
    fn to_exit_kind_uses_gdb_protocol_signal_numbers() {
        use gdb_signal::*;
        // Fatal GDB-protocol signals classify as a crash, via both `S` and `T`.
        // SIGBUS is 10 here, not the host POSIX 7; a real `S0a` bus-error reply
        // was previously misclassified as a clean `Ok`.
        for sig in [ILL, ABRT, EMT, FPE, BUS, SEGV] {
            assert_eq!(
                StopReply::Signal(sig).to_exit_kind(),
                ExitKind::Crash,
                "GDB signal {sig} must classify as a crash"
            );
            assert_eq!(
                StopReply::parse(format!("T{sig:02x}").as_bytes())
                    .unwrap()
                    .to_exit_kind(),
                ExitKind::Crash,
            );
        }
        // Benign stops: "no signal" (0) and the breakpoint / single-step trap.
        assert_eq!(StopReply::Signal(0).to_exit_kind(), ExitKind::Ok);
        assert_eq!(StopReply::Signal(TRAP).to_exit_kind(), ExitKind::Ok);
        // A normal process exit is clean; an `X` termination is a crash.
        assert_eq!(StopReply::Exited(0).to_exit_kind(), ExitKind::Ok);
        assert_eq!(StopReply::Terminated(SEGV).to_exit_kind(), ExitKind::Crash);
    }

    #[test]
    fn cont_drains_console_output_before_the_stop_reply() {
        // The stub prints two console chunks via `O<hex>` packets, then stops
        // cleanly. cont() must preserve the output and still reach the stop
        // reply rather than aborting on the first `O` frame.
        let (client_end, stub_end) = duplex();
        let log = Arc::new(Mutex::new(Vec::<String>::new()));
        let stub = MockGdbStub::new(stub_end, log)
            .with_stop_reply(b"W00".to_vec())
            .with_console_output(vec![b"hello ".to_vec(), b"world".to_vec()]);
        let handle = thread::spawn(move || stub.serve());

        let mut client = GdbClient::new(client_end);
        client.attach().unwrap();
        let (stop, output) = client.cont().unwrap();
        drop(client);
        handle.join().unwrap().unwrap();

        assert_eq!(stop, StopReply::Exited(0));
        assert_eq!(output, b"hello world");
    }

    #[test]
    fn cont_preserves_a_fatal_stop_after_console_output() {
        // Console output followed by a SIGSEGV stop must retain both the fault
        // signal and the printed output.
        let (client_end, stub_end) = duplex();
        let log = Arc::new(Mutex::new(Vec::<String>::new()));
        let stub = MockGdbStub::new(stub_end, log)
            .with_stop_reply(b"S0b".to_vec())
            .with_console_output(vec![b"panic: boom\n".to_vec()]);
        let handle = thread::spawn(move || stub.serve());

        let mut client = GdbClient::new(client_end);
        client.attach().unwrap();
        let (stop, output) = client.cont().unwrap();
        drop(client);
        handle.join().unwrap().unwrap();

        assert_eq!(stop, StopReply::Signal(11));
        assert_eq!(stop.to_exit_kind(), ExitKind::Crash);
        assert_eq!(output, b"panic: boom\n");
    }

    #[test]
    fn cont_bounds_oversized_console_output() {
        // Two chunks whose decoded total exceeds MAX_CONSOLE_BYTES must be
        // diagnosed before any stop reply, so an output stream cannot grow
        // without bound (the absolute execution deadline is enforced by the
        // campaign).
        let chunk = vec![b'a'; MAX_CONSOLE_BYTES / 2 + 1];
        let (client_end, stub_end) = duplex();
        let log = Arc::new(Mutex::new(Vec::<String>::new()));
        let stub = MockGdbStub::new(stub_end, log)
            .with_stop_reply(b"W00".to_vec())
            .with_console_output(vec![chunk.clone(), chunk]);
        thread::spawn(move || {
            let _ = stub.serve();
        });

        let mut client = GdbClient::new(client_end);
        client.attach().unwrap();
        let error = client.cont().unwrap_err();
        assert!(
            error.to_string().contains("console output exceeded"),
            "expected a bounded-output diagnostic, got: {error}"
        );
    }

    #[test]
    fn client_reads_expected_memory_buffer_and_issues_reset() {
        let coverage = [0xde_u8, 0xad, 0xbe, 0xef];
        let region_base = 0x2000_0000_u64;

        let log = Arc::new(Mutex::new(Vec::<String>::new()));
        let (client_end, stub_end) = duplex();
        let stub = MockGdbStub::new(stub_end, Arc::clone(&log))
            .with_region(region_base, coverage.to_vec());
        let handle = thread::spawn(move || stub.serve());

        let mut client = GdbClient::new(client_end);
        client.attach().unwrap();
        let read_back = client.read_memory(region_base, coverage.len()).unwrap();
        client.reset().unwrap();

        // Close the client's channel so the stub sees EOF and returns.
        drop(client);
        handle.join().unwrap().unwrap();

        assert_eq!(read_back, coverage);

        let log = log.lock().unwrap();
        // The reset sequence: extended-mode '!' followed by the 'R00' restart.
        assert!(log.iter().any(|p| p == "!"), "log missing '!': {log:?}");
        assert!(log.iter().any(|p| p == "R00"), "log missing 'R00': {log:?}");
        // '?' from attach precedes the reset packets.
        assert!(log.iter().any(|p| p == "?"), "log missing '?': {log:?}");
    }

    #[test]
    fn client_inserts_and_removes_software_breakpoint() {
        let log = Arc::new(Mutex::new(Vec::<String>::new()));
        let (client_end, stub_end) = duplex();
        let stub = MockGdbStub::new(stub_end, Arc::clone(&log));
        let handle = thread::spawn(move || stub.serve());

        let mut client = GdbClient::new(client_end);
        client.attach().unwrap();
        // Thumb breakpoint (kind 2) at the harness "done" symbol.
        client.insert_sw_breakpoint(0x0000_00a8, 2).unwrap();
        client.remove_sw_breakpoint(0x0000_00a8, 2).unwrap();
        drop(client);
        handle.join().unwrap().unwrap();

        let log = log.lock().unwrap();
        assert!(
            log.iter().any(|p| p == "Z0,a8,2"),
            "log missing Z0 insert: {log:?}"
        );
        assert!(
            log.iter().any(|p| p == "z0,a8,2"),
            "log missing z0 remove: {log:?}"
        );
    }

    #[test]
    fn gdb_transport_run_input_reconstructs_ring_coverage() {
        // Scripted target memory: an event ring holding three breadcrumbs, plus
        // its control words, plus a writable input region. Exercised through
        // the TargetTransport seam (arm -> run_input).
        let events = vec![
            Event::Crumb { id: 11 },
            Event::Crumb { id: 22 },
            Event::Crumb { id: 33 },
        ];
        let stream = encode_event_stream(&events); // 15 bytes
        let ring_capacity = 32_usize;
        let (image, write, wrapped) = simulate_ring(&stream, ring_capacity);
        assert!(!wrapped);

        let map = GdbMemoryMap {
            input_address: 0x1000,
            ring_address: 0x4000,
            ring_write_address: 0x5000,
            ring_wrapped_address: 0x5100,
            ring_capacity,
        };

        let log = Arc::new(Mutex::new(Vec::<String>::new()));
        let (client_end, stub_end) = duplex();
        let stub = MockGdbStub::new(stub_end, Arc::clone(&log))
            .with_region(map.input_address, vec![0_u8; 64])
            .with_region(map.ring_address, image)
            .with_region(map.ring_write_address, write.to_le_bytes().to_vec())
            .with_region(map.ring_wrapped_address, vec![u8::from(wrapped)]);
        let handle = thread::spawn(move || stub.serve());

        // `arm` is called once; the factory hands out the single client end via
        // interior mutability (a real backend would dial a fresh socket here).
        let client_slot = Mutex::new(Some(client_end));
        let transport = GdbRemoteTransport::new(
            move || {
                client_slot
                    .lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| TransportError::gdb("connect invoked more than once"))
            },
            map,
        );

        let mut session = transport.arm().unwrap();
        let outcome = session.run_input(b"payload").unwrap();
        drop(session);
        handle.join().unwrap().unwrap();

        assert_eq!(outcome.exit, ExitKind::Ok);
        assert_eq!(outcome.coverage_edges, vec![11, 22, 33]);

        // The per-iteration reset ran and the input was written.
        let log = log.lock().unwrap();
        assert!(log.iter().any(|p| p == "R00"), "log missing reset: {log:?}");
        assert!(
            log.iter().any(|p| p.starts_with("M1000,")),
            "log missing input write: {log:?}"
        );
    }

    #[test]
    fn gdb_session_retains_crash_when_coverage_readback_fails() {
        // A SIGSEGV stop followed by a too-short ring read must retain the crash
        // (exit Crash) and record the readback failure, rather than propagating
        // an error that erases the already-observed crash (#74).
        let map = GdbMemoryMap {
            input_address: 0x1000,
            ring_address: 0x4000,
            ring_write_address: 0x5000,
            ring_wrapped_address: 0x5100,
            ring_capacity: 32,
        };
        let log = Arc::new(Mutex::new(Vec::<String>::new()));
        let (client_end, stub_end) = duplex();
        let stub = MockGdbStub::new(stub_end, log)
            .with_stop_reply(b"S0b".to_vec())
            .with_region(map.input_address, vec![0_u8; 64])
            .with_region(map.ring_address, vec![0_u8; 8]) // too short for cap=32
            .with_region(map.ring_write_address, 4_u32.to_le_bytes().to_vec())
            .with_region(map.ring_wrapped_address, vec![0_u8]);
        thread::spawn(move || {
            let _ = stub.serve();
        });

        let client_slot = Mutex::new(Some(client_end));
        let transport = GdbRemoteTransport::new(
            move || {
                client_slot
                    .lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| TransportError::gdb("connect invoked more than once"))
            },
            map,
        );
        let mut session = transport.arm().unwrap();
        let outcome = session.run_input(b"boom").unwrap();

        assert_eq!(outcome.exit, ExitKind::Crash);
        assert!(
            outcome.coverage_incomplete.is_some(),
            "the readback failure must be recorded alongside the retained crash"
        );
    }

    /// A channel that serves a fixed script of bytes to reads and, once the
    /// script is exhausted, reports a read timeout — modelling a target that acks
    /// the `continue` packet and then goes silent (hangs) for the deadline.
    struct AckThenSilent {
        to_read: std::collections::VecDeque<u8>,
    }

    impl Read for AckThenSilent {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.to_read.pop_front() {
                Some(byte) => {
                    buf[0] = byte;
                    Ok(1)
                }
                None => Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
            }
        }
    }

    impl Write for AckThenSilent {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl ReadDeadline for AckThenSilent {
        fn set_read_deadline(&self, _timeout: Option<Duration>) -> bool {
            false
        }
    }

    #[test]
    fn cont_until_times_out_on_a_silent_target_within_deadline() {
        // The target acks the `c` packet (one `+`) then stays silent. With a
        // per-input deadline in force, the read timeout is the budget elapsing on
        // a hung target: cont_until reports DeadlineExceeded (a hang), NOT a
        // propagated I/O error that the caller would misread as a lost link.
        let channel = AckThenSilent {
            to_read: std::collections::VecDeque::from(vec![b'+']),
        };
        let mut client = GdbClient::new(channel);
        let deadline = Instant::now() + Duration::from_secs(3600);
        let (stop, output) = client.cont_until(Some(deadline)).unwrap();
        assert_eq!(stop, ContStop::DeadlineExceeded);
        assert!(
            output.is_empty(),
            "no stop reply was read from the hung target"
        );
    }

    #[test]
    fn cont_until_without_a_deadline_propagates_a_read_timeout() {
        // With NO deadline configured, a read timeout is a genuine I/O failure
        // (setup/control, not a target-execution hang) and must propagate rather
        // than be silently converted into a DeadlineExceeded result.
        let channel = AckThenSilent {
            to_read: std::collections::VecDeque::from(vec![b'+']),
        };
        let mut client = GdbClient::new(channel);
        let err = client.cont_until(None).unwrap_err();
        assert!(
            is_timeout_err(&err),
            "a bare read timeout must propagate: {err}"
        );
    }

    #[test]
    fn cont_until_partial_packet_then_stall_hits_the_deadline() {
        // #70 re-review (partial-response boundary): the target acks `c` and
        // begins a stop reply (`$T0`) but never terminates the packet before going
        // silent. A partial/dribbled packet must NOT hang past the per-input
        // deadline — the read budget expires and cont_until reports DeadlineExceeded
        // rather than blocking inside one packet.
        let channel = AckThenSilent {
            to_read: std::collections::VecDeque::from(vec![b'+', b'$', b'T', b'0']),
        };
        let mut client = GdbClient::new(channel);
        let deadline = Instant::now() + Duration::from_secs(3600);
        let (stop, _out) = client.cont_until(Some(deadline)).unwrap();
        assert_eq!(stop, ContStop::DeadlineExceeded);
    }

    #[test]
    fn tcpstream_read_deadline_is_actually_enforced() {
        // The ReadDeadline impl the bounded run-control relies on must really bound
        // a blocking read on the live channel type. Connect a loopback pair, arm a
        // short read deadline, and read with no data available: the OS returns a
        // timeout promptly rather than blocking forever (#70 re-review).
        use std::io::Read;
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).expect("connect");
        let _server = listener.accept().expect("accept").0; // keep the peer open (no data)

        assert!(
            ReadDeadline::set_read_deadline(&client, Some(Duration::from_millis(150))),
            "a TcpStream must be able to set a read deadline"
        );
        let started = Instant::now();
        let mut buf = [0_u8; 1];
        let err = (&client)
            .read(&mut buf)
            .expect_err("read must time out, not block forever");
        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "a read past the deadline is a timeout, got: {err:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the read deadline must bound the blocking read"
        );
    }

    #[test]
    fn gdb_session_reports_timeout_when_execution_deadline_elapses() {
        // A 1ns per-input deadline elapses before the stop reply can be read: the
        // session reports a first-class Timeout outcome (a hang) with a Timeout
        // fault — not a crash, not a propagated error — and does not read coverage
        // from the hung target (#70).
        let map = GdbMemoryMap {
            input_address: 0x1000,
            ring_address: 0x4000,
            ring_write_address: 0x5000,
            ring_wrapped_address: 0x5100,
            ring_capacity: 32,
        };
        let log = Arc::new(Mutex::new(Vec::<String>::new()));
        let (client_end, stub_end) = duplex();
        let stub = MockGdbStub::new(stub_end, log)
            .with_stop_reply(b"W00".to_vec())
            .with_region(map.input_address, vec![0_u8; 64])
            .with_region(map.ring_address, vec![0_u8; 32])
            .with_region(map.ring_write_address, 0_u32.to_le_bytes().to_vec())
            .with_region(map.ring_wrapped_address, vec![0_u8]);
        thread::spawn(move || {
            let _ = stub.serve();
        });

        let slot = Mutex::new(Some(client_end));
        let transport = GdbRemoteTransport::new(
            move || {
                slot.lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| TransportError::gdb("connect invoked more than once"))
            },
            map,
        )
        .with_exec_deadline(Some(Duration::from_nanos(1)));

        let mut session = transport.arm().unwrap();
        let outcome = session.run_input(b"x").unwrap();
        assert_eq!(outcome.exit, ExitKind::Timeout);
        assert_eq!(
            outcome.fault.expect("a hang carries a Timeout fault").kind,
            FaultKind::Timeout
        );
        assert!(
            outcome.coverage_incomplete.is_some(),
            "a hung target's coverage ring is not presented as complete"
        );
    }
}
