// SPDX-License-Identifier: Apache-2.0

//! In-process test harnesses so the transports are testable with no hardware.
//!
//! This module is compiled into the crate (not gated behind `#[cfg(test)]`) so
//! the host-path integration follow-up and later tracks can reuse the mocks:
//!
//! * [`duplex`] — a blocking in-memory bidirectional byte channel (a std-only
//!   stand-in for a socket/serial pair), so a mock target can run on a thread.
//! * [`MockAgent`] — speaks the target side of the [`crate::agent`] protocol,
//!   emitting a scripted edge set and fault per input.
//! * [`MockGdbStub`] — a minimal gdbstub speaking the target side of RSP.
//! * [`MockQmpServer`] — a minimal QMP monitor: greeting, capability
//!   negotiation, `stop`/`cont`, and `savevm`/`loadvm` via `human-monitor-command`.
//! * [`MockRenodeMonitor`] — a minimal Renode telnet monitor: `pause`,
//!   `Save`/`Load` and `machine StartGdbServer`, with Renode's telnet
//!   negotiation, echo, colours and error text.
//! * [`DirtyLogFile`] — writes the dirty-page log the way the QEMU plugin of
//!   [`crate::fast_snapshot`] does, so `reset=fast` runs against the mocks.
//! * [`encode_event_stream`] / [`simulate_ring`] — build `BHF_EVENTS` byte
//!   streams and simulate the Ada ring buffer for the coverage-reader tests.

use crate::agent::{encode_response, read_input_frame, AgentLimits};
use crate::error::{Result, TransportError};
use crate::gdb::GdbConnection;
use crate::outcome::{ExitKind, Fault, RunOutcome};
use event_log::Event;
use serde_json::Value;
use std::collections::VecDeque;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};

// ---------------------------------------------------------------------------
// In-memory blocking duplex channel
// ---------------------------------------------------------------------------

struct PipeState {
    buffer: VecDeque<u8>,
    closed: bool,
}

struct Pipe {
    state: Mutex<PipeState>,
    ready: Condvar,
}

/// The write half of a one-directional in-memory pipe.
struct PipeWriter {
    pipe: Arc<Pipe>,
}

/// The read half of a one-directional in-memory pipe.
struct PipeReader {
    pipe: Arc<Pipe>,
}

fn new_pipe() -> (PipeWriter, PipeReader) {
    let pipe = Arc::new(Pipe {
        state: Mutex::new(PipeState {
            buffer: VecDeque::new(),
            closed: false,
        }),
        ready: Condvar::new(),
    });
    (
        PipeWriter {
            pipe: Arc::clone(&pipe),
        },
        PipeReader { pipe },
    )
}

impl Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.pipe.state.lock().unwrap();
        if state.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "duplex peer reader was dropped",
            ));
        }
        state.buffer.extend(buf.iter().copied());
        self.pipe.ready.notify_all();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        if let Ok(mut state) = self.pipe.state.lock() {
            state.closed = true;
            self.pipe.ready.notify_all();
        }
    }
}

impl Read for PipeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut state = self.pipe.state.lock().unwrap();
        loop {
            if !state.buffer.is_empty() {
                let n = state.buffer.len().min(buf.len());
                for slot in buf.iter_mut().take(n) {
                    *slot = state.buffer.pop_front().expect("buffer non-empty");
                }
                return Ok(n);
            }
            if state.closed {
                return Ok(0); // EOF: the writer half was dropped.
            }
            state = self.pipe.ready.wait(state).unwrap();
        }
    }
}

/// One end of a bidirectional in-memory channel: reads what the peer wrote,
/// writes what the peer will read. Dropping an end closes its outbound
/// direction, so the peer's next read observes EOF.
pub struct DuplexStream {
    writer: PipeWriter,
    reader: PipeReader,
}

impl Read for DuplexStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl Write for DuplexStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

impl crate::gdb::ReadDeadline for DuplexStream {
    /// An in-memory pipe cannot set a read deadline — but it also never blocks
    /// indefinitely (a read returns promptly or observes EOF), so a per-input
    /// execution deadline is still enforced by the caller's wall-clock checks.
    fn set_read_deadline(&self, _timeout: Option<std::time::Duration>) -> bool {
        false
    }
}

/// Create a connected pair of [`DuplexStream`] ends.
pub fn duplex() -> (DuplexStream, DuplexStream) {
    let (a_writer, a_reader) = new_pipe(); // direction: end1 -> end2
    let (b_writer, b_reader) = new_pipe(); // direction: end2 -> end1
    (
        DuplexStream {
            writer: a_writer,
            reader: b_reader,
        },
        DuplexStream {
            writer: b_writer,
            reader: a_reader,
        },
    )
}

// ---------------------------------------------------------------------------
// Mock on-target agent
// ---------------------------------------------------------------------------

/// A scripted response the [`MockAgent`] returns for one input.
#[derive(Debug, Clone)]
pub struct ScriptedResponse {
    /// Termination status.
    pub exit: ExitKind,
    /// Coverage edges to report.
    pub edges: Vec<u32>,
    /// A fault to report, if any.
    pub fault: Option<Fault>,
}

impl ScriptedResponse {
    /// A clean run reporting `edges`.
    pub fn ok(edges: Vec<u32>) -> Self {
        Self {
            exit: ExitKind::Ok,
            edges,
            fault: None,
        }
    }

    /// A crashing run reporting `edges` and `fault`.
    pub fn crash(edges: Vec<u32>, fault: Fault) -> Self {
        Self {
            exit: ExitKind::Crash,
            edges,
            fault: Some(fault),
        }
    }

    fn to_outcome(&self) -> RunOutcome {
        RunOutcome {
            target: Default::default(),
            exit: self.exit,
            coverage_edges: self.edges.clone(),
            fault: self.fault.clone(),
            stdout: Vec::new(),
            coverage_incomplete: None,
            inconclusive: None,
        }
    }
}

/// A mock target agent: reads input frames and answers with scripted responses.
///
/// It records each received input into the shared `received` vector so tests
/// can assert delivery. It serves exactly `script.len()` inputs, then returns;
/// the script must therefore cover every input the host will send.
pub struct MockAgent<C> {
    channel: C,
    script: Vec<ScriptedResponse>,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    limits: AgentLimits,
}

impl<C: Read + Write> MockAgent<C> {
    /// Build a mock agent over `channel` with the given script.
    pub fn new(
        channel: C,
        script: Vec<ScriptedResponse>,
        received: Arc<Mutex<Vec<Vec<u8>>>>,
    ) -> Self {
        Self {
            channel,
            script,
            received,
            limits: AgentLimits::default(),
        }
    }

    /// Serve the scripted responses, one per received input.
    pub fn serve(self) -> Result<()> {
        let MockAgent {
            mut channel,
            script,
            received,
            limits,
        } = self;
        for response in &script {
            match read_input_frame(&mut channel, &limits)? {
                Some(input) => received.lock().unwrap().push(input),
                None => return Ok(()), // host closed the link early.
            }
            let bytes = encode_response(&response.to_outcome());
            channel.write_all(&bytes)?;
            channel.flush()?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Mock gdbstub
// ---------------------------------------------------------------------------

struct MemRegion {
    base: u64,
    data: Vec<u8>,
}

impl MemRegion {
    /// Byte offset of `[addr, addr+len)` within this region, if fully contained.
    fn contains(&self, addr: u64, len: usize) -> Option<usize> {
        let end = addr.checked_add(len as u64)?;
        let region_end = self.base + self.data.len() as u64;
        if addr >= self.base && end <= region_end {
            Some((addr - self.base) as usize)
        } else {
            None
        }
    }
}

/// A File-I/O request (`F<call>,<args>`, without the `F`) a [`MockGdbStub`]
/// makes while the target runs, with the bytes it first places in memory for
/// it; the run goes on when the debugger's reply arrives.
type FileIoRequest = (String, Option<(u64, Vec<u8>)>);

/// A minimal gdbstub speaking the target side of the RSP: acks packets, answers
/// `!`/`?`/`g`/`m`/`M`/`c`/`s`/`Z`/`z`, and records a per-iteration `R` reset. Serves
/// memory reads/writes against scripted regions.
pub struct MockGdbStub<C: Read + Write> {
    connection: GdbConnection<C>,
    regions: Vec<MemRegion>,
    log: Arc<Mutex<Vec<String>>>,
    stop_reply: Vec<u8>,
    /// Stop replies for successive `c`s, before `stop_reply` takes over; an
    /// empty one sends nothing, as a target that never stops.
    stop_sequence: VecDeque<Vec<u8>>,
    /// The reply to a single step `s`.
    step_reply: Vec<u8>,
    /// Whether a step `s` moves the program counter, modeled as the register
    /// block's first byte going up by 2 (see [`MockGdbStub::with_step_in_place`]).
    step_moves: bool,
    /// For successive `c`s, whether that run skips the run writes, before
    /// every later `c` writes them (see [`MockGdbStub::with_runs_that_write`]).
    run_writes_per_c: VecDeque<bool>,
    registers: Vec<u8>,
    /// Raw payloads emitted as `O<hex>` console-output packets before the stop
    /// reply on a `c`, modeling a target that prints while it runs.
    console_output: Vec<Vec<u8>>,
    /// Memory the target writes while it runs, applied on each `c`.
    run_writes: Vec<(u64, Vec<u8>)>,
    /// File-I/O requests the target makes on each `c` (#292).
    file_io: Vec<FileIoRequest>,
    /// Whether it takes monitor commands (`qRcmd`).
    monitor: bool,
    /// Whether it sends Renode's unprompted `S05`s (see
    /// [`MockGdbStub::with_unsolicited_stops`]).
    unsolicited_stops: bool,
    /// Where the run writes are logged by page, as the QEMU dirty-page plugin
    /// logs a guest's stores (see [`MockGdbStub::with_dirty_log`]).
    dirty_log: Option<DirtyLogFile>,
    /// The register block each `c` leaves (see
    /// [`MockGdbStub::with_run_registers`]).
    run_registers: Option<Vec<u8>>,
    /// The target description annexes served by `qXfer:features:read`.
    description: Vec<(String, String)>,
    /// Registers `p` reads, by number, as 32-bit values: their values now,
    /// those a monitor reset puts back, and those successive `c`s leave (see
    /// [`MockGdbStub::with_register`]).
    numbered: std::collections::BTreeMap<u32, u32>,
    numbered_baseline: std::collections::BTreeMap<u32, u32>,
    numbered_per_c: VecDeque<Vec<(u32, u32)>>,
}

impl<C: Read + Write> MockGdbStub<C> {
    /// Build a stub over `channel`; `log` records every received packet body.
    pub fn new(channel: C, log: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            connection: GdbConnection::new(channel),
            regions: Vec::new(),
            log,
            stop_reply: b"S05".to_vec(),
            stop_sequence: VecDeque::new(),
            step_reply: b"S05".to_vec(),
            step_moves: true,
            run_writes_per_c: VecDeque::new(),
            registers: vec![0_u8; 4],
            console_output: Vec::new(),
            run_writes: Vec::new(),
            file_io: Vec::new(),
            monitor: true,
            unsolicited_stops: false,
            dirty_log: None,
            run_registers: None,
            description: Vec::new(),
            numbered: std::collections::BTreeMap::new(),
            numbered_baseline: std::collections::BTreeMap::new(),
            numbered_per_c: VecDeque::new(),
        }
    }

    /// Serve `annexes` (`(name, document)`, `target.xml` among them) for
    /// `qXfer:features:read`, as a stub with a target description does.
    pub fn with_target_description(mut self, annexes: &[(&str, &str)]) -> Self {
        self.description = annexes
            .iter()
            .map(|(name, document)| ((*name).to_owned(), (*document).to_owned()))
            .collect();
        self
    }

    /// Serve register `number` for `p` as the 32-bit `value`, which a monitor
    /// reset (`qRcmd`) puts back.
    pub fn with_register(mut self, number: u32, value: u32) -> Self {
        self.numbered.insert(number, value);
        self.numbered_baseline.insert(number, value);
        self
    }

    /// Successive `c`s leave the numbered registers of each entry with those
    /// values, as runs that stop in different places do.
    pub fn with_registers_per_c(mut self, runs: Vec<Vec<(u32, u32)>>) -> Self {
        self.numbered_per_c = runs.into();
        self
    }

    /// Leave `registers` as the register block after each `c`, as a run that
    /// stops somewhere other than where it started does.
    pub fn with_run_registers(mut self, registers: Vec<u8>) -> Self {
        self.run_registers = Some(registers);
        self
    }

    /// Log the pages of each run write in `log`, as QEMU's dirty-page plugin
    /// logs the guest's stores (`reset=fast`). Memory the debugger writes is
    /// not logged, as the plugin does not see it.
    pub fn with_dirty_log(mut self, log: DirtyLogFile) -> Self {
        self.dirty_log = Some(log);
        self
    }

    /// Send an unprompted `S05` as the debugger connects and another after
    /// each `c`'s stop reply, as Renode's gdb server does.
    pub fn with_unsolicited_stops(mut self) -> Self {
        self.unsolicited_stops = true;
        self
    }

    /// Refuse monitor commands with an empty reply, as QEMU's system gdbstub
    /// refuses `R`.
    pub fn without_monitor(mut self) -> Self {
        self.monitor = false;
        self
    }

    /// On each `c`, write `data` at `address` and make a File-I/O
    /// `write(fd, address, len)` request for it, as a semihosting call routed
    /// to the debugger does; the run goes on when the reply arrives.
    pub fn with_file_io_write(mut self, fd: u64, address: u64, data: Vec<u8>) -> Self {
        let request = format!("write,{fd:x},{address:x},{:x}", data.len());
        self.file_io.push((request, Some((address, data))));
        self
    }

    /// On each `c`, make the File-I/O request `F<request>` (no `F`), with no
    /// memory placed for it.
    pub fn with_file_io_request(mut self, request: &str) -> Self {
        self.file_io.push((request.to_owned(), None));
        self
    }

    /// On each `c`, write `data` at `address` before the stop reply, modeling
    /// a target that records something (a comparison log) while it runs.
    pub fn with_run_write(mut self, address: u64, data: Vec<u8>) -> Self {
        self.run_writes.push((address, data));
        self
    }

    /// Register a memory region served for `m`/`M`.
    pub fn with_region(mut self, base: u64, data: Vec<u8>) -> Self {
        self.regions.push(MemRegion { base, data });
        self
    }

    /// Override the stop-reply packet returned by `?` and `c`.
    pub fn with_stop_reply(mut self, reply: Vec<u8>) -> Self {
        self.stop_reply = reply;
        self
    }

    /// Answer successive `c`s with `replies` in order, then with the stop
    /// reply. An empty reply sends nothing: the target runs on and never
    /// stops, so only a client's read deadline ends the wait.
    pub fn with_stop_sequence(mut self, replies: Vec<Vec<u8>>) -> Self {
        self.stop_sequence = replies.into();
        self
    }

    /// Answer a single step `s` with `reply` (by default `S05`, a trap one
    /// instruction on), as a stub that cannot step answers `E01`.
    pub fn with_step_reply(mut self, reply: &[u8]) -> Self {
        self.step_reply = reply.to_vec();
        self
    }

    /// Leave the registers as they are on a step `s`, as a target parked on a
    /// branch to itself (`b .`) does; by default a step moves the program
    /// counter.
    pub fn with_step_in_place(mut self) -> Self {
        self.step_moves = false;
        self
    }

    /// For successive `c`s, whether the run makes its run writes
    /// ([`MockGdbStub::with_run_write`]): `false` models a target that comes
    /// straight back to its stop without running. Every `c` past the list
    /// writes them.
    pub fn with_runs_that_write(mut self, writes: Vec<bool>) -> Self {
        self.run_writes_per_c = writes.into();
        self
    }

    /// Emit each payload as an `O<hex>` console-output packet before the stop
    /// reply on a `c`, modeling a target that writes to the console/semihosting
    /// while it runs.
    pub fn with_console_output(mut self, chunks: Vec<Vec<u8>>) -> Self {
        self.console_output = chunks;
        self
    }

    /// `qXfer:features:read:ANNEX:OFFSET,LENGTH`: `m` and a chunk, or `l`
    /// and the rest; an annex it does not have is an empty reply.
    fn handle_feature_read(&self, packet: &[u8]) -> Vec<u8> {
        let request = String::from_utf8_lossy(&packet[b"qXfer:features:read:".len()..]);
        let Some((annex, span)) = request.rsplit_once(':') else {
            return b"E00".to_vec();
        };
        let Some(document) = self
            .description
            .iter()
            .find_map(|(name, document)| (name == annex).then_some(document))
        else {
            return Vec::new();
        };
        let Some((offset, length)) = parse_addr_len(span.as_bytes()) else {
            return b"E00".to_vec();
        };
        let bytes = document.as_bytes();
        let start = (offset as usize).min(bytes.len());
        let end = (start + length).min(bytes.len());
        let mut reply = vec![if end == bytes.len() { b'l' } else { b'm' }];
        reply.extend_from_slice(&bytes[start..end]);
        reply
    }

    fn handle_read(&self, packet: &[u8]) -> Vec<u8> {
        // packet == b"m<addr>,<len>"
        let Some((addr, len)) = parse_addr_len(&packet[1..]) else {
            return b"E01".to_vec();
        };
        for region in &self.regions {
            if let Some(offset) = region.contains(addr, len) {
                return hex(&region.data[offset..offset + len]).into_bytes();
            }
        }
        b"E01".to_vec()
    }

    fn handle_write(&mut self, packet: &[u8]) -> Vec<u8> {
        // packet == b"M<addr>,<len>:<hex>"
        let Some(colon) = packet.iter().position(|&b| b == b':') else {
            return b"E01".to_vec();
        };
        let Some((addr, len)) = parse_addr_len(&packet[1..colon]) else {
            return b"E01".to_vec();
        };
        let Some(bytes) = unhex(&packet[colon + 1..]) else {
            return b"E01".to_vec();
        };
        if bytes.len() != len {
            return b"E01".to_vec();
        }
        for region in &mut self.regions {
            if let Some(offset) = region.contains(addr, len) {
                region.data[offset..offset + len].copy_from_slice(&bytes);
                return b"OK".to_vec();
            }
        }
        // Unmapped writes are accepted but dropped (harmless in tests).
        b"OK".to_vec()
    }

    /// Run the serve loop until the client closes the link.
    pub fn serve(mut self) -> Result<()> {
        if self.unsolicited_stops {
            self.connection.send_unacked(b"S05")?;
        }
        while let Some(packet) = self.connection.recv_packet_opt()? {
            self.log
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(&packet).into_owned());
            let Some(&command) = packet.first() else {
                self.connection.send_packet(b"")?; // empty packet
                continue;
            };
            match command {
                b'!' => self.connection.send_packet(b"OK")?,
                b'?' => {
                    let reply = self.stop_reply.clone();
                    self.connection.send_packet(&reply)?;
                }
                b'c' => {
                    let writes = self.run_writes_per_c.pop_front().unwrap_or(true);
                    for (address, data) in self.run_writes.clone().into_iter().filter(|_| writes) {
                        for region in &mut self.regions {
                            if let Some(offset) = region.contains(address, data.len()) {
                                region.data[offset..offset + data.len()].copy_from_slice(&data);
                            }
                        }
                        if let Some(log) = &self.dirty_log {
                            log.record(address, data.len())
                                .map_err(TransportError::from)?;
                        }
                    }
                    if let Some(log) = &self.dirty_log {
                        // The guest ran: the plugin saw it.
                        log.saw_access().map_err(TransportError::from)?;
                    }
                    if let Some(registers) = &self.run_registers {
                        self.registers = registers.clone();
                    }
                    for (number, value) in self.numbered_per_c.pop_front().unwrap_or_default() {
                        self.numbered.insert(number, value);
                    }
                    // File-I/O requests, each answered before the run goes on:
                    // the debugger reads the buffer with `m` and replies `F`.
                    for (request, placed) in self.file_io.clone() {
                        if let Some((address, data)) = placed {
                            for region in &mut self.regions {
                                if let Some(offset) = region.contains(address, data.len()) {
                                    region.data[offset..offset + data.len()].copy_from_slice(&data);
                                }
                            }
                        }
                        self.connection
                            .send_packet(format!("F{request}").as_bytes())?;
                        while let Some(reply) = self.connection.recv_packet_opt()? {
                            self.log
                                .lock()
                                .unwrap()
                                .push(String::from_utf8_lossy(&reply).into_owned());
                            match reply.first() {
                                // A reply with the Ctrl-C flag stops the
                                // target, which reports it and waits for `c`.
                                Some(b'F') if reply.ends_with(b",C") => {
                                    self.connection.send_packet(b"T02")?;
                                    while let Some(next) = self.connection.recv_packet_opt()? {
                                        self.log
                                            .lock()
                                            .unwrap()
                                            .push(String::from_utf8_lossy(&next).into_owned());
                                        if next.first() == Some(&b'c') {
                                            break;
                                        }
                                        self.connection.send_packet(b"")?;
                                    }
                                    break;
                                }
                                Some(b'F') => break,
                                Some(b'm') => {
                                    let read = self.handle_read(&reply);
                                    self.connection.send_packet(&read)?;
                                }
                                _ => self.connection.send_packet(b"")?,
                            }
                        }
                    }
                    // Emit any scripted console output as `O<hex>` packets first,
                    // exactly as a real stub does while the target prints, then
                    // the terminal stop reply.
                    for chunk in &self.console_output {
                        let mut packet = vec![b'O'];
                        packet.extend_from_slice(hex(chunk).as_bytes());
                        self.connection.send_packet(&packet)?;
                    }
                    let reply = self
                        .stop_sequence
                        .pop_front()
                        .unwrap_or_else(|| self.stop_reply.clone());
                    if reply.is_empty() {
                        continue;
                    }
                    self.connection.send_packet(&reply)?;
                    if self.unsolicited_stops {
                        self.connection.send_unacked(b"S05")?;
                    }
                }
                b's' => {
                    if self.step_moves {
                        if let Some(pc) = self.registers.first_mut() {
                            *pc = pc.wrapping_add(2);
                        }
                    }
                    let reply = self.step_reply.clone();
                    self.connection.send_packet(&reply)?;
                }
                b'g' => {
                    let reply = hex(&self.registers).into_bytes();
                    self.connection.send_packet(&reply)?;
                }
                b'm' => {
                    let reply = self.handle_read(&packet);
                    self.connection.send_packet(&reply)?;
                }
                b'M' => {
                    let reply = self.handle_write(&packet);
                    self.connection.send_packet(&reply)?;
                }
                b'R' => { /* restart: RSP defines no reply for `R`. */ }
                // A monitor command: a line of output, then OK.
                b'q' if self.monitor && packet.starts_with(b"qRcmd,") => {
                    // The mock's monitor command resets the machine.
                    self.numbered = self.numbered_baseline.clone();
                    self.connection.send_packet(b"O6f6b0a")?;
                    self.connection.send_packet(b"OK")?;
                }
                b'q' if packet.starts_with(b"qXfer:features:read:") => {
                    let reply = self.handle_feature_read(&packet);
                    self.connection.send_packet(&reply)?;
                }
                b'p' => {
                    let number = std::str::from_utf8(&packet[1..])
                        .ok()
                        .and_then(|number| u32::from_str_radix(number, 16).ok());
                    let reply = match number.and_then(|number| self.numbered.get(&number)) {
                        Some(value) => hex(&value.to_le_bytes()).into_bytes(),
                        None => b"E14".to_vec(),
                    };
                    self.connection.send_packet(&reply)?;
                }
                b'Z' | b'z' => self.connection.send_packet(b"OK")?, // (in|re)move breakpoint
                // QEMU's physical-memory mode for `m`/`M`: the mock's
                // memory has one address space.
                b'Q' if packet.starts_with(b"Qqemu.PhyMemMode:") => {
                    self.connection.send_packet(b"OK")?
                }
                _ => self.connection.send_packet(b"")?, // unsupported
            }
        }
        Ok(())
    }
}

/// Parse an `<addr>,<len>` pair of hex integers (no `0x`).
fn parse_addr_len(bytes: &[u8]) -> Option<(u64, usize)> {
    let text = std::str::from_utf8(bytes).ok()?;
    let (addr, len) = text.split_once(',')?;
    let addr = u64::from_str_radix(addr, 16).ok()?;
    let len = usize::from_str_radix(len, 16).ok()?;
    Some((addr, len))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn unhex(bytes: &[u8]) -> Option<Vec<u8>> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// Mock QMP monitor
// ---------------------------------------------------------------------------

/// A minimal QMP (QEMU Machine Protocol) server for driving [`crate::fullsystem`]
/// tests without a real `qemu-system`.
///
/// It sends the opening greeting, then for each request logs the executed
/// command and answers:
///
/// * `human-monitor-command` — logged as `hmp:<command-line>`; answered with
///   `{"return": ""}` (an empty HMP output, i.e. `savevm`/`loadvm` success),
///   or with the output [`MockQmpServer::with_hmp_output`] scripted for it.
/// * `system_reset` — logged; answered with a `RESET` event and then
///   `{"return": {}}`, in the order QEMU 8.2 sends them.
/// * any other command (`qmp_capabilities`, `stop`, `cont`, …) — logged by its
///   `execute` name; answered with `{"return": {}}`.
///
/// A request without an `execute` field is answered with a QMP `error` object.
pub struct MockQmpServer<C: Read + Write> {
    channel: C,
    log: Arc<Mutex<Vec<String>>>,
    /// HMP command lines and the output each answers with.
    hmp_output: Vec<(String, String)>,
}

impl<C: Read + Write> MockQmpServer<C> {
    /// Build a server over `channel`; `log` records each executed command.
    pub fn new(channel: C, log: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            channel,
            log,
            hmp_output: Vec::new(),
        }
    }

    /// Answer the HMP command line `command` (`info roms`) with `output`.
    pub fn with_hmp_output(mut self, command: &str, output: &str) -> Self {
        self.hmp_output
            .push((command.to_owned(), output.to_owned()));
        self
    }

    fn read_byte(&mut self) -> Result<Option<u8>> {
        let mut buf = [0_u8; 1];
        match self.channel.read(&mut buf)? {
            0 => Ok(None),
            _ => Ok(Some(buf[0])),
        }
    }

    /// Read one `\n`-terminated line; `Ok(None)` on a clean EOF between messages.
    fn read_line(&mut self) -> Result<Option<Vec<u8>>> {
        let mut line = Vec::new();
        loop {
            match self.read_byte()? {
                None if line.is_empty() => return Ok(None),
                None => {
                    return Err(TransportError::protocol(
                        "mock QMP client closed mid-message",
                    ))
                }
                Some(b'\n') => {
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                    return Ok(Some(line));
                }
                Some(byte) => line.push(byte),
            }
        }
    }

    fn send_line(&mut self, bytes: &[u8]) -> Result<()> {
        self.channel.write_all(bytes)?;
        self.channel.write_all(b"\n")?;
        self.channel.flush()?;
        Ok(())
    }

    /// Serve until the client closes the link.
    pub fn serve(mut self) -> Result<()> {
        self.send_line(
            br#"{"QMP":{"version":{"qemu":{"major":8,"minor":2,"micro":0},"package":""},"capabilities":[]}}"#,
        )?;
        while let Some(line) = self.read_line()? {
            let request: Value = serde_json::from_slice(&line).map_err(|error| {
                TransportError::protocol(format!("mock QMP received invalid JSON: {error}"))
            })?;
            match request.get("execute").and_then(Value::as_str) {
                Some("human-monitor-command") => {
                    let command_line = request
                        .get("arguments")
                        .and_then(|args| args.get("command-line"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    self.log.lock().unwrap().push(format!("hmp:{command_line}"));
                    let output = self
                        .hmp_output
                        .iter()
                        .find(|(command, _)| command == command_line)
                        .map_or("", |(_, output)| output.as_str());
                    let reply = serde_json::json!({ "return": output }).to_string();
                    self.send_line(reply.as_bytes())?;
                }
                Some(command) => {
                    self.log.lock().unwrap().push(command.to_string());
                    if command == "system_reset" {
                        self.send_line(
                            br#"{"timestamp":{"seconds":0,"microseconds":0},"event":"RESET","data":{"guest":false,"reason":"host-qmp-system-reset"}}"#,
                        )?;
                    }
                    self.send_line(br#"{"return":{}}"#)?;
                }
                None => {
                    self.send_line(
                        br#"{"error":{"class":"GenericError","desc":"request has no execute field"}}"#,
                    )?;
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The QEMU plugin's dirty-page log
// ---------------------------------------------------------------------------

/// A dirty-page log file written the way the QEMU plugin of
/// [`crate::fast_snapshot`] writes one: its header, then each page written
/// since bhf last emptied the log, once, until the log is full and says it
/// overflowed.
#[derive(Debug, Clone)]
pub struct DirtyLogFile {
    path: PathBuf,
}

/// The plugin log's header bytes.
const DIRTY_LOG_HEADER: usize = 88;

impl DirtyLogFile {
    /// Create (or truncate) the log at `path`, as the plugin does when QEMU
    /// loads it.
    pub fn create(path: &Path, page_bits: u32, capacity: u32) -> io::Result<Self> {
        let mut bytes = Vec::with_capacity(DIRTY_LOG_HEADER + capacity as usize * 8);
        bytes.extend_from_slice(&crate::fast_snapshot::DIRTY_LOG_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&crate::fast_snapshot::DIRTY_LOG_VERSION.to_le_bytes());
        bytes.extend_from_slice(&page_bits.to_le_bytes());
        bytes.extend_from_slice(&capacity.to_le_bytes());
        bytes.resize(DIRTY_LOG_HEADER + capacity as usize * 8, 0);
        std::fs::write(path, bytes)?;
        Self::open(path)
    }

    /// A writer for the log at `path`.
    pub fn open(path: &Path) -> io::Result<Self> {
        Ok(Self {
            path: path.to_owned(),
        })
    }

    /// The log's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn header(file: &mut std::fs::File) -> io::Result<[u8; DIRTY_LOG_HEADER]> {
        let mut header = [0_u8; DIRTY_LOG_HEADER];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut header)?;
        Ok(header)
    }

    fn file(&self) -> io::Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.path)
    }

    /// The guest made a memory access: acknowledge the log's epoch, as the
    /// plugin does on the first access it sees in one.
    pub fn saw_access(&self) -> io::Result<()> {
        let mut file = self.file()?;
        let header = Self::header(&mut file)?;
        let epoch = u64::from_le_bytes(header[16..24].try_into().expect("8 bytes"));
        file.seek(SeekFrom::Start(32))?;
        file.write_all(&epoch.wrapping_add(1).to_le_bytes())
    }

    /// The bit-band windows bhf put in the header, as `(alias, size,
    /// source)`, the unused ones left out.
    pub fn bitband_windows(&self) -> io::Result<Vec<(u64, u64, u64)>> {
        let header = Self::header(&mut self.file()?)?;
        let word = |at: usize| u64::from_le_bytes(header[at..at + 8].try_into().expect("8 bytes"));
        Ok((0..crate::fast_snapshot::BITBAND_WINDOWS)
            .map(|index| 40 + index * 24)
            .map(|at| (word(at), word(at + 8), word(at + 16)))
            .filter(|(_, size, _)| *size != 0)
            .collect())
    }

    /// Log the pages a store of `len` bytes at `address` writes.
    pub fn record(&self, address: u64, len: usize) -> io::Result<()> {
        if len == 0 {
            return Ok(());
        }
        let mut file = self.file()?;
        let header = Self::header(&mut file)?;
        let word = |at: usize| u32::from_le_bytes(header[at..at + 4].try_into().expect("4 bytes"));
        let (page_bits, capacity, mut count) = (word(8), word(12), word(24));
        let mut pages = vec![0_u8; count as usize * 8];
        file.read_exact(&mut pages)?;
        let mut recorded: Vec<u64> = pages
            .as_chunks::<8>()
            .0
            .iter()
            .map(|page| u64::from_le_bytes(*page))
            .collect();
        let first = address >> page_bits;
        let last = (address + len as u64 - 1) >> page_bits;
        for page in first..=last {
            if recorded.contains(&page) {
                continue;
            }
            if count >= capacity {
                file.seek(SeekFrom::Start(28))?;
                file.write_all(&1_u32.to_le_bytes())?;
                continue;
            }
            file.seek(SeekFrom::Start(
                DIRTY_LOG_HEADER as u64 + u64::from(count) * 8,
            ))?;
            file.write_all(&page.to_le_bytes())?;
            count += 1;
            recorded.push(page);
            file.seek(SeekFrom::Start(24))?;
            file.write_all(&count.to_le_bytes())?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Mock Renode monitor
// ---------------------------------------------------------------------------

/// A minimal Renode telnet monitor for driving [`crate::renode`] tests
/// without a real `renode`, modelled on Renode 1.17's wire bytes.
///
/// It opens with Renode's telnet option negotiation, banner and coloured
/// `(monitor) ` prompt, echoes each command line, and answers:
///
/// * `$name=value` — nothing (a variable assignment).
/// * `pause` / `start` — `Pausing emulation...` / `Starting emulation...`.
/// * `Save @PATH` — remembers `PATH`; no output.
/// * `Load @PATH` — when `PATH` was saved, no output, the gdb server stops,
///   as Renode's goes with the machine `Load` replaces, and no machine is
///   selected (the prompt reads `(monitor)`), as in Renode 1.17.0; otherwise
///   Renode's error text.
/// * `mach set "machine-0"` / `mach set 0` — selects the machine; another
///   name prints `Machine NAME not found.`
/// * `machine StartGdbServer PORT` — with a machine selected, sets the gdb
///   server to `PORT`, or Renode's "already attached" error while one runs;
///   with none, `No such command or device: machine`.
/// * anything else — `No such command or device: ...`.
///
/// Every command line is pushed to `log`. `gdb_server` holds the port of the
/// running gdb server, for the test's gdb dialer to check.
pub struct MockRenodeMonitor<C: Read + Write> {
    channel: C,
    log: Arc<Mutex<Vec<String>>>,
    gdb_server: Arc<Mutex<Option<u16>>>,
    saved: Vec<String>,
    failures: Vec<(String, String)>,
    startup_script: Option<String>,
    selected: bool,
}

impl<C: Read + Write> MockRenodeMonitor<C> {
    /// Build a monitor over `channel`.
    pub fn new(
        channel: C,
        log: Arc<Mutex<Vec<String>>>,
        gdb_server: Arc<Mutex<Option<u16>>>,
    ) -> Self {
        Self {
            channel,
            log,
            gdb_server,
            saved: Vec::new(),
            failures: Vec::new(),
            startup_script: None,
            selected: true,
        }
    }

    /// Print the `i @path` line and prompt of a board script Renode was
    /// started with, after the greeting, as `renode -P N path` does.
    pub fn with_startup_script(mut self, path: &str) -> Self {
        self.startup_script = Some(path.to_owned());
        self
    }

    /// Answer a command line starting with `prefix` with Renode's error text
    /// carrying `message`.
    pub fn with_failure(mut self, prefix: &str, message: &str) -> Self {
        self.failures.push((prefix.to_owned(), message.to_owned()));
        self
    }

    fn send(&mut self, bytes: &[u8]) -> Result<()> {
        self.channel.write_all(bytes)?;
        self.channel.flush()?;
        Ok(())
    }

    fn prompt(&mut self) -> Result<()> {
        if self.selected {
            self.send(b"\x1b[33m(machine-0) \x1b[0m")
        } else {
            self.send(b"\x1b[91m(monitor) \x1b[0m")
        }
    }

    fn error(&mut self, command: &str, message: &str) -> Result<()> {
        self.send(
            format!(
                "\x1b[91mThere was an error executing command '{command}': \r\n\x1b[0m\
                 \x1b[91m{message}\r\n\x1b[0m"
            )
            .as_bytes(),
        )?;
        self.prompt()
    }

    /// Read one command line; `Ok(None)` on a clean EOF.
    fn read_line(&mut self) -> Result<Option<String>> {
        let mut line = Vec::new();
        let mut buf = [0_u8; 1];
        loop {
            if self.channel.read(&mut buf)? == 0 {
                return Ok(None);
            }
            match buf[0] {
                b'\n' => return Ok(Some(String::from_utf8_lossy(&line).trim().to_owned())),
                b'\r' => {}
                byte => line.push(byte),
            }
        }
    }

    /// Serve until the client closes the link.
    pub fn serve(mut self) -> Result<()> {
        self.send(
            b"\xff\xfd\x00\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03\xff\xfc\"\x1b[0m\
              Renode, version 1.17.0 (mock)\n\r\n\r",
        )?;
        self.send(b"\x1b[91m(monitor) \x1b[0m")?;
        if let Some(script) = self.startup_script.clone() {
            self.send(format!("i @{script}\n\r").as_bytes())?;
            self.prompt()?;
        }
        while let Some(line) = self.read_line()? {
            self.log.lock().unwrap().push(line.clone());
            self.send(format!("{line}\n\r").as_bytes())?;
            if let Some((_, message)) = self
                .failures
                .iter()
                .find(|(prefix, _)| line.starts_with(prefix.as_str()))
                .cloned()
            {
                self.error(&line, &message)?;
                continue;
            }
            let (verb, argument) = line.split_once(' ').unwrap_or((line.as_str(), ""));
            match verb {
                // A monitor variable assignment prints nothing.
                _ if line.starts_with('$') => self.prompt()?,
                "pause" => {
                    self.send(b"Pausing emulation...\r\n\r")?;
                    self.prompt()?;
                }
                "start" => {
                    self.send(b"Starting emulation...\r\n\r")?;
                    self.prompt()?;
                }
                "Save" => {
                    self.saved.push(argument.trim_start_matches('@').to_owned());
                    self.prompt()?;
                }
                "Load"
                    if self
                        .saved
                        .iter()
                        .any(|path| *path == argument.trim_start_matches('@')) =>
                {
                    *self.gdb_server.lock().unwrap() = None;
                    self.selected = false;
                    self.prompt()?;
                }
                "mach" if argument.starts_with("set ") => {
                    let name = argument["set ".len()..].trim().trim_matches('"');
                    if name == "machine-0" || name == "0" {
                        self.selected = true;
                    } else {
                        self.send(format!("Machine {name} not found.\r\n").as_bytes())?;
                    }
                    self.prompt()?;
                }
                "Load" => self.error(&line, "Parameters did not match the signature")?,
                "machine" if self.selected && argument.starts_with("StartGdbServer ") => {
                    let port = argument["StartGdbServer ".len()..]
                        .trim()
                        .parse::<u16>()
                        .ok();
                    let running = *self.gdb_server.lock().unwrap();
                    match (running, port) {
                        (Some(running), _) => self.error(
                            &line,
                            &format!(
                                "CPU: machine-0.cpu is already attached to an existing GDB \
                                 server, running on port :{running}"
                            ),
                        )?,
                        (None, Some(port)) => {
                            *self.gdb_server.lock().unwrap() = Some(port);
                            self.prompt()?;
                        }
                        (None, None) => self.error(&line, "bad port")?,
                    }
                }
                _ => {
                    self.send(
                        format!("\x1b[91mNo such command or device: {verb}\r\n\x1b[0m").as_bytes(),
                    )?;
                    self.prompt()?;
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BHF_EVENTS stream + ring buffer builders
// ---------------------------------------------------------------------------

/// Encode a slice of [`Event`] into the `BHF_EVENTS` tag-length byte stream,
/// matching `ada_runtime/adafuzz-probe.adb` and [`event_log::EventReader`].
///
/// The `Mock` and `TopLevel` records carry trailing breadcrumb/target/testcase
/// context that the reader consumes but discards; this encoder emits zeros for
/// those so the stream stays byte-aligned with the reader.
pub fn encode_event_stream(events: &[Event]) -> Vec<u8> {
    let mut out = Vec::new();
    let push_u32 = |out: &mut Vec<u8>, value: u32| out.extend_from_slice(&value.to_le_bytes());
    let push_u64 = |out: &mut Vec<u8>, value: u64| out.extend_from_slice(&value.to_le_bytes());
    let push_string = |out: &mut Vec<u8>, value: &str| {
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value.as_bytes());
    };

    for event in events {
        match event {
            Event::Begin { testcase_id } => {
                out.push(1);
                push_u64(&mut out, *testcase_id);
            }
            Event::End { result_class } => {
                out.push(2);
                out.push(*result_class);
            }
            Event::Crumb { id } => {
                out.push(3);
                push_u32(&mut out, *id);
            }
            Event::Target { id } => {
                out.push(4);
                push_u32(&mut out, *id);
            }
            Event::Handler {
                exception_name,
                exception_message,
                handler_file,
                handler_line,
                last_breadcrumb,
                target_id,
                testcase_id,
            } => {
                out.push(5);
                push_string(&mut out, exception_name);
                push_string(&mut out, exception_message);
                push_string(&mut out, handler_file);
                push_u32(&mut out, *handler_line);
                push_u32(&mut out, *last_breadcrumb);
                push_u32(&mut out, *target_id);
                push_u64(&mut out, *testcase_id);
            }
            Event::Raise {
                exception_name,
                file,
                line,
                breadcrumb,
            } => {
                out.push(6);
                push_string(&mut out, exception_name);
                push_string(&mut out, file);
                push_u32(&mut out, *line);
                push_u32(&mut out, *breadcrumb);
            }
            Event::Mock { symbol } => {
                out.push(7);
                push_string(&mut out, symbol);
                push_u32(&mut out, 0); // last_breadcrumb (discarded)
                push_u32(&mut out, 0); // target_id (discarded)
                push_u64(&mut out, 0); // testcase_id (discarded)
            }
            Event::TopLevel {
                exception_name,
                exception_message,
            } => {
                out.push(8);
                push_string(&mut out, exception_name);
                push_string(&mut out, exception_message);
                push_u32(&mut out, 0); // last_breadcrumb (discarded)
                push_u32(&mut out, 0); // target_id (discarded)
                push_u64(&mut out, 0); // testcase_id (discarded)
            }
            Event::TargetEntry => out.push(9),
        }
    }
    out
}

/// Simulate the Ada `memory_buffer` ring: write `bytes` into a `capacity`-slot
/// ring exactly as `adafuzz-probe-memory_buffer.adb`'s `Write_Byte` does, and
/// return the resulting `(image, write_cursor, wrapped)`.
///
/// # Panics
/// Panics if `capacity` is zero (a ring must have at least one slot).
pub fn simulate_ring(bytes: &[u8], capacity: usize) -> (Vec<u8>, u32, bool) {
    assert!(capacity > 0, "ring capacity must be non-zero");
    let mut image = vec![0_u8; capacity];
    let mut write = 0_usize;
    let mut wrapped = false;
    for &byte in bytes {
        image[write] = byte;
        if write == capacity - 1 {
            write = 0;
            wrapped = true;
        } else {
            write += 1;
        }
    }
    (image, write as u32, wrapped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::thread;

    #[test]
    fn duplex_transfers_bytes_both_directions() {
        let (mut a, mut b) = duplex();
        let writer = thread::spawn(move || {
            b.write_all(b"ping").unwrap();
            let mut echo = [0_u8; 4];
            b.read_exact(&mut echo).unwrap();
            assert_eq!(&echo, b"pong");
        });
        let mut buf = [0_u8; 4];
        a.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        a.write_all(b"pong").unwrap();
        writer.join().unwrap();
    }

    #[test]
    fn duplex_read_observes_eof_when_peer_writer_dropped() {
        let (mut a, b) = duplex();
        drop(b);
        let mut buf = [0_u8; 4];
        assert_eq!(a.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn simulate_ring_matches_ada_write_byte_semantics() {
        // No wrap: cursor advances to the count, wrapped stays false.
        let (image, write, wrapped) = simulate_ring(&[1, 2, 3], 8);
        assert_eq!(&image[..3], &[1, 2, 3]);
        assert_eq!(write, 3);
        assert!(!wrapped);

        // Exactly full: wraps to 0 and sets wrapped.
        let (_, write, wrapped) = simulate_ring(&[1, 2, 3, 4], 4);
        assert_eq!(write, 0);
        assert!(wrapped);

        // Over-full: last byte overwrites index 0.
        let (image, write, wrapped) = simulate_ring(&[1, 2, 3, 4, 5], 4);
        assert_eq!(image, vec![5, 2, 3, 4]);
        assert_eq!(write, 1);
        assert!(wrapped);
    }
}
