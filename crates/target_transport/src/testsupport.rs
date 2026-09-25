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
//! * [`encode_event_stream`] / [`simulate_ring`] — build `BHF_EVENTS` byte
//!   streams and simulate the Ada ring buffer for the coverage-reader tests.

use crate::agent::{encode_response, read_input_frame, AgentLimits};
use crate::error::Result;
use crate::gdb::GdbConnection;
use crate::outcome::{ExitKind, Fault, RunOutcome};
use event_log::Event;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
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
            exit: self.exit,
            coverage_edges: self.edges.clone(),
            fault: self.fault.clone(),
            stdout: Vec::new(),
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

/// A minimal gdbstub speaking the target side of the RSP: acks packets, answers
/// `!`/`?`/`g`/`m`/`M`/`c`, and records a per-iteration `R` reset. Serves memory
/// reads/writes against scripted regions.
pub struct MockGdbStub<C: Read + Write> {
    connection: GdbConnection<C>,
    regions: Vec<MemRegion>,
    log: Arc<Mutex<Vec<String>>>,
    stop_reply: Vec<u8>,
    registers: Vec<u8>,
}

impl<C: Read + Write> MockGdbStub<C> {
    /// Build a stub over `channel`; `log` records every received packet body.
    pub fn new(channel: C, log: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            connection: GdbConnection::new(channel),
            regions: Vec::new(),
            log,
            stop_reply: b"S05".to_vec(),
            registers: vec![0_u8; 4],
        }
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
                b'?' | b'c' => {
                    let reply = self.stop_reply.clone();
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
