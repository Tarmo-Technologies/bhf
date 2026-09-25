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
//! The live-hardware / live-`qemu-system` path is gated (HDF-1 acceptance) and
//! not run in unit tests; the client logic here is exercised against the
//! in-crate mock gdbstub ([`crate::testsupport::MockGdbStub`]).
//!
//! Run-length-encoded responses (which real qemu/gdbserver emit for large
//! register/memory dumps) are detected and rejected with a descriptive error
//! rather than silently mis-decoded; expanding them is the HDF-4 live-path
//! follow-up.

use crate::coverage::MemoryBufferReader;
use crate::error::{Result, TransportError};
use crate::outcome::{ExitKind, RunOutcome};
use crate::transport::{TargetSession, TargetTransport};
use std::io::{Read, Write};

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

/// Un-escape RSP `}`-escaped data; reject run-length encoding.
fn unescape(data: &[u8]) -> Result<Vec<u8>> {
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
                return Err(TransportError::gdb(
                    "run-length-encoded response not supported yet (HDF-4 live path)",
                ));
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
    /// is HDF-2; here only the classically fatal signals count as a crash so a
    /// benign `SIGTRAP` breakpoint stop is not mislabeled.
    pub fn to_exit_kind(&self) -> ExitKind {
        match self {
            Self::Exited(_) => ExitKind::Ok,
            Self::Terminated(_) => ExitKind::Crash,
            Self::Signal(0) => ExitKind::Ok,
            Self::Signal(signal) => {
                // SIGILL(4) SIGABRT(6) SIGBUS(7) SIGFPE(8) SIGSEGV(11).
                if matches!(signal, 4 | 6 | 7 | 8 | 11) {
                    ExitKind::Crash
                } else {
                    ExitKind::Ok
                }
            }
        }
    }
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

    /// Continue execution via `c`, returning the stop reply.
    pub fn cont(&mut self) -> Result<StopReply> {
        let response = self.command(b"c")?;
        StopReply::parse(&response)
    }

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
}

impl<F> GdbRemoteTransport<F> {
    /// Build a transport with the given connection factory and memory map.
    pub fn new(connect: F, map: GdbMemoryMap) -> Self {
        Self { connect, map }
    }
}

impl<F, C> TargetTransport for GdbRemoteTransport<F>
where
    F: Fn() -> Result<C>,
    C: Read + Write + 'static,
{
    fn arm(&self) -> Result<Box<dyn TargetSession>> {
        let mut client = GdbClient::new((self.connect)()?);
        client.attach()?;
        Ok(Box::new(GdbSession {
            client,
            map: self.map,
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
}

impl<C: Read + Write> TargetSession for GdbSession<C> {
    fn run_input(&mut self, input: &[u8]) -> Result<RunOutcome> {
        self.client.reset()?;
        self.client.write_memory(self.map.input_address, input)?;
        let stop = self.client.cont()?;
        let coverage_edges = read_coverage_ring(&mut self.client, &self.map)?;
        Ok(RunOutcome {
            exit: stop.to_exit_kind(),
            coverage_edges,
            // Fault classification over the debug-probe path is HDF-2.
            fault: None,
            stdout: Vec::new(),
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
    fn decode_rejects_run_length_encoding() {
        let frame = encode_packet(&[b'0', RUN_LENGTH, b' ']);
        let error = decode_packet(&frame).unwrap_err();
        assert!(
            error.to_string().contains("run-length"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn stop_reply_parses_and_classifies() {
        assert_eq!(StopReply::parse(b"S05").unwrap(), StopReply::Signal(5));
        assert_eq!(StopReply::parse(b"S0b").unwrap(), StopReply::Signal(11));
        assert_eq!(StopReply::parse(b"W00").unwrap(), StopReply::Exited(0));
        assert_eq!(StopReply::parse(b"X0b").unwrap(), StopReply::Terminated(11));
        // SIGTRAP (breakpoint) is not a crash; SIGSEGV is.
        assert_eq!(StopReply::Signal(5).to_exit_kind(), ExitKind::Ok);
        assert_eq!(StopReply::Signal(11).to_exit_kind(), ExitKind::Crash);
        assert_eq!(StopReply::Terminated(11).to_exit_kind(), ExitKind::Crash);
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
}
