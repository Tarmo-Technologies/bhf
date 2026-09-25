// SPDX-License-Identifier: Apache-2.0

//! HIL (hardware-in-the-loop) real-board scaffold.
//!
//! This is the drop-in lane for a physical ARM board (see `docs/hil-bringup.md`):
//! plug in e.g. an ST Nucleo-F411RE, start OpenOCD (which exposes a gdbstub on
//! `:3333`), point `BHF_HIL_GDB` at it, and this test drives the REAL
//! [`target_transport::GdbClient`] / [`target_transport::GdbRemoteTransport`]
//! against the board's gdbstub over the exact same RSP path the emulator tests
//! use. No board is present in this environment, so the test self-skips unless
//! `BHF_HIL_GDB=host:port` is set — no further coding is needed to run it once a
//! board is attached.
//!
//! Environment:
//! * `BHF_HIL_GDB=host:port`         — the OpenOCD (or gdbserver) gdbstub. Required.
//! * `BHF_HIL_PROBE_ADDR=0x...`      — optional: an address to read back.
//! * `BHF_HIL_PROBE_LEN=N`           — optional: bytes to read at PROBE_ADDR (default 16).
//! * `BHF_HIL_INPUT_ADDR=0x...`      \
//! * `BHF_HIL_RING_ADDR=0x...`        \  set all five to drive a full
//! * `BHF_HIL_RING_WRITE_ADDR=0x...`  >  GdbRemoteTransport::run_input and read
//! * `BHF_HIL_RING_WRAPPED_ADDR=0x...`/   the on-board coverage ring.
//! * `BHF_HIL_RING_CAP=N`            /
//! * `BHF_HIL_INPUT=deadbeef`        — optional: hex input to deliver (default empty).

use std::net::TcpStream;
use std::time::Duration;
use target_transport::{
    GdbClient, GdbMemoryMap, GdbRemoteTransport, TargetTransport, TransportError,
};

fn env_addr(key: &str) -> Option<u64> {
    let raw = std::env::var(key).ok()?;
    let raw = raw.trim().to_owned();
    let value = if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        raw.parse::<u64>()
    };
    Some(value.unwrap_or_else(|_| panic!("{key}={raw:?} is not a valid address")))
}

fn env_usize(key: &str, default: usize) -> usize {
    match std::env::var(key) {
        Ok(v) => v
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("{key}={v:?} is not a valid integer")),
        Err(_) => default,
    }
}

fn connect(addr: &str) -> TcpStream {
    let stream = TcpStream::connect(addr)
        .unwrap_or_else(|e| panic!("BHF_HIL_GDB={addr:?}: could not connect to gdbstub: {e}"));
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("set read timeout");
    stream
}

#[test]
fn hil_board_gdb_path_runs_when_a_probe_is_configured() {
    let Ok(gdb) = std::env::var("BHF_HIL_GDB") else {
        eprintln!(
            "hil_board: SKIPPED — set BHF_HIL_GDB=host:port (e.g. 127.0.0.1:3333 from OpenOCD) \
             with a board attached to run the real-hardware path. See docs/hil-bringup.md."
        );
        return;
    };
    eprintln!("hil_board: driving the real RSP client against gdbstub at {gdb}");

    // Part 1: raw client — attach and read registers (proves the link is live).
    {
        let mut client = GdbClient::new(connect(&gdb));
        let stop = client.attach().expect("attach to board gdbstub");
        eprintln!("hil_board: attached, initial stop = {stop:?}");
        let regs = client.read_registers().expect("read general registers");
        assert!(!regs.is_empty(), "register block should be non-empty");
        eprintln!("hil_board: read {} register bytes", regs.len());

        if let Some(addr) = env_addr("BHF_HIL_PROBE_ADDR") {
            let len = env_usize("BHF_HIL_PROBE_LEN", 16);
            let bytes = client
                .read_memory(addr, len)
                .expect("read the configured probe region from the board");
            eprintln!("hil_board: read_memory({addr:#x}, {len}) = {bytes:02x?}");
        }
    }

    // Part 2: if a full coverage-ring map is configured, drive the transport seam
    // end to end (run one input, read the on-board coverage ring).
    if let (
        Some(input_address),
        Some(ring_address),
        Some(ring_write_address),
        Some(ring_wrapped_address),
    ) = (
        env_addr("BHF_HIL_INPUT_ADDR"),
        env_addr("BHF_HIL_RING_ADDR"),
        env_addr("BHF_HIL_RING_WRITE_ADDR"),
        env_addr("BHF_HIL_RING_WRAPPED_ADDR"),
    ) {
        let ring_capacity = env_usize("BHF_HIL_RING_CAP", 65_536);
        let map = GdbMemoryMap {
            input_address,
            ring_address,
            ring_write_address,
            ring_wrapped_address,
            ring_capacity,
        };
        let input = std::env::var("BHF_HIL_INPUT").unwrap_or_default();
        let input = decode_hex(&input);

        let addr = gdb.clone();
        let transport = GdbRemoteTransport::new(
            move || -> Result<TcpStream, TransportError> {
                TcpStream::connect(&addr).map_err(TransportError::from)
            },
            map,
        );
        let mut session = transport
            .arm()
            .expect("arm the board over the gdb transport");
        let outcome = session
            .run_input(&input)
            .expect("run one input against the board and read coverage");
        eprintln!(
            "hil_board: run_input({} bytes) -> exit={:?}, {} coverage edges: {:x?}",
            input.len(),
            outcome.exit,
            outcome.coverage_edges.len(),
            outcome.coverage_edges
        );
        assert!(
            !outcome.coverage_edges.is_empty(),
            "a configured coverage ring must yield at least one edge; \
             check the ring map and that the harness emitted breadcrumbs"
        );
    } else {
        eprintln!(
            "hil_board: coverage-ring map not fully configured (set BHF_HIL_INPUT_ADDR, \
             BHF_HIL_RING_ADDR, BHF_HIL_RING_WRITE_ADDR, BHF_HIL_RING_WRAPPED_ADDR to exercise \
             run_input + ring readback)."
        );
    }

    eprintln!("hil_board: PASSED against real hardware gdbstub {gdb}");
}

/// Decode an optional hex string (e.g. "deadbeef") into bytes; empty -> empty.
fn decode_hex(text: &str) -> Vec<u8> {
    let text = text.trim();
    if text.is_empty() {
        return Vec::new();
    }
    assert!(
        text.len().is_multiple_of(2),
        "BHF_HIL_INPUT must have an even number of hex digits"
    );
    (0..text.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&text[i..i + 2], 16)
                .unwrap_or_else(|_| panic!("BHF_HIL_INPUT has a non-hex digit near {i}"))
        })
        .collect()
}
