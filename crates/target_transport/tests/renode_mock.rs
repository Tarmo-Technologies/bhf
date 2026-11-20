// SPDX-License-Identifier: Apache-2.0

//! `RenodeTransport` end to end against a mock Renode monitor and mock gdb
//! servers that behave as Renode 1.17's do (#340).
//!
//! The mock monitor speaks Renode's telnet greeting, echo, colours and error
//! text, and prints a board script's `i @...` line after its greeting, as
//! `renode -P N board.resc` does. Its `Load` stops the gdb server and leaves
//! no machine selected, as Renode 1.17.0's does, and the gdb dialer here
//! refuses a connection while no server runs, so a transport that dialed gdb
//! without selecting the machine and starting the server after `Load` fails
//! these tests. Each gdb server sends Renode's unprompted
//! `S05` on connect and after each stop.

use std::io;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use event_log::Event;
use target_transport::testsupport::{
    duplex, encode_event_stream, simulate_ring, DuplexStream, MockGdbStub, MockRenodeMonitor,
};
use target_transport::{
    ExitKind, FaultKind, GdbMemoryMap, GuestFaultStatus, RenodeTransport, TargetTransport,
    TransportError,
};

const GDB_PORT: u16 = 3333;
const RING_CAP: usize = 64;
const DONE: u64 = 0x1a8;
const FAULT_WORD: u64 = 0x6000;

fn map() -> GdbMemoryMap {
    GdbMemoryMap {
        input_address: 0x1000,
        ring_address: 0x4000,
        ring_write_address: 0x5000,
        ring_wrapped_address: 0x5100,
        ring_capacity: RING_CAP,
    }
}

/// A shared log of command lines or packets.
type Log = Arc<Mutex<Vec<String>>>;

/// What a test inspects after driving the transport.
struct Rig {
    monitor_log: Log,
    /// One packet log per gdb connection the transport made.
    gdb_logs: Arc<Mutex<Vec<Log>>>,
}

/// The board a run sees: its stop reply, coverage and fault-status word.
#[derive(Clone)]
struct Board {
    stop_reply: Vec<u8>,
    edges: Vec<u32>,
    fault_word: u32,
}

impl Board {
    fn clean(edges: &[u32]) -> Self {
        Self {
            stop_reply: b"T05swbreak:;".to_vec(),
            edges: edges.to_vec(),
            fault_word: 0,
        }
    }
}

type Dial = Box<dyn Fn() -> Result<DuplexStream, TransportError>>;

/// A transport wired to a mock monitor (one connection) and a gdb dialer that
/// starts a fresh mock gdb server per connection while the monitor reports
/// one running on [`GDB_PORT`].
fn rig(board: Board, monitor_failure: Option<(&str, &str)>) -> (RenodeTransport<Dial, Dial>, Rig) {
    let monitor_log = Arc::new(Mutex::new(Vec::new()));
    let gdb_server = Arc::new(Mutex::new(None::<u16>));
    let (monitor_client, monitor_end) = duplex();
    let mut monitor = MockRenodeMonitor::new(
        monitor_end,
        Arc::clone(&monitor_log),
        Arc::clone(&gdb_server),
    )
    .with_startup_script("/work/board.resc");
    if let Some((prefix, message)) = monitor_failure {
        monitor = monitor.with_failure(prefix, message);
    }
    thread::spawn(move || {
        let _ = monitor.serve();
    });
    let monitor_slot = Mutex::new(Some(monitor_client));
    let connect_monitor: Dial = Box::new(move || {
        monitor_slot
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| TransportError::Protocol("monitor dialed twice".to_owned()))
    });

    let gdb_logs = Arc::new(Mutex::new(Vec::new()));
    let logs = Arc::clone(&gdb_logs);
    let connect_gdb: Dial = Box::new(move || {
        if *gdb_server.lock().unwrap() != Some(GDB_PORT) {
            return Err(TransportError::Io(io::Error::from(
                io::ErrorKind::ConnectionRefused,
            )));
        }
        let events: Vec<Event> = board.edges.iter().map(|&id| Event::Crumb { id }).collect();
        let (image, write, wrapped) = simulate_ring(&encode_event_stream(&events), RING_CAP);
        let log = Arc::new(Mutex::new(Vec::new()));
        logs.lock().unwrap().push(Arc::clone(&log));
        let (client, stub_end) = duplex();
        let stub = MockGdbStub::new(stub_end, log)
            .with_unsolicited_stops()
            .with_stop_reply(board.stop_reply.clone())
            .with_region(map().input_address, vec![0; 64])
            .with_region(map().ring_address, image)
            .with_region(map().ring_write_address, write.to_le_bytes().to_vec())
            .with_region(map().ring_wrapped_address, vec![u8::from(wrapped)])
            .with_region(FAULT_WORD, board.fault_word.to_le_bytes().to_vec());
        thread::spawn(move || {
            let _ = stub.serve();
        });
        Ok(client)
    });

    let transport = RenodeTransport::new(
        connect_monitor,
        connect_gdb,
        GDB_PORT,
        map(),
        "/tmp/board.save",
    )
    .unwrap()
    .with_harness_breakpoint(DONE, 2)
    .with_exec_deadline(Some(Duration::from_secs(30)));
    (
        transport,
        Rig {
            monitor_log,
            gdb_logs,
        },
    )
}

#[test]
fn arm_pauses_and_saves_the_baseline() {
    let (transport, rig) = rig(Board::clean(&[1]), None);
    let _session = transport.arm().unwrap();
    assert_eq!(
        *rig.monitor_log.lock().unwrap(),
        ["$bhf_sync=\"bhf\"", "pause", "Save @/tmp/board.save"]
    );
    assert!(
        rig.gdb_logs.lock().unwrap().is_empty(),
        "arm does not dial gdb: Load would drop the link"
    );
}

#[test]
fn each_input_loads_the_baseline_restarts_the_gdb_server_and_runs_over_a_new_link() {
    let (transport, rig) = rig(Board::clean(&[7, 8, 9]), None);
    let mut session = transport.arm().unwrap();
    for input in [&b"first"[..], b"second", b"third"] {
        let outcome = session.run_input(input).unwrap();
        assert_eq!(outcome.exit, ExitKind::Ok, "{outcome:?}");
        assert_eq!(outcome.coverage_edges, [7, 8, 9]);
    }

    let monitor = rig.monitor_log.lock().unwrap().clone();
    let per_input = [
        "pause",
        "Load @/tmp/board.save",
        "mach set \"machine-0\"",
        "machine StartGdbServer 3333",
    ];
    assert_eq!(
        &monitor[..3],
        ["$bhf_sync=\"bhf\"", "pause", "Save @/tmp/board.save"]
    );
    for run in monitor[3..].chunks(per_input.len()) {
        assert_eq!(run, per_input, "monitor log: {monitor:?}");
    }
    assert_eq!(monitor.len(), 3 + 3 * per_input.len());

    let gdb_logs = rig.gdb_logs.lock().unwrap();
    assert_eq!(gdb_logs.len(), 3, "one gdb link per input");
    for (log, input) in gdb_logs.iter().zip([&b"first"[..], b"second", b"third"]) {
        let log = log.lock().unwrap();
        let hex: String = input.iter().map(|b| format!("{b:02x}")).collect();
        let write = format!("M1000,{:x}:{hex}", input.len());
        let order = ["!", "?", "Z0,1a8,2", write.as_str(), "c"];
        let positions: Vec<usize> = order
            .iter()
            .map(|packet| {
                log.iter()
                    .position(|p| p == packet)
                    .unwrap_or_else(|| panic!("{packet} missing from {log:?}"))
            })
            .collect();
        assert!(
            positions.windows(2).all(|w| w[0] < w[1]),
            "attach, breakpoint, input, continue in order: {log:?}"
        );
    }
}

#[test]
fn the_same_input_twice_gives_the_same_outcome() {
    let (transport, _rig) = rig(Board::clean(&[0x100, 0x101, 0x300]), None);
    let mut session = transport.arm().unwrap();
    let first = session.run_input(b"\x42").unwrap();
    let second = session.run_input(b"\x42").unwrap();
    assert_eq!(first.coverage_edges, second.coverage_edges);
    assert_eq!(first.exit, second.exit);
}

#[test]
fn a_fatal_stop_reply_is_a_crash_attributed_to_renode() {
    let board = Board {
        stop_reply: b"T0b".to_vec(),
        ..Board::clean(&[1, 2])
    };
    let (transport, _rig) = rig(board, None);
    let outcome = transport.arm().unwrap().run_input(b"boom").unwrap();
    assert_eq!(outcome.exit, ExitKind::Crash);
    let fault = outcome.fault.expect("a crash carries a fault");
    assert_eq!(fault.kind, FaultKind::MemoryProtection);
    assert!(fault.detail.contains("renode"), "{}", fault.detail);
}

#[test]
fn a_fault_recorded_behind_a_benign_stop_is_a_crash() {
    let board = Board {
        fault_word: 0xDEAD_FA11,
        ..Board::clean(&[1])
    };
    let (transport, _rig) = rig(board, None);
    let transport = transport.with_fault_status(GuestFaultStatus::new(FAULT_WORD, 4, 0).unwrap());
    let outcome = transport.arm().unwrap().run_input(b"x").unwrap();
    assert_eq!(outcome.exit, ExitKind::Crash);
    assert!(
        outcome.fault.unwrap().detail.contains("0xdeadfa11"),
        "the fault-status word names the fault"
    );
}

#[test]
fn a_failed_load_is_an_error_carrying_renodes_text() {
    let (transport, rig) = rig(
        Board::clean(&[1]),
        Some(("Load", "Could not find file 'board.save'")),
    );
    let mut session = transport.arm().unwrap();
    let err = session.run_input(b"x").unwrap_err();
    assert!(
        matches!(&err, TransportError::TargetError(m) if m.contains("Could not find file")),
        "{err}"
    );
    assert!(
        rig.gdb_logs.lock().unwrap().is_empty(),
        "no run after a failed Load"
    );
}

#[test]
fn a_failed_save_fails_the_arm() {
    let (transport, _rig) = rig(
        Board::clean(&[1]),
        Some(("Save", "Access to the path is denied")),
    );
    let err = transport.arm().err().expect("arm must fail");
    assert!(err.to_string().contains("Access to the path"), "{err}");
}

#[test]
fn an_unsafe_snapshot_path_is_refused_at_construction() {
    let never: Dial = Box::new(|| Err(TransportError::Protocol("unused".to_owned())));
    let never_gdb: Dial = Box::new(|| Err(TransportError::Protocol("unused".to_owned())));
    let err = RenodeTransport::new(never, never_gdb, GDB_PORT, map(), "a b;quit")
        .err()
        .expect("a path with a space must be refused");
    assert!(err.to_string().contains("disallowed character"), "{err}");
}
