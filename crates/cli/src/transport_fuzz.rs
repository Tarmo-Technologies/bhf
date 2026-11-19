// SPDX-License-Identifier: Apache-2.0

//! HDF-1b: wire the `target_transport` seam into a runnable fuzz loop.
//!
//! HDF-1 landed the `TargetTransport`/`TargetSession` seam and its backends
//! (agent, gdb-remote, full-system) plus HDF-2's [`crate::transport_fault`]
//! finding seam, but nothing on the engine/CLI side consumed them — the crate
//! was tested-but-dead (roadmap CC-2, "no consumer"). This module is that
//! consumer: it adds a `--target-transport` option to `bhf fuzz` and drives a
//! coverage-guided fuzz loop through the transport, reusing the builtin engine's
//! machinery (the [`MutatorSuite`], the [`PowerScheduler`], and [`CoverageProxy`]
//! coverage folding) and turning a [`RunOutcome`] fault/crash into a written
//! finding via [`crate::transport_fault::outcome_finding`].
//!
//! # Additive by construction
//!
//! The loop is a SEPARATE code path, reached only when `--target-transport` is
//! set (see [`should_use_transport`] and the dispatch in [`crate::fuzz::run`]).
//! When the flag is absent, `bhf fuzz` runs the existing host libFuzzer/AFL path
//! byte-for-byte as before; nothing here touches the hot host loop.
//!
//! # In-tree vs gated
//!
//! The spec parser, the transport builder, and the fuzz loop are pure software
//! and are proven end-to-end against the in-crate [`target_transport::testsupport`]
//! mocks (an [`AgentTransport`] over `duplex()` + a scripted `MockAgent`). The
//! *live* backends the parser can build — an on-target agent over TCP/serial, a
//! gdbstub over TCP, a `qemu-system` QMP+gdbstub — dial real resources in their
//! connect closures and are DEPENDENCY-gated (hardware / emulator), exactly as
//! HDF-1 records. Building the transport is pure; only [`TargetTransport::arm`]
//! reaches out, so the parser/builder are fully testable with no hardware.
//!
//! # Spec grammar
//!
//! `--target-transport <spec>`:
//! * `agent:tcp:HOST:PORT`   — [`AgentTransport`] over a TCP socket.
//! * `agent:serial:PATH[,baud=N]` — [`AgentTransport`] over a serial device,
//!   opened raw with reads bounded by `--timeout`.
//! * `gdb:HOST:PORT`         — [`GdbRemoteTransport`]; needs `--transport-coverage-map`.
//! * `qemu-system:qmp=HOST:PORT,gdb=HOST:PORT[,snapshot=TAG][,reset=loadvm|persistent|fast]`
//!   — [`FullSystemTransport`]; needs `--transport-coverage-map`, `reset=persistent`
//!   needs `done=`, and `reset=fast` needs `dirty_log=PATH`, the log of the QEMU
//!   dirty-page plugin (#347).
//! * `renode:monitor=HOST:PORT,gdb=HOST:PORT[,snapshot=PATH]` — [`RenodeTransport`]
//!   over Renode's telnet monitor; needs `--transport-coverage-map`.
//!
//! `--transport-coverage-map input=<addr>,ring=<addr>,write=<addr>,wrapped=<addr>,cap=<n>`
//! (each `<addr>` is decimal or `0x`-hex) locates the coverage ring in target
//! memory for the memory-read backends (gdb / qemu-system / renode). The agent backend
//! carries coverage over its protocol and rejects a coverage map.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use corpus::{CorpusError, FindingEmitter};
use event_log::Testcase;
use fuzz_engine_builtin::{
    CoverageFeedback, CoverageInput, CoverageProxy, Dictionary, Grammar, MutationInput,
    MutationRng, MutatorConfig, MutatorSuite, PowerScheduler,
};
use serde::Serialize;
use target_transport::cycles::{CycleCounter, CycleSource};
use target_transport::{
    AgentTransport, CmpLogRegion, ExitKind, FullSystemReset, FullSystemTransport, GdbMemoryMap,
    GdbRemoteTransport, GuestFaultStatus, InputContract, RenodeTransport, ResetMode, RunOutcome,
    TargetSession, TargetTransport, TransportError,
};

use crate::fuzz::FuzzArgs;

/// The default coverage-corpus seed used when the caller supplies none, so the
/// mutator always has non-empty material to derive from.
const DEFAULT_SEED: &[u8] = b"BHF-transport-seed";

/// The default `qemu-system` baseline snapshot tag when the spec omits one.
const DEFAULT_SNAPSHOT_TAG: &str = "bhf-baseline";

/// Per-input I/O backstop when `--timeout` is not given, so a wedged peer that
/// never greets / never answers / drips partial responses trips a bound instead
/// of hanging a supposedly bounded campaign forever (#70). The documented
/// cleanup allowance.
const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(60);

/// Cap on the TCP connect phase — a connect should never consume the whole
/// per-input I/O backstop.
const CONNECT_TIMEOUT_CAP: Duration = Duration::from_secs(10);

/// Dial a TCP endpoint with bounded connect / read / write lifetimes (#70).
///
/// A target that never greets, never answers `continue`, or delivers only
/// partial responses trips the configured bound and surfaces a descriptive I/O
/// error, rather than blocking a read forever — which the campaign's
/// between-execution budget check cannot interrupt. `io_timeout` is the per
/// read/write bound; `None` falls back to [`DEFAULT_IO_TIMEOUT`].
fn connect_tcp_bounded(
    host: &str,
    port: u16,
    io_timeout: Option<Duration>,
) -> Result<std::net::TcpStream, TransportError> {
    use std::net::ToSocketAddrs;
    let io = io_timeout.unwrap_or(DEFAULT_IO_TIMEOUT);
    let connect = io.min(CONNECT_TIMEOUT_CAP);
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(TransportError::from)?
        .next()
        .ok_or_else(|| TransportError::Protocol(format!("could not resolve {host}:{port}")))?;
    let stream =
        std::net::TcpStream::connect_timeout(&addr, connect).map_err(TransportError::from)?;
    stream
        .set_read_timeout(Some(io))
        .map_err(TransportError::from)?;
    stream
        .set_write_timeout(Some(io))
        .map_err(TransportError::from)?;
    // One small frame per input, then a blocking read of the reply: Nagle
    // would hold each frame for the agent's delayed ACK.
    stream.set_nodelay(true).map_err(TransportError::from)?;
    Ok(stream)
}

/// True when `bhf fuzz` should take the transport-driven path instead of the
/// host libFuzzer/AFL path: exactly when `--target-transport` is set. When it is
/// `None`, the default flow is byte-for-byte unchanged.
pub(crate) fn should_use_transport(args: &FuzzArgs) -> bool {
    args.target_transport.is_some()
}

/// The `bhf fuzz` flags this lane does not wire. Remove a flag here when the
/// lane starts honouring it.
const UNSUPPORTED_FLAGS: &[&str] = &[
    "--cmplog-log",
    "--len-control",
    "--rss-limit-mb",
    "--fork-server",
    "--no-fork-server",
    "--qemu-user",
    "--qemu-arg",
    "--extension",
    "--sanitizers",
    "--symbolic-seed-source",
    "--sandbox",
    "--sandbox-tool",
    "--sandbox-strict",
    "--runtime-oracles",
    "--structured-inputs",
    "--print-final-stats",
    "--collector",
    "--collector-window-ms",
    "--protocol-profile",
    "--session-transport",
    "--session-reset",
    "--max-session-messages",
    "--session-reply-timeout",
    "--session-server-cmd",
];

/// The flags this run gives that the transport lane would ignore.
pub(crate) fn unsupported_flags(args: &FuzzArgs) -> Vec<&'static str> {
    crate::fuzz::given_flags(args)
        .into_iter()
        .filter(|flag| UNSUPPORTED_FLAGS.contains(flag))
        .collect()
}

// ---------------------------------------------------------------------------
// Spec parsing (pure, fully testable)
// ---------------------------------------------------------------------------

/// A parsed, validated `--target-transport` spec. Kept separate from the built
/// [`TargetTransport`] so the parse is inspectable and testable without dialing
/// any live resource (construction of the live transport happens in
/// [`TransportPlan::into_transport`], and the connection only in `arm`).
#[derive(Debug, Clone)]
pub(crate) enum TransportPlan {
    /// On-target agent over a TCP socket.
    AgentTcp { host: String, port: u16 },
    /// On-target agent over a serial device / file, opened raw at `baud`
    /// (the device's current rate when `None`).
    AgentSerial { path: PathBuf, baud: Option<u32> },
    /// Debug-probe / emulator gdbstub over TCP, reading the coverage ring by
    /// memory access described by `map`.
    Gdb {
        host: String,
        port: u16,
        map: GdbMemoryMap,
        /// The staging region's capacity and length word.
        input: InputContract,
        /// The firmware ELF the target runs (`firmware=`), whose identity each
        /// finding records (#248).
        firmware: Option<PathBuf>,
        /// The target cycle counter read around each run (`cycles=`, #251).
        cycles: Option<CycleCounter>,
        /// The address of the firmware's task identity word (`task_id=`, #252).
        task_id: Option<u64>,
        /// The firmware's comparison record (`cmplog=`, #386).
        cmplog: Option<CmpLogRegion>,
        /// Coverage from the semihosting channel (`coverage=semihosting`,
        /// #292), not the ring.
        semihosting: bool,
        /// The completion breakpoint `(address, RSP kind)` (`done=`, #293).
        harness_done: Option<(u64, u32)>,
        /// The firmware fault-status word (`fault=`, #293).
        fault_status: Option<GuestFaultStatus>,
        /// How the target is reset before each input (`reset=`, #293).
        reset: ResetMode,
        /// What the parser corrected in the spec, for the run to print.
        notes: Vec<String>,
    },
    /// Full-system `qemu-system` guest driven by QMP (snapshot lifecycle) + a
    /// gdbstub (input + coverage-ring readback).
    QemuSystem {
        qmp_host: String,
        qmp_port: u16,
        gdb_host: String,
        gdb_port: u16,
        map: GdbMemoryMap,
        /// The staging region's capacity and length word.
        input: InputContract,
        snapshot_tag: String,
        /// How the guest is brought back before each input (`reset=`).
        reset: FullSystemReset,
        /// The QEMU dirty-page plugin's log `reset=fast` reads (`dirty_log=`,
        /// #347).
        dirty_log: Option<PathBuf>,
        /// Completion breakpoint `(address, RSP kind)` planted at arm so a
        /// self-HardFaulting Cortex-M target halts back to the debugger instead
        /// of running `c` unbounded (#71). `None` for targets that trap on their
        /// own; the bounded run control (#70) still backstops a missing one.
        harness_done: Option<(u64, u32)>,
        /// Firmware fault-status contract read after each run so a fault that
        /// returns through the completion breakpoint is classified as a crash
        /// rather than a silent clean pass (#72).
        fault_status: Option<GuestFaultStatus>,
        /// The firmware ELF the guest runs (`firmware=`), whose identity each
        /// finding records (#248).
        firmware: Option<PathBuf>,
        /// The target cycle counter read around each run (`cycles=`, #251).
        cycles: Option<CycleCounter>,
        /// The address of the firmware's task identity word (`task_id=`, #252).
        task_id: Option<u64>,
        /// The firmware's comparison record (`cmplog=`, #386).
        cmplog: Option<CmpLogRegion>,
        /// Coverage from the semihosting channel (`coverage=semihosting`,
        /// #292), not the ring.
        semihosting: bool,
        /// What the parser corrected in the spec, for the run to print.
        notes: Vec<String>,
    },
    /// Full-system Renode board (#340) driven by its telnet monitor
    /// (`Save`/`Load` snapshot lifecycle) + the gdb server Renode starts on
    /// `gdb_port` after each `Load`.
    Renode {
        monitor_host: String,
        monitor_port: u16,
        gdb_host: String,
        gdb_port: u16,
        map: GdbMemoryMap,
        /// The staging region's capacity and length word.
        input: InputContract,
        /// The baseline state file on the Renode host (`snapshot=`).
        snapshot: String,
        /// The completion breakpoint `(address, RSP kind)` (`done=`).
        harness_done: Option<(u64, u32)>,
        /// The firmware fault-status word (`fault=`).
        fault_status: Option<GuestFaultStatus>,
        /// The firmware ELF the board runs (`firmware=`, #248).
        firmware: Option<PathBuf>,
        /// The target cycle counter read around each run (`cycles=`, #251).
        cycles: Option<CycleCounter>,
        /// The address of the firmware's task identity word (`task_id=`, #252).
        task_id: Option<u64>,
        /// The firmware's comparison record (`cmplog=`, #386).
        cmplog: Option<CmpLogRegion>,
        /// Coverage from the semihosting channel (`coverage=semihosting`).
        semihosting: bool,
        /// What the parser corrected in the spec, for the run to print.
        notes: Vec<String>,
    },
}

/// A descriptive failure parsing a `--target-transport` / `--transport-coverage-map`
/// spec, or building the transport. Never a silent `None`.
#[derive(Debug, thiserror::Error)]
pub(crate) enum TransportSpecError {
    #[error(
        "empty --target-transport spec; expected one of \
         agent:tcp:HOST:PORT, agent:serial:PATH[,baud=N], gdb:HOST:PORT, \
         qemu-system:qmp=HOST:PORT,gdb=HOST:PORT, renode:monitor=HOST:PORT,gdb=HOST:PORT"
    )]
    Empty,

    #[error(
        "unknown --target-transport backend {backend:?}; supported: \
         agent:tcp, agent:serial, gdb, qemu-system, renode"
    )]
    UnknownBackend { backend: String },

    #[error("malformed {backend} spec {spec:?}: {reason}")]
    Malformed {
        backend: &'static str,
        spec: String,
        reason: String,
    },

    #[error(
        "the {backend} backend requires --transport-coverage-map \
         (input=<addr>,input_cap=<n>,ring=<addr>,write=<addr>,wrapped=<addr>,cap=<n>, \
         and input_len=<addr> when the firmware reads the input length)"
    )]
    MissingCoverageMap { backend: &'static str },

    #[error(
        "--transport-coverage-map is not used by the agent backend \
         (coverage arrives over the agent protocol); remove it"
    )]
    UnexpectedCoverageMap,

    #[error(
        "malformed --transport-coverage-map field {field}={value:?}: \
         expected a decimal or 0x-hex integer"
    )]
    Field { field: String, value: String },

    #[error(
        "--transport-coverage-map is missing required key {key:?} (need input, input_cap, \
         ring, write, wrapped and cap, or input, input_cap and coverage=semihosting; input_cap \
         is the staging region's size in bytes)"
    )]
    MissingMapKey { key: &'static str },

    #[error(
        "--transport-coverage-map has unknown key {key:?} (allowed: input, input_cap, \
         input_len, ring, write, wrapped, cap, coverage, cmplog, cmplog_cap)"
    )]
    UnknownMapKey { key: String },

    #[error("--transport-coverage-map: {0}")]
    Coverage(String),

    #[error("--transport-coverage-map: {0}")]
    CmpLog(String),

    #[error("coverage ring capacity {cap} is not representable as a host-sized length")]
    CapTooLarge { cap: u64 },

    /// The license profile does not allow what the spec asks for (#347).
    #[error("{backend}: {reason}")]
    NotAllowed {
        backend: &'static str,
        reason: String,
    },

    /// A transport constructor rejected the spec (e.g. an unsafe snapshot tag).
    #[error(transparent)]
    Transport(#[from] TransportError),
}

impl TransportPlan {
    /// Parse a `--target-transport` spec plus the optional
    /// `--transport-coverage-map` into an inspectable plan.
    pub(crate) fn parse(
        spec: &str,
        coverage_map: Option<&str>,
    ) -> Result<Self, TransportSpecError> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err(TransportSpecError::Empty);
        }

        if let Some(rest) = spec.strip_prefix("agent:tcp:") {
            reject_coverage_map(coverage_map)?;
            let (host, port) = parse_host_port("agent:tcp", spec, rest)?;
            return Ok(Self::AgentTcp { host, port });
        }

        if let Some(rest) = spec.strip_prefix("agent:serial:") {
            reject_coverage_map(coverage_map)?;
            let malformed = |reason: String| TransportSpecError::Malformed {
                backend: "agent:serial",
                spec: spec.to_owned(),
                reason,
            };
            let (path, baud) = match rest.split_once(",baud=") {
                Some((path, baud)) => {
                    let baud = baud
                        .trim()
                        .parse::<u32>()
                        .ok()
                        .filter(|baud| *baud > 0)
                        .ok_or_else(|| {
                            malformed(format!("baud={baud} is not a positive integer"))
                        })?;
                    (path, Some(baud))
                }
                None => (rest, None),
            };
            if path.trim().is_empty() {
                return Err(malformed("device path is empty".to_owned()));
            }
            return Ok(Self::AgentSerial {
                path: PathBuf::from(path),
                baud,
            });
        }

        if let Some(rest) = spec.strip_prefix("agent:") {
            let sub = rest.split(':').next().unwrap_or(rest);
            return Err(TransportSpecError::Malformed {
                backend: "agent",
                spec: spec.to_owned(),
                reason: format!(
                    "unknown agent channel {sub:?}; expected agent:tcp:HOST:PORT \
                     or agent:serial:PATH"
                ),
            });
        }

        if let Some(rest) = spec.strip_prefix("gdb:") {
            let (map, input, cmplog, semihosting) = require_coverage_map("gdb", coverage_map)?;
            // `gdb:HOST:PORT[,firmware=PATH][,cycles=dwt|ADDR[,cpu_hz=N]][,task_id=ADDR]`
            // `[,done=ADDR[,done_kind=N]][,fault=ADDR[,fault_width=N][,fault_clear=N]]`
            // `[,reset=restart|monitor:CMD]`.
            let mut parts = rest.split(',');
            let (host, port) = parse_host_port("gdb", spec, parts.next().unwrap_or(""))?;
            let mut firmware = None;
            let mut task_id = None;
            let mut cycles = CycleKeys::default();
            let mut contract = ContractKeys::default();
            let mut reset = ResetMode::Restart;
            for part in parts.map(str::trim).filter(|part| !part.is_empty()) {
                let unknown = || TransportSpecError::Malformed {
                    backend: "gdb",
                    spec: spec.to_owned(),
                    reason: format!(
                        "unknown option {part:?}; allowed: firmware=PATH, cycles=dwt|ADDR, \
                         cpu_hz=N, task_id=ADDR, done=ADDR, done_kind=N, fault=ADDR, \
                         fault_width=N, fault_clear=N, reset=restart|monitor:CMD"
                    ),
                };
                let (key, value) = part.split_once('=').ok_or_else(unknown)?;
                match key.trim() {
                    "firmware" => firmware = Some(PathBuf::from(value.trim())),
                    "task_id" => task_id = Some(parse_int("task_id", value)?),
                    "reset" => reset = parse_reset(spec, value)?,
                    key if cycles.take(key, value)? => {}
                    key if contract.take(key, value)? => {}
                    _ => return Err(unknown()),
                }
            }
            let (harness_done, fault_status, notes) = contract.finish("gdb", spec)?;
            return Ok(Self::Gdb {
                host,
                port,
                map,
                input,
                firmware,
                cycles: cycles.counter("gdb", spec)?,
                task_id,
                cmplog,
                semihosting,
                harness_done,
                fault_status,
                reset,
                notes,
            });
        }

        if let Some(rest) = spec.strip_prefix("qemu-system:") {
            let (map, input, cmplog, semihosting) =
                require_coverage_map("qemu-system", coverage_map)?;
            return parse_qemu_system(spec, rest, map, input, cmplog, semihosting);
        }

        if let Some(rest) = spec.strip_prefix("renode:") {
            let (map, input, cmplog, semihosting) = require_coverage_map("renode", coverage_map)?;
            let parsed = SnapshotSpec::parse(
                "renode",
                "monitor",
                target_transport::renode::DEFAULT_SNAPSHOT_PATH,
                spec,
                rest,
            )?;
            return Ok(Self::Renode {
                monitor_host: parsed.control.0,
                monitor_port: parsed.control.1,
                gdb_host: parsed.gdb.0,
                gdb_port: parsed.gdb.1,
                map,
                input,
                snapshot: parsed.snapshot,
                harness_done: parsed.harness_done,
                fault_status: parsed.fault_status,
                firmware: parsed.firmware,
                cycles: parsed.cycles,
                task_id: parsed.task_id,
                cmplog,
                semihosting,
                notes: parsed.notes,
            });
        }

        Err(TransportSpecError::UnknownBackend {
            backend: spec.split(':').next().unwrap_or(spec).to_owned(),
        })
    }

    /// Build the live [`TargetTransport`] this plan describes. Pure: the
    /// connect closures dial their resource only when [`TargetTransport::arm`]
    /// is called, so this never touches hardware/emulator/socket by itself.
    ///
    /// `io_timeout` bounds each TCP connect/read/write and each serial read so
    /// a wedged peer cannot hang the campaign (#70).
    pub(crate) fn into_transport(
        self,
        io_timeout: Option<Duration>,
    ) -> Result<Box<dyn TargetTransport>, TransportSpecError> {
        match self {
            Self::AgentTcp { host, port } => Ok(Box::new(AgentTransport::new(move || {
                connect_tcp_bounded(&host, port, io_timeout)
            }))),
            // Raw mode, so no byte of a frame is echoed or translated, and every
            // read bounded by the I/O timeout, so a silent device ends the run.
            Self::AgentSerial { path, baud } => Ok(Box::new(AgentTransport::new(move || {
                crate::serial_port::open(&path, baud, io_timeout).map_err(TransportError::from)
            }))),
            Self::Gdb {
                host,
                port,
                map,
                input,
                firmware: _,
                cycles,
                task_id,
                cmplog,
                semihosting,
                harness_done,
                fault_status,
                reset,
                notes: _,
            } => {
                let mut transport = GdbRemoteTransport::new(
                    move || connect_tcp_bounded(&host, port, io_timeout),
                    map,
                )
                // The I/O bound doubles as the absolute per-input execution
                // deadline so a hung target is a bounded Timeout outcome, not
                // an unbounded wait behind the per-read socket timeout (#70).
                .with_exec_deadline(io_timeout)
                .with_input_contract(Some(input))
                .with_cycle_counter(cycles)
                .with_task_id(task_id)
                .with_cmplog(cmplog)
                .with_semihosting_coverage(semihosting)
                .with_reset(reset);
                if let Some((address, kind)) = harness_done {
                    transport = transport.with_harness_breakpoint(address, kind);
                }
                if let Some(status) = fault_status {
                    transport = transport.with_fault_status(status);
                }
                Ok(Box::new(transport))
            }
            Self::QemuSystem {
                qmp_host,
                qmp_port,
                gdb_host,
                gdb_port,
                map,
                input,
                snapshot_tag,
                reset,
                dirty_log,
                harness_done,
                fault_status,
                firmware: _,
                cycles,
                task_id,
                cmplog,
                semihosting,
                notes: _,
            } => {
                // reset=fast runs bhf's plugin inside QEMU: a license profile
                // must allow it (#347).
                if reset == FullSystemReset::Fast {
                    crate::auto::external_tools::qemu_plugin_gate(
                        crate::auto::external_tools::qemu_plugin_profile(),
                    )
                    .map_err(|reason| TransportSpecError::NotAllowed {
                        backend: "qemu-system",
                        reason,
                    })?;
                }
                let mut transport = FullSystemTransport::new(
                    move || connect_tcp_bounded(&qmp_host, qmp_port, io_timeout),
                    move || connect_tcp_bounded(&gdb_host, gdb_port, io_timeout),
                    map,
                    snapshot_tag,
                )?
                .with_reset(reset)
                .with_input_contract(Some(input))
                .with_cycle_counter(cycles)
                .with_task_id(task_id)
                .with_cmplog(cmplog)
                .with_semihosting_coverage(semihosting);
                if let Some(log) = dirty_log {
                    transport = transport.with_dirty_log(log);
                }
                // Wire the completion contract (#71) and the firmware
                // fault-status channel (#72) the parser captured, so the guide's
                // `bhf fuzz --target-transport qemu-system:...` command plants
                // the harness-done breakpoint itself rather than relying on an
                // out-of-band debugger.
                if let Some((address, kind)) = harness_done {
                    transport = transport.with_harness_breakpoint(address, kind);
                }
                if let Some(status) = fault_status {
                    transport = transport.with_fault_status(status);
                }
                // The I/O bound doubles as the absolute per-input execution
                // deadline (#70): a guest that never reaches the completion stop
                // is a bounded Timeout outcome, not an unbounded run-control wait.
                transport = transport.with_exec_deadline(io_timeout);
                Ok(Box::new(transport))
            }
            Self::Renode {
                monitor_host,
                monitor_port,
                gdb_host,
                gdb_port,
                map,
                input,
                snapshot,
                harness_done,
                fault_status,
                firmware: _,
                cycles,
                task_id,
                cmplog,
                semihosting,
                notes: _,
            } => {
                // Renode starts its gdb server on the port the spec dials.
                let mut transport = RenodeTransport::new(
                    move || connect_tcp_bounded(&monitor_host, monitor_port, io_timeout),
                    move || connect_tcp_bounded(&gdb_host, gdb_port, io_timeout),
                    gdb_port,
                    map,
                    snapshot,
                )?
                .with_input_contract(Some(input))
                .with_cycle_counter(cycles)
                .with_task_id(task_id)
                .with_cmplog(cmplog)
                .with_semihosting_coverage(semihosting)
                .with_exec_deadline(io_timeout);
                if let Some((address, kind)) = harness_done {
                    transport = transport.with_harness_breakpoint(address, kind);
                }
                if let Some(status) = fault_status {
                    transport = transport.with_fault_status(status);
                }
                Ok(Box::new(transport))
            }
        }
    }

    /// The plan `bhf replay` rebuilds a finding's target from: a persistent
    /// `qemu-system:` spec restores the snapshot before every input instead,
    /// so each replay and minimization run starts from the snapshot rather
    /// than from whatever the run before it left. A `reset=fast` spec does
    /// too, so a replay needs no dirty-page plugin in QEMU (#347).
    pub(crate) fn replay_from_baseline(mut self) -> Self {
        if let Self::QemuSystem {
            reset, dirty_log, ..
        } = &mut self
        {
            *reset = FullSystemReset::Loadvm;
            *dirty_log = None;
        }
        self
    }

    /// Whether the plan resets with the dirty-page fast snapshot
    /// (`qemu-system:...,reset=fast`, #347).
    pub(crate) fn resets_fast(&self) -> bool {
        self.dirty_log().is_some()
    }

    /// The dirty-page log a `reset=fast` spec reads (`dirty_log=`, #347).
    pub(crate) fn dirty_log(&self) -> Option<&Path> {
        match self {
            Self::QemuSystem {
                reset: FullSystemReset::Fast,
                dirty_log,
                ..
            } => dirty_log.as_deref(),
            _ => None,
        }
    }

    /// Whether the plan continues the guest's own input loop between clean
    /// inputs (`qemu-system:...,reset=persistent`).
    pub(crate) fn continues_the_guest_loop(&self) -> bool {
        matches!(
            self,
            Self::QemuSystem {
                reset: FullSystemReset::Persistent,
                ..
            }
        )
    }

    /// The staging region contract of a memory-read backend; `None` for the
    /// agent, whose own protocol carries the length.
    pub(crate) fn input_contract(&self) -> Option<InputContract> {
        match self {
            Self::Gdb { input, .. }
            | Self::QemuSystem { input, .. }
            | Self::Renode { input, .. } => Some(*input),
            _ => None,
        }
    }

    /// The firmware ELF the spec names (`firmware=`), if any.
    pub(crate) fn firmware(&self) -> Option<&Path> {
        match self {
            Self::Gdb { firmware, .. }
            | Self::QemuSystem { firmware, .. }
            | Self::Renode { firmware, .. } => firmware.as_deref(),
            _ => None,
        }
    }

    /// The target cycle counter the spec names (`cycles=`), if any.
    pub(crate) fn cycle_counter(&self) -> Option<CycleCounter> {
        match self {
            Self::Gdb { cycles, .. }
            | Self::QemuSystem { cycles, .. }
            | Self::Renode { cycles, .. } => *cycles,
            _ => None,
        }
    }

    /// The firmware's comparison record the coverage map names (`cmplog=`).
    pub(crate) fn cmplog(&self) -> Option<CmpLogRegion> {
        match self {
            Self::Gdb { cmplog, .. }
            | Self::QemuSystem { cmplog, .. }
            | Self::Renode { cmplog, .. } => *cmplog,
            _ => None,
        }
    }

    /// What the parser corrected in the spec (a Thumb `done=` address).
    pub(crate) fn notes(&self) -> &[String] {
        match self {
            Self::Gdb { notes, .. }
            | Self::QemuSystem { notes, .. }
            | Self::Renode { notes, .. } => notes,
            _ => &[],
        }
    }

    /// A short human label for the run summary / finding metadata.
    fn label(&self) -> String {
        match self {
            Self::AgentTcp { host, port } => format!("agent:tcp:{host}:{port}"),
            Self::AgentSerial { path, .. } => format!("agent:serial:{}", path.display()),
            Self::Gdb { host, port, .. } => format!("gdb:{host}:{port}"),
            Self::QemuSystem {
                qmp_host,
                qmp_port,
                gdb_host,
                gdb_port,
                ..
            } => format!("qemu-system:qmp={qmp_host}:{qmp_port},gdb={gdb_host}:{gdb_port}"),
            Self::Renode {
                monitor_host,
                monitor_port,
                gdb_host,
                gdb_port,
                ..
            } => format!("renode:monitor={monitor_host}:{monitor_port},gdb={gdb_host}:{gdb_port}"),
        }
    }
}

fn reject_coverage_map(coverage_map: Option<&str>) -> Result<(), TransportSpecError> {
    if coverage_map.is_some_and(|m| !m.trim().is_empty()) {
        return Err(TransportSpecError::UnexpectedCoverageMap);
    }
    Ok(())
}

fn require_coverage_map(
    backend: &'static str,
    coverage_map: Option<&str>,
) -> Result<(GdbMemoryMap, InputContract, Option<CmpLogRegion>, bool), TransportSpecError> {
    let map = coverage_map
        .filter(|m| !m.trim().is_empty())
        .ok_or(TransportSpecError::MissingCoverageMap { backend })?;
    parse_coverage_map(map)
}

fn parse_qemu_system(
    spec: &str,
    rest: &str,
    map: GdbMemoryMap,
    input: InputContract,
    cmplog: Option<CmpLogRegion>,
    semihosting: bool,
) -> Result<TransportPlan, TransportSpecError> {
    let parsed = SnapshotSpec::parse("qemu-system", "qmp", DEFAULT_SNAPSHOT_TAG, spec, rest)?;
    let malformed = |reason: String| TransportSpecError::Malformed {
        backend: "qemu-system",
        spec: spec.to_owned(),
        reason,
    };
    let reset = match parsed.reset.as_deref() {
        None | Some("loadvm") => FullSystemReset::Loadvm,
        Some("persistent") => FullSystemReset::Persistent,
        Some("fast") => FullSystemReset::Fast,
        Some(other) => {
            return Err(malformed(format!(
                "reset={other:?}: expected loadvm, persistent or fast"
            )))
        }
    };
    if reset == FullSystemReset::Persistent && parsed.harness_done.is_none() {
        return Err(malformed(
            "reset=persistent needs done=ADDR: the guest parks at its completion breakpoint \
             between inputs"
                .to_owned(),
        ));
    }
    match (reset, &parsed.dirty_log) {
        (FullSystemReset::Fast, None) => {
            return Err(malformed(
                "reset=fast needs dirty_log=PATH: the log the QEMU dirty-page plugin writes \
                 (-plugin libbhf_qemu_dirty_pages.so,log=PATH)"
                    .to_owned(),
            ))
        }
        (FullSystemReset::Loadvm | FullSystemReset::Persistent, Some(_)) => {
            return Err(malformed(
                "dirty_log= is the dirty-page log reset=fast reads; give reset=fast with it"
                    .to_owned(),
            ))
        }
        _ => {}
    }
    Ok(TransportPlan::QemuSystem {
        qmp_host: parsed.control.0,
        qmp_port: parsed.control.1,
        gdb_host: parsed.gdb.0,
        gdb_port: parsed.gdb.1,
        map,
        input,
        snapshot_tag: parsed.snapshot,
        reset,
        dirty_log: parsed.dirty_log,
        harness_done: parsed.harness_done,
        fault_status: parsed.fault_status,
        firmware: parsed.firmware,
        cycles: parsed.cycles,
        task_id: parsed.task_id,
        cmplog,
        semihosting,
        notes: parsed.notes,
    })
}

/// The keys the snapshot backends share: `qemu-system:` names its control
/// channel `qmp=`, `renode:` names it `monitor=`.
struct SnapshotSpec {
    control: (String, u16),
    gdb: (String, u16),
    snapshot: String,
    harness_done: Option<(u64, u32)>,
    fault_status: Option<GuestFaultStatus>,
    firmware: Option<PathBuf>,
    cycles: Option<CycleCounter>,
    task_id: Option<u64>,
    /// `reset=`, which only `qemu-system:` takes.
    reset: Option<String>,
    /// `dirty_log=`, which only `qemu-system:` takes (#347).
    dirty_log: Option<PathBuf>,
    notes: Vec<String>,
}

impl SnapshotSpec {
    fn parse(
        backend: &'static str,
        control_key: &'static str,
        default_snapshot: &str,
        spec: &str,
        rest: &str,
    ) -> Result<Self, TransportSpecError> {
        let mut control: Option<(String, u16)> = None;
        let mut gdb: Option<(String, u16)> = None;
        let mut snapshot = default_snapshot.to_owned();
        // Completion contract (#71) and firmware fault-status (#72), all optional.
        let mut contract = ContractKeys::default();
        let mut firmware: Option<PathBuf> = None;
        let mut cycles = CycleKeys::default();
        let mut task_id: Option<u64> = None;
        let mut reset: Option<String> = None;
        let mut dirty_log: Option<PathBuf> = None;
        let takes_reset = backend == "qemu-system";

        let malformed = |reason: String| TransportSpecError::Malformed {
            backend,
            spec: spec.to_owned(),
            reason,
        };

        for part in rest.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (key, value) = part
                .split_once('=')
                .ok_or_else(|| malformed(format!("expected key=value in {part:?}")))?;
            let value = value.trim();
            match key.trim() {
                key if key == control_key => {
                    control = Some(parse_host_port(backend, spec, value)?);
                }
                "gdb" => gdb = Some(parse_host_port(backend, spec, value)?),
                "snapshot" => snapshot = value.to_owned(),
                "firmware" => firmware = Some(PathBuf::from(value)),
                "task_id" => task_id = Some(parse_int("task_id", value)?),
                "reset" if takes_reset => reset = Some(value.to_owned()),
                "dirty_log" if takes_reset => dirty_log = Some(PathBuf::from(value)),
                key if cycles.take(key, value)? => {}
                key if contract.take(key, value)? => {}
                other => {
                    return Err(malformed(format!(
                        "unknown key {other:?}; allowed: {control_key}, gdb, snapshot, done, \
                         done_kind, fault, fault_width, fault_clear, firmware, cycles, cpu_hz, \
                         task_id{}",
                        if takes_reset {
                            ", reset, dirty_log"
                        } else {
                            ""
                        }
                    )))
                }
            }
        }

        let control = control
            .ok_or_else(|| malformed(format!("missing required key {control_key}=HOST:PORT")))?;
        let gdb = gdb.ok_or_else(|| malformed("missing required key gdb=HOST:PORT".to_owned()))?;
        let (harness_done, fault_status, notes) = contract.finish(backend, spec)?;
        Ok(Self {
            control,
            gdb,
            snapshot,
            harness_done,
            fault_status,
            firmware,
            cycles: cycles.counter(backend, spec)?,
            task_id,
            reset,
            dirty_log,
            notes,
        })
    }
}

/// The completion contract keys of a memory-read spec: `done=` and
/// `done_kind=` (#71), `fault=`, `fault_width=` and `fault_clear=` (#72).
/// The `qemu-system`, `renode` and, since #293, `gdb` backends take them.
struct ContractKeys {
    done: Option<u64>,
    /// The RSP breakpoint kind: 2, ARM Thumb's instruction size, by default.
    done_kind: u64,
    fault: Option<u64>,
    fault_width: u64,
    fault_clear: u64,
}

impl Default for ContractKeys {
    fn default() -> Self {
        Self {
            done: None,
            done_kind: 2,
            fault: None,
            fault_width: 4,
            fault_clear: 0,
        }
    }
}

impl ContractKeys {
    /// Take `key=value` when it is one of these keys.
    fn take(&mut self, key: &str, value: &str) -> Result<bool, TransportSpecError> {
        match key {
            "done" => self.done = Some(parse_int("done", value)?),
            "done_kind" => self.done_kind = parse_int("done_kind", value)?,
            "fault" => self.fault = Some(parse_int("fault", value)?),
            "fault_width" => self.fault_width = parse_int("fault_width", value)?,
            "fault_clear" => self.fault_clear = parse_int("fault_clear", value)?,
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// The completion breakpoint, the fault-status word, and what was
    /// corrected in the spec.
    #[allow(clippy::type_complexity)]
    fn finish(
        self,
        backend: &'static str,
        spec: &str,
    ) -> Result<(Option<(u64, u32)>, Option<GuestFaultStatus>, Vec<String>), TransportSpecError>
    {
        let malformed = |reason: String| TransportSpecError::Malformed {
            backend,
            spec: spec.to_owned(),
            reason,
        };
        let mut notes = Vec::new();
        let harness_done = match self.done {
            Some(address) => {
                let kind = u32::try_from(self.done_kind).map_err(|_| {
                    malformed(format!("done_kind {} is out of range", self.done_kind))
                })?;
                // `nm` prints a Thumb function's address with bit 0 set (the
                // interworking bit). A breakpoint there is unaligned and never
                // hits, so the run would wait out every input.
                let address = if kind == 2 && address & 1 == 1 {
                    notes.push(format!(
                        "done={address:#x} has the Thumb bit set; planting the breakpoint at {:#x}",
                        address & !1
                    ));
                    address & !1
                } else {
                    address
                };
                Some((address, kind))
            }
            None => None,
        };
        let fault_status = match self.fault {
            Some(address) => {
                let width = usize::try_from(self.fault_width).map_err(|_| {
                    malformed(format!("fault_width {} is out of range", self.fault_width))
                })?;
                // GuestFaultStatus::new validates the width (1..=8); its error
                // maps through TransportSpecError::Transport.
                Some(GuestFaultStatus::new(address, width, self.fault_clear)?)
            }
            None => None,
        };
        Ok((harness_done, fault_status, notes))
    }
}

/// A `gdb:` spec's `reset=` (#293): `restart`, the RSP `R` packet, or
/// `monitor:CMD`, a monitor command such as OpenOCD's `reset halt` or QEMU's
/// `system_reset`.
fn parse_reset(spec: &str, value: &str) -> Result<ResetMode, TransportSpecError> {
    let value = value.trim();
    if value == "restart" {
        return Ok(ResetMode::Restart);
    }
    match value.strip_prefix("monitor:").map(str::trim) {
        Some(command) if !command.is_empty() => Ok(ResetMode::Monitor(command.to_owned())),
        _ => Err(TransportSpecError::Malformed {
            backend: "gdb",
            spec: spec.to_owned(),
            reason: format!("reset={value:?}: expected restart or monitor:COMMAND"),
        }),
    }
}

/// The `cycles=` and `cpu_hz=` keys of a memory-read spec (#251).
#[derive(Default)]
struct CycleKeys {
    source: Option<CycleSource>,
    hz: Option<u64>,
}

impl CycleKeys {
    /// Take `key=value` when it is one of these keys.
    fn take(&mut self, key: &str, value: &str) -> Result<bool, TransportSpecError> {
        match key {
            "cycles" => {
                let value = value.trim();
                self.source = Some(if value.eq_ignore_ascii_case("dwt") {
                    CycleSource::Dwt
                } else {
                    CycleSource::Counter(parse_int("cycles", value)?)
                });
                Ok(true)
            }
            "cpu_hz" => {
                self.hz = Some(parse_int("cpu_hz", value)?).filter(|hz| *hz > 0);
                if self.hz.is_none() {
                    return Err(TransportSpecError::Field {
                        field: "cpu_hz".to_owned(),
                        value: value.to_owned(),
                    });
                }
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn counter(
        self,
        backend: &'static str,
        spec: &str,
    ) -> Result<Option<CycleCounter>, TransportSpecError> {
        match (self.source, self.hz) {
            (Some(source), hz) => Ok(Some(CycleCounter { source, hz })),
            (None, Some(_)) => Err(TransportSpecError::Malformed {
                backend,
                spec: spec.to_owned(),
                reason: "cpu_hz= needs cycles=dwt or cycles=ADDR".to_owned(),
            }),
            (None, None) => Ok(None),
        }
    }
}

fn parse_host_port(
    backend: &'static str,
    spec: &str,
    hostport: &str,
) -> Result<(String, u16), TransportSpecError> {
    let malformed = |reason: String| TransportSpecError::Malformed {
        backend,
        spec: spec.to_owned(),
        reason,
    };
    let (host, port) = hostport
        .rsplit_once(':')
        .ok_or_else(|| malformed(format!("expected HOST:PORT, got {hostport:?}")))?;
    if host.is_empty() {
        return Err(malformed(format!("host is empty in {hostport:?}")));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| malformed(format!("port {port:?} is not a valid 1..=65535 value")))?;
    if port == 0 {
        return Err(malformed("port 0 is not a valid port".to_owned()));
    }
    Ok((host.to_owned(), port))
}

/// The most CmpLog entries one read takes: the gdb client's read cap.
const MAX_CMPLOG_CAPACITY: u64 = 43_690;

fn parse_coverage_map(
    spec: &str,
) -> Result<(GdbMemoryMap, InputContract, Option<CmpLogRegion>, bool), TransportSpecError> {
    let mut input = None;
    let mut ring = None;
    let mut write = None;
    let mut wrapped = None;
    let mut cap = None;
    let mut input_cap = None;
    let mut input_len = None;
    let mut cmplog = None;
    let mut cmplog_cap = None;
    let mut semihosting = false;

    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| TransportSpecError::Field {
                field: part.to_owned(),
                value: String::new(),
            })?;
        let key = key.trim();
        match key {
            "input" => input = Some(parse_int(key, value)?),
            "ring" => ring = Some(parse_int(key, value)?),
            "write" => write = Some(parse_int(key, value)?),
            "wrapped" => wrapped = Some(parse_int(key, value)?),
            "cap" => cap = Some(parse_int(key, value)?),
            "input_cap" => input_cap = Some(parse_int(key, value)?),
            "input_len" => input_len = Some(parse_int(key, value)?),
            "cmplog" => cmplog = Some(parse_int(key, value)?),
            "cmplog_cap" => cmplog_cap = Some(parse_int(key, value)?),
            // Where each run's coverage comes from (#292): the ring the
            // memory_buffer probe fills, or the event stream the semihosting
            // probe writes to fd 2, which the target's semihosting calls
            // hand to the debugger.
            "coverage" => match value.trim() {
                "memory_buffer" => semihosting = false,
                "semihosting" => semihosting = true,
                other => {
                    return Err(TransportSpecError::Coverage(format!(
                        "coverage={other:?}: expected memory_buffer or semihosting"
                    )))
                }
            },
            other => {
                return Err(TransportSpecError::UnknownMapKey {
                    key: other.to_owned(),
                })
            }
        }
    }

    let input_address = input.ok_or(TransportSpecError::MissingMapKey { key: "input" })?;
    let map = if semihosting {
        // The semihosting channel replaces the ring: no ring is read, so one
        // named beside it would be a map that says two things.
        if let Some(key) = [
            ("ring", ring),
            ("write", write),
            ("wrapped", wrapped),
            ("cap", cap),
        ]
        .iter()
        .find_map(|(key, value)| value.map(|_| *key))
        {
            return Err(TransportSpecError::Coverage(format!(
                "coverage=semihosting reads the semihosting channel, not a ring: drop {key}="
            )));
        }
        GdbMemoryMap {
            input_address,
            ring_address: 0,
            ring_write_address: 0,
            ring_wrapped_address: 0,
            ring_capacity: 0,
        }
    } else {
        let cap = cap.ok_or(TransportSpecError::MissingMapKey { key: "cap" })?;
        let ring_capacity =
            usize::try_from(cap).map_err(|_| TransportSpecError::CapTooLarge { cap })?;
        GdbMemoryMap {
            input_address,
            ring_address: ring.ok_or(TransportSpecError::MissingMapKey { key: "ring" })?,
            ring_write_address: write.ok_or(TransportSpecError::MissingMapKey { key: "write" })?,
            ring_wrapped_address: wrapped
                .ok_or(TransportSpecError::MissingMapKey { key: "wrapped" })?,
            ring_capacity,
        }
    };
    // The staging region's size: bhf writes each input there, and one longer
    // than the region overwrites the guest globals after it.
    let input_cap = input_cap.ok_or(TransportSpecError::MissingMapKey { key: "input_cap" })?;
    let capacity = usize::try_from(input_cap)
        .map_err(|_| TransportSpecError::CapTooLarge { cap: input_cap })?;
    let contract = InputContract::new(capacity, input_len)?;
    // The comparison record (#386): its address and its entry capacity, which
    // the firmware's declaration fixes, so neither is guessed.
    let cmplog = match (cmplog, cmplog_cap) {
        (None, None) => None,
        (Some(address), Some(cap)) if (1..=MAX_CMPLOG_CAPACITY).contains(&cap) => {
            Some(CmpLogRegion {
                address,
                capacity: cap as usize,
            })
        }
        (Some(_), Some(cap)) => {
            return Err(TransportSpecError::CmpLog(format!(
                "cmplog_cap={cap} is outside 1..={MAX_CMPLOG_CAPACITY}"
            )))
        }
        (Some(_), None) => {
            return Err(TransportSpecError::CmpLog(
                "cmplog= needs cmplog_cap=N, the record's entry capacity".to_owned(),
            ))
        }
        (None, Some(_)) => {
            return Err(TransportSpecError::CmpLog(
                "cmplog_cap= needs cmplog=ADDR, the record's address".to_owned(),
            ))
        }
    };
    Ok((map, contract, cmplog, semihosting))
}

/// Parse a decimal or `0x`-hex unsigned integer.
fn parse_int(field: &str, value: &str) -> Result<u64, TransportSpecError> {
    let trimmed = value.trim();
    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        trimmed.parse::<u64>()
    };
    parsed.map_err(|_| TransportSpecError::Field {
        field: field.to_owned(),
        value: value.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// The transport-driven fuzz loop
// ---------------------------------------------------------------------------

/// Inputs to [`run_transport_campaign`], decoupled from clap so the loop is
/// testable against a mock transport in a temp dir.
#[derive(Debug, Clone)]
pub(crate) struct TransportFuzzConfig {
    pub work_dir: PathBuf,
    pub harness_id: String,
    /// Human label of the transport (for the summary + finding metadata).
    pub transport_label: String,
    /// Initial corpus seeds.
    pub seeds: Vec<Vec<u8>>,
    /// Total execution cap (bounded work — never unbounded).
    pub iterations: usize,
    /// Optional whole-campaign wall-clock budget (`--time`).
    pub time_budget: Option<Duration>,
    /// Optional absolute per-input execution deadline (`--timeout`). The transport
    /// itself enforces it (a hang is an `ExitKind::Timeout` outcome); this copy is
    /// persisted into each finding's replay profile so `bhf replay` rebuilds the
    /// transport with the SAME per-input bound and can reproduce a timing finding.
    pub per_input_timeout: Option<Duration>,
    /// Optional response-time deadline (`--deadline`). A completed run whose
    /// host-observed execution time exceeds it is recorded as a BHF-555 timing
    /// finding rather than discarded as a slow unit (#70).
    pub deadline: Option<Duration>,
    /// The raw `--target-transport` spec, persisted with each finding so it can
    /// be replayed against the same target/reset contract (#80).
    pub spec: String,
    /// Each worker's spec, `spec` with its `{worker}` resolved (#316); one
    /// worker's is `spec`.
    pub worker_specs: Vec<String>,
    /// The raw `--transport-coverage-map` spec, if any (persisted for replay).
    pub coverage_map: Option<String>,
    /// Ceiling on a generated input's length.
    pub max_len: usize,
    /// The staging region contract the memory-read backends write inputs
    /// under, recorded in each finding's transport profile.
    pub input_contract: Option<InputContract>,
    /// The identity of the firmware the spec's `firmware=` names, recorded in
    /// each finding and its transport profile (#248).
    pub firmware_identity: Option<serde_json::Value>,
    /// The target cycle counter the spec's `cycles=` names (#251). With a
    /// `cpu_hz=`, the deadline oracle times each run by it.
    pub cycle_counter: Option<CycleCounter>,
    /// Deterministic mutation RNG seed.
    pub rng_seed: u64,
    /// Stop as soon as this many DISTINCT findings are emitted.
    pub stop_after_findings: Option<usize>,
    /// Actionability profile for the emitted findings.
    pub mode: actionability::RunMode,
    /// The tokens the mutator splices in: `--dict`'s, then the harness's
    /// `dictionary.txt` and learned ones.
    pub dictionary: Vec<Vec<u8>>,
    /// `--grammar`: every input past the seeds is a fresh derivation of it.
    pub grammar: Option<Grammar>,
    /// The harness's `arg-layout.json`, when it decodes its arguments with
    /// `bhf_decode.h`: the mutator writes typed values into the scalar
    /// arguments' spans (#299).
    pub arg_layout: Option<harness_gen::arg_layout::ArgLayout>,
}

/// The JSON summary a transport-driven run reports (mirrors the shape of the
/// host lane's summary, restricted to what the transport path measures).
#[derive(Debug, Clone, Serialize)]
pub(crate) struct TransportFuzzSummary {
    pub schema_version: u32,
    pub harness_id: String,
    pub engine: String,
    pub transport: String,
    pub seeds: usize,
    pub executions: usize,
    /// Mutated inputs retained for reaching new coverage.
    pub corpus_new: usize,
    /// Distinct edge-transition bits observed (from the builtin coverage fold).
    pub coverage_edges: usize,
    /// Distinct block/hit-count bits observed.
    pub coverage_blocks: usize,
    /// Total crash/timeout outcomes seen (before dedup).
    pub crashes: usize,
    /// Executions whose coverage/evidence collection was incomplete (a post-stop
    /// readback failure). Non-zero means some coverage is partial, not that the
    /// run failed — surfaced so partial coverage is never read as complete (#74).
    pub incomplete_observations: usize,
    /// Executions whose clean/crash classification is UNRELIABLE because a
    /// configured fault-determining observation failed (e.g. a full-system
    /// completion whose firmware fault-status word could not be read). These are
    /// neither clean passes nor findings — surfaced so an inconclusive run is
    /// never silently counted as a clean execution (#72).
    pub inconclusive_observations: usize,
    /// Distinct finding ids written to `<work_dir>/findings/`.
    pub findings: Vec<String>,
    /// Set when the campaign stopped early on a non-clean run-control condition
    /// — a target-execution timeout (hang) or a lost transport (#70). `None` is
    /// a clean, fully-bounded completion. Distinct from a crash finding, which
    /// is a normal result recorded in `findings`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub halted: Option<String>,
    /// The target cycles the runs took, when the spec names a `cycles=`
    /// counter (#251).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_cycles: Option<CycleStats>,
    /// The workers that drove the campaign, one transport each (#316).
    pub workers: usize,
    /// The comparisons the firmware's CmpLog record reported, over all runs
    /// (`cmplog=`, #386).
    pub comparisons: usize,
    pub elapsed_secs: f64,
    /// `executions / elapsed_secs` (0.0 when no measurable time elapsed), as
    /// in a host run's `run.json`; also in each finding's transport profile.
    pub executions_per_sec: f64,
}

/// The campaign's throughput, recorded in each finding's transport profile.
#[derive(Debug, Clone, Copy, Serialize)]
struct Throughput {
    executions: usize,
    elapsed_secs: f64,
    executions_per_sec: f64,
}

impl Throughput {
    fn new(executions: usize, elapsed: Duration) -> Self {
        let elapsed_secs = elapsed.as_secs_f64();
        Self {
            executions,
            elapsed_secs,
            executions_per_sec: crate::fuzz::executions_per_sec(executions, elapsed_secs),
        }
    }
}

/// The fewest and most target cycles any completed run took, over `runs`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub(crate) struct CycleStats {
    pub runs: usize,
    pub min: u64,
    pub max: u64,
}

impl CycleStats {
    fn record(stats: &mut Option<Self>, cycles: Option<u64>) {
        let Some(cycles) = cycles else {
            return;
        };
        let entry = stats.get_or_insert(Self {
            runs: 0,
            min: cycles,
            max: cycles,
        });
        entry.runs += 1;
        entry.min = entry.min.min(cycles);
        entry.max = entry.max.max(cycles);
    }
}

/// How long a run took for the deadline oracle, and what measured it: the
/// target's cycles at `cpu_hz` when the spec names both and the counter
/// advanced, else the host's round-trip time `host` of the `run_input` call,
/// or of the reported run alone when the session ran more than it (a
/// `reset=persistent` continuation run again from the snapshot, #346).
pub(crate) fn run_time(
    counter: Option<CycleCounter>,
    outcome: &RunOutcome,
    host: Duration,
) -> (Duration, String) {
    let target = counter.and_then(|counter| {
        let cycles = outcome.target.cycles.filter(|cycles| *cycles > 0)?;
        Some((counter.duration(cycles)?, cycles, counter.hz?))
    });
    match target {
        Some((duration, cycles, hz)) => (
            duration,
            format!("target execution time ({cycles} cycles at {hz} Hz)"),
        ),
        None => (
            outcome.target.host_run_time.unwrap_or(host),
            "host-observed execution time".to_owned(),
        ),
    }
}

/// A failure running a transport-driven campaign.
#[derive(Debug, thiserror::Error)]
pub(crate) enum TransportFuzzError {
    #[error("target transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("worker transport: {0}")]
    Spec(#[from] TransportSpecError),
    #[error("writing finding: {0}")]
    Finding(#[from] CorpusError),
}

/// Fold one run's coverage edges into the builtin [`CoverageProxy`], reusing the
/// engine's exact edge/hit-count-bucket model. The transport's `coverage_edges`
/// map directly onto the breadcrumb (`crumbs`) channel a host testcase carries.
fn fold_coverage(coverage: &mut CoverageProxy, edges: &[u32]) -> CoverageFeedback {
    let testcase = Testcase {
        testcase_id: 0,
        target_id: 0,
        target_entered: false,
        crumbs: edges.to_vec(),
        handlers: Vec::new(),
        raises: Vec::new(),
        top_level: None,
        end: None,
        mocks: Vec::new(),
    };
    coverage.record(CoverageInput::new(&testcase, &[]))
}

/// Whether the loop should stop now: hit the iteration cap, the time budget, or
/// the distinct-finding target. Checked before every `run_input` so the loop
/// never runs unbounded and never runs one execution past its budget.
fn should_stop(
    executions: usize,
    iterations: usize,
    start: Instant,
    time_budget: Option<Duration>,
    distinct_findings: usize,
    stop_after_findings: Option<usize>,
) -> bool {
    if executions >= iterations {
        return true;
    }
    if let Some(budget) = time_budget {
        if start.elapsed() >= budget {
            return true;
        }
    }
    if let Some(target) = stop_after_findings {
        if distinct_findings >= target {
            return true;
        }
    }
    false
}

/// Drive a coverage-guided fuzz loop through `transport`, reusing the builtin
/// engine's mutator + power scheduler + coverage folding, and writing each
/// transport-reported fault as a finding via [`crate::transport_fault::outcome_finding`].
///
/// Bounded by `config.iterations` / `config.time_budget` / `config.stop_after_findings`.
/// Returns the run summary; propagates a transport or finding-write failure as a
/// descriptive error (never a silent `None`).
pub(crate) fn run_transport_campaign(
    transport: &dyn TargetTransport,
    config: &TransportFuzzConfig,
) -> Result<TransportFuzzSummary, TransportFuzzError> {
    let campaign = Campaign::new(config);
    run_worker(0, transport, &campaign, config)?;
    campaign.finish(config)
}

/// [`run_transport_campaign`] over `workers` transports at once (#316): worker
/// `w` drives the transport `make(w)` builds, in a thread of its own, and the
/// workers share one corpus, coverage map, schedule and finding set, so what
/// one finds the others mutate and a fault is one finding however many reach
/// it. The iteration cap and the time budget are the campaign's.
pub(crate) fn run_transport_campaign_workers(
    make: &(dyn Fn(usize) -> Result<Box<dyn TargetTransport>, TransportFuzzError> + Sync),
    workers: usize,
    config: &TransportFuzzConfig,
) -> Result<TransportFuzzSummary, TransportFuzzError> {
    let campaign = Campaign::new(config);
    let results: Vec<Result<(), TransportFuzzError>> = std::thread::scope(|scope| {
        let campaign = &campaign;
        let handles: Vec<_> = (0..workers.max(1))
            .map(|worker| {
                scope.spawn(move || {
                    let transport = make(worker)?;
                    let result = run_worker(worker, transport.as_ref(), campaign, config);
                    if result.is_err() {
                        // The others stop too: the campaign has failed.
                        campaign
                            .lock()
                            .halted
                            .get_or_insert_with(|| format!("worker {worker} failed"));
                    }
                    result
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("transport worker panicked"))
            .collect()
    });
    for result in results {
        result?;
    }
    campaign.finish(config)
}

/// What the workers of a transport campaign share.
struct Campaign {
    start: Instant,
    state: std::sync::Mutex<CampaignState>,
}

struct CampaignState {
    coverage: CoverageProxy,
    scheduler: PowerScheduler,
    emitter: FindingEmitter,
    /// The next seed to run.
    next_seed: usize,
    /// Seeds taken and not yet folded in: until none is, an empty schedule is
    /// not the end of the campaign.
    seeds_in_flight: usize,
    /// Executions a worker has begun: the iteration cap holds on them, so the
    /// workers together never run past it.
    started: usize,
    executions: usize,
    corpus_new: usize,
    crashes: usize,
    // Executions whose post-stop coverage/evidence collection was incomplete
    // (#74): surfaced in the summary so partial coverage — on a clean run or a
    // crash — is never silently presented as complete.
    incomplete_observations: usize,
    // Runs whose clean/crash classification is UNRELIABLE because a configured
    // fault-determining observation failed (#72 re-review): recorded here, never
    // counted as a clean pass and never turned into a fabricated finding.
    inconclusive_observations: usize,
    finding_ids: Vec<String>,
    /// The worker whose transport found each finding, for its replay profile.
    finding_workers: std::collections::HashMap<String, usize>,
    // Dedup findings on the same key the on-disk finding signature is built from
    // (rule_id | kind; the transport lane carries no stack frames), so one fault
    // class yields one finding regardless of how many inputs reach it.
    seen_findings: std::collections::HashSet<String>,
    // Distinct crash-candidate count per (target | rule | kind) class, bounding
    // how many distinct fault sites one class may retain (#75).
    class_counts: std::collections::HashMap<String, usize>,
    // Set when a run-control condition stops the campaign early (#70): a target
    // hang or a lost transport — a distinct, non-clean outcome.
    halted: Option<String>,
    // The target cycles of each completed run, when the spec reads a counter.
    target_cycles: Option<CycleStats>,
    /// The comparisons each corpus member's run recorded (#386), keyed by the
    /// member's bytes: the mutator splices their operands into it.
    cmplogs: std::collections::HashMap<Vec<u8>, std::sync::Arc<cmplog::CmpLog>>,
    comparisons: usize,
}

impl Campaign {
    fn new(config: &TransportFuzzConfig) -> Self {
        let emitter = FindingEmitter::with_metadata(
            config.work_dir.clone(),
            config.harness_id.clone(),
            "transport".to_owned(),
            config.transport_label.clone(),
        )
        .with_mode(config.mode);
        Self {
            start: Instant::now(),
            state: std::sync::Mutex::new(CampaignState {
                coverage: CoverageProxy::default(),
                scheduler: PowerScheduler::default(),
                emitter,
                next_seed: 0,
                seeds_in_flight: 0,
                started: 0,
                executions: 0,
                corpus_new: 0,
                crashes: 0,
                incomplete_observations: 0,
                inconclusive_observations: 0,
                finding_ids: Vec::new(),
                finding_workers: std::collections::HashMap::new(),
                seen_findings: std::collections::HashSet::new(),
                class_counts: std::collections::HashMap::new(),
                halted: None,
                target_cycles: None,
                cmplogs: std::collections::HashMap::new(),
                comparisons: 0,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CampaignState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn should_stop(&self, state: &CampaignState, config: &TransportFuzzConfig) -> bool {
        state.halted.is_some()
            || should_stop(
                state.started,
                config.iterations,
                self.start,
                config.time_budget,
                state.finding_ids.len(),
                config.stop_after_findings,
            )
    }

    /// Fold one run in: count it, keep its coverage, keep a clean input that
    /// reached new coverage (always, for a seed), and turn a fault into a
    /// finding.
    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        worker: usize,
        input: &[u8],
        seed: bool,
        outcome: &RunOutcome,
        elapsed: Duration,
        config: &TransportFuzzConfig,
    ) -> Result<(), TransportFuzzError> {
        let mut state = self.lock();
        let state = &mut *state;
        state.executions += 1;
        CycleStats::record(&mut state.target_cycles, outcome.target.cycles);
        if outcome.coverage_incomplete.is_some() {
            state.incomplete_observations += 1;
        }
        if outcome.inconclusive.is_some() {
            state.inconclusive_observations += 1;
        }
        state.comparisons += outcome.target.comparisons.len();
        let feedback = fold_coverage(&mut state.coverage, &outcome.coverage_edges);
        if seed {
            // Seeds are always corpus members.
            state
                .scheduler
                .insert_with_feedback(input, feedback.to_schedule_feedback());
            state.seeds_in_flight -= 1;
            keep_cmplog(state, input, outcome);
        } else if outcome.exit == ExitKind::Ok
            && outcome.inconclusive.is_none()
            && (feedback.new_bitmap_bits() > 0 || feedback.new_exception_signatures > 0)
        {
            // Retain a clean input that reached new coverage as a new corpus
            // seed, feeding its novelty back into the power schedule. A
            // crashing input becomes a finding, not a seed; an INCONCLUSIVE
            // run is not a proven clean pass, so it is not retained as a clean
            // seed either (#72 re-review).
            state
                .scheduler
                .insert_with_feedback(input, feedback.to_schedule_feedback());
            state.corpus_new += 1;
            keep_cmplog(state, input, outcome);
        }
        let before = state.finding_ids.len();
        handle_outcome(
            outcome,
            input,
            &config.transport_label,
            &state.emitter,
            &mut state.seen_findings,
            &mut state.class_counts,
            &mut state.finding_ids,
            &mut state.crashes,
        )?;
        // The deadline oracle is for a COMPLETED-but-slow run only: a crash
        // or execution timeout already yields its own finding, and an
        // INCONCLUSIVE run is not a proven clean completion — firing it for
        // either would fabricate a timing finding.
        if outcome.exit == ExitKind::Ok && outcome.inconclusive.is_none() {
            maybe_emit_deadline(
                run_time(config.cycle_counter, outcome, elapsed),
                config.deadline,
                input,
                &state.emitter,
                &mut state.seen_findings,
                &mut state.finding_ids,
                &mut state.crashes,
            )?;
        }
        for id in &state.finding_ids[before..] {
            state.finding_workers.insert(id.clone(), worker);
        }
        Ok(())
    }

    fn finish(
        self,
        config: &TransportFuzzConfig,
    ) -> Result<TransportFuzzSummary, TransportFuzzError> {
        let start = self.start;
        let state = self
            .state
            .into_inner()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let throughput = Throughput::new(state.executions, start.elapsed());
        // Persist a replayable target profile next to each finding (#80), with
        // the spec of the worker whose transport found it.
        persist_transport_profiles(
            config,
            &state.finding_ids,
            &state.finding_workers,
            throughput,
        );
        let snapshot = state.coverage.snapshot();
        Ok(TransportFuzzSummary {
            schema_version: 1,
            harness_id: config.harness_id.clone(),
            engine: "transport".to_owned(),
            transport: config.transport_label.clone(),
            seeds: config.seeds.len(),
            executions: state.executions,
            corpus_new: state.corpus_new,
            coverage_edges: snapshot.edge_bits,
            coverage_blocks: snapshot.breadcrumb_bits,
            crashes: state.crashes,
            incomplete_observations: state.incomplete_observations,
            inconclusive_observations: state.inconclusive_observations,
            findings: state.finding_ids,
            halted: state.halted,
            target_cycles: state.target_cycles,
            workers: config.worker_specs.len().max(1),
            comparisons: state.comparisons,
            elapsed_secs: throughput.elapsed_secs,
            executions_per_sec: throughput.executions_per_sec,
        })
    }
}

/// Keep the comparisons a new corpus member's run recorded, as the CmpLog
/// its mutations splice from: an operand found in the input is replaced with
/// the value it was compared against (#386).
fn keep_cmplog(state: &mut CampaignState, input: &[u8], outcome: &RunOutcome) {
    let mut log = cmplog::CmpLog::new();
    for comparison in &outcome.target.comparisons {
        log.record(cmplog::CmpEntry {
            site_id: u64::from(comparison.site),
            operand_a: comparison.lhs_bytes(),
            operand_b: comparison.rhs_bytes(),
            kind: cmplog::CmpKind::IntegerCompare,
        });
    }
    log.retain_spliceable(input);
    if !log.entries.is_empty() {
        state
            .cmplogs
            .insert(input.to_vec(), std::sync::Arc::new(log));
    }
}

/// One worker of a campaign: run seeds while any are left, then mutate the
/// shared corpus, each input through its own `transport`.
fn run_worker(
    worker: usize,
    transport: &dyn TargetTransport,
    campaign: &Campaign,
    config: &TransportFuzzConfig,
) -> Result<(), TransportFuzzError> {
    let mut session = transport.arm()?;
    let mutator = MutatorSuite::new(MutatorConfig {
        max_len: config.max_len.max(1),
        ..MutatorConfig::default()
    });
    // Worker 0 mutates as a campaign of one does; the others on streams of
    // their own.
    let mut rng = MutationRng::new(
        config
            .rng_seed
            .wrapping_add((worker as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)),
    );
    let dictionary = Dictionary::from_tokens(config.dictionary.iter().cloned());
    let halt = |reason: String| {
        let mut state = campaign.lock();
        if state.halted.is_none() {
            state.halted = Some(if config.worker_specs.len() > 1 {
                format!("worker {worker}: {reason}")
            } else {
                reason
            });
        }
    };

    // --- seed phase: every seed runs once, on whichever worker takes it. ---
    loop {
        let seed = {
            let mut state = campaign.lock();
            if campaign.should_stop(&state, config) || state.next_seed >= config.seeds.len() {
                break;
            }
            let seed = config.seeds[state.next_seed].clone();
            state.next_seed += 1;
            state.seeds_in_flight += 1;
            state.started += 1;
            seed
        };
        match run_one_input(session.as_mut(), &seed)? {
            Step::Halt(reason) => {
                campaign.lock().seeds_in_flight -= 1;
                halt(reason);
                return Ok(());
            }
            Step::Ran(outcome, elapsed) => {
                campaign.record(worker, &seed, true, &outcome, elapsed, config)?;
            }
        }
    }

    // --- mutation phase: scheduler-driven, coverage-guided. ---
    'outer: loop {
        let scheduled = {
            let mut state = campaign.lock();
            if campaign.should_stop(&state, config) {
                break;
            }
            match state.scheduler.select_next() {
                Some(scheduled) => {
                    let cmplog = state.cmplogs.get(&scheduled.bytes).cloned();
                    (scheduled, cmplog)
                }
                // Another worker's seed may yet arrive.
                None if state.seeds_in_flight > 0 => {
                    drop(state);
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                // No corpus (no seeds and none retained) — nothing to mutate.
                None => break,
            }
        };
        let (scheduled, cmplog) = scheduled;
        // The scheduler's power schedule sets how many children this seed earns.
        let children = scheduled.energy.max(1);
        for _ in 0..children {
            {
                let mut state = campaign.lock();
                if campaign.should_stop(&state, config) {
                    break 'outer;
                }
                state.started += 1;
            }
            // With a grammar, a target that parses it gets only its
            // sentences: a byte mutation of one would mostly not be.
            let generated = match &config.grammar {
                Some(grammar) => grammar.generate(config.max_len.max(1), &mut rng),
                None => {
                    let spans = config
                        .arg_layout
                        .as_ref()
                        .map(|layout| {
                            crate::fuzz::typed_spans::arg_layout_typed_spans(
                                layout,
                                &scheduled.bytes,
                            )
                        })
                        .unwrap_or_default();
                    let mut input =
                        MutationInput::new(&scheduled.bytes, &dictionary).with_typed_spans(&spans);
                    if let Some(log) = cmplog.as_deref() {
                        input = input.with_cmplog(log);
                    }
                    mutator.mutate(&input, &mut rng).map(|result| result.bytes)
                }
            };
            let input = generated.unwrap_or_else(|| scheduled.bytes.clone());
            match run_one_input(session.as_mut(), &input)? {
                Step::Halt(reason) => {
                    halt(reason);
                    break 'outer;
                }
                Step::Ran(outcome, elapsed) => {
                    campaign.record(worker, &input, false, &outcome, elapsed, config)?;
                }
            }
        }
    }
    Ok(())
}

/// Schema id and filename for the per-finding replay profile (#80).
const TRANSPORT_PROFILE_SCHEMA: &str = "bhf.transport-profile.v1";
pub(crate) const TRANSPORT_PROFILE_FILE: &str = "transport_profile.json";

/// Whether a `qemu-system:` spec names `reset=<mode>`.
fn qemu_system_resets_with(spec: &str, mode: &str) -> bool {
    let spec = spec.trim();
    spec.starts_with("qemu-system:")
        && spec.split(',').any(|part| {
            part.split_once('=')
                .is_some_and(|(key, value)| key.trim() == "reset" && value.trim() == mode)
        })
}

/// Whether a `qemu-system:` spec continues the guest's own input loop
/// between clean inputs (`reset=persistent`).
fn resets_persistently(spec: &str) -> bool {
    qemu_system_resets_with(spec, "persistent")
}

/// The backend and reset mechanism a spec implies, for the replay profile.
fn backend_and_reset(spec: &str) -> (&'static str, &'static str) {
    let spec = spec.trim();
    if spec.starts_with("agent:tcp") || spec.starts_with("agent:serial") {
        ("agent", "agent-protocol reset")
    } else if spec.starts_with("gdb:") {
        ("gdb-remote", "gdb R restart")
    } else if resets_persistently(spec) {
        (
            "qemu-system",
            "guest persistent loop; qmp loadvm before the first input and after a crash, hang \
             or inconclusive run",
        )
    } else if qemu_system_resets_with(spec, "fast") {
        (
            "qemu-system",
            "dirty-page fast snapshot: system_reset and the RAM pages the last run wrote put \
             back over gdb; qmp loadvm while a written page has no baseline yet",
        )
    } else if spec.starts_with("qemu-system:") {
        ("qemu-system", "qmp savevm/loadvm snapshot")
    } else if spec.starts_with("renode:") {
        ("renode", "renode Save/Load snapshot")
    } else {
        ("unknown", "unknown")
    }
}

/// Persist a versioned, portable target profile next to each emitted finding so
/// it can be replayed against the same target / reset contract (#80): the spec,
/// coverage map, transport label, backend and reset mechanism, and the known
/// fidelity limitations. Endpoints are recorded verbatim from the operator's
/// spec; `bhf replay --transport-endpoint` relocates them, and a report that is
/// published more widely should not embed sensitive endpoints indiscriminately.
fn persist_transport_profiles(
    config: &TransportFuzzConfig,
    finding_ids: &[String],
    finding_workers: &std::collections::HashMap<String, usize>,
    throughput: Throughput,
) {
    for id in finding_ids {
        // The spec of the worker whose transport found it (#316).
        let spec = finding_workers
            .get(id)
            .filter(|_| config.worker_specs.len() > 1)
            .and_then(|worker| config.worker_specs.get(*worker))
            .unwrap_or(&config.spec);
        persist_transport_profile(config, spec, id, throughput);
    }
}

fn persist_transport_profile(
    config: &TransportFuzzConfig,
    spec: &str,
    id: &str,
    throughput: Throughput,
) {
    let (backend, reset) = backend_and_reset(spec);
    let mut limitations = vec!["host-observed timing"];
    if config.firmware_identity.is_none() {
        limitations.push("firmware identity not recorded (name the ELF with firmware=)");
    }
    if resets_persistently(spec) {
        limitations.push(
            "reset=persistent: guest state carries over between clean inputs, so a finding \
             may depend on the inputs before it; bhf replay replays it from the snapshot",
        );
    }
    if qemu_system_resets_with(spec, "fast") {
        limitations.push(
            "reset=fast: devices come back by a machine reset, and RAM written out of the \
             dirty-page log's sight is not put back: a device's DMA, and on a Cortex-M core the \
             frame of an exception taken and returned before the stop where no store dirtied its \
             page (frames still stacked at the stop and bit-band stores are put back); bhf replay \
             restores with loadvm",
        );
    }
    // Persist the timing contract so `bhf replay` can reproduce a timing finding:
    // the per-input execution deadline (rebuild the transport with the SAME bound
    // so an execution-timeout re-times-out) and the response-time deadline (so a
    // "completed-but-slow" BHF-555 finding is re-evaluated against the same bound,
    // not silently reported as "no fault reproduced"). `null` when unset (#70/#80).
    let timing = serde_json::json!({
        "per_input_timeout_ms": config.per_input_timeout.map(|d| d.as_millis()),
        "deadline_ms": config.deadline.map(|d| d.as_millis()),
        // What times a run for the deadline (#251).
        "basis": match config.cycle_counter {
            Some(CycleCounter { hz: Some(_), .. }) => "target cycles",
            _ => "host round-trip",
        },
        "cpu_hz": config.cycle_counter.and_then(|counter| counter.hz),
    });
    let profile = serde_json::json!({
        "schema_version": TRANSPORT_PROFILE_SCHEMA,
        "spec": spec,
        "coverage_map": config.coverage_map,
        "transport_label": config.transport_label,
        "backend": backend,
        "reset_mechanism": reset,
        "timing": timing,
        // The staging region the input was written under (#84): its capacity
        // and the length word, `null` for a backend with no such region.
        "input_contract": config.input_contract.map(|contract| serde_json::json!({
            "capacity": contract.capacity,
            "length_word": contract.length_word,
        })),
        "firmware_identity": config.firmware_identity,
        // The campaign's executions per second (#346).
        "throughput": throughput,
        "limitations": limitations.join("; "),
    });
    let Ok(body) = serde_json::to_vec_pretty(&profile) else {
        return;
    };
    {
        let dir = config.work_dir.join("results").join("findings").join(id);
        let _ = std::fs::write(dir.join(TRANSPORT_PROFILE_FILE), &body);
        // The finding names the firmware it was found on, too (#248).
        if let Some(identity) = &config.firmware_identity {
            let path = dir.join("finding.json");
            if let Some(mut finding) = std::fs::read(&path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            {
                finding["firmware_identity"] = identity.clone();
                if let Ok(bytes) = serde_json::to_vec_pretty(&finding) {
                    let _ = std::fs::write(&path, bytes);
                }
            }
        }
    }
}

/// How a single transport execution concluded (#70): it ran (carrying the
/// outcome, boxed as the far larger variant, and the host-observed duration
/// for the deadline oracle), or it hit a bounded, non-clean run-control halt
/// (a target hang or a lost transport).
enum Step {
    Ran(Box<RunOutcome>, Duration),
    Halt(String),
}

/// Classification of an I/O failure that ESCAPES a run (#70). A genuine
/// target-execution timeout (a hang) is no longer classified here: the transport
/// session now surfaces it as a first-class [`ExitKind::Timeout`] outcome, so an
/// error reaching this point is necessarily a control/setup failure or a lost
/// link — never a target overrunning its per-input execution deadline.
enum RunFailure {
    /// A read/write timeout on a CONTROL/setup exchange (reset, input injection,
    /// handshake) or a run with no per-input deadline configured: the transport
    /// stopped responding. This is NOT the target overrunning its execution
    /// deadline (that is an `ExitKind::Timeout` outcome), so it halts WITHOUT
    /// inventing a target-execution timing finding.
    ControlTimeout,
    /// The transport link dropped mid-exchange.
    LostTransport,
    /// Any other failure (setup / protocol) — propagated, not swallowed.
    Other,
}

fn classify_run_failure(err: &TransportError) -> RunFailure {
    match err {
        TransportError::Io(io) => match io.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                RunFailure::ControlTimeout
            }
            std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::NotConnected => RunFailure::LostTransport,
            _ => RunFailure::Other,
        },
        _ => RunFailure::Other,
    }
}

/// Run one input, measuring its host-observed duration and classifying any I/O
/// failure that escapes the session (#70). A target-execution timeout (a hang)
/// is handled inside the session as an [`ExitKind::Timeout`] outcome and flows
/// back through [`Step::Ran`] → [`handle_outcome`] as a BHF-555 finding; here a
/// control/setup timeout and a lost transport halt the campaign WITHOUT inventing
/// a finding, and any other error propagates.
fn run_one_input(
    session: &mut dyn TargetSession,
    input: &[u8],
) -> Result<Step, TransportFuzzError> {
    let start = Instant::now();
    match session.run_input(input) {
        Ok(outcome) => Ok(Step::Ran(Box::new(outcome), start.elapsed())),
        Err(err) => match classify_run_failure(&err) {
            RunFailure::ControlTimeout => {
                Ok(Step::Halt(format!("transport control timeout: {err}")))
            }
            RunFailure::LostTransport => Ok(Step::Halt(format!("transport lost: {err}"))),
            RunFailure::Other => Err(TransportFuzzError::Transport(err)),
        },
    }
}

/// Emit the BHF-555 deadline finding when a completed run's host-observed
/// duration exceeded the configured `--deadline` (#70). A no-op when no
/// deadline is set or the run was fast enough.
#[allow(clippy::too_many_arguments)]
fn maybe_emit_deadline(
    (elapsed, measured): (Duration, String),
    deadline: Option<Duration>,
    input: &[u8],
    emitter: &FindingEmitter,
    seen: &mut std::collections::HashSet<String>,
    finding_ids: &mut Vec<String>,
    crashes: &mut usize,
) -> Result<(), CorpusError> {
    if let Some(deadline) = deadline {
        if elapsed > deadline {
            let report = crate::transport_fault::deadline_report(elapsed, deadline, &measured);
            emit_report(input, &report, emitter, seen, finding_ids, crashes)?;
        }
    }
    Ok(())
}

/// Turn one run outcome into a finding when it crashed/timed out, deduped by
/// fault class, and count crash outcomes. A clean outcome is a no-op.
/// Upper bound on DISTINCT crash candidates retained per (target | rule | kind)
/// class (#75). Distinct fault sites below this bound are each kept; beyond it
/// further distinct sites dedup, so a varying backend-reported address cannot
/// create unbounded findings.
const MAX_CANDIDATES_PER_CLASS: usize = 16;

#[allow(clippy::too_many_arguments)]
fn handle_outcome(
    outcome: &RunOutcome,
    input: &[u8],
    transport_label: &str,
    emitter: &FindingEmitter,
    seen: &mut std::collections::HashSet<String>,
    class_counts: &mut std::collections::HashMap<String, usize>,
    finding_ids: &mut Vec<String>,
    crashes: &mut usize,
) -> Result<(), CorpusError> {
    let Some(mut report) = crate::transport_fault::outcome_finding(outcome) else {
        return Ok(());
    };
    *crashes += 1;

    // Structured fault-site identity (#75). A backend-attributed faulting address
    // is a bounded SITE discriminator so two distinct sites of one fault class are
    // retained as separate candidates, and the target label keeps faults from
    // different targets from merging on identical relative values. The address is
    // a backend-reported access/stop address, NOT a verified instruction site, and
    // is never asserted as a confirmed root cause: candidates per class are capped.
    //
    // An UNLOCALIZED fault (no attributed address — e.g. a full-system signal or a
    // guest fault-status fault) must NOT collapse every later testcase into one
    // candidate (the #75 review): give each occurrence a distinct bounded slot
    // (`unlocalized#N` up to the cap) so later distinct faults keep their testcase,
    // and mark the grouping explicitly uncertain since they cannot be told apart.
    let class_key = format!("{transport_label}|{}|{}", report.rule_id, report.kind);
    let class_count = *class_counts.get(&class_key).unwrap_or(&0);
    // `site` is the human / persisted-signature label; `dedup_key` is what the
    // `seen` set keys on. A localized fault dedups on its exact address. An
    // UNLOCALIZED fault dedups on the INPUT HASH, NOT on the occurrence counter:
    // otherwise re-running the SAME testcase mints a fresh `unlocalized#N` identity
    // every time and exhausts the bounded per-class allowance before a genuinely
    // different testcase arrives (#75 re-review). The slot it is eventually given
    // is still `unlocalized#N` (a bounded, grouping-uncertain candidate).
    let (site, localized, dedup_key) = match outcome.fault.as_ref().and_then(|f| f.address) {
        Some(address) => {
            let site = format!("{address:#x}");
            let dedup = format!("{class_key}|{site}");
            (site, true, dedup)
        }
        None => (
            format!("unlocalized#{class_count}"),
            false,
            format!("{class_key}|unlocalized:{}", short_input_hash(input)),
        ),
    };

    // Same fault (localized address, or unlocalized identical testcase) -> dedup.
    if seen.contains(&dedup_key) {
        return Ok(());
    }
    // Bounded candidate evidence: once the class is saturated, stop splitting.
    let count = class_counts.entry(class_key).or_insert(0);
    if *count >= MAX_CANDIDATES_PER_CLASS {
        return Ok(());
    }

    if !localized {
        report.message.push_str(
            " [unlocalized fault site: no backend-attributed address — grouping uncertain]",
        );
    }
    // Carry the collection diagnostic, when present, into the finding so an
    // incomplete observation is not silently lost (#74 review).
    if let Some(diag) = &outcome.coverage_incomplete {
        report
            .message
            .push_str(&format!(" [coverage incomplete: {diag}]"));
    }
    // Fold the target + site into the persisted signature (via a synthetic frame)
    // so the on-disk signature/cluster identity AGREES with this campaign-level
    // dedup — removing the in-memory filter alone would not fix the empty-stack
    // signature collapse the issue calls out.
    report.stack.push(corpus::sanitizer::StackFrame {
        function: format!("<on-target fault {transport_label} @ {site}>"),
        file: None,
        line: None,
    });
    let id = emitter.emit_sanitizer_crash(input, &report)?;
    // The task the firmware says ran the input (#252).
    if let Some(task) = outcome.target.task_id {
        record_target_task(emitter, &id.0, task);
    }
    finding_ids.push(id.0);
    seen.insert(dedup_key);
    *count += 1;
    Ok(())
}

/// Add `target_task` (the firmware's task identity word, as hex) to the
/// finding `id`.
fn record_target_task(emitter: &FindingEmitter, id: &str, task: u64) {
    let path = corpus::layout::finding_dir(emitter.root(), id).join("finding.json");
    let Some(mut finding) = std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
    else {
        return;
    };
    finding["target_task"] = serde_json::json!({ "id": format!("{task:#x}") });
    if let Ok(bytes) = serde_json::to_vec_pretty(&finding) {
        let _ = std::fs::write(&path, bytes);
    }
}

/// A short, stable content hash of a testcase, used only to deduplicate repeated
/// identical inputs within an unlocalized fault class (#75 re-review) — not a
/// persisted identity. 64 bits of SHA-256 is ample to avoid in-run collisions.
fn short_input_hash(input: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(input);
    let mut out = String::with_capacity(16);
    for byte in &digest[..8] {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Persist one finding report for `input`, counting the non-clean outcome and
/// deduping on the on-disk signature key (rule_id | kind). Shared by the
/// crash/timeout path, the per-input timeout path, and the deadline oracle.
fn emit_report(
    input: &[u8],
    report: &corpus::SanitizerReport,
    emitter: &FindingEmitter,
    seen: &mut std::collections::HashSet<String>,
    finding_ids: &mut Vec<String>,
    crashes: &mut usize,
) -> Result<(), CorpusError> {
    *crashes += 1;
    let dedup_key = format!("{}|{}", report.rule_id, report.kind);
    if !seen.insert(dedup_key) {
        return Ok(());
    }
    let id = emitter.emit_sanitizer_crash(input, report)?;
    finding_ids.push(id.0);
    Ok(())
}

// ---------------------------------------------------------------------------
// CLI entry
// ---------------------------------------------------------------------------

/// `bhf fuzz --target-transport <spec>` entry point. Parses the spec, builds the
/// transport, loads seeds, runs the campaign, and prints the JSON summary.
pub(crate) fn run(args: FuzzArgs) -> i32 {
    match run_inner(args) {
        Ok(summary) => {
            // A run-control halt (target hang / lost transport) is a non-clean
            // outcome: print the summary (findings included) but exit non-zero so
            // it is never reported as a clean run (#70).
            let halted = summary.halted.is_some();
            match serde_json::to_string_pretty(&summary) {
                Ok(json) => {
                    println!("{json}");
                    i32::from(halted)
                }
                Err(error) => {
                    crate::bhfeprintln!("failed to render transport-fuzz summary: {error}");
                    1
                }
            }
        }
        Err(code) => code,
    }
}

/// Whether a `--target-transport` spec names each worker's target (#316).
fn has_worker_template(spec: &str) -> bool {
    resolve_worker_spec(spec, 0) != resolve_worker_spec(spec, 1)
}

/// `spec` for worker `worker`: `{worker}` is its number, and `{BASE+worker}`
/// (decimal) is `BASE` plus it, for a port per worker.
fn resolve_worker_spec(spec: &str, worker: usize) -> String {
    let mut out = String::with_capacity(spec.len());
    let mut rest = spec;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            out.push_str(&rest[open..]);
            return out;
        };
        let inner = &after[..close];
        let value = if inner == "worker" {
            Some(worker as u64)
        } else {
            inner
                .strip_suffix("+worker")
                .and_then(|base| base.trim().parse::<u64>().ok())
                .map(|base| base + worker as u64)
        };
        match value {
            Some(value) => out.push_str(&value.to_string()),
            None => out.push_str(&rest[open..open + 1 + close + 1]),
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

fn run_inner(mut args: FuzzArgs) -> Result<TransportFuzzSummary, i32> {
    let template = args
        .target_transport
        .clone()
        .expect("run() is only reached when --target-transport is set");
    // #316: `--workers N` is N transports, one spec each.
    let worker_specs = match args.workers {
        None | Some(crate::fuzz::FuzzWorkerCount::Fixed(0 | 1)) => {
            vec![resolve_worker_spec(&template, 0)]
        }
        Some(crate::fuzz::FuzzWorkerCount::Fixed(n)) if has_worker_template(&template) => (0..n
            as usize)
            .map(|worker| resolve_worker_spec(&template, worker))
            .collect(),
        Some(_) => {
            crate::bhfeprintln!(
                "bhf fuzz --target-transport: --workers runs one transport per worker: give \
                 a number of workers, and a spec naming each worker's target with {{worker}} \
                 (0, 1, ...) or {{BASE+worker}} (agent:tcp:127.0.0.1:{{9000+worker}})"
            );
            return Err(2);
        }
    };
    let spec = worker_specs[0].as_str();

    let plan =
        TransportPlan::parse(spec, args.transport_coverage_map.as_deref()).map_err(|error| {
            crate::bhfeprintln!("bhf fuzz --target-transport: {error}");
            2
        })?;
    for note in plan.notes() {
        crate::bhfeprintln!("bhf fuzz --target-transport: note: {note}");
    }
    // Never generate an input the staging region cannot hold.
    let input_contract = plan.input_contract();
    if let Some(contract) = input_contract {
        if args.max_len > contract.capacity {
            crate::bhfeprintln!(
                "bhf fuzz --target-transport: note: --max-len {} is more than input_cap={}; \
                 inputs are at most {} bytes",
                args.max_len,
                contract.capacity,
                contract.capacity
            );
            args.max_len = contract.capacity;
        }
    }
    // The firmware is read once, before anything runs: a finding recorded
    // against an image bhf could not read would name no build.
    let firmware_identity = match plan.firmware() {
        Some(path) => Some(
            binary_analysis::firmware_identity(path)
                .map_err(|error| {
                    crate::bhfeprintln!("bhf fuzz --target-transport: firmware=: {error}");
                    2
                })
                .and_then(|identity| {
                    serde_json::to_value(identity).map_err(|error| {
                        crate::bhfeprintln!("bhf fuzz --target-transport: firmware=: {error}");
                        2
                    })
                })?,
        ),
        None => None,
    };
    let cycle_counter = plan.cycle_counter();
    // One label for the campaign: a fault is one finding whichever worker's
    // target it is on.
    let transport_label = if worker_specs.len() > 1 {
        template.clone()
    } else {
        plan.label()
    };
    // Every worker's spec parses before any worker starts.
    let mut plans = vec![plan];
    for worker_spec in &worker_specs[1..] {
        plans.push(
            TransportPlan::parse(worker_spec, args.transport_coverage_map.as_deref()).map_err(
                |error| {
                    crate::bhfeprintln!("bhf fuzz --target-transport {worker_spec}: {error}");
                    2
                },
            )?,
        );
    }

    // Each worker's QEMU writes its own dirty-page log (#347).
    refuse_shared_dirty_logs(&plans).map_err(|error| {
        crate::bhfeprintln!("bhf fuzz --target-transport: {error}");
        2
    })?;
    // reset=fast reads the log QEMU's dirty-page plugin writes: without one,
    // build the plugin and say how to start QEMU with it (#347).
    for plan in &plans {
        let profile = crate::auto::external_tools::qemu_plugin_profile();
        fast_snapshot_preflight(plan, &args.work_dir, profile).map_err(|error| {
            crate::bhfeprintln!("bhf fuzz --target-transport: {error}");
            2
        })?;
    }

    let fail = |error: String| {
        crate::bhfeprintln!("bhf fuzz --target-transport: {error}");
        3
    };
    let grammar = crate::fuzz::load_grammar_for_run(args.grammar_file.as_deref()).map_err(fail)?;
    let dictionary = crate::fuzz::run_dictionary_tokens(
        &args.work_dir,
        &args.harness,
        args.dict_file.as_deref(),
    )
    .map_err(fail)?;
    let seeds = load_seeds(&args, grammar.as_ref()).map_err(fail)?;

    let config = TransportFuzzConfig {
        work_dir: args.work_dir.clone(),
        harness_id: args.harness.clone(),
        transport_label,
        seeds,
        iterations: args.effective_iterations(),
        time_budget: args.time,
        per_input_timeout: args.timeout,
        deadline: args.deadline,
        spec: spec.to_owned(),
        worker_specs: worker_specs.clone(),
        coverage_map: args.transport_coverage_map.clone(),
        max_len: args.max_len,
        input_contract,
        firmware_identity,
        cycle_counter,
        rng_seed: args.rng_seed,
        stop_after_findings: args.stop_after_findings,
        mode: args.mode,
        dictionary,
        grammar,
        arg_layout: crate::fuzz::typed_spans::find_arg_layout(&args.work_dir, &args.harness, None),
    };

    let timeout = args.timeout;
    let summary = if plans.len() == 1 {
        let transport = plans.remove(0).into_transport(timeout).map_err(|error| {
            crate::bhfeprintln!("bhf fuzz --target-transport: {error}");
            2
        })?;
        run_transport_campaign(transport.as_ref(), &config)
    } else {
        let make = |worker: usize| {
            plans[worker]
                .clone()
                .into_transport(timeout)
                .map_err(TransportFuzzError::from)
        };
        run_transport_campaign_workers(&make, plans.len(), &config)
    }
    .map_err(|error| {
        crate::bhfeprintln!("bhf fuzz --target-transport: {error}");
        1
    })?;
    // A counter that never moved times nothing: the deadline oracle used the
    // host's time instead (#251).
    if config.cycle_counter.is_some()
        && summary.executions > 0
        && summary.target_cycles.is_none_or(|stats| stats.max == 0)
    {
        crate::bhfeprintln!(
            "bhf fuzz --target-transport: note: the cycles= counter never advanced (QEMU's \
             Cortex-M models do not count DWT_CYCCNT; name a free-running counter with \
             cycles=ADDR); deadlines used host-observed time"
        );
    }
    Ok(summary)
}

/// Refuse `--workers` plans that name one dirty-page log (#347): two plugins
/// writing one file, and two sessions emptying it, would each take the
/// other's pages, so a guest's writes would go unrestored.
fn refuse_shared_dirty_logs(plans: &[TransportPlan]) -> Result<(), String> {
    let mut seen: Vec<(PathBuf, usize)> = Vec::new();
    for (worker, plan) in plans.iter().enumerate() {
        let Some(log) = plan.dirty_log() else {
            continue;
        };
        let key = comparable_path(log);
        if let Some((_, first)) = seen.iter().find(|(path, _)| *path == key) {
            return Err(format!(
                "workers {first} and {worker} both name the dirty-page log {}: each worker's \
                 qemu-system needs a log of its own; put {{worker}} in dirty_log= \
                 (dirty_log=/tmp/bhf-dirty-{{worker}}.log)",
                log.display()
            ));
        }
        seen.push((key, worker));
    }
    Ok(())
}

/// `path` in a form two spellings of one file share: canonical when it
/// exists, else its directory's canonical form and its name, else absolute.
fn comparable_path(path: &Path) -> PathBuf {
    if let Ok(path) = std::fs::canonicalize(path) {
        return path;
    }
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        if let Ok(parent) = std::fs::canonicalize(parent) {
            return parent.join(name);
        }
    }
    std::path::absolute(path).unwrap_or_else(|_| path.to_owned())
}

/// Check a `reset=fast` plan before anything connects (#347): the license
/// profile must allow bhf's plugin inside QEMU, and QEMU must be running it.
/// When the dirty-page log is not there, build the plugin under
/// `<work_dir>/qemu-plugin/` and say how to start QEMU with it.
fn fast_snapshot_preflight(
    plan: &TransportPlan,
    work_dir: &Path,
    profile: config::Profile,
) -> Result<(), String> {
    let Some(log) = plan.dirty_log() else {
        return Ok(());
    };
    crate::auto::external_tools::qemu_plugin_gate(profile)?;
    let Err(error) = target_transport::PluginDirtyLog::open(log) else {
        return Ok(());
    };
    let out_dir = work_dir.join("qemu-plugin");
    match crate::auto::external_tools::build_qemu_dirty_page_plugin(&out_dir) {
        Ok(library) => Err(format!(
            "{error}. bhf built the plugin at {}: start qemu-system with -plugin {},log={} \
             and run again",
            library.display(),
            library.display(),
            log.display()
        )),
        Err(build) => Err(format!("{error}. bhf could not build the plugin: {build}")),
    }
}

/// Load seeds from `--seed-input` / `--seed-file`, bounding each to
/// `--max-len`; with none, a derivation of `grammar` when there is one, else
/// the default seed.
fn load_seeds(args: &FuzzArgs, grammar: Option<&Grammar>) -> Result<Vec<Vec<u8>>, String> {
    let cap = args.max_len.max(1);
    let mut seeds: Vec<Vec<u8>> = args
        .seed_inputs
        .iter()
        .map(|s| truncate(s.as_bytes().to_vec(), cap))
        .collect();
    seeds.extend(args.seed_bytes.iter().map(|b| truncate(b.clone(), cap)));
    for path in &args.seed_files {
        let (bytes, _len) = crate::fuzz::read_seed_file_prefix(path, cap)
            .map_err(|error| format!("read seed file '{}': {error}", path.display()))?;
        seeds.push(bytes);
    }
    if seeds.is_empty() {
        let derived =
            grammar.and_then(|grammar| grammar.generate(cap, &mut MutationRng::new(args.rng_seed)));
        seeds.push(derived.unwrap_or_else(|| truncate(DEFAULT_SEED.to_vec(), cap)));
    }
    Ok(seeds)
}

fn truncate(mut bytes: Vec<u8>, cap: usize) -> Vec<u8> {
    bytes.truncate(cap);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use target_transport::testsupport::{duplex, MockAgent, ScriptedResponse};
    use target_transport::{AgentTransport, Fault, FaultKind, TransportError};

    // --- regression: the flag is opt-in; the default flow is untouched -------

    // `FuzzArgs` is a `clap::Args` group; wrap it in a `Parser` to parse a
    // `bhf fuzz`-style argument vector in isolation.
    #[derive(clap::Parser)]
    struct FuzzArgsHarness {
        #[command(flatten)]
        fuzz: FuzzArgs,
    }

    #[test]
    fn transport_path_is_off_by_default_and_opt_in() {
        use clap::Parser;

        // Omitting --target-transport leaves the field None, so `bhf fuzz` takes
        // the existing host libFuzzer/AFL path (should_use_transport == false).
        let default = FuzzArgsHarness::parse_from(["fuzz", "workdir", "--harness", "H-1"]).fuzz;
        assert!(default.target_transport.is_none());
        assert!(default.transport_coverage_map.is_none());
        assert!(
            !should_use_transport(&default),
            "the default flow must not route through the transport path"
        );

        // Passing it opts in.
        let with_transport = FuzzArgsHarness::parse_from([
            "fuzz",
            "workdir",
            "--harness",
            "H-1",
            "--target-transport",
            "agent:tcp:127.0.0.1:9999",
        ])
        .fuzz;
        assert_eq!(
            with_transport.target_transport.as_deref(),
            Some("agent:tcp:127.0.0.1:9999")
        );
        assert!(should_use_transport(&with_transport));
    }

    // --- spec-parser tests ---------------------------------------------------

    #[test]
    fn parses_agent_tcp_spec() {
        let plan = TransportPlan::parse("agent:tcp:127.0.0.1:9999", None).unwrap();
        match plan {
            TransportPlan::AgentTcp { host, port } => {
                assert_eq!(host, "127.0.0.1");
                assert_eq!(port, 9999);
            }
            other => panic!("expected AgentTcp, got {other:?}"),
        }
    }

    #[test]
    fn parses_agent_serial_spec() {
        let plan = TransportPlan::parse("agent:serial:/dev/ttyUSB0", None).unwrap();
        match plan {
            TransportPlan::AgentSerial { path, baud } => {
                assert_eq!(path, PathBuf::from("/dev/ttyUSB0"));
                assert_eq!(baud, None);
            }
            other => panic!("expected AgentSerial, got {other:?}"),
        }
    }

    /// The staging region's size is required: without it every input past the
    /// region's end overwrites the guest globals after it.
    #[test]
    fn the_coverage_map_requires_the_input_capacity_and_takes_a_length_word() {
        let missing = TransportPlan::parse(
            "gdb:127.0.0.1:1234",
            Some("input=0x1000,ring=0x4000,write=0x5000,wrapped=0x5100,cap=64"),
        )
        .unwrap_err();
        assert!(
            matches!(
                missing,
                TransportSpecError::MissingMapKey { key: "input_cap" }
            ),
            "{missing}"
        );
        assert!(missing.to_string().contains("input_cap"), "{missing}");

        let zero = TransportPlan::parse(
            "gdb:127.0.0.1:1234",
            Some("input=0x1000,input_cap=0,ring=0x4000,write=0x5000,wrapped=0x5100,cap=64"),
        )
        .unwrap_err();
        assert!(zero.to_string().contains("at least one byte"), "{zero}");

        let plan = TransportPlan::parse(
            "qemu-system:qmp=127.0.0.1:4444,gdb=127.0.0.1:1234",
            Some("input=0x1000,input_cap=0x40,input_len=0x1040,ring=0x4000,write=0x5000,wrapped=0x5100,cap=64"),
        )
        .unwrap();
        assert_eq!(
            plan.input_contract(),
            Some(InputContract::new(64, Some(0x1040)).unwrap())
        );
        let agent = TransportPlan::parse("agent:tcp:127.0.0.1:9", None).unwrap();
        assert_eq!(agent.input_contract(), None);
    }

    #[test]
    fn an_agent_serial_spec_takes_a_baud_rate() {
        let plan = TransportPlan::parse("agent:serial:/dev/ttyACM0,baud=115200", None).unwrap();
        match plan {
            TransportPlan::AgentSerial { path, baud } => {
                assert_eq!(path, PathBuf::from("/dev/ttyACM0"));
                assert_eq!(baud, Some(115_200));
            }
            other => panic!("expected AgentSerial, got {other:?}"),
        }
        for bad in [
            "agent:serial:/dev/ttyACM0,baud=fast",
            "agent:serial:/dev/ttyACM0,baud=0",
        ] {
            let error = TransportPlan::parse(bad, None).unwrap_err();
            assert!(
                error.to_string().contains("not a positive integer"),
                "{error}"
            );
        }
        let error = TransportPlan::parse("agent:serial:,baud=9600", None).unwrap_err();
        assert!(
            error.to_string().contains("device path is empty"),
            "{error}"
        );
    }

    /// #251: `cycles=` names DWT or a counter address, `cpu_hz=` its rate,
    /// and a deadline is timed by the target only when both are known and
    /// the counter moved.
    #[test]
    fn cycle_keys_parse_and_time_a_run_by_the_target() {
        let map = "input=0x1000,input_cap=64,ring=0x4000,write=0x5000,wrapped=0x5100,cap=512";
        let plan = TransportPlan::parse(
            "qemu-system:qmp=127.0.0.1:1,gdb=127.0.0.1:2,cycles=0x40028018,cpu_hz=25000000",
            Some(map),
        )
        .unwrap();
        assert_eq!(
            plan.cycle_counter(),
            Some(CycleCounter {
                source: CycleSource::Counter(0x4002_8018),
                hz: Some(25_000_000),
            })
        );
        let plan = TransportPlan::parse("gdb:127.0.0.1:2,cycles=dwt", Some(map)).unwrap();
        assert_eq!(
            plan.cycle_counter(),
            Some(CycleCounter {
                source: CycleSource::Dwt,
                hz: None,
            })
        );
        let error = TransportPlan::parse("gdb:127.0.0.1:2,cpu_hz=1000", Some(map)).unwrap_err();
        assert!(
            error.to_string().contains("cpu_hz= needs cycles="),
            "{error}"
        );
        assert!(TransportPlan::parse("gdb:127.0.0.1:2,cycles=dwt,cpu_hz=0", Some(map)).is_err());

        let counter = Some(CycleCounter {
            source: CycleSource::Dwt,
            hz: Some(1_000_000),
        });
        let mut outcome = RunOutcome::clean(Vec::new());
        let host = Duration::from_millis(40);
        outcome.target.cycles = Some(2_500);
        let (time, measured) = run_time(counter, &outcome, host);
        assert_eq!(time, Duration::from_micros(2_500));
        assert_eq!(
            measured,
            "target execution time (2500 cycles at 1000000 Hz)"
        );
        // A counter that did not move, or no rate, falls back to the host.
        outcome.target.cycles = Some(0);
        assert_eq!(run_time(counter, &outcome, host).0, host);
        outcome.target.cycles = Some(2_500);
        let no_rate = Some(CycleCounter {
            source: CycleSource::Dwt,
            hz: None,
        });
        assert_eq!(run_time(no_rate, &outcome, host).0, host);
        assert_eq!(
            run_time(None, &outcome, host).1,
            "host-observed execution time"
        );
        // A session that reports a run of its own (#346) is timed by it.
        outcome.target.host_run_time = Some(Duration::from_millis(3));
        assert_eq!(run_time(None, &outcome, host).0, Duration::from_millis(3));
        assert_eq!(
            run_time(counter, &outcome, host).0,
            Duration::from_micros(2_500),
            "target cycles still come first"
        );
    }

    #[test]
    fn parses_gdb_spec_with_coverage_map() {
        let map_spec =
            "input=0x1000,input_cap=64,ring=0x4000,write=0x5000,wrapped=0x5100,cap=65536";
        let plan = TransportPlan::parse("gdb:127.0.0.1:1234", Some(map_spec)).unwrap();
        match plan {
            TransportPlan::Gdb {
                host,
                port,
                map,
                input,
                firmware,
                cycles,
                task_id,
                cmplog,
                semihosting,
                harness_done,
                fault_status,
                reset,
                notes,
            } => {
                assert!(!semihosting);
                assert_eq!(harness_done, None);
                assert!(fault_status.is_none());
                assert_eq!(reset, ResetMode::Restart);
                assert!(notes.is_empty());
                assert_eq!(firmware, None);
                assert_eq!(cycles, None);
                assert_eq!(task_id, None);
                assert_eq!(cmplog, None);
                assert_eq!(input, InputContract::new(64, None).unwrap());
                assert_eq!(host, "127.0.0.1");
                assert_eq!(port, 1234);
                assert_eq!(map.input_address, 0x1000);
                assert_eq!(map.ring_address, 0x4000);
                assert_eq!(map.ring_write_address, 0x5000);
                assert_eq!(map.ring_wrapped_address, 0x5100);
                assert_eq!(map.ring_capacity, 65536);
            }
            other => panic!("expected Gdb, got {other:?}"),
        }
    }

    /// `nm` prints a Thumb function's address with bit 0 set; a Thumb
    /// breakpoint there never hits, so it is cleared with a note.
    #[test]
    fn a_thumb_done_address_has_its_interworking_bit_cleared_with_a_note() {
        let map_spec = "input=4096,input_cap=64,ring=16384,write=20480,wrapped=20736,cap=32";
        let plan = TransportPlan::parse(
            "qemu-system:qmp=127.0.0.1:4444,gdb=127.0.0.1:1234,done=0x189,done_kind=2",
            Some(map_spec),
        )
        .unwrap();
        let TransportPlan::QemuSystem { harness_done, .. } = &plan else {
            panic!("expected QemuSystem, got {plan:?}");
        };
        assert_eq!(*harness_done, Some((0x188, 2)));
        assert_eq!(
            plan.notes(),
            ["done=0x189 has the Thumb bit set; planting the breakpoint at 0x188"]
        );
        // An ARM (kind 4) or already even address is left alone.
        for (spec, want) in [
            ("done=0x189,done_kind=4", (0x189, 4)),
            ("done=0x188", (0x188, 2)),
        ] {
            let plan = TransportPlan::parse(
                &format!("qemu-system:qmp=127.0.0.1:4444,gdb=127.0.0.1:1234,{spec}"),
                Some(map_spec),
            )
            .unwrap();
            let TransportPlan::QemuSystem { harness_done, .. } = &plan else {
                panic!("expected QemuSystem");
            };
            assert_eq!(*harness_done, Some(want), "{spec}");
            assert!(plan.notes().is_empty(), "{spec}");
        }
    }

    #[test]
    fn parses_qemu_system_spec_with_default_and_explicit_snapshot() {
        let map_spec = "input=4096,input_cap=64,ring=16384,write=20480,wrapped=20736,cap=32";
        // Default snapshot tag.
        let plan = TransportPlan::parse(
            "qemu-system:qmp=127.0.0.1:4444,gdb=127.0.0.1:1234",
            Some(map_spec),
        )
        .unwrap();
        match plan {
            TransportPlan::QemuSystem {
                qmp_host,
                qmp_port,
                gdb_host,
                gdb_port,
                map,
                input,
                snapshot_tag,
                harness_done,
                fault_status,
                reset,
                dirty_log,
                firmware: _,
                cycles: _,
                task_id: _,
                cmplog: _,
                semihosting: _,
                notes,
            } => {
                assert!(notes.is_empty(), "{notes:?}");
                assert_eq!(
                    reset,
                    FullSystemReset::Loadvm,
                    "a loadvm per input by default"
                );
                assert_eq!(dirty_log, None);
                assert_eq!(input.capacity, 64);
                assert_eq!(qmp_host, "127.0.0.1");
                assert_eq!(qmp_port, 4444);
                assert_eq!(gdb_host, "127.0.0.1");
                assert_eq!(gdb_port, 1234);
                assert_eq!(map.input_address, 4096);
                assert_eq!(map.ring_capacity, 32);
                assert_eq!(snapshot_tag, DEFAULT_SNAPSHOT_TAG);
                // No completion contract keys => both unset.
                assert!(harness_done.is_none());
                assert!(fault_status.is_none());
            }
            other => panic!("expected QemuSystem, got {other:?}"),
        }
        // Explicit snapshot tag is honored.
        let plan = TransportPlan::parse(
            "qemu-system:qmp=h:1,gdb=h:2,snapshot=my-baseline",
            Some(map_spec),
        )
        .unwrap();
        match plan {
            TransportPlan::QemuSystem { snapshot_tag, .. } => {
                assert_eq!(snapshot_tag, "my-baseline");
            }
            other => panic!("expected QemuSystem, got {other:?}"),
        }
    }

    #[test]
    fn parses_qemu_system_completion_and_fault_status_contract() {
        let map_spec = "input=4096,input_cap=64,ring=16384,write=20480,wrapped=20736,cap=32";
        // done= plants the completion breakpoint (default Thumb kind 2); fault=
        // declares the firmware fault-status word (#71/#72).
        let plan = TransportPlan::parse(
            "qemu-system:qmp=h:1,gdb=h:2,done=0x1a8,fault=0x20000100",
            Some(map_spec),
        )
        .unwrap();
        match plan {
            TransportPlan::QemuSystem {
                harness_done,
                fault_status,
                ..
            } => {
                assert_eq!(harness_done, Some((0x1a8, 2)));
                let status = fault_status.expect("fault status present");
                assert_eq!(status.address, 0x2000_0100);
                assert_eq!(status.width, 4);
                assert_eq!(status.clear_value, 0);
            }
            other => panic!("expected QemuSystem, got {other:?}"),
        }
        // Explicit kind/width/clear are honored.
        let plan = TransportPlan::parse(
            "qemu-system:qmp=h:1,gdb=h:2,done=0x200,done_kind=4,fault=0x300,fault_width=2,fault_clear=0xff",
            Some(map_spec),
        )
        .unwrap();
        match plan {
            TransportPlan::QemuSystem {
                harness_done,
                fault_status,
                ..
            } => {
                assert_eq!(harness_done, Some((0x200, 4)));
                let status = fault_status.unwrap();
                assert_eq!(status.width, 2);
                assert_eq!(status.clear_value, 0xff);
            }
            other => panic!("expected QemuSystem, got {other:?}"),
        }
    }

    /// #293: a board over `gdb:` takes the qemu-system completion contract
    /// (`done=`, a Thumb address corrected; `fault=` and its width and clear
    /// value) and a reset by monitor command.
    #[test]
    fn the_gdb_spec_takes_the_completion_contract_and_a_monitor_reset() {
        let map_spec = "input=0x1000,input_cap=64,ring=0x4000,write=0x5000,wrapped=0x5100,cap=32";
        let plan = TransportPlan::parse(
            "gdb:127.0.0.1:3333,done=0xa9,fault=0x20000100,fault_width=2,fault_clear=0xff,\
             reset=monitor:reset halt",
            Some(map_spec),
        )
        .unwrap();
        let TransportPlan::Gdb {
            harness_done,
            fault_status,
            reset,
            notes,
            ..
        } = &plan
        else {
            panic!("expected Gdb, got {plan:?}");
        };
        assert_eq!(*harness_done, Some((0xa8, 2)));
        let status = fault_status.as_ref().unwrap();
        assert_eq!(
            (status.address, status.width, status.clear_value),
            (0x2000_0100, 2, 0xff)
        );
        assert_eq!(*reset, ResetMode::Monitor("reset halt".to_owned()));
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(plan.into_transport(None).is_ok());

        for (spec, want) in [
            (
                "gdb:h:1,reset=monitor:",
                "expected restart or monitor:COMMAND",
            ),
            ("gdb:h:1,reset=hard", "expected restart or monitor:COMMAND"),
            ("gdb:h:1,fault=0x10,fault_width=9", "must be 1..=8 bytes"),
            ("gdb:h:1,snapshot=x", "unknown option"),
        ] {
            let error = TransportPlan::parse(spec, Some(map_spec))
                .unwrap_err()
                .to_string();
            assert!(error.contains(want), "{spec}: {error}");
        }
    }

    /// #292: `coverage=semihosting` takes each run's coverage from the
    /// semihosting channel, so the map names no ring; `memory_buffer`, the
    /// default, needs one.
    #[test]
    fn semihosting_coverage_replaces_the_ring_in_the_map() {
        let semihosting = "input=0x1000,input_cap=64,coverage=semihosting";
        for spec in [
            "gdb:127.0.0.1:1234",
            "qemu-system:qmp=127.0.0.1:4444,gdb=127.0.0.1:1234",
        ] {
            let plan = TransportPlan::parse(spec, Some(semihosting)).unwrap();
            let (TransportPlan::Gdb {
                semihosting: on,
                map,
                ..
            }
            | TransportPlan::QemuSystem {
                semihosting: on,
                map,
                ..
            }) = plan
            else {
                panic!("expected a memory-read plan for {spec}");
            };
            assert!(on, "{spec}");
            assert_eq!(map.input_address, 0x1000);
            assert_eq!(map.ring_capacity, 0);
        }
        let ring = "input=0x1000,input_cap=64,ring=0x4000,write=0x5000,wrapped=0x5100,cap=32";
        let plan = TransportPlan::parse(
            "gdb:127.0.0.1:1234",
            Some(&format!("{ring},coverage=memory_buffer")),
        )
        .unwrap();
        assert!(matches!(
            plan,
            TransportPlan::Gdb {
                semihosting: false,
                ..
            }
        ));

        for (map, want) in [
            (
                format!("{ring},coverage=semihosting"),
                "coverage=semihosting reads the semihosting channel, not a ring: drop ring=",
            ),
            (
                "input=0x1000,input_cap=64,coverage=swo".to_owned(),
                "coverage=\"swo\": expected memory_buffer or semihosting",
            ),
            (
                "input=0x1000,input_cap=64".to_owned(),
                "missing required key \"cap\"",
            ),
        ] {
            let error = TransportPlan::parse("gdb:127.0.0.1:1234", Some(&map))
                .unwrap_err()
                .to_string();
            assert!(error.contains(want), "{map}: {error}");
        }
    }

    /// #386: `cmplog=` and `cmplog_cap=` name the firmware's comparison
    /// record, both or neither, with a capacity one read can take.
    #[test]
    fn the_coverage_map_names_a_cmplog_record() {
        let base = "input=0x1000,input_cap=64,ring=0x4000,write=0x5000,wrapped=0x5100,cap=64";
        let plan = TransportPlan::parse(
            "qemu-system:qmp=h:1,gdb=h:2",
            Some(&format!("{base},cmplog=0x20000258,cmplog_cap=32")),
        )
        .unwrap();
        assert_eq!(
            plan.cmplog(),
            Some(CmpLogRegion {
                address: 0x2000_0258,
                capacity: 32
            })
        );
        let plan = TransportPlan::parse("gdb:h:2", Some(base)).unwrap();
        assert_eq!(plan.cmplog(), None);
        for (extra, says) in [
            (",cmplog=0x2000", "cmplog= needs cmplog_cap=N"),
            (",cmplog_cap=8", "cmplog_cap= needs cmplog=ADDR"),
            (",cmplog=0x2000,cmplog_cap=0", "cmplog_cap=0 is outside"),
            (
                ",cmplog=0x2000,cmplog_cap=43691",
                "cmplog_cap=43691 is outside",
            ),
        ] {
            let error = TransportPlan::parse("gdb:h:2", Some(&format!("{base}{extra}")))
                .unwrap_err()
                .to_string();
            assert!(error.contains(says), "{extra}: {error}");
        }
    }

    #[test]
    fn qemu_system_rejects_invalid_fault_width() {
        let map_spec = "input=4096,input_cap=64,ring=16384,write=20480,wrapped=20736,cap=32";
        let error = TransportPlan::parse(
            "qemu-system:qmp=h:1,gdb=h:2,fault=0x300,fault_width=9",
            Some(map_spec),
        )
        .unwrap_err();
        // GuestFaultStatus::new rejects width 9 (>8); it surfaces as a Transport
        // spec error rather than being silently accepted.
        assert!(
            matches!(error, TransportSpecError::Transport(_)),
            "expected a transport validation error, got: {error}"
        );
    }

    #[test]
    fn the_qemu_system_spec_takes_a_persistent_reset_with_its_done_breakpoint() {
        let map_spec = "input=4096,input_cap=64,ring=16384,write=20480,wrapped=20736,cap=32";
        let reset_of = |spec: &str| match TransportPlan::parse(spec, Some(map_spec)) {
            Ok(TransportPlan::QemuSystem { reset, .. }) => Ok(reset),
            Ok(other) => panic!("expected QemuSystem, got {other:?}"),
            Err(error) => Err(error.to_string()),
        };
        assert_eq!(
            reset_of("qemu-system:qmp=h:1,gdb=h:2,done=0x1a8,reset=persistent"),
            Ok(FullSystemReset::Persistent)
        );
        assert_eq!(
            reset_of("qemu-system:qmp=h:1,gdb=h:2,reset=loadvm"),
            Ok(FullSystemReset::Loadvm)
        );
        // The guest parks at the completion breakpoint between inputs.
        let error = reset_of("qemu-system:qmp=h:1,gdb=h:2,reset=persistent").unwrap_err();
        assert!(error.contains("reset=persistent needs done="), "{error}");
        let error = reset_of("qemu-system:qmp=h:1,gdb=h:2,done=0x1a8,reset=quick").unwrap_err();
        assert!(
            error.contains("expected loadvm, persistent or fast"),
            "{error}"
        );
        // Renode's Load is the only reset it has.
        let error = TransportPlan::parse(
            "renode:monitor=h:1,gdb=h:2,done=0x1a8,reset=persistent",
            Some(RENODE_MAP),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("unknown key \"reset\""), "{error}");
        assert_eq!(
            backend_and_reset("qemu-system:qmp=h:1,gdb=h:2,done=0x1a8, reset=persistent"),
            (
                "qemu-system",
                "guest persistent loop; qmp loadvm before the first input and after a crash, \
                 hang or inconclusive run"
            )
        );
        assert_eq!(
            backend_and_reset("qemu-system:qmp=h:1,gdb=h:2,reset=loadvm"),
            ("qemu-system", "qmp savevm/loadvm snapshot")
        );
    }

    /// #347: `reset=fast` takes the dirty-page log the QEMU plugin writes,
    /// and only it does.
    #[test]
    fn the_qemu_system_spec_takes_a_fast_reset_with_its_dirty_page_log() {
        let map_spec = "input=4096,input_cap=64,ring=16384,write=20480,wrapped=20736,cap=32";
        let parse = |spec: &str| TransportPlan::parse(spec, Some(map_spec));
        let plan =
            parse("qemu-system:qmp=h:1,gdb=h:2,reset=fast,dirty_log=/run/dirty.log").unwrap();
        let TransportPlan::QemuSystem {
            reset, dirty_log, ..
        } = &plan
        else {
            panic!("expected QemuSystem, got {plan:?}");
        };
        assert_eq!(*reset, FullSystemReset::Fast);
        assert_eq!(dirty_log.as_deref(), Some(Path::new("/run/dirty.log")));
        assert_eq!(plan.dirty_log(), Some(Path::new("/run/dirty.log")));

        let error = parse("qemu-system:qmp=h:1,gdb=h:2,reset=fast")
            .unwrap_err()
            .to_string();
        assert!(error.contains("reset=fast needs dirty_log=PATH"), "{error}");
        let error = parse("qemu-system:qmp=h:1,gdb=h:2,dirty_log=/run/dirty.log")
            .unwrap_err()
            .to_string();
        assert!(error.contains("give reset=fast with it"), "{error}");
        // Renode keeps its own Load.
        let error = TransportPlan::parse(
            "renode:monitor=h:1,gdb=h:2,dirty_log=/run/dirty.log",
            Some(RENODE_MAP),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("unknown key \"dirty_log\""), "{error}");

        let (backend, reset) =
            backend_and_reset("qemu-system:qmp=h:1,gdb=h:2,reset=fast,dirty_log=/run/d.log");
        assert_eq!(backend, "qemu-system");
        assert!(reset.starts_with("dirty-page fast snapshot"), "{reset}");

        // A replay restores with loadvm, so it needs no plugin in QEMU.
        let replay = plan.replay_from_baseline();
        let TransportPlan::QemuSystem {
            reset, dirty_log, ..
        } = &replay
        else {
            panic!("expected QemuSystem, got {replay:?}");
        };
        assert_eq!((*reset, dirty_log), (FullSystemReset::Loadvm, &None));
        assert_eq!(replay.dirty_log(), None);
    }

    /// #347: before anything connects, a `reset=fast` run with no plugin log
    /// gets the plugin built and the `-plugin` argument to start QEMU with; a
    /// profile that does not allow the plugin is refused first.
    #[test]
    fn a_fast_reset_without_the_plugins_log_builds_the_plugin_and_says_how_to_load_it() {
        let work = crate::test_support::TestDir::new("fast-preflight");
        let log = work.join("dirty.log");
        let map_spec = "input=4096,input_cap=64,ring=16384,write=20480,wrapped=20736,cap=32";
        let plan = TransportPlan::parse(
            &format!(
                "qemu-system:qmp=h:1,gdb=h:2,reset=fast,dirty_log={}",
                log.display()
            ),
            Some(map_spec),
        )
        .unwrap();

        let refused =
            fast_snapshot_preflight(&plan, &work, config::Profile::StrictPermissive).unwrap_err();
        assert!(refused.contains("strict-permissive"), "{refused}");
        assert!(
            !work.join("qemu-plugin").exists(),
            "nothing is built when refused"
        );

        let message =
            fast_snapshot_preflight(&plan, &work, config::Profile::ExternalTools).unwrap_err();
        let library = work.join("qemu-plugin").join("libbhf_qemu_dirty_pages.so");
        if cfg!(unix) && which::which("cc").is_ok() && std::env::var_os("CC").is_none() {
            assert!(library.is_file(), "{message}");
            assert!(
                message.contains(&format!(
                    "-plugin {},log={}",
                    library.display(),
                    log.display()
                )),
                "{message}"
            );
        } else {
            assert!(message.contains("dirty-page log"), "{message}");
        }
        if !cfg!(unix) {
            assert!(message.contains("Linux or macOS host only"), "{message}");
            assert!(!library.exists(), "{message}");
        }

        // With the plugin's log there, the run goes on.
        target_transport::testsupport::DirtyLogFile::create(&log, 8, 16).unwrap();
        assert_eq!(
            fast_snapshot_preflight(&plan, &work, config::Profile::ExternalTools),
            Ok(())
        );
        // A plan that is not reset=fast has nothing to check.
        let loadvm = TransportPlan::parse("qemu-system:qmp=h:1,gdb=h:2", Some(map_spec)).unwrap();
        assert_eq!(
            fast_snapshot_preflight(&loadvm, &work, config::Profile::StrictPermissive),
            Ok(())
        );
    }

    /// #347: `--workers` specs that resolve to one dirty-page log are
    /// refused, however the path is spelled; a log per worker is not.
    #[test]
    fn workers_that_would_share_a_dirty_page_log_are_refused() {
        let dir = crate::test_support::TestDir::new("fast-workers");
        let map_spec = "input=4096,input_cap=64,ring=16384,write=20480,wrapped=20736,cap=32";
        let plans = |template: &str| {
            (0..2)
                .map(|worker| {
                    TransportPlan::parse(&resolve_worker_spec(template, worker), Some(map_spec))
                        .unwrap()
                })
                .collect::<Vec<_>>()
        };
        let shared = format!(
            "qemu-system:qmp=127.0.0.1:{{4444+worker}},gdb=127.0.0.1:{{3333+worker}},reset=fast,\
             dirty_log={}",
            dir.join("dirty.log").display()
        );
        let error = refuse_shared_dirty_logs(&plans(&shared)).unwrap_err();
        assert!(
            error.contains("workers 0 and 1") && error.contains("{worker}"),
            "{error}"
        );

        // One file under two spellings, there or not yet.
        for exists in [false, true] {
            if exists {
                std::fs::write(dir.join("dirty.log"), b"").unwrap();
            }
            let spelled = [
                dir.join("dirty.log"),
                dir.join(".").join("sub").join("..").join("dirty.log"),
            ];
            std::fs::create_dir_all(dir.join("sub")).unwrap();
            let two: Vec<TransportPlan> = spelled
                .iter()
                .enumerate()
                .map(|(worker, log)| {
                    TransportPlan::parse(
                        &format!(
                            "qemu-system:qmp=127.0.0.1:{},gdb=127.0.0.1:{},reset=fast,dirty_log={}",
                            4444 + worker,
                            3333 + worker,
                            log.display()
                        ),
                        Some(map_spec),
                    )
                    .unwrap()
                })
                .collect();
            assert!(
                refuse_shared_dirty_logs(&two).is_err(),
                "exists={exists}: {spelled:?}"
            );
        }

        let own = format!(
            "qemu-system:qmp=127.0.0.1:{{4444+worker}},gdb=127.0.0.1:{{3333+worker}},reset=fast,\
             dirty_log={}",
            dir.join("dirty-{worker}.log").display()
        );
        assert_eq!(refuse_shared_dirty_logs(&plans(&own)), Ok(()));
        // Plans without a fast reset have no log to share.
        let loadvm = "qemu-system:qmp=127.0.0.1:{4444+worker},gdb=127.0.0.1:{3333+worker}";
        assert_eq!(refuse_shared_dirty_logs(&plans(loadvm)), Ok(()));
    }

    /// #347: a `reset=fast` spec builds a transport that, against a mock
    /// monitor and gdb server whose guest logs its stores, learns the pages
    /// with one loadvm and then resets with system_reset alone.
    #[test]
    fn a_fast_qemu_system_spec_builds_a_transport_that_resets_without_a_loadvm() {
        use std::net::TcpListener;
        use target_transport::testsupport::{
            encode_event_stream, simulate_ring, DirtyLogFile, MockGdbStub, MockQmpServer,
        };
        let work = crate::test_support::TestDir::new("fast-transport");
        let log_path = work.join("dirty.log");
        let log = DirtyLogFile::create(&log_path, 8, 64).unwrap();
        let qmp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let gdb_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let qmp_port = qmp_listener.local_addr().unwrap().port();
        let gdb_port = gdb_listener.local_addr().unwrap().port();
        let qmp_log = Arc::new(Mutex::new(Vec::new()));
        let gdb_log = Arc::new(Mutex::new(Vec::new()));
        {
            let qmp_log = Arc::clone(&qmp_log);
            thread::spawn(move || {
                let (stream, _) = qmp_listener.accept().unwrap();
                let _ = MockQmpServer::new(stream, qmp_log).serve();
            });
        }
        {
            let gdb_log = Arc::clone(&gdb_log);
            thread::spawn(move || {
                let (stream, _) = gdb_listener.accept().unwrap();
                stream.set_nodelay(true).unwrap();
                let events: Vec<event_log::Event> = [0x10, 0x11]
                    .into_iter()
                    .map(|id| event_log::Event::Crumb { id })
                    .collect();
                let (image, write, wrapped) = simulate_ring(&encode_event_stream(&events), 64);
                let mut words = vec![0_u8; 512];
                words[..4].copy_from_slice(&write.to_le_bytes());
                words[0x100] = u8::from(wrapped);
                let mut ring = image;
                ring.resize(256, 0);
                let _ = MockGdbStub::new(stream, gdb_log)
                    .with_region(0x1000, vec![0; 256])
                    .with_region(0x4000, ring)
                    .with_region(0x5000, words)
                    .with_run_write(0x5000, write.to_le_bytes().to_vec())
                    .with_run_write(0x5100, vec![u8::from(wrapped)])
                    .with_dirty_log(log)
                    .serve();
            });
        }
        let spec = format!(
            "qemu-system:qmp=127.0.0.1:{qmp_port},gdb=127.0.0.1:{gdb_port},reset=fast,\
             dirty_log={}",
            log_path.display()
        );
        let plan = TransportPlan::parse(&spec, Some(PERSISTENT_MAP)).unwrap();
        let transport = plan.into_transport(Some(Duration::from_secs(10))).unwrap();
        let mut session = transport.arm().unwrap();
        for input in [b"abc", b"def", b"ghi"] {
            let outcome = session.run_input(input).unwrap();
            assert_eq!(outcome.exit, ExitKind::Ok, "{outcome:?}");
            assert_eq!(outcome.coverage_edges, [0x10, 0x11]);
        }
        let count = |entry: &str| {
            qmp_log
                .lock()
                .unwrap()
                .iter()
                .filter(|line| line.as_str() == entry)
                .count()
        };
        assert_eq!(
            count("hmp:loadvm bhf-baseline"),
            1,
            "{:?}",
            qmp_log.lock().unwrap()
        );
        assert_eq!(count("system_reset"), 1, "arm's: the fast ones go over gdb");
        let gdb = gdb_log.lock().unwrap();
        assert!(gdb.iter().any(|packet| packet == "Qqemu.PhyMemMode:1"));
        // `monitor system_reset` before the third input.
        let monitor_reset = "qRcmd,73797374656d5f7265736574";
        assert_eq!(
            gdb.iter().filter(|packet| *packet == monitor_reset).count(),
            1
        );
    }

    /// A mock QMP monitor and gdb server on loopback for a persistent
    /// `qemu-system:` spec: a guest that writes edges 0x10 and 0x11 on every
    /// run, its successive `c`s answered by `stops` (an empty one never
    /// stops). Returns the spec and the two logs.
    #[allow(clippy::type_complexity)]
    fn persistent_qemu_mocks(
        stops: Vec<Vec<u8>>,
    ) -> (String, Arc<Mutex<Vec<String>>>, Arc<Mutex<Vec<String>>>) {
        use std::net::TcpListener;
        use target_transport::testsupport::{
            encode_event_stream, simulate_ring, MockGdbStub, MockQmpServer,
        };
        let qmp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let gdb_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let qmp_port = qmp_listener.local_addr().unwrap().port();
        let gdb_port = gdb_listener.local_addr().unwrap().port();
        let qmp_log = Arc::new(Mutex::new(Vec::new()));
        let gdb_log = Arc::new(Mutex::new(Vec::new()));
        {
            let log = Arc::clone(&qmp_log);
            thread::spawn(move || {
                let (stream, _) = qmp_listener.accept().unwrap();
                let _ = MockQmpServer::new(stream, log).serve();
            });
        }
        {
            let log = Arc::clone(&gdb_log);
            thread::spawn(move || {
                let (stream, _) = gdb_listener.accept().unwrap();
                stream.set_nodelay(true).unwrap();
                let events: Vec<event_log::Event> = [0x10, 0x11]
                    .into_iter()
                    .map(|id| event_log::Event::Crumb { id })
                    .collect();
                let (image, write, wrapped) = simulate_ring(&encode_event_stream(&events), 64);
                let _ = MockGdbStub::new(stream, log)
                    .with_stop_sequence(stops)
                    .with_region(0x1000, vec![0; 64])
                    .with_region(0x4000, image)
                    .with_region(0x5000, write.to_le_bytes().to_vec())
                    .with_region(0x5100, vec![u8::from(wrapped)])
                    .with_run_write(0x5000, write.to_le_bytes().to_vec())
                    .with_run_write(0x5100, vec![u8::from(wrapped)])
                    .serve();
            });
        }
        let spec = format!(
            "qemu-system:qmp=127.0.0.1:{qmp_port},gdb=127.0.0.1:{gdb_port},done=0x1a8,\
             reset=persistent"
        );
        (spec, qmp_log, gdb_log)
    }

    const PERSISTENT_MAP: &str =
        "input=0x1000,input_cap=64,ring=0x4000,write=0x5000,wrapped=0x5100,cap=64";

    /// A persistent `qemu-system:` spec builds a transport that, against a
    /// mock monitor and gdb server on loopback, restores the snapshot once
    /// for three clean inputs.
    #[test]
    fn a_persistent_qemu_system_spec_builds_a_transport_that_restores_once() {
        let (spec, qmp_log, gdb_log) = persistent_qemu_mocks(Vec::new());
        let plan = TransportPlan::parse(&spec, Some(PERSISTENT_MAP)).unwrap();
        let transport = plan.into_transport(Some(Duration::from_secs(10))).unwrap();
        let mut session = transport.arm().unwrap();
        for input in [b"abc", b"def", b"ghi"] {
            let outcome = session.run_input(input).unwrap();
            assert_eq!(outcome.exit, ExitKind::Ok, "{outcome:?}");
            assert_eq!(outcome.coverage_edges, [0x10, 0x11]);
        }
        let loadvms = qmp_log
            .lock()
            .unwrap()
            .iter()
            .filter(|line| line.starts_with("hmp:loadvm"))
            .count();
        assert_eq!(loadvms, 1, "{:?}", qmp_log.lock().unwrap());
        let steps = gdb_log.lock().unwrap().iter().filter(|p| *p == "s").count();
        assert_eq!(steps, 2, "two continuations");
    }

    /// #346: a continuation that hangs before the loop is proven is run again
    /// from the snapshot, where the input is clean and fast. The deadline
    /// oracle judges that run, not the discarded hang plus the restore, so a
    /// `--deadline` under the execution deadline makes no false finding.
    #[test]
    fn a_hung_continuation_rerun_from_the_snapshot_is_no_deadline_finding() {
        let (spec, qmp_log, _gdb_log) = persistent_qemu_mocks(vec![
            b"S05".to_vec(),
            Vec::new(), // the continuation never comes back to done
            b"S05".to_vec(),
        ]);
        let plan = TransportPlan::parse(&spec, Some(PERSISTENT_MAP)).unwrap();
        let exec_deadline = Duration::from_millis(400);
        let transport = plan.into_transport(Some(exec_deadline)).unwrap();
        let work_dir = tmp_work_dir("persistent-deadline");
        let mut config = config(
            work_dir.to_path_buf(),
            vec![b"a".to_vec(), b"b".to_vec()],
            2,
        );
        config.spec = spec;
        config.per_input_timeout = Some(exec_deadline);
        config.deadline = Some(Duration::from_millis(150));

        let summary = run_transport_campaign(transport.as_ref(), &config).unwrap();
        assert_eq!(summary.executions, 2, "{summary:?}");
        assert!(summary.findings.is_empty(), "{summary:?}");
        assert_eq!(summary.crashes, 0, "{summary:?}");
        let loadvms = qmp_log
            .lock()
            .unwrap()
            .iter()
            .filter(|line| line.starts_with("hmp:loadvm"))
            .count();
        assert_eq!(
            loadvms, 2,
            "the hung continuation was run from the snapshot"
        );
    }

    #[test]
    fn replay_runs_a_persistent_spec_with_a_loadvm_per_input() {
        let map_spec = "input=4096,input_cap=64,ring=16384,write=20480,wrapped=20736,cap=32";
        let plan = TransportPlan::parse(
            "qemu-system:qmp=h:1,gdb=h:2,done=0x1a8,reset=persistent",
            Some(map_spec),
        )
        .unwrap()
        .replay_from_baseline();
        let TransportPlan::QemuSystem { reset, .. } = plan else {
            panic!("expected QemuSystem, got {plan:?}");
        };
        assert_eq!(reset, FullSystemReset::Loadvm);
    }

    #[test]
    fn qemu_system_into_transport_wires_completion_contract() {
        // The whole CLI parse -> build path accepts the completion contract and
        // produces a transport (the breakpoint/fault-status behavior itself is
        // proven end-to-end by the live RV-3 Cortex-M test).
        let map_spec = "input=4096,input_cap=64,ring=16384,write=20480,wrapped=20736,cap=32";
        let plan = TransportPlan::parse(
            "qemu-system:qmp=127.0.0.1:1,gdb=127.0.0.1:2,done=0x1a8,fault=0x20000100",
            Some(map_spec),
        )
        .unwrap();
        assert!(plan.into_transport(None).is_ok());
    }

    #[test]
    fn empty_spec_is_a_descriptive_error() {
        let error = TransportPlan::parse("", None).unwrap_err();
        assert!(matches!(error, TransportSpecError::Empty), "{error}");
        assert!(error.to_string().contains("empty"));
    }

    #[test]
    fn whitespace_only_spec_is_empty_error() {
        assert!(matches!(
            TransportPlan::parse("   ", None).unwrap_err(),
            TransportSpecError::Empty
        ));
    }

    #[test]
    fn unknown_agent_channel_is_descriptive() {
        let error = TransportPlan::parse("agent:bogus", None).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("unknown agent channel") && message.contains("bogus"),
            "message: {message}"
        );
    }

    #[test]
    fn unknown_backend_is_descriptive() {
        let error = TransportPlan::parse("carrierpigeon:host:1", None).unwrap_err();
        match error {
            TransportSpecError::UnknownBackend { backend } => assert_eq!(backend, "carrierpigeon"),
            other => panic!("expected UnknownBackend, got {other}"),
        }
    }

    #[test]
    fn agent_tcp_missing_port_is_descriptive() {
        let error = TransportPlan::parse("agent:tcp:localhost", None).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("HOST:PORT"), "message: {message}");
    }

    #[test]
    fn agent_tcp_zero_port_is_rejected() {
        let error = TransportPlan::parse("agent:tcp:localhost:0", None).unwrap_err();
        assert!(error.to_string().contains("port"), "{error}");
    }

    #[test]
    fn agent_serial_empty_path_is_descriptive() {
        let error = TransportPlan::parse("agent:serial:", None).unwrap_err();
        assert!(
            error.to_string().contains("device path is empty"),
            "{error}"
        );
    }

    #[test]
    fn gdb_without_coverage_map_is_descriptive() {
        let error = TransportPlan::parse("gdb:127.0.0.1:1234", None).unwrap_err();
        match error {
            TransportSpecError::MissingCoverageMap { backend } => assert_eq!(backend, "gdb"),
            other => panic!("expected MissingCoverageMap, got {other}"),
        }
    }

    #[test]
    fn agent_with_coverage_map_is_rejected() {
        let error = TransportPlan::parse(
            "agent:tcp:h:1",
            Some("input=0,input_cap=8,ring=0,write=0,wrapped=0,cap=1"),
        )
        .unwrap_err();
        assert!(
            matches!(error, TransportSpecError::UnexpectedCoverageMap),
            "{error}"
        );
    }

    #[test]
    fn coverage_map_bad_integer_is_descriptive() {
        let error = TransportPlan::parse(
            "gdb:h:1",
            Some("input=notanumber,ring=0,write=0,wrapped=0,cap=1"),
        )
        .unwrap_err();
        match error {
            TransportSpecError::Field { field, value } => {
                assert_eq!(field, "input");
                assert_eq!(value, "notanumber");
            }
            other => panic!("expected Field error, got {other}"),
        }
    }

    #[test]
    fn coverage_map_missing_key_is_descriptive() {
        // No `cap`.
        let error =
            TransportPlan::parse("gdb:h:1", Some("input=0,ring=0,write=0,wrapped=0")).unwrap_err();
        match error {
            TransportSpecError::MissingMapKey { key } => assert_eq!(key, "cap"),
            other => panic!("expected MissingMapKey, got {other}"),
        }
    }

    #[test]
    fn coverage_map_unknown_key_is_descriptive() {
        let error = TransportPlan::parse(
            "gdb:h:1",
            Some("input=0,ring=0,write=0,wrapped=0,cap=1,bogus=2"),
        )
        .unwrap_err();
        match error {
            TransportSpecError::UnknownMapKey { key } => assert_eq!(key, "bogus"),
            other => panic!("expected UnknownMapKey, got {other}"),
        }
    }

    // --- renode: (#340) -------------------------------------------------------

    const RENODE_MAP: &str =
        "input=0x1000,input_cap=64,ring=0x4000,write=0x5000,wrapped=0x5100,cap=64";

    #[test]
    fn parses_a_renode_spec_with_its_defaults() {
        let plan = TransportPlan::parse(
            "renode:monitor=127.0.0.1:1234,gdb=127.0.0.1:3333",
            Some(RENODE_MAP),
        )
        .unwrap();
        let TransportPlan::Renode {
            monitor_host,
            monitor_port,
            gdb_host,
            gdb_port,
            snapshot,
            map,
            harness_done,
            ..
        } = &plan
        else {
            panic!("expected Renode, got {plan:?}");
        };
        assert_eq!((monitor_host.as_str(), *monitor_port), ("127.0.0.1", 1234));
        assert_eq!((gdb_host.as_str(), *gdb_port), ("127.0.0.1", 3333));
        assert_eq!(snapshot, target_transport::renode::DEFAULT_SNAPSHOT_PATH);
        assert_eq!(map.ring_address, 0x4000);
        assert_eq!(*harness_done, None);
        assert_eq!(
            plan.label(),
            "renode:monitor=127.0.0.1:1234,gdb=127.0.0.1:3333"
        );
        assert_eq!(plan.input_contract().map(|c| c.capacity), Some(64));
        assert_eq!(
            backend_and_reset("renode:monitor=h:1,gdb=h:2"),
            ("renode", "renode Save/Load snapshot")
        );
    }

    #[test]
    fn a_renode_spec_takes_the_snapshot_path_and_the_completion_contract() {
        let plan = TransportPlan::parse(
            "renode:monitor=h:1,gdb=h:2,snapshot=/tmp/base.save,done=0x189,fault=0x20000100,\
             task_id=0x20000200,firmware=fw.elf,cycles=dwt,cpu_hz=64000000",
            Some(RENODE_MAP),
        )
        .unwrap();
        let TransportPlan::Renode {
            snapshot,
            harness_done,
            fault_status,
            task_id,
            ..
        } = &plan
        else {
            panic!("expected Renode, got {plan:?}");
        };
        assert_eq!(snapshot, "/tmp/base.save");
        assert_eq!(*harness_done, Some((0x188, 2)), "the Thumb bit is cleared");
        assert_eq!(fault_status.as_ref().map(|f| f.address), Some(0x2000_0100));
        assert_eq!(*task_id, Some(0x2000_0200));
        assert_eq!(plan.firmware(), Some(Path::new("fw.elf")));
        assert!(plan.cycle_counter().is_some());
        assert_eq!(plan.notes().len(), 1, "{:?}", plan.notes());
    }

    #[test]
    fn a_renode_spec_without_its_endpoints_or_map_is_refused() {
        let no_monitor = TransportPlan::parse("renode:gdb=h:2", Some(RENODE_MAP)).unwrap_err();
        assert!(
            no_monitor.to_string().contains("monitor=HOST:PORT"),
            "{no_monitor}"
        );
        let no_gdb = TransportPlan::parse("renode:monitor=h:1", Some(RENODE_MAP)).unwrap_err();
        assert!(no_gdb.to_string().contains("gdb=HOST:PORT"), "{no_gdb}");
        let no_map = TransportPlan::parse("renode:monitor=h:1,gdb=h:2", None).unwrap_err();
        assert!(
            matches!(
                no_map,
                TransportSpecError::MissingCoverageMap { backend: "renode" }
            ),
            "{no_map}"
        );
        let unknown = TransportPlan::parse("renode:monitor=h:1,gdb=h:2,qmp=h:3", Some(RENODE_MAP))
            .unwrap_err();
        assert!(
            unknown.to_string().contains("allowed: monitor, gdb"),
            "{unknown}"
        );
    }

    #[test]
    fn a_renode_snapshot_path_that_could_split_the_monitor_command_is_refused_at_build() {
        let plan = TransportPlan::parse(
            "renode:monitor=h:1,gdb=h:2,snapshot=a;quit",
            Some(RENODE_MAP),
        )
        .unwrap();
        let Err(error) = plan.into_transport(None) else {
            panic!("an unsafe snapshot path must be refused");
        };
        assert!(
            error.to_string().contains("disallowed character"),
            "{error}"
        );
    }

    #[test]
    fn the_unknown_backend_error_lists_renode() {
        let error = TransportPlan::parse("bogus:1", None).unwrap_err();
        assert!(error.to_string().contains("renode"), "{error}");
    }

    /// The parsed spec drives a whole Renode session over real sockets: the
    /// mock monitor and a mock gdb server listen on loopback ports, and the
    /// transport the CLI builds saves, loads, restarts the gdb server and
    /// reads the run's coverage.
    #[test]
    fn a_renode_spec_builds_a_transport_that_runs_over_tcp() {
        use std::net::TcpListener;
        use target_transport::testsupport::{
            encode_event_stream, simulate_ring, MockGdbStub, MockRenodeMonitor,
        };

        let monitor_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let gdb_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let monitor_port = monitor_listener.local_addr().unwrap().port();
        let gdb_port = gdb_listener.local_addr().unwrap().port();
        let monitor_log = Arc::new(Mutex::new(Vec::new()));
        let gdb_server = Arc::new(Mutex::new(None));
        {
            let log = Arc::clone(&monitor_log);
            let server = Arc::clone(&gdb_server);
            thread::spawn(move || {
                let (stream, _) = monitor_listener.accept().unwrap();
                let _ = MockRenodeMonitor::new(stream, log, server).serve();
            });
        }
        thread::spawn(move || {
            for stream in gdb_listener.incoming() {
                let Ok(stream) = stream else { return };
                let events: Vec<event_log::Event> = [0x10, 0x11]
                    .into_iter()
                    .map(|id| event_log::Event::Crumb { id })
                    .collect();
                let (image, write, wrapped) = simulate_ring(&encode_event_stream(&events), 64);
                let stub = MockGdbStub::new(stream, Arc::new(Mutex::new(Vec::new())))
                    .with_unsolicited_stops()
                    .with_stop_reply(b"T05swbreak:;".to_vec())
                    .with_region(0x1000, vec![0; 64])
                    .with_region(0x4000, image)
                    .with_region(0x5000, write.to_le_bytes().to_vec())
                    .with_region(0x5100, vec![u8::from(wrapped)]);
                thread::spawn(move || {
                    let _ = stub.serve();
                });
            }
        });

        let plan = TransportPlan::parse(
            &format!("renode:monitor=127.0.0.1:{monitor_port},gdb=127.0.0.1:{gdb_port},done=0x1a8"),
            Some(RENODE_MAP),
        )
        .unwrap();
        let transport = plan.into_transport(Some(Duration::from_secs(10))).unwrap();
        let mut session = transport.arm().unwrap();
        let outcome = session.run_input(b"abc").unwrap();
        assert_eq!(outcome.exit, ExitKind::Ok, "{outcome:?}");
        assert_eq!(outcome.coverage_edges, [0x10, 0x11]);
        let log = monitor_log.lock().unwrap();
        assert!(
            log.iter().any(|line| line == "Save @bhf-baseline.save")
                && log.iter().any(|line| line == "Load @bhf-baseline.save")
                && log
                    .iter()
                    .any(|line| *line == format!("machine StartGdbServer {gdb_port}")),
            "{log:?}"
        );
    }

    #[test]
    fn qemu_missing_qmp_key_is_descriptive() {
        let error = TransportPlan::parse(
            "qemu-system:gdb=h:2",
            Some("input=0,input_cap=8,ring=0,write=0,wrapped=0,cap=1"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("qmp"), "{error}");
    }

    // --- transport builder tests (pure; no live connection) ------------------

    #[test]
    fn agent_tcp_builds_a_transport() {
        // Construction is pure — the socket is only dialed on arm(), which we
        // never call here, so this needs no listener.
        let plan = TransportPlan::parse("agent:tcp:127.0.0.1:1", None).unwrap();
        assert!(plan.into_transport(None).is_ok());
    }

    #[test]
    fn qemu_system_rejects_unsafe_snapshot_tag_at_build_time() {
        // A snapshot tag with a space would be spliced into an HMP command line;
        // FullSystemTransport::new must reject it, surfacing as a Transport error.
        let map_spec = "input=0,input_cap=8,ring=0,write=0,wrapped=0,cap=1";
        let plan = TransportPlan::parse(
            "qemu-system:qmp=h:1,gdb=h:2,snapshot=bad tag",
            Some(map_spec),
        )
        .unwrap();
        let error = match plan.into_transport(None) {
            Ok(_) => panic!("an unsafe snapshot tag must be rejected"),
            Err(error) => error,
        };
        assert!(
            matches!(error, TransportSpecError::Transport(_)),
            "expected a Transport error, got {error}"
        );
        assert!(error.to_string().contains("snapshot tag"), "{error}");
    }

    /// #316: a spec names each worker's target with `{worker}` or
    /// `{BASE+worker}`; one without either is no per-worker spec.
    #[test]
    fn a_worker_spec_template_resolves_per_worker() {
        assert_eq!(
            resolve_worker_spec("agent:tcp:127.0.0.1:{9000+worker}", 2),
            "agent:tcp:127.0.0.1:9002"
        );
        assert_eq!(
            resolve_worker_spec("agent:serial:/dev/ttyUSB{worker},baud=115200", 1),
            "agent:serial:/dev/ttyUSB1,baud=115200"
        );
        assert!(has_worker_template("gdb:127.0.0.1:{3333+worker}"));
        assert!(!has_worker_template("agent:tcp:127.0.0.1:9000"));
        assert_eq!(
            resolve_worker_spec("x:{other}:{worker", 3),
            "x:{other}:{worker"
        );
    }

    /// A target whose edges are its input's first byte and which faults on an
    /// input holding `!`; it logs which worker ran each input.
    /// The inputs a target ran, with the worker that ran each.
    type RunLog = Arc<Mutex<Vec<(usize, Vec<u8>)>>>;

    #[derive(Clone)]
    struct LoggingTarget {
        worker: usize,
        log: RunLog,
        /// The workers that have run a mutated input: each one's first waits
        /// a bounded time for the others, so a loaded host's scheduler cannot
        /// let two workers spend the whole cap before the third starts. (A
        /// seed's run does not wait: a worker with no seed of its own waits
        /// for the seeds in flight.)
        started: Arc<(Mutex<std::collections::BTreeSet<usize>>, std::sync::Condvar)>,
        workers: usize,
    }

    impl TargetTransport for LoggingTarget {
        fn arm(&self) -> target_transport::Result<Box<dyn TargetSession>> {
            Ok(Box::new(self.clone()))
        }
    }

    impl TargetSession for LoggingTarget {
        fn run_input(&mut self, input: &[u8]) -> target_transport::Result<RunOutcome> {
            let (started, all) = &*self.started;
            let mut seen = started.lock().unwrap();
            let seed = input == b"a" || input == b"b";
            if !seed && seen.insert(self.worker) {
                all.notify_all();
                let _ = all
                    .wait_timeout_while(seen, std::time::Duration::from_secs(10), |seen| {
                        seen.len() < self.workers
                    })
                    .unwrap();
            } else {
                drop(seen);
            }
            self.log.lock().unwrap().push((self.worker, input.to_vec()));
            let faulted = input.contains(&b'!');
            Ok(RunOutcome {
                exit: if faulted {
                    ExitKind::Crash
                } else {
                    ExitKind::Ok
                },
                coverage_edges: vec![1, 100 + u32::from(input.first().copied().unwrap_or(0))],
                fault: faulted.then(|| target_transport::Fault {
                    kind: target_transport::FaultKind::MemoryProtection,
                    address: Some(0x2000_0100),
                    detail: "write past the frame".to_owned(),
                }),
                stdout: Vec::new(),
                coverage_incomplete: None,
                inconclusive: None,
                target: Default::default(),
            })
        }
    }

    /// #316: N workers, one transport each, share one campaign: every one of
    /// them runs inputs, together they run the campaign's iteration cap and
    /// no more, and a fault more than one reaches is one finding, replayed on
    /// the transport of the worker that found it.
    #[test]
    fn workers_share_one_campaign_over_their_own_transports() {
        let work = tmp_work_dir("workers");
        let mut cfg = config(work.to_path_buf(), vec![b"a".to_vec(), b"b".to_vec()], 600);
        cfg.worker_specs = (0..3)
            .map(|worker| format!("agent:tcp:127.0.0.1:{}", 9000 + worker))
            .collect();
        cfg.dictionary = vec![b"!".to_vec()];
        let log = Arc::new(Mutex::new(Vec::new()));
        let started = Arc::new((
            Mutex::new(std::collections::BTreeSet::new()),
            std::sync::Condvar::new(),
        ));
        let make = |worker: usize| -> Result<Box<dyn TargetTransport>, TransportFuzzError> {
            Ok(Box::new(LoggingTarget {
                worker,
                log: Arc::clone(&log),
                started: Arc::clone(&started),
                workers: 3,
            }))
        };
        let summary = run_transport_campaign_workers(&make, 3, &cfg).unwrap();
        assert_eq!(summary.workers, 3);
        assert_eq!(summary.executions, 600, "{summary:?}");
        let log = log.lock().unwrap();
        assert_eq!(log.len(), 600, "no worker runs past the cap");
        for worker in 0..3 {
            assert!(
                log.iter().any(|(who, _)| *who == worker),
                "worker {worker} ran no input"
            );
        }
        // The seeds ran once each, between them.
        let seed_runs = log
            .iter()
            .filter(|(_, input)| input.as_slice() == b"a" || input.as_slice() == b"b")
            .count();
        assert!(seed_runs >= 2, "{seed_runs}");
        let faulting = log
            .iter()
            .filter(|(_, input)| input.contains(&b'!'))
            .count();
        assert!(
            faulting > 1,
            "more than one input reached the fault: {faulting}"
        );
        assert_eq!(
            summary.findings.len(),
            1,
            "one fault, one finding: {summary:?}"
        );
        let profile: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                work.join("results/findings")
                    .join(&summary.findings[0])
                    .join(TRANSPORT_PROFILE_FILE),
            )
            .unwrap(),
        )
        .unwrap();
        // On the transport of a worker that ran a faulting input.
        let found_on: Vec<String> = log
            .iter()
            .filter(|(_, input)| input.contains(&b'!'))
            .map(|(who, _)| format!("agent:tcp:127.0.0.1:{}", 9000 + who))
            .collect();
        assert!(
            found_on.iter().any(|spec| profile["spec"] == spec.as_str()),
            "replayed where it was found: {profile:#}"
        );
    }

    // --- end-to-end loop tests against the mock agent ------------------------

    /// Build an [`AgentTransport`] over an in-memory `duplex()` whose target end
    /// is served by a `MockAgent` running the given script. Returns the transport
    /// and the shared `received` log of delivered inputs.
    #[allow(clippy::type_complexity)]
    fn mock_agent_transport(
        script: Vec<ScriptedResponse>,
    ) -> (Box<dyn TargetTransport>, Arc<Mutex<Vec<Vec<u8>>>>) {
        let received = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let received_for_factory = Arc::clone(&received);
        // arm() is called once; hand out the single host end via a slot.
        let (host_end, target_end) = duplex();
        let slot = Mutex::new(Some(host_end));
        let agent = MockAgent::new(target_end, script, received_for_factory);
        thread::spawn(move || {
            let _ = agent.serve();
        });
        let transport = AgentTransport::new(move || {
            slot.lock().unwrap().take().ok_or_else(|| {
                TransportError::Protocol("mock connect invoked more than once".to_owned())
            })
        });
        (Box::new(transport), received)
    }

    fn tmp_work_dir(tag: &str) -> crate::test_support::TestDir {
        crate::test_support::TestDir::new(&format!("transport-fuzz-{tag}"))
    }

    fn config(work_dir: PathBuf, seeds: Vec<Vec<u8>>, iterations: usize) -> TransportFuzzConfig {
        TransportFuzzConfig {
            work_dir,
            harness_id: "H-transport".to_owned(),
            transport_label: "mock-agent".to_owned(),
            seeds,
            iterations,
            time_budget: None,
            per_input_timeout: None,
            deadline: None,
            spec: "agent:tcp:127.0.0.1:65535".to_owned(),
            worker_specs: vec!["agent:tcp:127.0.0.1:65535".to_owned()],
            coverage_map: None,
            max_len: 4096,
            input_contract: None,
            firmware_identity: None,
            cycle_counter: None,
            rng_seed: 0x4756_4655_5a5a,
            stop_after_findings: None,
            mode: actionability::RunMode::Reporting,
            dictionary: Vec::new(),
            grammar: None,
            arg_layout: None,
        }
    }

    #[test]
    fn loop_folds_coverage_retains_new_edge_seed_and_writes_a_fault_finding() {
        // The mock serves responses positionally (one per delivered input), so
        // coverage is controlled by execution index regardless of mutated bytes:
        //   exec 0 (seed):     edges [10, 11]        -> baseline coverage
        //   exec 1 (mutation): edges [10, 11, 12]    -> NEW coverage, retained
        //   exec 2 (mutation): crash with a fault    -> a written finding
        let fault = Fault {
            kind: FaultKind::MemoryProtection,
            address: Some(0x2000_4000),
            detail: "MPU region 3".to_owned(),
        };
        let script = vec![
            ScriptedResponse::ok(vec![10, 11]),
            ScriptedResponse::ok(vec![10, 11, 12]),
            ScriptedResponse::crash(vec![10, 11, 12], fault),
        ];
        let (transport, received) = mock_agent_transport(script);

        let work_dir = tmp_work_dir("e2e");
        // 1 seed + 2 mutations == 3 scripted responses.
        let config = config(work_dir.to_path_buf(), vec![b"seed".to_vec()], 3);

        let summary = run_transport_campaign(transport.as_ref(), &config).unwrap();

        // (c) terminates on budget: exactly `iterations` executions, no more.
        assert_eq!(summary.executions, 3, "must stop at the iteration budget");

        // (a) coverage was folded across all three runs, and a new-edge input was
        // retained as a corpus seed.
        assert!(
            summary.coverage_blocks >= 3,
            "blocks 10,11,12 must all be folded: {summary:?}"
        );
        assert!(
            summary.coverage_edges >= 2,
            "edges 10->11 and 11->12 must be folded: {summary:?}"
        );
        assert_eq!(
            summary.corpus_new, 1,
            "exactly the new-edge mutation (exec 1) is retained: {summary:?}"
        );

        // (b) the scripted fault became a written finding on disk.
        assert_eq!(summary.crashes, 1, "one crash outcome seen");
        assert_eq!(
            summary.findings.len(),
            1,
            "one finding emitted: {summary:?}"
        );
        let finding_id = &summary.findings[0];
        let finding_json = work_dir
            .join("results")
            .join("findings")
            .join(finding_id)
            .join("finding.json");
        assert!(
            finding_json.exists(),
            "finding.json must be written to the work dir: {}",
            finding_json.display()
        );
        // It is classified through the HDF-2 seam: an MPU trap at a non-null
        // address maps to the BHF-210 memory-bounds family.
        let record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&finding_json).unwrap()).unwrap();
        assert_eq!(record["rule_id"], "BHF-210", "{record}");

        // All three inputs were actually delivered over the transport.
        assert_eq!(received.lock().unwrap().len(), 3);

        std::fs::remove_dir_all(&work_dir).ok();
    }

    #[test]
    fn loop_terminates_immediately_on_a_zero_time_budget() {
        // A zero wall-clock budget stops before any execution — the time-budget
        // branch of should_stop, exercised deterministically (no run_input call,
        // so the mock needs no script entries).
        let (transport, received) = mock_agent_transport(vec![]);
        let work_dir = tmp_work_dir("zero-budget");
        let mut config = config(work_dir.to_path_buf(), vec![b"seed".to_vec()], 1_000);
        config.time_budget = Some(Duration::from_secs(0));

        let summary = run_transport_campaign(transport.as_ref(), &config).unwrap();

        assert_eq!(summary.executions, 0, "zero-budget run does nothing");
        assert!(summary.findings.is_empty());
        assert!(received.lock().unwrap().is_empty());

        std::fs::remove_dir_all(&work_dir).ok();
    }

    #[test]
    fn classify_run_failure_distinguishes_timeout_lost_transport_and_other() {
        use std::io::{Error, ErrorKind};
        // A read timeout that ESCAPES the session is a control/setup timeout — a
        // genuine target-execution hang is surfaced by the session as an
        // ExitKind::Timeout outcome, never routed through here.
        for kind in [ErrorKind::WouldBlock, ErrorKind::TimedOut] {
            assert!(matches!(
                classify_run_failure(&TransportError::Io(Error::from(kind))),
                RunFailure::ControlTimeout
            ));
        }
        // ...a dropped link is a LostTransport...
        for kind in [
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::BrokenPipe,
            ErrorKind::UnexpectedEof,
            ErrorKind::NotConnected,
        ] {
            assert!(matches!(
                classify_run_failure(&TransportError::Io(Error::from(kind))),
                RunFailure::LostTransport
            ));
        }
        // ...and a protocol/setup error is neither (propagated, not swallowed).
        assert!(matches!(
            classify_run_failure(&TransportError::Protocol("bad frame".to_owned())),
            RunFailure::Other
        ));
    }

    #[test]
    fn deadline_oracle_records_a_slow_completed_run_as_bhf555() {
        // A zero deadline makes every completed run "too slow", so the clean seed
        // run is recorded as a BHF-555 timing finding rather than discarded —
        // the transport-lane deadline oracle (#70).
        let (transport, _received) = mock_agent_transport(vec![ScriptedResponse::ok(vec![1, 2])]);
        let work_dir = tmp_work_dir("deadline");
        let mut config = config(work_dir.to_path_buf(), vec![b"seed".to_vec()], 1);
        config.deadline = Some(Duration::from_secs(0));

        let summary = run_transport_campaign(transport.as_ref(), &config).unwrap();

        assert_eq!(summary.executions, 1);
        assert!(
            summary.halted.is_none(),
            "a slow-but-complete run is not a halt"
        );
        assert_eq!(
            summary.findings.len(),
            1,
            "the slow input is a finding: {summary:?}"
        );
        let finding_json = work_dir
            .join("results")
            .join("findings")
            .join(&summary.findings[0])
            .join("finding.json");
        let record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&finding_json).unwrap()).unwrap();
        assert_eq!(record["rule_id"], "BHF-555", "a timing finding: {record}");

        std::fs::remove_dir_all(&work_dir).ok();
    }

    #[test]
    fn loop_stops_after_the_requested_distinct_finding_count() {
        // Two crashes of the SAME fault class dedup to one finding; the run keeps
        // going. Give distinct classes and cap at one distinct finding.
        let script = vec![
            ScriptedResponse::crash(vec![1], Fault::new(FaultKind::StackOverflow)),
            ScriptedResponse::crash(vec![2], Fault::new(FaultKind::CpuException)),
        ];
        let (transport, _received) = mock_agent_transport(script);
        let work_dir = tmp_work_dir("stop-after");
        let mut config = config(work_dir.to_path_buf(), vec![b"seed".to_vec()], 2);
        config.stop_after_findings = Some(1);

        let summary = run_transport_campaign(transport.as_ref(), &config).unwrap();

        // The seed run (exec 0) crashes -> first distinct finding -> stop_after
        // reached, so the loop halts before a second execution.
        assert_eq!(summary.findings.len(), 1, "{summary:?}");
        assert_eq!(summary.executions, 1, "stops as soon as the target is met");

        std::fs::remove_dir_all(&work_dir).ok();
    }

    #[test]
    fn duplicate_fault_classes_at_the_same_site_collapse_to_one_finding() {
        // Two crashes of the same class AND same (unlocalized) site over two
        // executions dedup to one finding — predictable same-site dedup (#75).
        let script = vec![
            ScriptedResponse::crash(vec![1], Fault::new(FaultKind::StackOverflow)),
            ScriptedResponse::crash(vec![2], Fault::new(FaultKind::StackOverflow)),
        ];
        let (transport, _received) = mock_agent_transport(script);
        let work_dir = tmp_work_dir("dedup");
        let config = config(work_dir.to_path_buf(), vec![b"seed".to_vec()], 2);

        let summary = run_transport_campaign(transport.as_ref(), &config).unwrap();

        assert_eq!(summary.executions, 2);
        assert_eq!(summary.crashes, 2, "both crash outcomes are counted");
        assert_eq!(
            summary.findings.len(),
            1,
            "same fault class + site -> one finding: {summary:?}"
        );

        std::fs::remove_dir_all(&work_dir).ok();
    }

    #[test]
    fn distinct_fault_sites_of_one_class_retain_separate_findings() {
        // Two faults of the SAME class (memory-protection) but DISTINCT attributed
        // sites must both be retained — not collapsed to one and the second
        // testcase silently dropped (#75). Their persisted signatures must differ
        // too, so campaign dedup and on-disk clustering agree.
        let script = vec![
            ScriptedResponse::crash(
                vec![1],
                Fault {
                    kind: FaultKind::MemoryProtection,
                    address: Some(0x2000_4000),
                    detail: "site A".to_owned(),
                },
            ),
            ScriptedResponse::crash(
                vec![2],
                Fault {
                    kind: FaultKind::MemoryProtection,
                    address: Some(0x2000_8000),
                    detail: "site B".to_owned(),
                },
            ),
        ];
        let (transport, _received) = mock_agent_transport(script);
        let work_dir = tmp_work_dir("distinct-sites");
        let config = config(work_dir.to_path_buf(), vec![b"seed".to_vec()], 2);

        let summary = run_transport_campaign(transport.as_ref(), &config).unwrap();

        assert_eq!(summary.executions, 2);
        assert_eq!(
            summary.findings.len(),
            2,
            "two distinct sites of one class -> two findings: {summary:?}"
        );
        // The on-disk signatures differ (persisted identity agrees with dedup).
        let sig = |id: &str| -> String {
            let record: serde_json::Value = serde_json::from_slice(
                &std::fs::read(
                    work_dir
                        .join("results")
                        .join("findings")
                        .join(id)
                        .join("finding.json"),
                )
                .unwrap(),
            )
            .unwrap();
            record["signature"].as_str().unwrap().to_owned()
        };
        assert_ne!(
            sig(&summary.findings[0]),
            sig(&summary.findings[1]),
            "distinct sites must have distinct persisted signatures"
        );

        std::fs::remove_dir_all(&work_dir).ok();
    }

    #[test]
    fn campaign_persists_a_replayable_transport_profile() {
        // Each emitted transport finding gets a transport_profile.json recording
        // the spec/backend/reset so `bhf replay` can re-drive it against the same
        // target (#80).
        let fault = Fault {
            kind: FaultKind::MemoryProtection,
            address: Some(0x2000_4000),
            detail: String::new(),
        };
        let (transport, _received) =
            mock_agent_transport(vec![ScriptedResponse::crash(vec![1], fault)]);
        let work_dir = tmp_work_dir("profile");
        let mut config = config(work_dir.to_path_buf(), vec![b"seed".to_vec()], 1);
        config.spec = "agent:tcp:127.0.0.1:9000".to_owned();

        let summary = run_transport_campaign(transport.as_ref(), &config).unwrap();
        assert_eq!(summary.findings.len(), 1);

        let profile_path = work_dir
            .join("results")
            .join("findings")
            .join(&summary.findings[0])
            .join("transport_profile.json");
        let profile: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&profile_path).unwrap()).unwrap();
        assert_eq!(profile["schema_version"], "bhf.transport-profile.v1");
        assert_eq!(profile["spec"], "agent:tcp:127.0.0.1:9000");
        assert_eq!(profile["backend"], "agent");

        std::fs::remove_dir_all(&work_dir).ok();
    }

    #[test]
    fn the_campaign_records_its_executions_per_sec_in_the_summary_and_each_transport_profile() {
        let fault = Fault {
            kind: FaultKind::MemoryProtection,
            address: Some(0x2000_4000),
            detail: String::new(),
        };
        let (transport, _received) = mock_agent_transport(vec![
            ScriptedResponse::ok(vec![1]),
            ScriptedResponse::ok(vec![1]),
            ScriptedResponse::crash(vec![1], fault),
        ]);
        let work_dir = tmp_work_dir("throughput");
        let mut config = config(
            work_dir.to_path_buf(),
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
            3,
        );
        config.spec =
            "qemu-system:qmp=127.0.0.1:1,gdb=127.0.0.1:2,done=0x1a8,reset=persistent".to_owned();

        let summary = run_transport_campaign(transport.as_ref(), &config).unwrap();
        assert_eq!(summary.executions, 3);
        assert_eq!(summary.findings.len(), 1);
        assert!(summary.executions_per_sec > 0.0, "{summary:?}");
        let expected = summary.executions as f64 / summary.elapsed_secs;
        assert!(
            (summary.executions_per_sec - expected).abs() <= expected * 1e-9,
            "{summary:?}"
        );

        let profile_path = work_dir
            .join("results")
            .join("findings")
            .join(&summary.findings[0])
            .join("transport_profile.json");
        let profile: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&profile_path).unwrap()).unwrap();
        let throughput = &profile["throughput"];
        assert_eq!(throughput["executions"], 3, "{profile}");
        // serde_json reads a float back to within an ulp.
        let close = |field: &str, want: f64| {
            let got = throughput[field].as_f64().unwrap_or(f64::NAN);
            assert!((got - want).abs() <= want * 1e-12, "{field}: {profile}");
        };
        close("elapsed_secs", summary.elapsed_secs);
        close("executions_per_sec", summary.executions_per_sec);
        assert!(
            profile["reset_mechanism"]
                .as_str()
                .is_some_and(|reset| reset.starts_with("guest persistent loop")),
            "{profile}"
        );
        assert!(
            profile["limitations"]
                .as_str()
                .is_some_and(|text| text.contains("replays it from the snapshot")),
            "{profile}"
        );

        std::fs::remove_dir_all(&work_dir).ok();
    }

    #[test]
    fn unbounded_distinct_sites_are_capped_per_class() {
        // A fault class whose attributed address varies every execution must not
        // create unbounded findings: distinct candidates are capped per class
        // (#75), so a varying accessed address cannot explode the findings set.
        let script: Vec<ScriptedResponse> = (0..(MAX_CANDIDATES_PER_CLASS + 8))
            .map(|i| {
                ScriptedResponse::crash(
                    vec![1],
                    Fault {
                        kind: FaultKind::MemoryProtection,
                        address: Some(0x1_0000 + (i as u64) * 0x100),
                        detail: String::new(),
                    },
                )
            })
            .collect();
        let n = script.len();
        let (transport, _received) = mock_agent_transport(script);
        let work_dir = tmp_work_dir("capped");
        let config = config(work_dir.to_path_buf(), vec![b"seed".to_vec()], n);

        let summary = run_transport_campaign(transport.as_ref(), &config).unwrap();

        assert_eq!(summary.executions, n);
        assert_eq!(
            summary.findings.len(),
            MAX_CANDIDATES_PER_CLASS,
            "distinct candidates per class are bounded: {summary:?}"
        );

        std::fs::remove_dir_all(&work_dir).ok();
    }

    #[test]
    fn unlocalized_faults_retain_bounded_distinct_candidates() {
        // A fault with NO backend-attributed address (an unlocalized fault — e.g.
        // a full-system stop or a bare crash) must NOT collapse every later
        // testcase into one candidate (#75 review). Two such faults of one class
        // are each retained as a distinct bounded candidate (the later testcase is
        // not silently dropped), their persisted signatures differ, and each
        // finding carries explicit grouping uncertainty. The agent wire always
        // carries an address, so this exercises handle_outcome directly with the
        // address-less outcome the gdb/full-system lanes actually produce.
        use target_transport::RunOutcome;
        let work_dir = tmp_work_dir("unlocalized");
        let emitter = FindingEmitter::with_metadata(
            work_dir.to_path_buf(),
            "H-transport".to_owned(),
            "transport".to_owned(),
            "mock".to_owned(),
        );
        let mut seen = std::collections::HashSet::new();
        let mut class_counts = std::collections::HashMap::new();
        let mut finding_ids: Vec<String> = Vec::new();
        let mut crashes = 0usize;
        let bare_crash = || RunOutcome {
            target: Default::default(),
            exit: ExitKind::Crash,
            coverage_edges: Vec::new(),
            fault: None,
            stdout: Vec::new(),
            coverage_incomplete: None,
            inconclusive: None,
        };
        for input in [b"a".as_slice(), b"b".as_slice()] {
            handle_outcome(
                &bare_crash(),
                input,
                "mock",
                &emitter,
                &mut seen,
                &mut class_counts,
                &mut finding_ids,
                &mut crashes,
            )
            .unwrap();
        }
        assert_eq!(
            finding_ids.len(),
            2,
            "two unlocalized faults of one class are retained, not collapsed"
        );
        assert_eq!(crashes, 2);

        let record = |id: &str| -> serde_json::Value {
            serde_json::from_slice(
                &std::fs::read(
                    work_dir
                        .join("results")
                        .join("findings")
                        .join(id)
                        .join("finding.json"),
                )
                .unwrap(),
            )
            .unwrap()
        };
        let first = record(&finding_ids[0]);
        let second = record(&finding_ids[1]);
        assert_ne!(
            first["signature"].as_str().unwrap(),
            second["signature"].as_str().unwrap(),
            "distinct unlocalized candidates must have distinct persisted signatures"
        );
        assert!(
            first["exception"]["message"]
                .as_str()
                .unwrap()
                .contains("grouping uncertain"),
            "an unlocalized finding must carry explicit grouping uncertainty: {first}"
        );

        std::fs::remove_dir_all(&work_dir).ok();
    }

    #[test]
    fn repeated_unlocalized_testcase_does_not_consume_the_candidate_cap() {
        // #75 re-review: re-running the SAME unlocalized testcase must dedup on the
        // input hash BEFORE a candidate slot is allocated, so it cannot exhaust the
        // bounded per-class allowance ahead of a genuinely different testcase. Here
        // input "a" repeated three times yields ONE candidate, and a different input
        // "b" yields a second — two findings and two consumed slots, not four.
        use target_transport::RunOutcome;
        let work_dir = tmp_work_dir("unlocalized-dedup");
        let emitter = FindingEmitter::with_metadata(
            work_dir.to_path_buf(),
            "H-transport".to_owned(),
            "transport".to_owned(),
            "mock".to_owned(),
        );
        let mut seen = std::collections::HashSet::new();
        let mut class_counts = std::collections::HashMap::new();
        let mut finding_ids: Vec<String> = Vec::new();
        let mut crashes = 0usize;
        let bare_crash = || RunOutcome {
            target: Default::default(),
            exit: ExitKind::Crash,
            coverage_edges: Vec::new(),
            fault: None,
            stdout: Vec::new(),
            coverage_incomplete: None,
            inconclusive: None,
        };
        for input in [
            b"a".as_slice(),
            b"a".as_slice(),
            b"a".as_slice(),
            b"b".as_slice(),
        ] {
            handle_outcome(
                &bare_crash(),
                input,
                "mock",
                &emitter,
                &mut seen,
                &mut class_counts,
                &mut finding_ids,
                &mut crashes,
            )
            .unwrap();
        }
        assert_eq!(
            finding_ids.len(),
            2,
            "repeated identical unlocalized input dedups; only the distinct input adds a candidate"
        );
        // Exactly two bounded slots consumed for this one class (not four).
        assert_eq!(
            class_counts.values().copied().max().unwrap_or(0),
            2,
            "repeats must not consume the per-class candidate cap: {class_counts:?}"
        );

        std::fs::remove_dir_all(&work_dir).ok();
    }
}
