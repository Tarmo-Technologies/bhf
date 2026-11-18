// SPDX-License-Identifier: Apache-2.0

//! HDF-7: wire the pure `protocol_session` crate into a runnable `bhf fuzz` lane.
//!
//! `protocol_session` parses a versioned protocol profile, lowers each message
//! onto the reused `binframe` descriptor, projects the legal message ordering
//! onto the reused `ada_state_machine` graph, and drives / replays / minimizes a
//! response-dependent, multi-message session over a [`SessionTransport`] seam —
//! but it is deliberately hardware-free: it owns no sockets and no process
//! spawn. This module is the consumer that supplies the live side: a real TCP
//! [`TcpSessionTransport`], a bounded seed+mutation campaign loop, and the
//! finding emission + replay/minimize wiring, all reusing the existing
//! `results/` finding layout `bhf fuzz` already writes.
//!
//! # Additive by construction
//!
//! The lane is a SEPARATE code path, reached only when `--protocol-profile` is
//! set (see [`should_use_session`] and the dispatch in [`crate::fuzz::run`]).
//! Without it, `bhf fuzz` runs the existing host/transport paths byte-for-byte.
//!
//! # Two novelty channels, reported separately
//!
//! Scheduling folds a CAPPED protocol-state/transition novelty contribution into
//! the shared scheduler's breadcrumb channel, but the run summary keeps the code-
//! coverage channel (`coverage_edges` / `coverage_blocks`) and the state channel
//! (`states_covered` / `transitions_covered`) in distinct fields — never merged
//! into one number. A plain request/response transport reports no code edges, so
//! the code channel is honestly zero on such targets while the state channel
//! carries the novelty. A service bhf runs (`--session-server-cmd`) built with
//! `c_runtime/bhf_service_cov.c` reports its edges after each session (#363),
//! and a session that reaches new code is kept as one that reaches a new state
//! is.
//!
//! Nothing here names a downstream consumer: a finding is emitted for importers /
//! SARIF / vulnerability-management tools to read.

use std::collections::{BTreeSet, HashSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use corpus::{CorpusError, FindingEmitter};
use finding_rules::oracle_sdk::{OracleEvidence, OracleHit};
use fuzz_engine_builtin::{MutationRng, PowerScheduler, ScheduleFeedback};
use protocol_session::{
    mutate_fields, mutate_sequence, BoundValue, CodeCoverageNovelty, FieldRole, Framing, Profile,
    ProtocolModel, ReplyProgress, SessionRun, SessionRunner, SessionTestcase, SessionTransport,
    SessionVerdict, StateNovelty, StateNoveltyDelta, TransportError,
};
use serde::{Deserialize, Serialize};

use crate::fuzz::FuzzArgs;
use crate::session_server::{ServerExit, SessionServer, SERVER_EXIT_GRACE};

/// The versioned name of the per-finding session artifact sidecar.
const SESSION_ARTIFACT_SCHEMA: &str = "bhf.session-artifact.v1";
/// The `session.json` artifact a session finding carries in its finding dir.
const SESSION_ARTIFACT: &str = "session.json";
/// The self-contained replay/minimize metadata sidecar (profile + transport).
const SESSION_META: &str = "session_meta.json";
/// Upper bound on a single framed reply we will read off a socket, so a
/// misbehaving peer cannot drive an unbounded allocation.
const MAX_REPLY_BYTES: usize = 1 << 20;
/// Per-request socket read/write timeout, so a silent peer cannot hang a run.
const SESSION_IO_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a UDP request waits for its reply datagram. A datagram the target
/// drops is not answered at all, so the deadline is shorter than TCP's.
const UDP_REPLY_TIMEOUT: Duration = Duration::from_secs(1);
/// Cap on the state-novelty contribution folded into the shared scheduler's
/// breadcrumb channel, so protocol novelty can never dominate code coverage.
const STATE_NOVELTY_CAP: usize = 8;

/// How a session is reset between testcases. Recorded as the run's reset
/// fidelity so a finding states exactly how its session state was re-established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum SessionResetMode {
    /// A fresh connection per testcase: new per-session target state (a new
    /// handle / id / nonce is captured each run). The default.
    #[default]
    Reconnect,
    /// Keep one connection across testcases: per-session target state persists.
    None,
}

impl SessionResetMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SessionResetMode::Reconnect => "reconnect",
            SessionResetMode::None => "none",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "reconnect" => Ok(SessionResetMode::Reconnect),
            "none" => Ok(SessionResetMode::None),
            other => Err(format!(
                "unknown session reset mode {other:?}; expected reconnect or none"
            )),
        }
    }
}

/// True when `bhf fuzz` should take the session-driven lane instead of the host
/// / transport paths: exactly when `--protocol-profile` is set. When it is
/// `None`, the default flow is byte-for-byte unchanged.
pub(crate) fn should_use_session(args: &FuzzArgs) -> bool {
    args.protocol_profile.is_some()
}

/// The `bhf fuzz` flags this lane does not wire: its seeds are the profile's
/// legal sessions, and it bounds a run by `--iterations`/`--time` only.
/// Remove a flag here when the lane starts honouring it.
const UNSUPPORTED_FLAGS: &[&str] = &[
    "--workers",
    "--grammar",
    "--dict",
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
    "--structured-inputs",
    "--print-final-stats",
    "--collector",
    "--collector-window-ms",
    "--seed-input",
    "--seed-file",
    "--max-len",
    "--timeout",
    "--deadline",
    "--transport-coverage-map",
];

/// The flags this run gives that the session lane would ignore.
/// `--runtime-oracles` applies to a service bhf runs (#364): without
/// `--session-server-cmd` there is no process to put under the shim.
/// `--transport-coverage-map` applies to a `transport:` backend (#261).
pub(crate) fn unsupported_flags(args: &FuzzArgs) -> Vec<&'static str> {
    let over_target = args
        .session_transport
        .as_deref()
        .is_some_and(|spec| spec.trim().starts_with("transport:"));
    crate::fuzz::given_flags(args)
        .into_iter()
        .filter(|flag| {
            (UNSUPPORTED_FLAGS.contains(flag)
                && !(*flag == "--transport-coverage-map" && over_target))
                || (*flag == "--runtime-oracles" && args.session_server_cmd.is_none())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Transport spec parsing (pure, fully testable)
// ---------------------------------------------------------------------------

/// A parsed, validated `--session-transport` spec. Kept separate from the built
/// transport so the parse is inspectable without dialing any socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionTransportPlan {
    /// A TCP request/response backend: one socket connected per session.
    Tcp { host: String, port: u16 },
    /// A UDP backend: one datagram per message, one reply datagram awaited
    /// within the reply deadline, and a socket of its own per session.
    Udp { host: String, port: u16 },
    /// A serial device (a UART, a pty), opened raw at `baud` when given (#262).
    Serial { path: PathBuf, baud: Option<u32> },
    /// A `--target-transport` backend (#261): each message is one execution
    /// on the target. `spec` is the target-transport spec, and `coverage_map`
    /// the `--transport-coverage-map` a gdb or qemu-system backend needs.
    Target {
        spec: String,
        coverage_map: Option<String>,
    },
}

/// A descriptive failure parsing a `--session-transport` spec. Never a silent
/// `None`.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SessionSpecError {
    #[error(
        "empty --session-transport spec; expected tcp:HOST:PORT, udp:HOST:PORT, \
         serial:PATH[,baud=N] or transport:TARGET-TRANSPORT-SPEC"
    )]
    Empty,
    #[error(
        "unknown --session-transport backend {backend:?}; supported: tcp, udp, serial, \
         transport"
    )]
    UnknownBackend { backend: String },
    #[error("malformed {backend} spec {spec:?}: {reason}")]
    Malformed {
        backend: &'static str,
        spec: String,
        reason: String,
    },
}

impl SessionTransportPlan {
    /// Parse a `--session-transport` spec into an inspectable plan.
    pub(crate) fn parse(spec: &str) -> Result<Self, SessionSpecError> {
        Self::parse_with_map(spec, None)
    }

    /// Parse a `--session-transport` spec with the `--transport-coverage-map`
    /// a `transport:` backend takes.
    pub(crate) fn parse_with_map(
        spec: &str,
        coverage_map: Option<&str>,
    ) -> Result<Self, SessionSpecError> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err(SessionSpecError::Empty);
        }
        if let Some(rest) = spec.strip_prefix("tcp:") {
            let (host, port) = parse_host_port("tcp", spec, rest)?;
            return Ok(Self::Tcp { host, port });
        }
        if let Some(rest) = spec.strip_prefix("udp:") {
            let (host, port) = parse_host_port("udp", spec, rest)?;
            return Ok(Self::Udp { host, port });
        }
        if let Some(rest) = spec.strip_prefix("transport:") {
            let malformed = |reason: String| SessionSpecError::Malformed {
                backend: "transport",
                spec: spec.to_owned(),
                reason,
            };
            let plan = crate::transport_fuzz::TransportPlan::parse(rest, coverage_map)
                .map_err(|error| malformed(error.to_string()))?;
            // The session mutator edits messages, not one input's bytes: it
            // has no use for the comparisons, so the reads would be wasted.
            if plan.cmplog().is_some() {
                return Err(malformed(
                    "the session lane does not use cmplog=; it is read by \
                     `bhf fuzz --target-transport`"
                        .to_owned(),
                ));
            }
            return Ok(Self::Target {
                spec: rest.to_owned(),
                coverage_map: coverage_map.map(str::to_owned),
            });
        }
        if let Some(rest) = spec.strip_prefix("serial:") {
            let malformed = |reason: String| SessionSpecError::Malformed {
                backend: "serial",
                spec: spec.to_owned(),
                reason,
            };
            let (path, baud) = match rest.split_once(",baud=") {
                Some((path, baud)) => {
                    let baud = baud
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
            if path.is_empty() {
                return Err(malformed("the device path is empty".to_owned()));
            }
            return Ok(Self::Serial {
                path: PathBuf::from(path),
                baud,
            });
        }
        Err(SessionSpecError::UnknownBackend {
            backend: spec.split(':').next().unwrap_or(spec).to_owned(),
        })
    }

    /// A short human label for the run summary / finding metadata.
    pub(crate) fn label(&self) -> String {
        match self {
            Self::Tcp { host, port } => format!("tcp:{host}:{port}"),
            Self::Udp { host, port } => format!("udp:{host}:{port}"),
            Self::Serial { path, baud } => format!(
                "serial:{}{}",
                path.display(),
                baud.map(|baud| format!(",baud={baud}")).unwrap_or_default()
            ),
            Self::Target { spec, .. } => format!("transport:{spec}"),
        }
    }

    /// The host, port and whether it is UDP, for a service bhf starts; a
    /// serial device has no port to wait for.
    pub(crate) fn endpoint(&self) -> Result<(String, u16, bool), String> {
        match self {
            Self::Tcp { host, port } => Ok((host.clone(), *port, false)),
            Self::Udp { host, port } => Ok((host.clone(), *port, true)),
            Self::Serial { .. } | Self::Target { .. } => Err(format!(
                "--session-server-cmd needs a tcp: or udp: --session-transport, whose port \
                 bhf waits for; {} has none",
                self.label()
            )),
        }
    }

    /// The transport kind, for the reset-fidelity string.
    fn kind(&self) -> &'static str {
        match self {
            Self::Tcp { .. } => "tcp",
            Self::Udp { .. } => "udp",
            Self::Serial { .. } => "serial",
            Self::Target { .. } => "transport",
        }
    }

    /// Build the live transport this plan describes. The socket is dialed lazily
    /// on the first [`SessionTransport::reset`], so this itself touches nothing.
    /// `reply_timeout` overrides the backend's deadline for a reply
    /// ([`SESSION_IO_TIMEOUT`] over TCP, [`UDP_REPLY_TIMEOUT`] over UDP).
    pub(crate) fn into_transport(
        self,
        reset: SessionResetMode,
        framing: Framing,
        reply_timeout: Option<Duration>,
    ) -> Result<LiveTransport, String> {
        Ok(match self {
            Self::Tcp { host, port } => LiveTransport::Tcp(TcpSessionTransport::new(
                host,
                port,
                reset,
                framing,
                reply_timeout.unwrap_or(SESSION_IO_TIMEOUT),
            )),
            Self::Udp { host, port } => LiveTransport::Udp(UdpSessionTransport::new(
                host,
                port,
                reset,
                framing,
                reply_timeout.unwrap_or(UDP_REPLY_TIMEOUT),
            )),
            Self::Serial { path, baud } => LiveTransport::Serial(SerialSessionTransport {
                path,
                baud,
                reset,
                framing,
                io_timeout: reply_timeout.unwrap_or(SESSION_IO_TIMEOUT),
                port: None,
                pending: Vec::new(),
            }),
            Self::Target { spec, coverage_map } => {
                let transport =
                    crate::transport_fuzz::TransportPlan::parse(&spec, coverage_map.as_deref())
                        .and_then(|plan| {
                            plan.into_transport(Some(reply_timeout.unwrap_or(SESSION_IO_TIMEOUT)))
                        })
                        .map_err(|error| {
                            format!("--session-transport transport:{spec}: {error}")
                        })?;
                LiveTransport::Target(TargetSessionTransport::new(transport, reset))
            }
        })
    }
}

fn parse_host_port(
    backend: &'static str,
    spec: &str,
    hostport: &str,
) -> Result<(String, u16), SessionSpecError> {
    let malformed = |reason: String| SessionSpecError::Malformed {
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

// ---------------------------------------------------------------------------
// The live TCP request/response backend
// ---------------------------------------------------------------------------

/// A real TCP [`SessionTransport`]. Each request is framed as the profile's
/// `[framing]` says and the reply is read the same way: a length-prefixed,
/// delimited or fixed-size reply ends by its content, and a raw one when the
/// peer goes quiet. The read is bounded (`MAX_REPLY_BYTES`) and the socket has
/// a read/write timeout, so neither a huge reply nor a silent peer can wedge a
/// campaign.
pub(crate) struct TcpSessionTransport {
    host: String,
    port: u16,
    reset: SessionResetMode,
    framing: Framing,
    /// How long a reply may take to start, and a write to finish.
    io_timeout: Duration,
    stream: Option<TcpStream>,
    /// Bytes read past the end of the last reply.
    pending: Vec<u8>,
}

impl TcpSessionTransport {
    fn new(
        host: String,
        port: u16,
        reset: SessionResetMode,
        framing: Framing,
        io_timeout: Duration,
    ) -> Self {
        Self {
            host,
            port,
            reset,
            framing,
            io_timeout,
            stream: None,
            pending: Vec::new(),
        }
    }

    fn connect(&mut self) -> Result<(), TransportError> {
        self.stream = None;
        self.pending.clear();
        let stream = TcpStream::connect((self.host.as_str(), self.port)).map_err(|e| {
            TransportError::new(format!("connect {}:{}: {e}", self.host, self.port))
        })?;
        stream.set_read_timeout(Some(self.io_timeout)).ok();
        stream.set_write_timeout(Some(self.io_timeout)).ok();
        // Disable Nagle: a request/response session sends one small frame then
        // blocks on the reply, so Nagle + delayed-ACK would add a ~40ms stall per
        // round-trip. We frame explicitly, so coalescing buys nothing.
        stream.set_nodelay(true).ok();
        self.stream = Some(stream);
        Ok(())
    }

    /// Read until the framing has a whole reply. A raw reply is complete when
    /// no byte arrives for its idle window after the first, or the peer closes.
    fn read_reply(&mut self) -> Result<Vec<u8>, TransportError> {
        let idle = self.framing.reply_idle_ms().map(Duration::from_millis);
        let mut chunk = [0u8; 8192];
        loop {
            match self.framing.take_reply(&self.pending, MAX_REPLY_BYTES) {
                ReplyProgress::Complete { reply, consumed } => {
                    self.pending.drain(..consumed);
                    return Ok(reply);
                }
                ReplyProgress::Invalid(reason) => {
                    self.pending.clear();
                    return Err(TransportError::new(format!("session reply: {reason}")));
                }
                ReplyProgress::NeedMore => {}
            }
            let quiet_completes = idle.is_some() && !self.pending.is_empty();
            let stream = self
                .stream
                .as_mut()
                .ok_or_else(|| TransportError::new("tcp session is not connected; reset first"))?;
            let wait = if quiet_completes {
                idle
            } else {
                Some(self.io_timeout)
            };
            stream.set_read_timeout(wait).ok();
            match stream.read(&mut chunk) {
                Ok(0) if quiet_completes => return Ok(std::mem::take(&mut self.pending)),
                Ok(0) => {
                    return Err(lost(
                        &mut self.stream,
                        "session read reply: the connection closed".to_owned(),
                    ))
                }
                Ok(n) => self.pending.extend_from_slice(&chunk[..n]),
                Err(e)
                    if quiet_completes
                        && matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                {
                    return Ok(std::mem::take(&mut self.pending));
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(lost(&mut self.stream, format!("session read reply: {e}"))),
            }
        }
    }
}

/// The target ended the session (a closed or reset connection, or one that
/// stopped answering within the reply deadline): drop the stream, so the
/// next reset connects again whatever the reset mode.
fn lost(stream: &mut Option<TcpStream>, message: String) -> TransportError {
    *stream = None;
    TransportError::session_lost(message)
}

impl SessionTransport for TcpSessionTransport {
    fn send_request(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        let frame = self
            .framing
            .encode(request)
            .map_err(|e| TransportError::new(e.to_string()))?;
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| TransportError::new("tcp session is not connected; reset first"))?;
        stream
            .write_all(&frame)
            .and_then(|()| stream.flush())
            .map_err(|e| lost(&mut self.stream, format!("session write: {e}")))?;
        self.read_reply()
    }

    fn reset(&mut self) -> Result<(), TransportError> {
        // Reconnect establishes fresh per-session target state; `none` keeps the
        // one connection alive after the first dial.
        if self.stream.is_none() || matches!(self.reset, SessionResetMode::Reconnect) {
            self.connect()?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The live UDP backend
// ---------------------------------------------------------------------------

/// A UDP [`SessionTransport`]: each request is one datagram, framed as the
/// profile says, and its reply is the next datagram that comes back within
/// the reply deadline. A reset opens a new socket, so the target sees a new
/// source port and keeps no state for it. A reply that does not arrive, or a
/// datagram the target's host refuses (port unreachable), ends the session.
pub(crate) struct UdpSessionTransport {
    host: String,
    port: u16,
    reset: SessionResetMode,
    framing: Framing,
    reply_timeout: Duration,
    socket: Option<UdpSocket>,
}

impl UdpSessionTransport {
    fn new(
        host: String,
        port: u16,
        reset: SessionResetMode,
        framing: Framing,
        reply_timeout: Duration,
    ) -> Self {
        Self {
            host,
            port,
            reset,
            framing,
            reply_timeout,
            socket: None,
        }
    }

    fn open(&mut self) -> Result<(), TransportError> {
        self.socket = None;
        let target = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|e| TransportError::new(format!("resolve {}:{}: {e}", self.host, self.port)))?
            .next()
            .ok_or_else(|| {
                TransportError::new(format!(
                    "{}:{} resolves to no address",
                    self.host, self.port
                ))
            })?;
        let local: SocketAddr = if target.is_ipv4() {
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let socket = UdpSocket::bind(local)
            .and_then(|socket| socket.connect(target).map(|()| socket))
            .map_err(|e| TransportError::new(format!("open udp socket to {target}: {e}")))?;
        socket.set_read_timeout(Some(self.reply_timeout)).ok();
        socket.set_write_timeout(Some(self.reply_timeout)).ok();
        self.socket = Some(socket);
        Ok(())
    }

    fn lost(&mut self, message: String) -> TransportError {
        self.socket = None;
        TransportError::session_lost(message)
    }
}

impl SessionTransport for UdpSessionTransport {
    fn send_request(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        let datagram = self
            .framing
            .encode(request)
            .map_err(|e| TransportError::new(e.to_string()))?;
        let socket = self
            .socket
            .as_ref()
            .ok_or_else(|| TransportError::new("udp session is not open; reset first"))?;
        if let Err(e) = socket.send(&datagram) {
            return Err(self.lost(format!("session send: {e}")));
        }
        let mut buf = vec![0u8; 65_536];
        loop {
            let socket = self
                .socket
                .as_ref()
                .ok_or_else(|| TransportError::new("udp session is not open; reset first"))?;
            match socket.recv(&mut buf) {
                Ok(n) => {
                    return match self.framing.datagram_reply(&buf[..n], MAX_REPLY_BYTES) {
                        ReplyProgress::Complete { reply, .. } => Ok(reply),
                        ReplyProgress::Invalid(reason) => {
                            Err(TransportError::new(format!("session reply: {reason}")))
                        }
                        ReplyProgress::NeedMore => Err(TransportError::new(
                            "session reply: the datagram holds part of a reply",
                        )),
                    };
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(self.lost(format!(
                        "no reply datagram within {} ms",
                        self.reply_timeout.as_millis()
                    )))
                }
                Err(e) => return Err(self.lost(format!("session receive: {e}"))),
            }
        }
    }

    fn reset(&mut self) -> Result<(), TransportError> {
        if self.socket.is_none() || matches!(self.reset, SessionResetMode::Reconnect) {
            self.open()?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The live serial backend
// ---------------------------------------------------------------------------

/// A serial [`SessionTransport`] (#262): a UART or a pty, opened raw (as the
/// agent's `serial:` transport is: no echo, no line editing, no newline
/// translation) at the given baud rate. Requests are framed as the profile
/// says and replies read the same way, every read bounded by the reply
/// deadline. A device has no connection, so `--session-reset reconnect`
/// reopens it, which drops what it had sent; `none` keeps it open.
pub(crate) struct SerialSessionTransport {
    path: PathBuf,
    baud: Option<u32>,
    reset: SessionResetMode,
    framing: Framing,
    io_timeout: Duration,
    port: Option<crate::serial_port::SerialPort>,
    /// Bytes read past the end of the last reply.
    pending: Vec<u8>,
}

impl SerialSessionTransport {
    fn open(&mut self) -> Result<(), TransportError> {
        self.port = None;
        self.pending.clear();
        let port = crate::serial_port::open(&self.path, self.baud, Some(self.io_timeout))
            .map_err(|e| TransportError::new(format!("open {}: {e}", self.path.display())))?;
        self.port = Some(port);
        Ok(())
    }

    /// The device stopped answering, or failed: close it, so the next reset
    /// opens it again whatever the reset mode.
    fn lost(&mut self, message: String) -> TransportError {
        self.port = None;
        TransportError::session_lost(message)
    }

    /// Read until the framing has a whole reply. A raw reply is complete when
    /// no byte arrives for its idle window after the first.
    fn read_reply(&mut self) -> Result<Vec<u8>, TransportError> {
        let idle = self.framing.reply_idle_ms().map(Duration::from_millis);
        let mut chunk = [0u8; 4096];
        loop {
            match self.framing.take_reply(&self.pending, MAX_REPLY_BYTES) {
                ReplyProgress::Complete { reply, consumed } => {
                    self.pending.drain(..consumed);
                    return Ok(reply);
                }
                ReplyProgress::Invalid(reason) => {
                    self.pending.clear();
                    return Err(TransportError::new(format!("session reply: {reason}")));
                }
                ReplyProgress::NeedMore => {}
            }
            let quiet_completes = idle.is_some() && !self.pending.is_empty();
            let wait = if quiet_completes {
                idle
            } else {
                Some(self.io_timeout)
            };
            let port = self
                .port
                .as_mut()
                .ok_or_else(|| TransportError::new("serial session is not open; reset first"))?;
            if let Err(e) = port.set_read_timeout(wait) {
                return Err(self.lost(format!("session read reply: {e}")));
            }
            match port.read(&mut chunk) {
                Ok(n) => self.pending.extend_from_slice(&chunk[..n]),
                Err(e) if quiet_completes && e.kind() == std::io::ErrorKind::TimedOut => {
                    return Ok(std::mem::take(&mut self.pending));
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(self.lost(format!("session read reply: {e}"))),
            }
        }
    }
}

impl SessionTransport for SerialSessionTransport {
    fn send_request(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        let frame = self
            .framing
            .encode(request)
            .map_err(|e| TransportError::new(e.to_string()))?;
        let port = self
            .port
            .as_mut()
            .ok_or_else(|| TransportError::new("serial session is not open; reset first"))?;
        if let Err(e) = port.write_all(&frame).and_then(|()| port.flush()) {
            return Err(self.lost(format!("session write: {e}")));
        }
        self.read_reply()
    }

    fn reset(&mut self) -> Result<(), TransportError> {
        if self.port.is_none() || matches!(self.reset, SessionResetMode::Reconnect) {
            self.open()?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The target-transport backend
// ---------------------------------------------------------------------------

/// A session over a `--target-transport` backend (#261): an on-target agent,
/// a debug probe, an emulator. Each message is one execution: the message's
/// bytes are the input, and the reply is the backend's stdout channel, which
/// agent backends do not have (a profile over them captures nothing). A
/// fault, a crash or a hang ends the session at that message, which the lane
/// confirms and records as a finding, and the executions' coverage edges feed
/// its code channel. `--session-reset reconnect` arms a fresh target session
/// for each protocol session; `none` keeps one armed.
pub(crate) struct TargetSessionTransport {
    transport: Box<dyn target_transport::TargetTransport>,
    session: Option<Box<dyn target_transport::TargetSession>>,
    reset: SessionResetMode,
    edges: Vec<u64>,
}

impl TargetSessionTransport {
    pub(crate) fn new(
        transport: Box<dyn target_transport::TargetTransport>,
        reset: SessionResetMode,
    ) -> Self {
        Self {
            transport,
            session: None,
            reset,
            edges: Vec::new(),
        }
    }
}

impl SessionTransport for TargetSessionTransport {
    fn send_request(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| TransportError::new("target session is not armed; reset first"))?;
        let outcome = match session.run_input(request) {
            Ok(outcome) => outcome,
            Err(error) => {
                self.session = None;
                return Err(TransportError::session_lost(format!(
                    "the target transport failed on this message: {error}"
                )));
            }
        };
        self.edges
            .extend(outcome.coverage_edges.iter().map(|&edge| u64::from(edge)));
        if let Some(reason) = &outcome.inconclusive {
            return Err(TransportError::new(format!(
                "the target's verdict on this message is inconclusive: {reason}"
            )));
        }
        let fault = match (&outcome.fault, outcome.exit) {
            (Some(fault), _) => Some(format!(
                "{:?}{}{}",
                fault.kind,
                fault
                    .address
                    .map(|address| format!(" at {address:#x}"))
                    .unwrap_or_default(),
                if fault.detail.is_empty() {
                    String::new()
                } else {
                    format!(": {}", fault.detail)
                }
            )),
            (None, target_transport::ExitKind::Crash) => Some("a crash".to_owned()),
            (None, target_transport::ExitKind::Timeout) => Some("a hang".to_owned()),
            (None, _) => None,
        };
        if let Some(fault) = fault {
            // The target is in no state to go on: arm it again.
            self.session = None;
            return Err(TransportError::session_lost(format!(
                "the target faulted on this message: {fault}"
            )));
        }
        Ok(outcome.stdout)
    }

    fn reset(&mut self) -> Result<(), TransportError> {
        if self.session.is_none() || matches!(self.reset, SessionResetMode::Reconnect) {
            self.session = Some(
                self.transport
                    .arm()
                    .map_err(|error| TransportError::new(format!("arm the target: {error}")))?,
            );
        }
        Ok(())
    }

    fn take_coverage_edges(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.edges)
    }
}

/// A live backend, as `--session-transport` names it.
pub(crate) enum LiveTransport {
    Tcp(TcpSessionTransport),
    Udp(UdpSessionTransport),
    Serial(SerialSessionTransport),
    Target(TargetSessionTransport),
}

impl SessionTransport for LiveTransport {
    fn send_request(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        match self {
            LiveTransport::Tcp(transport) => transport.send_request(request),
            LiveTransport::Udp(transport) => transport.send_request(request),
            LiveTransport::Serial(transport) => transport.send_request(request),
            LiveTransport::Target(transport) => transport.send_request(request),
        }
    }

    fn reset(&mut self) -> Result<(), TransportError> {
        match self {
            LiveTransport::Tcp(transport) => transport.reset(),
            LiveTransport::Udp(transport) => transport.reset(),
            LiveTransport::Serial(transport) => transport.reset(),
            LiveTransport::Target(transport) => transport.reset(),
        }
    }

    fn take_coverage_edges(&mut self) -> Vec<u64> {
        match self {
            LiveTransport::Target(transport) => transport.take_coverage_edges(),
            _ => Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Seed synthesis
// ---------------------------------------------------------------------------

/// Synthesize the campaign's valid seed session(s) from the profile: a single
/// legal walk from the start state that covers each message type once, emitting a
/// message only once every back-reference it carries has a producer earlier in
/// the walk. For the OPEN/WRITE slice this yields the ordinary valid
/// `OPEN,WRITE` session (a non-escaping path) the campaign then mutates.
fn seed_sessions(model: &ProtocolModel) -> Vec<SessionTestcase> {
    let graph = model.graph();
    let total = model.messages().len();
    if total == 0 {
        return Vec::new();
    }
    let cap = model.max_messages().min(2 * total + 2).max(1);

    let mut produced: BTreeSet<String> = BTreeSet::new();
    let mut covered: BTreeSet<String> = BTreeSet::new();
    let mut messages = Vec::new();
    let mut cur = graph.initial();

    while covered.len() < total && messages.len() < cap {
        let choice = graph
            .open_entries(cur)
            .iter()
            .find(|name| !covered.contains(name.as_str()) && refs_satisfied(model, name, &produced))
            .cloned();
        let Some(name) = choice else { break };
        let Some(compiled) = model.message(&name) else {
            break;
        };
        messages.push(protocol_session::MessageInstance::from_seed(compiled));
        produced.insert(name.clone());
        covered.insert(name.clone());
        match graph.next_state(cur, &name) {
            Some(next) => cur = next,
            None => break,
        }
    }

    if messages.is_empty() {
        Vec::new()
    } else {
        vec![SessionTestcase::from_messages(
            model.profile_sha256(),
            messages,
        )]
    }
}

/// Whether every back-reference field of `message` has a producer already in the
/// `produced` set.
fn refs_satisfied(model: &ProtocolModel, message: &str, produced: &BTreeSet<String>) -> bool {
    let Some(compiled) = model.message(message) else {
        return false;
    };
    compiled.fields.iter().all(|field| match &field.role {
        FieldRole::Ref { source, .. } => produced.contains(source.split('.').next().unwrap_or("")),
        _ => true,
    })
}

/// A small, generic boundary-token dictionary spliced into bytes-typed fields.
/// `..` is the universal path-escape token; keeping it makes a bounded, fixed-
/// seed campaign deterministically reach a sandbox-escape boundary. No token is
/// consumer-specific.
fn boundary_dictionary() -> Vec<Vec<u8>> {
    vec![b"..".to_vec()]
}

// ---------------------------------------------------------------------------
// Campaign configuration / summary / errors
// ---------------------------------------------------------------------------

/// Inputs to [`run_session_campaign`], decoupled from clap so the loop is
/// testable against an in-memory transport in a temp dir.
#[derive(Debug, Clone)]
pub(crate) struct SessionFuzzConfig {
    pub work_dir: PathBuf,
    pub harness_id: String,
    /// SHA-256 of the driving profile (recorded on the run and every finding).
    pub profile_sha256: String,
    /// The full profile TOML, embedded in each finding's metadata so a finding
    /// replays/minimizes self-contained.
    pub profile_toml: String,
    /// The transport spec, used as the `transport` summary field and to rebuild
    /// the backend for replay/minimize.
    pub transport_label: String,
    /// The transport kind, for the reset-fidelity string.
    pub transport_kind: String,
    /// How a session is reset between testcases.
    pub reset: SessionResetMode,
    /// `--session-reply-timeout`, recorded so a replay waits as long.
    pub reply_timeout: Option<Duration>,
    /// `--session-server-cmd`, recorded so a replay can start the service.
    pub server_cmd: Option<String>,
    /// `--transport-coverage-map` of a `transport:` backend, recorded so a
    /// replay rebuilds it.
    pub coverage_map: Option<String>,
    /// Bounded cap on messages per session.
    pub max_messages: usize,
    /// The valid seed session(s) the campaign mutates.
    pub seeds: Vec<SessionTestcase>,
    /// Total execution cap (bounded work — never unbounded).
    pub iterations: usize,
    /// Optional wall-clock budget.
    pub time_budget: Option<Duration>,
    /// Deterministic mutation RNG seed.
    pub rng_seed: u64,
    /// Stop as soon as this many DISTINCT findings are emitted.
    pub stop_after_findings: Option<usize>,
    /// Actionability profile for the emitted findings.
    pub mode: actionability::RunMode,
}

impl SessionFuzzConfig {
    fn reset_fidelity(&self) -> String {
        format!("{};reset={}", self.transport_kind, self.reset.as_str())
    }
}

/// The JSON summary a session-driven run reports. The code-coverage channel
/// (`coverage_edges` / `coverage_blocks`) and the protocol-state channel
/// (`states_covered` / `transitions_covered`) are DISTINCT fields, never merged.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct SessionFuzzSummary {
    pub schema_version: u32,
    pub harness_id: String,
    pub engine: String,
    pub profile_sha256: String,
    pub transport: String,
    pub reset_fidelity: String,
    /// How the profile frames messages on the wire (`raw`, `length_prefix(u16 big)`).
    pub framing: String,
    pub seeds: usize,
    pub executions: usize,
    pub corpus_new: usize,
    /// Code-coverage channel (distinct edge bits). Zero on a transport that
    /// reports no edges; still present and reported separately.
    pub coverage_edges: usize,
    /// Code-coverage channel (block/hit-count bits).
    pub coverage_blocks: usize,
    /// Where the code channel's edges come from: `service`, a service bhf
    /// runs with an edge map (#363); `uninstrumented_service`, one that never
    /// wrote it; `target`, a `transport:` backend that reported edges (#261);
    /// or `none`.
    pub coverage_source: String,
    /// Protocol-state channel: distinct states visited.
    pub states_covered: usize,
    /// Protocol-state channel: distinct transitions walked.
    pub transitions_covered: usize,
    /// Sessions the target dropped, the second drive dropping them again at
    /// the same message (each is a BHF-210 finding, deduped by message).
    pub crashes: usize,
    /// Sessions the target dropped once but not when driven again; each is
    /// kept under `<work_dir>/session_disconnects/` for triage.
    pub unconfirmed_disconnects: usize,
    /// How many times bhf started the service (`--session-server-cmd`): once,
    /// and again after each crash. Zero when bhf did not run it.
    #[serde(skip_serializing_if = "is_zero")]
    pub server_starts: usize,
    /// Distinct finding ids written to `<work_dir>/results/findings/`.
    pub findings: Vec<String>,
    pub elapsed_secs: f64,
}

/// A failure running a session-driven campaign. Every variant is descriptive.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SessionFuzzError {
    #[error("session transport error: {0}")]
    Transport(TransportError),
    #[error("serializing session testcase: {0}")]
    Serialize(serde_json::Error),
    #[error("writing finding: {0}")]
    Finding(#[from] CorpusError),
    #[error("writing session artifact {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("the service did not start again: {0}")]
    Server(String),
}

/// The self-contained replay/minimize sidecar written next to a session finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionArtifactMeta {
    schema: String,
    profile_sha256: String,
    /// The full driving profile, embedded so replay/minimize is self-contained.
    profile_toml: String,
    /// The `--session-transport` spec to rebuild the backend.
    transport: String,
    transport_kind: String,
    /// `reconnect` | `none`.
    reset: String,
    reset_fidelity: String,
    rule_id: Option<String>,
    oracle: String,
    /// `--session-reply-timeout`, when the run gave one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reply_timeout_ms: Option<u64>,
    /// `--session-server-cmd`, when bhf ran the service: a replay starts it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    server_cmd: Option<String>,
    /// `--transport-coverage-map` of a `transport:` backend (#261).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    coverage_map: Option<String>,
    /// For a runtime-oracle finding of the service (#364), the hit's
    /// signature: a replay runs the service under the shim again and looks
    /// for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    runtime_signature: Option<String>,
    /// The runtrace mode (`reporting`, `attacking`) the service ran under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    runtrace_mode: Option<String>,
}

// ---------------------------------------------------------------------------
// The session campaign loop
// ---------------------------------------------------------------------------

/// Whether the loop should stop now: hit the iteration cap, the time budget, or
/// the distinct-finding target. Checked before every drive so the loop never
/// runs unbounded and never runs one execution past its budget.
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

/// Turn a capped state-novelty delta into scheduler feedback. The state
/// contribution rides the breadcrumb channel (weighted by the scheduler's
/// `breadcrumb_bit_bonus`) and is clamped so it cannot dominate code coverage.
fn schedule_feedback(delta: StateNoveltyDelta, new_edges: usize) -> ScheduleFeedback {
    let state = (delta.new_states + delta.new_transitions).min(STATE_NOVELTY_CAP);
    ScheduleFeedback {
        new_exception_signatures: 0,
        // The service's new code edges count in full (#363).
        new_breadcrumb_bits: u32::try_from(state.saturating_add(new_edges)).unwrap_or(u32::MAX),
    }
}

/// Apply one bounded, graph-legal mutation: mostly field-value mutation (which
/// discovers the field-level boundary), occasionally a structural sequence edit.
fn mutate_one(
    parent: &SessionTestcase,
    model: &ProtocolModel,
    rng: &mut MutationRng,
    dictionary: &[Vec<u8>],
    max_messages: usize,
) -> SessionTestcase {
    if rng.next_u64().is_multiple_of(8) {
        mutate_sequence(parent, model, rng, max_messages)
    } else {
        mutate_fields(parent, model, rng, dictionary)
    }
}

/// The oracle name of a session the target dropped.
pub(crate) const DISCONNECT_ORACLE: &str = "session-disconnect";
/// The oracle of a finding whose session crashed the service bhf runs
/// (`--session-server-cmd`), with the sanitizer report from its stderr.
pub(crate) const SERVER_CRASH_ORACLE: &str = "session-server-crash";
/// The oracle of a finding whose session made the service exit with no
/// sanitizer report.
pub(crate) const SERVER_EXIT_ORACLE: &str = "session-server-exit";
/// The rule of a session the target dropped: a reachable crash of the
/// service (at least a denial of service).
const DISCONNECT_RULE: &str = "BHF-210";
/// Failures to connect in a row after which a campaign stops: the target is
/// gone, not crashing on an input.
const MAX_CONNECT_FAILURES: usize = 3;
/// How long to wait before the next connection after a failed one, times the
/// failures so far: a service that restarts after a crash gets the time to.
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(200);

/// Dropped sessions and connection failures across one campaign.
#[derive(Debug, Default)]
struct CrashTally {
    crashes: usize,
    unconfirmed: usize,
    /// Failures to connect in a row; any drive that connects resets it.
    connect_failures: usize,
    /// The session driven before the current one: when the service is found
    /// gone before a session connects, that one is what crashed it.
    previous: Option<SessionTestcase>,
}

/// Drive `messages`, counting a failure to connect: `None` when the drive
/// could not connect or the candidate could not be driven, an error once
/// [`MAX_CONNECT_FAILURES`] connections in a row have failed.
fn drive_counting(
    runner: &SessionRunner,
    messages: &[protocol_session::MessageInstance],
    transport: &mut dyn SessionTransport,
    tally: &mut CrashTally,
) -> Result<Option<SessionRun>, SessionFuzzError> {
    match runner.drive(messages, transport) {
        Ok(run) => {
            tally.connect_failures = 0;
            Ok(Some(run))
        }
        Err(protocol_session::RunnerError::Connect(error)) => {
            tally.connect_failures += 1;
            if tally.connect_failures >= MAX_CONNECT_FAILURES {
                return Err(SessionFuzzError::Transport(TransportError::new(format!(
                    "{} ({} connection attempts in a row failed)",
                    error.message, tally.connect_failures
                ))));
            }
            let failures = u32::try_from(tally.connect_failures).unwrap_or(u32::MAX);
            std::thread::sleep(CONNECT_RETRY_DELAY.saturating_mul(failures));
            Ok(None)
        }
        // Candidate-specific error (an illegal transition, an encode or
        // response failure, a frame the wire cannot carry): skip it rather
        // than aborting the campaign.
        Err(_) => Ok(None),
    }
}

/// Keep a session the target dropped under `<work_dir>/session_disconnects/`
/// before it is driven again, so it survives a target that does not come back.
fn persist_disconnect(
    config: &SessionFuzzConfig,
    run: &SessionRun,
) -> Result<PathBuf, SessionFuzzError> {
    use sha2::Digest;
    let serialized = run
        .testcase
        .to_json()
        .map_err(SessionFuzzError::Serialize)?;
    let dir = config.work_dir.join("session_disconnects");
    std::fs::create_dir_all(&dir).map_err(|source| SessionFuzzError::Io {
        path: dir.display().to_string(),
        source,
    })?;
    let digest = corpus::hex_lower(&sha2::Sha256::digest(serialized.as_bytes()));
    let path = dir.join(format!("{}.json", &digest[..16]));
    write_artifact(&path, serialized.as_bytes())?;
    Ok(path)
}

/// The runtime sink oracles over a service bhf runs under the runtrace shim
/// (#364): the sinks the campaign's sessions reached, and the session each
/// input the tracker may confirm came from.
#[derive(Default)]
pub(crate) struct ServiceOracles {
    tracker: crate::auto::runtrace::SinkTaintTracker,
    sessions: std::collections::HashMap<Vec<u8>, SessionTestcase>,
}

/// The most sessions [`ServiceOracles`] keeps to attribute a confirmed sink to.
const MAX_ORACLE_SESSIONS: usize = 4096;

/// The key a runtime-oracle finding of the service is deduplicated by: its
/// rule and sink API. Each session's fuzzed bytes make a new command or path,
/// so keyed by the subject, as a replay matches it, one sink would be a
/// finding per session; the first session to reach it is the finding.
fn runtime_hit_key(hit: &OracleHit) -> String {
    format!("runtime:{}:{}", hit.rule_id, hit.api)
}

/// The bytes a session carries, as the shim matches a sink against them: its
/// messages' byte and TLV field values, in order. Integers and enum symbols
/// are framing, not text a service passes to a command or a path.
fn session_input_bytes(testcase: &SessionTestcase) -> Vec<u8> {
    let mut bytes = Vec::new();
    for message in &testcase.messages {
        for field in &message.fields {
            if let protocol_session::FieldValue::Bytes { value }
            | protocol_session::FieldValue::Tlv { value } = &field.value
            {
                bytes.extend_from_slice(value);
            }
        }
    }
    bytes
}

/// Emit a runtime-oracle finding of `testcase`: the oracle hit, with the
/// session as its testcase and the session artifacts beside it.
fn emit_runtime_hit(
    emitter: &FindingEmitter,
    testcase: &SessionTestcase,
    mut hit: OracleHit,
    config: &SessionFuzzConfig,
) -> Result<String, SessionFuzzError> {
    let serialized = testcase.to_json().map_err(SessionFuzzError::Serialize)?;
    hit.evidence.push(OracleEvidence::new(
        "state_path",
        testcase.state_path.join(" -> "),
    ));
    hit.evidence.push(OracleEvidence::new(
        "messages",
        testcase.messages.len().to_string(),
    ));
    let signature = crate::runtime_oracles::oracle_signature(&hit);
    let id = emitter.emit_oracle_hit(serialized.as_bytes(), &hit)?;
    write_session_artifacts(
        &id.0,
        &serialized,
        &hit.oracle_name,
        Some(&hit.rule_id),
        Some(&signature),
        config,
    )?;
    Ok(id.0)
}

/// Evaluate the events of the session `candidate` (its bytes `input`): emit
/// the per-run oracle hits now, and fold its sinks into the tracker the
/// campaign confirms at its end.
#[allow(clippy::too_many_arguments)]
fn observe_service_events(
    events: &[crate::auto::runtrace::RuntraceEvent],
    candidate: &SessionTestcase,
    input: &[u8],
    oracles: &mut ServiceOracles,
    emitter: &FindingEmitter,
    config: &SessionFuzzConfig,
    seen: &mut HashSet<String>,
    finding_ids: &mut Vec<String>,
) -> Result<bool, SessionFuzzError> {
    if events.is_empty() {
        return Ok(false);
    }
    let mut new_finding = false;
    for hit in crate::auto::runtrace::oracle_hits_from_events(events) {
        if seen.insert(runtime_hit_key(&hit)) {
            finding_ids.push(emit_runtime_hit(emitter, candidate, hit, config)?);
            new_finding = true;
        }
    }
    oracles.tracker.observe(events, input);
    if oracles.sessions.len() < MAX_ORACLE_SESSIONS || oracles.sessions.contains_key(input) {
        oracles
            .sessions
            .entry(input.to_vec())
            .or_insert_with(|| candidate.clone());
    }
    Ok(new_finding)
}

/// The findings of the sinks the campaign confirmed fuzz-controlled: tainted
/// by a session's bytes, never reached without them.
fn emit_confirmed_service_sinks(
    oracles: ServiceOracles,
    emitter: &FindingEmitter,
    config: &SessionFuzzConfig,
    seen: &mut HashSet<String>,
    finding_ids: &mut Vec<String>,
) -> Result<(), SessionFuzzError> {
    let ServiceOracles { tracker, sessions } = oracles;
    for confirmed in tracker.into_confirmed() {
        let Some(session) = sessions.get(&confirmed.input).or_else(|| {
            sessions
                .iter()
                .find(|(bytes, _)| bytes.starts_with(&confirmed.input))
                .map(|(_, session)| session)
        }) else {
            continue;
        };
        for hit in crate::auto::runtrace::confirmed_sink_hits(&confirmed) {
            if seen.insert(runtime_hit_key(&hit)) {
                finding_ids.push(emit_runtime_hit(emitter, session, hit, config)?);
            }
        }
    }
    Ok(())
}

/// Drive one candidate against the transport, folding both novelty channels and
/// emitting a finding (deduped by rule|oracle) on a clean-exit violation.
/// Returns the state-novelty delta, how many service edges it reached first,
/// and whether a NEW finding was emitted.
///
/// A session the target drops is a crash candidate: it is kept, driven again
/// on a new connection, and written as a finding when the target drops it at
/// the same message again. A failure to connect skips the candidate, and
/// [`MAX_CONNECT_FAILURES`] of them in a row abort the campaign; a
/// candidate-specific drive error is skipped so the loop keeps exploring.
#[allow(clippy::too_many_arguments)]
fn drive_candidate(
    candidate: &SessionTestcase,
    runner: &SessionRunner,
    transport: &mut dyn SessionTransport,
    state_novelty: &mut StateNovelty,
    code_novelty: &mut CodeCoverageNovelty,
    emitter: &FindingEmitter,
    config: &SessionFuzzConfig,
    seen: &mut HashSet<String>,
    finding_ids: &mut Vec<String>,
    tally: &mut CrashTally,
    server: Option<&mut SessionServer>,
    oracles: Option<&mut ServiceOracles>,
) -> Result<(StateNoveltyDelta, usize, bool), SessionFuzzError> {
    // Under the runtrace shim the service matches its sinks against the
    // bytes of the session in flight (#364).
    let input = session_input_bytes(candidate);
    if let Some(server) = server.as_deref() {
        server
            .publish_session_input(&input)
            .map_err(SessionFuzzError::Server)?;
    }
    // With a service bhf runs, a refused connection is the service gone: look
    // at it before counting a failure to connect.
    let (driven, refused) = match server.as_deref() {
        Some(_) => match runner.drive(&candidate.messages, transport) {
            Ok(run) => (Some(run), false),
            Err(protocol_session::RunnerError::Connect(_)) => (None, true),
            // A candidate the profile cannot drive (an encode or a response
            // error) says nothing about the service.
            Err(_) => (None, false),
        },
        None => (
            drive_counting(runner, &candidate.messages, transport, tally)?,
            false,
        ),
    };
    // A backend that runs the target per message reports its edges (#261).
    let mut new_edges = code_novelty.observe(&transport.take_coverage_edges());
    let mut oracle_finding = false;
    if let Some(server) = server {
        // The map outlives the process, so a session that crashed the service
        // still counts the code it reached.
        new_edges += code_novelty.observe(&server.coverage_edges());
        // Its events, before a restart brings the start-up of the next.
        if let Some(oracles) = oracles {
            let events = server.take_session_events();
            oracle_finding = observe_service_events(
                &events,
                candidate,
                &input,
                oracles,
                emitter,
                config,
                seen,
                finding_ids,
            )?;
        }
        let lost = refused
            || driven
                .as_ref()
                .is_some_and(|run| matches!(run.verdict, SessionVerdict::Disconnected { .. }));
        let grace = if lost {
            SERVER_EXIT_GRACE
        } else {
            Duration::ZERO
        };
        if server.exited_within(grace).is_some() {
            let blamed = match (refused, &tally.previous) {
                (true, Some(previous)) => previous.clone(),
                _ => candidate.clone(),
            };
            tally.previous = Some(candidate.clone());
            let delta = driven
                .as_ref()
                .map(|run| state_novelty.observe(&run.state_ids, &run.transitions))
                .unwrap_or_default();
            let new_finding = confirm_server_crash(
                &blamed,
                runner,
                transport,
                server,
                emitter,
                config,
                seen,
                finding_ids,
                tally,
            )?;
            return Ok((delta, new_edges, new_finding || oracle_finding));
        }
        if refused {
            drive_counting(runner, &candidate.messages, transport, tally)?;
        }
    }
    tally.previous = Some(candidate.clone());
    let Some(run) = driven else {
        return Ok((StateNoveltyDelta::default(), new_edges, oracle_finding));
    };

    let delta = state_novelty.observe(&run.state_ids, &run.transitions);

    let mut new_finding = false;
    if let SessionVerdict::Disconnected {
        step,
        message,
        error,
    } = &run.verdict
    {
        let kept = persist_disconnect(config, &run)?;
        let again = drive_counting(runner, &candidate.messages, transport, tally)?;
        let confirmed = again.is_some_and(|again| {
            matches!(again.verdict, SessionVerdict::Disconnected { step: again_step, .. } if again_step == *step)
        });
        if !confirmed {
            tally.unconfirmed += 1;
            return Ok((delta, new_edges, oracle_finding));
        }
        let _ = std::fs::remove_file(kept);
        tally.crashes += 1;
        if seen.insert(format!("{DISCONNECT_RULE}|{DISCONNECT_ORACLE}|{message}")) {
            let detail = format!(
                "the target dropped the session at message {} ({message}), and again when it \
                 was driven on a new connection: {error}",
                step + 1
            );
            let id = emit_session_finding(
                emitter,
                &run,
                DISCONNECT_ORACLE,
                Some(DISCONNECT_RULE),
                message,
                &detail,
                config,
            )?;
            finding_ids.push(id);
            new_finding = true;
        }
    }
    if let SessionVerdict::Finding {
        oracle,
        rule_id,
        message,
        detail,
    } = &run.verdict
    {
        let dedup = format!(
            "{}|{}",
            rule_id.as_deref().unwrap_or("HDF7-SESSION"),
            oracle
        );
        if seen.insert(dedup) {
            let id = emit_session_finding(
                emitter,
                &run,
                oracle,
                rule_id.as_deref(),
                message,
                detail,
                config,
            )?;
            finding_ids.push(id);
            new_finding = true;
        }
    }
    Ok((delta, new_edges, new_finding || oracle_finding))
}

/// The service exited after `blamed` ran: start it again, drive `blamed`
/// once more, and if the service exits again write the finding, from the
/// sanitizer report in its stderr when there is one. Either way the service
/// is running again for the campaign. `Ok(true)` when a new finding was
/// written.
#[allow(clippy::too_many_arguments)]
fn confirm_server_crash(
    blamed: &SessionTestcase,
    runner: &SessionRunner,
    transport: &mut dyn SessionTransport,
    server: &mut SessionServer,
    emitter: &FindingEmitter,
    config: &SessionFuzzConfig,
    seen: &mut HashSet<String>,
    finding_ids: &mut Vec<String>,
    tally: &mut CrashTally,
) -> Result<bool, SessionFuzzError> {
    server.start().map_err(SessionFuzzError::Server)?;
    tally.connect_failures = 0;
    let again = runner.drive(&blamed.messages, transport).ok();
    let exit = server.exited_within(SERVER_EXIT_GRACE);
    if exit.is_some() {
        server.start().map_err(SessionFuzzError::Server)?;
    }
    let (Some(exit), Some(run)) = (exit, again) else {
        tally.unconfirmed += 1;
        let kept = SessionRun {
            testcase: blamed.clone(),
            verdict: SessionVerdict::Clean,
            state_ids: Vec::new(),
            transitions: Vec::new(),
            sent_frames: Vec::new(),
        };
        persist_disconnect(config, &kept)?;
        return Ok(false);
    };
    tally.crashes += 1;
    let serialized = run
        .testcase
        .to_json()
        .map_err(SessionFuzzError::Serialize)?;
    let message = run
        .testcase
        .messages
        .last()
        .map_or("?", |message| message.message.as_str())
        .to_owned();
    if let Some(report) = corpus::sanitizer::parse_sanitizer_report(&exit.stderr) {
        let top = report
            .stack
            .first()
            .map_or("", |frame| frame.function.as_str());
        if !seen.insert(format!("{SERVER_CRASH_ORACLE}|{}|{top}", report.rule_id)) {
            return Ok(false);
        }
        let id = emitter.emit_sanitizer_crash_with_log(
            serialized.as_bytes(),
            &report,
            Some(exit.stderr.as_bytes()),
        )?;
        write_session_artifacts(
            &id.0,
            &serialized,
            SERVER_CRASH_ORACLE,
            Some(report.rule_id),
            None,
            config,
        )?;
        finding_ids.push(id.0);
        return Ok(true);
    }
    if !seen.insert(format!("{SERVER_EXIT_ORACLE}|{message}")) {
        return Ok(false);
    }
    let detail = format!(
        "the service ({}) exited with {} after the session, and again when the session was \
         driven on the service started again; its stderr has no sanitizer report",
        server.command(),
        exit.status
    );
    let id = emit_session_finding(
        emitter,
        &run,
        SERVER_EXIT_ORACLE,
        Some(DISCONNECT_RULE),
        &message,
        &detail,
        config,
    )?;
    finding_ids.push(id);
    Ok(true)
}

/// Drive a bounded, coverage- and state-guided session campaign against
/// `transport`, reusing the builtin [`PowerScheduler`] for seed selection and
/// `protocol_session`'s graph-gated structured mutation. Returns the run summary;
/// a transport or finding-write failure propagates as a descriptive error.
pub(crate) fn run_session_campaign(
    model: &ProtocolModel,
    transport: &mut dyn SessionTransport,
    config: &SessionFuzzConfig,
    mut server: Option<&mut SessionServer>,
) -> Result<SessionFuzzSummary, SessionFuzzError> {
    let start = Instant::now();
    let runner = SessionRunner::new(model);
    let dictionary = boundary_dictionary();
    let mut rng = MutationRng::new(config.rng_seed);
    let mut scheduler = PowerScheduler::default();
    let mut state_novelty = StateNovelty::new();
    let mut code_novelty = CodeCoverageNovelty::new();

    let emitter = FindingEmitter::with_metadata(
        config.work_dir.clone(),
        config.harness_id.clone(),
        "session".to_owned(),
        config.transport_label.clone(),
    )
    .with_mode(config.mode);

    let mut executions = 0usize;
    let mut corpus_new = 0usize;
    let mut finding_ids: Vec<String> = Vec::new();
    let mut seen_findings: HashSet<String> = HashSet::new();
    let mut tally = CrashTally::default();
    // The runtime sink oracles, when the service runs under the shim (#364).
    let mut service_oracles = server
        .as_ref()
        .is_some_and(|server| server.has_runtrace())
        .then(ServiceOracles::default);

    // --- seed phase: drive every seed once; seeds are always corpus members. ---
    let seed_count = config.seeds.len();
    for seed in &config.seeds {
        if should_stop(
            executions,
            config.iterations,
            start,
            config.time_budget,
            finding_ids.len(),
            config.stop_after_findings,
        ) {
            break;
        }
        let serialized = seed.to_json().map_err(SessionFuzzError::Serialize)?;
        let (delta, new_edges, _) = drive_candidate(
            seed,
            &runner,
            transport,
            &mut state_novelty,
            &mut code_novelty,
            &emitter,
            config,
            &mut seen_findings,
            &mut finding_ids,
            &mut tally,
            server.as_deref_mut(),
            service_oracles.as_mut(),
        )?;
        executions += 1;
        scheduler
            .insert_with_feedback(serialized.into_bytes(), schedule_feedback(delta, new_edges));
    }

    // --- mutation phase: scheduler-driven structured mutation. ---
    'outer: loop {
        if should_stop(
            executions,
            config.iterations,
            start,
            config.time_budget,
            finding_ids.len(),
            config.stop_after_findings,
        ) {
            break;
        }
        let Some(scheduled) = scheduler.select_next() else {
            break; // no corpus — nothing to mutate
        };
        let Ok(parent) = std::str::from_utf8(&scheduled.bytes)
            .map_err(|_| ())
            .and_then(|json| SessionTestcase::from_json(json).map_err(|_| ()))
        else {
            continue; // a corpus seed that is not valid session JSON — skip
        };

        let children = scheduled.energy.max(1);
        for _ in 0..children {
            if should_stop(
                executions,
                config.iterations,
                start,
                config.time_budget,
                finding_ids.len(),
                config.stop_after_findings,
            ) {
                break 'outer;
            }
            let candidate = mutate_one(&parent, model, &mut rng, &dictionary, config.max_messages);
            let serialized = candidate.to_json().map_err(SessionFuzzError::Serialize)?;
            let (delta, new_edges, _) = drive_candidate(
                &candidate,
                &runner,
                transport,
                &mut state_novelty,
                &mut code_novelty,
                &emitter,
                config,
                &mut seen_findings,
                &mut finding_ids,
                &mut tally,
                server.as_deref_mut(),
                service_oracles.as_mut(),
            )?;
            executions += 1;
            // A new protocol state, or new code in the service (#363).
            if delta.is_novel() || new_edges > 0 {
                scheduler.insert_with_feedback(
                    serialized.into_bytes(),
                    schedule_feedback(delta, new_edges),
                );
                corpus_new += 1;
            }
        }
    }

    if let Some(oracles) = service_oracles {
        emit_confirmed_service_sinks(
            oracles,
            &emitter,
            config,
            &mut seen_findings,
            &mut finding_ids,
        )?;
    }

    Ok(SessionFuzzSummary {
        schema_version: 1,
        harness_id: config.harness_id.clone(),
        engine: "session".to_owned(),
        profile_sha256: config.profile_sha256.clone(),
        transport: config.transport_label.clone(),
        reset_fidelity: config.reset_fidelity(),
        framing: model.framing().label(),
        seeds: seed_count,
        executions,
        corpus_new,
        coverage_edges: code_novelty.edges_covered(),
        coverage_blocks: 0,
        coverage_source: match server.as_ref().is_some_and(|server| server.has_coverage()) {
            true if code_novelty.edges_covered() > 0 => "service",
            // A map the service never wrote: it was not built with
            // `c_runtime/bhf_service_cov.c` and SanitizerCoverage.
            true => "uninstrumented_service",
            false if code_novelty.edges_covered() > 0 => "target",
            false => "none",
        }
        .to_owned(),
        states_covered: state_novelty.states_covered(),
        transitions_covered: state_novelty.transitions_covered(),
        crashes: tally.crashes,
        unconfirmed_disconnects: tally.unconfirmed,
        server_starts: server.as_ref().map_or(0, |server| server.starts()),
        findings: finding_ids,
        elapsed_secs: start.elapsed().as_secs_f64(),
    })
}

/// Emit one clean-exit session finding: build an [`OracleHit`] from the profile
/// oracle verdict, write it through the existing finding emitter (testcase.bin =
/// the serialized session), then write the `session.json` artifact and the
/// self-contained `session_meta.json` sidecar into the finding dir.
#[allow(clippy::too_many_arguments)]
fn emit_session_finding(
    emitter: &FindingEmitter,
    run: &SessionRun,
    oracle: &str,
    rule_id: Option<&str>,
    message: &str,
    detail: &str,
    config: &SessionFuzzConfig,
) -> Result<String, SessionFuzzError> {
    let serialized = run
        .testcase
        .to_json()
        .map_err(SessionFuzzError::Serialize)?;

    let mut evidence = vec![
        OracleEvidence::new("state_path", run.testcase.state_path.join(" -> ")),
        OracleEvidence::new("messages", run.testcase.messages.len().to_string()),
        OracleEvidence::new("detail", detail.to_owned()),
    ];
    for (source, value) in run.testcase.bindings.iter() {
        evidence.push(OracleEvidence::new(source.clone(), format_bound(value)));
    }

    let disconnect = oracle == DISCONNECT_ORACLE || oracle == SERVER_EXIT_ORACLE;
    let hit = OracleHit {
        oracle_name: oracle.to_owned(),
        rule_id: rule_id.unwrap_or("HDF7-SESSION").to_owned(),
        category: if disconnect { "crash" } else { "logic-bug" }.to_owned(),
        api: message.to_owned(),
        message: if oracle == SERVER_EXIT_ORACLE {
            format!("the service exited during the protocol session: {detail}")
        } else if disconnect {
            format!("the target dropped the protocol session: {detail}")
        } else {
            format!("protocol session reached a clean-exit violation: {detail}")
        },
        evidence,
    };

    let id = emitter.emit_oracle_hit(serialized.as_bytes(), &hit)?;
    write_session_artifacts(&id.0, &serialized, oracle, rule_id, None, config)?;
    Ok(id.0)
}

/// Write a session finding's `session.json` and `session_meta.json` into its
/// finding dir.
fn write_session_artifacts(
    id: &str,
    serialized: &str,
    oracle: &str,
    rule_id: Option<&str>,
    runtime_signature: Option<&str>,
    config: &SessionFuzzConfig,
) -> Result<(), SessionFuzzError> {
    let finding_dir = corpus::layout::finding_dir(&config.work_dir, id);
    write_artifact(&finding_dir.join(SESSION_ARTIFACT), serialized.as_bytes())?;
    let meta = SessionArtifactMeta {
        schema: SESSION_ARTIFACT_SCHEMA.to_owned(),
        profile_sha256: config.profile_sha256.clone(),
        profile_toml: config.profile_toml.clone(),
        transport: config.transport_label.clone(),
        transport_kind: config.transport_kind.clone(),
        reset: config.reset.as_str().to_owned(),
        reset_fidelity: config.reset_fidelity(),
        rule_id: rule_id.map(str::to_owned),
        oracle: oracle.to_owned(),
        reply_timeout_ms: config
            .reply_timeout
            .map(|timeout| u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX)),
        server_cmd: config.server_cmd.clone(),
        coverage_map: config.coverage_map.clone(),
        runtime_signature: runtime_signature.map(str::to_owned),
        runtrace_mode: runtime_signature.map(|_| config.mode.to_string().to_ascii_lowercase()),
    };
    let meta_bytes = serde_json::to_vec_pretty(&meta).map_err(SessionFuzzError::Serialize)?;
    write_artifact(&finding_dir.join(SESSION_META), &meta_bytes)
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

fn write_artifact(path: &Path, bytes: &[u8]) -> Result<(), SessionFuzzError> {
    std::fs::write(path, bytes).map_err(|source| SessionFuzzError::Io {
        path: path.display().to_string(),
        source,
    })
}

fn format_bound(value: &BoundValue) -> String {
    match value {
        BoundValue::Int { value } => format!("0x{value:x}"),
        BoundValue::Enum { symbol, code } => format!("{symbol}(0x{code:x})"),
        BoundValue::Bytes { value } => format!("{} bytes", value.len()),
    }
}

// ---------------------------------------------------------------------------
// Replay / minimize of a session finding
// ---------------------------------------------------------------------------

/// Whether a finding directory carries a session artifact (so `bhf replay` /
/// `bhf minimize` take the session path automatically, leaving opaque-input
/// findings untouched).
pub(crate) fn is_session_finding(finding_dir: &Path) -> bool {
    finding_dir.join(SESSION_ARTIFACT).is_file()
}

/// Load a session finding's recorded testcase, its profile-derived model, and a
/// freshly-built transport from the self-contained metadata sidecar.
fn load_session_finding(
    finding_dir: &Path,
) -> Result<(SessionTestcase, ProtocolModel, SessionArtifactMeta), String> {
    let artifact = finding_dir.join(SESSION_ARTIFACT);
    let testcase_json = std::fs::read_to_string(&artifact)
        .map_err(|e| format!("read {}: {e}", artifact.display()))?;
    let testcase = SessionTestcase::from_json(&testcase_json)
        .map_err(|e| format!("parse {}: {e}", artifact.display()))?;

    let meta_path = finding_dir.join(SESSION_META);
    let meta_json = std::fs::read_to_string(&meta_path)
        .map_err(|e| format!("read {}: {e}", meta_path.display()))?;
    let meta: SessionArtifactMeta = serde_json::from_str(&meta_json)
        .map_err(|e| format!("parse {}: {e}", meta_path.display()))?;

    let profile = Profile::from_toml(&meta.profile_toml)
        .map_err(|e| format!("rebuild profile from finding metadata: {e}"))?;
    let model =
        ProtocolModel::from_profile(&profile).map_err(|e| format!("compile profile model: {e}"))?;

    Ok((testcase, model, meta))
}

fn build_live_transport(
    meta: &SessionArtifactMeta,
    model: &ProtocolModel,
) -> Result<LiveTransport, String> {
    let plan = SessionTransportPlan::parse_with_map(&meta.transport, meta.coverage_map.as_deref())
        .map_err(|e| e.to_string())?;
    let reset = SessionResetMode::parse(&meta.reset)?;
    plan.into_transport(
        reset,
        model.framing().clone(),
        meta.reply_timeout_ms.map(Duration::from_millis),
    )
}

/// `bhf replay` of a session finding: re-drive the recorded session against a
/// freshly reset transport (re-capturing a fresh handle) and report whether it
/// still reaches the oracle verdict.
pub(crate) fn replay_session_outcome(
    finding_dir: &Path,
) -> Result<crate::replay::LaneReplay, String> {
    let (testcase, model, meta) = load_session_finding(finding_dir)?;
    let mut transport = build_live_transport(&meta, &model)?;
    let rule = meta.rule_id.as_deref().unwrap_or("<none>");
    if let (Some(signature), Some(command)) = (&meta.runtime_signature, &meta.server_cmd) {
        return replay_runtime_oracle(&testcase, &model, &meta, signature, command, &mut transport);
    }
    if let Some(mut server) = finding_server(&meta)? {
        let runner = SessionRunner::new(&model);
        let (_, exit) = drive_against_server(&runner, &testcase, &mut transport, &mut server.0)?;
        let matched = exit
            .as_ref()
            .is_some_and(|exit| server_exit_reproduces(exit, &meta));
        let replayed = match &exit {
            Some(exit) => format!(
                "the service exited with {}{}",
                exit.status,
                corpus::sanitizer::parse_sanitizer_report(&exit.stderr)
                    .map(|report| format!(", rule {}", report.rule_id))
                    .unwrap_or_default()
            ),
            None => "the service did not exit".to_owned(),
        };
        return Ok(crate::replay::LaneReplay {
            lane: "session",
            matched,
            status_line: if matched {
                "MATCH".to_owned()
            } else {
                "MISMATCH: the recorded session no longer makes the service exit".to_owned()
            },
            compared: format!("session oracle {} with rule {rule}", meta.oracle),
            differences: if matched {
                Vec::new()
            } else {
                vec![format!(
                    "verdict: recorded oracle {} with rule {rule}, replayed {replayed}",
                    meta.oracle
                )]
            },
            details: vec![
                crate::replay::Detail::new(
                    "transport",
                    format!("{} (reset {})", meta.transport, meta.reset),
                ),
                crate::replay::Detail::new("service", server.0.command().to_owned()),
            ],
            history: "replay",
            ..Default::default()
        });
    }
    let verdict = replay_verdict(&model, &testcase, &mut transport)?;
    let matched = verdict_reproduces(&verdict, &meta);
    let replayed = match &verdict {
        SessionVerdict::Finding {
            oracle, rule_id, ..
        } => format!(
            "oracle {oracle} fired with rule {}",
            rule_id.as_deref().unwrap_or("<none>")
        ),
        SessionVerdict::Disconnected { step, message, .. } => format!(
            "the target dropped the session at message {} ({message})",
            step + 1
        ),
        SessionVerdict::Clean => "no oracle fired".to_owned(),
    };
    Ok(crate::replay::LaneReplay {
        lane: "session",
        matched,
        status_line: if matched {
            "MATCH".to_owned()
        } else {
            "MISMATCH: the recorded session no longer reaches the oracle verdict".to_owned()
        },
        compared: format!("session oracle {} with rule {rule}", meta.oracle),
        differences: if matched {
            Vec::new()
        } else {
            vec![format!(
                "verdict: recorded oracle {} with rule {rule}, replayed {replayed}",
                meta.oracle
            )]
        },
        details: vec![crate::replay::Detail::new(
            "transport",
            format!("{} (reset {})", meta.transport, meta.reset),
        )],
        history: "replay",
        ..Default::default()
    })
}

/// `bhf replay` of a runtime-oracle finding of the service (#364): start the
/// service under the runtrace shim again, drive the session with its bytes as
/// the shim's input, and look for the recorded hit among its events' hits.
fn replay_runtime_oracle(
    testcase: &SessionTestcase,
    model: &ProtocolModel,
    meta: &SessionArtifactMeta,
    signature: &str,
    command: &str,
    transport: &mut dyn SessionTransport,
) -> Result<crate::replay::LaneReplay, String> {
    use crate::runtime_oracles::{RuntimeOracleMode, RuntimeOracles};
    let mode = meta.runtrace_mode.as_deref().unwrap_or("reporting");
    let oracles = RuntimeOracles::resolve(RuntimeOracleMode::On, mode)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "the runtrace shim is unavailable".to_owned())?;
    let (host, port, udp) = SessionTransportPlan::parse(&meta.transport)
        .map_err(|e| e.to_string())?
        .endpoint()?;
    let dir = tempfile::Builder::new()
        .prefix("bhf-session-server-")
        .tempdir()
        .map_err(|e| format!("create a dir for the service's logs: {e}"))?;
    let mut server = SessionServer::new(command.to_owned(), host, port, udp, dir.path())
        .with_runtime_oracles(&oracles, dir.path())?;
    server.start()?;
    let input = session_input_bytes(testcase);
    server.publish_session_input(&input)?;
    let _ = SessionRunner::new(model).replay(testcase, transport);
    let events = server.take_session_events();
    server.stop();
    let mut hits = crate::auto::runtrace::oracle_hits_from_events(&events);
    let mut tracker = crate::auto::runtrace::SinkTaintTracker::default();
    tracker.observe(&events, &input);
    for confirmed in tracker.into_confirmed() {
        hits.extend(crate::auto::runtrace::confirmed_sink_hits(&confirmed));
    }
    let matched = hits
        .iter()
        .any(|hit| crate::runtime_oracles::oracle_signature(hit) == signature);
    let rule = meta.rule_id.as_deref().unwrap_or("<none>");
    let replayed: Vec<String> = hits
        .iter()
        .map(|hit| format!("{} ({})", hit.oracle_name, hit.rule_id))
        .collect();
    Ok(crate::replay::LaneReplay {
        lane: "session",
        matched,
        status_line: if matched {
            "MATCH".to_owned()
        } else {
            "MISMATCH: the recorded session no longer reaches the service's sink".to_owned()
        },
        compared: format!(
            "runtime oracle {} with rule {rule} in the service",
            meta.oracle
        ),
        differences: if matched {
            Vec::new()
        } else {
            vec![format!(
                "verdict: recorded oracle {} with rule {rule}, replayed {}",
                meta.oracle,
                if replayed.is_empty() {
                    "no runtime oracle hit".to_owned()
                } else {
                    replayed.join(", ")
                }
            )]
        },
        details: vec![
            crate::replay::Detail::new(
                "transport",
                format!("{} (reset {})", meta.transport, meta.reset),
            ),
            crate::replay::Detail::new("service", command.to_owned()),
        ],
        history: "replay",
        ..Default::default()
    })
}

/// Whether `verdict` reproduces the SAME oracle finding that the metadata
/// recorded, by both oracle name and `rule_id`.
///
/// Replay and minimize must not accept *any* oracle firing as a reproduction:
/// under a multi-oracle profile (`[[oracle]]` is a list) a session recorded for
/// oracle `O1` can re-drive into a finding for a different oracle `O2`, which
/// would falsely "confirm" `O1` — or, in minimize, let delta-debugging shrink
/// away the very structure that triggered `O1` because a smaller sequence still
/// trips `O2`. Gating on the recorded oracle keeps each finding honest to the
/// oracle it was emitted for.
fn verdict_reproduces(verdict: &SessionVerdict, meta: &SessionArtifactMeta) -> bool {
    match verdict {
        SessionVerdict::Finding {
            oracle, rule_id, ..
        } => *oracle == meta.oracle && *rule_id == meta.rule_id,
        SessionVerdict::Disconnected { .. } => meta.oracle == DISCONNECT_ORACLE,
        SessionVerdict::Clean => false,
    }
}

/// The service a finding's run started, ready to start again for a replay or
/// a minimization, with a scratch dir for its logs; `None` when bhf did not
/// run the service or the finding is not of its exit.
fn finding_server(
    meta: &SessionArtifactMeta,
) -> Result<Option<(SessionServer, tempfile::TempDir)>, String> {
    let Some(command) = &meta.server_cmd else {
        return Ok(None);
    };
    if meta.oracle != SERVER_CRASH_ORACLE && meta.oracle != SERVER_EXIT_ORACLE {
        return Ok(None);
    }
    let (host, port, udp) = SessionTransportPlan::parse(&meta.transport)
        .map_err(|e| e.to_string())?
        .endpoint()?;
    let logs = tempfile::Builder::new()
        .prefix("bhf-session-server-")
        .tempdir()
        .map_err(|e| format!("create a dir for the service's logs: {e}"))?;
    let server = SessionServer::new(command.clone(), host, port, udp, logs.path());
    Ok(Some((server, logs)))
}

/// Start the service, drive `testcase` against it, and return the run and
/// how the service exited, if it did.
fn drive_against_server(
    runner: &SessionRunner,
    testcase: &SessionTestcase,
    transport: &mut dyn SessionTransport,
    server: &mut SessionServer,
) -> Result<(Option<SessionRun>, Option<ServerExit>), String> {
    server.start()?;
    let run = runner.replay(testcase, transport).ok();
    let exit = server.exited_within(SERVER_EXIT_GRACE);
    server.stop();
    Ok((run, exit))
}

/// Whether the service's exit is the one a finding recorded: for a
/// sanitizer report, one with the same rule.
fn server_exit_reproduces(exit: &ServerExit, meta: &SessionArtifactMeta) -> bool {
    match meta.oracle.as_str() {
        SERVER_CRASH_ORACLE => corpus::sanitizer::parse_sanitizer_report(&exit.stderr)
            .is_some_and(|report| Some(report.rule_id) == meta.rule_id.as_deref()),
        SERVER_EXIT_ORACLE => true,
        _ => false,
    }
}

/// Re-drive `testcase` against `transport` and return the verdict it reaches.
fn replay_verdict(
    model: &ProtocolModel,
    testcase: &SessionTestcase,
    transport: &mut dyn SessionTransport,
) -> Result<SessionVerdict, String> {
    let runner = SessionRunner::new(model);
    let run = runner
        .replay(testcase, transport)
        .map_err(|e| format!("replay session: {e}"))?;
    Ok(run.verdict)
}

/// Re-drive `testcase` against `transport` and report whether it reproduces the
/// recorded oracle finding (not merely *some* finding).
#[cfg(test)]
fn replay_reproduces(
    model: &ProtocolModel,
    testcase: &SessionTestcase,
    meta: &SessionArtifactMeta,
    transport: &mut dyn SessionTransport,
) -> Result<bool, String> {
    Ok(verdict_reproduces(
        &replay_verdict(model, testcase, transport)?,
        meta,
    ))
}

/// `bhf minimize` of a session finding: shrink the message sequence and the
/// bytes fields via the crate's minimizer (re-repairing computed fields and
/// re-resolving bindings on every candidate), keeping the finding reproducing,
/// then rewrite the smaller `session.json`.
pub(crate) fn minimize_session_finding(finding_dir: &Path) -> i32 {
    match minimize_session_inner(finding_dir) {
        Ok((original, minimized, reproduces)) => {
            println!(
                "SESSION-MINIMIZED original_messages={original} minimized_messages={minimized} reduced={} reproduces={reproduces} path={SESSION_ARTIFACT}",
                minimized < original
            );
            0
        }
        Err(error) => {
            bhfeprintln!("error: {error}");
            1
        }
    }
}

fn minimize_session_inner(finding_dir: &Path) -> Result<(usize, usize, bool), String> {
    let (testcase, model, meta) = load_session_finding(finding_dir)?;
    let mut server = finding_server(&meta)?;
    let (original_len, run, reproduces) = minimize_session_core(
        &model,
        &testcase,
        &meta,
        || build_live_transport(&meta, &model),
        server.as_mut().map(|(server, _)| server),
    )?;
    let minimized_len = run.testcase.messages.len();

    let serialized = run
        .testcase
        .to_json()
        .map_err(|e| format!("serialize minimized session: {e}"))?;
    let artifact = finding_dir.join(SESSION_ARTIFACT);
    std::fs::write(&artifact, serialized.as_bytes())
        .map_err(|e| format!("write {}: {e}", artifact.display()))?;
    // Keep the finding's primary testcase in step with the minimized repro.
    let testcase_bin = finding_dir.join("testcase.bin");
    if testcase_bin.exists() {
        std::fs::write(&testcase_bin, serialized.as_bytes())
            .map_err(|e| format!("write {}: {e}", testcase_bin.display()))?;
    }

    Ok((original_len, minimized_len, reproduces))
}

/// Shrink `testcase` while it keeps reproducing the recorded oracle finding,
/// then drive the minimized sequence once more for fresh evidence. Returns the
/// original message count, that final [`SessionRun`], and whether the minimized
/// sequence still reproduces the recorded oracle.
///
/// `make_transport` yields a *freshly reset* transport per drive, so the
/// dynamic binding is re-resolved and the computed fields re-repaired on every
/// candidate. Factoring the transport out keeps the oracle-gating logic
/// testable against an in-memory transport instead of a live socket.
fn minimize_session_core<T, F>(
    model: &ProtocolModel,
    testcase: &SessionTestcase,
    meta: &SessionArtifactMeta,
    mut make_transport: F,
    mut server: Option<&mut SessionServer>,
) -> Result<(usize, SessionRun, bool), String>
where
    T: SessionTransport,
    F: FnMut() -> Result<T, String>,
{
    let runner = SessionRunner::new(model);
    let original_len = testcase.messages.len();

    // Drive one candidate on a fresh transport (fresh handle) and, for a
    // finding of the service's exit, a service started again; only the
    // RECORDED oracle counts as still reproducing — a smaller sequence that
    // trips a different oracle must not be accepted.
    let mut drive = |candidate: &SessionTestcase| -> Result<(Option<SessionRun>, bool), String> {
        let mut transport = make_transport()?;
        match server.as_deref_mut() {
            Some(server) => {
                let (run, exit) = drive_against_server(&runner, candidate, &mut transport, server)?;
                let reproduces = exit
                    .as_ref()
                    .is_some_and(|exit| server_exit_reproduces(exit, meta));
                Ok((run, reproduces))
            }
            None => {
                let run = runner
                    .replay(candidate, &mut transport)
                    .map_err(|e| format!("replay session: {e}"))?;
                let reproduces = verdict_reproduces(&run.verdict, meta);
                Ok((Some(run), reproduces))
            }
        }
    };

    // Baseline: the recorded session must still reproduce the SAME recorded
    // oracle before we minimize it.
    let (_, reproduces) = drive(testcase).map_err(|e| format!("baseline {e}"))?;
    if !reproduces {
        return Err("the recorded session no longer reproduces; refusing to minimize".to_owned());
    }

    let minimized = runner.minimize(testcase, |candidate| {
        drive(candidate).is_ok_and(|(_, reproduces)| reproduces)
    });

    // Re-drive the minimized testcase once to capture its fresh evidence.
    let (run, reproduces) = drive(&minimized).map_err(|e| format!("drive minimized {e}"))?;
    let run = run.ok_or_else(|| "drive minimized session: it did not connect".to_owned())?;
    Ok((original_len, run, reproduces))
}

// ---------------------------------------------------------------------------
// CLI entry
// ---------------------------------------------------------------------------

/// `bhf fuzz --protocol-profile <PATH>` entry point. Loads and compiles the
/// profile, builds the transport, synthesizes the valid seed session, runs the
/// bounded campaign, and prints the JSON summary.
pub(crate) fn run(args: FuzzArgs) -> i32 {
    match run_inner(args) {
        Ok(summary) => match serde_json::to_string_pretty(&summary) {
            Ok(json) => {
                println!("{json}");
                0
            }
            Err(error) => {
                crate::bhfeprintln!("failed to render session-fuzz summary: {error}");
                1
            }
        },
        Err(code) => code,
    }
}

fn run_inner(args: FuzzArgs) -> Result<SessionFuzzSummary, i32> {
    let profile_path = args
        .protocol_profile
        .as_deref()
        .expect("run() is only reached when --protocol-profile is set");

    let profile_toml = std::fs::read_to_string(profile_path).map_err(|error| {
        crate::bhfeprintln!(
            "bhf fuzz --protocol-profile: read {}: {error}",
            profile_path.display()
        );
        3
    })?;
    let profile = Profile::from_toml(&profile_toml).map_err(|error| {
        crate::bhfeprintln!("bhf fuzz --protocol-profile: {error}");
        2
    })?;
    let model = ProtocolModel::from_profile(&profile).map_err(|error| {
        crate::bhfeprintln!("bhf fuzz --protocol-profile: {error}");
        2
    })?;

    let spec = args.session_transport.as_deref().ok_or_else(|| {
        crate::bhfeprintln!(
            "bhf fuzz --protocol-profile requires --session-transport <SPEC> (e.g. tcp:HOST:PORT)"
        );
        2
    })?;
    let plan = SessionTransportPlan::parse_with_map(spec, args.transport_coverage_map.as_deref())
        .map_err(|error| {
        crate::bhfeprintln!("bhf fuzz --session-transport: {error}");
        2
    })?;
    let transport_label = plan.label();
    let transport_kind = plan.kind().to_owned();
    let mut server = match args.session_server_cmd.as_deref() {
        Some(command) => {
            let (host, port, udp) = plan.endpoint().map_err(|error| {
                crate::bhfeprintln!("bhf fuzz: {error}");
                2
            })?;
            let mut server = SessionServer::new(
                command.to_owned(),
                host,
                port,
                udp,
                &args.work_dir.join("session_server"),
            )
            .with_coverage(&args.work_dir)
            .map_err(|error| {
                crate::bhfeprintln!("bhf fuzz --session-server-cmd: {error}");
                2
            })?;
            // `--runtime-oracles` runs the service under the runtrace shim (#364).
            let mode_label = args.mode.to_string().to_ascii_lowercase();
            let oracles =
                crate::runtime_oracles::RuntimeOracles::resolve(args.runtime_oracles, &mode_label)
                    .map_err(|error| {
                        crate::bhfeprintln!("bhf fuzz --runtime-oracles: {error}");
                        2
                    })?;
            if let Some(oracles) = &oracles {
                server = server
                    .with_runtime_oracles(oracles, &args.work_dir.join("session_server"))
                    .map_err(|error| {
                        crate::bhfeprintln!("bhf fuzz --session-server-cmd: {error}");
                        2
                    })?;
            }
            server.start().map_err(|error| {
                crate::bhfeprintln!("bhf fuzz --session-server-cmd: {error}");
                2
            })?;
            Some(server)
        }
        None => None,
    };
    let mut transport = plan
        .into_transport(
            args.session_reset,
            model.framing().clone(),
            args.session_reply_timeout,
        )
        .map_err(|error| {
            crate::bhfeprintln!("bhf fuzz: {error}");
            2
        })?;

    let seeds = seed_sessions(&model);
    if seeds.is_empty() {
        crate::bhfeprintln!(
            "bhf fuzz --protocol-profile: the profile has no legal seed session (no message is \
             reachable from the start state)"
        );
        return Err(2);
    }

    let config = SessionFuzzConfig {
        work_dir: args.work_dir.clone(),
        harness_id: args.harness.clone(),
        profile_sha256: model.profile_sha256().to_owned(),
        profile_toml,
        transport_label,
        transport_kind,
        reset: args.session_reset,
        reply_timeout: args.session_reply_timeout,
        server_cmd: args.session_server_cmd.clone(),
        coverage_map: args.transport_coverage_map.clone(),
        max_messages: args.max_session_messages,
        seeds,
        iterations: args.effective_iterations(),
        time_budget: args.time,
        rng_seed: args.rng_seed,
        stop_after_findings: args.stop_after_findings,
        mode: args.mode,
    };

    run_session_campaign(&model, &mut transport, &config, server.as_mut()).map_err(|error| {
        crate::bhfeprintln!("bhf fuzz --protocol-profile: {error}");
        1
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuzz_engine_builtin::crc32;

    const TOY: &str = include_str!("../../protocol_session/tests/fixtures/toy-open-write.toml");

    fn toy_model() -> ProtocolModel {
        ProtocolModel::from_profile(&Profile::from_toml(TOY).expect("parse")).expect("compile")
    }

    // --- an in-memory toy OPEN/WRITE service behind the transport seam -------
    // Mirrors the real vertical-slice service: OPEN issues a fresh per-session
    // handle (different after every reset); a WRITE through a handle whose OPEN
    // path escaped the sandbox ("..") returns the boundary status 0xEF.
    struct ToyService {
        session: u32,
        current_handle: Option<u32>,
        tainted: bool,
        open_count: u32,
    }

    impl ToyService {
        fn new() -> Self {
            Self {
                session: 0,
                current_handle: None,
                tainted: false,
                open_count: 0,
            }
        }

        fn base(&self) -> u32 {
            self.session
                .wrapping_mul(0x0100_0000)
                .wrapping_add(0x00AB_CD01)
        }
    }

    fn be16(buf: &[u8], at: usize) -> Option<usize> {
        let s = buf.get(at..at + 2)?;
        Some(usize::from(u16::from_be_bytes([s[0], s[1]])))
    }

    fn be32(buf: &[u8], at: usize) -> Option<u32> {
        let s = buf.get(at..at + 4)?;
        Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    impl SessionTransport for ToyService {
        fn send_request(&mut self, req: &[u8]) -> Result<Vec<u8>, TransportError> {
            let reject = || Ok(vec![0x01]);
            let Some(&op) = req.first() else {
                return reject();
            };
            match op {
                1 => {
                    let Some(len) = be16(req, 2) else {
                        return reject();
                    };
                    let path_end = 4 + len;
                    let crc_end = path_end + 4;
                    if req.len() < crc_end {
                        return reject();
                    }
                    if be32(req, path_end).unwrap() != crc32(&req[0..path_end]) {
                        return Ok(vec![0, 0, 0, 0]);
                    }
                    self.tainted = req[4..path_end].windows(2).any(|w| w == b"..");
                    let handle = self.base().wrapping_add(self.open_count);
                    self.open_count = self.open_count.wrapping_add(1);
                    self.current_handle = Some(handle);
                    Ok(handle.to_be_bytes().to_vec())
                }
                2 => {
                    let Some(handle) = be32(req, 1) else {
                        return reject();
                    };
                    let Some(len) = be16(req, 5) else {
                        return reject();
                    };
                    let data_end = 7 + len;
                    let crc_end = data_end + 4;
                    if req.len() < crc_end {
                        return reject();
                    }
                    if be32(req, data_end).unwrap() != crc32(&req[0..data_end]) {
                        return reject();
                    }
                    if self.current_handle == Some(handle) {
                        if self.tainted {
                            Ok(vec![0xEF])
                        } else {
                            Ok(vec![0x00])
                        }
                    } else {
                        Ok(vec![0x01])
                    }
                }
                _ => reject(),
            }
        }

        fn reset(&mut self) -> Result<(), TransportError> {
            self.session = self.session.wrapping_add(1);
            self.current_handle = None;
            self.tainted = false;
            self.open_count = 0;
            Ok(())
        }
    }

    fn tmp_work_dir(tag: &str) -> crate::test_support::TestDir {
        crate::test_support::TestDir::new(&format!("session-fuzz-{tag}"))
    }

    fn config(model: &ProtocolModel, work_dir: PathBuf, iterations: usize) -> SessionFuzzConfig {
        SessionFuzzConfig {
            work_dir,
            harness_id: "H-session".to_owned(),
            profile_sha256: model.profile_sha256().to_owned(),
            profile_toml: TOY.to_owned(),
            transport_label: "scripted".to_owned(),
            transport_kind: "scripted".to_owned(),
            reset: SessionResetMode::Reconnect,
            reply_timeout: None,
            server_cmd: None,
            coverage_map: None,
            max_messages: 64,
            seeds: seed_sessions(model),
            iterations,
            time_budget: None,
            rng_seed: 0x00C0_FFEE_D00D,
            stop_after_findings: None,
            mode: actionability::RunMode::Reporting,
        }
    }

    // `FuzzArgs` is a `clap::Args` group; wrap it in a `Parser` to parse a
    // `bhf fuzz`-style argument vector in isolation.
    #[derive(clap::Parser)]
    struct FuzzArgsHarness {
        #[command(flatten)]
        fuzz: FuzzArgs,
    }

    #[test]
    fn session_path_is_off_by_default_and_opt_in() {
        use clap::Parser;

        let default = FuzzArgsHarness::parse_from(["fuzz", "workdir", "--harness", "H-1"]).fuzz;
        assert!(default.protocol_profile.is_none());
        assert!(
            !should_use_session(&default),
            "the default flow must not route through the session lane"
        );

        let with_profile = FuzzArgsHarness::parse_from([
            "fuzz",
            "workdir",
            "--harness",
            "H-1",
            "--protocol-profile",
            "/some/profile.toml",
        ])
        .fuzz;
        assert_eq!(
            with_profile.protocol_profile.as_deref(),
            Some(Path::new("/some/profile.toml"))
        );
        assert!(should_use_session(&with_profile));
        // The reset default is reconnect and the message cap defaults to 64.
        assert_eq!(with_profile.session_reset, SessionResetMode::Reconnect);
        assert_eq!(with_profile.max_session_messages, 64);
    }

    #[test]
    fn parses_tcp_transport_spec() {
        let plan = SessionTransportPlan::parse("tcp:127.0.0.1:9000").unwrap();
        assert_eq!(
            plan,
            SessionTransportPlan::Tcp {
                host: "127.0.0.1".to_owned(),
                port: 9000
            }
        );
        assert_eq!(plan.label(), "tcp:127.0.0.1:9000");
        assert_eq!(plan.kind(), "tcp");
    }

    #[test]
    fn transport_spec_errors_are_descriptive() {
        assert!(matches!(
            SessionTransportPlan::parse("   ").unwrap_err(),
            SessionSpecError::Empty
        ));
        match SessionTransportPlan::parse("carrierpigeon:host:1").unwrap_err() {
            SessionSpecError::UnknownBackend { backend } => assert_eq!(backend, "carrierpigeon"),
            other => panic!("expected UnknownBackend, got {other}"),
        }
        assert!(SessionTransportPlan::parse("tcp:localhost")
            .unwrap_err()
            .to_string()
            .contains("HOST:PORT"));
        assert!(SessionTransportPlan::parse("tcp:localhost:0")
            .unwrap_err()
            .to_string()
            .contains("port"));
    }

    #[test]
    fn seed_session_is_a_legal_ref_satisfying_walk() {
        let model = toy_model();
        let seeds = seed_sessions(&model);
        assert_eq!(seeds.len(), 1);
        // The synthesized seed is the ordinary valid OPEN,WRITE session: OPEN
        // produces the handle WRITE references, in a legal order.
        assert_eq!(seeds[0].message_names(), vec!["OPEN", "WRITE"]);
    }

    #[test]
    fn loop_reports_code_and_state_coverage_separately() {
        // Seed with just OPEN (one transition); the campaign's structural
        // mutation discovers a second transition, so the STATE channel grows
        // while the CODE channel stays an honestly-reported, distinct zero.
        let model = toy_model();
        let work_dir = tmp_work_dir("separate-novelty");
        let mut cfg = config(&model, work_dir.to_path_buf(), 3000);
        cfg.seeds = vec![SessionTestcase::from_messages(
            model.profile_sha256(),
            vec![protocol_session::MessageInstance::from_seed(
                model.message("OPEN").unwrap(),
            )],
        )];

        let mut service = ToyService::new();
        let summary = run_session_campaign(&model, &mut service, &cfg, None).unwrap();

        assert!(
            summary.transitions_covered >= 2,
            "structural mutation must reach a new transition: {summary:?}"
        );
        assert!(summary.states_covered >= 2, "start + opened visited");
        // Two DISTINCT channels: the code channel is present and (for this
        // edge-less transport) honestly zero, never merged into the state one.
        assert_eq!(summary.coverage_edges, 0);
        assert_eq!(summary.coverage_blocks, 0);

        std::fs::remove_dir_all(&work_dir).ok();
    }

    #[test]
    fn summary_records_profile_hash_and_reset_fidelity() {
        let model = toy_model();
        let work_dir = tmp_work_dir("hash-fidelity");
        let cfg = config(&model, work_dir.to_path_buf(), 200);

        let mut service = ToyService::new();
        let summary = run_session_campaign(&model, &mut service, &cfg, None).unwrap();

        assert_eq!(summary.profile_sha256, model.profile_sha256());
        assert_eq!(summary.reset_fidelity, "scripted;reset=reconnect");
        assert_eq!(summary.transport, "scripted");
        assert_eq!(summary.engine, "session");

        std::fs::remove_dir_all(&work_dir).ok();
    }

    #[test]
    fn loop_is_bounded_by_time_and_findings() {
        let model = toy_model();

        // A zero-time budget stops before any execution.
        let work_dir = tmp_work_dir("zero-budget");
        let mut cfg = config(&model, work_dir.to_path_buf(), 10_000);
        cfg.time_budget = Some(Duration::from_secs(0));
        let mut service = ToyService::new();
        let summary = run_session_campaign(&model, &mut service, &cfg, None).unwrap();
        assert_eq!(summary.executions, 0, "zero-budget run does nothing");
        assert!(summary.findings.is_empty());
        std::fs::remove_dir_all(&work_dir).ok();

        // Stop as soon as the first distinct finding lands.
        let work_dir = tmp_work_dir("stop-after");
        let mut cfg = config(&model, work_dir.to_path_buf(), 10_000);
        cfg.stop_after_findings = Some(1);
        let mut service = ToyService::new();
        let summary = run_session_campaign(&model, &mut service, &cfg, None).unwrap();
        assert_eq!(
            summary.findings.len(),
            1,
            "exactly one finding: {summary:?}"
        );
        std::fs::remove_dir_all(&work_dir).ok();
    }

    #[test]
    fn campaign_reaches_boundary_and_writes_session_artifact() {
        // AC1/AC2 over the in-memory service: a fixed-seed, bounded campaign from
        // the ordinary valid OPEN,WRITE seed reaches the clean-exit boundary via
        // field mutation of the path, and the written finding carries the AC2
        // evidence plus the replay/minimize metadata sidecar.
        let model = toy_model();
        let work_dir = tmp_work_dir("artifact");
        let mut cfg = config(&model, work_dir.to_path_buf(), 8000);
        cfg.transport_label = "tcp:127.0.0.1:0".to_owned();
        cfg.transport_kind = "tcp".to_owned();
        cfg.stop_after_findings = Some(1);

        let mut service = ToyService::new();
        let summary = run_session_campaign(&model, &mut service, &cfg, None).unwrap();
        assert_eq!(
            summary.findings.len(),
            1,
            "the bounded campaign reached the boundary: {summary:?}"
        );
        assert_eq!(
            summary.crashes, 0,
            "the violation is clean-exit, not a crash"
        );

        let finding_dir = corpus::layout::finding_dir(&work_dir, &summary.findings[0]);
        assert!(is_session_finding(&finding_dir));

        let artifact =
            std::fs::read_to_string(finding_dir.join(SESSION_ARTIFACT)).expect("session.json");
        let testcase = SessionTestcase::from_json(&artifact).expect("parse session.json");
        assert!(testcase.messages.len() >= 2, "AC2: >= 2 messages");
        assert!(!testcase.state_path.is_empty(), "AC2: state path");
        assert!(
            testcase.captured_responses.iter().all(|r| !r.is_empty()),
            "AC2: captured replies"
        );
        assert!(
            testcase.bindings.contains("OPEN.response.handle"),
            "AC2: response-derived handle binding"
        );
        assert_eq!(testcase.profile_sha256, model.profile_sha256());

        let meta_json =
            std::fs::read_to_string(finding_dir.join(SESSION_META)).expect("session_meta.json");
        let meta: SessionArtifactMeta = serde_json::from_str(&meta_json).unwrap();
        assert_eq!(meta.schema, SESSION_ARTIFACT_SCHEMA);
        assert_eq!(meta.reset_fidelity, "tcp;reset=reconnect");
        assert_eq!(meta.profile_sha256, model.profile_sha256());
        // The metadata is self-contained: the profile round-trips.
        assert!(Profile::from_toml(&meta.profile_toml).is_ok());

        std::fs::remove_dir_all(&work_dir).ok();
    }

    // --- multi-oracle replay/minimize must honor the RECORDED oracle ---------
    //
    // A profile with two oracles over the same WRITE reply: O1 (status 0xE1) is
    // the real bug and only fires when a BUMP sits between OPEN and WRITE; O2
    // (status 0xE2) fires on a bare OPEN,WRITE. Replay/minimize of an O1 finding
    // must not treat an O2 firing as a reproduction.
    const MULTI_ORACLE: &str = r#"
schema = "bhf.protocol.v1"
start = "start"
transport = "tcp:127.0.0.1:0"

[[message]]
name = "OPEN"
[[message.field]]
name = "op"
type = "u8"
value = 1
[message.response]
[[message.response.capture]]
name = "ostatus"
type = "u8"
at = 0

[[message]]
name = "BUMP"
[[message.field]]
name = "op"
type = "u8"
value = 2
[message.response]
[[message.response.capture]]
name = "bstatus"
type = "u8"
at = 0

[[message]]
name = "WRITE"
[[message.field]]
name = "op"
type = "u8"
value = 3
[message.response]
[[message.response.capture]]
name = "wstatus"
type = "u8"
at = 0

[[transition]]
from = "start"
send = "OPEN"
to = "opened"
[[transition]]
from = "opened"
send = "BUMP"
to = "opened"
[[transition]]
from = "opened"
send = "WRITE"
to = "opened"

[[oracle]]
name = "O1"
rule_id = "R1"
message = "WRITE"
response_field = "wstatus"
equals = 225

[[oracle]]
name = "O2"
rule_id = "R2"
message = "WRITE"
response_field = "wstatus"
equals = 226
"#;

    /// An in-memory service for the multi-oracle profile. A WRITE returns the
    /// O1 status (0xE1) only when a BUMP preceded it this session; otherwise it
    /// returns the O2 status (0xE2). OPEN/BUMP return non-oracle status bytes.
    struct MultiOracleService {
        bumped: bool,
    }

    impl MultiOracleService {
        fn new() -> Self {
            Self { bumped: false }
        }
    }

    impl SessionTransport for MultiOracleService {
        fn send_request(&mut self, req: &[u8]) -> Result<Vec<u8>, TransportError> {
            match req.first().copied() {
                Some(1) => Ok(vec![0x10]),
                Some(2) => {
                    self.bumped = true;
                    Ok(vec![0x20])
                }
                Some(3) => Ok(vec![if self.bumped { 0xE1 } else { 0xE2 }]),
                _ => Ok(vec![0x01]),
            }
        }

        fn reset(&mut self) -> Result<(), TransportError> {
            self.bumped = false;
            Ok(())
        }
    }

    fn multi_oracle_model() -> ProtocolModel {
        ProtocolModel::from_profile(&Profile::from_toml(MULTI_ORACLE).expect("parse"))
            .expect("compile")
    }

    fn multi_oracle_meta(
        model: &ProtocolModel,
        oracle: &str,
        rule_id: &str,
    ) -> SessionArtifactMeta {
        SessionArtifactMeta {
            schema: SESSION_ARTIFACT_SCHEMA.to_owned(),
            profile_sha256: model.profile_sha256().to_owned(),
            profile_toml: MULTI_ORACLE.to_owned(),
            transport: "scripted".to_owned(),
            transport_kind: "scripted".to_owned(),
            reset: "reconnect".to_owned(),
            reset_fidelity: "scripted;reset=reconnect".to_owned(),
            rule_id: Some(rule_id.to_owned()),
            oracle: oracle.to_owned(),
            reply_timeout_ms: None,
            server_cmd: None,
            coverage_map: None,
            runtime_signature: None,
            runtrace_mode: None,
        }
    }

    fn instance(model: &ProtocolModel, name: &str) -> protocol_session::MessageInstance {
        protocol_session::MessageInstance::from_seed(model.message(name).expect(name))
    }

    fn session_of(model: &ProtocolModel, names: &[&str]) -> SessionTestcase {
        SessionTestcase::from_messages(
            model.profile_sha256(),
            names.iter().map(|n| instance(model, n)).collect(),
        )
    }

    #[test]
    fn replay_requires_the_recorded_oracle_not_just_any_finding() {
        let model = multi_oracle_model();
        let meta = multi_oracle_meta(&model, "O1", "R1");

        // Recorded as O1, but re-driven without the BUMP the WRITE trips O2.
        // A different oracle firing must NOT count as reproducing the O1 finding.
        let drifted = session_of(&model, &["OPEN", "WRITE"]);
        let mut svc = MultiOracleService::new();
        assert!(
            !replay_reproduces(&model, &drifted, &meta, &mut svc).unwrap(),
            "O2 firing must not falsely confirm an O1 finding"
        );

        // Control: the O1-triggering sequence does still reproduce O1.
        let faithful = session_of(&model, &["OPEN", "BUMP", "WRITE"]);
        let mut svc = MultiOracleService::new();
        assert!(
            replay_reproduces(&model, &faithful, &meta, &mut svc).unwrap(),
            "the recorded O1 sequence must still reproduce O1"
        );

        // And if the recorded oracle really were O2, the drifted sequence is a
        // faithful reproduction — the gate is on identity, not strictness.
        let meta_o2 = multi_oracle_meta(&model, "O2", "R2");
        let mut svc = MultiOracleService::new();
        assert!(
            replay_reproduces(&model, &drifted, &meta_o2, &mut svc).unwrap(),
            "OPEN,WRITE legitimately reproduces an O2 finding"
        );
    }

    #[test]
    fn minimize_preserves_the_recorded_oracles_structure() {
        let model = multi_oracle_model();
        let meta = multi_oracle_meta(&model, "O1", "R1");

        // The O1 repro depends on the BUMP between OPEN and WRITE. Dropping it
        // leaves OPEN,WRITE, which trips O2 — an any-finding predicate would
        // happily shrink the BUMP away. Gating on the recorded oracle keeps it.
        let recorded = session_of(&model, &["OPEN", "BUMP", "WRITE"]);

        let (original_len, run, reproduces) = minimize_session_core(
            &model,
            &recorded,
            &meta,
            || Ok::<_, String>(MultiOracleService::new()),
            None,
        )
        .unwrap();

        assert_eq!(original_len, 3);
        assert!(reproduces, "the minimized sequence still reproduces O1");
        assert_eq!(
            run.testcase.message_names(),
            vec!["OPEN", "BUMP", "WRITE"],
            "minimize must keep the BUMP O1 depends on, not collapse to the O2 sequence"
        );
        assert!(
            matches!(&run.verdict, SessionVerdict::Finding { oracle, .. } if oracle == "O1"),
            "the preserved reproduction must be O1, got {:?}",
            run.verdict
        );
    }

    #[test]
    fn minimize_refuses_when_the_recorded_oracle_no_longer_reproduces() {
        let model = multi_oracle_model();
        // Recorded as O1, but the only sequence we hand minimize reproduces O2.
        let meta = multi_oracle_meta(&model, "O1", "R1");
        let drifted = session_of(&model, &["OPEN", "WRITE"]);
        let err = minimize_session_core(
            &model,
            &drifted,
            &meta,
            || Ok::<_, String>(MultiOracleService::new()),
            None,
        )
        .unwrap_err();
        assert!(
            err.contains("no longer reproduces"),
            "baseline must refuse to minimize a non-reproducing O1 finding, got {err:?}"
        );
    }

    /// A peer that answers each request it reads with `reply:` and the
    /// request, framed as `framing` frames it. A raw reply goes out in two
    /// writes 10 ms apart, inside the reply's idle window.
    fn framed_echo_server(framing: Framing) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let framing = framing.clone();
                std::thread::spawn(move || {
                    let mut stream = stream;
                    let mut buffered = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let request = match framing.take_reply(&buffered, MAX_REPLY_BYTES) {
                            ReplyProgress::Complete { reply, consumed } => {
                                buffered.drain(..consumed);
                                reply
                            }
                            _ if framing.reply_idle_ms().is_some() && !buffered.is_empty() => {
                                std::mem::take(&mut buffered)
                            }
                            _ => match stream.read(&mut chunk) {
                                Ok(0) | Err(_) => return,
                                Ok(n) => {
                                    buffered.extend_from_slice(&chunk[..n]);
                                    continue;
                                }
                            },
                        };
                        let mut reply = b"reply:".to_vec();
                        reply.extend_from_slice(&request);
                        let wire = framing.encode(&reply).unwrap();
                        if framing.reply_idle_ms().is_some() {
                            let (head, tail) = wire.split_at(wire.len() / 2);
                            stream.write_all(head).unwrap();
                            std::thread::sleep(Duration::from_millis(10));
                            stream.write_all(tail).unwrap();
                        } else {
                            stream.write_all(&wire).unwrap();
                        }
                    }
                });
            }
        });
        port
    }

    /// #257: every framing mode frames the request and reads the reply over
    /// a real socket, twice on one connection.
    #[test]
    fn each_framing_mode_carries_requests_and_replies_over_tcp() {
        let cases = [
            (Framing::default(), b"reply:ping".to_vec()),
            (
                Framing::LengthPrefix {
                    width: 2,
                    endian: protocol_session::ByteOrder::Big,
                    includes_prefix: false,
                },
                b"reply:ping".to_vec(),
            ),
            (
                Framing::LengthPrefix {
                    width: 4,
                    endian: protocol_session::ByteOrder::Little,
                    includes_prefix: true,
                },
                b"reply:ping".to_vec(),
            ),
            (
                Framing::Delimiter {
                    delimiter: b"\r\n".to_vec(),
                },
                b"reply:ping".to_vec(),
            ),
            // The request is padded to 8 bytes, and the reply cut to 8.
            (Framing::Fixed { size: 8 }, b"reply:pi".to_vec()),
        ];
        for (framing, expected) in cases {
            let label = framing.label();
            let port = framed_echo_server(framing.clone());
            let mut transport = TcpSessionTransport::new(
                "127.0.0.1".to_owned(),
                port,
                SessionResetMode::None,
                framing,
                SESSION_IO_TIMEOUT,
            );
            transport.reset().unwrap();
            for _ in 0..2 {
                assert_eq!(
                    transport.send_request(b"ping").unwrap(),
                    expected,
                    "{label}"
                );
            }
        }
    }

    /// A raw peer that closes after its reply has answered: the reply is the
    /// bytes before the close.
    #[test]
    fn a_raw_reply_ends_when_the_peer_closes() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut chunk = [0u8; 64];
            let _ = stream.read(&mut chunk);
            stream.write_all(b"bye").unwrap();
        });
        let mut transport = TcpSessionTransport::new(
            "127.0.0.1".to_owned(),
            port,
            SessionResetMode::Reconnect,
            Framing::Raw {
                reply_idle_ms: 5_000,
            },
            SESSION_IO_TIMEOUT,
        );
        transport.reset().unwrap();
        let started = Instant::now();
        assert_eq!(transport.send_request(b"hi").unwrap(), b"bye");
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "waited for the idle window"
        );
    }

    /// A `TargetTransport` in memory: it records each input in order, answers
    /// with the input's length as a u32, reports an edge per input byte value, and
    /// faults on an input that starts with `fault_on`.
    #[derive(Clone, Default)]
    struct MockTarget {
        inputs: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        arms: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        fault_on: Option<u8>,
    }

    impl target_transport::TargetTransport for MockTarget {
        fn arm(&self) -> target_transport::Result<Box<dyn target_transport::TargetSession>> {
            self.arms.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Box::new(self.clone()))
        }
    }

    impl target_transport::TargetSession for MockTarget {
        fn run_input(
            &mut self,
            input: &[u8],
        ) -> target_transport::Result<target_transport::RunOutcome> {
            self.inputs.lock().unwrap().push(input.to_vec());
            let faulted = self.fault_on.is_some() && input.first() == self.fault_on.as_ref();
            Ok(target_transport::RunOutcome {
                exit: if faulted {
                    target_transport::ExitKind::Crash
                } else {
                    target_transport::ExitKind::Ok
                },
                coverage_edges: input.iter().map(|&byte| u32::from(byte) + 1).collect(),
                fault: faulted.then(|| target_transport::Fault {
                    kind: target_transport::FaultKind::MemoryProtection,
                    address: Some(0x0800_1234),
                    detail: "CFSR=0x8200".to_owned(),
                }),
                // Four bytes: the toy profile captures a u32 handle.
                stdout: u32::try_from(input.len())
                    .unwrap_or(u32::MAX)
                    .to_be_bytes()
                    .to_vec(),
                coverage_incomplete: None,
                inconclusive: None,
                target: Default::default(),
            })
        }
    }

    /// #261: over a target transport, a session's messages reach the target
    /// in order, one execution each, with a fresh arm per session; the
    /// executions' edges feed the code channel; and a fault at a message is
    /// a confirmed disconnect finding.
    #[test]
    fn a_target_transport_delivers_messages_in_order_and_a_fault_is_a_finding() {
        assert_eq!(
            SessionTransportPlan::parse("transport:agent:tcp:127.0.0.1:7000").unwrap(),
            SessionTransportPlan::Target {
                spec: "agent:tcp:127.0.0.1:7000".to_owned(),
                coverage_map: None,
            }
        );
        // A backend's own requirements are checked: gdb needs its map.
        let error = SessionTransportPlan::parse("transport:gdb:127.0.0.1:3333").unwrap_err();
        assert!(
            error.to_string().contains("--transport-coverage-map"),
            "{error}"
        );
        // #386: the session mutator has no use for a CmpLog record.
        let error = SessionTransportPlan::parse_with_map(
            "transport:gdb:127.0.0.1:3333",
            Some("input=1,input_cap=8,ring=2,write=3,wrapped=4,cap=8,cmplog=5,cmplog_cap=4"),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("does not use cmplog="),
            "{error}"
        );
        let model = toy_model();
        let seed = seed_sessions(&model).remove(0);
        let runner = SessionRunner::new(&model);

        let clean = MockTarget::default();
        let mut transport =
            TargetSessionTransport::new(Box::new(clean.clone()), SessionResetMode::Reconnect);
        let run = runner.drive(&seed.messages, &mut transport).unwrap();
        assert!(!run.verdict.is_disconnect(), "{:?}", run.verdict);
        let sent: Vec<u8> = clean
            .inputs
            .lock()
            .unwrap()
            .iter()
            .map(|input| input[0])
            .collect();
        assert_eq!(sent, [1, 2], "OPEN, then WRITE, each its own execution");
        assert!(!transport.take_coverage_edges().is_empty());
        assert!(transport.take_coverage_edges().is_empty(), "taken once");
        runner.drive(&seed.messages, &mut transport).unwrap();
        assert_eq!(
            clean.arms.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "reset=reconnect arms a target session per protocol session"
        );

        let work_dir = tmp_work_dir("target-transport");
        let mut cfg = config(&model, work_dir.to_path_buf(), 20);
        cfg.transport_label = "transport:mock".to_owned();
        cfg.transport_kind = "transport".to_owned();
        let faulty = MockTarget {
            fault_on: Some(2),
            ..MockTarget::default()
        };
        let mut transport =
            TargetSessionTransport::new(Box::new(faulty), SessionResetMode::Reconnect);
        let summary = run_session_campaign(&model, &mut transport, &cfg, None).unwrap();
        assert_eq!(summary.coverage_source, "target", "{summary:?}");
        assert!(summary.coverage_edges > 0, "{summary:?}");
        assert!(summary.crashes > 0, "{summary:?}");
        assert_eq!(summary.findings.len(), 1, "one per message: {summary:?}");
        let finding_dir = corpus::layout::finding_dir(&work_dir, &summary.findings[0]);
        let record = std::fs::read_to_string(finding_dir.join("finding.json")).unwrap();
        assert!(record.contains(DISCONNECT_RULE), "{record}");
        assert!(
            record.contains("faulted on this message") && record.contains("0x8001234"),
            "{record}"
        );
    }

    /// #258: a `udp:` spec, and a datagram per message: an echo peer answers,
    /// a silent one misses the reply deadline and a closed port refuses, and
    /// either ends the session.
    #[test]
    fn udp_sends_a_datagram_per_message_and_a_missing_reply_ends_the_session() {
        assert_eq!(
            SessionTransportPlan::parse("udp:127.0.0.1:9").unwrap(),
            SessionTransportPlan::Udp {
                host: "127.0.0.1".to_owned(),
                port: 9
            }
        );
        let udp = |port: u16, timeout_ms: u64| {
            let mut transport = UdpSessionTransport::new(
                "127.0.0.1".to_owned(),
                port,
                SessionResetMode::Reconnect,
                Framing::default(),
                Duration::from_millis(timeout_ms),
            );
            transport.reset().unwrap();
            transport
        };

        let echo = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while let Ok((n, peer)) = echo.recv_from(&mut buf) {
                let mut reply = b"reply:".to_vec();
                reply.extend_from_slice(&buf[..n]);
                let _ = echo.send_to(&reply, peer);
            }
        });
        let mut transport = udp(echo_port, 2_000);
        assert_eq!(transport.send_request(b"ping").unwrap(), b"reply:ping");
        assert_eq!(transport.send_request(b"pong").unwrap(), b"reply:pong");

        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let error = udp(silent.local_addr().unwrap().port(), 100)
            .send_request(b"ping")
            .unwrap_err();
        assert!(error.session_lost, "{error}");
        assert!(
            error.message.contains("no reply datagram within 100 ms"),
            "{error}"
        );

        let closed_port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let error = udp(closed_port, 1_000).send_request(b"ping").unwrap_err();
        assert!(error.session_lost, "{error}");
    }
}
