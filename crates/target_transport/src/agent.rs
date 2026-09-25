// SPDX-License-Identifier: Apache-2.0

//! On-target agent protocol.
//!
//! [`AgentTransport`] drives a target that runs a small BHF-authored agent over
//! any [`Read`] + [`Write`] channel (TCP socket, serial `/dev/tty*`, stdio).
//! One round-trip per input:
//!
//! ```text
//! host -> target:  {u32 le len}{len input bytes}
//! target -> host:  {u32 le status}
//!                  {u32 le n_edges}{n_edges * u32 le edge}
//!                  {u32 le fault_present}
//!                  if fault_present == 1:
//!                      {u32 le kind}{u64 le addr}{u32 le detail_len}{detail bytes}
//! ```
//!
//! `status` is [`STATUS_OK`] / [`STATUS_CRASH`] / [`STATUS_TIMEOUT`]; any other
//! value is a protocol error. Every inbound length (`n_edges`, `detail_len`,
//! and the on-target input length) is checked against a configurable cap in
//! [`AgentLimits`] *before* allocating, so a malformed oversized length is a
//! descriptive [`crate::error::TransportError::LengthCap`], never an allocation
//! bomb.
//!
//! The fault block always carries an address word; [`AgentTransport`] decodes
//! it as `Some(addr)` (targets send `0` when no address applies). `stdout` has
//! no channel in this protocol and is always empty in the returned
//! [`RunOutcome`].

use crate::error::{Result, TransportError};
use crate::outcome::{ExitKind, Fault, FaultKind, RunOutcome};
use crate::transport::{TargetSession, TargetTransport};
use crate::wire::{cap_len, read_u32_le, read_u32_le_opt, read_u64_le, read_vec};
use std::io::{Read, Write};

/// `status` word: the input completed cleanly.
pub const STATUS_OK: u32 = 0;
/// `status` word: the target faulted.
pub const STATUS_CRASH: u32 = 1;
/// `status` word: the target timed out.
pub const STATUS_TIMEOUT: u32 = 2;

/// `fault_present` word values.
const FAULT_ABSENT: u32 = 0;
const FAULT_PRESENT: u32 = 1;

/// Bounds on inbound lengths, enforced before allocation.
#[derive(Debug, Clone, Copy)]
pub struct AgentLimits {
    /// Cap on an on-target input frame length (host -> target direction, read
    /// by the target side / mock).
    pub max_input_len: usize,
    /// Cap on `n_edges` in a response.
    pub max_edges: usize,
    /// Cap on a fault `detail` byte length.
    pub max_detail_len: usize,
}

impl Default for AgentLimits {
    fn default() -> Self {
        Self {
            // 16 MiB input, ~1M edges, 64 KiB detail: generous for real
            // targets, still a hard ceiling against a hostile length field.
            max_input_len: 16 * 1024 * 1024,
            max_edges: 1 << 20,
            max_detail_len: 64 * 1024,
        }
    }
}

/// Map an [`ExitKind`] to its `status` word.
pub fn status_of(exit: ExitKind) -> u32 {
    match exit {
        ExitKind::Ok => STATUS_OK,
        ExitKind::Crash => STATUS_CRASH,
        ExitKind::Timeout => STATUS_TIMEOUT,
    }
}

/// Map a `status` word to an [`ExitKind`], rejecting unknown values.
pub fn exit_of(status: u32) -> Result<ExitKind> {
    match status {
        STATUS_OK => Ok(ExitKind::Ok),
        STATUS_CRASH => Ok(ExitKind::Crash),
        STATUS_TIMEOUT => Ok(ExitKind::Timeout),
        other => Err(TransportError::protocol(format!(
            "agent status word {other} is not one of ok(0)/crash(1)/timeout(2)"
        ))),
    }
}

/// Write a host -> target input frame: `{u32 le len}{bytes}`.
pub fn write_input_frame<W: Write>(writer: &mut W, input: &[u8]) -> Result<()> {
    let len = u32::try_from(input.len()).map_err(|_| {
        TransportError::protocol(format!(
            "input length {} exceeds the 32-bit frame length field",
            input.len()
        ))
    })?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(input)?;
    writer.flush()?;
    Ok(())
}

/// Read a host -> target input frame (target/mock side). Returns `Ok(None)` on
/// a clean EOF between frames (the host closed the link).
pub fn read_input_frame<R: Read>(reader: &mut R, limits: &AgentLimits) -> Result<Option<Vec<u8>>> {
    let Some(len) = read_u32_le_opt(reader, "agent input frame length")? else {
        return Ok(None);
    };
    let len = cap_len(len as u64, limits.max_input_len, "agent input")?;
    Ok(Some(read_vec(reader, len, "agent input bytes")?))
}

/// Encode a target -> host response (target/mock side). `stdout` is not carried
/// by this protocol and is ignored.
pub fn encode_response(outcome: &RunOutcome) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&status_of(outcome.exit).to_le_bytes());

    out.extend_from_slice(&(outcome.coverage_edges.len() as u32).to_le_bytes());
    for edge in &outcome.coverage_edges {
        out.extend_from_slice(&edge.to_le_bytes());
    }

    match &outcome.fault {
        None => out.extend_from_slice(&FAULT_ABSENT.to_le_bytes()),
        Some(fault) => {
            out.extend_from_slice(&FAULT_PRESENT.to_le_bytes());
            out.extend_from_slice(&fault.kind.to_wire().to_le_bytes());
            out.extend_from_slice(&fault.address.unwrap_or(0).to_le_bytes());
            let detail = fault.detail.as_bytes();
            out.extend_from_slice(&(detail.len() as u32).to_le_bytes());
            out.extend_from_slice(detail);
        }
    }
    out
}

/// Read a target -> host response (host side), enforcing `limits`.
pub fn read_response<R: Read>(reader: &mut R, limits: &AgentLimits) -> Result<RunOutcome> {
    let exit = exit_of(read_u32_le(reader, "agent response status")?)?;

    let declared_edges = read_u32_le(reader, "agent response edge count")?;
    let n_edges = cap_len(declared_edges as u64, limits.max_edges, "agent edge count")?;
    let mut coverage_edges = Vec::with_capacity(n_edges);
    for _ in 0..n_edges {
        coverage_edges.push(read_u32_le(reader, "agent response edge")?);
    }

    let fault = match read_u32_le(reader, "agent response fault-present")? {
        FAULT_ABSENT => None,
        FAULT_PRESENT => {
            let kind = FaultKind::from_wire(read_u32_le(reader, "agent fault kind")?);
            let address = read_u64_le(reader, "agent fault address")?;
            let declared_detail = read_u32_le(reader, "agent fault detail length")?;
            let detail_len = cap_len(
                declared_detail as u64,
                limits.max_detail_len,
                "agent fault detail",
            )?;
            let detail_bytes = read_vec(reader, detail_len, "agent fault detail bytes")?;
            let detail = String::from_utf8(detail_bytes).map_err(|error| {
                TransportError::protocol(format!("agent fault detail is not UTF-8: {error}"))
            })?;
            Some(Fault {
                kind,
                address: Some(address),
                detail,
            })
        }
        other => {
            return Err(TransportError::protocol(format!(
                "agent fault-present word {other} is not 0 or 1"
            )))
        }
    };

    Ok(RunOutcome {
        exit,
        coverage_edges,
        fault,
        stdout: Vec::new(),
    })
}

/// A live session over an armed agent channel.
pub struct AgentSession<C> {
    channel: C,
    limits: AgentLimits,
}

impl<C: Read + Write> AgentSession<C> {
    /// Wrap a connected channel as a session.
    pub fn new(channel: C, limits: AgentLimits) -> Self {
        Self { channel, limits }
    }
}

impl<C: Read + Write> TargetSession for AgentSession<C> {
    fn run_input(&mut self, input: &[u8]) -> Result<RunOutcome> {
        write_input_frame(&mut self.channel, input)?;
        read_response(&mut self.channel, &self.limits)
    }
}

/// A transport that connects a fresh agent channel per [`TargetTransport::arm`].
///
/// `connect` is a factory (dial the socket, open the serial port, spawn a
/// local mock) so arming can rebuild the link. Real backends connect on arm and
/// keep the persistent agent up across inputs.
pub struct AgentTransport<F> {
    connect: F,
    limits: AgentLimits,
}

impl<F> AgentTransport<F> {
    /// Build a transport with default [`AgentLimits`].
    pub fn new(connect: F) -> Self {
        Self {
            connect,
            limits: AgentLimits::default(),
        }
    }

    /// Build a transport with explicit limits.
    pub fn with_limits(connect: F, limits: AgentLimits) -> Self {
        Self { connect, limits }
    }
}

impl<F, C> TargetTransport for AgentTransport<F>
where
    F: Fn() -> Result<C>,
    C: Read + Write + 'static,
{
    fn arm(&self) -> Result<Box<dyn TargetSession>> {
        let channel = (self.connect)()?;
        Ok(Box::new(AgentSession::new(channel, self.limits)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::{duplex, MockAgent, ScriptedResponse};
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn agent_session_delivers_input_and_surfaces_monotonic_edges_and_fault() {
        // Scripted target: three inputs; the edge set grows monotonically and
        // the third execution faults.
        let script = vec![
            ScriptedResponse::ok(vec![1, 2]),
            ScriptedResponse::ok(vec![1, 2, 3]),
            ScriptedResponse::crash(
                vec![1, 2, 3, 4],
                Fault {
                    kind: FaultKind::CpuException,
                    address: Some(0xDEAD_BEEF),
                    detail: "hard fault vector 3".to_string(),
                },
            ),
        ];

        let (host_end, target_end) = duplex();
        let received = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let agent = MockAgent::new(target_end, script, Arc::clone(&received));
        let handle = thread::spawn(move || agent.serve());

        let mut session = AgentSession::new(host_end, AgentLimits::default());

        let inputs: [&[u8]; 3] = [b"first", b"second-input", b"third"];
        let mut outcomes = Vec::new();
        for input in inputs {
            outcomes.push(session.run_input(input).unwrap());
        }

        // The session's channel must be closed for the mock to see EOF and
        // return; drop it, then join.
        drop(session);
        handle.join().unwrap().unwrap();

        // Inputs were delivered verbatim and in order.
        let delivered = received.lock().unwrap().clone();
        assert_eq!(
            delivered,
            vec![
                b"first".to_vec(),
                b"second-input".to_vec(),
                b"third".to_vec()
            ]
        );

        // Edges are nonzero and monotonically growing across inputs.
        assert_eq!(outcomes[0].coverage_edges, vec![1, 2]);
        assert_eq!(outcomes[1].coverage_edges, vec![1, 2, 3]);
        assert_eq!(outcomes[2].coverage_edges, vec![1, 2, 3, 4]);
        for outcome in &outcomes {
            assert!(!outcome.coverage_edges.is_empty());
        }
        assert!(outcomes[0].coverage_edges.len() < outcomes[1].coverage_edges.len());
        assert!(outcomes[1].coverage_edges.len() < outcomes[2].coverage_edges.len());

        // The scripted fault is surfaced structurally.
        assert_eq!(outcomes[0].exit, ExitKind::Ok);
        assert_eq!(outcomes[1].exit, ExitKind::Ok);
        assert_eq!(outcomes[2].exit, ExitKind::Crash);
        assert_eq!(
            outcomes[2].fault,
            Some(Fault {
                kind: FaultKind::CpuException,
                address: Some(0xDEAD_BEEF),
                detail: "hard fault vector 3".to_string(),
            })
        );
    }

    #[test]
    fn agent_transport_arms_a_working_session() {
        // Exercise the trait object seam end to end: arm() -> run_input().
        let script = vec![ScriptedResponse::ok(vec![7, 8, 9])];
        let received = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));

        // The factory spawns a fresh mock on a fresh duplex and returns the
        // host end, exactly as a real dial-on-arm backend would.
        let received_for_factory = Arc::clone(&received);
        let transport = AgentTransport::new(move || {
            let (host_end, target_end) = duplex();
            let agent = MockAgent::new(
                target_end,
                script.clone(),
                Arc::clone(&received_for_factory),
            );
            thread::spawn(move || {
                let _ = agent.serve();
            });
            Ok(host_end)
        });

        let mut session = transport.arm().unwrap();
        let outcome = session.run_input(b"hello").unwrap();
        assert_eq!(outcome.exit, ExitKind::Ok);
        assert_eq!(outcome.coverage_edges, vec![7, 8, 9]);
        assert_eq!(received.lock().unwrap().clone(), vec![b"hello".to_vec()]);
    }

    #[test]
    fn read_response_rejects_oversized_edge_count_without_allocating() {
        // n_edges declared as ~4 billion; a naive reader would try to allocate
        // a 16 GiB Vec. With a small cap it must error first.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&STATUS_OK.to_le_bytes());
        bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // n_edges
                                                          // (no edge bytes follow; we must fail before reading them)

        let limits = AgentLimits {
            max_edges: 1024,
            ..AgentLimits::default()
        };
        let error = read_response(&mut bytes.as_slice(), &limits).unwrap_err();
        match error {
            TransportError::LengthCap {
                field,
                declared,
                cap,
            } => {
                assert_eq!(field, "agent edge count");
                assert_eq!(declared, u32::MAX as u64);
                assert_eq!(cap, 1024);
            }
            other => panic!("expected LengthCap, got {other}"),
        }
    }

    #[test]
    fn read_response_rejects_oversized_detail_length_without_allocating() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&STATUS_CRASH.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes()); // n_edges = 0
        bytes.extend_from_slice(&FAULT_PRESENT.to_le_bytes());
        bytes.extend_from_slice(&FaultKind::MemoryProtection.to_wire().to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes()); // addr
        bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // detail_len (bomb)

        let limits = AgentLimits {
            max_detail_len: 32,
            ..AgentLimits::default()
        };
        let error = read_response(&mut bytes.as_slice(), &limits).unwrap_err();
        assert!(
            matches!(error, TransportError::LengthCap { field, .. } if field == "agent fault detail"),
            "expected detail LengthCap, got {error}"
        );
    }

    #[test]
    fn read_response_rejects_unknown_status_word() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&99_u32.to_le_bytes());
        let error = read_response(&mut bytes.as_slice(), &AgentLimits::default()).unwrap_err();
        assert!(
            matches!(error, TransportError::Protocol(ref m) if m.contains("status word 99")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn response_round_trips_through_encode_and_read() {
        let outcome = RunOutcome {
            exit: ExitKind::Crash,
            coverage_edges: vec![3, 1, 4, 1, 5],
            fault: Some(Fault {
                kind: FaultKind::Watchdog,
                address: Some(0x2000_0000),
                detail: "watchdog reset".to_string(),
            }),
            stdout: Vec::new(),
        };
        let encoded = encode_response(&outcome);
        let decoded = read_response(&mut encoded.as_slice(), &AgentLimits::default()).unwrap();
        assert_eq!(decoded, outcome);
    }
}
