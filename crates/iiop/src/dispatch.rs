// SPDX-License-Identifier: Apache-2.0

//! GIOP request dispatch to a fake servant (HDF-7, deliverable 2).
//!
//! This is the piece that turns the GIOP/CDR decoder into an actual fuzzer input
//! path: raw fuzz bytes go in one end, and if they form a well-formed GIOP 1.2
//! request they are decoded (header → request → IDL-typed arguments) and
//! dispatched to a servant operation. No sockets are involved — a frame is just
//! a `&[u8]`, so the whole path is a pure function a fuzz harness can call
//! per input. An [`InMemoryTransport`] models a queue of pending request frames
//! for the stateful case, keeping the "transport" in memory.
//!
//! The servant is deliberately fake: [`Servant::invoke`] receives the decoded,
//! IDL-typed arguments and returns a logical reply. It reuses the crate's
//! existing IDL notions ([`IdlOperationCatalog`], [`DecodedRequestArguments`])
//! rather than inventing a parallel object model.

use std::collections::VecDeque;
use std::fmt;

use crate::encode::CdrValue;
use crate::giop::{parse_message, read_request_1_2, GiopError};
use crate::idl_args::{
    decode_request_arguments, DecodedArgument, DecodedRequestArguments, IdlArgumentDecodeError,
    IdlOperationCatalog,
};

/// A servant: it receives a decoded request and produces a reply. Implementors
/// dispatch on `request.operation` (and optionally `request.interface` /
/// `request.repository_id`).
pub trait Servant {
    fn invoke(
        &mut self,
        request: &DecodedRequestArguments<'_>,
    ) -> Result<ServantReply, ServantError>;
}

/// The logical result of a servant operation. A full GIOP `Reply` encoder is a
/// follow-up; for the fuzzable dispatch path the logical return value is what a
/// harness asserts on.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct ServantReply {
    pub result: Option<CdrValue>,
}

impl ServantReply {
    pub fn empty() -> Self {
        Self { result: None }
    }

    pub fn value(result: CdrValue) -> Self {
        Self {
            result: Some(result),
        }
    }
}

/// Errors a servant may raise. Distinct from decode errors: these mean the frame
/// decoded fine but the operation could not be served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServantError {
    UnknownOperation(String),
    BadArguments { operation: String, detail: String },
}

impl fmt::Display for ServantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServantError::UnknownOperation(operation) => {
                write!(f, "servant has no operation '{operation}'")
            }
            ServantError::BadArguments { operation, detail } => {
                write!(f, "servant rejected arguments for '{operation}': {detail}")
            }
        }
    }
}

impl std::error::Error for ServantError {}

/// The outcome of dispatching one frame: the decoded call plus the servant's
/// reply. Owned, so it does not borrow the input frame.
#[derive(Clone, Debug, PartialEq)]
pub struct Invocation {
    pub interface: String,
    pub operation: String,
    pub repository_id: Option<String>,
    pub arguments: Vec<DecodedArgument>,
    pub reply: ServantReply,
}

/// Errors from the full frame → request → dispatch path.
#[derive(Clone, Debug, PartialEq)]
pub enum DispatchError {
    /// The bytes were not a well-formed GIOP request.
    Giop(GiopError),
    /// The request decoded but its arguments did not match the IDL.
    Decode(IdlArgumentDecodeError),
    /// The request decoded but the servant could not serve it.
    Servant(ServantError),
}

impl fmt::Display for DispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DispatchError::Giop(error) => write!(f, "GIOP decode failed: {error}"),
            DispatchError::Decode(error) => write!(f, "argument decode failed: {error}"),
            DispatchError::Servant(error) => write!(f, "servant dispatch failed: {error}"),
        }
    }
}

impl std::error::Error for DispatchError {}

impl From<GiopError> for DispatchError {
    fn from(error: GiopError) -> Self {
        DispatchError::Giop(error)
    }
}

impl From<IdlArgumentDecodeError> for DispatchError {
    fn from(error: IdlArgumentDecodeError) -> Self {
        DispatchError::Decode(error)
    }
}

impl From<ServantError> for DispatchError {
    fn from(error: ServantError) -> Self {
        DispatchError::Servant(error)
    }
}

/// Drives raw GIOP frames into a servant using an IDL operation catalog to
/// decode arguments. This is the fuzzable unit: `handle_frame(bytes)` is the
/// single call a fuzz harness makes per input.
pub struct Dispatcher<S: Servant> {
    catalog: IdlOperationCatalog,
    servant: S,
}

impl<S: Servant> Dispatcher<S> {
    pub fn new(catalog: IdlOperationCatalog, servant: S) -> Self {
        Self { catalog, servant }
    }

    pub fn servant(&self) -> &S {
        &self.servant
    }

    pub fn servant_mut(&mut self) -> &mut S {
        &mut self.servant
    }

    /// Decode one GIOP 1.2 request frame and dispatch it to the servant.
    ///
    /// Path: `parse_message` → `read_request_1_2` → `decode_request_arguments`
    /// → `Servant::invoke`. Any malformed input produces a [`DispatchError`]
    /// rather than a panic, so a fuzzer's random bytes are handled cleanly.
    pub fn handle_frame(&mut self, frame: &[u8]) -> Result<Invocation, DispatchError> {
        let message = parse_message(frame)?;
        let request = read_request_1_2(&message)?;
        let decoded = decode_request_arguments(&request, &self.catalog)?;
        let reply = self.servant.invoke(&decoded)?;
        Ok(Invocation {
            interface: decoded.interface.clone(),
            operation: decoded.operation.clone(),
            repository_id: decoded.repository_id.clone(),
            arguments: decoded.arguments.clone(),
            reply,
        })
    }
}

/// An in-memory queue of request frames — the stateful "transport" for tests and
/// seed-driven sessions, with no sockets. Push encoded frames, then pump them
/// through a [`Dispatcher`].
#[derive(Clone, Debug, Default)]
pub struct InMemoryTransport {
    frames: VecDeque<Vec<u8>>,
}

impl InMemoryTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_frame(&mut self, frame: Vec<u8>) {
        self.frames.push_back(frame);
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Pop the next frame and dispatch it. Returns `None` when the queue is
    /// drained.
    pub fn serve_next<S: Servant>(
        &mut self,
        dispatcher: &mut Dispatcher<S>,
    ) -> Option<Result<Invocation, DispatchError>> {
        let frame = self.frames.pop_front()?;
        Some(dispatcher.handle_frame(&frame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::Request12;
    use crate::idl_args::DecodedArgumentValue;
    use idl_parser::parse_idl;

    /// A fake servant implementing `Echo::add` and `Echo::concat`, recording
    /// every call it serves.
    #[derive(Default)]
    struct EchoServant {
        calls: Vec<String>,
    }

    impl Servant for EchoServant {
        fn invoke(
            &mut self,
            request: &DecodedRequestArguments<'_>,
        ) -> Result<ServantReply, ServantError> {
            self.calls.push(request.operation.clone());
            match request.operation.as_str() {
                "add" => {
                    let mut sum: i64 = 0;
                    for arg in &request.arguments {
                        match arg.value {
                            DecodedArgumentValue::Long(value) => sum += i64::from(value),
                            _ => {
                                return Err(ServantError::BadArguments {
                                    operation: "add".to_owned(),
                                    detail: format!("expected long, got {:?}", arg.value),
                                })
                            }
                        }
                    }
                    Ok(ServantReply::value(CdrValue::LongLong(sum)))
                }
                "concat" => {
                    let mut joined = String::new();
                    for arg in &request.arguments {
                        if let DecodedArgumentValue::String(value) = &arg.value {
                            joined.push_str(value);
                        }
                    }
                    Ok(ServantReply::value(CdrValue::String(joined)))
                }
                other => Err(ServantError::UnknownOperation(other.to_owned())),
            }
        }
    }

    fn echo_catalog() -> IdlOperationCatalog {
        let idl = parse_idl(
            r#"
            interface Echo {
                long add(in long a, in long b);
                string concat(in string head, in string tail);
            };
            "#,
        )
        .expect("IDL parses");
        IdlOperationCatalog::from_idl_file(&idl)
    }

    #[test]
    fn encoded_request_roundtrips_and_dispatches_to_servant() {
        // The acceptance test: a GIOP request built by the new encoder decodes
        // via the existing decoder to the same logical request and dispatches to
        // a fake servant op.
        let frame = Request12::new(b"Echo".to_vec(), "add")
            .with_request_id(42)
            .with_arguments(vec![CdrValue::Long(2), CdrValue::Long(3)])
            .encode()
            .expect("encode request");

        let mut dispatcher = Dispatcher::new(echo_catalog(), EchoServant::default());
        let invocation = dispatcher.handle_frame(&frame).expect("dispatch");

        // Same logical request: interface, operation, and the decoded argument
        // values match what was encoded.
        assert_eq!(invocation.interface, "Echo");
        assert_eq!(invocation.operation, "add");
        assert_eq!(
            invocation
                .arguments
                .iter()
                .map(|arg| arg.value.clone())
                .collect::<Vec<_>>(),
            vec![DecodedArgumentValue::Long(2), DecodedArgumentValue::Long(3)]
        );
        // The servant actually ran and computed add(2, 3) = 5.
        assert_eq!(invocation.reply.result, Some(CdrValue::LongLong(5)));
        assert_eq!(dispatcher.servant().calls, vec!["add".to_owned()]);
    }

    #[test]
    fn big_endian_string_request_roundtrips() {
        // Exercise the other endianness and string arguments, so the alignment
        // and string encoding are proven both ways.
        let frame = Request12::new(b"Echo".to_vec(), "concat")
            .with_endian(crate::cdr::Endianness::Big)
            .with_arguments(vec![
                CdrValue::String("rad".to_owned()),
                CdrValue::String("ar".to_owned()),
            ])
            .encode()
            .expect("encode request");

        let mut dispatcher = Dispatcher::new(echo_catalog(), EchoServant::default());
        let invocation = dispatcher.handle_frame(&frame).expect("dispatch");
        assert_eq!(invocation.operation, "concat");
        assert_eq!(
            invocation.reply.result,
            Some(CdrValue::String("radar".to_owned()))
        );
    }

    #[test]
    fn in_memory_transport_pumps_multiple_frames() {
        let mut transport = InMemoryTransport::new();
        transport.push_frame(
            Request12::new(b"Echo".to_vec(), "add")
                .with_arguments(vec![CdrValue::Long(10), CdrValue::Long(1)])
                .encode()
                .unwrap(),
        );
        transport.push_frame(
            Request12::new(b"Echo".to_vec(), "add")
                .with_arguments(vec![CdrValue::Long(-4), CdrValue::Long(4)])
                .encode()
                .unwrap(),
        );

        let mut dispatcher = Dispatcher::new(echo_catalog(), EchoServant::default());
        let mut results = Vec::new();
        while let Some(outcome) = transport.serve_next(&mut dispatcher) {
            results.push(outcome.expect("dispatch"));
        }
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].reply.result, Some(CdrValue::LongLong(11)));
        assert_eq!(results[1].reply.result, Some(CdrValue::LongLong(0)));
        assert!(transport.is_empty());
    }

    #[test]
    fn random_bytes_do_not_panic_and_are_rejected() {
        // A fuzzer feeds garbage; the path must return an error, not panic.
        let mut dispatcher = Dispatcher::new(echo_catalog(), EchoServant::default());
        let garbage = [0xFFu8; 32];
        let err = dispatcher
            .handle_frame(&garbage)
            .expect_err("garbage rejected");
        assert!(matches!(err, DispatchError::Giop(_)), "got {err}");
        // A well-formed frame naming an unknown operation is a decode error,
        // surfaced cleanly.
        let frame = Request12::new(b"Echo".to_vec(), "nonexistent")
            .encode()
            .unwrap();
        let err = dispatcher
            .handle_frame(&frame)
            .expect_err("unknown op rejected");
        assert!(matches!(err, DispatchError::Decode(_)), "got {err}");
    }
}
