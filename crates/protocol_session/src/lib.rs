// SPDX-License-Identifier: Apache-2.0

//! Response-dependent, structured multi-message protocol sessions (HDF-7).
//!
//! This crate is the **pure library** behind stateful protocol fuzzing: it
//! parses a versioned protocol profile, lowers each message onto the reused
//! `binframe` descriptor + fix-up machinery, projects the legal message
//! ordering onto the reused `ada_state_machine` graph, and provides the
//! structured multi-message testcase, response-field extraction, response-
//! derived value binding, graph-gated field + sequence mutation with
//! computed-field repair, separate code-coverage vs protocol-state/transition
//! novelty tracking, and session drive / replay / minimization over a transport
//! seam.
//!
//! It is deliberately hardware-free: the live socket backend and the `bhf fuzz`
//! campaign loop live in the `bhf` binary crate. Here the transport is the
//! [`runner::SessionTransport`] trait, exercised in tests by the in-memory
//! [`runner::ScriptedTransport`] mock.
//!
//! The format and model are generic by construction; nothing here names a
//! downstream consumer. A finding is emitted for importers / SARIF /
//! vulnerability-management tools to read.

pub mod binding;
pub mod model;
pub mod mutate;
pub mod novelty;
pub mod profile;
pub mod response;
pub mod runner;
pub mod testcase;

pub use binding::{Bindings, BoundValue};
pub use model::{
    CaptureSpec, CompiledCapture, CompiledField, CompiledMessage, ComputedSpec, DataSpec,
    EncodeError, FieldRole, FieldValue, ModelError, ProtocolModel,
};
pub use mutate::{
    delete_message, insert_message, mutate_field_value, mutate_fields, mutate_sequence, reorder,
    replace_message, toggle_optional, MutateError,
};
pub use novelty::{CodeCoverageNovelty, StateNovelty, StateNoveltyDelta, TransitionId};
pub use profile::{
    ByteOrder, CaptureDef, FieldDef, FieldType, MessageDef, OracleDef, Profile, ProfileError,
    ResponseDef, SessionDef, TransitionDef, SCHEMA_V1,
};
pub use response::{extract, ResponseError};
pub use runner::{
    RunnerError, ScriptedTransport, SessionOracle, SessionRun, SessionRunner, SessionTransport,
    SessionVerdict, TransportError,
};
pub use testcase::{encode_message, FieldAssignment, MessageInstance, SessionTestcase};
