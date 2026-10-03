// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

//! Platform-neutral runtime-event collector contract (`bhf.collector-event.v1`).
//!
//! A *collector* observes the process, filesystem, and module-load effects a
//! target performs while a single testcase executes — including effects that a
//! target performs on a **clean exit** (no crash). The contract defined here is
//! deliberately OS-independent: it is a versioned, line-delimited JSON (JSONL)
//! event schema plus the pure logic needed to turn a stream of those events
//! into something importers (SARIF / vulnerability-management tools) can act on.
//!
//! This crate is **pure**: no subprocess, no OS tracer, no filesystem access.
//! Every piece of logic (schema (de)serialization, session grouping, ancestor /
//! descendant attribution, lexical path normalization, oracle mapping, and
//! fidelity accounting) is unit-testable on any host, which is what lets a Linux
//! CI runner exercise the entire contract. Concrete providers (a native Windows
//! ETW provider, an external sidecar, the in-process Linux adapter) live in
//! other crates and only have to emit the JSONL wire format defined here.
//!
//! The [`mock`] module ships a [`mock::MockCollector`] that speaks the wire
//! protocol and exercises the whole contract on every platform; it is the
//! always-on, dependency-free proof that an out-of-tree provider can target the
//! schema.

pub mod attribute;
pub mod collector;
pub mod fidelity;
pub mod mock;
pub mod normalize;
pub mod oracle_map;
pub mod provenance;
pub mod schema;
pub mod session;

pub use attribute::{attribute, AttributedSession};
pub use collector::{BackendInfo, Collector, CollectorContext, CollectorError};
pub use normalize::{escapes_root, normalize_path, NormalizedPath};
pub use oracle_map::to_oracle_event;
pub use provenance::CollectorProvenance;
pub use schema::{CollectorEvent, EventKind, EventPhase, Fidelity, ProcessIdentity, SCHEMA_ID};
pub use session::{CollectorSession, CollectorSessionSet};
