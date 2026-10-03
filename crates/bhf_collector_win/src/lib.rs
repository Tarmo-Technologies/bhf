// SPDX-License-Identifier: Apache-2.0
#![cfg_attr(not(windows), forbid(unsafe_code))]
#![deny(unsafe_op_in_unsafe_fn)]

//! Native Windows runtime-event provider for the `bhf.collector-event.v1`
//! contract.
//!
//! The crate is split so that everything except the raw ETW subscription is a
//! **pure, Linux-testable core** ([`win_core`]): it turns synthetic ETW-shaped
//! records into [`runtime_collector`] events, attributes them to the testcase's
//! descendant process tree, applies byte-origin taint, and serializes the
//! collector JSONL. Only the live ETW consumer ([`etw`]) is behind
//! `#[cfg(windows)]` and confines all `unsafe` FFI. On a non-Windows host the
//! crate still compiles (to its pure core), so Linux CI exercises the five
//! Windows event classes against synthetic records with no OS tracer.
//!
//! Observed classes: `CreateProcess*` and descendants, `ShellExecute*`
//! (target/verb/args + child), file create/open/write/rename/delete with
//! resolved paths, `LoadLibrary*`/image-load, and the descendant process tree.

pub mod win_core;

#[cfg(windows)]
pub mod etw;

pub use win_core::{WinCoreBuilder, WinFileOp, WinRawRecord};
