// SPDX-License-Identifier: Apache-2.0
#![cfg(windows)]

//! Live Windows ETW consumer. **Windows-only** (`#[cfg(windows)]`): this module
//! is excluded from non-Windows builds, so the crate compiles to its pure core
//! on Linux CI. All `unsafe` FFI is confined here; [`crate::win_core`] stays
//! safe and pure.
//!
//! Scope of this first cut: environment plumbing, core wiring, and an honest
//! real-time session probe. Starting a kernel ETW session requires rights the
//! target context may not have; when it does not, the provider records
//! [`runtime_collector::schema::Fidelity::permission_denied`] rather than
//! emitting a silent "clean" stream (AC #6). Full `EVENT_RECORD` payload
//! decoding for the process / file / image-load providers is validated on the
//! Windows runner via the gated `live_windows` test and is tracked as the
//! remaining native work; until a record is decoded its class is recorded in
//! `fidelity.unsupported_fields` rather than fabricated.

use runtime_collector::schema::CollectorEvent;
use runtime_collector::CollectorContext;
use std::ffi::OsStr;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;

use crate::win_core::WinCoreBuilder;

use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SUCCESS};
use windows_sys::Win32::System::Diagnostics::Etw::{
    ControlTraceW, StartTraceW, CONTROLTRACE_HANDLE, EVENT_TRACE_CONTROL_STOP,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, WNODE_FLAG_TRACED_GUID,
};

/// Process-wide ETW session name for the collector's real-time session.
const SESSION_NAME: &str = "bhf-collector-win";

/// Read the collector context from the `BHF_COLLECTOR_*` environment.
fn context_from_env() -> CollectorContext {
    let testcase = std::env::var("BHF_COLLECTOR_TESTCASE").unwrap_or_default();
    let worker = std::env::var("BHF_COLLECTOR_WORKER")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let root = std::env::var("BHF_COLLECTOR_ROOT").unwrap_or_default();
    let window_ms = std::env::var("BHF_COLLECTOR_WINDOW_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(250);
    CollectorContext::new(testcase, worker, root, window_ms)
}

fn root_pid_from_env() -> u32 {
    std::env::var("BHF_COLLECTOR_ROOT_PID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn fuzz_input_from_env() -> Vec<u8> {
    match std::env::var("BHF_COLLECTOR_INPUT") {
        Ok(path) if !path.is_empty() => std::fs::read(path).unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Outcome of the real-time session probe.
enum SessionProbe {
    /// A session could be started (and was stopped again): the host has rights.
    Available,
    /// The host lacks the rights to start an ETW session.
    PermissionDenied,
    /// Another error; treated as a non-fatal fidelity limitation.
    Other(u32),
}

/// Probe whether this context can start a real-time ETW session. Starting a
/// session is the privilege gate for observing the kernel providers; probing it
/// lets the provider report `permission_denied` honestly before claiming to
/// have watched anything.
fn probe_session() -> SessionProbe {
    // EVENT_TRACE_PROPERTIES is a header immediately followed by the logger name
    // buffer; allocate a single blob large enough for both.
    let name: Vec<u16> = OsStr::new(SESSION_NAME)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let name_bytes = name.len() * std::mem::size_of::<u16>();
    let total = props_size + name_bytes;
    let mut blob = vec![0u8; total];

    // SAFETY: `blob` is zero-initialized and at least `size_of::<EVENT_TRACE_PROPERTIES>()`
    // bytes long, so the cast and field writes stay within the allocation.
    let handle = unsafe {
        let props = blob.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        (*props).Wnode.BufferSize = total as u32;
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*props).LoggerNameOffset = props_size as u32;

        let mut handle: CONTROLTRACE_HANDLE = Default::default();
        let status = StartTraceW(&mut handle, name.as_ptr(), props);
        if status != ERROR_SUCCESS {
            return classify_status(status);
        }
        handle
    };

    // We only needed to know we *could* start it; stop it again immediately.
    // SAFETY: `blob` still backs a valid EVENT_TRACE_PROPERTIES and `handle`
    // came from a successful StartTraceW.
    unsafe {
        let props = blob.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        let _ = ControlTraceW(handle, name.as_ptr(), props, EVENT_TRACE_CONTROL_STOP);
    }
    SessionProbe::Available
}

fn classify_status(status: u32) -> SessionProbe {
    if status == ERROR_ACCESS_DENIED {
        SessionProbe::PermissionDenied
    } else {
        SessionProbe::Other(status)
    }
}

/// Observe a testcase and return the `bhf.collector-event.v1` JSONL stream.
///
/// This first cut performs the real session-rights probe and records fidelity
/// honestly. Decoding live `EVENT_RECORD`s into [`crate::win_core::WinRawRecord`]
/// for the process / file / image-load providers is the gated Windows-runner
/// work; until then the observable event classes are reported as unsupported
/// rather than silently treated as "the target did nothing".
pub fn collect(
    ctx: &CollectorContext,
    root_pid: u32,
    root_image: &str,
    fuzz_input: Vec<u8>,
) -> String {
    let mut builder = WinCoreBuilder::new(ctx, root_pid, root_image, fuzz_input);

    match probe_session() {
        SessionProbe::Available => {
            // Real-time payload decoding for the kernel providers is the
            // remaining native work; record it as a fidelity limitation so no
            // false "clean" assurance is implied.
            builder.mark_unsupported("etw.process_create");
            builder.mark_unsupported("etw.shell_execute");
            builder.mark_unsupported("etw.file_op");
            builder.mark_unsupported("etw.module_load");
        }
        SessionProbe::PermissionDenied => {
            builder.mark_permission_denied("StartTraceW returned ERROR_ACCESS_DENIED");
        }
        SessionProbe::Other(status) => {
            builder.mark_lost(0);
            builder.mark_unsupported(format!("etw.session_start_status={status}"));
        }
    }

    builder.finish(ctx.window_ms as f64 / 1000.0);
    builder.to_jsonl()
}

/// Sidecar `main`: read context from the environment, collect, and write the
/// JSONL stream to `BHF_COLLECTOR_LOG` (or stdout). Returns a process exit code.
pub fn main_entry() -> i32 {
    let ctx = context_from_env();
    let root_pid = root_pid_from_env();
    let root_image = std::env::var("BHF_COLLECTOR_ROOT_IMAGE").unwrap_or_default();
    let fuzz_input = fuzz_input_from_env();

    let jsonl = collect(&ctx, root_pid, &root_image, fuzz_input);

    // Validate we emit parseable schema before handing it to the sink.
    for line in jsonl.lines().filter(|l| !l.trim().is_empty()) {
        if serde_json::from_str::<CollectorEvent>(line).is_err() {
            eprintln!("bhf-collector-win: produced a malformed event line");
            return 1;
        }
    }

    match std::env::var("BHF_COLLECTOR_LOG") {
        Ok(path) if !path.is_empty() => match std::fs::File::create(&path) {
            Ok(mut f) => {
                if f.write_all(jsonl.as_bytes()).is_err() {
                    return 1;
                }
            }
            Err(_) => return 1,
        },
        _ => {
            print!("{jsonl}");
        }
    }
    0
}
