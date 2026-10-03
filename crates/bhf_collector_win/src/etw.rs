// SPDX-License-Identifier: Apache-2.0
#![cfg(windows)]

//! Live Windows ETW consumer. **Windows-only** (`#[cfg(windows)]`): this module
//! is excluded from non-Windows builds, so the crate compiles to its pure core
//! on Linux CI. All `unsafe` FFI is confined here; [`crate::win_core`] and
//! [`crate::win_etw_decode`] stay safe and pure.
//!
//! This consumer starts the NT Kernel Logger real-time session with the process,
//! file-I/O and image-load flags, opens it with a real-time `EVENT_RECORD`
//! callback, and runs `ProcessTrace` on a worker thread for the bounded
//! observation window. Every delivered `EVENT_RECORD` is routed through the pure
//! [`crate::win_etw_decode::EtwDecoder`] — the complete, Linux-unit-tested decode
//! of the process / file-I/O / image-load MOF payloads — and the decoded
//! [`crate::win_core::WinRawRecord`] is fed into the attribution core.
//!
//! Starting a kernel ETW session requires rights the target context may not
//! have; when `StartTraceW` returns `ERROR_ACCESS_DENIED` the provider records
//! [`runtime_collector::schema::Fidelity::permission_denied`] rather than
//! emitting a silent "clean" stream (AC #6). The end-to-end live run (that the
//! three positive fixtures actually produce their findings) is validated on the
//! Windows runner via the gated `live_windows` test; the decode logic itself is
//! exercised on every platform by the `win_etw_decode` unit tests.

use runtime_collector::schema::CollectorEvent;
use runtime_collector::CollectorContext;
use std::ffi::c_void;
use std::io::Write;
use std::ptr;
use std::time::Duration;

use crate::win_core::WinCoreBuilder;
use crate::win_etw_decode::{EtwDecoder, EtwGuid, EtwProvider, PointerSize, RawEtwEvent};

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, OpenTraceW, ProcessTrace, StartTraceW, CONTROLTRACE_HANDLE,
    EVENT_HEADER_FLAG_32_BIT_HEADER, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_FLAG,
    EVENT_TRACE_FLAG_FILE_IO, EVENT_TRACE_FLAG_FILE_IO_INIT, EVENT_TRACE_FLAG_IMAGE_LOAD,
    EVENT_TRACE_FLAG_PROCESS, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, KERNEL_LOGGER_NAMEW, PROCESSTRACE_HANDLE,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, SystemTraceControlGuid,
    WNODE_FLAG_TRACED_GUID,
};

/// Shared state the real-time callback mutates. Only the `ProcessTrace` worker
/// thread touches it between session start and join; the controlling thread
/// never reads it during that window, so the raw-pointer hand-off is sound.
struct ConsumerState {
    builder: WinCoreBuilder,
    decoder: EtwDecoder,
    /// First raw timestamp seen, used to normalize all events to seconds relative
    /// to the session start (the clock may be QPC or FILETIME; only the relative
    /// value matters to attribution / the post-exit window).
    base_ts: Option<i64>,
    /// Largest relative timestamp observed, used as the `end` boundary so every
    /// in-window event is retained by host-side attribution.
    max_ts: f64,
}

/// Number of 100ns ticks per second, used to render a raw timestamp as seconds.
const TICKS_PER_SEC: f64 = 10_000_000.0;

/// The kernel flags the collector subscribes to: process start/stop, image load,
/// and file I/O (plus the rundown that names existing file objects).
fn kernel_enable_flags() -> EVENT_TRACE_FLAG {
    EVENT_TRACE_FLAG_PROCESS
        | EVENT_TRACE_FLAG_IMAGE_LOAD
        | EVENT_TRACE_FLAG_FILE_IO
        | EVENT_TRACE_FLAG_FILE_IO_INIT
}

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

/// Outcome of trying to start the kernel session.
enum StartOutcome {
    Started(CONTROLTRACE_HANDLE),
    PermissionDenied,
    Other(u32),
}

/// A zero-initialized `EVENT_TRACE_PROPERTIES` blob with room for the logger name
/// appended after the header (the layout `StartTraceW`/`ControlTraceW` expect).
fn properties_blob() -> Vec<u8> {
    // The NT Kernel Logger name plus NUL, as UTF-16.
    let name_units = kernel_logger_name().len();
    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let total = props_size + name_units * std::mem::size_of::<u16>();
    vec![0u8; total]
}

/// `"NT Kernel Logger\0"` as UTF-16 code units.
fn kernel_logger_name() -> Vec<u16> {
    // KERNEL_LOGGER_NAMEW is a NUL-terminated wide literal; copy it out so we own
    // a mutable buffer for OpenTraceW's LoggerName.
    let mut out = Vec::new();
    let mut p = KERNEL_LOGGER_NAMEW;
    // SAFETY: KERNEL_LOGGER_NAMEW points at a static NUL-terminated wide string.
    unsafe {
        while *p != 0 {
            out.push(*p);
            p = p.add(1);
        }
    }
    out.push(0);
    out
}

/// Start the NT Kernel Logger real-time session with the collector's flags.
/// Retries once after stopping a pre-existing instance.
fn start_kernel_session() -> StartOutcome {
    match try_start_kernel_session() {
        Ok(handle) => StartOutcome::Started(handle),
        Err(ERROR_ALREADY_EXISTS) => {
            stop_kernel_session();
            match try_start_kernel_session() {
                Ok(handle) => StartOutcome::Started(handle),
                Err(ERROR_ACCESS_DENIED) => StartOutcome::PermissionDenied,
                Err(code) => StartOutcome::Other(code),
            }
        }
        Err(ERROR_ACCESS_DENIED) => StartOutcome::PermissionDenied,
        Err(code) => StartOutcome::Other(code),
    }
}

fn try_start_kernel_session() -> Result<CONTROLTRACE_HANDLE, u32> {
    let mut blob = properties_blob();
    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let name = kernel_logger_name();

    // SAFETY: `blob` is at least `size_of::<EVENT_TRACE_PROPERTIES>()` bytes and
    // zero-initialized; every field write stays within the allocation.
    let (status, handle) = unsafe {
        let props = blob.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        (*props).Wnode.BufferSize = blob.len() as u32;
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*props).Wnode.Guid = SystemTraceControlGuid;
        (*props).Wnode.ClientContext = 1; // QPC clock
        (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*props).FlushTimer = 1;
        (*props).EnableFlags = kernel_enable_flags();
        (*props).LoggerNameOffset = props_size as u32;

        let mut handle = CONTROLTRACE_HANDLE::default();
        let status = StartTraceW(&mut handle, name.as_ptr(), props);
        (status, handle)
    };
    if status == ERROR_SUCCESS {
        Ok(handle)
    } else {
        Err(status)
    }
}

/// Stop the NT Kernel Logger session by name (best effort).
fn stop_kernel_session() {
    let mut blob = properties_blob();
    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let name = kernel_logger_name();
    // SAFETY: zero-initialized blob large enough for the header; a STOP by name
    // needs only BufferSize + LoggerNameOffset set.
    unsafe {
        let props = blob.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        (*props).Wnode.BufferSize = blob.len() as u32;
        (*props).Wnode.Guid = SystemTraceControlGuid;
        (*props).LoggerNameOffset = props_size as u32;
        let handle = CONTROLTRACE_HANDLE::default();
        let _ = ControlTraceW(handle, name.as_ptr(), props, EVENT_TRACE_CONTROL_STOP);
    }
}

/// True when `OpenTraceW` returned the invalid-handle sentinel.
fn is_invalid_trace_handle(handle: &PROCESSTRACE_HANDLE) -> bool {
    handle.Value == u64::MAX || handle.Value == 0x0000_0000_FFFF_FFFF
}

/// Open the real-time session and consume events into `state` for `window_ms`.
/// `control` is the session handle used to stop it, which makes `ProcessTrace`
/// return. On an open failure the loss is recorded in fidelity, never hidden.
fn run_consumer(state_ptr: *mut ConsumerState, control: CONTROLTRACE_HANDLE, window_ms: u64) {
    let mut name = kernel_logger_name();

    // SAFETY: a zeroed EVENT_TRACE_LOGFILEW is a valid "no file" real-time
    // consumer once LoggerName/mode/callback/context are set.
    let process_handle = unsafe {
        let mut logfile: EVENT_TRACE_LOGFILEW = std::mem::zeroed();
        logfile.LoggerName = name.as_mut_ptr();
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);
        logfile.Context = state_ptr as *mut c_void;
        OpenTraceW(&mut logfile)
    };

    if is_invalid_trace_handle(&process_handle) {
        // SAFETY: nothing else touches `state` yet (the worker thread is not
        // spawned), so this exclusive access is sound.
        unsafe {
            (*state_ptr)
                .builder
                .mark_unsupported("etw.open_trace_failed");
        }
        stop_kernel_session();
        return;
    }

    // ProcessTrace blocks until the session stops; run it on a worker thread so
    // the controlling thread can bound the observation window.
    let handle_value = process_handle.Value;
    let worker = std::thread::spawn(move || {
        let handle = PROCESSTRACE_HANDLE {
            Value: handle_value,
        };
        // SAFETY: `handle` came from a successful OpenTraceW; a null time range
        // means "process everything until the session stops".
        unsafe {
            ProcessTrace(&handle, 1, ptr::null(), ptr::null());
        }
    });

    std::thread::sleep(Duration::from_millis(window_ms));

    // Stopping the session unblocks ProcessTrace on the worker thread.
    let _ = control;
    stop_kernel_session();
    let _ = worker.join();

    // SAFETY: the worker thread has joined, so the callback can no longer run and
    // this is again the only accessor of `state`/the trace handle.
    unsafe {
        CloseTrace(process_handle);
    }
    // keep `name` alive until the consumer is fully torn down.
    drop(name);
}

/// Real-time `EVENT_RECORD` callback. Routes the event through the pure decoder
/// and feeds any decoded record into the attribution core.
///
/// # Safety
/// ETW calls this with a valid `EVENT_RECORD*` whose `UserContext` is the
/// `*mut ConsumerState` installed on the logfile. It runs only on the
/// `ProcessTrace` worker thread.
unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    // SAFETY: ETW guarantees a valid record for the duration of the call.
    let record = unsafe { &*record };
    let state_ptr = record.UserContext as *mut ConsumerState;
    if state_ptr.is_null() {
        return;
    }
    // SAFETY: the controlling thread installed this pointer and does not touch
    // `*state_ptr` while ProcessTrace runs, so the worker thread has exclusive
    // access here.
    let state = unsafe { &mut *state_ptr };

    let header = &record.EventHeader;
    let provider = EtwProvider::from_guid(&guid_to_etw(&header.ProviderId));
    if provider == EtwProvider::Other {
        return;
    }

    let pointer_size = if (header.Flags as u32 & EVENT_HEADER_FLAG_32_BIT_HEADER) != 0 {
        PointerSize::Four
    } else {
        PointerSize::Eight
    };

    let raw_ts = header.TimeStamp;
    let base = *state.base_ts.get_or_insert(raw_ts);
    let rel = (raw_ts.saturating_sub(base)).max(0) as f64 / TICKS_PER_SEC;
    if rel > state.max_ts {
        state.max_ts = rel;
    }

    let len = record.UserDataLength as usize;
    let data_ptr = record.UserData as *const u8;
    // SAFETY: ETW provides `UserDataLength` bytes at `UserData` for this call.
    let user_data: &[u8] = if data_ptr.is_null() || len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data_ptr, len) }
    };

    let raw = RawEtwEvent {
        provider,
        opcode: header.EventDescriptor.Opcode,
        version: header.EventDescriptor.Version,
        pointer_size,
        header_pid: header.ProcessId,
        timestamp: rel,
        user_data,
    };
    if let Some(decoded) = state.decoder.decode(&raw) {
        state.builder.ingest(decoded);
    }
}

/// Convert a `windows_sys` `GUID` into the decoder's field-for-field GUID.
fn guid_to_etw(guid: &GUID) -> EtwGuid {
    EtwGuid::new(guid.data1, guid.data2, guid.data3, guid.data4)
}

/// Observe a testcase and return the `bhf.collector-event.v1` JSONL stream.
///
/// Starts the kernel logger, consumes process / file-I/O / image-load events for
/// the bounded window, decodes each `EVENT_RECORD` with the complete pure decoder
/// and attributes it to the testcase's descendant tree. A missing-rights start
/// records `fidelity.permission_denied` instead of fabricating a clean run.
pub fn collect(
    ctx: &CollectorContext,
    root_pid: u32,
    root_image: &str,
    fuzz_input: Vec<u8>,
) -> String {
    let mut state = Box::new(ConsumerState {
        builder: WinCoreBuilder::new(ctx, root_pid, root_image, fuzz_input),
        decoder: EtwDecoder::new(),
        base_ts: None,
        max_ts: 0.0,
    });

    match start_kernel_session() {
        StartOutcome::Started(control) => {
            let state_ptr: *mut ConsumerState = &mut *state;
            run_consumer(state_ptr, control, ctx.window_ms);
        }
        StartOutcome::PermissionDenied => {
            state
                .builder
                .mark_permission_denied("StartTraceW returned ERROR_ACCESS_DENIED");
        }
        StartOutcome::Other(status) => {
            state
                .builder
                .mark_unsupported(format!("etw.session_start_status={status}"));
        }
    }

    // Close the observation at the last event we saw (or the nominal window if no
    // event arrived) so host-side attribution keeps every in-window effect.
    let end_ts = state.max_ts.max(ctx.window_ms as f64 / 1000.0);
    state.builder.finish(end_ts);
    state.builder.to_jsonl()
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
