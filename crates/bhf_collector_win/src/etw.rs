// SPDX-License-Identifier: Apache-2.0
#![cfg(windows)]

//! Live Windows ETW consumer. **Windows-only** (`#[cfg(windows)]`): this module
//! is excluded from non-Windows builds, so the crate compiles to its pure core
//! on Linux CI. All `unsafe` FFI is confined here; [`crate::win_core`] and
//! [`crate::win_etw_decode`] stay safe and pure.
//!
//! This consumer starts a **BHF-owned, uniquely-named system-logger** real-time
//! session (NOT the single global NT Kernel Logger) with the process, file-I/O
//! and image-load flags, opens it with a real-time `EVENT_RECORD` callback, and
//! runs `ProcessTrace` on a worker thread for the bounded observation window.
//! Every delivered `EVENT_RECORD` is routed through the pure
//! [`crate::win_etw_decode::EtwDecoder`] — the complete, Linux-unit-tested decode
//! of the process / file-I/O / image-load MOF payloads — and the decoded
//! [`crate::win_core::WinRawRecord`] is fed into the attribution core.
//!
//! Session ownership (#77): the collector runs its own private system-logger
//! session so it can only ever stop a session it created. It never touches the
//! global NT Kernel Logger and never issues a STOP against a session it did not
//! start — a name collision is resolved by trying a fresh unique name (bounded),
//! never by stopping the (possibly unrelated) session that holds the name. The
//! whole ownership policy is the pure, Linux-tested [`crate::win_core`]
//! `decide_session_start` / `stop_plan_for_owned`; this module only maps Win32
//! status codes onto it and performs the resulting FFI calls.
//!
//! Starting a system-logger ETW session requires rights the target context may
//! not have; when `StartTraceW` returns `ERROR_ACCESS_DENIED` the provider
//! records [`runtime_collector::schema::Fidelity::permission_denied`] rather than
//! emitting a silent "clean" stream (AC #6). A collision-exhausted or other
//! acquisition failure is likewise recorded as a degraded observation, never a
//! clean one and never an aborted run. The end-to-end live run (that the three
//! positive fixtures actually produce their findings) is validated on the Windows
//! runner via the gated `live_windows` test; the decode logic itself is exercised
//! on every platform by the `win_etw_decode` unit tests.

use runtime_collector::schema::CollectorEvent;
use runtime_collector::CollectorContext;
use std::ffi::c_void;
use std::io::Write;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::win_core::{self, SessionStartDecision, SessionStopTarget, WinCoreBuilder};
use crate::win_etw_decode::{EtwDecoder, EtwGuid, EtwProvider, PointerSize, RawEtwEvent};

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, OpenTraceW, ProcessTrace, StartTraceW, CONTROLTRACE_HANDLE,
    EVENT_HEADER_FLAG_32_BIT_HEADER, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_FLAG,
    EVENT_TRACE_FLAG_FILE_IO, EVENT_TRACE_FLAG_FILE_IO_INIT, EVENT_TRACE_FLAG_IMAGE_LOAD,
    EVENT_TRACE_FLAG_PROCESS, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, EVENT_TRACE_SYSTEM_LOGGER_MODE, PROCESSTRACE_HANDLE,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, WNODE_FLAG_TRACED_GUID,
};

/// Process-global base for BHF-owned session instance ids, so two observations in
/// the same process (and each retry within one) always get a distinct session
/// name and GUID. Bumped by [`MAX_SESSION_NAME_ATTEMPTS`](win_core::MAX_SESSION_NAME_ATTEMPTS)
/// per acquisition to leave room for that acquisition's retries.
static SESSION_INSTANCE: AtomicU64 = AtomicU64::new(0);

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

/// Outcome of trying to acquire a BHF-owned ETW session.
enum StartOutcome {
    /// The session started and is owned by this process. `control` is the handle
    /// `StartTraceW` returned (teardown's only stop target); `name` is the owned
    /// session name, needed to open the real-time consumer.
    Started {
        control: CONTROLTRACE_HANDLE,
        name: Vec<u16>,
    },
    /// Starting a session was denied — recorded as a permission-denied fidelity
    /// limitation, never a clean run.
    PermissionDenied,
    /// A collision-exhausted or other acquisition failure — recorded as the given
    /// `fidelity.unsupported_fields` diagnostic, never a clean run. Nothing is
    /// stopped (BHF owns no session here).
    Unsupported(String),
}

/// A zero-initialized `EVENT_TRACE_PROPERTIES` blob with room for `name_slots`
/// trailing UTF-16 session names after the header. `StartTraceW` needs one slot
/// for the session name it copies in; a `ControlTraceW` STOP that reads the
/// session properties back needs room for both the logger name and the log-file
/// name, hence two slots.
fn properties_blob(name_units: usize, name_slots: usize) -> Vec<u8> {
    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let total = props_size + name_slots * name_units * std::mem::size_of::<u16>();
    vec![0u8; total]
}

/// A session name as an owned, NUL-terminated UTF-16 buffer for the ETW APIs.
fn session_name_utf16(name: &str) -> Vec<u16> {
    let mut out: Vec<u16> = name.encode_utf16().collect();
    out.push(0);
    out
}

/// A BHF-private session GUID derived from `(pid, instance)`, unique per live
/// session so concurrent BHF workers never share one. It is deliberately NOT
/// `SystemTraceControlGuid`: per Microsoft's "Configuring and Starting a
/// SystemTraceProvider Session", a system logger other than the NT Kernel Logger
/// must be given its own GUID and must not reuse `SystemTraceControlGuid`.
/// https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session
fn private_session_guid(pid: u32, instance: u64) -> GUID {
    // A fixed BHF namespace in the high 64 bits; the pid and instance in the low
    // 64 bits make each live session's GUID distinct.
    const BHF_NAMESPACE_HI: u64 = 0xB8F0_C011_7E70_0001;
    let lo = ((pid as u64) << 32) | (instance & 0xFFFF_FFFF);
    GUID::from_u128(((BHF_NAMESPACE_HI as u128) << 64) | lo as u128)
}

/// Acquire a BHF-owned real-time system-logger session with the collector's
/// kernel flags. On a name collision this tries a fresh unique name (bounded by
/// [`win_core::MAX_SESSION_NAME_ATTEMPTS`]) rather than stopping the colliding
/// session, and degrades (never aborts, never claims clean) when it cannot
/// acquire one. The retry/degrade policy is the pure [`win_core::decide_session_start`].
fn start_owned_session() -> StartOutcome {
    let pid = std::process::id();
    // Reserve this acquisition's slice of the instance space up front so its
    // retries — and any concurrent acquisition — never collide on a name/GUID.
    let base = SESSION_INSTANCE.fetch_add(
        win_core::MAX_SESSION_NAME_ATTEMPTS as u64,
        Ordering::Relaxed,
    );

    for attempt in 0..win_core::MAX_SESSION_NAME_ATTEMPTS {
        let instance = base + attempt as u64;
        let name = session_name_utf16(&win_core::owned_session_name(pid, instance));
        let guid = private_session_guid(pid, instance);
        let result = try_start_owned_session(&name, guid);
        let status = classify_start(&result);
        match win_core::decide_session_start(status, attempt) {
            SessionStartDecision::Proceed => {
                let control = result.expect("Proceed is returned only for a started session");
                return StartOutcome::Started { control, name };
            }
            SessionStartDecision::RetryWithNewName => continue,
            SessionStartDecision::Degrade(reason) => return degrade_outcome(&reason),
        }
    }

    // All attempts collided (every decision was RetryWithNewName): degrade.
    StartOutcome::Unsupported(win_core::SessionDegradeReason::NameCollisionExhausted.diagnostic())
}

/// Map a raw `StartTraceW` result to the platform-neutral status the pure policy
/// consumes, without consuming `result` (the handle is needed on success).
fn classify_start(result: &Result<CONTROLTRACE_HANDLE, u32>) -> win_core::SessionStartStatus {
    match result {
        Ok(_) => win_core::SessionStartStatus::Started,
        Err(code) if *code == ERROR_ALREADY_EXISTS => win_core::SessionStartStatus::AlreadyExists,
        Err(code) if *code == ERROR_ACCESS_DENIED => win_core::SessionStartStatus::AccessDenied,
        Err(code) => win_core::SessionStartStatus::Other(*code),
    }
}

/// Turn a degrade reason into the corresponding [`StartOutcome`]; a failed start
/// owns no session, so nothing is ever stopped here.
fn degrade_outcome(reason: &win_core::SessionDegradeReason) -> StartOutcome {
    match reason {
        win_core::SessionDegradeReason::PermissionDenied => StartOutcome::PermissionDenied,
        other => StartOutcome::Unsupported(other.diagnostic()),
    }
}

/// Start one BHF-owned system-logger session named `name` with GUID `guid`.
fn try_start_owned_session(name: &[u16], guid: GUID) -> Result<CONTROLTRACE_HANDLE, u32> {
    let mut blob = properties_blob(name.len(), 1);
    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();

    // SAFETY: `blob` is at least `size_of::<EVENT_TRACE_PROPERTIES>()` bytes and
    // zero-initialized, with one trailing name slot `StartTraceW` copies the
    // session name into; every field write stays within the allocation.
    let (status, handle) = unsafe {
        let props = blob.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        (*props).Wnode.BufferSize = blob.len() as u32;
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        // A BHF-private session GUID — NOT SystemTraceControlGuid, which is
        // reserved for the global NT Kernel Logger (see MS "Configuring and
        // Starting a SystemTraceProvider Session").
        (*props).Wnode.Guid = guid;
        (*props).Wnode.ClientContext = 1; // QPC clock

        // EVENT_TRACE_SYSTEM_LOGGER_MODE makes this a per-session system logger
        // that honors the kernel EnableFlags below without touching the single
        // global NT Kernel Logger; REAL_TIME_MODE delivers events live. Same MS
        // doc: a system logger needs SYSTEM_LOGGER_MODE plus EnableFlags.
        (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
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

/// Stop a session this process OWNS, identified by the control handle
/// `StartTraceW` returned. This is teardown's only stop path: the owned handle
/// comes from a successful start, so BHF can never stop a session it did not
/// create (#77). The authorized target is computed by the pure
/// [`win_core::stop_plan_for_owned`], whose [`SessionStopTarget`] has no by-name
/// variant — stopping an unowned session is unrepresentable.
fn stop_owned_session(control: CONTROLTRACE_HANDLE, name_units: usize) {
    let SessionStopTarget::OwnedHandle(handle_value) = win_core::stop_plan_for_owned(control.Value);
    let mut blob = properties_blob(name_units.max(1), 2);
    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    // SAFETY: zero-initialized blob large enough for the header plus two trailing
    // name slots that ControlTraceW writes the session/log-file names back into.
    unsafe {
        let props = blob.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        (*props).Wnode.BufferSize = blob.len() as u32;
        (*props).LoggerNameOffset = props_size as u32;
        (*props).LogFileNameOffset =
            (props_size + name_units.max(1) * std::mem::size_of::<u16>()) as u32;
        let handle = CONTROLTRACE_HANDLE {
            Value: handle_value,
        };
        // Stop BY HANDLE: the InstanceName is null so the session is identified
        // solely by the owned handle, never by a (possibly unowned) name.
        let _ = ControlTraceW(handle, ptr::null(), props, EVENT_TRACE_CONTROL_STOP);
    }
}

/// True when `OpenTraceW` returned the invalid-handle sentinel.
fn is_invalid_trace_handle(handle: &PROCESSTRACE_HANDLE) -> bool {
    handle.Value == u64::MAX || handle.Value == 0x0000_0000_FFFF_FFFF
}

/// Open the BHF-owned real-time session `name` and consume events into `state`
/// for `window_ms`. `control` is the owned session handle used to stop it, which
/// makes `ProcessTrace` return. On an open failure the loss is recorded in
/// fidelity, never hidden — and the owned session is still stopped by its handle.
fn run_consumer(
    state_ptr: *mut ConsumerState,
    control: CONTROLTRACE_HANDLE,
    name: &[u16],
    window_ms: u64,
) {
    // OpenTraceW wants a writable LoggerName buffer; copy the owned session name.
    let mut logger_name = name.to_vec();

    // SAFETY: a zeroed EVENT_TRACE_LOGFILEW is a valid "no file" real-time
    // consumer once LoggerName/mode/callback/context are set.
    let process_handle = unsafe {
        let mut logfile: EVENT_TRACE_LOGFILEW = std::mem::zeroed();
        logfile.LoggerName = logger_name.as_mut_ptr();
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
        // We started (and therefore own) this session, so stop it by its handle
        // even though the consumer could not open it — never by (unowned) name.
        stop_owned_session(control, name.len());
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

    // Stopping the OWNED session unblocks ProcessTrace on the worker thread. The
    // stop is issued strictly via the handle StartTraceW returned, not the name.
    stop_owned_session(control, name.len());
    let _ = worker.join();

    // SAFETY: the worker thread has joined, so the callback can no longer run and
    // this is again the only accessor of `state`/the trace handle.
    unsafe {
        CloseTrace(process_handle);
    }
    // keep `logger_name` alive until the consumer is fully torn down.
    drop(logger_name);
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
/// Starts a BHF-owned system-logger session, consumes process / file-I/O /
/// image-load events for the bounded window, decodes each `EVENT_RECORD` with the
/// complete pure decoder and attributes it to the testcase's descendant tree. A
/// missing-rights or otherwise failed start records a degraded fidelity
/// limitation (`permission_denied` / an unsupported-field diagnostic) instead of
/// fabricating a clean run, and never stops a session BHF did not create.
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

    match start_owned_session() {
        StartOutcome::Started { control, name } => {
            let state_ptr: *mut ConsumerState = &mut *state;
            run_consumer(state_ptr, control, &name, ctx.window_ms);
        }
        StartOutcome::PermissionDenied => {
            state
                .builder
                .mark_permission_denied("StartTraceW returned ERROR_ACCESS_DENIED");
        }
        StartOutcome::Unsupported(reason) => {
            state.builder.mark_unsupported(reason);
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
