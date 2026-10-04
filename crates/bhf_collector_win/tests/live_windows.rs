// SPDX-License-Identifier: Apache-2.0
#![cfg(windows)]

//! Dependency-gated live ETW tests. The whole file is `#[cfg(windows)]`, so on
//! Linux CI it compiles to an empty test binary and runs nothing. Each test is
//! additionally `#[ignore]` unless `BHF_WIN_LIVE=1`, so it only executes on a
//! Windows runner that opts in (the `windows-build` CI job sets the variable).

use bhf_collector_win::etw;
use runtime_collector::{CollectorContext, CollectorSessionSet};

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Diagnostics::Etw::{
    ControlTraceW, StartTraceW, CONTROLTRACE_HANDLE, EVENT_TRACE_CONTROL_QUERY,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE,
    WNODE_FLAG_TRACED_GUID,
};

fn live_enabled() -> bool {
    std::env::var("BHF_WIN_LIVE").as_deref() == Ok("1")
}

/// A zero-initialized properties blob with room for `slots` trailing name buffers.
fn props_blob(name_units: usize, slots: usize) -> Vec<u8> {
    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    vec![0u8; props_size + slots * name_units * std::mem::size_of::<u16>()]
}

/// A NUL-terminated UTF-16 session name.
fn wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

/// Start a plain real-time session with a private GUID and no provider enabled —
/// a stand-in for an unrelated profiler/diagnostic session that BHF must never
/// stop. Panics if the session cannot be created.
fn start_unrelated_session(name: &[u16], guid: GUID) -> CONTROLTRACE_HANDLE {
    let mut blob = props_blob(name.len(), 1);
    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    // SAFETY: zero-initialized blob with one trailing name slot StartTraceW copies
    // the session name into; every field write stays inside the allocation.
    unsafe {
        let props = blob.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        (*props).Wnode.BufferSize = blob.len() as u32;
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*props).Wnode.Guid = guid;
        (*props).Wnode.ClientContext = 1;
        (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*props).FlushTimer = 1;
        (*props).LoggerNameOffset = props_size as u32;
        let mut handle = CONTROLTRACE_HANDLE::default();
        let status = StartTraceW(&mut handle, name.as_ptr(), props);
        assert_eq!(
            status, ERROR_SUCCESS,
            "could not start the unrelated test session (status {status})"
        );
        handle
    }
}

/// Query a session by name; the returned Win32 status is `ERROR_SUCCESS` while
/// the session is alive.
fn query_session(name: &[u16]) -> u32 {
    let mut blob = props_blob(name.len(), 2);
    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    // SAFETY: zero-initialized blob large enough for the header plus two name slots
    // ControlTraceW writes the session/log-file names back into.
    unsafe {
        let props = blob.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        (*props).Wnode.BufferSize = blob.len() as u32;
        (*props).LoggerNameOffset = props_size as u32;
        (*props).LogFileNameOffset = (props_size + std::mem::size_of_val(name)) as u32;
        ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            name.as_ptr(),
            props,
            EVENT_TRACE_CONTROL_QUERY,
        )
    }
}

/// Stop a session by its own handle (test cleanup).
fn stop_session_by_handle(handle: CONTROLTRACE_HANDLE, name_units: usize) {
    let mut blob = props_blob(name_units.max(1), 2);
    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    // SAFETY: as `query_session`, with a valid owned handle.
    unsafe {
        let props = blob.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        (*props).Wnode.BufferSize = blob.len() as u32;
        (*props).LoggerNameOffset = props_size as u32;
        (*props).LogFileNameOffset =
            (props_size + name_units.max(1) * std::mem::size_of::<u16>()) as u32;
        let _ = ControlTraceW(handle, std::ptr::null(), props, EVENT_TRACE_CONTROL_STOP);
    }
}

fn ctx() -> CollectorContext {
    CollectorContext::new("tc-live", 0, "C:\\sandbox", 250)
}

#[test]
#[ignore = "requires BHF_WIN_LIVE=1 on a Windows runner"]
fn collect_emits_well_formed_schema() {
    if !live_enabled() {
        return;
    }
    let jsonl = etw::collect(
        &ctx(),
        std::process::id(),
        "C:\\sandbox\\target.exe",
        Vec::new(),
    );
    let set = CollectorSessionSet::from_jsonl(&jsonl);
    assert_eq!(set.malformed_lines, 0, "live stream must be valid schema");
    assert!(set.session("tc-live", 0).is_some());
}

#[test]
#[ignore = "requires BHF_WIN_LIVE=1 on a Windows runner"]
fn missing_session_rights_report_permission_denied_not_clean() {
    // AC #6 (native): a degraded ETW observation must never be reported clean —
    // when the provider records a fidelity limitation (e.g. it could not start
    // an ETW session without rights), `clean_assurance_ok()` must be false.
    //
    // This asserts the environment-robust invariant `degraded ⟹ not clean`
    // rather than assuming the runner lacks rights: GitHub's Windows runners are
    // elevated, so `etw::collect` starts the NT Kernel Logger session and
    // (correctly) reports a non-degraded, clean observation — there the
    // implication is vacuously true. On a runner without session rights the
    // permission limitation is recorded and the clean claim must be refused.
    // The deterministic form of this property is covered by the `win_core` unit
    // test `permission_denied_is_recorded_not_silent`.
    if !live_enabled() {
        return;
    }
    let jsonl = etw::collect(
        &ctx(),
        std::process::id(),
        "C:\\sandbox\\target.exe",
        Vec::new(),
    );
    let set = CollectorSessionSet::from_jsonl(&jsonl);
    let session = set.session("tc-live", 0).expect("session present");
    if session.fidelity.is_degraded() {
        assert!(
            !session.clean_assurance_ok(),
            "a degraded live observation must never be reported clean"
        );
    }
}

#[test]
#[ignore = "requires BHF_WIN_LIVE=1 on a Windows runner"]
fn owned_collection_never_stops_an_unrelated_or_peer_session() {
    // #77 (native): BHF runs its own uniquely-named system-logger session and may
    // stop only a session it created. This proves it live: an unrelated session
    // that is already running when BHF starts stays alive after BHF collects and
    // tears down, and two concurrent BHF workers each tear down only their own
    // session (so neither stops the other, nor the unrelated session).
    if !live_enabled() {
        return;
    }

    // An unrelated profiler/diagnostic session, already running, that BHF did not
    // create and must therefore never stop.
    let unrelated_name = wide(&format!("BHF-Live-Unrelated-{}", std::process::id()));
    let unrelated_guid = GUID::from_u128(0x0a1b2c3d_4e5f_6071_8293_a4b5c6d7e8f9);
    let unrelated = start_unrelated_session(&unrelated_name, unrelated_guid);
    assert_eq!(
        query_session(&unrelated_name),
        ERROR_SUCCESS,
        "the unrelated session should be running before BHF starts"
    );

    // Two concurrent BHF workers: each acquires its own uniquely-named session,
    // observes, and stops strictly by its own handle.
    let workers: Vec<_> = (0..2u32)
        .map(|w| {
            std::thread::spawn(move || {
                etw::collect(
                    &CollectorContext::new(format!("tc-live-{w}"), w, "C:\\sandbox", 150),
                    std::process::id(),
                    "C:\\sandbox\\target.exe",
                    Vec::new(),
                )
            })
        })
        .collect();
    let outputs: Vec<String> = workers.into_iter().map(|h| h.join().unwrap()).collect();

    // The unrelated session is STILL running: BHF stopped only sessions it owned.
    let status = query_session(&unrelated_name);
    // Clean up our test session first so a failed assertion never leaks it.
    stop_session_by_handle(unrelated, unrelated_name.len());
    assert_eq!(
        status, ERROR_SUCCESS,
        "BHF must not stop an unrelated ETW session it did not create (query status {status})"
    );

    // Each worker still produced a well-formed, parseable stream for its own
    // testcase — teardown by peers did not corrupt its observation.
    for (w, jsonl) in outputs.iter().enumerate() {
        let set = CollectorSessionSet::from_jsonl(jsonl);
        assert_eq!(
            set.malformed_lines, 0,
            "worker {w} stream must be valid schema"
        );
        assert!(
            set.session(&format!("tc-live-{w}"), w as u32).is_some(),
            "worker {w} session present"
        );
    }
}

#[test]
#[ignore = "requires BHF_WIN_LIVE=1 on a Windows runner"]
fn replay_readiness_ack_and_clean_control_scaffold() {
    // #76 native scaffold (gated BHF_WIN_LIVE). The FULL positive/clean control —
    // the host spawning a retained testcase as a REAL child UNDER the live ETW
    // session after the readiness ack, then handing off the child pid — is not yet
    // wired (the native sidecar observes its own window; the host-driven replay
    // spawn is the remaining piece). What IS native and asserted here: the #76
    // readiness ack the host relies on to confirm the collector is watching, and
    // the positive/clean invariant that a non-degraded live observation reports a
    // clean assurance.
    if !live_enabled() {
        return;
    }
    let ready = std::env::temp_dir().join(format!("bhf-live-ready-{}", std::process::id()));
    let _ = std::fs::remove_file(&ready);
    // SAFETY: nextest runs each test in its own process, so this env mutation is
    // process-local and not observed by other tests.
    std::env::set_var("BHF_COLLECTOR_READY", &ready);
    let jsonl = etw::collect(
        &ctx(),
        std::process::id(),
        "C:\\sandbox\\target.exe",
        Vec::new(),
    );
    std::env::remove_var("BHF_COLLECTOR_READY");

    assert!(
        ready.exists(),
        "the collector must signal the #76 readiness ack to the host"
    );
    let _ = std::fs::remove_file(&ready);

    let set = CollectorSessionSet::from_jsonl(&jsonl);
    assert_eq!(set.malformed_lines, 0, "live stream must be valid schema");
    let session = set.session("tc-live", 0).expect("session present");
    if !session.fidelity.is_degraded() {
        assert!(
            session.clean_assurance_ok(),
            "a non-degraded live observation is a clean assurance"
        );
    }
}

// The three positive fixtures (ShellExecuteExW on a fuzz-controlled target, a
// fuzz-controlled `..\\escaped` path, and LoadLibraryW on a fuzz-controlled
// non-system path) plus the fixed-constant negative controls require live
// EVENT_RECORD decoding, which is validated and completed on the Windows runner.
// They are tracked separately so this gate stays honest about what the current
// native cut observes.
