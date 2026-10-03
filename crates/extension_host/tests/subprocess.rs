// SPDX-License-Identifier: Apache-2.0
#![cfg(unix)]

//! Integration tests that spawn a real subprocess extension.
//!
//! The always-on path uses the in-repo `bhf_mock_extension` test binary to
//! exercise the real spawn/handshake/evaluate path and every fault mode. A
//! dependency-gated test additionally drives the out-of-tree Python reference
//! extension when `python3` is available, proving language-independent,
//! no-bhf-internals interop.
//!
//! This file is `cfg(unix)` because it asserts child kill/reap and (optionally)
//! resource-limit behaviour; the Windows build does not run
//! `package(extension_host)` tests.

use extension_host::{
    CaseId, CodecOutcome, EvaluateOutcome, ExtensionClient, ExtensionManifest, InfraFailure,
    Limits, MutateOutcome, RestartPolicy, SessionDriver, SessionOptions, SessionTarget, SpawnSpec,
};
use std::collections::BTreeMap;
use std::time::Duration;

const MOCK: &str = env!("CARGO_BIN_EXE_bhf_mock_extension");

/// Every session capability, requested as optional so an extension that provides
/// only a subset still negotiates cleanly.
const SESSION_CAPS: &[&str] = &[
    "codec.decode",
    "codec.encode",
    "codec.repair",
    "mutator.mutate",
    "scenario.next",
    "scenario.observe-response",
    "lifecycle.setup",
    "lifecycle.reset",
    "lifecycle.teardown",
];

fn case(worker: &str, testcase: &str) -> CaseId {
    CaseId::new("test-campaign", worker, testcase)
}

/// A spec driving the mock in `mode`, with a short per-call deadline and no
/// restarts (each test overrides what it needs).
fn mock_spec(mode: &str) -> SpawnSpec {
    let mut spec = SpawnSpec::new(MOCK);
    spec.args = vec!["--mode".to_string(), mode.to_string()];
    spec.limits = Limits {
        max_frame_bytes: 1 << 20,
        call_timeout: Duration::from_millis(500),
        max_outstanding: 1,
    };
    spec.restart = RestartPolicy::never();
    spec
}

/// A spec that also requests the full session capability surface as optional.
fn session_spec(mode: &str) -> SpawnSpec {
    let mut spec = mock_spec(mode);
    spec.optional_capabilities = SESSION_CAPS.iter().map(|c| c.to_string()).collect();
    spec
}

// ---- The toy target: `[u16 BE len][payload][u32 BE CRC-32]`, OPEN/WRITE. ----

fn toy_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn toy_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 6);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&toy_crc32(payload).to_be_bytes());
    out
}

/// Parse a frame into `(payload, crc_valid)`.
fn toy_parse(frame: &[u8]) -> Option<(Vec<u8>, bool)> {
    if frame.len() < 6 {
        return None;
    }
    let declared = u16::from_be_bytes([frame[0], frame[1]]) as usize;
    let payload = frame[2..frame.len() - 4].to_vec();
    let crc = u32::from_be_bytes([
        frame[frame.len() - 4],
        frame[frame.len() - 3],
        frame[frame.len() - 2],
        frame[frame.len() - 1],
    ]);
    let valid = declared == payload.len() && crc == toy_crc32(&payload);
    Some((payload, valid))
}

/// An in-process toy target: validates each frame's length+CRC, OPENs return a
/// fixed handle, WRITEs are acked. It records every received frame so a test can
/// assert what actually reached the target (binding, CRC validity after repair).
#[derive(Default)]
struct ToyTarget {
    handle: &'static str,
    received: Vec<ReceivedFrame>,
}

struct ReceivedFrame {
    label: Option<String>,
    crc_valid: bool,
}

impl ToyTarget {
    fn new() -> Self {
        Self {
            handle: "7",
            received: Vec::new(),
        }
    }
}

impl SessionTarget for ToyTarget {
    fn exchange(
        &mut self,
        _step: u32,
        label: Option<&str>,
        message: &[u8],
    ) -> std::io::Result<Vec<u8>> {
        let (payload, crc_valid) = toy_parse(message).unwrap_or((Vec::new(), false));
        self.received.push(ReceivedFrame {
            label: label.map(str::to_string),
            crc_valid,
        });
        if !crc_valid {
            return Ok(toy_frame(b"ERR badframe"));
        }
        let text = String::from_utf8_lossy(&payload);
        if text.starts_with("OPEN ") {
            Ok(toy_frame(format!("OPENOK {}", self.handle).as_bytes()))
        } else {
            Ok(toy_frame(b"WRITEOK"))
        }
    }
}

#[test]
fn client_handshakes_then_evaluates_ok_and_finding() {
    let mut client = ExtensionClient::spawn(mock_spec("well-behaved")).expect("spawn");
    // Negotiation happened before any evaluate.
    assert_eq!(client.negotiated().protocol, "bhf.extension.v1");
    assert!(client
        .negotiated()
        .caps
        .contains(&"oracle.evaluate".to_string()));
    // Provenance stamped the executable hash + negotiated caps.
    assert_eq!(client.provenance().executable_sha256.len(), 64);
    assert_eq!(
        client.provenance().negotiated_caps,
        vec!["oracle.evaluate".to_string()]
    );

    // A benign input is OK.
    let ok = client
        .evaluate(&case("worker-0", "tc-benign"), b"logs/run-01.txt")
        .expect("evaluate benign");
    assert_eq!(ok, EvaluateOutcome::Ok);

    // A planted sandbox-escape input is a finding carrying rule/signature/evidence.
    let outcome = client
        .evaluate(&case("worker-0", "tc-escape"), b"../etc/passwd")
        .expect("evaluate escape");
    match outcome {
        EvaluateOutcome::Finding(finding) => {
            assert_eq!(finding.rule, "oracle.path-escape");
            assert_eq!(finding.classification, "extension_oracle");
            assert_eq!(finding.signature_inputs[0], "oracle.path-escape");
            assert!(finding.evidence.iter().any(|e| e.key == "path"));
            assert_eq!(
                finding.min_predicate.as_deref(),
                Some("path-contains-dotdot")
            );
        }
        other => panic!("expected a finding, got {other:?}"),
    }
}

#[test]
fn evaluate_timeout_is_infrastructure_not_finding() {
    let mut spec = mock_spec("hang");
    spec.limits.call_timeout = Duration::from_millis(250);
    let mut client = ExtensionClient::spawn(spec).expect("spawn");

    let outcome = client
        .evaluate(&case("worker-0", "tc-1"), b"../escape")
        .expect("evaluate");
    assert!(
        matches!(
            outcome,
            EvaluateOutcome::Infrastructure(InfraFailure::Timeout { .. })
        ),
        "a hang must be a bounded timeout, never a finding; got {outcome:?}"
    );
    assert_eq!(client.provenance().loss_count, 1);
}

#[test]
fn extension_crash_is_infrastructure() {
    let mut client = ExtensionClient::spawn(mock_spec("crash")).expect("spawn");
    let outcome = client
        .evaluate(&case("worker-0", "tc-1"), b"../escape")
        .expect("evaluate");
    assert!(
        matches!(
            outcome,
            EvaluateOutcome::Infrastructure(InfraFailure::Crashed { .. })
        ),
        "a crash must be bounded infrastructure; got {outcome:?}"
    );
    assert_eq!(client.provenance().loss_count, 1);
}

#[test]
fn oversized_output_is_capped_infrastructure() {
    let mut spec = mock_spec("oversize");
    // Small hard cap so the mock's declared 50MB frame is rejected at the header.
    spec.limits.max_frame_bytes = 4096;
    let mut client = ExtensionClient::spawn(spec).expect("spawn");

    let outcome = client
        .evaluate(&case("worker-0", "tc-1"), b"anything")
        .expect("evaluate");
    match outcome {
        EvaluateOutcome::Infrastructure(InfraFailure::FrameTooLarge { declared, cap }) => {
            assert_eq!(declared, 50_000_000);
            assert_eq!(cap, 4096);
        }
        other => panic!("expected FrameTooLarge, got {other:?}"),
    }
}

#[test]
fn malformed_response_is_infrastructure() {
    let mut client = ExtensionClient::spawn(mock_spec("malformed")).expect("spawn");
    let outcome = client
        .evaluate(&case("worker-0", "tc-1"), b"anything")
        .expect("evaluate");
    assert!(
        matches!(
            outcome,
            EvaluateOutcome::Infrastructure(InfraFailure::Protocol { .. })
        ),
        "a non-JSON response must be a bounded protocol error; got {outcome:?}"
    );
}

#[test]
fn unsupported_capability_is_infrastructure() {
    let mut client = ExtensionClient::spawn(mock_spec("unsupported")).expect("spawn");
    let outcome = client
        .evaluate(&case("worker-0", "tc-1"), b"../escape")
        .expect("evaluate");
    assert!(
        matches!(outcome, EvaluateOutcome::Unsupported { .. }),
        "an unsupported reply must be surfaced as bounded, not a finding; got {outcome:?}"
    );
    assert!(outcome.is_infrastructure());
}

#[test]
fn extension_reported_infrastructure_error_is_bounded_without_restart() {
    // A clean `result: infrastructure_error` is bounded but NOT a transport
    // fault: the child is healthy, so no restart/loss is recorded.
    let mut client = ExtensionClient::spawn(mock_spec("infra-error")).expect("spawn");
    let outcome = client
        .evaluate(&case("worker-0", "tc-1"), b"anything")
        .expect("evaluate");
    assert!(matches!(
        outcome,
        EvaluateOutcome::Infrastructure(InfraFailure::ExtensionReported { .. })
    ));
    assert_eq!(client.provenance().restart_count, 0);
    assert_eq!(client.provenance().loss_count, 0);
}

#[test]
fn two_workers_cannot_cross_case_identity() {
    // Two independent clients, each with its own worker identity. Each client
    // validates that a response echoes ITS request's case; neither ever sees the
    // other's identity.
    let mut a = ExtensionClient::spawn(mock_spec("well-behaved")).expect("spawn a");
    let mut b = ExtensionClient::spawn(mock_spec("well-behaved")).expect("spawn b");
    let case_a = case("worker-A", "tc-1");
    let case_b = case("worker-B", "tc-1");

    let oa = a.evaluate(&case_a, b"../escape").expect("a eval");
    let ob = b.evaluate(&case_b, b"benign/path").expect("b eval");
    assert!(matches!(oa, EvaluateOutcome::Finding(_)));
    assert_eq!(ob, EvaluateOutcome::Ok);

    // Interleaved further traffic keeps each identity straight (no CaseMismatch).
    let oa2 = a.evaluate(&case_a, b"benign/again").expect("a eval 2");
    let ob2 = b.evaluate(&case_b, b"../escape").expect("b eval 2");
    assert_eq!(oa2, EvaluateOutcome::Ok);
    assert!(matches!(ob2, EvaluateOutcome::Finding(_)));
}

#[test]
fn mismatched_case_identity_is_rejected() {
    // The enforcement proof: a mock that echoes a DIFFERENT worker is caught.
    let mut client = ExtensionClient::spawn(mock_spec("tamper-case")).expect("spawn");
    let outcome = client
        .evaluate(&case("worker-A", "tc-1"), b"benign")
        .expect("evaluate");
    match outcome {
        EvaluateOutcome::Infrastructure(InfraFailure::CaseMismatch { expected, got }) => {
            assert_eq!(expected.worker, "worker-A");
            assert_eq!(got.worker, "EVIL");
        }
        other => panic!("expected CaseMismatch, got {other:?}"),
    }
}

#[test]
fn client_restarts_after_crash_per_policy() {
    // max_restarts = 1: the first child crashes mid-evaluate, the client restarts
    // once, and the fresh child succeeds.
    let state = tempfile::NamedTempFile::new().expect("state file");
    let mut spec = mock_spec("crash-once");
    spec.env = BTreeMap::from([(
        "MOCK_STATE_FILE".to_string(),
        state.path().display().to_string(),
    )]);
    spec.restart = RestartPolicy {
        max_restarts: 1,
        base_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(5),
    };
    let mut client = ExtensionClient::spawn(spec).expect("spawn");

    let outcome = client
        .evaluate(&case("worker-0", "tc-1"), b"benign")
        .expect("evaluate");
    assert_eq!(outcome, EvaluateOutcome::Ok, "fresh child should succeed");
    assert_eq!(client.provenance().restart_count, 1);
    assert_eq!(client.provenance().loss_count, 0);
}

#[test]
fn second_crash_is_terminal_with_loss() {
    // max_restarts = 1 against a mock that crashes EVERY time: restart once, then
    // the second crash is terminal and a loss is recorded.
    let mut spec = mock_spec("crash");
    spec.restart = RestartPolicy {
        max_restarts: 1,
        base_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(5),
    };
    let mut client = ExtensionClient::spawn(spec).expect("spawn");

    let outcome = client
        .evaluate(&case("worker-0", "tc-1"), b"benign")
        .expect("evaluate");
    assert!(matches!(
        outcome,
        EvaluateOutcome::Infrastructure(InfraFailure::Crashed { .. })
    ));
    assert_eq!(client.provenance().restart_count, 1);
    assert_eq!(client.provenance().loss_count, 1);
}

/// Read the newline-separated PIDs the mock logged to `MOCK_PID_LOG`.
fn read_pids(path: &std::path::Path) -> Vec<i32> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect()
}

/// Whether `pid` is a zombie (exited but not yet reaped by its parent, i.e. a
/// leaked child). A reaped child has no `/proc/<pid>` entry; an unreaped one that
/// has already exited is state `Z`. All mock children exit promptly, so a
/// non-reaped child is necessarily a zombie here.
fn is_zombie(pid: i32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        // "pid (comm) state ..." — comm may contain spaces/parens, so split on the
        // LAST ')' and read the state char that follows.
        Ok(stat) => match stat.rsplit_once(')') {
            Some((_, rest)) => rest.trim_start().starts_with('Z'),
            None => false,
        },
        Err(_) => false, // no /proc entry -> reaped / gone
    }
}

/// Regression (#57 follow-up): a persistently-failing re-handshake must be
/// TERMINAL and must not leak a child per remaining restart slot.
///
/// The first child handshakes then crashes; every respawn exits before its hello,
/// so `restart_child` fails on every attempt. With `max_restarts = 3` and the
/// evaluate loop (as `drive_fuzz_extension` runs over a retained corpus) calling
/// `evaluate` repeatedly, the pre-fix code both (a) re-attempted a respawn for
/// every remaining restart slot — `max_restarts` spawn-and-fail cycles — and
/// (b) dropped each failed-handshake `Session` via `?` without reaping its child
/// (`Session` had no `Drop`, and `std::process::Child` neither kills nor waits on
/// drop), leaking up to `max_restarts` zombies. The fix makes ONE failed
/// re-handshake terminal (at most one respawn) and reaps any dropped `Session`'s
/// child, so no spawned child survives.
#[test]
fn rehandshake_failure_is_terminal_and_reaps_every_child() {
    let state = tempfile::NamedTempFile::new().expect("state file");
    let pid_log = tempfile::NamedTempFile::new().expect("pid log");

    let mut spec = mock_spec("crash-then-unhandshake");
    spec.env = BTreeMap::from([
        (
            "MOCK_STATE_FILE".to_string(),
            state.path().display().to_string(),
        ),
        (
            "MOCK_PID_LOG".to_string(),
            pid_log.path().display().to_string(),
        ),
    ]);
    spec.restart = RestartPolicy {
        max_restarts: 3,
        base_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(5),
    };
    let mut client = ExtensionClient::spawn(spec).expect("spawn");

    // Drive the evaluate loop repeatedly: every call after the terminal failure
    // must short-circuit to a bounded crash, never re-attempt a respawn.
    for i in 0..5 {
        let outcome = client
            .evaluate(&case("worker-0", &format!("tc-{i}")), b"benign/path")
            .expect("evaluate");
        assert!(
            matches!(
                outcome,
                EvaluateOutcome::Infrastructure(InfraFailure::Crashed { .. })
            ),
            "call {i} must be a bounded crash; got {outcome:?}"
        );
    }

    // One failed re-handshake is terminal: exactly ONE restart was attempted (not
    // `max_restarts`), and exactly ONE terminal loss was recorded (not one per
    // call across the loop).
    assert_eq!(
        client.provenance().restart_count,
        1,
        "a terminal re-handshake failure must not keep respawning per restart slot"
    );
    assert_eq!(
        client.provenance().loss_count,
        1,
        "the terminal loss is recorded once, not re-recorded on every subsequent call"
    );

    // The mock logged every child it spawned: the first child plus exactly ONE
    // respawn (the single terminal failure) — two children total.
    let pids = read_pids(pid_log.path());
    assert_eq!(
        pids.len(),
        2,
        "expected first child + exactly one respawn; got PIDs {pids:?}"
    );

    // No spawned child is leaked: every PID is reaped (gone), none a zombie. The
    // client is still alive here, so a reaped respawn proves the reap happened at
    // `Session` drop (via `?` in `restart_child`), not at `ExtensionClient` drop.
    for pid in &pids {
        assert!(
            !is_zombie(*pid),
            "child {pid} was left unreaped (zombie) — a leaked process"
        );
    }
}

/// Best-effort SIGKILL the detached `grandchild-sleeper` whose pid the mock wrote
/// to `path`, so a passing test does not leave it holding the (now-detached) pipe
/// for its full self-terminate bound.
fn reap_grandchild(path: &std::path::Path) {
    if let Ok(contents) = std::fs::read_to_string(path) {
        if let Ok(pid) = contents.trim().parse::<i32>() {
            // SAFETY: `kill` is a plain libc syscall; `pid` is the one the
            // grandchild recorded for itself. A stale/reused pid at worst signals
            // nothing or an unrelated process we have no handle to — this is a
            // best-effort test cleanup, not a correctness guarantee.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
    }
}

/// Regression (#57 follow-up): a dropped `Session` whose extension double-forked a
/// grandchild that inherited the child's stdout must NOT hang teardown.
///
/// The mock, in `grandchild-holds-stdout`, spawns a grandchild that inherits fd 1
/// (the host's read-pipe write-end) and keeps it open, then the direct child
/// handshakes and vanishes on the first request without responding. The host's
/// frame-reader thread then blocks on `read` with no EOF (the grandchild still
/// holds the pipe), so the `Session` drop's reader-join would block indefinitely.
/// The fix bounds that join: teardown detaches the still-blocked reader after a
/// short deadline instead of hanging.
///
/// `evaluate` runs on a worker thread under a wall-clock budget, so a regression
/// (unbounded join) FAILS this test at the budget rather than hanging the whole
/// suite. The budget (20s) sits well above the fix's ~2s bound and well below the
/// grandchild's 120s pipe-hold, so pre-fix the join overruns the budget while
/// post-fix it returns comfortably. The direct child must be reaped (no zombie)
/// and the vanished extension must be a bounded infrastructure result, never a
/// finding — even for a planted sandbox-escape input.
#[test]
fn grandchild_holding_stdout_does_not_hang_teardown() {
    use std::sync::mpsc;

    let pid_log = tempfile::NamedTempFile::new().expect("pid log");
    let gc_pid = tempfile::NamedTempFile::new().expect("grandchild pid file");

    let mut spec = mock_spec("grandchild-holds-stdout");
    // A short per-call deadline: the host times the vanished extension out quickly,
    // then tears the session down — which is where the bounded join matters.
    spec.limits.call_timeout = Duration::from_millis(250);
    spec.env = BTreeMap::from([
        (
            "MOCK_PID_LOG".to_string(),
            pid_log.path().display().to_string(),
        ),
        (
            "MOCK_GRANDCHILD_PID_FILE".to_string(),
            gc_pid.path().display().to_string(),
        ),
    ]);

    // Drive spawn + evaluate + explicit teardown on a worker thread so an unbounded
    // join (the regression) trips the wall-clock budget below instead of hanging the
    // whole test binary.
    let (tx, rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut client = ExtensionClient::spawn(spec).expect("spawn");
        let outcome = client
            .evaluate(&case("worker-0", "tc-escape"), b"../etc/passwd")
            .expect("evaluate");
        // `shutdown` drops the (already torn-down) session again; still bounded.
        client.shutdown();
        let _ = tx.send(outcome);
    });

    let outcome = match rx.recv_timeout(Duration::from_secs(20)) {
        Ok(outcome) => outcome,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            reap_grandchild(gc_pid.path());
            panic!(
                "teardown did not return within the budget: the Session reader-join is \
                 unbounded and hung on a grandchild holding the stdout pipe open"
            );
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            reap_grandchild(gc_pid.path());
            panic!("worker thread panicked before sending an outcome");
        }
    };
    worker.join().expect("worker thread");

    // The vanished extension is a bounded infrastructure result, never a finding —
    // even though the input is a planted sandbox escape.
    assert!(
        matches!(outcome, EvaluateOutcome::Infrastructure(_)),
        "a vanished extension must be bounded infrastructure, never a finding; got {outcome:?}"
    );

    // Exactly one host-spawned extension child (restart = never; the grandchild
    // returns before logging its pid), and it was reaped by the `Session` drop —
    // not left a zombie, despite the grandchild still holding the stdout pipe.
    let pids = read_pids(pid_log.path());
    assert_eq!(
        pids.len(),
        1,
        "expected exactly the one direct child; got {pids:?}"
    );
    assert!(
        !is_zombie(pids[0]),
        "the direct child {} was left unreaped (zombie) despite the grandchild holding the pipe",
        pids[0]
    );

    // Clean up the detached grandchild so it does not linger for its full hold.
    reap_grandchild(gc_pid.path());
}

#[test]
fn from_manifest_spawns_handshakes_and_evaluates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("extension.toml");
    let toml = format!(
        r#"
schema = "bhf.extension-manifest.v1"
id = "mock"
executable = "{mock}"
allow-external-paths = true
args = ["--mode", "well-behaved"]
required-capabilities = ["oracle.evaluate"]

[limits]
call-timeout-ms = 1000
max-frame-bytes = 1048576
"#,
        mock = MOCK
    );
    std::fs::write(&manifest_path, toml).expect("write manifest");

    let manifest = ExtensionManifest::load(&manifest_path).expect("load manifest");
    let mut client = ExtensionClient::from_manifest(&manifest, &manifest_path).expect("spawn");

    // The manifest file was hashed as the config hash.
    assert!(client.provenance().config_sha256.is_some());
    assert_eq!(
        client.provenance().config_sha256.as_ref().unwrap().len(),
        64
    );

    let outcome = client
        .evaluate(&case("worker-0", "tc-1"), b"../../secret")
        .expect("evaluate");
    assert!(matches!(outcome, EvaluateOutcome::Finding(_)));
}

#[test]
fn per_case_digest_is_stable_and_diverges_on_different_output() {
    let mut client = ExtensionClient::spawn(mock_spec("well-behaved")).expect("spawn");
    client
        .evaluate(&case("worker-0", "tc-1"), b"benign/a")
        .expect("eval ok");
    let ok_digest = client.last_case_digest().expect("digest").to_string();

    client
        .evaluate(&case("worker-0", "tc-1"), b"benign/b")
        .expect("eval ok 2");
    assert_eq!(
        client.last_case_digest().unwrap(),
        ok_digest,
        "identical result class must digest identically"
    );

    client
        .evaluate(&case("worker-0", "tc-2"), b"../escape")
        .expect("eval finding");
    assert_ne!(
        client.last_case_digest().unwrap(),
        ok_digest,
        "a different result (finding) must diverge"
    );
}

#[test]
fn live_python_reference_extension_interops() {
    let python = match which::which("python3") {
        Ok(path) => path,
        Err(_) => {
            eprintln!("skipping live_python_reference_extension_interops: python3 not found");
            return;
        }
    };
    let script = format!(
        "{}/tests/fixtures/reference_extension.py",
        env!("CARGO_MANIFEST_DIR")
    );

    let mut spec = SpawnSpec::new(python);
    spec.args = vec![script];
    // Python wants a sane PATH; this also exercises env passthrough.
    spec.env_passthrough = vec!["PATH".to_string()];
    spec.limits.call_timeout = Duration::from_secs(10);
    spec.restart = RestartPolicy::never();

    let mut client = ExtensionClient::spawn(spec).expect("spawn python reference");
    assert_eq!(client.negotiated().protocol, "bhf.extension.v1");

    let finding = client
        .evaluate(&case("worker-0", "tc-escape"), b"../../etc/shadow")
        .expect("evaluate escape");
    match finding {
        EvaluateOutcome::Finding(finding) => {
            assert_eq!(finding.rule, "oracle.path-escape");
            assert_eq!(finding.signature_inputs[0], "oracle.path-escape");
        }
        other => panic!("expected a finding from the python reference, got {other:?}"),
    }

    let ok = client
        .evaluate(&case("worker-0", "tc-benign"), b"logs/run-01.txt")
        .expect("evaluate benign");
    assert_eq!(ok, EvaluateOutcome::Ok);

    // The env passthrough recorded PATH's name (never its value) in provenance.
    assert!(client
        .provenance()
        .env_allowlist
        .contains(&"PATH".to_string()));
}

// ── codec / mutator / scenario / lifecycle capabilities ─────────────────────

#[test]
fn session_capabilities_are_negotiated_when_requested() {
    // The host advertises the session caps as optional; the mock provides them,
    // so negotiation picks them up (a subset-declaring extension would simply
    // negotiate fewer — see `negotiation_rejects_missing_required_capability`).
    let client = ExtensionClient::spawn(session_spec("well-behaved")).expect("spawn");
    for cap in SESSION_CAPS {
        assert!(client.supports(cap), "expected {cap} to be negotiated");
    }
    assert!(client.supports("oracle.evaluate"));
}

#[test]
fn codec_decode_encode_and_repair_roundtrip() {
    use serde_json::json;
    let mut client = ExtensionClient::spawn(session_spec("well-behaved")).expect("spawn");
    let c = case("worker-0", "tc-codec");

    // decode a well-formed OPEN frame into its structured view.
    let frame = toy_frame(b"OPEN logs/run.txt");
    match client.decode(&c, &frame).expect("decode") {
        CodecOutcome::Decoded(value) => {
            assert_eq!(value["op"], "OPEN");
            assert_eq!(value["path"], "logs/run.txt");
            assert_eq!(value["crc_valid"], true);
        }
        other => panic!("expected Decoded, got {other:?}"),
    }

    // encode the structured value back to the identical frame bytes.
    let decoded = json!({ "op": "OPEN", "path": "logs/run.txt" });
    match client.encode(&c, decoded).expect("encode") {
        CodecOutcome::Bytes(bytes) => assert_eq!(bytes, frame, "encode is the inverse of decode"),
        other => panic!("expected Bytes, got {other:?}"),
    }

    // a frame with a clobbered CRC is repaired back to a valid frame.
    let mut corrupt = frame.clone();
    *corrupt.last_mut().unwrap() ^= 0xff;
    assert!(!toy_parse(&corrupt).unwrap().1, "corrupt frame is invalid");
    match client.repair(&c, &corrupt).expect("repair") {
        CodecOutcome::Bytes(bytes) => {
            assert!(toy_parse(&bytes).unwrap().1, "repaired frame is valid");
            assert_eq!(bytes, frame, "repair restores the computed fields");
        }
        other => panic!("expected Bytes, got {other:?}"),
    }
}

#[test]
fn mutator_is_deterministic_and_needs_repair() {
    let mut client = ExtensionClient::spawn(session_spec("well-behaved")).expect("spawn");
    let c = case("worker-0", "tc-mut");
    let frame = toy_frame(b"WRITE 7 data");

    let first = match client.mutate(&c, &frame, 42).expect("mutate") {
        MutateOutcome::Mutated(bytes) => bytes,
        other => panic!("expected Mutated, got {other:?}"),
    };
    let second = match client.mutate(&c, &frame, 42).expect("mutate again") {
        MutateOutcome::Mutated(bytes) => bytes,
        other => panic!("expected Mutated, got {other:?}"),
    };
    assert_eq!(first, second, "same (input, seed) is reproducible");
    assert_ne!(first, frame, "mutation changed the input");
    // The structure-aware mutation leaves computed fields stale; repair fixes them.
    assert!(!toy_parse(&first).unwrap().1, "mutated frame is malformed");
    match client.repair(&c, &first).expect("repair") {
        CodecOutcome::Bytes(bytes) => assert!(toy_parse(&bytes).unwrap().1),
        other => panic!("expected Bytes, got {other:?}"),
    }
}

#[test]
fn session_binds_open_handle_into_write_and_oracle_flags_escape() {
    let mut client = ExtensionClient::spawn(session_spec("well-behaved")).expect("spawn");
    let mut target = ToyTarget::new();
    let driver = SessionDriver::new(SessionOptions::default());
    let root = tempfile::tempdir().expect("root");

    let outcome = driver
        .run(
            &mut client,
            &mut target,
            &case("worker-0", "tc-escape"),
            root.path(),
            b"../etc/passwd",
        )
        .expect("session");

    // The clean-exit semantic violation is a finding.
    assert!(outcome.infrastructure.is_none(), "no fault: {outcome:?}");
    let finding = outcome.finding.expect("escape is a finding");
    assert_eq!(finding.rule, "oracle.path-escape");

    // Two scenario steps (OPEN then WRITE), both reaching the target well-formed.
    assert_eq!(outcome.steps.len(), 2);
    assert_eq!(outcome.steps[0].label.as_deref(), Some("OPEN"));
    let write = &outcome.steps[1];
    assert_eq!(write.label.as_deref(), Some("WRITE"));
    let (payload, valid) = toy_parse(&write.sent).expect("write parses");
    assert!(valid, "WRITE frame is well-formed");
    let text = String::from_utf8_lossy(&payload);
    assert!(
        text.starts_with("WRITE 7 "),
        "WRITE binds the handle 7 from the OPEN response: {text:?}"
    );
    assert!(
        target.received.iter().all(|r| r.crc_valid),
        "every frame reached the target well-formed"
    );
    assert_eq!(target.received[0].label.as_deref(), Some("OPEN"));
}

#[test]
fn session_repairs_mutated_frame_before_it_reaches_the_target() {
    // Control: mutate WITHOUT repair — the target sees a malformed frame.
    let mut client = ExtensionClient::spawn(session_spec("well-behaved")).expect("spawn");
    let mut target = ToyTarget::new();
    let driver = SessionDriver::new(SessionOptions {
        mutate_seed: Some(0x99),
        repair: false,
        max_steps: 8,
    });
    let root = tempfile::tempdir().expect("root");
    let outcome = driver
        .run(
            &mut client,
            &mut target,
            &case("worker-0", "tc-norepair"),
            root.path(),
            b"safe/path",
        )
        .expect("session");
    assert!(outcome.any_mutated(), "the mutator ran");
    assert!(!outcome.any_repaired(), "repair was disabled");
    assert!(
        target.received.iter().any(|r| !r.crc_valid),
        "an unrepaired mutation corrupts the frame at the target"
    );

    // With repair, the mutated frame is repaired before it reaches the target.
    let mut client2 = ExtensionClient::spawn(session_spec("well-behaved")).expect("spawn");
    let mut target2 = ToyTarget::new();
    let driver2 = SessionDriver::new(SessionOptions {
        mutate_seed: Some(0x99),
        repair: true,
        max_steps: 8,
    });
    let root2 = tempfile::tempdir().expect("root");
    let outcome2 = driver2
        .run(
            &mut client2,
            &mut target2,
            &case("worker-0", "tc-repair"),
            root2.path(),
            b"safe/path",
        )
        .expect("session");
    assert!(outcome2.any_mutated() && outcome2.any_repaired());
    assert!(
        target2.received.iter().all(|r| r.crc_valid),
        "repair makes the mutated frame well-formed at the target"
    );
    assert!(outcome2.finding.is_none(), "a safe path is not a finding");
}

#[test]
fn live_python_reference_full_session() {
    let python = match which::which("python3") {
        Ok(path) => path,
        Err(_) => {
            eprintln!("skipping live_python_reference_full_session: python3 not found");
            return;
        }
    };
    let script = format!(
        "{}/tests/fixtures/reference_extension.py",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut spec = SpawnSpec::new(python);
    spec.args = vec![script];
    spec.env_passthrough = vec!["PATH".to_string()];
    spec.optional_capabilities = SESSION_CAPS.iter().map(|c| c.to_string()).collect();
    spec.limits.call_timeout = Duration::from_secs(10);
    spec.restart = RestartPolicy::never();

    let mut client = ExtensionClient::spawn(spec).expect("spawn python reference");
    assert!(client.supports("scenario.next"));
    assert!(client.supports("codec.repair"));

    let mut target = ToyTarget::new();
    let driver = SessionDriver::new(SessionOptions {
        mutate_seed: Some(7),
        repair: true,
        max_steps: 8,
    });
    let root = tempfile::tempdir().expect("root");
    let outcome = driver
        .run(
            &mut client,
            &mut target,
            &case("worker-0", "tc-escape"),
            root.path(),
            b"../../etc/shadow",
        )
        .expect("python session");

    // The out-of-tree Python extension drives the full session: a mutated frame
    // is repaired before reaching the target, the OPEN handle is bound into the
    // WRITE, and the clean-exit escape is a finding — all with no bhf internals.
    let finding = outcome
        .finding
        .as_ref()
        .expect("python oracle flags the escape");
    assert_eq!(finding.rule, "oracle.path-escape");
    assert!(outcome.any_mutated() && outcome.any_repaired());
    assert!(target.received.iter().all(|r| r.crc_valid));
    let write = outcome
        .steps
        .iter()
        .find(|s| s.label.as_deref() == Some("WRITE"))
        .expect("a WRITE step");
    let (payload, _) = toy_parse(&write.sent).unwrap();
    assert!(String::from_utf8_lossy(&payload).starts_with("WRITE 7 "));
}
