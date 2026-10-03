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
    CaseId, EvaluateOutcome, ExtensionClient, ExtensionManifest, InfraFailure, Limits,
    RestartPolicy, SpawnSpec,
};
use std::collections::BTreeMap;
use std::time::Duration;

const MOCK: &str = env!("CARGO_BIN_EXE_bhf_mock_extension");

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
