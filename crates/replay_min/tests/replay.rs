// SPDX-License-Identifier: Apache-2.0

use corpus::{compute_signature, Signature};
use event_log::{HandlerEvent, Testcase};
use replay_min::{replay, replay_report_with_runner, HarnessRunner, ReplayError, ReplayResult};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn replay_match_when_harness_emits_recorded_signature_events() {
    let (_finding_dir_guard, finding_dir) = write_finding("match", canonical_signature());

    let result = replay(&finding_dir, fake_harness()).unwrap();

    assert_eq!(result, ReplayResult::Match);
}

#[test]
fn replay_mismatch_when_harness_emits_different_signature() {
    let (_finding_dir_guard, finding_dir) = write_finding("mismatch", canonical_signature());

    let result = replay(&finding_dir, fake_harness()).unwrap();

    assert!(matches!(
        result,
        ReplayResult::Mismatch {
            recorded,
            actual: Some(_)
        } if recorded == canonical_signature()
    ));
}

#[test]
fn replay_matches_recorded_signature_at_second_handler_index() {
    let testcase = testcase_with_handler_lines(&[5, 9]);
    let recorded = compute_signature(&testcase, &testcase.handlers[1]);
    let (_finding_dir_guard, finding_dir) = write_finding("multi-handler", recorded);

    let result = replay(&finding_dir, fake_harness()).unwrap();

    assert_eq!(result, ReplayResult::Match);
}

#[test]
fn replay_returns_mismatch_when_recorded_signature_absent_from_all_handlers() {
    let testcase = testcase_with_handler_lines(&[5, 9]);
    let actual = compute_signature(&testcase, &testcase.handlers[0]);
    let unrelated = testcase_with_handler_lines(&[13]);
    let recorded = compute_signature(&unrelated, &unrelated.handlers[0]);
    let (_finding_dir_guard, finding_dir) = write_finding("multi-handler", recorded);

    let result = replay(&finding_dir, fake_harness()).unwrap();

    assert_eq!(
        result,
        ReplayResult::Mismatch {
            recorded,
            actual: Some(actual)
        }
    );
}

#[test]
fn replay_returns_match_when_recorded_signature_at_first_handler_index() {
    let testcase = testcase_with_handler_lines(&[5, 9]);
    let recorded = compute_signature(&testcase, &testcase.handlers[0]);
    let (_finding_dir_guard, finding_dir) = write_finding("multi-handler", recorded);

    let result = replay(&finding_dir, fake_harness()).unwrap();

    assert_eq!(result, ReplayResult::Match);
}

#[test]
fn replay_returns_error_when_finding_missing() {
    let (_scratch4, scratch4) = temp_dir("missing");
    let missing = scratch4.join("F-0000-missing");

    let error = replay(&missing, fake_harness()).unwrap_err();

    assert!(matches!(error, ReplayError::MissingFinding { .. }));
}

#[test]
fn replay_returns_error_when_harness_binary_missing() {
    let (_finding_dir_guard, finding_dir) = write_finding("match", canonical_signature());
    let (_scratch3, scratch3) = temp_dir("missing-harness");
    let missing_harness = scratch3.join("missing-harness");

    let error = replay(&finding_dir, &missing_harness).unwrap_err();

    assert!(matches!(error, ReplayError::HarnessFailedToStart { .. }));
}

/// The report says what the finding recorded and what the replay raised:
/// the exception, its message and the handler that caught it, on a match and
/// on a mismatch.
#[test]
fn a_replay_report_describes_the_recorded_and_the_replayed_exception() {
    let recorded = testcase_with_handler_lines(&[9]);
    let described = serde_json::json!({
        "signature": canonical_signature(),
        "classification": "swallowed_predefined",
        "handler": recorded.handlers[0],
        "raises": [],
        "exception": {"name": "CONSTRAINT_ERROR", "message": "bad input"},
    });
    let runner = HarnessRunner::direct(fake_harness());
    let maps = corpus::SourceLineMaps::default();

    let (_finding_dir_guard, finding_dir) = write_finding_json("match", &described);
    let report = replay_report_with_runner(&finding_dir, &runner, &maps).unwrap();
    assert_eq!(report.result, ReplayResult::Match);
    let recorded = report.recorded.as_ref().expect("the finding describes it");
    let deciding = report.deciding().expect("the matching exception");
    for raised in [recorded, deciding] {
        assert_eq!(raised.what(), "CONSTRAINT_ERROR: bad input");
        assert_eq!(raised.handled_at.as_deref(), Some("pkg.adb:9"));
    }

    let (_finding_dir_guard, finding_dir) = write_finding_json("mismatch", &described);
    let report = replay_report_with_runner(&finding_dir, &runner, &maps).unwrap();
    assert!(matches!(report.result, ReplayResult::Mismatch { .. }));
    assert_eq!(
        report
            .recorded
            .as_ref()
            .and_then(|r| r.handled_at.as_deref()),
        Some("pkg.adb:9")
    );
    let replayed = report.deciding().expect("what the replay raised");
    assert_eq!(replayed.handled_at.as_deref(), Some("pkg.adb:10"));
    assert_eq!(replayed.name, "CONSTRAINT_ERROR");
}

/// On a mismatch the report compares the recorded exception with the
/// replayed one closest to it, not with whichever came first: here the same
/// exception caught by the same handler, reached after a different last
/// breadcrumb, comes second.
#[test]
fn a_mismatch_compares_the_replayed_exception_closest_to_the_recorded_one() {
    let mut recorded = testcase_with_handler_lines(&[9]);
    recorded.crumbs = vec![1, 2];
    recorded.handlers[0].last_breadcrumb = 2;
    let signature = compute_signature(&recorded, &recorded.handlers[0]);
    let described = serde_json::json!({
        "signature": signature,
        "classification": "swallowed_predefined",
        "handler": recorded.handlers[0],
        "raises": [],
        "exception": {"name": "CONSTRAINT_ERROR", "message": "bad input"},
    });
    let (_finding_dir_guard, finding_dir) = write_finding_json("multi-handler", &described);
    let runner = HarnessRunner::direct(fake_harness());
    let report =
        replay_report_with_runner(&finding_dir, &runner, &corpus::SourceLineMaps::default())
            .unwrap();

    assert_eq!(report.replayed.len(), 2, "{report:?}");
    let closest = &report.replayed[1];
    assert_eq!(closest.handled_at.as_deref(), Some("pkg.adb:9"));
    assert_eq!(
        report.result,
        ReplayResult::Mismatch {
            recorded: signature,
            actual: Some(closest.signature),
        }
    );
    assert_eq!(report.deciding(), Some(closest));
}

fn write_finding_json(input: &str, finding: &serde_json::Value) -> (tempfile::TempDir, PathBuf) {
    let (_scratch2, scratch2) = temp_dir(input);
    let finding_dir = scratch2.join("findings/F-0000-test");
    fs::create_dir_all(&finding_dir).unwrap();
    fs::write(finding_dir.join("testcase.bin"), input.as_bytes()).unwrap();
    fs::write(
        finding_dir.join("finding.json"),
        serde_json::to_vec(finding).unwrap(),
    )
    .unwrap();
    (_scratch2, finding_dir)
}

fn canonical_signature() -> Signature {
    let testcase = testcase_with_handler_lines(&[9]);
    compute_signature(&testcase, &testcase.handlers[0])
}

fn testcase_with_handler_lines(handler_lines: &[u32]) -> Testcase {
    Testcase {
        testcase_id: 1,
        target_id: 0x42,
        target_entered: false,
        crumbs: vec![1],
        handlers: handler_lines
            .iter()
            .enumerate()
            .map(|(index, handler_line)| HandlerEvent {
                sequence_index: 3 + index,
                exception_name: "CONSTRAINT_ERROR".to_owned(),
                exception_message: "bad input".to_owned(),
                handler_file: "pkg.adb".to_owned(),
                handler_line: *handler_line,
                last_breadcrumb: 1,
                target_id: 0x42,
                testcase_id: 1,
            })
            .collect(),
        raises: Vec::new(),
        top_level: None,
        end: None,
        mocks: Vec::new(),
    }
}

fn write_finding(input: &str, signature: Signature) -> (tempfile::TempDir, PathBuf) {
    let (_scratch1, scratch1) = temp_dir(input);
    let finding_dir = scratch1.join("findings/F-0000-test");
    fs::create_dir_all(&finding_dir).unwrap();
    fs::write(finding_dir.join("testcase.bin"), input.as_bytes()).unwrap();
    fs::write(
        finding_dir.join("finding.json"),
        serde_json::to_vec(&serde_json::json!({ "signature": signature })).unwrap(),
    )
    .unwrap();
    (_scratch1, finding_dir)
}

fn fake_harness() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_fake_harness"))
}

fn temp_dir(name: &str) -> (tempfile::TempDir, PathBuf) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    // A counter as well as the time: on Windows the clock's 100 ns tick is
    // coarse enough for two tests on parallel threads to read the same value,
    // and two tests sharing a dir overwrite each other's finding.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // Removed when this scope ends.
    let dir_tmp = tempfile::Builder::new()
        .prefix("bhf-")
        .tempdir()
        .expect("create test dir");
    let dir = dir_tmp
        .path()
        .join(format!("bhf-replay-{name}-{nonce}-{next}"));
    fs::create_dir_all(&dir).unwrap();
    (dir_tmp, dir)
}
