// SPDX-License-Identifier: Apache-2.0

//! Cross-crate conformance gate for the `bhf.collector-event.v1` wire format.
//!
//! This is the always-on contract test (it runs per-PR because it belongs to
//! `package(runtime_collector)`): it round-trips a canonical event for every
//! `EventKind`, checks the checked-in golden fixtures carry the required fields
//! and enum values, and asserts that malformed lines are rejected rather than
//! silently accepted. An out-of-repo provider can treat these fixtures as the
//! reference corpus for the contract.

use runtime_collector::schema::{CollectorEvent, EventKind, EventPhase};
use runtime_collector::SCHEMA_ID;

const ALL_KNOWN_KINDS: &[EventKind] = &[
    EventKind::ProcessCreate,
    EventKind::ShellExecute,
    EventKind::FileCreate,
    EventKind::FileOpen,
    EventKind::FileWrite,
    EventKind::FileRename,
    EventKind::FileDelete,
    EventKind::ModuleLoad,
    EventKind::Network,
    EventKind::Registry,
];

#[test]
fn every_kind_round_trips_through_jsonl() {
    for kind in ALL_KNOWN_KINDS {
        let ev = CollectorEvent::new("tc", 0, 1, EventPhase::Event, kind.clone());
        let line = ev.to_jsonl_line();
        let back: CollectorEvent = serde_json::from_str(&line).expect("round-trips");
        assert_eq!(&back.kind, kind);
        assert_eq!(back.schema, SCHEMA_ID);
    }
}

#[test]
fn golden_fixture_lines_are_valid_and_cover_all_kinds() {
    let raw = include_str!("fixtures/golden.jsonl");
    let mut seen_kinds = Vec::new();
    for line in raw.lines().filter(|l| !l.trim().is_empty()) {
        let ev: CollectorEvent = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("golden line must parse: {e}\n{line}"));
        assert_eq!(ev.schema, SCHEMA_ID, "every golden line pins the schema id");
        assert!(!ev.testcase.is_empty(), "testcase is required");
        if ev.kind.is_known() && !seen_kinds.contains(&ev.kind) {
            seen_kinds.push(ev.kind.clone());
        }
    }
    for kind in ALL_KNOWN_KINDS {
        assert!(
            seen_kinds.contains(kind),
            "golden corpus is missing a line for {kind:?}"
        );
    }
}

#[test]
fn golden_fixture_has_begin_and_end_boundaries() {
    let raw = include_str!("fixtures/golden.jsonl");
    let phases: Vec<EventPhase> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<CollectorEvent>(l).unwrap().phase)
        .collect();
    assert!(phases.contains(&EventPhase::Begin));
    assert!(phases.contains(&EventPhase::End));
}

#[test]
fn malformed_fixture_lines_are_rejected() {
    let raw = include_str!("fixtures/malformed.jsonl");
    for line in raw.lines().filter(|l| !l.trim().is_empty()) {
        assert!(
            serde_json::from_str::<CollectorEvent>(line).is_err(),
            "malformed line must be rejected, not accepted: {line}"
        );
    }
}
