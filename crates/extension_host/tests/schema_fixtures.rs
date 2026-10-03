// SPDX-License-Identifier: Apache-2.0

//! The authoritative wire-contract test: committed golden fixtures must
//! round-trip through the serde envelope types (the host's real parser), and a
//! deliberately-malformed fixture must be rejected. This runs per-PR in the fast
//! lane and adds no dependency. It is platform-independent (pure serde), so it
//! is NOT `cfg(unix)`-gated.

use extension_host::{Request, Response};
use std::path::PathBuf;

fn fixture(name: &str) -> String {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "fixtures", name]
        .iter()
        .collect();
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
}

/// A fixture must parse into the envelope type and re-serialize to the *same*
/// JSON value (the serde types enforce `deny_unknown_fields`, so this is the
/// real wire contract, not a looser check).
fn assert_roundtrips<T>(name: &str)
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let raw = fixture(name);
    let original: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{name} is not valid JSON: {e}"));
    let typed: T = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("{name} did not parse as the envelope type: {e}"));
    let reserialized = serde_json::to_value(&typed).expect("serialize");
    assert_eq!(
        original, reserialized,
        "{name} did not round-trip through the envelope type"
    );
}

#[test]
fn committed_request_fixture_roundtrips_through_envelope() {
    assert_roundtrips::<Request>("oracle_evaluate.request.json");
}

#[test]
fn committed_response_fixtures_roundtrip_through_envelope() {
    assert_roundtrips::<Response>("oracle_ok.response.json");
    assert_roundtrips::<Response>("oracle_finding.response.json");
}

#[test]
fn finding_fixture_exposes_rule_signature_and_evidence() {
    let resp: Response =
        serde_json::from_str(&fixture("oracle_finding.response.json")).expect("parse finding");
    let finding = resp.finding.expect("finding attached");
    assert_eq!(finding.rule, "oracle.path-escape");
    assert_eq!(
        finding.signature_inputs.first().unwrap(),
        "oracle.path-escape"
    );
    assert!(!finding.evidence.is_empty());
    assert_eq!(
        finding.min_predicate.as_deref(),
        Some("path-contains-dotdot")
    );
}

#[test]
fn deliberately_malformed_fixture_is_rejected() {
    let raw = fixture("malformed.response.json");
    // It is valid JSON...
    serde_json::from_str::<serde_json::Value>(&raw).expect("valid JSON");
    // ...but NOT a valid envelope (unknown field), proving the contract rejects
    // extended/forged responses rather than silently accepting them.
    assert!(
        serde_json::from_str::<Response>(&raw).is_err(),
        "an unknown field must be rejected by the envelope type"
    );
}
