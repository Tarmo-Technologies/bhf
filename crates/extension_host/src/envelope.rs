// SPDX-License-Identifier: Apache-2.0

//! The request/response envelope and the deterministic result classes.
//!
//! Every request and every response carries the full campaign/worker/testcase
//! [`CaseId`], so a response can be matched to its request and two workers can
//! never mix test-case or event identity. Wire structs use
//! `#[serde(deny_unknown_fields)]` so a malformed or extended response is a
//! parse error (a bounded infrastructure failure) rather than being silently
//! accepted.

use serde::{Deserialize, Serialize};

/// A request driven across the wire to the extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// The negotiated protocol identifier (`bhf.extension.v1`).
    pub protocol: String,
    /// The capability being invoked (e.g. `oracle.evaluate`).
    pub capability: String,
    /// The campaign/worker/testcase identity this request belongs to.
    pub case: CaseId,
    /// Capability-specific payload (opaque to the envelope layer).
    pub payload: serde_json::Value,
}

/// The campaign/worker/testcase identity stamped on every request and echoed on
/// every response.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseId {
    /// The campaign this case belongs to.
    pub campaign: String,
    /// The worker (fuzzing lane) that produced the case. Distinct workers must
    /// never see one another's cases.
    pub worker: String,
    /// The test-case identity within the worker.
    pub testcase: String,
}

impl CaseId {
    /// Construct a [`CaseId`] from owned-or-borrowed parts.
    pub fn new(
        campaign: impl Into<String>,
        worker: impl Into<String>,
        testcase: impl Into<String>,
    ) -> Self {
        Self {
            campaign: campaign.into(),
            worker: worker.into(),
            testcase: testcase.into(),
        }
    }
}

/// A response returned by the extension for a single request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    /// The protocol identifier; must match the negotiated protocol.
    pub protocol: String,
    /// The case identity echoed back; the host rejects a mismatch.
    pub case: CaseId,
    /// The deterministic result class.
    pub result: ResultClass,
    /// The finding payload, present iff `result == finding`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding: Option<FindingResult>,
    /// The capability-specific output payload, present on an `ok` response from a
    /// non-oracle capability (`codec.*`, `mutator.mutate`, `scenario.*`,
    /// `lifecycle.*`). Opaque to the envelope layer — each capability module parses
    /// its own shape. `oracle.evaluate` leaves it unset (its result travels in
    /// `finding`), so existing oracle responses are byte-for-byte unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    /// An optional human-readable detail (reason for a reject/unsupported/error).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The fixed, deterministic set of per-call result classes.
///
/// `ok`/`reject`/`finding` are target-truth outcomes; `unsupported` and
/// `infrastructure_error` are bounded extension-side failures that must never be
/// reported as a target vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultClass {
    /// The input was evaluated and is benign.
    Ok,
    /// The input was rejected by the extension (e.g. not decodable); drop it.
    Reject,
    /// The input triggered a semantic violation; a finding is attached.
    Finding,
    /// The requested capability is not supported for this input/mode.
    Unsupported,
    /// The extension hit an internal error it reports explicitly (bounded).
    InfrastructureError,
}

/// A stable, replayable finding emitted by a semantic oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingResult {
    /// The rule identifier that fired.
    pub rule: String,
    /// The finding classification (e.g. `extension_oracle`).
    pub classification: String,
    /// The ordered inputs to the finding signature. The host hashes these *in
    /// the order given* so the signature reproduces byte-for-byte on
    /// replay/minimize regardless of host-side iteration order.
    pub signature_inputs: Vec<String>,
    /// Supporting evidence key/value pairs.
    pub evidence: Vec<Evidence>,
    /// An optional minimization predicate identifier the extension exposes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_predicate: Option<String>,
}

/// A single evidence key/value pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// The evidence key.
    pub key: String,
    /// The evidence value.
    pub value: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_case() -> CaseId {
        CaseId::new("camp-1", "worker-7", "tc-00042")
    }

    #[test]
    fn request_roundtrips_with_case_identity() {
        let req = Request {
            protocol: crate::PROTOCOL.to_string(),
            capability: crate::capability::ORACLE_EVALUATE.to_string(),
            case: sample_case(),
            payload: json!({ "input_b64": "Zm9vYmFy" }),
        };
        let bytes = serde_json::to_vec(&req).expect("serialize");
        let back: Request = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(back, req);
        // Case identity survives the round-trip intact.
        assert_eq!(back.case, sample_case());
        // Re-serializing yields identical bytes (stable field order).
        let bytes2 = serde_json::to_vec(&back).expect("reserialize");
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn response_result_classes_all_parse() {
        for (text, expected) in [
            ("ok", ResultClass::Ok),
            ("reject", ResultClass::Reject),
            ("finding", ResultClass::Finding),
            ("unsupported", ResultClass::Unsupported),
            ("infrastructure_error", ResultClass::InfrastructureError),
        ] {
            let raw = json!({
                "protocol": crate::PROTOCOL,
                "case": { "campaign": "c", "worker": "w", "testcase": "t" },
                "result": text,
            });
            let resp: Response = serde_json::from_value(raw).expect("parse response");
            assert_eq!(resp.result, expected, "for result class {text}");
        }
    }

    #[test]
    fn unknown_envelope_field_is_rejected() {
        let raw = json!({
            "protocol": crate::PROTOCOL,
            "capability": "oracle.evaluate",
            "case": { "campaign": "c", "worker": "w", "testcase": "t" },
            "payload": {},
            "haxx": 1
        });
        let err = serde_json::from_value::<Request>(raw).expect_err("must reject unknown field");
        assert!(err.to_string().contains("haxx") || err.to_string().contains("unknown field"));
    }

    #[test]
    fn finding_result_carries_rule_signature_evidence_and_optional_min_predicate() {
        let raw = json!({
            "protocol": crate::PROTOCOL,
            "case": { "campaign": "c", "worker": "w", "testcase": "t" },
            "result": "finding",
            "finding": {
                "rule": "oracle.path-escape",
                "classification": "extension_oracle",
                "signature_inputs": ["oracle.path-escape", "../etc/passwd"],
                "evidence": [
                    { "key": "path", "value": "../etc/passwd" },
                    { "key": "reason", "value": "escapes sandbox root" }
                ],
                "min_predicate": "path-contains-dotdot"
            }
        });
        let resp: Response = serde_json::from_value(raw).expect("parse finding");
        assert_eq!(resp.result, ResultClass::Finding);
        let finding = resp.finding.expect("finding attached");
        assert_eq!(finding.rule, "oracle.path-escape");
        assert_eq!(finding.classification, "extension_oracle");
        assert_eq!(
            finding.signature_inputs,
            vec![
                "oracle.path-escape".to_string(),
                "../etc/passwd".to_string()
            ]
        );
        assert_eq!(finding.evidence.len(), 2);
        assert_eq!(finding.evidence[0].key, "path");
        assert_eq!(
            finding.min_predicate.as_deref(),
            Some("path-contains-dotdot")
        );
    }

    #[test]
    fn capability_value_channel_roundtrips_and_is_absent_on_oracle_responses() {
        // A non-oracle capability carries its structured output in `value`.
        let raw = json!({
            "protocol": crate::PROTOCOL,
            "case": { "campaign": "c", "worker": "w", "testcase": "t" },
            "result": "ok",
            "value": { "output_b64": "Zm9v", "label": "WRITE" }
        });
        let resp: Response = serde_json::from_value(raw.clone()).expect("parse value response");
        assert_eq!(resp.result, ResultClass::Ok);
        assert_eq!(resp.value.as_ref().unwrap()["output_b64"], json!("Zm9v"));
        // Re-serializing yields the same JSON (the field round-trips).
        assert_eq!(serde_json::to_value(&resp).unwrap(), raw);

        // An oracle `ok` response has neither `finding` nor `value`, so its bytes
        // are unchanged by the new field.
        let oracle = json!({
            "protocol": crate::PROTOCOL,
            "case": { "campaign": "c", "worker": "w", "testcase": "t" },
            "result": "ok"
        });
        let resp: Response = serde_json::from_value(oracle.clone()).expect("parse oracle ok");
        assert!(resp.value.is_none());
        assert!(resp.finding.is_none());
        assert_eq!(serde_json::to_value(&resp).unwrap(), oracle);
    }

    #[test]
    fn ok_response_has_no_finding() {
        let raw = json!({
            "protocol": crate::PROTOCOL,
            "case": { "campaign": "c", "worker": "w", "testcase": "t" },
            "result": "ok"
        });
        let resp: Response = serde_json::from_value(raw).expect("parse ok");
        assert_eq!(resp.result, ResultClass::Ok);
        assert!(resp.finding.is_none());
    }
}
