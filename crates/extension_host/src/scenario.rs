// SPDX-License-Identifier: Apache-2.0

//! The `scenario.next` / `scenario.observe-response` capability payloads.
//!
//! A scenario extension drives a *multi-message session*: it owns the state
//! machine, and the host owns the transport. For each step the host asks
//! `scenario.next` for the next message to send; after sending it and reading the
//! target's response, the host hands those response bytes back via
//! `scenario.observe-response`. The extension can then **bind a response-derived
//! value** (a handle, a nonce, a session id) into a later message — e.g. capture
//! the handle an `OPEN` returns and splice it into a subsequent `WRITE`.
//!
//! The extension is stateful across the session; the host resets that state
//! between cases via `lifecycle.reset`. The host never interprets the message
//! bytes — it just frames them to the target and relays the response back.

use crate::b64;
use serde::{Deserialize, Serialize};

/// Request payload for `scenario.next`: which step the host is asking for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioNextPayload {
    /// The zero-based step index the host is requesting. Monotonic within a case.
    pub step: u32,
    /// The raw test input that seeds the session (standard-base64), handed on the
    /// first step only. The extension derives its first message from this, so the
    /// fuzzing testcase drives the session content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed_b64: Option<String>,
}

impl ScenarioNextPayload {
    /// A `scenario.next` payload for `step`, with no seed.
    pub fn new(step: u32) -> Self {
        Self {
            step,
            seed_b64: None,
        }
    }

    /// A `scenario.next` payload carrying the session seed (first step).
    pub fn with_seed(step: u32, seed: &[u8]) -> Self {
        Self {
            step,
            seed_b64: Some(b64::encode(seed)),
        }
    }

    /// Serialize to the request-envelope payload value.
    pub fn to_value(&self) -> serde_json::Value {
        match &self.seed_b64 {
            Some(seed) => serde_json::json!({ "step": self.step, "seed_b64": seed }),
            None => serde_json::json!({ "step": self.step }),
        }
    }
}

/// The `scenario.next` response `value`: either the next message, or `done`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NextValue {
    /// `true` when the session has no further messages.
    #[serde(default)]
    pub done: bool,
    /// The next message's raw bytes, standard-base64 encoded. Absent iff `done`.
    #[serde(default)]
    pub message_b64: Option<String>,
    /// An optional diagnostic label for the step (e.g. `OPEN`, `WRITE`).
    #[serde(default)]
    pub label: Option<String>,
}

/// Request payload for `scenario.observe-response`: the target's response bytes
/// for the step the host just sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserveResponsePayload {
    /// The step index whose response this is (matches the `scenario.next` step).
    pub step: u32,
    /// The target's raw response bytes, standard-base64 encoded.
    pub response_b64: String,
}

impl ObserveResponsePayload {
    /// Build an observe-response payload from the step index and raw response.
    pub fn new(step: u32, response: &[u8]) -> Self {
        Self {
            step,
            response_b64: b64::encode(response),
        }
    }

    /// Serialize to the request-envelope payload value.
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::json!({ "step": self.step, "response_b64": self.response_b64 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn next_payload_carries_step() {
        assert_eq!(ScenarioNextPayload::new(2).to_value()["step"], json!(2));
    }

    #[test]
    fn next_value_parses_message_and_done() {
        let msg: NextValue =
            serde_json::from_value(json!({ "message_b64": "Zm9v", "label": "OPEN" })).unwrap();
        assert!(!msg.done);
        assert_eq!(msg.message_b64.as_deref(), Some("Zm9v"));
        assert_eq!(msg.label.as_deref(), Some("OPEN"));

        let done: NextValue = serde_json::from_value(json!({ "done": true })).unwrap();
        assert!(done.done);
        assert!(done.message_b64.is_none());
    }

    #[test]
    fn observe_payload_carries_step_and_response() {
        let payload = ObserveResponsePayload::new(0, b"OPENOK handle=7");
        let value = payload.to_value();
        assert_eq!(value["step"], json!(0));
        let back: ObserveResponsePayload = serde_json::from_value(value).unwrap();
        assert_eq!(back, payload);
    }
}
