// SPDX-License-Identifier: Apache-2.0

//! The `oracle.evaluate` capability payload.
//!
//! `oracle.evaluate` asks an extension to judge whether a single (clean-exiting)
//! test input triggers a private *semantic* violation — something a crash-only
//! fuzzer cannot see. The input is arbitrary bytes, so it travels base64-encoded
//! in a JSON string. The host only builds the request and classifies the typed
//! response; the actual oracle logic lives entirely in the out-of-process
//! extension.

use crate::b64;
use crate::{ExtensionError, Result};
use serde::{Deserialize, Serialize};

/// The request payload for `oracle.evaluate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatePayload {
    /// The test input, standard-base64 encoded.
    pub input_b64: String,
}

impl EvaluatePayload {
    /// Build a payload from raw input bytes.
    pub fn from_input(input: &[u8]) -> Self {
        Self {
            input_b64: b64::encode(input),
        }
    }

    /// Decode the carried input back to raw bytes.
    pub fn decode_input(&self) -> Result<Vec<u8>> {
        b64::decode(&self.input_b64).map_err(|e| {
            ExtensionError::protocol(format!("oracle.evaluate payload had invalid base64: {e}"))
        })
    }

    /// Serialize this payload to a JSON value for the request envelope.
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::json!({ "input_b64": self.input_b64 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_roundtrips_raw_bytes() {
        let input = vec![0x00u8, 0x2f, 0x2e, 0x2e, 0xff, b'/'];
        let payload = EvaluatePayload::from_input(&input);
        assert_eq!(payload.decode_input().expect("decode"), input);
    }

    #[test]
    fn payload_value_has_only_input_b64() {
        let payload = EvaluatePayload::from_input(b"../etc/passwd");
        let value = payload.to_value();
        assert_eq!(value["input_b64"], serde_json::json!(payload.input_b64));
        assert_eq!(value.as_object().unwrap().len(), 1);
    }

    #[test]
    fn payload_rejects_unknown_fields() {
        let raw = serde_json::json!({ "input_b64": "Zm9v", "extra": 1 });
        assert!(serde_json::from_value::<EvaluatePayload>(raw).is_err());
    }
}
