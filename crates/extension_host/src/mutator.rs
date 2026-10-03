// SPDX-License-Identifier: Apache-2.0

//! The `mutator.mutate` capability payload.
//!
//! A mutator extension supplies a *structure-aware* mutation of a test input: it
//! understands the input's format and can produce a variant that stays close to
//! valid (e.g. flip a field, grow a repeated element) where a byte-blind mutator
//! would mostly produce garbage the target rejects at its input gate. The host
//! hands the current input and a deterministic `seed`; the extension returns the
//! mutated raw bytes (or `reject` if it cannot mutate this input).
//!
//! The `seed` makes an extension mutation reproducible: the same `(input, seed)`
//! must produce the same output, so a mutation that found a defect replays.

use crate::b64;
use serde::{Deserialize, Serialize};

/// Request payload for `mutator.mutate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutatePayload {
    /// The current test input, standard-base64 encoded.
    pub input_b64: String,
    /// A deterministic mutation seed: the same `(input, seed)` must yield the
    /// same mutated output, so an extension mutation is reproducible on replay.
    pub seed: u64,
}

impl MutatePayload {
    /// Build a mutate payload from raw bytes and a deterministic seed.
    pub fn from_input(input: &[u8], seed: u64) -> Self {
        Self {
            input_b64: b64::encode(input),
            seed,
        }
    }

    /// Serialize to the request-envelope payload value.
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::json!({ "input_b64": self.input_b64, "seed": self.seed })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutate_payload_carries_input_and_seed() {
        let payload = MutatePayload::from_input(b"../etc/passwd", 0x1234_5678);
        let value = payload.to_value();
        assert_eq!(value["seed"], serde_json::json!(0x1234_5678u64));
        let back: MutatePayload = serde_json::from_value(value).unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn mutate_payload_rejects_unknown_fields() {
        let raw = serde_json::json!({ "input_b64": "Zm9v", "seed": 1, "nonce": 2 });
        assert!(serde_json::from_value::<MutatePayload>(raw).is_err());
    }
}
