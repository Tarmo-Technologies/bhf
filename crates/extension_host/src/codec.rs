// SPDX-License-Identifier: Apache-2.0

//! The `codec.decode` / `codec.encode` / `codec.repair` capability payloads.
//!
//! A codec extension understands a *structured* input format (a framed protocol,
//! a container, a checksummed record) that the fuzzer treats as opaque bytes.
//!
//! - `codec.decode` turns a raw frame into a structured value the host carries
//!   opaquely (the extension owns its shape; the host never interprets it).
//! - `codec.encode` turns a structured value back into raw bytes.
//! - `codec.repair` recomputes a frame's *computed* fields (length prefixes,
//!   checksums/CRCs) after a mutation corrupted them, so a mutated-but-broken
//!   frame becomes a well-formed one the target will actually parse.
//!
//! The host is codec-agnostic: it only ships the bytes/value across the wire and
//! parses the typed response. A decode/repair the extension cannot perform is a
//! `reject` (drop the input), never a finding.

use crate::b64;
use crate::{ExtensionError, Result};
use serde::{Deserialize, Serialize};

/// Request payload for `codec.decode`: the raw frame to decode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecodePayload {
    /// The raw frame, standard-base64 encoded.
    pub input_b64: String,
}

impl DecodePayload {
    /// Build a decode payload from raw bytes.
    pub fn from_input(input: &[u8]) -> Self {
        Self {
            input_b64: b64::encode(input),
        }
    }

    /// Serialize to the request-envelope payload value.
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::json!({ "input_b64": self.input_b64 })
    }
}

/// The structured value a `codec.decode` returns, carried opaquely by the host.
///
/// The host never interprets `decoded`; it only round-trips it back through
/// `codec.encode`. The wrapper exists so the response `value` has a stable,
/// `deny_unknown_fields` shape (`{ "decoded": <structured> }`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecodedValue {
    /// The extension-defined structured representation of the frame.
    pub decoded: serde_json::Value,
}

impl DecodedValue {
    /// Parse a `codec.decode` response `value`.
    pub fn from_value(value: &serde_json::Value) -> Result<Self> {
        serde_json::from_value(value.clone()).map_err(|e| {
            ExtensionError::protocol(format!(
                "codec.decode response value was not {{decoded}}: {e}"
            ))
        })
    }
}

/// Request payload for `codec.encode`: the structured value to re-encode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncodePayload {
    /// The structured value previously produced by `codec.decode` (or a mutated
    /// variant of it).
    pub decoded: serde_json::Value,
}

impl EncodePayload {
    /// Build an encode payload from a structured value.
    pub fn new(decoded: serde_json::Value) -> Self {
        Self { decoded }
    }

    /// Serialize to the request-envelope payload value.
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::json!({ "decoded": self.decoded })
    }
}

/// Request payload for `codec.repair`: a raw (possibly mutation-corrupted) frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepairPayload {
    /// The raw frame to repair, standard-base64 encoded.
    pub input_b64: String,
}

impl RepairPayload {
    /// Build a repair payload from raw bytes.
    pub fn from_input(input: &[u8]) -> Self {
        Self {
            input_b64: b64::encode(input),
        }
    }

    /// Serialize to the request-envelope payload value.
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::json!({ "input_b64": self.input_b64 })
    }
}

/// The `{ "output_b64": "…" }` shape shared by `codec.encode`, `codec.repair`,
/// and `mutator.mutate` responses: the raw output bytes, standard-base64 encoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OutputBytes {
    pub output_b64: String,
}

/// Parse a response `value` carrying `{ "output_b64": "…" }` into raw bytes.
pub(crate) fn output_bytes_from_value(value: &serde_json::Value) -> Result<Vec<u8>> {
    let parsed: OutputBytes = serde_json::from_value(value.clone()).map_err(|e| {
        ExtensionError::protocol(format!("response value was not {{output_b64}}: {e}"))
    })?;
    b64::decode(&parsed.output_b64)
        .map_err(|e| ExtensionError::protocol(format!("output_b64 was not valid base64: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decode_payload_roundtrips_raw_bytes() {
        let payload = DecodePayload::from_input(&[0x00, 0x05, b'h', b'i', 0xde, 0xad]);
        let value = payload.to_value();
        let back: DecodePayload = serde_json::from_value(value).unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn decoded_value_parses_structured_shape_and_rejects_extra_keys() {
        let ok = json!({ "decoded": { "op": "OPEN", "path": "../etc/passwd", "length": 13 } });
        let parsed = DecodedValue::from_value(&ok).unwrap();
        assert_eq!(parsed.decoded["op"], json!("OPEN"));
        // An unknown sibling key is rejected (the wrapper is strict).
        let bad = json!({ "decoded": {}, "surprise": 1 });
        assert!(DecodedValue::from_value(&bad).is_err());
    }

    #[test]
    fn encode_payload_carries_structured_value() {
        let payload = EncodePayload::new(json!({ "op": "WRITE", "handle": "h-1", "data": "AQ==" }));
        assert_eq!(payload.to_value()["decoded"]["op"], json!("WRITE"));
    }

    #[test]
    fn output_bytes_decodes_base64_and_rejects_malformed() {
        let value = json!({ "output_b64": "Zm9vYmFy" });
        assert_eq!(output_bytes_from_value(&value).unwrap(), b"foobar");
        // Not base64.
        assert!(output_bytes_from_value(&json!({ "output_b64": "not*b64" })).is_err());
        // Wrong shape.
        assert!(output_bytes_from_value(&json!({ "nope": 1 })).is_err());
    }
}
