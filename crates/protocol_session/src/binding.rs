// SPDX-License-Identifier: Apache-2.0

//! The response-derived binding table.
//!
//! A binding maps a fully-qualified source key (`MSG.response.FIELD`) to the
//! value captured from a reply. Later requests reference these keys to echo a
//! per-session handle / id / nonce / cookie the target only revealed at run
//! time. Bindings are populated live during a session drive and snapshotted
//! into the testcase artifact for diagnostics; replay re-captures fresh values
//! rather than reusing the snapshot.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A value captured from a response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BoundValue {
    /// An integer value (u8/u16/u32), stored width-agnostically.
    Int { value: u64 },
    /// A symbolic enum value with its resolved integer code.
    Enum { symbol: String, code: u64 },
    /// Opaque captured bytes.
    Bytes { value: Vec<u8> },
}

impl BoundValue {
    /// The integer view of this value, where one exists (int or enum code).
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            BoundValue::Int { value } | BoundValue::Enum { code: value, .. } => Some(*value),
            BoundValue::Bytes { .. } => None,
        }
    }

    /// The raw bytes of a byte-valued capture.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            BoundValue::Bytes { value } => Some(value),
            _ => None,
        }
    }
}

/// The live (or snapshotted) binding table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bindings {
    map: BTreeMap<String, BoundValue>,
}

impl Bindings {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind (or rebind) a source key to a captured value.
    pub fn bind(&mut self, source: impl Into<String>, value: BoundValue) {
        self.map.insert(source.into(), value);
    }

    /// Look up a bound value by its fully-qualified source key.
    pub fn get(&self, source: &str) -> Option<&BoundValue> {
        self.map.get(source)
    }

    pub fn contains(&self, source: &str) -> bool {
        self.map.contains_key(source)
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Iterate over `(source, value)` pairs in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &BoundValue)> {
        self.map.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_and_resolve_round_trips() {
        let mut bindings = Bindings::new();
        bindings.bind(
            "OPEN.response.handle",
            BoundValue::Int { value: 0xDEAD_BEEF },
        );
        assert_eq!(
            bindings
                .get("OPEN.response.handle")
                .and_then(BoundValue::as_u64),
            Some(0xDEAD_BEEF)
        );
        assert!(bindings.contains("OPEN.response.handle"));
        assert!(!bindings.contains("OPEN.response.missing"));
    }

    #[test]
    fn rebinding_replaces_the_prior_value() {
        let mut bindings = Bindings::new();
        bindings.bind("k", BoundValue::Int { value: 1 });
        bindings.bind("k", BoundValue::Int { value: 2 });
        assert_eq!(bindings.get("k").and_then(BoundValue::as_u64), Some(2));
        assert_eq!(bindings.len(), 1);
    }
}
