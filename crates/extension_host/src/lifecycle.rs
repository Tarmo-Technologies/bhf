// SPDX-License-Identifier: Apache-2.0

//! The `lifecycle.setup` / `lifecycle.reset` / `lifecycle.teardown` payloads.
//!
//! A lifecycle extension orchestrates per-case state:
//!
//! - `lifecycle.setup` runs once before the first case (allocate a working area,
//!   open a connection pool).
//! - `lifecycle.reset` runs between cases with a **fresh temp root**, so one
//!   case's side effects never leak into the next; the extension anchors its
//!   sandbox there (and an oracle can later judge a write as "outside the root").
//! - `lifecycle.teardown` runs once at the end (release everything).
//!
//! The host supplies the fresh root path on `reset` (and optionally `setup`); the
//! extension returns `ok`, or a bounded `infrastructure_error`/`unsupported` that
//! can never become a target finding.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Request payload for a `lifecycle.*` call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecyclePayload {
    /// The fresh working/sandbox root for this phase, if the host allocated one
    /// (always present on `reset`, optional on `setup`, absent on `teardown`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
}

impl LifecyclePayload {
    /// A payload carrying a root path.
    pub fn with_root(root: &Path) -> Self {
        Self {
            root: Some(root.display().to_string()),
        }
    }

    /// A payload carrying no root (e.g. `teardown`).
    pub fn empty() -> Self {
        Self { root: None }
    }

    /// Serialize to the request-envelope payload value.
    pub fn to_value(&self) -> serde_json::Value {
        match &self.root {
            Some(root) => serde_json::json!({ "root": root }),
            None => serde_json::json!({}),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_payload_carries_root_or_empty() {
        let with = LifecyclePayload::with_root(Path::new("/tmp/case-7"));
        assert_eq!(with.to_value()["root"], serde_json::json!("/tmp/case-7"));
        let without = LifecyclePayload::empty();
        assert_eq!(without.to_value(), serde_json::json!({}));
    }

    #[test]
    fn lifecycle_payload_rejects_unknown_fields() {
        let raw = serde_json::json!({ "root": "/tmp", "extra": true });
        assert!(serde_json::from_value::<LifecyclePayload>(raw).is_err());
    }
}
