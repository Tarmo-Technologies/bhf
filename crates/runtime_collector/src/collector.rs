// SPDX-License-Identifier: Apache-2.0

//! The platform-neutral collector seam.
//!
//! A [`Collector`] is anything that, told which testcase/worker is running and
//! how long to keep watching, produces a `bhf.collector-event.v1` JSONL stream.
//! The native Windows ETW provider, an external sidecar, and the in-process
//! Linux adapter are all collectors; so is the dependency-free
//! [`crate::mock::MockCollector`] used to exercise the contract on every
//! platform. Keeping the seam this small is what lets a provider be implemented
//! entirely outside this repo against the published schema.

use crate::session::CollectorSessionSet;
use std::error::Error;
use std::fmt;

/// Identity of a collector backend, recorded in provenance so a finding can be
/// audited back to the exact provider that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendInfo {
    /// Stable backend name, for example `mock` or `windows-etw`.
    pub name: String,
    /// Backend version string.
    pub version: String,
    /// Content/build hash of the backend (empty when not applicable).
    pub hash: String,
}

impl BackendInfo {
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        hash: impl Into<String>,
    ) -> Self {
        BackendInfo {
            name: name.into(),
            version: version.into(),
            hash: hash.into(),
        }
    }
}

/// What a host hands a collector for a single testcase.
///
/// These map directly onto the `BHF_COLLECTOR_*` environment variables an
/// out-of-process sidecar reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorContext {
    pub testcase: String,
    pub worker: u32,
    /// Allowed filesystem root used to decide whether a path escapes.
    pub root: String,
    /// Bounded post-exit observation window, in milliseconds.
    pub window_ms: u64,
}

impl CollectorContext {
    pub fn new(
        testcase: impl Into<String>,
        worker: u32,
        root: impl Into<String>,
        window_ms: u64,
    ) -> Self {
        CollectorContext {
            testcase: testcase.into(),
            worker,
            root: root.into(),
            window_ms,
        }
    }
}

/// Error surface for a collector run. A collector that is simply unavailable on
/// the current platform returns [`CollectorError::Unsupported`] rather than
/// pretending to have observed a clean run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectorError {
    /// This collector cannot run on the current platform.
    Unsupported(String),
    /// The collector lacked the rights it needed to observe.
    PermissionDenied(String),
    /// Something went wrong while producing the stream.
    Backend(String),
}

impl fmt::Display for CollectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CollectorError::Unsupported(m) => write!(f, "collector unsupported: {m}"),
            CollectorError::PermissionDenied(m) => write!(f, "collector permission denied: {m}"),
            CollectorError::Backend(m) => write!(f, "collector backend error: {m}"),
        }
    }
}

impl Error for CollectorError {}

/// A source of `bhf.collector-event.v1` events for a single testcase.
pub trait Collector {
    /// Identity of this backend, for provenance.
    fn backend(&self) -> BackendInfo;

    /// Observe `ctx` and return the raw JSONL stream the provider emitted. This
    /// is the exact wire format a real sidecar would write to its sink.
    fn observe(&self, ctx: &CollectorContext) -> Result<String, CollectorError>;

    /// Convenience: observe and parse into grouped sessions in one step.
    fn observe_sessions(
        &self,
        ctx: &CollectorContext,
    ) -> Result<CollectorSessionSet, CollectorError> {
        Ok(CollectorSessionSet::from_jsonl(&self.observe(ctx)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_is_descriptive() {
        assert!(CollectorError::Unsupported("no etw".into())
            .to_string()
            .contains("unsupported"));
        assert!(CollectorError::PermissionDenied("no rights".into())
            .to_string()
            .contains("permission denied"));
    }
}
