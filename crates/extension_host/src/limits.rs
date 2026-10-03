// SPDX-License-Identifier: Apache-2.0

//! Bounded-message guards: frame-size, per-call time, and outstanding-request
//! caps.
//!
//! These are the host-side limits that keep a misbehaving extension bounded. A
//! frame larger than the cap and an extra in-flight request are both turned into
//! deterministic, bounded failures rather than unbounded resource use.

use crate::client::InfraFailure;
use crate::handshake::WireLimits;
use crate::{ExtensionError, Result};
use std::time::Duration;

/// The resolved host-side limits for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The maximum framed message size, in bytes. A larger declared frame is a
    /// bounded infrastructure failure, reported before allocation.
    pub max_frame_bytes: usize,
    /// The per-call deadline. A call that does not respond within this window is
    /// a bounded `Timeout` infrastructure failure (and the child is killed).
    pub call_timeout: Duration,
    /// The maximum number of concurrently outstanding requests. The synchronous
    /// `oracle.evaluate` path keeps this at 1; the guard exists so future
    /// pipelined capabilities stay bounded.
    pub max_outstanding: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 8 * 1024 * 1024,
            call_timeout: Duration::from_secs(10),
            max_outstanding: 1,
        }
    }
}

impl Limits {
    /// Resolve the host limits from the negotiated wire limits, keeping the
    /// host's own `max_outstanding`.
    pub fn from_wire(wire: WireLimits, max_outstanding: usize) -> Self {
        Self {
            max_frame_bytes: usize::try_from(wire.max_frame_bytes).unwrap_or(usize::MAX),
            call_timeout: Duration::from_millis(wire.call_timeout_ms),
            max_outstanding: max_outstanding.max(1),
        }
    }

    /// Check a declared frame length against the cap, returning a bounded
    /// [`InfraFailure::FrameTooLarge`] (never a panic or an allocation) when it
    /// is exceeded.
    pub fn check_frame(&self, declared: u64) -> std::result::Result<(), InfraFailure> {
        if declared > self.max_frame_bytes as u64 {
            Err(InfraFailure::FrameTooLarge {
                declared,
                cap: self.max_frame_bytes,
            })
        } else {
            Ok(())
        }
    }
}

/// A counter that refuses more than `max` concurrently outstanding requests.
#[derive(Debug)]
pub struct OutstandingGuard {
    max: usize,
    inflight: usize,
}

impl OutstandingGuard {
    /// Create a guard permitting at most `max` concurrent requests (floored at 1).
    pub fn new(max: usize) -> Self {
        Self {
            max: max.max(1),
            inflight: 0,
        }
    }

    /// Reserve one in-flight slot, or fail if the cap is already reached.
    pub fn acquire(&mut self) -> Result<()> {
        if self.inflight >= self.max {
            return Err(ExtensionError::OutstandingLimit { max: self.max });
        }
        self.inflight += 1;
        Ok(())
    }

    /// Release one in-flight slot. Saturating at zero.
    pub fn release(&mut self) {
        self.inflight = self.inflight.saturating_sub(1);
    }

    /// The number of currently reserved slots.
    pub fn inflight(&self) -> usize {
        self.inflight
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outstanding_request_cap_rejects_extra_inflight() {
        let mut guard = OutstandingGuard::new(2);
        guard.acquire().expect("first slot");
        guard.acquire().expect("second slot");
        assert_eq!(guard.inflight(), 2);

        let err = guard.acquire().expect_err("third must be refused");
        assert!(matches!(err, ExtensionError::OutstandingLimit { max: 2 }));

        // Releasing a slot lets a new request through again.
        guard.release();
        guard.acquire().expect("slot freed");
        assert_eq!(guard.inflight(), 2);
    }

    #[test]
    fn frame_over_limit_is_infrastructure() {
        let limits = Limits {
            max_frame_bytes: 64,
            call_timeout: Duration::from_secs(1),
            max_outstanding: 1,
        };
        assert!(limits.check_frame(64).is_ok(), "at the cap is allowed");
        match limits.check_frame(65).expect_err("over the cap") {
            InfraFailure::FrameTooLarge { declared, cap } => {
                assert_eq!(declared, 65);
                assert_eq!(cap, 64);
            }
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn from_wire_takes_millis_and_floors_outstanding() {
        let limits = Limits::from_wire(
            WireLimits {
                max_frame_bytes: 4096,
                call_timeout_ms: 2500,
            },
            0,
        );
        assert_eq!(limits.max_frame_bytes, 4096);
        assert_eq!(limits.call_timeout, Duration::from_millis(2500));
        assert_eq!(limits.max_outstanding, 1, "outstanding floored at 1");
    }
}
