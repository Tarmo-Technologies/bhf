// SPDX-License-Identifier: Apache-2.0

//! Crash-isolation restart policy and loss-event accounting.
//!
//! When an extension crashes or times out, the host may restart it a bounded
//! number of times with an exponential backoff. Once the restart budget is
//! exhausted the loss is *terminal*: the call becomes a bounded infrastructure
//! result and a loss event is recorded in provenance. All timing is derived
//! arithmetically so the policy is deterministic and unit-testable without any
//! real sleeping.

use std::time::Duration;

/// An explicit restart policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartPolicy {
    /// The maximum number of restarts permitted over the session's lifetime.
    pub max_restarts: u32,
    /// The base backoff; the nth restart waits `base * 2^(n-1)` (saturating).
    pub base_backoff: Duration,
    /// An upper bound on any single backoff delay.
    pub max_backoff: Duration,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            max_restarts: 2,
            base_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
        }
    }
}

impl RestartPolicy {
    /// A policy that never restarts (every fault is immediately terminal).
    pub fn never() -> Self {
        Self {
            max_restarts: 0,
            base_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
        }
    }

    /// The backoff delay for the `attempt`-th restart (1-based), growing
    /// exponentially and clamped to `max_backoff`.
    pub fn backoff_for(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }
        let shift = attempt - 1;
        // Saturating exponential: base * 2^(attempt-1), clamped to max_backoff.
        let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
        let scaled = self
            .base_backoff
            .checked_mul(u32::try_from(factor).unwrap_or(u32::MAX))
            .unwrap_or(self.max_backoff);
        scaled.min(self.max_backoff)
    }
}

/// Mutable restart/loss accounting for a single session.
#[derive(Debug, Clone)]
pub struct RestartState {
    policy: RestartPolicy,
    restarts: u32,
    losses: u32,
}

impl RestartState {
    /// Create fresh state for `policy`.
    pub fn new(policy: RestartPolicy) -> Self {
        Self {
            policy,
            restarts: 0,
            losses: 0,
        }
    }

    /// Whether another restart is permitted under the budget.
    pub fn should_restart(&self) -> bool {
        self.restarts < self.policy.max_restarts
    }

    /// Record a restart and return the backoff to wait before respawning.
    ///
    /// # Panics
    /// Panics if called when [`Self::should_restart`] is `false`; callers must
    /// check the budget first.
    pub fn record_restart(&mut self) -> Duration {
        assert!(
            self.should_restart(),
            "record_restart called with the restart budget exhausted"
        );
        self.restarts += 1;
        self.policy.backoff_for(self.restarts)
    }

    /// Record a terminal loss event (surfaced in provenance).
    pub fn record_loss(&mut self) {
        self.losses += 1;
    }

    /// The number of restarts performed.
    pub fn restarts(&self) -> u32 {
        self.restarts
    }

    /// The number of terminal loss events recorded.
    pub fn losses(&self) -> u32 {
        self.losses
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_policy_caps_total_restarts() {
        let mut state = RestartState::new(RestartPolicy {
            max_restarts: 2,
            base_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_secs(1),
        });
        assert!(state.should_restart());
        state.record_restart();
        assert!(state.should_restart());
        state.record_restart();
        assert!(!state.should_restart(), "budget exhausted after 2 restarts");
        assert_eq!(state.restarts(), 2);
    }

    #[test]
    fn restart_policy_backs_off_exponentially() {
        let policy = RestartPolicy {
            max_restarts: 5,
            base_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(10),
        };
        assert_eq!(policy.backoff_for(1), Duration::from_millis(100));
        assert_eq!(policy.backoff_for(2), Duration::from_millis(200));
        assert_eq!(policy.backoff_for(3), Duration::from_millis(400));
        assert_eq!(policy.backoff_for(4), Duration::from_millis(800));
        // Strictly increasing until the clamp.
        assert!(policy.backoff_for(2) > policy.backoff_for(1));
        assert!(policy.backoff_for(3) > policy.backoff_for(2));
    }

    #[test]
    fn backoff_is_clamped_to_max() {
        let policy = RestartPolicy {
            max_restarts: 64,
            base_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(500),
        };
        // 2^9 * 100ms would be ~51s, but must clamp to 500ms.
        assert_eq!(policy.backoff_for(10), Duration::from_millis(500));
        // A huge attempt must not panic or overflow.
        assert_eq!(policy.backoff_for(u32::MAX), Duration::from_millis(500));
    }

    #[test]
    fn loss_events_accumulate() {
        let mut state = RestartState::new(RestartPolicy::never());
        assert_eq!(state.losses(), 0);
        state.record_loss();
        state.record_loss();
        assert_eq!(state.losses(), 2);
    }

    #[test]
    #[should_panic(expected = "restart budget exhausted")]
    fn record_restart_panics_past_budget() {
        let mut state = RestartState::new(RestartPolicy::never());
        state.record_restart();
    }
}
