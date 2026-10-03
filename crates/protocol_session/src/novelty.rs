// SPDX-License-Identifier: Apache-2.0

//! Novelty tracking, with the two channels kept strictly separate.
//!
//! Stateful fuzzing schedules on *two* independent signals:
//!
//! * **Code coverage** — the edges/blocks a run exercised in the target, folded
//!   by the engine's existing coverage machinery. Tracked here by
//!   [`CodeCoverageNovelty`].
//! * **Protocol state/transition novelty** — the states and transitions a
//!   session walked in the profile's [`ProtocolStateGraph`], tracked by
//!   [`StateNovelty`].
//!
//! The two are never merged into one number: a path that reaches an unvisited
//! transition is novel on the state channel even when it touched no new code,
//! and vice versa. Keeping them in separate trackers is what lets a campaign
//! report them separately.
//!
//! [`ProtocolStateGraph`]: ada_state_machine::adapter::ProtocolStateGraph

use std::collections::HashSet;

use ada_state_machine::adapter::StateId;

/// A transition identity: `(from_state, entry, to_state)`.
pub type TransitionId = (StateId, String, StateId);

/// How many states / transitions a single `observe` newly revealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StateNoveltyDelta {
    pub new_states: usize,
    pub new_transitions: usize,
}

impl StateNoveltyDelta {
    /// True when the observation revealed anything new on the state channel.
    pub fn is_novel(&self) -> bool {
        self.new_states > 0 || self.new_transitions > 0
    }
}

/// Tracks the set of protocol states and transitions visited across a campaign.
#[derive(Debug, Clone, Default)]
pub struct StateNovelty {
    states: HashSet<StateId>,
    transitions: HashSet<TransitionId>,
}

impl StateNovelty {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one session's walked `states` and `transitions` into the tracker,
    /// returning how many of each were new.
    pub fn observe(
        &mut self,
        states: &[StateId],
        transitions: &[TransitionId],
    ) -> StateNoveltyDelta {
        let mut delta = StateNoveltyDelta::default();
        for &state in states {
            if self.states.insert(state) {
                delta.new_states += 1;
            }
        }
        for transition in transitions {
            if self.transitions.insert(transition.clone()) {
                delta.new_transitions += 1;
            }
        }
        delta
    }

    /// Distinct states visited so far.
    pub fn states_covered(&self) -> usize {
        self.states.len()
    }

    /// Distinct transitions visited so far.
    pub fn transitions_covered(&self) -> usize {
        self.transitions.len()
    }
}

/// Tracks the set of code-coverage edge ids seen across a campaign. This is the
/// code channel, deliberately independent of [`StateNovelty`].
#[derive(Debug, Clone, Default)]
pub struct CodeCoverageNovelty {
    edges: HashSet<u64>,
}

impl CodeCoverageNovelty {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold a run's `edges` into the tracker, returning how many were new.
    pub fn observe(&mut self, edges: &[u64]) -> usize {
        let mut new = 0;
        for &edge in edges {
            if self.edges.insert(edge) {
                new += 1;
            }
        }
        new
    }

    /// Distinct code edges seen so far.
    pub fn edges_covered(&self) -> usize {
        self.edges.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_path_reports_new_states_and_transitions_then_zero() {
        let mut novelty = StateNovelty::new();
        let states = [0usize, 1usize];
        let transitions = [(0usize, "OPEN".to_owned(), 1usize)];
        let first = novelty.observe(&states, &transitions);
        assert!(first.new_states > 0 && first.new_transitions > 0);
        assert_eq!(novelty.states_covered(), 2);
        assert_eq!(novelty.transitions_covered(), 1);

        let second = novelty.observe(&states, &transitions);
        assert_eq!(second, StateNoveltyDelta::default());
        assert!(!second.is_novel());
    }

    #[test]
    fn new_transition_at_equal_code_coverage_is_novel() {
        let mut code = CodeCoverageNovelty::new();
        let mut state = StateNovelty::new();

        // First session: some code edges and a transition.
        assert_eq!(code.observe(&[10, 11]), 2);
        let d1 = state.observe(&[0, 1], &[(0usize, "OPEN".to_owned(), 1usize)]);
        assert!(d1.is_novel());

        // Second session: the SAME code edges (zero new code) but a new
        // transition. The state channel still reports novelty.
        assert_eq!(code.observe(&[10, 11]), 0, "no new code edges");
        let d2 = state.observe(&[1], &[(1usize, "WRITE".to_owned(), 1usize)]);
        assert_eq!(
            d2.new_transitions, 1,
            "new transition is novel regardless of code"
        );
    }
}
