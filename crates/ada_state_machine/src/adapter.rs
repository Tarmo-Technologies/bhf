// SPDX-License-Identifier: Apache-2.0

//! Engine-facing adapter for inferred state machines (HDF-7, deliverable 3).
//!
//! [`crate::infer_from_source`] produces a [`StateMachine`] that today only
//! feeds a print-JSON CLI subcommand. AFLNet-style stateful fuzzing needs a
//! different shape: given the state a session is in, which messages (entries)
//! are valid to send next, and which state each transition leads to, so the
//! engine can *order* inputs to drive a target through its protocol states
//! instead of firing single-shot inputs.
//!
//! [`ProtocolStateGraph`] is that shape: dense integer [`StateId`]s, an initial
//! state, and adjacency by source state. This is intentionally a thin, typed
//! projection — full engine integration (an input scheduler keyed on the graph)
//! is a noted follow-up; this adapter is the seam it would consume.

use serde::Serialize;

use crate::{MachineKind, StateMachine};

/// A dense state index into [`ProtocolStateGraph::states`].
pub type StateId = usize;

/// One protocol transition: sending `entry` from state `from` moves the session
/// to state `to`. `guarded` records that the source entry had a barrier
/// condition, so an ordering strategy can treat it as conditionally reachable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProtocolEdge {
    pub from: StateId,
    pub entry: String,
    pub to: StateId,
    pub guarded: bool,
}

/// An AFLNet-style projection of a [`StateMachine`]: states as integer ids,
/// a single initial state, and transitions grouped for lookup by source state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProtocolStateGraph {
    pub machine: String,
    pub kind: MachineKind,
    states: Vec<String>,
    open_entries: Vec<Vec<String>>,
    initial: StateId,
    edges: Vec<ProtocolEdge>,
}

impl ProtocolStateGraph {
    /// Project an inferred [`StateMachine`] into an ordering-friendly graph.
    ///
    /// States keep their declaration order; the initial state is `ready` (the
    /// name [`crate::infer_from_source`] assigns the entry state) when present,
    /// else state 0. Transitions that name an unknown state are dropped rather
    /// than silently pointing at a bogus index — inference always names known
    /// states today, so this only guards against future drift.
    pub fn from_machine(machine: &StateMachine) -> Self {
        let states: Vec<String> = machine.states.iter().map(|s| s.name.clone()).collect();
        let open_entries: Vec<Vec<String>> = machine
            .states
            .iter()
            .map(|s| s.open_entries.clone())
            .collect();

        let index_of = |name: &str| states.iter().position(|candidate| candidate == name);

        let initial = index_of("ready").unwrap_or(0);

        let edges = machine
            .transitions
            .iter()
            .filter_map(|transition| {
                let from = index_of(&transition.from)?;
                let to = index_of(&transition.to)?;
                Some(ProtocolEdge {
                    from,
                    entry: transition.entry.clone(),
                    to,
                    guarded: transition.barrier.is_some(),
                })
            })
            .collect();

        Self {
            machine: machine.name.clone(),
            kind: machine.kind,
            states,
            open_entries,
            initial,
            edges,
        }
    }

    pub fn initial(&self) -> StateId {
        self.initial
    }

    pub fn state_count(&self) -> usize {
        self.states.len()
    }

    pub fn states(&self) -> &[String] {
        &self.states
    }

    pub fn edges(&self) -> &[ProtocolEdge] {
        &self.edges
    }

    pub fn state_name(&self, id: StateId) -> Option<&str> {
        self.states.get(id).map(String::as_str)
    }

    pub fn state_id(&self, name: &str) -> Option<StateId> {
        self.states.iter().position(|candidate| candidate == name)
    }

    /// Entries that are open (callable) in `state`. For AFLNet ordering this is
    /// the alphabet of messages a session may send while in that state.
    pub fn open_entries(&self, state: StateId) -> &[String] {
        self.open_entries
            .get(state)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Transitions leaving `state`, i.e. the (message, next-state) options an
    /// ordering strategy chooses among.
    pub fn transitions_from(&self, state: StateId) -> impl Iterator<Item = &ProtocolEdge> {
        self.edges.iter().filter(move |edge| edge.from == state)
    }

    /// Resolve the state reached by sending `entry` from `state`, if any.
    pub fn next_state(&self, state: StateId, entry: &str) -> Option<StateId> {
        self.transitions_from(state)
            .find(|edge| edge.entry == entry)
            .map(|edge| edge.to)
    }
}

/// Project every machine inferred from `machines` into a graph.
pub fn protocol_graphs(machines: &[StateMachine]) -> Vec<ProtocolStateGraph> {
    machines
        .iter()
        .map(ProtocolStateGraph::from_machine)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infer_from_source;

    #[test]
    fn graph_exposes_states_and_transitions_for_a_protected_type() {
        let source = r#"
package P is
   protected type Counter is
      entry Increment;
      entry Decrement;
   end Counter;
end P;
"#;
        let machines = infer_from_source(source).expect("parse ok");
        let graph = ProtocolStateGraph::from_machine(&machines[0]);

        // Initial state is "ready" and both unguarded entries are open there.
        let initial = graph.initial();
        assert_eq!(graph.state_name(initial), Some("ready"));
        let open: Vec<&str> = graph
            .open_entries(initial)
            .iter()
            .map(String::as_str)
            .collect();
        assert!(open.iter().any(|e| e.eq_ignore_ascii_case("increment")));
        assert!(open.iter().any(|e| e.eq_ignore_ascii_case("decrement")));

        // From "ready", each entry transitions to its own "after-<entry>" state,
        // and next_state resolves the target — the adjacency an ordering
        // strategy walks.
        let increment_edge = graph
            .transitions_from(initial)
            .find(|edge| edge.entry.eq_ignore_ascii_case("increment"))
            .expect("increment transition present");
        let target = increment_edge.to;
        assert_eq!(
            graph.next_state(initial, &increment_edge.entry),
            Some(target)
        );
        assert!(
            graph
                .state_name(target)
                .is_some_and(|name| name.to_ascii_lowercase().starts_with("after-")),
            "increment leads to an after-<entry> state, got {:?}",
            graph.state_name(target)
        );

        // Every edge references in-bounds states — the graph is well-formed.
        for edge in graph.edges() {
            assert!(edge.from < graph.state_count());
            assert!(edge.to < graph.state_count());
        }
    }

    #[test]
    fn barrier_presence_maps_to_guarded_edge() {
        // Adapter unit test: a transition carrying a barrier becomes a guarded
        // edge; one without stays unguarded. Built directly from the public
        // model so it tests the adapter mapping, not tree-sitter's barrier
        // extraction (covered by the inference tests).
        use crate::{EntryBarrier, State, Transition};

        let machine = StateMachine {
            kind: MachineKind::Protected,
            name: "Gate".to_owned(),
            states: vec![
                State {
                    name: "ready".to_owned(),
                    open_entries: vec!["Unlock".to_owned()],
                },
                State {
                    name: "after-Open".to_owned(),
                    open_entries: vec![],
                },
                State {
                    name: "after-Unlock".to_owned(),
                    open_entries: vec![],
                },
            ],
            transitions: vec![
                Transition {
                    from: "ready".to_owned(),
                    entry: "Open".to_owned(),
                    to: "after-Open".to_owned(),
                    barrier: Some(EntryBarrier {
                        source: "Is_Locked".to_owned(),
                    }),
                },
                Transition {
                    from: "ready".to_owned(),
                    entry: "Unlock".to_owned(),
                    to: "after-Unlock".to_owned(),
                    barrier: None,
                },
            ],
        };

        let graph = ProtocolStateGraph::from_machine(&machine);
        let open_edge = graph
            .edges()
            .iter()
            .find(|edge| edge.entry == "Open")
            .expect("open transition present");
        assert!(open_edge.guarded, "barrier-guarded entry must be flagged");
        let unlock_edge = graph
            .edges()
            .iter()
            .find(|edge| edge.entry == "Unlock")
            .expect("unlock transition present");
        assert!(!unlock_edge.guarded, "unguarded entry must not be flagged");
        // The initial "ready" state resolves and its transitions target valid
        // states.
        assert_eq!(graph.state_name(graph.initial()), Some("ready"));
        assert_eq!(
            graph.next_state(graph.initial(), "Open"),
            graph.state_id("after-Open")
        );
    }

    #[test]
    fn protocol_graphs_projects_every_machine() {
        let source = r#"
package P is
   protected type Gate is
      entry Lock;
   end Gate;
   task type Worker is
      entry Start;
   end Worker;
end P;
"#;
        let machines = infer_from_source(source).expect("parse ok");
        let graphs = protocol_graphs(&machines);
        assert_eq!(graphs.len(), 2);
        assert!(graphs.iter().any(|g| g.kind == MachineKind::Protected));
        assert!(graphs.iter().any(|g| g.kind == MachineKind::Task));
    }
}
