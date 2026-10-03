// SPDX-License-Identifier: Apache-2.0

//! Ancestor / descendant attribution and the bounded post-exit observation
//! window.
//!
//! A clean-exit defect is frequently committed by a *descendant* of the testcase
//! process — a `CreateProcess*`/`ShellExecute*` child, or its grandchild — and
//! sometimes just after the testcase process itself has exited. Attribution
//! builds the testcase's process tree from the observed create events and keeps
//! only the events that (a) belong to that tree and (b) fall inside the bounded
//! window `[.., end_ts + window]`. Events outside the window are counted, not
//! silently honored, so an attacker cannot smuggle an effect in by delaying it.

use crate::schema::CollectorEvent;
use crate::session::CollectorSession;
use std::collections::BTreeSet;

/// A session with its process tree resolved and its events attributed.
#[derive(Debug, Clone)]
pub struct AttributedSession<'a> {
    /// Root process of the testcase (the attribution anchor).
    pub root_pid: Option<u32>,
    /// Every pid in the attributed descendant tree (feeds provenance scope).
    pub tree_pids: BTreeSet<u32>,
    /// Events belonging to the testcase tree and inside the window, in order.
    pub attributed: Vec<&'a CollectorEvent>,
    /// Events that belonged to the tree but fell outside the post-exit window.
    pub dropped_out_of_window: usize,
}

/// Attribute a session's events to its testcase tree within `window_ms` of the
/// testcase's exit.
pub fn attribute(session: &CollectorSession, window_ms: u64) -> AttributedSession<'_> {
    let root_pid = session.root_pid();
    let end_ts = session.end_ts();
    let cutoff = end_ts.map(|t| t + (window_ms as f64) / 1000.0);

    let mut tree: BTreeSet<u32> = BTreeSet::new();
    if let Some(root) = root_pid {
        tree.insert(root);
    }

    let mut attributed = Vec::new();
    let mut dropped_out_of_window = 0usize;

    for ev in &session.events {
        // Grow the descendant tree in seq order: a process whose parent is
        // already in the tree, or whose recorded ancestor is the root, joins it.
        let belongs = root_pid == Some(ev.process.pid)
            || ev.process.ancestor == root_pid && root_pid.is_some()
            || ev
                .process
                .parent
                .map(|p| tree.contains(&p))
                .unwrap_or(false);
        if belongs {
            tree.insert(ev.process.pid);
        }

        if !belongs {
            continue;
        }

        let in_window = match (ev.ts, cutoff) {
            (Some(ts), Some(cut)) => ts <= cut,
            // No timestamp or no end boundary => cannot be ruled out by the window.
            _ => true,
        };
        if in_window {
            attributed.push(ev);
        } else {
            dropped_out_of_window += 1;
        }
    }

    AttributedSession {
        root_pid,
        tree_pids: tree,
        attributed,
        dropped_out_of_window,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{CollectorEvent, EventKind, EventPhase, Fidelity, ProcessIdentity};
    use crate::session::CollectorSession;

    fn proc_create(
        seq: u64,
        pid: u32,
        parent: Option<u32>,
        ancestor: Option<u32>,
        ts: f64,
    ) -> CollectorEvent {
        let mut e = CollectorEvent::new("tc", 0, seq, EventPhase::Event, EventKind::ProcessCreate);
        e.process = ProcessIdentity {
            pid,
            parent,
            ancestor,
            ..Default::default()
        };
        e.ts = Some(ts);
        e
    }

    fn file_write(
        seq: u64,
        pid: u32,
        parent: Option<u32>,
        ancestor: Option<u32>,
        ts: f64,
    ) -> CollectorEvent {
        let mut e = CollectorEvent::new("tc", 0, seq, EventPhase::Event, EventKind::FileWrite);
        e.process = ProcessIdentity {
            pid,
            parent,
            ancestor,
            ..Default::default()
        };
        e.path = Some("/tmp/out".into());
        e.ts = Some(ts);
        e
    }

    fn begin(pid: u32, ts: f64) -> CollectorEvent {
        let mut e = CollectorEvent::new("tc", 0, 0, EventPhase::Begin, EventKind::ProcessCreate);
        e.process = ProcessIdentity {
            pid,
            ..Default::default()
        };
        e.ts = Some(ts);
        e
    }

    fn end(pid: u32, seq: u64, ts: f64) -> CollectorEvent {
        let mut e = CollectorEvent::new("tc", 0, seq, EventPhase::End, EventKind::ProcessCreate);
        e.process = ProcessIdentity {
            pid,
            ..Default::default()
        };
        e.ts = Some(ts);
        e
    }

    fn session(events: Vec<CollectorEvent>) -> CollectorSession {
        CollectorSession {
            testcase: "tc".into(),
            worker: 0,
            events,
            fidelity: Fidelity::default(),
        }
    }

    #[test]
    fn direct_child_event_attributed_to_testcase() {
        // Root 1000; a direct child 1001 (ancestor == root) does a file_write.
        let s = session(vec![
            begin(1000, 100.0),
            file_write(1, 1001, Some(1000), Some(1000), 101.0),
        ]);
        let a = attribute(&s, 250);
        assert_eq!(a.root_pid, Some(1000));
        assert!(a.tree_pids.contains(&1001));
        assert!(a
            .attributed
            .iter()
            .any(|e| e.process.pid == 1001 && e.kind == EventKind::FileWrite));
    }

    #[test]
    fn descendant_tree_event_attributed() {
        // Root 1000 -> child 1001 -> grandchild 1002 (parent chain, no ancestor).
        let s = session(vec![
            begin(1000, 100.0),
            proc_create(1, 1001, Some(1000), None, 100.5),
            proc_create(2, 1002, Some(1001), None, 100.7),
            file_write(3, 1002, Some(1001), None, 101.0),
        ]);
        let a = attribute(&s, 250);
        assert!(a.tree_pids.contains(&1001));
        assert!(a.tree_pids.contains(&1002), "grandchild must join the tree");
        assert!(a
            .attributed
            .iter()
            .any(|e| e.process.pid == 1002 && e.kind == EventKind::FileWrite));
    }

    #[test]
    fn unrelated_process_not_attributed() {
        // pid 9999 shares no ancestry with the testcase root.
        let s = session(vec![
            begin(1000, 100.0),
            file_write(1, 9999, Some(4242), Some(4242), 101.0),
        ]);
        let a = attribute(&s, 250);
        assert!(!a.tree_pids.contains(&9999));
        assert!(a.attributed.iter().all(|e| e.process.pid != 9999));
    }

    #[test]
    fn post_exit_event_within_window_kept_outside_dropped() {
        // end at T=110.0, window = 1000ms => cutoff 111.0.
        let s = session(vec![
            begin(1000, 100.0),
            file_write(1, 1001, Some(1000), Some(1000), 101.0),
            end(2, 1000, 110.0),
            // post-exit descendant effect at T + 0.5s (kept)
            file_write(3, 1001, Some(1000), Some(1000), 110.5),
            // post-exit descendant effect at T + 2s (dropped)
            file_write(4, 1001, Some(1000), Some(1000), 112.0),
        ]);
        let a = attribute(&s, 1000);
        let kept_ts: Vec<f64> = a.attributed.iter().filter_map(|e| e.ts).collect();
        assert!(kept_ts.contains(&110.5), "in-window post-exit event kept");
        assert!(!kept_ts.contains(&112.0), "out-of-window event not kept");
        assert_eq!(a.dropped_out_of_window, 1);
    }

    #[test]
    fn descendant_tree_scope_recorded() {
        let s = session(vec![
            begin(1000, 100.0),
            proc_create(1, 1001, Some(1000), None, 100.5),
            proc_create(2, 1002, Some(1001), None, 100.7),
        ]);
        let a = attribute(&s, 250);
        let scope: Vec<u32> = a.tree_pids.iter().copied().collect();
        assert_eq!(scope, vec![1000, 1001, 1002]);
    }
}
