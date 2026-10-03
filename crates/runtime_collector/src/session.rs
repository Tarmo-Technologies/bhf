// SPDX-License-Identifier: Apache-2.0

//! Session reader: group a JSONL event stream into per-testcase, per-worker
//! sessions.
//!
//! A collector sink is a flat stream of [`CollectorEvent`] lines produced by one
//! or more concurrent workers. The reader groups by `(testcase, worker)`,
//! restores `seq` order (lines may arrive interleaved), and merges each group's
//! [`Fidelity`] into a session total. Two workers racing on overlapping pids
//! stay isolated because grouping is keyed on the worker id, never on the pid.

use crate::schema::{CollectorEvent, Fidelity};

/// All events observed for one `(testcase, worker)` pair, in `seq` order.
#[derive(Debug, Clone, PartialEq)]
pub struct CollectorSession {
    pub testcase: String,
    pub worker: u32,
    pub events: Vec<CollectorEvent>,
    pub fidelity: Fidelity,
}

impl CollectorSession {
    /// Is this session free of any loss/permission/unsupported signal?
    pub fn clean_assurance_ok(&self) -> bool {
        self.fidelity.is_clean()
    }

    /// The pid of the testcase's root process, taken from the `begin` boundary
    /// when present, else the first `process_create`, else the first event.
    pub fn root_pid(&self) -> Option<u32> {
        use crate::schema::{EventKind, EventPhase};
        self.events
            .iter()
            .find(|e| e.phase == EventPhase::Begin)
            .or_else(|| {
                self.events
                    .iter()
                    .find(|e| e.kind == EventKind::ProcessCreate)
            })
            .or_else(|| self.events.first())
            .map(|e| e.process.pid)
    }

    /// Timestamp of the `end` boundary, if the provider emitted one.
    pub fn end_ts(&self) -> Option<f64> {
        use crate::schema::EventPhase;
        self.events
            .iter()
            .rev()
            .find(|e| e.phase == EventPhase::End)
            .and_then(|e| e.ts)
    }
}

/// The result of reading a whole collector sink: every session plus a count of
/// lines that could not be parsed at all (which is itself a loss signal).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CollectorSessionSet {
    pub sessions: Vec<CollectorSession>,
    pub malformed_lines: u64,
}

impl CollectorSessionSet {
    /// Parse a JSONL sink into grouped sessions. Blank lines are skipped; a line
    /// that fails to parse is counted in `malformed_lines` (never silently
    /// discarded — it degrades the clean assurance).
    pub fn from_jsonl(input: &str) -> Self {
        let mut set = CollectorSessionSet::default();
        for line in input.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<CollectorEvent>(line) {
                Ok(ev) => set.push_event(ev),
                Err(_) => set.malformed_lines += 1,
            }
        }
        for session in &mut set.sessions {
            session.events.sort_by_key(|e| e.seq);
            let mut total = Fidelity::default();
            for ev in &session.events {
                total.merge(&ev.fidelity);
            }
            session.fidelity = total;
        }
        set
    }

    fn push_event(&mut self, ev: CollectorEvent) {
        if let Some(session) = self
            .sessions
            .iter_mut()
            .find(|s| s.testcase == ev.testcase && s.worker == ev.worker)
        {
            session.events.push(ev);
        } else {
            self.sessions.push(CollectorSession {
                testcase: ev.testcase.clone(),
                worker: ev.worker,
                events: vec![ev],
                fidelity: Fidelity::default(),
            });
        }
    }

    /// A clean assurance holds only if nothing was lost at the line level and
    /// every session is itself clean.
    pub fn clean_assurance_ok(&self) -> bool {
        self.malformed_lines == 0
            && self
                .sessions
                .iter()
                .all(CollectorSession::clean_assurance_ok)
    }

    /// Look up one session by key.
    pub fn session(&self, testcase: &str, worker: u32) -> Option<&CollectorSession> {
        self.sessions
            .iter()
            .find(|s| s.testcase == testcase && s.worker == worker)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{EventKind, EventPhase, ProcessIdentity};

    fn ev(testcase: &str, worker: u32, seq: u64, pid: u32) -> CollectorEvent {
        let mut e = CollectorEvent::new(
            testcase,
            worker,
            seq,
            EventPhase::Event,
            EventKind::FileWrite,
        );
        e.process = ProcessIdentity {
            pid,
            ..Default::default()
        };
        e
    }

    #[test]
    fn session_groups_by_testcase_and_worker() {
        let mut lines = String::new();
        lines.push_str(&ev("A", 0, 1, 10).to_jsonl_line());
        lines.push('\n');
        lines.push_str(&ev("A", 1, 1, 20).to_jsonl_line());
        lines.push('\n');
        lines.push_str(&ev("B", 0, 1, 30).to_jsonl_line());
        lines.push('\n');

        let set = CollectorSessionSet::from_jsonl(&lines);
        assert_eq!(set.sessions.len(), 3);
        assert!(set.session("A", 0).is_some());
        assert!(set.session("A", 1).is_some());
        assert!(set.session("B", 0).is_some());
    }

    #[test]
    fn session_preserves_seq_order() {
        // Feed lines out of order; reader must restore seq order.
        let mut lines = String::new();
        for seq in [3u64, 1, 2, 0] {
            lines.push_str(&ev("A", 0, seq, 10).to_jsonl_line());
            lines.push('\n');
        }
        let set = CollectorSessionSet::from_jsonl(&lines);
        let session = set.session("A", 0).unwrap();
        let seqs: Vec<u64> = session.events.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3]);
    }

    #[test]
    fn overlapping_worker_trees_stay_isolated() {
        // Same testcase, two workers, *overlapping* pids (both use pid 1000/1001).
        let mut lines = String::new();
        // interleave the two workers' lines on the wire
        lines.push_str(&ev("A", 0, 1, 1000).to_jsonl_line());
        lines.push('\n');
        lines.push_str(&ev("A", 1, 1, 1000).to_jsonl_line());
        lines.push('\n');
        lines.push_str(&ev("A", 0, 2, 1001).to_jsonl_line());
        lines.push('\n');
        lines.push_str(&ev("A", 1, 2, 1001).to_jsonl_line());
        lines.push('\n');

        let set = CollectorSessionSet::from_jsonl(&lines);
        let w0 = set.session("A", 0).unwrap();
        let w1 = set.session("A", 1).unwrap();
        assert_eq!(w0.events.len(), 2);
        assert_eq!(w1.events.len(), 2);
        // Each session sees only its own worker's events, despite pid overlap.
        assert!(w0.events.iter().all(|e| e.worker == 0));
        assert!(w1.events.iter().all(|e| e.worker == 1));
    }

    #[test]
    fn malformed_line_is_counted_and_blocks_clean() {
        let mut lines = String::new();
        lines.push_str(&ev("A", 0, 1, 10).to_jsonl_line());
        lines.push('\n');
        lines.push_str("{ this is not json }");
        lines.push('\n');
        let set = CollectorSessionSet::from_jsonl(&lines);
        assert_eq!(set.sessions.len(), 1);
        assert_eq!(set.malformed_lines, 1);
        assert!(
            !set.clean_assurance_ok(),
            "an unparsable line must block a clean assurance"
        );
    }

    #[test]
    fn session_fidelity_is_merged_from_events() {
        let mut e1 = ev("A", 0, 1, 10);
        e1.fidelity.lost = 2;
        let mut e2 = ev("A", 0, 2, 10);
        e2.fidelity.permission_denied = true;
        let lines = format!("{}\n{}\n", e1.to_jsonl_line(), e2.to_jsonl_line());
        let set = CollectorSessionSet::from_jsonl(&lines);
        let session = set.session("A", 0).unwrap();
        assert_eq!(session.fidelity.lost, 2);
        assert!(session.fidelity.permission_denied);
        assert!(!session.clean_assurance_ok());
    }
}
