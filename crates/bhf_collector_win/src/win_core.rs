// SPDX-License-Identifier: Apache-2.0

//! Pure, platform-neutral core of the Windows provider.
//!
//! This module has **no** OS dependency: it accepts synthetic, ETW-shaped
//! records ([`WinRawRecord`]) and produces `bhf.collector-event.v1` events,
//! which is exactly what the `#[cfg(windows)]` ETW consumer feeds it at
//! runtime. Keeping the record→event logic here means the full attribution,
//! normalization, taint and fidelity behavior is unit-tested on Linux CI.
//!
//! Taint model: the core records whether an observed string carries a run of
//! the current fuzz input (a byte-origin match). This is the provider-side
//! signal; the host's cross-execution correlation refines the precise offset.
//! A string that never contains fuzz-input bytes (a fixed program constant)
//! stays `input_derived == false` and can never be taint-confirmed downstream.

use runtime_collector::normalize::normalize_path;
use runtime_collector::schema::{CollectorEvent, EventKind, EventPhase, Fidelity, ProcessIdentity};
use runtime_collector::CollectorContext;
use std::collections::BTreeSet;

/// A filesystem operation family, mirroring the ETW FileIo opcodes the provider
/// subscribes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinFileOp {
    Create,
    Open,
    Write,
    Rename,
    Delete,
}

impl WinFileOp {
    fn event_kind(self) -> EventKind {
        match self {
            WinFileOp::Create => EventKind::FileCreate,
            WinFileOp::Open => EventKind::FileOpen,
            WinFileOp::Write => EventKind::FileWrite,
            WinFileOp::Rename => EventKind::FileRename,
            WinFileOp::Delete => EventKind::FileDelete,
        }
    }
}

/// A decoded ETW record, in the neutral shape the pure core consumes. The live
/// consumer builds these from `EVENT_RECORD`s; tests build them directly.
#[derive(Debug, Clone)]
pub enum WinRawRecord {
    /// `CreateProcess*` / process-start.
    ProcessStart {
        pid: u32,
        parent_pid: u32,
        image: String,
        command_line: String,
        user: Option<String>,
        session: Option<u32>,
        ts: f64,
    },
    /// `ShellExecute*` target/verb/args and the launched child pid.
    ShellExecute {
        pid: u32,
        verb: String,
        file: String,
        params: Vec<String>,
        child_pid: u32,
        ts: f64,
    },
    /// File create/open/write/rename/delete.
    FileOp {
        pid: u32,
        op: WinFileOp,
        path: String,
        ts: f64,
    },
    /// `LoadLibrary*` / image-load.
    ImageLoad { pid: u32, path: String, ts: f64 },
    /// Process exit (used to bound the descendant tree; emits no event).
    ProcessStop { pid: u32, ts: f64 },
}

/// Builds collector events from ETW-shaped records, attributing to the
/// testcase's descendant process tree and emitting the JSONL wire format.
#[derive(Debug, Clone)]
pub struct WinCoreBuilder {
    testcase: String,
    worker: u32,
    root_pid: u32,
    root: String,
    fuzz_input: Vec<u8>,
    tree: BTreeSet<u32>,
    events: Vec<CollectorEvent>,
    seq: u64,
    fidelity: Fidelity,
    finished: bool,
}

impl WinCoreBuilder {
    /// Start observing a testcase rooted at `root_pid`. `fuzz_input` is the
    /// current testcase bytes used for the byte-origin taint check (pass an
    /// empty slice to disable taint confirmation).
    pub fn new(
        ctx: &CollectorContext,
        root_pid: u32,
        root_image: impl Into<String>,
        fuzz_input: impl Into<Vec<u8>>,
    ) -> Self {
        let mut builder = WinCoreBuilder {
            testcase: ctx.testcase.clone(),
            worker: ctx.worker,
            root_pid,
            root: ctx.root.clone(),
            fuzz_input: fuzz_input.into(),
            tree: BTreeSet::new(),
            events: Vec::new(),
            seq: 0,
            fidelity: Fidelity::default(),
            finished: false,
        };
        builder.tree.insert(root_pid);
        let mut begin = builder.event(EventPhase::Begin, EventKind::ProcessCreate);
        begin.process = ProcessIdentity {
            pid: root_pid,
            image: Some(root_image.into()),
            ..Default::default()
        };
        begin.ts = Some(0.0);
        builder.events.push(begin);
        builder
    }

    fn event(&mut self, phase: EventPhase, kind: EventKind) -> CollectorEvent {
        let ev = CollectorEvent::new(&self.testcase, self.worker, self.seq, phase, kind);
        self.seq += 1;
        ev
    }

    /// Byte-origin taint: does the observed string carry a run of fuzz input?
    fn taint(&self, observed: &str) -> (bool, Option<u32>) {
        if self.fuzz_input.is_empty() {
            return (false, None);
        }
        if find_subslice(observed.as_bytes(), &self.fuzz_input).is_some() {
            // The matched run originates at the start of the fuzz input; the
            // host's correlation pass computes the exact offset.
            (true, Some(0))
        } else {
            (false, None)
        }
    }

    fn in_tree(&self, pid: u32) -> bool {
        self.tree.contains(&pid)
    }

    /// Record that the provider could not observe with full fidelity.
    pub fn mark_permission_denied(&mut self, _detail: impl AsRef<str>) {
        self.fidelity.permission_denied = true;
    }

    /// Record a count of dropped/lost events.
    pub fn mark_lost(&mut self, n: u64) {
        self.fidelity.lost = self.fidelity.lost.saturating_add(n);
    }

    /// Record a schema field this platform/configuration could not populate.
    pub fn mark_unsupported(&mut self, field: impl Into<String>) {
        let field = field.into();
        if !self.fidelity.unsupported_fields.contains(&field) {
            self.fidelity.unsupported_fields.push(field);
        }
    }

    /// Ingest one decoded record. Records for processes outside the testcase's
    /// descendant tree are ignored (they are not the testcase's effects).
    pub fn ingest(&mut self, record: WinRawRecord) {
        match record {
            WinRawRecord::ProcessStart {
                pid,
                parent_pid,
                image,
                command_line,
                user,
                session,
                ts,
            } => {
                if !(self.in_tree(parent_pid) || pid == self.root_pid) {
                    return;
                }
                self.tree.insert(pid);
                let command = if command_line.is_empty() {
                    image.clone()
                } else {
                    command_line.clone()
                };
                let (input_derived, taint_offset) = self.taint(&command);
                let mut ev = self.event(EventPhase::Event, EventKind::ProcessCreate);
                ev.process = ProcessIdentity {
                    pid,
                    image: Some(image),
                    parent: Some(parent_pid),
                    ancestor: Some(self.root_pid),
                    user,
                    token: None,
                    session,
                };
                ev.path = ev.process.image.clone();
                ev.args = split_command(&command_line);
                ev.input_derived = input_derived;
                ev.taint_offset = taint_offset;
                ev.ts = Some(ts);
                self.events.push(ev);
            }
            WinRawRecord::ShellExecute {
                pid,
                verb,
                file,
                params,
                child_pid,
                ts,
            } => {
                if !self.in_tree(pid) {
                    return;
                }
                // The launched child joins the descendant tree.
                self.tree.insert(child_pid);
                let observed = format!("{verb} {file} {}", params.join(" "));
                let (input_derived, taint_offset) = self.taint(&observed);
                let mut ev = self.event(EventPhase::Event, EventKind::ShellExecute);
                ev.process = ProcessIdentity {
                    pid,
                    ancestor: Some(self.root_pid),
                    ..Default::default()
                };
                ev.path = Some(file);
                ev.verb = Some(verb);
                ev.args = params;
                ev.input_derived = input_derived;
                ev.taint_offset = taint_offset;
                ev.ts = Some(ts);
                self.events.push(ev);
            }
            WinRawRecord::FileOp { pid, op, path, ts } => {
                if !self.in_tree(pid) {
                    return;
                }
                let (input_derived, taint_offset) = self.taint(&path);
                let resolved = normalize_path(&self.root, &path).normalized;
                let mut ev = self.event(EventPhase::Event, op.event_kind());
                ev.process = ProcessIdentity {
                    pid,
                    ancestor: Some(self.root_pid),
                    ..Default::default()
                };
                ev.path = Some(resolved);
                ev.input_derived = input_derived;
                ev.taint_offset = taint_offset;
                ev.ts = Some(ts);
                self.events.push(ev);
            }
            WinRawRecord::ImageLoad { pid, path, ts } => {
                if !self.in_tree(pid) {
                    return;
                }
                let (input_derived, taint_offset) = self.taint(&path);
                let mut ev = self.event(EventPhase::Event, EventKind::ModuleLoad);
                ev.process = ProcessIdentity {
                    pid,
                    ancestor: Some(self.root_pid),
                    ..Default::default()
                };
                ev.path = Some(path);
                ev.input_derived = input_derived;
                ev.taint_offset = taint_offset;
                ev.ts = Some(ts);
                self.events.push(ev);
            }
            WinRawRecord::ProcessStop { pid, .. } => {
                // Exit of a tracked process does not emit an event but keeps the
                // pid in the tree so late descendant effects remain attributable.
                let _ = pid;
            }
        }
    }

    /// Close the observation with an `end` boundary carrying the merged
    /// fidelity. Idempotent.
    pub fn finish(&mut self, end_ts: f64) {
        if self.finished {
            return;
        }
        let fidelity = self.fidelity.clone();
        let mut end = self.event(EventPhase::End, EventKind::ProcessCreate);
        end.process = ProcessIdentity {
            pid: self.root_pid,
            ..Default::default()
        };
        end.ts = Some(end_ts);
        end.fidelity = fidelity;
        self.events.push(end);
        self.finished = true;
    }

    /// The events collected so far.
    pub fn events(&self) -> &[CollectorEvent] {
        &self.events
    }

    /// The attributed descendant process tree.
    pub fn tree_pids(&self) -> impl Iterator<Item = u32> + '_ {
        self.tree.iter().copied()
    }

    /// Serialize everything collected to the JSONL wire format.
    pub fn to_jsonl(&self) -> String {
        let mut out = String::new();
        for ev in &self.events {
            out.push_str(&ev.to_jsonl_line());
            out.push('\n');
        }
        out
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Split a Windows command line on whitespace, dropping the leading image.
fn split_command(command_line: &str) -> Vec<String> {
    let mut parts = command_line.split_whitespace().map(str::to_owned);
    // Drop argv[0] (the image); keep the arguments.
    let _ = parts.next();
    parts.collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtime_collector::CollectorSessionSet;

    const ROOT: &str = "C:\\sandbox";
    const MARKER: &[u8] = b"FUZZMARKER";

    fn ctx() -> CollectorContext {
        CollectorContext::new("tc-win", 0, ROOT, 250)
    }

    fn builder(fuzz_input: &[u8]) -> WinCoreBuilder {
        WinCoreBuilder::new(&ctx(), 1000, "C:\\sandbox\\target.exe", fuzz_input.to_vec())
    }

    #[test]
    fn builds_collector_jsonl_for_process_create() {
        let mut b = builder(b"");
        b.ingest(WinRawRecord::ProcessStart {
            pid: 1001,
            parent_pid: 1000,
            image: "C:\\Windows\\System32\\cmd.exe".into(),
            command_line: "cmd.exe /c dir".into(),
            user: Some("sandbox".into()),
            session: Some(1),
            ts: 1.0,
        });
        b.finish(2.0);
        let create = b
            .events()
            .iter()
            .find(|e| e.kind == EventKind::ProcessCreate && e.process.pid == 1001)
            .expect("process_create emitted");
        assert_eq!(create.process.parent, Some(1000));
        assert_eq!(create.args, vec!["/c".to_owned(), "dir".to_owned()]);
    }

    #[test]
    fn shell_execute_fields_and_child_join_tree() {
        let mut b = builder(b"");
        b.ingest(WinRawRecord::ShellExecute {
            pid: 1000,
            verb: "runas".into(),
            file: "C:\\sandbox\\payload.exe".into(),
            params: vec!["--go".into()],
            child_pid: 1001,
            ts: 1.0,
        });
        let ev = b
            .events()
            .iter()
            .find(|e| e.kind == EventKind::ShellExecute)
            .unwrap();
        assert_eq!(ev.verb.as_deref(), Some("runas"));
        assert_eq!(ev.path.as_deref(), Some("C:\\sandbox\\payload.exe"));
        assert_eq!(ev.args, vec!["--go".to_owned()]);
        assert!(
            b.tree_pids().any(|p| p == 1001),
            "launched child joins tree"
        );
    }

    #[test]
    fn file_ops_paths_are_resolved() {
        let mut b = builder(b"");
        b.ingest(WinRawRecord::FileOp {
            pid: 1000,
            op: WinFileOp::Write,
            path: "C:\\sandbox\\..\\escaped.bin".into(),
            ts: 1.0,
        });
        let ev = b
            .events()
            .iter()
            .find(|e| e.kind == EventKind::FileWrite)
            .unwrap();
        assert_eq!(ev.path.as_deref(), Some("C:\\escaped.bin"));
    }

    #[test]
    fn module_load_emitted() {
        let mut b = builder(b"");
        b.ingest(WinRawRecord::ImageLoad {
            pid: 1000,
            path: "C:\\sandbox\\plugins\\p.dll".into(),
            ts: 1.0,
        });
        assert!(b.events().iter().any(|e| e.kind == EventKind::ModuleLoad));
    }

    #[test]
    fn descendant_tree_attribution_and_isolation() {
        let mut b = builder(b"");
        // child
        b.ingest(WinRawRecord::ProcessStart {
            pid: 1001,
            parent_pid: 1000,
            image: "a.exe".into(),
            command_line: String::new(),
            user: None,
            session: None,
            ts: 1.0,
        });
        // grandchild
        b.ingest(WinRawRecord::ProcessStart {
            pid: 1002,
            parent_pid: 1001,
            image: "b.exe".into(),
            command_line: String::new(),
            user: None,
            session: None,
            ts: 1.1,
        });
        // unrelated process (parent not in tree)
        b.ingest(WinRawRecord::ProcessStart {
            pid: 5000,
            parent_pid: 4999,
            image: "other.exe".into(),
            command_line: String::new(),
            user: None,
            session: None,
            ts: 1.2,
        });
        let tree: Vec<u32> = b.tree_pids().collect();
        assert!(tree.contains(&1001) && tree.contains(&1002));
        assert!(
            !tree.contains(&5000),
            "unrelated process stays out of the tree"
        );
        // The unrelated record emits no attributed event.
        assert!(b.events().iter().all(|e| e.process.pid != 5000));
    }

    #[test]
    fn controlled_records_are_taint_confirmed_fixed_are_not() {
        // Controlled: the module path carries fuzz-input bytes -> taint-confirmed.
        let mut controlled = builder(MARKER);
        controlled.ingest(WinRawRecord::ImageLoad {
            pid: 1000,
            path: "C:\\Temp\\FUZZMARKER.dll".into(),
            ts: 1.0,
        });
        let ev = controlled
            .events()
            .iter()
            .find(|e| e.kind == EventKind::ModuleLoad)
            .unwrap();
        assert!(
            ev.is_tainted(),
            "a fuzz-controlled module load must be taint-confirmed"
        );

        // Fixed constant: the path never contains fuzz-input bytes.
        let mut fixed = builder(MARKER);
        fixed.ingest(WinRawRecord::ImageLoad {
            pid: 1000,
            path: "C:\\Windows\\System32\\kernel32.dll".into(),
            ts: 1.0,
        });
        let ev = fixed
            .events()
            .iter()
            .find(|e| e.kind == EventKind::ModuleLoad)
            .unwrap();
        assert!(
            !ev.is_tainted(),
            "a fixed constant must never be taint-confirmed"
        );
    }

    #[test]
    fn permission_denied_is_recorded_not_silent() {
        let mut b = builder(b"");
        b.mark_permission_denied("could not start ETW session without rights");
        b.finish(1.0);
        let set = CollectorSessionSet::from_jsonl(&b.to_jsonl());
        let session = set.session("tc-win", 0).unwrap();
        assert!(
            !session.clean_assurance_ok(),
            "permission denial must block a clean assurance, not report nothing"
        );
        assert!(session.fidelity.permission_denied);
    }

    #[test]
    fn jsonl_round_trips_through_session_reader() {
        let mut b = builder(b"");
        b.ingest(WinRawRecord::ProcessStart {
            pid: 1001,
            parent_pid: 1000,
            image: "a.exe".into(),
            command_line: "a.exe x".into(),
            user: None,
            session: None,
            ts: 1.0,
        });
        b.finish(2.0);
        let set = CollectorSessionSet::from_jsonl(&b.to_jsonl());
        assert_eq!(set.sessions.len(), 1);
        assert_eq!(set.malformed_lines, 0);
        let session = set.session("tc-win", 0).unwrap();
        // begin + process_create + end
        assert_eq!(session.events.len(), 3);
    }
}
