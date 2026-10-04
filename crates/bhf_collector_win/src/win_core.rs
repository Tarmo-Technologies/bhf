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

// --- Native ETW session-lifecycle policy (pure, Linux-tested) ---------------
//
// The native consumer in `crate::etw` runs its OWN uniquely-named ETW
// system-logger session and may stop ONLY a session it created. All of that
// ownership logic lives here, OS-free, so it is unit-tested on Linux; the native
// code maps `StartTraceW`/`ControlTraceW` status codes onto these types and acts
// on the decision, holding no policy of its own (#77).

/// Maximum number of distinct BHF-owned session names tried before degrading, so
/// a name-collision storm can never spawn an unbounded number of sessions (one
/// per testcase would leak resources and exhaust the 8 system-logger slots).
pub const MAX_SESSION_NAME_ATTEMPTS: u32 = 4;

/// The BHF-owned private ETW session name for this process and instance. Always a
/// descriptive, BHF-scoped name — never `KERNEL_LOGGER_NAME` — so the collector
/// can only ever control a session it started, never the global NT Kernel Logger
/// or another application's session.
pub fn owned_session_name(pid: u32, instance: u64) -> String {
    format!("BHF-Collector-{pid}-{instance}")
}

/// Platform-neutral outcome of one `StartTraceW` attempt on a BHF-owned name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStartStatus {
    /// `ERROR_SUCCESS`: the session was created and is owned by this process.
    Started,
    /// `ERROR_ALREADY_EXISTS`: a session with this name already exists. BHF does
    /// not own it, so it is never stopped — a fresh unique name is tried instead.
    AlreadyExists,
    /// `ERROR_ACCESS_DENIED`: the context lacks the rights to start a session.
    AccessDenied,
    /// Any other Win32 status code.
    Other(u32),
}

/// Why the collector recorded a degraded (non-clean) observation because it could
/// not acquire its own session. Each reason routes to a fidelity diagnostic —
/// never an abort of the fuzz run and never a clean-assurance claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionDegradeReason {
    /// Starting a session needs rights the current context did not have.
    PermissionDenied,
    /// Every attempted BHF-owned name was already taken.
    NameCollisionExhausted,
    /// Another Win32 failure (carries the status code for diagnostics).
    Other(u32),
}

impl SessionDegradeReason {
    /// The `fidelity.unsupported_fields` diagnostic string for this reason.
    pub fn diagnostic(&self) -> String {
        match self {
            SessionDegradeReason::PermissionDenied => "etw.session_start_access_denied".to_owned(),
            SessionDegradeReason::NameCollisionExhausted => {
                "etw.session_name_collision_exhausted".to_owned()
            }
            SessionDegradeReason::Other(code) => format!("etw.session_start_status={code}"),
        }
    }
}

/// What the consumer should do after one `StartTraceW` attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStartDecision {
    /// The session started and is owned; consume it, then stop via its handle.
    Proceed,
    /// The name collided; retry under a fresh unique name (attempts remain).
    RetryWithNewName,
    /// Give up and record a degraded observation; stop nothing.
    Degrade(SessionDegradeReason),
}

/// The whole session-acquisition policy. `attempt` is the zero-based retry index.
///
/// An `AlreadyExists` collision never authorizes a stop: while attempts remain it
/// asks for a fresh unique name, and once they are exhausted it degrades — the
/// colliding (unowned) session is left running in either case. Only `Proceed`
/// yields an owned session, and only an owned session is ever stopped (see
/// [`SessionStopTarget`]).
pub fn decide_session_start(status: SessionStartStatus, attempt: u32) -> SessionStartDecision {
    match status {
        SessionStartStatus::Started => SessionStartDecision::Proceed,
        SessionStartStatus::AccessDenied => {
            SessionStartDecision::Degrade(SessionDegradeReason::PermissionDenied)
        }
        SessionStartStatus::Other(code) => {
            SessionStartDecision::Degrade(SessionDegradeReason::Other(code))
        }
        SessionStartStatus::AlreadyExists => {
            if attempt + 1 < MAX_SESSION_NAME_ATTEMPTS {
                SessionStartDecision::RetryWithNewName
            } else {
                SessionStartDecision::Degrade(SessionDegradeReason::NameCollisionExhausted)
            }
        }
    }
}

/// The only thing teardown may ever stop: a session this process started and
/// still owns, identified by the control handle `StartTraceW` returned. There is
/// deliberately no by-name variant — the collector cannot even express stopping a
/// session it did not create, which is the #77 invariant enforced in the types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStopTarget {
    OwnedHandle(u64),
}

/// The stop plan for a session the collector owns (its `StartTraceW` control
/// handle). Teardown issues `ControlTraceW(EVENT_TRACE_CONTROL_STOP)` against this
/// handle — never a global or otherwise unowned session name.
pub fn stop_plan_for_owned(control_handle: u64) -> SessionStopTarget {
    SessionStopTarget::OwnedHandle(control_handle)
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
    fn owned_session_name_is_bhf_scoped_not_the_nt_kernel_logger() {
        let name = owned_session_name(4242, 7);
        assert!(name.starts_with("BHF-Collector-"), "name: {name}");
        assert!(name.contains("4242"), "carries the pid: {name}");
        assert_ne!(name, "NT Kernel Logger", "never the global kernel logger");
        // Distinct instances yield distinct names so a retry (or a concurrent
        // worker) never reuses a name that is already taken.
        assert_ne!(owned_session_name(4242, 0), owned_session_name(4242, 1));
        assert_ne!(owned_session_name(1, 0), owned_session_name(2, 0));
    }

    #[test]
    fn start_success_is_the_only_outcome_that_yields_a_stoppable_session() {
        assert_eq!(
            decide_session_start(SessionStartStatus::Started, 0),
            SessionStartDecision::Proceed
        );
        // Teardown stops strictly via the owned handle StartTraceW returned; the
        // stop target has no by-name variant, so an unowned session is unstoppable.
        assert_eq!(
            stop_plan_for_owned(0xDEAD_BEEF),
            SessionStopTarget::OwnedHandle(0xDEAD_BEEF)
        );
    }

    #[test]
    fn already_exists_collision_never_stops_the_unowned_session() {
        // Collision on a BHF-owned name: BHF did not create the colliding session,
        // so across every attempt the decision is retry-then-degrade — NEVER
        // Proceed, the only outcome that would yield an owned handle (and thus any
        // stop at all). This is the #77 "do not stop another app's session" proof.
        for attempt in 0..MAX_SESSION_NAME_ATTEMPTS {
            let decision = decide_session_start(SessionStartStatus::AlreadyExists, attempt);
            assert_ne!(
                decision,
                SessionStartDecision::Proceed,
                "a name collision must never be treated as an owned session (attempt {attempt})"
            );
            if attempt + 1 < MAX_SESSION_NAME_ATTEMPTS {
                assert_eq!(decision, SessionStartDecision::RetryWithNewName);
            } else {
                assert_eq!(
                    decision,
                    SessionStartDecision::Degrade(SessionDegradeReason::NameCollisionExhausted)
                );
            }
        }
    }

    #[test]
    fn collision_retries_are_bounded() {
        // The final attempt degrades rather than retrying, so the number of
        // sessions BHF can create per observation is bounded — no unbounded churn
        // of random sessions, one per testcase.
        let last = decide_session_start(
            SessionStartStatus::AlreadyExists,
            MAX_SESSION_NAME_ATTEMPTS - 1,
        );
        assert_eq!(
            last,
            SessionStartDecision::Degrade(SessionDegradeReason::NameCollisionExhausted)
        );
        // Every earlier attempt retries, so acquisition tries at most
        // MAX_SESSION_NAME_ATTEMPTS names before degrading — a bounded budget.
        let retries = (0..MAX_SESSION_NAME_ATTEMPTS - 1)
            .filter(|a| {
                decide_session_start(SessionStartStatus::AlreadyExists, *a)
                    == SessionStartDecision::RetryWithNewName
            })
            .count();
        assert_eq!(retries as u32, MAX_SESSION_NAME_ATTEMPTS - 1);
    }

    #[test]
    fn access_denied_degrades_to_permission_denied_not_abort() {
        assert_eq!(
            decide_session_start(SessionStartStatus::AccessDenied, 0),
            SessionStartDecision::Degrade(SessionDegradeReason::PermissionDenied)
        );
        // The degrade reason carries an actionable diagnostic, never silence.
        assert!(SessionDegradeReason::PermissionDenied
            .diagnostic()
            .contains("access_denied"));
    }

    #[test]
    fn other_status_degrades_with_the_code_in_the_diagnostic() {
        assert_eq!(
            decide_session_start(SessionStartStatus::Other(1450), 0),
            SessionStartDecision::Degrade(SessionDegradeReason::Other(1450))
        );
        assert!(SessionDegradeReason::Other(1450)
            .diagnostic()
            .contains("1450"));
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
