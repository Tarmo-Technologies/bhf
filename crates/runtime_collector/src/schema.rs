// SPDX-License-Identifier: Apache-2.0

//! Versioned, platform-neutral collector event schema (`bhf.collector-event.v1`).
//!
//! A collector emits **one JSON object per line** (JSONL). Each line is a
//! [`CollectorEvent`]. The vocabulary is a strict superset of the existing
//! runtime-audit stream so a single oracle layer can consume both. Unknown
//! `kind` values are preserved as [`EventKind::Unknown`] rather than dropped so
//! a newer provider never silently loses information when read by an older host.

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Wire identifier for version 1 of the collector event contract.
pub const SCHEMA_ID: &str = "bhf.collector-event.v1";

fn default_schema() -> String {
    SCHEMA_ID.to_owned()
}

/// Testcase lifecycle marker carried on every event.
///
/// A provider brackets a testcase's events with a [`EventPhase::Begin`] and a
/// [`EventPhase::End`]; everything observed in between is [`EventPhase::Event`].
/// The `End` boundary also carries the testcase's exit timestamp, which anchors
/// the bounded post-exit observation window (see [`crate::attribute`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventPhase {
    Begin,
    Event,
    End,
}

/// Normalized event family.
///
/// These families intentionally map onto the generic runtime-oracle event
/// vocabulary (see [`crate::oracle_map`]) so that frontends on different
/// operating systems (Win32 `CreateProcess*`, POSIX `execve`, ...) collapse into
/// one contract. `registry` is an optional family that only some providers
/// emit. An unrecognized wire value round-trips through [`EventKind::Unknown`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    ProcessCreate,
    ShellExecute,
    FileCreate,
    FileOpen,
    FileWrite,
    FileRename,
    FileDelete,
    ModuleLoad,
    Network,
    Registry,
    /// An unrecognized wire value, preserved verbatim.
    Unknown(String),
}

impl EventKind {
    /// Wire string for this kind.
    pub fn as_str(&self) -> &str {
        match self {
            EventKind::ProcessCreate => "process_create",
            EventKind::ShellExecute => "shell_execute",
            EventKind::FileCreate => "file_create",
            EventKind::FileOpen => "file_open",
            EventKind::FileWrite => "file_write",
            EventKind::FileRename => "file_rename",
            EventKind::FileDelete => "file_delete",
            EventKind::ModuleLoad => "module_load",
            EventKind::Network => "network",
            EventKind::Registry => "registry",
            EventKind::Unknown(raw) => raw.as_str(),
        }
    }

    /// Parse a wire string, preserving an unknown value instead of failing.
    pub fn from_wire(s: &str) -> Self {
        match s {
            "process_create" => EventKind::ProcessCreate,
            "shell_execute" => EventKind::ShellExecute,
            "file_create" => EventKind::FileCreate,
            "file_open" => EventKind::FileOpen,
            "file_write" => EventKind::FileWrite,
            "file_rename" => EventKind::FileRename,
            "file_delete" => EventKind::FileDelete,
            "module_load" => EventKind::ModuleLoad,
            "network" => EventKind::Network,
            "registry" => EventKind::Registry,
            other => EventKind::Unknown(other.to_owned()),
        }
    }

    /// True when the kind was recognized by this schema version.
    pub fn is_known(&self) -> bool {
        !matches!(self, EventKind::Unknown(_))
    }

    /// True for the filesystem event families.
    pub fn is_file(&self) -> bool {
        matches!(
            self,
            EventKind::FileCreate
                | EventKind::FileOpen
                | EventKind::FileWrite
                | EventKind::FileRename
                | EventKind::FileDelete
        )
    }
}

impl Serialize for EventKind {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for EventKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KindVisitor;
        impl Visitor<'_> for KindVisitor {
            type Value = EventKind;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a collector event-kind string")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<EventKind, E> {
                Ok(EventKind::from_wire(v))
            }
        }
        deserializer.deserialize_str(KindVisitor)
    }
}

/// Process identity for an event's acting process.
///
/// `ancestor` is the pid of the testcase's root process (the common ancestor
/// that attribution keys on); `parent` is the immediate parent. `user` / `token`
/// / `session` capture the security principal so a provider can distinguish, for
/// example, a privileged child from the testcase's own user context.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ancestor: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<u32>,
}

/// Collection-fidelity metadata.
///
/// A provider that cannot observe everything records *why* here rather than
/// implying a clean run. `lost` counts dropped events, `unsupported_fields`
/// names schema fields the provider could not populate on this platform, and
/// `permission_denied` flags that the provider lacked the rights to observe (for
/// example an ETW session it could not start). See [`crate::fidelity`] for how
/// these feed a refused "clean" assurance.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Fidelity {
    #[serde(default)]
    pub lost: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unsupported_fields: Vec<String>,
    #[serde(default)]
    pub permission_denied: bool,
}

/// A single collector event in the `bhf.collector-event.v1` contract.
///
/// `ts` is a Unix timestamp in fractional seconds; `seq` is a per-stream
/// monotonic counter the session reader uses to restore order even when lines
/// arrive interleaved. `input_derived` / `taint_offset` carry byte-origin taint
/// forward so the oracle layer can distinguish an input-controlled effect from a
/// fixed program constant. `evidence_ref` is an opaque back-reference into the
/// provider's own raw evidence (for example `etw:12345`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CollectorEvent {
    #[serde(default = "default_schema")]
    pub schema: String,
    pub testcase: String,
    pub worker: u32,
    pub seq: u64,
    pub phase: EventPhase,
    #[serde(default)]
    pub process: ProcessIdentity,
    pub kind: EventKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verb: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default)]
    pub input_derived: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taint_offset: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts: Option<f64>,
    #[serde(default)]
    pub fidelity: Fidelity,
}

impl CollectorEvent {
    /// Construct a minimal, schema-stamped event of a given kind.
    pub fn new(
        testcase: impl Into<String>,
        worker: u32,
        seq: u64,
        phase: EventPhase,
        kind: EventKind,
    ) -> Self {
        CollectorEvent {
            schema: default_schema(),
            testcase: testcase.into(),
            worker,
            seq,
            phase,
            process: ProcessIdentity::default(),
            kind,
            path: None,
            args: Vec::new(),
            verb: None,
            address: None,
            input_derived: false,
            taint_offset: None,
            evidence_ref: None,
            ts: None,
            fidelity: Fidelity::default(),
        }
    }

    /// Serialize to exactly one JSONL line (no trailing newline).
    pub fn to_jsonl_line(&self) -> String {
        // The struct is plain data with no map keys that can fail to serialize.
        serde_json::to_string(self).expect("CollectorEvent is always serializable")
    }

    /// True when this event carries confirmed byte-origin taint.
    pub fn is_tainted(&self) -> bool {
        self.input_derived && self.taint_offset.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn representative(kind: EventKind) -> CollectorEvent {
        let mut ev = CollectorEvent::new("tc-7", 2, 12, EventPhase::Event, kind);
        ev.process = ProcessIdentity {
            pid: 1234,
            image: Some("C:\\sandbox\\target.exe".into()),
            parent: Some(1200),
            ancestor: Some(1000),
            user: Some("sandbox-user".into()),
            token: Some("S-1-5-21".into()),
            session: Some(1),
        };
        ev.path = Some("C:\\sandbox\\out.bin".into());
        ev.args = vec!["--flag".into(), "value".into()];
        ev.verb = Some("open".into());
        ev.address = Some("10.0.0.5:8080".into());
        ev.input_derived = true;
        ev.taint_offset = Some(42);
        ev.evidence_ref = Some("etw:12345".into());
        ev.ts = Some(1_696_200_000.123);
        ev
    }

    #[test]
    fn schema_jsonl_round_trips() {
        let kinds = [
            EventKind::ProcessCreate,
            EventKind::ShellExecute,
            EventKind::FileCreate,
            EventKind::FileOpen,
            EventKind::FileWrite,
            EventKind::FileRename,
            EventKind::FileDelete,
            EventKind::ModuleLoad,
            EventKind::Network,
            EventKind::Registry,
        ];
        for kind in kinds {
            let ev = representative(kind.clone());
            let line = ev.to_jsonl_line();
            assert!(
                !line.contains('\n'),
                "a JSONL event must be a single line: {line}"
            );
            let back: CollectorEvent =
                serde_json::from_str(&line).expect("event line must deserialize");
            assert_eq!(ev, back, "round-trip must preserve the event");
            assert_eq!(back.schema, SCHEMA_ID);
            assert_eq!(back.kind, kind);
        }
    }

    #[test]
    fn phase_begin_and_end_round_trip() {
        for phase in [EventPhase::Begin, EventPhase::End] {
            let ev = CollectorEvent::new("tc", 0, 0, phase, EventKind::ProcessCreate);
            let back: CollectorEvent =
                serde_json::from_str(&ev.to_jsonl_line()).expect("phase line deserializes");
            assert_eq!(ev.phase, back.phase);
        }
    }

    #[test]
    fn unknown_kind_is_preserved() {
        let line = r#"{"schema":"bhf.collector-event.v1","testcase":"tc","worker":0,"seq":1,"phase":"event","kind":"mystery_future_kind"}"#;
        let ev: CollectorEvent = serde_json::from_str(line).expect("unknown kind deserializes");
        assert_eq!(
            ev.kind,
            EventKind::Unknown("mystery_future_kind".to_owned())
        );
        assert!(!ev.kind.is_known());
        // And it must round-trip back to the same wire value, not be dropped.
        assert!(ev.to_jsonl_line().contains("mystery_future_kind"));
    }

    #[test]
    fn process_identity_carries_security_principal() {
        let ev = representative(EventKind::ProcessCreate);
        let back: CollectorEvent = serde_json::from_str(&ev.to_jsonl_line()).unwrap();
        assert_eq!(back.process.user.as_deref(), Some("sandbox-user"));
        assert_eq!(back.process.token.as_deref(), Some("S-1-5-21"));
        assert_eq!(back.process.session, Some(1));
        assert_eq!(back.process.ancestor, Some(1000));
        assert_eq!(back.evidence_ref.as_deref(), Some("etw:12345"));
    }

    #[test]
    fn malformed_line_fails_to_deserialize() {
        // Missing the required `testcase`/`phase`/`kind` fields.
        let bad = r#"{"schema":"bhf.collector-event.v1","worker":0}"#;
        assert!(serde_json::from_str::<CollectorEvent>(bad).is_err());
    }
}
