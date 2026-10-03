// SPDX-License-Identifier: Apache-2.0

//! Collector provenance.
//!
//! Every collector-sourced finding has to be auditable: which backend produced
//! it, at what version/hash, which process tree it watched, for how long after
//! exit, which event classes that backend can observe at all, and what fidelity
//! limitations applied. The seven fields below are serialized into the run
//! manifest and each finding so a reviewer can tell a genuine clean run from one
//! the collector simply could not see.

use crate::attribute::AttributedSession;
use crate::collector::BackendInfo;
use crate::schema::Fidelity;
use serde::{Deserialize, Serialize};

/// The seven required provenance fields for a collector run / finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectorProvenance {
    /// 1. Backend name (for example `windows-etw`, `mock`).
    pub backend_name: String,
    /// 2. Backend version.
    pub backend_version: String,
    /// 3. Backend content/build hash.
    pub backend_hash: String,
    /// 4. The pids of the attributed descendant process tree.
    pub process_tree_scope: Vec<u32>,
    /// 5. The bounded post-exit observation window, in milliseconds.
    pub observation_window_ms: u64,
    /// 6. The event classes this backend can observe.
    pub supported_event_classes: Vec<String>,
    /// 7. Fidelity limitations that applied to this run.
    pub fidelity: Fidelity,
}

impl CollectorProvenance {
    /// Build provenance from an attributed session plus the resolved backend.
    pub fn from_attributed(
        backend: &BackendInfo,
        attributed: &AttributedSession<'_>,
        observation_window_ms: u64,
        supported_event_classes: Vec<String>,
        fidelity: Fidelity,
    ) -> Self {
        CollectorProvenance {
            backend_name: backend.name.clone(),
            backend_version: backend.version.clone(),
            backend_hash: backend.hash.clone(),
            process_tree_scope: attributed.tree_pids.iter().copied().collect(),
            observation_window_ms,
            supported_event_classes,
            fidelity,
        }
    }

    /// A clean assurance can only be claimed when no fidelity limitation applied.
    pub fn clean_assurance_ok(&self) -> bool {
        self.fidelity.is_clean()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribute::attribute;
    use crate::schema::{CollectorEvent, EventKind, EventPhase, ProcessIdentity};
    use crate::session::CollectorSession;

    fn sample_session(fidelity: Fidelity) -> CollectorSession {
        let mut begin =
            CollectorEvent::new("tc", 0, 0, EventPhase::Begin, EventKind::ProcessCreate);
        begin.process = ProcessIdentity {
            pid: 1000,
            ..Default::default()
        };
        begin.ts = Some(100.0);
        let mut child =
            CollectorEvent::new("tc", 0, 1, EventPhase::Event, EventKind::ProcessCreate);
        child.process = ProcessIdentity {
            pid: 1001,
            parent: Some(1000),
            ..Default::default()
        };
        child.ts = Some(100.5);
        CollectorSession {
            testcase: "tc".into(),
            worker: 0,
            events: vec![begin, child],
            fidelity,
        }
    }

    #[test]
    fn collector_provenance_serializes_all_fields() {
        let session = sample_session(Fidelity::default());
        let attributed = attribute(&session, 250);
        let backend = BackendInfo::new("windows-etw", "0.2.34", "deadbeef");
        let prov = CollectorProvenance::from_attributed(
            &backend,
            &attributed,
            250,
            vec!["process_create".into(), "module_load".into()],
            Fidelity::default(),
        );

        let json: serde_json::Value = serde_json::to_value(&prov).unwrap();
        for field in [
            "backend_name",
            "backend_version",
            "backend_hash",
            "process_tree_scope",
            "observation_window_ms",
            "supported_event_classes",
            "fidelity",
        ] {
            assert!(
                json.get(field).is_some(),
                "missing provenance field {field}"
            );
        }
        assert_eq!(prov.process_tree_scope, vec![1000, 1001]);

        // And it round-trips.
        let back: CollectorProvenance = serde_json::from_value(json).unwrap();
        assert_eq!(prov, back);
    }

    #[test]
    fn fidelity_limits_block_clean_claim() {
        let session = sample_session(Fidelity::default());
        let attributed = attribute(&session, 250);
        let backend = BackendInfo::new("mock", "1", "");

        let clean = CollectorProvenance::from_attributed(
            &backend,
            &attributed,
            250,
            vec!["process_create".into()],
            Fidelity::default(),
        );
        assert!(clean.clean_assurance_ok());

        let degraded = CollectorProvenance::from_attributed(
            &backend,
            &attributed,
            250,
            vec!["process_create".into()],
            Fidelity {
                lost: 2,
                permission_denied: true,
                ..Default::default()
            },
        );
        assert!(
            !degraded.clean_assurance_ok(),
            "lost events / permission denial must refuse a clean claim"
        );
    }
}
