// SPDX-License-Identifier: Apache-2.0

//! Collector provenance.
//!
//! Every collector-sourced finding has to be auditable: which backend produced
//! it, at what version/hash, which process tree it watched, for how long after
//! exit, which event classes that backend can observe at all, which classes it
//! actually saw fire on this run, and what fidelity limitations applied. The
//! fields below are serialized into the run manifest and each finding so a
//! reviewer can tell a genuine clean run from one the collector simply could not
//! see.
//!
//! `supported_event_classes` and `observed_event_classes` are kept deliberately
//! distinct (AC7): the former is the backend's *declared* coverage (what it can
//! observe at all), the latter is the subset that actually fired this run.
//! Conflating them — reporting only what fired as if it were the backend's
//! coverage — would make a blind-spot audit under-report where the collector is
//! blind, so they never share one field.

use crate::attribute::AttributedSession;
use crate::collector::BackendInfo;
use crate::schema::Fidelity;
use serde::{Deserialize, Serialize};

/// The required provenance fields for a collector run / finding (AC7).
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
    /// 6. The event classes this backend can observe *at all* (its declared
    ///    capability — not the subset that fired this run). Drives blind-spot
    ///    audits: an empty or short list means the backend is blind to the
    ///    classes it omits, regardless of what any single run happened to show.
    pub supported_event_classes: Vec<String>,
    /// 7. The event classes actually observed firing on *this* run (always a
    ///    subset of `supported_event_classes` for a declaring backend). Recorded
    ///    separately so "what the backend can see" is never confused with "what
    ///    it saw this time".
    pub observed_event_classes: Vec<String>,
    /// 8. Fidelity limitations that applied to this run.
    pub fidelity: Fidelity,
}

impl CollectorProvenance {
    /// Build provenance from an attributed session plus the resolved backend.
    ///
    /// `supported_event_classes` is taken from the backend's *declared* coverage
    /// ([`BackendInfo::supported_event_classes`]); `observed_event_classes` is
    /// the set the caller observed firing on this run.
    pub fn from_attributed(
        backend: &BackendInfo,
        attributed: &AttributedSession<'_>,
        observation_window_ms: u64,
        observed_event_classes: Vec<String>,
        fidelity: Fidelity,
    ) -> Self {
        CollectorProvenance {
            backend_name: backend.name.clone(),
            backend_version: backend.version.clone(),
            backend_hash: backend.hash.clone(),
            process_tree_scope: attributed.tree_pids.iter().copied().collect(),
            observation_window_ms,
            supported_event_classes: backend.supported_event_classes.clone(),
            observed_event_classes,
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
        // A backend that can observe five classes...
        let backend = BackendInfo::new("windows-etw", "0.2.34", "deadbeef")
            .with_supported_classes([
                "process_create",
                "shell_execute",
                "file_open",
                "file_write",
                "module_load",
            ]);
        // ...but only two fired on this run.
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
            "observed_event_classes",
            "fidelity",
        ] {
            assert!(
                json.get(field).is_some(),
                "missing provenance field {field}"
            );
        }
        assert_eq!(prov.process_tree_scope, vec![1000, 1001]);

        // AC7: supported = backend-declared coverage (five), observed = fired
        // this run (two). The two must not be conflated.
        assert_eq!(prov.supported_event_classes.len(), 5);
        assert_eq!(
            prov.observed_event_classes,
            vec!["process_create".to_owned(), "module_load".to_owned()]
        );
        assert_ne!(prov.supported_event_classes, prov.observed_event_classes);
        for observed in &prov.observed_event_classes {
            assert!(
                prov.supported_event_classes.contains(observed),
                "an observed class must be within the backend's declared coverage"
            );
        }

        // And it round-trips.
        let back: CollectorProvenance = serde_json::from_value(json).unwrap();
        assert_eq!(prov, back);
    }

    #[test]
    fn supported_classes_come_from_backend_not_from_what_fired() {
        // Regression for AC7: even when NOTHING fired this run, the backend's
        // declared coverage must still be reported — a blind-spot audit cannot
        // conclude a backend is blind just because a single run was quiet.
        let session = sample_session(Fidelity::default());
        let attributed = attribute(&session, 250);
        let backend = BackendInfo::new("windows-etw", "0.2.34", "deadbeef")
            .with_supported_classes(["process_create", "file_open", "module_load"]);
        let prov = CollectorProvenance::from_attributed(
            &backend,
            &attributed,
            250,
            Vec::new(), // nothing observed this run
            Fidelity::default(),
        );
        assert_eq!(
            prov.supported_event_classes,
            vec![
                "process_create".to_owned(),
                "file_open".to_owned(),
                "module_load".to_owned()
            ],
            "supported classes must reflect backend coverage, not this run's hits"
        );
        assert!(prov.observed_event_classes.is_empty());
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
