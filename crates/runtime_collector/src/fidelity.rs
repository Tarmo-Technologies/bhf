// SPDX-License-Identifier: Apache-2.0

//! Fidelity / loss accounting.
//!
//! The collector contract must never let a degraded observation masquerade as a
//! clean one. Every [`Fidelity`] signal — dropped events, platform-unsupported
//! fields, or a permission denial — propagates into a session total and blocks
//! any "the target did nothing dangerous" assurance. A host that wants to claim
//! a clean run has to prove it saw everything.

use crate::schema::Fidelity;

impl Fidelity {
    /// Fold another fidelity record into this running total. Losses add,
    /// permission denial is sticky, and unsupported-field names are unioned.
    pub fn merge(&mut self, other: &Fidelity) {
        self.lost = self.lost.saturating_add(other.lost);
        self.permission_denied |= other.permission_denied;
        for field in &other.unsupported_fields {
            if !self.unsupported_fields.contains(field) {
                self.unsupported_fields.push(field.clone());
            }
        }
    }

    /// True only when nothing was lost, denied, or unsupported.
    pub fn is_clean(&self) -> bool {
        self.lost == 0 && !self.permission_denied && self.unsupported_fields.is_empty()
    }

    /// True when any loss/denial/unsupported signal is present.
    pub fn is_degraded(&self) -> bool {
        !self.is_clean()
    }

    /// A short, human-readable reason the observation is degraded, if it is.
    pub fn degraded_reason(&self) -> Option<String> {
        if self.is_clean() {
            return None;
        }
        let mut parts = Vec::new();
        if self.lost > 0 {
            parts.push(format!("{} event(s) lost", self.lost));
        }
        if self.permission_denied {
            parts.push("permission denied".to_owned());
        }
        if !self.unsupported_fields.is_empty() {
            parts.push(format!(
                "unsupported field(s): {}",
                self.unsupported_fields.join(", ")
            ));
        }
        Some(parts.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_session_allows_clean() {
        let f = Fidelity::default();
        assert!(f.is_clean());
        assert!(!f.is_degraded());
        assert_eq!(f.degraded_reason(), None);
    }

    #[test]
    fn lost_events_block_clean_assurance() {
        let f = Fidelity {
            lost: 3,
            ..Default::default()
        };
        assert!(!f.is_clean(), "dropped events must block a clean claim");
        assert!(f.degraded_reason().unwrap().contains("3 event(s) lost"));
    }

    #[test]
    fn permission_denied_blocks_clean() {
        let f = Fidelity {
            permission_denied: true,
            ..Default::default()
        };
        assert!(!f.is_clean());
        assert!(f.degraded_reason().unwrap().contains("permission denied"));
    }

    #[test]
    fn unsupported_fields_recorded_not_dropped() {
        let f = Fidelity {
            unsupported_fields: vec!["process.token".to_owned()],
            ..Default::default()
        };
        assert!(!f.is_clean());
        assert!(f.degraded_reason().unwrap().contains("process.token"));
    }

    #[test]
    fn merge_accumulates_and_unions() {
        let mut total = Fidelity::default();
        total.merge(&Fidelity {
            lost: 1,
            unsupported_fields: vec!["a".into()],
            permission_denied: false,
        });
        total.merge(&Fidelity {
            lost: 2,
            unsupported_fields: vec!["a".into(), "b".into()],
            permission_denied: true,
        });
        assert_eq!(total.lost, 3);
        assert!(total.permission_denied);
        assert_eq!(
            total.unsupported_fields,
            vec!["a".to_owned(), "b".to_owned()]
        );
    }
}
