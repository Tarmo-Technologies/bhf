// SPDX-License-Identifier: Apache-2.0
//! `confirmation.level`: how strongly a finding is evidenced. The dynamic rows
//! gate on classification, sanitizer, stubs and confidence (first matching row
//! wins). bhf owns these semantics so importers need not re-derive them.

use crate::model::{ConfirmationLevel, Kind};

#[derive(Debug, Clone, Copy)]
pub struct ConfirmationInput<'a> {
    pub kind: Kind,
    pub classification: Option<&'a str>,
    pub confirmation: Option<&'a str>,
    pub sanitizer: Option<&'a str>,
    pub stubs_used: bool,
    pub confidence: Option<&'a str>,
}

pub fn level(input: &ConfirmationInput<'_>) -> ConfirmationLevel {
    let classification = input.classification.unwrap_or("").to_ascii_lowercase();
    let confirmation = input.confirmation.unwrap_or("").to_ascii_lowercase();
    match input.kind {
        Kind::Sca => return ConfirmationLevel::Advisory,
        Kind::Static => {
            return if matches!(confirmation.as_str(), "fuzz_confirmed" | "fuzz_exercised") {
                ConfirmationLevel::StaticConfirmed
            } else {
                ConfirmationLevel::Static
            }
        }
        _ => {}
    }
    let sanitizer_or_unhandled =
        input.sanitizer.is_some_and(|s| !s.is_empty()) || classification == "unhandled";
    if classification == "capability" {
        return ConfirmationLevel::Capability;
    }
    if classification == "intended_rejection" {
        return ConfirmationLevel::IntendedRejection;
    }
    if input.stubs_used {
        return ConfirmationLevel::CrashLead;
    }
    if classification == "oracle_hit" || confirmation == "runtime" {
        return ConfirmationLevel::RuntimeOracle;
    }
    let low_confidence = input
        .confidence
        .is_some_and(|c| c.eq_ignore_ascii_case("low"));
    if sanitizer_or_unhandled && low_confidence {
        return ConfirmationLevel::CrashLead;
    }
    if sanitizer_or_unhandled {
        return ConfirmationLevel::SanitizerCrash;
    }
    if input.kind == Kind::Differential {
        // A differential divergence is an oracle verdict, not a crash.
        return ConfirmationLevel::RuntimeOracle;
    }
    ConfirmationLevel::CrashLead
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ConfirmationLevel as L, Kind};

    fn input(kind: Kind) -> ConfirmationInput<'static> {
        ConfirmationInput {
            kind,
            classification: None,
            confirmation: None,
            sanitizer: None,
            stubs_used: false,
            confidence: None,
        }
    }

    #[test]
    fn gate_rows_in_order() {
        assert_eq!(
            level(&ConfirmationInput {
                classification: Some("capability"),
                ..input(Kind::Runtime)
            }),
            L::Capability
        );
        assert_eq!(
            level(&ConfirmationInput {
                classification: Some("intended_rejection"),
                ..input(Kind::Fuzz)
            }),
            L::IntendedRejection
        );
        assert_eq!(
            level(&ConfirmationInput {
                sanitizer: Some("asan"),
                stubs_used: true,
                ..input(Kind::Fuzz)
            }),
            L::CrashLead
        );
        assert_eq!(
            level(&ConfirmationInput {
                classification: Some("oracle_hit"),
                ..input(Kind::Fuzz)
            }),
            L::RuntimeOracle
        );
        assert_eq!(
            level(&ConfirmationInput {
                confirmation: Some("runtime"),
                ..input(Kind::Runtime)
            }),
            L::RuntimeOracle
        );
        assert_eq!(
            level(&ConfirmationInput {
                sanitizer: Some("asan"),
                confidence: Some("LOW"),
                ..input(Kind::Fuzz)
            }),
            L::CrashLead
        );
        assert_eq!(
            level(&ConfirmationInput {
                sanitizer: Some("asan"),
                ..input(Kind::Fuzz)
            }),
            L::SanitizerCrash
        );
        assert_eq!(
            level(&ConfirmationInput {
                classification: Some("unhandled"),
                ..input(Kind::Fuzz)
            }),
            L::SanitizerCrash
        );
        assert_eq!(level(&input(Kind::Differential)), L::RuntimeOracle);
        assert_eq!(level(&input(Kind::Binary)), L::CrashLead);
    }

    #[test]
    fn static_and_sca() {
        assert_eq!(level(&input(Kind::Static)), L::Static);
        assert_eq!(
            level(&ConfirmationInput {
                confirmation: Some("fuzz_confirmed"),
                ..input(Kind::Static)
            }),
            L::StaticConfirmed
        );
        assert_eq!(
            level(&ConfirmationInput {
                confirmation: Some("fuzz_exercised"),
                ..input(Kind::Static)
            }),
            L::StaticConfirmed
        );
        assert_eq!(level(&input(Kind::Sca)), L::Advisory);
    }
}
