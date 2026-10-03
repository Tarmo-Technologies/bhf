// SPDX-License-Identifier: Apache-2.0

//! Compose the `lifecycle.*`, `scenario.*`, `mutator.mutate`, `codec.repair`, and
//! `oracle.evaluate` capabilities into one multi-message session.
//!
//! The [`SessionDriver`] owns the *orchestration* (reset the per-case root, pull
//! each message from the extension, optionally mutate + repair it, relay it to the
//! target, feed the response back so the extension can bind a response-derived
//! value into a later message, then let the oracle judge the clean-exit outcome)
//! while the caller owns the *transport* via the [`SessionTarget`] seam. The
//! driver never speaks the target's wire protocol itself — that lives entirely in
//! the out-of-process extension (encode/decode/repair) and in the target — so this
//! does not duplicate any existing transport; a caller can back [`SessionTarget`]
//! with a live socket (e.g. the stateful-session TCP transport) or an in-process
//! toy target.
//!
//! Every extension fault (timeout, crash, oversized/malformed response,
//! unsupported capability, mismatched case identity) stays a bounded
//! infrastructure result recorded on the [`SessionOutcome`]; it never aborts the
//! host and can never become a target finding.

use crate::client::{
    AckOutcome, CodecOutcome, EvaluateOutcome, ExtensionClient, InfraFailure, MutateOutcome,
    ScenarioStep,
};
use crate::envelope::{CaseId, FindingResult};
use crate::{capability, Result};
use std::path::Path;

/// The transport seam: deliver one framed message to the target and return its
/// framed response. The driver treats both as opaque bytes.
pub trait SessionTarget {
    /// Send `message` (the `step`-th message, with an optional diagnostic
    /// `label`) to the target and return the target's response bytes.
    fn exchange(
        &mut self,
        step: u32,
        label: Option<&str>,
        message: &[u8],
    ) -> std::io::Result<Vec<u8>>;
}

/// How a session should be driven.
#[derive(Debug, Clone)]
pub struct SessionOptions {
    /// When `Some(seed)` and the extension provides `mutator.mutate`, each
    /// scenario message is mutated with this seed before being sent.
    pub mutate_seed: Option<u64>,
    /// When `true` and the extension provides `codec.repair`, each (possibly
    /// mutated) message is repaired — its length/checksum recomputed — before
    /// being sent, so a mutation-corrupted frame reaches the target well-formed.
    pub repair: bool,
    /// A hard cap on the number of scenario steps (bounds a buggy extension that
    /// never returns `done`).
    pub max_steps: u32,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            mutate_seed: None,
            repair: false,
            max_steps: 64,
        }
    }
}

/// What happened at one scenario step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStepRecord {
    /// The zero-based step index.
    pub step: u32,
    /// The extension's diagnostic label for the message (e.g. `OPEN`, `WRITE`).
    pub label: Option<String>,
    /// The exact bytes sent to the target (after any mutate + repair).
    pub sent: Vec<u8>,
    /// Whether `mutator.mutate` changed the message.
    pub mutated: bool,
    /// Whether `codec.repair` recomputed the message's computed fields.
    pub repaired: bool,
    /// The target's response bytes.
    pub response: Vec<u8>,
}

/// The result of driving one session.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionOutcome {
    /// The per-step record, in order.
    pub steps: Vec<SessionStepRecord>,
    /// The oracle finding, if a clean-exit semantic violation was detected.
    pub finding: Option<FindingResult>,
    /// The first bounded extension fault, if any (the session stops there; it is
    /// never a target finding).
    pub infrastructure: Option<InfraFailure>,
    /// Whether the oracle actually ran (`false` if the extension did not provide
    /// `oracle.evaluate`).
    pub oracle_ran: bool,
}

impl SessionOutcome {
    /// Whether any step's message was repaired.
    pub fn any_repaired(&self) -> bool {
        self.steps.iter().any(|s| s.repaired)
    }

    /// Whether any step's message was mutated.
    pub fn any_mutated(&self) -> bool {
        self.steps.iter().any(|s| s.mutated)
    }
}

/// Drives one multi-message session end to end over an [`ExtensionClient`].
#[derive(Debug, Clone, Default)]
pub struct SessionDriver {
    options: SessionOptions,
}

impl SessionDriver {
    /// A driver with the given options.
    pub fn new(options: SessionOptions) -> Self {
        Self { options }
    }

    /// Drive one session for `case`: reset the per-case `root`, pull/mutate/repair
    /// each message and relay it to `target`, bind each response, then let the
    /// oracle judge `testcase` (the semantic input, e.g. the OPEN path).
    ///
    /// A hard transport error from the extension client is returned as `Err`; a
    /// *bounded* extension fault is recorded on the returned [`SessionOutcome`]
    /// and never raised.
    pub fn run(
        &self,
        client: &mut ExtensionClient,
        target: &mut dyn SessionTarget,
        case: &CaseId,
        root: &Path,
        testcase: &[u8],
    ) -> Result<SessionOutcome> {
        let mut outcome = SessionOutcome::default();

        // Per-case setup + reset (a fresh root). Skipped if unsupported.
        if client.supports(capability::LIFECYCLE_SETUP)
            && record_ack(client.lifecycle_setup(case, Some(root))?, &mut outcome)
        {
            return Ok(outcome);
        }
        if client.supports(capability::LIFECYCLE_RESET)
            && record_ack(client.lifecycle_reset(case, root)?, &mut outcome)
        {
            return Ok(outcome);
        }

        if client.supports(capability::SCENARIO_NEXT) {
            self.drive_scenario(client, target, case, testcase, &mut outcome)?;
        }

        // The oracle judges the clean-exit outcome (only if nothing faulted).
        if outcome.infrastructure.is_none() && client.supports(capability::ORACLE_EVALUATE) {
            outcome.oracle_ran = true;
            match client.evaluate(case, testcase)? {
                EvaluateOutcome::Finding(finding) => outcome.finding = Some(*finding),
                EvaluateOutcome::Ok | EvaluateOutcome::Reject { .. } => {}
                EvaluateOutcome::Unsupported { .. } => {}
                EvaluateOutcome::Infrastructure(failure) => {
                    outcome.infrastructure.get_or_insert(failure);
                }
            }
        }

        if client.supports(capability::LIFECYCLE_TEARDOWN) {
            // Teardown faults are bounded but never override an earlier one.
            if let AckOutcome::Infrastructure(failure) = client.lifecycle_teardown(case)? {
                outcome.infrastructure.get_or_insert(failure);
            }
        }

        Ok(outcome)
    }

    /// The `scenario.next` → send → `scenario.observe-response` loop.
    fn drive_scenario(
        &self,
        client: &mut ExtensionClient,
        target: &mut dyn SessionTarget,
        case: &CaseId,
        testcase: &[u8],
        outcome: &mut SessionOutcome,
    ) -> Result<()> {
        for step in 0..self.options.max_steps {
            let next = if step == 0 {
                client.scenario_next_seeded(case, step, testcase)?
            } else {
                client.scenario_next(case, step)?
            };
            let message = match next {
                ScenarioStep::Message(message) => message,
                ScenarioStep::Done | ScenarioStep::Reject { .. } => break,
                ScenarioStep::Unsupported { detail } => {
                    outcome
                        .infrastructure
                        .get_or_insert(InfraFailure::ExtensionReported { detail });
                    break;
                }
                ScenarioStep::Infrastructure(failure) => {
                    outcome.infrastructure.get_or_insert(failure);
                    break;
                }
            };

            let label = message.label.clone();
            let mut bytes = message.bytes;
            let mut mutated = false;
            let mut repaired = false;

            // Structure-aware mutation of the message (optional).
            if let Some(seed) = self.options.mutate_seed {
                if client.supports(capability::MUTATOR_MUTATE) {
                    match client.mutate(case, &bytes, seed)? {
                        MutateOutcome::Mutated(m) => {
                            bytes = m;
                            mutated = true;
                        }
                        MutateOutcome::Reject { .. } | MutateOutcome::Unsupported { .. } => {}
                        MutateOutcome::Infrastructure(failure) => {
                            outcome.infrastructure.get_or_insert(failure);
                            break;
                        }
                    }
                }
            }

            // Repair the (possibly mutated) frame's computed fields (optional).
            if self.options.repair && client.supports(capability::CODEC_REPAIR) {
                match client.repair(case, &bytes)? {
                    CodecOutcome::Bytes(b) => {
                        bytes = b;
                        repaired = true;
                    }
                    CodecOutcome::Reject { .. } | CodecOutcome::Unsupported { .. } => {}
                    CodecOutcome::Decoded(_) => {}
                    CodecOutcome::Infrastructure(failure) => {
                        outcome.infrastructure.get_or_insert(failure);
                        break;
                    }
                }
            }

            let response = match target.exchange(step, label.as_deref(), &bytes) {
                Ok(response) => response,
                Err(err) => {
                    outcome
                        .infrastructure
                        .get_or_insert(InfraFailure::Protocol {
                            detail: format!("session target transport error: {err}"),
                        });
                    break;
                }
            };

            outcome.steps.push(SessionStepRecord {
                step,
                label,
                sent: bytes,
                mutated,
                repaired,
                response: response.clone(),
            });

            // Bind the response so a later message can use a response-derived value.
            if client.supports(capability::SCENARIO_OBSERVE_RESPONSE) {
                if let AckOutcome::Infrastructure(failure) =
                    client.scenario_observe_response(case, step, &response)?
                {
                    outcome.infrastructure.get_or_insert(failure);
                    break;
                }
            }
        }
        Ok(())
    }
}

/// Record a bounded-fault ack onto the outcome. Returns `true` if the caller
/// should stop (a fault was recorded).
fn record_ack(ack: AckOutcome, outcome: &mut SessionOutcome) -> bool {
    match ack {
        AckOutcome::Ok => false,
        AckOutcome::Unsupported { detail } => {
            outcome
                .infrastructure
                .get_or_insert(InfraFailure::ExtensionReported { detail });
            true
        }
        AckOutcome::Infrastructure(failure) => {
            outcome.infrastructure.get_or_insert(failure);
            true
        }
    }
}
