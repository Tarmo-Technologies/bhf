// SPDX-License-Identifier: Apache-2.0

//! The extension stages of the builtin fuzz loop (`bhf fuzz --extension`).
//!
//! An explicitly trusted extension that provides them takes part in the loop
//! itself, not only in the oracle pass after it:
//!
//! - `mutator.mutate` (#314): one in [`EXTENSION_EVERY`] mutated children is
//!   the extension's mutation of the base the loop picked.
//!
//! The mutation stage is bounded: at most [`MAX_CALLS`] calls and a quarter
//! of the pass's time budget ([`DEFAULT_BUDGET`] without one). A call that
//! times out, or an extension that stops answering, cuts the stage off for
//! the rest of the pass, and the campaign goes on with the builtin
//! mutations.

use std::path::Path;
use std::time::{Duration, Instant};

use extension_host::{capability, CaseId, ExtensionClient, ExtensionManifest, MutateOutcome};
use fuzz_engine_builtin::MutationRng;
use serde_json::{json, Value};

/// One in this many mutated children comes from an extension stage.
pub(super) const EXTENSION_EVERY: u64 = 4;

/// The most mutate calls one pass makes.
pub(super) const MAX_CALLS: usize = 1000;

/// The stage's time budget for a pass without `--time`.
pub(super) const DEFAULT_BUDGET: Duration = Duration::from_secs(60);

/// The capabilities the stages use, offered as optional.
const STAGE_CAPS: &[&str] = &[capability::MUTATOR_MUTATE];

/// The stages of one pass.
pub(super) struct ExtensionStage {
    client: ExtensionClient,
    campaign: String,
    mutate: bool,
    budget: Duration,
    spent: Duration,
    calls: usize,
    children: u64,
    mutated: usize,
    mutate_declined: usize,
    cut_off: Option<String>,
}

impl ExtensionStage {
    /// The stages `manifest`'s extension provides. `None` when it provides
    /// none of them, or cannot be started (the oracle pass reports that).
    pub(super) fn open(
        manifest: &Path,
        campaign: &str,
        pass_budget: Option<Duration>,
    ) -> Option<Self> {
        let loaded = ExtensionManifest::load(manifest).ok()?;
        let client =
            ExtensionClient::from_manifest_with_optional(&loaded, manifest, STAGE_CAPS).ok()?;
        let mutate = client.supports(capability::MUTATOR_MUTATE);
        if !mutate {
            return None;
        }
        Some(Self {
            client,
            campaign: campaign.to_owned(),
            mutate,
            budget: pass_budget.map_or(DEFAULT_BUDGET, |budget| budget / 4),
            spent: Duration::ZERO,
            calls: 0,
            children: 0,
            mutated: 0,
            mutate_declined: 0,
            cut_off: None,
        })
    }

    /// The next mutated child from the extension's mutation stage, made from
    /// `base`, or `None`: the loop makes this child itself. One in
    /// [`EXTENSION_EVERY`] children is the stage's, within its bounds.
    pub(super) fn child(&mut self, base: &[u8], rng: &mut MutationRng) -> Option<Vec<u8>> {
        if !self.mutate || self.cut_off.is_some() {
            return None;
        }
        self.children += 1;
        if !self.children.is_multiple_of(EXTENSION_EVERY) {
            return None;
        }
        if self.calls >= MAX_CALLS {
            self.cut_off = Some(format!("reached its bound of {MAX_CALLS} calls"));
            return None;
        }
        if self.spent >= self.budget {
            self.cut_off = Some(format!(
                "reached its time bound of {} ms",
                self.budget.as_millis()
            ));
            return None;
        }
        let started = Instant::now();
        let child = self.mutate_child(base, rng);
        self.spent += started.elapsed();
        child
    }

    fn case(&self, stage: &str) -> CaseId {
        CaseId::new(
            &self.campaign,
            "ext-stage",
            format!("{stage}-{}", self.calls),
        )
    }

    fn mutate_child(&mut self, base: &[u8], rng: &mut MutationRng) -> Option<Vec<u8>> {
        self.calls += 1;
        let case = self.case("mutate");
        match self.client.mutate(&case, base, rng.next_u64()) {
            Ok(MutateOutcome::Mutated(bytes)) => {
                self.mutated += 1;
                Some(bytes)
            }
            Ok(MutateOutcome::Reject { .. } | MutateOutcome::Unsupported { .. }) => {
                self.mutate_declined += 1;
                None
            }
            Ok(MutateOutcome::Infrastructure(failure)) => {
                self.cut_off = Some(format!("mutator.mutate failed: {failure:?}"));
                None
            }
            Err(error) => {
                self.cut_off = Some(format!("mutator.mutate failed: {error}"));
                None
            }
        }
    }

    /// What the stages did, for the run summary's `extension.stages`.
    pub(super) fn finish(self) -> Value {
        json!({
            "mutator": self.mutate,
            "calls": self.calls,
            "spent_ms": u64::try_from(self.spent.as_millis()).unwrap_or(u64::MAX),
            "budget_ms": u64::try_from(self.budget.as_millis()).unwrap_or(u64::MAX),
            "mutated": self.mutated,
            "mutate_declined": self.mutate_declined,
            "cut_off": self.cut_off,
        })
    }
}
