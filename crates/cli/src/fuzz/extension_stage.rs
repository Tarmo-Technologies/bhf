// SPDX-License-Identifier: Apache-2.0

//! The extension stages of the builtin fuzz loop (`bhf fuzz --extension`).
//!
//! An explicitly trusted extension that provides them takes part in the loop
//! itself, not only in the oracle pass after it:
//!
//! - `mutator.mutate` (#314): one in [`EXTENSION_EVERY`] mutated children is
//!   the extension's mutation of the base the loop picked.
//! - `codec.decode` + `codec.encode` (#373): a child is the base decoded to
//!   the extension's structured value, one value of it mutated, and encoded
//!   back, so a framed format keeps its length and checksum fields right.
//!   Decode and encode errors are counted; they are never findings.
//! - `lifecycle.setup` / `reset` / `teardown` (#374): setup runs before the
//!   pass, reset before every case after the first, teardown after the
//!   pass. A setup or reset the extension answers as failed (or unsupported)
//!   stops the campaign with its message: the cases would run on a fixture
//!   it did not prepare. An extension that crashes, times out or answers
//!   garbage is bounded infrastructure, as everywhere else: its stages stop
//!   and the campaign goes on without them.
//!
//! The mutation and codec stages are bounded: at most [`MAX_CALLS`] calls
//! and a quarter of the pass's time budget ([`DEFAULT_BUDGET`] without one).
//! A call that times out, or an extension that stops answering, cuts the
//! stage off for the rest of the pass, and the campaign goes on with the
//! builtin mutations.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use extension_host::{
    capability, AckOutcome, CaseId, CodecOutcome, ExtensionClient, ExtensionManifest, InfraFailure,
    MutateOutcome,
};
use fuzz_engine_builtin::MutationRng;
use serde_json::{json, Value};

/// One in this many mutated children comes from an extension stage.
pub(super) const EXTENSION_EVERY: u64 = 4;

/// The most mutate and codec calls one pass makes.
pub(super) const MAX_CALLS: usize = 1000;

/// The stages' time budget for a pass without `--time`.
pub(super) const DEFAULT_BUDGET: Duration = Duration::from_secs(60);

/// The capabilities the stages use, offered as optional.
const STAGE_CAPS: &[&str] = &[
    capability::MUTATOR_MUTATE,
    capability::CODEC_DECODE,
    capability::CODEC_ENCODE,
    capability::LIFECYCLE_SETUP,
    capability::LIFECYCLE_RESET,
    capability::LIFECYCLE_TEARDOWN,
];

/// The stages of one pass.
pub(super) struct ExtensionStage {
    client: ExtensionClient,
    campaign: String,
    root: PathBuf,
    mutate: bool,
    codec: bool,
    reset: bool,
    teardown: bool,
    budget: Duration,
    spent: Duration,
    calls: usize,
    children: u64,
    cases: usize,
    mutated: usize,
    mutate_declined: usize,
    encoded: usize,
    codec_errors: usize,
    resets: usize,
    cut_off: Option<String>,
}

impl ExtensionStage {
    /// The stages `manifest`'s extension provides, set up with `root` as its
    /// case root. `None` when it provides none of them, or cannot be started
    /// (the oracle pass reports that). A setup the extension answers as failed
    /// is an error.
    pub(super) fn open(
        manifest: &Path,
        campaign: &str,
        root: &Path,
        pass_budget: Option<Duration>,
    ) -> Result<Option<Self>, String> {
        let Ok(loaded) = ExtensionManifest::load(manifest) else {
            return Ok(None);
        };
        let Ok(mut client) =
            ExtensionClient::from_manifest_with_optional(&loaded, manifest, STAGE_CAPS)
        else {
            return Ok(None);
        };
        let mutate = client.supports(capability::MUTATOR_MUTATE);
        let codec =
            client.supports(capability::CODEC_DECODE) && client.supports(capability::CODEC_ENCODE);
        let setup = client.supports(capability::LIFECYCLE_SETUP);
        let reset = client.supports(capability::LIFECYCLE_RESET);
        let teardown = client.supports(capability::LIFECYCLE_TEARDOWN);
        if !(mutate || codec || setup || reset || teardown) {
            return Ok(None);
        }
        if setup {
            let case = CaseId::new(campaign, "ext-stage", "setup");
            if let Err(fault) =
                hook_result("lifecycle.setup", client.lifecycle_setup(&case, Some(root)))?
            {
                bhfeprintln!("bhf fuzz: {fault}; the extension's stages are off for this pass");
                return Ok(None);
            }
        }
        Ok(Some(Self {
            client,
            campaign: campaign.to_owned(),
            root: root.to_path_buf(),
            mutate,
            codec,
            reset,
            teardown,
            budget: pass_budget.map_or(DEFAULT_BUDGET, |budget| budget / 4),
            spent: Duration::ZERO,
            calls: 0,
            children: 0,
            cases: 0,
            mutated: 0,
            mutate_declined: 0,
            encoded: 0,
            codec_errors: 0,
            resets: 0,
            cut_off: None,
        }))
    }

    /// Before each case: `lifecycle.reset` once a case has run. An error stops
    /// the campaign.
    pub(super) fn before_case(&mut self) -> Result<(), String> {
        self.cases += 1;
        if !self.reset || self.cases == 1 {
            return Ok(());
        }
        let case = CaseId::new(&self.campaign, "ext-stage", format!("reset-{}", self.cases));
        match hook_result(
            "lifecycle.reset",
            self.client.lifecycle_reset(&case, &self.root),
        )? {
            Ok(()) => self.resets += 1,
            Err(fault) => {
                self.cut_off = Some(fault);
                (self.mutate, self.codec, self.reset, self.teardown) = (false, false, false, false);
            }
        }
        Ok(())
    }

    /// The next mutated child from an extension stage, made from `base`, or
    /// `None`: the loop makes this child itself. One in [`EXTENSION_EVERY`]
    /// children is the stages', alternating mutation and codec when the
    /// extension provides both, within the stages' bounds.
    pub(super) fn child(&mut self, base: &[u8], rng: &mut MutationRng) -> Option<Vec<u8>> {
        if !(self.mutate || self.codec) || self.cut_off.is_some() {
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
        let turn = self.children / EXTENSION_EVERY;
        let use_codec = self.codec && (!self.mutate || turn.is_multiple_of(2));
        let started = Instant::now();
        let child = if use_codec {
            self.codec_child(base, rng)
        } else {
            self.mutate_child(base, rng)
        };
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

    fn codec_child(&mut self, base: &[u8], rng: &mut MutationRng) -> Option<Vec<u8>> {
        self.calls += 1;
        let case = self.case("codec");
        let decoded = match self.client.decode(&case, base) {
            Ok(CodecOutcome::Decoded(value)) => value,
            Ok(CodecOutcome::Infrastructure(failure)) => {
                self.codec_errors += 1;
                self.cut_off = Some(format!("codec.decode failed: {failure:?}"));
                return None;
            }
            Ok(_) => {
                self.codec_errors += 1;
                return None;
            }
            Err(error) => {
                self.codec_errors += 1;
                self.cut_off = Some(format!("codec.decode failed: {error}"));
                return None;
            }
        };
        let mut value = decoded;
        mutate_value(&mut value, rng);
        match self.client.encode(&case, value) {
            Ok(CodecOutcome::Bytes(bytes)) => {
                self.encoded += 1;
                Some(bytes)
            }
            Ok(CodecOutcome::Infrastructure(failure)) => {
                self.codec_errors += 1;
                self.cut_off = Some(format!("codec.encode failed: {failure:?}"));
                None
            }
            Ok(_) => {
                self.codec_errors += 1;
                None
            }
            Err(error) => {
                self.codec_errors += 1;
                self.cut_off = Some(format!("codec.encode failed: {error}"));
                None
            }
        }
    }

    /// Tear the session down, and what the stages did, for the run summary's
    /// `extension.stages`.
    pub(super) fn finish(mut self) -> Value {
        let teardown = self.teardown.then(|| {
            let case = CaseId::new(&self.campaign, "ext-stage", "teardown");
            matches!(self.client.lifecycle_teardown(&case), Ok(AckOutcome::Ok))
        });
        json!({
            "mutator": self.mutate,
            "codec": self.codec,
            "calls": self.calls,
            "spent_ms": u64::try_from(self.spent.as_millis()).unwrap_or(u64::MAX),
            "budget_ms": u64::try_from(self.budget.as_millis()).unwrap_or(u64::MAX),
            "mutated": self.mutated,
            "mutate_declined": self.mutate_declined,
            "encoded": self.encoded,
            "codec_errors": self.codec_errors,
            "lifecycle": {
                "reset": self.reset,
                "resets": self.resets,
                "teardown": teardown,
            },
            "cut_off": self.cut_off,
        })
    }
}

/// A lifecycle hook's result: `Ok(Ok(()))` on its acknowledgement,
/// `Ok(Err(fault))` when the extension crashed, timed out or answered garbage
/// (its stages stop), and `Err` with the message that stops the campaign when
/// the extension answered that the hook failed.
fn hook_result(
    hook: &str,
    outcome: extension_host::Result<AckOutcome>,
) -> Result<Result<(), String>, String> {
    let detail = |detail: Option<String>| detail.map(|d| format!(": {d}")).unwrap_or_default();
    match outcome {
        Ok(AckOutcome::Ok) => Ok(Ok(())),
        Ok(AckOutcome::Unsupported { detail: d }) => {
            Err(format!("extension {hook} failed: unsupported{}", detail(d)))
        }
        Ok(AckOutcome::Infrastructure(InfraFailure::ExtensionReported { detail: d })) => {
            Err(format!("extension {hook} failed{}", detail(d)))
        }
        Ok(AckOutcome::Infrastructure(failure)) => {
            Ok(Err(format!("extension {hook} failed: {failure:?}")))
        }
        Err(error) => Ok(Err(format!("extension {hook} failed: {error}"))),
    }
}

/// Mutate one value of a decoded structure in place: a number nudged or
/// replaced by a boundary, a string edited (a byte inserted, removed or
/// replaced, or the string doubled), a boolean flipped, or an array element
/// duplicated or removed.
pub(super) fn mutate_value(value: &mut Value, rng: &mut MutationRng) {
    let mut leaves = Vec::new();
    collect_leaves(value, &mut Vec::new(), &mut leaves);
    let Some(pick) = rng.choose_index(leaves.len()) else {
        return;
    };
    let Some(target) = value.pointer_mut(&leaves[pick]) else {
        return;
    };
    match target {
        Value::Bool(flag) => *flag = !*flag,
        Value::Number(number) => *target = mutate_number(number, rng),
        Value::String(text) => mutate_string(text, rng),
        Value::Array(items) => {
            if let Some(at) = rng.choose_index(items.len()) {
                if rng.coin() {
                    let copy = items[at].clone();
                    items.insert(at, copy);
                } else {
                    items.remove(at);
                }
            }
        }
        Value::Null | Value::Object(_) => {}
    }
}

/// JSON pointers to each mutable value: every scalar, and every non-empty
/// array.
fn collect_leaves(value: &Value, path: &mut Vec<String>, out: &mut Vec<String>) {
    let pointer = |path: &[String]| {
        path.iter()
            .map(|part| format!("/{}", part.replace('~', "~0").replace('/', "~1")))
            .collect::<String>()
    };
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                path.push(key.clone());
                collect_leaves(child, path, out);
                path.pop();
            }
        }
        Value::Array(items) => {
            if !items.is_empty() {
                out.push(pointer(path));
            }
            for (index, child) in items.iter().enumerate() {
                path.push(index.to_string());
                collect_leaves(child, path, out);
                path.pop();
            }
        }
        Value::Null => {}
        _ => out.push(pointer(path)),
    }
}

fn mutate_number(number: &serde_json::Number, rng: &mut MutationRng) -> Value {
    const BOUNDARIES: [i64; 8] = [0, 1, -1, 127, 255, 65535, i32::MAX as i64, i64::MIN];
    if let Some(n) = number.as_i64() {
        let next = match rng.next_u8() % 4 {
            0 => n.wrapping_add(1),
            1 => n.wrapping_sub(1),
            2 => n.wrapping_mul(2),
            _ => BOUNDARIES[usize::from(rng.next_u8()) % BOUNDARIES.len()],
        };
        json!(next)
    } else if let Some(n) = number.as_u64() {
        json!(n.wrapping_add(1))
    } else {
        json!(number.as_f64().unwrap_or(0.0) * -1.5)
    }
}

fn mutate_string(text: &mut String, rng: &mut MutationRng) {
    let mut bytes = std::mem::take(text).into_bytes();
    match rng.next_u8() % 4 {
        0 => {
            let at = rng.choose_index(bytes.len() + 1).unwrap_or(0);
            bytes.insert(at, printable(rng));
        }
        1 => {
            if let Some(at) = rng.choose_index(bytes.len()) {
                bytes.remove(at);
            }
        }
        2 => {
            if let Some(at) = rng.choose_index(bytes.len()) {
                bytes[at] = printable(rng);
            }
        }
        _ => {
            let copy = bytes.clone();
            bytes.extend(copy);
        }
    }
    *text = String::from_utf8_lossy(&bytes).into_owned();
}

/// A printable ASCII byte, so an edited string stays valid UTF-8.
fn printable(rng: &mut MutationRng) -> u8 {
    b' ' + rng.next_u8() % 95
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_decoded_value_is_mutated_in_one_place_and_stays_its_shape() {
        let mut rng = MutationRng::new(7);
        let original = json!({ "op": "OPEN", "path": "track", "length": 10, "crc_valid": true });
        let mut changed = 0;
        for _ in 0..64 {
            let mut value = original.clone();
            mutate_value(&mut value, &mut rng);
            let fields = value.as_object().unwrap();
            assert_eq!(
                fields.keys().collect::<Vec<_>>(),
                original.as_object().unwrap().keys().collect::<Vec<_>>()
            );
            let differing = fields
                .iter()
                .filter(|(key, field)| original[key.as_str()] != **field)
                .count();
            assert!(differing <= 1, "{value}");
            changed += differing;
        }
        assert!(changed > 32, "most mutations change a value");
    }

    #[test]
    fn strings_stay_valid_text_and_arrays_change_length() {
        let mut rng = MutationRng::new(3);
        let mut text = "track".to_owned();
        for _ in 0..200 {
            mutate_string(&mut text, &mut rng);
            text.truncate(64);
        }
        assert!(String::from_utf8(text.into_bytes()).is_ok());
        let mut value = json!({ "items": [1] });
        let mut lengths = std::collections::BTreeSet::new();
        for _ in 0..32 {
            let mut copy = value.clone();
            // Only the array (and its one number) can change.
            mutate_value(&mut copy, &mut rng);
            lengths.insert(copy["items"].as_array().unwrap().len());
        }
        assert!(lengths.contains(&0) && lengths.contains(&2), "{lengths:?}");
        value["items"] = json!([]);
        mutate_value(&mut value, &mut rng);
        assert_eq!(value, json!({ "items": [] }), "nothing to mutate");
    }
}
