// SPDX-License-Identifier: Apache-2.0

//! Field-value and sequence-structure mutation, each gated so a mutant is
//! always a legal, re-encodable session.
//!
//! * **Field mutation** ([`mutate_fields`], [`mutate_field_value`]) edits the
//!   concrete value of a data field within its declared type bounds (an integer
//!   never overflows its width, a bounded-bytes field never exceeds its `max`,
//!   an enum only ever holds a declared symbol). Computed and reference fields
//!   are never touched directly — they are recomputed / re-resolved by the
//!   encode (repair) pass.
//! * **Sequence mutation** ([`mutate_sequence`] and the targeted
//!   insert/delete/replace/reorder operations) edits the message list, but only
//!   where the profile's [`ProtocolStateGraph`] permits: a produced mutant is
//!   always a legal state path and never strands a reference consumer, and a
//!   growth past the message cap fails with [`MutateError::TooManyMessages`].
//!
//! Every structural mutation is followed by a repair at encode time, so the
//! derived fields stay valid and the bindings stay resolvable.
//!
//! [`ProtocolStateGraph`]: ada_state_machine::adapter::ProtocolStateGraph

use ada_state_machine::adapter::StateId;
use fuzz_engine_builtin::MutationRng;

use crate::model::{DataSpec, FieldRole, FieldValue, ProtocolModel};
use crate::testcase::{MessageInstance, SessionTestcase};

/// Mutate the value of one randomly chosen data field of the testcase, within
/// the field's type bounds. `dictionary` supplies byte tokens that may be
/// spliced into bytes-typed fields (e.g. a traversal token). The sequence
/// structure is unchanged.
pub fn mutate_fields(
    testcase: &SessionTestcase,
    model: &ProtocolModel,
    rng: &mut MutationRng,
    dictionary: &[Vec<u8>],
) -> SessionTestcase {
    // Collect all (message index, field name) pairs that are mutable data.
    let mut targets: Vec<(usize, String)> = Vec::new();
    for (mi, instance) in testcase.messages.iter().enumerate() {
        let Some(compiled) = model.message(&instance.message) else {
            continue;
        };
        for assignment in &instance.fields {
            if let Some(field) = compiled.data_field(&assignment.name) {
                if let FieldRole::Data(_) = field.role {
                    targets.push((mi, field.name.clone()));
                }
            }
        }
    }

    let mut out = testcase.clone();
    let Some(index) = rng.choose_index(targets.len()) else {
        return out;
    };
    let (mi, field_name) = targets[index].clone();

    // Resolve the field's data spec for bounds.
    let spec = model
        .message(&out.messages[mi].message)
        .and_then(|m| m.data_field(&field_name))
        .and_then(|f| match &f.role {
            FieldRole::Data(spec) => Some(spec.clone()),
            _ => None,
        });
    let Some(spec) = spec else {
        return out;
    };

    if let Some(current) = out.messages[mi].get(&field_name).cloned() {
        let mutated = mutate_field_value(&spec, &current, rng, dictionary);
        out.messages[mi].set(&field_name, mutated);
    }
    out
}

/// Mutate a single field value within its type bounds. Pure and deterministic
/// given `rng`'s state.
pub fn mutate_field_value(
    spec: &DataSpec,
    value: &FieldValue,
    rng: &mut MutationRng,
    dictionary: &[Vec<u8>],
) -> FieldValue {
    match spec {
        DataSpec::Bytes { max } => FieldValue::Bytes {
            value: mutate_bytes(value_bytes(value), *max, rng, dictionary),
        },
        DataSpec::Tlv { .. } => FieldValue::Tlv {
            value: mutate_bytes(value_bytes(value), None, rng, dictionary),
        },
        DataSpec::Int { width, .. } => FieldValue::Int {
            value: rng.next_u64() & width_mask(*width),
        },
        DataSpec::Enum { variants, .. } => {
            let symbols: Vec<&String> = variants.keys().collect();
            let symbol = rng
                .choose_index(symbols.len())
                .map(|i| symbols[i].clone())
                .unwrap_or_else(|| match value {
                    FieldValue::Enum { symbol } => symbol.clone(),
                    _ => String::new(),
                });
            FieldValue::Enum { symbol }
        }
    }
}

fn value_bytes(value: &FieldValue) -> Vec<u8> {
    match value {
        FieldValue::Bytes { value } | FieldValue::Tlv { value } => value.clone(),
        _ => Vec::new(),
    }
}

fn mutate_bytes(
    mut bytes: Vec<u8>,
    max: Option<usize>,
    rng: &mut MutationRng,
    dictionary: &[Vec<u8>],
) -> Vec<u8> {
    // Five operations: splice a dictionary token, flip, append, pop, replace.
    let op = rng.next_u64() % 5;
    match op {
        0 if !dictionary.is_empty() => {
            if let Some(i) = rng.choose_index(dictionary.len()) {
                let token = &dictionary[i];
                let at = rng.choose_index(bytes.len() + 1).unwrap_or(0);
                bytes.splice(at..at, token.iter().copied());
            }
        }
        1 if !bytes.is_empty() => {
            if let Some(i) = rng.choose_index(bytes.len()) {
                bytes[i] ^= rng.next_u8();
            }
        }
        2 => bytes.push(rng.next_u8()),
        3 if !bytes.is_empty() => {
            bytes.pop();
        }
        _ => {
            if let Some(i) = rng.choose_index(bytes.len()) {
                bytes[i] = rng.next_u8();
            } else {
                bytes.push(rng.next_u8());
            }
        }
    }
    if let Some(max) = max {
        bytes.truncate(max);
    }
    bytes
}

fn width_mask(width: fuzz_engine_builtin::IntWidth) -> u64 {
    match width {
        fuzz_engine_builtin::IntWidth::U8 => 0xFF,
        fuzz_engine_builtin::IntWidth::U16 => 0xFFFF,
        fuzz_engine_builtin::IntWidth::U32 => 0xFFFF_FFFF,
    }
}

/// Apply one random, graph-legal structural mutation. If the chosen edit would
/// be illegal or exceed the cap, the testcase is returned unchanged — a mutant
/// is never an illegal path.
pub fn mutate_sequence(
    testcase: &SessionTestcase,
    model: &ProtocolModel,
    rng: &mut MutationRng,
    max_messages: usize,
) -> SessionTestcase {
    let names = testcase.message_names();
    let Some(states) = state_ids(model, &names) else {
        return testcase.clone();
    };
    let len = testcase.messages.len();
    let graph = model.graph();

    let result = match rng.next_u64() % 4 {
        0 => {
            // insert a message legal in the state at the chosen position.
            let pos = rng.choose_index(len + 1).unwrap_or(0);
            let state = states[pos];
            let entries = graph.open_entries(state);
            match rng.choose_index(entries.len()) {
                Some(i) => insert_message(testcase, model, pos, &entries[i], max_messages),
                None => return testcase.clone(),
            }
        }
        1 if len > 0 => {
            let pos = rng.choose_index(len).unwrap();
            delete_message(testcase, model, pos)
        }
        2 if len > 0 => {
            let pos = rng.choose_index(len).unwrap();
            let state = states[pos];
            let entries = graph.open_entries(state);
            match rng.choose_index(entries.len()) {
                Some(i) => replace_message(testcase, model, pos, &entries[i]),
                None => return testcase.clone(),
            }
        }
        3 if len >= 2 => {
            let i = rng.choose_index(len).unwrap();
            let j = rng.choose_index(len).unwrap();
            reorder(testcase, model, i, j)
        }
        _ => return testcase.clone(),
    };

    result.unwrap_or_else(|_| testcase.clone())
}

/// Insert a fresh seed instance of `message` at `index`, if the result is a
/// legal, non-stranding path within the cap.
pub fn insert_message(
    testcase: &SessionTestcase,
    model: &ProtocolModel,
    index: usize,
    message: &str,
    max_messages: usize,
) -> Result<SessionTestcase, MutateError> {
    if testcase.messages.len() + 1 > max_messages {
        return Err(MutateError::TooManyMessages {
            limit: max_messages,
        });
    }
    let compiled = model
        .message(message)
        .ok_or_else(|| MutateError::UnknownMessage {
            name: message.to_owned(),
        })?;
    let mut messages = testcase.messages.clone();
    let at = index.min(messages.len());
    messages.insert(at, MessageInstance::from_seed(compiled));
    finish(testcase, model, messages)
}

/// Delete the message at `index`, if the result stays legal and strands no
/// reference consumer.
pub fn delete_message(
    testcase: &SessionTestcase,
    model: &ProtocolModel,
    index: usize,
) -> Result<SessionTestcase, MutateError> {
    let mut messages = testcase.messages.clone();
    if index >= messages.len() {
        return Err(MutateError::IndexOutOfRange { index });
    }
    messages.remove(index);
    finish(testcase, model, messages)
}

/// Replace the message at `index` with a fresh seed instance of `message`.
pub fn replace_message(
    testcase: &SessionTestcase,
    model: &ProtocolModel,
    index: usize,
    message: &str,
) -> Result<SessionTestcase, MutateError> {
    let compiled = model
        .message(message)
        .ok_or_else(|| MutateError::UnknownMessage {
            name: message.to_owned(),
        })?;
    let mut messages = testcase.messages.clone();
    if index >= messages.len() {
        return Err(MutateError::IndexOutOfRange { index });
    }
    messages[index] = MessageInstance::from_seed(compiled);
    finish(testcase, model, messages)
}

/// Swap the messages at `i` and `j`, if the result stays legal.
pub fn reorder(
    testcase: &SessionTestcase,
    model: &ProtocolModel,
    i: usize,
    j: usize,
) -> Result<SessionTestcase, MutateError> {
    let mut messages = testcase.messages.clone();
    if i >= messages.len() || j >= messages.len() {
        return Err(MutateError::IndexOutOfRange { index: i.max(j) });
    }
    messages.swap(i, j);
    finish(testcase, model, messages)
}

/// Toggle an optional field present/absent (bounded-var-data / optional lever).
pub fn toggle_optional(
    testcase: &SessionTestcase,
    model: &ProtocolModel,
    message_index: usize,
    field: &str,
) -> Result<SessionTestcase, MutateError> {
    let mut out = testcase.clone();
    let instance = out
        .messages
        .get_mut(message_index)
        .ok_or(MutateError::IndexOutOfRange {
            index: message_index,
        })?;
    let compiled = model
        .message(&instance.message)
        .ok_or_else(|| MutateError::UnknownMessage {
            name: instance.message.clone(),
        })?;
    let compiled_field = compiled
        .data_field(field)
        .ok_or_else(|| MutateError::UnknownMessage {
            name: format!("{}.{field}", instance.message),
        })?;
    if !compiled_field.optional {
        return Err(MutateError::NotOptional {
            field: field.to_owned(),
        });
    }
    if instance.get(field).is_some() {
        instance.remove(field);
    } else {
        let seed = compiled
            .seed_values()
            .get(field)
            .cloned()
            .unwrap_or_else(|| default_for(&compiled_field.role));
        instance.set(field, seed);
    }
    Ok(out)
}

fn default_for(role: &FieldRole) -> FieldValue {
    match role {
        FieldRole::Data(DataSpec::Bytes { .. }) => FieldValue::Bytes { value: Vec::new() },
        FieldRole::Data(DataSpec::Int { .. }) => FieldValue::Int { value: 0 },
        FieldRole::Data(DataSpec::Enum { variants, .. }) => FieldValue::Enum {
            symbol: variants.keys().next().cloned().unwrap_or_default(),
        },
        _ => FieldValue::Bytes { value: Vec::new() },
    }
}

/// Validate a candidate message list and assemble the resulting testcase (with
/// a recomputed state path and cleared run-time evidence).
fn finish(
    testcase: &SessionTestcase,
    model: &ProtocolModel,
    messages: Vec<MessageInstance>,
) -> Result<SessionTestcase, MutateError> {
    let names: Vec<&str> = messages.iter().map(|m| m.message.as_str()).collect();
    let state_path = state_path_names(model, &names)?;
    check_refs(model, &messages)?;
    Ok(SessionTestcase {
        profile_sha256: testcase.profile_sha256.clone(),
        messages,
        state_path,
        captured_responses: Vec::new(),
        bindings: crate::binding::Bindings::new(),
    })
}

fn state_ids(model: &ProtocolModel, names: &[&str]) -> Option<Vec<StateId>> {
    let graph = model.graph();
    let mut cur = graph.initial();
    let mut path = vec![cur];
    for &name in names {
        cur = graph.next_state(cur, name)?;
        path.push(cur);
    }
    Some(path)
}

fn state_path_names(model: &ProtocolModel, names: &[&str]) -> Result<Vec<String>, MutateError> {
    let graph = model.graph();
    let mut cur = graph.initial();
    let mut path = vec![graph.state_name(cur).unwrap_or("?").to_owned()];
    for &name in names {
        match graph.next_state(cur, name) {
            Some(next) => {
                cur = next;
                path.push(graph.state_name(cur).unwrap_or("?").to_owned());
            }
            None => {
                return Err(MutateError::IllegalTransition {
                    message: name.to_owned(),
                    state: graph.state_name(cur).unwrap_or("?").to_owned(),
                })
            }
        }
    }
    Ok(path)
}

fn check_refs(model: &ProtocolModel, messages: &[MessageInstance]) -> Result<(), MutateError> {
    for (i, instance) in messages.iter().enumerate() {
        let compiled =
            model
                .message(&instance.message)
                .ok_or_else(|| MutateError::UnknownMessage {
                    name: instance.message.clone(),
                })?;
        for field in &compiled.fields {
            if let FieldRole::Ref { source, .. } = &field.role {
                let producer = source.split('.').next().unwrap_or("");
                let produced = messages[..i].iter().any(|m| m.message == producer);
                if !produced {
                    return Err(MutateError::StrandedRef {
                        message: instance.message.clone(),
                        reference: source.clone(),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Errors from sequence mutation. Every variant names the offender.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MutateError {
    #[error("inserting a message would exceed the {limit}-message session cap")]
    TooManyMessages { limit: usize },
    #[error("message {message:?} is not legal to send from state {state:?}")]
    IllegalTransition { message: String, state: String },
    #[error("message {message:?} references {reference:?} with no prior producer")]
    StrandedRef { message: String, reference: String },
    #[error("no message type named {name:?} in the model")]
    UnknownMessage { name: String },
    #[error("message index {index} is out of range")]
    IndexOutOfRange { index: usize },
    #[error("field {field:?} is not optional")]
    NotOptional { field: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{Bindings, BoundValue};
    use crate::model::{DataSpec, ProtocolModel};
    use crate::profile::Profile;
    use crate::testcase::{encode_message, MessageInstance, SessionTestcase};
    use fuzz_engine_builtin::{Endian, IntWidth};

    const TOY: &str = include_str!("../tests/fixtures/toy-open-write.toml");

    fn toy_model() -> ProtocolModel {
        ProtocolModel::from_profile(&Profile::from_toml(TOY).unwrap()).unwrap()
    }

    fn open_write_seed(model: &ProtocolModel) -> SessionTestcase {
        let messages = vec![
            MessageInstance::from_seed(model.message("OPEN").unwrap()),
            MessageInstance::from_seed(model.message("WRITE").unwrap()),
        ];
        SessionTestcase::from_messages(model.profile_sha256(), messages)
    }

    fn handle_bindings() -> Bindings {
        let mut b = Bindings::new();
        b.bind(
            "OPEN.response.handle",
            BoundValue::Int { value: 0x1234_5678 },
        );
        b
    }

    fn assert_all_encode(model: &ProtocolModel, testcase: &SessionTestcase) {
        let bindings = handle_bindings();
        for instance in &testcase.messages {
            let frame = encode_message(model, instance, &bindings).expect("re-encode clean");
            assert!(frame.verify(), "every mutant frame must verify");
        }
    }

    #[test]
    fn sequence_insert_delete_replace_reorder_only_where_legal() {
        let model = toy_model();
        let seed = open_write_seed(&model);

        // Insert an OPEN at index 1: start->OPEN->opened->OPEN->opened->WRITE.
        let inserted = insert_message(&seed, &model, 1, "OPEN", 64).expect("legal insert");
        assert_eq!(inserted.message_names(), vec!["OPEN", "OPEN", "WRITE"]);
        // The resulting state path is accepted by the graph.
        assert!(state_ids(&model, &inserted.message_names()).is_some());
        assert_all_encode(&model, &inserted);

        // Deleting the only OPEN leaves [WRITE], which is illegal from "start"
        // (and would also strand WRITE's handle ref): the delete is rejected.
        let err = delete_message(&seed, &model, 0).unwrap_err();
        assert_eq!(
            err,
            MutateError::IllegalTransition {
                message: "WRITE".to_owned(),
                state: "start".to_owned(),
            }
        );
        // Deleting the trailing WRITE is legal.
        let deleted = delete_message(&seed, &model, 1).expect("legal delete");
        assert_eq!(deleted.message_names(), vec!["OPEN"]);

        // Replace the WRITE with an OPEN (legal in state "opened").
        let replaced = replace_message(&seed, &model, 1, "OPEN").expect("legal replace");
        assert_eq!(replaced.message_names(), vec!["OPEN", "OPEN"]);
        assert_all_encode(&model, &replaced);

        // Reorder to [WRITE, OPEN]: WRITE is illegal from the start state, so
        // the mutation is rejected (never produced).
        let err = reorder(&seed, &model, 0, 1).unwrap_err();
        assert_eq!(
            err,
            MutateError::IllegalTransition {
                message: "WRITE".to_owned(),
                state: "start".to_owned(),
            }
        );
    }

    #[test]
    fn delete_that_strands_a_reference_is_rejected() {
        // A graph where B is legal from the start state but references A's
        // response, so deleting A keeps the path legal yet strands the ref.
        let src = r#"
schema = "bhf.protocol.v1"
start = "s0"
[[message]]
name = "A"
[[message.field]]
name = "op"
type = "u8"
value = 1
[message.response]
[[message.response.capture]]
name = "x"
type = "u32"
at = 0
[[message]]
name = "B"
[[message.field]]
name = "ref"
type = "u32"
ref = "A.response.x"
[[transition]]
from = "s0"
send = "A"
to = "s1"
[[transition]]
from = "s0"
send = "B"
to = "s1"
[[transition]]
from = "s1"
send = "B"
to = "s1"
"#;
        let model = ProtocolModel::from_profile(&Profile::from_toml(src).unwrap()).unwrap();
        let messages = vec![
            MessageInstance::from_seed(model.message("A").unwrap()),
            MessageInstance::from_seed(model.message("B").unwrap()),
        ];
        let seed = SessionTestcase::from_messages(model.profile_sha256(), messages);
        let err = delete_message(&seed, &model, 0).unwrap_err();
        assert_eq!(
            err,
            MutateError::StrandedRef {
                message: "B".to_owned(),
                reference: "A.response.x".to_owned(),
            }
        );
    }

    #[test]
    fn field_value_mutation_is_type_bounded() {
        let mut rng = MutationRng::new(0xA11CE);

        // u8 integer never exceeds 0xFF.
        let int_spec = DataSpec::Int {
            width: IntWidth::U8,
            endian: Endian::Big,
        };
        let mut value = FieldValue::Int { value: 0 };
        for _ in 0..512 {
            value = mutate_field_value(&int_spec, &value, &mut rng, &[]);
            if let FieldValue::Int { value } = value {
                assert!(value <= 0xFF, "u8 mutation stayed within width");
            }
        }

        // bytes(max=256) never exceeds 256 bytes, even with dictionary splices.
        let bytes_spec = DataSpec::Bytes { max: Some(256) };
        let dictionary = vec![b"..".to_vec(), vec![0u8; 400]];
        let mut value = FieldValue::Bytes {
            value: b"seed".to_vec(),
        };
        for _ in 0..512 {
            value = mutate_field_value(&bytes_spec, &value, &mut rng, &dictionary);
            if let FieldValue::Bytes { value } = &value {
                assert!(value.len() <= 256, "bounded bytes stayed within max");
            }
        }
    }

    #[test]
    fn exceeding_max_messages_is_descriptive() {
        let model = toy_model();
        let seed = open_write_seed(&model);
        let err = insert_message(&seed, &model, 1, "OPEN", 2).unwrap_err();
        assert_eq!(err, MutateError::TooManyMessages { limit: 2 });
    }

    #[test]
    fn oversized_frame_is_descriptive() {
        // A message whose frame exceeds its max_len surfaces binframe's
        // MessageTooLong through encode_message.
        let src = r#"
schema = "bhf.protocol.v1"
start = "s"
[[message]]
name = "BIG"
max_len = 4
[[message.field]]
name = "body"
type = "bytes"
value = "abcdefgh"
"#;
        let model = ProtocolModel::from_profile(&Profile::from_toml(src).unwrap()).unwrap();
        let instance = MessageInstance::from_seed(model.message("BIG").unwrap());
        let err = encode_message(&model, &instance, &Bindings::new()).unwrap_err();
        assert!(
            matches!(
                err,
                crate::model::EncodeError::Frame(
                    fuzz_engine_builtin::BinFrameError::MessageTooLong { .. }
                )
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn toggle_optional_flips_presence() {
        let model = toy_model();
        let seed = open_write_seed(&model);
        // WRITE.flags is optional and present in the seed (value = 0).
        assert!(seed.messages[1].get("flags").is_some());
        let off = toggle_optional(&seed, &model, 1, "flags").expect("toggle off");
        assert!(off.messages[1].get("flags").is_none());
        let on = toggle_optional(&off, &model, 1, "flags").expect("toggle on");
        assert!(on.messages[1].get("flags").is_some());
    }
}
