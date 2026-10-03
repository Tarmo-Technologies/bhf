// SPDX-License-Identifier: Apache-2.0

//! The structured, multi-message testcase.
//!
//! A [`SessionTestcase`] is a *sequence* of structured [`MessageInstance`]s
//! (each carrying the concrete values of its data fields), plus the state path
//! walked, the raw reply bytes captured per step, and a diagnostic snapshot of
//! the response-derived [`Bindings`]. It serializes to JSON as the `session.json`
//! artifact an importer / vulnerability-management tool reads back.
//!
//! Encoding a message follows the HDF-7 mutate -> repair contract exactly (see
//! [`crate::model::CompiledMessage::build_frame`]): reference fields are
//! resolved from the live bindings and every computed length / checksum / offset
//! is recomputed over the resolved bytes, so the frame always passes the
//! target's integrity gate.

use fuzz_engine_builtin::EncodedMessage;
use serde::{Deserialize, Serialize};

use crate::binding::Bindings;
use crate::model::{CompiledMessage, EncodeError, FieldValue, ProtocolModel};

/// A concrete assignment of a value to a named data field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldAssignment {
    pub name: String,
    pub value: FieldValue,
}

/// One structured message in a session: a message-type name plus the concrete
/// values of the data fields present in this instance. Computed fields and
/// reference fields are not stored — they are recomputed / resolved at encode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageInstance {
    pub message: String,
    pub fields: Vec<FieldAssignment>,
}

impl MessageInstance {
    /// Build an instance from a compiled message's seed values, preserving field
    /// declaration order.
    pub fn from_seed(message: &CompiledMessage) -> Self {
        let seeds = message.seed_values();
        let fields = message
            .fields
            .iter()
            .filter_map(|field| {
                seeds.get(&field.name).map(|value| FieldAssignment {
                    name: field.name.clone(),
                    value: value.clone(),
                })
            })
            .collect();
        Self {
            message: message.name.clone(),
            fields,
        }
    }

    /// The field assignments as a name -> value map (present fields only).
    pub fn values(&self) -> std::collections::BTreeMap<String, FieldValue> {
        self.fields
            .iter()
            .map(|assignment| (assignment.name.clone(), assignment.value.clone()))
            .collect()
    }

    pub fn get(&self, name: &str) -> Option<&FieldValue> {
        self.fields
            .iter()
            .find(|f| f.name == name)
            .map(|f| &f.value)
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut FieldValue> {
        self.fields
            .iter_mut()
            .find(|f| f.name == name)
            .map(|f| &mut f.value)
    }

    /// Set a field's value, inserting it if absent (e.g. toggling an optional
    /// field present).
    pub fn set(&mut self, name: &str, value: FieldValue) {
        if let Some(existing) = self.get_mut(name) {
            *existing = value;
        } else {
            self.fields.push(FieldAssignment {
                name: name.to_owned(),
                value,
            });
        }
    }

    /// Remove a field (e.g. toggling an optional field absent).
    pub fn remove(&mut self, name: &str) {
        self.fields.retain(|f| f.name != name);
    }
}

/// Encode one message instance into frame bytes, resolving references from the
/// live bindings and recomputing every derived field.
pub fn encode_message(
    model: &ProtocolModel,
    instance: &MessageInstance,
    bindings: &Bindings,
) -> Result<EncodedMessage, EncodeError> {
    let compiled = model
        .message(&instance.message)
        .ok_or_else(|| EncodeError::UnknownMessage {
            name: instance.message.clone(),
        })?;
    compiled.build_frame(&instance.values(), bindings)
}

/// A structured, multi-message testcase and the evidence captured when it ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTestcase {
    /// SHA-256 of the profile that produced this testcase.
    pub profile_sha256: String,
    /// The ordered structured messages.
    pub messages: Vec<MessageInstance>,
    /// The state names visited, starting from the initial state.
    pub state_path: Vec<String>,
    /// Raw reply bytes captured per step (diagnostic).
    pub captured_responses: Vec<Vec<u8>>,
    /// A snapshot of the response-derived bindings (diagnostic; replay
    /// re-captures fresh values rather than reusing this).
    pub bindings: Bindings,
}

impl SessionTestcase {
    /// A structure-only testcase (the input to a drive): just the message
    /// sequence, with the run-time evidence empty.
    pub fn from_messages(
        profile_sha256: impl Into<String>,
        messages: Vec<MessageInstance>,
    ) -> Self {
        Self {
            profile_sha256: profile_sha256.into(),
            messages,
            state_path: Vec::new(),
            captured_responses: Vec::new(),
            bindings: Bindings::new(),
        }
    }

    /// The message-type names in order.
    pub fn message_names(&self) -> Vec<&str> {
        self.messages.iter().map(|m| m.message.as_str()).collect()
    }

    /// Serialize to the `session.json` artifact form.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from the `session.json` artifact form.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::BoundValue;
    use crate::model::ProtocolModel;
    use crate::profile::Profile;

    const TOY: &str = include_str!("../tests/fixtures/toy-open-write.toml");

    fn toy_model() -> ProtocolModel {
        ProtocolModel::from_profile(&Profile::from_toml(TOY).unwrap()).unwrap()
    }

    fn write_instance(model: &ProtocolModel) -> MessageInstance {
        MessageInstance::from_seed(model.message("WRITE").unwrap())
    }

    #[test]
    fn encode_write_resolves_handle_ref_and_recomputes_crc() {
        let model = toy_model();
        let mut bindings = Bindings::new();
        bindings.bind(
            "OPEN.response.handle",
            BoundValue::Int { value: 0xDEAD_BEEF },
        );

        let frame = encode_message(&model, &write_instance(&model), &bindings).expect("encode");
        // The handle field holds the bound value, big-endian.
        let handle_span = frame.span("handle").expect("handle span");
        assert_eq!(&frame.bytes()[handle_span], &0xDEAD_BEEFu32.to_be_bytes());
        // The CRC (which covers the handle) was recomputed over the resolved
        // value, so the frame verifies.
        assert!(
            frame.verify(),
            "WRITE must verify after ref resolution + fix-up"
        );
    }

    #[test]
    fn encode_with_unresolved_ref_is_descriptive() {
        let model = toy_model();
        let err = encode_message(&model, &write_instance(&model), &Bindings::new()).unwrap_err();
        assert_eq!(
            err,
            EncodeError::Unresolved {
                field: "handle".to_owned(),
                reference: "OPEN.response.handle".to_owned(),
            }
        );
    }

    #[test]
    fn mutate_then_repair_keeps_frame_valid() {
        let model = toy_model();
        let open = model.message("OPEN").unwrap();
        let mut instance = MessageInstance::from_seed(open);

        // Mutate the path (a longer value): the len prefix and CRC are both
        // stale until the encode (repair) pass recomputes them.
        instance.set(
            "path",
            FieldValue::Bytes {
                value: b"../escaped-and-longer-path".to_vec(),
            },
        );
        let frame = encode_message(&model, &instance, &Bindings::new()).expect("encode");
        assert!(frame.verify(), "re-encoded frame must verify after repair");

        // The recomputed length prefix matches the mutated path length.
        let len_span = frame.span("len").expect("len span");
        let stored = u16::from_be_bytes([
            frame.bytes()[len_span.start],
            frame.bytes()[len_span.start + 1],
        ]);
        assert_eq!(usize::from(stored), b"../escaped-and-longer-path".len());
    }

    #[test]
    fn session_testcase_round_trips_json() {
        let model = toy_model();
        let messages = vec![
            MessageInstance::from_seed(model.message("OPEN").unwrap()),
            write_instance(&model),
        ];
        let mut testcase = SessionTestcase::from_messages(model.profile_sha256(), messages);
        testcase.state_path = vec!["start".into(), "opened".into(), "opened".into()];
        testcase.captured_responses = vec![vec![0, 0, 0, 1], vec![0]];
        testcase
            .bindings
            .bind("OPEN.response.handle", BoundValue::Int { value: 1 });

        let json = testcase.to_json().expect("serialize");
        let restored = SessionTestcase::from_json(&json).expect("deserialize");
        assert_eq!(restored, testcase);
    }

    #[test]
    fn artifact_records_required_evidence() {
        let model = toy_model();
        let messages = vec![
            MessageInstance::from_seed(model.message("OPEN").unwrap()),
            write_instance(&model),
        ];
        let mut testcase = SessionTestcase::from_messages(model.profile_sha256(), messages);
        testcase.state_path = vec!["start".into(), "opened".into(), "opened".into()];
        testcase.captured_responses = vec![vec![0x11, 0x22, 0x33, 0x44], vec![0xEF]];
        testcase.bindings.bind(
            "OPEN.response.handle",
            BoundValue::Int { value: 0x1122_3344 },
        );

        // >= 2 structured messages.
        assert!(testcase.messages.len() >= 2);
        // Non-empty state path.
        assert!(!testcase.state_path.is_empty());
        // Per-step captured response bytes.
        assert_eq!(testcase.captured_responses.len(), 2);
        assert!(!testcase.captured_responses[0].is_empty());
        // A handle binding sourced from OPEN.response.handle.
        assert!(testcase.bindings.contains("OPEN.response.handle"));
        // The profile hash travels with the artifact.
        assert_eq!(testcase.profile_sha256, model.profile_sha256());
    }
}
