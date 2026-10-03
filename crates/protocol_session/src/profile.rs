// SPDX-License-Identifier: Apache-2.0

//! Versioned protocol-profile schema (`bhf.protocol.v1`) and its TOML parser.
//!
//! A profile declares the message types of a response-dependent, multi-message
//! protocol: the typed fields of each message (byte order, width, enums,
//! bounded variable-length data, optional fields), the computed fields a
//! serializer must recompute after any mutation (length / checksum / CRC / TLV
//! length / offset / back-reference), the legal message ordering as a state
//! machine, the response fields a reply exposes, the later-request references
//! back to captured response values, the session setup/teardown/reset, and the
//! response-condition / violation-state oracles that flag a security violation
//! which exits cleanly (no crash).
//!
//! Parsing is total and every rejection names the offender: an unknown schema,
//! a duplicate message name, a dangling response reference, or malformed TOML
//! each return a distinct [`ProfileError`] variant rather than a silent `None`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The only schema version this crate understands.
pub const SCHEMA_V1: &str = "bhf.protocol.v1";

/// Default cap on messages per session when the profile omits `max_messages`.
pub const DEFAULT_MAX_MESSAGES: usize = 64;

/// Declared type of a message field (or a response capture).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    /// Opaque, possibly variable-length bytes (bounded by `max`).
    Bytes,
    /// Unsigned 8-bit integer.
    U8,
    /// Unsigned 16-bit integer.
    U16,
    /// Unsigned 32-bit integer.
    U32,
    /// A symbolic enumeration mapped to an integer code.
    Enum,
    /// A tag-length-value record (its length is computed).
    Tlv,
}

/// Byte order for a multi-byte field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ByteOrder {
    Big,
    Little,
}

/// One declared field of a message.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct FieldDef {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: FieldType,
    #[serde(default)]
    pub endian: Option<ByteOrder>,
    /// Inclusive byte-length bound for a `bytes` field.
    #[serde(default)]
    pub max: Option<usize>,
    /// When true, the field may be present or absent in a given instance.
    #[serde(default)]
    pub optional: bool,
    /// A computed-field spec, e.g. `length(path)`, `crc32(op,len,path)`,
    /// `offset(target)`. Mutually exclusive with `reference`.
    #[serde(default)]
    pub computed: Option<String>,
    /// A back-reference to a captured response value, `MSG.response.FIELD`.
    #[serde(rename = "ref", default)]
    pub reference: Option<String>,
    /// Symbol -> integer code map for an `enum` field.
    #[serde(default)]
    pub variants: Option<BTreeMap<String, u64>>,
    /// Explicit wire width (`u8`/`u16`/`u32`) for an `enum` field. When absent,
    /// the width is inferred from the largest variant code. Set it to make an
    /// enum occupy a field wider than its codes imply, so it does not under-size
    /// and shift the fields that follow it on the wire.
    #[serde(default)]
    pub width: Option<FieldType>,
    /// Tag value for a `tlv` field.
    #[serde(default)]
    pub tag: Option<u64>,
    /// Seed / initial value used when constructing an initial instance.
    #[serde(default)]
    pub value: Option<toml::Value>,
}

/// One response capture: a typed slice of the reply bytes at a fixed offset.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CaptureDef {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: FieldType,
    /// Byte offset of the captured value within the reply.
    pub at: usize,
    #[serde(default)]
    pub endian: Option<ByteOrder>,
    /// Byte length for a `bytes` capture.
    #[serde(default)]
    pub len: Option<usize>,
    /// Symbol -> integer code map for an `enum` capture.
    #[serde(default)]
    pub variants: Option<BTreeMap<String, u64>>,
    /// Explicit wire width (`u8`/`u16`/`u32`) for an `enum` capture. When
    /// absent, the width is inferred from the largest variant code. Set it when
    /// the reply encodes the enum in a field wider than its codes imply, so the
    /// captures that follow it are read at the right offset.
    #[serde(default)]
    pub width: Option<FieldType>,
}

/// The response specification attached to a message.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct ResponseDef {
    #[serde(default, rename = "capture")]
    pub captures: Vec<CaptureDef>,
}

/// One declared message type.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct MessageDef {
    pub name: String,
    /// Upper bound on the encoded frame size (bytes).
    #[serde(default)]
    pub max_len: Option<usize>,
    #[serde(default, rename = "field")]
    pub fields: Vec<FieldDef>,
    #[serde(default)]
    pub response: Option<ResponseDef>,
}

impl MessageDef {
    pub fn field(&self, name: &str) -> Option<&FieldDef> {
        self.fields.iter().find(|f| f.name == name)
    }
}

/// A legal transition: sending `send` while in state `from` moves to state `to`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TransitionDef {
    pub from: String,
    pub send: String,
    pub to: String,
}

/// Session lifecycle hooks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct SessionDef {
    /// Messages to send before the main sequence.
    #[serde(default)]
    pub setup: Vec<String>,
    /// Messages to send after the main sequence.
    #[serde(default)]
    pub teardown: Vec<String>,
    /// How a session is reset between testcases (`reconnect` | `none`).
    #[serde(default)]
    pub reset: Option<String>,
}

/// An oracle that flags a (crash-free) security violation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct OracleDef {
    pub name: String,
    /// Stable rule identifier reported with a finding.
    #[serde(default)]
    pub rule_id: Option<String>,
    /// Restrict a response-condition oracle to one message's reply.
    #[serde(default)]
    pub message: Option<String>,
    /// Name of the response field whose value triggers the oracle.
    #[serde(default)]
    pub response_field: Option<String>,
    /// Sentinel value the `response_field` must equal to trigger.
    #[serde(default)]
    pub equals: Option<u64>,
    /// Arrival in this declared state triggers the oracle.
    #[serde(default)]
    pub violation_state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawProfile {
    schema: String,
    #[serde(default)]
    transport: Option<String>,
    #[serde(default)]
    max_messages: Option<usize>,
    #[serde(default)]
    start: Option<String>,
    #[serde(default, rename = "message")]
    message: Vec<MessageDef>,
    #[serde(default, rename = "transition")]
    transition: Vec<TransitionDef>,
    #[serde(default)]
    session: Option<SessionDef>,
    #[serde(default, rename = "oracle")]
    oracle: Vec<OracleDef>,
}

/// A parsed, validated protocol profile.
#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    schema: String,
    transport: Option<String>,
    max_messages: usize,
    start_state: String,
    messages: Vec<MessageDef>,
    transitions: Vec<TransitionDef>,
    session: SessionDef,
    oracles: Vec<OracleDef>,
    source_sha256: String,
}

impl Profile {
    /// Parse a profile from its TOML source. The returned profile records the
    /// SHA-256 of `source` so every run and artifact can carry the profile hash.
    pub fn from_toml(source: &str) -> Result<Self, ProfileError> {
        let raw: RawProfile = toml::from_str(source).map_err(|e| ProfileError::Malformed {
            message: e.to_string(),
        })?;

        if raw.schema != SCHEMA_V1 {
            return Err(ProfileError::UnknownSchema { found: raw.schema });
        }

        // Reject duplicate message names (name is the protocol's dispatch key).
        let mut seen = BTreeMap::new();
        for message in &raw.message {
            if seen.insert(message.name.clone(), ()).is_some() {
                return Err(ProfileError::DuplicateMessage {
                    name: message.name.clone(),
                });
            }
        }

        // Validate later-request references to captured response values.
        for message in &raw.message {
            for field in &message.fields {
                if let Some(reference) = &field.reference {
                    validate_reference(&raw.message, &message.name, &field.name, reference)?;
                }
            }
        }

        // Validate transitions name known messages so the state graph is sound.
        let names: Vec<&str> = raw.message.iter().map(|m| m.name.as_str()).collect();
        for transition in &raw.transition {
            if !names.contains(&transition.send.as_str()) {
                return Err(ProfileError::BadReference {
                    field: format!("transition {}->{}", transition.from, transition.to),
                    reference: transition.send.clone(),
                });
            }
        }

        // Resolve the start state: explicit `start`, else the `from` of the
        // first transition, else a synthetic default.
        let start_state = raw
            .start
            .or_else(|| raw.transition.first().map(|t| t.from.clone()))
            .unwrap_or_else(|| "start".to_owned());

        let max_messages = raw.max_messages.unwrap_or(DEFAULT_MAX_MESSAGES);
        let source_sha256 = hex_sha256(source.as_bytes());

        Ok(Self {
            schema: raw.schema,
            transport: raw.transport,
            max_messages,
            start_state,
            messages: raw.message,
            transitions: raw.transition,
            session: raw.session.unwrap_or_default(),
            oracles: raw.oracle,
            source_sha256,
        })
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn transport(&self) -> Option<&str> {
        self.transport.as_deref()
    }

    pub fn max_messages(&self) -> usize {
        self.max_messages
    }

    pub fn start_state(&self) -> &str {
        &self.start_state
    }

    pub fn messages(&self) -> &[MessageDef] {
        &self.messages
    }

    pub fn message(&self, name: &str) -> Option<&MessageDef> {
        self.messages.iter().find(|m| m.name == name)
    }

    pub fn transitions(&self) -> &[TransitionDef] {
        &self.transitions
    }

    pub fn session(&self) -> &SessionDef {
        &self.session
    }

    pub fn oracles(&self) -> &[OracleDef] {
        &self.oracles
    }

    /// The SHA-256 of the profile source, as lowercase hex. Recorded on every
    /// run and artifact so a finding can be traced to the exact profile.
    pub fn profile_sha256(&self) -> &str {
        &self.source_sha256
    }
}

fn validate_reference(
    messages: &[MessageDef],
    message: &str,
    field: &str,
    reference: &str,
) -> Result<(), ProfileError> {
    let parts: Vec<&str> = reference.split('.').collect();
    let bad = || ProfileError::BadReference {
        field: format!("{message}.{field}"),
        reference: reference.to_owned(),
    };
    if parts.len() != 3 || parts[1] != "response" {
        return Err(bad());
    }
    let (src_message, capture) = (parts[0], parts[2]);
    let Some(def) = messages.iter().find(|m| m.name == src_message) else {
        return Err(bad());
    };
    let has_capture = def
        .response
        .as_ref()
        .is_some_and(|r| r.captures.iter().any(|c| c.name == capture));
    if !has_capture {
        return Err(bad());
    }
    Ok(())
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Errors from profile parsing / validation. Every variant names the offender.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    #[error("malformed protocol profile: {message}")]
    Malformed { message: String },
    #[error("unknown protocol-profile schema {found:?}, expected {SCHEMA_V1:?}")]
    UnknownSchema { found: String },
    #[error("duplicate message name {name:?} in protocol profile")]
    DuplicateMessage { name: String },
    #[error("field {field:?} references undefined response value {reference:?}")]
    BadReference { field: String, reference: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOY: &str = include_str!("../tests/fixtures/toy-open-write.toml");

    #[test]
    fn parses_toy_open_write_profile() {
        let profile = Profile::from_toml(TOY).expect("toy profile parses");
        assert_eq!(profile.schema(), SCHEMA_V1);
        assert_eq!(profile.transport(), Some("tcp"));
        assert_eq!(profile.start_state(), "start");

        // Exactly two messages, OPEN and WRITE.
        let names: Vec<&str> = profile.messages().iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["OPEN", "WRITE"]);

        let open = profile.message("OPEN").expect("OPEN present");
        // path : bytes(max = 256)
        let path = open.field("path").expect("OPEN.path");
        assert_eq!(path.ty, FieldType::Bytes);
        assert_eq!(path.max, Some(256));
        // len : u32 computed length(path)
        let len = open.field("len").expect("OPEN.len");
        assert_eq!(len.ty, FieldType::U16);
        assert_eq!(len.computed.as_deref(), Some("length(path)"));
        // crc : u32 computed crc32 covering op,mode,len,path
        let crc = open.field("crc").expect("OPEN.crc");
        assert_eq!(crc.ty, FieldType::U32);
        assert_eq!(crc.computed.as_deref(), Some("crc32(op,mode,len,path)"));
        // mode is an enum; and OPEN captures a u32 handle at offset 0.
        assert_eq!(open.field("mode").unwrap().ty, FieldType::Enum);
        let response = open.response.as_ref().expect("OPEN response");
        let handle = &response.captures[0];
        assert_eq!(handle.name, "handle");
        assert_eq!(handle.ty, FieldType::U32);
        assert_eq!(handle.at, 0);

        // WRITE.handle : u32 ref OPEN.response.handle
        let write = profile.message("WRITE").expect("WRITE present");
        let handle_ref = write.field("handle").expect("WRITE.handle");
        assert_eq!(handle_ref.ty, FieldType::U32);
        assert_eq!(
            handle_ref.reference.as_deref(),
            Some("OPEN.response.handle")
        );
        // Optional field present somewhere (WRITE.flags).
        assert!(write.field("flags").expect("WRITE.flags").optional);

        // Transitions: start->OPEN->opened, opened->WRITE->opened (and reopen).
        assert!(profile
            .transitions()
            .iter()
            .any(|t| t.from == "start" && t.send == "OPEN" && t.to == "opened"));
        assert!(profile
            .transitions()
            .iter()
            .any(|t| t.from == "opened" && t.send == "WRITE" && t.to == "opened"));

        // Session reset and an oracle are declared.
        assert_eq!(profile.session().reset.as_deref(), Some("reconnect"));
        assert!(!profile.oracles().is_empty());

        // Profile hash is a 64-char hex digest.
        assert_eq!(profile.profile_sha256().len(), 64);
        assert!(profile
            .profile_sha256()
            .bytes()
            .all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn unknown_schema_is_descriptive() {
        let err = Profile::from_toml("schema = \"bhf.protocol.v99\"\n").unwrap_err();
        assert_eq!(
            err,
            ProfileError::UnknownSchema {
                found: "bhf.protocol.v99".to_owned()
            }
        );
    }

    #[test]
    fn duplicate_message_name_rejected() {
        let src = r#"
schema = "bhf.protocol.v1"
[[message]]
name = "OPEN"
[[message]]
name = "OPEN"
"#;
        let err = Profile::from_toml(src).unwrap_err();
        assert_eq!(
            err,
            ProfileError::DuplicateMessage {
                name: "OPEN".to_owned()
            }
        );
    }

    #[test]
    fn ref_to_unknown_message_or_field_rejected() {
        let src = r#"
schema = "bhf.protocol.v1"
[[message]]
name = "WRITE"
[[message.field]]
name = "handle"
type = "u32"
ref = "OPEN.response.handle"
"#;
        let err = Profile::from_toml(src).unwrap_err();
        assert_eq!(
            err,
            ProfileError::BadReference {
                field: "WRITE.handle".to_owned(),
                reference: "OPEN.response.handle".to_owned(),
            }
        );
    }

    #[test]
    fn malformed_toml_is_descriptive() {
        let err = Profile::from_toml("schema = \n").unwrap_err();
        match err {
            ProfileError::Malformed { message } => assert!(!message.is_empty()),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn profile_hash_is_stable_and_source_sensitive() {
        let a = Profile::from_toml(TOY).unwrap();
        let b = Profile::from_toml(TOY).unwrap();
        assert_eq!(a.profile_sha256(), b.profile_sha256());
        let mutated = format!("{TOY}\n# trailing comment\n");
        let c = Profile::from_toml(&mutated).unwrap();
        assert_ne!(a.profile_sha256(), c.profile_sha256());
    }
}
