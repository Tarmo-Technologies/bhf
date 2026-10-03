// SPDX-License-Identifier: Apache-2.0

//! Compile a parsed [`Profile`] into a typed, executable model.
//!
//! Two products come out of compilation:
//!
//! 1. **A per-message binary descriptor.** `binframe` (the reused HDF-7 framing
//!    library) has exactly five field variants — `Bytes`, `Tlv`, `Length`,
//!    `Checksum`, `Offset` — and **no scalar-integer or enum variant**. So a
//!    non-computed `u8`/`u16`/`u32`/`enum` profile field is lowered to a
//!    [`Field::Bytes`] whose value is the integer (enum: symbol -> code) encoded
//!    at the declared width and byte order; computed `length`/`crc*`/`tlv`/
//!    `offset` fields lower to `Length`/`Checksum`/`Tlv`/`Offset`. This lowering
//!    is the heart of the model.
//!
//! 2. **A protocol state graph.** The profile's transitions are projected onto
//!    [`ProtocolStateGraph`] (the reused AFLNet-style adjacency) by synthesizing
//!    a [`StateMachine`] with the start state at index 0 — so `from_machine`'s
//!    `initial()` (which falls back to index 0 when no state is named `ready`)
//!    resolves to the profile's start state. Mutation legality and novelty are
//!    both driven off this graph.

use std::collections::BTreeMap;

use ada_state_machine::adapter::ProtocolStateGraph;
use ada_state_machine::{MachineKind, State, StateMachine, Transition};
use fuzz_engine_builtin::{
    BinFrameError, ChecksumKind, EncodedMessage, Endian, Field, IntWidth, Message,
};
use serde::{Deserialize, Serialize};

use crate::binding::Bindings;
use crate::profile::{ByteOrder, FieldDef, FieldType, MessageDef, OracleDef, Profile, SessionDef};

/// A concrete value assigned to a data field of a message instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FieldValue {
    /// Opaque, variable-length bytes.
    Bytes { value: Vec<u8> },
    /// An unsigned integer (width enforced at encode time).
    Int { value: u64 },
    /// A symbolic enum value (resolved to its code at encode time).
    Enum { symbol: String },
    /// A TLV record value.
    Tlv { value: Vec<u8> },
}

/// The lowering role of a compiled field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldRole {
    Data(DataSpec),
    Computed(ComputedSpec),
    /// A later-request reference to a captured response value.
    Ref {
        source: String,
        width: IntWidth,
        endian: Endian,
    },
}

/// How a concrete data field lowers onto `binframe`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataSpec {
    Bytes {
        max: Option<usize>,
    },
    Int {
        width: IntWidth,
        endian: Endian,
    },
    Enum {
        width: IntWidth,
        endian: Endian,
        variants: BTreeMap<String, u64>,
    },
    Tlv {
        tag: u64,
        tag_width: IntWidth,
        len_width: IntWidth,
        endian: Endian,
    },
}

/// A computed field recomputed by the fix-up pass after any mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComputedSpec {
    Length {
        width: IntWidth,
        endian: Endian,
        covers: Vec<String>,
    },
    Checksum {
        kind: ChecksumKind,
        endian: Endian,
        covers: Vec<String>,
    },
    Offset {
        width: IntWidth,
        endian: Endian,
        target: String,
    },
}

/// A compiled field: its name, whether it is optional, its lowering role, and
/// (for data fields) the seed value used to construct an initial instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledField {
    pub name: String,
    pub optional: bool,
    pub role: FieldRole,
    pub seed: Option<FieldValue>,
}

impl CompiledField {
    pub fn is_mutable_data(&self) -> bool {
        matches!(self.role, FieldRole::Data(_))
    }
}

/// How a response capture decodes a slice of the reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureSpec {
    Int {
        width: IntWidth,
        endian: Endian,
    },
    Enum {
        width: IntWidth,
        endian: Endian,
        variants: BTreeMap<String, u64>,
    },
    Bytes {
        len: usize,
    },
}

/// A compiled response capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledCapture {
    pub name: String,
    pub at: usize,
    pub spec: CaptureSpec,
}

/// A compiled message type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledMessage {
    pub name: String,
    pub max_len: usize,
    pub fields: Vec<CompiledField>,
    pub response: Vec<CompiledCapture>,
}

impl CompiledMessage {
    /// Seed values for every field that an initial instance carries: required
    /// data fields (declared seed or a type default) and present optional data
    /// fields (only those with a declared seed).
    pub fn seed_values(&self) -> BTreeMap<String, FieldValue> {
        let mut values = BTreeMap::new();
        for field in &self.fields {
            let FieldRole::Data(spec) = &field.role else {
                continue;
            };
            match (&field.seed, field.optional) {
                (Some(seed), _) => {
                    values.insert(field.name.clone(), seed.clone());
                }
                (None, false) => {
                    values.insert(field.name.clone(), default_value(spec));
                }
                (None, true) => {} // optional + no seed => absent in the seed instance
            }
        }
        values
    }

    /// The names of the data fields that are present in `values`, in field
    /// declaration order.
    pub fn data_field(&self, name: &str) -> Option<&CompiledField> {
        self.fields
            .iter()
            .find(|f| f.name == name && f.is_mutable_data())
    }

    /// Assemble and encode this message into an internally-consistent frame.
    ///
    /// The sequence mirrors the HDF-7 fix-up contract: lay the frame out with a
    /// zero placeholder for every reference field, encode (computing length /
    /// checksum / offset once), overwrite each reference field from the live
    /// [`Bindings`], then re-run the fix-up so any length/CRC that *covers* a
    /// reference is recomputed over the resolved value.
    pub fn build_frame(
        &self,
        values: &BTreeMap<String, FieldValue>,
        bindings: &Bindings,
    ) -> Result<EncodedMessage, EncodeError> {
        let mut fields: Vec<Field> = Vec::with_capacity(self.fields.len());
        let mut refs: Vec<(String, String, IntWidth, Endian)> = Vec::new();

        for field in &self.fields {
            match &field.role {
                FieldRole::Data(spec) => {
                    if field.optional && !values.contains_key(&field.name) {
                        continue; // absent optional field
                    }
                    let value =
                        values
                            .get(&field.name)
                            .ok_or_else(|| EncodeError::MissingValue {
                                field: field.name.clone(),
                            })?;
                    fields.push(lower_data_field(&field.name, spec, value)?);
                }
                FieldRole::Computed(spec) => fields.push(lower_computed_field(&field.name, spec)),
                FieldRole::Ref {
                    source,
                    width,
                    endian,
                } => {
                    fields.push(Field::bytes(&field.name, vec![0u8; width.size()]));
                    refs.push((field.name.clone(), source.clone(), *width, *endian));
                }
            }
        }

        let mut encoded = Message::new(fields)
            .with_max_len(self.max_len)
            .encode()
            .map_err(EncodeError::Frame)?;

        for (field, source, width, endian) in &refs {
            let bound = bindings
                .get(source)
                .and_then(|value| value.as_u64())
                .ok_or_else(|| EncodeError::Unresolved {
                    field: field.clone(),
                    reference: source.clone(),
                })?;
            if bound > width_max(*width) {
                return Err(EncodeError::ValueTooWide {
                    field: field.clone(),
                    value: bound,
                });
            }
            encoded
                .set_field_bytes(field, &encode_uint(*width, *endian, bound))
                .map_err(EncodeError::Frame)?;
        }

        // Re-run the fix-up so computed fields covering a reference recompute.
        encoded.fixup_in_place().map_err(EncodeError::Frame)?;
        Ok(encoded)
    }
}

/// The compiled, executable protocol model.
#[derive(Debug, Clone)]
pub struct ProtocolModel {
    profile_sha256: String,
    max_messages: usize,
    start_state: String,
    messages: Vec<CompiledMessage>,
    graph: ProtocolStateGraph,
    oracles: Vec<OracleDef>,
    session: SessionDef,
}

impl ProtocolModel {
    /// Compile a validated [`Profile`] into an executable model.
    pub fn from_profile(profile: &Profile) -> Result<Self, ModelError> {
        let messages = profile
            .messages()
            .iter()
            .map(compile_message)
            .collect::<Result<Vec<_>, _>>()?;

        let graph = build_state_graph(profile)?;

        Ok(Self {
            profile_sha256: profile.profile_sha256().to_owned(),
            max_messages: profile.max_messages(),
            start_state: profile.start_state().to_owned(),
            messages,
            graph,
            oracles: profile.oracles().to_vec(),
            session: profile.session().clone(),
        })
    }

    pub fn profile_sha256(&self) -> &str {
        &self.profile_sha256
    }

    pub fn max_messages(&self) -> usize {
        self.max_messages
    }

    pub fn start_state(&self) -> &str {
        &self.start_state
    }

    pub fn messages(&self) -> &[CompiledMessage] {
        &self.messages
    }

    pub fn message(&self, name: &str) -> Option<&CompiledMessage> {
        self.messages.iter().find(|m| m.name == name)
    }

    pub fn graph(&self) -> &ProtocolStateGraph {
        &self.graph
    }

    pub fn oracles(&self) -> &[OracleDef] {
        &self.oracles
    }

    pub fn session(&self) -> &SessionDef {
        &self.session
    }
}

fn compile_message(def: &MessageDef) -> Result<CompiledMessage, ModelError> {
    let field_names: Vec<&str> = def.fields.iter().map(|f| f.name.as_str()).collect();
    let optional_names: Vec<&str> = def
        .fields
        .iter()
        .filter(|f| f.optional)
        .map(|f| f.name.as_str())
        .collect();

    let mut fields = Vec::with_capacity(def.fields.len());
    for field in &def.fields {
        fields.push(compile_field(
            &def.name,
            field,
            &field_names,
            &optional_names,
        )?);
    }

    let response = def
        .response
        .as_ref()
        .map(|r| {
            r.captures
                .iter()
                .map(|c| compile_capture(&def.name, c))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();

    Ok(CompiledMessage {
        name: def.name.clone(),
        max_len: def
            .max_len
            .unwrap_or(fuzz_engine_builtin::binframe::DEFAULT_MAX_LEN),
        fields,
        response,
    })
}

fn compile_field(
    message: &str,
    def: &FieldDef,
    field_names: &[&str],
    optional_names: &[&str],
) -> Result<CompiledField, ModelError> {
    let endian = to_endian(def.endian);

    let role = if let Some(spec) = &def.computed {
        compile_computed(message, def, spec, field_names, optional_names)?
    } else if let Some(source) = &def.reference {
        let width = int_width(def.ty).ok_or_else(|| ModelError::IllegalFieldType {
            message: message.to_owned(),
            field: def.name.clone(),
            reason: "reference fields must be u8/u16/u32".to_owned(),
        })?;
        FieldRole::Ref {
            source: source.clone(),
            width,
            endian,
        }
    } else {
        FieldRole::Data(compile_data_spec(message, def, endian)?)
    };

    // Optional applies only to concrete data fields.
    let optional = def.optional && matches!(role, FieldRole::Data(_));
    let seed = match &role {
        FieldRole::Data(spec) => def
            .value
            .as_ref()
            .map(|v| seed_from_toml(message, &def.name, spec, v))
            .transpose()?,
        _ => None,
    };

    Ok(CompiledField {
        name: def.name.clone(),
        optional,
        role,
        seed,
    })
}

fn compile_data_spec(
    message: &str,
    def: &FieldDef,
    endian: Endian,
) -> Result<DataSpec, ModelError> {
    Ok(match def.ty {
        FieldType::Bytes => DataSpec::Bytes { max: def.max },
        FieldType::U8 => DataSpec::Int {
            width: IntWidth::U8,
            endian,
        },
        FieldType::U16 => DataSpec::Int {
            width: IntWidth::U16,
            endian,
        },
        FieldType::U32 => DataSpec::Int {
            width: IntWidth::U32,
            endian,
        },
        FieldType::Enum => {
            let variants = def
                .variants
                .clone()
                .ok_or_else(|| ModelError::EnumWithoutVariants {
                    message: message.to_owned(),
                    field: def.name.clone(),
                })?;
            if variants.is_empty() {
                return Err(ModelError::EnumWithoutVariants {
                    message: message.to_owned(),
                    field: def.name.clone(),
                });
            }
            DataSpec::Enum {
                width: width_for_codes(variants.values().copied()),
                endian,
                variants,
            }
        }
        FieldType::Tlv => DataSpec::Tlv {
            tag: def.tag.unwrap_or(0),
            tag_width: IntWidth::U16,
            len_width: IntWidth::U16,
            endian,
        },
    })
}

fn compile_computed(
    message: &str,
    def: &FieldDef,
    spec: &str,
    field_names: &[&str],
    optional_names: &[&str],
) -> Result<FieldRole, ModelError> {
    let (name, args) = split_call(spec).ok_or_else(|| ModelError::BadComputedSpec {
        message: message.to_owned(),
        field: def.name.clone(),
        spec: spec.to_owned(),
    })?;
    let endian = to_endian(def.endian);

    let ensure_known = |target: &str| -> Result<(), ModelError> {
        if !field_names.contains(&target) {
            return Err(ModelError::UnknownCover {
                message: message.to_owned(),
                field: def.name.clone(),
                cover: target.to_owned(),
            });
        }
        if optional_names.contains(&target) {
            return Err(ModelError::ComputedCoversOptional {
                message: message.to_owned(),
                field: def.name.clone(),
                cover: target.to_owned(),
            });
        }
        Ok(())
    };

    match name {
        "length" | "crc32" | "crc16" | "sum8" | "xor8" => {
            if args.is_empty() {
                return Err(ModelError::BadComputedSpec {
                    message: message.to_owned(),
                    field: def.name.clone(),
                    spec: spec.to_owned(),
                });
            }
            for cover in &args {
                ensure_known(cover)?;
            }
            if name == "length" {
                let width = int_width(def.ty).ok_or_else(|| ModelError::IllegalFieldType {
                    message: message.to_owned(),
                    field: def.name.clone(),
                    reason: "length fields must be u8/u16/u32".to_owned(),
                })?;
                Ok(FieldRole::Computed(ComputedSpec::Length {
                    width,
                    endian,
                    covers: args,
                }))
            } else {
                let kind = match name {
                    "crc32" => ChecksumKind::Crc32,
                    "crc16" => ChecksumKind::Crc16Ccitt,
                    "sum8" => ChecksumKind::Sum8,
                    "xor8" => ChecksumKind::Xor8,
                    _ => unreachable!(),
                };
                Ok(FieldRole::Computed(ComputedSpec::Checksum {
                    kind,
                    endian,
                    covers: args,
                }))
            }
        }
        "offset" => {
            if args.len() != 1 {
                return Err(ModelError::BadComputedSpec {
                    message: message.to_owned(),
                    field: def.name.clone(),
                    spec: spec.to_owned(),
                });
            }
            ensure_known(&args[0])?;
            let width = int_width(def.ty).ok_or_else(|| ModelError::IllegalFieldType {
                message: message.to_owned(),
                field: def.name.clone(),
                reason: "offset fields must be u8/u16/u32".to_owned(),
            })?;
            Ok(FieldRole::Computed(ComputedSpec::Offset {
                width,
                endian,
                target: args.into_iter().next().unwrap(),
            }))
        }
        _ => Err(ModelError::BadComputedSpec {
            message: message.to_owned(),
            field: def.name.clone(),
            spec: spec.to_owned(),
        }),
    }
}

fn compile_capture(
    message: &str,
    def: &crate::profile::CaptureDef,
) -> Result<CompiledCapture, ModelError> {
    let endian = to_endian(def.endian);
    let spec = match def.ty {
        FieldType::U8 => CaptureSpec::Int {
            width: IntWidth::U8,
            endian,
        },
        FieldType::U16 => CaptureSpec::Int {
            width: IntWidth::U16,
            endian,
        },
        FieldType::U32 => CaptureSpec::Int {
            width: IntWidth::U32,
            endian,
        },
        FieldType::Enum => {
            let variants = def
                .variants
                .clone()
                .ok_or_else(|| ModelError::EnumWithoutVariants {
                    message: message.to_owned(),
                    field: def.name.clone(),
                })?;
            CaptureSpec::Enum {
                width: width_for_codes(variants.values().copied()),
                endian,
                variants,
            }
        }
        FieldType::Bytes => CaptureSpec::Bytes {
            len: def.len.ok_or_else(|| ModelError::CaptureWithoutLen {
                message: message.to_owned(),
                field: def.name.clone(),
            })?,
        },
        FieldType::Tlv => {
            return Err(ModelError::IllegalFieldType {
                message: message.to_owned(),
                field: def.name.clone(),
                reason: "tlv response captures are not supported".to_owned(),
            })
        }
    };
    Ok(CompiledCapture {
        name: def.name.clone(),
        at: def.at,
        spec,
    })
}

fn build_state_graph(profile: &Profile) -> Result<ProtocolStateGraph, ModelError> {
    // Ordered, de-duplicated state list with the start state at index 0.
    let start = profile.start_state().to_owned();
    let mut order: Vec<String> = vec![start.clone()];
    let push = |name: &str, order: &mut Vec<String>| {
        if !order.iter().any(|s| s == name) {
            order.push(name.to_owned());
        }
    };
    for transition in profile.transitions() {
        let (from, to) = (transition.from.clone(), transition.to.clone());
        push(&from, &mut order);
        push(&to, &mut order);
    }

    // `from_machine` resolves the initial state as index_of("ready") || 0; a
    // non-start state named "ready" would steal the initial slot.
    if let Some(bad) = order.iter().skip(1).find(|s| s.as_str() == "ready") {
        return Err(ModelError::ReservedStateName { name: bad.clone() });
    }

    let states = order
        .iter()
        .map(|name| State {
            name: name.clone(),
            open_entries: profile
                .transitions()
                .iter()
                .filter(|t| &t.from == name)
                .map(|t| t.send.clone())
                .collect(),
        })
        .collect();

    let transitions = profile
        .transitions()
        .iter()
        .map(|t| Transition {
            from: t.from.clone(),
            entry: t.send.clone(),
            to: t.to.clone(),
            barrier: None,
        })
        .collect();

    let machine = StateMachine {
        kind: MachineKind::Protected,
        name: "protocol".to_owned(),
        states,
        transitions,
    };

    let graph = ProtocolStateGraph::from_machine(&machine);
    // By construction the start state is index 0 and no other state is "ready".
    if graph.state_name(graph.initial()) != Some(start.as_str()) {
        return Err(ModelError::StartStateUnresolved { name: start });
    }
    Ok(graph)
}

// --- lowering helpers ---------------------------------------------------------

fn lower_data_field(name: &str, spec: &DataSpec, value: &FieldValue) -> Result<Field, EncodeError> {
    match (spec, value) {
        (DataSpec::Bytes { max }, FieldValue::Bytes { value }) => {
            if let Some(max) = max {
                if value.len() > *max {
                    return Err(EncodeError::BoundExceeded {
                        field: name.to_owned(),
                        len: value.len(),
                        max: *max,
                    });
                }
            }
            Ok(Field::bytes(name, value.clone()))
        }
        (DataSpec::Int { width, endian }, FieldValue::Int { value }) => {
            if *value > width_max(*width) {
                return Err(EncodeError::ValueTooWide {
                    field: name.to_owned(),
                    value: *value,
                });
            }
            Ok(Field::bytes(name, encode_uint(*width, *endian, *value)))
        }
        (
            DataSpec::Enum {
                width,
                endian,
                variants,
            },
            FieldValue::Enum { symbol },
        ) => {
            let code = *variants
                .get(symbol)
                .ok_or_else(|| EncodeError::UnknownSymbol {
                    field: name.to_owned(),
                    symbol: symbol.clone(),
                })?;
            Ok(Field::bytes(name, encode_uint(*width, *endian, code)))
        }
        (
            DataSpec::Tlv {
                tag,
                tag_width,
                len_width,
                endian,
            },
            FieldValue::Tlv { value },
        ) => Ok(Field::Tlv {
            name: name.to_owned(),
            tag: u32::try_from(*tag).map_err(|_| EncodeError::ValueTooWide {
                field: name.to_owned(),
                value: *tag,
            })?,
            tag_width: *tag_width,
            len_width: *len_width,
            endian: *endian,
            value: value.clone(),
        }),
        (spec, value) => Err(EncodeError::TypeMismatch {
            field: name.to_owned(),
            expected: spec_kind(spec),
            got: value_kind(value),
        }),
    }
}

fn lower_computed_field(name: &str, spec: &ComputedSpec) -> Field {
    match spec {
        ComputedSpec::Length {
            width,
            endian,
            covers,
        } => Field::length(name, *width, *endian, &cover_refs(covers)),
        ComputedSpec::Checksum {
            kind,
            endian,
            covers,
        } => Field::checksum(name, *kind, *endian, &cover_refs(covers)),
        ComputedSpec::Offset {
            width,
            endian,
            target,
        } => Field::offset(name, *width, *endian, target),
    }
}

fn cover_refs(covers: &[String]) -> Vec<&str> {
    covers.iter().map(String::as_str).collect()
}

fn default_value(spec: &DataSpec) -> FieldValue {
    match spec {
        DataSpec::Bytes { .. } => FieldValue::Bytes { value: Vec::new() },
        DataSpec::Int { .. } => FieldValue::Int { value: 0 },
        DataSpec::Enum { variants, .. } => {
            let symbol = variants
                .iter()
                .min_by_key(|(_, code)| **code)
                .map(|(symbol, _)| symbol.clone())
                .unwrap_or_default();
            FieldValue::Enum { symbol }
        }
        DataSpec::Tlv { .. } => FieldValue::Tlv { value: Vec::new() },
    }
}

fn seed_from_toml(
    message: &str,
    field: &str,
    spec: &DataSpec,
    value: &toml::Value,
) -> Result<FieldValue, ModelError> {
    let bad = || ModelError::BadSeedValue {
        message: message.to_owned(),
        field: field.to_owned(),
    };
    Ok(match spec {
        DataSpec::Bytes { .. } | DataSpec::Tlv { .. } => {
            let bytes = toml_to_bytes(value).ok_or_else(bad)?;
            if matches!(spec, DataSpec::Bytes { .. }) {
                FieldValue::Bytes { value: bytes }
            } else {
                FieldValue::Tlv { value: bytes }
            }
        }
        DataSpec::Int { .. } => {
            let n = value.as_integer().ok_or_else(bad)?;
            FieldValue::Int {
                value: u64::try_from(n).map_err(|_| bad())?,
            }
        }
        DataSpec::Enum { variants, .. } => {
            let symbol = value.as_str().ok_or_else(bad)?.to_owned();
            if !variants.contains_key(&symbol) {
                return Err(bad());
            }
            FieldValue::Enum { symbol }
        }
    })
}

fn toml_to_bytes(value: &toml::Value) -> Option<Vec<u8>> {
    match value {
        toml::Value::String(s) => Some(s.clone().into_bytes()),
        toml::Value::Array(items) => {
            let mut bytes = Vec::with_capacity(items.len());
            for item in items {
                let n = item.as_integer()?;
                bytes.push(u8::try_from(n).ok()?);
            }
            Some(bytes)
        }
        _ => None,
    }
}

fn spec_kind(spec: &DataSpec) -> &'static str {
    match spec {
        DataSpec::Bytes { .. } => "bytes",
        DataSpec::Int { .. } => "int",
        DataSpec::Enum { .. } => "enum",
        DataSpec::Tlv { .. } => "tlv",
    }
}

fn value_kind(value: &FieldValue) -> &'static str {
    match value {
        FieldValue::Bytes { .. } => "bytes",
        FieldValue::Int { .. } => "int",
        FieldValue::Enum { .. } => "enum",
        FieldValue::Tlv { .. } => "tlv",
    }
}

pub(crate) fn to_endian(order: Option<ByteOrder>) -> Endian {
    match order {
        Some(ByteOrder::Little) => Endian::Little,
        _ => Endian::Big,
    }
}

pub(crate) fn int_width(ty: FieldType) -> Option<IntWidth> {
    match ty {
        FieldType::U8 => Some(IntWidth::U8),
        FieldType::U16 => Some(IntWidth::U16),
        FieldType::U32 => Some(IntWidth::U32),
        _ => None,
    }
}

pub(crate) fn width_for_codes(codes: impl Iterator<Item = u64>) -> IntWidth {
    let max = codes.max().unwrap_or(0);
    if max <= u64::from(u8::MAX) {
        IntWidth::U8
    } else if max <= u64::from(u16::MAX) {
        IntWidth::U16
    } else {
        IntWidth::U32
    }
}

pub(crate) fn width_max(width: IntWidth) -> u64 {
    match width {
        IntWidth::U8 => u64::from(u8::MAX),
        IntWidth::U16 => u64::from(u16::MAX),
        IntWidth::U32 => u64::from(u32::MAX),
    }
}

pub(crate) fn encode_uint(width: IntWidth, endian: Endian, value: u64) -> Vec<u8> {
    match (width, endian) {
        (IntWidth::U8, _) => vec![value as u8],
        (IntWidth::U16, Endian::Big) => (value as u16).to_be_bytes().to_vec(),
        (IntWidth::U16, Endian::Little) => (value as u16).to_le_bytes().to_vec(),
        (IntWidth::U32, Endian::Big) => (value as u32).to_be_bytes().to_vec(),
        (IntWidth::U32, Endian::Little) => (value as u32).to_le_bytes().to_vec(),
    }
}

fn split_call(spec: &str) -> Option<(&str, Vec<String>)> {
    let open = spec.find('(')?;
    if !spec.ends_with(')') {
        return None;
    }
    let name = spec[..open].trim();
    if name.is_empty() {
        return None;
    }
    let inner = &spec[open + 1..spec.len() - 1];
    let args: Vec<String> = inner
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    Some((name, args))
}

/// Errors from compiling a profile into a model. Every variant names the
/// offending message and field.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModelError {
    #[error("field {message}.{field} has an illegal type: {reason}")]
    IllegalFieldType {
        message: String,
        field: String,
        reason: String,
    },
    #[error("enum field {message}.{field} declares no variants")]
    EnumWithoutVariants { message: String, field: String },
    #[error("bytes response capture {message}.{field} is missing a `len`")]
    CaptureWithoutLen { message: String, field: String },
    #[error("computed field {message}.{field} has a malformed spec {spec:?}")]
    BadComputedSpec {
        message: String,
        field: String,
        spec: String,
    },
    #[error("computed field {message}.{field} covers unknown field {cover:?}")]
    UnknownCover {
        message: String,
        field: String,
        cover: String,
    },
    #[error("computed field {message}.{field} covers optional field {cover:?}")]
    ComputedCoversOptional {
        message: String,
        field: String,
        cover: String,
    },
    #[error("seed value for {message}.{field} does not match the field type")]
    BadSeedValue { message: String, field: String },
    #[error("state {name:?} is reserved and may not be a non-start state")]
    ReservedStateName { name: String },
    #[error("start state {name:?} did not resolve as the graph's initial state")]
    StartStateUnresolved { name: String },
}

/// Errors from assembling and encoding a concrete frame.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    #[error("no message type named {name:?} in the model")]
    UnknownMessage { name: String },
    #[error("no value supplied for required field {field:?}")]
    MissingValue { field: String },
    #[error("field {field:?} expected a {expected} value but got {got}")]
    TypeMismatch {
        field: String,
        expected: &'static str,
        got: &'static str,
    },
    #[error("value {value} for field {field:?} does not fit the declared width")]
    ValueTooWide { field: String, value: u64 },
    #[error("field {field:?} is {len} bytes, exceeding its max of {max}")]
    BoundExceeded {
        field: String,
        len: usize,
        max: usize,
    },
    #[error("enum field {field:?} has no variant named {symbol:?}")]
    UnknownSymbol { field: String, symbol: String },
    #[error("reference field {field:?} is unresolved: no binding for {reference:?}")]
    Unresolved { field: String, reference: String },
    #[error("frame assembly failed: {0}")]
    Frame(BinFrameError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Profile;

    const TOY: &str = include_str!("../tests/fixtures/toy-open-write.toml");

    fn toy_model() -> ProtocolModel {
        ProtocolModel::from_profile(&Profile::from_toml(TOY).expect("parse")).expect("compile")
    }

    #[test]
    fn message_compiles_to_binframe_descriptor() {
        let model = toy_model();
        let open = model.message("OPEN").expect("OPEN");
        let frame = open
            .build_frame(&open.seed_values(), &Bindings::new())
            .expect("encode OPEN");
        assert!(frame.verify(), "freshly encoded OPEN must verify");

        // len covers path ("track" = 5 bytes).
        let len_span = frame.span("len").expect("len span");
        let stored_len = u16::from_be_bytes([
            frame.bytes()[len_span.start],
            frame.bytes()[len_span.start + 1],
        ]);
        assert_eq!(usize::from(stored_len), b"track".len());

        // crc covers op,mode,len,path (everything before the crc field).
        let crc_span = frame.span("crc").expect("crc span");
        let covered = &frame.bytes()[..crc_span.start];
        let stored_crc = u32::from_be_bytes([
            frame.bytes()[crc_span.start],
            frame.bytes()[crc_span.start + 1],
            frame.bytes()[crc_span.start + 2],
            frame.bytes()[crc_span.start + 3],
        ]);
        assert_eq!(stored_crc, fuzz_engine_builtin::crc32(covered));
    }

    #[test]
    fn profile_projects_to_state_graph() {
        let model = toy_model();
        let graph = model.graph();
        let start = graph.initial();
        assert_eq!(graph.state_name(start), Some("start"));
        assert!(graph.open_entries(start).iter().any(|e| e == "OPEN"));
        let opened = graph.next_state(start, "OPEN").expect("OPEN -> opened");
        assert_eq!(graph.state_name(opened), Some("opened"));
        assert_eq!(graph.next_state(opened, "WRITE"), Some(opened));
        assert_eq!(graph.next_state(opened, "OPEN"), Some(opened));
    }

    #[test]
    fn scalar_and_enum_fields_lower_to_bytes() {
        let model = toy_model();

        // enum (mode) lowers to a single byte = its code.
        let open = model.message("OPEN").unwrap();
        let frame = open
            .build_frame(&open.seed_values(), &Bindings::new())
            .unwrap();
        let mode_span = frame.span("mode").expect("mode span");
        assert_eq!(mode_span.len(), 1, "u8 enum lowers to one byte");
        assert_eq!(frame.bytes()[mode_span.start], 0, "'read' => code 0");

        // u32 reference (handle) lowers to 4 big-endian bytes from the binding.
        let write = model.message("WRITE").unwrap();
        let mut bindings = Bindings::new();
        bindings.bind(
            "OPEN.response.handle",
            crate::binding::BoundValue::Int { value: 0x1122_3344 },
        );
        let frame = write.build_frame(&write.seed_values(), &bindings).unwrap();
        let handle_span = frame.span("handle").expect("handle span");
        assert_eq!(handle_span.len(), 4, "u32 lowers to four bytes");
        assert_eq!(
            &frame.bytes()[handle_span.clone()],
            &0x1122_3344u32.to_be_bytes()
        );
        assert!(frame.verify(), "handle-bound WRITE must verify");
    }

    #[test]
    fn illegal_computed_type_is_rejected() {
        let src = r#"
schema = "bhf.protocol.v1"
start = "s"
[[message]]
name = "M"
[[message.field]]
name = "body"
type = "bytes"
computed = "length(body)"
"#;
        let profile = Profile::from_toml(src).expect("parse");
        let err = ProtocolModel::from_profile(&profile).unwrap_err();
        assert!(
            matches!(err, ModelError::IllegalFieldType { ref field, .. } if field == "body"),
            "got {err:?}"
        );
    }

    #[test]
    fn computed_cover_of_unknown_field_is_rejected() {
        let src = r#"
schema = "bhf.protocol.v1"
start = "s"
[[message]]
name = "M"
[[message.field]]
name = "len"
type = "u16"
computed = "length(nope)"
"#;
        let profile = Profile::from_toml(src).expect("parse");
        let err = ProtocolModel::from_profile(&profile).unwrap_err();
        assert!(
            matches!(err, ModelError::UnknownCover { ref cover, .. } if cover == "nope"),
            "got {err:?}"
        );
    }

    #[test]
    fn non_start_state_named_ready_is_rejected() {
        let src = r#"
schema = "bhf.protocol.v1"
start = "start"
[[message]]
name = "GO"
[[transition]]
from = "start"
send = "GO"
to = "ready"
"#;
        let profile = Profile::from_toml(src).expect("parse");
        let err = ProtocolModel::from_profile(&profile).unwrap_err();
        assert!(
            matches!(err, ModelError::ReservedStateName { .. }),
            "got {err:?}"
        );
    }
}
