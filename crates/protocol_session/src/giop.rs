// SPDX-License-Identifier: Apache-2.0

//! A `kind = "giop"` profile: every message is a GIOP 1.2 Request (#315).
//!
//! ```toml
//! kind = "giop"
//!
//! [giop]
//! object_key = "Warehouse"   # the object key the requests address
//! endian = "big"             # the requests' byte order: big (the default)
//!                            # or little
//!
//! [[message]]
//! name = "STORE"
//! operation = "store"        # the message's name when absent
//! # object_key = "Other"     # another object key for this request
//!
//! [[message.field]]          # the operation's in parameters, in order
//! name = "slot"
//! type = "unsigned short"
//! value = 1
//!
//! [message.response]
//! [[message.response.capture]]
//! name = "reply_status"      # the Reply header's status
//! type = "enum"
//! variants = { no_exception = 0 }
//!
//! [[message.response.capture]]
//! name = "stocked"           # the next value of the body: the result
//! type = "long"
//! ```
//!
//! A field's type is an IDL type: `octet`, `boolean` and `char`, `short` and
//! `unsigned short`, `long` and `unsigned long`, an `enum` (which CDR
//! marshals as an unsigned long), `string` and `sequence<octet>`. A field may
//! reference a captured value; a computed or TLV field has no place in CDR,
//! which carries its own lengths. The iiop crate marshals the arguments and
//! frames the GIOP 1.2 Request, a response expected and its request id the
//! message's place in the profile, counted from 1.
//!
//! A reply is read with iiop's GIOP decoder, and must be the GIOP 1.2 Reply
//! to the request's id. A capture named `reply_status` or `request_id` reads
//! that field of the Reply header; every other capture reads the next value
//! of the body (the operation's result, then its out parameters) at its type,
//! and needs a reply with no exception. Captures take no `at`.

use std::collections::BTreeMap;

use iiop::cdr::{CdrError, CdrReader, Endianness};
use iiop::encode::{CdrValue, Request12};
use iiop::giop::{parse_message, read_reply_1_2, ReplyStatus};
use serde::{Deserialize, Serialize};

use crate::binding::{Bindings, BoundValue};
use crate::model::{
    spec_kind, value_kind, CaptureSpec, CompiledCapture, CompiledField, DataSpec, EncodeError,
    FieldRole, FieldValue, ModelError,
};
use crate::profile::{ByteOrder, CaptureDef, FieldDef, FieldType, MessageDef};
use crate::response::ResponseError;

/// A `giop` profile's `[giop]` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GiopDef {
    /// The object key a request addresses (a KeyAddr target), unless its
    /// message names its own.
    #[serde(default)]
    pub object_key: Option<String>,
    /// The requests' byte order; big-endian when absent.
    #[serde(default)]
    pub endian: Option<ByteOrder>,
}

/// How an argument or a reply value is marshalled in CDR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdrKind {
    /// `octet`, `boolean`, `char`.
    Octet,
    /// `short`, `unsigned short`.
    UShort,
    /// `long`, `unsigned long`, an `enum`.
    ULong,
    /// `string`: a u32 length counting a NUL, the bytes and the NUL.
    String,
    /// `sequence<octet>`: a u32 count and the bytes.
    OctetSequence,
}

impl CdrKind {
    /// The kind a field or capture of type `ty` marshals as; a TLV has none.
    fn of(ty: FieldType) -> Option<Self> {
        match ty {
            FieldType::U8 => Some(Self::Octet),
            FieldType::U16 => Some(Self::UShort),
            FieldType::U32 | FieldType::Enum => Some(Self::ULong),
            FieldType::String => Some(Self::String),
            FieldType::Bytes => Some(Self::OctetSequence),
            FieldType::Tlv => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Octet => "octet",
            Self::UShort => "unsigned short",
            Self::ULong => "unsigned long",
            Self::String => "string",
            Self::OctetSequence => "sequence<octet>",
        }
    }
}

/// What a compiled `giop` message's frame is: the request's target and how
/// each of its fields marshals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GiopRequest {
    pub operation: String,
    pub object_key: Vec<u8>,
    pub endian: ByteOrder,
    /// The request id: the message's place in the profile, from 1. A reply
    /// names the request it answers by it.
    pub request_id: u32,
    /// Each field's CDR kind, in field order.
    pub arguments: Vec<CdrKind>,
}

/// What a `giop` capture reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyField {
    /// The Reply header's status (`NO_EXCEPTION` is 0).
    ReplyStatus,
    /// The Reply header's request id.
    RequestId,
    /// The next value of the reply's body.
    Body,
}

fn giop_error(message: &str, reason: String) -> ModelError {
    ModelError::Giop {
        message: message.to_owned(),
        reason,
    }
}

/// The CDR kind of a `giop` message's field, or why it has none.
pub(crate) fn argument_kind(message: &str, def: &FieldDef) -> Result<CdrKind, ModelError> {
    if def.computed.is_some() {
        return Err(giop_error(
            message,
            format!(
                "field {:?} is computed, and CDR carries its own lengths",
                def.name
            ),
        ));
    }
    if def.ty == FieldType::Enum && def.width.is_some_and(|width| width != FieldType::U32) {
        return Err(giop_error(
            message,
            format!(
                "enum field {:?} is marshalled as an unsigned long, so its width is u32",
                def.name
            ),
        ));
    }
    CdrKind::of(def.ty).ok_or_else(|| {
        giop_error(
            message,
            format!("field {:?} is a tlv, which has no CDR type", def.name),
        )
    })
}

/// Compile the request a `giop` message is: the message at `index` in the
/// profile, its operation, and its object key.
pub(crate) fn compile_request(
    def: &MessageDef,
    index: usize,
    giop: Option<&GiopDef>,
) -> Result<GiopRequest, ModelError> {
    let object_key = def
        .object_key
        .as_ref()
        .or_else(|| giop.and_then(|giop| giop.object_key.as_ref()))
        .ok_or_else(|| {
            giop_error(
                &def.name,
                "no object key: set `object_key` in [giop] or on the message".to_owned(),
            )
        })?;
    let arguments = def
        .fields
        .iter()
        .map(|field| argument_kind(&def.name, field))
        .collect::<Result<Vec<_>, _>>()?;
    let request_id = u32::try_from(index + 1)
        .map_err(|_| giop_error(&def.name, "too many messages for a request id".to_owned()))?;
    Ok(GiopRequest {
        operation: def.operation.clone().unwrap_or_else(|| def.name.clone()),
        object_key: object_key.as_bytes().to_vec(),
        endian: giop.and_then(|giop| giop.endian).unwrap_or(ByteOrder::Big),
        request_id,
        arguments,
    })
}

/// Compile a `giop` message's response capture.
pub(crate) fn compile_capture(message: &str, def: &CaptureDef) -> Result<CaptureSpec, ModelError> {
    let unused = [
        ("at", def.at.is_some()),
        ("len", def.len.is_some()),
        ("tag", def.tag.is_some()),
        ("tag_width", def.tag_width.is_some()),
        ("len_width", def.len_width.is_some()),
    ];
    if let Some((key, _)) = unused.iter().find(|(_, set)| *set) {
        return Err(giop_error(
            message,
            format!(
                "capture {:?} takes no `{key}`: a GIOP reply's values are read in order, at \
                 their CDR types",
                def.name
            ),
        ));
    }
    let kind = CdrKind::of(def.ty).ok_or_else(|| {
        giop_error(
            message,
            format!("capture {:?} is a tlv, which has no CDR type", def.name),
        )
    })?;
    let field = match def.name.as_str() {
        "reply_status" => ReplyField::ReplyStatus,
        "request_id" => ReplyField::RequestId,
        _ => ReplyField::Body,
    };
    let enum_width_ok = def.width.is_none_or(|width| width == FieldType::U32);
    if (field != ReplyField::Body && kind != CdrKind::ULong) || !enum_width_ok {
        return Err(giop_error(
            message,
            format!(
                "capture {:?} is an unsigned long (u32 or a u32 enum)",
                def.name
            ),
        ));
    }
    let variants = match def.ty {
        FieldType::Enum => Some(def.variants.clone().filter(|v| !v.is_empty()).ok_or_else(
            || ModelError::EnumWithoutVariants {
                message: message.to_owned(),
                field: def.name.clone(),
            },
        )?),
        _ => None,
    };
    Ok(CaptureSpec::Giop {
        field,
        kind,
        variants,
    })
}

/// An argument's value before it is marshalled.
enum Argument {
    Int(u64),
    Bytes(Vec<u8>),
}

fn data_argument(name: &str, spec: &DataSpec, value: &FieldValue) -> Result<Argument, EncodeError> {
    match (spec, value) {
        (DataSpec::Int { .. }, FieldValue::Int { value }) => Ok(Argument::Int(*value)),
        (DataSpec::Enum { variants, .. }, FieldValue::Enum { symbol }) => variants
            .get(symbol)
            .map(|code| Argument::Int(*code))
            .ok_or_else(|| EncodeError::UnknownSymbol {
                field: name.to_owned(),
                symbol: symbol.clone(),
            }),
        (DataSpec::Bytes { max }, FieldValue::Bytes { value }) => match max {
            Some(max) if value.len() > *max => Err(EncodeError::BoundExceeded {
                field: name.to_owned(),
                len: value.len(),
                max: *max,
            }),
            _ => Ok(Argument::Bytes(value.clone())),
        },
        (spec, value) => Err(EncodeError::TypeMismatch {
            field: name.to_owned(),
            expected: spec_kind(spec),
            got: value_kind(value),
        }),
    }
}

fn cdr_value(name: &str, kind: CdrKind, argument: Argument) -> Result<CdrValue, EncodeError> {
    let too_wide = |value: u64| EncodeError::ValueTooWide {
        field: name.to_owned(),
        value,
    };
    Ok(match (kind, argument) {
        (CdrKind::Octet, Argument::Int(value)) => {
            CdrValue::Octet(u8::try_from(value).map_err(|_| too_wide(value))?)
        }
        (CdrKind::UShort, Argument::Int(value)) => {
            CdrValue::UShort(u16::try_from(value).map_err(|_| too_wide(value))?)
        }
        (CdrKind::ULong, Argument::Int(value)) => {
            CdrValue::ULong(u32::try_from(value).map_err(|_| too_wide(value))?)
        }
        (CdrKind::String, Argument::Bytes(bytes)) => CdrValue::RawString(bytes),
        (CdrKind::OctetSequence, Argument::Bytes(bytes)) => {
            CdrValue::Sequence(bytes.into_iter().map(CdrValue::Octet).collect())
        }
        (kind, argument) => {
            return Err(EncodeError::TypeMismatch {
                field: name.to_owned(),
                expected: kind.name(),
                got: match argument {
                    Argument::Int(_) => "int",
                    Argument::Bytes(_) => "bytes",
                },
            })
        }
    })
}

fn endianness(order: ByteOrder) -> Endianness {
    match order {
        ByteOrder::Big => Endianness::Big,
        ByteOrder::Little => Endianness::Little,
    }
}

/// Encode a `giop` message: its fields, as the operation's arguments, in a
/// GIOP 1.2 Request. A reference field takes the value it is bound to.
pub(crate) fn encode_request(
    request: &GiopRequest,
    fields: &[CompiledField],
    values: &BTreeMap<String, FieldValue>,
    bindings: &Bindings,
) -> Result<Vec<u8>, EncodeError> {
    let mut arguments = Vec::with_capacity(fields.len());
    for (field, kind) in fields.iter().zip(&request.arguments) {
        let argument = match &field.role {
            FieldRole::Data(spec) => {
                // An absent optional argument is a request that leaves it out.
                let Some(value) = values.get(&field.name) else {
                    if field.optional {
                        continue;
                    }
                    return Err(EncodeError::MissingValue {
                        field: field.name.clone(),
                    });
                };
                data_argument(&field.name, spec, value)?
            }
            FieldRole::Ref { source, .. } => {
                let unresolved = || EncodeError::Unresolved {
                    field: field.name.clone(),
                    reference: source.clone(),
                };
                match bindings.get(source).ok_or_else(unresolved)? {
                    BoundValue::Bytes { value } => Argument::Bytes(value.clone()),
                    bound => Argument::Int(bound.as_u64().ok_or_else(unresolved)?),
                }
            }
            FieldRole::Computed(_) => {
                return Err(EncodeError::Giop(format!(
                    "field {:?} is computed, which a GIOP request has no place for",
                    field.name
                )))
            }
        };
        arguments.push(cdr_value(&field.name, *kind, argument)?);
    }
    Request12::new(request.object_key.clone(), request.operation.clone())
        .with_endian(endianness(request.endian))
        .with_request_id(request.request_id)
        .with_arguments(arguments)
        .encode()
        .map_err(|error| EncodeError::Giop(error.to_string()))
}

/// A value read from a reply before it is bound.
enum Captured {
    Int(u64),
    Bytes(Vec<u8>),
}

fn read_value(body: &mut CdrReader<'_>, kind: CdrKind) -> Result<Captured, CdrError> {
    Ok(match kind {
        CdrKind::Octet => Captured::Int(u64::from(body.read_octet()?)),
        CdrKind::UShort => Captured::Int(u64::from(body.read_u16()?)),
        CdrKind::ULong => Captured::Int(u64::from(body.read_u32()?)),
        // Its bytes as they are, which need not be UTF-8.
        CdrKind::String => {
            let bytes = body.read_octet_sequence()?;
            match bytes.split_last() {
                Some((0, chars)) => Captured::Bytes(chars.to_vec()),
                _ => {
                    return Err(CdrError::InvalidStringTerminator {
                        offset: body.position().saturating_sub(1),
                    })
                }
            }
        }
        CdrKind::OctetSequence => Captured::Bytes(body.read_octet_sequence()?.to_vec()),
    })
}

/// Extract a `giop` message's captures from `reply`, which must be the GIOP
/// 1.2 Reply to its request.
pub(crate) fn extract_reply(
    message: &str,
    request: &GiopRequest,
    captures: &[CompiledCapture],
    reply: &[u8],
) -> Result<Vec<(String, BoundValue)>, ResponseError> {
    let fail = |reason: String| ResponseError::Giop {
        message: message.to_owned(),
        reason,
    };
    let parsed = parse_message(reply).map_err(|error| fail(error.to_string()))?;
    let parsed = read_reply_1_2(&parsed).map_err(|error| fail(error.to_string()))?;
    if parsed.request_id != request.request_id {
        return Err(fail(format!(
            "it answers request {}, not request {}",
            parsed.request_id, request.request_id
        )));
    }
    let mut body = parsed.body_reader();
    let mut out = Vec::with_capacity(captures.len());
    for capture in captures {
        let CaptureSpec::Giop {
            field,
            kind,
            variants,
        } = &capture.spec
        else {
            return Err(fail(format!(
                "capture {:?} reads bytes at an offset, not a GIOP reply",
                capture.name
            )));
        };
        let value = match field {
            ReplyField::ReplyStatus => Captured::Int(u64::from(u32::from(parsed.status))),
            ReplyField::RequestId => Captured::Int(u64::from(parsed.request_id)),
            ReplyField::Body if parsed.status != ReplyStatus::NoException => {
                return Err(fail(format!(
                    "capture {:?} reads a result, and the reply's status is {:?}",
                    capture.name, parsed.status
                )))
            }
            ReplyField::Body => read_value(&mut body, *kind)
                .map_err(|error| fail(format!("capture {:?}: {error}", capture.name)))?,
        };
        let bound = match (value, variants) {
            (Captured::Int(code), Some(variants)) => {
                let symbol = variants
                    .iter()
                    .find(|(_, c)| **c == code)
                    .map(|(symbol, _)| symbol.clone())
                    .ok_or_else(|| ResponseError::OutOfRange {
                        field: capture.name.clone(),
                        value: code,
                    })?;
                BoundValue::Enum { symbol, code }
            }
            (Captured::Int(value), None) => BoundValue::Int { value },
            (Captured::Bytes(value), _) => BoundValue::Bytes { value },
        };
        out.push((format!("{message}.response.{}", capture.name), bound));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::Framing;
    use crate::model::ProtocolModel;
    use crate::profile::{Profile, ProfileError, ProfileKind};
    use crate::response::extract_reply;
    use crate::testcase::{encode_message, MessageInstance};
    use iiop::dispatch::{DispatchError, Dispatcher, Servant, ServantError, ServantReply};
    use iiop::encode::Reply12;
    use iiop::giop::{read_request_1_2, CompletionStatus};
    use iiop::idl_args::{
        DecodedArgumentValue, DecodedRequestArguments, IdlArgumentDecodeError, IdlOperationCatalog,
    };

    const WAREHOUSE: &str = include_str!("../tests/fixtures/giop-warehouse.toml");
    const WAREHOUSE_IDL: &str = include_str!("../tests/fixtures/warehouse.idl");

    fn warehouse() -> ProtocolModel {
        ProtocolModel::from_profile(&Profile::from_toml(WAREHOUSE).expect("parse"))
            .expect("compile")
    }

    /// A servant that answers every operation with nothing.
    struct Nothing;

    impl Servant for Nothing {
        fn invoke(
            &mut self,
            _request: &DecodedRequestArguments<'_>,
        ) -> Result<ServantReply, ServantError> {
            Ok(ServantReply::empty())
        }
    }

    fn dispatcher() -> Dispatcher<Nothing> {
        let idl = idl_parser::parse_idl(WAREHOUSE_IDL).expect("the IDL parses");
        Dispatcher::new(IdlOperationCatalog::from_idl_file(&idl), Nothing)
    }

    fn frame(model: &ProtocolModel, instance: &MessageInstance, bindings: &Bindings) -> Vec<u8> {
        encode_message(model, instance, bindings)
            .expect("encode")
            .into_bytes()
    }

    fn bound_bin(bin: u64) -> Bindings {
        let mut bindings = Bindings::new();
        bindings.bind("OPEN_BIN.response.bin", BoundValue::Int { value: bin });
        bindings
    }

    #[test]
    fn a_giop_profile_compiles_each_message_to_a_request() {
        let profile = Profile::from_toml(WAREHOUSE).unwrap();
        assert_eq!(profile.kind(), ProfileKind::Giop);
        assert_eq!(
            profile.framing(),
            &Framing::Giop,
            "framed by the GIOP header"
        );
        let model = warehouse();
        let open = model.message("OPEN_BIN").unwrap().giop.clone().unwrap();
        assert_eq!(
            open,
            GiopRequest {
                operation: "open_bin".to_owned(),
                object_key: b"Warehouse".to_vec(),
                endian: ByteOrder::Big,
                request_id: 1,
                arguments: vec![CdrKind::String],
            }
        );
        let store = model.message("STORE").unwrap().giop.clone().unwrap();
        assert_eq!(store.request_id, 2);
        assert_eq!(
            store.arguments,
            [CdrKind::ULong, CdrKind::UShort, CdrKind::ULong]
        );
    }

    #[test]
    fn an_encoded_request_decodes_against_the_operations_idl() {
        let model = warehouse();
        let store = MessageInstance::from_seed(model.message("STORE").unwrap());
        let bytes = frame(&model, &store, &bound_bin(0xcafe_f00d));

        let message = parse_message(&bytes).expect("a GIOP message");
        assert_eq!(message.header.endian, Endianness::Big);
        let request = read_request_1_2(&message).expect("a GIOP 1.2 Request");
        assert_eq!(request.request_id, 2);
        assert_eq!(request.response_flags, 0x03, "a response expected");
        let invocation = dispatcher().handle_frame(&bytes).expect("dispatch");
        assert_eq!(invocation.interface, "Warehouse");
        assert_eq!(invocation.operation, "store");
        assert_eq!(
            invocation
                .arguments
                .iter()
                .map(|argument| argument.value.clone())
                .collect::<Vec<_>>(),
            [
                DecodedArgumentValue::ULong(0xcafe_f00d),
                DecodedArgumentValue::UShort(1),
                DecodedArgumentValue::Long(5),
            ],
            "the captured handle, then the seeds, at their IDL types"
        );

        // A string the mutator made is sent as it is, UTF-8 or not, and an
        // IDL decoder refuses it.
        let mut open = MessageInstance::from_seed(model.message("OPEN_BIN").unwrap());
        let label = |bytes: &[u8]| FieldValue::Bytes {
            value: bytes.to_vec(),
        };
        assert_eq!(
            dispatcher()
                .handle_frame(&frame(&model, &open, &Bindings::new()))
                .unwrap()
                .arguments[0]
                .value,
            DecodedArgumentValue::String("spares".to_owned())
        );
        open.set("label", label(b"sp\xffres"));
        let error = dispatcher()
            .handle_frame(&frame(&model, &open, &Bindings::new()))
            .unwrap_err();
        assert!(
            matches!(
                error,
                DispatchError::Decode(IdlArgumentDecodeError::Cdr {
                    source: CdrError::InvalidUtf8 { .. },
                    ..
                })
            ),
            "{error}"
        );
        // A string past its `max` is refused before it is sent.
        open.set("label", label(&[b'a'; 33]));
        assert!(matches!(
            encode_message(&model, &open, &Bindings::new()),
            Err(EncodeError::BoundExceeded { max: 32, .. })
        ));
    }

    #[test]
    fn a_reply_is_read_header_first_then_its_body_in_order() {
        let model = warehouse();
        let store = model.message("STORE").unwrap();
        for endian in [Endianness::Big, Endianness::Little] {
            let reply = Reply12::new(2, ReplyStatus::NoException)
                .with_endian(endian)
                .with_body(vec![CdrValue::Long(-3)])
                .encode()
                .unwrap();
            let captures = extract_reply(store, &reply).expect("the reply to STORE");
            assert_eq!(
                captures,
                [
                    (
                        "STORE.response.reply_status".to_owned(),
                        BoundValue::Enum {
                            symbol: "no_exception".to_owned(),
                            code: 0
                        }
                    ),
                    (
                        "STORE.response.stocked".to_owned(),
                        BoundValue::Int {
                            value: u64::from(-3i32 as u32)
                        }
                    ),
                ]
            );
        }
    }

    #[test]
    fn a_reply_that_does_not_answer_the_request_is_not_captured() {
        let model = warehouse();
        let store = model.message("STORE").unwrap();
        let error = |reply: &[u8]| extract_reply(store, reply).unwrap_err().to_string();

        let another = Reply12::new(9, ReplyStatus::NoException)
            .with_body(vec![CdrValue::Long(1)])
            .encode()
            .unwrap();
        assert!(
            error(&another).contains("answers request 9, not request 2"),
            "{}",
            error(&another)
        );
        let exception = Reply12::system_exception(
            2,
            "IDL:omg.org/CORBA/BAD_PARAM:1.0",
            0,
            CompletionStatus::CompletedNo,
        )
        .encode()
        .unwrap();
        assert_eq!(
            extract_reply(store, &exception),
            Err(ResponseError::OutOfRange {
                field: "reply_status".to_owned(),
                value: 2
            }),
            "only a reply with no exception advances the session"
        );
        let short = Reply12::new(2, ReplyStatus::NoException).encode().unwrap();
        assert!(
            error(&short).contains("capture \"stocked\""),
            "{}",
            error(&short)
        );
        assert!(error(b"RTPS\x02\x03").contains("truncated GIOP header"));
    }

    const STRINGS: &str = r#"
schema = "bhf.protocol.v1"
kind = "giop"
start = "start"

[giop]
object_key = "Echo"
endian = "little"

[[message]]
name = "NAME"

[[message.field]]
name = "blob"
type = "sequence<octet>"
value = [1, 2, 3]

[message.response]
[[message.response.capture]]
name = "token"
type = "string"

[[message.response.capture]]
name = "request_id"
type = "unsigned long"

[[message]]
name = "GREET"
object_key = "Other"

[[message.field]]
name = "who"
type = "string"
ref = "NAME.response.token"

[[message.field]]
name = "times"
type = "short"
value = -2

[[transition]]
from = "start"
send = "NAME"
to = "named"

[[transition]]
from = "named"
send = "GREET"
to = "named"
"#;

    #[test]
    fn strings_and_octet_sequences_marshal_and_a_captured_string_is_sent_back() {
        let model =
            ProtocolModel::from_profile(&Profile::from_toml(STRINGS).unwrap()).expect("compile");
        let name = model.message("NAME").unwrap();
        assert_eq!(name.giop.as_ref().unwrap().operation, "NAME");
        let bytes = frame(&model, &MessageInstance::from_seed(name), &Bindings::new());
        let message = parse_message(&bytes).unwrap();
        assert_eq!(message.header.endian, Endianness::Little);
        let request = read_request_1_2(&message).unwrap();
        assert_eq!(
            request.arguments_reader().read_octet_sequence().unwrap(),
            [1, 2, 3]
        );

        let reply = Reply12::new(1, ReplyStatus::NoException)
            .with_body(vec![CdrValue::RawString(b"t\xffk".to_vec())])
            .encode()
            .unwrap();
        let captures = extract_reply(name, &reply).unwrap();
        assert_eq!(
            captures[0].1,
            BoundValue::Bytes {
                value: b"t\xffk".to_vec()
            },
            "a string's bytes, without its NUL"
        );
        assert_eq!(captures[1].1, BoundValue::Int { value: 1 });

        let mut bindings = Bindings::new();
        bindings.bind("NAME.response.token", captures[0].1.clone());
        let greet = model.message("GREET").unwrap();
        let bytes = frame(&model, &MessageInstance::from_seed(greet), &bindings);
        let message = parse_message(&bytes).unwrap();
        let request = read_request_1_2(&message).unwrap();
        assert_eq!(request.request_id, 2);
        let iiop::giop::TargetAddress::KeyAddr(key) = request.target else {
            panic!("a KeyAddr target");
        };
        assert_eq!(key, b"Other");
        let mut arguments = request.arguments_reader();
        assert_eq!(arguments.read_octet_sequence().unwrap(), b"t\xffk\0");
        assert_eq!(arguments.read_i16().unwrap(), -2, "a negative short seed");
    }

    #[test]
    fn a_giop_profile_refuses_what_cdr_has_no_place_for() {
        let giop = |extra: &str| {
            format!(
                "schema = \"bhf.protocol.v1\"\nkind = \"giop\"\n[giop]\nobject_key = \"K\"\n\
                 [[message]]\nname = \"M\"\n{extra}"
            )
        };
        for (profile, wanted) in [
            (
                giop(
                    "[[message.field]]\nname = \"n\"\ntype = \"u16\"\ncomputed = \"length(s)\"\n\
                      [[message.field]]\nname = \"s\"\ntype = \"string\"",
                ),
                "field \"n\" is computed",
            ),
            (
                giop("[[message.field]]\nname = \"t\"\ntype = \"tlv\"\ntag = 1"),
                "field \"t\" is a tlv",
            ),
            (
                giop(
                    "[[message.field]]\nname = \"e\"\ntype = \"enum\"\nwidth = \"u16\"\n\
                      variants = { a = 0 }",
                ),
                "its width is u32",
            ),
            (
                giop(
                    "[message.response]\n[[message.response.capture]]\nname = \"r\"\n\
                      type = \"long\"\nat = 4",
                ),
                "takes no `at`",
            ),
            (
                giop(
                    "[message.response]\n[[message.response.capture]]\nname = \"reply_status\"\n\
                      type = \"string\"",
                ),
                "is an unsigned long",
            ),
            (
                "schema = \"bhf.protocol.v1\"\nkind = \"giop\"\n[[message]]\nname = \"M\""
                    .to_owned(),
                "no object key",
            ),
        ] {
            let parsed = Profile::from_toml(&profile).expect("parse");
            let error = ProtocolModel::from_profile(&parsed)
                .unwrap_err()
                .to_string();
            assert!(error.contains(wanted), "{profile}\n=> {error}");
        }

        // GIOP's keys in a binary profile, and another framing in a giop one.
        let binary = "schema = \"bhf.protocol.v1\"\n";
        assert_eq!(
            Profile::from_toml(&format!("{binary}[giop]\nobject_key = \"K\"")).unwrap_err(),
            ProfileError::NotGiop {
                key: "[giop]".to_owned()
            }
        );
        assert_eq!(
            Profile::from_toml(&format!(
                "{binary}[[message]]\nname = \"M\"\noperation = \"op\""
            ))
            .unwrap_err(),
            ProfileError::NotGiop {
                key: "message M's `operation`".to_owned()
            }
        );
        let framed = Profile::from_toml(
            &giop("").replace("[[message]]", "[framing]\nkind = \"raw\"\n[[message]]"),
        )
        .unwrap_err();
        assert!(
            framed.to_string().contains("framed by their GIOP header"),
            "{framed}"
        );
    }
}
