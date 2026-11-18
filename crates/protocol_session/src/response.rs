// SPDX-License-Identifier: Apache-2.0

//! Response-field extraction.
//!
//! After a request is sent the target returns a reply; a message's compiled
//! response captures decode typed values (a per-session handle / id / nonce /
//! status) out of the reply at fixed offsets. Extraction is bounded and total:
//! a reply too short for a capture yields [`ResponseError::Truncated`] with the
//! byte counts, and an enum value with no matching symbol yields
//! [`ResponseError::OutOfRange`] — never a panic and never a silent default.
//! A `giop` message's reply is a GIOP Reply, whose values [`extract_reply`]
//! reads in order (see [`crate::giop`]).

use fuzz_engine_builtin::{Endian, IntWidth};

use crate::binding::BoundValue;
use crate::model::CaptureSpec;
use crate::model::{CompiledCapture, CompiledMessage};

/// Extract every response capture of `message` from `reply`: the values of
/// its GIOP Reply for a `giop` message, and the slices at the captures'
/// offsets otherwise.
pub fn extract_reply(
    message: &CompiledMessage,
    reply: &[u8],
) -> Result<Vec<(String, BoundValue)>, ResponseError> {
    match &message.giop {
        Some(request) => {
            crate::giop::extract_reply(&message.name, request, &message.response, reply)
        }
        None => extract(&message.name, &message.response, reply),
    }
}

/// Extract every response capture of `message` from `reply`, returning
/// `(source_key, value)` pairs where `source_key` is `MSG.response.NAME` — the
/// key a later request's reference resolves against.
pub fn extract(
    message: &str,
    captures: &[CompiledCapture],
    reply: &[u8],
) -> Result<Vec<(String, BoundValue)>, ResponseError> {
    let mut out = Vec::with_capacity(captures.len());
    for capture in captures {
        let value = extract_one(message, capture, reply)?;
        out.push((format!("{message}.response.{}", capture.name), value));
    }
    Ok(out)
}

fn extract_one(
    message: &str,
    capture: &CompiledCapture,
    reply: &[u8],
) -> Result<BoundValue, ResponseError> {
    match &capture.spec {
        CaptureSpec::Giop { .. } => Err(ResponseError::Giop {
            message: message.to_owned(),
            reason: format!(
                "capture {:?} reads a GIOP reply, which extract_reply reads",
                capture.name
            ),
        }),
        CaptureSpec::Int { width, endian } => {
            let value = read_uint(reply, capture.at, *width, *endian, &capture.name)?;
            Ok(BoundValue::Int { value })
        }
        CaptureSpec::Enum {
            width,
            endian,
            variants,
        } => {
            let code = read_uint(reply, capture.at, *width, *endian, &capture.name)?;
            let symbol = variants
                .iter()
                .find(|(_, c)| **c == code)
                .map(|(symbol, _)| symbol.clone())
                .ok_or_else(|| ResponseError::OutOfRange {
                    field: capture.name.clone(),
                    value: code,
                })?;
            Ok(BoundValue::Enum { symbol, code })
        }
        CaptureSpec::Tlv {
            tag,
            tag_width,
            len_width,
            endian,
        } => {
            let mut at = capture.at;
            loop {
                if at >= reply.len() {
                    return Err(ResponseError::TlvNotFound {
                        field: capture.name.clone(),
                        tag: *tag,
                    });
                }
                let record_tag = read_uint(reply, at, *tag_width, *endian, &capture.name)?;
                let len_at = at + tag_width.size();
                let len = read_uint(reply, len_at, *len_width, *endian, &capture.name)?;
                let start = len_at + len_width.size();
                let end = usize::try_from(len)
                    .ok()
                    .and_then(|len| start.checked_add(len))
                    .ok_or(ResponseError::Truncated {
                        field: capture.name.clone(),
                        needed: usize::MAX,
                        got: reply.len(),
                    })?;
                let value = reply.get(start..end).ok_or(ResponseError::Truncated {
                    field: capture.name.clone(),
                    needed: end,
                    got: reply.len(),
                })?;
                if tag.is_none_or(|tag| tag == record_tag) {
                    return Ok(BoundValue::Bytes {
                        value: value.to_vec(),
                    });
                }
                at = end;
            }
        }
        CaptureSpec::Bytes { len } => {
            let end = capture
                .at
                .checked_add(*len)
                .ok_or(ResponseError::Truncated {
                    field: capture.name.clone(),
                    needed: usize::MAX,
                    got: reply.len(),
                })?;
            let slice = reply.get(capture.at..end).ok_or(ResponseError::Truncated {
                field: capture.name.clone(),
                needed: end,
                got: reply.len(),
            })?;
            Ok(BoundValue::Bytes {
                value: slice.to_vec(),
            })
        }
    }
}

fn read_uint(
    reply: &[u8],
    at: usize,
    width: IntWidth,
    endian: Endian,
    field: &str,
) -> Result<u64, ResponseError> {
    let end = at
        .checked_add(width.size())
        .ok_or(ResponseError::Truncated {
            field: field.to_owned(),
            needed: usize::MAX,
            got: reply.len(),
        })?;
    let slice = reply.get(at..end).ok_or(ResponseError::Truncated {
        field: field.to_owned(),
        needed: end,
        got: reply.len(),
    })?;
    Ok(match (width, endian) {
        (IntWidth::U8, _) => u64::from(slice[0]),
        (IntWidth::U16, Endian::Big) => u64::from(u16::from_be_bytes([slice[0], slice[1]])),
        (IntWidth::U16, Endian::Little) => u64::from(u16::from_le_bytes([slice[0], slice[1]])),
        (IntWidth::U32, Endian::Big) => {
            u64::from(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
        }
        (IntWidth::U32, Endian::Little) => {
            u64::from(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
        }
    })
}

/// Errors from response extraction. Both variants name the offending capture.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResponseError {
    #[error("response capture {field:?} needs {needed} byte(s) but the reply has {got}")]
    Truncated {
        field: String,
        needed: usize,
        got: usize,
    },
    #[error("enum response capture {field:?} saw out-of-range value {value}")]
    OutOfRange { field: String, value: u64 },
    #[error("tlv response capture {field:?} found no record{}", tag.map(|tag| format!(" with tag {tag}")).unwrap_or_default())]
    TlvNotFound { field: String, tag: Option<u64> },
    /// A `giop` message's reply is not the GIOP Reply its captures read.
    #[error("the reply to giop message {message}: {reason}")]
    Giop { message: String, reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ProtocolModel;
    use crate::profile::Profile;

    const TOY: &str = include_str!("../tests/fixtures/toy-open-write.toml");

    fn open_captures() -> Vec<CompiledCapture> {
        let model = ProtocolModel::from_profile(&Profile::from_toml(TOY).unwrap()).unwrap();
        model.message("OPEN").unwrap().response.clone()
    }

    #[test]
    fn extracts_u32_handle_from_reply() {
        // reply = [handle:u32 BE][trailing status byte]
        let mut reply = 0xDEAD_BEEFu32.to_be_bytes().to_vec();
        reply.push(0x00);
        let bound = extract("OPEN", &open_captures(), &reply).expect("extract");
        assert_eq!(bound.len(), 1);
        assert_eq!(bound[0].0, "OPEN.response.handle");
        assert_eq!(bound[0].1, BoundValue::Int { value: 0xDEAD_BEEF });
    }

    #[test]
    fn truncated_reply_is_descriptive() {
        let reply = vec![0x00, 0x11]; // only 2 bytes, handle needs 4
        let err = extract("OPEN", &open_captures(), &reply).unwrap_err();
        assert_eq!(
            err,
            ResponseError::Truncated {
                field: "handle".to_owned(),
                needed: 4,
                got: 2,
            }
        );
    }

    #[test]
    fn enum_response_field_maps_symbol_and_rejects_unknown() {
        let variants: std::collections::BTreeMap<String, u64> =
            [("ok".to_owned(), 0u64), ("busy".to_owned(), 1u64)]
                .into_iter()
                .collect();
        let capture = CompiledCapture {
            name: "state".to_owned(),
            at: 0,
            spec: CaptureSpec::Enum {
                width: IntWidth::U8,
                endian: Endian::Big,
                variants,
            },
        };
        let ok = extract("REPLY", std::slice::from_ref(&capture), &[1]).expect("maps");
        assert_eq!(
            ok[0].1,
            BoundValue::Enum {
                symbol: "busy".to_owned(),
                code: 1
            }
        );
        let err = extract("REPLY", std::slice::from_ref(&capture), &[9]).unwrap_err();
        assert_eq!(
            err,
            ResponseError::OutOfRange {
                field: "state".to_owned(),
                value: 9
            }
        );
    }
}
