// SPDX-License-Identifier: Apache-2.0

//! Structure-aware binary framing with **computed fields** (HDF-7, deliverable 1).
//!
//! The text CFG in [`crate::grammar`] can only concatenate literal and
//! non-terminal runs; it has no notion of a byte position, so it cannot keep a
//! length prefix, a CRC, a TLV length, or an offset/back-reference consistent
//! after a mutation. A naive byte fuzzer that flips a payload byte therefore
//! fails the very first integrity gate of a length/checksum-framed protocol and
//! never reaches the parser body.
//!
//! # Design choice: typed descriptor + fix-up pass (option (b))
//!
//! Rather than bolt semantic actions onto the CFG expander — which would require
//! attaching positional identity, numeric width/endianness, and a post-order
//! evaluation to a grammar that is fundamentally position-free — this module
//! takes the *typed message descriptor + fix-up pass* route. This mirrors how
//! structure-aware fuzzers in the wild handle derived fields (libFuzzer /
//! AFL++ `afl_custom_post_process`, `libprotobuf-mutator`, FormatFuzzer): mutate
//! a structured value freely, then a serializer recomputes the derived fields.
//!
//! A [`Message`] is an ordered list of typed [`Field`]s. [`Message::encode`]
//! lays the bytes out, records every field's byte span, and computes the derived
//! fields once. The engine's byte-mutation pipeline can then flip payload bytes
//! and call [`EncodedMessage::fixup_in_place`] to make the frame internally
//! consistent again, and [`EncodedMessage::verify`] models the target's
//! integrity gate. [`frame_seed_corpus`] returns the `Vec<Vec<u8>>` shape the
//! CLI seed loader consumes, so a descriptor set seeds a campaign directly.
//!
//! All sizes are bounded: a message declares a `max_len`, encoding refuses to
//! exceed it, and every derived value is width-checked before it is written.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Range;

/// Default upper bound on a single encoded frame (bytes). Chosen to match the
/// engine's typical `--max-len` ceiling while keeping encoding work bounded.
pub const DEFAULT_MAX_LEN: usize = 64 * 1024;

/// Byte order for a multi-byte computed field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endian {
    Big,
    Little,
}

/// Width of an integer-valued computed field. Bounded to the widths real
/// length/offset/checksum fields use, so a value can never need more than 4
/// bytes of layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntWidth {
    U8,
    U16,
    U32,
}

impl IntWidth {
    pub fn size(self) -> usize {
        match self {
            IntWidth::U8 => 1,
            IntWidth::U16 => 2,
            IntWidth::U32 => 4,
        }
    }

    /// The inclusive maximum value this width can hold.
    fn max_value(self) -> u64 {
        match self {
            IntWidth::U8 => u64::from(u8::MAX),
            IntWidth::U16 => u64::from(u16::MAX),
            IntWidth::U32 => u64::from(u32::MAX),
        }
    }
}

/// A checksum/CRC algorithm over a covered byte range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumKind {
    /// CRC-32/ISO-HDLC (zlib / PNG / Ethernet): reflected, poly `0xEDB88320`,
    /// init `0xFFFFFFFF`, xorout `0xFFFFFFFF`. Check value of `"123456789"` is
    /// `0xCBF43926`.
    Crc32,
    /// CRC-16/CCITT-FALSE: poly `0x1021`, init `0xFFFF`, no reflection, xorout
    /// `0x0000`. Check value of `"123456789"` is `0x29B1`.
    Crc16Ccitt,
    /// 8-bit modular sum of the covered bytes.
    Sum8,
    /// 8-bit XOR (longitudinal redundancy) of the covered bytes.
    Xor8,
}

impl ChecksumKind {
    /// Layout width of the checksum output field.
    pub fn output_width(self) -> IntWidth {
        match self {
            ChecksumKind::Crc32 => IntWidth::U32,
            ChecksumKind::Crc16Ccitt => IntWidth::U16,
            ChecksumKind::Sum8 | ChecksumKind::Xor8 => IntWidth::U8,
        }
    }

    fn compute(self, bytes: &[u8]) -> u64 {
        match self {
            ChecksumKind::Crc32 => u64::from(crc32(bytes)),
            ChecksumKind::Crc16Ccitt => u64::from(crc16_ccitt(bytes)),
            ChecksumKind::Sum8 => u64::from(bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))),
            ChecksumKind::Xor8 => u64::from(bytes.iter().fold(0u8, |acc, &b| acc ^ b)),
        }
    }
}

/// One field of a [`Message`]. Concrete data fields (`Bytes`, `Tlv`) carry their
/// own bytes; derived fields (`Length`, `Checksum`, `Offset`) are placeholders
/// recomputed by the fix-up pass from the named fields they reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Field {
    /// Opaque payload bytes — the mutable part of the frame.
    Bytes { name: String, value: Vec<u8> },
    /// A tag-length-value record: a fixed-width `tag`, a fixed-width length
    /// (computed from `value`), then `value`. The length is a computed field.
    Tlv {
        name: String,
        tag: u32,
        tag_width: IntWidth,
        len_width: IntWidth,
        endian: Endian,
        value: Vec<u8>,
    },
    /// A length field whose value is the total byte length of the `covers`
    /// fields, taken in declaration order.
    Length {
        name: String,
        width: IntWidth,
        endian: Endian,
        covers: Vec<String>,
    },
    /// A checksum/CRC over the concatenated bytes of the `covers` fields.
    Checksum {
        name: String,
        kind: ChecksumKind,
        endian: Endian,
        covers: Vec<String>,
    },
    /// A back-reference: the byte offset (from frame start) of `target`.
    Offset {
        name: String,
        width: IntWidth,
        endian: Endian,
        target: String,
    },
}

impl Field {
    pub fn name(&self) -> &str {
        match self {
            Field::Bytes { name, .. }
            | Field::Tlv { name, .. }
            | Field::Length { name, .. }
            | Field::Checksum { name, .. }
            | Field::Offset { name, .. } => name,
        }
    }

    // --- terse constructors, so descriptors read cleanly ---

    pub fn bytes(name: &str, value: impl Into<Vec<u8>>) -> Self {
        Field::Bytes {
            name: name.to_owned(),
            value: value.into(),
        }
    }

    pub fn tlv(name: &str, tag: u32, endian: Endian, value: impl Into<Vec<u8>>) -> Self {
        Field::Tlv {
            name: name.to_owned(),
            tag,
            tag_width: IntWidth::U16,
            len_width: IntWidth::U16,
            endian,
            value: value.into(),
        }
    }

    pub fn length(name: &str, width: IntWidth, endian: Endian, covers: &[&str]) -> Self {
        Field::Length {
            name: name.to_owned(),
            width,
            endian,
            covers: covers.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    pub fn checksum(name: &str, kind: ChecksumKind, endian: Endian, covers: &[&str]) -> Self {
        Field::Checksum {
            name: name.to_owned(),
            kind,
            endian,
            covers: covers.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    pub fn offset(name: &str, width: IntWidth, endian: Endian, target: &str) -> Self {
        Field::Offset {
            name: name.to_owned(),
            width,
            endian,
            target: target.to_owned(),
        }
    }
}

/// A typed binary message descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    fields: Vec<Field>,
    max_len: usize,
}

impl Message {
    pub fn new(fields: Vec<Field>) -> Self {
        Self {
            fields,
            max_len: DEFAULT_MAX_LEN,
        }
    }

    pub fn with_max_len(mut self, max_len: usize) -> Self {
        self.max_len = max_len;
        self
    }

    pub fn fields(&self) -> &[Field] {
        &self.fields
    }

    /// Lay the message out into bytes, record every field's span, resolve the
    /// derived-field references, and compute the derived fields once. Returns a
    /// re-fixable [`EncodedMessage`].
    pub fn encode(&self) -> Result<EncodedMessage, BinFrameError> {
        if self.fields.is_empty() {
            return Err(BinFrameError::EmptyMessage);
        }

        let mut bytes: Vec<u8> = Vec::new();
        let mut spans: BTreeMap<String, Range<usize>> = BTreeMap::new();
        // Derivations captured with field-name references; resolved to byte
        // ranges after the whole layout is known.
        let mut pending: Vec<PendingDerivation> = Vec::new();

        for field in &self.fields {
            let name = field.name().to_owned();
            if spans.contains_key(&name) {
                return Err(BinFrameError::DuplicateField(name));
            }
            let start = bytes.len();
            match field {
                Field::Bytes { value, .. } => bytes.extend_from_slice(value),
                Field::Tlv {
                    tag,
                    tag_width,
                    len_width,
                    endian,
                    value,
                    ..
                } => {
                    // tag
                    write_uint_vec(&mut bytes, *tag_width, *endian, u64::from(*tag)).map_err(
                        |_| BinFrameError::ValueTooWide {
                            field: format!("{name}.tag"),
                            value: u64::from(*tag),
                            width: *tag_width,
                        },
                    )?;
                    // length placeholder
                    let len_start = bytes.len();
                    bytes.resize(len_start + len_width.size(), 0);
                    let len_out = len_start..bytes.len();
                    // value
                    let value_start = bytes.len();
                    bytes.extend_from_slice(value);
                    let value_range = value_start..bytes.len();
                    pending.push(PendingDerivation::TlvLength {
                        out: len_out,
                        width: *len_width,
                        endian: *endian,
                        value: value_range,
                    });
                }
                Field::Length { width, .. } => {
                    bytes.resize(start + width.size(), 0);
                }
                Field::Checksum { kind, .. } => {
                    bytes.resize(start + kind.output_width().size(), 0);
                }
                Field::Offset { width, .. } => {
                    bytes.resize(start + width.size(), 0);
                }
            }
            spans.insert(name, start..bytes.len());
        }

        if bytes.len() > self.max_len {
            return Err(BinFrameError::MessageTooLong {
                len: bytes.len(),
                max_len: self.max_len,
            });
        }

        // Resolve name references now that every span is known.
        for field in &self.fields {
            match field {
                Field::Length {
                    name,
                    width,
                    endian,
                    covers,
                } => {
                    let out = spans[name].clone();
                    let covered = resolve_covers(name, covers, &spans)?;
                    pending.push(PendingDerivation::Length {
                        out,
                        width: *width,
                        endian: *endian,
                        covers: covered,
                    });
                }
                Field::Checksum {
                    name,
                    kind,
                    endian,
                    covers,
                } => {
                    let out = spans[name].clone();
                    let covered = resolve_covers(name, covers, &spans)?;
                    pending.push(PendingDerivation::Checksum {
                        out,
                        kind: *kind,
                        endian: *endian,
                        covers: covered,
                    });
                }
                Field::Offset {
                    name,
                    width,
                    endian,
                    target,
                } => {
                    let out = spans[name].clone();
                    let target_span =
                        spans
                            .get(target)
                            .ok_or_else(|| BinFrameError::UnknownReference {
                                field: name.clone(),
                                referenced: target.clone(),
                            })?;
                    pending.push(PendingDerivation::Offset {
                        out,
                        width: *width,
                        endian: *endian,
                        target_start: target_span.start,
                    });
                }
                Field::Bytes { .. } | Field::Tlv { .. } => {}
            }
        }

        let mut encoded = EncodedMessage {
            bytes,
            spans,
            derivations: pending,
        };
        encoded.fixup_in_place()?;
        Ok(encoded)
    }
}

fn resolve_covers(
    field: &str,
    covers: &[String],
    spans: &BTreeMap<String, Range<usize>>,
) -> Result<Vec<Range<usize>>, BinFrameError> {
    if covers.is_empty() {
        return Err(BinFrameError::EmptyCoverage {
            field: field.to_owned(),
        });
    }
    covers
        .iter()
        .map(|name| {
            spans
                .get(name)
                .cloned()
                .ok_or_else(|| BinFrameError::UnknownReference {
                    field: field.to_owned(),
                    referenced: name.clone(),
                })
        })
        .collect()
}

/// A laid-out message plus the recipe to recompute its derived fields. The byte
/// buffer can be mutated in place (preserving its length); calling
/// [`EncodedMessage::fixup_in_place`] restores every length/checksum/offset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedMessage {
    bytes: Vec<u8>,
    spans: BTreeMap<String, Range<usize>>,
    derivations: Vec<PendingDerivation>,
}

impl EncodedMessage {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The byte range a named field occupies in the current layout.
    pub fn span(&self, name: &str) -> Option<Range<usize>> {
        self.spans.get(name).cloned()
    }

    /// Overwrite the bytes of a named field in place. The replacement must be
    /// exactly the field's current width, so the layout — and therefore every
    /// derivation's byte range — stays valid. Callers who need to change a
    /// field's length rebuild the [`Message`] and re-[`encode`](Message::encode)
    /// instead.
    pub fn set_field_bytes(&mut self, name: &str, value: &[u8]) -> Result<(), BinFrameError> {
        let span = self
            .spans
            .get(name)
            .cloned()
            .ok_or_else(|| BinFrameError::UnknownField(name.to_owned()))?;
        if value.len() != span.len() {
            return Err(BinFrameError::FieldWidthMismatch {
                field: name.to_owned(),
                expected: span.len(),
                actual: value.len(),
            });
        }
        self.bytes[span].copy_from_slice(value);
        Ok(())
    }

    /// Recompute every derived field on the current bytes. Position/length
    /// derived fields (length, offset, TLV length) are written first, then
    /// checksums, so a checksum that covers a length/offset field sees its
    /// final value. This is the post-mutation consistency step for the engine's
    /// byte-mutation pipeline.
    pub fn fixup_in_place(&mut self) -> Result<(), BinFrameError> {
        let derivations = std::mem::take(&mut self.derivations);
        let result = self.apply_derivations(&derivations);
        self.derivations = derivations;
        result
    }

    fn apply_derivations(
        &mut self,
        derivations: &[PendingDerivation],
    ) -> Result<(), BinFrameError> {
        // Pass 1: everything except checksums (content-independent, so a
        // checksum computed in pass 2 covers their settled bytes).
        for derivation in derivations {
            if !matches!(derivation, PendingDerivation::Checksum { .. }) {
                let (out, width, endian, value) = derivation.evaluate(&self.bytes);
                write_uint(&mut self.bytes, out, width, endian, value)?;
            }
        }
        // Pass 2: checksums.
        for derivation in derivations {
            if matches!(derivation, PendingDerivation::Checksum { .. }) {
                let (out, width, endian, value) = derivation.evaluate(&self.bytes);
                write_uint(&mut self.bytes, out, width, endian, value)?;
            }
        }
        Ok(())
    }

    /// True when every derived field in the current bytes already holds its
    /// computed value — i.e. the frame would pass the target's integrity gate.
    pub fn verify(&self) -> bool {
        self.derivations.iter().all(|derivation| {
            let (out, width, _endian, value) = derivation.evaluate(&self.bytes);
            match read_uint(&self.bytes, out, width, derivation.endian()) {
                Some(actual) => actual == value,
                None => false,
            }
        })
    }

    /// Check a *foreign* buffer against this message's layout: the buffer must
    /// have the same length and hold consistent derived fields. This is the
    /// integrity gate a naive byte fuzzer must pass — and cannot, because it
    /// does not recompute the CRC/length after mutating the payload.
    pub fn verify_bytes(&self, buf: &[u8]) -> bool {
        if buf.len() != self.bytes.len() {
            return false;
        }
        self.derivations.iter().all(|derivation| {
            let (out, width, endian, value) = derivation.evaluate(buf);
            match read_uint(buf, out, width, endian) {
                Some(actual) => actual == value,
                None => false,
            }
        })
    }
}

/// A derivation resolved to concrete byte ranges.
#[derive(Clone, Debug, PartialEq, Eq)]
enum PendingDerivation {
    Length {
        out: Range<usize>,
        width: IntWidth,
        endian: Endian,
        covers: Vec<Range<usize>>,
    },
    Checksum {
        out: Range<usize>,
        kind: ChecksumKind,
        endian: Endian,
        covers: Vec<Range<usize>>,
    },
    Offset {
        out: Range<usize>,
        width: IntWidth,
        endian: Endian,
        target_start: usize,
    },
    TlvLength {
        out: Range<usize>,
        width: IntWidth,
        endian: Endian,
        value: Range<usize>,
    },
}

impl PendingDerivation {
    /// Returns `(out_range, width, endian, computed_value)`.
    fn evaluate(&self, bytes: &[u8]) -> (Range<usize>, IntWidth, Endian, u64) {
        match self {
            PendingDerivation::Length {
                out,
                width,
                endian,
                covers,
            } => {
                let total: u64 = covers.iter().map(|range| range.len() as u64).sum();
                (out.clone(), *width, *endian, total)
            }
            PendingDerivation::Checksum {
                out,
                kind,
                endian,
                covers,
            } => {
                let mut data = Vec::new();
                for range in covers {
                    data.extend_from_slice(&bytes[range.clone()]);
                }
                (
                    out.clone(),
                    kind.output_width(),
                    *endian,
                    kind.compute(&data),
                )
            }
            PendingDerivation::Offset {
                out,
                width,
                endian,
                target_start,
            } => (out.clone(), *width, *endian, *target_start as u64),
            PendingDerivation::TlvLength {
                out,
                width,
                endian,
                value,
            } => (out.clone(), *width, *endian, value.len() as u64),
        }
    }

    fn endian(&self) -> Endian {
        match self {
            PendingDerivation::Length { endian, .. }
            | PendingDerivation::Checksum { endian, .. }
            | PendingDerivation::Offset { endian, .. }
            | PendingDerivation::TlvLength { endian, .. } => *endian,
        }
    }
}

/// Encode a set of descriptors into the `Vec<Vec<u8>>` seed shape the CLI seed
/// loader consumes. Each descriptor yields one internally-consistent frame,
/// giving a fuzz campaign valid starting frames that already pass length/CRC
/// gates.
pub fn frame_seed_corpus(messages: &[Message]) -> Result<Vec<Vec<u8>>, BinFrameError> {
    messages
        .iter()
        .map(|message| message.encode().map(EncodedMessage::into_bytes))
        .collect()
}

/// Errors from descriptor validation or encoding. Every variant names the field
/// at fault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BinFrameError {
    EmptyMessage,
    DuplicateField(String),
    UnknownField(String),
    EmptyCoverage {
        field: String,
    },
    UnknownReference {
        field: String,
        referenced: String,
    },
    ValueTooWide {
        field: String,
        value: u64,
        width: IntWidth,
    },
    FieldWidthMismatch {
        field: String,
        expected: usize,
        actual: usize,
    },
    MessageTooLong {
        len: usize,
        max_len: usize,
    },
}

impl fmt::Display for BinFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BinFrameError::EmptyMessage => write!(f, "binary frame descriptor has no fields"),
            BinFrameError::DuplicateField(name) => {
                write!(f, "duplicate field name {name:?} in frame descriptor")
            }
            BinFrameError::UnknownField(name) => {
                write!(f, "no field named {name:?} in encoded frame")
            }
            BinFrameError::EmptyCoverage { field } => {
                write!(f, "computed field {field:?} covers no fields")
            }
            BinFrameError::UnknownReference { field, referenced } => write!(
                f,
                "computed field {field:?} references undefined field {referenced:?}"
            ),
            BinFrameError::ValueTooWide {
                field,
                value,
                width,
            } => write!(
                f,
                "computed value {value} for field {field:?} does not fit in {width:?}"
            ),
            BinFrameError::FieldWidthMismatch {
                field,
                expected,
                actual,
            } => write!(
                f,
                "replacement for field {field:?} is {actual} byte(s), field is {expected}"
            ),
            BinFrameError::MessageTooLong { len, max_len } => write!(
                f,
                "encoded frame is {len} byte(s), exceeding the {max_len}-byte bound"
            ),
        }
    }
}

impl std::error::Error for BinFrameError {}

fn write_uint(
    buf: &mut [u8],
    range: Range<usize>,
    width: IntWidth,
    endian: Endian,
    value: u64,
) -> Result<(), BinFrameError> {
    if value > width.max_value() {
        return Err(BinFrameError::ValueTooWide {
            field: format!("<offset {}>", range.start),
            value,
            width,
        });
    }
    let encoded = encode_uint(width, endian, value);
    buf[range].copy_from_slice(&encoded);
    Ok(())
}

fn write_uint_vec(
    buf: &mut Vec<u8>,
    width: IntWidth,
    endian: Endian,
    value: u64,
) -> Result<(), ()> {
    if value > width.max_value() {
        return Err(());
    }
    buf.extend_from_slice(&encode_uint(width, endian, value));
    Ok(())
}

fn encode_uint(width: IntWidth, endian: Endian, value: u64) -> Vec<u8> {
    match (width, endian) {
        (IntWidth::U8, _) => vec![value as u8],
        (IntWidth::U16, Endian::Big) => (value as u16).to_be_bytes().to_vec(),
        (IntWidth::U16, Endian::Little) => (value as u16).to_le_bytes().to_vec(),
        (IntWidth::U32, Endian::Big) => (value as u32).to_be_bytes().to_vec(),
        (IntWidth::U32, Endian::Little) => (value as u32).to_le_bytes().to_vec(),
    }
}

fn read_uint(buf: &[u8], range: Range<usize>, width: IntWidth, endian: Endian) -> Option<u64> {
    let slice = buf.get(range)?;
    if slice.len() != width.size() {
        return None;
    }
    Some(match (width, endian) {
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

/// CRC-32/ISO-HDLC (zlib). Reflected algorithm, poly `0xEDB88320`, init/xorout
/// `0xFFFFFFFF`. Bounded: one pass over `bytes`.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// CRC-16/CCITT-FALSE. Poly `0x1021`, init `0xFFFF`, no reflection, xorout `0`.
/// Bounded: one pass over `bytes`.
pub fn crc16_ccitt(bytes: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for &byte in bytes {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::MutationRng;

    #[test]
    fn crc32_matches_standard_check_vector() {
        // The canonical CRC-32 check value for the ASCII string "123456789".
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0x0000_0000);
    }

    #[test]
    fn crc16_ccitt_matches_standard_check_vector() {
        // The canonical CRC-16/CCITT-FALSE check value for "123456789".
        assert_eq!(crc16_ccitt(b"123456789"), 0x29B1);
    }

    /// Build the acceptance fixture: a big-endian frame of
    /// `[u16 length][payload][u32 CRC-32]`, where the length covers the payload
    /// and the CRC covers length+payload.
    fn length_crc_message(payload: &[u8]) -> Message {
        Message::new(vec![
            Field::length("length", IntWidth::U16, Endian::Big, &["payload"]),
            Field::bytes("payload", payload.to_vec()),
            Field::checksum(
                "crc",
                ChecksumKind::Crc32,
                Endian::Big,
                &["length", "payload"],
            ),
        ])
    }

    #[test]
    fn length_and_crc_are_computed_on_encode() {
        let payload = b"radar-track-0xDEADBEEF";
        let encoded = length_crc_message(payload).encode().expect("encode");

        // The length field holds the payload length, big-endian.
        let length_span = encoded.span("length").expect("length span");
        let stored_len = u16::from_be_bytes([
            encoded.bytes()[length_span.start],
            encoded.bytes()[length_span.start + 1],
        ]);
        assert_eq!(usize::from(stored_len), payload.len());

        // The CRC field holds CRC-32 over length+payload.
        let crc_span = encoded.span("crc").expect("crc span");
        let covered = &encoded.bytes()[..crc_span.start];
        let stored_crc = u32::from_be_bytes([
            encoded.bytes()[crc_span.start],
            encoded.bytes()[crc_span.start + 1],
            encoded.bytes()[crc_span.start + 2],
            encoded.bytes()[crc_span.start + 3],
        ]);
        assert_eq!(stored_crc, crc32(covered));
        assert!(encoded.verify(), "freshly encoded frame must verify");
    }

    #[test]
    fn fixup_reaches_past_crc_gate_but_naive_mutation_does_not() {
        // Acceptance criterion: a generated/fixed-up frame is accepted past the
        // integrity check; a frame whose payload was flipped without a re-fixup
        // (what a naive byte fuzzer produces) is rejected by the CRC gate.
        let mut encoded = length_crc_message(b"initial-payload-value")
            .encode()
            .expect("encode");
        assert!(encoded.verify());

        // A naive byte fuzzer flips a payload byte and stops there.
        let payload_span = encoded.span("payload").expect("payload span");
        encoded.bytes[payload_span.start] ^= 0xFF;
        assert!(
            !encoded.verify(),
            "payload changed but CRC not recomputed: the gate must reject it"
        );

        // The structure-aware path recomputes the derived fields.
        encoded.fixup_in_place().expect("fixup");
        assert!(
            encoded.verify(),
            "after fix-up the frame must pass the CRC gate"
        );
    }

    #[test]
    fn naive_random_buffer_is_rejected_by_the_gate() {
        // A random buffer of the right length (a naive byte fuzzer's output)
        // does not satisfy the length+CRC gate. Deterministic RNG seed so the
        // assertion is a fixed, reproducible outcome.
        let encoded = length_crc_message(b"telemetry-frame-body")
            .encode()
            .expect("encode");
        let mut rng = MutationRng::new(0xBADC0FFEE0DDF00D);
        let mut random = vec![0u8; encoded.len()];
        for byte in random.iter_mut() {
            *byte = rng.next_u8();
        }
        assert!(
            !encoded.verify_bytes(&random),
            "a random same-length buffer must fail the length+CRC gate"
        );
        // The genuine frame passes the same gate.
        assert!(encoded.verify_bytes(encoded.bytes()));
    }

    #[test]
    fn tlv_roundtrip_stays_consistent_after_value_mutation() {
        // Acceptance criterion: build a TLV frame, mutate a value, re-fixup,
        // and the length/tag stay consistent. A value-length change is a
        // descriptor-level mutation, so we rebuild + re-encode.
        let build = |value: &[u8]| {
            Message::new(vec![
                Field::tlv("record", 0x1234, Endian::Big, value.to_vec()),
                Field::length("total", IntWidth::U16, Endian::Big, &["record"]),
            ])
        };

        let original = build(b"track").encode().expect("encode original");
        assert!(original.verify());

        // Inspect the TLV: tag (2) + len (2) + value.
        let record_span = original.span("record").expect("record span");
        let record = &original.bytes()[record_span.clone()];
        assert_eq!(u16::from_be_bytes([record[0], record[1]]), 0x1234, "tag");
        assert_eq!(
            usize::from(u16::from_be_bytes([record[2], record[3]])),
            b"track".len(),
            "declared TLV length matches value length"
        );

        // Mutate the value to a *different length* and re-encode.
        let mutated = build(b"track-updated-longer")
            .encode()
            .expect("encode mutated");
        assert!(mutated.verify(), "re-encoded TLV frame is consistent");
        let mrec_span = mutated.span("record").expect("record span");
        let mrec = &mutated.bytes()[mrec_span];
        assert_eq!(
            u16::from_be_bytes([mrec[0], mrec[1]]),
            0x1234,
            "tag preserved"
        );
        assert_eq!(
            usize::from(u16::from_be_bytes([mrec[2], mrec[3]])),
            b"track-updated-longer".len(),
            "TLV length recomputed for the new value"
        );
        // Outer length covers the whole (now larger) TLV record.
        let total_span = mutated.span("total").expect("total span");
        let total = u16::from_be_bytes([
            mutated.bytes()[total_span.start],
            mutated.bytes()[total_span.start + 1],
        ]);
        assert_eq!(usize::from(total), mrec_span_len(&mutated));
    }

    fn mrec_span_len(msg: &EncodedMessage) -> usize {
        msg.span("record").expect("record span").len()
    }

    #[test]
    fn tlv_inplace_value_edit_refixes_checksum() {
        // A same-length TLV value edit is the engine's byte-mutation fast path:
        // set_field_bytes over the value then fixup_in_place.
        let mut encoded = Message::new(vec![
            Field::tlv("record", 0x01, Endian::Little, b"ABCDE".to_vec()),
            Field::checksum("sum", ChecksumKind::Sum8, Endian::Big, &["record"]),
        ])
        .encode()
        .expect("encode");
        assert!(encoded.verify());

        // TLV value sits after tag(2)+len(2); overwrite in place, same width.
        let record_span = encoded.span("record").expect("record span");
        let value_start = record_span.start + 4;
        let value_len = record_span.len() - 4;
        let new_value: Vec<u8> = (0..value_len).map(|i| 0x40 + i as u8).collect();
        encoded.bytes[value_start..value_start + value_len].copy_from_slice(&new_value);
        assert!(!encoded.verify(), "checksum stale after value edit");
        encoded.fixup_in_place().expect("fixup");
        assert!(encoded.verify(), "checksum re-derived after value edit");
    }

    #[test]
    fn offset_back_reference_points_at_target_field() {
        let encoded = Message::new(vec![
            Field::offset("ptr", IntWidth::U16, Endian::Big, "target"),
            Field::bytes("filler", vec![0u8; 5]),
            Field::bytes("target", b"HERE".to_vec()),
        ])
        .encode()
        .expect("encode");
        assert!(encoded.verify());
        let ptr_span = encoded.span("ptr").expect("ptr span");
        let stored = u16::from_be_bytes([
            encoded.bytes()[ptr_span.start],
            encoded.bytes()[ptr_span.start + 1],
        ]);
        assert_eq!(usize::from(stored), encoded.span("target").unwrap().start);
    }

    #[test]
    fn length_value_too_wide_is_a_descriptive_error() {
        // A payload longer than a u8 length can hold must be rejected, not
        // silently truncated.
        let err = Message::new(vec![
            Field::length("length", IntWidth::U8, Endian::Big, &["payload"]),
            Field::bytes("payload", vec![0u8; 300]),
        ])
        .encode()
        .expect_err("must reject overflow");
        assert!(
            matches!(err, BinFrameError::ValueTooWide { .. }),
            "got {err}"
        );
    }

    #[test]
    fn undefined_reference_is_rejected() {
        let err = Message::new(vec![Field::length(
            "length",
            IntWidth::U16,
            Endian::Big,
            &["nope"],
        )])
        .encode()
        .expect_err("must reject dangling reference");
        assert!(
            matches!(err, BinFrameError::UnknownReference { ref referenced, .. } if referenced == "nope"),
            "got {err}"
        );
    }

    #[test]
    fn duplicate_field_name_is_rejected() {
        let err = Message::new(vec![
            Field::bytes("dup", b"a".to_vec()),
            Field::bytes("dup", b"b".to_vec()),
        ])
        .encode()
        .expect_err("must reject duplicate names");
        assert!(matches!(err, BinFrameError::DuplicateField(name) if name == "dup"));
    }

    #[test]
    fn max_len_bound_is_enforced() {
        let err = Message::new(vec![Field::bytes("payload", vec![0u8; 64])])
            .with_max_len(16)
            .encode()
            .expect_err("must reject over-long frame");
        assert!(
            matches!(err, BinFrameError::MessageTooLong { .. }),
            "got {err}"
        );
    }

    #[test]
    fn frame_seed_corpus_yields_verifiable_frames() {
        let corpus = frame_seed_corpus(&[
            length_crc_message(b"seed-one"),
            length_crc_message(b"seed-two-longer"),
        ])
        .expect("corpus");
        assert_eq!(corpus.len(), 2);
        // Each seed must pass its own gate: re-decode by rebuilding the same
        // descriptor and verifying the bytes.
        let gate_one = length_crc_message(b"seed-one").encode().unwrap();
        assert!(gate_one.verify_bytes(&corpus[0]));
    }
}
