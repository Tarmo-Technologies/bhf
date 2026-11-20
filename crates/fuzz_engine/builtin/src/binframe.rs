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
//! [`FrameCodec`] applies one descriptor to the single-input lane (`bhf fuzz
//! --frame`): it decodes any byte string into the descriptor's fields, mutates
//! a field or takes a byte mutation of the whole frame, and re-encodes, so
//! every input the harness runs carries a right length and CRC.
//!
//! All sizes are bounded: a message declares a `max_len`, encoding refuses to
//! exceed it, and every derived value is width-checked before it is written.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Range;

use crate::rng::MutationRng;

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

// --- single-input frame codec (`bhf fuzz --frame`) ---------------------------

/// How a data field of a [`FrameCodec`] is sized when an input is decoded
/// against the frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldShape {
    /// Exactly as wide as the template's value: an integer or an enum lowered
    /// to bytes. `codes` are encodings a field mutation favours (an enum's
    /// variants, at the field's width); empty for a plain integer.
    Fixed { codes: Vec<Vec<u8>> },
    /// Variable-length bytes, at most `max` when given.
    Variable { max: Option<usize> },
}

/// How many times [`FrameCodec`] halves the longest variable field of a frame
/// whose derived values do not fit (a `u8` length over 255 bytes, a frame
/// past its `max_len`) before it falls back to the template's frame.
const MAX_TRIM_ROUNDS: usize = 32;

/// The longest run a variable-field mutation inserts or repeats.
const MAX_FIELD_GROWTH: usize = 64;

/// A frame descriptor applied to single inputs: the fast in-process lane's
/// equivalent of AFL++'s `afl_custom_post_process`.
///
/// [`FrameCodec::repair`] decodes any byte string against the template's
/// layout — fixed-width fields by position, a variable field by the length
/// field that gives it, the last variable field by what is left — and
/// re-encodes it, so every length, checksum and offset is right again after
/// a byte mutation. [`FrameCodec::mutate`] edits one decoded data field
/// (grow, shrink or overwrite a payload, an interesting value or enum code in
/// an integer) and re-encodes, which reaches parser code past a length/CRC
/// gate that byte mutation alone never passes.
#[derive(Clone, Debug)]
pub struct FrameCodec {
    template: Message,
    slots: Vec<Slot>,
    /// Bytes every frame has whatever its variable fields hold.
    fixed_len: usize,
    /// The variable field that takes the bytes the others leave.
    last_variable: Option<usize>,
    seed: Vec<u8>,
}

#[derive(Clone, Debug)]
enum Slot {
    Fixed {
        width: usize,
        codes: Vec<Vec<u8>>,
    },
    /// A `Bytes` value or a TLV's value: `header` fixed bytes before it (a
    /// TLV's tag and length), at most `cap` bytes long.
    Variable {
        header: usize,
        cap: usize,
        hint: Hint,
        seed_len: usize,
    },
    Computed {
        width: usize,
    },
}

/// Where a variable field that is not the last one reads its length from.
#[derive(Clone, Copy, Debug)]
enum Hint {
    /// Its own TLV length prefix.
    TlvPrefix { width: IntWidth, endian: Endian },
    /// An earlier length field (by index), less the fixed bytes of the other
    /// fields it covers.
    Length { field: usize, overhead: usize },
    /// Nothing gives it: the template's length.
    Seed,
}

impl FrameCodec {
    /// A codec for frames laid out as `template`, whose field values are the
    /// seed frame's. A `Bytes` field is variable-length unless `shapes` says
    /// otherwise; a TLV's value is always variable-length. A `Fixed` code that
    /// is not the field's width is an error.
    pub fn new(
        template: Message,
        shapes: &BTreeMap<String, FieldShape>,
    ) -> Result<Self, BinFrameError> {
        let seed = template.encode()?.into_bytes();
        let mut slots = Vec::with_capacity(template.fields.len());
        for field in &template.fields {
            slots.push(match field {
                Field::Bytes { name, value } => match shapes.get(name) {
                    Some(FieldShape::Fixed { codes }) => {
                        if let Some(code) = codes.iter().find(|code| code.len() != value.len()) {
                            return Err(BinFrameError::FieldWidthMismatch {
                                field: name.clone(),
                                expected: value.len(),
                                actual: code.len(),
                            });
                        }
                        Slot::Fixed {
                            width: value.len(),
                            codes: codes.clone(),
                        }
                    }
                    Some(FieldShape::Variable { max }) => Slot::Variable {
                        header: 0,
                        cap: max.unwrap_or(usize::MAX),
                        hint: Hint::Seed,
                        seed_len: value.len(),
                    },
                    None => Slot::Variable {
                        header: 0,
                        cap: usize::MAX,
                        hint: Hint::Seed,
                        seed_len: value.len(),
                    },
                },
                Field::Tlv {
                    name,
                    tag_width,
                    len_width,
                    endian,
                    value,
                    ..
                } => {
                    let max = match shapes.get(name) {
                        Some(FieldShape::Variable { max: Some(max) }) => *max,
                        _ => usize::MAX,
                    };
                    Slot::Variable {
                        header: tag_width.size() + len_width.size(),
                        cap: max.min(len_width.max_value() as usize),
                        hint: Hint::TlvPrefix {
                            width: *len_width,
                            endian: *endian,
                        },
                        seed_len: value.len(),
                    }
                }
                Field::Length { width, .. } | Field::Offset { width, .. } => Slot::Computed {
                    width: width.size(),
                },
                Field::Checksum { kind, .. } => Slot::Computed {
                    width: kind.output_width().size(),
                },
            });
        }

        let fixed_len: usize = slots
            .iter()
            .map(|slot| match slot {
                Slot::Fixed { width, .. } | Slot::Computed { width } => *width,
                Slot::Variable { header, .. } => *header,
            })
            .sum();
        let index_of = |name: &str| template.fields.iter().position(|f| f.name() == name);
        // A length field that covers one variable field and otherwise fixed
        // fields bounds that field, and gives its length when it comes first.
        for (at, field) in template.fields.iter().enumerate() {
            let Field::Length { width, covers, .. } = field else {
                continue;
            };
            let covered: Vec<usize> = covers.iter().filter_map(|name| index_of(name)).collect();
            let variable: Vec<usize> = covered
                .iter()
                .copied()
                .filter(|&i| matches!(slots[i], Slot::Variable { .. }))
                .collect();
            let [target] = variable[..] else {
                continue;
            };
            let overhead: usize = covered
                .iter()
                .filter(|&&i| i != target)
                .map(|&i| match &slots[i] {
                    Slot::Fixed { width, .. } | Slot::Computed { width } => *width,
                    Slot::Variable { .. } => 0,
                })
                .sum();
            if let Slot::Variable {
                header, cap, hint, ..
            } = &mut slots[target]
            {
                let room = (width.max_value() as usize).saturating_sub(overhead + *header);
                *cap = (*cap).min(room);
                if at < target && matches!(hint, Hint::Seed) {
                    *hint = Hint::Length {
                        field: at,
                        overhead: overhead + *header,
                    };
                }
            }
        }
        let room = template.max_len.saturating_sub(fixed_len);
        for slot in &mut slots {
            if let Slot::Variable { cap, .. } = slot {
                *cap = (*cap).min(room);
            }
        }
        let last_variable = slots
            .iter()
            .rposition(|slot| matches!(slot, Slot::Variable { .. }));
        Ok(Self {
            template,
            slots,
            fixed_len,
            last_variable,
            seed,
        })
    }

    /// The template's own frame: a well-formed seed for a campaign.
    pub fn seed(&self) -> &[u8] {
        &self.seed
    }

    /// `bytes` decoded against the frame and re-encoded with every derived
    /// field recomputed. A valid frame comes back unchanged; any other byte
    /// string becomes the frame its bytes decode to.
    pub fn repair(&self, bytes: &[u8]) -> Vec<u8> {
        self.encode_values(self.decode(bytes))
    }

    /// One data field of `base` (decoded as [`FrameCodec::repair`] does)
    /// mutated, and the frame re-encoded: a payload grown, shrunk or
    /// overwritten, or an integer set to an interesting value, an enum code,
    /// or nudged. The frame stays within `max_len` bytes where `base` was.
    pub fn mutate(&self, base: &[u8], max_len: usize, rng: &mut MutationRng) -> Vec<u8> {
        let mut values = self.decode(base);
        let data: Vec<usize> = self
            .slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| !matches!(slot, Slot::Computed { .. }))
            .map(|(index, _)| index)
            .collect();
        let Some(index) = rng.choose_index(data.len()).map(|pick| data[pick]) else {
            return self.encode_values(values);
        };
        match &self.slots[index] {
            Slot::Fixed { codes, .. } => mutate_fixed(&mut values[index], codes, rng),
            Slot::Variable { cap, .. } => {
                let others: usize = self
                    .slots
                    .iter()
                    .zip(&values)
                    .enumerate()
                    .filter(|(i, (slot, _))| *i != index && matches!(slot, Slot::Variable { .. }))
                    .map(|(_, (_, value))| value.len())
                    .sum();
                let room = (*cap).min(max_len.saturating_sub(self.fixed_len + others));
                mutate_variable(&mut values[index], room, rng);
            }
            Slot::Computed { .. } => {}
        }
        self.encode_values(values)
    }

    /// Each field's bytes in `bytes`: a fixed field's by position (zero-padded
    /// past the end), a variable field's at the length its hint gives (the
    /// last one takes what the others leave), at most its cap. A computed
    /// field's stored bytes are kept so a later field can read its length.
    fn decode(&self, bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut budget = bytes.len().saturating_sub(self.fixed_len);
        let mut cursor = 0usize;
        let mut values: Vec<Vec<u8>> = Vec::with_capacity(self.slots.len());
        for (index, slot) in self.slots.iter().enumerate() {
            match slot {
                Slot::Fixed { width, .. } | Slot::Computed { width } => {
                    values.push(take_padded(bytes, cursor, *width));
                    cursor += width;
                }
                Slot::Variable {
                    header,
                    cap,
                    hint,
                    seed_len,
                } => {
                    let header_bytes = take_padded(bytes, cursor, *header);
                    cursor += header;
                    let len = if Some(index) == self.last_variable {
                        budget
                    } else {
                        self.hinted_len(*hint, *seed_len, &header_bytes, &values)
                            .min(budget)
                    };
                    budget -= len;
                    let start = cursor.min(bytes.len());
                    let end = (cursor + len.min(*cap)).min(bytes.len());
                    values.push(bytes[start..end].to_vec());
                    cursor += len;
                }
            }
        }
        values
    }

    fn hinted_len(&self, hint: Hint, seed_len: usize, header: &[u8], values: &[Vec<u8>]) -> usize {
        let stored = match hint {
            Hint::Seed => return seed_len,
            Hint::TlvPrefix { width, endian } => read_uint(
                header,
                header.len() - width.size()..header.len(),
                width,
                endian,
            ),
            Hint::Length { field, overhead } => match &self.template.fields[field] {
                Field::Length { width, endian, .. } => {
                    read_uint(&values[field], 0..width.size(), *width, *endian)
                        .map(|stored| stored.saturating_sub(overhead as u64))
                }
                _ => None,
            },
        };
        stored.map_or(0, |len| usize::try_from(len).unwrap_or(usize::MAX))
    }

    /// The template with `values` in its data fields, encoded; the longest
    /// variable field is halved while a derived value does not fit.
    fn encode_values(&self, mut values: Vec<Vec<u8>>) -> Vec<u8> {
        for _ in 0..MAX_TRIM_ROUNDS {
            match self.message_with(&values).encode() {
                Ok(encoded) => return encoded.into_bytes(),
                Err(BinFrameError::ValueTooWide { .. } | BinFrameError::MessageTooLong { .. }) => {
                    let longest = self
                        .slots
                        .iter()
                        .enumerate()
                        .filter(|(_, slot)| matches!(slot, Slot::Variable { .. }))
                        .map(|(index, _)| index)
                        .max_by_key(|&index| values[index].len());
                    match longest {
                        Some(index) if !values[index].is_empty() => {
                            let half = values[index].len() / 2;
                            values[index].truncate(half);
                        }
                        _ => break,
                    }
                }
                Err(_) => break,
            }
        }
        self.seed.clone()
    }

    fn message_with(&self, values: &[Vec<u8>]) -> Message {
        let fields = self
            .template
            .fields
            .iter()
            .zip(values)
            .map(|(field, value)| match field {
                Field::Bytes { name, .. } => Field::Bytes {
                    name: name.clone(),
                    value: value.clone(),
                },
                Field::Tlv {
                    name,
                    tag,
                    tag_width,
                    len_width,
                    endian,
                    ..
                } => Field::Tlv {
                    name: name.clone(),
                    tag: *tag,
                    tag_width: *tag_width,
                    len_width: *len_width,
                    endian: *endian,
                    value: value.clone(),
                },
                computed => computed.clone(),
            })
            .collect();
        Message {
            fields,
            max_len: self.template.max_len,
        }
    }
}

/// `width` bytes of `bytes` from `at`, zero-padded past its end.
fn take_padded(bytes: &[u8], at: usize, width: usize) -> Vec<u8> {
    let mut out = vec![0u8; width];
    if let Some(available) = bytes.get(at..) {
        let n = available.len().min(width);
        out[..n].copy_from_slice(&available[..n]);
    }
    out
}

/// Byte patterns of the boundary integers at any width: zero, all ones, the
/// sign bit, one, and the largest positive value, in either byte order.
fn interesting_fixed(width: usize, pick: u64) -> Vec<u8> {
    let mut out = vec![0u8; width];
    match pick % 7 {
        0 => {}
        1 => out.fill(0xFF),
        2 => out[0] = 0x80,
        3 => out[width - 1] = 0x01,
        4 => out[0] = 0x01,
        5 => {
            out.fill(0xFF);
            out[0] = 0x7F;
        }
        _ => {
            out.fill(0xFF);
            out[width - 1] = 0x7F;
        }
    }
    out
}

fn mutate_fixed(value: &mut [u8], codes: &[Vec<u8>], rng: &mut MutationRng) {
    let width = value.len();
    if width == 0 {
        return;
    }
    match rng.next_u64() % 4 {
        0 if !codes.is_empty() => {
            let pick = rng.choose_index(codes.len()).unwrap_or(0);
            value.copy_from_slice(&codes[pick]);
        }
        0 | 1 => value.copy_from_slice(&interesting_fixed(width, rng.next_u64())),
        // Add or subtract a small delta, as an integer of either byte order.
        2 if width <= 8 => {
            let little = rng.coin();
            if little {
                value.reverse();
            }
            let mut wide = [0u8; 8];
            wide[8 - width..].copy_from_slice(value);
            let delta = 1 + rng.next_u64() % 16;
            let current = u64::from_be_bytes(wide);
            let next = if rng.coin() {
                current.wrapping_add(delta)
            } else {
                current.wrapping_sub(delta)
            };
            value.copy_from_slice(&next.to_be_bytes()[8 - width..]);
            if little {
                value.reverse();
            }
        }
        _ => {
            let at = rng.choose_index(width).unwrap_or(0);
            value[at] = rng.next_u8();
        }
    }
}

/// One edit of a variable field's value, which stays at most `room` bytes.
fn mutate_variable(value: &mut Vec<u8>, room: usize, rng: &mut MutationRng) {
    let len = value.len();
    let grow = room.saturating_sub(len).min(MAX_FIELD_GROWTH);
    match rng.next_u64() % 7 {
        // Insert a run of random bytes.
        0 if grow > 0 => {
            let n = 1 + rng.choose_index(grow).unwrap_or(0);
            let at = rng.choose_index(len + 1).unwrap_or(0);
            let run: Vec<u8> = (0..n).map(|_| rng.next_u8()).collect();
            value.splice(at..at, run);
        }
        // Duplicate a chunk of the value.
        1 if grow > 0 && len > 0 => {
            let from = rng.choose_index(len).unwrap_or(0);
            let n = (1 + rng.choose_index(len - from).unwrap_or(0)).min(grow);
            let at = rng.choose_index(len + 1).unwrap_or(0);
            let chunk = value[from..from + n].to_vec();
            value.splice(at..at, chunk);
        }
        // Repeat one byte, the way a length-overflow input is built.
        2 if grow > 0 && len > 0 => {
            let byte = value[rng.choose_index(len).unwrap_or(0)];
            let n = 1 + rng.choose_index(grow).unwrap_or(0);
            let at = rng.choose_index(len + 1).unwrap_or(0);
            value.splice(at..at, std::iter::repeat_n(byte, n));
        }
        // Delete a range.
        3 if len > 0 => {
            let at = rng.choose_index(len).unwrap_or(0);
            let n = 1 + rng.choose_index(len - at).unwrap_or(0);
            value.drain(at..at + n);
        }
        // Truncate.
        4 if len > 0 => value.truncate(rng.choose_index(len).unwrap_or(0)),
        // Overwrite a byte.
        5 if len > 0 => {
            let at = rng.choose_index(len).unwrap_or(0);
            value[at] = rng.next_u8();
        }
        // Flip a bit.
        6 if len > 0 => {
            let at = rng.choose_index(len).unwrap_or(0);
            value[at] ^= 1 << (rng.next_u64() % 8);
        }
        // Nothing above applies (an empty value with no room is left as is).
        _ if grow > 0 => value.push(rng.next_u8()),
        _ if len > 0 => value[0] ^= 0x01,
        _ => {}
    }
    value.truncate(room);
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

/// `value` laid out at `width` in `endian` order (truncated to the width).
pub fn encode_uint(width: IntWidth, endian: Endian, value: u64) -> Vec<u8> {
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

    /// The payload of a `length_crc_message` frame whose length and CRC are
    /// right; `None` for any other byte string.
    fn valid_payload(frame: &[u8]) -> Option<&[u8]> {
        let crc_at = frame.len().checked_sub(4)?;
        if crc_at < 2 {
            return None;
        }
        let declared = usize::from(u16::from_be_bytes([frame[0], frame[1]]));
        let stored = u32::from_be_bytes(frame[crc_at..].try_into().ok()?);
        (declared == crc_at - 2 && stored == crc32(&frame[..crc_at])).then(|| &frame[2..crc_at])
    }

    fn length_crc_codec(payload: &[u8]) -> FrameCodec {
        FrameCodec::new(length_crc_message(payload), &BTreeMap::new()).expect("codec")
    }

    #[test]
    fn frame_codec_leaves_a_valid_frame_unchanged() {
        let codec = length_crc_codec(b"OPEN track");
        assert_eq!(valid_payload(codec.seed()), Some(&b"OPEN track"[..]));
        assert_eq!(codec.repair(codec.seed()), codec.seed());
        let other = length_crc_message(b"a different payload")
            .encode()
            .unwrap()
            .into_bytes();
        assert_eq!(codec.repair(&other), other, "any valid frame is kept");
    }

    #[test]
    fn frame_codec_repairs_length_and_crc_after_a_byte_mutation() {
        let codec = length_crc_codec(b"OPEN track");
        // A byte inserted into the payload: the length and CRC are stale.
        let mut grown = codec.seed().to_vec();
        grown.insert(7, b'X');
        assert_eq!(valid_payload(&grown), None);
        let repaired = codec.repair(&grown);
        assert_eq!(valid_payload(&repaired), Some(&b"OPEN Xtrack"[..]));

        // A flipped payload byte keeps the length; only the CRC is redone.
        let mut flipped = codec.seed().to_vec();
        flipped[3] ^= 0x20;
        let repaired = codec.repair(&flipped);
        assert_eq!(valid_payload(&repaired), Some(&b"OpEN track"[..]));

        // A stored length or CRC changed alone is put back.
        let mut stale = codec.seed().to_vec();
        stale[1] = 0x99;
        *stale.last_mut().unwrap() ^= 0xFF;
        assert_eq!(codec.repair(&stale), codec.seed());
    }

    #[test]
    fn frame_codec_repairs_a_too_short_input_into_a_frame() {
        let codec = length_crc_codec(b"OPEN track");
        for input in [&b""[..], b"\x00", b"\x12\x34\x56"] {
            let repaired = codec.repair(input);
            assert_eq!(valid_payload(&repaired), Some(&b""[..]), "{input:?}");
        }
    }

    #[test]
    fn frame_codec_reads_a_middle_field_from_its_length_field() {
        // [u8 name_len][name][body][u8 sum8 over all three]: `name` is not the
        // last variable field, so its length comes from `name_len`.
        let template = Message::new(vec![
            Field::length("name_len", IntWidth::U8, Endian::Big, &["name"]),
            Field::bytes("name", b"abc".to_vec()),
            Field::bytes("body", b"0123".to_vec()),
            Field::checksum(
                "sum",
                ChecksumKind::Sum8,
                Endian::Big,
                &["name_len", "name", "body"],
            ),
        ]);
        let codec = FrameCodec::new(template, &BTreeMap::new()).unwrap();
        let mut input = vec![5u8];
        input.extend_from_slice(b"hello");
        input.extend_from_slice(b"world!!");
        input.push(0);
        let repaired = codec.repair(&input);
        let mut expected = vec![5u8];
        expected.extend_from_slice(b"helloworld!!");
        let sum = expected.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        expected.push(sum);
        assert_eq!(repaired, expected);
    }

    #[test]
    fn frame_codec_reads_a_tlv_value_from_its_own_prefix_and_keeps_its_tag() {
        let template = Message::new(vec![
            Field::tlv("record", 0x0102, Endian::Big, b"abc".to_vec()),
            Field::bytes("tail", b"zz".to_vec()),
        ]);
        let codec = FrameCodec::new(template, &BTreeMap::new()).unwrap();
        // A wrong tag and a TLV length of 4.
        let input = [
            0xAA, 0xBB, 0x00, 0x04, b'w', b'x', b'y', b'z', b'T', b'T', b'T',
        ];
        assert_eq!(
            codec.repair(&input),
            [0x01, 0x02, 0x00, 0x04, b'w', b'x', b'y', b'z', b'T', b'T', b'T']
        );
    }

    #[test]
    fn frame_codec_keeps_a_fixed_field_at_its_width() {
        // [u16 kind][payload][crc16 over both].
        let template = Message::new(vec![
            Field::bytes("kind", vec![0x00, 0x01]),
            Field::bytes("payload", b"data".to_vec()),
            Field::checksum(
                "crc",
                ChecksumKind::Crc16Ccitt,
                Endian::Big,
                &["kind", "payload"],
            ),
        ]);
        let shapes = BTreeMap::from([(
            "kind".to_owned(),
            FieldShape::Fixed {
                codes: vec![vec![0x00, 0x01], vec![0x00, 0x02]],
            },
        )]);
        let codec = FrameCodec::new(template, &shapes).unwrap();
        let mut rng = MutationRng::new(7);
        let mut codes_seen = std::collections::BTreeSet::new();
        for _ in 0..400 {
            let out = codec.mutate(codec.seed(), 4096, &mut rng);
            let crc_at = out.len() - 2;
            let stored = u16::from_be_bytes([out[crc_at], out[crc_at + 1]]);
            assert_eq!(stored, crc16_ccitt(&out[..crc_at]), "{out:?}");
            assert!(out.len() >= 4);
            codes_seen.insert([out[0], out[1]]);
        }
        assert!(codes_seen.contains(&[0x00, 0x02]), "the other enum code");
        assert!(codes_seen.len() > 3, "the field is mutated: {codes_seen:?}");
    }

    #[test]
    fn frame_codec_rejects_a_code_of_the_wrong_width() {
        let template = Message::new(vec![Field::bytes("kind", vec![0x00, 0x01])]);
        let shapes = BTreeMap::from([(
            "kind".to_owned(),
            FieldShape::Fixed {
                codes: vec![vec![0x02]],
            },
        )]);
        let err = FrameCodec::new(template, &shapes).unwrap_err();
        assert!(
            matches!(err, BinFrameError::FieldWidthMismatch { ref field, expected: 2, actual: 1 } if field == "kind"),
            "{err}"
        );
    }

    #[test]
    fn frame_codec_field_mutations_are_all_valid_frames_and_change_the_length() {
        let codec = length_crc_codec(b"OPEN track");
        let mut rng = MutationRng::new(0x5EED);
        let mut base = codec.seed().to_vec();
        let mut lengths = std::collections::BTreeSet::new();
        for _ in 0..1000 {
            let out = codec.mutate(&base, 512, &mut rng);
            let payload = valid_payload(&out).unwrap_or_else(|| panic!("invalid {out:?}"));
            assert!(out.len() <= 512);
            lengths.insert(payload.len());
            base = out;
        }
        assert!(lengths.len() > 10, "payload lengths: {lengths:?}");
    }

    #[test]
    fn frame_codec_keeps_a_payload_within_its_length_width() {
        // A u8 length can describe at most 255 payload bytes.
        let template = Message::new(vec![
            Field::length("len", IntWidth::U8, Endian::Big, &["payload"]),
            Field::bytes("payload", vec![b'A'; 250]),
            Field::checksum("x", ChecksumKind::Xor8, Endian::Big, &["payload"]),
        ]);
        let codec = FrameCodec::new(template, &BTreeMap::new()).unwrap();
        let mut rng = MutationRng::new(3);
        let mut base = codec.seed().to_vec();
        for _ in 0..500 {
            base = codec.mutate(&base, 4096, &mut rng);
            let payload = &base[1..base.len() - 1];
            assert_eq!(usize::from(base[0]), payload.len());
            assert!(payload.len() <= 255);
        }
        // A byte mutation past the bound is cut back to a frame that fits.
        let long = vec![0x41u8; 600];
        let repaired = codec.repair(&long);
        assert_eq!(usize::from(repaired[0]), repaired.len() - 2);
    }
}
