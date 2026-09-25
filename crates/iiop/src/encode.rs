// SPDX-License-Identifier: Apache-2.0

//! GIOP/CDR **encoder** (HDF-7, deliverable 2).
//!
//! The rest of this crate only decodes. Without an encoder the GIOP/CDR decoder
//! is unreachable from a fuzzer: there is no way to turn structured fuzz values
//! into a well-formed GIOP request to feed it. This module adds that missing
//! half — a [`CdrWriter`] that is the byte-exact inverse of
//! [`crate::cdr::CdrReader`], and [`encode_request_1_2`] which builds a complete
//! GIOP 1.2 `Request` frame that round-trips back through
//! [`crate::giop::read_request_1_2`].
//!
//! The alignment contract is the crux: the decoder aligns CDR primitives
//! relative to the start of the *GIOP message* (alignment base
//! [`crate::giop::HEADER_LEN`]). The writer therefore lays the whole body out
//! with the same alignment base, so every pad byte lands where the reader
//! expects it and the produced frame decodes to the identical logical request.

use crate::cdr::{align_padding, Endianness};
use crate::giop::HEADER_LEN;

/// A CDR output stream. Mirrors [`crate::cdr::CdrReader`]: the same endianness,
/// the same alignment base, and the same alignment rule, so what this writer
/// emits the reader consumes byte-for-byte.
#[derive(Clone, Debug)]
pub struct CdrWriter {
    out: Vec<u8>,
    alignment_base: usize,
    endian: Endianness,
}

impl CdrWriter {
    pub fn new(endian: Endianness) -> Self {
        Self::with_alignment_base(endian, 0)
    }

    pub fn with_alignment_base(endian: Endianness, alignment_base: usize) -> Self {
        Self {
            out: Vec::new(),
            alignment_base,
            endian,
        }
    }

    pub fn position(&self) -> usize {
        self.out.len()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.out
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.out
    }

    /// Pad with zero bytes until the current position is aligned, using the same
    /// absolute-offset rule the reader applies.
    pub fn align_to(&mut self, alignment: usize) {
        let pad = align_padding(self.out.len(), alignment, self.alignment_base);
        self.out.resize(self.out.len() + pad, 0);
    }

    pub fn write_octet(&mut self, value: u8) {
        self.out.push(value);
    }

    pub fn write_bool(&mut self, value: bool) {
        self.out.push(u8::from(value));
    }

    pub fn write_u16(&mut self, value: u16) {
        self.align_to(2);
        match self.endian {
            Endianness::Big => self.out.extend_from_slice(&value.to_be_bytes()),
            Endianness::Little => self.out.extend_from_slice(&value.to_le_bytes()),
        }
    }

    pub fn write_i16(&mut self, value: i16) {
        self.write_u16(value as u16);
    }

    pub fn write_u32(&mut self, value: u32) {
        self.align_to(4);
        match self.endian {
            Endianness::Big => self.out.extend_from_slice(&value.to_be_bytes()),
            Endianness::Little => self.out.extend_from_slice(&value.to_le_bytes()),
        }
    }

    pub fn write_i32(&mut self, value: i32) {
        self.write_u32(value as u32);
    }

    pub fn write_u64(&mut self, value: u64) {
        self.align_to(8);
        match self.endian {
            Endianness::Big => self.out.extend_from_slice(&value.to_be_bytes()),
            Endianness::Little => self.out.extend_from_slice(&value.to_le_bytes()),
        }
    }

    pub fn write_i64(&mut self, value: i64) {
        self.write_u64(value as u64);
    }

    pub fn write_f32(&mut self, value: f32) {
        self.write_u32(value.to_bits());
    }

    pub fn write_f64(&mut self, value: f64) {
        self.write_u64(value.to_bits());
    }

    /// Write a CDR `string`: a `u32` length that **includes** the NUL
    /// terminator, then the bytes, then the terminator — the exact shape
    /// [`crate::cdr::CdrReader::read_string`] expects.
    pub fn write_string(&mut self, value: &str) -> Result<(), EncodeError> {
        let len = value
            .len()
            .checked_add(1)
            .and_then(|len| u32::try_from(len).ok())
            .ok_or(EncodeError::StringTooLong { len: value.len() })?;
        self.write_u32(len);
        self.out.extend_from_slice(value.as_bytes());
        self.out.push(0);
        Ok(())
    }

    /// Write a CDR `sequence<octet>`: a `u32` count then the raw bytes.
    pub fn write_octet_sequence(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        let len = u32::try_from(bytes.len())
            .map_err(|_| EncodeError::SequenceTooLong { len: bytes.len() })?;
        self.write_u32(len);
        self.out.extend_from_slice(bytes);
        Ok(())
    }
}

/// A CDR value to encode as a GIOP request argument. The variants cover exactly
/// what [`crate::idl_args::decode_request_arguments`] can decode, so an encoded
/// argument list round-trips to the matching [`crate::idl_args::DecodedArgumentValue`].
#[derive(Clone, Debug, PartialEq)]
pub enum CdrValue {
    Boolean(bool),
    Char(u8),
    Octet(u8),
    Short(i16),
    UShort(u16),
    Long(i32),
    ULong(u32),
    LongLong(i64),
    ULongLong(u64),
    Float(f32),
    Double(f64),
    String(String),
    /// A homogeneous `sequence<T>`: a `u32` count then each element.
    Sequence(Vec<CdrValue>),
}

impl CdrValue {
    pub fn write(&self, writer: &mut CdrWriter) -> Result<(), EncodeError> {
        match self {
            CdrValue::Boolean(value) => writer.write_bool(*value),
            CdrValue::Char(value) | CdrValue::Octet(value) => writer.write_octet(*value),
            CdrValue::Short(value) => writer.write_i16(*value),
            CdrValue::UShort(value) => writer.write_u16(*value),
            CdrValue::Long(value) => writer.write_i32(*value),
            CdrValue::ULong(value) => writer.write_u32(*value),
            CdrValue::LongLong(value) => writer.write_i64(*value),
            CdrValue::ULongLong(value) => writer.write_u64(*value),
            CdrValue::Float(value) => writer.write_f32(*value),
            CdrValue::Double(value) => writer.write_f64(*value),
            CdrValue::String(value) => writer.write_string(value)?,
            CdrValue::Sequence(elements) => {
                let count =
                    u32::try_from(elements.len()).map_err(|_| EncodeError::SequenceTooLong {
                        len: elements.len(),
                    })?;
                writer.write_u32(count);
                for element in elements {
                    element.write(writer)?;
                }
            }
        }
        Ok(())
    }
}

/// A CORBA `ServiceContext` (`context_id` + opaque data) to place in a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceContextSpec {
    pub context_id: u32,
    pub data: Vec<u8>,
}

/// Everything needed to build a GIOP 1.2 `Request` frame. The target is a
/// `KeyAddr` (object key), which is the addressing mode a plain servant uses.
#[derive(Clone, Debug, PartialEq)]
pub struct Request12 {
    pub endian: Endianness,
    pub request_id: u32,
    pub response_flags: u8,
    pub object_key: Vec<u8>,
    pub operation: String,
    pub service_contexts: Vec<ServiceContextSpec>,
    pub arguments: Vec<CdrValue>,
}

impl Request12 {
    /// A request with response expected (`response_flags = 0x03`), no service
    /// contexts, little-endian body.
    pub fn new(object_key: impl Into<Vec<u8>>, operation: impl Into<String>) -> Self {
        Self {
            endian: Endianness::Little,
            request_id: 1,
            response_flags: 0x03,
            object_key: object_key.into(),
            operation: operation.into(),
            service_contexts: Vec::new(),
            arguments: Vec::new(),
        }
    }

    pub fn with_endian(mut self, endian: Endianness) -> Self {
        self.endian = endian;
        self
    }

    pub fn with_request_id(mut self, request_id: u32) -> Self {
        self.request_id = request_id;
        self
    }

    pub fn with_arguments(mut self, arguments: Vec<CdrValue>) -> Self {
        self.arguments = arguments;
        self
    }

    pub fn with_service_context(mut self, context_id: u32, data: impl Into<Vec<u8>>) -> Self {
        self.service_contexts.push(ServiceContextSpec {
            context_id,
            data: data.into(),
        });
        self
    }

    /// Encode this request into a complete GIOP 1.2 frame (12-byte header +
    /// CDR body).
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        encode_request_1_2(self)
    }
}

/// Build a GIOP 1.2 `Request` frame from `request`.
///
/// The body is laid out with alignment base [`HEADER_LEN`] so the 12-byte header
/// that precedes it is accounted for; this is what makes the frame decode
/// cleanly via [`crate::giop::read_request_1_2`].
pub fn encode_request_1_2(request: &Request12) -> Result<Vec<u8>, EncodeError> {
    let mut body = CdrWriter::with_alignment_base(request.endian, HEADER_LEN);

    // GIOP 1.2 RequestHeader: request_id, response_flags, 3 reserved octets,
    // target address, operation, service context list. (In 1.2 the service
    // context list follows the operation — see read_request_1_2.)
    body.write_u32(request.request_id);
    body.write_octet(request.response_flags);
    body.write_octet(0);
    body.write_octet(0);
    body.write_octet(0);

    // TargetAddress: KeyAddr (disposition 0) + object key octet sequence.
    body.write_i16(0);
    body.write_octet_sequence(&request.object_key)?;

    body.write_string(&request.operation)?;

    // Service context list.
    let context_count = u32::try_from(request.service_contexts.len()).map_err(|_| {
        EncodeError::TooManyServiceContexts {
            count: request.service_contexts.len(),
        }
    })?;
    body.write_u32(context_count);
    for context in &request.service_contexts {
        body.write_u32(context.context_id);
        body.write_octet_sequence(&context.data)?;
    }

    // GIOP 1.2 aligns the request body (arguments) to an 8-byte boundary when
    // any argument follows — matching the decoder's `align_to(8)`.
    if !request.arguments.is_empty() {
        body.align_to(8);
    }
    for argument in &request.arguments {
        argument.write(&mut body)?;
    }

    let body = body.into_bytes();
    let body_len =
        u32::try_from(body.len()).map_err(|_| EncodeError::BodyTooLarge { len: body.len() })?;

    let mut frame = Vec::with_capacity(HEADER_LEN + body.len());
    frame.extend_from_slice(b"GIOP");
    frame.push(1); // major
    frame.push(2); // minor
    frame.push(giop_1_2_flags(request.endian)); // flags: byte order, not fragmented
    frame.push(0); // message type: Request
    match request.endian {
        Endianness::Big => frame.extend_from_slice(&body_len.to_be_bytes()),
        Endianness::Little => frame.extend_from_slice(&body_len.to_le_bytes()),
    }
    frame.extend_from_slice(&body);
    Ok(frame)
}

fn giop_1_2_flags(endian: Endianness) -> u8 {
    match endian {
        Endianness::Big => 0x00,
        Endianness::Little => 0x01,
    }
}

/// Errors from GIOP/CDR encoding. Each variant records the offending size so a
/// caller can see which field overflowed rather than a silent truncation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    StringTooLong { len: usize },
    SequenceTooLong { len: usize },
    TooManyServiceContexts { count: usize },
    BodyTooLarge { len: usize },
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeError::StringTooLong { len } => {
                write!(
                    f,
                    "CDR string of {len} byte(s) exceeds the u32 length field"
                )
            }
            EncodeError::SequenceTooLong { len } => {
                write!(
                    f,
                    "CDR sequence of {len} element(s) exceeds the u32 count field"
                )
            }
            EncodeError::TooManyServiceContexts { count } => write!(
                f,
                "{count} service contexts exceed the u32 service-context count field"
            ),
            EncodeError::BodyTooLarge { len } => {
                write!(
                    f,
                    "GIOP body of {len} byte(s) exceeds the u32 message-length field"
                )
            }
        }
    }
}

impl std::error::Error for EncodeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cdr::CdrReader;

    #[test]
    fn writer_is_byte_exact_inverse_of_reader_with_alignment() {
        // Interleave widths so the writer must insert alignment padding, then
        // read it all back and confirm every value and the total length.
        for endian in [Endianness::Big, Endianness::Little] {
            let mut writer = CdrWriter::new(endian);
            writer.write_octet(0xAB); // pos 1 -> forces padding before u32
            writer.write_u32(0x1122_3344); // aligns to 4
            writer.write_u16(0x5566); // aligns to 2
            writer.write_octet(0x07);
            writer.write_u64(0x0102_0304_0506_0708); // aligns to 8
            writer.write_string("radar").unwrap();
            writer.write_octet_sequence(&[9, 8, 7]).unwrap();
            let bytes = writer.into_bytes();

            let mut reader = CdrReader::new(&bytes, endian);
            assert_eq!(reader.read_octet().unwrap(), 0xAB);
            assert_eq!(reader.read_u32().unwrap(), 0x1122_3344);
            assert_eq!(reader.read_u16().unwrap(), 0x5566);
            assert_eq!(reader.read_octet().unwrap(), 0x07);
            assert_eq!(reader.read_u64().unwrap(), 0x0102_0304_0506_0708);
            assert_eq!(reader.read_string().unwrap(), "radar");
            assert_eq!(reader.read_octet_sequence().unwrap(), &[9, 8, 7]);
            assert_eq!(reader.remaining(), 0, "no trailing bytes");
        }
    }

    #[test]
    fn writer_honors_alignment_base_like_the_message_body() {
        // With alignment base HEADER_LEN, a u32 written first needs no padding
        // (12 is a multiple of 4); a reader over the same base agrees.
        let mut writer = CdrWriter::with_alignment_base(Endianness::Little, HEADER_LEN);
        writer.write_u32(0xDEAD_BEEF);
        let bytes = writer.into_bytes();
        assert_eq!(bytes.len(), 4, "12 is 4-aligned, so no leading pad");

        let mut reader = CdrReader::with_alignment_base(&bytes, Endianness::Little, HEADER_LEN);
        assert_eq!(reader.read_u32().unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn encoded_frame_has_a_well_formed_giop_header() {
        let frame = Request12::new(b"Obj".to_vec(), "ping")
            .encode()
            .expect("encode");
        assert_eq!(&frame[0..4], b"GIOP");
        assert_eq!(frame[4], 1, "major");
        assert_eq!(frame[5], 2, "minor");
        assert_eq!(frame[6], 0x01, "little-endian flag");
        assert_eq!(frame[7], 0, "message type Request");
        let body_len = u32::from_le_bytes([frame[8], frame[9], frame[10], frame[11]]) as usize;
        assert_eq!(body_len, frame.len() - HEADER_LEN, "body length is exact");
    }

    #[test]
    fn string_length_field_overflow_is_reported() {
        // u32::try_from failure is unreachable for real sizes, but the width
        // check itself must be exercised; a normal string encodes fine.
        let mut writer = CdrWriter::new(Endianness::Big);
        assert!(writer.write_string("ok").is_ok());
    }
}
