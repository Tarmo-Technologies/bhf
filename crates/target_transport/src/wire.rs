// SPDX-License-Identifier: Apache-2.0

//! Small little-endian read helpers shared by the framed backends.
//!
//! Every helper turns a short read at end-of-stream into a descriptive
//! [`TransportError::Protocol`] rather than a generic I/O error, so callers can
//! tell "the peer closed mid-frame" from "the socket died".

use crate::error::{Result, TransportError};
use std::io::{self, Read};

/// Read exactly `buf.len()` bytes, mapping a mid-frame EOF to a protocol error
/// that names `context`.
fn read_exact_ctx<R: Read>(reader: &mut R, buf: &mut [u8], context: &str) -> Result<()> {
    match reader.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Err(
            TransportError::protocol(format!("truncated stream while reading {context}")),
        ),
        Err(error) => Err(TransportError::Io(error)),
    }
}

/// Read a little-endian `u32`.
pub(crate) fn read_u32_le<R: Read>(reader: &mut R, context: &str) -> Result<u32> {
    let mut buf = [0_u8; 4];
    read_exact_ctx(reader, &mut buf, context)?;
    Ok(u32::from_le_bytes(buf))
}

/// Read a little-endian `u64`.
pub(crate) fn read_u64_le<R: Read>(reader: &mut R, context: &str) -> Result<u64> {
    let mut buf = [0_u8; 8];
    read_exact_ctx(reader, &mut buf, context)?;
    Ok(u64::from_le_bytes(buf))
}

/// Read a leading little-endian `u32`, returning `Ok(None)` on a *clean* EOF at
/// the field boundary (no bytes available). A partial read is a protocol error.
///
/// Used by the on-target side of the agent protocol to distinguish an orderly
/// shutdown (the host closed the link between inputs) from a truncated frame.
pub(crate) fn read_u32_le_opt<R: Read>(reader: &mut R, context: &str) -> Result<Option<u32>> {
    let mut first = [0_u8; 1];
    let read = reader.read(&mut first)?;
    if read == 0 {
        return Ok(None);
    }
    let mut rest = [0_u8; 3];
    read_exact_ctx(reader, &mut rest, context)?;
    Ok(Some(u32::from_le_bytes([
        first[0], rest[0], rest[1], rest[2],
    ])))
}

/// Read exactly `len` bytes into a fresh `Vec`, having already checked `len`
/// against a cap upstream.
pub(crate) fn read_vec<R: Read>(reader: &mut R, len: usize, context: &str) -> Result<Vec<u8>> {
    let mut buf = vec![0_u8; len];
    read_exact_ctx(reader, &mut buf, context)?;
    Ok(buf)
}

/// Guard a declared length against a cap *before* allocating, returning the
/// cap error variant otherwise.
pub(crate) fn cap_len(declared: u64, cap: usize, field: &'static str) -> Result<usize> {
    if declared > cap as u64 {
        return Err(TransportError::LengthCap {
            field,
            declared,
            cap,
        });
    }
    Ok(declared as usize)
}
