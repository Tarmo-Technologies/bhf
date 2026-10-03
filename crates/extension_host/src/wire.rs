// SPDX-License-Identifier: Apache-2.0

//! Length-framed message codec: `{u32 LE length}{payload}`.
//!
//! The declared length is checked against a cap *before* any allocation, so a
//! malformed oversized header can never drive bhf out-of-memory. A clean EOF at
//! a frame boundary is reported as `Ok(None)` (the peer closed the link between
//! messages); a partial read mid-frame is an [`ExtensionError::Protocol`]. This
//! mirrors the `{u32 LE length}{payload}` idiom used elsewhere in the tree.

use crate::{ExtensionError, Result};
use std::io::{self, Read, Write};

/// Write a single length-framed message. The payload length is validated to fit
/// in a `u32` header.
pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<()> {
    let len = u32::try_from(payload.len()).map_err(|_| {
        ExtensionError::protocol(format!(
            "payload of {} bytes does not fit in a u32 frame header",
            payload.len()
        ))
    })?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(payload)?;
    writer.flush()?;
    Ok(())
}

/// Read a single length-framed message, guarding the declared length against
/// `cap` before allocating the body.
///
/// Returns:
/// - `Ok(Some(payload))` for a complete frame,
/// - `Ok(None)` for a *clean* EOF at the length-field boundary (no bytes
///   available — the peer closed between messages),
/// - `Err(ExtensionError::FrameTooLarge)` if the declared length exceeds `cap`
///   (no body is read),
/// - `Err(ExtensionError::Protocol)` for a truncated header or body.
pub fn read_frame<R: Read>(reader: &mut R, cap: usize) -> Result<Option<Vec<u8>>> {
    let declared = match read_len_opt(reader)? {
        Some(len) => len,
        None => return Ok(None),
    };
    if declared as u64 > cap as u64 {
        return Err(ExtensionError::FrameTooLarge {
            declared: declared as u64,
            cap,
        });
    }
    let mut body = vec![0u8; declared as usize];
    read_exact_ctx(reader, &mut body, "frame body")?;
    Ok(Some(body))
}

/// Read the 4-byte little-endian length, mapping a clean EOF at the very first
/// byte to `Ok(None)` and a partial header to a protocol error.
fn read_len_opt<R: Read>(reader: &mut R) -> Result<Option<u32>> {
    let mut first = [0u8; 1];
    let read = reader.read(&mut first)?;
    if read == 0 {
        return Ok(None);
    }
    let mut rest = [0u8; 3];
    read_exact_ctx(reader, &mut rest, "frame length header")?;
    Ok(Some(u32::from_le_bytes([
        first[0], rest[0], rest[1], rest[2],
    ])))
}

fn read_exact_ctx<R: Read>(reader: &mut R, buf: &mut [u8], context: &str) -> Result<()> {
    match reader.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Err(
            ExtensionError::protocol(format!("truncated stream while reading {context}")),
        ),
        Err(error) => Err(ExtensionError::Io(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_roundtrips_payload() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"{}").expect("write");
        // Header is the u32 LE length followed by the payload bytes.
        assert_eq!(&buf[..4], &2u32.to_le_bytes());
        assert_eq!(&buf[4..], b"{}");

        let mut cursor = Cursor::new(buf);
        let frame = read_frame(&mut cursor, 1024).expect("read").expect("frame");
        assert_eq!(frame, b"{}");

        // A second read at the boundary is a clean EOF.
        assert!(read_frame(&mut cursor, 1024).expect("eof").is_none());
    }

    #[test]
    fn declared_length_over_cap_errors_before_alloc() {
        let cap = 16usize;
        // Header claims cap + 1 bytes; follow it with a body that is present but
        // must never be touched.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((cap as u32) + 1).to_le_bytes());
        bytes.extend_from_slice(&vec![0xABu8; cap + 1]);
        let mut cursor = Cursor::new(bytes);

        let err = read_frame(&mut cursor, cap).expect_err("must reject");
        match err {
            ExtensionError::FrameTooLarge { declared, cap: c } => {
                assert_eq!(declared, cap as u64 + 1);
                assert_eq!(c, cap);
            }
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
        // The body was NOT consumed: only the 4-byte header was read.
        assert_eq!(
            cursor.position(),
            4,
            "body must not be read before cap check"
        );
    }

    #[test]
    fn truncated_body_is_protocol_error() {
        // Header says 8 bytes, body only has 3.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&8u32.to_le_bytes());
        bytes.extend_from_slice(b"abc");
        let mut cursor = Cursor::new(bytes);

        let err = read_frame(&mut cursor, 1024).expect_err("truncated");
        match err {
            ExtensionError::Protocol(msg) => assert!(msg.contains("truncated"), "msg: {msg}"),
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    #[test]
    fn truncated_header_is_protocol_error_not_eof() {
        // Only 2 of the 4 header bytes are present: a partial header, not a
        // clean boundary EOF.
        let mut cursor = Cursor::new(vec![0x01u8, 0x00]);
        let err = read_frame(&mut cursor, 1024).expect_err("partial header");
        assert!(matches!(err, ExtensionError::Protocol(_)));
    }

    #[test]
    fn clean_eof_at_header_boundary_is_none() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        assert!(read_frame(&mut cursor, 1024).expect("eof").is_none());
    }
}
