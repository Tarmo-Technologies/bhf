// SPDX-License-Identifier: Apache-2.0

//! Parsers in a private module. Each has a planted bug behind a short gate.

/// A header line, parsed with `str::parse`.
pub struct Header {
    pub fields: usize,
}

impl core::str::FromStr for Header {
    type Err = ();

    /// Behind `H:`, the field count is read one byte past the end.
    fn from_str(s: &str) -> Result<Self, ()> {
        let bytes = s.as_bytes();
        if bytes.len() < 3 || bytes[0] != b'H' || bytes[1] != b':' {
            return Err(());
        }
        Ok(Header {
            fields: bytes[bytes.len()] as usize,
        })
    }
}

/// A packet, converted from bytes with `TryFrom`.
pub struct Packet {
    pub kind: u8,
}

impl TryFrom<&[u8]> for Packet {
    type Error = ();

    /// Behind `P`, the packet's second byte indexes the packet unchecked.
    fn try_from(data: &[u8]) -> Result<Self, ()> {
        if data.len() < 2 || data[0] != b'P' {
            return Err(());
        }
        Ok(Packet {
            kind: data[data[1] as usize],
        })
    }
}

/// How `decode` reads a record.
pub enum Mode {
    Strict,
    Fast,
}

/// Decode a record. In `Mode::Fast`, a `F` record's length byte is trusted.
pub fn decode(data: &[u8], mode: Mode) -> u32 {
    match mode {
        Mode::Strict => data.iter().map(|&b| u32::from(b)).sum(),
        Mode::Fast => {
            if data.len() < 2 || data[0] != b'F' {
                return 0;
            }
            (0..data[1] as usize).map(|i| u32::from(data[2 + i])).sum()
        }
    }
}
