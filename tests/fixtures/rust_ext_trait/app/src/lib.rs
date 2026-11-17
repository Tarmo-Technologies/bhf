// SPDX-License-Identifier: Apache-2.0
//
// Static methods of trait impls whose traits come from elsewhere (#338): a
// dependency's `Decode`, imported by `use` for `Record` and spelled in full
// for `Frame`, and the standard `From<&[u8]>` for `Packet`. Each is callable
// only by UFCS, and each has a planted out-of-bounds read behind a one-byte
// tag.

use wiredep::Decode;

pub struct Record {
    pub total: usize,
}

impl Decode for Record {
    /// A planted bug: the count after the `R` tag is trusted.
    fn decode(bytes: &[u8]) -> Self {
        if bytes.len() < 2 || bytes[0] != b'R' {
            return Record { total: 0 };
        }
        let count = bytes[1] as usize;
        let mut total = 0;
        for i in 0..count {
            total += bytes[2 + i] as usize;
        }
        Record { total }
    }
}

pub struct Frame {
    pub kind: u8,
}

impl wiredep::Decode for Frame {
    /// A planted bug: the offset after the `F` tag is trusted.
    fn decode(bytes: &[u8]) -> Self {
        if bytes.len() < 2 || bytes[0] != b'F' {
            return Frame { kind: 0 };
        }
        Frame {
            kind: bytes[bytes[1] as usize],
        }
    }
}

pub struct Packet {
    pub kind: u8,
}

impl From<&[u8]> for Packet {
    /// A planted bug: the offset after the `P` tag is trusted.
    fn from(bytes: &[u8]) -> Self {
        if bytes.len() < 2 || bytes[0] != b'P' {
            return Packet { kind: 0 };
        }
        Packet {
            kind: bytes[bytes[1] as usize],
        }
    }
}

/// Generic over what it tags: a harness cannot choose `T`, so the decoder is
/// refused, and the refusal says why.
pub struct Tagged<T> {
    pub tag: u8,
    marker: std::marker::PhantomData<T>,
}

impl<T> Decode for Tagged<T> {
    fn decode(bytes: &[u8]) -> Self {
        Tagged {
            tag: bytes.first().copied().unwrap_or(0),
            marker: std::marker::PhantomData,
        }
    }
}

/// Takes no input: nothing to fuzz.
pub struct Limits {
    pub depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { depth: 8 }
    }
}
