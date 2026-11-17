// SPDX-License-Identifier: Apache-2.0

//! Comparison operands read out of target memory for on-target CmpLog (#386).
//! The code under test is built with `-fsanitize-coverage=trace-cmp`; its
//! `__sanitizer_cov_trace_cmp*` callbacks append each comparison to a record
//! in RAM, and the gdb and full-system backends read the record after each
//! run, as they read the coverage ring:
//!
//! ```c
//! struct bhf_cmplog {
//!     uint32_t count;     /* comparisons the input ran; may pass the capacity */
//!     uint32_t reserved;
//!     struct { uint64_t lhs, rhs; uint32_t width, site; } entries[CAPACITY];
//! };
//! ```
//!
//! All fields are little-endian. The backend zeroes `count` before each run,
//! and reads `min(count, CAPACITY)` entries after it.

use crate::error::{Result, TransportError};
use crate::gdb::{read_u32, GdbClient};
use std::io::{Read, Write};

/// The bytes before the first entry: the count and a reserved word.
pub const HEADER_SIZE: usize = 8;
/// The bytes of one entry.
pub const ENTRY_SIZE: usize = 24;

/// Where the firmware keeps its comparison record, and how many entries it
/// has room for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CmpLogRegion {
    pub address: u64,
    pub capacity: usize,
}

/// One comparison the target ran: its operands, each `width` bytes wide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Comparison {
    /// The comparison's site (a guard number or the caller's address).
    pub site: u32,
    /// The operands' width in bytes: 1, 2, 4 or 8.
    pub width: u32,
    pub lhs: u64,
    pub rhs: u64,
}

impl Comparison {
    /// The left operand as the target held it: little-endian, `width` bytes.
    pub fn lhs_bytes(&self) -> Vec<u8> {
        self.lhs.to_le_bytes()[..self.width as usize].to_vec()
    }

    /// The right operand, little-endian, `width` bytes.
    pub fn rhs_bytes(&self) -> Vec<u8> {
        self.rhs.to_le_bytes()[..self.width as usize].to_vec()
    }
}

/// Decode the `count` entries of a record's entry image. The image holds at
/// least `min(count, capacity)` entries; `count` past the capacity means the
/// record filled and later comparisons were dropped.
pub fn decode(count: u32, image: &[u8], capacity: usize) -> Result<Vec<Comparison>> {
    let kept = (count as usize).min(capacity);
    if image.len() < kept * ENTRY_SIZE {
        return Err(TransportError::protocol(format!(
            "cmplog image holds {} bytes; {kept} entries need {}",
            image.len(),
            kept * ENTRY_SIZE
        )));
    }
    let word = |entry: &[u8], at: usize| {
        u32::from_le_bytes([entry[at], entry[at + 1], entry[at + 2], entry[at + 3]])
    };
    let wide = |entry: &[u8], at: usize| {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&entry[at..at + 8]);
        u64::from_le_bytes(bytes)
    };
    image
        .as_chunks::<ENTRY_SIZE>()
        .0
        .iter()
        .take(kept)
        .enumerate()
        .map(|(index, entry)| {
            let width = word(entry, 16);
            if !matches!(width, 1 | 2 | 4 | 8) {
                return Err(TransportError::protocol(format!(
                    "cmplog entry {index} has width {width}; expected 1, 2, 4 or 8 \
                     (is cmplog= the record's address?)"
                )));
            }
            Ok(Comparison {
                lhs: wide(entry, 0),
                rhs: wide(entry, 8),
                width,
                site: word(entry, 20),
            })
        })
        .collect()
}

/// Zero the record's count before a run.
pub fn clear<C: Read + Write>(client: &mut GdbClient<C>, region: &CmpLogRegion) -> Result<()> {
    client.write_memory(region.address, &0u32.to_le_bytes())
}

/// Read the comparisons the run recorded.
pub fn read<C: Read + Write>(
    client: &mut GdbClient<C>,
    region: &CmpLogRegion,
) -> Result<Vec<Comparison>> {
    let count = read_u32(client, region.address)?;
    let kept = (count as usize).min(region.capacity);
    if kept == 0 {
        return Ok(Vec::new());
    }
    let image = client.read_memory(region.address + HEADER_SIZE as u64, kept * ENTRY_SIZE)?;
    decode(count, &image, region.capacity)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(lhs: u64, rhs: u64, width: u32, site: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&lhs.to_le_bytes());
        out.extend_from_slice(&rhs.to_le_bytes());
        out.extend_from_slice(&width.to_le_bytes());
        out.extend_from_slice(&site.to_le_bytes());
        out
    }

    #[test]
    fn recorded_operand_buffers_decode_into_comparisons() {
        let mut image = entry(0x4141_4141, 0xDEAD_BEEF, 4, 7);
        image.extend(entry(0x31, 0x7f, 1, 9));
        let comparisons = decode(2, &image, 8).unwrap();
        assert_eq!(
            comparisons,
            vec![
                Comparison {
                    site: 7,
                    width: 4,
                    lhs: 0x4141_4141,
                    rhs: 0xDEAD_BEEF
                },
                Comparison {
                    site: 9,
                    width: 1,
                    lhs: 0x31,
                    rhs: 0x7f
                },
            ]
        );
        assert_eq!(comparisons[0].lhs_bytes(), b"AAAA");
        assert_eq!(comparisons[0].rhs_bytes(), [0xEF, 0xBE, 0xAD, 0xDE]);
        assert_eq!(comparisons[1].rhs_bytes(), [0x7f]);
    }

    #[test]
    fn a_count_past_the_capacity_keeps_the_capacity() {
        let mut image = entry(1, 2, 2, 1);
        image.extend(entry(3, 4, 2, 2));
        let comparisons = decode(500, &image, 2).unwrap();
        assert_eq!(comparisons.len(), 2);
        assert_eq!(comparisons[1].lhs, 3);
    }

    #[test]
    fn a_width_that_is_not_an_operand_size_is_an_error() {
        let error = decode(1, &entry(1, 2, 3, 0), 4).unwrap_err();
        assert!(error.to_string().contains("width 3"), "{error}");
    }

    #[test]
    fn a_short_image_is_an_error() {
        let error = decode(2, &entry(1, 2, 4, 0), 4).unwrap_err();
        assert!(error.to_string().contains("2 entries need 48"), "{error}");
    }
}
