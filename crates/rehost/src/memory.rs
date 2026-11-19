// SPDX-License-Identifier: Apache-2.0

//! The memory the image and its RAM occupy.
//!
//! Memory is a set of non-overlapping banks: the image's segments (read-only
//! unless the ELF marks them writable) and RAM. A bank remembers its
//! contents at reset and which 1 KiB pages a run wrote, so a reset copies
//! back only those pages. The peripheral window, the private peripheral bus
//! and the SRAM bit-band alias are answered by the core; this module serves
//! the banks and the bit-band alias's target bytes.

use crate::image::Image;
use crate::{MemoryRange, SetupError};

const PAGE_SHIFT: u32 = 10;
/// Most bytes all banks may hold together.
const MAX_MAPPED_BYTES: u64 = 1024 * 1024 * 1024;

/// Start and end of the Cortex-M SRAM bit-band region and its alias.
const BITBAND_SRAM: u32 = 0x2000_0000;
const BITBAND_ALIAS: u32 = 0x2200_0000;
const BITBAND_ALIAS_END: u32 = 0x2400_0000;

/// Why a bank access failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Miss {
    /// No bank holds the address.
    Unmapped,
    /// The bank is read-only.
    ReadOnly,
}

struct Bank {
    base: u32,
    data: Vec<u8>,
    pristine: Vec<u8>,
    writable: bool,
    dirty: Vec<u64>,
}

impl Bank {
    fn new(base: u32, pristine: Vec<u8>, writable: bool) -> Self {
        let pages = (pristine.len() >> PAGE_SHIFT) + 1;
        Self {
            base,
            data: pristine.clone(),
            pristine,
            writable,
            dirty: vec![0; pages.div_ceil(64)],
        }
    }

    #[cfg(test)]
    fn end(&self) -> u64 {
        u64::from(self.base) + self.data.len() as u64
    }

    /// The offset of `len` bytes at `address`, when all of them are here.
    #[inline]
    fn offset(&self, address: u32, len: u32) -> Option<usize> {
        let offset = address.wrapping_sub(self.base) as usize;
        (address >= self.base && offset + len as usize <= self.data.len()).then_some(offset)
    }

    #[inline]
    fn mark(&mut self, offset: usize, len: usize) {
        let first = offset >> PAGE_SHIFT;
        let last = (offset + len.max(1) - 1) >> PAGE_SHIFT;
        for page in first..=last {
            self.dirty[page / 64] |= 1 << (page % 64);
        }
    }

    fn reset(&mut self) {
        for (word_index, word) in self.dirty.iter_mut().enumerate() {
            let mut bits = std::mem::take(word);
            while bits != 0 {
                let page = word_index * 64 + bits.trailing_zeros() as usize;
                bits &= bits - 1;
                let start = page << PAGE_SHIFT;
                let end = (start + (1 << PAGE_SHIFT)).min(self.data.len());
                if start < end {
                    self.data[start..end].copy_from_slice(&self.pristine[start..end]);
                }
            }
        }
    }
}

pub(crate) struct Memory {
    banks: Vec<Bank>,
    last: usize,
}

impl Memory {
    /// The image's segments and the RAM it runs in: `ram` plus the ranges
    /// the image's relocated and zero-initialised segments name.
    pub(crate) fn new(image: &Image, ram: &[MemoryRange]) -> Result<Self, SetupError> {
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        for range in ram {
            if range.size == 0 {
                return Err(SetupError::EmptyRam { base: range.base });
            }
            let end = u64::from(range.base) + u64::from(range.size);
            if end > 1 << 32 {
                return Err(SetupError::RamOverflow {
                    base: range.base,
                    size: range.size,
                });
            }
            ranges.push((u64::from(range.base), end));
        }
        for range in image.ram() {
            ranges.push((
                u64::from(range.address),
                u64::from(range.address) + u64::from(range.size),
            ));
        }
        // Union of the RAM ranges.
        ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (start, end) in ranges {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        let mapped: u64 = merged.iter().map(|(start, end)| end - start).sum::<u64>()
            + image
                .segments()
                .iter()
                .map(|segment| u64::from(segment.size))
                .sum::<u64>();
        if mapped > MAX_MAPPED_BYTES {
            return Err(SetupError::TooMuchMemory { bytes: mapped });
        }
        let mut rams: Vec<(u32, Vec<u8>)> = merged
            .iter()
            .map(|&(start, end)| (start as u32, vec![0u8; (end - start) as usize]))
            .collect();
        let mut banks = Vec::new();
        for segment in image.segments() {
            let start = u64::from(segment.address);
            let end = segment.end();
            let home = rams.iter_mut().find(|(base, bytes)| {
                start >= u64::from(*base) && end <= u64::from(*base) + bytes.len() as u64
            });
            if let Some((base, bytes)) = home {
                let offset = (segment.address - *base) as usize;
                bytes[offset..offset + segment.data.len()].copy_from_slice(&segment.data);
                continue;
            }
            if let Some((base, _)) = rams.iter().find(|(base, bytes)| {
                start < u64::from(*base) + bytes.len() as u64 && end > u64::from(*base)
            }) {
                return Err(SetupError::RamOverlapsImage {
                    ram: *base,
                    segment: segment.address,
                });
            }
            let mut bytes = segment.data.clone();
            bytes.resize(segment.size as usize, 0);
            banks.push(Bank::new(segment.address, bytes, segment.writable));
        }
        for (base, bytes) in rams {
            banks.push(Bank::new(base, bytes, true));
        }
        banks.sort_by_key(|bank| bank.base);
        Ok(Self { banks, last: 0 })
    }

    /// Put every bank back as it was at reset.
    pub(crate) fn reset(&mut self) {
        for bank in &mut self.banks {
            bank.reset();
        }
    }

    #[inline]
    fn find(&mut self, address: u32, len: u32) -> Option<(usize, usize)> {
        if let Some(offset) = self
            .banks
            .get(self.last)
            .and_then(|bank| bank.offset(address, len))
        {
            return Some((self.last, offset));
        }
        for (index, bank) in self.banks.iter().enumerate() {
            if let Some(offset) = bank.offset(address, len) {
                self.last = index;
                return Some((index, offset));
            }
        }
        None
    }

    /// Whether a bank holds `address`.
    pub(crate) fn is_mapped(&self, address: u32) -> bool {
        self.banks
            .iter()
            .any(|bank| bank.offset(address, 1).is_some())
    }

    /// Whether a writable bank holds all `len` bytes at `address`.
    pub(crate) fn is_writable(&self, address: u32, len: u32) -> bool {
        self.banks
            .iter()
            .any(|bank| bank.writable && bank.offset(address, len).is_some())
    }

    /// Whether one bank holds all `len` bytes at `address`.
    pub(crate) fn holds(&self, address: u32, len: u32) -> bool {
        self.banks
            .iter()
            .any(|bank| bank.offset(address, len).is_some())
    }

    /// Read `len` (1, 2 or 4) little-endian bytes.
    #[inline]
    pub(crate) fn read(&mut self, address: u32, len: u32) -> Result<u32, Miss> {
        if let Some((bank, offset)) = self.find(address, len) {
            let bytes = &self.banks[bank].data[offset..offset + len as usize];
            return Ok(match len {
                1 => u32::from(bytes[0]),
                2 => u32::from(u16::from_le_bytes([bytes[0], bytes[1]])),
                _ => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            });
        }
        // An access that straddles two adjacent banks.
        let mut value = 0u32;
        for index in 0..len {
            let at = address.checked_add(index).ok_or(Miss::Unmapped)?;
            let (bank, offset) = self.find(at, 1).ok_or(Miss::Unmapped)?;
            value |= u32::from(self.banks[bank].data[offset]) << (8 * index);
        }
        Ok(value)
    }

    /// Write `len` (1, 2 or 4) little-endian bytes.
    #[inline]
    pub(crate) fn write(&mut self, address: u32, len: u32, value: u32) -> Result<(), Miss> {
        if let Some((index, offset)) = self.find(address, len) {
            let bank = &mut self.banks[index];
            if !bank.writable {
                return Err(Miss::ReadOnly);
            }
            let bytes = value.to_le_bytes();
            bank.data[offset..offset + len as usize].copy_from_slice(&bytes[..len as usize]);
            bank.mark(offset, len as usize);
            return Ok(());
        }
        // Check every byte before writing any.
        for index in 0..len {
            let at = address.checked_add(index).ok_or(Miss::Unmapped)?;
            let (bank, _) = self.find(at, 1).ok_or(Miss::Unmapped)?;
            if !self.banks[bank].writable {
                return Err(Miss::ReadOnly);
            }
        }
        for index in 0..len {
            let (bank, offset) = self.find(address + index, 1).ok_or(Miss::Unmapped)?;
            let bank = &mut self.banks[bank];
            bank.data[offset] = (value >> (8 * index)) as u8;
            bank.mark(offset, 1);
        }
        Ok(())
    }

    /// Place `bytes` at `address`, writable bank or not: how the input is
    /// delivered into a fixed buffer.
    pub(crate) fn place(&mut self, address: u32, bytes: &[u8]) -> Result<(), Miss> {
        let len = u32::try_from(bytes.len()).map_err(|_| Miss::Unmapped)?;
        if len == 0 {
            return Ok(());
        }
        let (index, offset) = self.find(address, len).ok_or(Miss::Unmapped)?;
        let bank = &mut self.banks[index];
        bank.data[offset..offset + bytes.len()].copy_from_slice(bytes);
        bank.mark(offset, bytes.len());
        Ok(())
    }

    /// The byte and bit a bit-band alias word stands for, when `address` is
    /// in the SRAM alias and a bank holds the byte.
    pub(crate) fn bitband(&self, address: u32) -> Option<(u32, u32)> {
        if !(BITBAND_ALIAS..BITBAND_ALIAS_END).contains(&address) {
            return None;
        }
        let offset = address - BITBAND_ALIAS;
        let byte = BITBAND_SRAM + (offset >> 5);
        let bit = (offset >> 2) & 7;
        self.is_mapped(byte).then_some((byte, bit))
    }

    /// Each bank's start, end and writability.
    #[cfg(test)]
    pub(crate) fn banks(&self) -> Vec<(u32, u64, bool)> {
        self.banks
            .iter()
            .map(|bank| (bank.base, bank.end(), bank.writable))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::Image;

    fn memory(image: &Image, ram: &[MemoryRange]) -> Memory {
        Memory::new(image, ram).unwrap()
    }

    #[test]
    fn reads_writes_and_reset_restore_ram_and_respect_read_only_images() {
        let image = Image::raw(&[1, 2, 3, 4, 5, 6, 7, 8], 0x0800_0000).unwrap();
        let mut memory = memory(
            &image,
            &[MemoryRange {
                base: 0x2000_0000,
                size: 0x1000,
            }],
        );
        assert_eq!(memory.read(0x0800_0000, 4), Ok(0x0403_0201));
        assert_eq!(memory.read(0x0800_0003, 2), Ok(0x0504), "unaligned");
        assert_eq!(memory.write(0x0800_0000, 4, 0), Err(Miss::ReadOnly));
        assert_eq!(memory.read(0x0800_0008, 1), Err(Miss::Unmapped));
        assert_eq!(memory.write(0x2000_0ffe, 2, 0xbeef), Ok(()));
        assert_eq!(memory.read(0x2000_0ffe, 2), Ok(0xbeef));
        assert_eq!(memory.write(0x2000_0fff, 2, 0), Err(Miss::Unmapped));
        memory.reset();
        assert_eq!(memory.read(0x2000_0ffe, 2), Ok(0), "reset restores RAM");
    }

    #[test]
    fn a_segment_inside_ram_is_part_of_it_and_comes_back_on_reset() {
        let image = Image::raw(&[0xaa; 4], 0x2000_0010).unwrap();
        let mut memory = memory(
            &image,
            &[MemoryRange {
                base: 0x2000_0000,
                size: 0x100,
            }],
        );
        assert_eq!(memory.banks().len(), 1, "one RAM bank holds the segment");
        assert_eq!(memory.read(0x2000_0010, 4), Ok(0xaaaa_aaaa));
        memory.write(0x2000_0010, 4, 7).unwrap();
        memory.reset();
        assert_eq!(memory.read(0x2000_0010, 4), Ok(0xaaaa_aaaa));
    }

    #[test]
    fn ram_that_cuts_through_a_segment_is_refused() {
        let image = Image::raw(&[0; 0x20], 0x2000_0000).unwrap();
        let error = Memory::new(
            &image,
            &[MemoryRange {
                base: 0x2000_0010,
                size: 0x100,
            }],
        )
        .err()
        .unwrap();
        assert_eq!(
            error,
            SetupError::RamOverlapsImage {
                ram: 0x2000_0010,
                segment: 0x2000_0000
            }
        );
    }

    #[test]
    fn overlapping_ram_ranges_merge_and_bad_ranges_are_refused() {
        let image = Image::raw(&[0; 4], 0).unwrap();
        let memory = memory(
            &image,
            &[
                MemoryRange {
                    base: 0x2000_0000,
                    size: 0x100,
                },
                MemoryRange {
                    base: 0x2000_0080,
                    size: 0x100,
                },
            ],
        );
        assert_eq!(
            memory.banks(),
            vec![(0, 4, false), (0x2000_0000, 0x2000_0180, true)]
        );
        assert!(matches!(
            Memory::new(
                &image,
                &[MemoryRange {
                    base: 0x2000_0000,
                    size: 0
                }]
            ),
            Err(SetupError::EmptyRam { .. })
        ));
        assert!(matches!(
            Memory::new(
                &image,
                &[MemoryRange {
                    base: 0xffff_0000,
                    size: 0x20000
                }]
            ),
            Err(SetupError::RamOverflow { .. })
        ));
    }

    #[test]
    fn an_access_across_adjacent_banks_reads_both() {
        let image = Image::raw(&[0x11, 0x22], 0x1fff_fffe).unwrap();
        let mut memory = memory(
            &image,
            &[MemoryRange {
                base: 0x2000_0000,
                size: 0x10,
            }],
        );
        memory.write(0x2000_0000, 2, 0x4433).unwrap();
        assert_eq!(memory.read(0x1fff_fffe, 4), Ok(0x4433_2211));
        assert_eq!(
            memory.write(0x1fff_ffff, 2, 0),
            Err(Miss::ReadOnly),
            "a write is refused whole when any byte is read-only"
        );
    }

    #[test]
    fn the_bit_band_alias_names_a_ram_byte_and_bit() {
        let image = Image::raw(&[0; 4], 0).unwrap();
        let memory = memory(
            &image,
            &[MemoryRange {
                base: 0x2000_0000,
                size: 0x100,
            }],
        );
        // Bit 3 of byte 0x20000004.
        assert_eq!(
            memory.bitband(0x2200_0000 + 4 * 32 + 3 * 4),
            Some((0x2000_0004, 3))
        );
        assert_eq!(memory.bitband(0x2200_0000 + 0x200 * 32), None, "past RAM");
        assert_eq!(memory.bitband(0x2000_0000), None, "not the alias");
    }

    #[test]
    fn place_writes_into_read_only_banks_and_reset_undoes_it() {
        let image = Image::raw(&[0; 8], 0x0800_0000).unwrap();
        let mut memory = memory(&image, &[]);
        memory.place(0x0800_0002, b"hi").unwrap();
        assert_eq!(memory.read(0x0800_0002, 2), Ok(0x6968));
        assert_eq!(memory.place(0x0800_0007, b"hi"), Err(Miss::Unmapped));
        memory.reset();
        assert_eq!(memory.read(0x0800_0002, 2), Ok(0));
    }
}
