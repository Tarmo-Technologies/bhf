// SPDX-License-Identifier: Apache-2.0

//! Firmware images: a 32-bit little-endian ARM ELF executable, or a raw image
//! (a flash dump, `objcopy -O binary` output) loaded at a base address.
//!
//! An ELF image is loaded the way a flash programmer writes it: each `PT_LOAD`
//! segment's file bytes go to its physical (load) address. A segment whose
//! virtual address differs from its load address (`.data`, copied to RAM by
//! the start-up code), or that has no file bytes (`.bss`), also names a RAM
//! range at its virtual address, which the machine maps.

use thiserror::Error;

/// Largest image, and largest span of memory one segment may claim.
const MAX_SEGMENT_BYTES: u64 = 256 * 1024 * 1024;
/// Most bytes all of an image's segments may claim together.
const MAX_IMAGE_BYTES: u64 = 512 * 1024 * 1024;
/// Most `PT_LOAD` segments read from one ELF.
const MAX_SEGMENTS: usize = 256;
/// Most symbols kept from one ELF.
const MAX_SYMBOLS: usize = 1 << 20;

const EM_ARM: u16 = 40;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const SHT_SYMTAB: u32 = 2;
const SHN_UNDEF: u16 = 0;
const SHN_ABS: u16 = 0xfff1;
const STT_FUNC: u8 = 2;

/// Names start-up files give the section holding the vector table.
const VECTOR_SECTIONS: [&str; 5] = [
    ".isr_vector",
    ".vectors",
    ".vector_table",
    ".isr_vectors",
    ".intvecs",
];

/// Why an image could not be loaded.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LoadError {
    #[error("the image is empty")]
    Empty,
    #[error("not an ELF file (no \\x7fELF magic)")]
    NotElf,
    #[error("ELF class {0} is not 32-bit: a Cortex-M image is a 32-bit ELF")]
    Not32Bit(u8),
    #[error("ELF data encoding {0} is not little-endian: Cortex-M images are little-endian")]
    NotLittleEndian(u8),
    #[error("ELF machine {0} is not ARM (40)")]
    NotArm(u16),
    #[error("the ELF is truncated: {0}")]
    Truncated(&'static str),
    #[error("the ELF has {0} loadable segments, more than the {MAX_SEGMENTS} read")]
    TooManySegments(usize),
    #[error("the ELF has no loadable (PT_LOAD) segment with bytes")]
    NoSegments,
    #[error(
        "segment at {address:#010x} spans {size} bytes, past the end of the 32-bit address space"
    )]
    AddressOverflow { address: u32, size: u64 },
    #[error(
        "segment at {address:#010x} claims {size} bytes, more than the {MAX_SEGMENT_BYTES} allowed"
    )]
    SegmentTooLarge { address: u32, size: u64 },
    #[error("the image's segments claim more than {MAX_IMAGE_BYTES} bytes")]
    ImageTooLarge,
    #[error("segments at {first:#010x} and {second:#010x} overlap")]
    Overlap { first: u32, second: u32 },
}

/// The file format an image was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    Elf,
    Raw,
}

impl ImageFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Elf => "elf",
            Self::Raw => "raw",
        }
    }
}

/// Bytes the image places in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// Where the bytes are loaded.
    pub address: u32,
    /// The bytes; the segment spans `size` bytes, zero past `data.len()`.
    pub data: Vec<u8>,
    /// Bytes of memory the segment spans, at least `data.len()`.
    pub size: u32,
    /// The program header marked the segment writable (`PF_W`).
    pub writable: bool,
    /// The program header marked the segment executable (`PF_X`).
    pub executable: bool,
}

impl Segment {
    /// One past the last address the segment spans.
    pub fn end(&self) -> u64 {
        u64::from(self.address) + u64::from(self.size)
    }
}

/// A RAM range the image runs in: a relocated or zero-initialised segment's
/// virtual address range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RamRange {
    pub address: u32,
    pub size: u32,
    pub executable: bool,
}

/// A named address from the ELF symbol table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    /// The address, without the Thumb bit for a function.
    pub address: u32,
    pub size: u32,
    pub function: bool,
}

/// A loaded firmware image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    format: ImageFormat,
    segments: Vec<Segment>,
    ram: Vec<RamRange>,
    symbols: Vec<Symbol>,
    vector_table: u32,
    entry: Option<u32>,
}

impl Image {
    /// Load an image, telling ELF from raw by the ELF magic. A raw image
    /// needs `base`; an ELF says where it loads, so `base` must be `None`.
    pub fn load(bytes: &[u8], base: Option<u32>) -> Result<Self, LoadError> {
        match base {
            Some(base) => Self::raw(bytes, base),
            None => Self::elf(bytes),
        }
    }

    /// Whether `bytes` start with the ELF magic.
    pub fn is_elf(bytes: &[u8]) -> bool {
        bytes.starts_with(b"\x7fELF")
    }

    /// A raw image: `bytes` loaded at `base`, read-only. Its vector table is
    /// at `base`.
    pub fn raw(bytes: &[u8], base: u32) -> Result<Self, LoadError> {
        if bytes.is_empty() {
            return Err(LoadError::Empty);
        }
        let size = bytes.len() as u64;
        if size > MAX_SEGMENT_BYTES {
            return Err(LoadError::SegmentTooLarge {
                address: base,
                size,
            });
        }
        if u64::from(base) + size > 1 << 32 {
            return Err(LoadError::AddressOverflow {
                address: base,
                size,
            });
        }
        Ok(Self {
            format: ImageFormat::Raw,
            segments: vec![Segment {
                address: base,
                data: bytes.to_vec(),
                size: size as u32,
                writable: false,
                executable: true,
            }],
            ram: Vec::new(),
            symbols: Vec::new(),
            vector_table: base,
            entry: None,
        })
    }

    /// A 32-bit little-endian ARM ELF executable.
    pub fn elf(bytes: &[u8]) -> Result<Self, LoadError> {
        let elf = Elf::parse(bytes)?;
        let mut segments = Vec::new();
        let mut ram = Vec::new();
        let mut claimed = 0u64;
        for header in elf.program_headers()? {
            if header.kind != PT_LOAD || header.memsz == 0 {
                continue;
            }
            if segments.len() + ram.len() >= MAX_SEGMENTS {
                return Err(LoadError::TooManySegments(segments.len() + ram.len() + 1));
            }
            let writable = header.flags & PF_W != 0;
            let executable = header.flags & PF_X != 0;
            let filesz = header.filesz.min(header.memsz);
            check_span(header.vaddr, u64::from(header.memsz))?;
            claimed += u64::from(header.memsz);
            if claimed > MAX_IMAGE_BYTES {
                return Err(LoadError::ImageTooLarge);
            }
            if filesz > 0 {
                let relocated = header.vaddr != header.paddr;
                // A relocated segment's load copy holds only the file bytes;
                // the RAM it runs in is mapped at its virtual address.
                let size = if relocated { filesz } else { header.memsz };
                check_span(header.paddr, u64::from(size))?;
                let data = elf
                    .slice(header.offset, filesz)
                    .ok_or(LoadError::Truncated("segment bytes"))?
                    .to_vec();
                segments.push(Segment {
                    address: header.paddr,
                    data,
                    size,
                    writable: writable && !relocated,
                    executable,
                });
                if relocated {
                    ram.push(RamRange {
                        address: header.vaddr,
                        size: header.memsz,
                        executable,
                    });
                }
            } else {
                ram.push(RamRange {
                    address: header.vaddr,
                    size: header.memsz,
                    executable,
                });
            }
        }
        if segments.is_empty() {
            return Err(LoadError::NoSegments);
        }
        segments.sort_by_key(|segment| segment.address);
        for pair in segments.windows(2) {
            if pair[0].end() > u64::from(pair[1].address) {
                return Err(LoadError::Overlap {
                    first: pair[0].address,
                    second: pair[1].address,
                });
            }
        }
        let sections = elf.section_headers().unwrap_or_default();
        let symbols = elf.symbols(&sections);
        let vector_table = elf
            .named_section(&sections, &VECTOR_SECTIONS)
            .map(|section| section.addr)
            .unwrap_or(segments[0].address);
        Ok(Self {
            format: ImageFormat::Elf,
            segments,
            ram,
            symbols,
            vector_table,
            entry: Some(elf.entry),
        })
    }

    pub fn format(&self) -> ImageFormat {
        self.format
    }

    /// The bytes the image loads, by ascending address.
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// RAM ranges the image's relocated and zero-initialised segments run in.
    pub fn ram(&self) -> &[RamRange] {
        &self.ram
    }

    pub fn symbols(&self) -> &[Symbol] {
        &self.symbols
    }

    /// The symbol called `name`.
    pub fn symbol(&self, name: &str) -> Option<&Symbol> {
        self.symbols.iter().find(|symbol| symbol.name == name)
    }

    /// Where the vector table is: the start of a vector-table section
    /// (`.isr_vector`, `.vectors`, ...), else the lowest loaded address.
    pub fn vector_table(&self) -> u32 {
        self.vector_table
    }

    /// The ELF entry point, for information: a Cortex-M starts at the reset
    /// vector, not here.
    pub fn entry(&self) -> Option<u32> {
        self.entry
    }

    /// The little-endian word at `address`, when the image loads bytes there.
    pub fn read_u32(&self, address: u32) -> Option<u32> {
        let mut word = [0u8; 4];
        for (index, byte) in word.iter_mut().enumerate() {
            let at = address.checked_add(index as u32)?;
            let segment = self
                .segments
                .iter()
                .find(|segment| at >= segment.address && u64::from(at) < segment.end())?;
            *byte = segment
                .data
                .get((at - segment.address) as usize)
                .copied()
                .unwrap_or(0);
        }
        Some(u32::from_le_bytes(word))
    }
}

fn check_span(address: u32, size: u64) -> Result<(), LoadError> {
    if size > MAX_SEGMENT_BYTES {
        return Err(LoadError::SegmentTooLarge { address, size });
    }
    if u64::from(address) + size > 1 << 32 {
        return Err(LoadError::AddressOverflow { address, size });
    }
    Ok(())
}

struct ProgramHeader {
    kind: u32,
    offset: u32,
    vaddr: u32,
    paddr: u32,
    filesz: u32,
    memsz: u32,
    flags: u32,
}

#[derive(Debug, Clone, Default)]
struct SectionHeader {
    name: u32,
    kind: u32,
    addr: u32,
    offset: u32,
    size: u32,
    link: u32,
}

/// The parts of an ELF32 little-endian file the loader reads.
struct Elf<'a> {
    bytes: &'a [u8],
    entry: u32,
    phoff: u32,
    shoff: u32,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
}

impl<'a> Elf<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, LoadError> {
        if bytes.is_empty() {
            return Err(LoadError::Empty);
        }
        if !Image::is_elf(bytes) {
            return Err(LoadError::NotElf);
        }
        if bytes.len() < 52 {
            return Err(LoadError::Truncated("ELF header"));
        }
        if bytes[4] != 1 {
            return Err(LoadError::Not32Bit(bytes[4]));
        }
        if bytes[5] != 1 {
            return Err(LoadError::NotLittleEndian(bytes[5]));
        }
        let elf = Self {
            bytes,
            entry: le32(bytes, 24).unwrap_or(0),
            phoff: le32(bytes, 28).unwrap_or(0),
            shoff: le32(bytes, 32).unwrap_or(0),
            phentsize: le16(bytes, 42).unwrap_or(0),
            phnum: le16(bytes, 44).unwrap_or(0),
            shentsize: le16(bytes, 46).unwrap_or(0),
            shnum: le16(bytes, 48).unwrap_or(0),
            shstrndx: le16(bytes, 50).unwrap_or(0),
        };
        let machine = le16(bytes, 18).unwrap_or(0);
        if machine != EM_ARM {
            return Err(LoadError::NotArm(machine));
        }
        Ok(elf)
    }

    fn slice(&self, offset: u32, len: u32) -> Option<&'a [u8]> {
        let start = offset as usize;
        let end = start.checked_add(len as usize)?;
        self.bytes.get(start..end)
    }

    fn program_headers(&self) -> Result<Vec<ProgramHeader>, LoadError> {
        if self.phnum == 0 {
            return Err(LoadError::NoSegments);
        }
        if self.phentsize < 32 {
            return Err(LoadError::Truncated("program header entry size"));
        }
        let mut headers = Vec::with_capacity(usize::from(self.phnum));
        for index in 0..u32::from(self.phnum) {
            let at = u64::from(self.phoff) + u64::from(index) * u64::from(self.phentsize);
            let entry = u32::try_from(at)
                .ok()
                .and_then(|at| self.slice(at, 32))
                .ok_or(LoadError::Truncated("program headers"))?;
            headers.push(ProgramHeader {
                kind: le32(entry, 0).unwrap_or(0),
                offset: le32(entry, 4).unwrap_or(0),
                vaddr: le32(entry, 8).unwrap_or(0),
                paddr: le32(entry, 12).unwrap_or(0),
                filesz: le32(entry, 16).unwrap_or(0),
                memsz: le32(entry, 20).unwrap_or(0),
                flags: le32(entry, 24).unwrap_or(0),
            });
        }
        Ok(headers)
    }

    /// The section headers, or `None` when the file has none or they do not
    /// fit in it: a stripped or truncated table only loses the symbols.
    fn section_headers(&self) -> Option<Vec<SectionHeader>> {
        if self.shnum == 0 || self.shentsize < 40 {
            return None;
        }
        let mut headers = Vec::with_capacity(usize::from(self.shnum));
        for index in 0..u32::from(self.shnum) {
            let at = u64::from(self.shoff) + u64::from(index) * u64::from(self.shentsize);
            let entry = u32::try_from(at).ok().and_then(|at| self.slice(at, 40))?;
            headers.push(SectionHeader {
                name: le32(entry, 0)?,
                kind: le32(entry, 4)?,
                addr: le32(entry, 12)?,
                offset: le32(entry, 16)?,
                size: le32(entry, 20)?,
                link: le32(entry, 24)?,
            });
        }
        Some(headers)
    }

    fn string(&self, table: &SectionHeader, offset: u32) -> Option<&'a str> {
        if offset >= table.size {
            return None;
        }
        let bytes = self.slice(table.offset.checked_add(offset)?, table.size - offset)?;
        let end = bytes.iter().position(|&byte| byte == 0)?;
        std::str::from_utf8(&bytes[..end]).ok()
    }

    fn named_section<'s>(
        &self,
        sections: &'s [SectionHeader],
        names: &[&str],
    ) -> Option<&'s SectionHeader> {
        let strings = sections.get(usize::from(self.shstrndx))?;
        sections.iter().find(|section| {
            self.string(strings, section.name)
                .is_some_and(|name| names.contains(&name))
        })
    }

    fn symbols(&self, sections: &[SectionHeader]) -> Vec<Symbol> {
        let mut symbols = Vec::new();
        for table in sections.iter().filter(|section| section.kind == SHT_SYMTAB) {
            let Some(strings) = sections.get(table.link as usize) else {
                continue;
            };
            let Some(entries) = self.slice(table.offset, table.size) else {
                continue;
            };
            for entry in entries.as_chunks::<16>().0 {
                if symbols.len() >= MAX_SYMBOLS {
                    return symbols;
                }
                let (Some(name), Some(value), Some(size), Some(shndx)) = (
                    le32(entry, 0),
                    le32(entry, 4),
                    le32(entry, 8),
                    le16(entry, 14),
                ) else {
                    continue;
                };
                if shndx == SHN_UNDEF {
                    continue;
                }
                let Some(name) = self.string(strings, name).filter(|name| !name.is_empty()) else {
                    continue;
                };
                let function = entry[12] & 0xf == STT_FUNC;
                symbols.push(Symbol {
                    name: name.to_owned(),
                    address: if function { value & !1 } else { value },
                    size,
                    function: function && shndx != SHN_ABS,
                });
            }
        }
        symbols
    }
}

fn le16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn le32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

/// Builds small ELF files for tests.
#[cfg(test)]
pub(crate) mod elf_builder {
    /// One `PT_LOAD` segment of a test ELF.
    pub(crate) struct LoadSegment {
        pub(crate) vaddr: u32,
        pub(crate) paddr: u32,
        pub(crate) data: Vec<u8>,
        pub(crate) memsz: u32,
        pub(crate) flags: u32,
    }

    /// An ELF32 little-endian ARM executable with `segments`, and, when
    /// `symbols` or `sections` is not empty, a section table holding a
    /// symbol table of `(name, value, size, type)` and the named sections
    /// `(name, address)`.
    pub(crate) fn build(
        segments: &[LoadSegment],
        sections: &[(&str, u32)],
        symbols: &[(&str, u32, u32, u8)],
    ) -> Vec<u8> {
        build_with(segments, sections, symbols, 40, 1, 1)
    }

    pub(crate) fn build_with(
        segments: &[LoadSegment],
        sections: &[(&str, u32)],
        symbols: &[(&str, u32, u32, u8)],
        machine: u16,
        class: u8,
        data: u8,
    ) -> Vec<u8> {
        let phoff = 52u32;
        let mut out = vec![0u8; 52];
        out[..4].copy_from_slice(b"\x7fELF");
        out[4] = class;
        out[5] = data;
        out[6] = 1;
        out[16..18].copy_from_slice(&2u16.to_le_bytes());
        out[18..20].copy_from_slice(&machine.to_le_bytes());
        out[20..24].copy_from_slice(&1u32.to_le_bytes());
        out[24..28].copy_from_slice(&0x0800_0009u32.to_le_bytes());
        out[28..32].copy_from_slice(&phoff.to_le_bytes());
        out[40..42].copy_from_slice(&52u16.to_le_bytes());
        out[42..44].copy_from_slice(&32u16.to_le_bytes());
        out[44..46].copy_from_slice(&(segments.len() as u16).to_le_bytes());
        out.resize(52 + 32 * segments.len(), 0);
        for (index, segment) in segments.iter().enumerate() {
            let offset = out.len() as u32;
            out.extend_from_slice(&segment.data);
            let header = 52 + 32 * index;
            let fields = [
                1,
                offset,
                segment.vaddr,
                segment.paddr,
                segment.data.len() as u32,
                segment.memsz,
                segment.flags,
                4,
            ];
            for (slot, value) in fields.iter().enumerate() {
                out[header + 4 * slot..header + 4 * slot + 4].copy_from_slice(&value.to_le_bytes());
            }
        }
        if sections.is_empty() && symbols.is_empty() {
            return out;
        }
        // Section names: "", the named sections, ".symtab", ".strtab", ".shstrtab".
        let mut shstrtab = vec![0u8];
        let mut name_offsets = Vec::new();
        for name in
            sections
                .iter()
                .map(|(name, _)| *name)
                .chain([".symtab", ".strtab", ".shstrtab"])
        {
            name_offsets.push(shstrtab.len() as u32);
            shstrtab.extend_from_slice(name.as_bytes());
            shstrtab.push(0);
        }
        let mut strtab = vec![0u8];
        let mut symtab = vec![0u8; 16];
        for (name, value, size, kind) in symbols {
            let name_offset = strtab.len() as u32;
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
            let mut entry = [0u8; 16];
            entry[0..4].copy_from_slice(&name_offset.to_le_bytes());
            entry[4..8].copy_from_slice(&value.to_le_bytes());
            entry[8..12].copy_from_slice(&size.to_le_bytes());
            entry[12] = 0x10 | kind;
            entry[14..16].copy_from_slice(&1u16.to_le_bytes());
            symtab.extend_from_slice(&entry);
        }
        let symtab_offset = out.len() as u32;
        out.extend_from_slice(&symtab);
        let strtab_offset = out.len() as u32;
        out.extend_from_slice(&strtab);
        let shstrtab_offset = out.len() as u32;
        out.extend_from_slice(&shstrtab);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        let shoff = out.len() as u32;
        let count = 1 + sections.len() + 3;
        let mut table = vec![0u8; 40];
        let mut push = |name: u32, kind: u32, addr: u32, offset: u32, size: u32, link: u32| {
            let mut entry = [0u8; 40];
            for (slot, value) in [name, kind, 0, addr, offset, size, link, 0, 4, 0]
                .iter()
                .enumerate()
            {
                entry[4 * slot..4 * slot + 4].copy_from_slice(&value.to_le_bytes());
            }
            table.extend_from_slice(&entry);
        };
        for (index, (_, addr)) in sections.iter().enumerate() {
            push(name_offsets[index], 1, *addr, 0, 0, 0);
        }
        let base = sections.len();
        let strtab_index = (1 + base + 1) as u32;
        push(
            name_offsets[base],
            2,
            0,
            symtab_offset,
            symtab.len() as u32,
            strtab_index,
        );
        push(
            name_offsets[base + 1],
            3,
            0,
            strtab_offset,
            strtab.len() as u32,
            0,
        );
        push(
            name_offsets[base + 2],
            3,
            0,
            shstrtab_offset,
            shstrtab.len() as u32,
            0,
        );
        out.extend_from_slice(&table);
        out[32..36].copy_from_slice(&shoff.to_le_bytes());
        out[46..48].copy_from_slice(&40u16.to_le_bytes());
        out[48..50].copy_from_slice(&(count as u16).to_le_bytes());
        out[50..52].copy_from_slice(&((count - 1) as u16).to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::elf_builder::{build, build_with, LoadSegment};
    use super::*;

    fn flash(data: &[u8]) -> LoadSegment {
        LoadSegment {
            vaddr: 0x0800_0000,
            paddr: 0x0800_0000,
            data: data.to_vec(),
            memsz: data.len() as u32,
            flags: PF_X | 4,
        }
    }

    #[test]
    fn raw_image_loads_at_its_base_with_the_vector_table_there() {
        let bytes = [0x00, 0x10, 0x00, 0x20, 0x09, 0x00, 0x00, 0x08];
        let image = Image::raw(&bytes, 0x0800_0000).unwrap();
        assert_eq!(image.format(), ImageFormat::Raw);
        assert_eq!(image.vector_table(), 0x0800_0000);
        assert_eq!(image.segments().len(), 1);
        let segment = &image.segments()[0];
        assert_eq!(segment.address, 0x0800_0000);
        assert_eq!(segment.size, 8);
        assert!(!segment.writable);
        assert_eq!(image.read_u32(0x0800_0000), Some(0x2000_1000));
        assert_eq!(image.read_u32(0x0800_0004), Some(0x0800_0009));
        assert_eq!(image.read_u32(0x0800_0006), None, "reads past the end");
        assert!(image.symbols().is_empty());
        assert_eq!(image.entry(), None);
    }

    #[test]
    fn raw_image_refuses_empty_and_wrapping_images() {
        assert_eq!(Image::raw(&[], 0), Err(LoadError::Empty));
        assert_eq!(
            Image::raw(&[0; 16], 0xffff_fff8),
            Err(LoadError::AddressOverflow {
                address: 0xffff_fff8,
                size: 16
            })
        );
        // A raw image may end exactly at the top of the address space.
        assert!(Image::raw(&[0; 8], 0xffff_fff8).is_ok());
    }

    #[test]
    fn load_picks_raw_with_a_base_and_elf_without() {
        let elf = build(&[flash(&[1, 2, 3, 4])], &[], &[]);
        assert_eq!(Image::load(&elf, None).unwrap().format(), ImageFormat::Elf);
        // With a base, even ELF bytes are a raw image: the caller asked for it.
        assert_eq!(
            Image::load(&elf, Some(0x100)).unwrap().format(),
            ImageFormat::Raw
        );
        assert_eq!(Image::load(&[1, 2, 3], None), Err(LoadError::NotElf));
    }

    #[test]
    fn elf_loads_segments_at_their_load_address() {
        let code = [0xaa; 16];
        let data = [1, 2, 3, 4];
        let elf = build(
            &[
                flash(&code),
                // .data: runs at 0x20000000, stored in flash after the code.
                LoadSegment {
                    vaddr: 0x2000_0000,
                    paddr: 0x0800_0010,
                    data: data.to_vec(),
                    memsz: 0x40,
                    flags: PF_W | 4,
                },
                // .bss with no file bytes.
                LoadSegment {
                    vaddr: 0x2000_0100,
                    paddr: 0x2000_0100,
                    data: Vec::new(),
                    memsz: 0x80,
                    flags: PF_W | 4,
                },
            ],
            &[],
            &[],
        );
        let image = Image::elf(&elf).unwrap();
        assert_eq!(image.format(), ImageFormat::Elf);
        let segments = image.segments();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].address, 0x0800_0000);
        assert_eq!(segments[0].data, code);
        assert!(segments[0].executable);
        assert_eq!(segments[1].address, 0x0800_0010);
        assert_eq!(segments[1].data, data);
        assert_eq!(
            segments[1].size, 4,
            "the load copy holds only the file bytes"
        );
        assert!(!segments[1].writable, "the flash copy of .data is not RAM");
        assert_eq!(
            image.ram(),
            &[
                RamRange {
                    address: 0x2000_0000,
                    size: 0x40,
                    executable: false
                },
                RamRange {
                    address: 0x2000_0100,
                    size: 0x80,
                    executable: false
                }
            ]
        );
        // No vector-table section: the lowest loaded address.
        assert_eq!(image.vector_table(), 0x0800_0000);
        assert_eq!(image.entry(), Some(0x0800_0009));
    }

    #[test]
    fn elf_symbols_resolve_and_functions_drop_the_thumb_bit() {
        let elf = build(
            &[flash(&[0; 64])],
            &[(".text", 0x0800_0040), (".isr_vector", 0x0800_0000)],
            &[
                ("main", 0x0800_0021, 12, STT_FUNC),
                ("rx_buf", 0x2000_0008, 64, 1),
            ],
        );
        let image = Image::elf(&elf).unwrap();
        let main = image.symbol("main").unwrap();
        assert_eq!(main.address, 0x0800_0020);
        assert!(main.function);
        let buffer = image.symbol("rx_buf").unwrap();
        assert_eq!((buffer.address, buffer.size), (0x2000_0008, 64));
        assert!(!buffer.function);
        assert!(image.symbol("missing").is_none());
        assert_eq!(image.vector_table(), 0x0800_0000);
    }

    #[test]
    fn elf_vector_table_section_wins_over_the_lowest_address() {
        let elf = build(
            &[
                LoadSegment {
                    vaddr: 0,
                    paddr: 0,
                    data: vec![0; 8],
                    memsz: 8,
                    flags: PF_X | 4,
                },
                flash(&[0; 64]),
            ],
            &[(".isr_vector", 0x0800_0000)],
            &[],
        );
        assert_eq!(Image::elf(&elf).unwrap().vector_table(), 0x0800_0000);
    }

    #[test]
    fn elf_refuses_foreign_and_malformed_files() {
        let segments = [flash(&[0; 8])];
        assert_eq!(
            Image::elf(&build_with(&segments, &[], &[], 62, 1, 1)),
            Err(LoadError::NotArm(62))
        );
        assert_eq!(
            Image::elf(&build_with(&segments, &[], &[], 40, 2, 1)),
            Err(LoadError::Not32Bit(2))
        );
        assert_eq!(
            Image::elf(&build_with(&segments, &[], &[], 40, 1, 2)),
            Err(LoadError::NotLittleEndian(2))
        );
        assert_eq!(Image::elf(&[]), Err(LoadError::Empty));
        assert_eq!(
            Image::elf(b"\x7fELF\x01\x01"),
            Err(LoadError::Truncated("ELF header"))
        );
        let elf = build(&segments, &[], &[]);
        assert_eq!(
            Image::elf(&elf[..elf.len() - 4]),
            Err(LoadError::Truncated("segment bytes"))
        );
        assert_eq!(
            Image::elf(&elf[..70]),
            Err(LoadError::Truncated("program headers"))
        );
        assert_eq!(
            Image::elf(&build(&[], &[], &[])),
            Err(LoadError::NoSegments)
        );
    }

    #[test]
    fn elf_refuses_overlapping_and_oversized_segments() {
        let overlapping = build(
            &[
                flash(&[0; 16]),
                LoadSegment {
                    vaddr: 0x0800_0008,
                    paddr: 0x0800_0008,
                    data: vec![0; 16],
                    memsz: 16,
                    flags: 4,
                },
            ],
            &[],
            &[],
        );
        assert_eq!(
            Image::elf(&overlapping),
            Err(LoadError::Overlap {
                first: 0x0800_0000,
                second: 0x0800_0008
            })
        );
        let huge = build(
            &[LoadSegment {
                vaddr: 0x2000_0000,
                paddr: 0x2000_0000,
                data: Vec::new(),
                memsz: 0xf000_0000,
                flags: PF_W,
            }],
            &[],
            &[],
        );
        assert!(matches!(
            Image::elf(&huge),
            Err(LoadError::SegmentTooLarge { .. })
        ));
        let wrapping = build(
            &[LoadSegment {
                vaddr: 0xffff_fff0,
                paddr: 0xffff_fff0,
                data: vec![0; 32],
                memsz: 32,
                flags: 4,
            }],
            &[],
            &[],
        );
        assert!(matches!(
            Image::elf(&wrapping),
            Err(LoadError::AddressOverflow { .. })
        ));
    }

    #[test]
    fn elf_with_a_truncated_section_table_still_loads_without_symbols() {
        let mut elf = build(
            &[flash(&[0; 8])],
            &[],
            &[("main", 0x0800_0001, 2, STT_FUNC)],
        );
        // Point the section table past the end of the file.
        elf[32..36].copy_from_slice(&0xffff_0000u32.to_le_bytes());
        let image = Image::elf(&elf).unwrap();
        assert!(image.symbols().is_empty());
    }
}
