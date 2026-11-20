// SPDX-License-Identifier: Apache-2.0

//! The dirty-page fast snapshot of the full-system lane (`reset=fast`).
//!
//! A `loadvm` restores the whole machine from the snapshot on disk: every RAM
//! page, every device, every CPU. A run changes a handful of pages, so most of
//! that work puts back what did not change. The fast snapshot restores what the
//! run changed and nothing else:
//!
//! * **CPUs and devices**: a `system_reset` ([`Machine::reset_devices`]). The
//!   baseline is the machine as a reset leaves it (the transport issues one
//!   before it takes the baseline), so a reset brings every CPU and device
//!   back to it, a fault's exception state included. QEMU keeps RAM across a
//!   reset, reloading only the image segments it loaded into RAM
//!   ([`reset_reloaded_ranges`]).
//! * **RAM**: the pages the guest wrote. A QEMU TCG plugin
//!   ([`DIRTY_PAGE_PLUGIN_SOURCE`], loaded with `-plugin`) records the
//!   guest-physical page of every store to RAM in a log file
//!   ([`PluginDirtyLog`]), a store to a bit-band alias as the RAM word it
//!   writes ([`MemoryMap::bitband`]). bhf adds the writes the log does not
//!   see ([`FastSnapshot::note_unlogged_write`]): its own (the input), and on
//!   a Cortex-M core the exception frames still on the stack at the stop
//!   ([`live_exception_frames`]), which the core stacks without a store. It
//!   writes the baseline of each page back.
//!
//! bhf learns a page's baseline the first time the guest writes it. That reset
//! restores the whole machine from the full snapshot ([`Machine::restore_all`],
//! a `loadvm`), and bhf reads the page from the restored guest. Once the pages
//! a target writes are known, every reset is fast. A log that overflowed, a
//! page past [`FastSnapshotLimits::max_baseline_bytes`], and the reset after
//! one that failed part way restore the whole machine too.
//!
//! The log is bound to the QEMU that runs it: after a run that reached a stop,
//! the plugin must have acknowledged the log's current epoch
//! ([`DirtyLog::take`]), and the epoch must be the one this reader wrote, so a
//! log no plugin writes, or one a second session empties too, is refused.
//!
//! What the log does not see is not restored: a device's DMA into RAM, a
//! device's own state that a reset does not clear (a flash part's contents),
//! and on a Cortex-M core the frame of an exception taken and returned before
//! the stop (an interrupt), when no store dirtied its page.

use crate::error::{Result, TransportError};
use crate::gdb::GdbClient;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// The C source of the QEMU TCG plugin that writes the dirty-page log. Build
/// it as a shared object (`cc -shared -fPIC -O2 -o libbhf_qemu_dirty_pages.so
/// bhf_qemu_dirty_pages.c -lpthread`) and load it into `qemu-system-*` with
/// `-plugin ./libbhf_qemu_dirty_pages.so,log=PATH`.
pub const DIRTY_PAGE_PLUGIN_SOURCE: &str = include_str!("../qemu_plugin/bhf_qemu_dirty_pages.c");

/// The plugin source's file name.
pub const DIRTY_PAGE_PLUGIN_SOURCE_NAME: &str = "bhf_qemu_dirty_pages.c";

/// The shared object the plugin source builds to.
pub const DIRTY_PAGE_PLUGIN_LIBRARY_NAME: &str = "libbhf_qemu_dirty_pages.so";

/// The log's first word: `BXDP` little-endian.
pub const DIRTY_LOG_MAGIC: u32 = 0x5044_5842;
/// The log layout this reader speaks.
pub const DIRTY_LOG_VERSION: u32 = 1;
/// Bytes before the page array.
const HEADER_BYTES: u64 = 88;
/// Offset of the `epoch` word.
const EPOCH_OFFSET: u64 = 16;
/// Offset of the `count` and `overflow` words.
const COUNT_OFFSET: u64 = 24;
/// Offset of the `bitband` windows, each `alias`, `size`, `source` (`u64`s).
const BITBAND_OFFSET: u64 = 40;
/// The bit-band windows the log header holds.
pub const BITBAND_WINDOWS: usize = 2;
/// The smallest and largest page the log may use: 64 bytes to 64 KiB.
pub const MIN_PAGE_BITS: u32 = 6;
pub const MAX_PAGE_BITS: u32 = 16;
/// The most pages a log may hold between two clears.
pub const MAX_LOG_CAPACITY: u32 = 4 * 1024 * 1024;

/// The largest memory read or write one gdb packet carries: QEMU's gdbstub
/// takes packets of up to 4 KiB, and `M` and `m` send each byte as two hex
/// digits.
const MEMORY_CHUNK: usize = 1024;

/// Guest memory the snapshot reads baselines from and writes them back to.
/// Writes through it are the host's, not the guest's: the dirty-page log does
/// not record them.
pub trait GuestMemory {
    /// Read `len` bytes at `address`.
    fn read(&mut self, address: u64, len: usize) -> Result<Vec<u8>>;
    /// Write `bytes` at `address`.
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<()>;
}

impl<C: Read + Write> GuestMemory for GdbClient<C> {
    fn read(&mut self, address: u64, len: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let chunk = (len - out.len()).min(MEMORY_CHUNK);
            out.extend(self.read_memory(address + out.len() as u64, chunk)?);
        }
        Ok(out)
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<()> {
        for (index, chunk) in bytes.chunks(MEMORY_CHUNK).enumerate() {
            self.write_memory(address + (index * MEMORY_CHUNK) as u64, chunk)?;
        }
        Ok(())
    }
}

/// The pages written since a log was last emptied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirtyPages {
    /// These pages, by number (`address >> page_bits`).
    Pages(BTreeSet<u64>),
    /// More pages than the log holds: which ones is not known.
    Overflowed,
}

impl DirtyPages {
    /// Add the pages `[address, address + len)` covers.
    pub fn add_range(&mut self, address: u64, len: u64, page_bits: u32) {
        if let Self::Pages(pages) = self {
            pages.extend(pages_of(address, len, page_bits));
        }
    }
}

/// The pages `[address, address + len)` covers.
fn pages_of(address: u64, len: u64, page_bits: u32) -> impl Iterator<Item = u64> {
    let first = address >> page_bits;
    let last = match len {
        0 => None,
        len => Some(address.saturating_add(len - 1) >> page_bits),
    };
    last.into_iter().flat_map(move |last| first..=last)
}

/// A record of the pages the guest wrote.
pub trait DirtyLog {
    /// The log's page size, as a power of two.
    fn page_bits(&self) -> u32;
    /// The pages written since the last call, emptying the log. The guest
    /// must be stopped. `ran`: the guest ran to a stop since the last call,
    /// so whatever writes the log must have seen it run; a log that shows no
    /// sign of that is refused, since it is not the guest's.
    fn take(&mut self, ran: bool) -> Result<DirtyPages>;
}

/// A bit-band window of an ARMv7-M core: a store to a word of
/// `[alias, alias + size)` sets or clears one bit of the RAM byte at
/// `source + ((address - alias) >> 5)`. QEMU's bit-band device writes that
/// byte itself, out of the plugin's sight, so the plugin logs a store to the
/// alias as the RAM word it writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitBandWindow {
    /// The alias window's first address.
    pub alias: u64,
    /// The alias window's bytes (32 for each byte it aliases).
    pub size: u64,
    /// The first address of the memory it aliases.
    pub source: u64,
}

/// The log file the QEMU plugin ([`DIRTY_PAGE_PLUGIN_SOURCE`]) writes: a
/// fixed header, then the page numbers. bhf reads it and empties it while the
/// guest is stopped; a new epoch tells the plugin the log was emptied.
#[derive(Debug)]
pub struct PluginDirtyLog {
    file: File,
    path: PathBuf,
    page_bits: u32,
    capacity: u32,
    /// The epoch the log is in: the one this reader last wrote, or found when
    /// it opened the log.
    epoch: u64,
}

/// The fields of a log's header.
#[derive(Debug, Clone, Copy)]
struct LogHeader {
    magic: u32,
    version: u32,
    page_bits: u32,
    capacity: u32,
    epoch: u64,
    count: u32,
    overflow: u32,
    /// The plugin's acknowledgement: one more than the last epoch the guest
    /// made a memory access in, 0 for none.
    seen: u64,
}

impl PluginDirtyLog {
    /// Open the log the plugin keeps at `path`, checking its header.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let missing = |reason: String| {
            TransportError::protocol(format!(
                "dirty-page log {}: {reason}; reset=fast needs qemu-system started with \
                 -plugin {DIRTY_PAGE_PLUGIN_LIBRARY_NAME},log={} (the plugin built from \
                 {DIRTY_PAGE_PLUGIN_SOURCE_NAME})",
                path.display(),
                path.display()
            ))
        };
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| missing(error.to_string()))?;
        let length = file
            .metadata()
            .map_err(|error| missing(error.to_string()))?
            .len();
        if length < HEADER_BYTES {
            return Err(missing(format!(
                "{length} bytes is shorter than the {HEADER_BYTES}-byte header"
            )));
        }
        let header = read_header(&mut file)?;
        if header.magic != DIRTY_LOG_MAGIC {
            return Err(missing(format!(
                "magic {:#010x} is not the plugin's {DIRTY_LOG_MAGIC:#010x}",
                header.magic
            )));
        }
        if header.version != DIRTY_LOG_VERSION {
            return Err(TransportError::protocol(format!(
                "dirty-page log {}: layout version {} (this bhf reads version \
                 {DIRTY_LOG_VERSION}); rebuild the plugin from this bhf's \
                 {DIRTY_PAGE_PLUGIN_SOURCE_NAME}",
                path.display(),
                header.version
            )));
        }
        if !(MIN_PAGE_BITS..=MAX_PAGE_BITS).contains(&header.page_bits) {
            return Err(TransportError::protocol(format!(
                "dirty-page log {}: page_bits {} is outside {MIN_PAGE_BITS}..={MAX_PAGE_BITS}",
                path.display(),
                header.page_bits
            )));
        }
        if !(1..=MAX_LOG_CAPACITY).contains(&header.capacity) {
            return Err(TransportError::protocol(format!(
                "dirty-page log {}: capacity {} is outside 1..={MAX_LOG_CAPACITY}",
                path.display(),
                header.capacity
            )));
        }
        let needed = HEADER_BYTES + u64::from(header.capacity) * 8;
        if length < needed {
            return Err(TransportError::protocol(format!(
                "dirty-page log {}: {length} bytes cannot hold its {} pages ({needed} bytes)",
                path.display(),
                header.capacity
            )));
        }
        Ok(Self {
            file,
            path: path.to_owned(),
            page_bits: header.page_bits,
            capacity: header.capacity,
            epoch: header.epoch,
        })
    }

    /// The log file's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Tell the plugin which bit-band windows the machine has (at most
    /// [`BITBAND_WINDOWS`]; the rest are cleared), so it logs a store to an
    /// alias as the RAM word the store writes. The guest must be stopped.
    pub fn set_bitband_windows(&mut self, windows: &[BitBandWindow]) -> Result<()> {
        if windows.len() > BITBAND_WINDOWS {
            return Err(TransportError::protocol(format!(
                "dirty-page log {}: {} bit-band windows, more than the {BITBAND_WINDOWS} the \
                 log holds",
                self.path.display(),
                windows.len()
            )));
        }
        let mut bytes = Vec::with_capacity(BITBAND_WINDOWS * 24);
        for index in 0..BITBAND_WINDOWS {
            let window = windows.get(index).copied().unwrap_or(BitBandWindow {
                alias: 0,
                size: 0,
                source: 0,
            });
            for word in [window.alias, window.size, window.source] {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
        }
        self.file.seek(SeekFrom::Start(BITBAND_OFFSET))?;
        self.file.write_all(&bytes)?;
        Ok(())
    }
}

fn read_header(file: &mut File) -> Result<LogHeader> {
    let mut bytes = [0_u8; HEADER_BYTES as usize];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut bytes)?;
    let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"));
    Ok(LogHeader {
        magic: u32_at(0),
        version: u32_at(4),
        page_bits: u32_at(8),
        capacity: u32_at(12),
        epoch: u64::from_le_bytes(bytes[16..24].try_into().expect("8 bytes")),
        count: u32_at(24),
        overflow: u32_at(28),
        seen: u64::from_le_bytes(bytes[32..40].try_into().expect("8 bytes")),
    })
}

impl DirtyLog for PluginDirtyLog {
    fn page_bits(&self) -> u32 {
        self.page_bits
    }

    fn take(&mut self, ran: bool) -> Result<DirtyPages> {
        let header = read_header(&mut self.file)?;
        if header.magic != DIRTY_LOG_MAGIC
            || header.page_bits != self.page_bits
            || header.capacity != self.capacity
        {
            return Err(TransportError::protocol(format!(
                "dirty-page log {}: its header changed under bhf (magic {:#010x}, page_bits \
                 {}, capacity {}): qemu-system restarted with other plugin arguments",
                self.path.display(),
                header.magic,
                header.page_bits,
                header.capacity
            )));
        }
        if header.epoch != self.epoch {
            return Err(TransportError::protocol(format!(
                "dirty-page log {}: its epoch is {}, not the {} bhf left it in: another bhf \
                 session empties this log too, or qemu-system restarted; give each qemu-system \
                 its own log (with --workers, put {{worker}} in dirty_log=)",
                self.path.display(),
                header.epoch,
                self.epoch
            )));
        }
        if ran && header.seen != self.epoch.wrapping_add(1) {
            return Err(TransportError::protocol(format!(
                "dirty-page log {}: the guest ran, and no dirty-page plugin saw it run: no \
                 plugin in this qemu-system writes this log, so it would report no page the \
                 guest wrote; start qemu-system with -plugin \
                 {DIRTY_PAGE_PLUGIN_LIBRARY_NAME},log={} (the plugin built from \
                 {DIRTY_PAGE_PLUGIN_SOURCE_NAME})",
                self.path.display(),
                self.path.display()
            )));
        }
        let dirty = if header.overflow != 0 || header.count > self.capacity {
            DirtyPages::Overflowed
        } else {
            let mut raw = vec![0_u8; header.count as usize * 8];
            self.file.seek(SeekFrom::Start(HEADER_BYTES))?;
            self.file.read_exact(&mut raw)?;
            DirtyPages::Pages(
                raw.as_chunks::<8>()
                    .0
                    .iter()
                    .map(|page| u64::from_le_bytes(*page))
                    .collect(),
            )
        };
        // Empty the log, then start a new epoch so the plugin records afresh.
        let epoch = self.epoch.wrapping_add(1);
        self.file.seek(SeekFrom::Start(COUNT_OFFSET))?;
        self.file.write_all(&[0_u8; 8])?;
        self.file.seek(SeekFrom::Start(EPOCH_OFFSET))?;
        self.file.write_all(&epoch.to_le_bytes())?;
        self.epoch = epoch;
        Ok(dirty)
    }
}

/// Bounds on what a fast snapshot keeps.
#[derive(Debug, Clone, Copy)]
pub struct FastSnapshotLimits {
    /// The baseline bytes kept for pages the guest writes. A page past it is
    /// not learned, and a reset after a run that wrote it restores the whole
    /// machine.
    pub max_baseline_bytes: usize,
}

impl Default for FastSnapshotLimits {
    fn default() -> Self {
        Self {
            max_baseline_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Pages `first..first + count`, all with a baseline, written back as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageRun {
    pub first: u64,
    pub count: u64,
}

/// How the snapshot brings memory back after a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestorePlan {
    /// Write these runs of pages back from their baseline.
    Pages(Vec<PageRun>),
    /// Restore the whole machine, then learn the baseline of `learn`: pages
    /// the guest wrote that have none yet. Empty when the log overflowed.
    Full { learn: Vec<u64> },
}

/// The baseline of every page a guest has been seen to write.
#[derive(Debug, Clone)]
pub struct DirtyPageSnapshot {
    page_bits: u32,
    baseline: BTreeMap<u64, Vec<u8>>,
    max_pages: usize,
}

impl DirtyPageSnapshot {
    /// An empty snapshot of `2^page_bits`-byte pages.
    pub fn new(page_bits: u32, limits: FastSnapshotLimits) -> Result<Self> {
        if !(MIN_PAGE_BITS..=MAX_PAGE_BITS).contains(&page_bits) {
            return Err(TransportError::protocol(format!(
                "page_bits {page_bits} is outside {MIN_PAGE_BITS}..={MAX_PAGE_BITS}"
            )));
        }
        Ok(Self {
            page_bits,
            baseline: BTreeMap::new(),
            max_pages: limits.max_baseline_bytes >> page_bits,
        })
    }

    /// The page size, as a power of two.
    pub fn page_bits(&self) -> u32 {
        self.page_bits
    }

    /// The pages whose baseline is known.
    pub fn known_pages(&self) -> usize {
        self.baseline.len()
    }

    /// How to bring back memory after a run wrote `dirty`.
    pub fn plan(&self, dirty: &DirtyPages) -> RestorePlan {
        let DirtyPages::Pages(pages) = dirty else {
            return RestorePlan::Full { learn: Vec::new() };
        };
        let learn: Vec<u64> = pages
            .iter()
            .copied()
            .filter(|page| !self.baseline.contains_key(page))
            .collect();
        if !learn.is_empty() {
            return RestorePlan::Full { learn };
        }
        RestorePlan::Pages(runs(pages.iter().copied()))
    }

    /// Write `runs` back from their baseline. Returns the pages written.
    pub fn apply<M: GuestMemory + ?Sized>(&self, memory: &mut M, runs: &[PageRun]) -> Result<u64> {
        let mut written = 0;
        for run in runs {
            let mut bytes = Vec::with_capacity((run.count as usize) << self.page_bits);
            for page in run.first..run.first + run.count {
                let baseline = self.baseline.get(&page).ok_or_else(|| {
                    TransportError::protocol(format!(
                        "page {:#x} has no baseline to write back",
                        page << self.page_bits
                    ))
                })?;
                bytes.extend_from_slice(baseline);
            }
            memory.write(run.first << self.page_bits, &bytes)?;
            written += run.count;
        }
        Ok(written)
    }

    /// Read the baseline of `pages` from `memory`, which holds the baseline
    /// (the whole machine was just restored). Pages past the limit are left
    /// out. Returns the pages learned.
    pub fn learn<M: GuestMemory + ?Sized>(&mut self, memory: &mut M, pages: &[u64]) -> Result<u64> {
        let room = self.max_pages.saturating_sub(self.baseline.len());
        let fresh = pages
            .iter()
            .copied()
            .filter(|page| !self.baseline.contains_key(page))
            .collect::<BTreeSet<u64>>()
            .into_iter()
            .take(room);
        let size = 1_usize << self.page_bits;
        let mut learned = 0;
        for run in runs(fresh) {
            let bytes = memory.read(run.first << self.page_bits, (run.count as usize) * size)?;
            for (index, page) in bytes.chunks_exact(size).enumerate() {
                self.baseline
                    .insert(run.first + index as u64, page.to_vec());
            }
            learned += run.count;
        }
        Ok(learned)
    }
}

/// Group ascending page numbers into runs of consecutive pages.
fn runs(pages: impl IntoIterator<Item = u64>) -> Vec<PageRun> {
    let mut out: Vec<PageRun> = Vec::new();
    for page in pages {
        match out.last_mut() {
            Some(run) if run.first + run.count == page => run.count += 1,
            _ => out.push(PageRun {
                first: page,
                count: 1,
            }),
        }
    }
    out
}

/// The RAM ranges, as `(address, len)`, that QEMU's reset reloads, from the
/// HMP `info roms` listing: each image blob QEMU loaded into RAM (`mem=ram`)
/// it writes again on every reset, its zero fill included. A blob in ROM is
/// written once, and a firmware file is not reloaded, so neither counts. A
/// line this cannot read is left out, which only costs writes.
pub fn reset_reloaded_ranges(info_roms: &str) -> Vec<(u64, u64)> {
    let field = |line: &str, key: &str| {
        line.split_whitespace()
            .find_map(|word| word.strip_prefix(key))
            .map(str::to_owned)
    };
    info_roms
        .lines()
        .filter(|line| line.starts_with("addr=") && field(line, "mem=").as_deref() == Some("ram"))
        .filter_map(|line| {
            let address = u64::from_str_radix(&field(line, "addr=")?, 16).ok()?;
            let size = field(line, "size=")?;
            let size = u64::from_str_radix(size.strip_prefix("0x")?, 16).ok()?;
            Some((address, size))
        })
        .collect()
}

/// The parts of QEMU's memory map the fast snapshot needs, from the HMP
/// `info mtree -f` listing (every address space's flat view).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryMap {
    /// RAM, as `(address, len)` ranges.
    pub ram: Vec<(u64, u64)>,
    /// The bit-band windows whose aliased memory is RAM.
    pub bitband: Vec<BitBandWindow>,
}

/// The bytes of alias of an ARMv7-M bit-band window, 32 for each byte of the
/// 1 MiB it aliases, which lies this far below it (QEMU's `bitband` regions
/// at 0x2200_0000 and 0x4200_0000 alias 0x2000_0000 and 0x4000_0000).
const BITBAND_ALIAS_BYTES: u64 = 0x0200_0000;

impl MemoryMap {
    /// Read the RAM ranges and bit-band windows from `info mtree -f`, whose
    /// lines read `  0000000020000000-00000000203fffff (prio 0, ram): name`.
    /// A line this cannot read is left out.
    pub fn from_info_mtree(listing: &str) -> Self {
        let mut ram: Vec<(u64, u64)> = Vec::new();
        let mut aliases: Vec<u64> = Vec::new();
        for line in listing.lines() {
            let Some((range, rest)) = line.trim().split_once(' ') else {
                continue;
            };
            let Some((start, end)) = range.split_once('-') else {
                continue;
            };
            let (Ok(start), Ok(end)) =
                (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
            else {
                continue;
            };
            let Some(len) = end.checked_sub(start).and_then(|span| span.checked_add(1)) else {
                continue;
            };
            let Some((attributes, name)) = rest.split_once("): ") else {
                continue;
            };
            let kind = attributes.rsplit(", ").next().unwrap_or_default();
            let name = name.split_whitespace().next().unwrap_or_default();
            match (kind, name) {
                ("ram", _) if !ram.contains(&(start, len)) => ram.push((start, len)),
                ("i/o", "bitband") if len == BITBAND_ALIAS_BYTES && !aliases.contains(&start) => {
                    aliases.push(start)
                }
                _ => {}
            }
        }
        ram.sort_unstable();
        let bitband = aliases
            .into_iter()
            .filter_map(|alias| {
                let source = alias.checked_sub(BITBAND_ALIAS_BYTES)?;
                let aliased = (source, BITBAND_ALIAS_BYTES >> 5);
                (!clip_to(&ram, aliased).is_empty()).then_some(BitBandWindow {
                    alias,
                    size: BITBAND_ALIAS_BYTES,
                    source,
                })
            })
            .collect();
        Self { ram, bitband }
    }
}

/// The parts of `range` (`(address, len)`) that lie in `ram`.
fn clip_to(ram: &[(u64, u64)], (address, len): (u64, u64)) -> Vec<(u64, u64)> {
    let end = address.saturating_add(len);
    ram.iter()
        .filter_map(|&(base, size)| {
            let start = address.max(base);
            let stop = end.min(base.saturating_add(size));
            (start < stop).then(|| (start, stop - start))
        })
        .collect()
}

/// The registers of a Cortex-M (M-profile) core the fast snapshot reads, by
/// their gdb register number, from the gdbstub's target description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MProfileRegisters {
    /// The stack pointer in use.
    pub sp: u32,
    /// The program status register, whose IPSR field names the active
    /// exception.
    pub xpsr: u32,
    /// The process stack pointer (`org.gnu.gdb.arm.m-system`), when the stub
    /// describes it.
    pub psp: Option<u32>,
}

impl MProfileRegisters {
    /// Find the registers in the target description `documents` (the
    /// `target.xml` annex, then each it includes, in order). `None` when the
    /// core is not M-profile (no `org.gnu.gdb.arm.m-profile` feature).
    pub fn from_target_description(documents: &[String]) -> Option<Self> {
        if !documents
            .iter()
            .any(|document| document.contains("\"org.gnu.gdb.arm.m-profile\""))
        {
            return None;
        }
        // A register without a regnum is one past the register before it,
        // across features, as gdb numbers them.
        let mut next = 0_u32;
        let mut numbers: BTreeMap<String, u32> = BTreeMap::new();
        for document in documents {
            for tag in document.split("<reg ").skip(1) {
                let tag = tag.split('>').next().unwrap_or_default();
                let attribute = |key: &str| {
                    let start = tag.find(&format!("{key}=\""))? + key.len() + 2;
                    let len = tag[start..].find('"')?;
                    Some(tag[start..start + len].to_owned())
                };
                let Some(name) = attribute("name") else {
                    continue;
                };
                let number = attribute("regnum")
                    .and_then(|regnum| regnum.parse().ok())
                    .unwrap_or(next);
                next = number.saturating_add(1);
                numbers.entry(name).or_insert(number);
            }
        }
        Some(Self {
            sp: *numbers.get("sp")?,
            xpsr: *numbers.get("xpsr")?,
            psp: numbers.get("psp").copied(),
        })
    }
}

/// An M-profile core where a run stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MProfileStop {
    /// The stack pointer in use (the main one, in handler mode).
    pub sp: u64,
    /// The program status register.
    pub xpsr: u32,
    /// The process stack pointer, when it was read.
    pub psp: Option<u64>,
}

impl MProfileStop {
    /// An exception is active (`IPSR`, the low 9 bits of `xPSR`, is not 0),
    /// so its frame, and those of any it preempted, are still stacked.
    pub fn in_handler(&self) -> bool {
        self.xpsr & 0x1ff != 0
    }
}

/// The most an M-profile exception entry stacks: 8 words, 18 more with the
/// floating-point state, 10 for the v8-M secure context and 16 for its
/// floating-point registers, and a word of alignment.
pub const MAX_EXCEPTION_FRAME: u64 = 0xd8;
/// How far below the baseline's stack pointer a stop's main stack pointer may
/// be and still be taken as the stack the baseline starts.
pub const STACK_SPAN_LIMIT: u64 = 64 * 1024;
/// How much above the stop's stack pointer is taken to hold the frames of
/// the active exceptions when the stack does not run up to the baseline's
/// (the firmware moved it).
pub const HANDLER_STACK_WINDOW: u64 = 4 * 1024;

/// The RAM a Cortex-M core may have written stacking the exception frames
/// still live at `stop`, as `(address, len)` ranges: the core stacks a frame
/// without a store, so the dirty-page log does not see it.
///
/// With an exception active, the frames lie above the main stack pointer: up
/// to `baseline_sp` (the stack pointer arm took the baseline with) when the
/// stack runs up to it, else in the [`HANDLER_STACK_WINDOW`] above it; and,
/// for a thread on the process stack, at `psp`. In thread mode no frame is
/// live: an exception that returned took its frame off the stack, though not
/// out of RAM, so its frame is put back only when a store dirtied the page.
pub fn live_exception_frames(
    stop: MProfileStop,
    baseline_sp: u64,
    ram: &[(u64, u64)],
) -> Vec<(u64, u64)> {
    if !stop.in_handler() {
        return Vec::new();
    }
    let main = match baseline_sp.checked_sub(stop.sp) {
        Some(span) if span > 0 && span <= STACK_SPAN_LIMIT => (stop.sp, span),
        _ => (stop.sp, HANDLER_STACK_WINDOW),
    };
    let process = stop
        .psp
        .filter(|psp| *psp != 0)
        .map(|psp| (psp, MAX_EXCEPTION_FRAME));
    std::iter::once(main)
        .chain(process)
        .flat_map(|range| clip_to(ram, range))
        .collect()
}

/// What restores the machine's CPUs and devices, and the whole machine.
pub trait Machine {
    /// Bring every CPU and device back to the baseline, leaving RAM as it is
    /// (QEMU's `system_reset`).
    fn reset_devices(&mut self) -> Result<()>;
    /// Restore the whole machine, RAM included, from the full snapshot
    /// (QMP `stop` + `loadvm`).
    fn restore_all(&mut self) -> Result<()>;
}

/// How one [`FastSnapshot::reset`] brought the machine back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastReset {
    /// A device reset and `pages` pages written back from their baseline.
    DirtyPages { pages: u64 },
    /// The whole machine restored from the full snapshot, and the baseline of
    /// `learned` pages read from it.
    Full { learned: u64 },
}

/// A dirty-page log, the baselines it has taught, and the pages the host
/// writes, driven between runs by [`FastSnapshot::reset`].
#[derive(Debug)]
pub struct FastSnapshot<L> {
    log: L,
    pages: DirtyPageSnapshot,
    /// Pages written since the last reset that the log does not see.
    unlogged: BTreeSet<u64>,
    /// The guest ran to a stop since the last reset.
    ran: bool,
    /// The last reset did not finish, so what memory holds is unknown.
    incomplete: bool,
    /// `(address, len)` ranges the device reset itself puts back.
    reloaded: Vec<(u64, u64)>,
}

impl<L: DirtyLog> FastSnapshot<L> {
    /// Start from a machine at its baseline: whatever the log holds is from
    /// before the baseline, and is dropped.
    pub fn new(mut log: L, limits: FastSnapshotLimits) -> Result<Self> {
        let pages = DirtyPageSnapshot::new(log.page_bits(), limits)?;
        log.take(false)?;
        Ok(Self {
            log,
            pages,
            unlogged: BTreeSet::new(),
            ran: false,
            incomplete: false,
            reloaded: Vec::new(),
        })
    }

    /// Name the `(address, len)` ranges of RAM that [`Machine::reset_devices`]
    /// puts back by itself: QEMU's reset reloads the image segments it loaded
    /// into RAM ([`reset_reloaded_ranges`]). A dirty page wholly inside one
    /// is neither learned nor written.
    pub fn with_reset_reloaded(mut self, ranges: Vec<(u64, u64)>) -> Self {
        self.reloaded = ranges;
        self
    }

    /// Whether the device reset puts back all of `page`.
    fn reloaded_by_reset(&self, page: u64) -> bool {
        let bits = self.pages.page_bits;
        let (start, end) = (page << bits, (page + 1) << bits);
        self.reloaded.iter().any(|&(address, len)| {
            address <= start && address.checked_add(len).is_some_and(|stop| end <= stop)
        })
    }

    /// The baselines learned so far.
    pub fn snapshot(&self) -> &DirtyPageSnapshot {
        &self.pages
    }

    /// `[address, address + len)` was written in a way the log does not see:
    /// by the host before a run (the input), or by the machine itself (a
    /// Cortex-M core stacking an exception frame). The next reset puts back
    /// its pages too.
    pub fn note_unlogged_write(&mut self, address: u64, len: usize) {
        self.unlogged
            .extend(pages_of(address, len as u64, self.pages.page_bits));
    }

    /// The guest ran to a stop (its done breakpoint or a fault), so the log
    /// must show it saw the run ([`DirtyLog::take`]).
    pub fn note_guest_ran(&mut self) {
        self.ran = true;
    }

    /// Bring `target` back to the baseline after a run: reset its devices and
    /// write back the pages the run dirtied, or restore the whole machine
    /// when a dirtied page has no baseline yet (then learn it), the log
    /// overflowed, or the last reset failed part way.
    pub fn reset<T: GuestMemory + Machine + ?Sized>(
        &mut self,
        target: &mut T,
    ) -> Result<FastReset> {
        let mut dirty = self.log.take(std::mem::take(&mut self.ran))?;
        for page in std::mem::take(&mut self.unlogged) {
            if let DirtyPages::Pages(pages) = &mut dirty {
                pages.insert(page);
            }
        }
        if let DirtyPages::Pages(pages) = &mut dirty {
            pages.retain(|page| !self.reloaded_by_reset(*page));
        }
        let plan = if std::mem::replace(&mut self.incomplete, true) {
            RestorePlan::Full { learn: Vec::new() }
        } else {
            self.pages.plan(&dirty)
        };
        let reset = match plan {
            RestorePlan::Pages(runs) => {
                target.reset_devices()?;
                let pages = self.pages.apply(target, &runs)?;
                FastReset::DirtyPages { pages }
            }
            RestorePlan::Full { learn } => {
                target.restore_all()?;
                let learned = self.pages.learn(target, &learn)?;
                FastReset::Full { learned }
            }
        };
        self.incomplete = false;
        Ok(reset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    const PAGE_BITS: u32 = 8;
    const PAGE: usize = 1 << PAGE_BITS;
    /// The mock guest's RAM: 16 pages at 0x2000_0000.
    const RAM_BASE: u64 = 0x2000_0000;
    const RAM_PAGES: usize = 16;

    /// A guest whose stores are logged by page, as the plugin logs them, and
    /// whose host reads and writes are not.
    struct Guest {
        ram: Vec<u8>,
        /// What a full restore puts back: the RAM at the baseline.
        saved: Vec<u8>,
        dirty: BTreeSet<u64>,
        overflowed: bool,
        /// Host writes, as (address, length).
        writes: Vec<(u64, usize)>,
        reads: Vec<(u64, usize)>,
        device_resets: usize,
        full_restores: usize,
        /// A host write fails after this many succeed.
        fail_writes_after: Option<usize>,
    }

    impl Guest {
        fn new() -> Rc<RefCell<Self>> {
            let ram: Vec<u8> = (0..RAM_PAGES * PAGE).map(|i| (i * 7 + 3) as u8).collect();
            Rc::new(RefCell::new(Self {
                saved: ram.clone(),
                ram,
                dirty: BTreeSet::new(),
                overflowed: false,
                writes: Vec::new(),
                reads: Vec::new(),
                device_resets: 0,
                full_restores: 0,
                fail_writes_after: None,
            }))
        }

        fn offset(address: u64, len: usize) -> usize {
            let offset = (address - RAM_BASE) as usize;
            assert!(
                offset + len <= RAM_PAGES * PAGE,
                "{address:#x}+{len} is past RAM"
            );
            offset
        }

        /// The guest stores `bytes` at `address`.
        fn store(&mut self, address: u64, bytes: &[u8]) {
            let offset = Self::offset(address, bytes.len());
            self.ram[offset..offset + bytes.len()].copy_from_slice(bytes);
            self.dirty
                .extend(pages_of(address, bytes.len() as u64, PAGE_BITS));
        }

        /// The bytes of RAM page `index` (counted from `RAM_BASE`).
        fn page(&self, index: usize) -> &[u8] {
            &self.ram[index * PAGE..(index + 1) * PAGE]
        }
    }

    /// The host's view of the guest's memory.
    struct Memory(Rc<RefCell<Guest>>);

    impl GuestMemory for Memory {
        fn read(&mut self, address: u64, len: usize) -> Result<Vec<u8>> {
            let mut guest = self.0.borrow_mut();
            guest.reads.push((address, len));
            let offset = Guest::offset(address, len);
            Ok(guest.ram[offset..offset + len].to_vec())
        }

        fn write(&mut self, address: u64, bytes: &[u8]) -> Result<()> {
            let mut guest = self.0.borrow_mut();
            if let Some(left) = guest.fail_writes_after.as_mut() {
                if *left == 0 {
                    return Err(TransportError::protocol("mock write failed"));
                }
                *left -= 1;
            }
            guest.writes.push((address, bytes.len()));
            let offset = Guest::offset(address, bytes.len());
            guest.ram[offset..offset + bytes.len()].copy_from_slice(bytes);
            Ok(())
        }
    }

    /// The guest's dirty-page log.
    struct Log(Rc<RefCell<Guest>>);

    impl DirtyLog for Log {
        fn page_bits(&self) -> u32 {
            PAGE_BITS
        }

        fn take(&mut self, _ran: bool) -> Result<DirtyPages> {
            let mut guest = self.0.borrow_mut();
            let dirty = std::mem::take(&mut guest.dirty);
            Ok(if std::mem::take(&mut guest.overflowed) {
                DirtyPages::Overflowed
            } else {
                DirtyPages::Pages(dirty)
            })
        }
    }

    /// The machine: a device reset leaves RAM alone but for the range it
    /// reloads, if any; a full restore puts back the saved RAM.
    struct Board {
        guest: Rc<RefCell<Guest>>,
        reloads: Option<(u64, u64)>,
    }

    fn board(guest: Rc<RefCell<Guest>>) -> Board {
        Board {
            guest,
            reloads: None,
        }
    }

    impl Board {
        fn reloading(mut self, range: (u64, u64)) -> Self {
            self.reloads = Some(range);
            self
        }
    }

    impl Machine for Board {
        fn reset_devices(&mut self) -> Result<()> {
            let mut guest = self.guest.borrow_mut();
            guest.device_resets += 1;
            if let Some((address, len)) = self.reloads {
                let offset = Guest::offset(address, len as usize);
                let saved = guest.saved[offset..offset + len as usize].to_vec();
                guest.ram[offset..offset + len as usize].copy_from_slice(&saved);
            }
            Ok(())
        }

        fn restore_all(&mut self) -> Result<()> {
            let mut guest = self.guest.borrow_mut();
            guest.full_restores += 1;
            guest.ram = guest.saved.clone();
            Ok(())
        }
    }

    /// The guest's memory and machine as one target, as a session has them.
    struct Both<'a>(&'a mut Memory, &'a mut Board);

    impl GuestMemory for Both<'_> {
        fn read(&mut self, address: u64, len: usize) -> Result<Vec<u8>> {
            self.0.read(address, len)
        }

        fn write(&mut self, address: u64, bytes: &[u8]) -> Result<()> {
            self.0.write(address, bytes)
        }
    }

    impl Machine for Both<'_> {
        fn reset_devices(&mut self) -> Result<()> {
            self.1.reset_devices()
        }

        fn restore_all(&mut self) -> Result<()> {
            self.1.restore_all()
        }
    }

    fn page_address(index: u64) -> u64 {
        RAM_BASE + (index << PAGE_BITS)
    }

    fn rig() -> (Rc<RefCell<Guest>>, FastSnapshot<Log>, Memory, Board) {
        let guest = Guest::new();
        let fast =
            FastSnapshot::new(Log(Rc::clone(&guest)), FastSnapshotLimits::default()).unwrap();
        let memory = Memory(Rc::clone(&guest));
        let board = board(Rc::clone(&guest));
        (guest, fast, memory, board)
    }

    /// A run that stores into pages 1, 5 and 6 (one store straddles 5 and 6).
    fn run(guest: &Rc<RefCell<Guest>>, tag: u8) {
        let mut guest = guest.borrow_mut();
        guest.store(page_address(1) + 4, &[tag; 8]);
        guest.store(page_address(6) - 2, &[tag ^ 0xff; 4]);
    }

    #[test]
    fn a_reset_writes_back_only_the_pages_the_guest_dirtied() {
        let (guest, mut fast, mut memory, mut board) = rig();
        let baseline = guest.borrow().ram.clone();

        // The first run's pages have no baseline yet: restore it all, learn them.
        run(&guest, 0x11);
        let reset = fast.reset(&mut Both(&mut memory, &mut board)).unwrap();
        assert_eq!(reset, FastReset::Full { learned: 3 });
        assert_eq!(guest.borrow().full_restores, 1);
        assert_eq!(guest.borrow().ram, baseline);
        assert_eq!(fast.snapshot().known_pages(), 3);

        // The second run dirties the same pages: a device reset and two
        // writes, page 1 alone and pages 5..=6 as one.
        run(&guest, 0x22);
        assert_ne!(guest.borrow().ram, baseline);
        guest.borrow_mut().writes.clear();
        let reset = fast.reset(&mut Both(&mut memory, &mut board)).unwrap();
        assert_eq!(reset, FastReset::DirtyPages { pages: 3 });
        let guest = guest.borrow();
        assert_eq!(
            guest.full_restores, 1,
            "no full restore once the pages are known"
        );
        assert_eq!(guest.device_resets, 1);
        assert_eq!(
            guest.writes,
            vec![(page_address(1), PAGE), (page_address(5), 2 * PAGE)],
            "only the dirty pages are written, consecutive ones together"
        );
        assert_eq!(guest.ram, baseline, "memory is back at the baseline");
        drop(guest);

        // A run that dirties one known page writes that page back alone.
        let guest_handle = Rc::clone(&memory.0);
        guest_handle
            .borrow_mut()
            .store(page_address(5) + 9, &[0x77; 2]);
        guest_handle.borrow_mut().writes.clear();
        assert_eq!(
            fast.reset(&mut Both(&mut memory, &mut board)).unwrap(),
            FastReset::DirtyPages { pages: 1 }
        );
        assert_eq!(guest_handle.borrow().writes, vec![(page_address(5), PAGE)]);
        assert_eq!(guest_handle.borrow().page(5), &baseline[5 * PAGE..6 * PAGE]);
    }

    #[test]
    fn a_page_dirtied_for_the_first_time_is_learned_from_a_full_restore() {
        let (guest, mut fast, mut memory, mut board) = rig();
        let baseline = guest.borrow().ram.clone();
        run(&guest, 0x11);
        fast.reset(&mut Both(&mut memory, &mut board)).unwrap();

        // Page 9 is new; pages 1, 5 and 6 are not.
        run(&guest, 0x33);
        guest.borrow_mut().store(page_address(9), &[0x44; 16]);
        guest.borrow_mut().reads.clear();
        let reset = fast.reset(&mut Both(&mut memory, &mut board)).unwrap();
        assert_eq!(reset, FastReset::Full { learned: 1 });
        assert_eq!(guest.borrow().reads, vec![(page_address(9), PAGE)]);
        assert_eq!(guest.borrow().ram, baseline);

        // Now all four are known.
        run(&guest, 0x55);
        guest.borrow_mut().store(page_address(9) + 3, &[0x66]);
        let reset = fast.reset(&mut Both(&mut memory, &mut board)).unwrap();
        assert_eq!(reset, FastReset::DirtyPages { pages: 4 });
        assert_eq!(guest.borrow().ram, baseline);
        assert_eq!(guest.borrow().full_restores, 2);
    }

    #[test]
    fn a_page_the_host_wrote_is_restored_with_the_guests() {
        let (guest, mut fast, mut memory, mut board) = rig();
        let baseline = guest.borrow().ram.clone();
        // Teach page 3, which only the host writes (the input region).
        fast.note_unlogged_write(page_address(3) + 16, 32);
        Memory(Rc::clone(&guest))
            .write(page_address(3) + 16, &[0xaa; 32])
            .unwrap();
        assert_eq!(
            fast.reset(&mut Both(&mut memory, &mut board)).unwrap(),
            FastReset::Full { learned: 1 }
        );

        fast.note_unlogged_write(page_address(3) + 16, 32);
        memory.write(page_address(3) + 16, &[0xbb; 32]).unwrap();
        guest.borrow_mut().writes.clear();
        assert_eq!(
            fast.reset(&mut Both(&mut memory, &mut board)).unwrap(),
            FastReset::DirtyPages { pages: 1 }
        );
        assert_eq!(guest.borrow().writes, vec![(page_address(3), PAGE)]);
        assert_eq!(guest.borrow().ram, baseline);
    }

    #[test]
    fn an_overflowed_log_restores_the_whole_machine() {
        let (guest, mut fast, mut memory, mut board) = rig();
        let baseline = guest.borrow().ram.clone();
        run(&guest, 0x11);
        fast.reset(&mut Both(&mut memory, &mut board)).unwrap();

        run(&guest, 0x22);
        guest.borrow_mut().overflowed = true;
        let reset = fast.reset(&mut Both(&mut memory, &mut board)).unwrap();
        assert_eq!(reset, FastReset::Full { learned: 0 });
        assert_eq!(guest.borrow().full_restores, 2);
        assert_eq!(guest.borrow().ram, baseline);
    }

    #[test]
    fn a_reset_that_failed_part_way_is_followed_by_a_full_restore() {
        let (guest, mut fast, mut memory, mut board) = rig();
        let baseline = guest.borrow().ram.clone();
        run(&guest, 0x11);
        fast.reset(&mut Both(&mut memory, &mut board)).unwrap();

        // The write of pages 5..=6 fails after page 1's.
        run(&guest, 0x22);
        guest.borrow_mut().fail_writes_after = Some(1);
        fast.reset(&mut Both(&mut memory, &mut board)).unwrap_err();
        guest.borrow_mut().fail_writes_after = None;
        assert_ne!(guest.borrow().ram, baseline);

        // The log was emptied by the failed reset, so only a full restore
        // knows what to put back.
        let reset = fast.reset(&mut Both(&mut memory, &mut board)).unwrap();
        assert_eq!(reset, FastReset::Full { learned: 0 });
        assert_eq!(guest.borrow().ram, baseline);
    }

    #[test]
    fn pages_past_the_baseline_limit_are_not_learned_and_restore_in_full() {
        let guest = Guest::new();
        let baseline = guest.borrow().ram.clone();
        let limits = FastSnapshotLimits {
            max_baseline_bytes: 2 * PAGE,
        };
        let mut fast = FastSnapshot::new(Log(Rc::clone(&guest)), limits).unwrap();
        let (mut memory, mut board) = (Memory(Rc::clone(&guest)), board(Rc::clone(&guest)));
        run(&guest, 0x11);
        assert_eq!(
            fast.reset(&mut Both(&mut memory, &mut board)).unwrap(),
            FastReset::Full { learned: 2 }
        );
        assert_eq!(fast.snapshot().known_pages(), 2);
        // Page 6 has no baseline, so every run that writes it restores in full.
        run(&guest, 0x22);
        assert_eq!(
            fast.reset(&mut Both(&mut memory, &mut board)).unwrap(),
            FastReset::Full { learned: 0 }
        );
        assert_eq!(guest.borrow().ram, baseline);
        assert_eq!(guest.borrow().full_restores, 2);
    }

    #[test]
    fn a_new_snapshot_drops_what_the_log_held_before_the_baseline() {
        let guest = Guest::new();
        guest.borrow_mut().store(page_address(2), &[1, 2, 3]);
        let mut fast =
            FastSnapshot::new(Log(Rc::clone(&guest)), FastSnapshotLimits::default()).unwrap();
        let (mut memory, mut board) = (Memory(Rc::clone(&guest)), board(Rc::clone(&guest)));
        // Nothing ran since the baseline: nothing to restore.
        assert_eq!(
            fast.reset(&mut Both(&mut memory, &mut board)).unwrap(),
            FastReset::DirtyPages { pages: 0 }
        );
        assert!(guest.borrow().writes.is_empty());
    }

    #[test]
    fn a_page_the_device_reset_reloads_is_neither_learned_nor_written() {
        let (guest, fast, mut memory, _board) = rig();
        // The reset reloads page 1 and the first half of page 5 (an image
        // segment), as QEMU's reset reloads the image it loaded into RAM.
        let segment = (page_address(1), (4 * PAGE + PAGE / 2) as u64);
        let mut fast = fast.with_reset_reloaded(vec![segment]);
        let mut board = board(Rc::clone(&guest)).reloading(segment);
        let baseline = guest.borrow().ram.clone();

        run(&guest, 0x11);
        guest.borrow_mut().reads.clear();
        assert_eq!(
            fast.reset(&mut Both(&mut memory, &mut board)).unwrap(),
            FastReset::Full { learned: 2 }
        );
        assert_eq!(
            guest.borrow().reads,
            vec![(page_address(5), 2 * PAGE)],
            "page 1 is the reset's, page 5 only half"
        );

        run(&guest, 0x22);
        guest.borrow_mut().writes.clear();
        assert_eq!(
            fast.reset(&mut Both(&mut memory, &mut board)).unwrap(),
            FastReset::DirtyPages { pages: 2 }
        );
        assert_eq!(guest.borrow().writes, vec![(page_address(5), 2 * PAGE)]);
        assert_eq!(guest.borrow().ram, baseline);
    }

    #[test]
    fn qemus_rom_list_names_the_ram_its_reset_reloads() {
        let roms = "addr=0000000000000000 size=0x000144 mem=ram name=\"fw.elf ELF program \
                    header segment 0\"\r\naddr=0000000020000000 size=0x000250 mem=ram \
                    name=\"fw.elf ELF program header segment 1\"\r\naddr=0000000000001000 \
                    size=0x000020 mem=rom name=\"bootrom\"\r\nfw=genroms/linuxboot.bin \
                    size=0x000400 name=\"linuxboot.bin\"\r\npc.rom size=0x020000 name=\"x\"\r\n";
        assert_eq!(
            reset_reloaded_ranges(roms),
            vec![(0, 0x144), (0x2000_0000, 0x250)],
            "RAM blobs only: a ROM is written once, a firmware file is not reloaded"
        );
        assert_eq!(reset_reloaded_ranges(""), Vec::new());
        assert_eq!(
            reset_reloaded_ranges("addr=zz size=0x10 mem=ram"),
            Vec::new()
        );
    }

    #[test]
    fn pages_of_a_range_cover_its_first_and_last_byte() {
        assert_eq!(pages_of(0x100, 0, 8).collect::<Vec<_>>(), Vec::<u64>::new());
        assert_eq!(pages_of(0x1ff, 1, 8).collect::<Vec<_>>(), vec![1]);
        assert_eq!(pages_of(0x1ff, 2, 8).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(pages_of(0x200, 0x201, 8).collect::<Vec<_>>(), vec![2, 3, 4]);
        let mut dirty = DirtyPages::Overflowed;
        dirty.add_range(0, 4096, 8);
        assert_eq!(dirty, DirtyPages::Overflowed);
    }

    // -- the plugin's log file ------------------------------------------------

    fn log_file(dir: &tempfile::TempDir, page_bits: u32, capacity: u32) -> PathBuf {
        let path = dir.path().join("dirty.log");
        crate::testsupport::DirtyLogFile::create(&path, page_bits, capacity).unwrap();
        path
    }

    #[test]
    fn the_plugin_log_reports_its_pages_and_empties_into_a_new_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let path = log_file(&dir, 10, 8);
        let writer = crate::testsupport::DirtyLogFile::open(&path).unwrap();
        writer.record(0x2000_0000, 4).unwrap();
        writer.record(0x2000_03fe, 4).unwrap(); // straddles pages 0x80000 and 0x80001
        writer.record(0x2000_0010, 1).unwrap(); // a page already recorded

        let mut log = PluginDirtyLog::open(&path).unwrap();
        assert_eq!(log.page_bits(), 10);
        assert_eq!(
            log.take(false).unwrap(),
            DirtyPages::Pages([0x80000, 0x80001].into())
        );
        let header = read_header(&mut File::open(&path).unwrap()).unwrap();
        assert_eq!((header.count, header.overflow, header.epoch), (0, 0, 1));
        assert_eq!(log.take(false).unwrap(), DirtyPages::Pages(BTreeSet::new()));

        writer.record(0x2000_0800, 1).unwrap();
        assert_eq!(
            log.take(false).unwrap(),
            DirtyPages::Pages([0x80002].into())
        );
    }

    #[test]
    fn a_full_plugin_log_reads_as_overflowed() {
        let dir = tempfile::tempdir().unwrap();
        let path = log_file(&dir, 8, 2);
        let writer = crate::testsupport::DirtyLogFile::open(&path).unwrap();
        for page in 0..3_u64 {
            writer.record(page << 8, 1).unwrap();
        }
        let mut log = PluginDirtyLog::open(&path).unwrap();
        assert_eq!(log.take(false).unwrap(), DirtyPages::Overflowed);
        writer.record(0, 1).unwrap();
        assert_eq!(log.take(false).unwrap(), DirtyPages::Pages([0].into()));
    }

    #[test]
    fn a_missing_or_foreign_log_is_refused_with_how_to_start_qemu() {
        let dir = tempfile::tempdir().unwrap();
        let missing = PluginDirtyLog::open(dir.path().join("none.log")).unwrap_err();
        let message = missing.to_string();
        assert!(
            message.contains("-plugin") && message.contains(DIRTY_PAGE_PLUGIN_LIBRARY_NAME),
            "{message}"
        );

        let foreign = dir.path().join("foreign.log");
        std::fs::write(&foreign, [0_u8; 128]).unwrap();
        let message = PluginDirtyLog::open(&foreign).unwrap_err().to_string();
        assert!(message.contains("magic"), "{message}");

        let short = dir.path().join("short.log");
        let path = log_file(&dir, 8, 4);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.truncate(HEADER_BYTES as usize + 8);
        std::fs::write(&short, bytes).unwrap();
        let message = PluginDirtyLog::open(&short).unwrap_err().to_string();
        assert!(message.contains("cannot hold"), "{message}");
    }

    #[test]
    fn a_log_no_plugin_writes_is_refused_once_the_guest_has_run() {
        // A well-formed log left by an earlier QEMU, with no plugin in the
        // one bhf drives: nothing acknowledges the epoch.
        let dir = tempfile::tempdir().unwrap();
        let path = log_file(&dir, 8, 16);
        let writer = crate::testsupport::DirtyLogFile::open(&path).unwrap();
        let mut log = PluginDirtyLog::open(&path).unwrap();
        // Before any run there is nothing to show.
        assert_eq!(log.take(false).unwrap(), DirtyPages::Pages(BTreeSet::new()));
        let message = log.take(true).unwrap_err().to_string();
        assert!(
            message.contains("no dirty-page plugin saw it run") && message.contains("-plugin"),
            "{message}"
        );

        // A plugin that acknowledged the epoch the run was in is believed.
        let mut log = PluginDirtyLog::open(&path).unwrap();
        writer.saw_access().unwrap();
        writer.record(0x2000_0000, 4).unwrap();
        assert_eq!(
            log.take(true).unwrap(),
            DirtyPages::Pages([0x20_0000].into())
        );
        // An acknowledgement of an earlier epoch is not one of this run's.
        let message = log.take(true).unwrap_err().to_string();
        assert!(message.contains("no dirty-page plugin"), "{message}");
    }

    #[test]
    fn a_log_another_session_empties_is_refused() {
        // Two sessions (two --workers workers given one dirty_log=) reading
        // one log would each take the other's pages.
        let dir = tempfile::tempdir().unwrap();
        let path = log_file(&dir, 8, 16);
        let mut first = PluginDirtyLog::open(&path).unwrap();
        let mut second = PluginDirtyLog::open(&path).unwrap();
        first.take(false).unwrap();
        let message = second.take(false).unwrap_err().to_string();
        assert!(
            message.contains("another bhf session") && message.contains("{worker}"),
            "{message}"
        );
        // The first goes on reading its own log.
        first.take(false).unwrap();
    }

    #[test]
    fn the_bitband_windows_go_into_the_log_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = log_file(&dir, 8, 16);
        let writer = crate::testsupport::DirtyLogFile::open(&path).unwrap();
        let mut log = PluginDirtyLog::open(&path).unwrap();
        let sram = BitBandWindow {
            alias: 0x2200_0000,
            size: 0x0200_0000,
            source: 0x2000_0000,
        };
        log.set_bitband_windows(&[sram]).unwrap();
        assert_eq!(
            writer.bitband_windows().unwrap(),
            vec![(0x2200_0000, 0x0200_0000, 0x2000_0000)]
        );
        // Setting fewer clears the rest; more than the header holds is refused.
        log.set_bitband_windows(&[]).unwrap();
        assert_eq!(writer.bitband_windows().unwrap(), Vec::new());
        let message = log
            .set_bitband_windows(&[sram; BITBAND_WINDOWS + 1])
            .unwrap_err()
            .to_string();
        assert!(message.contains("bit-band windows"), "{message}");
        // The windows sit between the header words and the pages.
        log.set_bitband_windows(&[sram, sram]).unwrap();
        writer.record(0x2000_0100, 1).unwrap();
        assert_eq!(
            log.take(false).unwrap(),
            DirtyPages::Pages([0x20_0001].into())
        );
    }

    /// `info mtree -f` from QEMU 8.2.2's mps2-an385, cut down.
    const MPS2_MTREE: &str = "FlatView #1\r\n AS \"memory\", root: system\r\n Root memory \
        region: system\r\n  0000000000000000-00000000003fffff (prio 0, ram): mps.ssram1\r\n  \
        0000000000800000-0000000000ffffff (prio -1000, i/o): RESERVED 1\r\n  \
        0000000020000000-00000000203fffff (prio 0, ram): mps.ssram23\r\n  \
        0000000020400000-00000000207fffff (prio 0, ram): mps.ssram23\r\n\r\nFlatView #2\r\n \
        AS \"cpu-memory-0\", root: armv7m-container\r\n  0000000000000000-00000000003fffff \
        (prio 0, ram): mps.ssram1\r\n  0000000020000000-00000000203fffff (prio 0, ram): \
        mps.ssram23\r\n  0000000022000000-0000000023ffffff (prio 0, i/o): bitband\r\n  \
        0000000040000000-0000000040000fff (prio 0, i/o): cmsdk-apb-timer\r\n  \
        0000000042000000-0000000043ffffff (prio 0, i/o): bitband\r\n  \
        00000000e000e000-00000000e000e00f (prio 0, i/o): nvic_sysregs\r\n";

    #[test]
    fn qemus_memory_map_names_its_ram_and_the_bitband_windows_onto_it() {
        let map = MemoryMap::from_info_mtree(MPS2_MTREE);
        assert_eq!(
            map.ram,
            vec![
                (0, 0x40_0000),
                (0x2000_0000, 0x40_0000),
                (0x2040_0000, 0x40_0000)
            ]
        );
        // The SRAM window aliases RAM; the peripheral one aliases devices,
        // which the machine reset restores.
        assert_eq!(
            map.bitband,
            vec![BitBandWindow {
                alias: 0x2200_0000,
                size: 0x0200_0000,
                source: 0x2000_0000,
            }]
        );
        assert_eq!(MemoryMap::from_info_mtree(""), MemoryMap::default());
        assert_eq!(
            MemoryMap::from_info_mtree("  zz-10 (prio 0, ram): x\n  0-0 (prio 0, ram): y\n").ram,
            vec![(0, 1)]
        );
    }

    #[test]
    fn a_cortex_m_target_description_names_its_stack_and_status_registers() {
        let target = r#"<?xml version="1.0"?><target><architecture>arm</architecture><xi:include href="arm-m-profile.xml"/><xi:include href="arm-m-system.xml"/></target>"#;
        let core = r#"<feature name="org.gnu.gdb.arm.m-profile">
  <reg name="r0" bitsize="32"/><reg name="r1" bitsize="32"/><reg name="r2" bitsize="32"/>
  <reg name="r3" bitsize="32"/><reg name="r4" bitsize="32"/><reg name="r5" bitsize="32"/>
  <reg name="r6" bitsize="32"/><reg name="r7" bitsize="32"/><reg name="r8" bitsize="32"/>
  <reg name="r9" bitsize="32"/><reg name="r10" bitsize="32"/><reg name="r11" bitsize="32"/>
  <reg name="r12" bitsize="32"/><reg name="sp" bitsize="32" type="data_ptr"/>
  <reg name="lr" bitsize="32"/><reg name="pc" bitsize="32" type="code_ptr"/>
  <reg name="xpsr" bitsize="32" regnum="25"/>
</feature>"#;
        let system = r#"<feature name="org.gnu.gdb.arm.m-system">
<reg name="msp" bitsize="32" regnum="26"/>
<reg name="psp" bitsize="32" regnum="27"/>
</feature>"#;
        let documents = [target, core, system].map(str::to_owned);
        assert_eq!(
            MProfileRegisters::from_target_description(&documents),
            Some(MProfileRegisters {
                sp: 13,
                xpsr: 25,
                psp: Some(27)
            })
        );
        // Without the system feature there is no process stack pointer.
        assert_eq!(
            MProfileRegisters::from_target_description(&documents[..2]),
            Some(MProfileRegisters {
                sp: 13,
                xpsr: 25,
                psp: None
            })
        );
        // An A-profile core, or a stub with no description, is not one.
        let a_profile =
            r#"<feature name="org.gnu.gdb.arm.core"><reg name="sp" bitsize="32"/></feature>"#;
        assert_eq!(
            MProfileRegisters::from_target_description(&[a_profile.to_owned()]),
            None
        );
        assert_eq!(MProfileRegisters::from_target_description(&[]), None);
    }

    #[test]
    fn the_frames_of_active_exceptions_lie_above_the_stack_pointer() {
        let ram = [(0x2000_0000, 0x40_0000)];
        let top = 0x2040_0000;
        // Thread mode: no exception is active, so no frame is live.
        let thread = MProfileStop {
            sp: top - 0x40,
            xpsr: 0x0100_0000,
            psp: None,
        };
        assert_eq!(live_exception_frames(thread, top, &ram), Vec::new());

        // A HardFault (exception 3) on the main stack: everything from the
        // stop's stack pointer up to the baseline's.
        let fault = MProfileStop {
            sp: top - 0x60,
            xpsr: 0x0100_0003,
            psp: Some(0),
        };
        assert_eq!(
            live_exception_frames(fault, top, &ram),
            vec![(top - 0x60, 0x60)]
        );

        // A thread on the process stack faulted: its frame sits at PSP.
        let task = MProfileStop {
            psp: Some(0x2000_8000),
            ..fault
        };
        assert_eq!(
            live_exception_frames(task, top, &ram),
            vec![(top - 0x60, 0x60), (0x2000_8000, MAX_EXCEPTION_FRAME)]
        );

        // The firmware moved the stack far from the baseline's: the window
        // above the stop's stack pointer.
        let moved = MProfileStop {
            sp: 0x2002_0010 - 0x40,
            ..fault
        };
        assert_eq!(
            live_exception_frames(moved, top, &ram),
            vec![(0x2002_0010 - 0x40, HANDLER_STACK_WINDOW)]
        );

        // Nothing outside RAM: a stack pointer at the top of RAM keeps only
        // what is in it, one in a device none.
        let edge = MProfileStop {
            sp: top - 0x10,
            psp: Some(0x4000_0000),
            ..fault
        };
        assert_eq!(
            live_exception_frames(edge, top + 0x100_0000, &ram),
            vec![(top - 0x10, 0x10)]
        );
    }

    #[test]
    fn a_frame_the_log_did_not_see_is_restored_with_the_guests_pages() {
        // A core that stacks a frame into page 8 writes it without a store:
        // noted as an unlogged write, it is learned and put back as a page
        // the guest dirtied is.
        let (guest, mut fast, mut memory, mut board) = rig();
        let baseline = guest.borrow().ram.clone();
        let frame = page_address(8) + 0xe0;
        let stack_frame = |guest: &Rc<RefCell<Guest>>| {
            let mut guest = guest.borrow_mut();
            let offset = Guest::offset(frame, 0x20);
            guest.ram[offset..offset + 0x20].copy_from_slice(&[0xee; 0x20]);
        };
        stack_frame(&guest);
        fast.note_unlogged_write(frame, 0x20);
        assert_eq!(
            fast.reset(&mut Both(&mut memory, &mut board)).unwrap(),
            FastReset::Full { learned: 1 }
        );
        stack_frame(&guest);
        fast.note_unlogged_write(frame, 0x20);
        guest.borrow_mut().writes.clear();
        assert_eq!(
            fast.reset(&mut Both(&mut memory, &mut board)).unwrap(),
            FastReset::DirtyPages { pages: 1 }
        );
        assert_eq!(guest.borrow().writes, vec![(page_address(8), PAGE)]);
        assert_eq!(guest.borrow().ram, baseline);
    }

    #[test]
    fn the_plugin_source_writes_the_layout_this_reader_reads() {
        // The constants the C plugin and this reader share.
        let source = DIRTY_PAGE_PLUGIN_SOURCE;
        assert!(source.contains(&format!("#define LOG_MAGIC {DIRTY_LOG_MAGIC:#010x}u")));
        assert!(source.contains(&format!("#define LOG_VERSION {DIRTY_LOG_VERSION}u")));
        assert!(source.contains(&format!("#define HEADER_BYTES {HEADER_BYTES}u")));
        assert!(source.contains(&format!("#define BITBAND_WINDOWS {BITBAND_WINDOWS}\n")));
        assert!(
            source.contains("  uint64_t seen;\n  struct bitband_window bitband[BITBAND_WINDOWS];")
        );
        assert!(source.contains(&format!(
            "parse_number(arg + 10, {MIN_PAGE_BITS}, {MAX_PAGE_BITS}, &value)"
        )));
        assert!(source.contains(&format!(
            "parse_number(arg + 9, 1, {MAX_LOG_CAPACITY}, &value)"
        )));
    }
}
