// SPDX-License-Identifier: Apache-2.0

//! Peripheral (MMIO) models: what a read of a peripheral register returns.
//!
//! A model applies at a site: a register address, read by one instruction or
//! by any. A passthrough model takes the read's bytes from the input, so the
//! fuzzer drives what the firmware sees there (Fuzzware calls this model
//! "identity"); a constant model returns the same value every time; a
//! bit-extract model feeds only the bits of its mask from the input, as
//! many whole bytes as they need, the way a status register's ready bit is
//! the one bit a polling loop tests (`infer.rs` infers these). A read no
//! model names gets the default: zero, or the input's bytes. The input a
//! run's peripheral reads take is a stream, consumed in order; a read that
//! needs more bytes than are left ends the run, since the firmware asked for
//! more input than the testcase holds. Writes to peripheral registers are
//! dropped.

use std::collections::HashMap;

/// What a model's reads return.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MmioModelKind {
    /// The read's bytes, as many as the access is wide, come from the input.
    Passthrough,
    /// The read returns `value`, cut to the access width.
    Constant { value: u32 },
    /// The bits of `mask` (within the access width) come from the input, in
    /// order from the lowest, and the others read as zero; a read takes as
    /// many bytes as the bits fill.
    BitExtract { mask: u32 },
}

impl MmioModelKind {
    /// A stable name for the kind.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passthrough => "passthrough",
            Self::Constant { .. } => "constant",
            Self::BitExtract { .. } => "bitextract",
        }
    }

    /// Whether its reads take bytes from the input.
    pub fn takes_input(self) -> bool {
        matches!(self, Self::Passthrough | Self::BitExtract { .. })
    }
}

/// A model for the reads of one peripheral register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MmioModel {
    /// The register's address: the address of the access, as the
    /// instruction computes it.
    pub address: u32,
    /// The instruction that reads it; `None` serves every instruction. A
    /// model for one instruction wins over one for the register.
    pub pc: Option<u32>,
    pub kind: MmioModelKind,
}

/// What a read of a peripheral register no model names returns.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum MmioDefault {
    /// Zero, with nothing taken from the input.
    #[default]
    Zero,
    /// The read's bytes, from the input.
    Passthrough,
}

impl MmioDefault {
    /// A stable name for the default.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Zero => "zero",
            Self::Passthrough => "passthrough",
        }
    }
}

/// The peripheral models of a machine.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MmioConfig {
    pub models: Vec<MmioModel>,
    pub default: MmioDefault,
}

impl MmioConfig {
    /// Whether any peripheral read takes bytes from the input.
    pub fn takes_input(&self) -> bool {
        self.default == MmioDefault::Passthrough
            || self.models.iter().any(|model| model.kind.takes_input())
    }
}

/// One peripheral read a run made, as a recorded trace holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmioAccess {
    /// The instruction that read.
    pub pc: u32,
    pub address: u32,
    /// Bytes read: 1, 2 or 4.
    pub size: u8,
    /// The value the read returned.
    pub value: u32,
    /// Instructions the run had executed before the read.
    pub instructions: u64,
    /// Whether a model served the read, rather than the default.
    pub modelled: bool,
    /// A digest of the stores to memory (the image and its RAM) the run made
    /// since the peripheral read before this one, in order, with their
    /// addresses, widths and values; zero when it made none. Two reads with
    /// the same digest followed the same stores.
    pub stores: u64,
}

/// The value of the next read of `address` by `pc` is XORed with `xor`:
/// how inference asks what the bits of a read decide. Until it is made, no
/// read is traced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Probe {
    pub(crate) address: u32,
    pub(crate) pc: u32,
    pub(crate) xor: u32,
}

/// The input ran out at a read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Exhausted;

/// Where a run's peripheral reads were, to go back to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MmioMark {
    cursor: usize,
    reads: u64,
    stores: u64,
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0100_0000_01b3;

/// The models in force and the state of a run's peripheral reads.
pub(crate) struct Mmio {
    by_site: HashMap<(u32, u32), MmioModelKind>,
    by_address: HashMap<u32, MmioModelKind>,
    default: MmioDefault,
    stream: Vec<u8>,
    cursor: usize,
    pub(crate) reads: u64,
    trace_limit: usize,
    pub(crate) trace: Vec<MmioAccess>,
    /// The digest of the stores since the last read, while a trace records.
    stores: u64,
    pub(crate) probe: Option<Probe>,
}

#[inline]
fn width_mask(size: u32) -> u32 {
    match size {
        1 => 0xff,
        2 => 0xffff,
        _ => 0xffff_ffff,
    }
}

/// The low bits of `bits` spread into the set bits of `mask`, lowest first.
fn deposit(mut bits: u32, mut mask: u32) -> u32 {
    let mut value = 0;
    while mask != 0 {
        let lowest = mask & mask.wrapping_neg();
        if bits & 1 != 0 {
            value |= lowest;
        }
        bits >>= 1;
        mask &= mask - 1;
    }
    value
}

impl Mmio {
    /// The models of `config`, which the machine has checked hold at most
    /// one model per site.
    pub(crate) fn new(config: &MmioConfig) -> Self {
        let mut by_site = HashMap::new();
        let mut by_address = HashMap::new();
        for model in &config.models {
            match model.pc {
                Some(pc) => by_site.insert((model.address, pc), model.kind),
                None => by_address.insert(model.address, model.kind),
            };
        }
        Self {
            by_site,
            by_address,
            default: config.default,
            stream: Vec::new(),
            cursor: 0,
            reads: 0,
            trace_limit: 0,
            trace: Vec::new(),
            stores: 0,
            probe: None,
        }
    }

    /// Start a run whose peripheral reads take `stream`.
    pub(crate) fn begin(&mut self, stream: &[u8]) {
        self.stream.clear();
        self.stream.extend_from_slice(stream);
        self.cursor = 0;
        self.reads = 0;
        self.stores = 0;
        self.trace.clear();
    }

    /// Where the run's reads are now.
    pub(crate) fn mark(&self) -> MmioMark {
        MmioMark {
            cursor: self.cursor,
            reads: self.reads,
            stores: self.stores,
        }
    }

    /// Go back to `mark`, with an empty trace.
    pub(crate) fn rewind(&mut self, mark: MmioMark) {
        self.cursor = mark.cursor;
        self.reads = mark.reads;
        self.stores = mark.stores;
        self.trace.clear();
    }

    /// Whether the trace records more reads.
    #[inline]
    pub(crate) fn tracing(&self) -> bool {
        self.trace.len() < self.trace_limit && self.probe.is_none()
    }

    /// A store of `size` bytes of `value` at `address` to memory, folded into
    /// the digest the next traced read records.
    pub(crate) fn note_store(&mut self, address: u32, size: u32, value: u32) {
        let mut digest = if self.stores == 0 {
            FNV_OFFSET
        } else {
            self.stores
        };
        for word in [address, size, value] {
            digest = (digest ^ u64::from(word)).wrapping_mul(FNV_PRIME);
        }
        self.stores = digest.max(1);
    }

    /// Bytes of the stream the run's reads have taken.
    pub(crate) fn consumed(&self) -> usize {
        self.cursor
    }

    pub(crate) fn set_trace_limit(&mut self, limit: usize) {
        self.trace_limit = limit;
        if limit == 0 {
            self.trace = Vec::new();
        }
    }

    fn take(&mut self, len: usize) -> Result<u32, Exhausted> {
        let bytes = self
            .stream
            .get(self.cursor..self.cursor + len)
            .ok_or(Exhausted)?;
        let value = bytes
            .iter()
            .rev()
            .fold(0u32, |value, &byte| value << 8 | u32::from(byte));
        self.cursor += len;
        Ok(value)
    }

    /// The next byte of the stream, for the interrupt schedule.
    pub(crate) fn take_byte(&mut self) -> Option<u8> {
        self.take(1).ok().map(|value| value as u8)
    }

    /// A read of `size` (1, 2 or 4) bytes at `address` by the instruction at
    /// `pc`, after `instructions` instructions.
    pub(crate) fn read(
        &mut self,
        address: u32,
        pc: u32,
        size: u32,
        instructions: u64,
    ) -> Result<u32, Exhausted> {
        let model = self
            .by_site
            .get(&(address, pc))
            .or_else(|| self.by_address.get(&address))
            .copied();
        let width = width_mask(size);
        let mut value = match model {
            Some(MmioModelKind::Constant { value }) => value & width,
            Some(MmioModelKind::Passthrough) => self.take(size as usize)?,
            Some(MmioModelKind::BitExtract { mask }) => {
                let mask = mask & width;
                let bytes = mask.count_ones().div_ceil(8) as usize;
                deposit(self.take(bytes)?, mask)
            }
            None => match self.default {
                MmioDefault::Zero => 0,
                MmioDefault::Passthrough => self.take(size as usize)?,
            },
        };
        if let Some(probe) = self.probe {
            if probe.address == address && probe.pc == pc {
                value = (value ^ probe.xor) & width;
                self.probe = None;
            }
        }
        self.reads += 1;
        if self.tracing() {
            self.trace.push(MmioAccess {
                pc,
                address,
                size: size as u8,
                value,
                instructions,
                modelled: model.is_some(),
                stores: std::mem::take(&mut self.stores),
            });
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn mmio(models: &[MmioModel], default: MmioDefault) -> Mmio {
        Mmio::new(&MmioConfig {
            models: models.to_vec(),
            default,
        })
    }

    #[test]
    fn passthrough_reads_take_the_input_in_order_little_endian() {
        let mut mmio = mmio(&[], MmioDefault::Passthrough);
        mmio.begin(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        assert_eq!(mmio.read(0x4000_0000, 0, 4, 0), Ok(0x4433_2211));
        assert_eq!(mmio.read(0x4000_0000, 0, 2, 0), Ok(0x6655));
        assert_eq!(mmio.read(0x4000_0000, 0, 1, 0), Ok(0x77));
        assert_eq!(mmio.consumed(), 7);
        assert_eq!(mmio.read(0x4000_0000, 0, 1, 0), Err(Exhausted));
        // A read wider than what is left takes nothing.
        mmio.begin(&[1, 2, 3]);
        assert_eq!(mmio.read(0x4000_0000, 0, 4, 0), Err(Exhausted));
        assert_eq!(mmio.consumed(), 0);
        assert_eq!(mmio.reads, 0, "an exhausted read is not a read");
    }

    #[test]
    fn constants_are_cut_to_the_access_and_take_no_input() {
        let model = MmioModel {
            address: 0x4000_0004,
            pc: None,
            kind: MmioModelKind::Constant { value: 0x1234_5678 },
        };
        let mut mmio = mmio(&[model], MmioDefault::Passthrough);
        mmio.begin(&[]);
        assert_eq!(mmio.read(0x4000_0004, 0x100, 4, 0), Ok(0x1234_5678));
        assert_eq!(mmio.read(0x4000_0004, 0x100, 2, 0), Ok(0x5678));
        assert_eq!(mmio.read(0x4000_0004, 0x100, 1, 0), Ok(0x78));
        assert_eq!(mmio.consumed(), 0);
        // Another register falls to the default, here the empty input.
        assert_eq!(mmio.read(0x4000_0008, 0x100, 1, 0), Err(Exhausted));
    }

    #[test]
    fn bit_extract_feeds_only_its_bits_whole_bytes_at_a_time() {
        let at = |mask| MmioModel {
            address: 0x4000_0000,
            pc: None,
            kind: MmioModelKind::BitExtract { mask },
        };
        // One bit: a byte a read, its lowest bit the register's bit 5.
        let mut one = mmio(&[at(0x20)], MmioDefault::Zero);
        one.begin(&[0x01, 0xfe, 0x03]);
        assert_eq!(one.read(0x4000_0000, 0, 4, 0), Ok(0x20));
        assert_eq!(one.read(0x4000_0000, 0, 4, 0), Ok(0));
        assert_eq!(one.read(0x4000_0000, 0, 1, 0), Ok(0x20));
        assert_eq!(one.consumed(), 3);
        // Scattered bits fill in order from the lowest; nine take two bytes.
        let mut scattered = mmio(&[at(0x8000_0101)], MmioDefault::Zero);
        scattered.begin(&[0b110]);
        assert_eq!(scattered.read(0x4000_0000, 0, 4, 0), Ok(0x8000_0100));
        let mut nine = mmio(&[at(0x1ff << 4)], MmioDefault::Zero);
        nine.begin(&[0xff, 0x01, 0x00]);
        assert_eq!(nine.read(0x4000_0000, 0, 4, 0), Ok(0x1ff0));
        assert_eq!(nine.consumed(), 2);
        assert_eq!(nine.read(0x4000_0000, 0, 4, 0), Err(Exhausted));
        // Bits outside the access width are not read, so take nothing.
        let mut narrow = mmio(&[at(0x100)], MmioDefault::Zero);
        narrow.begin(&[]);
        assert_eq!(narrow.read(0x4000_0000, 0, 1, 0), Ok(0));
        assert!(at(0x20).kind.takes_input());
    }

    #[test]
    fn a_probe_flips_bits_of_one_read_only_and_the_trace_starts_there() {
        let mut mmio = mmio(&[], MmioDefault::Zero);
        mmio.set_trace_limit(8);
        mmio.begin(&[]);
        mmio.probe = Some(Probe {
            address: 0x4000_0000,
            pc: 0x100,
            xor: 0x120,
        });
        assert_eq!(mmio.read(0x4000_0000, 0x104, 1, 0), Ok(0), "another site");
        assert_eq!(
            mmio.read(0x4000_0000, 0x100, 1, 1),
            Ok(0x20),
            "cut to a byte"
        );
        assert_eq!(mmio.read(0x4000_0000, 0x100, 1, 2), Ok(0), "once");
        let traced: Vec<(u32, u32, u64)> = mmio
            .trace
            .iter()
            .map(|read| (read.pc, read.value, read.instructions))
            .collect();
        assert_eq!(traced, vec![(0x100, 0x20, 1), (0x100, 0, 2)]);
        assert_eq!(mmio.reads, 3);
    }

    #[test]
    fn a_traced_read_records_a_digest_of_the_stores_before_it() {
        let mut mmio = mmio(&[], MmioDefault::Zero);
        mmio.set_trace_limit(8);
        mmio.begin(&[]);
        mmio.read(0x4000_0000, 0x100, 4, 0).unwrap();
        for _ in 0..2 {
            mmio.note_store(0x2000_0000, 4, 7);
            mmio.read(0x4000_0000, 0x100, 4, 0).unwrap();
        }
        mmio.note_store(0x2000_0004, 4, 7);
        mmio.read(0x4000_0000, 0x100, 4, 0).unwrap();
        mmio.note_store(0x2000_0000, 4, 8);
        mmio.read(0x4000_0000, 0x100, 4, 0).unwrap();
        mmio.note_store(0x2000_0000, 4, 7);
        mmio.note_store(0x2000_0000, 4, 7);
        mmio.read(0x4000_0000, 0x100, 4, 0).unwrap();
        let digests: Vec<u64> = mmio.trace.iter().map(|read| read.stores).collect();
        assert_eq!(digests[0], 0, "no stores");
        assert_eq!(digests[1], digests[2], "the same store");
        assert_ne!(digests[1], 0);
        for other in &digests[3..] {
            assert_ne!(*other, digests[1], "another address, value or count");
        }
        assert_eq!(digests[3..].iter().collect::<HashSet<_>>().len(), 3);
    }

    #[test]
    fn a_model_for_an_instruction_wins_and_the_default_is_zero() {
        let models = [
            MmioModel {
                address: 0x4000_0000,
                pc: None,
                kind: MmioModelKind::Constant { value: 1 },
            },
            MmioModel {
                address: 0x4000_0000,
                pc: Some(0x200),
                kind: MmioModelKind::Constant { value: 2 },
            },
        ];
        let mut mmio = mmio(&models, MmioDefault::Zero);
        mmio.begin(&[0xff]);
        assert_eq!(mmio.read(0x4000_0000, 0x100, 4, 0), Ok(1));
        assert_eq!(mmio.read(0x4000_0000, 0x200, 4, 0), Ok(2));
        assert_eq!(mmio.read(0x4000_0010, 0x200, 4, 0), Ok(0));
        assert_eq!(mmio.consumed(), 0);
    }
}
