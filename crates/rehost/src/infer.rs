// SPDX-License-Identifier: Apache-2.0

//! Inferring bit-extract MMIO models from how firmware polls its
//! peripherals.
//!
//! A polling loop reads one status register over and over until a bit
//! changes: `while (!(USART->SR & RXNE)) {}`. Read as zero it spins until
//! the instruction budget runs out; fed whole from the input it eats the
//! input a few bytes a poll, on a bit the fuzzer has to hit by chance. The
//! loops show in a recorded trace of a run's peripheral reads
//! ([`Machine::trace_mmio`]): one instruction reads one register at least
//! [`MIN_POLLS`] times in a row, with no other peripheral read between, and
//! no model serves it.
//!
//! What a loop tests is found by probing, which needs neither source nor
//! symbolic execution: the run is paused just before the loop's first read
//! and run on from there with bits of that read flipped, and compared with
//! the recorded run from that read on. A bit whose flip changes the path to
//! the next peripheral read (another register is read next, none is, or the
//! same one after a different number of instructions) is a bit the firmware
//! tests; a bit-extract model for that instruction feeds just those bits
//! from the input. When no single bit changes the path, all of them are
//! flipped and then each one the loop does not need is put back, for loops
//! that wait for several bits at once.
//!
//! The same shape, one instruction reading one register over and over, is
//! also how a getter reads a data register in a dispatch loop
//! (`for (;;) { c = fifo_pop(); ... }`), where every bit matters and a test
//! such as `c == 'X'` shows in no single-bit flip. A read zero would answer
//! only gains bits from a bit-extract model, but a read the passthrough
//! default feeds from the input would lose the rest, so such a loop gets a
//! model only once it is shown to be a status poll ([`NotAPoll`] says why
//! not): some bit ends it, it stores nothing to memory between its reads
//! but the same stores each time round, and no value of the bits outside
//! the mask changes its path (every value of them for a read of up to 16
//! bits, every value of each byte's for a 32-bit read).
//!
//! Inference repeats on the run that gets past the loops already found, each
//! pinned to a value that ends it, so a loop behind another (the receive
//! poll after the transmit poll of a prompt) is found too.

use crate::machine::{Machine, MachineConfig, SetupError};
use crate::mmio::{MmioAccess, MmioDefault, MmioModel, MmioModelKind};
use crate::Image;
use std::collections::HashSet;

/// Reads in a row that make a polling loop.
pub const MIN_POLLS: usize = 8;
/// Rounds of inference, each on the run that gets past the loops found.
const MAX_ROUNDS: usize = 16;
/// Polling loops one inference decides.
const MAX_LOOPS: usize = 32;
/// Inputs an inference runs.
const MAX_INPUTS: usize = 8;
/// Peripheral reads the trace of an inference run keeps.
const TRACE_LIMIT: usize = 1 << 16;
/// Instructions a probe runs past the point where the recorded run read
/// again, for the path a flipped bit takes to show.
const PROBE_SLACK: u64 = 100_000;

/// A register one instruction reads over and over in a recorded trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollingLoop {
    /// The instruction that reads.
    pub pc: u32,
    pub address: u32,
    /// Bytes each read takes: 1, 2 or 4.
    pub size: u8,
    /// Where in the trace the loop's first read is.
    pub first: usize,
    /// Reads in a row, as far as the trace holds them.
    pub polls: usize,
    /// What the first read returned.
    pub value: u32,
    /// Whether the loop stores to memory between its reads, other than the
    /// same stores each time round (a call's saved registers, say): work
    /// done with what it reads, which a status poll does not do.
    pub writes: bool,
}

/// The polling loops of a recorded trace, first one first: each run of at
/// least `min_polls` reads in a row of one register by one instruction that
/// no model served. A register an instruction polls again later is named
/// once, at its first loop.
pub fn polling_loops(trace: &[MmioAccess], min_polls: usize) -> Vec<PollingLoop> {
    let min_polls = min_polls.max(2);
    let mut loops = Vec::new();
    let mut seen = HashSet::new();
    let mut start = 0;
    while start < trace.len() {
        let read = trace[start];
        let polls = trace[start..]
            .iter()
            .take_while(|other| (other.pc, other.address) == (read.pc, read.address))
            .count();
        if !read.modelled && polls >= min_polls && seen.insert((read.pc, read.address)) {
            // The stores before each read after the first: the ones each
            // time round the loop.
            let rounds = &trace[start + 1..start + polls];
            loops.push(PollingLoop {
                pc: read.pc,
                address: read.address,
                size: read.size,
                first: start,
                polls,
                value: read.value,
                writes: rounds.iter().any(|other| other.stores != rounds[0].stores),
            });
        }
        start += polls;
    }
    loops
}

/// How a probed run went on from the read at `index`, against the recorded
/// run it repeats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// As before: the same register read next, as many instructions later.
    Same,
    /// The path changed, but the same instruction read the register next.
    Changed,
    /// The loop ended: another register was read next, or none was.
    Left,
}

/// Compare the reads of a recorded run from the one at `index` on with
/// `probed`, the reads of a run that repeats it with that read's value
/// changed, from that read on: the probed read, then the one after it.
pub fn probe_outcome(recorded: &[MmioAccess], index: usize, probed: &[MmioAccess]) -> ProbeOutcome {
    let (Some(read), Some(next)) = (recorded.get(index), recorded.get(index + 1)) else {
        return ProbeOutcome::Same;
    };
    let Some(after) = probed.get(1) else {
        return ProbeOutcome::Left;
    };
    if (after.pc, after.address) != (next.pc, next.address) {
        return ProbeOutcome::Left;
    }
    let at = probed[0].instructions;
    if after.instructions.wrapping_sub(at) == next.instructions.wrapping_sub(read.instructions) {
        ProbeOutcome::Same
    } else {
        ProbeOutcome::Changed
    }
}

/// Why a loop whose read takes the input is not taken for a status poll.
/// Its read then keeps taking all its bytes from the input, since a
/// bit-extract model would feed the firmware only some of the bits it uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAPoll {
    /// No bit the probes flipped ends the loop: it is not waiting for one.
    NoExit,
    /// The loop stores to memory between its reads.
    WritesMemory,
    /// This value of the read, which differs from the recorded one only in
    /// bits outside the mask, changes the loop's path: the loop compares
    /// more than the bits one flip at a time shows (`c == 'X'`).
    OtherBits { value: u32 },
}

impl NotAPoll {
    /// A stable name for the reason.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoExit => "no_exit",
            Self::WritesMemory => "writes_memory",
            Self::OtherBits { .. } => "other_bits",
        }
    }
}

/// What inference decided about one polling loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InferredLoop {
    pub polling: PollingLoop,
    /// The bits whose value changes the loop's path: the bits a bit-extract
    /// model feeds from the input. Zero when no probe changed it.
    pub mask: u32,
    /// A value of the read that ends the loop, when a probe found one.
    pub exit: Option<u32>,
    /// Why the loop is not taken for a status poll, for a loop whose read
    /// takes the input: it then gets no model.
    pub not_a_poll: Option<NotAPoll>,
}

impl InferredLoop {
    /// A bit-extract model for the polling instruction, feeding the bits
    /// that decide the loop from the input.
    pub fn bit_extract(&self) -> Option<MmioModel> {
        (self.mask != 0 && self.not_a_poll.is_none()).then_some(MmioModel {
            address: self.polling.address,
            pc: Some(self.polling.pc),
            kind: MmioModelKind::BitExtract { mask: self.mask },
        })
    }

    /// A constant model for the polling instruction that ends the loop at
    /// its first read.
    pub fn constant(&self) -> Option<MmioModel> {
        self.exit
            .filter(|_| self.not_a_poll.is_none())
            .map(|value| MmioModel {
                address: self.polling.address,
                pc: Some(self.polling.pc),
                kind: MmioModelKind::Constant { value },
            })
    }
}

/// The nonzero subsets of `set`, smallest first.
fn subsets(set: u32) -> impl Iterator<Item = u32> {
    let mut subset = 0u32;
    std::iter::from_fn(move || {
        subset = subset.wrapping_sub(set) & set;
        (subset != 0).then_some(subset)
    })
}

/// What to XOR into a read of `size` bytes to check that its bits outside
/// `mask` decide nothing: every combination of two or more of them (each
/// one alone has been flipped already), of all of them for a read of up to
/// 16 bits and of each byte's for a wider one.
fn other_values(size: u8, mask: u32) -> impl Iterator<Item = u32> {
    let groups: Vec<u32> = match size {
        1 => vec![0xff & !mask],
        2 => vec![0xffff & !mask],
        _ => (0..4).map(|lane| (0xff << (8 * lane)) & !mask).collect(),
    };
    groups
        .into_iter()
        .flat_map(subsets)
        .filter(|xor| xor.count_ones() >= 2)
}

/// Decide which bits of `polling`, a loop of `trace`, the firmware tests.
/// `probe(xor)` repeats the recorded run with the loop's first read XORed
/// with `xor` and returns that run's reads from that one on. `fed` says
/// the read takes its bytes from the input, so the loop has to be shown to
/// be a status poll. Returns the decision and the probes it took.
pub fn decide(
    trace: &[MmioAccess],
    polling: &PollingLoop,
    fed: bool,
    mut probe: impl FnMut(u32) -> Vec<MmioAccess>,
) -> (InferredLoop, usize) {
    let bits = u32::from(polling.size.clamp(1, 4)) * 8;
    let width = u32::MAX >> (32 - bits);
    let mut probes = 0;
    let mut outcome = |xor: u32| {
        probes += 1;
        probe_outcome(trace, polling.first, &probe(xor))
    };
    let mut mask = 0u32;
    let mut leaving = 0u32;
    for bit in 0..bits {
        match outcome(1 << bit) {
            ProbeOutcome::Same => {}
            ProbeOutcome::Changed => mask |= 1 << bit,
            ProbeOutcome::Left => {
                mask |= 1 << bit;
                leaving |= 1 << bit;
            }
        }
    }
    // The lowest bit that ends the loop alone.
    let mut exit = (leaving != 0).then(|| polling.value ^ (leaving & leaving.wrapping_neg()));
    if mask == 0 && outcome(width) == ProbeOutcome::Left {
        // No bit alone decides the loop, all of them together do: keep the
        // ones it cannot end without.
        let mut needed = width;
        for bit in 0..bits {
            let fewer = needed & !(1 << bit);
            if fewer != 0 && outcome(fewer) == ProbeOutcome::Left {
                needed = fewer;
            }
        }
        mask = needed;
        exit = Some(polling.value ^ needed);
    }
    let not_a_poll = if !fed {
        None
    } else if exit.is_none() {
        Some(NotAPoll::NoExit)
    } else if polling.writes {
        Some(NotAPoll::WritesMemory)
    } else {
        other_values(polling.size, mask)
            .find(|&xor| outcome(xor) != ProbeOutcome::Same)
            .map(|xor| NotAPoll::OtherBits {
                value: polling.value ^ xor,
            })
    };
    (
        InferredLoop {
            polling: *polling,
            mask,
            exit,
            not_a_poll,
        },
        probes,
    )
}

/// What an inference found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inference {
    /// The polling loops found, in the order they were found.
    pub loops: Vec<InferredLoop>,
    /// Rounds run: each on the run that gets past the loops found before.
    pub rounds: usize,
    /// Probe runs made.
    pub probes: usize,
}

impl Inference {
    /// A bit-extract model for each status poll some bits decide.
    pub fn bit_extract_models(&self) -> Vec<MmioModel> {
        self.loops
            .iter()
            .filter_map(InferredLoop::bit_extract)
            .collect()
    }

    /// A constant model for each status poll a probe found a way out of.
    pub fn constant_models(&self) -> Vec<MmioModel> {
        self.loops
            .iter()
            .filter_map(InferredLoop::constant)
            .collect()
    }
}

/// Infer the polling loops `inputs` reach in `image` run as `config` says,
/// and the bits that decide each: the loops of registers `config`'s models
/// do not serve, found in each run's trace and decided by probes. Under the
/// passthrough default those reads take the input, so each loop is checked
/// to be a status poll as well.
pub fn infer_polling_models(
    image: &Image,
    config: &MachineConfig,
    inputs: &[Vec<u8>],
) -> Result<Inference, SetupError> {
    let inputs = &inputs[..inputs.len().min(MAX_INPUTS)];
    let fed = config.mmio.default == MmioDefault::Passthrough;
    let mut inference = Inference::default();
    let mut pins: Vec<MmioModel> = Vec::new();
    let mut seen = HashSet::new();
    'rounds: while inference.rounds < MAX_ROUNDS {
        inference.rounds += 1;
        let mut round = config.clone();
        round.mmio.models.extend(pins.iter().copied());
        let mut machine = Machine::new(image, round)?;
        let mut pinned = false;
        for input in inputs {
            machine.trace_mmio(TRACE_LIMIT);
            machine.run(input);
            let trace = machine.mmio_trace().to_vec();
            for polling in polling_loops(&trace, MIN_POLLS) {
                if !seen.insert((polling.pc, polling.address)) {
                    continue;
                }
                if inference.loops.len() >= MAX_LOOPS {
                    break 'rounds;
                }
                let budget = trace[polling.first + 1]
                    .instructions
                    .saturating_add(PROBE_SLACK);
                // A run repeats exactly, so it reaches the read again.
                let Some(point) = machine.pause_before(input, &trace[polling.first], budget) else {
                    continue;
                };
                let (inferred, probes) = decide(&trace, &polling, fed, |xor| {
                    machine.probe_from(&point, input, xor, budget).to_vec()
                });
                inference.probes += probes;
                if let Some(pin) = inferred.constant() {
                    pins.push(pin);
                    pinned = true;
                }
                inference.loops.push(inferred);
            }
        }
        if !pinned {
            break;
        }
    }
    Ok(inference)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A recorded read; `at` is the instruction count.
    fn read(pc: u32, address: u32, value: u32, at: u64) -> MmioAccess {
        MmioAccess {
            pc,
            address,
            size: 4,
            value,
            instructions: at,
            modelled: false,
            stores: 0,
        }
    }

    const SR: u32 = 0x4001_1000;
    const DR: u32 = 0x4001_1004;
    const ID: u32 = 0x4001_1008;
    const POLL: u32 = 0x0800_0102;

    /// A recorded run of `while (!(SR & 0x20)) {}` reading zero: an ID read,
    /// then `polls` status reads three instructions apart.
    fn recorded_poll(polls: usize) -> Vec<MmioAccess> {
        let mut trace = vec![read(0x0800_0100, ID, 0x11, 4)];
        trace.extend((0..polls).map(|index| read(POLL, SR, 0, 10 + 3 * index as u64)));
        trace
    }

    /// What firmware polling the status bits `exit` (any of them set ends
    /// the loop) and testing `error` inside it (one more instruction) does
    /// when the read at `first` is XORed with `xor`: the probed read and
    /// the read after it, as a probe returns them.
    fn polled(first: usize, xor: u32, exit: u32, error: u32) -> Vec<MmioAccess> {
        let mut trace = recorded_poll(first);
        let value = trace[first].value ^ xor;
        trace[first].value = value;
        let at = trace[first].instructions;
        if value & exit != 0 {
            trace.push(read(0x0800_0108, DR, 0, at + 4));
        } else {
            let extra = u64::from(value & error != 0);
            trace.push(read(POLL, SR, 0, at + 3 + extra));
        }
        trace.split_off(first)
    }

    /// The loop `recorded` holds, as [`polling_loops`] finds it.
    fn the_loop(recorded: &[MmioAccess]) -> PollingLoop {
        let loops = polling_loops(recorded, MIN_POLLS);
        assert_eq!(loops.len(), 1, "{loops:?}");
        loops[0]
    }

    #[test]
    fn a_register_read_over_and_over_by_one_instruction_is_a_polling_loop() {
        let mut trace = recorded_poll(20);
        // Reads of the data register in a row are a loop as well; whether
        // the probes show it to be a status poll is for `decide`. Below the
        // threshold, or served by a model, they are not.
        trace.extend((0..3).map(|index| read(0x0800_0200, DR, 0x41, 100 + index)));
        trace.extend((0..10).map(|index| MmioAccess {
            modelled: true,
            ..read(0x0800_0300, DR, 0x42, 200 + index)
        }));
        trace.extend((0..9).map(|index| read(0x0800_0400, DR, 0x43, 300 + 4 * index)));
        // The same loop again later is not named twice.
        trace.extend((0..12).map(|index| read(POLL, SR, 0, 400 + 3 * index)));
        let loops = polling_loops(&trace, MIN_POLLS);
        assert_eq!(
            loops,
            vec![
                PollingLoop {
                    pc: POLL,
                    address: SR,
                    size: 4,
                    first: 1,
                    polls: 20,
                    value: 0,
                    writes: false,
                },
                PollingLoop {
                    pc: 0x0800_0400,
                    address: DR,
                    size: 4,
                    first: 34,
                    polls: 9,
                    value: 0x43,
                    writes: false,
                },
            ]
        );
        // Another register between two reads breaks the loop.
        let mut alternating = Vec::new();
        for index in 0..20 {
            alternating.push(read(POLL, SR, 0, 10 * index));
            alternating.push(read(0x0800_0104, ID, 0, 10 * index + 5));
        }
        assert_eq!(polling_loops(&alternating, MIN_POLLS), Vec::new());
        assert_eq!(polling_loops(&[], MIN_POLLS), Vec::new());
    }

    #[test]
    fn a_loop_writes_when_its_stores_differ_from_one_time_round_to_the_next() {
        // The same stores each time round (a call's saved registers), and
        // stores before the loop: no writes.
        let mut same = recorded_poll(12);
        for (index, poll) in same.iter_mut().enumerate() {
            poll.stores = if index < 2 { index as u64 + 5 } else { 0x77 };
        }
        assert!(!the_loop(&same).writes);
        // A store that differs once, a buffer filling, say.
        let mut filling = same.clone();
        filling[7].stores = 0x78;
        assert!(the_loop(&filling).writes);
        let mut none_then_one = recorded_poll(12);
        none_then_one[12].stores = 1;
        assert!(the_loop(&none_then_one).writes);
    }

    #[test]
    fn a_probe_that_reads_elsewhere_next_left_the_loop() {
        let recorded = recorded_poll(10);
        let at = 1;
        assert_eq!(
            probe_outcome(&recorded, at, &polled(at, 1, 0x20, 0)),
            ProbeOutcome::Same
        );
        assert_eq!(
            probe_outcome(&recorded, at, &polled(at, 0x20, 0x20, 0)),
            ProbeOutcome::Left
        );
        assert_eq!(
            probe_outcome(&recorded, at, &polled(at, 0x08, 0x20, 0x08)),
            ProbeOutcome::Changed
        );
        // A probe whose run read nothing more left the loop too.
        assert_eq!(
            probe_outcome(&recorded, at, &recorded[at..=at]),
            ProbeOutcome::Left
        );
    }

    #[test]
    fn inference_on_a_recorded_trace_feeds_the_bits_the_loop_tests() {
        let trace = recorded_poll(16);
        let polling = the_loop(&trace);
        let mut probed = Vec::new();
        let (inferred, probes) = decide(&trace, &polling, false, |xor| {
            probed.push(xor);
            polled(polling.first, xor, 0x20, 0x08)
        });
        assert_eq!(probes, 32, "one probe a bit");
        assert_eq!(probed, (0..32).map(|bit| 1u32 << bit).collect::<Vec<_>>());
        // Bit 5 ends the loop; bit 3 takes another path through it.
        assert_eq!(inferred.mask, 0x28);
        assert_eq!(inferred.exit, Some(0x20));
        assert_eq!(inferred.not_a_poll, None);
        assert_eq!(
            inferred.bit_extract(),
            Some(MmioModel {
                address: SR,
                pc: Some(POLL),
                kind: MmioModelKind::BitExtract { mask: 0x28 },
            })
        );
        assert_eq!(
            inferred.constant().map(|model| model.kind),
            Some(MmioModelKind::Constant { value: 0x20 })
        );
    }

    #[test]
    fn a_status_poll_whose_read_takes_the_input_is_checked_at_the_other_values() {
        let trace = recorded_poll(16);
        let polling = the_loop(&trace);
        let mut probed = Vec::new();
        let (inferred, probes) = decide(&trace, &polling, true, |xor| {
            probed.push(xor);
            polled(polling.first, xor, 0x20, 0x08)
        });
        assert_eq!((inferred.mask, inferred.not_a_poll), (0x28, None));
        // A 32-bit read: every value of each byte's other bits, two or more
        // of them, after the 32 single bits. Byte 0 has six of them.
        let checked = (64 - 1 - 6) + 3 * (256 - 1 - 8);
        assert_eq!(probes, 32 + checked);
        assert_eq!(probed[32..36], [0x03, 0x05, 0x06, 0x07]);
        assert!(probed[32..].iter().all(|xor| xor & 0x28 == 0));
        assert!(inferred.bit_extract().is_some());
    }

    #[test]
    fn a_loop_whose_read_takes_the_input_and_that_nothing_ends_keeps_it_whole() {
        // `for (;;) { c = DR; if (c == 1) armed++; }`, read as zero: bit 0
        // changes the path, no bit ends the loop.
        let trace = recorded_poll(16);
        let polling = the_loop(&trace);
        let decided = |fed| {
            decide(&trace, &polling, fed, |xor| {
                polled(polling.first, xor, 0, 1)
            })
        };
        let (inferred, probes) = decided(true);
        assert_eq!((inferred.mask, inferred.exit), (0x01, None));
        assert_eq!(inferred.not_a_poll, Some(NotAPoll::NoExit));
        assert_eq!(probes, 32);
        assert_eq!((inferred.bit_extract(), inferred.constant()), (None, None));
        // Read as zero it gains the bit.
        let (zero, _) = decided(false);
        assert_eq!(zero.not_a_poll, None);
        assert!(zero.bit_extract().is_some());
    }

    #[test]
    fn a_loop_that_stores_between_its_reads_keeps_its_read_whole() {
        let mut trace = recorded_poll(16);
        for (index, poll) in trace.iter_mut().enumerate().skip(2) {
            poll.stores = index as u64;
        }
        let polling = the_loop(&trace);
        assert!(polling.writes);
        let (inferred, probes) = decide(&trace, &polling, true, |xor| {
            polled(polling.first, xor, 0x20, 0)
        });
        assert_eq!((inferred.mask, inferred.exit), (0x20, Some(0x20)));
        assert_eq!(inferred.not_a_poll, Some(NotAPoll::WritesMemory));
        assert_eq!(probes, 32, "no value check");
        assert_eq!(inferred.bit_extract(), None);
    }

    #[test]
    fn a_byte_compared_whole_is_found_among_the_values_of_the_other_bits() {
        // `for (;;) { c = DR; if (c == 4) break; if (c == 'X') ...; }`: bit 2
        // ends the loop, and 'X' takes another path no single bit shows.
        let mut trace = recorded_poll(16);
        for read in &mut trace {
            read.size = 1;
        }
        let polling = the_loop(&trace);
        let dispatch = |xor: u32| {
            let mut run = polled(polling.first, xor, 0x04, 0);
            if xor == u32::from(b'X') {
                run[1].instructions += 2;
            }
            run
        };
        let (inferred, probes) = decide(&trace, &polling, true, dispatch);
        assert_eq!((inferred.mask, inferred.exit), (0x04, Some(0x04)));
        assert_eq!(
            inferred.not_a_poll,
            Some(NotAPoll::OtherBits {
                value: u32::from(b'X')
            })
        );
        assert_eq!(inferred.not_a_poll.unwrap().as_str(), "other_bits");
        assert_eq!(inferred.bit_extract(), None);
        let before_x = subsets(0xfb)
            .filter(|xor| xor.count_ones() >= 2)
            .take_while(|&xor| xor != u32::from(b'X'))
            .count();
        assert_eq!(probes, 8 + before_x + 1);
        // Without the 'X' the same loop is a status poll: every value of
        // the seven other bits is tried.
        let (poll, probes) = decide(&trace, &polling, true, |xor| {
            polled(polling.first, xor, 0x04, 0)
        });
        assert_eq!(poll.not_a_poll, None);
        assert_eq!(probes, 8 + (128 - 1 - 7));
    }

    #[test]
    fn a_halfword_read_is_checked_at_every_value_of_its_other_bits() {
        let mut trace = recorded_poll(16);
        for read in &mut trace {
            read.size = 2;
        }
        let polling = the_loop(&trace);
        let mut checked = HashSet::new();
        let (inferred, probes) = decide(&trace, &polling, true, |xor| {
            checked.insert(xor);
            let mut run = polled(polling.first, xor, 0x8000, 0);
            if xor == 0x1234 {
                run[1].instructions += 1;
            }
            run
        });
        assert_eq!(
            inferred.not_a_poll,
            Some(NotAPoll::OtherBits { value: 0x1234 }),
            "a value across both bytes"
        );
        // Sixteen single bits, then every combination of two or more of the
        // fifteen others up to 0x1234; the thirteen bits below it came alone.
        assert_eq!(probes, 16 + (0x1234 - 13));
        assert!(checked.contains(&0x1234));
    }

    #[test]
    fn a_loop_that_waits_for_two_bits_at_once_needs_both() {
        // `while ((SR & 0x81) != 0x81) {}`: no bit alone ends it.
        let trace = recorded_poll(16);
        let polling = the_loop(&trace);
        let (inferred, probes) = decide(&trace, &polling, false, |xor| {
            let mut run = recorded_poll(polling.first);
            let at = run[polling.first].instructions;
            run.push(if xor & 0x81 == 0x81 {
                read(0x0800_0108, DR, 0, at + 4)
            } else {
                read(POLL, SR, 0, at + 3)
            });
            run.split_off(polling.first)
        });
        assert_eq!(inferred.mask, 0x81);
        assert_eq!(inferred.exit, Some(0x81));
        assert_eq!(probes, 32 + 1 + 32);
    }

    #[test]
    fn a_loop_no_bit_decides_gets_no_model() {
        // A data register read in a counted loop: the value goes nowhere.
        let trace = recorded_poll(16);
        let polling = the_loop(&trace);
        let (inferred, probes) =
            decide(&trace, &polling, false, |_| trace[polling.first..].to_vec());
        assert_eq!((inferred.mask, inferred.exit), (0, None));
        assert_eq!(probes, 33, "each bit, then all of them");
        assert_eq!(inferred.bit_extract(), None);
        assert_eq!(inferred.constant(), None);
    }

    #[test]
    fn a_byte_wide_poll_probes_eight_bits() {
        let mut trace = recorded_poll(16);
        for read in &mut trace {
            read.size = 1;
        }
        let polling = the_loop(&trace);
        let (inferred, probes) = decide(&trace, &polling, false, |xor| {
            polled(polling.first, xor, 0x80, 0)
        });
        assert_eq!((inferred.mask, probes), (0x80, 8));
    }

    #[test]
    fn subsets_come_smallest_first() {
        assert_eq!(
            subsets(0b1011).collect::<Vec<_>>(),
            vec![0b0001, 0b0010, 0b0011, 0b1000, 0b1001, 0b1010, 0b1011]
        );
        assert_eq!(subsets(0).count(), 0);
        assert_eq!(subsets(u32::MAX).take(3).collect::<Vec<_>>(), vec![1, 2, 3]);
        assert_eq!(other_values(4, 0xff00_00ff).count(), 2 * (256 - 1 - 8));
    }
}
