// SPDX-License-Identifier: Apache-2.0

//! Interrupts: the NVIC's enable, pending and priority registers, SysTick's
//! and PendSV's pending bits, and the input-chosen schedule that raises
//! interrupts while a run goes on.
//!
//! Firmware that waits for its peripherals to interrupt it (a UART's
//! receive interrupt, a timer tick) never progresses when nothing raises
//! one. The schedule does: every *tick* it takes one byte from the input
//! stream, the same stream peripheral reads take (`mmio.rs`), and pends one
//! of the interrupts the firmware has enabled (the NVIC's external
//! interrupts and SysTick, when its counter and its interrupt are on): the
//! byte modulo how many are enabled picks which, in order of exception
//! number, and its top three bits pick the wait until the next tick, a
//! multiple of the interval ([`InterruptConfig`]). So the interrupt
//! schedule is part of the testcase, and the fuzzer chooses which interrupt
//! comes when, as Fuzzware's fuzzed interrupt triggers do. A tick with
//! nothing enabled takes no byte, and a tick the input has no byte left for
//! raises nothing.
//!
//! When the core waits for an interrupt (`WFI`, `WFE`, or a branch to
//! itself) and one could wake it, time runs on to the next tick at once
//! rather than spinning; with nothing that could wake it, the run ends idle
//! as before. A pending interrupt is taken between two instructions when
//! its group priority is higher than the core's execution priority (the
//! active exceptions, `BASEPRI`, `PRIMASK` and `FAULTMASK`, with
//! `AIRCR.PRIGROUP`'s grouping); the firmware's own pending bits (`ISPR`,
//! `ICSR.PENDSVSET`, `ICSR.PENDSTSET`) are taken the same way.
//!
//! An interrupt's handler counts its own edges: the edge into the handler
//! is from the interrupt, not from the block it interrupted, and the return
//! goes back to the interrupted block's edge context without counting an
//! edge, so where an interrupt lands does not make new coverage of its own.

use crate::cpu::{Core, Step, SVCALL};

/// The interval of the schedule when none is named, in instructions.
pub const DEFAULT_INTERRUPT_INTERVAL: u64 = 1000;
/// Interrupts a run's log keeps ([`crate::Machine::interrupt_log`]).
pub const INTERRUPT_LOG_LIMIT: usize = 64;

const SYSTICK: u32 = 15;
const PENDSV: u32 = 14;
/// External interrupts the NVIC can have (exceptions 16 to 255).
const IRQS: usize = 240;

const SYST_CSR: u32 = 0xe000_e010;
const NVIC_ISER: u32 = 0xe000_e100;
const NVIC_ICER: u32 = 0xe000_e180;
const NVIC_ISPR: u32 = 0xe000_e200;
const NVIC_ICPR: u32 = 0xe000_e280;
const NVIC_IABR: u32 = 0xe000_e300;
const NVIC_IPR: u32 = 0xe000_e400;
const NVIC_IPR_END: u32 = NVIC_IPR + IRQS as u32;
pub(crate) const ICSR: u32 = 0xe000_ed04;
pub(crate) const AIRCR: u32 = 0xe000_ed0c;
const SHPR2: u32 = 0xe000_ed1c;
const SHPR3: u32 = 0xe000_ed20;

const ICSR_PENDSVSET: u32 = 1 << 28;
const ICSR_PENDSVCLR: u32 = 1 << 27;
const ICSR_PENDSTSET: u32 = 1 << 26;
const ICSR_PENDSTCLR: u32 = 1 << 25;
const ICSR_ISRPENDING: u32 = 1 << 22;
const ICSR_RETTOBASE: u32 = 1 << 11;

/// The execution priority of Thread mode with nothing masked: lower than
/// any configurable priority.
const BASE_PRIORITY: i32 = 256;

/// How a machine raises interrupts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptConfig {
    /// Instructions from one tick of the schedule to the next when a tick's
    /// byte picks the plain wait; the other waits are multiples of it (see
    /// [`schedule_wait`]). Must be at least 1.
    pub interval: u64,
}

impl Default for InterruptConfig {
    fn default() -> Self {
        Self {
            interval: DEFAULT_INTERRUPT_INTERVAL,
        }
    }
}

/// One interrupt a run took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptEvent {
    /// Instructions the run had executed when it took the interrupt.
    pub instructions: u64,
    /// The exception number: 14 PendSV, 15 SysTick, `16 + n` IRQ `n`.
    pub exception: u32,
    /// The instruction it interrupted, which the handler returns to.
    pub pc: u32,
}

impl InterruptEvent {
    /// The external interrupt number, or `None` for SysTick and PendSV.
    pub fn irq(&self) -> Option<u32> {
        self.exception.checked_sub(16)
    }
}

/// The instructions until the next tick that a tick's byte picks with its
/// top three bits: the interval, a half, a quarter, one instruction, four,
/// eight and sixteen times it, and twice it (the plain interval and a near
/// multiple sit at the two ends, where the values a mutator favours, 0x00
/// and 0xff, fall). Never zero.
pub fn schedule_wait(interval: u64, byte: u8) -> u64 {
    let interval = interval.max(1);
    let wait = match byte >> 5 {
        0 => interval,
        1 => interval / 2,
        2 => interval / 4,
        3 => 1,
        4 => interval.saturating_mul(4),
        5 => interval.saturating_mul(8),
        6 => interval.saturating_mul(16),
        _ => interval.saturating_mul(2),
    };
    wait.max(1)
}

/// The interrupt controller's state and the schedule's.
#[derive(Clone)]
pub(crate) struct Nvic {
    interval: u64,
    enabled: [u32; 8],
    pending: [u32; 8],
    priority: [u8; IRQS],
    pendsv: bool,
    systick: bool,
    /// `AIRCR.PRIGROUP`.
    prigroup: u32,
    /// The instruction count at which the next tick is due.
    next_tick: u64,
    /// The edge-map context of each interrupt being handled, innermost last.
    contexts: Vec<u32>,
    pub(crate) taken: u64,
    pub(crate) log: Vec<InterruptEvent>,
    /// Bytes of the input the schedule took.
    pub(crate) schedule_bytes: usize,
}

impl Nvic {
    pub(crate) fn new(config: InterruptConfig) -> Self {
        let mut nvic = Self {
            interval: config.interval.max(1),
            enabled: [0; 8],
            pending: [0; 8],
            priority: [0; IRQS],
            pendsv: false,
            systick: false,
            prigroup: 0,
            next_tick: 0,
            contexts: Vec::new(),
            taken: 0,
            log: Vec::new(),
            schedule_bytes: 0,
        };
        nvic.reset();
        nvic
    }

    /// The state at reset: nothing enabled or pending, every priority zero.
    pub(crate) fn reset(&mut self) {
        self.enabled = [0; 8];
        self.pending = [0; 8];
        self.priority = [0; IRQS];
        self.pendsv = false;
        self.systick = false;
        self.prigroup = 0;
        self.next_tick = self.interval;
        self.contexts.clear();
        self.taken = 0;
        self.log.clear();
        self.schedule_bytes = 0;
    }

    fn bit(irq: usize) -> (usize, u32) {
        (irq / 32, 1 << (irq % 32))
    }

    fn set_pending(&mut self, exception: u32) {
        match exception {
            PENDSV => self.pendsv = true,
            SYSTICK => self.systick = true,
            _ => {
                let (word, bit) = Self::bit(exception as usize - 16);
                self.pending[word] |= bit;
            }
        }
    }

    fn clear_pending(&mut self, exception: u32) {
        match exception {
            PENDSV => self.pendsv = false,
            SYSTICK => self.systick = false,
            _ => {
                let (word, bit) = Self::bit(exception as usize - 16);
                self.pending[word] &= !bit;
            }
        }
    }

    fn any_pending(&self) -> bool {
        self.pendsv || self.systick || self.pending.iter().any(|&word| word != 0)
    }

    /// The external interrupts the firmware has enabled, as exception
    /// numbers, lowest first.
    fn enabled_irqs(&self) -> impl Iterator<Item = u32> + '_ {
        set_bits(&self.enabled).map(|irq| irq + 16)
    }

    /// The exceptions pending that the NVIC would take: enabled external
    /// interrupts, SysTick and PendSV.
    fn pending_exceptions(&self) -> impl Iterator<Item = u32> + '_ {
        let mut words = [0u32; 8];
        for (word, (pending, enabled)) in
            words.iter_mut().zip(self.pending.iter().zip(&self.enabled))
        {
            *word = pending & enabled;
        }
        let system = [
            self.pendsv.then_some(PENDSV),
            self.systick.then_some(SYSTICK),
        ];
        system
            .into_iter()
            .flatten()
            .chain(set_bits_owned(words).map(|irq| irq + 16))
    }

    /// The word the NVIC answers a read of `word` with, if it is one of its
    /// registers.
    pub(crate) fn read(&self, word: u32, active: &[u32]) -> Option<u32> {
        let index = |base: u32| ((word - base) / 4) as usize;
        Some(match word {
            NVIC_ISER..=0xe000_e11c | NVIC_ICER..=0xe000_e19c => {
                let base = if word < NVIC_ICER {
                    NVIC_ISER
                } else {
                    NVIC_ICER
                };
                self.enabled[index(base)]
            }
            NVIC_ISPR..=0xe000_e21c | NVIC_ICPR..=0xe000_e29c => {
                let base = if word < NVIC_ICPR {
                    NVIC_ISPR
                } else {
                    NVIC_ICPR
                };
                self.pending[index(base)]
            }
            NVIC_IABR..=0xe000_e31c => {
                let first = index(NVIC_IABR) as u32 * 32 + 16;
                active
                    .iter()
                    .filter(|&&exception| (first..first + 32).contains(&exception))
                    .fold(0, |bits, &exception| bits | 1 << (exception - first))
            }
            NVIC_IPR..NVIC_IPR_END => {
                let first = (word - NVIC_IPR) as usize;
                u32::from_le_bytes([
                    self.priority[first],
                    self.priority[first + 1],
                    self.priority[first + 2],
                    self.priority[first + 3],
                ])
            }
            AIRCR => 0xfa05_0000 | self.prigroup << 8,
            _ => return None,
        })
    }

    /// A write of the bits `bits` (in place, under `mask`) to `word`, when it
    /// is one of the NVIC's registers; returns whether it was.
    pub(crate) fn write(&mut self, word: u32, bits: u32, mask: u32) -> bool {
        let index = |base: u32| ((word - base) / 4) as usize;
        match word {
            NVIC_ISER..=0xe000_e11c => self.enabled[index(NVIC_ISER)] |= bits,
            NVIC_ICER..=0xe000_e19c => self.enabled[index(NVIC_ICER)] &= !bits,
            NVIC_ISPR..=0xe000_e21c => self.pending[index(NVIC_ISPR)] |= bits,
            NVIC_ICPR..=0xe000_e29c => self.pending[index(NVIC_ICPR)] &= !bits,
            NVIC_IABR..=0xe000_e31c => {}
            NVIC_IPR..NVIC_IPR_END => {
                let first = (word - NVIC_IPR) as usize;
                for byte in 0..4 {
                    if mask >> (8 * byte) & 0xff != 0 {
                        self.priority[first + byte] = (bits >> (8 * byte)) as u8;
                    }
                }
            }
            _ => return false,
        }
        // The last word's bits past IRQ 239 do not exist.
        self.enabled[7] &= 0xffff;
        self.pending[7] &= 0xffff;
        true
    }
}

/// The indexes of the set bits of `words`, lowest first.
fn set_bits(words: &[u32; 8]) -> impl Iterator<Item = u32> + '_ {
    words.iter().enumerate().flat_map(|(index, &word)| {
        (0..32)
            .filter(move |bit| word >> bit & 1 != 0)
            .map(move |bit| index as u32 * 32 + bit)
    })
}

fn set_bits_owned(words: [u32; 8]) -> impl Iterator<Item = u32> {
    (0..8).flat_map(move |index| {
        let word = words[index];
        (0..32)
            .filter(move |bit| word >> bit & 1 != 0)
            .map(move |bit| index as u32 * 32 + bit)
    })
}

impl Core {
    /// The configured priority of exception `number`.
    fn exception_priority(&self, number: u32) -> i32 {
        match number {
            2 => -2,
            3 => -1,
            SVCALL => (self.ppb_word(SHPR2) >> 24) as i32,
            PENDSV => (self.ppb_word(SHPR3) >> 16 & 0xff) as i32,
            SYSTICK => (self.ppb_word(SHPR3) >> 24) as i32,
            n if n >= 16 => self
                .irq
                .as_ref()
                .map_or(0, |nvic| i32::from(nvic.priority[(n - 16) as usize])),
            _ => 0,
        }
    }

    /// The group priority of `priority` under `AIRCR.PRIGROUP`: the bits
    /// above the subpriority's.
    fn group_priority(&self, priority: i32) -> i32 {
        if priority < 0 {
            return priority;
        }
        let prigroup = self.irq.as_ref().map_or(0, |nvic| nvic.prigroup);
        priority & (0xff << (prigroup + 1)) & 0xff
    }

    /// The core's execution priority: what an exception's group priority
    /// must be below to preempt. `WFI` wakes for an interrupt `PRIMASK`
    /// alone masks, so `ignore_primask` leaves it out.
    fn execution_priority(&self, ignore_primask: bool) -> i32 {
        let mut priority = BASE_PRIORITY;
        for &active in &self.active {
            priority = priority.min(self.group_priority(self.exception_priority(active)));
        }
        if self.basepri != 0 {
            priority = priority.min(self.group_priority(self.basepri as i32));
        }
        if self.primask && !ignore_primask {
            priority = priority.min(0);
        }
        if self.faultmask {
            priority = priority.min(-1);
        }
        priority
    }

    /// Whether an `SVC` now cannot be taken: SVCall's group priority does
    /// not preempt the execution priority. That is so in SVCall's own
    /// handler, in a handler at its priority or higher, and under
    /// `PRIMASK`, `FAULTMASK` or a `BASEPRI` at its priority or higher.
    pub(crate) fn supervisor_call_masked(&self) -> bool {
        self.group_priority(self.exception_priority(SVCALL)) >= self.execution_priority(false)
    }

    /// The pending exception the NVIC would take next, with its group
    /// priority: the highest priority, then the lowest number.
    fn next_pending(&self) -> Option<(u32, i32)> {
        let nvic = self.irq.as_ref()?;
        if !nvic.any_pending() {
            return None;
        }
        nvic.pending_exceptions()
            .map(|number| {
                let priority = self.exception_priority(number);
                (self.group_priority(priority), priority, number)
            })
            .min()
            .map(|(group, _, number)| (number, group))
    }

    /// The interrupts the schedule can raise now, lowest number first:
    /// SysTick when its counter and its interrupt are on, then the enabled
    /// external interrupts.
    fn schedule_candidates(&self) -> Vec<u32> {
        let Some(nvic) = self.irq.as_ref() else {
            return Vec::new();
        };
        let systick = self.ppb_word(SYST_CSR) & 3 == 3;
        systick
            .then_some(SYSTICK)
            .into_iter()
            .chain(nvic.enabled_irqs())
            .collect()
    }

    /// A tick of the schedule: pend the interrupt the next input byte picks
    /// and set the wait to the next tick. Returns whether it pended one.
    fn tick(&mut self) -> bool {
        let candidates = self.schedule_candidates();
        let instructions = self.instructions;
        if candidates.is_empty() {
            if let Some(nvic) = self.irq.as_mut() {
                nvic.next_tick = instructions.saturating_add(nvic.interval);
            }
            return false;
        }
        let byte = self.mmio.take_byte();
        let Some(nvic) = self.irq.as_mut() else {
            return false;
        };
        let Some(byte) = byte else {
            // The input has no byte left for the schedule: no more ticks.
            nvic.next_tick = u64::MAX;
            return false;
        };
        nvic.schedule_bytes += 1;
        nvic.set_pending(candidates[usize::from(byte) % candidates.len()]);
        nvic.next_tick = instructions.saturating_add(schedule_wait(nvic.interval, byte));
        true
    }

    /// Between two instructions: tick when a tick is due, and take the
    /// pending interrupt that can preempt, if any. Returns whether it took
    /// one, in which case the core is at the handler's first instruction.
    pub(crate) fn service_interrupts(&mut self) -> Result<bool, crate::cpu::Trap> {
        let Some(nvic) = self.irq.as_ref() else {
            return Ok(false);
        };
        if self.instructions >= nvic.next_tick {
            self.tick();
        }
        match self.next_pending() {
            Some((number, group)) if group < self.execution_priority(false) => {
                self.interrupt(number)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Whether the core, waiting, is woken: an interrupt that can preempt
    /// is pending, or the schedule, run on to its next ticks, raises one.
    /// With nothing enabled that could preempt it stays asleep, and so it
    /// does when the input runs out first.
    pub(crate) fn wakes(&mut self, wfi: bool) -> bool {
        if self.irq.is_none() {
            return false;
        }
        let limit = self.execution_priority(wfi);
        loop {
            if self.next_pending().is_some_and(|(_, group)| group < limit) {
                return true;
            }
            let could_wake = self
                .schedule_candidates()
                .into_iter()
                .any(|number| self.group_priority(self.exception_priority(number)) < limit);
            if !could_wake || !self.tick() {
                return false;
            }
        }
    }

    /// Take the asynchronous exception `number` between two instructions:
    /// stack the frame with the interrupted instruction as the return
    /// address and go to its handler.
    fn interrupt(&mut self, number: u32) -> Step {
        let pc = self.pc;
        let context = self.edges.previous();
        if let Some(nvic) = self.irq.as_mut() {
            nvic.clear_pending(number);
        }
        self.take_exception(number, pc)?;
        let instructions = self.instructions;
        if let Some(nvic) = self.irq.as_mut() {
            nvic.contexts.push(context);
            nvic.taken += 1;
            if nvic.log.len() < INTERRUPT_LOG_LIMIT {
                nvic.log.push(InterruptEvent {
                    instructions,
                    exception: number,
                    pc,
                });
            }
        }
        // No instruction branched to the handler.
        self.last_pc = None;
        self.pc = self.next_pc;
        self.block_end = false;
        self.blocks += 1;
        self.edges.enter_handler(number, self.pc);
        Ok(())
    }

    /// After an exception return from `number`: for an interrupt, go back to
    /// the edge context it interrupted and count no edge for the return.
    pub(crate) fn returned_from(&mut self, number: u32) {
        if number == SVCALL {
            return;
        }
        if let Some(context) = self.irq.as_mut().and_then(|nvic| nvic.contexts.pop()) {
            self.edges.resume(context);
            self.block_end = false;
        }
    }

    /// `ICSR` as read: the active and pending exceptions and the PendSV and
    /// SysTick pending bits.
    pub(crate) fn icsr(&self) -> u32 {
        let mut value = self.ipsr & 0x1ff;
        if self.ipsr != 0 && self.active.len() == 1 {
            value |= ICSR_RETTOBASE;
        }
        if let Some((number, _)) = self.next_pending() {
            value |= (number & 0x1ff) << 12;
        }
        if let Some(nvic) = self.irq.as_ref() {
            if nvic.pending.iter().any(|&word| word != 0) {
                value |= ICSR_ISRPENDING;
            }
            if nvic.systick {
                value |= ICSR_PENDSTSET;
            }
            if nvic.pendsv {
                value |= ICSR_PENDSVSET;
            }
        }
        value
    }

    /// A write to `ICSR`: set or clear PendSV's and SysTick's pending bits.
    pub(crate) fn write_icsr(&mut self, bits: u32) {
        let Some(nvic) = self.irq.as_mut() else {
            return;
        };
        if bits & ICSR_PENDSVSET != 0 {
            nvic.pendsv = true;
        } else if bits & ICSR_PENDSVCLR != 0 {
            nvic.pendsv = false;
        }
        if bits & ICSR_PENDSTSET != 0 {
            nvic.systick = true;
        } else if bits & ICSR_PENDSTCLR != 0 {
            nvic.systick = false;
        }
    }

    /// A write to `AIRCR` with its key: the priority grouping.
    pub(crate) fn write_prigroup(&mut self, value: u32) {
        if let Some(nvic) = self.irq.as_mut() {
            nvic.prigroup = (value >> 8) & 7;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ticks_byte_picks_the_wait_with_its_top_bits() {
        let waits: Vec<u64> = (0..8u8).map(|top| schedule_wait(1000, top << 5)).collect();
        assert_eq!(waits, [1000, 500, 250, 1, 4000, 8000, 16000, 2000]);
        // The low bits are the interrupt's, not the wait's.
        assert_eq!(schedule_wait(1000, 0x1f), 1000);
        // Never zero, whatever the interval.
        assert_eq!(schedule_wait(1, 0x40), 1);
        assert_eq!(schedule_wait(0, 0), 1);
    }

    #[test]
    fn enable_and_pending_registers_set_and_clear_their_bits() {
        let mut nvic = Nvic::new(InterruptConfig::default());
        assert!(nvic.write(NVIC_ISER + 4, 1 << 5, u32::MAX));
        assert!(nvic.write(NVIC_ISER, 1 << 3, u32::MAX));
        assert_eq!(nvic.read(NVIC_ISER + 4, &[]), Some(1 << 5));
        assert_eq!(
            nvic.read(NVIC_ICER + 4, &[]),
            Some(1 << 5),
            "ICER reads too"
        );
        assert_eq!(nvic.enabled_irqs().collect::<Vec<_>>(), [19, 53]);
        // Writing zeros changes nothing; ICER clears only its ones.
        assert!(nvic.write(NVIC_ISER, 0, u32::MAX));
        assert!(nvic.write(NVIC_ICER, 1 << 3, u32::MAX));
        assert_eq!(nvic.enabled_irqs().collect::<Vec<_>>(), [53]);
        // A pending interrupt the firmware has not enabled is not taken.
        assert!(nvic.write(NVIC_ISPR, 1 << 1, u32::MAX));
        assert_eq!(nvic.pending_exceptions().count(), 0);
        assert!(nvic.any_pending());
        assert!(nvic.write(NVIC_ICPR, 1 << 1, u32::MAX));
        assert!(!nvic.any_pending());
        // Bits past IRQ 239 do not exist.
        assert!(nvic.write(NVIC_ISER + 28, u32::MAX, u32::MAX));
        assert_eq!(nvic.read(NVIC_ISER + 28, &[]), Some(0xffff));
        assert!(
            !nvic.write(0xe000_ed08, 1, u32::MAX),
            "VTOR is not the NVIC's"
        );
    }

    #[test]
    fn priority_bytes_are_written_under_the_access_mask() {
        let mut nvic = Nvic::new(InterruptConfig::default());
        // A byte store of 0x50 to IPR[37].
        assert!(nvic.write(NVIC_IPR + 36, 0x50 << 8, 0xff << 8));
        assert_eq!(nvic.priority[37], 0x50);
        assert_eq!(nvic.read(NVIC_IPR + 36, &[]), Some(0x50 << 8));
        assert!(nvic.write(NVIC_IPR + 36, 0x1020_3040, u32::MAX));
        assert_eq!(nvic.priority[36..40], [0x40, 0x30, 0x20, 0x10]);
    }

    #[test]
    fn the_active_bits_read_from_the_exceptions_being_handled() {
        let nvic = Nvic::new(InterruptConfig::default());
        assert_eq!(nvic.read(NVIC_IABR + 4, &[53, 15]), Some(1 << 5));
        assert_eq!(nvic.read(NVIC_IABR, &[17]), Some(1 << 1));
    }
}
