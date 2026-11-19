// SPDX-License-Identifier: Apache-2.0

//! The ARMv7-M core: registers, the private peripheral bus, exceptions, and
//! the fetch-decode-execute step. The 16-bit and 32-bit Thumb encodings are
//! executed in `thumb16.rs` and `thumb32.rs`.
//!
//! What is modelled: the integer Thumb-2 instruction set of a Cortex-M3/M4
//! (with the M4's halfword multiplies and saturation, without its SIMD and
//! floating-point instructions), the banked stack pointers, the IT state,
//! `SVC` exception entry and return, the System Control Block registers a
//! start-up file writes (`VTOR`, `CCR`, `CPACR`, `AIRCR`), semihosting
//! output and exit, and peripheral reads through the MMIO models
//! (`mmio.rs`). Interrupts, the MPU and privilege checks are not.

use crate::coverage::EdgeMap;
use crate::fault::{Fault, FaultKind};
use crate::memory::{Memory, Miss};
use crate::mmio::Mmio;
use crate::IdleReason;
use std::collections::HashMap;

pub(crate) const PERIPHERAL_BASE: u32 = 0x4000_0000;
pub(crate) const PERIPHERAL_END: u32 = 0x6000_0000;
pub(crate) const PPB_BASE: u32 = 0xe000_0000;
pub(crate) const PPB_END: u32 = 0xe010_0000;

const CPUID: u32 = 0xe000_ed00;
const ICSR: u32 = 0xe000_ed04;
const VTOR: u32 = 0xe000_ed08;
const AIRCR: u32 = 0xe000_ed0c;
const CCR: u32 = 0xe000_ed14;
const SHPR2: u32 = 0xe000_ed1c;
const CPACR: u32 = 0xe000_ed88;
const DWT_CYCCNT: u32 = 0xe000_1004;
/// Cortex-M4 r0p1.
const CPUID_VALUE: u32 = 0x410f_c241;
const CCR_RESET: u32 = 1 << 9;
const CCR_UNALIGN_TRP: u32 = 1 << 3;
const CCR_DIV_0_TRP: u32 = 1 << 4;
const CCR_STKALIGN: u32 = 1 << 9;
const SVCALL: u32 = 11;
const SEMIHOSTING_BKPT: u32 = 0xab;
/// Most semihosting output kept from one run.
const MAX_OUTPUT: usize = 64 * 1024;

/// Why a step did not complete normally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Trap {
    Fault(Fault),
    Unsupported {
        pc: u32,
        encoding: u32,
        what: &'static str,
    },
    Idle {
        pc: u32,
        reason: IdleReason,
    },
    SemihostingExit {
        code: u32,
    },
    SystemReset {
        pc: u32,
    },
    /// A peripheral read wanted more input than the run had left.
    InputExhausted {
        pc: u32,
        address: u32,
    },
}

pub(crate) type Step = Result<(), Trap>;

/// What [`Core::save`] keeps.
pub(crate) struct Saved {
    r: [u32; 16],
    pc: u32,
    next_pc: u32,
    /// N, Z, C, V, Q and `EPSR.T`.
    flags: [bool; 6],
    it: u8,
    ipsr: u32,
    primask: bool,
    faultmask: bool,
    basepri: u32,
    control: u32,
    other_sp: u32,
    active: Vec<u32>,
    event: bool,
    monitor: bool,
    ppb: HashMap<u32, u32>,
    vtor: u32,
    ccr: u32,
    cpacr: u32,
    block_end: bool,
    direct_branch: bool,
    pending_exception: Option<u32>,
    pending_return: Option<u32>,
    last_pc: Option<u32>,
    instructions: u64,
    blocks: u64,
    /// Bytes of semihosting output written.
    output: usize,
}

/// Whether the architecture lets code run from `address`: the Code, SRAM
/// and external RAM regions do; peripheral, device and system space never.
#[inline]
pub(crate) fn executable_region(address: u32) -> bool {
    address < PERIPHERAL_BASE || (0x6000_0000..0xa000_0000).contains(&address)
}

pub(crate) struct Core {
    /// `r0`-`r14`; `r[13]` is the stack pointer in use. `r[15]` is unused:
    /// the program counter is `pc`.
    pub(crate) r: [u32; 16],
    /// The address of the instruction being executed.
    pub(crate) pc: u32,
    pub(crate) next_pc: u32,
    pub(crate) n: bool,
    pub(crate) z: bool,
    pub(crate) c: bool,
    pub(crate) v: bool,
    pub(crate) q: bool,
    /// `EPSR.T`: clear means the next instruction faults (INVSTATE).
    pub(crate) thumb: bool,
    /// `ITSTATE`.
    pub(crate) it: u8,
    pub(crate) ipsr: u32,
    pub(crate) primask: bool,
    pub(crate) faultmask: bool,
    pub(crate) basepri: u32,
    /// `CONTROL`: bit 0 nPRIV, bit 1 SPSEL.
    pub(crate) control: u32,
    /// The stack pointer not in use.
    other_sp: u32,
    /// Exceptions being handled, outermost first.
    active: Vec<u32>,
    event: bool,
    monitor: bool,
    pub(crate) mem: Memory,
    /// What peripheral registers read as.
    pub(crate) mmio: Mmio,
    /// Words the private peripheral bus holds, other than the cached ones.
    ppb: HashMap<u32, u32>,
    vtor_reset: u32,
    pub(crate) vtor: u32,
    pub(crate) ccr: u32,
    pub(crate) cpacr: u32,
    pub(crate) edges: EdgeMap,
    pub(crate) block_end: bool,
    /// The instruction was a direct branch, so a branch to itself is a loop
    /// nothing can leave.
    pub(crate) direct_branch: bool,
    pub(crate) pending_exception: Option<u32>,
    pub(crate) pending_return: Option<u32>,
    pub(crate) last_pc: Option<u32>,
    pub(crate) instructions: u64,
    pub(crate) blocks: u64,
    pub(crate) output: Vec<u8>,
}

impl Core {
    pub(crate) fn new(mem: Memory, mmio: Mmio, vtor: u32) -> Self {
        Self {
            r: [0; 16],
            pc: 0,
            next_pc: 0,
            n: false,
            z: false,
            c: false,
            v: false,
            q: false,
            thumb: true,
            it: 0,
            ipsr: 0,
            primask: false,
            faultmask: false,
            basepri: 0,
            control: 0,
            other_sp: 0,
            active: Vec::new(),
            event: false,
            monitor: false,
            mem,
            mmio,
            ppb: HashMap::new(),
            vtor_reset: vtor,
            vtor,
            ccr: CCR_RESET,
            cpacr: 0,
            edges: EdgeMap::new(),
            block_end: false,
            direct_branch: false,
            pending_exception: None,
            pending_return: None,
            last_pc: None,
            instructions: 0,
            blocks: 0,
            output: Vec::new(),
        }
    }

    /// The state a reset leaves: memory as loaded, `sp` and `pc` from the
    /// vector table, everything else zero.
    pub(crate) fn reset(&mut self, sp: u32, reset_vector: u32) {
        self.mem.reset();
        self.r = [0; 16];
        self.r[13] = sp & !3;
        self.r[14] = 0xffff_ffff;
        self.pc = reset_vector & !1;
        self.next_pc = self.pc;
        self.thumb = reset_vector & 1 != 0;
        (self.n, self.z, self.c, self.v, self.q) = (false, false, false, false, false);
        self.it = 0;
        self.ipsr = 0;
        self.primask = false;
        self.faultmask = false;
        self.basepri = 0;
        self.control = 0;
        self.other_sp = 0;
        self.active.clear();
        self.event = false;
        self.monitor = false;
        self.ppb.clear();
        self.vtor = self.vtor_reset;
        self.ccr = CCR_RESET;
        self.cpacr = 0;
        self.edges.clear();
        self.edges.enter(self.pc);
        self.block_end = false;
        self.direct_branch = false;
        self.pending_exception = None;
        self.pending_return = None;
        self.last_pc = None;
        self.instructions = 0;
        self.blocks = 1;
        self.output.clear();
    }

    /// The core's state between two instructions, to go back to with
    /// [`Core::restore`]. Memory and the peripheral reads keep their own
    /// marks; the edge map is left out, since nothing a run does depends on
    /// it.
    pub(crate) fn save(&self) -> Saved {
        // Every field is named, so a field added to the core has to be
        // saved or left out here on purpose.
        let Self {
            r,
            pc,
            next_pc,
            n,
            z,
            c,
            v,
            q,
            thumb,
            it,
            ipsr,
            primask,
            faultmask,
            basepri,
            control,
            other_sp,
            active,
            event,
            monitor,
            mem: _,
            mmio: _,
            ppb,
            vtor_reset: _,
            vtor,
            ccr,
            cpacr,
            edges: _,
            block_end,
            direct_branch,
            pending_exception,
            pending_return,
            last_pc,
            instructions,
            blocks,
            output,
        } = self;
        Saved {
            r: *r,
            pc: *pc,
            next_pc: *next_pc,
            flags: [*n, *z, *c, *v, *q, *thumb],
            it: *it,
            ipsr: *ipsr,
            primask: *primask,
            faultmask: *faultmask,
            basepri: *basepri,
            control: *control,
            other_sp: *other_sp,
            active: active.clone(),
            event: *event,
            monitor: *monitor,
            ppb: ppb.clone(),
            vtor: *vtor,
            ccr: *ccr,
            cpacr: *cpacr,
            block_end: *block_end,
            direct_branch: *direct_branch,
            pending_exception: *pending_exception,
            pending_return: *pending_return,
            last_pc: *last_pc,
            instructions: *instructions,
            blocks: *blocks,
            output: output.len(),
        }
    }

    /// Go back to the state `saved` holds.
    pub(crate) fn restore(&mut self, saved: &Saved) {
        self.r = saved.r;
        self.pc = saved.pc;
        self.next_pc = saved.next_pc;
        [self.n, self.z, self.c, self.v, self.q, self.thumb] = saved.flags;
        self.it = saved.it;
        self.ipsr = saved.ipsr;
        self.primask = saved.primask;
        self.faultmask = saved.faultmask;
        self.basepri = saved.basepri;
        self.control = saved.control;
        self.other_sp = saved.other_sp;
        self.active.clone_from(&saved.active);
        self.event = saved.event;
        self.monitor = saved.monitor;
        self.ppb.clone_from(&saved.ppb);
        self.vtor = saved.vtor;
        self.ccr = saved.ccr;
        self.cpacr = saved.cpacr;
        self.block_end = saved.block_end;
        self.direct_branch = saved.direct_branch;
        self.pending_exception = saved.pending_exception;
        self.pending_return = saved.pending_return;
        self.last_pc = saved.last_pc;
        self.instructions = saved.instructions;
        self.blocks = saved.blocks;
        self.output.truncate(saved.output);
    }

    // ---- registers and flags ----------------------------------------------

    /// Register `n` as an operand: `r15` reads as the instruction's address
    /// plus 4.
    #[inline]
    pub(crate) fn reg(&self, n: u32) -> u32 {
        if n == 15 {
            self.pc.wrapping_add(4)
        } else {
            self.r[n as usize]
        }
    }

    /// Write register `n`; the stack pointer drops its low two bits, and a
    /// write to `r15` branches.
    #[inline]
    pub(crate) fn set_reg(&mut self, n: u32, value: u32) {
        match n {
            13 => self.r[13] = value & !3,
            15 => self.branch(value),
            _ => self.r[n as usize] = value,
        }
    }

    /// `Align(PC, 4)` for a literal load.
    #[inline]
    pub(crate) fn literal_base(&self) -> u32 {
        self.pc.wrapping_add(4) & !3
    }

    #[inline]
    pub(crate) fn set_nz(&mut self, value: u32) {
        self.n = value >> 31 != 0;
        self.z = value == 0;
    }

    #[inline]
    pub(crate) fn set_nzcv(&mut self, value: u32, carry: bool, overflow: bool) {
        self.set_nz(value);
        self.c = carry;
        self.v = overflow;
    }

    pub(crate) fn condition(&self, cond: u32) -> bool {
        match cond & 0xf {
            0 => self.z,
            1 => !self.z,
            2 => self.c,
            3 => !self.c,
            4 => self.n,
            5 => !self.n,
            6 => self.v,
            7 => !self.v,
            8 => self.c && !self.z,
            9 => !self.c || self.z,
            10 => self.n == self.v,
            11 => self.n != self.v,
            12 => !self.z && self.n == self.v,
            13 => self.z || self.n != self.v,
            _ => true,
        }
    }

    #[inline]
    pub(crate) fn in_it_block(&self) -> bool {
        self.it & 0xf != 0
    }

    fn advance_it(&mut self) {
        if self.it & 7 == 0 {
            self.it = 0;
        } else {
            self.it = (self.it & 0xe0) | ((self.it << 1) & 0x1f);
        }
    }

    pub(crate) fn xpsr(&self) -> u32 {
        (u32::from(self.n) << 31)
            | (u32::from(self.z) << 30)
            | (u32::from(self.c) << 29)
            | (u32::from(self.v) << 28)
            | (u32::from(self.q) << 27)
            | ((u32::from(self.it) & 3) << 25)
            | (u32::from(self.thumb) << 24)
            | ((u32::from(self.it) >> 2) << 10)
            | (self.ipsr & 0x1ff)
    }

    /// The flags `MRS APSR` reads.
    pub(crate) fn apsr(&self) -> u32 {
        self.xpsr() & 0xf800_0000
    }

    pub(crate) fn set_apsr(&mut self, value: u32) {
        self.n = value >> 31 & 1 != 0;
        self.z = value >> 30 & 1 != 0;
        self.c = value >> 29 & 1 != 0;
        self.v = value >> 28 & 1 != 0;
        self.q = value >> 27 & 1 != 0;
    }

    fn sp_is_psp(&self) -> bool {
        self.ipsr == 0 && self.control & 2 != 0
    }

    pub(crate) fn msp(&self) -> u32 {
        if self.sp_is_psp() {
            self.other_sp
        } else {
            self.r[13]
        }
    }

    pub(crate) fn psp(&self) -> u32 {
        if self.sp_is_psp() {
            self.r[13]
        } else {
            self.other_sp
        }
    }

    pub(crate) fn set_msp(&mut self, value: u32) {
        if self.sp_is_psp() {
            self.other_sp = value & !3;
        } else {
            self.r[13] = value & !3;
        }
    }

    pub(crate) fn set_psp(&mut self, value: u32) {
        if self.sp_is_psp() {
            self.r[13] = value & !3;
        } else {
            self.other_sp = value & !3;
        }
    }

    /// `MSR CONTROL`: SPSEL changes only in Thread mode.
    pub(crate) fn set_control(&mut self, value: u32) {
        let was_psp = self.sp_is_psp();
        if self.ipsr == 0 {
            self.control = value & 3;
        } else {
            self.control = (self.control & 2) | (value & 1);
        }
        if was_psp != self.sp_is_psp() {
            std::mem::swap(&mut self.r[13], &mut self.other_sp);
        }
    }

    // ---- branches -----------------------------------------------------------

    /// `BranchWritePC`: branch to `target` with its low bit dropped.
    #[inline]
    pub(crate) fn branch(&mut self, target: u32) {
        self.next_pc = target & !1;
        self.block_end = true;
    }

    /// `BXWritePC` / `LoadWritePC`: an interworking branch, or, in Handler
    /// mode to an `EXC_RETURN` value, an exception return when the
    /// instruction completes.
    pub(crate) fn branch_exchange(&mut self, target: u32) {
        if self.ipsr != 0 && target >> 28 == 0xf {
            self.pending_return = Some(target);
            self.block_end = true;
            return;
        }
        self.thumb = target & 1 != 0;
        self.branch(target);
    }

    /// `BLXWritePC`: an interworking branch that never returns from an
    /// exception.
    pub(crate) fn branch_link_exchange(&mut self, target: u32) {
        self.thumb = target & 1 != 0;
        self.branch(target);
    }

    // ---- faults ---------------------------------------------------------

    pub(crate) fn fault(&self, kind: FaultKind, address: Option<u32>) -> Trap {
        let mut registers = self.r;
        registers[15] = self.pc;
        Trap::Fault(Fault {
            kind,
            pc: self.pc,
            address,
            from: None,
            registers,
            xpsr: self.xpsr(),
        })
    }

    /// A fault on fetching from `address`, which the previous instruction
    /// branched to.
    fn fetch_fault(&self, kind: FaultKind, address: u32) -> Trap {
        let mut registers = self.r;
        registers[15] = address;
        Trap::Fault(Fault {
            kind,
            pc: address,
            address: Some(address),
            from: self.last_pc,
            registers,
            xpsr: self.xpsr(),
        })
    }

    pub(crate) fn unsupported(&self, encoding: u32, what: &'static str) -> Trap {
        Trap::Unsupported {
            pc: self.pc,
            encoding,
            what,
        }
    }

    pub(crate) fn undefined(&self) -> Trap {
        self.fault(FaultKind::Undefined, None)
    }

    // ---- memory ---------------------------------------------------------

    #[inline]
    fn fetch(&mut self, address: u32) -> Result<u16, Trap> {
        if executable_region(address) {
            if let Ok(value) = self.mem.read(address, 2) {
                return Ok(value as u16);
            }
        }
        Err(self.fetch_fault(FaultKind::FetchInvalid, address))
    }

    /// A load of `size` (1, 2 or 4) bytes that may be unaligned.
    #[inline]
    pub(crate) fn load(&mut self, address: u32, size: u32) -> Result<u32, Trap> {
        if size > 1 && address & (size - 1) != 0 && self.ccr & CCR_UNALIGN_TRP != 0 {
            return Err(self.fault(FaultKind::Unaligned, Some(address)));
        }
        match self.mem.read(address, size) {
            Ok(value) => Ok(value),
            Err(_) => self.load_outside_memory(address, size),
        }
    }

    /// A word load that must be word aligned (LDM, LDRD, LDREX, POP).
    #[inline]
    pub(crate) fn load_word_aligned(&mut self, address: u32) -> Result<u32, Trap> {
        if address & 3 != 0 {
            return Err(self.fault(FaultKind::Unaligned, Some(address)));
        }
        self.load(address, 4)
    }

    fn load_outside_memory(&mut self, address: u32, size: u32) -> Result<u32, Trap> {
        if (PPB_BASE..PPB_END).contains(&address) {
            return Ok(self.ppb_read(address, size));
        }
        if (PERIPHERAL_BASE..PERIPHERAL_END).contains(&address) {
            return self
                .mmio
                .read(address, self.pc, size, self.instructions)
                .map_err(|_| Trap::InputExhausted {
                    pc: self.pc,
                    address,
                });
        }
        if let Some((byte, bit)) = self.mem.bitband(address) {
            let value = self.mem.read(byte, 1).unwrap_or(0);
            return Ok((value >> bit) & 1);
        }
        Err(self.fault(FaultKind::ReadUnmapped, Some(address)))
    }

    /// A store of `size` (1, 2 or 4) bytes that may be unaligned.
    #[inline]
    pub(crate) fn store(&mut self, address: u32, size: u32, value: u32) -> Step {
        if size > 1 && address & (size - 1) != 0 && self.ccr & CCR_UNALIGN_TRP != 0 {
            return Err(self.fault(FaultKind::Unaligned, Some(address)));
        }
        match self.mem.write(address, size, value) {
            Ok(()) => {
                if self.mmio.tracing() {
                    self.mmio.note_store(address, size, value);
                }
                Ok(())
            }
            Err(Miss::ReadOnly) => Err(self.fault(FaultKind::WriteReadOnly, Some(address))),
            Err(Miss::Unmapped) => self.store_outside_memory(address, size, value),
        }
    }

    /// A word store that must be word aligned (STM, STRD, STREX, PUSH).
    #[inline]
    pub(crate) fn store_word_aligned(&mut self, address: u32, value: u32) -> Step {
        if address & 3 != 0 {
            return Err(self.fault(FaultKind::Unaligned, Some(address)));
        }
        self.store(address, 4, value)
    }

    fn store_outside_memory(&mut self, address: u32, size: u32, value: u32) -> Step {
        if (PPB_BASE..PPB_END).contains(&address) {
            return self.ppb_write(address, size, value);
        }
        if (PERIPHERAL_BASE..PERIPHERAL_END).contains(&address) {
            // Peripheral writes go nowhere.
            return Ok(());
        }
        if let Some((byte, bit)) = self.mem.bitband(address) {
            let old = self.mem.read(byte, 1).unwrap_or(0);
            let new = if value & 1 != 0 {
                old | (1 << bit)
            } else {
                old & !(1 << bit)
            };
            return match self.mem.write(byte, 1, new) {
                Ok(()) => {
                    if self.mmio.tracing() {
                        self.mmio.note_store(address, size, value);
                    }
                    Ok(())
                }
                Err(_) => Err(self.fault(FaultKind::WriteReadOnly, Some(address))),
            };
        }
        Err(self.fault(FaultKind::WriteUnmapped, Some(address)))
    }

    fn ppb_word(&self, word: u32) -> u32 {
        match word {
            CPUID => CPUID_VALUE,
            ICSR => self.ipsr & 0x1ff,
            VTOR => self.vtor,
            CCR => self.ccr,
            CPACR => self.cpacr,
            DWT_CYCCNT => self.instructions as u32,
            _ => self.ppb.get(&word).copied().unwrap_or(0),
        }
    }

    fn ppb_read(&self, address: u32, size: u32) -> u32 {
        let word = address & !3;
        let shift = 8 * (address & 3);
        let value = self.ppb_word(word) >> shift;
        match size {
            1 => value & 0xff,
            2 => value & 0xffff,
            _ => value,
        }
    }

    fn ppb_write(&mut self, address: u32, size: u32, value: u32) -> Step {
        let word = address & !3;
        let shift = 8 * (address & 3);
        let mask = match size {
            1 => 0xffu32,
            2 => 0xffff,
            _ => 0xffff_ffff,
        } << shift;
        let merged = (self.ppb_word(word) & !mask) | ((value << shift) & mask);
        match word {
            CPUID | ICSR => {}
            VTOR => self.vtor = merged & 0xffff_ff80,
            // STKALIGN is fixed at one on a Cortex-M4.
            CCR => self.ccr = merged | CCR_STKALIGN,
            CPACR => self.cpacr = merged,
            AIRCR => {
                if merged >> 16 == 0x05fa && merged & 4 != 0 {
                    return Err(Trap::SystemReset { pc: self.pc });
                }
            }
            _ => {
                self.ppb.insert(word, merged);
            }
        }
        Ok(())
    }

    // ---- exceptions -------------------------------------------------------

    /// `SVC`: taken when the instruction completes, unless the core is at a
    /// priority SVCall cannot preempt, which escalates to HardFault.
    pub(crate) fn supervisor_call(&mut self) -> Step {
        let svc_priority = self.ppb_word(SHPR2) >> 24;
        let masked = self.primask
            || self.faultmask
            || self.ipsr != 0
            || (self.basepri != 0 && svc_priority >= self.basepri);
        if masked {
            return Err(self.fault(FaultKind::Escalation, None));
        }
        self.pending_exception = Some(SVCALL);
        Ok(())
    }

    /// Exception entry: stack the frame, switch to Handler mode on the main
    /// stack, and branch to the vector.
    fn take_exception(&mut self, number: u32, return_address: u32) -> Step {
        let sp = self.r[13];
        let realign = self.ccr & CCR_STKALIGN != 0 && sp & 4 != 0;
        let frame = sp.wrapping_sub(0x20) & !(u32::from(realign) << 2);
        let xpsr = (self.xpsr() & !(1 << 9)) | (u32::from(realign) << 9);
        let words = [
            self.r[0],
            self.r[1],
            self.r[2],
            self.r[3],
            self.r[12],
            self.r[14],
            return_address,
            xpsr,
        ];
        for (index, word) in words.iter().enumerate() {
            self.store_word_aligned(frame.wrapping_add(4 * index as u32), *word)?;
        }
        let from_thread = self.ipsr == 0;
        let from_psp = self.sp_is_psp();
        self.r[13] = frame;
        self.r[14] = match (from_thread, from_psp) {
            (false, _) => 0xffff_fff1,
            (true, false) => 0xffff_fff9,
            (true, true) => 0xffff_fffd,
        };
        if from_psp {
            std::mem::swap(&mut self.r[13], &mut self.other_sp);
        }
        self.control &= !2;
        self.ipsr = number;
        self.active.push(number);
        self.it = 0;
        self.monitor = false;
        let vector = self.load(self.vtor.wrapping_add(4 * number), 4)?;
        self.thumb = vector & 1 != 0;
        self.branch(vector);
        Ok(())
    }

    /// Exception return to the state an `EXC_RETURN` value names.
    fn exception_return(&mut self, exc_return: u32) -> Step {
        if exc_return & 0x0fff_ffe0 != 0x0fff_ffe0 {
            return Err(self.fault(FaultKind::InvalidExceptionReturn, Some(exc_return)));
        }
        if exc_return & 0x10 == 0 {
            return Err(
                self.unsupported(exc_return, "exception return with a floating-point frame")
            );
        }
        let (to_thread, to_psp) = match exc_return & 0xf {
            0x1 => (false, false),
            0x9 => (true, false),
            0xd => (true, true),
            _ => return Err(self.fault(FaultKind::InvalidExceptionReturn, Some(exc_return))),
        };
        // Thread mode is returned to from the last active exception only.
        if to_thread != (self.active.len() == 1) {
            return Err(self.fault(FaultKind::InvalidExceptionReturn, Some(exc_return)));
        }
        // In Handler mode r13 is the main stack; other_sp the process stack.
        let frame = if to_psp { self.other_sp } else { self.r[13] };
        let mut words = [0u32; 8];
        for (index, word) in words.iter_mut().enumerate() {
            *word = self.load_word_aligned(frame.wrapping_add(4 * index as u32))?;
        }
        let xpsr = words[7];
        let after = frame
            .wrapping_add(0x20)
            .wrapping_add(((xpsr >> 9) & 1) << 2);
        self.active.pop();
        if to_psp {
            self.other_sp = after;
        } else {
            self.r[13] = after;
        }
        self.ipsr = if to_thread {
            0
        } else {
            self.active.last().copied().unwrap_or(0)
        };
        let was_psp = to_psp;
        self.control = (self.control & !2) | (u32::from(to_psp) << 1);
        if was_psp {
            std::mem::swap(&mut self.r[13], &mut self.other_sp);
        }
        self.r[0] = words[0];
        self.r[1] = words[1];
        self.r[2] = words[2];
        self.r[3] = words[3];
        self.r[12] = words[4];
        self.r[14] = words[5];
        self.set_apsr(xpsr);
        self.it = (((xpsr >> 25) & 3) | (((xpsr >> 10) & 0x3f) << 2)) as u8;
        self.thumb = (xpsr >> 24) & 1 != 0;
        self.monitor = false;
        self.next_pc = words[6] & !1;
        self.block_end = true;
        Ok(())
    }

    // ---- miscellaneous instructions ----------------------------------------

    pub(crate) fn wait_for_interrupt(&self) -> Step {
        Err(Trap::Idle {
            pc: self.pc,
            reason: IdleReason::WaitForInterrupt,
        })
    }

    pub(crate) fn wait_for_event(&mut self) -> Step {
        if std::mem::take(&mut self.event) {
            return Ok(());
        }
        Err(Trap::Idle {
            pc: self.pc,
            reason: IdleReason::WaitForEvent,
        })
    }

    pub(crate) fn send_event(&mut self) {
        self.event = true;
    }

    pub(crate) fn set_monitor(&mut self, open: bool) {
        self.monitor = open;
    }

    /// Whether the exclusive monitor is open, closing it.
    pub(crate) fn take_monitor(&mut self) -> bool {
        std::mem::take(&mut self.monitor)
    }

    pub(crate) fn divide_by_zero(&self) -> Result<u32, Trap> {
        if self.ccr & CCR_DIV_0_TRP != 0 {
            Err(self.fault(FaultKind::DivideByZero, None))
        } else {
            Ok(0)
        }
    }

    /// A coprocessor instruction (both halfwords in `encoding`): floating
    /// point (coprocessors 10 and 11) with access enabled in `CPACR` is not
    /// implemented; any other faults.
    pub(crate) fn coprocessor(&self, encoding: u32) -> Step {
        let coprocessor = (encoding >> 8) & 0xf;
        let enabled = match coprocessor {
            10 => (self.cpacr >> 20) & 3 != 0,
            11 => (self.cpacr >> 22) & 3 != 0,
            _ => false,
        };
        if enabled {
            Err(self.unsupported(encoding, "floating-point instruction"))
        } else {
            Err(self.fault(FaultKind::NoCoprocessor, None))
        }
    }

    /// `BKPT`: semihosting (`BKPT 0xAB`), or a HardFault with no debugger.
    pub(crate) fn breakpoint(&mut self, imm8: u32) -> Step {
        if imm8 != SEMIHOSTING_BKPT {
            return Err(self.fault(FaultKind::Breakpoint, None));
        }
        let operation = self.r[0];
        let argument = self.r[1];
        let result = match operation {
            // SYS_WRITEC: the character at r1.
            0x03 => {
                let byte = self.load(argument, 1)?;
                self.emit(&[byte as u8]);
                0
            }
            // SYS_WRITE0: the NUL-terminated string at r1. Writes stop
            // reading once the output is full, so a run's semihosting work
            // is bounded by it.
            0x04 => {
                let mut address = argument;
                while self.output.len() < MAX_OUTPUT {
                    let byte = self.load(address, 1)? as u8;
                    if byte == 0 {
                        break;
                    }
                    self.emit(&[byte]);
                    address = address.wrapping_add(1);
                }
                0
            }
            // SYS_WRITE: [handle, buffer, length]; returns bytes not written.
            0x05 => {
                let buffer = self.load(argument.wrapping_add(4), 4)?;
                let length = self.load(argument.wrapping_add(8), 4)?;
                let room = MAX_OUTPUT.saturating_sub(self.output.len());
                for index in 0..length.min(room as u32) {
                    let byte = self.load(buffer.wrapping_add(index), 1)? as u8;
                    self.emit(&[byte]);
                }
                0
            }
            // SYS_EXIT: r1 is the reason; ADP_Stopped_ApplicationExit is
            // success.
            0x18 => {
                return Err(Trap::SemihostingExit {
                    code: u32::from(argument != 0x2_0026),
                })
            }
            // SYS_EXIT_EXTENDED: [reason, exit code].
            0x20 => {
                let reason = self.load(argument, 4)?;
                let code = self.load(argument.wrapping_add(4), 4)?;
                return Err(Trap::SemihostingExit {
                    code: if reason == 0x2_0026 { code } else { 1 },
                });
            }
            _ => u32::MAX,
        };
        self.r[0] = result;
        Ok(())
    }

    fn emit(&mut self, bytes: &[u8]) {
        let room = MAX_OUTPUT.saturating_sub(self.output.len());
        self.output
            .extend_from_slice(&bytes[..bytes.len().min(room)]);
    }

    // ---- the step -----------------------------------------------------------

    /// Execute one instruction.
    pub(crate) fn step(&mut self) -> Step {
        let pc = self.pc;
        if !self.thumb {
            return Err(self.fetch_fault(FaultKind::InvalidState, pc));
        }
        let first = u32::from(self.fetch(pc)?);
        let wide = first >> 11 >= 0b11101;
        let second = if wide {
            u32::from(self.fetch(pc.wrapping_add(2))?)
        } else {
            0
        };
        self.next_pc = pc.wrapping_add(if wide { 4 } else { 2 });
        self.direct_branch = false;
        let in_it = self.in_it_block();
        let last_in_it = in_it && self.it & 0xf == 0x8;
        if !in_it || self.condition(u32::from(self.it >> 4)) {
            if wide {
                self.exec32(first, second)?;
            } else {
                self.exec16(first)?;
            }
        }
        if in_it {
            self.advance_it();
            if last_in_it {
                self.block_end = true;
            }
        }
        if let Some(exc_return) = self.pending_return.take() {
            self.exception_return(exc_return)?;
        }
        if let Some(number) = self.pending_exception.take() {
            self.take_exception(number, self.next_pc)?;
        }
        if self.direct_branch && self.next_pc == pc {
            return Err(Trap::Idle {
                pc,
                reason: IdleReason::BranchToSelf,
            });
        }
        self.last_pc = Some(pc);
        self.pc = self.next_pc;
        self.instructions += 1;
        if self.block_end {
            self.block_end = false;
            self.blocks += 1;
            self.edges.enter(self.pc);
        }
        Ok(())
    }
}
