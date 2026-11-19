// SPDX-License-Identifier: Apache-2.0

//! A machine: an image mapped into memory with its RAM, reset and run one
//! input at a time.

use crate::coverage::EdgeMap;
use crate::cpu::{executable_region, Core, Saved, Trap, PERIPHERAL_BASE, PERIPHERAL_END};
use crate::fault::Fault;
use crate::image::Image;
use crate::memory::{Checkpoint, Memory};
use crate::mmio::{Mmio, MmioAccess, MmioConfig, MmioMark, MmioModelKind, Probe};
use std::collections::HashSet;
use thiserror::Error;

/// Where the RAM of most Cortex-M parts starts.
pub const DEFAULT_RAM_BASE: u32 = 0x2000_0000;
/// The RAM mapped when none is named: 1 MiB from [`DEFAULT_RAM_BASE`].
pub const DEFAULT_RAM_SIZE: u32 = 0x0010_0000;
/// The instruction budget of one run when none is named.
pub const DEFAULT_MAX_INSTRUCTIONS: u64 = 1_000_000;

/// A range of RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRange {
    pub base: u32,
    pub size: u32,
}

impl MemoryRange {
    /// 1 MiB at `0x20000000`, the start of the Cortex-M SRAM region.
    pub fn default_ram() -> Self {
        Self {
            base: DEFAULT_RAM_BASE,
            size: DEFAULT_RAM_SIZE,
        }
    }
}

/// How a run's input reaches the firmware: written into a fixed buffer, as
/// a receive routine would leave it. Peripheral reads that take input (see
/// [`MmioConfig`]) take the bytes after the buffer's `capacity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputBuffer {
    /// Where the input is written.
    pub address: u32,
    /// The bytes the buffer holds; a longer input is cut to this.
    pub capacity: u32,
    /// Where the input's length is written, as a little-endian `u32`.
    pub length_word: Option<u32>,
    /// Write the input when the core first reaches this address (after the
    /// start-up code has cleared `.bss`, say); `None` writes it at reset.
    pub inject_at: Option<u32>,
}

/// How to map and run an image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineConfig {
    /// RAM beside the image; the ranges the image's own `.data` and `.bss`
    /// segments name are mapped as well.
    pub ram: Vec<MemoryRange>,
    /// Where the vector table is; `None` uses the image's.
    pub vector_table: Option<u32>,
    pub input: Option<InputBuffer>,
    /// Addresses at which a run ends cleanly.
    pub exit_at: Vec<u32>,
    /// The most instructions one run executes.
    pub max_instructions: u64,
    /// What peripheral registers read as.
    pub mmio: MmioConfig,
}

impl Default for MachineConfig {
    fn default() -> Self {
        Self {
            ram: vec![MemoryRange::default_ram()],
            vector_table: None,
            input: None,
            exit_at: Vec::new(),
            max_instructions: DEFAULT_MAX_INSTRUCTIONS,
            mmio: MmioConfig::default(),
        }
    }
}

/// Why a machine could not be set up for an image.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SetupError {
    #[error("RAM at {base:#010x} has no bytes")]
    EmptyRam { base: u32 },
    #[error("RAM at {base:#010x} of {size:#x} bytes runs past the end of the address space")]
    RamOverflow { base: u32, size: u32 },
    #[error("RAM at {ram:#010x} overlaps part of the image segment at {segment:#010x}")]
    RamOverlapsImage { ram: u32, segment: u32 },
    #[error("the image and its RAM need {bytes} bytes, more than the 1 GiB allowed")]
    TooMuchMemory { bytes: u64 },
    #[error(
        "no vector table at {address:#010x}: the image holds nothing there (is the raw image's base address right?)"
    )]
    NoVectorTable { address: u32 },
    #[error(
        "the reset vector {vector:#010x} does not point at Thumb code in the image (is the base address or the vector table right?)"
    )]
    BadResetVector { vector: u32 },
    #[error(
        "the initial stack pointer {sp:#010x} is not in RAM: name the RAM it is in with a RAM range"
    )]
    StackOutsideRam { sp: u32 },
    #[error("the input buffer at {address:#010x} of {capacity} bytes is not inside the image or its RAM")]
    InputOutsideMemory { address: u32, capacity: u32 },
    #[error("the input buffer has no room: its capacity is zero")]
    EmptyInputBuffer,
    #[error("the input length word at {address:#010x} is not inside the image or its RAM")]
    LengthOutsideMemory { address: u32 },
    #[error("{what} {address:#010x} is not an address the image holds code at")]
    NotCode { what: &'static str, address: u32 },
    #[error("the instruction budget is zero")]
    NoBudget,
    #[error(
        "the MMIO model for {address:#010x} is outside the peripheral window 0x40000000-0x5fffffff"
    )]
    MmioOutsidePeripherals { address: u32 },
    #[error(
        "the MMIO model for {address:#010x} would never be used: RAM or an image segment holds that \
         address, and memory answers its reads"
    )]
    MmioInMemory { address: u32 },
    #[error("two MMIO models for the register at {address:#010x} {}", read_by(*.pc))]
    DuplicateMmioModel { address: u32, pc: Option<u32> },
    #[error("the bit-extract model for {address:#010x} has no bits in its mask")]
    EmptyBitMask { address: u32 },
}

fn read_by(pc: Option<u32>) -> String {
    match pc {
        Some(pc) => format!("read at pc {pc:#010x}"),
        None => "read by any instruction".to_owned(),
    }
}

/// Why the core went idle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleReason {
    /// `WFI`, with no interrupt modelled to wake it.
    WaitForInterrupt,
    /// `WFE` with no event pending.
    WaitForEvent,
    /// A branch to itself.
    BranchToSelf,
}

impl IdleReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WaitForInterrupt => "wfi",
            Self::WaitForEvent => "wfe",
            Self::BranchToSelf => "branch_to_self",
        }
    }
}

/// How a run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// The core reached an exit address.
    Exit { address: u32 },
    /// The core went idle with nothing to wake it.
    Idle { pc: u32, reason: IdleReason },
    /// The firmware called semihosting `SYS_EXIT`.
    SemihostingExit { code: u32 },
    /// The firmware requested a system reset (`AIRCR.SYSRESETREQ`).
    SystemReset { pc: u32 },
    /// The run used its instruction budget.
    InstructionLimit,
    /// The core met an instruction this emulator does not implement: a limit
    /// of the emulator, not a fault of the firmware.
    Unsupported {
        pc: u32,
        encoding: u32,
        what: &'static str,
    },
    /// A peripheral read wanted more input than the run had left: the
    /// firmware asked for more than the testcase holds.
    InputExhausted { pc: u32, address: u32 },
    /// The firmware faulted.
    Fault(Fault),
}

impl Stop {
    /// A stable name for how the run ended.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Exit { .. } => "exit",
            Self::Idle { .. } => "idle",
            Self::SemihostingExit { .. } => "semihosting_exit",
            Self::SystemReset { .. } => "system_reset",
            Self::InstructionLimit => "instruction_limit",
            Self::Unsupported { .. } => "unsupported",
            Self::InputExhausted { .. } => "input_exhausted",
            Self::Fault(_) => "fault",
        }
    }
}

/// One run of an input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Execution {
    pub stop: Stop,
    /// Instructions the run executed.
    pub instructions: u64,
    /// Basic blocks the run entered.
    pub blocks: u64,
    /// Bytes of the input written into the buffer, or `None` when the run
    /// never reached the address that writes it or there is no buffer.
    pub input_delivered: Option<usize>,
    /// Peripheral registers the run read.
    pub mmio_reads: u64,
    /// Bytes of the input its peripheral reads took.
    pub mmio_input: usize,
    /// What the firmware wrote through semihosting.
    pub output: Vec<u8>,
}

/// An image mapped and ready to run.
pub struct Machine {
    pub(crate) core: Core,
    initial_sp: u32,
    reset_vector: u32,
    input: Option<InputBuffer>,
    exit_at: Vec<u32>,
    max_instructions: u64,
    /// The input buffer the run going on has still to write at its
    /// injection address.
    pending: Option<InputBuffer>,
    /// Bytes of the input the run going on wrote into the buffer.
    delivered: Option<usize>,
}

/// A run paused just before one of its peripheral reads, to be run on from
/// there again and again with that read's value changed
/// ([`Machine::probe_from`]).
pub(crate) struct ProbePoint {
    address: u32,
    pc: u32,
    core: Saved,
    memory: Checkpoint,
    mmio: MmioMark,
    pending: Option<InputBuffer>,
    delivered: Option<usize>,
}

impl Machine {
    /// Map `image` and its RAM, and check that it can start: the vector table
    /// is in the image, the reset vector points at Thumb code, the stack is in
    /// RAM, the input buffer and the exit and injection addresses are in
    /// memory, and each MMIO model names a peripheral register that no RAM
    /// or image segment holds, at most once per site, read by code.
    pub fn new(image: &Image, config: MachineConfig) -> Result<Self, SetupError> {
        if config.max_instructions == 0 {
            return Err(SetupError::NoBudget);
        }
        let mut memory = Memory::new(image, &config.ram)?;
        let vector_table = config.vector_table.unwrap_or(image.vector_table());
        let initial_sp = memory
            .read(vector_table, 4)
            .map_err(|_| SetupError::NoVectorTable {
                address: vector_table,
            })?;
        let reset_vector = memory.read(vector_table.wrapping_add(4), 4).map_err(|_| {
            SetupError::NoVectorTable {
                address: vector_table,
            }
        })?;
        let reset_pc = reset_vector & !1;
        if reset_vector & 1 == 0 || !executable_region(reset_pc) || !memory.holds(reset_pc, 2) {
            return Err(SetupError::BadResetVector {
                vector: reset_vector,
            });
        }
        if initial_sp & !3 == 0 || !memory.is_writable(initial_sp.wrapping_sub(4) & !3, 4) {
            return Err(SetupError::StackOutsideRam { sp: initial_sp });
        }
        if let Some(input) = &config.input {
            if input.capacity == 0 {
                return Err(SetupError::EmptyInputBuffer);
            }
            if !memory.holds(input.address, input.capacity) {
                return Err(SetupError::InputOutsideMemory {
                    address: input.address,
                    capacity: input.capacity,
                });
            }
            if let Some(address) = input.length_word {
                if !memory.holds(address, 4) {
                    return Err(SetupError::LengthOutsideMemory { address });
                }
            }
            if let Some(address) = input.inject_at {
                check_code(&memory, "the input injection address", address)?;
            }
        }
        for &address in &config.exit_at {
            check_code(&memory, "the exit address", address)?;
        }
        let mut sites = HashSet::new();
        for model in &config.mmio.models {
            if !(PERIPHERAL_BASE..PERIPHERAL_END).contains(&model.address) {
                return Err(SetupError::MmioOutsidePeripherals {
                    address: model.address,
                });
            }
            if memory.holds(model.address, 1) {
                return Err(SetupError::MmioInMemory {
                    address: model.address,
                });
            }
            if let Some(pc) = model.pc {
                check_code(&memory, "an MMIO model's instruction address", pc)?;
            }
            if model.kind == (MmioModelKind::BitExtract { mask: 0 }) {
                return Err(SetupError::EmptyBitMask {
                    address: model.address,
                });
            }
            if !sites.insert((model.address, model.pc)) {
                return Err(SetupError::DuplicateMmioModel {
                    address: model.address,
                    pc: model.pc,
                });
            }
        }
        Ok(Self {
            core: Core::new(memory, Mmio::new(&config.mmio), vector_table),
            initial_sp,
            reset_vector,
            input: config.input,
            exit_at: config.exit_at,
            max_instructions: config.max_instructions,
            pending: None,
            delivered: None,
        })
    }

    /// The stack pointer the vector table starts the core with.
    pub fn initial_sp(&self) -> u32 {
        self.initial_sp
    }

    /// The reset vector, with its Thumb bit.
    pub fn reset_vector(&self) -> u32 {
        self.reset_vector
    }

    /// The edges the last run took.
    pub fn edge_map(&self) -> &EdgeMap {
        &self.core.edges
    }

    /// Record the first `limit` peripheral reads of each run from now on;
    /// zero stops recording.
    pub fn trace_mmio(&mut self, limit: usize) {
        self.core.mmio.set_trace_limit(limit);
    }

    /// The peripheral reads of the last run, as far as its trace holds them.
    pub fn mmio_trace(&self) -> &[MmioAccess] {
        &self.core.mmio.trace
    }

    /// `len` bytes of the image or its RAM at `address` as the last run left
    /// them, or `None` when memory does not hold them all.
    pub fn read_memory(&mut self, address: u32, len: u32) -> Option<Vec<u8>> {
        (0..len)
            .map(|offset| {
                let at = address.checked_add(offset)?;
                self.core.mem.read(at, 1).ok().map(|byte| byte as u8)
            })
            .collect()
    }

    /// Reset the machine and run `input` until it stops.
    pub fn run(&mut self, input: &[u8]) -> Execution {
        self.run_within(input, self.max_instructions)
    }

    /// Run `input` up to the instruction that makes `read`, a peripheral
    /// read a traced run of the same input recorded, and keep the state
    /// there; `None` when the run stops before it, within `budget`
    /// instructions.
    pub(crate) fn pause_before(
        &mut self,
        input: &[u8],
        read: &MmioAccess,
        budget: u64,
    ) -> Option<ProbePoint> {
        self.start(input);
        let budget = budget.min(self.max_instructions);
        let at = read.instructions;
        if self
            .resume(input, budget, |core| core.instructions >= at)
            .is_some()
            || self.core.instructions != at
        {
            return None;
        }
        Some(ProbePoint {
            address: read.address,
            pc: read.pc,
            core: self.core.save(),
            memory: self.core.mem.checkpoint(),
            mmio: self.core.mmio.mark(),
            pending: self.pending,
            delivered: self.delivered,
        })
    }

    /// Run on from `point` with its read's value XORed with `xor`, until the
    /// peripheral read after it or `budget` instructions in all (never more
    /// than the machine's budget). Returns the probed read and the one after
    /// it, as far as the run made them.
    pub(crate) fn probe_from(
        &mut self,
        point: &ProbePoint,
        input: &[u8],
        xor: u32,
        budget: u64,
    ) -> &[MmioAccess] {
        self.core.mem.rollback(&point.memory);
        self.core.restore(&point.core);
        // The machine may have run another input since the pause.
        self.core.mmio.begin(self.peripheral_input(input));
        self.core.mmio.rewind(point.mmio);
        self.pending = point.pending;
        self.delivered = point.delivered;
        self.core.mmio.probe = Some(Probe {
            address: point.address,
            pc: point.pc,
            xor,
        });
        self.core.mmio.set_trace_limit(2);
        let budget = budget.min(self.max_instructions);
        self.resume(input, budget, |core| core.mmio.trace.len() >= 2);
        self.core.mmio.probe = None;
        &self.core.mmio.trace
    }

    fn run_within(&mut self, input: &[u8], budget: u64) -> Execution {
        self.start(input);
        let stop = loop {
            if let Some(stop) = self.resume(input, budget, |_| false) {
                break stop;
            }
        };
        Execution {
            stop,
            instructions: self.core.instructions,
            blocks: self.core.blocks,
            input_delivered: self.delivered,
            mmio_reads: self.core.mmio.reads,
            mmio_input: self.core.mmio.consumed(),
            output: std::mem::take(&mut self.core.output),
        }
    }

    /// The bytes of `input` peripheral reads take: the buffer takes the
    /// first `capacity`, and they take the rest.
    fn peripheral_input<'a>(&self, input: &'a [u8]) -> &'a [u8] {
        let buffered = self
            .input
            .map_or(0, |buffer| input.len().min(buffer.capacity as usize));
        &input[buffered..]
    }

    /// Reset the core and start a run of `input`.
    fn start(&mut self, input: &[u8]) {
        self.core.reset(self.initial_sp, self.reset_vector);
        self.core.mmio.begin(self.peripheral_input(input));
        self.pending = self.input;
        self.delivered = None;
        if let Some(buffer) = self.pending.filter(|buffer| buffer.inject_at.is_none()) {
            self.delivered = Some(self.deliver(&buffer, input));
            self.pending = None;
        }
    }

    /// Run on until the run stops, or return `None` when `pause` holds
    /// between two instructions.
    fn resume(&mut self, input: &[u8], budget: u64, pause: impl Fn(&Core) -> bool) -> Option<Stop> {
        loop {
            if pause(&self.core) {
                return None;
            }
            if self.core.instructions >= budget {
                return Some(Stop::InstructionLimit);
            }
            let pc = self.core.pc;
            if self.exit_at.contains(&pc) {
                return Some(Stop::Exit { address: pc });
            }
            if let Some(buffer) = self.pending.filter(|buffer| buffer.inject_at == Some(pc)) {
                self.delivered = Some(self.deliver(&buffer, input));
                self.pending = None;
            }
            if let Err(trap) = self.core.step() {
                return Some(match trap {
                    Trap::Fault(fault) => Stop::Fault(fault),
                    Trap::Unsupported { pc, encoding, what } => {
                        Stop::Unsupported { pc, encoding, what }
                    }
                    Trap::Idle { pc, reason } => Stop::Idle { pc, reason },
                    Trap::SemihostingExit { code } => Stop::SemihostingExit { code },
                    Trap::SystemReset { pc } => Stop::SystemReset { pc },
                    Trap::InputExhausted { pc, address } => Stop::InputExhausted { pc, address },
                });
            }
        }
    }

    /// Write `input`, cut to the buffer, and its length word.
    fn deliver(&mut self, buffer: &InputBuffer, input: &[u8]) -> usize {
        let bytes = &input[..input.len().min(buffer.capacity as usize)];
        // Both were checked to be in memory when the machine was set up.
        let _ = self.core.mem.place(buffer.address, bytes);
        if let Some(address) = buffer.length_word {
            let _ = self
                .core
                .mem
                .place(address, &(bytes.len() as u32).to_le_bytes());
        }
        bytes.len()
    }
}

fn check_code(memory: &Memory, what: &'static str, address: u32) -> Result<(), SetupError> {
    if address & 1 != 0 || !executable_region(address) || !memory.holds(address, 2) {
        return Err(SetupError::NotCode { what, address });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A raw image at 0: a vector table (sp 0x20001000, reset 0x41), then
    /// `code` at 0x40.
    pub(crate) fn image(code: &[u16]) -> Image {
        let mut bytes = vec![0u8; 0x40];
        bytes[..4].copy_from_slice(&0x2000_1000u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&0x41u32.to_le_bytes());
        for halfword in code {
            bytes.extend_from_slice(&halfword.to_le_bytes());
        }
        Image::raw(&bytes, 0).unwrap()
    }

    #[test]
    fn a_machine_starts_at_the_reset_vector_with_the_vector_table_stack() {
        // wfi
        let mut machine = Machine::new(&image(&[0xbf30]), MachineConfig::default()).unwrap();
        assert_eq!(machine.initial_sp(), 0x2000_1000);
        assert_eq!(machine.reset_vector(), 0x41);
        let run = machine.run(&[]);
        assert_eq!(
            run.stop,
            Stop::Idle {
                pc: 0x40,
                reason: IdleReason::WaitForInterrupt
            }
        );
        assert_eq!(run.instructions, 0);
        assert_eq!(run.input_delivered, None);
    }

    #[test]
    fn setup_refuses_images_that_cannot_start() {
        let config = MachineConfig::default();
        let mut bytes = vec![0u8; 0x44];
        bytes[..4].copy_from_slice(&0x2000_1000u32.to_le_bytes());
        // Reset vector without the Thumb bit.
        bytes[4..8].copy_from_slice(&0x40u32.to_le_bytes());
        let image = Image::raw(&bytes, 0).unwrap();
        assert_eq!(
            Machine::new(&image, config.clone()).err(),
            Some(SetupError::BadResetVector { vector: 0x40 })
        );
        // Reset vector outside the image.
        bytes[4..8].copy_from_slice(&0x1001u32.to_le_bytes());
        let image = Image::raw(&bytes, 0).unwrap();
        assert_eq!(
            Machine::new(&image, config.clone()).err(),
            Some(SetupError::BadResetVector { vector: 0x1001 })
        );
        // Stack outside RAM.
        bytes[4..8].copy_from_slice(&0x41u32.to_le_bytes());
        bytes[..4].copy_from_slice(&0x1000_0000u32.to_le_bytes());
        let image = Image::raw(&bytes, 0).unwrap();
        assert_eq!(
            Machine::new(&image, config.clone()).err(),
            Some(SetupError::StackOutsideRam { sp: 0x1000_0000 })
        );
        // A vector table where the image has nothing.
        assert_eq!(
            Machine::new(
                &image,
                MachineConfig {
                    vector_table: Some(0x0800_0000),
                    ..config.clone()
                }
            )
            .err(),
            Some(SetupError::NoVectorTable {
                address: 0x0800_0000
            })
        );
        assert_eq!(
            Machine::new(
                &self::image(&[0xbf30]),
                MachineConfig {
                    max_instructions: 0,
                    ..config
                }
            )
            .err(),
            Some(SetupError::NoBudget)
        );
    }

    #[test]
    fn setup_refuses_an_input_buffer_or_addresses_outside_memory() {
        let image = image(&[0xbf30]);
        let with_input = |input: InputBuffer| MachineConfig {
            input: Some(input),
            ..MachineConfig::default()
        };
        let buffer = InputBuffer {
            address: 0x2000_0000,
            capacity: 16,
            length_word: None,
            inject_at: None,
        };
        assert!(Machine::new(&image, with_input(buffer)).is_ok());
        assert_eq!(
            Machine::new(
                &image,
                with_input(InputBuffer {
                    address: 0x200f_fff8,
                    ..buffer
                })
            )
            .err(),
            Some(SetupError::InputOutsideMemory {
                address: 0x200f_fff8,
                capacity: 16
            })
        );
        assert_eq!(
            Machine::new(
                &image,
                with_input(InputBuffer {
                    capacity: 0,
                    ..buffer
                })
            )
            .err(),
            Some(SetupError::EmptyInputBuffer)
        );
        assert_eq!(
            Machine::new(
                &image,
                with_input(InputBuffer {
                    length_word: Some(0x3000_0000),
                    ..buffer
                })
            )
            .err(),
            Some(SetupError::LengthOutsideMemory {
                address: 0x3000_0000
            })
        );
        assert_eq!(
            Machine::new(
                &image,
                with_input(InputBuffer {
                    inject_at: Some(0x2000_0000),
                    ..buffer
                })
            )
            .err(),
            None,
            "RAM can hold code"
        );
        assert_eq!(
            Machine::new(
                &image,
                with_input(InputBuffer {
                    inject_at: Some(0x4000_0000),
                    ..buffer
                })
            )
            .err(),
            Some(SetupError::NotCode {
                what: "the input injection address",
                address: 0x4000_0000
            })
        );
        assert_eq!(
            Machine::new(
                &image,
                MachineConfig {
                    exit_at: vec![0x43],
                    ..MachineConfig::default()
                }
            )
            .err(),
            Some(SetupError::NotCode {
                what: "the exit address",
                address: 0x43
            })
        );
    }

    #[test]
    fn the_input_is_cut_to_the_buffer_and_its_length_written() {
        // ldr r0, [pc, #4]; ldr r1, [r0]; ldr r2, [r0, #4]; wfi; .word 0x20000000
        let code = [0x4801, 0x6801, 0x6842, 0xbf30, 0x0000, 0x2000];
        let mut machine = Machine::new(
            &image(&code),
            MachineConfig {
                input: Some(InputBuffer {
                    address: 0x2000_0000,
                    capacity: 4,
                    length_word: Some(0x2000_0004),
                    inject_at: None,
                }),
                ..MachineConfig::default()
            },
        )
        .unwrap();
        let run = machine.run(b"ABCDEF");
        assert_eq!(run.input_delivered, Some(4));
        assert_eq!(machine.core.r[1], u32::from_le_bytes(*b"ABCD"));
        assert_eq!(machine.core.r[2], 4, "the length word holds the cut length");
        // The next run starts from a clean buffer.
        let run = machine.run(b"Z");
        assert_eq!(run.input_delivered, Some(1));
        assert_eq!(machine.core.r[1], u32::from(b'Z'));
    }

    /// `mov.w r0, #0x20000000; mov.w r1, #0x40000000; ldrb r2, [r0];
    /// ldrb r3, [r1]; ldrh r4, [r1, #2]; wfi`: a buffer byte, then a byte
    /// and a halfword of peripheral registers.
    const BUFFER_THEN_PERIPHERAL: [u16; 8] = [
        0xf04f, 0x5000, 0xf04f, 0x4180, 0x7802, 0x780b, 0x884c, 0xbf30,
    ];

    fn passthrough_at(address: u32) -> crate::MmioModel {
        crate::MmioModel {
            address,
            pc: None,
            kind: crate::MmioModelKind::Passthrough,
        }
    }

    #[test]
    fn the_buffer_takes_its_capacity_and_peripheral_reads_take_the_rest() {
        let mut machine = Machine::new(
            &image(&BUFFER_THEN_PERIPHERAL),
            MachineConfig {
                input: Some(InputBuffer {
                    address: 0x2000_0000,
                    capacity: 2,
                    length_word: None,
                    inject_at: None,
                }),
                mmio: MmioConfig {
                    models: vec![passthrough_at(0x4000_0000)],
                    default: crate::MmioDefault::Passthrough,
                },
                ..MachineConfig::default()
            },
        )
        .unwrap();
        let run = machine.run(b"ABcde");
        assert!(matches!(run.stop, Stop::Idle { .. }), "{:?}", run.stop);
        assert_eq!(run.input_delivered, Some(2));
        assert_eq!(machine.core.r[2], u32::from(b'A'));
        assert_eq!(
            machine.core.r[3],
            u32::from(b'c'),
            "the byte after the buffer"
        );
        assert_eq!(machine.core.r[4], u32::from_le_bytes(*b"de\0\0"));
        assert_eq!((run.mmio_reads, run.mmio_input), (2, 3));
        // An input no longer than the buffer leaves the peripheral reads none.
        let run = machine.run(b"AB");
        assert_eq!(
            run.stop,
            Stop::InputExhausted {
                pc: 0x4a,
                address: 0x4000_0000
            }
        );
    }

    #[test]
    fn without_models_peripheral_registers_read_as_zero() {
        let mut machine =
            Machine::new(&image(&BUFFER_THEN_PERIPHERAL), MachineConfig::default()).unwrap();
        let run = machine.run(b"xyz");
        assert!(matches!(run.stop, Stop::Idle { .. }), "{:?}", run.stop);
        assert_eq!((machine.core.r[3], machine.core.r[4]), (0, 0));
        assert_eq!((run.mmio_reads, run.mmio_input), (2, 0));
    }

    #[test]
    fn setup_refuses_mmio_models_off_the_peripheral_window_twice_or_off_code() {
        let image = image(&BUFFER_THEN_PERIPHERAL);
        let with = |models: Vec<crate::MmioModel>| MachineConfig {
            mmio: MmioConfig {
                models,
                default: crate::MmioDefault::Zero,
            },
            ..MachineConfig::default()
        };
        assert_eq!(
            Machine::new(&image, with(vec![passthrough_at(0x2000_0000)])).err(),
            Some(SetupError::MmioOutsidePeripherals {
                address: 0x2000_0000
            })
        );
        assert_eq!(
            Machine::new(&image, with(vec![passthrough_at(0x6000_0000)])).err(),
            Some(SetupError::MmioOutsidePeripherals {
                address: 0x6000_0000
            })
        );
        let error = Machine::new(
            &image,
            with(vec![
                passthrough_at(0x4000_0000),
                passthrough_at(0x4000_0000),
            ]),
        )
        .err()
        .unwrap();
        assert_eq!(
            error,
            SetupError::DuplicateMmioModel {
                address: 0x4000_0000,
                pc: None
            }
        );
        assert!(error.to_string().contains("by any instruction"), "{error}");
        let at = |pc| crate::MmioModel {
            pc: Some(pc),
            ..passthrough_at(0x4000_0000)
        };
        // One model for the register and one for an instruction are two
        // sites; two for the same instruction are one.
        assert!(Machine::new(&image, with(vec![passthrough_at(0x4000_0000), at(0x4a)])).is_ok());
        let error = Machine::new(&image, with(vec![at(0x4a), at(0x4a)]))
            .err()
            .unwrap();
        assert!(
            error.to_string().contains("read at pc 0x0000004a"),
            "{error}"
        );
        assert_eq!(
            Machine::new(&image, with(vec![at(0x4b)])).err(),
            Some(SetupError::NotCode {
                what: "an MMIO model's instruction address",
                address: 0x4b
            })
        );
        let no_bits = crate::MmioModel {
            kind: crate::MmioModelKind::BitExtract { mask: 0 },
            ..passthrough_at(0x4000_0000)
        };
        assert_eq!(
            Machine::new(&image, with(vec![no_bits])).err(),
            Some(SetupError::EmptyBitMask {
                address: 0x4000_0000
            })
        );
    }

    #[test]
    fn setup_refuses_an_mmio_model_for_an_address_memory_holds() {
        // RAM mapped over a register answers its reads before any model
        // would, so the model would never be used.
        let image = image(&BUFFER_THEN_PERIPHERAL);
        let config = |ram: Vec<MemoryRange>| MachineConfig {
            ram,
            mmio: MmioConfig {
                models: vec![passthrough_at(0x4000_0000)],
                default: crate::MmioDefault::Zero,
            },
            ..MachineConfig::default()
        };
        let over = MemoryRange {
            base: 0x4000_0000,
            size: 0x1000,
        };
        let error = Machine::new(&image, config(vec![MemoryRange::default_ram(), over]))
            .err()
            .unwrap();
        assert_eq!(
            error,
            SetupError::MmioInMemory {
                address: 0x4000_0000
            }
        );
        assert!(error.to_string().contains("would never be used"), "{error}");
        // RAM elsewhere in the window leaves the modelled register alone.
        let beside = MemoryRange {
            base: 0x4000_1000,
            ..over
        };
        let mut machine =
            Machine::new(&image, config(vec![MemoryRange::default_ram(), beside])).unwrap();
        let run = machine.run(b"z");
        assert_eq!((run.mmio_reads, machine.core.r[3]), (2, u32::from(b'z')));
    }

    /// The command-dispatch fixture (`tests/fixtures/dispatch.c`): `fifo_pop`
    /// reads its data register at 0x080000a2; 0x01 arms it (a store), 0x04
    /// ends the session, and 'X' once armed three times stores to
    /// 0x60000000, which nothing maps.
    fn dispatch() -> Machine {
        let image = Image::elf(include_bytes!("../tests/fixtures/dispatch.elf")).unwrap();
        let config = MachineConfig {
            max_instructions: 100_000,
            mmio: MmioConfig {
                models: Vec::new(),
                default: crate::MmioDefault::Passthrough,
            },
            ..MachineConfig::default()
        };
        Machine::new(&image, config).unwrap()
    }

    /// A trace's reads as their instruction, register, value and count.
    fn reads(trace: &[MmioAccess]) -> Vec<(u32, u32, u32, u64)> {
        trace
            .iter()
            .map(|read| (read.pc, read.address, read.value, read.instructions))
            .collect()
    }

    #[test]
    fn a_probe_runs_on_from_a_paused_run_as_a_fresh_run_of_the_changed_input_does() {
        let mut machine = dispatch();
        let input = [0u8; 16];
        machine.trace_mmio(64);
        machine.run(&input);
        let recorded = machine.mmio_trace().to_vec();
        assert_eq!(recorded.len(), 16);
        let at = 5;
        let point = machine
            .pause_before(&input, &recorded[at], 100_000)
            .unwrap();
        // Unchanged, the probe repeats the recorded reads.
        let unchanged = machine.probe_from(&point, &input, 0, 100_000).to_vec();
        assert_eq!(unchanged, recorded[at..at + 2]);
        // Each arm stores a new count; a probe after them starts again from
        // the count at the pause, so 'X' finds the device not armed and
        // reads on instead of storing through the wild pointer.
        for _ in 0..3 {
            let armed = machine.probe_from(&point, &input, 0x01, 100_000);
            assert_eq!(armed.len(), 2);
        }
        let fire = reads(machine.probe_from(&point, &input, u32::from(b'X'), 100_000));
        let mut changed = input;
        changed[at] = b'X';
        machine.trace_mmio(64);
        machine.run(&changed);
        assert_eq!(fire, reads(&machine.mmio_trace()[at..at + 2]));
        assert_eq!(fire[1].0, 0x0800_00a2, "back at the read");
        // Ending the session: no read follows.
        let end = machine.probe_from(&point, &input, 0x04, 100_000);
        assert_eq!(end.len(), 1);
        // A run after the probes starts from reset as ever.
        machine.trace_mmio(64);
        machine.run(&input);
        assert_eq!(machine.mmio_trace(), &recorded[..]);
    }

    #[test]
    fn a_traced_run_records_the_stores_between_its_peripheral_reads() {
        let mut machine = dispatch();
        machine.trace_mmio(64);
        machine.run(&[0, 0, 1, 1, 0, 0]);
        let stores: Vec<u64> = machine
            .mmio_trace()
            .iter()
            .map(|read| read.stores)
            .collect();
        assert_eq!(stores.len(), 6);
        // The start-up code's and main's stores come before the first read;
        // each arm stores a new count before the read after it.
        assert_ne!(stores[0], 0);
        assert_eq!((stores[1], stores[2]), (0, 0));
        assert!(stores[3] != 0 && stores[4] != 0 && stores[3] != stores[4]);
        assert_eq!(stores[5], 0);
        // Without a trace nothing is noted.
        machine.trace_mmio(0);
        machine.run(&[1, 1]);
        assert!(machine.mmio_trace().is_empty());
    }

    #[test]
    fn the_budget_and_exit_addresses_end_a_run() {
        // loop: adds r0, #1; b loop
        let code = [0x3001, 0xe7fd];
        let mut machine = Machine::new(
            &image(&code),
            MachineConfig {
                max_instructions: 100,
                ..MachineConfig::default()
            },
        )
        .unwrap();
        let run = machine.run(&[]);
        assert_eq!(run.stop, Stop::InstructionLimit);
        assert_eq!(run.instructions, 100);
        let mut machine = Machine::new(
            &image(&code),
            MachineConfig {
                exit_at: vec![0x42],
                ..MachineConfig::default()
            },
        )
        .unwrap();
        let run = machine.run(&[]);
        assert_eq!(run.stop, Stop::Exit { address: 0x42 });
        assert_eq!(run.instructions, 1);
    }
}
