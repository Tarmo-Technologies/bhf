// SPDX-License-Identifier: Apache-2.0

//! A machine: an image mapped into memory with its RAM, reset and run one
//! input at a time.

use crate::coverage::EdgeMap;
use crate::cpu::{executable_region, Core, Trap};
use crate::fault::Fault;
use crate::image::Image;
use crate::memory::Memory;
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
/// a receive routine would leave it.
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
}

impl Default for MachineConfig {
    fn default() -> Self {
        Self {
            ram: vec![MemoryRange::default_ram()],
            vector_table: None,
            input: None,
            exit_at: Vec::new(),
            max_instructions: DEFAULT_MAX_INSTRUCTIONS,
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
    /// never reached the address that writes it.
    pub input_delivered: Option<usize>,
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
}

impl Machine {
    /// Map `image` and its RAM, and check that it can start: the vector table
    /// is in the image, the reset vector points at Thumb code, the stack is in
    /// RAM, and the input buffer and the exit and injection addresses are in
    /// memory.
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
        Ok(Self {
            core: Core::new(memory, vector_table),
            initial_sp,
            reset_vector,
            input: config.input,
            exit_at: config.exit_at,
            max_instructions: config.max_instructions,
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
        self.core.reset(self.initial_sp, self.reset_vector);
        let mut pending = self.input;
        let mut delivered = None;
        if let Some(buffer) = pending.filter(|buffer| buffer.inject_at.is_none()) {
            delivered = Some(self.deliver(&buffer, input));
            pending = None;
        }
        let stop = loop {
            if self.core.instructions >= self.max_instructions {
                break Stop::InstructionLimit;
            }
            let pc = self.core.pc;
            if self.exit_at.contains(&pc) {
                break Stop::Exit { address: pc };
            }
            if let Some(buffer) = pending.filter(|buffer| buffer.inject_at == Some(pc)) {
                delivered = Some(self.deliver(&buffer, input));
                pending = None;
            }
            if let Err(trap) = self.core.step() {
                break match trap {
                    Trap::Fault(fault) => Stop::Fault(fault),
                    Trap::Unsupported { pc, encoding, what } => {
                        Stop::Unsupported { pc, encoding, what }
                    }
                    Trap::Idle { pc, reason } => Stop::Idle { pc, reason },
                    Trap::SemihostingExit { code } => Stop::SemihostingExit { code },
                    Trap::SystemReset { pc } => Stop::SystemReset { pc },
                };
            }
        };
        Execution {
            stop,
            instructions: self.core.instructions,
            blocks: self.core.blocks,
            input_delivered: delivered,
            output: std::mem::take(&mut self.core.output),
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
