// SPDX-License-Identifier: Apache-2.0

//! Rehosting: run an unmodified Cortex-M firmware image, with no source and
//! no instrumentation, in an emulator, and record the basic-block coverage
//! of each run into an edge map.
//!
//! The emulator is this crate's own interpreter of the ARMv7-M integer
//! Thumb-2 instruction set. An [`Image`] is an ELF or a raw image at a base
//! address; a [`Machine`] maps it with its RAM and, for each input, resets
//! the core from the vector table (the initial stack pointer and the reset
//! vector, as the hardware does), writes the input into a fixed buffer,
//! and runs until the firmware goes idle, reaches an exit address, faults,
//! or uses its instruction budget. Every basic block it enters is counted
//! into an AFL-style [`EdgeMap`].
//!
//! ```
//! use rehost::{Image, InputBuffer, Machine, MachineConfig, Stop};
//!
//! // A raw image at 0: the vector table (stack 0x20001000, reset 0x41),
//! // then `ldr r0, [pc, #4]; ldrb r1, [r0]; wfi` and the buffer address.
//! let mut bytes = vec![0u8; 0x40];
//! bytes[..4].copy_from_slice(&0x2000_1000u32.to_le_bytes());
//! bytes[4..8].copy_from_slice(&0x41u32.to_le_bytes());
//! for halfword in [0x4801u16, 0x7801, 0xbf30, 0x0000, 0x0000, 0x2000] {
//!     bytes.extend_from_slice(&halfword.to_le_bytes());
//! }
//! let image = Image::raw(&bytes, 0).unwrap();
//! let config = MachineConfig {
//!     input: Some(InputBuffer {
//!         address: 0x2000_0000,
//!         capacity: 64,
//!         length_word: None,
//!         inject_at: None,
//!     }),
//!     ..MachineConfig::default()
//! };
//! let mut machine = Machine::new(&image, config).unwrap();
//! let run = machine.run(b"A");
//! assert!(matches!(run.stop, Stop::Idle { .. }));
//! assert!(machine.edge_map().edges() > 0);
//! ```
//!
//! What a rehosted run does not model: peripherals (their registers read as
//! zero and drop writes), interrupts, the floating-point unit, the M4's SIMD
//! instructions, the MPU and privilege. An instruction outside the model
//! stops the run as [`Stop::Unsupported`], a limit of the emulator rather
//! than a fault of the firmware.

mod alu;
#[cfg(test)]
mod core_tests;
mod coverage;
mod cpu;
mod fault;
mod image;
mod machine;
mod memory;
mod thumb16;
mod thumb32;

pub use coverage::{CoverageMap, EdgeMap, EDGE_MAP_SIZE};
pub use fault::{Fault, FaultClass, FaultKind};
pub use image::{Image, ImageFormat, LoadError, RamRange, Segment, Symbol};
pub use machine::{
    Execution, IdleReason, InputBuffer, Machine, MachineConfig, MemoryRange, SetupError, Stop,
    DEFAULT_MAX_INSTRUCTIONS, DEFAULT_RAM_BASE, DEFAULT_RAM_SIZE,
};
