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
//! Peripheral registers read through MMIO models ([`MmioConfig`]): a model
//! for a register, or for one instruction's reads of it, takes the read's
//! bytes from the input (passthrough), returns a constant, or feeds only the
//! bits of a mask from the input (bit-extract), and a read no model names
//! returns zero or, with [`MmioDefault::Passthrough`], the input's bytes.
//! [`infer_polling_models`] finds the status-register polling loops a run
//! stalls in and the bits that decide them, for bit-extract models, and
//! keeps a read the input feeds whole when its loop is not shown to be a
//! status poll ([`NotAPoll`]). Peripheral reads take the input as a stream
//! (after the bytes an [`InputBuffer`] holds), and a read the input has no
//! bytes left for ends the run as [`Stop::InputExhausted`]. Peripheral
//! writes are dropped. Which addresses are peripheral registers is the
//! machine's windows ([`MachineConfig::peripheral_windows`]): the whole
//! Cortex-M peripheral region, or the address blocks a part's CMSIS-SVD
//! file gives ([`Svd::windows`]), outside which an access faults.
//!
//! Interrupts come from a schedule in the input ([`InterruptConfig`]): every
//! tick takes one byte of the same stream and pends one of the interrupts
//! the firmware has enabled in the NVIC (or SysTick), the byte choosing
//! which and how long until the next tick, and a core that waits for an
//! interrupt runs on to the next tick. The NVIC takes a pending interrupt
//! when its priority preempts the core's, stacking the frame and entering
//! the handler as the hardware does; the firmware's own pending bits are
//! taken the same way. Without a schedule nothing is ever taken.
//!
//! What a rehosted run does not model: peripheral behaviour beyond those
//! reads (a peripheral never raises an interrupt of its own accord: the
//! schedule does), the floating-point unit, the M4's SIMD instructions, the
//! MPU and privilege. An instruction outside the model stops the run as
//! [`Stop::Unsupported`], a limit of the emulator rather than a fault of the
//! firmware.

mod alu;
#[cfg(test)]
mod core_tests;
mod coverage;
mod cpu;
mod fault;
mod image;
mod infer;
#[cfg(test)]
mod irq_tests;
mod machine;
mod memory;
mod mmio;
mod nvic;
mod svd;
mod thumb16;
mod thumb32;

pub use coverage::{CoverageMap, EdgeMap, EDGE_MAP_SIZE};
pub use fault::{Fault, FaultClass, FaultKind};
pub use image::{Image, ImageFormat, LoadError, RamRange, Segment, Symbol};
pub use infer::{
    decide, infer_polling_models, polling_loops, probe_outcome, Inference, InferredLoop, NotAPoll,
    PollingLoop, ProbeOutcome, MIN_POLLS,
};
pub use machine::{
    Execution, IdleReason, InputBuffer, Machine, MachineConfig, MemoryRange, SetupError, Stop,
    DEFAULT_MAX_INSTRUCTIONS, DEFAULT_RAM_BASE, DEFAULT_RAM_SIZE,
};
pub use mmio::{MmioAccess, MmioConfig, MmioDefault, MmioModel, MmioModelKind, PeripheralWindow};
pub use nvic::{
    schedule_wait, InterruptConfig, InterruptEvent, DEFAULT_INTERRUPT_INTERVAL, INTERRUPT_LOG_LIMIT,
};
pub use svd::{AddressBlock, BlockUsage, Svd, SvdError, SvdInterrupt, SvdPeripheral};
