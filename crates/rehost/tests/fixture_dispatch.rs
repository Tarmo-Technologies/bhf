// SPDX-License-Identifier: Apache-2.0

//! The command-dispatch fixture firmware (`tests/fixtures/dispatch.c`) reads
//! its commands from a peripheral's data register through a getter, so one
//! instruction reads one register over and over: a polling loop, as a trace
//! shows it. Bit 2 (0x04, end of session) ends the loop and bit 0 (0x01,
//! arm) changes its path, but so does the byte 'X', which no single-bit flip
//! shows. Under the passthrough default the read takes its byte from the
//! input, and a bit-extract model for bits 0 and 2 would leave 'X' out of
//! reach, so inference keeps the read whole and the fuzzer can still reach
//! the wild store.

use rehost::{
    infer_polling_models, polling_loops, FaultKind, Image, Machine, MachineConfig, MmioConfig,
    MmioDefault, MmioModel, MmioModelKind, NotAPoll, Stop, MIN_POLLS,
};
use std::path::PathBuf;

const FIFO_DATA: u32 = 0x4001_3004;
/// `ldrb r0, [r3, #4]` in `fifo_pop` (`arm-none-eabi-objdump -d dispatch.elf`).
const FIFO_POP: u32 = 0x0800_00a2;
const WILD: u32 = 0x6000_0000;

fn image() -> Image {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dispatch.elf");
    let bytes =
        std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    Image::elf(&bytes).unwrap()
}

fn config(default: MmioDefault, models: Vec<MmioModel>) -> MachineConfig {
    MachineConfig {
        max_instructions: 200_000,
        mmio: MmioConfig { models, default },
        ..MachineConfig::default()
    }
}

/// Armed three times, then 'X'.
const FIRE: &[u8] = &[1, 1, 1, b'X'];

#[test]
fn the_getter_reads_the_data_register_in_a_loop_a_trace_shows() {
    let image = image();
    let mut machine = Machine::new(&image, config(MmioDefault::Passthrough, Vec::new())).unwrap();
    machine.trace_mmio(64);
    let run = machine.run(&[0; 32]);
    assert_eq!(
        run.stop,
        Stop::InputExhausted {
            pc: FIFO_POP,
            address: FIFO_DATA
        }
    );
    let loops = polling_loops(machine.mmio_trace(), MIN_POLLS);
    assert_eq!(loops.len(), 1, "{loops:?}");
    assert_eq!(
        (loops[0].pc, loops[0].address, loops[0].size, loops[0].polls),
        (FIFO_POP, FIFO_DATA, 1, 32)
    );
    assert!(!loops[0].writes, "a zero command stores nothing");
    // Arming stores a new count each time round.
    machine.run(&[1; 32]);
    let loops = polling_loops(machine.mmio_trace(), MIN_POLLS);
    assert!(loops[0].writes, "{loops:?}");
}

#[test]
fn a_dispatch_loop_whose_read_takes_the_input_keeps_it_whole() {
    let image = image();
    let inference = infer_polling_models(
        &image,
        &config(MmioDefault::Passthrough, Vec::new()),
        &[FIRE.to_vec(), vec![0; 4096]],
    )
    .unwrap();
    assert_eq!(inference.loops.len(), 1, "{inference:?}");
    let found = inference.loops[0];
    assert_eq!(
        (found.polling.pc, found.polling.address),
        (FIFO_POP, FIFO_DATA)
    );
    // One flip at a time shows bits 0 and 2 only; trying the other bits
    // finds 'X'.
    assert_eq!((found.mask, found.exit), (0x05, Some(0x04)));
    assert_eq!(
        found.not_a_poll,
        Some(NotAPoll::OtherBits {
            value: u32::from(b'X')
        })
    );
    assert_eq!(inference.bit_extract_models(), Vec::new());
    assert_eq!(inference.constant_models(), Vec::new());
    // The read keeps taking the input whole, and 'X' reaches the store.
    let mut machine = Machine::new(&image, config(MmioDefault::Passthrough, Vec::new())).unwrap();
    let Stop::Fault(fault) = machine.run(FIRE).stop else {
        panic!("the armed 'X' should store through the wild pointer");
    };
    assert_eq!(
        (fault.kind, fault.address),
        (FaultKind::WriteUnmapped, Some(WILD))
    );
}

#[test]
fn a_bit_extract_model_for_the_bits_one_flip_shows_hides_the_bug() {
    // What inference would add if it took the loop for a status poll.
    let narrowed = MmioModel {
        address: FIFO_DATA,
        pc: Some(FIFO_POP),
        kind: MmioModelKind::BitExtract { mask: 0x05 },
    };
    let image = image();
    let mut machine =
        Machine::new(&image, config(MmioDefault::Passthrough, vec![narrowed])).unwrap();
    let run = machine.run(FIRE);
    assert_eq!(
        run.stop,
        Stop::InputExhausted {
            pc: FIFO_POP,
            address: FIFO_DATA
        },
        "'X' reads as 0"
    );
    let armed = image.symbol("armed").unwrap().address;
    assert_eq!(machine.read_memory(armed, 4).unwrap(), vec![3, 0, 0, 0]);
}

#[test]
fn read_as_zero_the_same_loop_gains_the_bits_that_decide_it() {
    // Nothing feeds the read under the zero default, so the bits a
    // bit-extract model feeds are all gain.
    let inference = infer_polling_models(
        &image(),
        &config(MmioDefault::Zero, Vec::new()),
        &[Vec::new()],
    )
    .unwrap();
    assert_eq!(inference.loops.len(), 1, "{inference:?}");
    assert_eq!(inference.loops[0].not_a_poll, None);
    assert_eq!(
        inference.bit_extract_models(),
        vec![MmioModel {
            address: FIFO_DATA,
            pc: Some(FIFO_POP),
            kind: MmioModelKind::BitExtract { mask: 0x05 },
        }]
    );
    assert_eq!(inference.probes, 8, "no value check");
}
