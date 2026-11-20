// SPDX-License-Identifier: Apache-2.0

//! The polled-UART fixture firmware (`tests/fixtures/uart.c`) waits for a
//! status bit before every byte it sends or reads. Read as zero, the status
//! register stalls it in its first polling loop; fed whole from the input it
//! eats four input bytes a poll and the record never lines up. Inference
//! finds both polling loops and the bit each one waits for, and with
//! bit-extract models for them a line from the input reaches the parser's
//! stack overflow.

use rehost::{
    infer_polling_models, polling_loops, FaultClass, Image, Machine, MachineConfig, MmioConfig,
    MmioDefault, MmioModel, MmioModelKind, Stop, MIN_POLLS,
};
use std::path::PathBuf;

const USART_SR: u32 = 0x4001_1000;
/// `ldr r3, [r2, #0]` in `uart_putc` and in `uart_getc`
/// (`arm-none-eabi-objdump -d uart.elf`).
const TXE_POLL: u32 = 0x0800_00a2;
const RXNE_POLL: u32 = 0x0800_00b2;

fn image() -> Image {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/uart.elf");
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

fn bit_extract(pc: u32, mask: u32) -> MmioModel {
    MmioModel {
        address: USART_SR,
        pc: Some(pc),
        kind: MmioModelKind::BitExtract { mask },
    }
}

/// The input as the inferred models read it: a byte for the prompt's
/// transmit poll, then for each byte of the line a byte for its receive poll
/// and the four bytes of the data register.
fn polled_line(line: &[u8]) -> Vec<u8> {
    let mut input = vec![1];
    for &byte in line.iter().chain(b"\n") {
        input.extend_from_slice(&[1, byte, 0, 0, 0]);
    }
    input
}

/// "FUZZC", a length of 16, and 16 bytes: the last four land on the saved
/// return address.
fn overflowing_line() -> Vec<u8> {
    let mut line = b"FUZZC\x10".to_vec();
    line.extend_from_slice(&[b'A'; 16]);
    line
}

#[test]
fn a_recorded_trace_shows_the_first_polling_loop() {
    let image = image();
    let mut machine = Machine::new(&image, config(MmioDefault::Zero, Vec::new())).unwrap();
    machine.trace_mmio(64);
    let run = machine.run(b"");
    assert_eq!(run.stop, Stop::InstructionLimit, "the transmit poll stalls");
    let trace = machine.mmio_trace();
    assert_eq!(trace.len(), 64);
    let loops = polling_loops(trace, MIN_POLLS);
    assert_eq!(loops.len(), 1, "{loops:?}");
    assert_eq!(
        (loops[0].pc, loops[0].address, loops[0].size, loops[0].value),
        (TXE_POLL, USART_SR, 4, 0)
    );
    assert_eq!((loops[0].first, loops[0].polls), (0, 64));
}

#[test]
fn inference_finds_both_polling_loops_and_the_bit_each_waits_for() {
    let image = image();
    for default in [MmioDefault::Zero, MmioDefault::Passthrough] {
        let inference =
            infer_polling_models(&image, &config(default, Vec::new()), &[vec![0; 4096]]).unwrap();
        let found: Vec<(u32, u32, u32, Option<u32>)> = inference
            .loops
            .iter()
            .map(|inferred| {
                (
                    inferred.polling.pc,
                    inferred.polling.address,
                    inferred.mask,
                    inferred.exit,
                )
            })
            .collect();
        assert_eq!(
            found,
            vec![
                (TXE_POLL, USART_SR, 0x80, Some(0x80)),
                (RXNE_POLL, USART_SR, 0x20, Some(0x20)),
            ],
            "{default:?}"
        );
        assert_eq!(
            inference.bit_extract_models(),
            vec![bit_extract(TXE_POLL, 0x80), bit_extract(RXNE_POLL, 0x20)]
        );
        assert!(
            inference
                .loops
                .iter()
                .all(|found| found.not_a_poll.is_none()),
            "{default:?}"
        );
        // The transmit loop is found, then the receive loop behind it, then
        // a round that finds nothing new.
        assert_eq!(inference.rounds, 3, "{default:?}");
        // 32 bits of each status read; read from the input, each is checked
        // at every value of each byte's other bits as well.
        let checked = match default {
            MmioDefault::Zero => 0,
            MmioDefault::Passthrough => (128 - 1 - 7) + 3 * (256 - 1 - 8),
        };
        assert_eq!(inference.probes, 2 * (32 + checked), "{default:?}");
    }
}

#[test]
fn with_the_inferred_models_a_polled_line_reaches_the_parser_bug() {
    let image = image();
    let inference = infer_polling_models(
        &image,
        &config(MmioDefault::Passthrough, Vec::new()),
        &[vec![0; 4096]],
    )
    .unwrap();
    let input = polled_line(&overflowing_line());
    let mut machine = Machine::new(
        &image,
        config(MmioDefault::Passthrough, inference.bit_extract_models()),
    )
    .unwrap();
    let run = machine.run(&input);
    let Stop::Fault(fault) = &run.stop else {
        panic!("the line should smash the stack, not {:?}", run.stop);
    };
    assert_eq!(fault.class(), FaultClass::BadPc);
    assert_eq!(
        fault.pc, 0x4141_4140,
        "the return address came from the line"
    );
    assert_eq!(run.mmio_input, input.len(), "every byte was read");
    // A short field parses cleanly, and the input runs out at the transmit
    // poll of the reply.
    let run = machine.run(&polled_line(b"FUZZC\x02AB"));
    assert_eq!(
        run.stop,
        Stop::InputExhausted {
            pc: TXE_POLL,
            address: USART_SR
        }
    );
    let lines = image.symbol("lines").unwrap().address;
    assert_eq!(machine.read_memory(lines, 4).unwrap(), vec![1, 0, 0, 0]);
}

#[test]
fn without_bit_extract_models_the_same_line_never_reaches_the_parser() {
    let image = image();
    let input = polled_line(&overflowing_line());
    let lines = image.symbol("lines").unwrap().address;
    // Status read as zero: the first poll spins until the budget runs out.
    let mut zero = Machine::new(&image, config(MmioDefault::Zero, Vec::new())).unwrap();
    assert_eq!(zero.run(&input).stop, Stop::InstructionLimit);
    // Status read from the input, four bytes a poll: the line falls apart.
    let mut whole = Machine::new(&image, config(MmioDefault::Passthrough, Vec::new())).unwrap();
    let run = whole.run(&input);
    assert!(
        !matches!(run.stop, Stop::Fault(_)),
        "{:?} should not reach the overflow",
        run.stop
    );
    assert_eq!(
        whole.read_memory(lines, 4).unwrap(),
        vec![0; 4],
        "no line was parsed"
    );
}
