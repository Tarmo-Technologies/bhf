// SPDX-License-Identifier: Apache-2.0

//! The interrupt-driven UART fixture firmware (`tests/fixtures/irq.c`)
//! enables its receive interrupt and sleeps; only the interrupt handler
//! reads the UART and calls the frame parser. With no interrupts it never
//! reads a byte. With the schedule, each tick raises the receive interrupt
//! on a byte of the input, the handler takes the next byte of the frame
//! from the data register, and a frame with a wild offset reaches the
//! parser's unchecked store, in the handler.

use rehost::{
    FaultKind, IdleReason, Image, InterruptConfig, Machine, MachineConfig, MmioConfig, MmioDefault,
    Stop,
};
use std::path::PathBuf;

/// `wfi` in main, and the instruction after it, which an interrupt taken
/// there returns to (`arm-none-eabi-objdump -d irq.elf`).
const MAIN_WFI: u32 = 0x0800_01ca;
const AFTER_WFI: u32 = 0x0800_01cc;
/// `strb r2, [r3, #28]` in `parse_frame`: the table store.
const TABLE_STORE: u32 = 0x0800_0110;
/// USART1 is IRQ 37.
const USART1_EXCEPTION: u32 = 16 + 37;

fn image() -> Image {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/irq.elf");
    let bytes =
        std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    Image::elf(&bytes).unwrap()
}

/// Every unmodelled peripheral read takes the input; `interrupts` turns the
/// schedule on.
fn machine(image: &Image, interrupts: bool) -> Machine {
    let config = MachineConfig {
        max_instructions: 200_000,
        mmio: MmioConfig {
            models: Vec::new(),
            default: MmioDefault::Passthrough,
        },
        interrupts: interrupts.then(InterruptConfig::default),
        ..MachineConfig::default()
    };
    Machine::new(image, config).unwrap()
}

/// `bytes` as the firmware receives them: for each, the tick's byte (here
/// zero: the receive interrupt, the plain wait), the status register with
/// RXNE set, and the data register.
fn received(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .flat_map(|&byte| [0x00, 0x20, 0, 0, 0, byte, 0, 0, 0])
        .collect()
}

/// A "FUZZW" frame storing `value` at `offset` in the table, and its newline.
fn store_frame(offset: u32, value: u8) -> Vec<u8> {
    let mut frame = b"FUZZW".to_vec();
    frame.extend_from_slice(&offset.to_le_bytes());
    frame.push(value);
    frame.push(b'\n');
    frame
}

fn word(machine: &mut Machine, image: &Image, symbol: &str) -> u32 {
    let address = image.symbol(symbol).unwrap().address;
    let bytes = machine.read_memory(address, 4).unwrap();
    u32::from_le_bytes(bytes.try_into().unwrap())
}

#[test]
fn without_interrupts_the_firmware_sleeps_before_reading_a_byte() {
    let image = image();
    let mut machine = machine(&image, false);
    let run = machine.run(&received(&store_frame(0x0100_0001, 0x5a)));
    assert_eq!(
        run.stop,
        Stop::Idle {
            pc: MAIN_WFI,
            reason: IdleReason::WaitForInterrupt
        }
    );
    assert_eq!((run.mmio_reads, run.interrupts), (0, 0));
    assert_eq!(word(&mut machine, &image, "frames"), 0);
}

#[test]
fn each_tick_raises_the_receive_interrupt_and_its_handler_reads_a_byte() {
    let image = image();
    let mut machine = machine(&image, true);
    let run = machine.run(&received(b"FUZZQ\n"));
    // A tick for each byte, and one more with no input left: asleep.
    assert_eq!(
        run.stop,
        Stop::Idle {
            pc: MAIN_WFI,
            reason: IdleReason::WaitForInterrupt
        }
    );
    assert_eq!(run.interrupts, 6);
    assert_eq!((run.interrupt_input, run.mmio_input), (6, 48));
    assert_eq!(run.mmio_reads, 12, "status and data, six times");
    assert_eq!(word(&mut machine, &image, "frames"), 1);
    assert_eq!(word(&mut machine, &image, "last_command"), u32::from(b'Q'));
    let log = machine.interrupt_log();
    assert_eq!(log.len(), 6);
    for event in log {
        assert_eq!((event.exception, event.irq()), (USART1_EXCEPTION, Some(37)));
        assert_eq!(event.pc, AFTER_WFI, "taken as main sleeps");
    }
    // A status read without RXNE: the handler returns and reads no data.
    let mut input = vec![0x00, 0, 0, 0, 0];
    input.extend_from_slice(&received(b"\n"));
    let run = machine.run(&input);
    assert_eq!((run.interrupts, run.mmio_reads), (2, 3));
    assert_eq!(word(&mut machine, &image, "frames"), 1);
}

#[test]
fn a_wild_offset_in_a_received_frame_faults_in_the_interrupt_handler() {
    let image = image();
    let mut machine = machine(&image, true);
    let input = received(&store_frame(0x0100_0001, 0x5a));
    let run = machine.run(&input);
    let Stop::Fault(fault) = &run.stop else {
        panic!("{:?}", run.stop);
    };
    assert_eq!(fault.kind, FaultKind::WriteUnmapped);
    assert_eq!(fault.pc, TABLE_STORE);
    let table = image.symbol("table").unwrap().address;
    assert_eq!(fault.address, Some(table + 0x0100_0001));
    assert_eq!(fault.xpsr & 0x1ff, USART1_EXCEPTION, "in the handler");
    // An offset inside the table is clean, and the same frame never faults
    // with no interrupts.
    let run = machine.run(&received(&store_frame(1, 0x5a)));
    assert!(matches!(run.stop, Stop::Idle { .. }), "{:?}", run.stop);
    let run = self::machine(&image, false).run(&input);
    assert!(matches!(run.stop, Stop::Idle { .. }), "{:?}", run.stop);
}

#[test]
fn a_run_with_its_interrupt_schedule_repeats_on_a_new_machine() {
    let image = image();
    let input = received(&store_frame(0x0100_0001, 0x5a));
    let mut first = machine(&image, true);
    let once = first.run(&input);
    let edges = first.edge_map().counts().to_vec();
    let log = first.interrupt_log().to_vec();
    first.run(&received(b"FUZZQ\n"));
    assert_eq!(first.run(&input), once);
    let mut second = machine(&image, true);
    assert_eq!(second.run(&input), once);
    assert_eq!(second.edge_map().counts(), &edges[..]);
    assert_eq!(second.interrupt_log(), &log[..]);
}
