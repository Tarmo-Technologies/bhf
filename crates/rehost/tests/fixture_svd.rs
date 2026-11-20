// SPDX-License-Identifier: Apache-2.0

//! Peripheral windows from CMSIS-SVD device descriptions. A vendor's file
//! (`tests/fixtures/ARM_Example.svd`, Arm's CMSIS example) and the fixture
//! part's (`tests/fixtures/irq.svd`) give each peripheral's address blocks
//! as windows; with them only those addresses are peripheral registers, so
//! a load or store between peripherals is an invalid access rather than a
//! read the default model answers.

use rehost::{
    BlockUsage, FaultKind, Image, InputBuffer, InterruptConfig, Machine, MachineConfig, MmioConfig,
    MmioDefault, MmioModel, MmioModelKind, PeripheralWindow, SetupError, Stop, Svd,
};
use std::path::PathBuf;

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn svd(name: &str) -> Svd {
    Svd::parse(&String::from_utf8(fixture(name)).unwrap()).unwrap()
}

fn window(name: &str, base: u32, size: u32) -> PeripheralWindow {
    PeripheralWindow {
        name: name.to_owned(),
        base,
        size,
    }
}

#[test]
fn a_vendor_svd_gives_each_peripherals_address_block_as_a_window() {
    let svd = svd("ARM_Example.svd");
    assert_eq!(svd.device.as_deref(), Some("ARM_Example"));
    let names: Vec<&str> = svd.peripherals.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["TIMER0", "TIMER1", "TIMER2"]);
    // TIMER1 and TIMER2 are derived from TIMER0 and inherit its block.
    let timer1 = &svd.peripherals[1];
    assert_eq!(timer1.derived_from.as_deref(), Some("TIMER0"));
    assert_eq!(timer1.base, 0x4001_0100);
    assert_eq!(timer1.blocks.len(), 1);
    assert_eq!((timer1.blocks[0].offset, timer1.blocks[0].size), (0, 0x100));
    assert_eq!(timer1.blocks[0].usage, BlockUsage::Registers);
    // Each has its own interrupt.
    let interrupts: Vec<(&str, u32)> = svd
        .peripherals
        .iter()
        .flat_map(|p| p.interrupts.iter())
        .map(|interrupt| (interrupt.name.as_str(), interrupt.value))
        .collect();
    assert_eq!(interrupts, [("TIMER0", 0), ("TIMER1", 4), ("TIMER2", 6)]);
    assert_eq!(svd.interrupt_name(4), Some("TIMER1"));
    assert_eq!(svd.interrupt_name(5), None);
    assert_eq!(
        svd.windows(),
        [
            window("TIMER0", 0x4001_0000, 0x100),
            window("TIMER1", 0x4001_0100, 0x100),
            window("TIMER2", 0x4001_0200, 0x100),
        ]
    );
    assert!(svd.unplaced().is_empty());
}

#[test]
fn derived_peripherals_arrays_and_reserved_blocks_give_their_windows() {
    let svd = svd("irq.svd");
    assert_eq!(svd.device.as_deref(), Some("WIDGET_M4"));
    // TIM%s with dimIndex 2,3 is TIM2 and TIM3, 0x400 apart; CRC's reserved
    // block is no window; the System Control Block is the core's own.
    assert_eq!(
        svd.windows(),
        [
            window("TIM2", 0x4000_0000, 0x400),
            window("TIM3", 0x4000_0400, 0x400),
            window("USART2", 0x4000_4400, 0x400),
            window("USART1", 0x4001_1000, 0x400),
            window("CRC", 0x4002_3000, 4),
        ]
    );
    assert_eq!(svd.interrupt_name(37), Some("USART1"));
    assert_eq!(svd.interrupt_name(38), Some("USART2"));
}

/// The fault fixture (`faults.c`), its input in `rx_buf` at `main`, with
/// the windows `windows` (or the whole peripheral region).
fn faults(windows: Option<Vec<PeripheralWindow>>) -> (Image, MachineConfig) {
    let image = Image::elf(&fixture("faults.elf")).unwrap();
    let config = MachineConfig {
        input: Some(InputBuffer {
            address: image.symbol("rx_buf").unwrap().address,
            capacity: 64,
            length_word: Some(image.symbol("rx_len").unwrap().address),
            inject_at: Some(image.symbol("main").unwrap().address),
        }),
        peripheral_windows: windows,
        ..MachineConfig::default()
    };
    (image, config)
}

/// "FUZZ", the command byte, and a little-endian address.
fn record(command: u8, address: u32) -> Vec<u8> {
    let mut bytes = b"FUZZ".to_vec();
    bytes.push(command);
    bytes.extend_from_slice(&address.to_le_bytes());
    bytes
}

fn stop(config: &MachineConfig, image: &Image, input: &[u8]) -> Stop {
    Machine::new(image, config.clone()).unwrap().run(input).stop
}

fn fault_kind(stop: &Stop) -> Option<(FaultKind, Option<u32>)> {
    match stop {
        Stop::Fault(fault) => Some((fault.kind, fault.address)),
        _ => None,
    }
}

#[test]
fn with_svd_windows_an_access_between_peripherals_is_an_invalid_access() {
    let (image, guessed) = faults(None);
    let (_, described) = faults(Some(svd("irq.svd").windows()));
    let between = record(b'R', 0x4002_0000);
    // Guessed, the whole region is registers, and the read is zero.
    assert!(matches!(
        stop(&guessed, &image, &between),
        Stop::Idle { .. }
    ));
    assert_eq!(
        fault_kind(&stop(&described, &image, &between)),
        Some((FaultKind::ReadUnmapped, Some(0x4002_0000)))
    );
    // A register the SVD names still reads through the models.
    let data = record(b'R', 0x4001_1004);
    assert!(matches!(stop(&described, &image, &data), Stop::Idle { .. }));
    // CRC's first word is a register; the rest of its block is reserved.
    assert!(matches!(
        stop(&described, &image, &record(b'W', 0x4002_3000)),
        Stop::Idle { .. }
    ));
    assert_eq!(
        fault_kind(&stop(&described, &image, &record(b'W', 0x4002_3008))),
        Some((FaultKind::WriteUnmapped, Some(0x4002_3008)))
    );
    // Past the region the SVD names nothing either way.
    assert_eq!(
        fault_kind(&stop(&guessed, &image, &record(b'R', 0x6000_0000))),
        Some((FaultKind::ReadUnmapped, Some(0x6000_0000)))
    );
}

#[test]
fn the_peripheral_bit_band_alias_follows_the_windows() {
    let (image, described) = faults(Some(svd("irq.svd").windows()));
    // 0x42220000 is bit 0 of 0x40011000 (USART1's status register);
    // 0x42400000 is bit 0 of 0x40020000, which no peripheral holds.
    assert!(matches!(
        stop(&described, &image, &record(b'W', 0x4222_0000)),
        Stop::Idle { .. }
    ));
    assert_eq!(
        fault_kind(&stop(&described, &image, &record(b'W', 0x4240_0000))),
        Some((FaultKind::WriteUnmapped, Some(0x4240_0000)))
    );
}

#[test]
fn a_model_outside_the_windows_is_refused() {
    let (image, mut config) = faults(Some(svd("irq.svd").windows()));
    let model = |address| MmioModel {
        address,
        pc: None,
        kind: MmioModelKind::Passthrough,
    };
    config.mmio = MmioConfig {
        models: vec![model(0x4001_1004)],
        default: MmioDefault::Zero,
    };
    assert!(Machine::new(&image, config.clone()).is_ok());
    config.mmio.models.push(model(0x4002_0000));
    let error = Machine::new(&image, config).err().unwrap();
    assert_eq!(
        error,
        SetupError::MmioOutsideWindows {
            address: 0x4002_0000
        }
    );
    assert!(error.to_string().contains("peripheral windows"), "{error}");
}

#[test]
fn setup_refuses_an_empty_window_or_one_past_the_address_space() {
    let (image, mut config) = faults(None);
    for bad in [
        window("EMPTY", 0x4000_0000, 0),
        window("WRAP", 0xffff_ff00, 0x200),
    ] {
        config.peripheral_windows = Some(vec![bad.clone()]);
        assert_eq!(
            Machine::new(&image, config.clone()).err(),
            Some(SetupError::BadPeripheralWindow {
                name: bad.name,
                base: bad.base,
                size: bad.size
            })
        );
    }
}

#[test]
fn the_interrupt_driven_fixture_runs_the_same_inside_its_svd_windows() {
    let image = Image::elf(&fixture("irq.elf")).unwrap();
    let config = |windows: Option<Vec<PeripheralWindow>>| MachineConfig {
        max_instructions: 200_000,
        mmio: MmioConfig {
            models: Vec::new(),
            default: MmioDefault::Passthrough,
        },
        peripheral_windows: windows,
        interrupts: Some(InterruptConfig::default()),
        ..MachineConfig::default()
    };
    let mut frame = b"FUZZW".to_vec();
    frame.extend_from_slice(&0x0100_0001u32.to_le_bytes());
    frame.extend_from_slice(b"Z\n");
    let input: Vec<u8> = frame
        .iter()
        .flat_map(|&byte| [0x00, 0x20, 0, 0, 0, byte, 0, 0, 0])
        .collect();
    let guessed = Machine::new(&image, config(None)).unwrap().run(&input);
    let described = Machine::new(&image, config(Some(svd("irq.svd").windows())))
        .unwrap()
        .run(&input);
    assert!(matches!(guessed.stop, Stop::Fault(_)), "{:?}", guessed.stop);
    assert_eq!(described, guessed);
}
