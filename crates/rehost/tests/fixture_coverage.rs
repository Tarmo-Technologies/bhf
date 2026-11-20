// SPDX-License-Identifier: Apache-2.0

//! The fixture firmware (`tests/fixtures/magic.c`, built by
//! `tests/fixtures/build.sh`) runs unmodified from its reset vector, and its
//! edge coverage grows as the input matches more of the record it parses.

use rehost::{IdleReason, Image, InputBuffer, Machine, MachineConfig, Stop};
use std::path::PathBuf;

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn symbol(image: &Image, name: &str) -> u32 {
    image
        .symbol(name)
        .unwrap_or_else(|| panic!("the fixture has no {name} symbol"))
        .address
}

/// The input goes into `rx_buf`, its length into `rx_len`, when `main` starts:
/// after the start-up code has cleared `.bss`.
fn machine(image: &Image, symbols: &Image) -> Machine {
    let config = MachineConfig {
        input: Some(InputBuffer {
            address: symbol(symbols, "rx_buf"),
            capacity: 64,
            length_word: Some(symbol(symbols, "rx_len")),
            inject_at: Some(symbol(symbols, "main")),
        }),
        ..MachineConfig::default()
    };
    Machine::new(image, config).unwrap()
}

fn edges(machine: &mut Machine, input: &[u8]) -> usize {
    let run = machine.run(input);
    assert!(
        matches!(
            run.stop,
            Stop::Idle {
                reason: IdleReason::WaitForInterrupt,
                ..
            }
        ),
        "{input:?} should end in main's wfi loop, not {:?}",
        run.stop
    );
    assert_eq!(run.input_delivered, Some(input.len().min(64)));
    machine.edge_map().edges()
}

#[test]
fn elf_fixture_coverage_grows_as_the_input_matches_more() {
    let image = Image::elf(&fixture("magic.elf")).unwrap();
    let mut machine = machine(&image, &image);
    let counts: Vec<usize> = ["", "F", "FU", "FUZ", "FUZZ", "FUZZa1234"]
        .iter()
        .map(|input| edges(&mut machine, input.as_bytes()))
        .collect();
    for pair in counts.windows(2) {
        assert!(
            pair[1] > pair[0],
            "each longer matching prefix reaches more edges: {counts:?}"
        );
    }
    // Inputs that leave the parser at the same check take the same edges.
    let mismatch = edges(&mut machine, b"X");
    assert_eq!(edges(&mut machine, b"Y"), mismatch);
    assert!(mismatch > counts[0], "a byte to compare is a block more");
    assert_eq!(
        edges(&mut machine, b"FX"),
        edges(&mut machine, b"FQ"),
        "both fail the second check"
    );
    // Each record kind runs a different arm of the parser's switch.
    let arms: Vec<Vec<u8>> = ["FUZZa1", "FUZZb1", "FUZZc1", "FUZZd1"]
        .iter()
        .map(|input| {
            edges(&mut machine, input.as_bytes());
            machine.edge_map().counts().to_vec()
        })
        .collect();
    for (index, arm) in arms.iter().enumerate() {
        for other in &arms[index + 1..] {
            assert_ne!(arm, other, "two record kinds took the same edges");
        }
    }
}

/// What `parse_record` in `magic.c` returns for `input`.
fn parse_record(input: &[u8]) -> u32 {
    let checksum = |bytes: &[u8]| -> u32 {
        const WEIGHTS: [u32; 4] = [3, 5, 7, 11];
        bytes.iter().enumerate().fold(0u32, |sum, (index, &byte)| {
            sum.wrapping_add(u32::from(byte) * WEIGHTS[index & 3] * 2)
        })
    };
    let input = &input[..input.len().min(64)];
    let prefix = b"FUZZ";
    let matched = input
        .iter()
        .zip(prefix)
        .take_while(|(byte, expected)| byte == expected)
        .count();
    if matched < 4 {
        return matched as u32;
    }
    match input.get(4) {
        Some(b'a') => checksum(&input[5..]) / 3,
        Some(b'b') => checksum(input) % 7,
        Some(b'c') => ((checksum(input) as i32) / -5) as u32,
        Some(b'd') => checksum(input) << 3,
        _ => 4,
    }
}

#[test]
fn the_firmware_computes_what_its_source_says() {
    let image = Image::elf(&fixture("magic.elf")).unwrap();
    let result = symbol(&image, "result");
    let mut machine = machine(&image, &image);
    let inputs: [&[u8]; 9] = [
        b"",
        b"FUQ",
        b"FUZZ",
        b"FUZZa0123456789",
        b"FUZZb\xff\xfe\xfd\xfc",
        b"FUZZc\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
        b"FUZZcabc",
        b"FUZZd\x80\x81\x82",
        b"FUZZe",
    ];
    for input in inputs {
        edges(&mut machine, input);
        let bytes = machine.read_memory(result, 4).unwrap();
        assert_eq!(
            u32::from_le_bytes(bytes.try_into().unwrap()),
            parse_record(input),
            "{input:?}"
        );
    }
}

#[test]
fn the_same_input_takes_the_same_edges_every_run() {
    let image = Image::elf(&fixture("magic.elf")).unwrap();
    let mut machine = machine(&image, &image);
    edges(&mut machine, b"FUZZd12345678");
    let first = machine.edge_map().counts().to_vec();
    edges(&mut machine, b"FUZZ");
    edges(&mut machine, b"FUZZd12345678");
    assert_eq!(machine.edge_map().counts(), first.as_slice());
}

#[test]
fn raw_fixture_at_its_flash_base_runs_like_the_elf() {
    let elf = Image::elf(&fixture("magic.elf")).unwrap();
    let raw = Image::raw(&fixture("magic.bin"), 0x0800_0000).unwrap();
    assert_eq!(raw.vector_table(), elf.vector_table());
    let mut from_elf = machine(&elf, &elf);
    let mut from_raw = machine(&raw, &elf);
    for input in ["", "FU", "FUZZb77", "FUZZc-5"] {
        let elf_edges = edges(&mut from_elf, input.as_bytes());
        let raw_edges = edges(&mut from_raw, input.as_bytes());
        assert_eq!(elf_edges, raw_edges, "{input:?}");
        assert_eq!(
            from_elf.edge_map().counts(),
            from_raw.edge_map().counts(),
            "{input:?}"
        );
    }
}

#[test]
fn an_input_written_at_reset_is_cleared_by_the_start_up_code() {
    // Written before the start-up code runs, the input lands in .bss and is
    // zeroed, so the parser never sees it: the reason for `inject_at`.
    let image = Image::elf(&fixture("magic.elf")).unwrap();
    let config = MachineConfig {
        input: Some(InputBuffer {
            address: symbol(&image, "rx_buf"),
            capacity: 64,
            length_word: Some(symbol(&image, "rx_len")),
            inject_at: None,
        }),
        ..MachineConfig::default()
    };
    let mut machine = Machine::new(&image, config).unwrap();
    let empty = edges(&mut machine, b"");
    assert_eq!(edges(&mut machine, b"FUZZa1"), empty);
}
