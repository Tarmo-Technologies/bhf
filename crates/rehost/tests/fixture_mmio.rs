// SPDX-License-Identifier: Apache-2.0

//! The peripheral fixture firmware (`tests/fixtures/mmio.c`) takes its input
//! from a peripheral's data register, after checking its ID register. With
//! no models every peripheral register reads as zero and the ID check sends
//! it to sleep; a constant model for the ID register and an input-fed
//! (passthrough) model for the data register take it to its parser.

use rehost::{
    FaultKind, IdleReason, Image, Machine, MachineConfig, MmioAccess, MmioConfig, MmioDefault,
    MmioModel, MmioModelKind, Stop,
};
use std::path::PathBuf;

const PERIPH_ID: u32 = 0x4001_3000;
const PERIPH_DATA: u32 = 0x4001_3004;
const PERIPH_ID_VALUE: u32 = 0x4c31_a5c3;

fn image() -> Image {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mmio.elf");
    let bytes =
        std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    Image::elf(&bytes).unwrap()
}

fn symbol(image: &Image, name: &str) -> u32 {
    image
        .symbol(name)
        .unwrap_or_else(|| panic!("the fixture has no {name} symbol"))
        .address
}

fn word(machine: &mut Machine, address: u32) -> u32 {
    u32::from_le_bytes(machine.read_memory(address, 4).unwrap().try_into().unwrap())
}

fn models() -> Vec<MmioModel> {
    vec![
        MmioModel {
            address: PERIPH_ID,
            pc: None,
            kind: MmioModelKind::Constant {
                value: PERIPH_ID_VALUE,
            },
        },
        MmioModel {
            address: PERIPH_DATA,
            pc: None,
            kind: MmioModelKind::Passthrough,
        },
    ]
}

fn machine(image: &Image, mmio: MmioConfig) -> Machine {
    Machine::new(
        image,
        MachineConfig {
            mmio,
            ..MachineConfig::default()
        },
    )
    .unwrap()
}

fn modelled(image: &Image) -> Machine {
    machine(
        image,
        MmioConfig {
            models: models(),
            default: MmioDefault::Zero,
        },
    )
}

/// The length byte the firmware reads first, then the record.
fn stream(record: &[u8]) -> Vec<u8> {
    let mut bytes = vec![record.len() as u8];
    bytes.extend_from_slice(record);
    bytes
}

fn idle(machine: &mut Machine, input: &[u8]) -> usize {
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
    machine.edge_map().edges()
}

#[test]
fn without_models_the_id_check_fails_and_the_parser_is_never_reached() {
    let image = image();
    let state = symbol(&image, "state");
    let mut machine = machine(&image, MmioConfig::default());
    let empty = idle(&mut machine, b"");
    assert_eq!(word(&mut machine, state), 1, "the ID register read as zero");
    // Without a model the input reaches nothing: every run is the same.
    assert_eq!(idle(&mut machine, &stream(b"FUZZ")), empty);
    let run = machine.run(&stream(b"FUZZ"));
    assert_eq!(run.mmio_reads, 1, "only the ID register is read");
    assert_eq!(run.mmio_input, 0);
}

#[test]
fn a_constant_id_and_an_input_fed_data_register_reach_the_parser() {
    let image = image();
    let (state, result) = (symbol(&image, "state"), symbol(&image, "result"));
    let mut machine = modelled(&image);
    let mut counts = Vec::new();
    for (record, parsed) in [
        (&b""[..], 0),
        (b"F", 1),
        (b"FU", 2),
        (b"FUZ", 3),
        (b"FUZZ", 4),
    ] {
        let input = stream(record);
        counts.push(idle(&mut machine, &input));
        assert_eq!(word(&mut machine, state), 2, "{record:?} was parsed");
        assert_eq!(word(&mut machine, result), parsed, "{record:?}");
        let run = machine.run(&input);
        assert_eq!(run.mmio_input, input.len(), "{record:?}: every byte read");
        assert_eq!(run.mmio_reads, 2 + record.len() as u64, "{record:?}");
    }
    for pair in counts.windows(2) {
        assert!(
            pair[1] > pair[0],
            "each longer matching prefix reaches more edges: {counts:?}"
        );
    }
}

#[test]
fn the_input_fed_default_serves_every_register_no_model_names() {
    let image = image();
    let result = symbol(&image, "result");
    let mut machine = machine(
        &image,
        MmioConfig {
            models: models()[..1].to_vec(),
            default: MmioDefault::Passthrough,
        },
    );
    idle(&mut machine, &stream(b"FUZ"));
    assert_eq!(word(&mut machine, result), 3);
}

#[test]
fn a_model_for_one_instruction_wins_over_one_for_the_register() {
    let image = image();
    let result = symbol(&image, "result");
    // `ldrb r0, [r4, #4]` at 0x08000112 reads the length (`arm-none-eabi-
    // objdump -d mmio.elf`); the loop after it reads the record.
    let mut mmio = MmioConfig {
        models: models(),
        default: MmioDefault::Zero,
    };
    mmio.models.push(MmioModel {
        address: PERIPH_DATA,
        pc: Some(0x0800_0112),
        kind: MmioModelKind::Constant { value: 3 },
    });
    let mut machine = machine(&image, mmio);
    let run = machine.run(b"FUZZ");
    assert!(matches!(run.stop, Stop::Idle { .. }), "{:?}", run.stop);
    assert_eq!(run.mmio_input, 3, "the length came from the model");
    assert_eq!(word(&mut machine, result), 3, "the record is \"FUZ\"");
}

#[test]
fn a_run_that_wants_more_input_than_it_has_stops() {
    let image = image();
    let mut machine = modelled(&image);
    // The length says 10 bytes; 3 follow.
    let run = machine.run(b"\x0aFUZ");
    assert_eq!(
        run.stop,
        Stop::InputExhausted {
            pc: 0x0800_0128,
            address: PERIPH_DATA
        }
    );
    assert_eq!(run.stop.as_str(), "input_exhausted");
    assert_eq!(run.mmio_input, 4);
}

#[test]
fn an_out_of_bounds_record_faults_and_runs_the_same_on_a_new_machine() {
    let image = image();
    let table = symbol(&image, "table");
    let mut record = b"FUZZW".to_vec();
    record.extend_from_slice(&0x4000_0000u32.to_le_bytes());
    record.push(0x5a);
    let input = stream(&record);
    let mut machine = modelled(&image);
    let run = machine.run(&input);
    let Stop::Fault(fault) = &run.stop else {
        panic!("the record should fault, not {:?}", run.stop);
    };
    assert_eq!(fault.kind, FaultKind::WriteUnmapped);
    assert_eq!(fault.address, Some(table.wrapping_add(0x4000_0000)));
    // The same models on another machine reproduce the run exactly.
    let edges = machine.edge_map().counts().to_vec();
    let mut again = modelled(&image);
    assert_eq!(again.run(&input), run);
    assert_eq!(again.edge_map().counts(), edges.as_slice());
}

#[test]
fn a_recorded_trace_lists_each_peripheral_read() {
    let image = image();
    let mut machine = modelled(&image);
    assert!(machine.mmio_trace().is_empty());
    machine.trace_mmio(16);
    machine.run(&stream(b"FU"));
    let trace: Vec<(u32, u32, u8, u32, bool)> = machine
        .mmio_trace()
        .iter()
        .map(|access: &MmioAccess| {
            (
                access.pc,
                access.address,
                access.size,
                access.value,
                access.modelled,
            )
        })
        .collect();
    assert_eq!(
        trace,
        vec![
            (0x0800_0102, PERIPH_ID, 4, PERIPH_ID_VALUE, true),
            (0x0800_0112, PERIPH_DATA, 1, 2, true),
            (0x0800_0128, PERIPH_DATA, 1, u32::from(b'F'), true),
            (0x0800_0128, PERIPH_DATA, 1, u32::from(b'U'), true),
        ]
    );
    let instructions: Vec<u64> = machine
        .mmio_trace()
        .iter()
        .map(|access| access.instructions)
        .collect();
    assert!(
        instructions.windows(2).all(|pair| pair[0] < pair[1]),
        "{instructions:?}"
    );
    // The trace keeps at most its limit; a limit of zero stops recording.
    machine.trace_mmio(2);
    machine.run(&stream(b"FUZZ"));
    assert_eq!(machine.mmio_trace().len(), 2);
    machine.trace_mmio(0);
    machine.run(&stream(b"FUZZ"));
    assert!(machine.mmio_trace().is_empty());
}
