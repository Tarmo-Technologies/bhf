// SPDX-License-Identifier: Apache-2.0

//! The fault fixture (`tests/fixtures/faults.c`) faults in each class the
//! input selects: an invalid access, a bad PC, and a HardFault, and inputs
//! that do not fault run to the idle loop.

use rehost::{Fault, FaultClass, FaultKind, Image, InputBuffer, Machine, MachineConfig, Stop};
use std::path::PathBuf;

fn machine() -> Machine {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/faults.elf");
    let image = Image::elf(&std::fs::read(&path).unwrap()).unwrap();
    let symbol = |name: &str| image.symbol(name).unwrap().address;
    let config = MachineConfig {
        input: Some(InputBuffer {
            address: symbol("rx_buf"),
            capacity: 64,
            length_word: Some(symbol("rx_len")),
            inject_at: Some(symbol("main")),
        }),
        ..MachineConfig::default()
    };
    Machine::new(&image, config).unwrap()
}

/// "FUZZ", the command, and the address operand, little-endian.
fn record(command: u8, operand: Option<u32>) -> Vec<u8> {
    let mut input = b"FUZZ".to_vec();
    input.push(command);
    if let Some(operand) = operand {
        input.extend_from_slice(&operand.to_le_bytes());
    }
    input
}

fn fault(machine: &mut Machine, input: &[u8]) -> Fault {
    match machine.run(input).stop {
        Stop::Fault(fault) => fault,
        other => panic!("{input:?} should fault, the run stopped with {other:?}"),
    }
}

#[test]
fn stores_and_loads_outside_memory_are_invalid_accesses() {
    let mut machine = machine();
    let write = fault(&mut machine, &record(b'W', Some(0x6000_0000)));
    assert_eq!(write.class(), FaultClass::InvalidAccess);
    assert_eq!(write.kind, FaultKind::WriteUnmapped);
    assert_eq!(write.address, Some(0x6000_0000));
    assert_eq!(
        write.registers[0], 0x6000_0000,
        "copy_at's address argument"
    );
    let flash = fault(&mut machine, &record(b'W', Some(0x0800_0010)));
    assert_eq!(flash.kind, FaultKind::WriteReadOnly);
    assert_eq!(flash.pc, write.pc, "the same store in copy_at");
    let read = fault(&mut machine, &record(b'R', Some(0x7000_0000)));
    assert_eq!(
        (read.class(), read.kind, read.address),
        (
            FaultClass::InvalidAccess,
            FaultKind::ReadUnmapped,
            Some(0x7000_0000)
        )
    );
    // The same store to another unmapped address is the same finding.
    let elsewhere = fault(&mut machine, &record(b'W', Some(0x9000_0004)));
    assert_eq!(elsewhere.signature(), write.signature());
    assert_ne!(read.signature(), write.signature());
}

#[test]
fn stores_into_ram_and_peripherals_do_not_fault() {
    let mut machine = machine();
    for address in [0x2000_0100, 0x4001_1004, 0xe000_e010] {
        let run = machine.run(&record(b'W', Some(address)));
        assert!(
            matches!(run.stop, Stop::Idle { .. }),
            "{address:#x}: {:?}",
            run.stop
        );
    }
    assert!(matches!(machine.run(b"FUZQ").stop, Stop::Idle { .. }));
}

#[test]
fn calls_through_a_bad_pointer_are_bad_pcs_from_the_call_site() {
    let mut machine = machine();
    let peripheral = fault(&mut machine, &record(b'J', Some(0x4000_0001)));
    assert_eq!(peripheral.class(), FaultClass::BadPc);
    assert_eq!(peripheral.kind, FaultKind::FetchInvalid);
    assert_eq!(peripheral.pc, 0x4000_0000);
    let call_site = peripheral.from.expect("the branch that went there");
    let arm_state = fault(&mut machine, &record(b'J', Some(0x0800_0100)));
    assert_eq!(arm_state.kind, FaultKind::InvalidState);
    assert_eq!(arm_state.from, Some(call_site));
    let unmapped = fault(&mut machine, &record(b'J', Some(0x3000_0001)));
    assert_eq!(unmapped.signature(), peripheral.signature());
}

#[test]
fn undefined_instructions_and_trapped_division_are_hard_faults() {
    let mut machine = machine();
    let trap = fault(&mut machine, &record(b'U', None));
    assert_eq!(
        (trap.class(), trap.kind),
        (FaultClass::HardFault, FaultKind::Undefined)
    );
    let mut divide = record(b'D', None);
    divide.push(0);
    let zero = fault(&mut machine, &divide);
    assert_eq!(
        (zero.class(), zero.kind),
        (FaultClass::HardFault, FaultKind::DivideByZero)
    );
    divide[5] = 5;
    assert!(matches!(machine.run(&divide).stop, Stop::Idle { .. }));
}

#[test]
fn a_fault_replays_identically() {
    let mut machine = machine();
    let input = record(b'W', Some(0x6000_0000));
    let first = machine.run(&input);
    machine.run(b"FUZZ");
    let again = machine.run(&input);
    assert_eq!(first, again);
}
