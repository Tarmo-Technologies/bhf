// SPDX-License-Identifier: Apache-2.0

//! Behaviour of the core on short programs. Each program is a raw image at
//! address 0: a vector table (stack 0x20001000, reset vector 0x41, and an
//! SVCall vector when the test names one), then the code at 0x40. The
//! encodings come from the GNU assembler for `-mcpu=cortex-m4`; each line's
//! comment is its address and disassembly.

use crate::{Execution, FaultKind, IdleReason, Image, Machine, MachineConfig, Stop};

/// alu_flags
const ALU_FLAGS: &[u16] = &[
    0x2000, // 0x0040: movs r0, #0
    0x3801, // 0x0042: subs r0, #1
    0x1c41, // 0x0044: adds r1, r0, #1
    0xf04f, 0x4200, // 0x0046: mov.w r2, #2147483648
    0x1e53, // 0x004a: subs r3, r2, #1
    0xbf30, // 0x004c: wfi
    0xbf00, // 0x004e: nop
];
/// it_block
const IT_BLOCK: &[u16] = &[
    0x2005, // 0x0040: movs r0, #5
    0x2805, // 0x0042: cmp r0, #5
    0xbf0c, // 0x0044: ite eq
    0x2101, // 0x0046: moveq r1, #1
    0x2102, // 0x0048: movne r1, #2
    0xbf18, // 0x004a: it ne
    0x2203, // 0x004c: movne r2, #3
    0x1803, // 0x004e: adds r3, r0, r0
    0x2400, // 0x0050: movs r4, #0
    0x2c01, // 0x0052: cmp r4, #1
    0xbf48, // 0x0054: it mi
    0x3401, // 0x0056: addmi r4, #1
    0xf3ef, 0x8500, // 0x0058: mrs r5, CPSR
    0xbf30, // 0x005c: wfi
    0xbf00, // 0x005e: nop
];
/// loads_stores
const LOADS_STORES: &[u16] = &[
    0x4808, // 0x0040: ldr r0, [pc, #32]
    0x4909, // 0x0042: ldr r1, [pc, #36]
    0x6001, // 0x0044: str r1, [r0, #0]
    0x7842, // 0x0046: ldrb r2, [r0, #1]
    0xf9b0, 0x3002, // 0x0048: ldrsh.w r3, [r0, #2]
    0x80c1, // 0x004c: strh r1, [r0, #6]
    0x6844, // 0x004e: ldr r4, [r0, #4]
    0xf850, 0x5b04, // 0x0050: ldr.w r5, [r0], #4
    0xf850, 0x6d04, // 0x0054: ldr.w r6, [r0, #-4]!
    0xe9d0, 0x7800, // 0x0058: ldrd r7, r8, [r0]
    0xb406, // 0x005c: push {r1, r2}
    0xe8bd, 0x0600, // 0x005e: ldmia.w sp!, {r9, sl}
    0xbf30, // 0x0062: wfi
    0x0100, 0x2000, // 0x0064: .word 0x20000100
    0x3344, 0x1122, // 0x0068: .word 0x11223344
];
/// calls
const CALLS: &[u16] = &[
    0x2000, // 0x0040: movs r0, #0
    0xf000, 0xf80c, // 0x0042: bl 5e <add_three>
    0xa107, // 0x0046: add r1, pc, #28
    0x3101, // 0x0048: adds r1, #1
    0x4788, // 0x004a: blx r1
    0x2202, // 0x004c: movs r2, #2
    0xe8df, 0xf002, // 0x004e: tbb [pc, r2]
    0x0000, // 0x0052: .short 0x0000
    0x0002, // 0x0054: .short 0x0002
    0x3064, // 0x0056: adds r0, #100
    0xb103, // 0x0058: cbz r3, 5c <done>
    0x2000, // 0x005a: movs r0, #0
    0xbf30, // 0x005c: wfi
    0xb500, // 0x005e: push {lr}
    0x3003, // 0x0060: adds r0, #3
    0xbd00, // 0x0062: pop {pc}
    0x3004, // 0x0064: adds r0, #4
    0x4770, // 0x0066: bx lr
];
/// svc_call
const SVC_CALL: &[u16] = &[
    0x2005, // 0x0040: movs r0, #5
    0xdf00, // 0x0042: svc 0
    0x3001, // 0x0044: adds r0, #1
    0xf3ef, 0x8605, // 0x0046: mrs r6, IPSR
    0xbf30, // 0x004a: wfi
    0x9900, // 0x004c: ldr r1, [sp, #0]
    0x310a, // 0x004e: adds r1, #10
    0x9100, // 0x0050: str r1, [sp, #0]
    0xf3ef, 0x8705, // 0x0052: mrs r7, IPSR
    0x46f0, // 0x0056: mov r8, lr
    0x4770, // 0x0058: bx lr
    0xbf00, // 0x005a: nop
];
/// bad_exc_return
const BAD_EXC_RETURN: &[u16] = &[
    0xdf00, // 0x0040: svc 0
    0xbf30, // 0x0042: wfi
    0xf06f, 0x000a, // 0x0044: mvn.w r0, #10
    0x4700, // 0x0048: bx r0
    0xbf00, // 0x004a: nop
];
/// read_unmapped
const READ_UNMAPPED: &[u16] = &[
    0xf04f, 0x5040, // 0x0040: mov.w r0, #805306368
    0x6801, // 0x0044: ldr r1, [r0, #0]
    0xbf00, // 0x0046: nop
];
/// write_read_only
const WRITE_READ_ONLY: &[u16] = &[
    0x2000, // 0x0040: movs r0, #0
    0x6000, // 0x0042: str r0, [r0, #0]
];
/// write_unmapped
const WRITE_UNMAPPED: &[u16] = &[
    0xf04f, 0x4010, // 0x0040: mov.w r0, #2415919104
    0x6000, // 0x0044: str r0, [r0, #0]
    0xbf00, // 0x0046: nop
];
/// fetch_invalid
const FETCH_INVALID: &[u16] = &[
    0x4800, // 0x0040: ldr r0, [pc, #0]
    0x4700, // 0x0042: bx r0
    0x0001, 0x4000, // 0x0044: .word 0x40000001
];
/// invalid_state
const INVALID_STATE: &[u16] = &[
    0xf44f, 0x7080, // 0x0040: mov.w r0, #256
    0x4700, // 0x0044: bx r0
    0xbf00, // 0x0046: nop
];
/// undefined
const UNDEFINED: &[u16] = &[
    0xde07, // 0x0040: udf #7
    0xbf00, // 0x0042: nop
];
/// unaligned_ldm
const UNALIGNED_LDM: &[u16] = &[
    0x4801, // 0x0040: ldr r0, [pc, #4]
    0xe890, 0x0006, // 0x0042: ldmia.w r0, {r1, r2}
    0x0000, // 0x0046: .short 0x0000
    0x0002, 0x2000, // 0x0048: .word 0x20000002
];
/// divide
const DIVIDE: &[u16] = &[
    0x2109, // 0x0040: movs r1, #9
    0x2200, // 0x0042: movs r2, #0
    0xfbb1, 0xf3f2, // 0x0044: udiv r3, r1, r2
    0x4803, // 0x0048: ldr r0, [pc, #12]
    0x6804, // 0x004a: ldr r4, [r0, #0]
    0xf044, 0x0410, // 0x004c: orr.w r4, r4, #16
    0x6004, // 0x0050: str r4, [r0, #0]
    0xfb91, 0xf5f2, // 0x0052: sdiv r5, r1, r2
    0x0000, // 0x0056: .short 0x0000
    0xed14, 0xe000, // 0x0058: .word 0xe000ed14
];
/// floating_point
const FLOATING_POINT: &[u16] = &[
    0x4801, // 0x0040: ldr r0, [pc, #4]
    0xee00, 0x1a10, // 0x0042: vmov s0, r1
    0x0000, // 0x0046: .short 0x0000
    0xed88, 0xe000, // 0x0048: .word 0xe000ed88
];
/// floating_point_enabled
const FLOATING_POINT_ENABLED: &[u16] = &[
    0x4802, // 0x0040: ldr r0, [pc, #8]
    0xf44f, 0x0170, // 0x0042: mov.w r1, #15728640
    0x6001, // 0x0046: str r1, [r0, #0]
    0xee00, 0x1a10, // 0x0048: vmov s0, r1
    0xed88, 0xe000, // 0x004c: .word 0xe000ed88
];
/// breakpoint
const BREAKPOINT: &[u16] = &[
    0xbe01, // 0x0040: bkpt 0x0001
    0xbf00, // 0x0042: nop
];
/// escalation
const ESCALATION: &[u16] = &[
    0xb672, // 0x0040: cpsid i
    0xdf00, // 0x0042: svc 0
];
/// branch_to_self
const BRANCH_TO_SELF: &[u16] = &[
    0x2001, // 0x0040: movs r0, #1
    0xe7fe, // 0x0042: b.n 42 <loop>
];
/// wait_for_event
const WAIT_FOR_EVENT: &[u16] = &[
    0xbf40, // 0x0040: sev
    0xbf20, // 0x0042: wfe
    0x2001, // 0x0044: movs r0, #1
    0xbf20, // 0x0046: wfe
];
/// semihosting
const SEMIHOSTING: &[u16] = &[
    0x2004, // 0x0040: movs r0, #4
    0xa102, // 0x0042: add r1, pc, #8
    0xbeab, // 0x0044: bkpt 0x00ab
    0x2018, // 0x0046: movs r0, #24
    0x4901, // 0x0048: ldr r1, [pc, #4]
    0xbeab, // 0x004a: bkpt 0x00ab
    0x6968, 0x000a, // 0x004c: .word 0x000a6968
    0x0026, 0x0002, // 0x0050: .word 0x00020026
];
/// semihosting_full_output
const SEMIHOSTING_FULL_OUTPUT: &[u16] = &[
    0x490b, // 0x0040: ldr r1, [pc, #44]
    0x2005, // 0x0042: movs r0, #5
    0xbeab, // 0x0044: bkpt 0x00ab
    0x490b, // 0x0046: ldr r1, [pc, #44]
    0x2005, // 0x0048: movs r0, #5
    0xbeab, // 0x004a: bkpt 0x00ab
    0x2004, // 0x004c: movs r0, #4
    0xf04f, 0x5140, // 0x004e: mov.w r1, #805306368
    0xbeab, // 0x0052: bkpt 0x00ab
    0xbf30, // 0x0054: wfi
    0xbf00, // 0x0056: nop
    0x0001, 0x0000, // 0x0058: .word 0x00000001
    0x0000, 0x2000, // 0x005c: .word 0x20000000
    0x0000, 0x0001, // 0x0060: .word 0x00010000
    0x0001, 0x0000, // 0x0064: .word 0x00000001
    0x0000, 0x3000, // 0x0068: .word 0x30000000
    0xffff, 0xffff, // 0x006c: .word 0xffffffff
    0x0058, 0x0000, // 0x0070: .word 0x00000058
    0x0064, 0x0000, // 0x0074: .word 0x00000064
];
/// system_reset
const SYSTEM_RESET: &[u16] = &[
    0x4801, // 0x0040: ldr r0, [pc, #4]
    0x4902, // 0x0042: ldr r1, [pc, #8]
    0x6001, // 0x0044: str r1, [r0, #0]
    0x0000, // 0x0046: .short 0x0000
    0xed0c, 0xe000, // 0x0048: .word 0xe000ed0c
    0x0004, 0x05fa, // 0x004c: .word 0x05fa0004
];
/// simd
const SIMD: &[u16] = &[
    0xfa81, 0xf042, // 0x0040: uadd8 r0, r1, r2
];
/// system_registers
const SYSTEM_REGISTERS: &[u16] = &[
    0x4806, // 0x0040: ldr r0, [pc, #24]
    0x6801, // 0x0042: ldr r1, [r0, #0]
    0x4806, // 0x0044: ldr r0, [pc, #24]
    0x6001, // 0x0046: str r1, [r0, #0]
    0x6802, // 0x0048: ldr r2, [r0, #0]
    0x4806, // 0x004a: ldr r0, [pc, #24]
    0x2301, // 0x004c: movs r3, #1
    0x6003, // 0x004e: str r3, [r0, #0]
    0x4c05, // 0x0050: ldr r4, [pc, #20]
    0x6825, // 0x0052: ldr r5, [r4, #0]
    0x6806, // 0x0054: ldr r6, [r0, #0]
    0x4805, // 0x0056: ldr r0, [pc, #20]
    0x6807, // 0x0058: ldr r7, [r0, #0]
    0xbf30, // 0x005a: wfi
    0xed00, 0xe000, // 0x005c: .word 0xe000ed00
    0x1004, 0x4001, // 0x0060: .word 0x40011004
    0x200c, 0x2200, // 0x0064: .word 0x2200200c
    0x0100, 0x2000, // 0x0068: .word 0x20000100
    0x1004, 0xe000, // 0x006c: .word 0xe0001004
];
/// relocated_vectors
const RELOCATED_VECTORS: &[u16] = &[
    0xf04f, 0x5000, // 0x0040: mov.w r0, #536870912
    0xa103, // 0x0044: add r1, pc, #12
    0x3101, // 0x0046: adds r1, #1
    0x62c1, // 0x0048: str r1, [r0, #44]
    0x4a03, // 0x004a: ldr r2, [pc, #12]
    0x6010, // 0x004c: str r0, [r2, #0]
    0xdf00, // 0x004e: svc 0
    0xbf30, // 0x0050: wfi
    0xbf00, // 0x0052: nop
    0x252a, // 0x0054: movs r5, #42
    0x4770, // 0x0056: bx lr
    0xed08, 0xe000, // 0x0058: .word 0xe000ed08
];
/// branch_not_taken
const BRANCH_NOT_TAKEN: &[u16] = &[
    0x2001, // 0x0040: movs r0, #1
    0x4288, // 0x0042: cmp r0, r1
    0xd000, // 0x0044: beq.n 48 <skip>
    0x2201, // 0x0046: movs r2, #1
    0xbf30, // 0x0048: wfi
    0xbf00, // 0x004a: nop
];

fn image(code: &[u16], svc_handler: Option<u32>) -> Image {
    let mut bytes = vec![0u8; 0x40];
    bytes[..4].copy_from_slice(&0x2000_1000u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&0x41u32.to_le_bytes());
    if let Some(handler) = svc_handler {
        bytes[44..48].copy_from_slice(&(handler | 1).to_le_bytes());
    }
    for halfword in code {
        bytes.extend_from_slice(&halfword.to_le_bytes());
    }
    Image::raw(&bytes, 0).unwrap()
}

fn execute_with(code: &[u16], svc_handler: Option<u32>) -> (Machine, Execution) {
    let mut machine = Machine::new(&image(code, svc_handler), MachineConfig::default()).unwrap();
    let run = machine.run(&[]);
    (machine, run)
}

fn execute(code: &[u16]) -> (Machine, Execution) {
    execute_with(code, None)
}

fn fault_of(run: &Execution) -> &crate::Fault {
    match &run.stop {
        Stop::Fault(fault) => fault,
        other => panic!("expected a fault, the run stopped with {other:?}"),
    }
}

fn idle_at(pc: u32) -> Stop {
    Stop::Idle {
        pc,
        reason: IdleReason::WaitForInterrupt,
    }
}

#[test]
fn arithmetic_sets_the_flags() {
    let (machine, run) = execute(ALU_FLAGS);
    assert_eq!(run.stop, idle_at(0x4c));
    let core = &machine.core;
    assert_eq!(core.r[..4], [0xffff_ffff, 0, 0x8000_0000, 0x7fff_ffff]);
    assert_eq!((core.n, core.z, core.c, core.v), (false, false, true, true));
    assert_eq!(run.instructions, 5);
}

#[test]
fn it_blocks_select_instructions_and_keep_the_flags_inside() {
    let (machine, run) = execute(IT_BLOCK);
    assert_eq!(run.stop, idle_at(0x5c));
    let core = &machine.core;
    assert_eq!(core.r[1], 1, "the then arm ran");
    assert_eq!(core.r[2], 0, "the skipped instruction did not");
    assert_eq!(core.r[3], 10);
    assert_eq!(core.r[4], 1, "addmi ran");
    assert_eq!(
        core.r[5] & 0xf000_0000,
        0x8000_0000,
        "a 16-bit add inside an IT block leaves cmp's flags"
    );
    assert_eq!(run.blocks, 4, "every IT block ends a basic block");
}

#[test]
fn loads_and_stores_address_memory_as_encoded() {
    let (machine, run) = execute(LOADS_STORES);
    assert_eq!(run.stop, idle_at(0x62));
    let r = &machine.core.r;
    assert_eq!(r[0], 0x2000_0100, "post-index then pre-index writeback");
    assert_eq!(r[2], 0x33);
    assert_eq!(r[3], 0x1122);
    assert_eq!(r[4], 0x3344_0000);
    assert_eq!((r[5], r[6]), (0x1122_3344, 0x1122_3344));
    assert_eq!((r[7], r[8]), (0x1122_3344, 0x3344_0000));
    assert_eq!((r[9], r[10]), (0x1122_3344, 0x33));
    assert_eq!(r[13], 0x2000_1000, "push and pop balance");
}

#[test]
fn calls_returns_and_table_branches_follow_the_code() {
    let (machine, run) = execute(CALLS);
    assert_eq!(run.stop, idle_at(0x5c));
    assert_eq!(machine.core.r[0], 3 + 4 + 100);
    assert_eq!(machine.core.r[13], 0x2000_1000);
}

#[test]
fn svc_enters_the_handler_on_the_main_stack_and_returns() {
    let (machine, run) = execute_with(SVC_CALL, Some(0x4c));
    assert_eq!(run.stop, idle_at(0x4a));
    let core = &machine.core;
    assert_eq!(core.r[0], 16, "the handler changed the stacked r0");
    assert_eq!(core.r[7], 11, "IPSR in the handler is SVCall");
    assert_eq!(
        core.r[8], 0xffff_fff9,
        "EXC_RETURN: thread mode, main stack"
    );
    assert_eq!(core.r[6], 0, "back in thread mode");
    assert_eq!(core.r[13], 0x2000_1000);
}

#[test]
fn an_invalid_exception_return_faults() {
    let (_, run) = execute_with(BAD_EXC_RETURN, Some(0x44));
    let fault = fault_of(&run);
    assert_eq!(fault.kind, FaultKind::InvalidExceptionReturn);
    assert_eq!((fault.pc, fault.address), (0x48, Some(0xffff_fff5)));
}

#[test]
fn accesses_outside_memory_fault_with_the_address() {
    for (code, kind, pc, address) in [
        (READ_UNMAPPED, FaultKind::ReadUnmapped, 0x44, 0x3000_0000),
        (WRITE_READ_ONLY, FaultKind::WriteReadOnly, 0x42, 0),
        (WRITE_UNMAPPED, FaultKind::WriteUnmapped, 0x44, 0x9000_0000),
        (UNALIGNED_LDM, FaultKind::Unaligned, 0x42, 0x2000_0002),
    ] {
        let (_, run) = execute(code);
        let fault = fault_of(&run);
        assert_eq!(fault.kind, kind);
        assert_eq!((fault.pc, fault.address), (pc, Some(address)), "{kind:?}");
        assert_eq!(fault.registers[15], pc);
    }
}

#[test]
fn branches_to_where_no_code_runs_fault_with_their_source() {
    let (_, run) = execute(FETCH_INVALID);
    let fault = fault_of(&run);
    assert_eq!(fault.kind, FaultKind::FetchInvalid);
    assert_eq!(
        (fault.pc, fault.address, fault.from),
        (0x4000_0000, Some(0x4000_0000), Some(0x42))
    );
    let (_, run) = execute(INVALID_STATE);
    let fault = fault_of(&run);
    assert_eq!(fault.kind, FaultKind::InvalidState);
    assert_eq!((fault.pc, fault.from), (0x100, Some(0x44)));
}

#[test]
fn hard_fault_causes_stop_the_run() {
    for (code, kind, pc) in [
        (UNDEFINED, FaultKind::Undefined, 0x40),
        (BREAKPOINT, FaultKind::Breakpoint, 0x40),
        (ESCALATION, FaultKind::Escalation, 0x42),
        (FLOATING_POINT, FaultKind::NoCoprocessor, 0x42),
    ] {
        let (_, run) = execute(code);
        let fault = fault_of(&run);
        assert_eq!((fault.kind, fault.pc), (kind, pc));
    }
}

#[test]
fn encodings_the_architecture_leaves_undefined_fault() {
    // Each takes a HardFault on QEMU's Cortex-M4 (mps2-an386) too.
    let undefined: &[&[u16]] = &[
        // Unallocated miscellaneous 16-bit encodings (A5.2.5).
        &[0xb600],
        &[0xb620],
        &[0xb650],
        &[0xb680],
        &[0xb700],
        &[0xb7e0],
        &[0xb800],
        &[0xb8e0],
        &[0xba80],
        &[0xbaa0],
        // Unallocated long multiply and divide encodings (A5.3.17).
        &[0xfb81, 0x3412],
        &[0xfbc1, 0x3412],
        &[0xfbc1, 0x34e2],
        &[0xfbd1, 0x3402],
        &[0xfbd1, 0x3482],
        &[0xfbe1, 0x3412],
        &[0xfbf1, 0x3402],
        // Multiply (A5.3.16): unallocated op1/op2, and bits [7:6] not 00.
        &[0xfb01, 0x0322],
        &[0xfb21, 0x0322],
        &[0xfb71, 0x0312],
        &[0xfb01, 0x03c2],
        &[0xfb01, 0x0342],
        // Data processing (register), A5.3.12: unallocated parallel
        // add/subtract, and bits [15:12] not 1111.
        &[0xfab1, 0xf302],
        &[0xfaf1, 0xf302],
        &[0xfa91, 0xf332],
        &[0xfa01, 0x0302],
        &[0xfa91, 0xe302],
        // Op 0110 is PKHBT/PKHTB only as a shifted-register encoding with S
        // clear: as a modified immediate, or with S set, it is unallocated.
        &[0xf0c1, 0x0301],
        &[0xead1, 0x0302],
    ];
    for code in undefined {
        let (_, run) = execute(code);
        match &run.stop {
            Stop::Fault(fault) => assert_eq!(
                (fault.kind, fault.pc),
                (FaultKind::Undefined, 0x40),
                "{code:04x?}"
            ),
            other => panic!("{code:04x?} stopped with {other:?}, not a fault"),
        }
    }
}

#[test]
fn division_by_zero_is_zero_unless_ccr_traps_it() {
    let (machine, run) = execute(DIVIDE);
    assert_eq!(machine.core.r[3], 0, "udiv by zero without the trap");
    let fault = fault_of(&run);
    assert_eq!((fault.kind, fault.pc), (FaultKind::DivideByZero, 0x52));
}

#[test]
fn instructions_outside_the_model_are_reported_as_unsupported() {
    let (_, run) = execute(FLOATING_POINT_ENABLED);
    assert_eq!(
        run.stop,
        Stop::Unsupported {
            pc: 0x48,
            encoding: 0xee00_1a10,
            what: "floating-point instruction"
        }
    );
    let (_, run) = execute(SIMD);
    assert!(
        matches!(run.stop, Stop::Unsupported { pc: 0x40, .. }),
        "{:?}",
        run.stop
    );
    // The M4's DSP multiplies, packing and parallel arithmetic.
    for code in [
        [0xfbc1, 0x3482], // smlalbb r3, r4, r1, r2
        [0xfbc1, 0x34c2], // smlald r3, r4, r1, r2
        [0xfbd1, 0x34c2], // smlsld r3, r4, r1, r2
        [0xfb21, 0x0302], // smlad r3, r1, r2, r0
        [0xfb41, 0x0302], // smlsd r3, r1, r2, r0
        [0xfb71, 0x0302], // usada8 r3, r1, r2, r0
        [0xfb71, 0xf302], // usad8 r3, r1, r2
        [0xeac1, 0x0302], // pkhbt r3, r1, r2
        [0xfa91, 0xf302], // sadd16 r3, r1, r2
        [0xfac1, 0xf362], // uhsub8 r3, r1, r2
        [0xfa2f, 0xf382], // sxtb16 r3, r2
    ] {
        let (_, run) = execute(&code);
        assert!(
            matches!(run.stop, Stop::Unsupported { pc: 0x40, .. }),
            "{code:04x?}: {:?}",
            run.stop
        );
    }
}

#[test]
fn idle_loops_end_the_run() {
    let (_, run) = execute(BRANCH_TO_SELF);
    assert_eq!(
        run.stop,
        Stop::Idle {
            pc: 0x42,
            reason: IdleReason::BranchToSelf
        }
    );
    let (machine, run) = execute(WAIT_FOR_EVENT);
    assert_eq!(machine.core.r[0], 1, "the first wfe consumed the event");
    assert_eq!(
        run.stop,
        Stop::Idle {
            pc: 0x46,
            reason: IdleReason::WaitForEvent
        }
    );
}

#[test]
fn semihosting_writes_output_and_exits() {
    let (_, run) = execute(SEMIHOSTING);
    assert_eq!(run.output, b"hi\n");
    assert_eq!(run.stop, Stop::SemihostingExit { code: 0 });
}

#[test]
fn semihosting_writes_stop_reading_once_the_output_is_full() {
    // The first SYS_WRITE fills the 64 KiB output from RAM. The SYS_WRITE
    // and SYS_WRITE0 after it name an unmapped buffer: a write that has no
    // room left reads nothing, so neither faults and the run reaches `wfi`.
    let (_, run) = execute(SEMIHOSTING_FULL_OUTPUT);
    assert_eq!(run.stop, idle_at(0x54));
    assert_eq!(run.output.len(), 64 * 1024);
}

#[test]
fn a_system_reset_request_ends_the_run() {
    let (_, run) = execute(SYSTEM_RESET);
    assert_eq!(run.stop, Stop::SystemReset { pc: 0x44 });
}

#[test]
fn system_registers_peripherals_and_bit_band_behave() {
    let (machine, run) = execute(SYSTEM_REGISTERS);
    assert_eq!(run.stop, idle_at(0x5a));
    let r = &machine.core.r;
    assert_eq!(r[1], 0x410f_c241, "CPUID is a Cortex-M4");
    assert_eq!(r[2], 0, "a peripheral register reads as zero");
    assert_eq!(r[5], 1 << 3, "the bit-band write set bit 3 of 0x20000100");
    assert_eq!(r[6], 1, "the alias reads the bit back");
    assert_eq!(r[7], 12, "DWT_CYCCNT counts instructions");
}

#[test]
fn svc_uses_the_vector_table_vtor_names() {
    let (machine, run) = execute(RELOCATED_VECTORS);
    assert_eq!(run.stop, idle_at(0x50));
    assert_eq!(machine.core.r[5], 42);
}

#[test]
fn a_conditional_branch_ends_a_block_taken_or_not() {
    let (not_taken, run) = execute(BRANCH_NOT_TAKEN);
    assert_eq!(run.blocks, 2);
    // `cmp r0, r0` (0x4280) in place of `cmp r0, r1`: the branch is taken.
    let mut code = BRANCH_NOT_TAKEN.to_vec();
    code[1] = 0x4280;
    let (taken, run) = execute(&code);
    assert_eq!(run.blocks, 2);
    assert_eq!(taken.edge_map().edges(), 2);
    assert_eq!(not_taken.edge_map().edges(), 2);
    assert_ne!(
        taken.edge_map().counts(),
        not_taken.edge_map().counts(),
        "the two sides of the branch are different edges"
    );
}
