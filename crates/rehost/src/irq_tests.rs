// SPDX-License-Identifier: Apache-2.0

//! Interrupts on short programs. Each program is a raw image at address 0:
//! a vector table of 32 entries (stack 0x20001000, reset vector 0x81, and
//! the handlers the test names), then the code at 0x80. The encodings come
//! from the GNU assembler for `-mcpu=cortex-m4`; each line's comment is its
//! address and disassembly.

use crate::{
    Execution, FaultKind, IdleReason, Image, InterruptConfig, Machine, MachineConfig, Stop,
    DEFAULT_INTERRUPT_INTERVAL,
};

/// Enable IRQ 0 with interrupts masked, sleep, then unmask.
const MASKED_WAKE: &[u16] = &[
    0x4805, // 0x0080: ldr r0, [pc, #20]   (0xe000e100, NVIC_ISER0)
    0x2101, // 0x0082: movs r1, #1
    0xb672, // 0x0084: cpsid i
    0x6001, // 0x0086: str r1, [r0, #0]
    0xbf30, // 0x0088: wfi
    0x4623, // 0x008a: mov r3, r4
    0xb662, // 0x008c: cpsie i
    0xbf00, // 0x008e: nop
    0xbf30, // 0x0090: wfi
    0xe7fe, // 0x0092: b.n 92 <done>
    0x3401, // 0x0094: irq0: adds r4, #1
    0x4770, // 0x0096: bx lr
    0xe100, 0xe000, // 0x0098: .word 0xe000e100
];
/// IRQ 0 at priority 0x80 pends IRQ 1, at 0x40; then PendSV from ICSR.
const PRIORITIES: &[u16] = &[
    0x480e, // 0x0080: ldr r0, [pc, #56]   (NVIC_ISER0)
    0x2103, // 0x0082: movs r1, #3
    0x6001, // 0x0084: str r1, [r0, #0]
    0x4a0e, // 0x0086: ldr r2, [pc, #56]   (NVIC_IPR0)
    0xf44f, 0x4181, // 0x0088: mov.w r1, #0x4080
    0x6011, // 0x008c: str r1, [r2, #0]
    0x4a0d, // 0x008e: ldr r2, [pc, #52]   (NVIC_ISPR0)
    0x2101, // 0x0090: movs r1, #1
    0x6011, // 0x0092: str r1, [r2, #0]
    0xbf00, // 0x0094: nop
    0x4a0c, // 0x0096: ldr r2, [pc, #48]   (ICSR)
    0xf04f, 0x5180, // 0x0098: mov.w r1, #0x10000000 (PENDSVSET)
    0x6011, // 0x009c: str r1, [r2, #0]
    0xbf00, // 0x009e: nop
    0xbf30, // 0x00a0: wfi
    0xe7fe, // 0x00a2: b.n a2 <done>
    0x4a07, // 0x00a4: irq0: ldr r2, [pc, #28] (NVIC_ISPR0)
    0x2102, // 0x00a6: movs r1, #2
    0x6011, // 0x00a8: str r1, [r2, #0]
    0xbf00, // 0x00aa: nop
    0x4635, // 0x00ac: mov r5, r6
    0x3401, // 0x00ae: adds r4, #1
    0x4770, // 0x00b0: bx lr
    0x2607, // 0x00b2: irq1: movs r6, #7
    0x4770, // 0x00b4: bx lr
    0x3701, // 0x00b6: pendsv: adds r7, #1
    0x4770, // 0x00b8: bx lr
    0x0000, // 0x00ba: .short 0x0000
    0xe100, 0xe000, // 0x00bc: .word 0xe000e100
    0xe400, 0xe000, // 0x00c0: .word 0xe000e400
    0xe200, 0xe000, // 0x00c4: .word 0xe000e200
    0xed04, 0xe000, // 0x00c8: .word 0xe000ed04
];
/// Turn on SysTick and its interrupt and enable IRQ 1, then sleep.
const SYSTICK_AND_IRQ1: &[u16] = &[
    0x4805, // 0x0080: ldr r0, [pc, #20]   (SYST_CSR)
    0x2103, // 0x0082: movs r1, #3
    0x6001, // 0x0084: str r1, [r0, #0]
    0x4805, // 0x0086: ldr r0, [pc, #20]   (NVIC_ISER0)
    0x2102, // 0x0088: movs r1, #2
    0x6001, // 0x008a: str r1, [r0, #0]
    0xbf30, // 0x008c: done: wfi
    0xe7fd, // 0x008e: b.n 8c <done>
    0x3401, // 0x0090: systick: adds r4, #1
    0x4770, // 0x0092: bx lr
    0x3501, // 0x0094: irq1: adds r5, #1
    0x4770, // 0x0096: bx lr
    0xe010, 0xe000, // 0x0098: .word 0xe000e010
    0xe100, 0xe000, // 0x009c: .word 0xe000e100
];
/// The same, then mask interrupts and spin.
const MASKED_SPIN: &[u16] = &[
    0x4805, // 0x0080: ldr r0, [pc, #20]   (SYST_CSR)
    0x2103, // 0x0082: movs r1, #3
    0x6001, // 0x0084: str r1, [r0, #0]
    0x4805, // 0x0086: ldr r0, [pc, #20]   (NVIC_ISER0)
    0x2102, // 0x0088: movs r1, #2
    0x6001, // 0x008a: str r1, [r0, #0]
    0xb672, // 0x008c: cpsid i
    0xe7fe, // 0x008e: spin: b.n 8e <spin>
    0x3401, // 0x0090: systick: adds r4, #1
    0x4770, // 0x0092: bx lr
    0x3501, // 0x0094: irq1: adds r5, #1
    0x4770, // 0x0096: bx lr
    0xe010, 0xe000, // 0x0098: .word 0xe000e010
    0xe100, 0xe000, // 0x009c: .word 0xe000e100
];
/// Enable IRQ 0, count to 40, sleep.
const COUNT_LOOP: &[u16] = &[
    0x4806, // 0x0080: ldr r0, [pc, #24]   (NVIC_ISER0)
    0x2101, // 0x0082: movs r1, #1
    0x6001, // 0x0084: str r1, [r0, #0]
    0x2200, // 0x0086: movs r2, #0
    0x3201, // 0x0088: loop: adds r2, #1
    0x2a28, // 0x008a: cmp r2, #40
    0xd1fc, // 0x008c: bne.n 88 <loop>
    0xbf30, // 0x008e: wfi
    0xe7fe, // 0x0090: done: b.n 90 <done>
    0x3401, // 0x0092: irq0: adds r4, #1
    0x2c64, // 0x0094: cmp r4, #100
    0xd800, // 0x0096: bhi.n 9a <big>
    0x4770, // 0x0098: bx lr
    0x4770, // 0x009a: big: bx lr
    0xe100, 0xe000, // 0x009c: .word 0xe000e100
];
/// IRQ 0 at priority 0x80 makes a supervisor call; SVCall stays at 0.
const SVC_IN_IRQ: &[u16] = &[
    0x4809, // 0x0080: ldr r0, [pc, #36]   (NVIC_IPR0)
    0x2180, // 0x0082: movs r1, #128
    0x6001, // 0x0084: str r1, [r0, #0]
    0x4809, // 0x0086: ldr r0, [pc, #36]   (NVIC_ISER0)
    0x2101, // 0x0088: movs r1, #1
    0x6001, // 0x008a: str r1, [r0, #0]
    0x4808, // 0x008c: ldr r0, [pc, #32]   (NVIC_ISPR0)
    0x6001, // 0x008e: str r1, [r0, #0]
    0xbf00, // 0x0090: nop
    0xbf30, // 0x0092: done: wfi
    0xe7fd, // 0x0094: b.n 92 <done>
    0x3401, // 0x0096: irq0: adds r4, #1
    0xdf00, // 0x0098: svc 0
    0x3501, // 0x009a: adds r5, #1
    0x4770, // 0x009c: bx lr
    0xf3ef, 0x8605, // 0x009e: svc: mrs r6, IPSR
    0x4677, // 0x00a2: mov r7, lr
    0x4770, // 0x00a4: bx lr
    0x0000, // 0x00a6: .short 0x0000
    0xe400, 0xe000, // 0x00a8: .word 0xe000e400
    0xe100, 0xe000, // 0x00ac: .word 0xe000e100
    0xe200, 0xe000, // 0x00b0: .word 0xe000e200
];
/// Enable IRQ 0 and sleep; its handler sets FAULTMASK and returns.
const FAULTMASK_IN_IRQ: &[u16] = &[
    0x4803, // 0x0080: ldr r0, [pc, #12]   (NVIC_ISER0)
    0x2101, // 0x0082: movs r1, #1
    0x6001, // 0x0084: str r1, [r0, #0]
    0xbf30, // 0x0086: done: wfi
    0xe7fd, // 0x0088: b.n 86 <done>
    0x3401, // 0x008a: irq0: adds r4, #1
    0xb671, // 0x008c: cpsid f
    0x4770, // 0x008e: bx lr
    0xe100, 0xe000, // 0x0090: .word 0xe000e100
];

/// The image of `code` with the handlers `(exception, address)`.
fn image(code: &[u16], handlers: &[(u32, u32)]) -> Image {
    let mut bytes = vec![0u8; 0x80];
    bytes[..4].copy_from_slice(&0x2000_1000u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&0x81u32.to_le_bytes());
    for &(exception, address) in handlers {
        let at = 4 * exception as usize;
        bytes[at..at + 4].copy_from_slice(&(address | 1).to_le_bytes());
    }
    for halfword in code {
        bytes.extend_from_slice(&halfword.to_le_bytes());
    }
    Image::raw(&bytes, 0).unwrap()
}

fn machine(code: &[u16], handlers: &[(u32, u32)], interval: Option<u64>) -> Machine {
    let config = MachineConfig {
        interrupts: interval.map(|interval| InterruptConfig { interval }),
        ..MachineConfig::default()
    };
    Machine::new(&image(code, handlers), config).unwrap()
}

/// Each interrupt the last run took, as its exception and the instruction
/// it interrupted.
fn taken(machine: &Machine) -> Vec<(u32, u32)> {
    machine
        .interrupt_log()
        .iter()
        .map(|event| (event.exception, event.pc))
        .collect()
}

fn idle(pc: u32, reason: IdleReason) -> Stop {
    Stop::Idle { pc, reason }
}

#[test]
fn without_a_schedule_wfi_ends_the_run_as_before() {
    let mut machine = machine(MASKED_WAKE, &[(16, 0x94)], None);
    let run = machine.run(&[0; 8]);
    assert_eq!(run.stop, idle(0x88, IdleReason::WaitForInterrupt));
    assert_eq!((run.interrupts, run.interrupt_input), (0, 0));
    assert!(machine.interrupt_log().is_empty());
}

#[test]
fn wfi_wakes_for_an_interrupt_primask_masks_and_the_core_takes_it_once_unmasked() {
    let mut machine = machine(MASKED_WAKE, &[(16, 0x94)], Some(DEFAULT_INTERRUPT_INTERVAL));
    let run = machine.run(&[0, 0, 0]);
    // Woken at 0x88 with the interrupt masked: the handler had not run.
    assert_eq!(machine.core.r[3], 0);
    // Taken once unmasked, then at the second wfi, then at the spin, each
    // on a byte of the input; the fourth tick has none and the core sleeps.
    assert_eq!(machine.core.r[4], 3);
    assert_eq!(taken(&machine), [(16, 0x8e), (16, 0x92), (16, 0x92)]);
    assert_eq!((run.interrupts, run.interrupt_input), (3, 3));
    assert_eq!(run.stop, idle(0x92, IdleReason::BranchToSelf));
    // The schedule took the bytes; no peripheral read did.
    assert_eq!(run.mmio_input, 0);
}

#[test]
fn a_higher_priority_interrupt_preempts_a_handler_and_pendsv_is_taken_from_icsr() {
    let handlers = [(14, 0xb6), (16, 0xa4), (17, 0xb2)];
    let mut machine = machine(PRIORITIES, &handlers, Some(DEFAULT_INTERRUPT_INTERVAL));
    let run = machine.run(&[]);
    // IRQ 0 is taken after its pending bit is set; IRQ 1, pended by its
    // handler at a higher priority, preempts it before the `mov`.
    assert_eq!(taken(&machine), [(16, 0x94), (17, 0xaa), (14, 0x9e)]);
    assert_eq!(machine.core.r[5], 7, "IRQ 1 ran inside IRQ 0's handler");
    assert_eq!((machine.core.r[4], machine.core.r[7]), (1, 1));
    // Nothing left to take and no input for the schedule: asleep.
    assert_eq!(run.stop, idle(0xa0, IdleReason::WaitForInterrupt));
    assert_eq!(run.interrupt_input, 0);
}

#[test]
fn priority_grouping_with_no_group_bits_stops_preemption() {
    let handlers = [(14, 0xb6), (16, 0xa4), (17, 0xb2)];
    // The same program, after `AIRCR = 0x05fa0700` (PRIGROUP 7: every
    // priority bit is a subpriority, so nothing preempts a handler).
    let mut code = vec![
        0x4801, // 0x0080: ldr r0, [pc, #4]    (AIRCR)
        0x4902, // 0x0082: ldr r1, [pc, #8]    (0x05fa0700)
        0x6001, // 0x0084: str r1, [r0, #0]
        0xe003, // 0x0086: b.n 90
        0xed0c, 0xe000, // 0x0088: .word 0xe000ed0c
        0x0700, 0x05fa, // 0x008c: .word 0x05fa0700
    ];
    code.extend_from_slice(PRIORITIES);
    let shift = 2 * code.len() as u32 - 2 * PRIORITIES.len() as u32;
    let handlers = handlers.map(|(exception, address)| (exception, address + shift));
    let mut machine = machine(&code, &handlers, Some(DEFAULT_INTERRUPT_INTERVAL));
    let run = machine.run(&[]);
    // IRQ 1 waits for IRQ 0's handler to return, and is taken there.
    assert_eq!(
        taken(&machine),
        [(16, 0x94 + shift), (17, 0x94 + shift), (14, 0x9e + shift)]
    );
    assert_eq!(machine.core.r[5], 0, "IRQ 1 did not preempt");
    assert_eq!(machine.core.r[6], 7, "but ran");
    assert!(matches!(run.stop, Stop::Idle { .. }), "{:?}", run.stop);
}

#[test]
fn each_ticks_byte_picks_one_of_the_enabled_interrupts_in_exception_order() {
    let handlers = [(15, 0x90), (17, 0x94)];
    let mut machine = machine(
        SYSTICK_AND_IRQ1,
        &handlers,
        Some(DEFAULT_INTERRUPT_INTERVAL),
    );
    // SysTick (15) and IRQ 1 (17) are enabled: a byte's value modulo two.
    let run = machine.run(&[0, 1, 1, 0, 3]);
    let exceptions: Vec<u32> = taken(&machine).iter().map(|(number, _)| *number).collect();
    assert_eq!(exceptions, [15, 17, 17, 15, 17]);
    assert_eq!((machine.core.r[4], machine.core.r[5]), (2, 3));
    assert_eq!((run.interrupts, run.interrupt_input), (5, 5));
    assert_eq!(run.stop, idle(0x8c, IdleReason::WaitForInterrupt));
    assert_eq!(machine.interrupt_log()[1].irq(), Some(1));
    assert_eq!(machine.interrupt_log()[0].irq(), None, "SysTick");
}

#[test]
fn a_spin_with_interrupts_masked_ends_idle_without_taking_input() {
    let handlers = [(15, 0x90), (17, 0x94)];
    let mut machine = machine(MASKED_SPIN, &handlers, Some(DEFAULT_INTERRUPT_INTERVAL));
    let run = machine.run(&[0; 16]);
    assert_eq!(run.stop, idle(0x8e, IdleReason::BranchToSelf));
    assert_eq!((run.interrupts, run.interrupt_input), (0, 0));
}

#[test]
fn a_ticks_top_bits_set_the_wait_to_the_next_tick() {
    let mut machine = machine(COUNT_LOOP, &[(16, 0x92)], Some(10));
    // Waits of the interval (10), four times it, and half of it.
    let run = machine.run(&[0x00, 0x80, 0x20]);
    let at: Vec<u64> = machine
        .interrupt_log()
        .iter()
        .map(|event| event.instructions)
        .collect();
    assert_eq!(at, [10, 20, 60]);
    assert_eq!(machine.core.r[2], 40, "the loop ran to its end");
    assert_eq!(run.stop, idle(0x8e, IdleReason::WaitForInterrupt));
}

#[test]
fn where_an_interrupt_lands_changes_no_edge_of_the_code_it_interrupts() {
    let mut machine = machine(COUNT_LOOP, &[(16, 0x92)], Some(10));
    let first = machine.run(&[0x00, 0x00, 0x00]);
    let first_at = taken(&machine);
    let first_edges = machine.edge_map().counts().to_vec();
    let second = machine.run(&[0x20, 0x20, 0x20]);
    let second_at = taken(&machine);
    assert_eq!((first.interrupts, second.interrupts), (3, 3));
    assert_ne!(first_at, second_at, "the interrupts landed elsewhere");
    assert_eq!(
        first_edges,
        machine.edge_map().counts(),
        "the same edges, counted the same"
    );
    // A run with no interrupt has the loop's edges and none of the
    // handler's.
    let quiet = machine.run(&[]);
    assert_eq!(quiet.interrupts, 0);
    assert!(machine.edge_map().edges() < first_edges.iter().filter(|&&c| c != 0).count());
}

#[test]
fn a_run_with_interrupts_repeats_exactly() {
    let run = |machine: &mut Machine, input: &[u8]| -> (Execution, Vec<u8>, Vec<(u32, u32)>) {
        let run = machine.run(input);
        (run, machine.edge_map().counts().to_vec(), taken(machine))
    };
    let handlers = [(15, 0x90), (17, 0x94)];
    let mut machine = machine(
        SYSTICK_AND_IRQ1,
        &handlers,
        Some(DEFAULT_INTERRUPT_INTERVAL),
    );
    let input = [3, 0, 7, 0x41, 0xff];
    let once = run(&mut machine, &input);
    machine.run(&[0; 3]);
    assert_eq!(run(&mut machine, &input), once);
    let mut fresh = self::machine(
        SYSTICK_AND_IRQ1,
        &handlers,
        Some(DEFAULT_INTERRUPT_INTERVAL),
    );
    assert_eq!(run(&mut fresh, &input), once);
}

#[test]
fn setup_refuses_a_schedule_with_no_interval() {
    let config = MachineConfig {
        interrupts: Some(InterruptConfig { interval: 0 }),
        ..MachineConfig::default()
    };
    assert_eq!(
        Machine::new(&image(COUNT_LOOP, &[]), config).err(),
        Some(crate::SetupError::NoInterruptInterval)
    );
}

#[test]
fn a_supervisor_call_in_a_handler_it_can_preempt_is_taken() {
    let handlers = [(11, 0x9e), (16, 0x96)];
    let mut machine = machine(SVC_IN_IRQ, &handlers, Some(DEFAULT_INTERRUPT_INTERVAL));
    let run = machine.run(&[]);
    // SVCall's priority 0 is above IRQ 0's 0x80: the call is taken inside
    // the handler, on the main stack, and returns to it.
    assert_eq!(run.stop, idle(0x92, IdleReason::WaitForInterrupt));
    assert_eq!(taken(&machine), [(16, 0x90)]);
    let core = &machine.core;
    assert_eq!((core.r[4], core.r[5]), (1, 1), "the handler ran on");
    assert_eq!(core.r[6], 11, "IPSR in the SVC handler is SVCall");
    assert_eq!(core.r[7], 0xffff_fff1, "it returns to Handler mode");
    assert_eq!(core.ipsr, 0);
}

#[test]
fn a_supervisor_call_in_a_handler_at_its_priority_escalates() {
    // IRQ 0 left at priority 0, SVCall's: the call cannot be taken.
    let mut code = SVC_IN_IRQ.to_vec();
    code[1] = 0x2100; // 0x0082: movs r1, #0
    let handlers = [(11, 0x9e), (16, 0x96)];
    let mut machine = machine(&code, &handlers, Some(DEFAULT_INTERRUPT_INTERVAL));
    let run = machine.run(&[]);
    let Stop::Fault(fault) = &run.stop else {
        panic!("expected a fault, the run stopped with {:?}", run.stop);
    };
    assert_eq!((fault.kind, fault.pc), (FaultKind::Escalation, 0x98));
    assert_eq!(machine.core.r[6], 0, "the SVC handler never ran");
}

#[test]
fn an_exception_return_clears_faultmask() {
    let mut machine = machine(
        FAULTMASK_IN_IRQ,
        &[(16, 0x8a)],
        Some(DEFAULT_INTERRUPT_INTERVAL),
    );
    let run = machine.run(&[0, 0, 0]);
    // FAULTMASK set in the handler is gone once it returns, so every
    // tick's interrupt is still taken.
    assert_eq!(machine.core.r[4], 3);
    assert_eq!((run.interrupts, run.interrupt_input), (3, 3));
    assert!(!machine.core.faultmask);
    assert_eq!(run.stop, idle(0x86, IdleReason::WaitForInterrupt));
}
