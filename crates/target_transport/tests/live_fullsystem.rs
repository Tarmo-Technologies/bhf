// SPDX-License-Identifier: Apache-2.0

//! RV-3 — live full-system snapshot validation (the flagship).
//!
//! This proves [`target_transport::FullSystemTransport`] end-to-end against a
//! REAL emulated Cortex-M core. A tiny `arm-none-eabi` bare-metal image is built
//! at test time with a FIXED memory map:
//!
//! * an **input** region (`bhf_input`),
//! * a **coverage ring** in the [`target_transport::MemoryBufferReader`] format
//!   (`adafuzz_probe_memory_buffer` + `_write` + `_wrapped`, byte-for-byte the
//!   Ada `adafuzz-probe-memory_buffer.adb` layout, emitting `BHF_EVENTS` `Crumb`
//!   records), and
//! * a **planted fault path** taken only for the input byte `0xF7`: it executes a
//!   real undefined instruction (`udf #0`) which the Cortex-M vectors to
//!   `HardFault_Handler`, which records a distinct fault-marker breadcrumb.
//!
//! The test boots it under `qemu-system-arm -M mps2-an385` with QMP + a gdbstub
//! and drives the real transport: `arm()` (savevm baseline) -> per-input `loadvm`
//! reset -> input write over gdb -> continue -> `MemoryBufferReader` reads the
//! ring -> assert coverage edges, determinism, and the planted fault.
//!
//! # Two gotchas handled here
//!
//! 1. **savevm needs a block device.** A diskless `-kernel` boot fails `savevm`
//!    with "no block device". We attach a small scratch `qcow2` via
//!    `-drive if=none,...` (not wired to any guest device); QEMU still uses it to
//!    store vmstate, so `savevm`/`loadvm` work. This is the FULL snapshot path —
//!    no reset-only fallback was needed.
//! 2. **Cortex-M cannot self-halt with `bkpt`.** With halting-debug disabled
//!    under the QEMU gdbstub, a guest `bkpt` escalates to a HardFault instead of
//!    stopping to the debugger, so `continue` would never return. We plant a
//!    gdbstub software breakpoint (`Z0`) at the harness `harness_done` symbol via
//!    [`FullSystemTransport::with_harness_breakpoint`]; QEMU keeps it across
//!    `loadvm`, so one insert covers every iteration.
//!
//! Self-skips loudly ONLY when a tool is absent; `BHF_HIL_REQUIRE=1`
//! (scripts/hil-emu.sh) turns a missing tool into a hard failure.

mod common;

use common::{connect_tcp_retry, connect_unix_retry, gate, ChildGuard, TempDir};
use std::process::Command;
use std::time::Duration;
use target_transport::{
    ExitKind, FullSystemTransport, GdbMemoryMap, TargetTransport, TransportError,
};

const CC: &str = "arm-none-eabi-gcc";
const QEMU: &str = "qemu-system-arm";
const QEMU_IMG: &str = "qemu-img";

const RING_CAP: usize = 512;

const HARNESS_LD: &str = r#"MEMORY {
  FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 4M
  RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 4M
}
ENTRY(Reset_Handler)
SECTIONS {
  .text : { KEEP(*(.isr_vector)) *(.text*) *(.rodata*) } > FLASH
  .data : { *(.data*) } > RAM
  .bss  : { *(.bss*) *(COMMON) } > RAM
  . = ALIGN(8);
  _estack = ORIGIN(RAM) + LENGTH(RAM);
}
"#;

const HARNESS_C: &str = r#"#include <stdint.h>
extern uint32_t _estack;
void Reset_Handler(void);
void HardFault_Handler(void);
void Default_Handler(void){ while(1){} }

/* Minimal Cortex-M vector table: [0]=SP, [1]=reset, [2]=NMI, [3]=HardFault. */
__attribute__((section(".isr_vector"), used))
uint32_t vectors[] = {
  (uint32_t)&_estack,
  (uint32_t)Reset_Handler,
  (uint32_t)Default_Handler,
  (uint32_t)HardFault_Handler,
};

/* Coverage ring in the MemoryBufferReader format: base + write cursor +
   wrapped flag, matching ada_runtime/adafuzz-probe-memory_buffer.adb. */
#define RING_CAP 512
volatile uint8_t  adafuzz_probe_memory_buffer[RING_CAP];
volatile uint32_t adafuzz_probe_memory_buffer_write = 0;
volatile uint8_t  adafuzz_probe_memory_buffer_wrapped = 0;
volatile uint32_t adafuzz_probe_memory_buffer_capacity = RING_CAP;

static void ring_write_byte(uint8_t v){
  adafuzz_probe_memory_buffer[adafuzz_probe_memory_buffer_write] = v;
  if (adafuzz_probe_memory_buffer_write == RING_CAP - 1) {
    adafuzz_probe_memory_buffer_write = 0;
    adafuzz_probe_memory_buffer_wrapped = 1;
  } else {
    adafuzz_probe_memory_buffer_write++;
  }
}
/* BHF_EVENTS Crumb record: tag byte 3, then the u32 id little-endian. */
static void emit_crumb(uint32_t id){
  ring_write_byte(3);
  ring_write_byte((uint8_t)(id & 0xff));
  ring_write_byte((uint8_t)((id >> 8) & 0xff));
  ring_write_byte((uint8_t)((id >> 16) & 0xff));
  ring_write_byte((uint8_t)((id >> 24) & 0xff));
}

volatile uint8_t  bhf_input[64];
volatile uint32_t bhf_fault_flag = 0;

void harness_done(void){ while(1){} }   /* host plants a gdb breakpoint here */

void HardFault_Handler(void){
  emit_crumb(0xFA17);            /* distinct fault-path marker breadcrumb */
  bhf_fault_flag = 0xDEADFA11u;
  harness_done();
}

void Reset_Handler(void){
  emit_crumb(0x100);             /* always-taken prologue edges */
  emit_crumb(0x101);
  uint8_t b = bhf_input[0];
  if (b == 0xF7) {
    emit_crumb(0x1FA);           /* "danger" edge, just before the fault */
    __asm volatile("udf #0");    /* REAL undefined instruction -> HardFault */
    emit_crumb(0x1FB);           /* must NOT be reached */
  } else if (b == 0x42) {
    emit_crumb(0x200);
    emit_crumb(0x201);
  } else {
    emit_crumb(0x300);
  }
  harness_done();
}
"#;

/// Boot the bare-metal image under qemu-system-arm with QMP + gdbstub + the
/// scratch qcow2, returning the running child plus its endpoints.
struct LiveTarget {
    _qemu: ChildGuard,
    gdb_port: u16,
    qmp_path: std::path::PathBuf,
}

fn boot(dir: &TempDir, elf: &std::path::Path) -> LiveTarget {
    let scratch = dir.join("scratch.qcow2");
    let created = Command::new(QEMU_IMG)
        .args(["create", "-f", "qcow2"])
        .arg(&scratch)
        .arg("16M")
        .output()
        .unwrap_or_else(|e| panic!("failed to run {QEMU_IMG}: {e}"));
    assert!(
        created.status.success(),
        "{QEMU_IMG} create failed: {}",
        String::from_utf8_lossy(&created.stderr)
    );

    let gdb_port = common::free_tcp_port();
    let qmp_path = dir.join("qmp.sock");
    let _ = std::fs::remove_file(&qmp_path);

    let child = Command::new(QEMU)
        .args(["-M", "mps2-an385", "-nographic", "-S", "-kernel"])
        .arg(elf)
        .arg("-gdb")
        .arg(format!("tcp::{gdb_port}"))
        .arg("-drive")
        .arg(format!(
            "if=none,file={},format=qcow2,id=sc0",
            scratch.display()
        ))
        .arg("-qmp")
        .arg(format!("unix:{},server,nowait", qmp_path.display()))
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {QEMU}: {e}"));
    let guard = ChildGuard::new(child, format!("{QEMU} mps2-an385 gdb:{gdb_port}"));
    eprintln!(
        "live_fullsystem: launched `{QEMU} -M mps2-an385 -kernel {} -S -gdb tcp::{gdb_port} \
         -drive if=none,file=<scratch.qcow2>,format=qcow2,id=sc0 -qmp unix:{},server,nowait`",
        elf.display(),
        qmp_path.display()
    );
    LiveTarget {
        _qemu: guard,
        gdb_port,
        qmp_path,
    }
}

#[test]
fn live_fullsystem_snapshot_reads_coverage_and_detects_planted_fault() {
    if let Err(reason) = gate(
        "live_fullsystem_snapshot_reads_coverage_and_detects_planted_fault",
        &[CC, QEMU, QEMU_IMG],
    ) {
        eprintln!("{reason}");
        return;
    }

    let dir = TempDir::new("bhf-live-fs").expect("temp dir");
    let src = dir.join("harness.c");
    let ld = dir.join("harness.ld");
    let elf = dir.join("harness.elf");
    std::fs::write(&src, HARNESS_C).expect("write harness.c");
    std::fs::write(&ld, HARNESS_LD).expect("write harness.ld");

    let built = Command::new(CC)
        .args([
            "-mcpu=cortex-m3",
            "-mthumb",
            "-nostdlib",
            "-nostartfiles",
            "-ffreestanding",
            "-O0",
            "-g",
            "-T",
        ])
        .arg(&ld)
        .arg("-o")
        .arg(&elf)
        .arg(&src)
        .status()
        .unwrap_or_else(|e| panic!("failed to run {CC}: {e}"));
    assert!(
        built.success(),
        "{CC} failed to build the bare-metal image (tool present -> real failure)"
    );

    // Fixed memory map, discovered from the linked image.
    let input_address = common::nm_symbol("nm", &elf, "bhf_input");
    let ring_address = common::nm_symbol("nm", &elf, "adafuzz_probe_memory_buffer");
    let ring_write_address = common::nm_symbol("nm", &elf, "adafuzz_probe_memory_buffer_write");
    let ring_wrapped_address = common::nm_symbol("nm", &elf, "adafuzz_probe_memory_buffer_wrapped");
    // `nm` sets the Thumb bit (bit 0) on function symbols; strip it for the bp.
    let harness_done = common::nm_symbol("nm", &elf, "harness_done") & !1;
    eprintln!(
        "live_fullsystem: map input={input_address:#x} ring={ring_address:#x} \
         write={ring_write_address:#x} wrapped={ring_wrapped_address:#x} \
         harness_done={harness_done:#x}"
    );

    let map = GdbMemoryMap {
        input_address,
        ring_address,
        ring_write_address,
        ring_wrapped_address,
        ring_capacity: RING_CAP,
    };

    let target = boot(&dir, &elf);
    let gdb_port = target.gdb_port;
    let qmp_path = target.qmp_path.clone();

    // Connect factories (each called once by arm()): dial the real QMP socket and
    // the real gdbstub, with read timeouts so a wedged emulator errors instead of
    // hanging the test forever.
    let qmp_path_for_closure = qmp_path.clone();
    let connect_qmp = move || -> Result<std::os::unix::net::UnixStream, TransportError> {
        let stream = connect_unix_retry(&qmp_path_for_closure, Duration::from_secs(10))
            .map_err(TransportError::from)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(TransportError::from)?;
        Ok(stream)
    };
    let connect_gdb = move || -> Result<std::net::TcpStream, TransportError> {
        let stream =
            connect_tcp_retry(gdb_port, Duration::from_secs(10)).map_err(TransportError::from)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(TransportError::from)?;
        Ok(stream)
    };

    let transport = FullSystemTransport::new(connect_qmp, connect_gdb, map, "bhf_base")
        .expect("build FullSystemTransport")
        // Thumb software breakpoint (kind 2) at the harness done symbol.
        .with_harness_breakpoint(harness_done, 2);

    // arm(): QMP handshake, gdb attach, plant the harness breakpoint, quiesce,
    // and savevm the clean baseline (this is the "savevm needs a block device"
    // gotcha in action — it succeeds thanks to the scratch qcow2).
    let mut session = transport.arm().expect("arm the live full-system target");
    eprintln!("live_fullsystem: arm() OK — QMP handshake + gdb attach + savevm baseline");

    // Expected coverage edge sets (breadcrumb ids emitted along each path).
    const PROLOGUE: [u32; 2] = [0x100, 0x101];
    let normal: Vec<u32> = [PROLOGUE.as_slice(), &[0x200, 0x201]].concat();
    let default: Vec<u32> = [PROLOGUE.as_slice(), &[0x300]].concat();
    // Fault path: prologue, "danger", then the HardFault marker. 0x1FB is never
    // reached because the udf diverts control into the fault vector.
    let fault: Vec<u32> = [PROLOGUE.as_slice(), &[0x1FA, 0xFA17]].concat();
    const FAULT_MARKER: u32 = 0xFA17;

    let run = |session: &mut Box<dyn target_transport::TargetSession>, byte: u8| {
        session
            .run_input(&[byte])
            .unwrap_or_else(|e| panic!("run_input({byte:#04x}) failed: {e}"))
    };

    // ---- normal input (0x42) ----
    let out_normal = run(&mut session, 0x42);
    assert_eq!(
        out_normal.coverage_edges, normal,
        "normal input must take the A branch"
    );
    assert_eq!(out_normal.exit, ExitKind::Ok, "clean stop at harness_done");
    assert!(out_normal.fault.is_none());
    assert!(
        !out_normal.coverage_edges.contains(&FAULT_MARKER),
        "normal input must not hit the fault path"
    );
    eprintln!(
        "live_fullsystem: input=0x42 edges={:x?} exit={:?}",
        out_normal.coverage_edges, out_normal.exit
    );

    // ---- default input (0x00) — a DIFFERENT branch, proving input reaches code ----
    let out_default = run(&mut session, 0x00);
    assert_eq!(
        out_default.coverage_edges, default,
        "default input must take the B branch"
    );
    assert_ne!(
        out_default.coverage_edges, out_normal.coverage_edges,
        "different inputs must produce different coverage"
    );
    eprintln!(
        "live_fullsystem: input=0x00 edges={:x?}",
        out_default.coverage_edges
    );

    // ---- planted fault input (0xF7) ----
    let out_fault = run(&mut session, 0xF7);
    assert_eq!(
        out_fault.coverage_edges, fault,
        "fault input must take the danger edge then the HardFault marker"
    );
    assert!(
        out_fault.coverage_edges.contains(&FAULT_MARKER),
        "the planted-fault input must yield the fault-handler marker breadcrumb"
    );
    assert!(
        !out_fault.coverage_edges.contains(&0x1FB),
        "the post-udf edge must be unreachable — proving the udf really faulted"
    );
    eprintln!(
        "live_fullsystem: input=0xF7 edges={:x?} — REAL Cortex-M HardFault path taken",
        out_fault.coverage_edges
    );

    // ---- determinism: the snapshot reset makes the same input reproducible even
    // after a fault iteration contaminated the guest ----
    let out_repeat = run(&mut session, 0x42);
    assert_eq!(
        out_repeat.coverage_edges, out_normal.coverage_edges,
        "same input after loadvm reset must reproduce identical coverage"
    );
    eprintln!(
        "live_fullsystem: determinism — 0x42 again edges={:x?} (== first run)",
        out_repeat.coverage_edges
    );

    eprintln!(
        "live_fullsystem: PASSED — live snapshot reset + coverage-ring readback + \
         planted-fault detection on real emulated Cortex-M"
    );
}
