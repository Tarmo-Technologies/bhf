// SPDX-License-Identifier: Apache-2.0

//! Live `RenodeTransport` run against a real Renode emulator (#340).
//!
//! A bare-metal Cortex-M3 image is built at test time with `arm-none-eabi-gcc`
//! and loaded into a minimal Renode board (an NVIC, a `cortex-m3` CPU, flash
//! at 0 and SRAM at `0x2000_0000`, described inline so the test needs no
//! network). The image keeps a coverage ring in the `MemoryBufferReader`
//! layout, records a breadcrumb per branch, and takes a planted fault for the
//! input byte `0xF7`: a real `udf #0`, which Cortex-M escalates to
//! `HardFault_Handler`, which sets a fault-status word and returns through
//! `harness_done`.
//!
//! Renode starts with its telnet monitor on a free port and the board loaded
//! but not started. The transport then saves the baseline, and per input
//! loads it, selects the machine again, restarts the gdb server, plants the
//! `harness_done` breakpoint, writes the input, continues, and reads the
//! ring. The test checks coverage,
//! determinism of a repeated input, the planted fault, and a clean run after
//! it.
//!
//! Needs `renode` on `PATH` (or its path in `BHF_RENODE`) and the
//! `arm-none-eabi` toolchain. Without them the test skips with a note;
//! `BHF_REQUIRE_TOOLS=1` (or the hil-emu lane's `BHF_HIL_REQUIRE`) makes a
//! missing tool a failure.
#![cfg(unix)]

mod common;

use common::{connect_tcp_retry, free_tcp_port, tool_on_path, ChildGuard, TempDir};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use target_transport::{
    ExitKind, FaultKind, GdbMemoryMap, GuestFaultStatus, RenodeTransport, TargetTransport,
    TransportError,
};

const CC: &str = "arm-none-eabi-gcc";
const NM: &str = "arm-none-eabi-nm";
const RING_CAP: usize = 512;

const BOARD_REPL: &str = r#"nvic: IRQControllers.NVIC @ sysbus 0xE000E000
    -> cpu@0

cpu: CPU.CortexM @ sysbus
    cpuType: "cortex-m3"
    nvic: nvic

flash: Memory.MappedMemory @ sysbus 0x0
    size: 0x40000

sram: Memory.MappedMemory @ sysbus 0x20000000
    size: 0x10000
"#;

const HARNESS_LD: &str = r#"MEMORY {
  FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 256K
  RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
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

__attribute__((section(".isr_vector"), used))
uint32_t vectors[] = {
  (uint32_t)&_estack,
  (uint32_t)Reset_Handler,
  (uint32_t)Default_Handler,
  (uint32_t)HardFault_Handler,
};

#define RING_CAP 512
volatile uint8_t  adafuzz_probe_memory_buffer[RING_CAP];
volatile uint32_t adafuzz_probe_memory_buffer_write = 0;
volatile uint8_t  adafuzz_probe_memory_buffer_wrapped = 0;

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

__attribute__((noinline)) void harness_done(void){ __asm volatile(""); while(1){} }

void HardFault_Handler(void){
  emit_crumb(0xFA17);
  bhf_fault_flag = 0xDEADFA11u;
  harness_done();
}

void Reset_Handler(void){
  emit_crumb(0x100);
  emit_crumb(0x101);
  uint8_t b = bhf_input[0];
  if (b == 0xF7) {
    emit_crumb(0x1FA);
    __asm volatile("udf #0");
    emit_crumb(0x1FB);
  } else if (b == 0x42) {
    emit_crumb(0x200);
    emit_crumb(0x201);
  } else {
    emit_crumb(0x300);
  }
  harness_done();
}
"#;

/// The Renode launcher: `BHF_RENODE`, else `renode` on `PATH`.
fn renode() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("BHF_RENODE") {
        return Some(PathBuf::from(path));
    }
    tool_on_path("renode").then(|| PathBuf::from("renode"))
}

fn tools_required() -> bool {
    std::env::var_os("BHF_REQUIRE_TOOLS").is_some_and(|value| value == "1")
        || std::env::var_os("BHF_HIL_REQUIRE").is_some()
}

fn build_image(dir: &TempDir) -> PathBuf {
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
    assert!(built.success(), "{CC} failed to build the image");
    elf
}

/// Start Renode with its monitor on `monitor_port` and the board loaded but
/// not started.
fn launch(renode: &Path, dir: &TempDir, elf: &Path, monitor_port: u16) -> ChildGuard {
    let repl = dir.join("board.repl");
    std::fs::write(&repl, BOARD_REPL).expect("write board.repl");
    let script = dir.join("board.resc");
    std::fs::write(
        &script,
        format!(
            "mach create\nmachine LoadPlatformDescription @{}\nsysbus LoadELF @{}\n",
            repl.display(),
            elf.display()
        ),
    )
    .expect("write board.resc");
    let log = std::fs::File::create(dir.join("renode.log")).expect("create renode.log");
    let child = Command::new(renode)
        .arg("--disable-gui")
        .arg("-P")
        .arg(monitor_port.to_string())
        .arg(&script)
        .current_dir(dir.path())
        .stdin(Stdio::null())
        .stdout(log.try_clone().expect("clone log handle"))
        .stderr(log)
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", renode.display()));
    ChildGuard::new(child, format!("renode -P {monitor_port}"))
}

#[test]
fn live_renode_snapshot_reads_coverage_and_detects_planted_fault() {
    let renode = renode();
    let missing: Vec<&str> = [
        (renode.is_none(), "renode (or BHF_RENODE)"),
        (!tool_on_path(CC), CC),
        (!tool_on_path(NM), NM),
    ]
    .into_iter()
    .filter_map(|(absent, tool)| absent.then_some(tool))
    .collect();
    if !missing.is_empty() {
        assert!(
            !tools_required(),
            "BHF_REQUIRE_TOOLS=1 and the live Renode test's tools are absent: {}",
            missing.join(", ")
        );
        eprintln!(
            "live_renode: SKIPPED, missing tool(s): {}",
            missing.join(", ")
        );
        return;
    }
    let renode = renode.expect("checked above");

    let dir = TempDir::new("bhf-live-renode").expect("temp dir");
    let elf = build_image(&dir);
    let map = GdbMemoryMap {
        input_address: common::nm_symbol(NM, &elf, "bhf_input"),
        ring_address: common::nm_symbol(NM, &elf, "adafuzz_probe_memory_buffer"),
        ring_write_address: common::nm_symbol(NM, &elf, "adafuzz_probe_memory_buffer_write"),
        ring_wrapped_address: common::nm_symbol(NM, &elf, "adafuzz_probe_memory_buffer_wrapped"),
        ring_capacity: RING_CAP,
    };
    let harness_done = common::nm_symbol(NM, &elf, "harness_done") & !1;
    let fault_flag = common::nm_symbol(NM, &elf, "bhf_fault_flag");

    let monitor_port = free_tcp_port();
    let gdb_port = free_tcp_port();
    let _renode = launch(&renode, &dir, &elf, monitor_port);

    let connect_monitor = move || -> Result<std::net::TcpStream, TransportError> {
        // .NET start-up and the board load take a few seconds.
        let stream = connect_tcp_retry(monitor_port, Duration::from_secs(60))?;
        stream.set_read_timeout(Some(Duration::from_secs(60)))?;
        Ok(stream)
    };
    let connect_gdb = move || -> Result<std::net::TcpStream, TransportError> {
        let stream = connect_tcp_retry(gdb_port, Duration::from_secs(10))?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        Ok(stream)
    };
    let snapshot = dir.join("baseline.save");
    let transport = RenodeTransport::new(
        connect_monitor,
        connect_gdb,
        gdb_port,
        map,
        snapshot.to_str().expect("utf-8 temp path"),
    )
    .expect("build RenodeTransport")
    .with_harness_breakpoint(harness_done, 2)
    .with_fault_status(GuestFaultStatus::new(fault_flag, 4, 0).expect("fault-status contract"))
    .with_exec_deadline(Some(Duration::from_secs(20)));

    let mut session = transport.arm().unwrap_or_else(|err| {
        let log = std::fs::read_to_string(dir.join("renode.log")).unwrap_or_default();
        panic!("arm the Renode board: {err}\nrenode.log:\n{log}")
    });
    assert!(snapshot.is_file(), "Save wrote the baseline state file");

    let run = |session: &mut Box<dyn target_transport::TargetSession>, input: &[u8]| {
        session.run_input(input).unwrap_or_else(|err| {
            let log = std::fs::read_to_string(dir.join("renode.log")).unwrap_or_default();
            panic!("run {input:02x?}: {err}\nrenode.log:\n{log}")
        })
    };

    let clean = run(&mut session, &[0x42]);
    assert_eq!(clean.exit, ExitKind::Ok, "{clean:?}");
    assert_eq!(clean.coverage_edges, [0x100, 0x101, 0x200, 0x201]);

    let again = run(&mut session, &[0x42]);
    assert_eq!(
        again.coverage_edges, clean.coverage_edges,
        "the baseline Load makes a repeated input deterministic"
    );

    let other = run(&mut session, &[0x00]);
    assert_eq!(other.exit, ExitKind::Ok);
    assert_eq!(other.coverage_edges, [0x100, 0x101, 0x300]);

    let fault = run(&mut session, &[0xF7]);
    assert_eq!(fault.exit, ExitKind::Crash, "{fault:?}");
    assert_eq!(
        fault.fault.as_ref().map(|f| &f.kind),
        Some(&FaultKind::CpuException)
    );
    assert!(fault.coverage_edges.contains(&0x1FA));
    assert!(fault.coverage_edges.contains(&0xFA17));
    assert!(!fault.coverage_edges.contains(&0x1FB));

    let after = run(&mut session, &[0x42]);
    assert_eq!(
        after.exit,
        ExitKind::Ok,
        "the fault does not leak into the next run"
    );
    assert_eq!(after.coverage_edges, clean.coverage_edges);
}
