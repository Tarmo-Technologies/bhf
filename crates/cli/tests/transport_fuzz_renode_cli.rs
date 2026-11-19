// SPDX-License-Identifier: Apache-2.0

//! `bhf fuzz --target-transport renode:...` end to end through the shipped
//! CLI against a real Renode emulator (#340): a bare-metal Cortex-M3 image on
//! a minimal Renode board, a planted-fault seed, and a persisted crash
//! finding classified from the firmware's fault-status word.
//!
//! Needs `renode` on `PATH` (or its path in `BHF_RENODE`),
//! `arm-none-eabi-gcc` and `arm-none-eabi-nm`. Without Renode it skips unless
//! `BHF_RENODE_CLI=1`, which scripts/hil-emu.sh sets after
//! scripts/ci/install-renode.sh: the nightly's `BHF_REQUIRE_TOOLS=1` shards
//! do not install Renode. `BHF_REQUIRE_TOOLS=1` makes a missing cross
//! toolchain a failure.

#![cfg(unix)]

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod support;

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
  if (bhf_input[0] == 0xF7) {
    emit_crumb(0x1FA);
    __asm volatile("udf #0");
  } else {
    emit_crumb(0x300);
  }
  harness_done();
}
"#;

/// Set to `1` to make a missing Renode a failure.
const RENODE_REQUIRED: &str = "BHF_RENODE_CLI";

fn renode() -> Option<PathBuf> {
    let found = std::env::var_os("BHF_RENODE")
        .map(PathBuf::from)
        .or_else(|| which::which("renode").ok());
    let required = std::env::var_os(RENODE_REQUIRED).is_some_and(|value| value == "1");
    support::require_tool_with(found.is_some(), "renode", required).then(|| found.expect("checked"))
}

fn tool_present(tool: &str) -> bool {
    support::require_tool(which::which(tool).is_ok(), tool)
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn nm_symbol(elf: &Path, symbol: &str) -> u64 {
    let out = Command::new(NM)
        .arg(elf)
        .output()
        .unwrap_or_else(|e| panic!("run {NM}: {e}"));
    assert!(out.status.success(), "{NM} failed on {}", elf.display());
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let (addr, _, name) = (fields.next()?, fields.next()?, fields.next()?);
            (name == symbol).then(|| u64::from_str_radix(addr, 16).expect("nm address"))
        })
        .unwrap_or_else(|| panic!("symbol {symbol} not found in {}", elf.display()))
}

/// Kills Renode on drop so a failed assertion never leaks the process.
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_port(port: u16, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn cli_renode_transport_persists_a_classified_fault_finding() {
    let Some(renode) = renode() else {
        eprintln!(
            "skip transport_fuzz_renode_cli: renode is not installed (set {RENODE_REQUIRED}=1 \
             to require it, BHF_RENODE to name it)"
        );
        return;
    };
    if !tool_present(CC) || !tool_present(NM) {
        eprintln!("skip transport_fuzz_renode_cli: the arm-none-eabi toolchain is missing");
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();

    let (src, ld, elf) = (dir.join("fw.c"), dir.join("fw.ld"), dir.join("fw.elf"));
    std::fs::write(&src, HARNESS_C).unwrap();
    std::fs::write(&ld, HARNESS_LD).unwrap();
    let built = Command::new(CC)
        .args(["-mcpu=cortex-m3", "-mthumb", "-nostdlib", "-nostartfiles"])
        .args(["-ffreestanding", "-O0", "-g", "-T"])
        .arg(&ld)
        .arg("-o")
        .arg(&elf)
        .arg(&src)
        .status()
        .expect("run arm-none-eabi-gcc");
    assert!(built.success(), "the Cortex-M image must build");

    let repl = dir.join("board.repl");
    std::fs::write(&repl, BOARD_REPL).unwrap();
    let script = dir.join("board.resc");
    std::fs::write(
        &script,
        format!(
            "mach create\nmachine LoadPlatformDescription @{}\nsysbus LoadELF @{}\n",
            repl.display(),
            elf.display()
        ),
    )
    .unwrap();
    let monitor_port = free_port();
    let gdb_port = free_port();
    let log = std::fs::File::create(dir.join("renode.log")).unwrap();
    let _renode = ChildGuard(
        Command::new(&renode)
            .args(["--disable-gui", "-P", &monitor_port.to_string()])
            .arg(&script)
            .current_dir(dir)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn renode"),
    );
    assert!(
        wait_port(monitor_port, Duration::from_secs(60)),
        "Renode's monitor never opened port {monitor_port}"
    );

    let snapshot = dir.join("baseline.save");
    let spec = format!(
        "renode:monitor=127.0.0.1:{monitor_port},gdb=127.0.0.1:{gdb_port},snapshot={},\
         done={:#x},fault={:#x}",
        snapshot.display(),
        nm_symbol(&elf, "harness_done"),
        nm_symbol(&elf, "bhf_fault_flag"),
    );
    let map = format!(
        "input={:#x},input_cap=64,ring={:#x},write={:#x},wrapped={:#x},cap={RING_CAP}",
        nm_symbol(&elf, "bhf_input"),
        nm_symbol(&elf, "adafuzz_probe_memory_buffer"),
        nm_symbol(&elf, "adafuzz_probe_memory_buffer_write"),
        nm_symbol(&elf, "adafuzz_probe_memory_buffer_wrapped"),
    );
    let seed = dir.join("seed.bin");
    std::fs::write(&seed, [0xF7_u8]).unwrap();
    let work = dir.join("work");
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["fuzz", "--target-transport", &spec])
        .args(["--transport-coverage-map", &map])
        .args(["--harness", "renode-fixture"])
        .arg("--seed-file")
        .arg(&seed)
        .args(["--iterations", "1", "--time", "60s", "--timeout", "30"])
        .arg(&work)
        .output()
        .expect("run bhf fuzz");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let renode_log = std::fs::read_to_string(dir.join("renode.log")).unwrap_or_default();
    assert!(
        out.status.success(),
        "bhf fuzz --target-transport renode failed ({:?})\nstdout:\n{stdout}\nstderr:\n{stderr}\
         \nrenode.log:\n{renode_log}",
        out.status.code()
    );
    let summary: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("summary JSON: {e}\n{stdout}\n{stderr}"));
    assert!(
        summary["crashes"].as_u64().unwrap_or(0) >= 1,
        "the planted-fault seed is a crash: {summary}"
    );
    let findings = summary["findings"].as_array().expect("findings array");
    let id = findings
        .first()
        .and_then(|id| id.as_str())
        .unwrap_or_else(|| panic!("a finding is persisted: {summary}"));
    let finding_dir = work.join("results").join("findings").join(id);
    let finding: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(finding_dir.join("finding.json")).expect("finding.json"),
    )
    .unwrap();
    assert!(
        finding.to_string().contains("0xdeadfa11"),
        "the finding carries the firmware fault-status word: {finding}"
    );
    let profile: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(finding_dir.join("transport_profile.json"))
            .expect("transport_profile.json"),
    )
    .unwrap();
    assert_eq!(profile["backend"], "renode", "{profile}");
    assert!(
        snapshot.is_file(),
        "Renode saved the baseline at {}",
        snapshot.display()
    );
}
