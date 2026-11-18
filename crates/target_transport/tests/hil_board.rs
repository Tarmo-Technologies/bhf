// SPDX-License-Identifier: Apache-2.0

//! HIL (hardware-in-the-loop) board lane over the gdb transport (#293).
//!
//! A board is described by a **board profile** (`docs/hil-boards/*.toml`): the
//! `gdb:` transport spec of its debug probe (gdbstub endpoint, completion
//! breakpoint `done=`, fault-status word `fault=`, `reset=`) and the coverage
//! map of its firmware (`input=`, `input_cap=`, the ring), the same specs
//! `bhf fuzz --board-profile` runs. This test drives the real
//! [`target_transport::GdbClient`] / [`target_transport::GdbRemoteTransport`]
//! against the board's gdbstub with that contract: attach, read the
//! registers, then run inputs and read the coverage ring.
//!
//! * `hil_board_gdb_path_runs_when_a_probe_is_configured` runs against a real
//!   board: `BHF_HIL_PROFILE=board.toml` (or the older `BHF_HIL_GDB` and
//!   `BHF_HIL_*_ADDR` variables below). It self-skips without them.
//! * `hil_board_profile_runs_against_the_qemu_stand_in` builds a Cortex-M
//!   firmware that starts as a board's does (it zeroes `.bss` and takes its
//!   input in `.noinit`), boots it under `qemu-system-arm` with only a
//!   gdbstub, writes its profile and runs the same lane against it. It
//!   self-skips without `arm-none-eabi-gcc` and `qemu-system-arm` (a failure
//!   under `BHF_HIL_REQUIRE=1`).
//!
//! Environment of the real-board test:
//! * `BHF_HIL_PROFILE=board.toml`    — the board profile. Or, without one:
//! * `BHF_HIL_GDB=host:port`         — the OpenOCD (or gdbserver) gdbstub.
//! * `BHF_HIL_PROBE_ADDR=0x...`      — optional: an address to read back.
//! * `BHF_HIL_PROBE_LEN=N`           — optional: bytes to read at PROBE_ADDR (default 16).
//! * `BHF_HIL_INPUT_ADDR=0x...`      \
//! * `BHF_HIL_RING_ADDR=0x...`        \  set all five to drive a full
//! * `BHF_HIL_RING_WRITE_ADDR=0x...`  >  GdbRemoteTransport::run_input and read
//! * `BHF_HIL_RING_WRAPPED_ADDR=0x...`/   the on-board coverage ring.
//! * `BHF_HIL_RING_CAP=N`            /
//! * `BHF_HIL_INPUT=deadbeef`        — optional: hex input to deliver (default empty).

use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;
use target_transport::{
    GdbClient, GdbMemoryMap, GdbRemoteTransport, GuestFaultStatus, InputContract, ResetMode,
    RunOutcome, TargetTransport, TransportError,
};

#[cfg(unix)]
mod common;

/// One board's transport contract, from its profile or the environment.
#[derive(Debug)]
struct Board {
    gdb: String,
    map: Option<GdbMemoryMap>,
    input_cap: Option<usize>,
    done: Option<(u64, u32)>,
    fault: Option<GuestFaultStatus>,
    reset: ResetMode,
}

impl Board {
    /// The board a profile describes: its `gdb` spec and `coverage_map`.
    fn from_profile(path: &Path) -> Self {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("board profile {}: {e}", path.display()));
        let profile: toml::Table = text
            .parse()
            .unwrap_or_else(|e| panic!("board profile {}: {e}", path.display()));
        let field = |key: &str| profile.get(key).and_then(|value| value.as_str());
        let spec = field("gdb")
            .unwrap_or_else(|| panic!("board profile {} has no gdb lane", path.display()));
        let mut parts = spec
            .strip_prefix("gdb:")
            .unwrap_or_else(|| panic!("gdb lane {spec:?} is not a gdb: spec"))
            .split(',');
        let mut board = Board {
            gdb: parts.next().unwrap_or_default().to_owned(),
            map: None,
            input_cap: None,
            done: None,
            fault: None,
            reset: ResetMode::Restart,
        };
        let (mut done_kind, mut fault_width, mut fault_clear) = (2, 4, 0);
        let mut fault = None;
        for (key, value) in pairs(parts) {
            match key {
                "done" => board.done = Some((parse_addr(key, value), 0)),
                "done_kind" => done_kind = parse_addr(key, value) as u32,
                "fault" => fault = Some(parse_addr(key, value)),
                "fault_width" => fault_width = parse_addr(key, value) as usize,
                "fault_clear" => fault_clear = parse_addr(key, value),
                "reset" => {
                    board.reset = match value.strip_prefix("monitor:") {
                        Some(command) => ResetMode::Monitor(command.to_owned()),
                        None => ResetMode::Restart,
                    }
                }
                // Read by `bhf fuzz`, not by this lane.
                "firmware" | "cycles" | "cpu_hz" | "task_id" => {}
                other => panic!("gdb lane {spec:?}: unknown key {other:?}"),
            }
        }
        // As `bhf fuzz` does: a Thumb function's `nm` address has bit 0 set.
        board.done = board.done.map(|(address, _)| {
            let address = if done_kind == 2 {
                address & !1
            } else {
                address
            };
            (address, done_kind)
        });
        board.fault = fault.map(|address| {
            GuestFaultStatus::new(address, fault_width, fault_clear).expect("fault word width")
        });
        if let Some(map) = field("coverage_map") {
            let mut keys = std::collections::HashMap::new();
            for (key, value) in pairs(map.split(',')) {
                keys.insert(key.to_owned(), parse_addr(key, value));
            }
            let key = |name: &str| {
                *keys
                    .get(name)
                    .unwrap_or_else(|| panic!("coverage_map {map:?} has no {name}="))
            };
            board.input_cap = Some(key("input_cap") as usize);
            board.map = Some(GdbMemoryMap {
                input_address: key("input"),
                ring_address: key("ring"),
                ring_write_address: key("write"),
                ring_wrapped_address: key("wrapped"),
                ring_capacity: key("cap") as usize,
            });
        }
        board
    }

    /// The board the `BHF_HIL_*` variables describe.
    fn from_env(gdb: String) -> Self {
        let map = match (
            env_addr("BHF_HIL_INPUT_ADDR"),
            env_addr("BHF_HIL_RING_ADDR"),
            env_addr("BHF_HIL_RING_WRITE_ADDR"),
            env_addr("BHF_HIL_RING_WRAPPED_ADDR"),
        ) {
            (Some(input), Some(ring), Some(write), Some(wrapped)) => Some(GdbMemoryMap {
                input_address: input,
                ring_address: ring,
                ring_write_address: write,
                ring_wrapped_address: wrapped,
                ring_capacity: env_usize("BHF_HIL_RING_CAP", 65_536),
            }),
            _ => None,
        };
        Board {
            gdb,
            map,
            input_cap: None,
            done: None,
            fault: None,
            reset: ResetMode::Restart,
        }
    }

    /// Attach and read the registers over the raw client: the link is live.
    fn attach(&self) {
        let mut client = GdbClient::new(connect(&self.gdb));
        let stop = client.attach().expect("attach to the board's gdbstub");
        eprintln!("hil_board: attached, initial stop = {stop:?}");
        let regs = client.read_registers().expect("read general registers");
        assert!(!regs.is_empty(), "register block should be non-empty");
        eprintln!("hil_board: read {} register bytes", regs.len());
        if let Some(addr) = env_addr("BHF_HIL_PROBE_ADDR") {
            let len = env_usize("BHF_HIL_PROBE_LEN", 16);
            let bytes = client
                .read_memory(addr, len)
                .expect("read the configured probe region from the board");
            eprintln!("hil_board: read_memory({addr:#x}, {len}) = {bytes:02x?}");
        }
    }

    /// Run each input over the gdb transport with the board's contract; one
    /// outcome per input.
    fn run(&self, inputs: &[Vec<u8>]) -> Vec<RunOutcome> {
        let map = self.map.expect("a coverage map to run inputs");
        let addr = self.gdb.clone();
        let mut transport = GdbRemoteTransport::new(
            move || -> Result<TcpStream, TransportError> {
                let stream = TcpStream::connect(&addr)?;
                stream.set_read_timeout(Some(Duration::from_secs(30)))?;
                Ok(stream)
            },
            map,
        )
        .with_reset(self.reset.clone())
        .with_exec_deadline(Some(Duration::from_secs(10)))
        .with_input_contract(
            self.input_cap
                .map(|cap| InputContract::new(cap, None).expect("input_cap")),
        );
        if let Some((address, kind)) = self.done {
            transport = transport.with_harness_breakpoint(address, kind);
        }
        if let Some(status) = self.fault.clone() {
            transport = transport.with_fault_status(status);
        }
        let mut session = transport
            .arm()
            .expect("arm the board over the gdb transport");
        inputs
            .iter()
            .map(|input| {
                let outcome = session
                    .run_input(input)
                    .expect("run one input against the board and read coverage");
                eprintln!(
                    "hil_board: run_input({input:02x?}) -> exit={:?}, fault={:?}, edges {:x?}",
                    outcome.exit,
                    outcome.fault.as_ref().map(|fault| &fault.detail),
                    outcome.coverage_edges
                );
                outcome
            })
            .collect()
    }
}

/// The `key=value` pairs of a spec's comma-separated fields.
fn pairs<'a>(parts: impl Iterator<Item = &'a str>) -> impl Iterator<Item = (&'a str, &'a str)> {
    parts
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.split_once('=')
                .map(|(key, value)| (key.trim(), value.trim()))
                .unwrap_or_else(|| panic!("{part:?} is not key=value"))
        })
}

fn parse_addr(key: &str, raw: &str) -> u64 {
    let value = match raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => raw.parse::<u64>(),
    };
    value.unwrap_or_else(|_| panic!("{key}={raw:?} is not a valid address"))
}

fn env_addr(key: &str) -> Option<u64> {
    let raw = std::env::var(key).ok()?;
    Some(parse_addr(key, raw.trim()))
}

fn env_usize(key: &str, default: usize) -> usize {
    match std::env::var(key) {
        Ok(v) => v
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("{key}={v:?} is not a valid integer")),
        Err(_) => default,
    }
}

fn connect(addr: &str) -> TcpStream {
    let stream = TcpStream::connect(addr)
        .unwrap_or_else(|e| panic!("gdbstub {addr:?}: could not connect: {e}"));
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("set read timeout");
    stream
}

#[test]
fn hil_board_gdb_path_runs_when_a_probe_is_configured() {
    let board = if let Some(profile) = std::env::var_os("BHF_HIL_PROFILE") {
        Board::from_profile(Path::new(&profile))
    } else if let Ok(gdb) = std::env::var("BHF_HIL_GDB") {
        Board::from_env(gdb)
    } else {
        eprintln!(
            "hil_board: SKIPPED — set BHF_HIL_PROFILE=board.toml (or BHF_HIL_GDB=host:port, \
             e.g. 127.0.0.1:3333 from OpenOCD) with a board attached to run the real-hardware \
             path. See docs/hil-bringup.md."
        );
        return;
    };
    eprintln!(
        "hil_board: driving the real RSP client against gdbstub at {}",
        board.gdb
    );
    board.attach();
    if board.map.is_some() {
        let input = decode_hex(&std::env::var("BHF_HIL_INPUT").unwrap_or_default());
        let outcome = board.run(&[input]).remove(0);
        assert!(
            !outcome.coverage_edges.is_empty(),
            "a configured coverage ring must yield at least one edge; \
             check the ring map and that the harness emitted breadcrumbs"
        );
    } else {
        eprintln!(
            "hil_board: no coverage map (set a profile's coverage_map, or BHF_HIL_INPUT_ADDR, \
             BHF_HIL_RING_ADDR, BHF_HIL_RING_WRITE_ADDR and BHF_HIL_RING_WRAPPED_ADDR) to \
             exercise run_input and the ring readback."
        );
    }
    eprintln!("hil_board: PASSED against gdbstub {}", board.gdb);
}

/// A Cortex-M firmware that starts as a board's does: its reset handler
/// zeroes `.bss` (the ring and the fault word), and the host's input lives in
/// `.noinit`, which the startup leaves alone. The input's first byte picks a
/// path: 0xF7 faults, and the HardFault handler records the fault and returns
/// through `harness_done`.
#[cfg(unix)]
const STAND_IN_C: &str = r#"#include <stdint.h>
extern uint32_t _estack, _sbss, _ebss;
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
volatile uint32_t adafuzz_probe_memory_buffer_write;
volatile uint8_t  adafuzz_probe_memory_buffer_wrapped;
volatile uint32_t bhf_fault_flag;
__attribute__((section(".noinit"))) volatile uint8_t bhf_input[64];
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
  ring_write_byte((uint8_t)id);
  ring_write_byte((uint8_t)(id >> 8));
  ring_write_byte((uint8_t)(id >> 16));
  ring_write_byte((uint8_t)(id >> 24));
}
void harness_done(void){ while(1){} }
void HardFault_Handler(void){
  emit_crumb(0xFA17);
  bhf_fault_flag = 0xDEADFA11u;
  harness_done();
}
void Reset_Handler(void){
  for (volatile uint32_t *p = &_sbss; p < &_ebss; p++) *p = 0;
  emit_crumb(0x100);
  uint8_t b = bhf_input[0];
  if (b == 0xF7) {
    emit_crumb(0x1FA);
    __asm volatile("udf #0");
  } else if (b == 0x42) {
    emit_crumb(0x200);
    emit_crumb(0x201);
  } else {
    emit_crumb(0x300);
  }
  harness_done();
}
"#;

#[cfg(unix)]
const STAND_IN_LD: &str = r#"MEMORY {
  FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 4M
  RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 4M
}
ENTRY(Reset_Handler)
SECTIONS {
  .text : { KEEP(*(.isr_vector)) *(.text*) *(.rodata*) } > FLASH
  .data : { *(.data*) } > RAM
  .bss (NOLOAD) : { _sbss = .; *(.bss*) *(COMMON) . = ALIGN(4); _ebss = .; } > RAM
  .noinit (NOLOAD) : { *(.noinit*) } > RAM
  . = ALIGN(8);
  _estack = ORIGIN(RAM) + LENGTH(RAM);
}
"#;

/// The board lane against QEMU standing in for a board (#293): the profile
/// carries the completion breakpoint, the fault word and a monitor reset
/// (QEMU's system gdbstub refuses `R`), and each input runs from reset.
#[cfg(unix)]
#[test]
fn hil_board_profile_runs_against_the_qemu_stand_in() {
    use std::process::Command;
    const TEST: &str = "hil_board_profile_runs_against_the_qemu_stand_in";
    if let Err(reason) = common::gate(TEST, &["arm-none-eabi-gcc", "qemu-system-arm"]) {
        eprintln!("{reason}");
        return;
    }
    let dir = common::TempDir::new("hil-board-stand-in").expect("temp dir");
    let (src, ld, elf) = (dir.join("fw.c"), dir.join("fw.ld"), dir.join("fw.elf"));
    std::fs::write(&src, STAND_IN_C).unwrap();
    std::fs::write(&ld, STAND_IN_LD).unwrap();
    let built = Command::new("arm-none-eabi-gcc")
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
        .expect("run arm-none-eabi-gcc");
    assert!(built.success(), "the stand-in firmware did not build");
    let nm = if common::tool_on_path("arm-none-eabi-nm") {
        "arm-none-eabi-nm"
    } else {
        "nm"
    };
    let symbol = |name: &str| common::nm_symbol(nm, &elf, name);

    let port = common::free_tcp_port();
    let qemu = Command::new("qemu-system-arm")
        .args(["-M", "mps2-an385", "-nographic", "-S", "-kernel"])
        .arg(&elf)
        .arg("-gdb")
        .arg(format!("tcp::{port}"))
        .spawn()
        .expect("spawn qemu-system-arm");
    let _qemu = common::ChildGuard::new(qemu, "qemu-system-arm");
    drop(
        common::connect_tcp_retry(port, Duration::from_secs(45))
            .expect("qemu's gdbstub never came up"),
    );

    // The profile a bring-up writes, as docs/hil-boards/qemu-mps2-an385.toml.
    let profile = dir.join("board.toml");
    std::fs::write(
        &profile,
        format!(
            "name = \"qemu-mps2-an385\"\n\
             gdb = \"gdb:127.0.0.1:{port},done={:#x},fault={:#x},reset=monitor:system_reset\"\n\
             coverage_map = \"input={:#x},input_cap=64,ring={:#x},write={:#x},wrapped={:#x},cap=512\"\n",
            symbol("harness_done"),
            symbol("bhf_fault_flag"),
            symbol("bhf_input"),
            symbol("adafuzz_probe_memory_buffer"),
            symbol("adafuzz_probe_memory_buffer_write"),
            symbol("adafuzz_probe_memory_buffer_wrapped"),
        ),
    )
    .unwrap();
    let board = Board::from_profile(&profile);
    assert_eq!(board.reset, ResetMode::Monitor("system_reset".to_owned()));
    board.attach();

    let outcomes = board.run(&[b"A".to_vec(), vec![0xF7], b"B".to_vec(), b"A".to_vec()]);
    let edges: Vec<&[u32]> = outcomes
        .iter()
        .map(|o| o.coverage_edges.as_slice())
        .collect();
    assert_eq!(edges[0], [0x100, 0x300]);
    assert_eq!(edges[1], [0x100, 0x1FA, 0xFA17]);
    assert_eq!(edges[2], [0x100, 0x200, 0x201]);
    // Each input runs from reset: the ring the startup cleared holds only
    // its own path, not the earlier ones'.
    assert_eq!(edges[3], edges[0]);
    let exits: Vec<_> = outcomes.iter().map(|o| o.exit).collect();
    use target_transport::ExitKind::{Crash, Ok};
    assert_eq!(exits, [Ok, Crash, Ok, Ok]);
    let fault = outcomes[1].fault.as_ref().expect("the fault word's fault");
    assert!(fault.detail.contains("0xdeadfa11"), "{}", fault.detail);
    assert!(outcomes
        .iter()
        .all(|o| o.coverage_incomplete.is_none() && o.inconclusive.is_none()));
}

/// Decode an optional hex string (e.g. "deadbeef") into bytes; empty -> empty.
fn decode_hex(text: &str) -> Vec<u8> {
    let text = text.trim();
    if text.is_empty() {
        return Vec::new();
    }
    assert!(
        text.len().is_multiple_of(2),
        "BHF_HIL_INPUT must have an even number of hex digits"
    );
    (0..text.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&text[i..i + 2], 16)
                .unwrap_or_else(|_| panic!("BHF_HIL_INPUT has a non-hex digit near {i}"))
        })
        .collect()
}
