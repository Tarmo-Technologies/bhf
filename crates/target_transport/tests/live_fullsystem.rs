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
//!
//! The shared emulator helpers use Unix sockets: Unix hosts only.
#![cfg(unix)]

mod common;

use common::{connect_tcp_retry, connect_unix_retry, gate, ChildGuard, TempDir};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use target_transport::{
    ExitKind, FaultKind, FullSystemReset, FullSystemTransport, GdbMemoryMap, GuestFaultStatus,
    RunOutcome, TargetSession, TargetTransport, TransportError,
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

#ifdef BHF_PERSISTENT
/* reset=persistent: done returns into the input loop in Reset_Handler. */
__attribute__((noinline)) void harness_done(void){ __asm volatile("" ::: "memory"); }
#elif defined(BHF_SPIN_DONE)
/* done spins in place: built -O1, this is a single `b.n .`. */
__attribute__((noinline, used)) void harness_done(void){ for(;;){} }
#else
void harness_done(void){ while(1){} }   /* host plants a gdb breakpoint here */
#endif

void HardFault_Handler(void){
  emit_crumb(0xFA17);            /* distinct fault-path marker breadcrumb */
  bhf_fault_flag = 0xDEADFA11u;
  harness_done();
  for (;;) {}
}

static void run_one(void){
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
}

#ifdef BHF_PERSISTENT
/* Counts the loop's turns since the snapshot: only a restore clears it, so
 * the 0x50 crumb marks the first input after one. */
volatile uint32_t bhf_turns = 0;
#endif

void Reset_Handler(void){
#ifdef BHF_PERSISTENT
  for (;;) {
    if (bhf_turns++ == 0) emit_crumb(0x50);
    run_one();
    harness_done();
  }
#else
  run_one();
  harness_done();
#endif
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
    // The firmware's HardFault_Handler records the fault in this data word before
    // returning through harness_done; it is the explicit fault-status channel.
    let fault_flag_address = common::nm_symbol("nm", &elf, "bhf_fault_flag");
    eprintln!(
        "live_fullsystem: map input={input_address:#x} ring={ring_address:#x} \
         write={ring_write_address:#x} wrapped={ring_wrapped_address:#x} \
         harness_done={harness_done:#x} fault_flag={fault_flag_address:#x}"
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
        .with_harness_breakpoint(harness_done, 2)
        // The HardFault handler returns through harness_done, so its SIGTRAP
        // looks benign; the fault-status word makes the crash observable (#72).
        .with_fault_status(
            GuestFaultStatus::new(fault_flag_address, 4, 0).expect("fault-status contract"),
        );

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
    // #72: the HardFault must surface as a classified crash through the fault
    // channel, not a silent clean pass — coverage reachability is NOT the proof.
    assert_eq!(
        out_fault.exit,
        ExitKind::Crash,
        "the planted HardFault must classify as a crash, not a clean completion"
    );
    let fault = out_fault
        .fault
        .as_ref()
        .expect("the HardFault must carry a structured fault record");
    assert_eq!(fault.kind, FaultKind::CpuException);
    eprintln!(
        "live_fullsystem: input=0xF7 edges={:x?} exit={:?} fault={:?} — REAL Cortex-M HardFault classified",
        out_fault.coverage_edges, out_fault.exit, fault.kind
    );

    // ---- determinism: the snapshot reset makes the same input reproducible even
    // after a fault iteration contaminated the guest ----
    let out_repeat = run(&mut session, 0x42);
    assert_eq!(
        out_repeat.coverage_edges, out_normal.coverage_edges,
        "same input after loadvm reset must reproduce identical coverage"
    );
    // #72: the loadvm reset must also clear the firmware fault flag the previous
    // iteration set — a clean input after a fault must not inherit the crash.
    assert_eq!(
        out_repeat.exit,
        ExitKind::Ok,
        "a clean input after a fault must reset to Ok, not inherit the fault flag"
    );
    assert!(
        out_repeat.fault.is_none(),
        "the fault flag must not carry over across the snapshot reset"
    );
    eprintln!(
        "live_fullsystem: determinism — 0x42 again edges={:x?} exit={:?} (== first run, fault cleared)",
        out_repeat.coverage_edges, out_repeat.exit
    );

    eprintln!(
        "live_fullsystem: PASSED — live snapshot reset + coverage-ring readback + \
         planted-fault detection on real emulated Cortex-M"
    );
}

// ---------------------------------------------------------------------------
// reset=persistent: the guest's own input loop between clean inputs
// ---------------------------------------------------------------------------

/// Which build of the harness a test boots.
#[derive(Clone, Copy)]
enum Image {
    /// `-O0`, `harness_done` spins after its prologue: the RV-3 image.
    Plain,
    /// `-DBHF_PERSISTENT`, `-O0`: `harness_done` returns into an input loop.
    Persistent,
    /// `-DBHF_SPIN_DONE`, `-O1`: `harness_done` is one `b.n .`, a branch to
    /// itself.
    SpinningDone,
}

/// Build the harness as `image`.
fn build_image(dir: &TempDir, image: Image) -> PathBuf {
    let src = dir.join("harness.c");
    let ld = dir.join("harness.ld");
    let elf = dir.join("harness.elf");
    std::fs::write(&src, HARNESS_C).expect("write harness.c");
    std::fs::write(&ld, HARNESS_LD).expect("write harness.ld");
    let (define, optimization) = match image {
        Image::Plain => (None, "-O0"),
        Image::Persistent => (Some("-DBHF_PERSISTENT"), "-O0"),
        Image::SpinningDone => (Some("-DBHF_SPIN_DONE"), "-O1"),
    };
    let mut cc = Command::new(CC);
    cc.args([
        "-mcpu=cortex-m3",
        "-mthumb",
        "-nostdlib",
        "-nostartfiles",
        "-ffreestanding",
        optimization,
        "-g",
    ]);
    cc.args(define);
    let built = cc
        .arg("-T")
        .arg(&ld)
        .arg("-o")
        .arg(&elf)
        .arg(&src)
        .status()
        .unwrap_or_else(|e| panic!("failed to run {CC}: {e}"));
    assert!(built.success(), "{CC} failed to build the bare-metal image");
    elf
}

/// A QMP channel that keeps what bhf sends on it, to count its restores.
struct Recorded<S> {
    inner: S,
    sent: Arc<Mutex<Vec<u8>>>,
}

impl<S: Read> Read for Recorded<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<S: Write> Write for Recorded<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.sent.lock().unwrap().extend_from_slice(&buf[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// The `loadvm`s sent on a [`Recorded`] channel.
fn loadvms(sent: &Arc<Mutex<Vec<u8>>>) -> usize {
    let sent = sent.lock().unwrap();
    sent.windows(b"loadvm ".len())
        .filter(|window| *window == b"loadvm ")
        .count()
}

/// A booted image and the transport that drives it with `reset`, its QMP
/// traffic kept in `sent`.
struct Rig {
    target: LiveTarget,
    map: GdbMemoryMap,
    harness_done: u64,
    fault_flag: u64,
    sent: Arc<Mutex<Vec<u8>>>,
}

impl Rig {
    fn boot(dir: &TempDir, elf: &Path) -> Self {
        let map = GdbMemoryMap {
            input_address: common::nm_symbol("nm", elf, "bhf_input"),
            ring_address: common::nm_symbol("nm", elf, "adafuzz_probe_memory_buffer"),
            ring_write_address: common::nm_symbol("nm", elf, "adafuzz_probe_memory_buffer_write"),
            ring_wrapped_address: common::nm_symbol(
                "nm",
                elf,
                "adafuzz_probe_memory_buffer_wrapped",
            ),
            ring_capacity: RING_CAP,
        };
        Self {
            target: boot(dir, elf),
            map,
            harness_done: common::nm_symbol("nm", elf, "harness_done") & !1,
            fault_flag: common::nm_symbol("nm", elf, "bhf_fault_flag"),
            sent: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn arm(&self, reset: FullSystemReset, deadline: Duration) -> Box<dyn TargetSession> {
        let qmp_path = self.target.qmp_path.clone();
        let sent = Arc::clone(&self.sent);
        let connect_qmp =
            move || -> Result<Recorded<std::os::unix::net::UnixStream>, TransportError> {
                let stream = connect_unix_retry(&qmp_path, Duration::from_secs(10))?;
                // savevm writes the qcow2, which a busy host's disk can hold up.
                stream.set_read_timeout(Some(Duration::from_secs(120)))?;
                Ok(Recorded {
                    inner: stream,
                    sent: Arc::clone(&sent),
                })
            };
        let gdb_port = self.target.gdb_port;
        let connect_gdb = move || -> Result<std::net::TcpStream, TransportError> {
            let stream = connect_tcp_retry(gdb_port, Duration::from_secs(10))?;
            stream.set_read_timeout(Some(Duration::from_secs(30)))?;
            stream.set_nodelay(true)?;
            Ok(stream)
        };
        FullSystemTransport::new(connect_qmp, connect_gdb, self.map, "bhf_base")
            .expect("build FullSystemTransport")
            .with_harness_breakpoint(self.harness_done, 2)
            .with_fault_status(GuestFaultStatus::new(self.fault_flag, 4, 0).expect("fault word"))
            .with_exec_deadline(Some(deadline))
            .with_reset(reset)
            .arm()
            .expect("arm the live full-system target")
    }
}

fn run(session: &mut Box<dyn TargetSession>, byte: u8) -> RunOutcome {
    session
        .run_input(&[byte])
        .unwrap_or_else(|e| panic!("run_input({byte:#04x}) failed: {e}"))
}

/// The edges a run of `byte` takes in the harness; `fresh` adds the 0x50 the
/// persistent variant emits on its first turn after a restore.
fn edges(byte: u8, fresh: bool) -> Vec<u32> {
    let mut edges = if fresh { vec![0x50] } else { Vec::new() };
    edges.extend([0x100, 0x101]);
    match byte {
        0xF7 => edges.extend([0x1FA, 0xFA17]),
        0x42 => edges.extend([0x200, 0x201]),
        _ => edges.push(0x300),
    }
    edges
}

#[test]
fn live_fullsystem_persistent_loop_restores_only_after_a_fault() {
    if let Err(reason) = gate(
        "live_fullsystem_persistent_loop_restores_only_after_a_fault",
        &[CC, QEMU, QEMU_IMG],
    ) {
        eprintln!("{reason}");
        return;
    }
    let dir = TempDir::new("bhf-live-fs-persistent").expect("temp dir");
    let elf = build_image(&dir, Image::Persistent);
    let rig = Rig::boot(&dir, &elf);
    let mut session = rig.arm(FullSystemReset::Persistent, Duration::from_secs(10));

    // (input, the 0x50 first-turn crumb expected, loadvms sent so far)
    let script: [(u8, bool, usize); 7] = [
        (0x42, true, 1), // the first input runs from the restored snapshot
        (0x00, false, 1),
        (0x42, false, 1),
        (0xF7, false, 1), // the HardFault: found on a continuation
        (0x42, true, 2),  // ... and followed by a loadvm
        (0x00, false, 2),
        (0x42, false, 2),
    ];
    for (byte, fresh, restores) in script {
        let outcome = run(&mut session, byte);
        eprintln!(
            "live_fullsystem persistent: input={byte:#04x} edges={:x?} exit={:?} loadvms={}",
            outcome.coverage_edges,
            outcome.exit,
            loadvms(&rig.sent)
        );
        assert_eq!(
            outcome.coverage_edges,
            edges(byte, fresh),
            "input {byte:#04x}"
        );
        if byte == 0xF7 {
            assert_eq!(outcome.exit, ExitKind::Crash);
            assert_eq!(
                outcome.fault.expect("the HardFault carries a fault").kind,
                FaultKind::CpuException
            );
        } else {
            assert_eq!(outcome.exit, ExitKind::Ok, "input {byte:#04x}");
            assert!(outcome.fault.is_none(), "input {byte:#04x}");
        }
        assert_eq!(loadvms(&rig.sent), restores, "loadvms after {byte:#04x}");
    }
}

#[test]
fn live_fullsystem_persistent_loop_refuses_a_firmware_that_does_not_loop() {
    if let Err(reason) = gate(
        "live_fullsystem_persistent_loop_refuses_a_firmware_that_does_not_loop",
        &[CC, QEMU, QEMU_IMG],
    ) {
        eprintln!("{reason}");
        return;
    }
    // The plain image's harness_done spins, so a continuation never comes back.
    let dir = TempDir::new("bhf-live-fs-noloop").expect("temp dir");
    let elf = build_image(&dir, Image::Plain);
    let rig = Rig::boot(&dir, &elf);
    let mut session = rig.arm(FullSystemReset::Persistent, Duration::from_millis(500));
    // Each hanging continuation is run again from the snapshot and that run
    // reported: no false hang.
    for byte in [0x42, 0x00, 0x42] {
        let outcome = run(&mut session, byte);
        assert_eq!(outcome.exit, ExitKind::Ok, "input {byte:#04x}: {outcome:?}");
        assert_eq!(outcome.coverage_edges, edges(byte, false));
    }
    let error = session
        .run_input(&[0x00])
        .expect_err("a guest that never comes back is refused");
    let message = error.to_string();
    assert!(message.contains("reset=persistent"), "{message}");
    eprintln!("live_fullsystem persistent: refused as expected: {message}");
}

#[test]
fn live_fullsystem_persistent_loop_refuses_a_done_that_spins_in_place() {
    if let Err(reason) = gate(
        "live_fullsystem_persistent_loop_refuses_a_done_that_spins_in_place",
        &[CC, QEMU, QEMU_IMG],
    ) {
        eprintln!("{reason}");
        return;
    }
    // A noinline `for (;;) {}` built -O1 is one `b.n .`: the step off it lands
    // on it again, and a `c` from there stops at once with the ring empty. A
    // continuation must not read that as a clean run of its input.
    let dir = TempDir::new("bhf-live-fs-spin").expect("temp dir");
    let elf = build_image(&dir, Image::SpinningDone);
    let rig = Rig::boot(&dir, &elf);
    let mut session = rig.arm(FullSystemReset::Persistent, Duration::from_secs(10));
    let mut refusals = 0;
    for byte in [0x42, 0x00, 0xF7, 0x42, 0xF7, 0x00, 0xF7] {
        match session.run_input(&[byte]) {
            Ok(outcome) => {
                eprintln!(
                    "live_fullsystem spin: input={byte:#04x} edges={:x?} exit={:?}",
                    outcome.coverage_edges, outcome.exit
                );
                // Every run that is reported ran from the snapshot.
                assert_eq!(
                    outcome.coverage_edges,
                    edges(byte, false),
                    "input {byte:#04x}"
                );
                let expected = if byte == 0xF7 {
                    ExitKind::Crash
                } else {
                    ExitKind::Ok
                };
                assert_eq!(outcome.exit, expected, "input {byte:#04x}: {outcome:?}");
            }
            Err(error) => {
                let message = error.to_string();
                eprintln!("live_fullsystem spin: input={byte:#04x} refused: {message}");
                assert!(
                    message.contains("changed no register") && message.contains("reset=loadvm"),
                    "{message}"
                );
                refusals += 1;
            }
        }
    }
    // A refusal leaves the guest unparked, so the input after it runs from
    // the snapshot, and each input after a clean one is refused.
    assert_eq!(refusals, 3, "inputs 2, 5 and 7 continue a parked guest");
}

/// Run inputs through `session` for `window`, counting into `executions`.
fn run_for(
    session: &mut Box<dyn TargetSession>,
    window: Duration,
    persistent: bool,
    executions: &mut usize,
) {
    let start = Instant::now();
    while start.elapsed() < window {
        let byte = if executions.is_multiple_of(2) {
            0x42
        } else {
            0x00
        };
        let outcome = run(session, byte);
        assert_eq!(outcome.exit, ExitKind::Ok, "input {byte:#04x}: {outcome:?}");
        // A loadvm per input makes every run the loop's first turn.
        let fresh = !persistent || *executions == 0;
        assert_eq!(
            outcome.coverage_edges,
            edges(byte, fresh),
            "run {executions}"
        );
        *executions += 1;
    }
}

/// The throughput the persistent loop buys over a `loadvm` per input, both
/// measured here on the same image (run nightly by scripts/hil-emu.sh).
#[test]
#[ignore = "benchmark: run with --ignored (nightly, live QEMU)"]
fn live_fullsystem_persistent_loop_outruns_a_loadvm_per_input() {
    if let Err(reason) = gate(
        "live_fullsystem_persistent_loop_outruns_a_loadvm_per_input",
        &[CC, QEMU, QEMU_IMG],
    ) {
        eprintln!("{reason}");
        return;
    }
    // Each mode gets the window in slices taken in turn, so a change in the
    // host's load meets both alike.
    const SLICE: Duration = Duration::from_millis(500);
    const SLICES: u32 = 6;
    let build = TempDir::new("bhf-live-fs-bench").expect("temp dir");
    let elf = build_image(&build, Image::Persistent);
    let loadvm_dir = TempDir::new("bhf-live-fs-bench-loadvm").expect("temp dir");
    let loadvm_rig = Rig::boot(&loadvm_dir, &elf);
    let persistent_dir = TempDir::new("bhf-live-fs-bench-persistent").expect("temp dir");
    let persistent_rig = Rig::boot(&persistent_dir, &elf);
    let mut loadvm = loadvm_rig.arm(FullSystemReset::Loadvm, Duration::from_secs(10));
    let mut persistent = persistent_rig.arm(FullSystemReset::Persistent, Duration::from_secs(10));

    let (mut loadvm_runs, mut persistent_runs) = (0_usize, 0_usize);
    for _ in 0..SLICES {
        run_for(&mut loadvm, SLICE, false, &mut loadvm_runs);
        run_for(&mut persistent, SLICE, true, &mut persistent_runs);
    }
    assert_eq!(loadvms(&loadvm_rig.sent), loadvm_runs);
    assert_eq!(
        loadvms(&persistent_rig.sent),
        1,
        "no restore between clean inputs"
    );

    // After thousands of continuations (and their QMP events), a fault is
    // still found and followed by a working loadvm.
    let fault = run(&mut persistent, 0xF7);
    assert_eq!(fault.exit, ExitKind::Crash);
    let after = run(&mut persistent, 0x42);
    assert_eq!(after.exit, ExitKind::Ok);
    assert_eq!(
        after.coverage_edges,
        edges(0x42, true),
        "restored after the fault"
    );
    assert_eq!(loadvms(&persistent_rig.sent), 2);

    let secs = (SLICE * SLICES).as_secs_f64();
    let ratio = persistent_runs as f64 / loadvm_runs.max(1) as f64;
    eprintln!(
        "live_fullsystem bench: window={secs}s loadvm={loadvm_runs} ({:.1} exec/s) \
         persistent={persistent_runs} ({:.1} exec/s) ratio={ratio:.2}x",
        loadvm_runs as f64 / secs,
        persistent_runs as f64 / secs,
    );
    assert!(
        persistent_runs >= 3 * loadvm_runs,
        "reset=persistent ran {persistent_runs} inputs in {secs}s, loadvm per input \
         {loadvm_runs}: under 3x"
    );
}
