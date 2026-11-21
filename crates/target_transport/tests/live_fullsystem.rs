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
use target_transport::fast_snapshot::{
    DIRTY_PAGE_PLUGIN_LIBRARY_NAME, DIRTY_PAGE_PLUGIN_SOURCE, DIRTY_PAGE_PLUGIN_SOURCE_NAME,
};
use target_transport::{
    ExitKind, FaultKind, FullSystemReset, FullSystemTransport, GdbMemoryMap, GuestFaultStatus,
    ResetKind, RunOutcome, TargetSession, TargetTransport, TransportError,
};

const CC: &str = "arm-none-eabi-gcc";
const QEMU: &str = "qemu-system-arm";
const QEMU_IMG: &str = "qemu-img";
/// The host C compiler that builds the dirty-page plugin (#347).
const HOST_CC: &str = "cc";

const RING_CAP: usize = 512;

/// The benchmarks take turns: run together (as `--ignored` runs them), each
/// would time the other's guests too.
static BENCHMARK: Mutex<()> = Mutex::new(());

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

#ifdef BHF_STATE
/* reset=fast's blind spots: RAM no image segment covers, so a machine reset
   leaves it as the last run did. A word set through the SRAM bit-band alias,
   which QEMU writes without a guest store: */
#define STATE_WORD (*(volatile uint32_t *)0x20010000u)
#define STATE_BIT  (*(volatile uint32_t *)(0x22000000u + (0x10000u << 5)))
/* and the page a fault's exception frame reaches into, which no store writes. */
#define FRAME_PAGE ((volatile uint32_t *)0x20020000u)
#endif

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
#ifdef BHF_STATE
  if (STATE_WORD != 0) emit_crumb(0x5B);   /* an earlier run's bit-band store */
  if ((FRAME_PAGE[0] | FRAME_PAGE[1] | FRAME_PAGE[2] | FRAME_PAGE[3]) != 0)
    emit_crumb(0x5F);                      /* an earlier fault's frame */
  STATE_BIT = 1;
#endif
  uint8_t b = bhf_input[0];
  if (b == 0xF7) {
    emit_crumb(0x1FA);           /* "danger" edge, just before the fault */
    __asm volatile("udf #0");    /* REAL undefined instruction -> HardFault */
    emit_crumb(0x1FB);           /* must NOT be reached */
#ifdef BHF_STATE
  } else if (b == 0xF5) {
    emit_crumb(0x1F5);
    /* Fault on a stack whose 32-byte frame reaches 16 bytes into FRAME_PAGE;
       the handler's own stores land below it. */
    __asm volatile("movw r0, #0x0010\n\tmovt r0, #0x2002\n\tmov sp, r0\n\tudf #1"
                   ::: "r0", "memory");
#endif
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
    boot_with_plugin(dir, elf, None)
}

/// Build the dirty-page QEMU plugin (`reset=fast`, #347) in `dir`.
fn build_dirty_page_plugin(dir: &TempDir) -> PathBuf {
    let source = dir.join(DIRTY_PAGE_PLUGIN_SOURCE_NAME);
    let library = dir.join(DIRTY_PAGE_PLUGIN_LIBRARY_NAME);
    std::fs::write(&source, DIRTY_PAGE_PLUGIN_SOURCE).expect("write the plugin source");
    let built = Command::new(HOST_CC)
        .args(["-shared", "-fPIC", "-O2", "-Wall", "-Werror", "-o"])
        .arg(&library)
        .arg(&source)
        .arg("-lpthread")
        .output()
        .unwrap_or_else(|e| panic!("failed to run {HOST_CC}: {e}"));
    assert!(
        built.status.success(),
        "{HOST_CC} failed to build the dirty-page plugin: {}",
        String::from_utf8_lossy(&built.stderr)
    );
    library
}

/// [`boot`], with QEMU loading the dirty-page `plugin` and its `log` when
/// given.
fn boot_with_plugin(
    dir: &TempDir,
    elf: &std::path::Path,
    plugin: Option<(&Path, &Path)>,
) -> LiveTarget {
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
        .args(
            plugin
                .map(|(plugin, log)| {
                    [
                        "-plugin".to_owned(),
                        format!("{},log={}", plugin.display(), log.display()),
                    ]
                })
                .into_iter()
                .flatten(),
        )
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {QEMU}: {e}"));
    let guard = ChildGuard::new(child, format!("{QEMU} mps2-an385 gdb:{gdb_port}"));
    eprintln!(
        "live_fullsystem: launched `{QEMU} -M mps2-an385 -kernel {} -S -gdb tcp::{gdb_port} \
         -drive if=none,file=<scratch.qcow2>,format=qcow2,id=sc0 -qmp unix:{},server,nowait{}`",
        elf.display(),
        qmp_path.display(),
        plugin
            .map(|(plugin, log)| format!(" -plugin {},log={}", plugin.display(), log.display()))
            .unwrap_or_default()
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
    /// `-DBHF_STATE`, `-O0`: each run sets a word through the bit-band alias
    /// and input `0xF5` faults with its frame reaching into a page no store
    /// writes, both in RAM no image segment covers; a run that finds either
    /// left from an earlier one emits a crumb for it.
    State,
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
        Image::State => (Some("-DBHF_STATE"), "-O0"),
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
    /// The dirty-page log QEMU's plugin writes, when it loads one.
    dirty_log: Option<PathBuf>,
}

impl Rig {
    fn boot(dir: &TempDir, elf: &Path) -> Self {
        Self::boot_with_plugin(dir, elf, None)
    }

    /// Boot with the dirty-page plugin at `plugin` loaded, its log in `dir`.
    fn boot_fast(dir: &TempDir, elf: &Path, plugin: &Path) -> Self {
        Self::boot_with_plugin(dir, elf, Some(plugin))
    }

    fn boot_with_plugin(dir: &TempDir, elf: &Path, plugin: Option<&Path>) -> Self {
        let dirty_log = plugin.map(|_| dir.join("dirty.log"));
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
        let target = boot_with_plugin(dir, elf, plugin.zip(dirty_log.as_deref()));
        Self {
            target,
            map,
            harness_done: common::nm_symbol("nm", elf, "harness_done") & !1,
            fault_flag: common::nm_symbol("nm", elf, "bhf_fault_flag"),
            sent: Arc::new(Mutex::new(Vec::new())),
            dirty_log,
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
        let mut transport =
            FullSystemTransport::new(connect_qmp, connect_gdb, self.map, "bhf_base")
                .expect("build FullSystemTransport")
                .with_harness_breakpoint(self.harness_done, 2)
                .with_fault_status(
                    GuestFaultStatus::new(self.fault_flag, 4, 0).expect("fault word"),
                )
                .with_exec_deadline(Some(deadline))
                .with_reset(reset);
        if let Some(log) = &self.dirty_log {
            transport = transport.with_dirty_log(log);
        }
        transport.arm().expect("arm the live full-system target")
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
    let _turn = BENCHMARK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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

// ---------------------------------------------------------------------------
// reset=fast: the dirty-page fast snapshot (#347)
// ---------------------------------------------------------------------------

/// The tools the fast snapshot's live tests need: the RV-3 set and a host C
/// compiler for the plugin.
const FAST_TOOLS: [&str; 4] = [CC, QEMU, QEMU_IMG, HOST_CC];

#[test]
fn live_fullsystem_fast_snapshot_brings_a_fault_back_without_a_loadvm() {
    if let Err(reason) = gate(
        "live_fullsystem_fast_snapshot_brings_a_fault_back_without_a_loadvm",
        &FAST_TOOLS,
    ) {
        eprintln!("{reason}");
        return;
    }
    let dir = TempDir::new("bhf-live-fs-fast").expect("temp dir");
    let plugin = build_dirty_page_plugin(&dir);
    let elf = build_image(&dir, Image::Plain);
    let rig = Rig::boot_fast(&dir, &elf, &plugin);
    let mut session = rig.arm(FullSystemReset::Fast, Duration::from_secs(10));

    // Two faults in a row: a HardFault leaves the CPU in handler mode with the
    // fault active, and a second one there would lock the core up, so the
    // second fault's handler running shows the reset cleared the first.
    let script = [
        0x42, 0x00, 0xF7, 0xF7, 0x42, 0x00, 0xF7, 0x42, 0xF7, 0xF7, 0x00,
    ];
    let mut kinds = Vec::new();
    for (index, byte) in script.into_iter().enumerate() {
        let outcome = run(&mut session, byte);
        let reset = outcome.target.reset;
        eprintln!(
            "live_fullsystem fast: input={byte:#04x} edges={:x?} exit={:?} reset={reset:?} \
             loadvms={}",
            outcome.coverage_edges,
            outcome.exit,
            loadvms(&rig.sent)
        );
        assert_eq!(
            outcome.coverage_edges,
            edges(byte, false),
            "input {index}: {byte:#04x}"
        );
        if byte == 0xF7 {
            assert_eq!(outcome.exit, ExitKind::Crash, "input {index}");
            assert_eq!(
                outcome.fault.expect("the HardFault carries a fault").kind,
                FaultKind::CpuException
            );
        } else {
            assert_eq!(outcome.exit, ExitKind::Ok, "input {index}: {outcome:?}");
            assert!(
                outcome.fault.is_none(),
                "the fault word was put back: {outcome:?}"
            );
        }
        assert_eq!(
            reset.is_none(),
            index == 0,
            "every input but the first resets"
        );
        kinds.extend(reset.map(|reset| reset.kind));
    }
    // A loadvm only while bhf learns the pages a run writes: the first reset,
    // and at most one more for a page only the fault path writes.
    let full = kinds
        .iter()
        .filter(|kind| **kind == ResetKind::Full)
        .count();
    assert_eq!(
        kinds[0],
        ResetKind::Full,
        "the first reset learns the pages"
    );
    assert!(full <= 2, "{kinds:?}");
    assert_eq!(loadvms(&rig.sent), full);
    // Every reset after the first fault's page was learned is a dirty-page one,
    // the resets after a fault included.
    assert!(
        kinds[4..].iter().all(|kind| *kind == ResetKind::DirtyPages),
        "{kinds:?}"
    );
}

/// How many times lower `reset=fast`'s mean reset must be than a `loadvm`'s.
/// Local runs measure 12.4x to 20.8x and a loaded scheduled runner has
/// measured 9.5x (#452), so 5x stays clear of the runners' timing noise and
/// still fails a fast snapshot that regresses toward a `loadvm`'s cost.
const FAST_RESET_MIN_SPEEDUP: f64 = 5.0;

/// The measured speedup of `fast_mean` over `loadvm_mean`, or the benchmark's
/// failure message when it is under [`FAST_RESET_MIN_SPEEDUP`].
fn fast_reset_speedup(loadvm_mean: Duration, fast_mean: Duration) -> Result<f64, String> {
    let ratio = loadvm_mean.as_secs_f64() / fast_mean.as_secs_f64().max(f64::MIN_POSITIVE);
    if ratio >= FAST_RESET_MIN_SPEEDUP {
        Ok(ratio)
    } else {
        Err(format!(
            "reset=fast's mean reset took {fast_mean:?}, a loadvm {loadvm_mean:?}: \
             {ratio:.1}x lower, under the {FAST_RESET_MIN_SPEEDUP}x required"
        ))
    }
}

/// The threshold passes the slowest speedup a scheduled runner has measured
/// (9.5x) and fails a fast snapshot that is no faster than a `loadvm`.
#[test]
fn the_fast_reset_threshold_passes_runner_noise_and_fails_parity() {
    let loadvm = Duration::from_micros(5_700);
    for measured in [9.5, 12.4, 20.8] {
        let ratio = fast_reset_speedup(loadvm, loadvm.div_f64(measured))
            .unwrap_or_else(|failure| panic!("{measured}x: {failure}"));
        assert!(
            (ratio - measured).abs() < 0.01,
            "{measured}x read as {ratio}x"
        );
    }
    for measured in [0.5, 1.0, 2.0, 4.9] {
        let failure = fast_reset_speedup(loadvm, loadvm.div_f64(measured))
            .expect_err("a speedup under the threshold fails");
        assert!(
            failure.contains(&format!("{measured:.1}x lower")),
            "the message reports the measured ratio: {failure}"
        );
    }
}

/// The reset latency the dirty-page fast snapshot buys over a `loadvm`, both
/// measured here on the same image and inputs, faults included (run nightly
/// by scripts/hil-emu.sh).
#[test]
#[ignore = "benchmark: run with --ignored (nightly, live QEMU)"]
fn live_fullsystem_fast_snapshot_resets_five_times_faster_than_loadvm() {
    if let Err(reason) = gate(
        "live_fullsystem_fast_snapshot_resets_five_times_faster_than_loadvm",
        &FAST_TOOLS,
    ) {
        eprintln!("{reason}");
        return;
    }
    let _turn = BENCHMARK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Each mode gets the window in slices taken in turn, so a change in the
    // host's load meets both alike.
    const SLICE: Duration = Duration::from_millis(500);
    const SLICES: u32 = 6;
    const INPUTS: [u8; 3] = [0x42, 0x00, 0xF7];
    let build = TempDir::new("bhf-live-fs-fast-bench").expect("temp dir");
    let plugin = build_dirty_page_plugin(&build);
    let elf = build_image(&build, Image::Plain);
    let loadvm_dir = TempDir::new("bhf-live-fs-fast-bench-loadvm").expect("temp dir");
    let loadvm_rig = Rig::boot(&loadvm_dir, &elf);
    let fast_dir = TempDir::new("bhf-live-fs-fast-bench-fast").expect("temp dir");
    let fast_rig = Rig::boot_fast(&fast_dir, &elf, &plugin);
    let mut loadvm = loadvm_rig.arm(FullSystemReset::Loadvm, Duration::from_secs(10));
    let mut fast = fast_rig.arm(FullSystemReset::Fast, Duration::from_secs(10));

    /// The reset times of the runs in a slice, by kind.
    #[derive(Default)]
    struct Resets {
        full: Vec<Duration>,
        dirty_pages: Vec<Duration>,
    }
    let slice = |session: &mut Box<dyn TargetSession>, resets: &mut Resets, runs: &mut usize| {
        let start = Instant::now();
        while start.elapsed() < SLICE {
            let byte = INPUTS[*runs % INPUTS.len()];
            let outcome = run(session, byte);
            let expected = if byte == 0xF7 {
                ExitKind::Crash
            } else {
                ExitKind::Ok
            };
            assert_eq!(outcome.exit, expected, "input {byte:#04x}: {outcome:?}");
            assert_eq!(outcome.coverage_edges, edges(byte, false), "run {runs}");
            let reset = outcome
                .target
                .reset
                .expect("every measured run follows a reset");
            match reset.kind {
                ResetKind::Full => resets.full.push(reset.time),
                ResetKind::DirtyPages => resets.dirty_pages.push(reset.time),
            }
            *runs += 1;
        }
    };
    // Warm up: the fast snapshot learns the pages these inputs write, and
    // each guest's code is translated once, before anything is measured.
    for byte in INPUTS.iter().cycle().take(3 * INPUTS.len()) {
        run(&mut loadvm, *byte);
        run(&mut fast, *byte);
    }

    let (mut loadvm_resets, mut fast_resets) = (Resets::default(), Resets::default());
    let (mut loadvm_runs, mut fast_runs) = (0_usize, 0_usize);
    for _ in 0..SLICES {
        slice(&mut loadvm, &mut loadvm_resets, &mut loadvm_runs);
        slice(&mut fast, &mut fast_resets, &mut fast_runs);
    }
    assert!(loadvm_resets.dirty_pages.is_empty());
    assert!(
        fast_resets.full.is_empty(),
        "once warm, no fast reset needs a loadvm: {} did",
        fast_resets.full.len()
    );

    let mean = |times: &[Duration]| times.iter().sum::<Duration>() / times.len().max(1) as u32;
    let loadvm_mean = mean(&loadvm_resets.full);
    let fast_mean = mean(&fast_resets.dirty_pages);
    let ratio = loadvm_mean.as_secs_f64() / fast_mean.as_secs_f64().max(f64::MIN_POSITIVE);
    let secs = (SLICE * SLICES).as_secs_f64();
    eprintln!(
        "live_fullsystem fast bench: window={secs}s loadvm: {loadvm_runs} runs ({:.1} exec/s), \
         mean reset {loadvm_mean:?}; fast: {fast_runs} runs ({:.1} exec/s), mean reset \
         {fast_mean:?}; reset latency {ratio:.1}x lower",
        loadvm_runs as f64 / secs,
        fast_runs as f64 / secs,
    );
    if let Err(failure) = fast_reset_speedup(loadvm_mean, fast_mean) {
        panic!("{failure}");
    }
}

/// The edges a run of `byte` takes in the [`Image::State`] harness when it
/// starts from the baseline: `0xF5` faults on a moved stack.
fn state_edges(byte: u8) -> Vec<u32> {
    match byte {
        0xF5 => vec![0x100, 0x101, 0x1F5, 0xFA17],
        byte => edges(byte, false),
    }
}

#[test]
fn live_fullsystem_fast_snapshot_restores_bitband_stores_and_fault_frames() {
    if let Err(reason) = gate(
        "live_fullsystem_fast_snapshot_restores_bitband_stores_and_fault_frames",
        &FAST_TOOLS,
    ) {
        eprintln!("{reason}");
        return;
    }
    let dir = TempDir::new("bhf-live-fs-fast-state").expect("temp dir");
    let plugin = build_dirty_page_plugin(&dir);
    let elf = build_image(&dir, Image::State);
    let rig = Rig::boot_fast(&dir, &elf, &plugin);
    let mut session = rig.arm(FullSystemReset::Fast, Duration::from_secs(10));

    // Every run sets the bit-band word; 0xF5 stacks a frame into a page no
    // store writes. A run that finds either from the run before emits 0x5B
    // or 0x5F, which a run from the baseline, as under loadvm, never does.
    let script = [0x42, 0xF5, 0x42, 0x00, 0xF5, 0xF5, 0x42, 0x00, 0xF5, 0x42];
    let mut kinds = Vec::new();
    for (index, byte) in script.into_iter().enumerate() {
        let outcome = run(&mut session, byte);
        eprintln!(
            "live_fullsystem fast state: input={byte:#04x} edges={:x?} exit={:?} reset={:?}",
            outcome.coverage_edges, outcome.exit, outcome.target.reset
        );
        assert_eq!(
            outcome.coverage_edges,
            state_edges(byte),
            "input {index} ({byte:#04x}) did not run from the baseline"
        );
        let expected = if byte == 0xF5 {
            ExitKind::Crash
        } else {
            ExitKind::Ok
        };
        assert_eq!(outcome.exit, expected, "input {index}: {outcome:?}");
        kinds.extend(outcome.target.reset.map(|reset| reset.kind));
    }
    // Once the pages are learned the resets are fast, those after a fault
    // included.
    assert!(
        kinds[3..].iter().all(|kind| *kind == ResetKind::DirtyPages),
        "{kinds:?}"
    );
}

#[test]
fn live_fullsystem_fast_snapshot_refuses_a_log_no_plugin_writes() {
    if let Err(reason) = gate(
        "live_fullsystem_fast_snapshot_refuses_a_log_no_plugin_writes",
        &[CC, QEMU, QEMU_IMG],
    ) {
        eprintln!("{reason}");
        return;
    }
    // QEMU without the plugin, and a well-formed log from some other run at
    // dirty_log=: no store would be logged, so state would carry from one
    // input to the next. The first reset after a run refuses it.
    let dir = TempDir::new("bhf-live-fs-fast-stale").expect("temp dir");
    let elf = build_image(&dir, Image::Plain);
    let mut rig = Rig::boot(&dir, &elf);
    let log = dir.join("stale.log");
    target_transport::testsupport::DirtyLogFile::create(&log, 8, 64).expect("write a stale log");
    rig.dirty_log = Some(log);
    let mut session = rig.arm(FullSystemReset::Fast, Duration::from_secs(10));
    assert_eq!(run(&mut session, 0x42).exit, ExitKind::Ok);
    let message = session
        .run_input(&[0x42])
        .expect_err("a log no plugin writes is refused")
        .to_string();
    assert!(
        message.contains("no dirty-page plugin saw it run") && message.contains("-plugin"),
        "{message}"
    );
}
