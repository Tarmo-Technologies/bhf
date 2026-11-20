// SPDX-License-Identifier: Apache-2.0

//! End-to-end regression for `bhf fuzz --target-transport qemu-system:...` over
//! the bare-metal Cortex-M fixture, through the SHIPPED CLI (not a library-only
//! constructor). It proves the CLI wires the completion contract (#71) — it
//! plants the harness-done breakpoint itself, with no out-of-band debugger — and
//! the firmware fault-status channel (#72), so a planted HardFault seed produces
//! a persisted, classified crash finding.
//!
//! Gated on `arm-none-eabi-gcc` + `qemu-system-arm` + `qemu-img` + `nm`; it
//! self-skips when they are absent (CI runners without the emulator toolchain),
//! exactly like the `target_transport` RV-3 live test it mirrors.

#![cfg(unix)]

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

mod support;

const CC: &str = "arm-none-eabi-gcc";
const QEMU: &str = "qemu-system-arm";
const QEMU_IMG: &str = "qemu-img";
const NM: &str = "nm";
const RING_CAP: usize = 512;

// The Cortex-M fixture mirrors crates/target_transport/tests/live_fullsystem.rs:
// a prologue, an input-gated fault path (0xF7 -> `udf #0` -> HardFault), and a
// HardFault handler that records 0xDEADFA11 in bhf_fault_flag before returning
// through harness_done (where the host plants the completion breakpoint).
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
#ifdef BHF_SEMIHOSTING
/* The semihosting probe's channel (#292): each event goes to the semihosting
 * stderr (`:tt` opened for append), which QEMU's
 * `-semihosting-config target=gdb` hands to the debugger as a File-I/O
 * write to fd 2. */
static int semihost(int op, void *arg){
  register int r0 __asm__("r0") = op;
  register void *r1 __asm__("r1") = arg;
  __asm volatile("bkpt 0xab" : "+r"(r0) : "r"(r1) : "memory");
  return r0;
}
static int bhf_stderr = -1;
static void emit_crumb(uint32_t id){
  if (bhf_stderr < 0) {
    static const char tt[] = ":tt";
    uint32_t open_args[3] = {(uint32_t)tt, 8, 3};
    bhf_stderr = semihost(0x01, open_args);
  }
  uint8_t event[5] = {3, (uint8_t)id, (uint8_t)(id >> 8), (uint8_t)(id >> 16),
                      (uint8_t)(id >> 24)};
  uint32_t write_args[3] = {(uint32_t)bhf_stderr, (uint32_t)event, 5};
  semihost(0x05, write_args);
}
#else
static void emit_crumb(uint32_t id){
  ring_write_byte(3);
  ring_write_byte((uint8_t)(id & 0xff));
  ring_write_byte((uint8_t)((id >> 8) & 0xff));
  ring_write_byte((uint8_t)((id >> 16) & 0xff));
  ring_write_byte((uint8_t)((id >> 24) & 0xff));
}
#endif
volatile uint8_t  bhf_input[64];
volatile uint32_t bhf_fault_flag = 0;
#ifdef BHF_PERSISTENT
/* reset=persistent: done returns into the input loop in Reset_Handler. */
__attribute__((noinline)) void harness_done(void){ __asm volatile("" ::: "memory"); }
#else
void harness_done(void){ while(1){} }
#endif
void HardFault_Handler(void){
  emit_crumb(0xFA17);
  bhf_fault_flag = 0xDEADFA11u;
  harness_done();
  for (;;) {}
}
#ifdef BHF_CMPLOG
/* The comparison record bhf reads after each run (#386), filled by the
 * trace-cmp callbacks of the code under test (check.c). */
#define BHF_CMPLOG_CAP 32
struct bhf_cmp { uint64_t lhs, rhs; uint32_t width, site; };
volatile struct {
  uint32_t count;
  uint32_t reserved;
  struct bhf_cmp entries[BHF_CMPLOG_CAP];
} bhf_cmplog;
#define BHF_CMP(w) do { \
  uint32_t n = bhf_cmplog.count; \
  if (n < BHF_CMPLOG_CAP) { \
    bhf_cmplog.entries[n].lhs = a; \
    bhf_cmplog.entries[n].rhs = b; \
    bhf_cmplog.entries[n].width = w; \
    bhf_cmplog.entries[n].site = (uint32_t)__builtin_return_address(0); \
  } \
  bhf_cmplog.count = n + 1; \
} while (0)
void __sanitizer_cov_trace_cmp1(uint8_t a, uint8_t b){ BHF_CMP(1); }
void __sanitizer_cov_trace_cmp2(uint16_t a, uint16_t b){ BHF_CMP(2); }
void __sanitizer_cov_trace_cmp4(uint32_t a, uint32_t b){ BHF_CMP(4); }
void __sanitizer_cov_trace_cmp8(uint64_t a, uint64_t b){ BHF_CMP(8); }
void __sanitizer_cov_trace_const_cmp1(uint8_t a, uint8_t b){ BHF_CMP(1); }
void __sanitizer_cov_trace_const_cmp2(uint16_t a, uint16_t b){ BHF_CMP(2); }
void __sanitizer_cov_trace_const_cmp4(uint32_t a, uint32_t b){ BHF_CMP(4); }
void __sanitizer_cov_trace_const_cmp8(uint64_t a, uint64_t b){ BHF_CMP(8); }
void __sanitizer_cov_trace_switch(uint64_t v, uint64_t *cases){ (void)v; (void)cases; }
int bhf_check(const volatile uint8_t *in);
/* A fault behind a 4-byte magic, and no other: random mutation does not
 * find 1 in 2^32. */
void Reset_Handler(void){
  emit_crumb(0x100);
  if (bhf_check(bhf_input)) {
    emit_crumb(0x4FA);
    __asm volatile("udf #0");
  }
  emit_crumb(0x400);
  harness_done();
}
#else
static void run_one(void){
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
}
void Reset_Handler(void){
#ifdef BHF_PERSISTENT
  for (;;) { run_one(); harness_done(); }
#else
  run_one();
  harness_done();
#endif
}
#endif
"#;

/// The code under test of the CmpLog variant, built with
/// `-fsanitize-coverage=trace-cmp`: GCC calls
/// `__sanitizer_cov_trace_const_cmp4(0x5AFEC0DE, word)` before the compare.
const CHECK_C: &str = r#"#include <stdint.h>
int bhf_check(const volatile uint8_t *in){
  uint32_t word = (uint32_t)in[0] | ((uint32_t)in[1] << 8) |
                  ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
  return word == 0x5AFEC0DEu;
}
"#;

fn tool_present(tool: &str) -> bool {
    let present = { which::which(tool).is_ok() };
    support::require_tool(present, tool)
}

fn bhf_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bhf"))
}

/// A free loopback TCP port (bind to :0, read the assigned port, release it).
/// Racy by nature, but adequate for a gated single-process emulator test.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

/// Read a symbol's address from `nm`, stripping the ARM Thumb bit when asked
/// (function symbols carry bit 0 set; data symbols do not).
fn nm_symbol(elf: &Path, symbol: &str, strip_thumb: bool) -> u64 {
    let out = Command::new(NM)
        .arg(elf)
        .output()
        .unwrap_or_else(|e| panic!("run {NM}: {e}"));
    assert!(out.status.success(), "{NM} failed on {}", elf.display());
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let (Some(addr), Some(_kind), Some(name)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        if name == symbol {
            let value = u64::from_str_radix(addr, 16)
                .unwrap_or_else(|_| panic!("parse nm address {addr:?} for {symbol}"));
            return if strip_thumb { value & !1 } else { value };
        }
    }
    panic!("symbol {symbol} not found in {}", elf.display());
}

/// Kills the qemu child on drop so a failed assertion never leaks the process.
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Poll a loopback port until it accepts a connection or the deadline passes.
fn wait_port(port: u16, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// The Cortex-M fixture built and booted under `qemu-system-arm`, paused, with
/// QMP and the gdbstub on loopback ports; `None` when a tool is missing.
struct Fixture {
    _guard: ChildGuard,
    qmp_port: u16,
    gdb_port: u16,
    input_addr: u64,
    ring_addr: u64,
    write_addr: u64,
    wrapped_addr: u64,
    fault_flag: u64,
    harness_done: u64,
    /// `bhf_cmplog`, in the CmpLog variant.
    cmplog_addr: Option<u64>,
}

const ARM_FLAGS: [&str; 7] = [
    "-mcpu=cortex-m3",
    "-mthumb",
    "-nostdlib",
    "-nostartfiles",
    "-ffreestanding",
    "-O0",
    "-g",
];

impl Fixture {
    fn boot(test: &str, dir: &Path) -> Option<Self> {
        Self::boot_variant(test, dir, false)
    }

    /// Boot the fixture; with `cmplog`, the variant whose only fault is
    /// behind a 4-byte magic its trace-cmp callbacks record.
    fn boot_variant(test: &str, dir: &Path, cmplog: bool) -> Option<Self> {
        Self::boot_with(test, dir, cmplog, false)
    }

    /// [`Self::boot_variant`]; with `semihosting`, the variant that writes
    /// its crumbs to the semihosting channel instead of the ring, under a
    /// QEMU that routes semihosting to the debugger.
    fn boot_with(test: &str, dir: &Path, cmplog: bool, semihosting: bool) -> Option<Self> {
        Self::boot_opts(test, dir, cmplog, semihosting, false, None)
    }

    /// [`Self::boot_with`]; with `persistent`, the variant whose
    /// `harness_done` returns into an input loop (`reset=persistent`), and
    /// with `ports`, QMP and the gdbstub on those `(qmp, gdb)` ports.
    fn boot_opts(
        test: &str,
        dir: &Path,
        cmplog: bool,
        semihosting: bool,
        persistent: bool,
        ports: Option<(u16, u16)>,
    ) -> Option<Self> {
        Self::boot_full(test, dir, cmplog, semihosting, persistent, ports, &[])
    }

    /// The plain fixture, with QEMU given `qemu_args` too (a `-plugin`).
    fn boot_with_qemu_args(
        test: &str,
        dir: &Path,
        ports: Option<(u16, u16)>,
        qemu_args: &[String],
    ) -> Option<Self> {
        Self::boot_full(test, dir, false, false, false, ports, qemu_args)
    }

    fn boot_full(
        test: &str,
        dir: &Path,
        cmplog: bool,
        semihosting: bool,
        persistent: bool,
        ports: Option<(u16, u16)>,
        qemu_args: &[String],
    ) -> Option<Self> {
        for tool in [CC, QEMU, QEMU_IMG, NM] {
            if !tool_present(tool) {
                eprintln!("SKIP {test}: {tool} not on PATH");
                return None;
            }
        }
        let src = dir.join("harness.c");
        let ld = dir.join("harness.ld");
        let elf = dir.join("harness.elf");
        std::fs::write(&src, HARNESS_C).unwrap();
        std::fs::write(&ld, HARNESS_LD).unwrap();

        let mut link = Command::new(CC);
        link.args(ARM_FLAGS);
        if cmplog {
            let check = dir.join("check.c");
            let object = dir.join("check.o");
            std::fs::write(&check, CHECK_C).unwrap();
            let compiled = Command::new(CC)
                .args(ARM_FLAGS)
                .args(["-fsanitize-coverage=trace-cmp", "-c"])
                .arg(&check)
                .arg("-o")
                .arg(&object)
                .status()
                .unwrap_or_else(|e| panic!("run {CC}: {e}"));
            assert!(compiled.success(), "{CC} failed to build check.c");
            link.arg("-DBHF_CMPLOG").arg(&object);
        }
        if semihosting {
            link.arg("-DBHF_SEMIHOSTING");
        }
        if persistent {
            link.arg("-DBHF_PERSISTENT");
        }
        let built = link
            .arg("-T")
            .arg(&ld)
            .arg("-o")
            .arg(&elf)
            .arg(&src)
            .status()
            .unwrap_or_else(|e| panic!("run {CC}: {e}"));
        assert!(built.success(), "{CC} failed to build the fixture");

        // Scratch block device so qemu `savevm` has somewhere to write the snapshot.
        let scratch = dir.join("scratch.qcow2");
        let created = Command::new(QEMU_IMG)
            .args(["create", "-f", "qcow2"])
            .arg(&scratch)
            .arg("16M")
            .output()
            .unwrap_or_else(|e| panic!("run {QEMU_IMG}: {e}"));
        assert!(created.status.success(), "{QEMU_IMG} create failed");

        // The CLI parses only TCP HOST:PORT endpoints, so expose qmp AND gdb over
        // TCP (this also exercises the #79 doc correction that qmp must be a TCP
        // socket).
        let (qmp_port, gdb_port) = ports.unwrap_or_else(|| (free_port(), free_port()));
        let mut qemu = Command::new(QEMU);
        if semihosting {
            qemu.args(["-semihosting-config", "enable=on,target=gdb"]);
        }
        let child = qemu
            .args(["-M", "mps2-an385", "-nographic", "-S", "-kernel"])
            .arg(&elf)
            .arg("-gdb")
            .arg(format!("tcp::{gdb_port}"))
            .arg("-drive")
            .arg(format!(
                "if=none,file={},format=qcow2,id=sc0",
                scratch.display()
            ))
            .arg("-qmp")
            .arg(format!("tcp:127.0.0.1:{qmp_port},server,nowait"))
            .args(qemu_args)
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {QEMU}: {e}"));
        let guard = ChildGuard(child);

        // Generous boot budgets: under a loaded CI/dev host (e.g. a concurrent
        // workspace build) qemu can take tens of seconds to open its sockets.
        assert!(
            wait_port(qmp_port, Duration::from_secs(45)),
            "qemu QMP port never came up"
        );
        assert!(
            wait_port(gdb_port, Duration::from_secs(45)),
            "qemu gdbstub port never came up"
        );
        Some(Self {
            _guard: guard,
            qmp_port,
            gdb_port,
            input_addr: nm_symbol(&elf, "bhf_input", false),
            ring_addr: nm_symbol(&elf, "adafuzz_probe_memory_buffer", false),
            write_addr: nm_symbol(&elf, "adafuzz_probe_memory_buffer_write", false),
            wrapped_addr: nm_symbol(&elf, "adafuzz_probe_memory_buffer_wrapped", false),
            fault_flag: nm_symbol(&elf, "bhf_fault_flag", false),
            harness_done: nm_symbol(&elf, "harness_done", true),
            cmplog_addr: cmplog.then(|| nm_symbol(&elf, "bhf_cmplog", false)),
        })
    }

    fn spec(&self) -> String {
        format!(
            "qemu-system:qmp=127.0.0.1:{},gdb=127.0.0.1:{},done={:#x},done_kind=2,fault={:#x}",
            self.qmp_port, self.gdb_port, self.harness_done, self.fault_flag
        )
    }

    fn coverage_map(&self, input_cap: usize) -> String {
        format!(
            "input={:#x},input_cap={input_cap},ring={:#x},write={:#x},wrapped={:#x},cap={RING_CAP}",
            self.input_addr, self.ring_addr, self.write_addr, self.wrapped_addr
        )
    }

    /// `bhf fuzz` over the fixture with one seed; its exit status, summary
    /// JSON and stderr.
    fn fuzz(
        &self,
        dir: &Path,
        name: &str,
        seed: &[u8],
        input_cap: usize,
    ) -> (std::process::ExitStatus, serde_json::Value, String) {
        let seed_path = dir.join(format!("{name}.bin"));
        std::fs::write(&seed_path, seed).unwrap();
        let out = Command::new(bhf_bin())
            .args(["fuzz", "--target-transport", &self.spec()])
            .args(["--transport-coverage-map", &self.coverage_map(input_cap)])
            .args(["--harness", "cortex-m-fixture"])
            .arg("--seed-file")
            .arg(&seed_path)
            .args(["--iterations", "1", "--time", "30s"])
            .arg(dir.join(format!("work-{name}")))
            .output()
            .expect("run bhf fuzz");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        let summary = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("summary JSON: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}"));
        (out.status, summary, stderr)
    }
}

#[test]
fn cli_qemu_system_transport_persists_a_classified_fault_finding() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let Some(fixture) = Fixture::boot(
        "cli_qemu_system_transport_persists_a_classified_fault_finding",
        dir,
    ) else {
        return;
    };
    let Fixture {
        qmp_port,
        gdb_port,
        input_addr,
        ring_addr,
        write_addr,
        wrapped_addr,
        fault_flag,
        harness_done,
        ..
    } = fixture;

    // Seed with the planted-fault byte so the single seed execution faults.
    let seed = dir.join("seed.bin");
    std::fs::write(&seed, [0xF7_u8]).unwrap();
    let work = dir.join("work");

    let spec = format!(
        "qemu-system:qmp=127.0.0.1:{qmp_port},gdb=127.0.0.1:{gdb_port},\
         done={harness_done:#x},done_kind=2,fault={fault_flag:#x}"
    );
    let map = format!(
        "input={input_addr:#x},input_cap=64,ring={ring_addr:#x},write={write_addr:#x},\
         wrapped={wrapped_addr:#x},cap={RING_CAP}"
    );

    let out = Command::new(bhf_bin())
        .args(["fuzz", "--target-transport", &spec])
        .args(["--transport-coverage-map", &map])
        .args(["--harness", "cortex-m-fixture"])
        .arg("--seed-file")
        .arg(&seed)
        .args(["--iterations", "1", "--time", "30s"])
        .arg(&work) // positional WORK_DIR
        .output()
        .expect("run bhf fuzz");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "bhf fuzz --target-transport qemu-system failed (code {:?})\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status.code()
    );

    let summary: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("summary JSON: {e}\n{stdout}"));
    assert!(
        summary["crashes"].as_u64().unwrap_or(0) >= 1,
        "the planted-fault seed must be classified as a crash: {summary}"
    );
    let findings = summary["findings"].as_array().expect("findings array");
    assert!(
        !findings.is_empty(),
        "a fault finding must be persisted: {summary}"
    );

    // The finding is on disk and records a crash the CLI produced itself.
    let findings_dir = work.join("results").join("findings");
    let id = findings[0].as_str().expect("finding id");
    let finding_json = findings_dir.join(id).join("finding.json");
    assert!(
        finding_json.exists(),
        "finding.json must be persisted at {}",
        finding_json.display()
    );
    let finding: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&finding_json).unwrap()).unwrap();
    // The finding must carry the triggering input so it is reproducible.
    assert!(
        finding.get("exception").is_some() || finding.get("rule_id").is_some(),
        "finding must carry fault classification: {finding}"
    );

    eprintln!("cli_qemu_system_transport: PASSED — CLI planted the breakpoint and persisted {id}");
}

/// The fixture's `bhf_fault_flag` sits right after its 64-byte `bhf_input`.
/// A seed of the clean-path byte whose bytes past 64 spell the fault magic
/// overwrote the flag when the transport wrote it whole, and the run reported
/// a CPU exception that never happened. With `input_cap=64` those bytes never
/// reach it; a cap past the flag shows they would have.
#[test]
fn cli_qemu_system_inputs_longer_than_the_cap_never_reach_the_fault_word() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let Some(fixture) = Fixture::boot(
        "cli_qemu_system_inputs_longer_than_the_cap_never_reach_the_fault_word",
        dir,
    ) else {
        return;
    };
    let offset = usize::try_from(fixture.fault_flag - fixture.input_addr).unwrap();
    assert!(offset >= 64, "bhf_fault_flag precedes the input buffer");
    let mut seed = vec![0x42_u8; offset + 4];
    seed[offset..].copy_from_slice(&0xDEAD_FA11_u32.to_le_bytes());

    let (status, capped, stderr) = fixture.fuzz(dir, "capped", &seed, 64);
    assert!(status.success(), "{stderr}");
    assert_eq!(
        capped["crashes"].as_u64(),
        Some(0),
        "the bytes past input_cap must not reach the fault word: {capped}\n{stderr}"
    );
    assert!(
        stderr.contains("--max-len 4096 is more than input_cap=64"),
        "the run says it cut --max-len: {stderr}"
    );

    let (status, uncapped, stderr) = fixture.fuzz(dir, "uncapped", &seed, offset + 4);
    assert!(status.success(), "{stderr}");
    assert!(
        uncapped["crashes"].as_u64().unwrap_or(0) >= 1,
        "a cap past the fault word lets the overwrite through: {uncapped}\n{stderr}"
    );
}

/// On-target CmpLog (#386): the comparison operands the firmware records
/// solve a 4-byte magic within a fixed execution count, and the same run
/// without `cmplog=` does not. Each run boots its own guest: a campaign's
/// baseline snapshot is the guest as arm finds it, and one left at the
/// completion breakpoint by an earlier campaign never runs an input again.
#[test]
fn cli_qemu_system_cmplog_solves_a_four_byte_magic() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let run = |name: &str, cmplog: bool| {
        let dir = tmp.path().join(name);
        std::fs::create_dir(&dir).unwrap();
        let fixture = Fixture::boot_variant(
            "cli_qemu_system_cmplog_solves_a_four_byte_magic",
            &dir,
            true,
        )?;
        let mut map = fixture.coverage_map(64);
        if cmplog {
            map.push_str(&format!(
                ",cmplog={:#x},cmplog_cap=32",
                fixture.cmplog_addr.unwrap()
            ));
        }
        let seed = dir.join("seed.bin");
        std::fs::write(&seed, b"AAAA").unwrap();
        let out = Command::new(bhf_bin())
            .args(["fuzz", "--target-transport", &fixture.spec()])
            .args(["--transport-coverage-map", &map])
            .args(["--harness", "cortex-m-cmplog"])
            .arg("--seed-file")
            .arg(&seed)
            .args(["--iterations", "300", "--rng-seed", "7", "--time", "120s"])
            .arg(dir.join("work"))
            .output()
            .expect("run bhf fuzz");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{name}: {stderr}");
        let summary: serde_json::Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("{name} summary JSON: {e}\n{stdout}\n{stderr}"));
        Some((summary, dir.join("work/results/findings")))
    };

    let Some((without, _)) = run("without", false) else {
        return;
    };
    assert_eq!(without["executions"], 300, "{without:#}");
    assert_eq!(without["comparisons"], 0, "{without:#}");
    assert_eq!(
        without["findings"],
        serde_json::json!([]),
        "random mutation found the magic: {without:#}"
    );

    let (with, findings_dir) = run("with", true).unwrap();
    assert_eq!(with["incomplete_observations"], 0, "{with:#}");
    assert!(
        with["comparisons"].as_u64().unwrap_or(0) >= 1,
        "the firmware's comparisons were not read: {with:#}"
    );
    let findings = with["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "the magic was not solved: {with:#}");
    let input = std::fs::read(
        findings_dir
            .join(findings[0].as_str().unwrap())
            .join("testcase.bin"),
    )
    .unwrap();
    assert!(
        input.starts_with(&0x5AFE_C0DE_u32.to_le_bytes()),
        "the finding's input is the magic: {input:02x?}"
    );
}

/// Semihosting coverage (#292): the fixture's probe writes each crumb to its
/// semihosting stderr, which QEMU hands to bhf's gdb connection as File-I/O
/// writes. The campaign reads no ring: its coverage grows with each seed's
/// path through the firmware, and the fault seed's crash is recorded. Each
/// run boots its own guest.
#[test]
fn cli_qemu_system_semihosting_coverage_grows_with_each_path() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let run = |name: &str, seeds: &[&[u8]]| {
        let dir = tmp.path().join(name);
        std::fs::create_dir(&dir).unwrap();
        let fixture = Fixture::boot_with(
            "cli_qemu_system_semihosting_coverage_grows_with_each_path",
            &dir,
            false,
            true,
        )?;
        let map = format!(
            "input={:#x},input_cap=64,coverage=semihosting",
            fixture.input_addr
        );
        let mut fuzz = Command::new(bhf_bin());
        fuzz.args(["fuzz", "--target-transport", &fixture.spec()])
            .args(["--transport-coverage-map", &map])
            .args(["--harness", "cortex-m-semihosting"]);
        for (index, seed) in seeds.iter().enumerate() {
            let path = dir.join(format!("seed-{index}.bin"));
            std::fs::write(&path, seed).unwrap();
            fuzz.arg("--seed-file").arg(path);
        }
        let out = fuzz
            .args(["--iterations", &seeds.len().to_string(), "--time", "60s"])
            .arg(dir.join("work"))
            .output()
            .expect("run bhf fuzz");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let summary: serde_json::Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("{name} summary JSON: {e}\n{stdout}\n{stderr}"));
        assert_eq!(summary["incomplete_observations"], 0, "{name}: {summary:#}");
        Some(summary)
    };

    // 0x100, 0x101, then the default branch's 0x300: two edges between them.
    let Some(one) = run("one", &[b"A"]) else {
        return;
    };
    let edges = |summary: &serde_json::Value| summary["coverage_edges"].as_u64().unwrap_or(0);
    assert_eq!(edges(&one), 2, "the stream was not decoded: {one:#}");
    // 0x42 takes the branch to 0x200 and 0x201: two edges more.
    let two = run("two", &[b"A", b"B"]).unwrap();
    assert_eq!(
        edges(&two),
        4,
        "the second path added no coverage: {one:#}\n{two:#}"
    );
    let fault = run("fault", &[&[0xF7]]).unwrap();
    assert_eq!(
        fault["findings"].as_array().map(Vec::len),
        Some(1),
        "the fault seed's crash was not recorded: {fault:#}"
    );
}

/// #346: `reset=persistent` through the shipped CLI. The guest's own input
/// loop runs the seeds; the planted fault, met on a continuation, is still a
/// finding; its transport profile records the campaign's exec/s and the
/// reset; and `bhf replay` reproduces it from the snapshot on a fresh guest.
#[test]
fn cli_qemu_system_persistent_reset_finds_the_fault_and_records_executions_per_sec() {
    let test = "cli_qemu_system_persistent_reset_finds_the_fault_and_records_executions_per_sec";
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let Some(fixture) = Fixture::boot_opts(test, dir, false, false, true, None) else {
        return;
    };
    let seeds = [0x42_u8, 0x00, 0xF7, 0x42, 0x00];
    let work = dir.join("work");
    let mut fuzz = Command::new(bhf_bin());
    fuzz.args([
        "fuzz",
        "--target-transport",
        &format!("{},reset=persistent", fixture.spec()),
    ])
    .args(["--transport-coverage-map", &fixture.coverage_map(64)])
    .args(["--harness", "cortex-m-fixture"]);
    for (i, byte) in seeds.iter().enumerate() {
        let seed = dir.join(format!("seed-{i}.bin"));
        std::fs::write(&seed, [*byte]).unwrap();
        fuzz.arg("--seed-file").arg(seed);
    }
    let out = fuzz
        .args(["--iterations", &seeds.len().to_string(), "--time", "60s"])
        .args(["--timeout", "10s"])
        .arg(&work)
        .output()
        .expect("run bhf fuzz");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "bhf fuzz reset=persistent failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let summary: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("summary JSON: {e}\n{stdout}"));
    assert_eq!(summary["executions"], seeds.len(), "{summary:#}");
    assert_eq!(summary["crashes"], 1, "{summary:#}");
    assert!(
        summary["executions_per_sec"]
            .as_f64()
            .is_some_and(|rate| rate > 0.0),
        "{summary:#}"
    );
    let findings = summary["findings"].as_array().expect("findings array");
    assert_eq!(findings.len(), 1, "{summary:#}");

    let finding = work
        .join("results/findings")
        .join(findings[0].as_str().unwrap());
    let profile: serde_json::Value =
        serde_json::from_slice(&std::fs::read(finding.join("transport_profile.json")).unwrap())
            .unwrap();
    assert_eq!(
        profile["throughput"]["executions"],
        seeds.len(),
        "{profile:#}"
    );
    assert!(
        profile["throughput"]["executions_per_sec"]
            .as_f64()
            .is_some_and(|rate| rate > 0.0),
        "{profile:#}"
    );
    assert!(
        profile["reset_mechanism"]
            .as_str()
            .is_some_and(|reset| reset.starts_with("guest persistent loop")),
        "{profile:#}"
    );
    eprintln!(
        "cli persistent: {} executions at {} exec/s, finding {}",
        summary["executions"], summary["executions_per_sec"], findings[0]
    );

    // The guest the campaign leaves is no baseline: replay on a fresh one at
    // the recorded endpoints.
    let ports = (fixture.qmp_port, fixture.gdb_port);
    drop(fixture);
    let _fresh = Fixture::boot_opts(test, dir, false, false, true, Some(ports))
        .expect("tools were present a moment ago");
    let replay = Command::new(bhf_bin())
        .arg("replay")
        .arg(&finding)
        .output()
        .expect("run bhf replay");
    let replay_stdout = String::from_utf8_lossy(&replay.stdout);
    assert!(
        replay.status.success() && replay_stdout.contains("MATCH"),
        "bhf replay of a persistent finding: {replay_stdout}\n{}",
        String::from_utf8_lossy(&replay.stderr)
    );
}

/// #347: `reset=fast` end to end. Without the plugin's log, `bhf fuzz` builds
/// the dirty-page plugin and says how to load it; with QEMU running it, the
/// campaign finds the planted fault, and the inputs after it run clean from
/// the baseline with no `loadvm` between them. The finding replays on a
/// fresh guest without the plugin.
#[test]
fn cli_qemu_system_fast_reset_builds_its_plugin_finds_the_fault_and_replays() {
    let test = "cli_qemu_system_fast_reset_builds_its_plugin_finds_the_fault_and_replays";
    if !tool_present("cc") {
        eprintln!("SKIP {test}: cc not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let work = dir.join("work");
    let log = dir.join("dirty.log");
    let seeds = [0x42_u8, 0x00, 0xF7, 0x42, 0x00, 0x42];
    let fuzz = |fixture: &Fixture| {
        let mut fuzz = Command::new(bhf_bin());
        fuzz.env_remove("BHF_PROFILE")
            .args([
                "fuzz",
                "--target-transport",
                &format!("{},reset=fast,dirty_log={}", fixture.spec(), log.display()),
            ])
            .args(["--transport-coverage-map", &fixture.coverage_map(64)])
            .args(["--harness", "cortex-m-fixture"]);
        for (i, byte) in seeds.iter().enumerate() {
            let seed = dir.join(format!("seed-{i}.bin"));
            std::fs::write(&seed, [*byte]).unwrap();
            fuzz.arg("--seed-file").arg(seed);
        }
        fuzz.args(["--iterations", &seeds.len().to_string(), "--time", "60s"])
            .args(["--timeout", "10s"])
            .arg(&work)
            .output()
            .expect("run bhf fuzz")
    };

    // QEMU without the plugin: bhf builds it and refuses the run.
    let Some(plain) = Fixture::boot(test, dir) else {
        return;
    };
    let out = fuzz(&plain);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    let plugin = work.join("qemu-plugin/libbhf_qemu_dirty_pages.so");
    assert!(plugin.is_file(), "{stderr}");
    let load = format!("{},log={}", plugin.display(), log.display());
    assert!(stderr.contains(&format!("-plugin {load}")), "{stderr}");
    let ports = (plain.qmp_port, plain.gdb_port);
    drop(plain);

    // QEMU with it, as the message says.
    let fixture =
        Fixture::boot_with_qemu_args(test, dir, Some(ports), &["-plugin".to_owned(), load])
            .expect("tools were present a moment ago");
    let out = fuzz(&fixture);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "bhf fuzz reset=fast failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let summary: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("summary JSON: {e}\n{stdout}"));
    assert_eq!(summary["executions"], seeds.len(), "{summary:#}");
    // One crash: the fault word and the exception state went back with the
    // reset, so the inputs after the fault are clean.
    assert_eq!(summary["crashes"], 1, "{summary:#}");
    let findings = summary["findings"].as_array().expect("findings array");
    assert_eq!(findings.len(), 1, "{summary:#}");
    let finding = work
        .join("results/findings")
        .join(findings[0].as_str().unwrap());
    let profile: serde_json::Value =
        serde_json::from_slice(&std::fs::read(finding.join("transport_profile.json")).unwrap())
            .unwrap();
    assert!(
        profile["reset_mechanism"]
            .as_str()
            .is_some_and(|reset| reset.starts_with("dirty-page fast snapshot")),
        "{profile:#}"
    );
    assert!(
        profile["limitations"]
            .as_str()
            .is_some_and(|limits| limits.contains("reset=fast")),
        "{profile:#}"
    );

    // A replay restores with loadvm: a fresh guest without the plugin.
    drop(fixture);
    let _fresh = Fixture::boot_opts(test, dir, false, false, false, Some(ports))
        .expect("tools were present a moment ago");
    let replay = Command::new(bhf_bin())
        .arg("replay")
        .arg(&finding)
        .output()
        .expect("run bhf replay");
    let replay_stdout = String::from_utf8_lossy(&replay.stdout);
    assert!(
        replay.status.success() && replay_stdout.contains("MATCH"),
        "bhf replay of a reset=fast finding: {replay_stdout}\n{}",
        String::from_utf8_lossy(&replay.stderr)
    );
}

/// #248: a `firmware=` image bhf cannot read is reported before anything
/// connects, so no finding is recorded against an unknown build.
#[test]
fn an_unreadable_firmware_image_is_reported() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("missing.elf");
    let text = tmp.path().join("notes.txt");
    std::fs::write(&text, "not an image").unwrap();
    for (firmware, says) in [(&missing, "cannot read"), (&text, "is not an ELF file")] {
        let out = Command::new(bhf_bin())
            .args([
                "fuzz",
                "--target-transport",
                &format!(
                    "qemu-system:qmp=127.0.0.1:1,gdb=127.0.0.1:2,firmware={}",
                    firmware.display()
                ),
                "--transport-coverage-map",
                "input=0x1000,input_cap=64,ring=0x2000,write=0x3000,wrapped=0x3004,cap=512",
                "--harness",
                "h",
                "--iterations",
                "1",
            ])
            .arg(tmp.path().join("work"))
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{stderr}");
        assert!(
            stderr.contains("firmware=") && stderr.contains(says),
            "{says}: {stderr}"
        );
    }
}

/// The pinned FreeRTOS kernel: `BHF_RTOS_KERNEL`, or a fetch of the pinned
/// commit into `dir`.
fn freertos_kernel(dir: &Path) -> PathBuf {
    let kernel = if let Some(path) = std::env::var_os("BHF_RTOS_KERNEL") {
        PathBuf::from(path)
    } else {
        let path = dir.join("kernel");
        assert!(Command::new("git")
            .args(["init", "-q"])
            .arg(&path)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .arg("-C")
            .arg(&path)
            .args([
                "fetch",
                "-q",
                "--depth",
                "1",
                "https://github.com/FreeRTOS/FreeRTOS-Kernel",
                "8be86d4a24fd4091f8f4192018423ab590f408db"
            ])
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .arg("-C")
            .arg(&path)
            .args(["checkout", "-q", "FETCH_HEAD"])
            .status()
            .unwrap()
            .success());
        path
    };
    let head = Command::new("git")
        .arg("-C")
        .arg(&kernel)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert!(head.status.success());
    assert_eq!(
        String::from_utf8_lossy(&head.stdout).trim(),
        "8be86d4a24fd4091f8f4192018423ab590f408db",
        "FreeRTOS CLI validation requires the pinned kernel"
    );
    kernel
}

/// Build the FreeRTOS reference profile into `dir/rtos.elf`, or `None` (a
/// skip line printed) unless `BHF_RTOS_CLI=1`.
fn build_freertos(test: &str, dir: &Path) -> Option<PathBuf> {
    build_freertos_with(test, dir, "rtos.elf", &[])
}

/// [`build_freertos`] of the image `name` with extra compiler `defines`
/// (`-DBHF_ISR_ENTRY` for the interrupt-driven entry point).
fn build_freertos_with(test: &str, dir: &Path, name: &str, defines: &[&str]) -> Option<PathBuf> {
    if std::env::var("BHF_RTOS_CLI").ok().as_deref() != Some("1") {
        eprintln!("SKIP {test}: set BHF_RTOS_CLI=1");
        return None;
    }
    for tool in [CC, QEMU, QEMU_IMG, NM, "git"] {
        assert!(tool_present(tool), "BHF_RTOS_CLI=1 requires {tool}");
    }
    let kernel = freertos_kernel(dir);
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target_transport/tests/freertos");
    let inc_port = kernel.join("portable/GCC/ARM_CM3");
    let elf = dir.join(name);
    let built = Command::new(CC)
        .args(defines)
        .args([
            "-mcpu=cortex-m3",
            "-mthumb",
            "-nostdlib",
            "-nostartfiles",
            "-ffreestanding",
            "-O1",
            "-g",
        ])
        .arg("-I")
        .arg(&fx)
        .arg("-I")
        .arg(kernel.join("include"))
        .arg("-I")
        .arg(&inc_port)
        .arg("-T")
        .arg(fx.join("link.ld"))
        .arg("-o")
        .arg(&elf)
        .arg(fx.join("startup.c"))
        .arg(fx.join("app.c"))
        .arg(kernel.join("tasks.c"))
        .arg(kernel.join("queue.c"))
        .arg(kernel.join("list.c"))
        .arg(inc_port.join("port.c"))
        .arg(kernel.join("portable/MemMang/heap_4.c"))
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "FreeRTOS compile: {}",
        String::from_utf8_lossy(&built.stderr)
    );
    Some(elf)
}

/// A stopped `qemu-system-arm` guest running `elf`, killed on drop.
struct RtosGuest {
    _guard: ChildGuard,
    qmp_port: u16,
    gdb_port: u16,
}

impl RtosGuest {
    /// Boot `elf` stopped, with a scratch drive for `savevm`, on fresh ports
    /// (or `ports`, to replay at the recorded endpoints).
    fn boot(elf: &Path, dir: &Path, tag: &str, ports: Option<(u16, u16)>) -> Self {
        Self::boot_with(elf, dir, tag, ports, &[])
    }

    /// [`Self::boot`] with extra `qemu-system-arm` arguments.
    fn boot_with(
        elf: &Path,
        dir: &Path,
        tag: &str,
        ports: Option<(u16, u16)>,
        qemu_args: &[&str],
    ) -> Self {
        let scratch = dir.join(format!("scratch-{tag}.qcow2"));
        assert!(Command::new(QEMU_IMG)
            .args(["create", "-f", "qcow2"])
            .arg(&scratch)
            .arg("16M")
            .output()
            .unwrap()
            .status
            .success());
        let (qmp_port, gdb_port) = ports.unwrap_or_else(|| (free_port(), free_port()));
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
            .arg(format!("tcp:127.0.0.1:{qmp_port},server,nowait"))
            .args(qemu_args)
            .spawn()
            .unwrap();
        let guest = Self {
            _guard: ChildGuard(child),
            qmp_port,
            gdb_port,
        };
        assert!(wait_port(qmp_port, Duration::from_secs(45)));
        assert!(wait_port(gdb_port, Duration::from_secs(45)));
        guest
    }

    /// The `--target-transport` spec for this guest, and the
    /// `--transport-coverage-map` for `elf`.
    fn spec_and_map(&self, elf: &Path) -> (String, String) {
        let symbol = |name, thumb| nm_symbol(elf, name, thumb);
        // #248: the findings record the image they were found on.
        let spec = format!(
            "qemu-system:qmp=127.0.0.1:{},gdb=127.0.0.1:{},done={:#x},done_kind=2,fault={:#x},\
             firmware={}",
            self.qmp_port,
            self.gdb_port,
            symbol("harness_done", true),
            symbol("bhf_fault_flag", false),
            elf.display()
        );
        let map = format!(
            "input={:#x},input_cap=64,ring={:#x},write={:#x},wrapped={:#x},cap=512",
            symbol("bhf_input", false),
            symbol("adafuzz_probe_memory_buffer", false),
            symbol("adafuzz_probe_memory_buffer_write", false),
            symbol("adafuzz_probe_memory_buffer_wrapped", false)
        );
        (spec, map)
    }

    /// `bhf fuzz` of this guest with one seed file per byte of `seeds`.
    fn fuzz(&self, elf: &Path, work: &Path, seeds: &[u8], extra: &[&str]) -> serde_json::Value {
        self.fuzz_with_spec(elf, work, seeds, extra, "")
    }

    /// [`Self::fuzz`] with `,`-joined keys added to the transport spec.
    fn fuzz_with_spec(
        &self,
        elf: &Path,
        work: &Path,
        seeds: &[u8],
        extra: &[&str],
        spec_keys: &str,
    ) -> serde_json::Value {
        let (mut spec, map) = self.spec_and_map(elf);
        if !spec_keys.is_empty() {
            spec.push(',');
            spec.push_str(spec_keys);
        }
        let mut cmd = Command::new(bhf_bin());
        cmd.args([
            "fuzz",
            "--target-transport",
            &spec,
            "--transport-coverage-map",
            &map,
            "--harness",
            "freertos-queue",
        ]);
        for (i, byte) in seeds.iter().enumerate() {
            let seed = work.with_extension(format!("seed-{i}.bin"));
            std::fs::write(&seed, [*byte]).unwrap();
            cmd.arg("--seed-file").arg(seed);
        }
        let out = cmd
            .args(["--iterations", &seeds.len().to_string(), "--time", "60s"])
            .args(["--max-len", "64"])
            .args(extra)
            .arg(work)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "FreeRTOS CLI: {}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }
}

fn sha256_of(path: &Path) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(std::fs::read(path).unwrap());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Actual FreeRTOS CLI acceptance, separate from the bare-metal Cortex-M test.
/// Opt in because it obtains a pinned upstream kernel unless BHF_RTOS_KERNEL is
/// supplied. Each CLI invocation opens a fresh transport session on one guest.
#[test]
fn cli_freertos_clean_fault_clean() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let Some(elf) = build_freertos("cli_freertos_clean_fault_clean", dir) else {
        return;
    };
    let elf_sha256 = sha256_of(&elf);
    for (i, byte, expect_crash) in [(0, 0x42_u8, false), (1, 0xF7, true), (2, 0x42, false)] {
        let guest = RtosGuest::boot(&elf, dir, &i.to_string(), None);
        let work = dir.join(format!("work-{i}"));
        let summary = guest.fuzz(&elf, &work, &[byte], &[]);
        assert_eq!(
            summary["crashes"].as_u64().unwrap_or(0) > 0,
            expect_crash,
            "FreeRTOS CLI {i}: {summary}"
        );
        if expect_crash {
            let findings = summary["findings"].as_array().unwrap();
            assert!(!findings.is_empty(), "FreeRTOS crash must retain a finding");
            let finding_id = findings[0].as_str().unwrap();
            let finding = work.join("results/findings").join(finding_id);
            assert!(finding.join("transport_profile.json").is_file());
            for file in ["finding.json", "transport_profile.json"] {
                let raw: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(finding.join(file)).unwrap()).unwrap();
                let identity = &raw["firmware_identity"];
                assert_eq!(identity["sha256"], elf_sha256.as_str(), "{file}: {raw:#}");
                assert_eq!(identity["rtos"]["name"], "FreeRTOS", "{file}: {raw:#}");
                assert_eq!(identity["rtos"]["version"], "V11.1.0+", "{file}: {raw:#}");
                assert!(
                    identity["toolchain"]
                        .as_str()
                        .is_some_and(|t| t.starts_with("GCC ")),
                    "{file}: {raw:#}"
                );
            }

            // Replay must start from reset, at the recorded QMP/GDB endpoints.
            // A daemon parked at harness_done would snapshot a completed run.
            let ports = (guest.qmp_port, guest.gdb_port);
            drop(guest);
            let _replay_guest = RtosGuest::boot(&elf, dir, "replay", Some(ports));
            let replay = Command::new(bhf_bin())
                .arg("replay")
                .arg(&finding)
                .output()
                .unwrap();
            assert!(
                replay.status.success(),
                "FreeRTOS replay: {}\n{}",
                String::from_utf8_lossy(&replay.stdout),
                String::from_utf8_lossy(&replay.stderr)
            );
            assert!(String::from_utf8_lossy(&replay.stdout).contains("MATCH"));
        }
    }
}

/// #249: the reference profile's timeout and state-contamination controls.
/// `0xD0` never reaches `harness_done`, so its run ends at `--timeout` as a
/// timeout finding (BHF-555). `0xC5` leaves `bhf_carryover` set where startup
/// does not clear it, and a `0x42` that saw it would fault: run after it in
/// the same session, the `0x42` is clean only because the snapshot reset
/// restored the guest's memory.
#[test]
fn cli_freertos_hang_times_out_and_the_reset_clears_state() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let Some(elf) = build_freertos(
        "cli_freertos_hang_times_out_and_the_reset_clears_state",
        dir,
    ) else {
        return;
    };
    let guest = RtosGuest::boot(&elf, dir, "hang", None);
    let started = Instant::now();
    let work = dir.join("work-hang");
    let summary = guest.fuzz(&elf, &work, &[0xD0], &["--timeout", "2s"]);
    assert!(started.elapsed() < Duration::from_secs(45), "{summary}");
    let findings = summary["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{summary}");
    let raw: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            work.join("results/findings")
                .join(findings[0].as_str().unwrap())
                .join("finding.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(raw["rule_id"], "BHF-555", "{raw:#}");
    drop(guest);

    let guest = RtosGuest::boot(&elf, dir, "reset", None);
    let summary = guest.fuzz(&elf, &dir.join("work-reset"), &[0xC5, 0x42], &[]);
    assert_eq!(summary["executions"], 2, "{summary}");
    assert_eq!(
        summary["crashes"], 0,
        "the 0x42 after a 0xC5 is clean: {summary}"
    );
}

/// #251: a run's target cycles come from a counter the guest keeps, read
/// before and after the run. QEMU models no `DWT_CYCCNT`, so this reads the
/// MPS2 FPGAIO `COUNTER` (a 25 MHz up-counter) under `-icount`, where it
/// advances with the instructions run. `sleep=off` keeps host time out of it:
/// with icount's default `sleep=on`, the clock follows the host while the
/// guest idles waiting for an input, and a loaded runner added ticks to some
/// runs (#422). Input `0xB0` busy-loops one unit, `0xB7` eight and `0xBF`
/// sixteen. Each run also counts the delivery and completion around the
/// loop, a cost that differs between QEMU builds, so the check is on
/// differences that span several units: the eight units from `0xB7` to `0xBF`
/// cost about what the seven from `0xB0` to `0xB7` do, unit for unit.
#[test]
fn cli_freertos_target_cycles_grow_with_a_busy_loop() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let Some(elf) = build_freertos("cli_freertos_target_cycles_grow_with_a_busy_loop", dir) else {
        return;
    };
    let mut cycles = Vec::new();
    for (tag, byte) in [("one", 0xB0_u8), ("eight", 0xB7), ("sixteen", 0xBF)] {
        let guest = RtosGuest::boot_with(&elf, dir, tag, None, &["-icount", "shift=0,sleep=off"]);
        let summary = guest.fuzz_with_spec(
            &elf,
            &dir.join(format!("work-{tag}")),
            &[byte],
            &[],
            "cycles=0x40028018,cpu_hz=25000000",
        );
        let stats = &summary["target_cycles"];
        assert_eq!(stats["runs"], 1, "{summary}");
        cycles.push(stats["max"].as_u64().unwrap());
    }
    assert!(cycles[0] > 0, "{cycles:?}");
    let seven = cycles[1].saturating_sub(cycles[0]);
    let eight = cycles[2].saturating_sub(cycles[1]);
    assert!(
        seven > 0 && eight > 0,
        "more busy work takes more cycles: {cycles:?}"
    );
    let per_unit_ratio = (7 * eight) as f64 / (8 * seven) as f64;
    assert!(
        (0.8..=1.2).contains(&per_unit_ratio),
        "a unit of busy work costs about the same from 0xB7 to 0xBF as from 0xB0 to 0xB7: \
         {cycles:?}"
    );
}

/// #252: the interrupt-driven entry point. The `BHF_ISR_ENTRY` image gets its
/// input from a receive interrupt, whose handler posts it to the consumer task
/// with `xQueueSendFromISR`; no task forwards it. The planted `0xF7` fault is
/// found through that path, and the finding records the task the firmware
/// says ran it (`task_id=` reads `bhf_task_id`), a task control block in the
/// kernel's heap.
#[test]
fn cli_freertos_isr_entry_finds_a_fault_and_records_the_task() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let Some(elf) = build_freertos_with(
        "cli_freertos_isr_entry_finds_a_fault_and_records_the_task",
        dir,
        "rtos-isr.elf",
        &["-DBHF_ISR_ENTRY"],
    ) else {
        return;
    };
    let task_word = format!("task_id={:#x}", nm_symbol(&elf, "bhf_task_id", false));
    let heap = nm_symbol(&elf, "ucHeap", false);

    let guest = RtosGuest::boot(&elf, dir, "isr-fault", None);
    let work = dir.join("work-isr-fault");
    let summary = guest.fuzz_with_spec(&elf, &work, &[0xF7], &[], &task_word);
    assert!(summary["crashes"].as_u64().unwrap_or(0) > 0, "{summary}");
    let finding = work
        .join("results/findings")
        .join(summary["findings"][0].as_str().unwrap());
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(finding.join("finding.json")).unwrap()).unwrap();
    let task = raw["target_task"]["id"].as_str().expect("the task id");
    let task = u64::from_str_radix(task.trim_start_matches("0x"), 16).unwrap();
    assert!(
        (heap..heap + 32 * 1024).contains(&task),
        "the task id {task:#x} is a TCB in the kernel heap at {heap:#x}: {raw:#}"
    );
    drop(guest);

    let guest = RtosGuest::boot(&elf, dir, "isr-clean", None);
    let summary = guest.fuzz_with_spec(&elf, &dir.join("work-isr-clean"), &[0x42], &[], &task_word);
    assert_eq!(summary["executions"], 1, "{summary}");
    assert_eq!(summary["crashes"], 0, "{summary}");
}
