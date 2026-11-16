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
static void emit_crumb(uint32_t id){
  ring_write_byte(3);
  ring_write_byte((uint8_t)(id & 0xff));
  ring_write_byte((uint8_t)((id >> 8) & 0xff));
  ring_write_byte((uint8_t)((id >> 16) & 0xff));
  ring_write_byte((uint8_t)((id >> 24) & 0xff));
}
volatile uint8_t  bhf_input[64];
volatile uint32_t bhf_fault_flag = 0;
void harness_done(void){ while(1){} }
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
}

impl Fixture {
    fn boot(test: &str, dir: &Path) -> Option<Self> {
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
        let qmp_port = free_port();
        let gdb_port = free_port();
        let child = Command::new(QEMU)
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
    let elf = dir.join("rtos.elf");
    let built = Command::new(CC)
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
        let (spec, map) = self.spec_and_map(elf);
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
