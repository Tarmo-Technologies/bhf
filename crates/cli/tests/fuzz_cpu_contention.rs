// SPDX-License-Identifier: Apache-2.0

//! Fuzzing throughput under CPU contention degrades with the CPU share bhf
//! gets, not by orders of magnitude.
//!
//! The harness burns a fixed amount of CPU time at startup, like a target with
//! heavy static initialisers. Pinned to one core next to a busy loop it gets
//! about half that core, so its startup takes about twice as long. The run
//! must still bring its fork-server up and keep a fair fraction of the
//! uncontended rate, measured in the same test so the runner's speed cancels
//! out. Linux only (taskset); skips without taskset or a C compiler.

use std::path::Path;
use std::process::{Child, Command, Stdio};

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// CPU time the harness spends starting up. A busy loop on the same core
/// doubles its wall time, past the fixed 2 s the handshake used to allow.
const STARTUP_CPU_MS: u32 = 1500;

const TARGET: &str = r#"// SPDX-License-Identifier: Apache-2.0
#include <stddef.h>
#include <stdint.h>
#include <time.h>

static double cpu_ms(void) {
    struct timespec now;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &now);
    return now.tv_sec * 1e3 + now.tv_nsec / 1e6;
}

/* A heavy startup: spin until this process has used STARTUP_CPU_MS of CPU. */
__attribute__((constructor)) static void heavy_startup(void) {
    volatile unsigned long sink = 0;
    while (cpu_ms() < STARTUP_CPU_MS) sink++;
}

int bhf_run_one(const uint8_t *data, size_t size) {
    int acc = 0;
    for (size_t i = 0; i < size; i++) acc += data[i] == 'A' ? 1 : 0;
    return acc;
}
"#;

fn tmpdir() -> TestDir {
    TestDir::new("cpu-contention")
}

fn runs(program: &str, arg: &str) -> bool {
    Command::new(program)
        .arg(arg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// The highest CPU this process may run on.
fn last_allowed_cpu() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let list = status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))?;
    list.trim()
        .split(',')
        .filter_map(|range| range.rsplit('-').next()?.trim().parse().ok())
        .max()
}

/// A busy loop pinned to `cpu`, killed on drop.
struct BusyLoop(Child);

impl BusyLoop {
    fn start(cpu: u32) -> Self {
        Self(
            Command::new("taskset")
                .args(["-c", &cpu.to_string(), "sh", "-c", "while :; do :; done"])
                .spawn()
                .unwrap(),
        )
    }
}

impl Drop for BusyLoop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Executions and whether the fork-server came up, for one pinned run.
fn pinned_run(cpu: u32, work: &Path, seed: &Path) -> (u64, bool) {
    for dir in ["corpus", "results", "fuzz_runs", "events"] {
        let _ = std::fs::remove_dir_all(work.join(dir));
    }
    let output = Command::new("taskset")
        .args(["-c", &cpu.to_string()])
        .arg(env!("CARGO_BIN_EXE_bhf"))
        .arg("fuzz")
        .arg(work)
        .args(["--harness", "H-SLOWSTART", "--engine", "builtin"])
        .arg("--seed-file")
        .arg(seed)
        .args(["--time", "8s"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "fuzz summary is not JSON ({e}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    (
        summary["executions"].as_u64().unwrap(),
        summary["execution"]["forkserver"].as_bool().unwrap(),
    )
}

#[test]
fn a_busy_neighbour_costs_a_fair_share_not_the_run() {
    if !cfg!(target_os = "linux") || !runs("taskset", "--version") {
        eprintln!("skipping: needs taskset (Linux)");
        return;
    }
    let Some(compiler) = ["clang", "cc", "gcc"]
        .into_iter()
        .find(|cc| runs(cc, "--version"))
    else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let cpu = last_allowed_cpu().expect("an allowed CPU");

    let root = tmpdir();
    let work = root.join("work");
    let harness_dir = work.join("harnesses/H-SLOWSTART");
    std::fs::create_dir_all(&harness_dir).unwrap();
    std::fs::write(harness_dir.join("target.c"), TARGET).unwrap();
    let driver = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime/bhf_driver.c");
    let built = Command::new(compiler)
        .current_dir(&harness_dir)
        .args(["-O1", "-o", "main", "target.c"])
        .arg(format!("-DSTARTUP_CPU_MS={STARTUP_CPU_MS}"))
        .arg(&driver)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let seed = root.join("seed.bin");
    std::fs::write(&seed, b"hello").unwrap();

    let (alone, alone_forkserver) = pinned_run(cpu, &work, &seed);
    let (contended, contended_forkserver) = {
        let _busy = BusyLoop::start(cpu);
        pinned_run(cpu, &work, &seed)
    };
    let _ = std::fs::remove_dir_all(&root);

    assert!(alone_forkserver, "the uncontended run uses the fork-server");
    assert!(
        contended_forkserver,
        "a slow start next to a busy loop must still bring the fork-server up"
    );
    // A fair share is about half the uncontended rate, less the longer startup.
    // Allow a wide margin: the collapse this guards against is 1000x.
    assert!(
        contended * 10 >= alone,
        "contended run made {contended} execs, uncontended {alone}"
    );
}
