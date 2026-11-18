// SPDX-License-Identifier: Apache-2.0

//! The reference target-side agent as a FreeRTOS task under
//! `qemu-system-arm -M mps2-an385` (#290): `freertos/agent_task.c` serves the
//! agent protocol over UART0, which `-serial tcp:` makes a socket, and
//! `bhf fuzz --target-transport agent:tcp` drives it. A clean input, a
//! HardFault and a clean input again run in one boot (the task recovers from
//! the fault), the fault is a finding, and `bhf replay` reproduces it.
//!
//! Opt in with `BHF_RTOS_CLI=1`: it needs `arm-none-eabi-gcc` and
//! `qemu-system-arm`, and fetches the pinned FreeRTOS kernel unless
//! `BHF_RTOS_KERNEL` names a checkout of it.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const KERNEL_COMMIT: &str = "8be86d4a24fd4091f8f4192018423ab590f408db";

fn tool_present(tool: &str) -> bool {
    let present = Command::new(tool)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    support::require_tool(present, tool)
}

fn kernel(dir: &Path) -> PathBuf {
    let kernel = match std::env::var_os("BHF_RTOS_KERNEL") {
        Some(path) => PathBuf::from(path),
        None => {
            let path = dir.join("kernel");
            let git = |args: &[&str]| {
                assert!(Command::new("git").args(args).status().unwrap().success());
            };
            git(&["init", "-q", path.to_str().unwrap()]);
            git(&[
                "-C",
                path.to_str().unwrap(),
                "fetch",
                "-q",
                "--depth",
                "1",
                "https://github.com/FreeRTOS/FreeRTOS-Kernel",
                KERNEL_COMMIT,
            ]);
            git(&["-C", path.to_str().unwrap(), "checkout", "-q", "FETCH_HEAD"]);
            path
        }
    };
    let head = Command::new("git")
        .arg("-C")
        .arg(&kernel)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&head.stdout).trim(),
        KERNEL_COMMIT,
        "the FreeRTOS agent validation needs the pinned kernel"
    );
    kernel
}

/// Build the agent image: the agent and the kernel without coverage, the
/// code under test with GCC's `trace-pc`.
fn build_image(dir: &Path) -> PathBuf {
    let kernel = kernel(dir);
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fx = repo.join("crates/target_transport/tests/freertos");
    let port = kernel.join("portable/GCC/ARM_CM3");
    let flags = ["-mcpu=cortex-m3", "-mthumb", "-ffreestanding", "-O1", "-g"];
    let target = dir.join("agent_target.o");
    let compiled = Command::new("arm-none-eabi-gcc")
        .args(flags)
        .arg("-fsanitize-coverage=trace-pc")
        .arg("-c")
        .arg(fx.join("agent_target.c"))
        .arg("-o")
        .arg(&target)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let elf = dir.join("agent.elf");
    let linked = Command::new("arm-none-eabi-gcc")
        .args(flags)
        .args(["-nostdlib", "-nostartfiles"])
        .arg("-I")
        .arg(&fx)
        .arg("-I")
        .arg(repo.join("c_runtime"))
        .arg("-I")
        .arg(kernel.join("include"))
        .arg("-I")
        .arg(&port)
        .arg("-T")
        .arg(fx.join("link.ld"))
        .arg("-o")
        .arg(&elf)
        .arg(fx.join("startup.c"))
        .arg(fx.join("agent_task.c"))
        .arg(repo.join("c_runtime/bhf_agent.c"))
        .arg(&target)
        .arg(kernel.join("tasks.c"))
        .arg(kernel.join("queue.c"))
        .arg(kernel.join("list.c"))
        .arg(port.join("port.c"))
        .arg(kernel.join("portable/MemMang/heap_4.c"))
        .arg("-lgcc")
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    elf
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Guest(Child);

impl Drop for Guest {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Boot `elf` with UART0 on a TCP socket, once the socket listens.
fn boot(elf: &Path, port: u16) -> Guest {
    let guest = Command::new("qemu-system-arm")
        .args(["-M", "mps2-an385", "-nographic", "-monitor", "none"])
        .arg("-serial")
        .arg(format!("tcp:127.0.0.1:{port},server=on,wait=off"))
        .arg("-kernel")
        .arg(elf)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            Instant::now() < deadline,
            "the guest's UART socket never listened"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // That probe connection was the UART's; let the guest see it close.
    std::thread::sleep(Duration::from_millis(200));
    Guest(guest)
}

fn bhf(work: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
        .current_dir(work)
        .args(args)
        .output()
        .unwrap()
}

/// One `bhf fuzz` run of `input` alone through the agent: its summary.
fn fuzz_one(work: &Path, spec: &str, input: &str) -> serde_json::Value {
    let out = bhf(
        work,
        &[
            "fuzz",
            "bhf_work",
            "--harness",
            "H-rtos-agent",
            "--target-transport",
            spec,
            "--seed-input",
            input,
            "--iterations",
            "1",
            "--timeout",
            "5s",
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{input}: {stderr}");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|error| panic!("{error}: {stderr}"))
}

#[test]
fn the_freertos_agent_task_runs_clean_fault_clean_and_replays() {
    if std::env::var("BHF_RTOS_CLI").ok().as_deref() != Some("1") {
        eprintln!("SKIP: set BHF_RTOS_CLI=1");
        return;
    }
    for tool in ["arm-none-eabi-gcc", "qemu-system-arm", "git"] {
        assert!(tool_present(tool), "BHF_RTOS_CLI=1 requires {tool}");
    }
    let work = TestDir::new("freertos-agent");
    let elf = build_image(work.path());
    let port = free_port();
    let _guest = boot(&elf, port);
    let spec = format!("agent:tcp:127.0.0.1:{port}");

    let clean = fuzz_one(work.path(), &spec, "A");
    assert_eq!(clean["findings"], serde_json::json!([]), "{clean:#}");
    assert!(
        clean["coverage_edges"].as_u64().unwrap_or(0) >= 1,
        "{clean:#}"
    );

    let fault = fuzz_one(work.path(), &spec, "BUG");
    let id = fault["findings"][0]
        .as_str()
        .unwrap_or_else(|| panic!("the HardFault is not a finding: {fault:#}"))
        .to_owned();
    let finding = work.join("bhf_work/results/findings").join(&id);
    let record = std::fs::read_to_string(finding.join("finding.json")).unwrap();
    assert!(record.contains("HardFault"), "{record}");

    // The task recovered: the same boot runs a clean input again.
    let again = fuzz_one(work.path(), &spec, "A");
    assert_eq!(again["findings"], serde_json::json!([]), "{again:#}");

    let replay = bhf(work.path(), &["replay", finding.to_str().unwrap()]);
    let replayed = String::from_utf8_lossy(&replay.stdout);
    assert_eq!(
        replay.status.code(),
        Some(0),
        "{replayed}\n{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(
        replayed.contains("MATCH") && !replayed.contains("MISMATCH"),
        "{replayed}"
    );
}
