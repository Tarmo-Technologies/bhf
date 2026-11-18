// SPDX-License-Identifier: Apache-2.0

//! The reference target-side agent on Zephyr (#291): the `qemu_cortex_m3`
//! sample of `c_runtime/zephyr/` serves the agent protocol on UART1, which
//! `-serial tcp:` makes a socket, and `bhf fuzz --target-transport agent:tcp`
//! drives it. A clean input, a CPU exception and a clean input again run in
//! one boot (a new agent thread serves after the fault), the fault is a
//! finding, and `bhf replay` reproduces it.
//!
//! Opt in with `BHF_ZEPHYR_CLI=1`: it needs `west` and a Zephyr tree
//! (`ZEPHYR_BASE`), `arm-none-eabi-gcc` (used through Zephyr's `gnuarmemb`
//! toolchain variant unless `ZEPHYR_TOOLCHAIN_VARIANT` names another) and
//! `qemu-system-arm`.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// Build the sample into `dir` with west; its `zephyr.elf`.
fn build_sample(dir: &Path) -> PathBuf {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut west = Command::new("west");
    west.args(["build", "-p", "always", "-b", "qemu_cortex_m3", "-d"])
        .arg(dir.join("build"))
        .arg(repo.join("c_runtime/zephyr/samples/agent"));
    if std::env::var_os("ZEPHYR_TOOLCHAIN_VARIANT").is_none() {
        let gcc = which::which("arm-none-eabi-gcc").unwrap();
        let root = gcc.parent().and_then(Path::parent).unwrap();
        west.env("ZEPHYR_TOOLCHAIN_VARIANT", "gnuarmemb")
            .env("GNUARMEMB_TOOLCHAIN_PATH", root);
    }
    let built = west.output().unwrap();
    assert!(
        built.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&built.stdout),
        String::from_utf8_lossy(&built.stderr)
    );
    dir.join("build/zephyr/zephyr.elf")
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

/// Boot `elf` with UART1 on a TCP socket, once the socket listens.
fn boot(elf: &Path, port: u16) -> Guest {
    let guest = Command::new("qemu-system-arm")
        .args(["-M", "lm3s6965evb", "-nographic", "-monitor", "none"])
        .args(["-serial", "null", "-serial"])
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
            "H-zephyr-agent",
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
fn the_zephyr_agent_sample_runs_clean_fault_clean_and_replays() {
    if std::env::var("BHF_ZEPHYR_CLI").ok().as_deref() != Some("1") {
        eprintln!("SKIP: set BHF_ZEPHYR_CLI=1");
        return;
    }
    for tool in ["west", "arm-none-eabi-gcc", "qemu-system-arm"] {
        assert!(
            which::which(tool).is_ok(),
            "BHF_ZEPHYR_CLI=1 requires {tool}"
        );
    }
    assert!(
        std::env::var_os("ZEPHYR_BASE").is_some(),
        "BHF_ZEPHYR_CLI=1 requires ZEPHYR_BASE"
    );
    let work = TestDir::new("zephyr-agent");
    let elf = build_sample(work.path());
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
        .unwrap_or_else(|| panic!("the CPU exception is not a finding: {fault:#}"))
        .to_owned();
    let finding = work.join("bhf_work/results/findings").join(&id);
    let record = std::fs::read_to_string(finding.join("finding.json")).unwrap();
    assert!(record.contains("Zephyr fatal error"), "{record}");

    // A new agent thread serves the next input in the same boot.
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
