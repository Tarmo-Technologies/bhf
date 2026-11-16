// SPDX-License-Identifier: Apache-2.0

//! `bhf fuzz --target-transport agent:serial:PATH` over a pseudo-terminal.
//! The tty used to stay in its cooked line discipline, which turned the
//! frame's 0x0A bytes into 0x0D 0x0A and held the agent's reply until a
//! newline arrived, and nothing bounded a read from a silent device. The port
//! is now raw and every read ends at `--timeout`.
#![cfg(target_os = "linux")]

use std::ffi::CStr;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::time::{Duration, Instant};

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// A pseudo-terminal: the master end and the slave's path, which starts in
/// the default cooked mode as a real tty does.
fn pty() -> (std::fs::File, String) {
    // SAFETY: libc calls on a fresh descriptor, each result checked.
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(master >= 0);
        assert_eq!(libc::grantpt(master), 0);
        assert_eq!(libc::unlockpt(master), 0);
        let mut name = [0 as libc::c_char; 128];
        assert_eq!(libc::ptsname_r(master, name.as_mut_ptr(), name.len()), 0);
        (
            std::fs::File::from(OwnedFd::from_raw_fd(master)),
            CStr::from_ptr(name.as_ptr()).to_string_lossy().into_owned(),
        )
    }
}

/// Read `n` bytes from the master within `within`; fewer when it runs out.
fn read_master(master: &mut std::fs::File, n: usize, within: Duration) -> Vec<u8> {
    let deadline = Instant::now() + within;
    let mut got = Vec::new();
    while got.len() < n && Instant::now() < deadline {
        let mut poll = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        if unsafe { libc::poll(&mut poll, 1, 100) } <= 0 {
            continue;
        }
        let mut chunk = vec![0_u8; n - got.len()];
        if let Ok(read) = master.read(&mut chunk) {
            got.extend_from_slice(&chunk[..read]);
        }
    }
    got
}

fn fuzz(work: &TestDir, slave: &str, seed: &[u8]) -> std::process::Child {
    let seed_path = work.join("seed.bin");
    std::fs::write(&seed_path, seed).unwrap();
    Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["fuzz", work.join("bhf_work").to_str().unwrap()])
        .args(["--harness", "serial-agent"])
        .args([
            "--target-transport",
            &format!("agent:serial:{slave},baud=115200"),
        ])
        .arg("--seed-file")
        .arg(&seed_path)
        .args(["--iterations", "1", "--timeout", "1s", "--time", "20s"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn bhf fuzz")
}

#[test]
fn an_agent_frame_with_newline_bytes_crosses_the_tty_unchanged() {
    let work = TestDir::new("agent-serial-frame");
    let (mut master, slave) = pty();
    let seed = [0x0A, 0x0D, 0x0A, b'x'];
    let child = fuzz(&work, &slave, &seed);

    // The agent: read the frame, reply clean with one edge spelled in CR/LF.
    let frame = read_master(&mut master, 4 + seed.len(), Duration::from_secs(10));
    let mut reply = Vec::new();
    reply.extend_from_slice(&0_u32.to_le_bytes()); // status: ran to completion
    reply.extend_from_slice(&1_u32.to_le_bytes()); // one edge
    reply.extend_from_slice(&0x0A0D_0A0D_u32.to_le_bytes());
    reply.extend_from_slice(&0_u32.to_le_bytes()); // no fault
    master.write_all(&reply).unwrap();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    let mut want = (seed.len() as u32).to_le_bytes().to_vec();
    want.extend_from_slice(&seed);
    assert_eq!(frame, want, "the frame arrives byte for byte: {stderr}");
    assert!(out.status.success(), "{stderr}");
    let summary: serde_json::Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {stderr}"));
    assert_eq!(summary["executions"], 1, "{summary}");
}

#[test]
fn a_silent_serial_device_ends_the_run_within_the_timeout() {
    let work = TestDir::new("agent-serial-silent");
    let (_master, slave) = pty();
    let started = Instant::now();
    let out = fuzz(&work, &slave, b"A").wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the run waited {:?} on a silent device: {stderr}",
        started.elapsed()
    );
    let summary: serde_json::Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {stderr}"));
    assert!(
        summary["halted"]
            .as_str()
            .is_some_and(|why| why.contains("the serial device sent nothing within 1000ms")),
        "{summary}"
    );
}
