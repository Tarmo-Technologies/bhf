// SPDX-License-Identifier: Apache-2.0

//! `bhf fuzz --target-transport agent:serial:PATH` over a pseudo-terminal.
//! The tty used to stay in its cooked line discipline, which turned the
//! frame's 0x0A bytes into 0x0D 0x0A and held the agent's reply until a
//! newline arrived, and nothing bounded a read from a silent device. The port
//! is now raw and every read ends at `--timeout`.
#![cfg(target_os = "linux")]

use std::ffi::CStr;
use std::io::{BufRead, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

mod support;

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

/// The repository's reference agent (`c_runtime/examples/agent_posix.c`)
/// with the loopback test's target, whose "BUG" writes through a null
/// pointer; `None` without clang.
fn build_reference_agent(dir: &Path) -> Option<PathBuf> {
    if !support::require_tool(which::which("clang").is_ok(), "clang") {
        return None;
    }
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let runtime = repo.join("c_runtime");
    let compile = |args: &[&std::ffi::OsStr]| {
        let status = Command::new("clang").args(args).status().unwrap();
        assert!(status.success(), "clang {args:?}");
    };
    compile(&[
        "-std=c99".as_ref(),
        "-c".as_ref(),
        runtime.join("bhf_agent.c").as_os_str(),
        "-o".as_ref(),
        dir.join("bhf_agent.o").as_os_str(),
    ]);
    compile(&[
        "-Wall".as_ref(),
        "-Werror".as_ref(),
        "-I".as_ref(),
        runtime.as_os_str(),
        "-c".as_ref(),
        runtime.join("examples/agent_posix.c").as_os_str(),
        "-o".as_ref(),
        dir.join("agent_posix.o").as_os_str(),
    ]);
    compile(&[
        "-fsanitize-coverage=trace-pc-guard".as_ref(),
        "-O0".as_ref(),
        "-c".as_ref(),
        repo.join("crates/target_transport/tests/agent/target.c")
            .as_os_str(),
        "-o".as_ref(),
        dir.join("target.o").as_os_str(),
    ]);
    let agent = dir.join("agent");
    compile(&[
        dir.join("agent_posix.o").as_os_str(),
        dir.join("bhf_agent.o").as_os_str(),
        dir.join("target.o").as_os_str(),
        "-o".as_ref(),
        agent.as_os_str(),
    ]);
    Some(agent)
}

/// A child killed when the test ends.
struct Killed(std::process::Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// #293: the reference agent on a pseudo-terminal, standing in for a board's
/// UART, through a board profile's serial lane. A campaign of 300 inputs
/// reads the agent's coverage over the tty, grows it with each seed's path,
/// and records the fault the "BUG" seed raises; the agent serves on after it.
#[test]
fn the_reference_agent_on_a_pty_runs_a_board_profiles_serial_lane() {
    let work = TestDir::new("agent-serial-reference");
    let Some(agent) = build_reference_agent(work.path()) else {
        eprintln!("SKIP: clang is not installed");
        return;
    };
    let mut child = Command::new(&agent)
        .arg("--pty")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn the reference agent");
    let mut tty = String::new();
    std::io::BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut tty)
        .unwrap();
    let _agent = Killed(child);
    let profile = work.join("board.toml");
    std::fs::write(
        &profile,
        format!(
            "name = \"pty-agent\"\nserial = \"agent:serial:{},baud=115200\"\n",
            tty.trim()
        ),
    )
    .unwrap();
    let run = |name: &str, seeds: &[&[u8]], iterations: usize| {
        let mut fuzz = Command::new(env!("CARGO_BIN_EXE_bhf"));
        fuzz.args(["fuzz", work.join(name).to_str().unwrap()])
            .args(["--harness", "pty-agent", "--board-profile"])
            .arg(&profile)
            .args(["--board-lane", "serial"]);
        for (index, seed) in seeds.iter().enumerate() {
            let path = work.join(format!("{name}-seed-{index}.bin"));
            std::fs::write(&path, seed).unwrap();
            fuzz.arg("--seed-file").arg(path);
        }
        let out = fuzz
            .args(["--iterations", &iterations.to_string()])
            .args(["--timeout", "2s", "--time", "60s"])
            .output()
            .expect("run bhf fuzz");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(out.status.success(), "{name}: {stderr}");
        let summary: serde_json::Value =
            serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {stderr}"));
        assert_eq!(summary["executions"], iterations, "{name}: {summary:#}");
        assert_eq!(summary["incomplete_observations"], 0, "{name}: {summary:#}");
        assert!(summary["halted"].is_null(), "{name}: {summary:#}");
        (summary, stderr)
    };

    let edges = |summary: &serde_json::Value| summary["coverage_edges"].as_u64().unwrap_or(0);
    let (first, stderr) = run("first", &[b"B"], 300);
    assert!(
        stderr.contains("board \"pty-agent\" over agent:serial:"),
        "{stderr}"
    );
    assert!(edges(&first) >= 2, "no coverage over the tty: {first:#}");
    assert_eq!(first["findings"], serde_json::json!([]), "{first:#}");
    let (second, _) = run("second", &[b"B", b"BU", b"BUG", b"BU"], 300);
    assert!(
        edges(&second) > edges(&first),
        "the deeper seeds added no coverage: {first:#}\n{second:#}"
    );
    assert_eq!(
        second["findings"].as_array().map(Vec::len),
        Some(1),
        "the fault was not recorded once: {second:#}"
    );
}
