// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for the gated live-emulator integration tests
//! ([`live_gdb`](../live_gdb.rs), [`live_fullsystem`](../live_fullsystem.rs),
//! [`hil_board`](../hil_board.rs)).
//!
//! These tests drive the REAL [`target_transport`] RSP / QMP clients against a
//! real `qemu-<arch>` / `qemu-system-arm` gdbstub. They self-skip only when a
//! required tool is genuinely absent, and they print loudly when they do. The
//! `scripts/hil-emu.sh` lane sets `BHF_HIL_REQUIRE=1`, which flips every "skip on
//! missing tool" into a hard failure so the emulator validations cannot silently
//! no-op in CI.

#![allow(dead_code)]

use std::io;
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// True when the caller (the `hil-emu` lane) requires these gated tests to run:
/// a missing tool then becomes a hard failure instead of a skip.
pub fn require_hil() -> bool {
    std::env::var_os("BHF_HIL_REQUIRE").is_some()
}

/// True if `tool` resolves to an executable file on `PATH` (like `command -v`).
pub fn tool_on_path(tool: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|dir| {
        let candidate = dir.join(tool);
        candidate
            .metadata()
            .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    })
}

/// Return the subset of `tools` that are NOT on `PATH`.
pub fn missing_tools<'a>(tools: &[&'a str]) -> Vec<&'a str> {
    tools.iter().copied().filter(|t| !tool_on_path(t)).collect()
}

/// Decide whether a gated test should run. `Ok(())` means "run for real".
///
/// * All tools present -> `Ok(())`.
/// * A tool missing and `BHF_HIL_REQUIRE` set -> **panic** (the lane demanded a
///   real run, so a missing tool is a failure, never a silent skip).
/// * A tool missing otherwise -> `Err(reason)`; the caller must `eprintln!` it
///   loudly and `return` (a documented self-skip).
pub fn gate(test_name: &str, tools: &[&str]) -> Result<(), String> {
    let missing = missing_tools(tools);
    if missing.is_empty() {
        return Ok(());
    }
    let hint = format!(
        "{test_name}: SKIPPED — missing tool(s): {}. Install the qemu + cross \
         toolchains (see scripts/hil-emu.sh) to run the live path.",
        missing.join(", ")
    );
    if require_hil() {
        panic!(
            "BHF_HIL_REQUIRE=1 demands the live path but these tools are absent: {}. \
             {hint}",
            missing.join(", ")
        );
    }
    Err(hint)
}

/// A child process that is killed and reaped when the guard is dropped, so a
/// panicking test never leaks a running emulator.
pub struct ChildGuard {
    child: Child,
    label: String,
}

impl ChildGuard {
    pub fn new(child: Child, label: impl Into<String>) -> Self {
        Self {
            child,
            label: label.into(),
        }
    }

    /// True if the child is still running (has not exited on its own).
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = &self.label; // retained for debugging on failure
    }
}

/// Grab an ephemeral TCP port on the loopback, then release it so a child can
/// bind it. There is a small race window; the callers connect with retry.
pub fn free_tcp_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

/// Connect to `127.0.0.1:port`, retrying until `deadline` so the emulator has
/// time to open its gdbstub listener.
pub fn connect_tcp_retry(port: u16, deadline: Duration) -> io::Result<TcpStream> {
    let start = Instant::now();
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => return Ok(stream),
            Err(error) => {
                if start.elapsed() >= deadline {
                    return Err(error);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Connect to a Unix socket at `path`, retrying until `deadline` so the emulator
/// has time to create its QMP socket.
pub fn connect_unix_retry(path: &Path, deadline: Duration) -> io::Result<UnixStream> {
    let start = Instant::now();
    loop {
        match UnixStream::connect(path) {
            Ok(stream) => return Ok(stream),
            Err(error) => {
                if start.elapsed() >= deadline {
                    return Err(error);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// A temporary directory removed when the guard drops.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create `std::env::temp_dir()/<prefix>-<pid>-<nanos>`.
    pub fn new(prefix: &str) -> io::Result<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Read a symbol's address out of an ELF via `<nm> <elf>`; panics with a
/// descriptive message if the symbol is absent (a build/link regression).
pub fn nm_symbol(nm: &str, elf: &Path, symbol: &str) -> u64 {
    let output = Command::new(nm)
        .arg(elf)
        .output()
        .unwrap_or_else(|e| panic!("failed to run {nm} on {}: {e}", elf.display()));
    assert!(
        output.status.success(),
        "{nm} failed on {}: {}",
        elf.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        // nm format: "<hexaddr> <type> <name>"
        let mut fields = line.split_whitespace();
        let addr = fields.next();
        let _kind = fields.next();
        let name = fields.next();
        if name == Some(symbol) {
            if let Some(addr) = addr {
                return u64::from_str_radix(addr.trim(), 16)
                    .unwrap_or_else(|e| panic!("bad nm address {addr:?} for {symbol}: {e}"));
            }
        }
    }
    panic!("symbol {symbol:?} not found in {}", elf.display());
}
