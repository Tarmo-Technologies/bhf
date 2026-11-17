// SPDX-License-Identifier: Apache-2.0

//! The service a session campaign starts, watches and restarts
//! (`--session-server-cmd`, #260).
//!
//! The session lane drives a protocol over a socket, so on its own it sees a
//! crash only as a dropped connection, and once a service is gone the
//! campaign is over. With `--session-server-cmd` bhf runs the service itself
//! (built with ASan, typically), its stderr captured to a log: it waits for
//! the port before the first session, checks after each session whether the
//! service exited, reads the sanitizer report from the log when it did, and
//! starts it again so the campaign goes on.
//!
//! The command runs through the platform shell (`sh -c`, `cmd /C`) in its own
//! process group, which is killed when the server is stopped or bhf exits.

use std::io::Read;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// How long a service may take to accept connections after it starts.
pub(crate) const SERVER_START_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a service that dropped a session may take to exit: a sanitizer
/// writes its whole report before the process ends.
pub(crate) const SERVER_EXIT_GRACE: Duration = Duration::from_secs(2);
/// A UDP service cannot be probed with a connection: once it has run this
/// long without exiting it is taken as ready.
const UDP_SETTLE: Duration = Duration::from_millis(300);
/// How much of a service's stderr a finding keeps.
const STDERR_CAP: u64 = 256 * 1024;
/// The sanitizer options a service runs with unless the environment sets its
/// own: report and exit on the first error, with no leak check at exit.
const DEFAULT_ASAN_OPTIONS: &str = "halt_on_error=1:abort_on_error=0:detect_leaks=0:symbolize=1";

/// A service that exited while bhf ran it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServerExit {
    /// How it ended: `exit status 1`, `signal 11`.
    pub status: String,
    /// Its stderr since it was last started (the first [`STDERR_CAP`] bytes).
    pub stderr: String,
}

/// A service bhf runs for a session campaign.
pub(crate) struct SessionServer {
    command: String,
    host: String,
    port: u16,
    udp: bool,
    log_dir: PathBuf,
    child: Option<Running>,
    starts: usize,
}

struct Running {
    child: Child,
    _group: replay_min::process::ProcessGroupGuard,
    log: PathBuf,
}

impl SessionServer {
    /// A service started by `command` that serves `host:port`; its logs go
    /// under `log_dir`.
    pub(crate) fn new(command: String, host: String, port: u16, udp: bool, log_dir: &Path) -> Self {
        Self {
            command,
            host,
            port,
            udp,
            log_dir: log_dir.to_path_buf(),
            child: None,
            starts: 0,
        }
    }

    /// The command line the service runs.
    pub(crate) fn command(&self) -> &str {
        &self.command
    }

    /// How many times the service has been started.
    pub(crate) fn starts(&self) -> usize {
        self.starts
    }

    /// Start the service and wait until it serves its port: a TCP service
    /// when it accepts a connection, a UDP one when it has run for a moment.
    /// The error names why it did not start and carries its stderr.
    pub(crate) fn start(&mut self) -> Result<(), String> {
        self.stop();
        std::fs::create_dir_all(&self.log_dir)
            .map_err(|e| format!("create {}: {e}", self.log_dir.display()))?;
        self.starts += 1;
        let log = self
            .log_dir
            .join(format!("server-{}.stderr.log", self.starts));
        let stderr =
            std::fs::File::create(&log).map_err(|e| format!("create {}: {e}", log.display()))?;
        let mut command = shell_command(&self.command);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr);
        if std::env::var_os("ASAN_OPTIONS").is_none() {
            command.env("ASAN_OPTIONS", DEFAULT_ASAN_OPTIONS);
        }
        replay_min::process::isolate_process_group(&mut command);
        let child = command
            .spawn()
            .map_err(|e| format!("run `{}`: {e}", self.command))?;
        let group = replay_min::process::guard_process_group(&child);
        self.child = Some(Running {
            child,
            _group: group,
            log,
        });

        let started = Instant::now();
        let target = self.target_addr();
        loop {
            if let Some(exit) = self.exited_within(Duration::ZERO) {
                return Err(format!(
                    "the service exited before it served {}:{} ({}); its stderr:\n{}",
                    self.host,
                    self.port,
                    exit.status,
                    exit.stderr.trim_end()
                ));
            }
            let ready = if self.udp {
                started.elapsed() >= UDP_SETTLE
            } else {
                target.as_ref().is_some_and(|addr| {
                    TcpStream::connect_timeout(addr, Duration::from_millis(200)).is_ok()
                })
            };
            if ready {
                return Ok(());
            }
            if started.elapsed() >= SERVER_START_TIMEOUT {
                let stderr = self.stderr_so_far();
                self.stop();
                return Err(format!(
                    "the service did not serve {}:{} within {}s; its stderr:\n{}",
                    self.host,
                    self.port,
                    SERVER_START_TIMEOUT.as_secs(),
                    stderr.trim_end()
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Whether the service has exited, waiting up to `grace` for it to.
    pub(crate) fn exited_within(&mut self, grace: Duration) -> Option<ServerExit> {
        let deadline = Instant::now() + grace;
        loop {
            let running = self.child.as_mut()?;
            if let Ok(Some(status)) = running.child.try_wait() {
                let stderr = read_capped(&running.log);
                self.child = None;
                return Some(ServerExit {
                    status: describe_status(status),
                    stderr,
                });
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Stop the service (and everything it started) if it runs.
    pub(crate) fn stop(&mut self) {
        if let Some(mut running) = self.child.take() {
            replay_min::process::kill_process_group(&mut running.child);
            let _ = running.child.wait();
        }
    }

    fn stderr_so_far(&self) -> String {
        self.child
            .as_ref()
            .map(|running| read_capped(&running.log))
            .unwrap_or_default()
    }

    fn target_addr(&self) -> Option<SocketAddr> {
        (self.host.as_str(), self.port)
            .to_socket_addrs()
            .ok()?
            .next()
    }
}

impl Drop for SessionServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn shell_command(command_line: &str) -> Command {
    if cfg!(windows) {
        let mut command = Command::new("cmd");
        command.args(["/C", command_line]);
        command
    } else {
        let mut command = Command::new("sh");
        command.args(["-c", command_line]);
        command
    }
}

fn read_capped(path: &Path) -> String {
    let mut bytes = Vec::new();
    if let Ok(file) = std::fs::File::open(path) {
        let _ = file.take(STDERR_CAP).read_to_end(&mut bytes);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn describe_status(status: std::process::ExitStatus) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return format!("signal {signal}");
        }
    }
    match status.code() {
        Some(code) => format!("exit status {code}"),
        None => "an unknown status".to_owned(),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// A service that listens is ready, and one that exits says how, with
    /// its stderr; a restart starts it again.
    #[test]
    fn a_service_is_started_watched_and_restarted() {
        let dir = tempfile::tempdir().unwrap();
        let port = free_port();
        let script = dir.path().join("serve.py");
        std::fs::write(
            &script,
            "import socket, sys\n\
             s = socket.socket()\n\
             s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n\
             s.bind(('127.0.0.1', int(sys.argv[1])))\n\
             s.listen()\n\
             c, _ = s.accept()\n\
             c, _ = s.accept()\n\
             sys.stderr.write('ERROR: AddressSanitizer: planted\\n')\n\
             sys.exit(1)\n",
        )
        .unwrap();
        if Command::new("python3").arg("-c").arg("1").status().is_err() {
            eprintln!("skipping: no python3");
            return;
        }
        let mut server = SessionServer::new(
            format!("python3 {} {port}", script.display()),
            "127.0.0.1".to_owned(),
            port,
            false,
            &dir.path().join("logs"),
        );
        // The readiness probe is the first connection; the second ends it.
        server.start().unwrap();
        assert_eq!(server.exited_within(Duration::ZERO), None);
        drop(TcpStream::connect(("127.0.0.1", port)).unwrap());
        let exit = server
            .exited_within(SERVER_EXIT_GRACE)
            .expect("the service exited");
        assert_eq!(exit.status, "exit status 1");
        assert!(
            exit.stderr.contains("AddressSanitizer: planted"),
            "{exit:?}"
        );
        server.start().unwrap();
        assert_eq!(server.starts(), 2);
        assert!(dir.path().join("logs/server-2.stderr.log").is_file());
    }

    #[test]
    fn a_service_that_does_not_start_says_why_with_its_stderr() {
        let dir = tempfile::tempdir().unwrap();
        let mut server = SessionServer::new(
            "echo cannot bind >&2; exit 3".to_owned(),
            "127.0.0.1".to_owned(),
            free_port(),
            false,
            dir.path(),
        );
        let error = server.start().unwrap_err();
        assert!(error.contains("exited before it served"), "{error}");
        assert!(error.contains("exit status 3"), "{error}");
        assert!(error.contains("cannot bind"), "{error}");
    }
}
