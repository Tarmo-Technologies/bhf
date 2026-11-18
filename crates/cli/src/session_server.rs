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
//!
//! With [`SessionServer::with_coverage`] the service also gets `BHF_COV_SHM`
//! (#363): a map bhf owns, one byte per edge, that a service built with
//! SanitizerCoverage and `c_runtime/bhf_service_cov.c` fills. It outlives a
//! restart, so coverage accumulates over the campaign.
//!
//! With [`SessionServer::with_runtime_oracles`] the service runs under the
//! runtrace shim (#364). Before each session bhf writes the bytes the session
//! carries where the shim reads its input, and after it bhf takes the events
//! the session caused: those after the service started serving, so its
//! start-up is no session's.

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
/// The size of the service's edge map: one byte per edge, as bhf_driver.c's.
const COVERAGE_MAP_BYTES: usize = 1 << 16;
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
    coverage: Option<CoverageMap>,
    runtrace: Option<ServiceRuntrace>,
}

/// The runtrace a service writes under the shim, and the file the shim reads
/// the session in flight from.
struct ServiceRuntrace {
    env: Vec<(String, String)>,
    log: PathBuf,
    input: PathBuf,
    /// How much of `log` earlier sessions, and the start-up, have taken.
    offset: u64,
}

/// The edge map a service writes, and the path it is told.
struct CoverageMap {
    _file: crate::fuzz::shared_map::SharedMapFile,
    path: String,
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
            coverage: None,
            runtrace: None,
        }
    }

    /// Run the service under the runtrace shim `oracles` names, its log and
    /// the session input file in `dir`.
    pub(crate) fn with_runtime_oracles(
        mut self,
        oracles: &crate::runtime_oracles::RuntimeOracles,
        dir: &Path,
    ) -> Result<Self, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let log = dir.join("service-runtrace.jsonl");
        let input = dir.join("service-input.bin");
        std::fs::write(&input, b"").map_err(|e| format!("create {}: {e}", input.display()))?;
        let mut env = oracles.env_pairs(&log);
        env.push((
            "BHF_SHIM_INPUT_FILE".to_owned(),
            input.display().to_string(),
        ));
        env.push(("BHF_SHIM_INPUT_FILE_SHARED".to_owned(), "1".to_owned()));
        self.runtrace = Some(ServiceRuntrace {
            env,
            log,
            input,
            offset: 0,
        });
        Ok(self)
    }

    /// Whether the service runs under the runtrace shim.
    pub(crate) fn has_runtrace(&self) -> bool {
        self.runtrace.is_some()
    }

    /// Make `bytes` the input the shim matches the service's sinks against:
    /// the bytes of the session about to be driven.
    pub(crate) fn publish_session_input(&self, bytes: &[u8]) -> Result<(), String> {
        let Some(runtrace) = &self.runtrace else {
            return Ok(());
        };
        // A new file, renamed in: the shim re-reads it when its inode changes.
        let next = runtrace.input.with_extension("bin.next");
        std::fs::write(&next, bytes).map_err(|e| format!("write {}: {e}", next.display()))?;
        std::fs::rename(&next, &runtrace.input)
            .map_err(|e| format!("rename {}: {e}", runtrace.input.display()))
    }

    /// The runtrace events since the last call (or since the service started
    /// serving): those of the session just driven.
    pub(crate) fn take_session_events(&mut self) -> Vec<crate::auto::runtrace::RuntraceEvent> {
        let Some(runtrace) = &mut self.runtrace else {
            return Vec::new();
        };
        let text = read_from(&runtrace.log, &mut runtrace.offset);
        let mut events = crate::auto::runtrace::parse_str(&text);
        crate::auto::runtrace::dedupe_in_place(&mut events);
        events
    }

    /// Give the service an edge map in `work_dir`'s shared-map dir, which it
    /// fills when built with `c_runtime/bhf_service_cov.c`.
    pub(crate) fn with_coverage(mut self, work_dir: &Path) -> Result<Self, String> {
        let (file, path) =
            crate::fuzz::shared_map::SharedMapFile::create(work_dir, COVERAGE_MAP_BYTES)?;
        self.coverage = Some(CoverageMap { _file: file, path });
        Ok(self)
    }

    /// Whether the service is given an edge map.
    pub(crate) fn has_coverage(&self) -> bool {
        self.coverage.is_some()
    }

    /// The edges the service has reached so far, by index; none when it has
    /// no map, or is not instrumented.
    pub(crate) fn coverage_edges(&self) -> Vec<u64> {
        let Some(coverage) = &self.coverage else {
            return Vec::new();
        };
        let Ok(bytes) = std::fs::read(&coverage.path) else {
            return Vec::new();
        };
        bytes
            .iter()
            .enumerate()
            .filter(|(_, byte)| **byte != 0)
            .map(|(index, _)| index as u64)
            .collect()
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
        if let Some(coverage) = &self.coverage {
            command.env("BHF_COV_SHM", &coverage.path);
        }
        if let Some(runtrace) = &self.runtrace {
            command.envs(runtrace.env.iter().map(|(key, value)| (key, value)));
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
                // What the service did before it served is its start-up.
                if let Some(runtrace) = &mut self.runtrace {
                    read_from(&runtrace.log, &mut runtrace.offset);
                }
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

/// The complete lines of `path` from `offset` on, moving `offset` past them.
fn read_from(path: &Path, offset: &mut u64) -> String {
    use std::io::{Seek, SeekFrom};
    let Ok(mut file) = std::fs::File::open(path) else {
        return String::new();
    };
    if file.seek(SeekFrom::Start(*offset)).is_err() {
        return String::new();
    }
    let mut bytes = Vec::new();
    if file.take(STDERR_CAP * 64).read_to_end(&mut bytes).is_err() {
        return String::new();
    }
    // A line still being written is the next call's.
    let complete = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |at| at + 1);
    *offset += complete as u64;
    String::from_utf8_lossy(&bytes[..complete]).into_owned()
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
