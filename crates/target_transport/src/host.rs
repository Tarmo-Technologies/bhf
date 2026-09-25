// SPDX-License-Identifier: Apache-2.0

//! Reference host-child transport (Unix).
//!
//! A self-contained [`TargetTransport`] that spawns a child process, feeds the
//! input on stdin, captures stdout, and maps the child's exit/signal to an
//! [`ExitKind`] + [`Fault`]. It deliberately does *not* collect coverage: the
//! production host lane's `mmap(BHF_COV_SHM)` / fork-server coverage path is a
//! separate, supervised follow-up (HDF-1 deliverable 5) and is not refactored
//! here. This impl exists to prove the seam accepts the host path and to give
//! the follow-up a shape to grow into; `coverage_edges` is therefore always
//! empty.
//!
//! Limitation: input is written, then the child is waited on, then stdout is
//! drained. That is correct for the small I/O a fuzz iteration exchanges but
//! would deadlock a child that streams more than a pipe buffer of stdout while
//! blocked on further stdin. The production adopter uses the fork server, which
//! does not have this constraint.

use crate::error::{Result, TransportError};
use crate::outcome::{ExitKind, Fault, FaultKind, RunOutcome};
use crate::transport::{TargetSession, TargetTransport};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Poll interval while waiting for a timed child to exit.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Spawns a child process per input and reports its exit as a [`RunOutcome`].
#[derive(Debug, Clone)]
pub struct HostChildTransport {
    program: PathBuf,
    args: Vec<OsString>,
    timeout: Option<Duration>,
}

impl HostChildTransport {
    /// Build a transport that runs `program`.
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            timeout: None,
        }
    }

    /// Append a single argument.
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append several arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set a per-input wall-clock deadline; on expiry the child is killed and
    /// the run reported as [`ExitKind::Timeout`].
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

impl TargetTransport for HostChildTransport {
    fn arm(&self) -> Result<Box<dyn TargetSession>> {
        Ok(Box::new(HostChildSession {
            program: self.program.clone(),
            args: self.args.clone(),
            timeout: self.timeout,
        }))
    }
}

/// A session that spawns one child per [`TargetSession::run_input`].
struct HostChildSession {
    program: PathBuf,
    args: Vec<OsString>,
    timeout: Option<Duration>,
}

impl TargetSession for HostChildSession {
    fn run_input(&mut self, input: &[u8]) -> Result<RunOutcome> {
        let mut child = Command::new(&self.program)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| {
                TransportError::protocol(format!(
                    "spawn host child {}: {error}",
                    self.program.display()
                ))
            })?;

        // Write the input and close stdin (EOF) so the child can finish.
        {
            let mut stdin = child.stdin.take().ok_or_else(|| {
                TransportError::protocol("host child stdin pipe was not captured")
            })?;
            stdin.write_all(input)?;
        }

        let status = match self.timeout {
            None => child.wait()?,
            Some(timeout) => {
                let deadline = Instant::now() + timeout;
                loop {
                    if let Some(status) = child.try_wait()? {
                        break status;
                    }
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Ok(RunOutcome {
                            exit: ExitKind::Timeout,
                            coverage_edges: Vec::new(),
                            fault: Some(Fault {
                                kind: FaultKind::Timeout,
                                address: None,
                                detail: format!(
                                    "host child exceeded {} ms deadline",
                                    timeout.as_millis()
                                ),
                            }),
                            stdout: Vec::new(),
                        });
                    }
                    std::thread::sleep(POLL_INTERVAL);
                }
            }
        };

        let mut stdout = Vec::new();
        if let Some(mut pipe) = child.stdout.take() {
            pipe.read_to_end(&mut stdout)?;
        }

        let (exit, fault) = classify_status(&status);
        Ok(RunOutcome {
            exit,
            coverage_edges: Vec::new(),
            fault,
            stdout,
        })
    }
}

/// Map a child exit status to an [`ExitKind`] + optional [`Fault`].
///
/// Crash detection follows the host lane: a delivered signal is a crash;
/// any exit code (zero or not) is a clean completion.
fn classify_status(status: &ExitStatus) -> (ExitKind, Option<Fault>) {
    match status.signal() {
        Some(signal) => (
            ExitKind::Crash,
            Some(Fault {
                kind: fault_kind_from_signal(signal),
                address: None,
                detail: format!("host child terminated by signal {signal}"),
            }),
        ),
        None => (ExitKind::Ok, None),
    }
}

/// Map a POSIX signal number to the placeholder [`FaultKind`] taxonomy.
fn fault_kind_from_signal(signal: i32) -> FaultKind {
    match signal {
        // SIGSEGV(11), SIGBUS(7): memory-protection faults.
        11 | 7 => FaultKind::MemoryProtection,
        // SIGILL(4), SIGFPE(8): CPU exceptions.
        4 | 8 => FaultKind::CpuException,
        // SIGABRT(6): assertion / abort.
        6 => FaultKind::AssertionPanic,
        other => FaultKind::Other(other as u32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_child_echoes_stdin_and_reports_clean_exit() {
        // `cat` copies stdin to stdout and exits 0.
        let transport = HostChildTransport::new("/bin/cat").timeout(Duration::from_secs(5));
        let mut session = transport.arm().unwrap();
        let outcome = session.run_input(b"radar-track-frame").unwrap();

        assert_eq!(outcome.exit, ExitKind::Ok);
        assert_eq!(outcome.stdout, b"radar-track-frame");
        assert!(outcome.fault.is_none());
        assert!(outcome.coverage_edges.is_empty());
    }

    #[test]
    fn host_child_signal_is_classified_as_a_crash() {
        // The shell SIGSEGVs itself; the host lane must see a signal, not an
        // exit code.
        let transport = HostChildTransport::new("/bin/sh")
            .args(["-c", "kill -SEGV $$"])
            .timeout(Duration::from_secs(5));
        let mut session = transport.arm().unwrap();
        let outcome = session.run_input(b"").unwrap();

        assert_eq!(outcome.exit, ExitKind::Crash);
        let fault = outcome.fault.expect("crash must carry a fault");
        assert_eq!(fault.kind, FaultKind::MemoryProtection);
    }

    #[test]
    fn host_child_deadline_is_reported_as_timeout() {
        let transport = HostChildTransport::new("/bin/sh")
            .args(["-c", "sleep 5"])
            .timeout(Duration::from_millis(150));
        let mut session = transport.arm().unwrap();
        let outcome = session.run_input(b"").unwrap();

        assert_eq!(outcome.exit, ExitKind::Timeout);
        assert_eq!(outcome.fault.map(|f| f.kind), Some(FaultKind::Timeout));
    }

    #[test]
    fn host_child_nonzero_exit_code_is_not_a_crash() {
        // Exit code 3 is a clean completion in the signal-based host model.
        let transport = HostChildTransport::new("/bin/sh")
            .args(["-c", "exit 3"])
            .timeout(Duration::from_secs(5));
        let mut session = transport.arm().unwrap();
        let outcome = session.run_input(b"").unwrap();

        assert_eq!(outcome.exit, ExitKind::Ok);
        assert!(outcome.fault.is_none());
    }
}
