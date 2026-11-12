// SPDX-License-Identifier: Apache-2.0

//! Bounded runs of a harness (or a launcher in front of one): the child gets
//! its own process group, so a timeout kills every process it started, and
//! the threads draining its pipes are waited for a bounded time, so a
//! descendant that still holds a pipe cannot hang the caller.

use std::process::{Child, Command, ExitStatus};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How long the pipe-draining threads of a killed child are waited for.
pub const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// Start `command` in its own process group and, on Linux, have the kernel
/// kill it when the process that spawned it dies.
#[cfg(unix)]
pub fn isolate_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
    #[cfg(target_os = "linux")]
    // SAFETY: prctl is async-signal-safe and touches no memory of the parent.
    unsafe {
        command.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            Ok(())
        });
    }
}

#[cfg(not(unix))]
pub fn isolate_process_group(_command: &mut Command) {}

/// SIGKILL `child`'s process group (it must have been started with
/// [`isolate_process_group`]), then the child itself.
#[cfg(unix)]
pub fn kill_process_group(child: &mut Child) {
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: a negative pid names the process group led by `pid`.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let _ = child.kill();
}

#[cfg(not(unix))]
pub fn kill_process_group(child: &mut Child) {
    let _ = child.kill();
}

/// Wait for `child` until `timeout` has passed, then kill its process group.
/// Returns its exit status (`None` when it could not be read) and whether it
/// was killed for running too long.
pub fn wait_with_timeout(
    child: &mut Child,
    timeout: Duration,
) -> std::io::Result<(Option<ExitStatus>, bool)> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok((Some(status), false));
        }
        if Instant::now() >= deadline {
            kill_process_group(child);
            return Ok((child.wait().ok(), true));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The result of `handle`, waiting at most `grace` for it; a thread still
/// running after that (a descendant of a killed child holds its pipe) is left
/// to finish on its own.
pub fn join_bounded<T>(handle: JoinHandle<T>, grace: Duration) -> Option<T> {
    let deadline = Instant::now() + grace;
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    handle.join().ok()
}

/// Read `pipe` to its end on a thread, keeping at most `limit` bytes.
pub fn drain(mut pipe: impl std::io::Read + Send + 'static, limit: usize) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut chunk = [0u8; 64 * 1024];
        while let Ok(read) = pipe.read(&mut chunk) {
            if read == 0 {
                break;
            }
            let room = limit.saturating_sub(kept.len());
            kept.extend_from_slice(&chunk[..read.min(room)]);
        }
        kept
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::process::Stdio;

    /// A launcher whose own child keeps running: the timeout kills both, and
    /// the drain of the pipe they share returns once the grace has passed.
    #[test]
    fn a_timeout_kills_the_whole_process_group() {
        let started = Instant::now();
        let mut command = Command::new("sh");
        command
            .args(["-c", "sleep 30 & sleep 30; echo done"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        isolate_process_group(&mut command);
        let mut child = command.spawn().unwrap();
        let stdout = drain(child.stdout.take().unwrap(), 1024);
        let (status, timed_out) =
            wait_with_timeout(&mut child, Duration::from_millis(300)).unwrap();
        assert!(timed_out);
        assert!(status.is_some_and(|status| !status.success()));
        let output = join_bounded(stdout, DRAIN_GRACE);
        assert_eq!(output.as_deref(), Some(&b""[..]), "the group was killed");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_bounded_join_gives_up_on_a_thread_that_does_not_finish() {
        let (_keep, wait) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            let _ = wait.recv();
        });
        assert_eq!(join_bounded(handle, Duration::from_millis(50)), None);
    }
}
