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

/// Do not let an emulated child write a core dump: a guest crash under
/// qemu-user makes qemu dump its own, huge address space, which takes
/// minutes.
#[cfg(unix)]
pub fn disable_core_dumps(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: setrlimit is async-signal-safe and touches no memory of the
    // parent.
    unsafe {
        command.pre_exec(|| {
            let none = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            libc::setrlimit(libc::RLIMIT_CORE, &none);
            Ok(())
        });
    }
}

#[cfg(not(unix))]
pub fn disable_core_dumps(_command: &mut Command) {}

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

/// Kills a child's process group when dropped, and while it lives, when bhf
/// is ended by SIGINT, SIGTERM or SIGHUP.
///
/// A child started with [`isolate_process_group`] does not get the terminal's
/// Ctrl-C, and `PR_SET_PDEATHSIG` ends only the child itself, so without the
/// guard an interrupted bhf would leave whatever a launcher harness started
/// running. The signal handler (installed with the first guard, for each
/// signal whose disposition is still the default) kills every guarded group
/// and then re-raises the signal, so bhf still ends by it. At most
/// [`GUARDED_GROUPS`] groups are covered by the handler at once; a guard taken
/// beyond that still kills its group when dropped.
///
/// Wait for the child with [`ProcessGroupGuard::wait_then_kill`]: it kills the
/// group before the child is reaped, while the child's pid (the group's id)
/// cannot have been given to another process, and then stops guarding it, so
/// neither the drop nor the signal handler can later kill a group that reused
/// the id.
#[derive(Debug)]
pub struct ProcessGroupGuard {
    #[cfg(unix)]
    pgid: i32,
    #[cfg(unix)]
    slot: Option<usize>,
}

/// How a guarded run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// The child exited on its own.
    Exited,
    /// It was still running at the timeout and was killed.
    TimedOut,
    /// The caller's watchdog asked for it to be killed.
    Stopped,
}

/// How many live process groups the signal handler can kill.
pub const GUARDED_GROUPS: usize = 64;

#[cfg(unix)]
static GROUPS: [std::sync::atomic::AtomicI32; GUARDED_GROUPS] =
    [const { std::sync::atomic::AtomicI32::new(0) }; GUARDED_GROUPS];

/// Guard `child`'s process group (it must have been started with
/// [`isolate_process_group`]); see [`ProcessGroupGuard`].
#[cfg(unix)]
pub fn guard_process_group(child: &Child) -> ProcessGroupGuard {
    use std::sync::atomic::Ordering;
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(install_group_killer);
    let pgid = i32::try_from(child.id()).unwrap_or(0);
    let slot = (pgid > 0)
        .then(|| {
            GROUPS.iter().position(|slot| {
                slot.compare_exchange(0, pgid, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            })
        })
        .flatten();
    ProcessGroupGuard { pgid, slot }
}

#[cfg(not(unix))]
pub fn guard_process_group(_child: &Child) -> ProcessGroupGuard {
    ProcessGroupGuard {}
}

impl ProcessGroupGuard {
    /// Wait for the guarded `child` (the group's leader) until `timeout` has
    /// passed, then SIGKILL its whole process group (whatever it left
    /// running, or all of it on a timeout) and stop guarding the group.
    /// Returns its exit status (`None` when it could not be read) and whether
    /// it was killed for running too long, as [`wait_with_timeout`] does.
    ///
    /// On Linux the child is waited for without being reaped
    /// (`waitid(WNOWAIT)`), so the group is killed while its id is still
    /// held; elsewhere it is killed right after the child is reaped.
    #[cfg(unix)]
    pub fn wait_then_kill(
        &mut self,
        child: &mut Child,
        timeout: Duration,
    ) -> std::io::Result<(Option<ExitStatus>, bool)> {
        let (status, ended) = self.wait_then_kill_unless(child, timeout, |_| false)?;
        Ok((status, ended == Ended::TimedOut))
    }

    #[cfg(not(unix))]
    pub fn wait_then_kill(
        &mut self,
        child: &mut Child,
        timeout: Duration,
    ) -> std::io::Result<(Option<ExitStatus>, bool)> {
        wait_with_timeout(child, timeout)
    }

    /// [`Self::wait_then_kill`], also ending the run early when `stop`, asked
    /// with the child's pid every few milliseconds while it runs, says so (a
    /// memory watchdog). Returns how the run ended.
    #[cfg(unix)]
    pub fn wait_then_kill_unless(
        &mut self,
        child: &mut Child,
        timeout: Duration,
        mut stop: impl FnMut(u32) -> bool,
    ) -> std::io::Result<(Option<ExitStatus>, Ended)> {
        let deadline = Instant::now() + timeout;
        let ended = loop {
            if leader_exited(child)? {
                break Ended::Exited;
            }
            if Instant::now() >= deadline {
                break Ended::TimedOut;
            }
            if stop(child.id()) {
                break Ended::Stopped;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        self.kill_and_release();
        if ended != Ended::Exited {
            let _ = child.kill();
            return Ok((child.wait().ok(), ended));
        }
        child.wait().map(|status| (Some(status), Ended::Exited))
    }

    /// [`Self::wait_then_kill`]; `stop` is not consulted on this platform.
    #[cfg(not(unix))]
    pub fn wait_then_kill_unless(
        &mut self,
        child: &mut Child,
        timeout: Duration,
        _stop: impl FnMut(u32) -> bool,
    ) -> std::io::Result<(Option<ExitStatus>, Ended)> {
        let (status, timed_out) = wait_with_timeout(child, timeout)?;
        Ok((
            status,
            if timed_out {
                Ended::TimedOut
            } else {
                Ended::Exited
            },
        ))
    }

    /// SIGKILL the group (once), then take it out of the signal handler's
    /// slots.
    #[cfg(unix)]
    fn kill_and_release(&mut self) {
        if self.pgid > 0 {
            // SAFETY: a negative pid names the process group led by `pgid`.
            unsafe {
                libc::kill(-self.pgid, libc::SIGKILL);
            }
        }
        self.pgid = 0;
        if let Some(slot) = self.slot.take() {
            GROUPS[slot].store(0, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

/// Whether `child` has exited. On Linux it is left unreaped (a zombie still
/// holds its pid); elsewhere it is reaped.
#[cfg(target_os = "linux")]
fn leader_exited(child: &mut Child) -> std::io::Result<bool> {
    let pid: libc::id_t = child.id();
    // SAFETY: waitid writes only into `info`, a zeroed siginfo_t it owns.
    let (rc, info) = unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let rc = libc::waitid(
            libc::P_PID,
            pid,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        );
        (rc, info)
    };
    if rc != 0 {
        // Already reaped, or waitid is unavailable: fall back to reaping.
        return Ok(child.try_wait()?.is_some());
    }
    // SAFETY: waitid filled `info` (si_pid stays 0 when nothing exited).
    Ok(unsafe { info.si_pid() } != 0)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn leader_exited(child: &mut Child) -> std::io::Result<bool> {
    Ok(child.try_wait()?.is_some())
}

#[cfg(unix)]
impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        self.kill_and_release();
    }
}

/// Install [`kill_guarded_groups`] for SIGINT, SIGTERM and SIGHUP, each only
/// when its disposition is the default: a signal bhf ignores (under `nohup`)
/// or that something else handles is left alone.
#[cfg(unix)]
fn install_group_killer() {
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: sigaction with a zeroed struct only reads the current
        // disposition; the handler installed is async-signal-safe.
        unsafe {
            let mut current: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(signal, std::ptr::null(), &mut current) != 0
                || current.sa_sigaction != libc::SIG_DFL
            {
                continue;
            }
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = kill_guarded_groups as extern "C" fn(libc::c_int) as usize;
            libc::sigemptyset(&mut action.sa_mask);
            // Back to the default on entry, so the re-raise below ends bhf.
            action.sa_flags = libc::SA_RESETHAND;
            libc::sigaction(signal, &action, std::ptr::null_mut());
        }
    }
}

/// The signal handler: SIGKILL every guarded group, then raise `signal` again
/// (its disposition is the default by now), so bhf ends by it. Only
/// async-signal-safe calls.
#[cfg(unix)]
extern "C" fn kill_guarded_groups(signal: libc::c_int) {
    for slot in &GROUPS {
        let pgid = slot.load(std::sync::atomic::Ordering::SeqCst);
        if pgid > 0 {
            // SAFETY: kill is async-signal-safe.
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
        }
    }
    // SAFETY: raise is async-signal-safe.
    unsafe {
        libc::raise(signal);
    }
}

/// Wait for `child` until `timeout` has passed, then kill its process group.
/// Returns its exit status (`None` when it could not be read) and whether it
/// was killed for running too long.
pub fn wait_with_timeout(
    child: &mut Child,
    timeout: Duration,
) -> std::io::Result<(Option<ExitStatus>, bool)> {
    if let Some(status) = wait_exit_within(child, timeout)? {
        return Ok((Some(status), false));
    }
    kill_process_group(child);
    Ok((child.wait().ok(), true))
}

/// Wait at most `timeout` for `child` to exit: its exit status, or `None` if
/// it is still running. The wait blocks on the process itself (a pidfd on
/// Linux, the process handle on Windows), so the caller wakes when the child
/// exits rather than on the next tick of a sleep loop. A sleep tick costs
/// every execution its length, and on a loaded machine each wakeup also waits
/// for a CPU. Elsewhere this falls back to a short, growing poll.
pub fn wait_exit_within(
    child: &mut Child,
    timeout: Duration,
) -> std::io::Result<Option<ExitStatus>> {
    if let Some(status) = child.try_wait()? {
        return Ok(Some(status));
    }
    if timeout.is_zero() {
        return Ok(None);
    }
    let deadline = Instant::now() + timeout;
    match block_until_exit(child, deadline) {
        Some(_) => child.try_wait(),
        None => poll_until_exit(child, deadline),
    }
}

/// Milliseconds left until `deadline`, rounded up so a sub-millisecond
/// remainder still waits, and capped at `max`.
fn millis_until(deadline: Instant, max: u32) -> u32 {
    let left = deadline.saturating_duration_since(Instant::now());
    left.as_nanos().div_ceil(1_000_000).min(u128::from(max)) as u32
}

/// Block until `child` exits (`Some(true)`) or `deadline` passes
/// (`Some(false)`); `None` when the platform offers no such wait.
#[cfg(target_os = "linux")]
fn block_until_exit(child: &Child, deadline: Instant) -> Option<bool> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let pid = libc::pid_t::try_from(child.id()).ok()?;
    // SAFETY: pidfd_open takes a pid and flags and returns a new fd or -1. The
    // child is not reaped yet, so `pid` still names it.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    let fd = i32::try_from(fd).ok().filter(|fd| *fd >= 0)?;
    // SAFETY: the kernel just returned this fd and nothing else owns it.
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd) };
    loop {
        let mut pfd = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = millis_until(deadline, i32::MAX as u32) as i32;
        // SAFETY: `pfd` is a valid pollfd for the duration of the call.
        match unsafe { libc::poll(&mut pfd, 1, millis) } {
            ready if ready > 0 => return Some(true),
            0 if Instant::now() >= deadline => return Some(false),
            0 => {}
            _ if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted => {}
            _ => return None,
        }
    }
}

#[cfg(windows)]
fn block_until_exit(child: &Child, deadline: Instant) -> Option<bool> {
    use std::os::windows::io::AsRawHandle;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 0x102;
    #[link(name = "kernel32")]
    extern "system" {
        fn WaitForSingleObject(handle: *mut std::ffi::c_void, milliseconds: u32) -> u32;
    }
    loop {
        // Stay below INFINITE (u32::MAX); a longer wait loops.
        let millis = millis_until(deadline, u32::MAX - 1);
        // SAFETY: the handle is the live process handle `child` owns.
        match unsafe { WaitForSingleObject(child.as_raw_handle(), millis) } {
            WAIT_OBJECT_0 => return Some(true),
            WAIT_TIMEOUT if Instant::now() >= deadline => return Some(false),
            WAIT_TIMEOUT => {}
            _ => return None,
        }
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn block_until_exit(_child: &Child, _deadline: Instant) -> Option<bool> {
    None
}

/// The fallback wait: poll, sleeping 0.1 ms at first and at most 5 ms.
fn poll_until_exit(child: &mut Child, deadline: Instant) -> std::io::Result<Option<ExitStatus>> {
    let mut nap = Duration::from_micros(100);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        std::thread::sleep(nap.min(deadline - now));
        nap = (nap * 2).min(Duration::from_millis(5));
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

/// Write `bytes` to `child`'s stdin on a thread, then close the pipe so the
/// child sees end of input. Returns `None` when the child has no piped stdin.
///
/// Writing on a thread keeps the caller's timeout running: a child that never
/// reads an input larger than the pipe buffer would otherwise block the write,
/// and with it the wait, forever. A `BrokenPipe` is not an error (the child
/// exited, or was killed, before it read everything; its exit status is the
/// result). Rust ignores SIGPIPE, so such a write fails instead of killing the
/// caller. A descendant that left the child's process group and still holds
/// the pipe's read end can keep the write blocked; join the handle with
/// [`join_bounded`], which leaves such a thread to finish on its own, as it
/// does for the drain threads.
pub fn feed_stdin(child: &mut Child, bytes: Vec<u8>) -> Option<JoinHandle<std::io::Result<()>>> {
    use std::io::Write;
    let mut stdin = child.stdin.take()?;
    Some(std::thread::spawn(move || {
        let written = stdin.write_all(&bytes).and_then(|()| stdin.flush());
        drop(stdin);
        match written {
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
            other => other,
        }
    }))
}

/// The blocking wait on every platform: an exited child's status comes back,
/// and a running one is reported as running once the timeout passes.
#[cfg(all(test, any(unix, windows)))]
mod wait_tests {
    use super::*;

    fn shell(unix: &str, windows: &str) -> Child {
        let mut command = if cfg!(windows) {
            let mut command = Command::new("cmd");
            command.args(["/c", windows]);
            command
        } else {
            let mut command = Command::new("sh");
            command.args(["-c", unix]);
            command
        };
        command.spawn().unwrap()
    }

    #[test]
    fn an_exiting_child_is_waited_for_and_a_running_one_times_out() {
        let mut quick = shell("exit 3", "exit 3");
        let status = wait_exit_within(&mut quick, Duration::from_secs(10)).unwrap();
        assert_eq!(status.and_then(|status| status.code()), Some(3));

        let mut slow = shell(
            "exec sleep 30",
            r"%SystemRoot%\System32\ping.exe -n 30 127.0.0.1 > nul",
        );
        let started = Instant::now();
        let status = wait_exit_within(&mut slow, Duration::from_millis(300)).unwrap();
        let waited = started.elapsed();
        assert!(status.is_none(), "still running");
        assert!(waited >= Duration::from_millis(300), "{waited:?}");
        assert!(waited < Duration::from_secs(10), "{waited:?}");
        let _ = slow.kill();
        let _ = slow.wait();
    }
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

    /// Waiting blocks until the child exits instead of waking on a sleep tick:
    /// the waiting thread switches out about once, however long the child runs.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_wait_blocks_until_the_child_exits() {
        let switches = || {
            // SAFETY: `usage` is a valid out-pointer for the duration of the call.
            let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::getrusage(libc::RUSAGE_THREAD, &mut usage) },
                0
            );
            usage.ru_nvcsw
        };
        let mut child = Command::new("sh")
            .args(["-c", "sleep 0.4"])
            .spawn()
            .unwrap();
        let before = switches();
        let (status, timed_out) = wait_with_timeout(&mut child, Duration::from_secs(10)).unwrap();
        let woke = switches() - before;
        assert!(!timed_out);
        assert!(status.is_some_and(|status| status.success()));
        assert!(woke <= 4, "a 400 ms child took {woke} wakeups to wait for");
    }

    /// A child that outlives the timeout is still killed at it.
    #[test]
    fn a_wait_still_times_out_a_child_that_keeps_running() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 30"]);
        isolate_process_group(&mut command);
        let mut child = command.spawn().unwrap();
        let started = Instant::now();
        let (_, timed_out) = wait_with_timeout(&mut child, Duration::from_millis(400)).unwrap();
        let waited = started.elapsed();
        assert!(timed_out);
        assert!(waited >= Duration::from_millis(400), "{waited:?}");
        assert!(waited < Duration::from_secs(10), "{waited:?}");
    }

    #[test]
    fn core_dumps_are_off_for_an_emulated_child() {
        let mut command = Command::new("sh");
        command.args(["-c", "ulimit -c"]).stdout(Stdio::piped());
        disable_core_dumps(&mut command);
        let output = command.output().unwrap();
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "0");
    }

    #[test]
    fn a_bounded_join_gives_up_on_a_thread_that_does_not_finish() {
        let (_keep, wait) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            let _ = wait.recv();
        });
        assert_eq!(join_bounded(handle, Duration::from_millis(50)), None);
    }

    /// A child that never reads an input larger than the pipe buffer is still
    /// killed at the timeout, and the writer thread ends once it is.
    #[test]
    fn a_child_that_ignores_its_input_still_times_out() {
        let started = Instant::now();
        let mut command = Command::new("sh");
        command
            .args(["-c", "exec sleep 30"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        isolate_process_group(&mut command);
        let mut child = command.spawn().unwrap();
        let writer = feed_stdin(&mut child, vec![0u8; 1 << 20]).expect("a piped stdin");
        let (_, timed_out) = wait_with_timeout(&mut child, Duration::from_millis(300)).unwrap();
        assert!(timed_out);
        assert!(matches!(join_bounded(writer, DRAIN_GRACE), Some(Ok(()))));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }

    /// Every fed byte reaches the child, and the pipe is closed after them so
    /// the child sees the end of its input.
    #[test]
    fn fed_input_reaches_the_child_and_is_closed() {
        // Removed when this scope ends.
        let dir_tmp = tempfile::Builder::new()
            .prefix("bhf-")
            .tempdir()
            .expect("create test dir");
        let dir = dir_tmp.path().join(format!(
            "bhf-feed-stdin-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("out");
        let bytes: Vec<u8> = (0..1u32 << 20).map(|i| (i % 251) as u8).collect();
        let mut command = Command::new("sh");
        command
            .args(["-c", "cat > \"$0\""])
            .arg(&out)
            .stdin(Stdio::piped());
        isolate_process_group(&mut command);
        let mut child = command.spawn().unwrap();
        let writer = feed_stdin(&mut child, bytes.clone()).expect("a piped stdin");
        let (status, timed_out) = wait_with_timeout(&mut child, Duration::from_secs(20)).unwrap();
        assert!(!timed_out);
        assert!(status.is_some_and(|status| status.success()));
        assert!(matches!(join_bounded(writer, DRAIN_GRACE), Some(Ok(()))));
        assert_eq!(std::fs::read(&out).unwrap(), bytes);
        let _ = std::fs::remove_dir_all(&dir);

        let mut command = Command::new("true");
        command.stdin(Stdio::null());
        let mut child = command.spawn().unwrap();
        assert!(feed_stdin(&mut child, b"x".to_vec()).is_none());
        let _ = child.wait();
    }

    /// Whether `pid` has ended: gone, or a zombie nobody has reaped yet.
    #[cfg(target_os = "linux")]
    fn ended(pid: &str) -> bool {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(_) => true,
            Ok(stat) => stat
                .rsplit_once(')')
                .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z')),
        }
    }

    /// Dropping the guard kills what the child started, too.
    #[cfg(target_os = "linux")]
    #[test]
    fn dropping_the_guard_kills_the_group() {
        use std::io::BufRead;
        let mut command = Command::new("sh");
        command
            .args(["-c", "sleep 30 & echo $!; wait"])
            .stdout(Stdio::piped());
        isolate_process_group(&mut command);
        let mut child = command.spawn().unwrap();
        let guard = guard_process_group(&child);
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let background = line.trim().to_owned();
        assert!(!background.is_empty());
        assert!(!ended(&background), "the background sleep runs");
        drop(guard);
        let deadline = Instant::now() + Duration::from_secs(2);
        while !ended(&background) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let gone = ended(&background);
        if !gone {
            let _ = Command::new("kill").args(["-9", &background]).status();
        }
        let _ = child.wait();
        assert!(gone, "process {background} outlived the guard");
    }

    /// Waiting through the guard kills what the child left running as soon as
    /// the child exits, before the child is reaped and its pid (the group's
    /// id) can go to another process, and then lets the group go: neither the
    /// drop nor the signal handler kills that id again.
    #[cfg(target_os = "linux")]
    #[test]
    fn waiting_through_the_guard_kills_the_group_and_releases_it() {
        use std::io::BufRead;
        use std::sync::atomic::Ordering;
        let mut command = Command::new("sh");
        command
            .args(["-c", "sleep 30 & echo $!"])
            .stdout(Stdio::piped());
        isolate_process_group(&mut command);
        let mut child = command.spawn().unwrap();
        let pgid = i32::try_from(child.id()).unwrap();
        let mut guard = guard_process_group(&child);
        assert!(GROUPS
            .iter()
            .any(|slot| slot.load(Ordering::SeqCst) == pgid));
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let background = line.trim().to_owned();
        assert!(!background.is_empty());

        let (status, timed_out) = guard
            .wait_then_kill(&mut child, Duration::from_secs(10))
            .unwrap();
        assert!(!timed_out);
        assert!(status.is_some_and(|status| status.success()));
        let deadline = Instant::now() + Duration::from_secs(2);
        while !ended(&background) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let gone = ended(&background);
        if !gone {
            let _ = Command::new("kill").args(["-9", &background]).status();
        }
        assert!(gone, "process {background} outlived the wait");
        assert!(
            GROUPS
                .iter()
                .all(|slot| slot.load(Ordering::SeqCst) != pgid),
            "the handler no longer kills group {pgid}"
        );
        assert_eq!(guard.pgid, 0, "the drop no longer kills group {pgid}");
    }

    /// A child that outlives the timeout is killed with its group, through
    /// the guard too.
    #[cfg(target_os = "linux")]
    #[test]
    fn waiting_through_the_guard_still_times_out() {
        let started = Instant::now();
        let mut command = Command::new("sh");
        command
            .args(["-c", "sleep 30 & sleep 30"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        isolate_process_group(&mut command);
        let mut child = command.spawn().unwrap();
        let stdout = drain(child.stdout.take().unwrap(), 1024);
        let mut guard = guard_process_group(&child);
        let (status, timed_out) = guard
            .wait_then_kill(&mut child, Duration::from_millis(300))
            .unwrap();
        assert!(timed_out);
        assert!(status.is_some_and(|status| !status.success()));
        assert_eq!(
            join_bounded(stdout, DRAIN_GRACE).as_deref(),
            Some(&b""[..]),
            "the group was killed"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
