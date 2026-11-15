// SPDX-License-Identifier: Apache-2.0

//! Bounded subprocess capture for build/smoke-test commands that must inspect
//! stdout or stderr. Source-controlled build/import code can print forever, so
//! `Command::output` is not safe at this trust boundary.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn max_stream_bytes() -> usize {
    crate::resource_limits::dynamic_bytes(
        "BHF_MAX_SUBPROCESS_OUTPUT_BYTES",
        1024,
        4 * crate::resource_limits::MIB,
        4 * crate::resource_limits::MIB,
        64 * crate::resource_limits::MIB,
    )
}

pub(crate) struct BoundedOutput {
    pub(crate) output: Output,
    pub(crate) stdout_truncated: bool,
    pub(crate) stderr_truncated: bool,
    pub(crate) timed_out: bool,
}

#[cfg(unix)]
fn prepare_child(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
    #[cfg(target_os = "linux")]
    unsafe {
        command.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn prepare_child(_command: &mut Command) {}

#[cfg(unix)]
fn kill_child_tree(child: &mut std::process::Child) {
    let pid = child.id() as i32;
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    let _ = child.kill();
}

#[cfg(not(unix))]
fn kill_child_tree(child: &mut std::process::Child) {
    let _ = child.kill();
}

/// Read `reader` to the end, keeping at most `cap` bytes (its head and tail),
/// and copy every chunk to `forward` as it arrives when one is given.
fn read_head_tail_forwarding(
    mut reader: impl Read,
    cap: usize,
    mut forward: Option<impl Write>,
) -> (Vec<u8>, bool) {
    let head_cap = cap / 2;
    let tail_cap = cap.saturating_sub(head_cap);
    let mut head = Vec::with_capacity(head_cap);
    let mut tail: VecDeque<u8> = VecDeque::with_capacity(tail_cap);
    let mut truncated = false;
    let mut chunk = [0_u8; 64 * 1024];
    while let Ok(read) = reader.read(&mut chunk) {
        if read == 0 {
            break;
        }
        if let Some(sink) = forward.as_mut() {
            // Forwarding is best effort: a closed terminal must not stop the
            // capture the caller still needs.
            let _ = sink.write_all(&chunk[..read]);
            let _ = sink.flush();
        }
        let mut bytes = &chunk[..read];
        if head.len() < head_cap {
            let take = bytes.len().min(head_cap - head.len());
            head.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
        }
        if !bytes.is_empty() {
            if tail.len().saturating_add(bytes.len()) > tail_cap {
                let excess = tail
                    .len()
                    .saturating_add(bytes.len())
                    .saturating_sub(tail_cap);
                tail.drain(..excess.min(tail.len()));
                truncated = true;
                if bytes.len() > tail_cap {
                    bytes = &bytes[bytes.len() - tail_cap..];
                }
            }
            tail.extend(bytes);
        }
    }
    if truncated {
        head.extend_from_slice(b"\n[bhf: subprocess output truncated]\n");
    }
    head.extend(tail);
    (head, truncated)
}

/// A whole-run deadline that every subprocess is clamped to.
///
/// Build steps carry generous individual timeouts (30 minutes for a compile),
/// which is right for one target and wrong for a bounded sweep: a single slow
/// build outlasted a `--campaign-time 150` run by minutes, so the budget the
/// operator set did not describe the run. Setting this makes every child
/// inherit "whatever is left", so the campaign ends when it was asked to.
static CAMPAIGN_DEADLINE: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

/// Work already in flight when the budget runs out gets this much longer to
/// finish, so the last target is cut off cleanly rather than mid-link.
///
/// A QUARTER of the campaign, capped at two minutes and floored at ten seconds
/// — not a flat two minutes. A round may start moments before the deadline and
/// its compile then runs for the whole grace, so a flat grace is added to every
/// campaign no matter how small: with `--campaign-time 120` it DOUBLED the
/// phase, and Proton's run came to 84s discovery + 120s campaign + 120s grace
/// against a 510s allowance. Scaling keeps the overshoot proportional to the
/// budget the operator actually set.
static CAMPAIGN_GRACE: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();

/// The operator's whole campaign budget, used to size the grace and the
/// per-subprocess ceiling.
static CAMPAIGN_TOTAL: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();

fn campaign_grace() -> Duration {
    *CAMPAIGN_GRACE.get().unwrap_or(&Duration::from_secs(120))
}

/// Bound every subsequent subprocess by `deadline`. Idempotent: the first
/// deadline set for a process wins, so nested code cannot extend it.
///
/// `campaign` is the operator's total budget, used to size the grace.
pub(crate) fn set_campaign_deadline(deadline: Instant, campaign: Option<Duration>) {
    let _ = CAMPAIGN_DEADLINE.set(deadline);
    if let Some(campaign) = campaign {
        let _ = CAMPAIGN_TOTAL.set(campaign);
        // Publish the same ceiling to crates that spawn compilers themselves and
        // cannot depend on this module (compiler_adapter runs gprbuild).
        std::env::set_var(
            "BHF_SUBPROCESS_TIMEOUT_SECS",
            (campaign / 4)
                .max(Duration::from_secs(15))
                .as_secs()
                .to_string(),
        );
        let _ = CAMPAIGN_GRACE
            .set((campaign / 4).clamp(Duration::from_secs(10), Duration::from_secs(120)));
    }
}

/// Has the operator's budget passed? Callers use this to stop starting work
/// that cannot finish, and to report an honest "budget exhausted" instead of a
/// mystery build failure. Deliberately the REAL deadline, not the grace-padded
/// one the subprocess clamp uses: work already running gets the grace, new
/// rounds do not.
pub(crate) fn campaign_budget_exhausted() -> bool {
    CAMPAIGN_DEADLINE
        .get()
        .is_some_and(|deadline| Instant::now() >= *deadline)
}

/// The effective timeout: the caller's, or the time left in the campaign (plus
/// the grace) when that is shorter. A floor keeps a nearly-expired budget from
/// spawning processes that are killed before they can do anything.
fn clamp_to_campaign(timeout: Duration) -> Duration {
    let Some(deadline) = CAMPAIGN_DEADLINE.get() else {
        return timeout;
    };
    let remaining = (*deadline + campaign_grace())
        .saturating_duration_since(Instant::now())
        .max(Duration::from_secs(5));
    // No SINGLE subprocess may take more than a quarter of the campaign, even
    // while the whole budget is still unspent. Remaining-time alone does not stop
    // the FIRST build from eating everything: on AdaCore/gnat-llvm one generated
    // harness sent `gnat1` into a spin and, because the budget was untouched, the
    // clamp allowed it the entire campaign — one target consumed the run and it
    // was killed with nothing to show. A build that cannot finish in a quarter of
    // the budget leaves no time to fuzz what it produces.
    timeout.min(remaining).min(per_call_ceiling())
}

/// The most any one subprocess may take: a quarter of the campaign, floored at
/// 15s so a small budget can still run a compiler. Unbounded with no campaign.
fn per_call_ceiling() -> Duration {
    CAMPAIGN_TOTAL
        .get()
        .map(|total| (*total / 4).max(Duration::from_secs(15)))
        .unwrap_or(Duration::MAX)
}

/// Point a command that executes TARGET code at its own binary's directory.
///
/// Target code runs with attacker-controlled input and does whatever it likes
/// with the filesystem. Inheriting bhf's CWD means those writes land wherever
/// the user happened to invoke bhf — very often the tree being scanned. An
/// empty file literally named `AAAAAA` turned up in this repository's root after a
/// sweep, which is a fuzz input used as a filename.
///
/// Beyond the mess, it breaks `--resume`: a write into the scanned tree changes
/// the source identity the next run compares against, so a run can invalidate its
/// own fingerprint. The harness's own directory is under the work dir, so writes
/// stay with the run that caused them.
pub(crate) fn run_target_beside_binary(command: &mut Command, binary: &std::path::Path) {
    if let Some(dir) = binary.parent().filter(|dir| dir.is_dir()) {
        command.current_dir(dir);
    }
}

/// A command that runs `binary`, killed after `seconds` by coreutils `timeout`
/// where that is on `PATH`. Callers run it with [`bounded_replay_output`],
/// whose bound is the only one where no wrapper runs; the wrapper makes sure
/// the binary itself dies (`timeout` signals the program it execs). Never on
/// Windows: `timeout` there is the console pause command
/// (`System32\timeout.exe`), which rejects `-s KILL` and runs nothing, so a
/// replay through it saw no crash at all.
pub(crate) fn killed_after(binary: &std::path::Path, seconds: u32) -> Command {
    if cfg!(unix) && which::which("timeout").is_ok() {
        let mut command = Command::new("timeout");
        command
            .arg("-s")
            .arg("KILL")
            .arg(seconds.to_string())
            .arg(binary);
        command
    } else {
        Command::new(binary)
    }
}

/// Run a command to completion with INHERITED stdio (so compiler output still
/// streams to the terminal), bounded by the same campaign clamp as
/// [`output_with_timeout`], in its own process group so a timeout kills the
/// whole tree.
///
/// `Command::status()` does none of that. A generated Ada harness that sent
/// `gnat1` into a spin ran `gprbuild` for the entire campaign on
/// AdaCore/gnat-llvm, and because the child was neither grouped nor
/// death-signalled it SURVIVED bhf being killed: orphaned `gprbuild`/`gcc`/
/// `gnat1` processes were found still running 39 hours after their sweep,
/// stealing CPU from every later run on the machine.
/// Spawn, riding out the two transient failures that make an `exec` of a FRESHLY
/// WRITTEN executable fail.
///
/// `ExecutableFileBusy` (`ETXTBSY`): the kernel refuses to exec a file that is
/// still open for writing ANYWHERE. bhf's whole shape is build-then-run — a
/// harness build followed immediately by a fuzz or replay of the binary it just
/// produced — and in a multi-threaded process a child forked by one thread
/// inherits a write descriptor another thread has not closed yet. The window is
/// microseconds, so it surfaces only under load: as an intermittent CI failure
/// that reads like a broken harness rather than a race.
///
/// `WouldBlock` (`EAGAIN`) covers a transient fork failure when a loaded box is
/// briefly out of process slots.
///
/// Placed here, at the one spawn every bounded subprocess goes through, rather
/// than at each call site: `replay` got its own copy of this in 0.2.27 and the
/// multicore worker spawn and the TSan/MSan corpus replays were all still exposed.
/// Matched on `ErrorKind` rather than raw errno so it compiles on every target.
fn spawn_riding_out_transients(command: &mut Command) -> io::Result<std::process::Child> {
    const RETRY_DELAY: Duration = Duration::from_millis(25);
    const RETRIES: usize = 40; // ~1s total, far longer than either window lasts
    for _ in 0..RETRIES {
        match command.spawn() {
            Ok(child) => return Ok(child),
            Err(error) => {
                if !matches!(
                    error.kind(),
                    io::ErrorKind::ExecutableFileBusy | io::ErrorKind::WouldBlock
                ) {
                    return Err(error);
                }
                std::thread::sleep(RETRY_DELAY);
            }
        }
    }
    command.spawn()
}

/// Run a command with bounded stdout/stderr and a wall-clock timeout. Both pipes
/// are drained concurrently so a noisy child cannot deadlock on a full pipe.
pub(crate) fn output_with_timeout(command: &mut Command, timeout: Duration) -> io::Result<Output> {
    capture_with_timeout(command, clamp_to_campaign(timeout), max_stream_bytes())
        .map(|captured| captured.output)
}

/// As [`output_with_timeout`], plus whether the child was KILLED for exceeding its
/// wall clock.
///
/// A timed-out child is reported to the caller as a normal non-success exit, which
/// is indistinguishable from the target itself failing — so a consumer that treats
/// "not a success" as a measured result silently converts "we never finished
/// looking" into "we looked and found nothing". Callers whose conclusion depends on
/// the run having COMPLETED (the sanitizer replays) need the distinction.
pub(crate) fn output_with_timeout_flagged(
    command: &mut Command,
    timeout: Duration,
) -> io::Result<(Output, bool)> {
    capture_with_timeout(command, clamp_to_campaign(timeout), max_stream_bytes())
        .map(|captured| (captured.output, captured.timed_out))
}

/// Run a [`killed_after`] command bounded by `timeout`, which should exceed
/// the wrapper's seconds; the flag is true when the run was CUT OFF rather
/// than finished: killed at `timeout` (the only bound on Windows, or on a Unix
/// host without coreutils `timeout`, where the killed child's status is an
/// ordinary failure or a signal), or by the wrapper (exit 124, or 137 for its
/// SIGKILL). A cut-off replay saw only part of what the input does, so it
/// stands for no crash, coverage or behaviour.
pub(crate) fn bounded_replay_output(
    command: &mut Command,
    timeout: Duration,
) -> io::Result<(Output, bool)> {
    let (output, timed_out) = output_with_timeout_flagged(command, timeout)?;
    let wrapper_killed = cfg!(unix) && matches!(output.status.code(), Some(124 | 137));
    Ok((output, timed_out || wrapper_killed))
}

/// As [`output_with_timeout`], but the child's stdout and stderr are also
/// copied to this process's stdout and stderr as they arrive. A long build
/// stays visible to the operator while its bounded output is kept for
/// diagnosis afterwards. The flag is true when the child was killed for
/// exceeding `timeout`.
pub(crate) fn output_with_timeout_teed(
    command: &mut Command,
    timeout: Duration,
) -> io::Result<(Output, bool)> {
    capture_impl(
        command,
        clamp_to_campaign(timeout),
        max_stream_bytes(),
        true,
    )
    .map(|captured| (captured.output, captured.timed_out))
}

/// Variant for consumers (notably external analyzer JSON) that need to reject a
/// truncated stream rather than treating the bounded head/tail as complete data.
pub(crate) fn capture_with_timeout(
    command: &mut Command,
    timeout: Duration,
    max_stream_bytes: usize,
) -> io::Result<BoundedOutput> {
    capture_impl(command, timeout, max_stream_bytes, false)
}

fn capture_impl(
    command: &mut Command,
    timeout: Duration,
    max_stream_bytes: usize,
    tee: bool,
) -> io::Result<BoundedOutput> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    prepare_child(command);
    let mut child = spawn_riding_out_transients(command)?;
    let stdout = child.stdout.take().map(|pipe| {
        std::thread::spawn(move || {
            read_head_tail_forwarding(pipe, max_stream_bytes, tee.then(io::stdout))
        })
    });
    let stderr = child.stderr.take().map(|pipe| {
        std::thread::spawn(move || {
            read_head_tail_forwarding(pipe, max_stream_bytes, tee.then(io::stderr))
        })
    });
    let deadline = Instant::now() + timeout;
    let (status, timed_out) = loop {
        match child.try_wait() {
            Err(error) => {
                kill_child_tree(&mut child);
                let _ = child.wait();
                // Reaping closes the pipes so the readers cannot remain blocked.
                let _ = stdout.and_then(|reader| reader.join().ok());
                let _ = stderr.and_then(|reader| reader.join().ok());
                return Err(error);
            }
            Ok(Some(status)) => break (status, false),
            Ok(None) if Instant::now() >= deadline => {
                kill_child_tree(&mut child);
                break (child.wait()?, true);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
        }
    };
    let (stdout, stdout_truncated) = stdout
        .and_then(|reader| reader.join().ok())
        .unwrap_or_default();
    let (mut stderr, stderr_truncated) = stderr
        .and_then(|reader| reader.join().ok())
        .unwrap_or_default();
    if timed_out {
        stderr.extend_from_slice(b"\nbhf: subprocess exceeded its wall-clock timeout\n");
    }
    Ok(BoundedOutput {
        output: Output {
            status,
            stdout,
            stderr,
        },
        stdout_truncated,
        stderr_truncated,
        timed_out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A replay bounded by [`killed_after`] runs the binary: through coreutils
    /// `timeout` on Unix, directly on Windows, where `timeout` is the console
    /// pause command and ran nothing. The test binary lists its own tests.
    #[test]
    fn a_command_killed_after_a_timeout_runs_the_binary() {
        let binary = std::env::current_exe().unwrap();
        let mut command = killed_after(&binary, 30);
        if cfg!(unix) && which::which("timeout").is_ok() {
            assert_eq!(command.get_program(), "timeout");
        } else {
            assert_eq!(command.get_program(), binary.as_os_str());
        }
        let output = output_with_timeout(
            command.args(["--list", "a_command_killed_after_a_timeout_runs_the_binary"]),
            Duration::from_secs(60),
        )
        .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("a_command_killed_after_a_timeout_runs_the_binary"),
            "{output:?}"
        );
    }

    /// A replay killed at bhf's own bound is cut off, not finished: with no
    /// `timeout` wrapper (Windows, or a Unix host without coreutils) the
    /// killed child's status is an ordinary failure (Windows) or a signal
    /// (Unix), neither of which is the wrapper's 124 or 137.
    #[test]
    fn a_replay_killed_at_its_bound_is_cut_off() {
        let mut sleeper = if cfg!(windows) {
            let mut ping = Command::new("ping");
            ping.args(["-n", "30", "127.0.0.1"]);
            ping
        } else {
            let mut sleep = Command::new("sleep");
            sleep.arg("30");
            sleep
        };
        let started = Instant::now();
        let (output, cut_off) =
            bounded_replay_output(&mut sleeper, Duration::from_millis(500)).unwrap();
        assert!(cut_off, "{output:?}");
        assert!(started.elapsed() < Duration::from_secs(20), "{output:?}");
    }

    /// Where the coreutils wrapper runs, its timeout statuses (124, and 137
    /// for `-s KILL`) cut the replay off; any other exit is a finished run.
    #[test]
    #[cfg(unix)]
    fn a_replay_the_timeout_wrapper_killed_is_cut_off() {
        for (code, cut) in [(124, true), (137, true), (1, false), (0, false)] {
            let (output, cut_off) = bounded_replay_output(
                Command::new("sh").args(["-c", &format!("exit {code}")]),
                Duration::from_secs(20),
            )
            .unwrap();
            assert_eq!(cut_off, cut, "exit {code}: {output:?}");
        }
    }

    #[test]
    #[cfg(unix)]
    fn teed_capture_keeps_both_streams_and_reports_a_timeout() {
        let (output, timed_out) = output_with_timeout_teed(
            Command::new("sh").args(["-c", "echo built; echo 'undefined reference' >&2; exit 2"]),
            Duration::from_secs(20),
        )
        .unwrap();
        assert!(!timed_out);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(String::from_utf8_lossy(&output.stdout), "built\n");
        assert!(String::from_utf8_lossy(&output.stderr).contains("undefined reference"));

        let (output, timed_out) = output_with_timeout_teed(
            Command::new("sh").args(["-c", "sleep 30"]),
            Duration::from_millis(200),
        )
        .unwrap();
        assert!(timed_out);
        assert!(!output.status.success());
    }

    #[test]
    #[cfg(unix)]
    fn a_freshly_written_executable_still_open_for_writing_is_retried_not_failed() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        // The build-then-run shape of bhf: a harness is written and executed
        // moments later. Holding the writer open reproduces deterministically the
        // ETXTBSY a loaded host hits by accident, which used to surface as a hard
        // "failed to start" — and, in the sanitizer replays, as a silent zero.
        let dir = std::env::temp_dir().join(format!(
            "bhf-etxtbsy-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("fresh.sh");
        let mut writer = std::fs::File::create(&script).unwrap();
        writer.write_all(b"#!/bin/sh\nexit 0\n").unwrap();
        writer.flush().unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let bare = Command::new(&script).spawn();
        let reproduced = matches!(
            &bare,
            Err(e) if e.kind() == io::ErrorKind::ExecutableFileBusy
        );
        if let Ok(mut child) = bare {
            let _ = child.wait();
        }

        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(60));
            drop(writer);
        });
        let out = output_with_timeout(&mut Command::new(&script), Duration::from_secs(10));
        releaser.join().unwrap();
        assert!(
            out.is_ok(),
            "a bounded spawn must ride out ETXTBSY, got {:?}",
            out.err()
        );
        assert!(out.unwrap().status.success());
        if !reproduced {
            eprintln!("note: this filesystem did not produce ETXTBSY for an open writer");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn captures_both_streams() {
        let output = output_with_timeout(
            Command::new("sh")
                .arg("-c")
                .arg("printf out; printf err >&2"),
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"out");
        assert_eq!(output.stderr, b"err");
    }

    #[test]
    #[cfg(unix)]
    fn timeout_reaps_descendants_holding_capture_pipes() {
        let start = Instant::now();
        let output = output_with_timeout(
            Command::new("sh").arg("-c").arg("sleep 30 & wait"),
            Duration::from_millis(50),
        )
        .unwrap();
        assert!(!output.status.success());
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("wall-clock timeout"));
    }

    #[test]
    fn bounded_capture_reports_truncation() {
        let (bytes, truncated) =
            read_head_tail_forwarding(&b"0123456789abcdef"[..], 8, None::<io::Sink>);
        assert!(truncated);
        assert!(bytes.starts_with(b"0123"));
        assert!(bytes.ends_with(b"cdef"));
        // A forwarding sink sees every byte, not just the kept head and tail.
        let mut forwarded = Vec::new();
        let (kept, _) =
            read_head_tail_forwarding(&b"0123456789abcdef"[..], 8, Some(&mut forwarded));
        assert_eq!(kept, bytes);
        assert_eq!(forwarded, b"0123456789abcdef");
    }

    #[test]
    fn a_campaign_deadline_clamps_subprocess_timeouts_but_grants_a_grace() {
        // Without a deadline the caller's timeout is used verbatim.
        assert_eq!(
            clamp_to_campaign(Duration::from_secs(1800)),
            Duration::from_secs(1800)
        );

        // With one, a generous build timeout is cut to what is left plus the
        // grace: a 30-minute compile must not outlive a two-minute campaign.
        set_campaign_deadline(
            Instant::now() + Duration::from_secs(60),
            Some(Duration::from_secs(60)),
        );
        let clamped = clamp_to_campaign(Duration::from_secs(1800));
        // The grace is a quarter of the campaign (15s here), not a flat two
        // minutes, so a small budget is not doubled by the margin.
        assert!(
            clamped <= Duration::from_secs(60) + campaign_grace(),
            "clamped to {clamped:?}"
        );
        assert_eq!(campaign_grace(), Duration::from_secs(15));
        assert!(
            clamped >= Duration::from_secs(5),
            "a floor keeps work possible"
        );
        // A timeout shorter than the remaining budget is left alone.
        assert_eq!(
            clamp_to_campaign(Duration::from_secs(3)),
            Duration::from_secs(3)
        );
        // The budget itself has not passed yet, so new work may still start.
        assert!(!campaign_budget_exhausted());
    }
}
