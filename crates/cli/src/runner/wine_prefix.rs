// SPDX-License-Identifier: Apache-2.0

//! The Wine prefix a Windows harness runs in (#394).
//!
//! Wine creates its prefix (`$WINEPREFIX`, else `~/.wine`) the first time a
//! program runs in it, and that takes far longer than a harness start: the
//! fork server stops waiting for the harness's ready byte, every input times
//! out while the prefix is being written, and the target looks as if it was
//! never entered. So bhf creates a missing prefix itself, once, before the
//! first harness runs under Wine. An existing prefix costs one `stat`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// How long creating a prefix may take. It takes about 15 seconds on an idle
/// machine; a loaded one or a slow disk takes longer.
const CREATE_TIMEOUT: Duration = Duration::from_secs(300);

/// How long bhf looks for the new prefix's registry once `wineboot` and the
/// Wine server are done: the server writes it as it exits.
const REGISTRY_GRACE: Duration = Duration::from_secs(10);

/// Held while a prefix is checked or created, so targets that start at the
/// same time create it once. It holds why each prefix bhf could not create
/// failed: a later target in the same run gets that reason at once instead
/// of waiting for Wine again.
static PREFIX_FAILURES: Mutex<BTreeMap<PathBuf, String>> = Mutex::new(BTreeMap::new());

/// Whether `program` is a Wine loader: `wine`, `wine64`, `wine-stable`,
/// `wine64-development` or a path to one.
pub(crate) fn is_wine_program(program: &Path) -> bool {
    let Some(name) = program.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    let name = name.strip_suffix(".exe").unwrap_or(&name);
    let Some(rest) = name.strip_prefix("wine") else {
        return false;
    };
    let rest = rest.strip_prefix("64").unwrap_or(rest);
    match rest.strip_prefix('-') {
        None => rest.is_empty(),
        Some(flavour) => !flavour.is_empty() && flavour.chars().all(|c| c.is_ascii_alphanumeric()),
    }
}

/// Make sure the Wine prefix exists before the first harness runs under
/// `wine`, creating it when it does not. The error names the prefix and what
/// Wine printed; a harness could not run in that prefix either.
pub(crate) fn ensure_prefix(wine: &Path) -> Result<(), String> {
    let Some(prefix) = prefix_dir(std::env::var_os("WINEPREFIX"), std::env::var_os("HOME")) else {
        // No WINEPREFIX and no HOME: Wine reports that itself.
        return Ok(());
    };
    ensure_prefix_at(wine, &prefix, CREATE_TIMEOUT)
}

/// The prefix a Wine started from this process uses: `WINEPREFIX`, else
/// `~/.wine`.
fn prefix_dir(wineprefix: Option<OsString>, home: Option<OsString>) -> Option<PathBuf> {
    match wineprefix.filter(|prefix| !prefix.is_empty()) {
        Some(prefix) => Some(PathBuf::from(prefix)),
        None => home
            .filter(|home| !home.is_empty())
            .map(|home| PathBuf::from(home).join(".wine")),
    }
}

/// Whether Wine has created `prefix`: it writes the machine registry,
/// `system.reg`, there when it does.
fn prefix_created(prefix: &Path) -> bool {
    prefix.join("system.reg").is_file()
}

fn ensure_prefix_at(wine: &Path, prefix: &Path, timeout: Duration) -> Result<(), String> {
    let mut failures = PREFIX_FAILURES
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if prefix_created(prefix) {
        return Ok(());
    }
    if let Some(reason) = failures.get(prefix) {
        return Err(reason.clone());
    }
    create_prefix(wine, prefix, timeout).inspect_err(|reason| {
        failures.insert(prefix.to_path_buf(), reason.clone());
    })
}

/// Create `prefix` with `wine wineboot --init`, within `timeout`.
fn create_prefix(wine: &Path, prefix: &Path, timeout: Duration) -> Result<(), String> {
    bhfeprintln!(
        "bhf: creating the Wine prefix {} for the first run under {} (once; this can take a \
         minute)",
        prefix.display(),
        wine.display()
    );
    let started = Instant::now();
    let deadline = started + timeout;
    let boot = format!("{} wineboot --init", wine.display());
    let mut wineboot = wine_command(wine, prefix);
    wineboot.args(["wineboot", "--init"]);
    let (status, stderr) = run_until(wineboot, deadline).map_err(|error| match error {
        RunError::Spawn(error) => format!(
            "could not run `{boot}` to create the Wine prefix {}: {error}",
            prefix.display()
        ),
        RunError::TimedOut(stderr) => format!(
            "`{boot}` did not finish creating the Wine prefix {} within {}s{}. {}",
            prefix.display(),
            timeout.as_secs(),
            stderr_note(&stderr),
            remedy(prefix)
        ),
    })?;
    if !status.success() {
        return Err(format!(
            "`{boot}` could not create the Wine prefix {}: it {}{}. {}",
            prefix.display(),
            exit_text(status),
            stderr_note(&stderr),
            remedy(prefix)
        ));
    }
    // The programs wineboot started keep the Wine server up for a while, and
    // the server writes the registry as it exits: wait for that, so the
    // first harness starts in a finished prefix with nothing else running.
    if let Some(server) = wineserver_for(wine) {
        let mut wait = wine_command(&server, prefix);
        wait.arg("--wait");
        // A server that does not stop is not the prefix's fault: the
        // registry check below decides.
        let _ = run_until(wait, deadline);
    }
    let registry_deadline = deadline.min(Instant::now() + REGISTRY_GRACE);
    while !prefix_created(prefix) {
        if Instant::now() >= registry_deadline {
            return Err(format!(
                "`{boot}` finished but left no Wine prefix at {} (no system.reg){}. {}",
                prefix.display(),
                stderr_note(&stderr),
                remedy(prefix)
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    bhfeprintln!(
        "bhf: created the Wine prefix {} in {:.1}s",
        prefix.display(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// `program` set up to act on `prefix` quietly. Wine's Mono and Gecko
/// add-ons are left out unless the operator says otherwise: a harness needs
/// neither, and installing them asks on a desktop and stalls the run.
fn wine_command(program: &Path, prefix: &Path) -> Command {
    let mut command = Command::new(program);
    command
        .env("WINEPREFIX", prefix)
        .env("WINEDEBUG", "-all")
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    if std::env::var_os("WINEDLLOVERRIDES").is_none() {
        command.env("WINEDLLOVERRIDES", "mscoree,mshtml=");
    }
    command
}

/// The Wine server that goes with `wine`: `WINESERVER`, the `wineserver`
/// beside it, or the one on `PATH`.
fn wineserver_for(wine: &Path) -> Option<PathBuf> {
    if let Some(server) = std::env::var_os("WINESERVER").filter(|server| !server.is_empty()) {
        return Some(PathBuf::from(server));
    }
    let beside = which::which(wine)
        .ok()
        .and_then(|wine| wine.parent().map(|dir| dir.join("wineserver")))
        .filter(|server| server.is_file());
    beside.or_else(|| which::which("wineserver").ok())
}

enum RunError {
    Spawn(std::io::Error),
    /// Killed at the deadline, with what it had printed.
    TimedOut(String),
}

/// Run `command` to its end or to `deadline`, whichever comes first, killing
/// it (and the processes it started in its group) at the deadline. Its
/// stderr goes to a file, not a pipe: the Wine server and the programs
/// wineboot starts outlive it and would hold a pipe open.
fn run_until(mut command: Command, deadline: Instant) -> Result<(ExitStatus, String), RunError> {
    let mut log = tempfile::tempfile().map_err(RunError::Spawn)?;
    command.stderr(log.try_clone().map_err(RunError::Spawn)?);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(RunError::Spawn)?;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) | Err(_) => break None,
        }
    };
    let status = match status {
        Some(status) => status,
        None => {
            kill_group(&mut child);
            let _ = child.wait();
            return Err(RunError::TimedOut(tail(&mut log)));
        }
    };
    Ok((status, tail(&mut log)))
}

#[cfg(unix)]
fn kill_group(child: &mut std::process::Child) {
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: signalling the process group the child leads; no memory is
        // shared with the call.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let _ = child.kill();
}

#[cfg(not(unix))]
fn kill_group(child: &mut std::process::Child) {
    let _ = child.kill();
}

/// The last few lines of `log`.
fn tail(log: &mut std::fs::File) -> String {
    const KEEP: u64 = 2048;
    let length = log.seek(SeekFrom::End(0)).unwrap_or(0);
    let _ = log.seek(SeekFrom::Start(length.saturating_sub(KEEP)));
    let mut bytes = Vec::new();
    let _ = log.take(KEEP).read_to_end(&mut bytes);
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    lines[lines.len().saturating_sub(5)..].join(" | ")
}

fn stderr_note(stderr: &str) -> String {
    if stderr.is_empty() {
        String::new()
    } else {
        format!(" (it printed: {stderr})")
    }
}

fn exit_text(status: ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("exited with status {code}"),
        None => "was killed by a signal".to_owned(),
    }
}

fn remedy(prefix: &Path) -> String {
    format!(
        "Create it by hand with `WINEPREFIX={} wineboot --init`, or set WINEPREFIX to a \
         working prefix, and run bhf again",
        prefix.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prefix_is_wineprefix_else_dot_wine_in_home() {
        assert_eq!(
            prefix_dir(Some("/w/prefix".into()), Some("/home/u".into())),
            Some(PathBuf::from("/w/prefix"))
        );
        assert_eq!(
            prefix_dir(None, Some("/home/u".into())),
            Some(PathBuf::from("/home/u/.wine"))
        );
        assert_eq!(
            prefix_dir(Some("".into()), Some("/home/u".into())),
            Some(PathBuf::from("/home/u/.wine"))
        );
        assert_eq!(prefix_dir(None, None), None);
    }

    #[test]
    fn wine_loaders_are_told_from_other_runners() {
        for wine in [
            "wine",
            "wine64",
            "/usr/bin/wine",
            "/opt/wine/bin/wine64",
            "wine-stable",
            "wine64-development",
            "WINE.exe",
        ] {
            assert!(is_wine_program(Path::new(wine)), "{wine}");
        }
        for other in [
            "qemu-aarch64",
            "wineserver",
            "winedbg",
            "wine-run.sh",
            "tools/run-wine",
            "",
        ] {
            assert!(!is_wine_program(Path::new(other)), "{other}");
        }
    }

    #[cfg(unix)]
    mod with_a_stand_in_wine {
        use super::super::*;
        use std::os::unix::fs::PermissionsExt as _;

        /// An executable shell script at `dir/name`.
        fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
            let path = dir.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path
        }

        /// A `wine` that logs how it was run and, for `wineboot --init`,
        /// writes the prefix's registry; a `wineserver` beside it that logs
        /// its arguments.
        fn creating_wine(dir: &Path) -> PathBuf {
            let log = dir.join("calls.log");
            script(
                dir,
                "wineserver",
                &format!("echo \"wineserver $*\" >> '{}'", log.display()),
            );
            script(
                dir,
                "wine",
                &format!(
                    "echo \"wine $* WINEDEBUG=$WINEDEBUG WINEPREFIX=$WINEPREFIX \
                     WINEDLLOVERRIDES=$WINEDLLOVERRIDES\" >> '{log}'\n\
                     if [ \"$1 $2\" = 'wineboot --init' ]; then\n\
                     \x20 mkdir -p \"$WINEPREFIX\" && echo 'WINE REGISTRY' > \"$WINEPREFIX/system.reg\"\n\
                     fi",
                    log = log.display()
                ),
            )
        }

        #[test]
        fn an_existing_prefix_is_used_without_running_wine() {
            let dir = tempfile::tempdir().unwrap();
            let wine = creating_wine(dir.path());
            let prefix = dir.path().join("prefix");
            std::fs::create_dir(&prefix).unwrap();
            std::fs::write(prefix.join("system.reg"), "WINE REGISTRY").unwrap();
            ensure_prefix_at(&wine, &prefix, Duration::from_secs(30)).unwrap();
            assert!(
                !dir.path().join("calls.log").exists(),
                "nothing runs for an existing prefix"
            );
        }

        #[test]
        fn a_missing_prefix_is_created_with_wineboot_before_the_first_launch() {
            let dir = tempfile::tempdir().unwrap();
            let wine = creating_wine(dir.path());
            let prefix = dir.path().join("fresh");
            ensure_prefix_at(&wine, &prefix, Duration::from_secs(30)).unwrap();
            assert!(prefix.join("system.reg").is_file());
            let calls = std::fs::read_to_string(dir.path().join("calls.log")).unwrap();
            let calls: Vec<&str> = calls.lines().collect();
            let overrides =
                std::env::var("WINEDLLOVERRIDES").unwrap_or_else(|_| "mscoree,mshtml=".to_owned());
            assert_eq!(
                calls,
                [
                    format!(
                        "wine wineboot --init WINEDEBUG=-all WINEPREFIX={} \
                         WINEDLLOVERRIDES={overrides}",
                        prefix.display()
                    )
                    .as_str(),
                    "wineserver --wait",
                ],
                "wineboot creates it quietly, then bhf waits for the server"
            );
            // Created once: a second check runs nothing.
            std::fs::remove_file(dir.path().join("calls.log")).unwrap();
            ensure_prefix_at(&wine, &prefix, Duration::from_secs(30)).unwrap();
            assert!(!dir.path().join("calls.log").exists());
        }

        #[test]
        fn a_prefix_wine_cannot_create_is_an_error_naming_it() {
            let dir = tempfile::tempdir().unwrap();
            let wine = script(
                dir.path(),
                "wine",
                "echo 'wine: could not load kernel32.dll' >&2\nexit 3",
            );
            let prefix = dir.path().join("broken");
            let error = ensure_prefix_at(&wine, &prefix, Duration::from_secs(30)).unwrap_err();
            assert!(error.contains(&prefix.display().to_string()), "{error}");
            assert!(error.contains("exited with status 3"), "{error}");
            assert!(error.contains("could not load kernel32.dll"), "{error}");
            assert!(error.contains("wineboot --init"), "{error}");
        }

        /// A prefix Wine could not create is not tried again for the next
        /// target of the same run: a stalled wineboot would cost each one
        /// the whole timeout.
        #[test]
        fn a_prefix_wine_could_not_create_is_tried_once() {
            let dir = tempfile::tempdir().unwrap();
            let calls = dir.path().join("calls.log");
            let wine = script(
                dir.path(),
                "wine",
                &format!(
                    "echo \"wine $*\" >> '{}'\necho 'wine: could not load kernel32.dll' >&2\nexit 3",
                    calls.display()
                ),
            );
            let prefix = dir.path().join("broken");
            let first = ensure_prefix_at(&wine, &prefix, Duration::from_secs(30)).unwrap_err();
            let second = ensure_prefix_at(&wine, &prefix, Duration::from_secs(30)).unwrap_err();
            assert_eq!(second, first, "the same reason, straight away");
            assert_eq!(
                std::fs::read_to_string(&calls).unwrap().lines().count(),
                1,
                "wineboot runs once"
            );
        }

        #[test]
        fn a_wineboot_that_leaves_no_registry_is_an_error() {
            let dir = tempfile::tempdir().unwrap();
            let wine = script(dir.path(), "wine", "exit 0");
            let prefix = dir.path().join("empty");
            let error = ensure_prefix_at(&wine, &prefix, Duration::from_secs(1)).unwrap_err();
            assert!(error.contains("no system.reg"), "{error}");
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn a_wineboot_that_never_finishes_is_stopped_at_the_timeout() {
            let dir = tempfile::tempdir().unwrap();
            let pid_file = dir.path().join("pid");
            // A process wineboot started, as Wine's own services are.
            let wine = script(
                dir.path(),
                "wine",
                &format!(
                    "sleep 60 &\necho $! > '{}'\necho 'wine: starting' >&2\nwait",
                    pid_file.display()
                ),
            );
            let prefix = dir.path().join("slow");
            let started = Instant::now();
            let error = ensure_prefix_at(&wine, &prefix, Duration::from_millis(700)).unwrap_err();
            assert!(started.elapsed() < Duration::from_secs(20), "bounded");
            assert!(error.contains("did not finish"), "{error}");
            assert!(error.contains("wine: starting"), "{error}");
            let pid = std::fs::read_to_string(&pid_file).unwrap();
            let gone = || {
                std::fs::read_to_string(format!("/proc/{}/stat", pid.trim()))
                    .map_or(true, |stat| stat.contains(") Z "))
            };
            let until = Instant::now() + Duration::from_secs(5);
            while !gone() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(50));
            }
            assert!(
                gone(),
                "what the stalled wineboot started is killed with it"
            );
        }
    }
}
