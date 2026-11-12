// SPDX-License-Identifier: Apache-2.0

//! `bhf replay --debugger`: re-run a C/C++ finding's testcase under gdb, lldb
//! or (on Windows) cdb in batch mode, stopping at the harness's target
//! function to print its arguments and stack, then continuing to the crash
//! and printing the stack again.
//!
//! The harness runs with the replay's environment (the runtime mode and the
//! env the finding recorded as injected), and a preload library such as the
//! runtrace shim is handed to the harness alone, never to the debugger. The
//! sanitizers are configured so the debugger sees the fault: AddressSanitizer
//! leaves SIGSEGV/SIGBUS/SIGFPE to it (`handle_segv=0`, ...) and aborts after a
//! report (`abort_on_error=1`), UBSan aborts on its first report, and leak
//! detection is off (LeakSanitizer does not run under ptrace).

use serde::Serialize;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// How long one debugger session may run.
const DEBUGGER_TIMEOUT: Duration = Duration::from_secs(120);
/// Most bytes of debugger output kept.
const MAX_TRANSCRIPT: usize = 1024 * 1024;

/// The debugger `--debugger` asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DebuggerChoice {
    /// cdb on Windows when present, else gdb, else lldb.
    Auto,
    Gdb,
    Lldb,
    Cdb,
}

impl DebuggerChoice {
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        match text.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(Self::Auto),
            "gdb" => Ok(Self::Gdb),
            "lldb" => Ok(Self::Lldb),
            "cdb" => Ok(Self::Cdb),
            other => Err(format!(
                "unknown debugger `{other}`: use gdb, lldb or cdb (or no value to pick one)"
            )),
        }
    }
}

/// A debugger found on PATH.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DebuggerKind {
    Gdb,
    Lldb,
    Cdb,
}

impl DebuggerKind {
    fn program(self) -> &'static str {
        match self {
            DebuggerKind::Gdb => "gdb",
            DebuggerKind::Lldb => "lldb",
            DebuggerKind::Cdb => "cdb",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Debugger {
    pub(crate) kind: DebuggerKind,
    pub(crate) exe: PathBuf,
}

/// The debugger to use for `choice`, found on `path` (the `PATH` value), or
/// why there is none.
pub(crate) fn resolve(
    choice: DebuggerChoice,
    path: Option<&std::ffi::OsStr>,
) -> Result<Debugger, String> {
    let order: &[DebuggerKind] = match choice {
        DebuggerChoice::Gdb => &[DebuggerKind::Gdb],
        DebuggerChoice::Lldb => &[DebuggerKind::Lldb],
        DebuggerChoice::Cdb => &[DebuggerKind::Cdb],
        DebuggerChoice::Auto if cfg!(windows) => {
            &[DebuggerKind::Cdb, DebuggerKind::Gdb, DebuggerKind::Lldb]
        }
        DebuggerChoice::Auto => &[DebuggerKind::Gdb, DebuggerKind::Lldb],
    };
    for kind in order {
        if let Some(exe) = on_path(kind.program(), path) {
            return Ok(Debugger { kind: *kind, exe });
        }
    }
    let wanted = order
        .iter()
        .map(|kind| kind.program())
        .collect::<Vec<_>>()
        .join(" or ");
    let install = if cfg!(windows) {
        "install the Debugging Tools for Windows (cdb, part of the Windows SDK) or gdb"
    } else if cfg!(target_os = "macos") {
        "install lldb (xcode-select --install) or gdb"
    } else {
        "install gdb (apt install gdb, dnf install gdb) or lldb"
    };
    Err(format!(
        "--debugger needs {wanted} on PATH, and none was found: {install}, or run the replay \
         without --debugger"
    ))
}

fn on_path(program: &str, path: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    let names: Vec<String> = if cfg!(windows) {
        vec![format!("{program}.exe"), program.to_owned()]
    } else {
        vec![program.to_owned()]
    };
    std::env::split_paths(path?).find_map(|dir| {
        names
            .iter()
            .map(|name| dir.join(name))
            .find(|candidate| candidate.is_file())
    })
}

/// What the session ran and printed.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct DebuggerSession {
    pub(crate) tool: DebuggerKind,
    /// The command line, program first.
    pub(crate) command: Vec<String>,
    /// The function the session broke on, when the harness records one.
    pub(crate) breakpoint: Option<String>,
    /// The debugger's stdout and stderr, bounded.
    pub(crate) transcript: String,
    pub(crate) timed_out: bool,
    /// What qualifies the transcript.
    pub(crate) notes: Vec<String>,
}

/// The arguments (after the program) of a batch session over `harness` on
/// `testcase`: break at `target`, print its arguments and full stack,
/// remove the breakpoint, continue to the crash, print the stack again.
/// `stdin_input`: the harness reads the testcase on stdin (AFL harnesses).
/// `inferior_env` is set for the harness alone (gdb through an `env`
/// exec-wrapper, lldb through `target.env-vars`; cdb has no such setting).
pub(crate) fn command_args(
    kind: DebuggerKind,
    harness: &Path,
    testcase: &Path,
    stdin_input: bool,
    target: Option<&str>,
    inferior_env: &[(String, String)],
) -> Vec<String> {
    let harness = harness.display().to_string();
    let testcase = testcase.display().to_string();
    let mut args: Vec<String> = Vec::new();
    match kind {
        DebuggerKind::Gdb => {
            args.extend(["-q", "-nx", "-batch"].map(str::to_owned));
            let mut ex = |command: String| {
                args.push("-ex".to_owned());
                args.push(command);
            };
            ex("set debuginfod enabled off".to_owned());
            ex("set pagination off".to_owned());
            ex("set confirm off".to_owned());
            ex("set breakpoint pending on".to_owned());
            if !inferior_env.is_empty() {
                // gdb starts the wrapper through the shell, which execs
                // `env`, which execs the harness: neither gdb nor the shell
                // loads the preload library.
                let assignments = inferior_env
                    .iter()
                    .map(|(key, value)| shell_quote(&format!("{key}={value}")))
                    .collect::<Vec<_>>()
                    .join(" ");
                ex(format!("set exec-wrapper env {assignments}"));
            }
            if let Some(target) = target {
                // A template or operator name needs quoting.
                let spec = if target.contains(['<', '(', ' ']) {
                    format!("'{target}'")
                } else {
                    target.to_owned()
                };
                ex(format!("break {spec}"));
            }
            ex(if stdin_input {
                format!("run < {}", gdb_quote(&testcase))
            } else {
                "run".to_owned()
            });
            if target.is_some() {
                ex(
                    "echo \\n--- bhf: stopped (at the target entry, or earlier at a fault) ---\\n"
                        .to_owned(),
                );
                ex("info args".to_owned());
                ex("bt full".to_owned());
                ex("delete".to_owned());
                ex("continue".to_owned());
            }
            ex("echo \\n--- bhf: stopped at the crash ---\\n".to_owned());
            ex("bt full".to_owned());
            args.push("--args".to_owned());
            args.push(harness);
            if !stdin_input {
                args.push(testcase);
            }
        }
        DebuggerKind::Lldb => {
            // In batch mode lldb stops running `-o` commands at the first one
            // that fails and once the harness crashes (a signal or a
            // sanitizer stop of its own); the `-k` commands run after a
            // crash, wherever it happened. A sanitizer report stops at a
            // breakpoint on the sanitizer's own report path instead, before
            // lldb's sanitizer plugin handles it (that handling crashes some
            // lldb releases), and the `-o` commands go on from there. The
            // markers are comments, which lldb echoes and which need no
            // script interpreter.
            const CRASH_MARKER: &str = "# --- bhf: stopped at the crash ---";
            args.extend(["--batch", "--no-lldbinit"].map(str::to_owned));
            let mut once = Vec::new();
            let mut o = |command: String| once.push(command);
            o("settings set auto-confirm true".to_owned());
            if !inferior_env.is_empty() {
                let assignments = inferior_env
                    .iter()
                    .map(|(key, value)| lldb_quote(&format!("{key}={value}")))
                    .collect::<Vec<_>>()
                    .join(" ");
                o(format!("settings set target.env-vars {assignments}"));
            }
            if let Some(target) = target {
                // Breakpoint 1.
                o(format!("breakpoint set --name '{target}'"));
            }
            // AddressSanitizer calls Die() after printing its report; UBSan's
            // handlers run before theirs.
            o("breakpoint set --name __sanitizer::Die".to_owned());
            o("breakpoint set --func-regex '^__ubsan_handle_'".to_owned());
            o(if stdin_input {
                format!("process launch -i {}", lldb_quote(&testcase))
            } else {
                format!("process launch -- {}", lldb_quote(&testcase))
            });
            if target.is_some() {
                o(
                    "# --- bhf: stopped (at the target entry, or earlier at a fault) ---"
                        .to_owned(),
                );
                o("bt all".to_owned());
                o("frame variable --no-locals".to_owned());
                o("breakpoint delete 1".to_owned());
                o("process continue".to_owned());
            }
            o(CRASH_MARKER.to_owned());
            o("bt all".to_owned());
            o("frame variable".to_owned());
            for command in once {
                args.push("-o".to_owned());
                args.push(command);
            }
            for command in [CRASH_MARKER, "bt all", "frame variable"] {
                args.push("-k".to_owned());
                args.push(command.to_owned());
            }
            args.push("--".to_owned());
            args.push(harness);
        }
        DebuggerKind::Cdb => {
            let mut commands = vec![".symopt+0x40".to_owned()];
            if let Some(target) = target {
                commands.push(format!("bu {target}"));
                commands.push("g".to_owned());
                commands.push(
                    ".echo --- bhf: stopped (at the target entry, or earlier at a fault) ---"
                        .to_owned(),
                );
                commands.push("dv /t".to_owned());
                commands.push("kP".to_owned());
                commands.push("bc *".to_owned());
            }
            commands.push("g".to_owned());
            commands.push(".echo --- bhf: stopped at the crash ---".to_owned());
            commands.push("kP".to_owned());
            commands.push("q".to_owned());
            args.extend(["-lines".to_owned(), "-c".to_owned(), commands.join(";")]);
            args.push(harness);
            if !stdin_input {
                args.push(testcase);
            }
        }
    }
    args
}

/// `text` as one POSIX shell word.
fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

fn gdb_quote(path: &str) -> String {
    format!("\"{}\"", path.replace('\\', "\\\\").replace('"', "\\\""))
}

fn lldb_quote(path: &str) -> String {
    format!("'{}'", path.replace('\'', "'\\''"))
}

/// Variables set for the harness alone: a library preloaded into the
/// debugger as well would run inside it.
const INFERIOR_ONLY: &[&str] = &["LD_PRELOAD", "DYLD_INSERT_LIBRARIES"];

/// The environment of a debugger session, by who is given it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionEnv {
    /// Set on the debugger, whose harness inherits it.
    pub(crate) inherited: Vec<(String, String)>,
    /// Set for the harness alone (see [`command_args`]).
    pub(crate) inferior: Vec<(String, String)>,
}

/// The environment of a debugger session over a replay that ran with
/// `replay_env` (in order; a later entry wins): the same variables, the
/// sanitizer options with the signals left to the debugger, an abort after
/// every report and no leak check, and a preload library for the harness
/// alone.
pub(crate) fn session_env(replay_env: &[(String, String)]) -> SessionEnv {
    let mut env = SessionEnv::default();
    for (key, value) in replay_env {
        let extra = match key.as_str() {
            "ASAN_OPTIONS" => {
                ":handle_segv=0:handle_sigbus=0:handle_sigfpe=0:handle_sigill=0:\
                 abort_on_error=1:detect_leaks=0"
            }
            "UBSAN_OPTIONS" => ":halt_on_error=1:abort_on_error=1:print_stacktrace=1",
            _ => "",
        };
        let list = if INFERIOR_ONLY.contains(&key.as_str()) {
            &mut env.inferior
        } else {
            &mut env.inherited
        };
        list.retain(|(other, _)| other != key);
        list.push((key.clone(), format!("{value}{extra}")));
    }
    env
}

/// Run the session over a replay that ran with `replay_env`, and collect its
/// transcript.
pub(crate) fn run(
    debugger: &Debugger,
    harness: &Path,
    testcase: &Path,
    stdin_input: bool,
    target: Option<&str>,
    leak: bool,
    replay_env: &[(String, String)],
) -> DebuggerSession {
    let env = session_env(replay_env);
    let inferior: &[(String, String)] = if debugger.kind == DebuggerKind::Cdb {
        &[]
    } else {
        &env.inferior
    };
    let args = command_args(
        debugger.kind,
        harness,
        testcase,
        stdin_input,
        target,
        inferior,
    );
    let mut command_line = vec![debugger.exe.display().to_string()];
    command_line.extend(args.iter().cloned());
    let mut notes = Vec::new();
    if debugger.kind == DebuggerKind::Cdb && !env.inferior.is_empty() {
        notes.push(format!(
            "cdb starts the harness with its own environment, so the replay's {} is not set \
             for it",
            env.inferior
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if debugger.kind == DebuggerKind::Lldb {
        notes.push(
            "lldb stops a sanitizer report at the sanitizer's report function; for UBSan that \
             is before the report is printed (the replay's own run printed it)"
                .to_owned(),
        );
    }
    if target.is_none() {
        notes.push(
            "the harness's generation metadata names no target function (it was generated by an \
             older bhf), so the session only stops at the crash; regenerate the harness to also \
             stop at the target's entry"
                .to_owned(),
        );
    }
    if leak {
        notes.push(
            "LeakSanitizer does not run under a debugger, so a leak is not reported here; the \
             session shows the run up to its exit"
                .to_owned(),
        );
    }
    notes.push(
        "generated harnesses build with -O1, so some locals print as <optimized out>; the \
         arguments at the target's entry are the reliable values. For every local, rebuild the \
         harness dir with `make -B main CFLAGS='-O0 -g ...'` in a copy"
            .to_owned(),
    );
    // One pipe for stdout and stderr keeps the debugger's output and the
    // sanitizer's report (the harness's stderr) in the order they happened.
    let pipe =
        std::io::pipe().and_then(|(reader, writer)| Ok((reader, writer.try_clone()?, writer)));
    let (reader, out_writer, err_writer) = match pipe {
        Ok(pipe) => pipe,
        Err(error) => {
            notes.push(format!("no pipe for the debugger's output: {error}"));
            return DebuggerSession {
                tool: debugger.kind,
                command: command_line,
                breakpoint: target.map(str::to_owned),
                transcript: String::new(),
                timed_out: false,
                notes,
            };
        }
    };
    let mut command = Command::new(&debugger.exe);
    command
        .args(&args)
        .stdin(Stdio::null())
        .stdout(out_writer)
        .stderr(err_writer);
    for (key, value) in &env.inherited {
        command.env(key, value);
    }
    let session = |transcript: String, timed_out: bool, notes: Vec<String>| DebuggerSession {
        tool: debugger.kind,
        command: command_line.clone(),
        breakpoint: target.map(str::to_owned),
        transcript,
        timed_out,
        notes,
    };
    let spawned = command.spawn();
    // The command holds the pipe's write ends; the reader sees its end of
    // file only once they are closed.
    drop(command);
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            notes.push(format!(
                "{} could not start: {error}",
                debugger.exe.display()
            ));
            return session(String::new(), false, notes);
        }
    };
    let output = drain(reader);
    let deadline = Instant::now() + DEBUGGER_TIMEOUT;
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                timed_out = true;
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => break,
        }
    }
    let transcript = String::from_utf8_lossy(&output.join().unwrap_or_default()).into_owned();
    if timed_out {
        notes.push(format!(
            "the session was still running after {}s and was killed",
            DEBUGGER_TIMEOUT.as_secs()
        ));
    }
    session(transcript, timed_out, notes)
}

fn drain(mut pipe: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut chunk = [0u8; 64 * 1024];
        while let Ok(read) = pipe.read(&mut chunk) {
            if read == 0 {
                break;
            }
            let room = MAX_TRANSCRIPT.saturating_sub(kept.len());
            kept.extend_from_slice(&chunk[..read.min(room)]);
        }
        kept
    })
}

impl DebuggerSession {
    /// The session as text, after the replay summary.
    pub(crate) fn lines(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "--- debugger session ({}{}) ---",
            self.tool.program(),
            self.breakpoint
                .as_deref()
                .map(|target| format!(", breaking at {target}"))
                .unwrap_or_default()
        )];
        lines.push(format!("$ {}", self.command.join(" ")));
        lines.extend(self.transcript.lines().map(str::to_owned));
        for note in &self.notes {
            lines.push(format!("note: {note}"));
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn choices_parse_and_unknown_ones_are_named() {
        assert_eq!(DebuggerChoice::parse("GDB"), Ok(DebuggerChoice::Gdb));
        assert_eq!(DebuggerChoice::parse(""), Ok(DebuggerChoice::Auto));
        assert!(DebuggerChoice::parse("windbg")
            .unwrap_err()
            .contains("gdb, lldb or cdb"));
    }

    #[test]
    fn a_missing_debugger_is_explained() {
        let empty = tempfile::tempdir().unwrap();
        let error = resolve(DebuggerChoice::Gdb, Some(empty.path().as_os_str())).unwrap_err();
        assert!(error.contains("needs gdb on PATH"), "{error}");
        assert!(error.contains("install"), "{error}");
        let error = resolve(DebuggerChoice::Auto, Some(empty.path().as_os_str())).unwrap_err();
        assert!(error.contains("or lldb"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn auto_picks_the_first_debugger_on_path() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lldb"), "#!/bin/sh\n").unwrap();
        let found = resolve(DebuggerChoice::Auto, Some(dir.path().as_os_str())).unwrap();
        assert_eq!(found.kind, DebuggerKind::Lldb);
        std::fs::write(dir.path().join("gdb"), "#!/bin/sh\n").unwrap();
        let found = resolve(DebuggerChoice::Auto, Some(dir.path().as_os_str())).unwrap();
        assert_eq!(found.kind, DebuggerKind::Gdb);
    }

    #[test]
    fn gdb_breaks_at_the_target_prints_args_and_stacks_then_continues() {
        let args = command_args(
            DebuggerKind::Gdb,
            Path::new("/w/main"),
            Path::new("/f/testcase.bin"),
            false,
            Some("widgets::Codec::decode"),
            &[],
        );
        let text = args.join(" | ");
        let order = [
            "set debuginfod enabled off",
            "break widgets::Codec::decode",
            "-ex | run",
            "info args",
            "bt full",
            "delete",
            "continue",
            "stopped at the crash",
            "--args | /w/main | /f/testcase.bin",
        ];
        let mut at = 0;
        for needle in order {
            let found = text[at..]
                .find(needle)
                .unwrap_or_else(|| panic!("{needle:?} not after {at} in {text}"));
            at += found;
        }
        let stdin = command_args(
            DebuggerKind::Gdb,
            Path::new("/w/main_afl"),
            Path::new("/f/a b.bin"),
            true,
            None,
            &[],
        );
        assert!(
            stdin.contains(&"run < \"/f/a b.bin\"".to_owned()),
            "{stdin:?}"
        );
        assert!(!stdin.iter().any(|a| a.starts_with("break ")), "{stdin:?}");
        assert_eq!(stdin.last().map(String::as_str), Some("/w/main_afl"));
        let template = command_args(
            DebuggerKind::Gdb,
            Path::new("/w/main"),
            Path::new("/f/t"),
            false,
            Some("parse<int>"),
            &[],
        );
        assert!(
            template.contains(&"break 'parse<int>'".to_owned()),
            "{template:?}"
        );
    }

    /// lldb's batch mode runs no `-o` command once the harness crashes, so
    /// the crash-site commands are `-k` (on-crash) commands too, and a
    /// sanitizer report stops at a breakpoint on its report path.
    #[test]
    fn lldb_prints_the_crash_site_from_on_crash_commands() {
        let args = command_args(
            DebuggerKind::Lldb,
            Path::new("/w/main"),
            Path::new("/f/t.bin"),
            false,
            Some("read_bits"),
            &[("LD_PRELOAD".to_owned(), "/s/lib shim.so".to_owned())],
        );
        let pairs: Vec<(&str, &str)> = args
            .windows(2)
            .filter(|pair| matches!(pair[0].as_str(), "-o" | "-k"))
            .map(|pair| (pair[0].as_str(), pair[1].as_str()))
            .collect();
        let once: Vec<&str> = pairs
            .iter()
            .filter(|(f, _)| *f == "-o")
            .map(|(_, c)| *c)
            .collect();
        let on_crash: Vec<&str> = pairs
            .iter()
            .filter(|(f, _)| *f == "-k")
            .map(|(_, c)| *c)
            .collect();
        assert_eq!(
            on_crash,
            [
                "# --- bhf: stopped at the crash ---",
                "bt all",
                "frame variable"
            ],
            "{args:?}"
        );
        let launch = once
            .iter()
            .position(|c| *c == "process launch -- '/f/t.bin'")
            .unwrap_or_else(|| panic!("{once:?}"));
        let before = &once[..launch];
        assert!(
            before.contains(&"settings set target.env-vars 'LD_PRELOAD=/s/lib shim.so'"),
            "the preload library goes to the harness only: {once:?}"
        );
        assert_eq!(
            before
                .iter()
                .filter(|c| c.starts_with("breakpoint set"))
                .copied()
                .collect::<Vec<_>>(),
            [
                "breakpoint set --name 'read_bits'",
                "breakpoint set --name __sanitizer::Die",
                "breakpoint set --func-regex '^__ubsan_handle_'",
            ]
        );
        assert_eq!(
            &once[launch + 1..],
            [
                "# --- bhf: stopped (at the target entry, or earlier at a fault) ---",
                "bt all",
                "frame variable --no-locals",
                "breakpoint delete 1",
                "process continue",
                "# --- bhf: stopped at the crash ---",
                "bt all",
                "frame variable",
            ]
        );
        assert!(!args.iter().any(|a| a.starts_with("script")), "{args:?}");
        assert_eq!(&args[args.len() - 2..], ["--", "/w/main"]);
    }

    #[test]
    fn cdb_sessions_do_the_same_steps() {
        let cdb = command_args(
            DebuggerKind::Cdb,
            Path::new("C:/w/main.exe"),
            Path::new("C:/f/t.bin"),
            false,
            Some("read_bits"),
            &[],
        );
        assert_eq!(cdb[0], "-lines");
        assert!(
            cdb[2].starts_with(".symopt+0x40;bu read_bits;g;"),
            "{cdb:?}"
        );
        assert!(cdb[2].ends_with(";g;.echo --- bhf: stopped at the crash ---;kP;q"));
        assert_eq!(&cdb[3..], ["C:/w/main.exe", "C:/f/t.bin"]);
    }

    /// gdb hands a preload library to the harness through an `env`
    /// exec-wrapper, so neither gdb nor its shell loads it.
    #[test]
    fn gdb_preloads_into_the_harness_only() {
        let args = command_args(
            DebuggerKind::Gdb,
            Path::new("/w/main"),
            Path::new("/f/t.bin"),
            false,
            None,
            &[("LD_PRELOAD".to_owned(), "/s/it's.so".to_owned())],
        );
        let wrapper = args
            .iter()
            .position(|a| a.starts_with("set exec-wrapper"))
            .unwrap_or_else(|| panic!("{args:?}"));
        assert_eq!(
            args[wrapper],
            "set exec-wrapper env 'LD_PRELOAD=/s/it'\\''s.so'"
        );
        let run = args.iter().position(|a| a == "run").unwrap();
        assert!(wrapper < run, "{args:?}");
        let plain = command_args(
            DebuggerKind::Gdb,
            Path::new("/w/main"),
            Path::new("/f/t.bin"),
            false,
            None,
            &[],
        );
        assert!(
            !plain.iter().any(|a| a.contains("exec-wrapper")),
            "{plain:?}"
        );
    }

    /// The session runs with the replay's environment: its sanitizer options
    /// with the faults left to the debugger, its runtime mode and injected
    /// variables (a later entry winning), and a preload library apart.
    #[test]
    fn the_session_keeps_the_replay_environment_and_leaves_faults_to_the_debugger() {
        let replay: Vec<(String, String)> = [
            ("ASAN_OPTIONS", "symbolize=1"),
            ("UBSAN_OPTIONS", "print_summary=1"),
            ("LD_PRELOAD", "/s/libbhf_runtrace.so"),
            ("BHF_RUNTRACE_MODE", "rng"),
            ("WIDGET_MODE", "x"),
            ("WIDGET_MODE", "y"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let env = session_env(&replay);
        let value = |key: &str| {
            env.inherited
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
                .unwrap_or_else(|| panic!("{key} in {env:?}"))
        };
        let asan = value("ASAN_OPTIONS");
        assert!(asan.starts_with("symbolize=1:"), "{asan}");
        assert!(asan.ends_with("detect_leaks=0"), "{asan}");
        assert!(asan.contains("handle_segv=0") && asan.contains("abort_on_error=1"));
        let ubsan = value("UBSAN_OPTIONS");
        assert!(ubsan.contains("abort_on_error=1") && ubsan.contains("halt_on_error=1"));
        assert_eq!(value("BHF_RUNTRACE_MODE"), "rng");
        assert_eq!(value("WIDGET_MODE"), "y");
        assert_eq!(
            env.inherited
                .iter()
                .filter(|(k, _)| k == "WIDGET_MODE")
                .count(),
            1
        );
        assert!(
            !env.inherited.iter().any(|(k, _)| k == "LD_PRELOAD"),
            "{env:?}"
        );
        assert_eq!(
            env.inferior,
            [("LD_PRELOAD".to_owned(), "/s/libbhf_runtrace.so".to_owned())]
        );
    }
}
