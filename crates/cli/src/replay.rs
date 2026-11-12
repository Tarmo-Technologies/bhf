// SPDX-License-Identifier: Apache-2.0

use crate::crash_identity;
use crate::finding_arg::resolve_finding_arg;
use crate::protocol_detect::{Detection, HarnessProtocol, ProtocolBasis};
use crate::runner::{engine_for, harness_runner, HarnessEngine, SandboxModeArg};
use replay_min::HarnessRunner;
use serde::Serialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// A short, truthful description of the backend a C/C++ replay actually used, so
/// a reproduced finding records whether it ran under qemu-user and/or a sandbox
/// rather than leaving that implicit (#81).
fn replay_backend(runner: &HarnessRunner) -> String {
    let mut parts = vec![if runner.qemu_prefix().is_some() {
        "qemu-user".to_owned()
    } else {
        "native".to_owned()
    }];
    let sandbox = runner.sandbox_metadata();
    if sandbox.mode != "none" {
        parts.push(format!("sandbox={}", sandbox.mode));
    }
    format!("replay ({})", parts.join(", "))
}

#[derive(Debug, clap::Args)]
pub struct ReplayArgs {
    /// Finding directory, or finding ID under bhf_work/results/findings.
    #[arg(
        value_name = "FINDING_DIR",
        required_unless_present = "finding",
        conflicts_with = "finding"
    )]
    pub finding_dir: Option<PathBuf>,

    /// Finding directory, or finding ID under bhf_work/results/findings.
    #[arg(long, value_name = "ID_OR_DIR")]
    pub finding: Option<PathBuf>,

    /// Harness binary path. Optional: when omitted it is auto-resolved from the
    /// finding's recorded `fixture_path` (relative to the work dir holding the
    /// finding first) or `harness_id` (`<work>/{harnesses,auto,generated_harnesses,build}/<harness_id>/main`).
    /// Pass this to override the auto-resolved path.
    #[arg(long)]
    pub harness: Option<PathBuf>,

    /// qemu-user executable for ELF-Linux cross-target replay.
    #[arg(long, value_name = "QEMU")]
    pub qemu_user: Option<PathBuf>,

    /// Extra argument passed to qemu-user before the harness path.
    #[arg(
        long = "qemu-arg",
        value_name = "ARG",
        allow_hyphen_values = true,
        requires = "qemu_user"
    )]
    pub qemu_args: Vec<String>,

    /// Sandbox wrapper for harness execution.
    #[arg(long, value_enum, default_value_t = SandboxModeArg::Auto)]
    pub sandbox: SandboxModeArg,

    /// Override sandbox wrapper executable.
    #[arg(long, value_name = "PATH", requires = "sandbox")]
    pub sandbox_tool: Option<PathBuf>,

    /// Fail if the requested sandbox tool is unavailable.
    #[arg(long)]
    pub sandbox_strict: bool,

    /// Relocate an on-target transport finding's endpoint to `HOST:PORT` for
    /// replay (the recorded endpoint is often gone/unreachable). Applies to
    /// agent:tcp / gdb transport findings; ignored for host harness findings.
    #[arg(long = "transport-endpoint", value_name = "HOST:PORT")]
    pub transport_endpoint: Option<String>,

    /// Print the result as one `bhf.replay.v1` JSON document on stdout instead
    /// of the MATCH/MISMATCH line and summary, for every kind of finding.
    /// Exit codes are unchanged.
    #[arg(long)]
    pub json: bool,

    /// Also print the harness's own output (the raw sanitizer report, or a
    /// binary target's stderr) after the summary. Session, collector and
    /// transport replays run no local harness, and an Ada harness reports
    /// through its event log, so they have none to print.
    #[arg(long = "show-output")]
    pub show_output: bool,

    /// Also print the value each harness parameter was decoded to: run a
    /// generated C/C++ harness with BHF_TRACE_ARGS=1 and show its BHF_ARG lines
    /// as a table (name, type, the testcase bytes it came from, value or buffer
    /// length, allocation size and a hex preview, and an output's value after
    /// the call). With --json they are the `arguments` array.
    #[arg(long = "show-args")]
    pub show_args: bool,
}

/// How the replay result is printed.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct OutputMode {
    pub(crate) json: bool,
    pub(crate) show_output: bool,
    pub(crate) show_args: bool,
}

/// How long one replayed execution may run before it is killed.
pub(crate) const REPLAY_TIMEOUT: Duration = Duration::from_secs(10);
/// Most bytes of harness stdout / stderr kept from one replay.
const MAX_CAPTURED_OUTPUT: usize = 4 * 1024 * 1024;
/// Crash-stack frames shown in the summary.
const SUMMARY_FRAMES: usize = 6;

pub fn run(args: ReplayArgs) -> i32 {
    let finding_dir = resolve_finding_arg(args.finding_dir, args.finding);
    let output = OutputMode {
        json: args.json,
        show_output: args.show_output,
        show_args: args.show_args,
    };
    // HDF-7: a finding carrying a session artifact replays by re-driving the
    // recorded multi-message session against a freshly reset transport (which
    // re-captures a fresh handle), not by re-running a harness binary.
    if crate::session_fuzz::is_session_finding(&finding_dir) {
        let lane = crate::session_fuzz::replay_session_outcome(&finding_dir);
        return finish_lane(&finding_dir, lane, output);
    }
    // #60: a collector-sourced semantic finding reproduces deterministically from
    // its stored CollectorSession evidence (re-evaluating the oracle registry and
    // surfacing the attributing event + process tree), not from a harness re-run,
    // so it dispatches before any harness resolution.
    if crate::collector_run::is_collector_finding(&finding_dir) {
        let lane = crate::collector_run::replay_collector_outcome(&finding_dir);
        return finish_lane(&finding_dir, lane, output);
    }
    // #80: an on-target transport finding replays by re-driving its recorded
    // input through the SAME transport (rebuilt from its persisted profile,
    // endpoint relocatable), checking the fault identity — never by resolving a
    // host harness, which would not be equivalent assurance.
    if crate::transport_replay::is_transport_finding(&finding_dir) {
        let lane = crate::transport_replay::replay_transport_outcome(
            &finding_dir,
            args.transport_endpoint.as_deref(),
        );
        return finish_lane(&finding_dir, lane, output);
    }
    // The finding already records where its harness was built; resolve it so the
    // user does not have to repeat `--harness`. An explicit `--harness` always wins.
    let harness = match resolve_harness(&finding_dir, args.harness) {
        Ok(harness) => harness,
        Err(error) => return report_error(&output, &finding_dir, &error),
    };
    if crate::binary_fuzz::is_binary_finding(&finding_dir) {
        let lane = crate::binary_fuzz::replay_binary_outcome(&finding_dir, &harness);
        return finish_lane(&finding_dir, lane, output);
    }
    // One protocol detector for fuzz, replay and minimize: the harness's
    // sources are looked up in every harness dir of the work dir that holds
    // the finding, and a binary staged alone is recognised by what is compiled
    // into it.
    let work = corpus::layout::work_dir_for_finding(&finding_dir);
    let work_dirs: Vec<&Path> = work.iter().map(PathBuf::as_path).collect();
    let detection = crate::protocol_detect::detect(&harness, &work_dirs);
    // A harness from a bhf with a different input format still replays its own
    // findings, but the operator needs to know a regenerated one will not.
    if let Some(note) = harness_format_note_for(&harness, &detection) {
        bhfeprintln!("note: {note}");
    }
    let engine = if is_afl_harness(&harness) {
        HarnessEngine::CAfl
    } else {
        engine_for(detection.protocol)
    };
    // Build the runner ONCE, before dispatching by engine, so every replay path
    // — Ada framed, C libFuzzer, C AFL — honors --qemu-user / sandbox. The C
    // paths used to `return` here with a bare Command::new(harness), silently
    // bypassing the requested runner (#81).
    let runner = harness_runner(
        harness,
        args.qemu_user,
        args.qemu_args,
        args.sandbox,
        args.sandbox_tool,
        args.sandbox_strict,
    );
    match engine {
        HarnessEngine::CAfl => replay_c(&finding_dir, &runner, CInput::Stdin, &detection, output),
        HarnessEngine::CLibFuzzer => {
            replay_c(&finding_dir, &runner, CInput::ArgvFile, &detection, output)
        }
        HarnessEngine::AdaStdin => replay_ada(&finding_dir, &runner, &detection, output),
    }
}

fn is_afl_harness(harness: &Path) -> bool {
    matches!(
        harness.file_name().and_then(|n| n.to_str()),
        Some("main_afl" | "main_afl.exe")
    )
}

/// Print an error the way the chosen output asks for, and return exit code 1.
fn report_error(output: &OutputMode, finding_dir: &Path, error: &str) -> i32 {
    if output.json {
        println!(
            "{}",
            json!({
                "schema_version": REPLAY_SCHEMA,
                "verdict": "error",
                "finding": finding_ref(finding_dir),
                "error": error,
            })
        );
    }
    bhfeprintln!("error: {error}");
    1
}

/// `error` and every error it wraps, joined with `: `.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !text.ends_with(&cause_text) {
            text.push_str(": ");
            text.push_str(&cause_text);
        }
        source = cause.source();
    }
    text
}

/// Resolve the harness binary for a finding. An explicit `--harness` always
/// wins. Otherwise read the finding's `finding.json` and resolve its recorded
/// `fixture_path` in the work dir holding the finding first (the path bhf ran
/// it at) or, failing that, from `harness_id` against the standard
/// `<work>/auto/<harness_id>/main` layout — trying a couple of work-root
/// candidates relative to the finding directory — and only then a
/// `fixture_path` that points into another work dir. Errors naming every path
/// tried, and telling the user to pass `--harness`, when nothing resolves.
fn resolve_harness(finding_dir: &Path, explicit: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(harness) = explicit {
        return Ok(harness);
    }
    let finding_path = finding_dir.join("finding.json");
    let raw: Value = std::fs::read(&finding_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| {
            format!(
                "cannot read {} to auto-resolve the harness; pass --harness <path>",
                finding_path.display()
            )
        })?;

    let mut tried: Vec<PathBuf> = Vec::new();

    // 1) `fixture_path` records the harness binary that ran when the finding
    // was observed — the most direct resolution.
    let fixture = raw.get("fixture_path").and_then(|v| v.as_str());
    if let Some(fixture) = fixture {
        for candidate in corpus::finding::fixture_path_candidates(finding_dir, fixture) {
            if candidate.is_file() {
                return Ok(candidate);
            }
            tried.push(candidate);
        }
    }

    // 2) `harness_id` against `<work>/<root>/<harness_id>/<leaf>` for a couple
    // of plausible work roots relative to the finding dir (results layout is
    // `<work>/results/findings/<F-...>/`, recovered via
    // `corpus::layout::work_dir_for_finding`; the finding dir's grandparent and
    // parent are tried too for the legacy and flat layouts).
    if let Some(harness_id) = raw.get("harness_id").and_then(|v| v.as_str()) {
        for work in harness_work_roots(finding_dir) {
            let mut dirs = crate::auto::layout::harness_dir_candidates(&work, harness_id);
            dirs.push(work.join("build").join(harness_id));
            for harness_dir in dirs {
                for leaf in ["main", "main_afl", "main.exe", "main_afl.exe"] {
                    let candidate = harness_dir.join(leaf);
                    if candidate.is_file() {
                        return Ok(candidate);
                    }
                    if !tried.contains(&candidate) {
                        tried.push(candidate);
                    }
                }
            }
        }
    }

    // 3) A `fixture_path` recorded in another work dir (the original of a
    // copy), as recorded, only once this work dir has no harness for it.
    if let Some(candidate) =
        fixture.and_then(|fixture| corpus::finding::fixture_path_fallback(finding_dir, fixture))
    {
        if candidate.is_file() {
            return Ok(candidate);
        }
        tried.push(candidate);
    }

    let looked = if tried.is_empty() {
        "no fixture_path or harness_id recorded in the finding".to_owned()
    } else {
        tried
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    Err(format!(
        "could not auto-resolve the harness binary for finding {}; looked at: {looked}. \
         Pass --harness <path>.",
        finding_dir.display()
    ))
}

/// The harness a finding records ([`resolve_harness`] without an explicit
/// path): its `fixture_path` resolved in the work dir holding the finding
/// (see [`corpus::finding::fixture_path_candidates`]), then its `harness_id`
/// under `harnesses/`, `auto/`, `generated_harnesses/` and `build/`.
pub(crate) fn recorded_harness(finding_dir: &Path) -> Result<PathBuf, String> {
    resolve_harness(finding_dir, None)
}

/// The input-format note for a generated harness binary (see
/// [`crate::generate_harness::stale_harness_format_note`]), read from the
/// metadata next to it.
fn harness_format_note(harness: &Path) -> Option<String> {
    crate::generate_harness::stale_harness_format_note(harness.parent()?)
}

/// [`harness_format_note`] for the harness replay runs: the metadata next to
/// the binary, else next to the driver source `detection` found, so a binary
/// `bhf build` staged alone into `build/<id>/` is checked against the harness
/// dir it was built from.
fn harness_format_note_for(harness: &Path, detection: &Detection) -> Option<String> {
    if harness.parent()?.join("generation-metadata.json").is_file() {
        return harness_format_note(harness);
    }
    match &detection.basis {
        ProtocolBasis::SourceMarker(source) | ProtocolBasis::PlainSource(source) => {
            crate::generate_harness::stale_harness_format_note(source.parent()?)
        }
        _ => None,
    }
}

/// Candidate fuzz-work roots for a finding directory, most-likely first. The
/// results layout nests findings as `<work>/results/findings/<F-...>/`, so the
/// work root comes from [`corpus::layout::work_dir_for_finding`]; the finding
/// dir's grandparent and parent are offered as fallbacks for the legacy and
/// flatter layouts.
fn harness_work_roots(finding_dir: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let mut push = |p: PathBuf| {
        if !roots.contains(&p) {
            roots.push(p);
        }
    };
    if let Some(work) = corpus::layout::work_dir_for_finding(finding_dir) {
        push(work);
    }
    if let Some(grandparent) = finding_dir.parent().and_then(Path::parent) {
        push(grandparent.to_path_buf());
    }
    if let Some(parent) = finding_dir.parent() {
        push(parent.to_path_buf());
    }
    roots
}

/// How a C/C++ harness takes the testcase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CInput {
    /// libFuzzer single-input mode and bhf's driver: `./harness <file>`.
    ArgvFile,
    /// AFL persistent mode: the bytes on stdin.
    Stdin,
}

/// One execution of a C/C++ harness on a testcase.
#[derive(Debug)]
pub(crate) struct CRun {
    pub(crate) status: Option<std::process::ExitStatus>,
    pub(crate) timed_out: bool,
    pub(crate) duration: Duration,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

impl CRun {
    /// The crash this run reported: a sanitizer report, or an undiagnosed
    /// fatal signal shaped the way the fuzz loop records one.
    pub(crate) fn report(&self) -> Option<corpus::SanitizerReport> {
        let stderr = String::from_utf8_lossy(&self.stderr);
        corpus::parse_sanitizer_report(&stderr).or_else(|| {
            let status = self.status.filter(|_| !self.timed_out)?;
            crate::fatal_signal::classify(&status, &stderr)
                .map(|_| crate::fuzz::fatal_signal_report(&status, &stderr))
        })
    }

    fn exit(&self) -> ExitSummary {
        let (code, signal) = exit_parts(self.status);
        ExitSummary::process(
            code,
            signal,
            self.timed_out.then_some(REPLAY_TIMEOUT),
            self.duration,
        )
    }
}

#[cfg(unix)]
fn exit_parts(status: Option<std::process::ExitStatus>) -> (Option<i32>, Option<i32>) {
    use std::os::unix::process::ExitStatusExt;
    status.map_or((None, None), |status| (status.code(), status.signal()))
}

#[cfg(not(unix))]
fn exit_parts(status: Option<std::process::ExitStatus>) -> (Option<i32>, Option<i32>) {
    (status.and_then(|status| status.code()), None)
}

fn signal_name(signal: i32) -> Option<&'static str> {
    Some(match signal {
        4 => "SIGILL",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        _ => return None,
    })
}

/// Whether the finding records a leak, which only reproduces with leak
/// detection on.
pub(crate) fn is_leak_finding(raw: &Value) -> bool {
    let text = |pointer: &str| {
        raw.pointer(pointer)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase()
    };
    text("/rule_id") == "bhf-208"
        || text("/exception/sanitizer") == "lsan"
        || text("/exception/name").contains("memory_leak")
}

/// The environment of a C/C++ replay: the fuzz child's sanitizer options and,
/// for an argv-file harness (the builtin engine's lanes), the runtrace shim
/// (native runs only), the recorded runtime mode and any env the finding
/// recorded as injected (which wins).
fn replay_env(parsed: &Value, runner: &HarnessRunner, input: CInput) -> Vec<(String, String)> {
    let mut env = crate::fuzz::sanitizer_child_env(is_leak_finding(parsed));
    if input == CInput::Stdin {
        return env;
    }

    // Slice C: recover the runtime_mode block the auto loop stamped
    // into this finding. Pre-Slice-C findings have no such block —
    // `pass` falls back to "audit" and `env_injected` to an empty
    // map so replay still runs (just without env injection).
    let runtime_mode = parsed.get("runtime_mode").and_then(|v| v.as_object());
    let pass = runtime_mode
        .and_then(|m| m.get("pass"))
        .and_then(|v| v.as_str())
        .unwrap_or("audit");
    let env_injected: Vec<(String, String)> = runtime_mode
        .and_then(|m| m.get("env_injected"))
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                .collect()
        })
        .unwrap_or_default();

    // The host LD_PRELOAD runtrace shim is a HOST .so, so it is injected only
    // for a NATIVE replay — never forced into a foreign process running under
    // qemu-user (#81).
    if runner.qemu_prefix().is_none() {
        if let Some(shim) = crate::auto::shim_path::locate() {
            env.push((
                "LD_PRELOAD".to_owned(),
                crate::auto::shim_path::ld_preload_value(&shim),
            ));
        }
    }
    env.push(("BHF_RUNTRACE_MODE".to_owned(), pass.to_owned()));
    env.extend(env_injected);
    env
}

/// Run `testcase` through a C/C++ harness the way the fuzz child ran it: via
/// the runner (so --qemu-user / sandbox apply, or a strict sandbox is rejected
/// early), with the finding's recorded environment and the fuzz child's
/// sanitizer options. Output is drained while the harness runs, so a long
/// sanitizer report cannot block it.
pub(crate) fn run_c_testcase(
    raw: &Value,
    runner: &HarnessRunner,
    input: CInput,
    testcase_path: &Path,
    timeout: Duration,
) -> Result<CRun, String> {
    run_c_testcase_with_env(raw, runner, input, testcase_path, timeout, &[])
}

/// [`run_c_testcase`] with `extra_env` set on top of the replay environment.
pub(crate) fn run_c_testcase_with_env(
    raw: &Value,
    runner: &HarnessRunner,
    input: CInput,
    testcase_path: &Path,
    timeout: Duration,
    extra_env: &[(String, String)],
) -> Result<CRun, String> {
    use std::io::Write;
    use std::process::Stdio;

    let harness = runner.harness_path();
    let bytes = match input {
        CInput::Stdin => Some(
            std::fs::read(testcase_path)
                .map_err(|error| format!("read {}: {error}", testcase_path.display()))?,
        ),
        CInput::ArgvFile => None,
    };
    let mut cmd = runner
        .command_wrapped(testcase_path)
        .map_err(|error| format!("replay runner: {}", error_chain(&error)))?;
    if input == CInput::ArgvFile {
        cmd.arg(testcase_path);
    }
    cmd.stdin(if input == CInput::Stdin {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    // Command::env (not std::env::set_var) so the parent env is untouched
    // between replays in one process.
    for (key, value) in replay_env(raw, runner, input)
        .into_iter()
        .chain(extra_env.iter().cloned())
    {
        cmd.env(key, value);
    }
    let started = Instant::now();
    let mut child =
        spawn_harness(&mut cmd).map_err(|error| format!("spawn {}: {error}", harness.display()))?;
    let stdout = child.stdout.take().map(drain);
    let stderr = child.stderr.take().map(drain);
    if let (Some(bytes), Some(mut stdin)) = (bytes, child.stdin.take()) {
        // A harness that exits before reading all of its input closes the pipe;
        // its exit status, not the write, is the result.
        let _ = stdin.write_all(&bytes);
    }
    let deadline = started + timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    timed_out = true;
                    break child.wait().ok();
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("poll {}: {error}", harness.display())),
        }
    };
    let duration = started.elapsed();
    let join = |handle: Option<std::thread::JoinHandle<Vec<u8>>>| {
        handle
            .and_then(|handle| handle.join().ok())
            .unwrap_or_default()
    };
    Ok(CRun {
        status,
        timed_out,
        duration,
        stdout: join(stdout),
        stderr: join(stderr),
    })
}

/// Read a child pipe to its end on a thread, keeping at most
/// [`MAX_CAPTURED_OUTPUT`] bytes.
fn drain(mut pipe: impl std::io::Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut chunk = [0u8; 64 * 1024];
        while let Ok(read) = pipe.read(&mut chunk) {
            if read == 0 {
                break;
            }
            let room = MAX_CAPTURED_OUTPUT.saturating_sub(kept.len());
            kept.extend_from_slice(&chunk[..read.min(room)]);
        }
        kept
    })
}

pub(crate) const REPLAY_SCHEMA: &str = "bhf.replay.v1";

/// The decoded harness arguments `--show-args` reports.
#[derive(Debug, Serialize)]
struct ArgumentsReport {
    /// The traced values, in the order the harness printed them.
    traced: Vec<corpus::decoded_args::TracedArg>,
    /// The parameter whose buffer the replayed memory access hit.
    #[serde(skip_serializing_if = "Option::is_none")]
    accessed_parameter: Option<Value>,
    /// Why nothing was traced.
    #[serde(skip_serializing_if = "Option::is_none")]
    unavailable: Option<String>,
}

impl ArgumentsReport {
    fn unavailable(reason: impl Into<String>) -> Self {
        ArgumentsReport {
            traced: Vec::new(),
            accessed_parameter: None,
            unavailable: Some(reason.into()),
        }
    }

    /// The arguments a replayed harness printed on `stderr`, and the parameter
    /// whose buffer `report`'s memory access hit.
    fn from_run(
        harness: &Path,
        stderr: &[u8],
        report: Option<&corpus::SanitizerReport>,
        input: Option<&[u8]>,
    ) -> Self {
        let mut traced = corpus::decoded_args::parse_arg_trace(&String::from_utf8_lossy(stderr));
        if let Some(input) = input {
            corpus::decoded_args::annotate_length_prefixes(&mut traced, input);
        }
        if traced.is_empty() {
            return Self::unavailable(if crate::fuzz::harness_has_arg_trace(harness) {
                "the harness printed no BHF_ARG lines: it decodes no arguments, or stopped before \
                 decoding them"
            } else {
                "the harness was built without the argument trace; regenerate it with this bhf, \
                 or read the arguments under a debugger (see the C/C++ guide)"
            });
        }
        let accessed_parameter = report
            .and_then(|report| report.access.as_ref())
            .and_then(|access| serde_json::to_value(access).ok())
            .and_then(|access| corpus::decoded_args::accessed_parameter(&access, &traced));
        ArgumentsReport {
            traced,
            accessed_parameter,
            unavailable: None,
        }
    }

    fn lines(&self) -> Vec<String> {
        if let Some(reason) = &self.unavailable {
            return vec![format!("--- no decoded arguments: {reason} ---")];
        }
        let mut lines = vec!["--- decoded arguments (BHF_TRACE_ARGS=1) ---".to_owned()];
        lines.extend(
            corpus::decoded_args::render_table(&self.traced)
                .into_iter()
                .map(|line| format!("  {line}")),
        );
        if let Some(parameter) = &self.accessed_parameter {
            lines.push(accessed_parameter_line(parameter));
        }
        lines
    }
}

/// `the access hit parameter `buffer`'s buffer at offset 1`.
pub(crate) fn accessed_parameter_line(parameter: &Value) -> String {
    let name = parameter.get("name").and_then(Value::as_str).unwrap_or("?");
    let offset = parameter
        .get("offset")
        .map(Value::to_string)
        .unwrap_or_default();
    match parameter.get("basis").and_then(Value::as_str) {
        Some("region_start") => {
            format!("  the access hit parameter `{name}`'s buffer, at offset {offset}")
        }
        Some("region_interior") => format!(
            "  the access hit parameter `{name}`'s buffer, which starts inside the region, at \
             offset {offset}"
        ),
        _ => format!(
            "  the faulting address is {offset} byte(s) past parameter `{name}` (the nearest \
             traced pointer below it)"
        ),
    }
}

#[derive(Debug, Serialize)]
struct FindingRef {
    id: String,
    dir: String,
}

fn finding_ref(finding_dir: &Path) -> FindingRef {
    FindingRef {
        id: finding_dir
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
        dir: finding_dir.display().to_string(),
    }
}

/// How a replayed process ended.
#[derive(Debug, Serialize)]
pub(crate) struct ExitSummary {
    code: Option<i32>,
    signal: Option<i32>,
    timed_out: bool,
    duration_ms: u64,
    text: String,
}

impl ExitSummary {
    /// A process that exited with `code`, was killed by `signal`, or was
    /// killed after running past `timed_out_after`.
    pub(crate) fn process(
        code: Option<i32>,
        signal: Option<i32>,
        timed_out_after: Option<Duration>,
        duration: Duration,
    ) -> Self {
        let seconds = duration.as_secs_f64();
        let text = match (timed_out_after, code, signal) {
            (Some(limit), _, _) => format!("timed out after {} (killed)", seconds_text(limit)),
            (None, _, Some(signal)) => match signal_name(signal) {
                Some(name) => format!("signal {signal} ({name}) after {seconds:.2}s"),
                None => format!("signal {signal} after {seconds:.2}s"),
            },
            (None, Some(code), None) => format!("exit status {code} after {seconds:.2}s"),
            (None, None, None) => format!("exit status unknown after {seconds:.2}s"),
        };
        Self::described(code, signal, timed_out_after.is_some(), duration, text)
    }

    /// An ending the lane describes itself (`text`).
    pub(crate) fn described(
        code: Option<i32>,
        signal: Option<i32>,
        timed_out: bool,
        duration: Duration,
        text: String,
    ) -> Self {
        Self {
            code,
            signal,
            timed_out,
            duration_ms: u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
            text,
        }
    }
}

/// `10s`, or `1.5s` for a limit that is not a whole number of seconds.
fn seconds_text(duration: Duration) -> String {
    if duration.subsec_millis() == 0 {
        format!("{}s", duration.as_secs())
    } else {
        format!("{:.1}s", duration.as_secs_f64())
    }
}

#[derive(Debug, Serialize)]
struct HarnessSummary {
    path: String,
    protocol: String,
    protocol_basis: String,
    sha256: Option<String>,
    recorded_sha256: Option<String>,
    sha256_matches: Option<bool>,
}

#[derive(Debug, Serialize)]
struct TestcaseSummary {
    path: String,
    size: Option<u64>,
    sha256: Option<String>,
}

#[derive(Debug, Serialize)]
struct CrashSummary {
    rule: String,
    kind: String,
    sanitizer: Option<String>,
    message: String,
    sink: Option<String>,
    location: Option<String>,
    frames: Vec<String>,
    access: Option<Value>,
    access_text: Option<String>,
    allocated: Vec<String>,
}

#[derive(Debug, Serialize)]
struct OutputCapture {
    stdout: String,
    stderr: String,
}

/// One labelled line of a replay summary.
#[derive(Debug, Serialize)]
pub(crate) struct Detail {
    pub(crate) label: String,
    pub(crate) value: String,
}

impl Detail {
    pub(crate) fn new(label: &str, value: impl Into<String>) -> Self {
        Self {
            label: label.to_owned(),
            value: value.into(),
        }
    }
}

#[derive(Debug, Serialize)]
struct ReplaySummary {
    schema_version: &'static str,
    verdict: &'static str,
    finding: FindingRef,
    /// The replay lane of a finding that is not replayed through a C/C++ or
    /// Ada harness: `binary`, `session`, `collector` or `transport`.
    #[serde(skip_serializing_if = "Option::is_none")]
    lane: Option<&'static str>,
    recorded_rule: Option<String>,
    recorded_sink: Option<String>,
    compared: Vec<crash_identity::Check>,
    differences: Vec<String>,
    /// What qualifies the verdict (an unsymbolized replay, for one).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    notes: Vec<String>,
    crash: Option<CrashSummary>,
    /// The Ada lane compares event-log signatures instead of reports.
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Value>,
    /// What a non-harness lane reports beyond its verdict.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    details: Vec<Detail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit: Option<ExitSummary>,
    /// The harness or target binary that ran; absent for a lane that runs none.
    #[serde(skip_serializing_if = "Option::is_none")]
    harness: Option<HarnessSummary>,
    testcase: TestcaseSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<OutputCapture>,
    /// `--show-args`: the decoded harness arguments, or why there are none.
    #[serde(skip_serializing_if = "Option::is_none")]
    arguments: Option<ArgumentsReport>,
    /// `bhf replay` printed the status line first; kept for the text view.
    #[serde(skip)]
    status_line: String,
    #[serde(skip)]
    compared_line: String,
}

fn sha256_file(path: &Path) -> Option<String> {
    use sha2::Digest;
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = sha2::Sha256::new();
    let mut chunk = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
    }
    Some(format!("{:x}", hasher.finalize()))
}

fn harness_summary(raw: &Value, harness: &Path, detection: &Detection) -> HarnessSummary {
    binary_summary(
        raw,
        harness,
        detection.protocol.label().to_owned(),
        detection.basis.describe(),
    )
}

/// The binary that ran, its sha256, and whether that is the sha256 the finding
/// recorded (`build.binary.sha256`, or a binary finding's `binary.sha256`).
fn binary_summary(raw: &Value, path: &Path, protocol: String, basis: String) -> HarnessSummary {
    let sha256 = sha256_file(path);
    let recorded_sha256 = ["/build/binary/sha256", "/binary/sha256"]
        .iter()
        .find_map(|pointer| raw.pointer(pointer).and_then(Value::as_str))
        .map(str::to_owned);
    let sha256_matches = sha256
        .as_deref()
        .zip(recorded_sha256.as_deref())
        .map(|(a, b)| a.eq_ignore_ascii_case(b));
    HarnessSummary {
        path: path.display().to_string(),
        protocol,
        protocol_basis: basis,
        sha256,
        recorded_sha256,
        sha256_matches,
    }
}

fn testcase_summary(path: &Path) -> TestcaseSummary {
    TestcaseSummary {
        path: path.display().to_string(),
        size: std::fs::metadata(path).ok().map(|m| m.len()),
        sha256: sha256_file(path),
    }
}

fn frame_line(index: usize, frame: &corpus::sanitizer::StackFrame) -> String {
    let location = match (&frame.file, frame.line) {
        (Some(file), Some(line)) => format!(" {file}:{line}"),
        (Some(file), None) => format!(" {file}"),
        _ => String::new(),
    };
    format!("#{index} {}{location}", frame.function)
}

fn access_text(access: &corpus::sanitizer::MemoryAccess) -> String {
    let direction = match access.direction {
        corpus::sanitizer::AccessDirection::Read => "READ",
        corpus::sanitizer::AccessDirection::Write => "WRITE",
        corpus::sanitizer::AccessDirection::Unknown => "access",
    };
    let mut text = direction.to_owned();
    if let Some(size) = access.size {
        text.push_str(&format!(" of size {size}"));
    }
    if let Some(address) = &access.address {
        text.push_str(&format!(" at {address}"));
    }
    if let Some(hint) = &access.address_hint {
        text.push_str(&format!(" ({hint})"));
    }
    if let Some(region) = &access.region {
        let mut parts = Vec::new();
        if let (Some(relation), Some(distance)) = (&region.relation, region.distance) {
            parts.push(format!("{distance} bytes {relation}"));
        }
        let object = match (&region.variable, region.size) {
            (Some(variable), Some(size)) => format!("{} '{variable}' of {size} bytes", region.kind),
            (Some(variable), None) => format!("{} '{variable}'", region.kind),
            (None, Some(size)) => format!("a {size}-byte {} region", region.kind),
            (None, None) => format!("a {} region", region.kind),
        };
        parts.push(object);
        if let Some(offset) = region.offset {
            parts.push(format!("(offset {offset})"));
        }
        text.push_str(&format!("; {}", parts.join(" ")));
    }
    text
}

fn crash_summary(report: &corpus::SanitizerReport) -> CrashSummary {
    let access = report.access.as_deref();
    CrashSummary {
        rule: report.rule_id.to_owned(),
        kind: report.kind.clone(),
        sanitizer: report.sanitizer.map(|s| s.as_str().to_owned()),
        message: report.message.clone(),
        sink: crash_identity::replayed_sink(report),
        location: report.site(),
        frames: report
            .stack
            .iter()
            .take(SUMMARY_FRAMES)
            .enumerate()
            .map(|(index, frame)| frame_line(index, frame))
            .collect(),
        access: access.and_then(|access| serde_json::to_value(access).ok()),
        access_text: access.map(access_text),
        allocated: access
            .map(|access| {
                access
                    .alloc_stack
                    .iter()
                    .take(3)
                    .enumerate()
                    .map(|(index, frame)| frame_line(index, frame))
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// Render the human summary: the status line, then one labelled line each.
fn render_text(summary: &ReplaySummary) -> Vec<String> {
    let mut lines = vec![summary.status_line.clone()];
    let mut push = |label: &str, value: String| {
        lines.push(format!("  {label:<10} {value}"));
    };
    push(
        "finding",
        format!("{} ({})", summary.finding.id, summary.finding.dir),
    );
    if !summary.compared_line.is_empty() {
        push("compared", summary.compared_line.clone());
    }
    for difference in &summary.differences {
        push("differs", difference.clone());
    }
    for note in &summary.notes {
        push("note", note.clone());
    }
    match &summary.crash {
        Some(crash) => {
            let sanitizer = crash
                .sanitizer
                .as_deref()
                .map(|s| format!(" ({s})"))
                .unwrap_or_default();
            push(
                "crash",
                format!(
                    "{} {}{sanitizer}: {}",
                    crash.rule, crash.kind, crash.message
                ),
            );
            if let Some(sink) = &crash.sink {
                push("sink", sink.clone());
            }
            if let Some(location) = &crash.location {
                push("reported", location.clone());
            }
            for (index, frame) in crash.frames.iter().enumerate() {
                push(if index == 0 { "frames" } else { "" }, frame.clone());
            }
            if let Some(access) = &crash.access_text {
                push("access", access.clone());
            }
            for (index, frame) in crash.allocated.iter().enumerate() {
                push(if index == 0 { "allocated" } else { "" }, frame.clone());
            }
        }
        None if summary.signature.is_none() && summary.lane.is_none() => {
            push("crash", "none reported".to_owned());
        }
        None => {}
    }
    if let Some(signature) = &summary.signature {
        push("signature", signature_text(signature));
    }
    for detail in &summary.details {
        push(&detail.label, detail.value.clone());
    }
    if let Some(exit) = &summary.exit {
        push("exit", exit.text.clone());
    }
    if let Some(harness) = &summary.harness {
        let build = match (harness.sha256_matches, &harness.recorded_sha256) {
            (Some(true), _) => "; sha256 matches the recorded build".to_owned(),
            (Some(false), Some(recorded)) => format!(
                "; WARNING: sha256 differs from the recorded build ({}), so this is not the \
                 binary the finding was recorded with",
                short_hash(recorded)
            ),
            _ => String::new(),
        };
        push(
            if summary.lane.is_some() {
                "binary"
            } else {
                "harness"
            },
            format!(
                "{} ({}: {}){build}",
                harness.path, harness.protocol, harness.protocol_basis
            ),
        );
    }
    let testcase = &summary.testcase;
    push(
        "testcase",
        format!(
            "{}, {} bytes, sha256 {}",
            testcase.path,
            testcase
                .size
                .map_or_else(|| "?".to_owned(), |size| size.to_string()),
            testcase.sha256.as_deref().map_or("?", short_hash)
        ),
    );
    lines
}

fn signature_text(signature: &Value) -> String {
    let field = |key: &str| {
        signature
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or("<none>")
            .to_owned()
    };
    format!(
        "recorded {} replayed {}",
        field("recorded"),
        field("replayed")
    )
}

/// The first 16 characters of a hash. The value can come from a hand-edited
/// finding.json, so it is cut by character, never inside one.
fn short_hash(hash: &str) -> &str {
    let end = hash
        .char_indices()
        .nth(16)
        .map_or(hash.len(), |(index, _)| index);
    &hash[..end]
}

/// Print a summary: JSON on stdout, or the status line and summary (stdout for
/// a MATCH, stderr for a MISMATCH, as the status line always was), then the
/// harness output when asked for.
/// `captured` is the harness's (stdout, stderr), or why there is none.
fn emit(summary: &ReplaySummary, output: OutputMode, captured: Result<(&[u8], &[u8]), &str>) {
    if output.json {
        match serde_json::to_string_pretty(summary) {
            Ok(text) => println!("{text}"),
            Err(error) => bhfeprintln!("error: serialize replay result: {error}"),
        }
        return;
    }
    let mut lines = render_text(summary);
    if let Some(arguments) = &summary.arguments {
        lines.extend(arguments.lines());
    }
    for line in &lines {
        if summary.verdict == "match" {
            println!("{line}");
        } else {
            bhfeprintln!("{line}");
        }
    }
    if output.show_output {
        match captured {
            Ok((stdout, stderr)) => print_harness_output(stdout, stderr),
            Err(reason) => bhfeprintln!("--- no harness output: {reason} ---"),
        }
    }
}

fn print_harness_output(stdout: &[u8], stderr: &[u8]) {
    for (name, bytes) in [("stderr", stderr), ("stdout", stdout)] {
        if bytes.is_empty() {
            continue;
        }
        bhfeprintln!("--- harness {name} ---");
        let text = String::from_utf8_lossy(bytes);
        bhfeprint!("{text}");
        if !text.ends_with('\n') {
            bhfeprintln!();
        }
    }
}

fn read_finding(finding_dir: &Path) -> Result<Value, String> {
    let path = finding_dir.join("finding.json");
    std::fs::read(&path)
        .map_err(|error| format!("read {}: {error}", path.display()))
        .and_then(|bytes| {
            serde_json::from_slice(&bytes)
                .map_err(|error| format!("read {}: {error}", path.display()))
        })
}

/// After a reproduction is recorded in `finding.json`, rebuild results/ when
/// the finding lives in a work dir with a results index, so findings.json's
/// evidence hashes and the attestation describe the files on disk.
fn refresh_results(finding_dir: &Path) {
    let Some(work) = corpus::layout::results_work_dir_for_finding(finding_dir) else {
        return;
    };
    if !corpus::layout::results_dir(&work)
        .join("findings.json")
        .is_file()
    {
        return;
    }
    if let Err(error) = results::rebuild(&work, &results::RebuildOptions::default()) {
        bhfeprintln!(
            "warning: results index not rebuilt after the replay: {error}; run 'bhf report' to \
             refresh it"
        );
    }
}

/// Record a full reproduction: stamp `last_seen` and keep results/ current.
fn record_reproduction(finding_dir: &Path, runner: &HarnessRunner) {
    // A read-only evidence tree must not fail the replay.
    if corpus::finding::touch_last_seen(finding_dir, &replay_backend(runner)).is_ok() {
        refresh_results(finding_dir);
    }
}

/// Printed when a replayed report has no frame naming a function and no
/// source position: the crash class still matched, but not where it happened.
pub(crate) const UNSYMBOLIZED_NOTE: &str =
    "the replayed report names no function or source position, so where it crashed was not \
     compared; the replay looks unsymbolized: put llvm-symbolizer on PATH or set \
     ASAN_SYMBOLIZER_PATH";

/// What a replay lane that does not run a C/C++ or Ada harness found: session,
/// collector, transport and binary findings. [`finish_lane`] prints it the way
/// it prints a harness replay, records a match and keeps results/ current.
#[derive(Debug, Default)]
pub(crate) struct LaneReplay {
    /// `binary`, `session`, `collector` or `transport`.
    pub(crate) lane: &'static str,
    pub(crate) matched: bool,
    /// `MATCH`, or the lane's `MISMATCH ...` line.
    pub(crate) status_line: String,
    /// What was compared.
    pub(crate) compared: String,
    /// Why it did not match, one line each.
    pub(crate) differences: Vec<String>,
    /// Further labelled summary lines.
    pub(crate) details: Vec<Detail>,
    /// How the replayed process ended, when the lane ran one.
    pub(crate) exit: Option<ExitSummary>,
    /// The process's (stdout, stderr), when the lane ran one and kept them.
    pub(crate) output: Option<(Vec<u8>, Vec<u8>)>,
    /// The target binary the lane ran, with its input mode.
    pub(crate) binary: Option<(PathBuf, String)>,
    /// The `history` command a match is recorded under.
    pub(crate) history: &'static str,
}

/// Print a lane's result (a summary, or `--json`), stamp `last_seen` on a
/// match and rebuild results/ so its hashes and attestation stay current.
/// Exit codes: 0 = MATCH, 3 = MISMATCH, 1 = error.
pub(crate) fn finish_lane(
    finding_dir: &Path,
    lane: Result<LaneReplay, String>,
    output: OutputMode,
) -> i32 {
    let lane = match lane {
        Ok(lane) => lane,
        Err(error) => return report_error(&output, finding_dir, &error),
    };
    if lane.matched && corpus::finding::touch_last_seen(finding_dir, lane.history).is_ok() {
        refresh_results(finding_dir);
    }
    let raw = read_finding(finding_dir).unwrap_or(Value::Null);
    // A sanitized binary target prints a sanitizer report.
    let report = lane
        .output
        .as_ref()
        .and_then(|(_, stderr)| corpus::parse_sanitizer_report(&String::from_utf8_lossy(stderr)));
    let summary = ReplaySummary {
        schema_version: REPLAY_SCHEMA,
        verdict: if lane.matched { "match" } else { "mismatch" },
        finding: finding_ref(finding_dir),
        lane: Some(lane.lane),
        recorded_rule: raw
            .get("rule_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        recorded_sink: crash_identity::recorded_sink(&raw),
        compared: Vec::new(),
        compared_line: lane.compared,
        differences: lane.differences,
        notes: Vec::new(),
        crash: report.as_ref().map(crash_summary),
        signature: None,
        details: lane.details,
        exit: lane.exit,
        harness: lane.binary.as_ref().map(|(path, mode)| {
            binary_summary(
                &raw,
                path,
                format!("binary, {mode}"),
                "the input mode the finding recorded".to_owned(),
            )
        }),
        testcase: testcase_summary(&finding_dir.join("testcase.bin")),
        output: lane
            .output
            .as_ref()
            .filter(|_| output.show_output)
            .map(|(stdout, stderr)| OutputCapture {
                stdout: String::from_utf8_lossy(stdout).into_owned(),
                stderr: String::from_utf8_lossy(stderr).into_owned(),
            }),
        arguments: output.show_args.then(|| {
            ArgumentsReport::unavailable(format!(
                "a {} replay runs no generated C/C++ harness",
                lane.lane
            ))
        }),
        status_line: lane.status_line,
    };
    let captured = match &lane.output {
        Some((stdout, stderr)) => Ok((stdout.as_slice(), stderr.as_slice())),
        None if lane.binary.is_some() => Err("the target's output was not kept"),
        None => Err("this replay runs no local harness"),
    };
    emit(&summary, output, captured);
    if lane.matched {
        0
    } else {
        3
    }
}

/// Reproduce a C/C++ finding: run the recorded testcase (argv[1] for
/// libFuzzer and bhf driver harnesses, stdin for AFL) and compare the crash it
/// reports with the finding's rule, kind and sink (or reported site). Exit
/// codes: 0 = MATCH, 3 = MISMATCH, 1 = error.
pub(crate) fn replay_c(
    finding_dir: &Path,
    runner: &HarnessRunner,
    input: CInput,
    detection: &Detection,
    output: OutputMode,
) -> i32 {
    let raw = match read_finding(finding_dir) {
        Ok(raw) => raw,
        Err(error) => return report_error(&output, finding_dir, &error),
    };
    let Some(recorded_rule) = raw
        .get("rule_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        let error = format!(
            "finding {} has no rule_id; cannot replay a C/C++ crash without a baseline",
            finding_dir.join("finding.json").display()
        );
        return report_error(&output, finding_dir, &error);
    };
    let testcase_path = finding_dir.join("testcase.bin");
    let trace_env: Vec<(String, String)> = if output.show_args {
        vec![(
            corpus::decoded_args::TRACE_ARGS_ENV.to_owned(),
            "1".to_owned(),
        )]
    } else {
        Vec::new()
    };
    let run = match run_c_testcase_with_env(
        &raw,
        runner,
        input,
        &testcase_path,
        REPLAY_TIMEOUT,
        &trace_env,
    ) {
        Ok(run) => run,
        Err(error) => return report_error(&output, finding_dir, &error),
    };
    let report = run.report();
    let arguments = output.show_args.then(|| {
        let input = std::fs::read(&testcase_path).ok();
        ArgumentsReport::from_run(
            runner.harness_path(),
            &run.stderr,
            report.as_ref(),
            input.as_deref(),
        )
    });
    let comparison = report
        .as_ref()
        .map(|report| crash_identity::compare(&raw, report))
        .unwrap_or_default();
    let reproduced = report.is_some() && comparison.matches();
    let actual = match (&report, run.timed_out) {
        (Some(report), _) => report.rule_id.to_owned(),
        (None, true) => "<timeout>".to_owned(),
        (None, false) => "<none>".to_owned(),
    };
    let status_line = if reproduced {
        "MATCH".to_owned()
    } else if report.is_some() {
        format!(
            "MISMATCH recorded={recorded_rule} actual={actual} differs={}",
            comparison.differing_fields()
        )
    } else {
        format!("MISMATCH recorded={recorded_rule} actual={actual}")
    };
    let mut differences = comparison.difference_lines();
    if report.is_none() {
        differences.push(if run.timed_out {
            format!(
                "no crash: the harness was still running after {}s and was killed",
                REPLAY_TIMEOUT.as_secs()
            )
        } else {
            format!("no crash: {}", run.exit().text)
        });
    }
    let mut notes = Vec::new();
    if report.is_some() && comparison.location_not_compared() {
        notes.push(UNSYMBOLIZED_NOTE.to_owned());
    }
    if reproduced {
        record_reproduction(finding_dir, runner);
    }
    let summary = ReplaySummary {
        schema_version: REPLAY_SCHEMA,
        verdict: if reproduced { "match" } else { "mismatch" },
        finding: finding_ref(finding_dir),
        lane: None,
        recorded_rule: Some(recorded_rule),
        recorded_sink: crash_identity::recorded_sink(&raw),
        compared_line: comparison.compared_line(),
        compared: comparison.checks.clone(),
        differences,
        notes,
        crash: report.as_ref().map(crash_summary),
        signature: None,
        details: Vec::new(),
        exit: Some(run.exit()),
        harness: Some(harness_summary(&raw, runner.harness_path(), detection)),
        testcase: testcase_summary(&testcase_path),
        output: output.show_output.then(|| OutputCapture {
            stdout: String::from_utf8_lossy(&run.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&run.stderr).into_owned(),
        }),
        arguments,
        status_line,
    };
    emit(&summary, output, Ok((&run.stdout, &run.stderr)));
    if reproduced {
        0
    } else {
        3
    }
}

/// Reproduce a libFuzzer-protocol C/C++ finding with default output.
#[cfg(test)]
fn replay_c_libfuzzer(finding_dir: &Path, runner: &HarnessRunner) -> i32 {
    let detection = Detection {
        protocol: HarnessProtocol::LibFuzzerSingleInput,
        basis: crate::protocol_detect::ProtocolBasis::Default,
    };
    replay_c(
        finding_dir,
        runner,
        CInput::ArgvFile,
        &detection,
        OutputMode::default(),
    )
}

/// Reproduce an Ada (event-log) finding by its handler signature.
fn replay_ada(
    finding_dir: &Path,
    runner: &HarnessRunner,
    detection: &Detection,
    output: OutputMode,
) -> i32 {
    let raw = read_finding(finding_dir).unwrap_or(Value::Null);
    let started = Instant::now();
    let replayed = replay_min::replay_with_runner(finding_dir, runner);
    // replay_min returns a result only for a harness that exited 0 (any other
    // exit is an error), so a result's exit status is 0; the time covers the
    // run and reading back its event log.
    let exit = ExitSummary::process(Some(0), None, None, started.elapsed());
    let (verdict, status_line, signature, differences) = match replayed {
        Ok(replay_min::ReplayResult::Match) => {
            let recorded = raw
                .get("signature")
                .and_then(Value::as_str)
                .map(str::to_owned);
            record_reproduction(finding_dir, runner);
            (
                "match",
                "MATCH".to_owned(),
                json!({"recorded": recorded, "replayed": recorded}),
                Vec::new(),
            )
        }
        Ok(replay_min::ReplayResult::Mismatch { recorded, actual }) => {
            let actual = actual
                .map(|signature| signature.hex())
                .unwrap_or_else(|| "<none>".to_owned());
            (
                "mismatch",
                format!("MISMATCH recorded={} actual={actual}", recorded.hex()),
                json!({"recorded": recorded.hex(), "replayed": actual}),
                vec![format!(
                    "signature: recorded {}, replayed {actual}",
                    recorded.hex()
                )],
            )
        }
        Err(error) => {
            let mut message = error_chain(&error);
            if detection.protocol == HarnessProtocol::StdinEventLog {
                message.push_str(&format!(
                    ". The harness was run as an Ada stdin harness ({}); if it is a C/C++ \
                         harness, pass the binary next to its main.c/main.cpp with --harness, or \
                         rebuild it with this bhf",
                    detection.basis.describe()
                ));
            }
            return report_error(&output, finding_dir, &message);
        }
    };
    let testcase_path = finding_dir.join("testcase.bin");
    let summary = ReplaySummary {
        schema_version: REPLAY_SCHEMA,
        verdict,
        finding: finding_ref(finding_dir),
        recorded_rule: raw
            .get("rule_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        lane: None,
        recorded_sink: crash_identity::recorded_sink(&raw),
        compared: Vec::new(),
        compared_line: "event-log signature".to_owned(),
        differences,
        notes: Vec::new(),
        crash: None,
        signature: Some(signature),
        details: Vec::new(),
        exit: Some(exit),
        harness: Some(harness_summary(&raw, runner.harness_path(), detection)),
        testcase: testcase_summary(&testcase_path),
        output: None,
        arguments: output
            .show_args
            .then(|| ArgumentsReport::unavailable("an Ada harness has no argument trace")),
        status_line,
    };
    emit(
        &summary,
        output,
        Err("an Ada harness reports through its event log, which replay compares"),
    );
    if verdict == "match" {
        0
    } else {
        3
    }
}

/// Spawn a freshly-written harness, retrying the two transient failures that make
/// an `exec` of a just-created executable fail.
///
/// `ETXTBSY` is the real one: the kernel refuses to exec a file still open for
/// writing anywhere, so building (or copying) a harness and immediately replaying
/// it races the writer's descriptor being closed. It is load- and
/// filesystem-dependent, which is why it surfaced as an occasional CI failure and
/// never locally — `replay` exiting 1 with a bare "spawn ...: Text file busy",
/// which reads like a broken harness rather than a race. `EAGAIN` covers a
/// transient fork failure when the box is briefly out of process slots, which a
/// loaded sweep machine does hit.
///
/// Both mean "try again in a moment", not "this cannot run", so both are retried.
fn spawn_harness(command: &mut std::process::Command) -> std::io::Result<std::process::Child> {
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(25);
    const RETRIES: usize = 40; // ~1s total, far longer than either window lasts
    for _ in 0..RETRIES {
        match command.spawn() {
            Ok(child) => return Ok(child),
            Err(error) => {
                if !transient_spawn_failure(&error) {
                    return Err(error);
                }
                std::thread::sleep(RETRY_DELAY);
            }
        }
    }
    command.spawn()
}

/// Whether a spawn failure is one of the two "try again in a moment" kinds.
///
/// Matched through `ErrorKind` rather than raw errno so this compiles on every
/// target — `libc` is not available on the MSVC build, which is how the first
/// attempt at this broke the Windows job.
fn transient_spawn_failure(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ExecutableFileBusy | std::io::ErrorKind::WouldBlock
    )
}

#[cfg(all(test, unix))]
mod silent_abort_tests {
    use super::replay_c_libfuzzer;
    use replay_min::HarnessRunner;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn libfuzzer_replay_matches_silent_abort_finding() {
        let root = tempdir().expect("tempdir");
        let finding = root.path().join("finding");
        fs::create_dir(&finding).expect("finding dir");
        fs::write(finding.join("finding.json"), r#"{"rule_id":"BHF-210"}"#).expect("finding");
        fs::write(finding.join("testcase.bin"), b"crash").expect("testcase");

        let harness = root.path().join("abort.sh");
        fs::write(&harness, "#!/bin/sh\nkill -ABRT $$\n").expect("harness");
        let mut permissions = fs::metadata(&harness).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&harness, permissions).expect("chmod");

        assert_eq!(
            replay_c_libfuzzer(&finding, &HarnessRunner::direct(harness.clone())),
            0
        );
    }

    #[test]
    fn libfuzzer_replay_rejects_diagnosed_abort() {
        let root = tempdir().expect("tempdir");
        let finding = root.path().join("finding");
        fs::create_dir(&finding).expect("finding dir");
        fs::write(finding.join("finding.json"), r#"{"rule_id":"BHF-210"}"#).expect("finding");
        fs::write(finding.join("testcase.bin"), b"reject").expect("testcase");

        let harness = root.path().join("assert.sh");
        fs::write(
            &harness,
            "#!/bin/sh\necho 'Assertion value failed.' >&2\nkill -ABRT $$\n",
        )
        .expect("harness");
        let mut permissions = fs::metadata(&harness).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&harness, permissions).expect("chmod");

        assert_eq!(
            replay_c_libfuzzer(&finding, &HarnessRunner::direct(harness.clone())),
            3
        );
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_accessed_parameter_line_says_how_the_buffer_was_matched() {
        let line = |basis: &str| {
            super::accessed_parameter_line(
                &serde_json::json!({"name": "buf", "offset": 5, "basis": basis}),
            )
        };
        assert_eq!(
            line("region_start"),
            "  the access hit parameter `buf`'s buffer, at offset 5"
        );
        assert_eq!(
            line("region_interior"),
            "  the access hit parameter `buf`'s buffer, which starts inside the region, at offset 5"
        );
        assert!(line("nearest_pointer").contains("5 byte(s) past parameter `buf`"));
    }

    #[test]
    fn harness_roots_start_at_the_work_dir_for_results_layout() {
        let roots = super::harness_work_roots(std::path::Path::new("/w/results/findings/F-1"));
        assert_eq!(roots[0], std::path::PathBuf::from("/w"));
    }

    #[test]
    fn replay_reports_ubsan_stacks_and_check_names_like_the_fuzz_child() {
        let env = crate::fuzz::sanitizer_child_env(false);
        let options = &env.iter().find(|(k, _)| k == "UBSAN_OPTIONS").unwrap().1;
        assert!(options.contains("print_stacktrace=1"), "{options}");
        assert!(options.contains("report_error_type=1"), "{options}");
    }

    #[test]
    fn harness_roots_handle_legacy_depth() {
        let roots = super::harness_work_roots(std::path::Path::new("/w/findings/F-1"));
        assert_eq!(roots[0], std::path::PathBuf::from("/w"));
    }

    #[test]
    fn harness_roots_dedupe_overlapping_candidates() {
        // For the legacy depth, work_dir_for_finding and the grandparent both
        // yield /w; it must appear once, followed by the finding's parent.
        let roots = super::harness_work_roots(std::path::Path::new("/w/findings/F-1"));
        assert_eq!(
            roots,
            vec![
                std::path::PathBuf::from("/w"),
                std::path::PathBuf::from("/w/findings"),
            ]
        );
    }

    /// Replaying against a harness built with an older input format says so,
    /// read from the metadata beside the harness binary.
    #[test]
    fn replay_notes_a_harness_of_another_input_format() {
        let dir = tempfile::tempdir().unwrap();
        let harness = dir.path().join("main");
        std::fs::write(&harness, b"").unwrap();
        assert!(super::harness_format_note(&harness).is_none());
        std::fs::write(
            dir.path().join("generation-metadata.json"),
            r#"{"schema_version":1,"language":"cpp"}"#,
        )
        .unwrap();
        let note = super::harness_format_note(&harness).expect("format 1 is reported");
        assert!(note.contains("input format 1"), "{note}");
        std::fs::write(
            dir.path().join("generation-metadata.json"),
            format!(
                r#"{{"schema_version":1,"harness_format_version":{}}}"#,
                harness_gen::HARNESS_FORMAT_VERSION
            ),
        )
        .unwrap();
        assert!(super::harness_format_note(&harness).is_none());
    }

    /// A binary `bhf build` staged alone into `build/<id>/` has no metadata
    /// beside it; the note is read from the harness dir whose driver source
    /// the protocol detector found.
    #[test]
    fn replay_notes_the_input_format_of_a_staged_harness() {
        let work = tempfile::tempdir().unwrap();
        let source_dir = work.path().join("harnesses/H-X1");
        let staged_dir = work.path().join("build/H-X1");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::create_dir_all(&staged_dir).unwrap();
        std::fs::write(source_dir.join("main.cpp"), "/* BHF_FRAMED */\n").unwrap();
        std::fs::write(
            source_dir.join("generation-metadata.json"),
            r#"{"schema_version":1,"language":"cpp"}"#,
        )
        .unwrap();
        let harness = staged_dir.join("main");
        std::fs::write(&harness, b"").unwrap();
        let detection = crate::protocol_detect::detect(&harness, &[work.path()]);
        let note = super::harness_format_note_for(&harness, &detection)
            .expect("the source dir's format 1 is reported");
        assert!(note.contains("input format 1"), "{note}");
        assert!(note.contains("harnesses/H-X1"), "{note}");

        // Metadata beside the binary wins over the source dir's.
        std::fs::write(
            staged_dir.join("generation-metadata.json"),
            format!(
                r#"{{"schema_version":1,"harness_format_version":{}}}"#,
                harness_gen::HARNESS_FORMAT_VERSION
            ),
        )
        .unwrap();
        assert!(super::harness_format_note_for(&harness, &detection).is_none());
    }
}
