// SPDX-License-Identifier: Apache-2.0

use crate::minimize::MinimizeStrategy;
use crate::runner::SandboxModeArg;
use anyhow::{anyhow, Context};
use clap::ValueEnum;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, clap::Args)]
pub struct BinaryFuzzArgs {
    /// Executable binary to fuzz.
    pub binary: PathBuf,

    /// BHF work directory where findings are written.
    #[arg(long, default_value = "bhf_work")]
    pub work_dir: PathBuf,

    /// How fuzz bytes are delivered to the executable.
    #[arg(long, value_enum, default_value_t = BinaryInputMode::Stdin)]
    pub input_mode: BinaryInputMode,

    /// Maximum number of seed executions.
    #[arg(long, default_value_t = 256)]
    pub iterations: usize,

    /// Literal seed input bytes.
    #[arg(long = "seed-input")]
    pub seed_inputs: Vec<String>,

    /// File containing seed input bytes.
    #[arg(long = "seed-file")]
    pub seed_files: Vec<PathBuf>,

    /// Per-execution timeout in milliseconds. Applied to the afl-qemu mutation
    /// campaign (`afl-fuzz -t`) as well as the crash-replay oracle, so both use
    /// the same policy.
    #[arg(long, default_value_t = 10_000)]
    pub timeout_ms: u64,

    /// Child-process memory limit in MiB for the afl-qemu engine (`afl-fuzz -m`).
    /// Accepts an integer or `none`; defaults to `none` because QEMU mode maps a
    /// large virtual address space and a tight cap aborts the campaign.
    #[arg(long = "mem-mb", default_value = "none")]
    pub mem_mb: String,

    /// Environment variable passed as KEY=VALUE. Repeatable.
    #[arg(long = "env")]
    pub env: Vec<String>,

    /// Runner/emulator to launch the target under, e.g. `wine` or `qemu-x86_64`.
    /// The target binary and its `--target-arg`s follow. Builtin engine only
    /// (afl-qemu provides its own `-Q` runner).
    #[arg(long = "runner")]
    pub runner: Option<String>,

    /// Argument for the `--runner` prefix, placed before the target binary.
    /// Repeatable. Requires `--runner`.
    #[arg(long = "runner-arg")]
    pub runner_args: Vec<String>,

    /// Fixed argument passed to the target before the fuzz input. Repeatable. A
    /// literal `@@` token is replaced by the input-file path (file mode); with no
    /// `@@`, file-mode input is appended last. Lets a manual binary-only harness
    /// express `wine ./harness.exe --mode fuzz @@`.
    #[arg(long = "target-arg")]
    pub target_args: Vec<String>,

    /// Sandbox mode recorded in finding provenance.
    #[arg(long, value_enum, default_value_t = SandboxModeArg::Auto)]
    pub sandbox: SandboxModeArg,

    /// Fuzzing engine. `builtin` replays the seeds and detects crashes (no
    /// mutation/coverage). `afl-qemu` drives AFL++ in QEMU mode (`afl-fuzz -Q`)
    /// so a binary-only / foreign-arch target with NO source still gets
    /// coverage-guided mutation — qemu's DBT injects edge coverage during
    /// translation. `auto` (default) uses afl-qemu when its toolchain is present,
    /// else falls back to builtin.
    #[arg(long, value_enum, default_value_t = BinaryFuzzEngine::Auto)]
    pub engine: BinaryFuzzEngine,

    /// Wall-clock budget for the afl-qemu engine (e.g. 30s, 5m). Ignored by the
    /// builtin engine. Defaults to ~100ms per `--iterations`, clamped to [1s,30s].
    #[arg(long = "time")]
    pub time: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BinaryFuzzEngine {
    Builtin,
    #[value(name = "afl-qemu")]
    AflQemu,
    Auto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BinaryInputMode {
    Stdin,
    File,
}

impl BinaryInputMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stdin => "stdin",
            Self::File => "file",
        }
    }
}

/// How one target execution is launched (#47): an optional runner/emulator
/// prefix (e.g. `wine`, `qemu-x86_64`) with its own args, the target binary, and
/// fixed target arguments. A literal `@@` token among the target args marks where
/// the fuzz input file goes (file mode); without one, file-mode input is appended
/// last. Captured in the finding so replay/minimize reproduce the exact command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TargetInvocation {
    pub(crate) binary: PathBuf,
    pub(crate) runner: Option<String>,
    pub(crate) runner_args: Vec<String>,
    pub(crate) target_args: Vec<String>,
}

/// The `@@` input-file placeholder token (AFL's convention, reused here).
const INPUT_PLACEHOLDER: &str = "@@";

impl TargetInvocation {
    fn from_args(args: &BinaryFuzzArgs) -> Self {
        Self {
            binary: args.binary.clone(),
            runner: args.runner.clone(),
            runner_args: args.runner_args.clone(),
            target_args: args.target_args.clone(),
        }
    }

    /// Reject invocations that cannot be launched coherently, with an actionable
    /// message. Pure over the fields so it is unit-testable.
    fn validate(&self, mode: BinaryInputMode, engine_is_afl_qemu: bool) -> anyhow::Result<()> {
        if self.runner.is_none() && !self.runner_args.is_empty() {
            return Err(anyhow!(
                "--runner-arg requires --runner (the program to pass the args to)"
            ));
        }
        if mode == BinaryInputMode::Stdin && self.target_args.iter().any(|a| a == INPUT_PLACEHOLDER)
        {
            return Err(anyhow!(
                "a '@@' target-arg has nothing to substitute in stdin input mode; \
                 use --input-mode file, or drop the '@@'"
            ));
        }
        if engine_is_afl_qemu && self.runner.is_some() {
            return Err(anyhow!(
                "--runner is not supported with the afl-qemu engine (afl-fuzz -Q provides its \
                 own QEMU runner); use --engine builtin to run under a custom runner, or drop \
                 --runner"
            ));
        }
        Ok(())
    }

    /// The `(program, argv)` to spawn for one execution. `input_path` is the fuzz
    /// testcase file for file mode, `None` for stdin. A `@@` target-arg is
    /// replaced by the input path; in file mode with no `@@`, the input path is
    /// appended last. Pure (no FS/spawn) so the argv is unit-testable.
    fn command_for(&self, input_path: Option<&Path>) -> (PathBuf, Vec<String>) {
        let (program, mut argv) = match &self.runner {
            Some(runner) => {
                let mut argv = self.runner_args.clone();
                argv.push(self.binary.display().to_string());
                (PathBuf::from(runner), argv)
            }
            None => (self.binary.clone(), Vec::new()),
        };
        let mut substituted = false;
        for arg in &self.target_args {
            if arg == INPUT_PLACEHOLDER {
                if let Some(path) = input_path {
                    argv.push(path.display().to_string());
                    substituted = true;
                }
                // stdin mode: a stray `@@` is rejected by validate(), so this is
                // unreachable there; skip defensively rather than emit the token.
            } else {
                argv.push(arg.clone());
            }
        }
        if let Some(path) = input_path {
            if !substituted {
                argv.push(path.display().to_string());
            }
        }
        (program, argv)
    }

    /// The argv rendered for provenance, with `@@` marking the input position (so
    /// the recorded command is replayable and human-readable regardless of the
    /// concrete per-run testcase path).
    fn provenance_argv(&self, mode: BinaryInputMode) -> Vec<String> {
        let placeholder = PathBuf::from(INPUT_PLACEHOLDER);
        let input = (mode == BinaryInputMode::File).then_some(placeholder);
        let (program, args) = self.command_for(input.as_deref());
        let mut argv = vec![program.display().to_string()];
        argv.extend(args);
        argv
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BinaryMinimizeSummary {
    pub(crate) original_len: usize,
    pub(crate) minimized_len: usize,
    pub(crate) removed_bytes: usize,
    pub(crate) reduced: bool,
}

pub fn run(args: BinaryFuzzArgs) -> i32 {
    match run_inner(args) {
        Ok(summary) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&summary).unwrap_or_default()
            );
            0
        }
        Err(error) => {
            bhfeprintln!("{error:#}");
            1
        }
    }
}

fn run_inner(args: BinaryFuzzArgs) -> anyhow::Result<Value> {
    if args.iterations == 0 {
        return Err(anyhow!("--iterations must be greater than zero"));
    }
    let env = parse_env(&args.env)?;
    let seeds = collect_seeds(&args.seed_inputs, &args.seed_files)?;
    let seeds = if seeds.is_empty() {
        vec![Vec::new()]
    } else {
        seeds
    };
    let findings_dir = args.work_dir.join("findings");
    fs::create_dir_all(&findings_dir)
        .with_context(|| format!("create {}", findings_dir.display()))?;

    // Engine dispatch. afl-qemu gives coverage-guided mutation for binary-only /
    // foreign-arch targets via QEMU DBT; builtin just replays the seeds.
    let engine = resolve_binary_engine(args.engine)?;
    let invocation = TargetInvocation::from_args(&args);
    invocation.validate(
        args.input_mode,
        matches!(engine, ResolvedEngine::AflQemu(_)),
    )?;
    match engine {
        ResolvedEngine::AflQemu(aq) => {
            return run_afl_qemu(&args, &aq, &seeds, &env, &findings_dir);
        }
        ResolvedEngine::Builtin => {}
    }

    let tmp_dir = args.work_dir.join("binary_fuzz/tmp");
    fs::create_dir_all(&tmp_dir).with_context(|| format!("create {}", tmp_dir.display()))?;

    let mut finding_ids = Vec::new();
    let mut executions = 0usize;
    for seed in seeds.iter().cycle().take(args.iterations.min(seeds.len())) {
        executions += 1;
        let run = run_binary_once(
            &invocation,
            args.input_mode,
            seed,
            &env,
            Duration::from_millis(args.timeout_ms),
            &tmp_dir,
        )?;
        if run.crashed() {
            let id = next_binary_finding_id(&findings_dir)?;
            let dir = findings_dir.join(&id);
            fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
            fs::write(dir.join("testcase.bin"), seed)
                .with_context(|| format!("write {}", dir.join("testcase.bin").display()))?;
            let finding = render_finding(&id, &args, seed, &env, &run)?;
            fs::write(
                dir.join("finding.json"),
                serde_json::to_vec_pretty(&finding)?,
            )
            .with_context(|| format!("write {}", dir.join("finding.json").display()))?;
            finding_ids.push(id);
            break;
        }
    }

    Ok(json!({
        "schema_version": "bhf.binary_fuzz.run.v1",
        "binary": args.binary,
        "input_mode": args.input_mode.as_str(),
        "executions": executions,
        "findings": finding_ids
    }))
}

/// The concrete engine a binary-fuzz run resolved to.
#[derive(Debug)]
enum ResolvedEngine {
    Builtin,
    AflQemu(AflQemu),
}

/// AFL++ QEMU-mode toolchain: `afl-fuzz` plus the `afl-qemu-trace` it shells out
/// to for DBT-injected edge coverage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AflQemu {
    pub(crate) afl_fuzz: PathBuf,
    pub(crate) afl_qemu_trace: PathBuf,
}

/// Resolve the concrete engine. Explicit `afl-qemu` hard-requires the toolchain
/// (actionable error if missing); `auto` falls back to builtin with a note.
fn resolve_binary_engine(engine: BinaryFuzzEngine) -> anyhow::Result<ResolvedEngine> {
    match engine {
        BinaryFuzzEngine::Builtin => Ok(ResolvedEngine::Builtin),
        BinaryFuzzEngine::AflQemu => resolve_afl_qemu()
            .map(ResolvedEngine::AflQemu)
            .map_err(|reason| anyhow!(reason)),
        BinaryFuzzEngine::Auto => match resolve_afl_qemu() {
            Ok(aq) => Ok(ResolvedEngine::AflQemu(aq)),
            Err(reason) => {
                bhfeprintln!(
                    "bhf binary-fuzz: {reason}; falling back to the builtin \
                     seed-replay engine (no coverage-guided mutation)"
                );
                Ok(ResolvedEngine::Builtin)
            }
        },
    }
}

/// Resolve the AFL++ QEMU-mode toolchain, or an ACTIONABLE reason it's missing.
pub(crate) fn resolve_afl_qemu() -> Result<AflQemu, String> {
    let afl_fuzz = which_on_path("afl-fuzz").ok_or_else(|| {
        "afl-fuzz not found on PATH; install AFL++ (apt install afl++, or build AFLplusplus)"
            .to_owned()
    })?;
    let afl_qemu_trace = resolve_afl_qemu_trace().ok_or_else(|| {
        "afl-qemu-trace not found (AFL++ QEMU mode is built separately); run \
         `AFLplusplus/qemu_mode/build_qemu_support.sh` or set BHF_AFL_QEMU_TRACE to its path"
            .to_owned()
    })?;
    Ok(AflQemu {
        afl_fuzz,
        afl_qemu_trace,
    })
}

/// Locate `afl-qemu-trace`: explicit `BHF_AFL_QEMU_TRACE` override, then PATH,
/// then `AFL_PATH`, then the common AFL install dirs. Reads the environment and
/// delegates the (pure) ordering to [`afl_qemu_trace_candidates`].
pub(crate) fn resolve_afl_qemu_trace() -> Option<PathBuf> {
    let override_var = std::env::var_os("BHF_AFL_QEMU_TRACE").map(PathBuf::from);
    let path_dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).collect())
        .unwrap_or_default();
    let afl_path = std::env::var_os("AFL_PATH").map(PathBuf::from);
    afl_qemu_trace_candidates(override_var, &path_dirs, afl_path)
        .into_iter()
        .find(|p| p.is_file())
}

/// Ordered candidate file paths for `afl-qemu-trace`, most-specific first: the
/// explicit override file, then each PATH/`AFL_PATH`/install dir joined with the
/// binary name. Pure (no FS/env) so the precedence is unit-testable.
fn afl_qemu_trace_candidates(
    override_var: Option<PathBuf>,
    path_dirs: &[PathBuf],
    afl_path: Option<PathBuf>,
) -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(over) = override_var {
        candidates.push(over);
    }
    for dir in path_dirs {
        candidates.push(dir.join("afl-qemu-trace"));
    }
    if let Some(afl_path) = afl_path {
        candidates.push(afl_path.join("afl-qemu-trace"));
    }
    candidates.push(PathBuf::from("/usr/lib/afl/afl-qemu-trace"));
    candidates.push(PathBuf::from("/usr/local/lib/afl/afl-qemu-trace"));
    candidates
}

fn which_on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|p| p.is_file())
    })
}

/// Build the `afl-fuzz -Q` argv for a binary-only target. File-input mode appends
/// `@@` (AFL substitutes the testcase path); stdin mode omits it (AFL feeds the
/// testcase on stdin). `-t` sets the per-exec timeout (ms) and `-m` the child
/// memory limit so the campaign matches the replay oracle. Kept pure for testing.
// A flat flag-bundle builder: the inputs are distinct afl-fuzz knobs, and a
// struct would only scatter the same fields without clarifying the one argv.
#[allow(clippy::too_many_arguments)]
fn afl_qemu_argv(
    binary: &Path,
    seeds_dir: &Path,
    out_dir: &Path,
    secs: u64,
    timeout_ms: u64,
    mem: &str,
    mode: BinaryInputMode,
    target_args: &[String],
) -> Vec<String> {
    let mut argv = vec![
        "-Q".to_owned(),
        "-i".to_owned(),
        seeds_dir.display().to_string(),
        "-o".to_owned(),
        out_dir.display().to_string(),
        "-V".to_owned(),
        secs.to_string(),
        "-t".to_owned(),
        timeout_ms.to_string(),
        "-m".to_owned(),
        mem.to_owned(),
        "--".to_owned(),
        binary.display().to_string(),
    ];
    // Fixed target args follow the binary; AFL substitutes a `@@` among them with
    // the testcase path. If file mode has no explicit `@@`, append one so AFL
    // still passes the testcase as a file argument (its default is stdin).
    argv.extend(target_args.iter().cloned());
    if mode == BinaryInputMode::File && !target_args.iter().any(|a| a == INPUT_PLACEHOLDER) {
        argv.push(INPUT_PLACEHOLDER.to_owned());
    }
    argv
}

/// Resolve the `--mem-mb` value into the afl-fuzz `-m` argument plus the value to
/// record in run provenance. `none`/`0` map to AFL's unlimited `none`; any other
/// value must be a MiB integer.
fn afl_mem_arg(mem_mb: &str) -> anyhow::Result<(String, Value)> {
    let trimmed = mem_mb.trim();
    if trimmed.eq_ignore_ascii_case("none") || trimmed == "0" {
        return Ok(("none".to_owned(), Value::String("none".to_owned())));
    }
    let mib: u64 = trimmed
        .parse()
        .map_err(|_| anyhow!("--mem-mb must be a MiB integer or 'none', got '{mem_mb}'"))?;
    Ok((mib.to_string(), json!(mib)))
}

/// The afl-fuzz `-V` wall-clock budget in seconds: `--time` if given, else
/// ~100ms per `--iterations`, clamped to [1s, 30s].
fn afl_qemu_budget_secs(time: Option<&str>, iterations: usize) -> u64 {
    if let Some(secs) = time.and_then(parse_duration_secs) {
        return secs.max(1);
    }
    ((iterations as u64).saturating_mul(100) / 1000).clamp(1, 30)
}

/// Parse a coarse duration (`30s`, `5m`, `1h`, `500ms`, or bare seconds) to whole
/// seconds. Returns `None` on a malformed value.
fn parse_duration_secs(value: &str) -> Option<u64> {
    let value = value.trim();
    let (num, mult): (&str, u64) = if let Some(rest) = value.strip_suffix("ms") {
        // Round sub-second up to 1s (afl-fuzz -V is second-granular).
        return rest.trim().parse::<u64>().ok().map(|ms| ms.div_ceil(1000));
    } else if let Some(rest) = value.strip_suffix('h') {
        (rest, 3600)
    } else if let Some(rest) = value.strip_suffix('m') {
        (rest, 60)
    } else if let Some(rest) = value.strip_suffix('s') {
        (rest, 1)
    } else {
        (value, 1)
    };
    num.trim()
        .parse::<u64>()
        .ok()
        .map(|n| n.saturating_mul(mult))
}

/// Drive AFL++ in QEMU mode (`afl-fuzz -Q`) against a binary-only target: qemu's
/// DBT injects edge coverage so a foreign-arch / no-source binary gets
/// coverage-guided mutation. Harvest `out/default/crashes/` and confirm+record
/// each as a `binary_crash` finding via the same crash oracle as builtin.
fn run_afl_qemu(
    args: &BinaryFuzzArgs,
    aq: &AflQemu,
    seeds: &[Vec<u8>],
    env: &BTreeMap<String, String>,
    findings_dir: &Path,
) -> anyhow::Result<Value> {
    let afl_out = args.work_dir.join("afl_qemu_out");
    let _ = fs::remove_dir_all(&afl_out);
    let seeds_dir = afl_out.join("seeds");
    let out_dir = afl_out.join("out");
    fs::create_dir_all(&seeds_dir).with_context(|| format!("create {}", seeds_dir.display()))?;
    fs::create_dir_all(&out_dir).with_context(|| format!("create {}", out_dir.display()))?;

    // afl-fuzz needs at least one non-empty seed to start.
    let mut wrote = 0usize;
    for (idx, seed) in seeds.iter().enumerate() {
        if seed.is_empty() {
            continue;
        }
        fs::write(seeds_dir.join(format!("seed-{idx:04}")), seed)?;
        wrote += 1;
    }
    if wrote == 0 {
        fs::write(seeds_dir.join("seed-default"), b"AAAA")?;
    }

    let secs = afl_qemu_budget_secs(args.time.as_deref(), args.iterations);
    let (mem_arg, mem_provenance) = afl_mem_arg(&args.mem_mb)?;
    let argv = afl_qemu_argv(
        &args.binary,
        &seeds_dir,
        &out_dir,
        secs,
        args.timeout_ms,
        &mem_arg,
        args.input_mode,
        &args.target_args,
    );
    let afl_trace_dir = aq
        .afl_qemu_trace
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let mut cmd = Command::new(&aq.afl_fuzz);
    cmd.args(&argv)
        // afl-fuzz -Q finds afl-qemu-trace via AFL_PATH (then alongside afl-fuzz).
        .env("AFL_PATH", &afl_trace_dir)
        .env("AFL_NO_UI", "1")
        .env("AFL_SKIP_CPUFREQ", "1")
        .env("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in env {
        cmd.env(key, value);
    }
    let output = cmd
        .output()
        .with_context(|| format!("spawn afl-fuzz '{}'", aq.afl_fuzz.display()))?;
    // afl-fuzz self-terminates by signal when -V expires (code None) — that's the
    // intended end of a time-boxed run, not a failure. A positive exit is a real
    // error (bad seed, core_pattern, missing afl-qemu-trace, …).
    if output.status.code().is_some_and(|code| code != 0) {
        let tail: String = String::from_utf8_lossy(&output.stderr)
            .lines()
            .rev()
            .take(12)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
        return Err(anyhow!(
            "afl-fuzz -Q exited non-zero ({:?}). Output tail:\n{tail}",
            output.status.code()
        ));
    }

    // Harvest crashes: confirm each against the binary (own crash oracle) so the
    // finding carries a real signature, deduped by signature.
    let crashes_dir = out_dir.join("default").join("crashes");
    let tmp_dir = afl_out.join("replay_tmp");
    fs::create_dir_all(&tmp_dir)?;
    let mut finding_ids = Vec::new();
    let mut seen_signatures = std::collections::HashSet::new();
    // Confirm with the same target args AFL used (runner is forbidden for
    // afl-qemu, so it is always a bare/target-arg invocation here).
    let invocation = TargetInvocation::from_args(args);
    if crashes_dir.is_dir() {
        let mut entries: Vec<PathBuf> = fs::read_dir(&crashes_dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.file_name().is_some_and(|n| n != "README.txt"))
            .collect();
        entries.sort();
        for crash in entries {
            let input = fs::read(&crash)?;
            let run = run_binary_once(
                &invocation,
                args.input_mode,
                &input,
                env,
                Duration::from_millis(args.timeout_ms),
                &tmp_dir,
            )?;
            if !run.crashed() || !seen_signatures.insert(run.signature.clone()) {
                continue;
            }
            let id = next_binary_finding_id(findings_dir)?;
            let dir = findings_dir.join(&id);
            fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
            fs::write(dir.join("testcase.bin"), &input)?;
            let finding = render_finding(&id, args, &input, env, &run)?;
            fs::write(
                dir.join("finding.json"),
                serde_json::to_vec_pretty(&finding)?,
            )?;
            finding_ids.push(id);
        }
    }
    let _ = fs::remove_dir_all(&tmp_dir);

    Ok(json!({
        "schema_version": "bhf.binary_fuzz.run.v1",
        "binary": args.binary,
        "input_mode": args.input_mode.as_str(),
        "engine": "afl-qemu",
        "afl_qemu_trace": aq.afl_qemu_trace,
        "time_secs": secs,
        "timeout_ms": args.timeout_ms,
        "mem_limit_mb": mem_provenance,
        "findings": finding_ids
    }))
}

pub(crate) fn is_binary_finding(finding_dir: &Path) -> bool {
    fs::read(finding_dir.join("finding.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| value.get("kind").and_then(Value::as_str).map(str::to_owned))
        .is_some_and(|kind| kind == "binary_crash")
}

pub(crate) fn replay_binary_finding(finding_dir: &Path, binary: &Path) -> i32 {
    match replay_binary_finding_inner(finding_dir, binary) {
        Ok(true) => {
            println!("MATCH");
            0
        }
        Ok(false) => {
            bhfeprintln!("MISMATCH binary crash signature changed");
            3
        }
        Err(error) => {
            bhfeprintln!("error: {error:#}");
            1
        }
    }
}

pub(crate) fn minimize_binary_finding(
    finding_dir: &Path,
    binary: &Path,
    strategy: MinimizeStrategy,
) -> anyhow::Result<BinaryMinimizeSummary> {
    if strategy != MinimizeStrategy::Bytes {
        return Err(anyhow!(
            "minimize --strategy typed is not yet supported for binary findings"
        ));
    }
    let finding = read_finding(finding_dir)?;
    let mode = finding_input_mode(&finding)?;
    let env = finding_env(&finding);
    let timeout = finding_timeout(&finding);
    let expected = finding_signature(&finding)?;
    let original = fs::read(finding_dir.join("testcase.bin"))
        .with_context(|| format!("read {}", finding_dir.join("testcase.bin").display()))?;
    let invocation = finding_invocation(&finding, binary);
    let tmp_dir = finding_dir.join("binary_minimize_tmp");
    fs::create_dir_all(&tmp_dir).with_context(|| format!("create {}", tmp_dir.display()))?;
    let result = replay_min::ddmin_bytes(&original, |candidate| -> anyhow::Result<bool> {
        let run = run_binary_once(&invocation, mode, candidate, &env, timeout, &tmp_dir)?;
        Ok(run.signature == expected)
    })?;
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::write(finding_dir.join("min_testcase.bin"), &result.minimized)
        .with_context(|| format!("write {}", finding_dir.join("min_testcase.bin").display()))?;
    let removed = result.original_len.saturating_sub(result.minimized.len());
    update_binary_finding_minimized(
        finding_dir,
        result.original_len,
        result.minimized.len(),
        removed,
    )?;
    Ok(BinaryMinimizeSummary {
        original_len: result.original_len,
        minimized_len: result.minimized.len(),
        removed_bytes: removed,
        reduced: removed > 0,
    })
}

fn replay_binary_finding_inner(finding_dir: &Path, binary: &Path) -> anyhow::Result<bool> {
    let finding = read_finding(finding_dir)?;
    let input = fs::read(finding_dir.join("testcase.bin"))
        .with_context(|| format!("read {}", finding_dir.join("testcase.bin").display()))?;
    let tmp_dir = finding_dir.join("binary_replay_tmp");
    fs::create_dir_all(&tmp_dir).with_context(|| format!("create {}", tmp_dir.display()))?;
    let invocation = finding_invocation(&finding, binary);
    let run = run_binary_once(
        &invocation,
        finding_input_mode(&finding)?,
        &input,
        &finding_env(&finding),
        finding_timeout(&finding),
        &tmp_dir,
    )?;
    let _ = fs::remove_dir_all(&tmp_dir);
    Ok(run.signature == finding_signature(&finding)?)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BinaryRun {
    exit_code: Option<i32>,
    /// Unix termination signal, when the process was killed by one
    /// (SIGSEGV/SIGABRT/...). `None` on a normal exit or non-Unix.
    signal: Option<i32>,
    timeout: bool,
    stderr: String,
    signature: String,
}

impl BinaryRun {
    fn crashed(&self) -> bool {
        // A signal termination (segfault/abort — the dominant crash
        // class for un-sanitized legacy binaries) yields exit_code ==
        // None, so it must be detected via `signal`, not exit code.
        self.timeout || self.signal.is_some() || self.exit_code.is_some_and(|code| code != 0)
    }
}

/// The terminating signal of a finished child, on Unix. Always `None`
/// elsewhere so the call site stays portable.
#[cfg(unix)]
fn termination_signal(status: &std::process::ExitStatus) -> Option<i32> {
    std::os::unix::process::ExitStatusExt::signal(status)
}

#[cfg(not(unix))]
fn termination_signal(_status: &std::process::ExitStatus) -> Option<i32> {
    None
}

fn run_binary_once(
    inv: &TargetInvocation,
    mode: BinaryInputMode,
    input: &[u8],
    env: &BTreeMap<String, String>,
    timeout: Duration,
    tmp_dir: &Path,
) -> anyhow::Result<BinaryRun> {
    // Materialize the file-mode testcase first so the invocation can place its
    // path (at a `@@` token or appended); stdin mode delivers it on the pipe.
    let input_file = match mode {
        BinaryInputMode::Stdin => None,
        BinaryInputMode::File => {
            let path = tmp_dir.join(format!("input-{}.bin", nonce()));
            fs::write(&path, input).with_context(|| format!("write {}", path.display()))?;
            Some(path)
        }
    };
    let (program, argv) = inv.command_for(input_file.as_deref());
    let mut cmd = Command::new(&program);
    cmd.args(&argv);
    cmd.stdout(Stdio::null()).stderr(Stdio::piped());
    for (key, value) in env {
        cmd.env(key, value);
    }
    match mode {
        BinaryInputMode::Stdin => {
            cmd.stdin(Stdio::piped());
        }
        BinaryInputMode::File => {
            cmd.stdin(Stdio::null());
        }
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn {}", program.display()))?;
    if mode == BinaryInputMode::Stdin {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(input);
        }
    }
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    loop {
        match child.try_wait()? {
            Some(_) => break,
            None => {
                if Instant::now() >= deadline {
                    timed_out = true;
                    let _ = child.kill();
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    let output = child.wait_with_output()?;
    if let Some(path) = input_file {
        let _ = fs::remove_file(path);
    }
    let exit_code = output.status.code();
    let signal = termination_signal(&output.status);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let signature = if timed_out {
        "timeout".to_owned()
    } else if let Some(sig) = signal {
        // Distinguish crash signals (SIGSEGV vs SIGABRT ...) instead of
        // collapsing every signal into exit:-1.
        format!("signal:{}:{}", sig, sha256_hex(stderr.as_bytes()))
    } else {
        format!(
            "exit:{}:{}",
            exit_code.unwrap_or(-1),
            sha256_hex(stderr.as_bytes())
        )
    };
    Ok(BinaryRun {
        exit_code,
        signal,
        timeout: timed_out,
        stderr,
        signature,
    })
}

fn render_finding(
    id: &str,
    args: &BinaryFuzzArgs,
    input: &[u8],
    env: &BTreeMap<String, String>,
    run: &BinaryRun,
) -> anyhow::Result<Value> {
    Ok(json!({
        "id": id,
        "kind": "binary_crash",
        "rule_id": "BHF-501",
        "severity": "high",
        "confidence": "high",
        "message": "Binary crashed under BHF binary-fuzz",
        "binary": {
            "path": args.binary,
            "sha256": sha256_hex(&fs::read(&args.binary).with_context(|| format!("read {}", args.binary.display()))?)
        },
        "command": {
            "argv": TargetInvocation::from_args(args).provenance_argv(args.input_mode),
            "runner": args.runner,
            "runner_args": args.runner_args,
            "target_args": args.target_args,
            "timeout_ms": args.timeout_ms,
            "sandbox": format!("{:?}", args.sandbox).to_ascii_lowercase()
        },
        "input": {
            "mode": args.input_mode.as_str(),
            "bytes": input.len(),
            "testcase": "testcase.bin"
        },
        "env": env,
        "crash": {
            "exit_code": run.exit_code,
            "timeout": run.timeout,
            "signature": run.signature,
            "stderr_excerpt": stderr_excerpt(&run.stderr)
        },
        "paths": {
            "testcase": "testcase.bin"
        },
        "triage": {
            "replay": format!("bhf replay --harness {} {}", args.binary.display(), id)
        }
    }))
}

fn collect_seeds(seed_inputs: &[String], seed_files: &[PathBuf]) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut seeds = seed_inputs
        .iter()
        .map(|seed| seed.as_bytes().to_vec())
        .collect::<Vec<_>>();
    for file in seed_files {
        seeds.push(fs::read(file).with_context(|| format!("read {}", file.display()))?);
    }
    Ok(seeds)
}

fn parse_env(items: &[String]) -> anyhow::Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for item in items {
        let Some((key, value)) = item.split_once('=') else {
            return Err(anyhow!("--env must be KEY=VALUE, got `{item}`"));
        };
        out.insert(key.to_owned(), value.to_owned());
    }
    Ok(out)
}

fn read_finding(finding_dir: &Path) -> anyhow::Result<Value> {
    let path = finding_dir.join("finding.json");
    serde_json::from_slice(&fs::read(&path).with_context(|| format!("read {}", path.display()))?)
        .with_context(|| format!("parse {}", path.display()))
}

fn finding_input_mode(finding: &Value) -> anyhow::Result<BinaryInputMode> {
    match finding.pointer("/input/mode").and_then(Value::as_str) {
        Some("stdin") => Ok(BinaryInputMode::Stdin),
        Some("file") => Ok(BinaryInputMode::File),
        Some(other) => Err(anyhow!("unsupported binary input mode `{other}`")),
        None => Err(anyhow!("binary finding is missing input.mode")),
    }
}

fn finding_env(finding: &Value) -> BTreeMap<String, String> {
    finding
        .get("env")
        .and_then(Value::as_object)
        .map(|env| {
            env.iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|value| (key.clone(), value.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// String array at a JSON pointer in a finding (e.g. recorded runner/target
/// args), or empty when absent/malformed.
fn finding_str_array(finding: &Value, pointer: &str) -> Vec<String> {
    finding
        .pointer(pointer)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Rebuild the [`TargetInvocation`] from a finding for replay/minimize, using
/// `binary` as the target path (the caller supplies it; it may be re-pathed) and
/// the recorded runner + args so the launch reproduces the original command. A
/// finding from before #47 has no runner/target args and replays as a bare
/// binary invocation, unchanged.
fn finding_invocation(finding: &Value, binary: &Path) -> TargetInvocation {
    TargetInvocation {
        binary: binary.to_path_buf(),
        runner: finding
            .pointer("/command/runner")
            .and_then(Value::as_str)
            .map(str::to_owned),
        runner_args: finding_str_array(finding, "/command/runner_args"),
        target_args: finding_str_array(finding, "/command/target_args"),
    }
}

fn finding_timeout(finding: &Value) -> Duration {
    Duration::from_millis(
        finding
            .pointer("/command/timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(10_000),
    )
}

fn finding_signature(finding: &Value) -> anyhow::Result<String> {
    finding
        .pointer("/crash/signature")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("binary finding is missing crash.signature"))
}

fn update_binary_finding_minimized(
    finding_dir: &Path,
    original_len: usize,
    minimized_len: usize,
    removed_bytes: usize,
) -> anyhow::Result<()> {
    let path = finding_dir.join("finding.json");
    let mut value: Value = serde_json::from_slice(&fs::read(&path)?)?;
    value["paths"]["minimized"] = json!("min_testcase.bin");
    value["minimal_reproducer"] = json!("min_testcase.bin");
    value["minimization"] = json!({
        "strategy": "bytes",
        "original_len": original_len,
        "minimized_len": minimized_len,
        "removed_bytes": removed_bytes,
        "reduced": removed_bytes > 0
    });
    fs::write(&path, serde_json::to_vec_pretty(&value)?)?;
    Ok(())
}

fn next_binary_finding_id(findings_dir: &Path) -> anyhow::Result<String> {
    let mut max_id = 0usize;
    if findings_dir.is_dir() {
        for entry in fs::read_dir(findings_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if let Some(number) = name
                .strip_prefix("BF-")
                .and_then(|value| value.parse::<usize>().ok())
            {
                max_id = max_id.max(number);
            }
        }
    }
    Ok(format!("BF-{next:04}", next = max_id + 1))
}

fn stderr_excerpt(stderr: &str) -> String {
    stderr.chars().take(4096).collect()
}

fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(exit_code: Option<i32>, signal: Option<i32>, timeout: bool) -> BinaryRun {
        BinaryRun {
            exit_code,
            signal,
            timeout,
            stderr: String::new(),
            signature: String::new(),
        }
    }

    #[test]
    fn crashed_detects_signal_termination() {
        // SIGSEGV/SIGABRT: exit_code is None, signal is Some — the
        // case the old code missed entirely.
        assert!(run(None, Some(11), false).crashed(), "SIGSEGV is a crash");
        assert!(run(None, Some(6), false).crashed(), "SIGABRT is a crash");
    }

    #[test]
    fn crashed_classifies_exit_and_timeout() {
        assert!(
            run(Some(1), None, false).crashed(),
            "nonzero exit is a crash"
        );
        assert!(run(None, None, true).crashed(), "timeout is a crash");
        assert!(
            !run(Some(0), None, false).crashed(),
            "clean exit is not a crash"
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_binary_once_records_segfault_as_crash() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("bhf-binfuzz-{}", nonce()));
        fs::create_dir_all(&dir).unwrap();
        let script = dir.join("crasher.sh");
        {
            let mut f = fs::File::create(&script).unwrap();
            // Kill self with SIGSEGV — a signal termination, exit code None.
            f.write_all(b"#!/bin/sh\nkill -SEGV $$\n").unwrap();
            f.set_permissions(fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        let invocation = TargetInvocation {
            binary: script.clone(),
            runner: None,
            runner_args: Vec::new(),
            target_args: Vec::new(),
        };
        let run = run_binary_once(
            &invocation,
            BinaryInputMode::Stdin,
            b"",
            &BTreeMap::new(),
            Duration::from_secs(5),
            &dir,
        )
        .expect("spawn crasher");
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(run.signal, Some(11), "SIGSEGV captured");
        assert!(run.crashed(), "segfault must register as a crash");
        assert!(
            run.signature.starts_with("signal:11:"),
            "signature distinguishes the signal, got {}",
            run.signature
        );
    }

    // --- #47: runner prefix + target arguments ---

    fn inv(runner: Option<&str>, runner_args: &[&str], target_args: &[&str]) -> TargetInvocation {
        TargetInvocation {
            binary: PathBuf::from("/b/target"),
            runner: runner.map(str::to_owned),
            runner_args: runner_args.iter().map(|s| s.to_string()).collect(),
            target_args: target_args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn command_for_bare_stdin_is_just_the_binary() {
        let (prog, argv) = inv(None, &[], &[]).command_for(None);
        assert_eq!(prog, PathBuf::from("/b/target"));
        assert!(argv.is_empty());
    }

    #[test]
    fn command_for_file_mode_appends_input_when_no_placeholder() {
        let (prog, argv) =
            inv(None, &[], &["--mode", "fuzz"]).command_for(Some(Path::new("/t/in.bin")));
        assert_eq!(prog, PathBuf::from("/b/target"));
        assert_eq!(argv, vec!["--mode", "fuzz", "/t/in.bin"]);
    }

    #[test]
    fn command_for_substitutes_the_placeholder_in_place() {
        let (_, argv) =
            inv(None, &[], &["--in", "@@", "--verbose"]).command_for(Some(Path::new("/t/in.bin")));
        assert_eq!(argv, vec!["--in", "/t/in.bin", "--verbose"]);
    }

    #[test]
    fn command_for_runner_prefixes_binary_then_target_args() {
        let (prog, argv) = inv(Some("wine"), &[], &["--mode", "fuzz", "@@"])
            .command_for(Some(Path::new("/t/in.bin")));
        assert_eq!(prog, PathBuf::from("wine"));
        assert_eq!(argv, vec!["/b/target", "--mode", "fuzz", "/t/in.bin"]);
    }

    #[test]
    fn command_for_runner_with_runner_args() {
        let (prog, argv) = inv(Some("qemu-x86_64"), &["-L", "/sysroot"], &[]).command_for(None);
        assert_eq!(prog, PathBuf::from("qemu-x86_64"));
        assert_eq!(argv, vec!["-L", "/sysroot", "/b/target"]);
    }

    #[test]
    fn validate_rejects_runner_arg_without_runner() {
        assert!(inv(None, &["-L", "/x"], &[])
            .validate(BinaryInputMode::File, false)
            .is_err());
    }

    #[test]
    fn validate_rejects_placeholder_in_stdin_mode_but_allows_it_for_file() {
        assert!(inv(None, &[], &["@@"])
            .validate(BinaryInputMode::Stdin, false)
            .is_err());
        assert!(inv(None, &[], &["@@"])
            .validate(BinaryInputMode::File, false)
            .is_ok());
    }

    #[test]
    fn validate_rejects_runner_with_afl_qemu_engine() {
        assert!(inv(Some("wine"), &[], &[])
            .validate(BinaryInputMode::File, true)
            .is_err());
        assert!(inv(Some("wine"), &[], &[])
            .validate(BinaryInputMode::File, false)
            .is_ok());
    }

    #[test]
    fn provenance_argv_marks_the_input_position() {
        let file = inv(None, &[], &["--in", "@@"]).provenance_argv(BinaryInputMode::File);
        assert_eq!(file, vec!["/b/target", "--in", "@@"]);
        let stdin =
            inv(Some("wine"), &[], &["--mode", "fuzz"]).provenance_argv(BinaryInputMode::Stdin);
        assert_eq!(stdin, vec!["wine", "/b/target", "--mode", "fuzz"]);
    }

    #[cfg(unix)]
    #[test]
    fn end_to_end_runner_and_target_arg_launched_recorded_and_replayable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("bhf-binfuzz-runner-{}", nonce()));
        fs::create_dir_all(&dir).unwrap();
        let script = dir.join("probe.sh");
        // Crash (SIGSEGV) only when launched with a "boom" argument.
        fs::write(
            &script,
            b"#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = boom ] && kill -SEGV $$; done\nexit 0\n",
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let work = dir.join("work");

        let mk = |target_args: Vec<String>| BinaryFuzzArgs {
            binary: script.clone(),
            work_dir: work.clone(),
            input_mode: BinaryInputMode::Stdin,
            iterations: 4,
            seed_inputs: vec!["x".to_owned()],
            seed_files: Vec::new(),
            timeout_ms: 5000,
            mem_mb: "none".to_owned(),
            env: Vec::new(),
            runner: Some("/bin/sh".to_owned()),
            runner_args: Vec::new(),
            target_args,
            sandbox: SandboxModeArg::Auto,
            engine: BinaryFuzzEngine::Builtin,
            time: None,
        };

        // Without the triggering arg the target exits 0 — no finding.
        let clean = run_inner(mk(Vec::new())).unwrap();
        assert_eq!(clean["findings"].as_array().unwrap().len(), 0, "{clean}");

        // With it: one finding, recorded with the runner + target arg, replayable.
        let _ = fs::remove_dir_all(&work);
        let found = run_inner(mk(vec!["boom".to_owned()])).unwrap();
        let ids = found["findings"].as_array().unwrap();
        assert_eq!(ids.len(), 1, "{found}");
        let id = ids[0].as_str().unwrap();
        let fdir = work.join("findings").join(id);
        let finding: Value =
            serde_json::from_slice(&fs::read(fdir.join("finding.json")).unwrap()).unwrap();
        assert_eq!(finding.pointer("/command/runner").unwrap(), "/bin/sh");
        assert_eq!(
            finding.pointer("/command/target_args").unwrap(),
            &json!(["boom"])
        );
        let argv = finding
            .pointer("/command/argv")
            .unwrap()
            .as_array()
            .unwrap();
        assert!(argv.iter().any(|a| a.as_str() == Some("boom")), "{found}");
        assert!(
            argv.iter().any(|a| a.as_str() == Some("/bin/sh")),
            "{found}"
        );

        // Replay reproduces the crash using the recorded invocation.
        assert_eq!(replay_binary_finding(&fdir, &script), 0);

        let _ = fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod afl_qemu_tests {
    use super::*;

    #[test]
    fn argv_stdin_mode_has_no_at_at() {
        let argv = afl_qemu_argv(
            Path::new("/b/target"),
            Path::new("/s"),
            Path::new("/o"),
            7,
            1000,
            "none",
            BinaryInputMode::Stdin,
            &[],
        );
        assert_eq!(
            argv,
            vec![
                "-Q",
                "-i",
                "/s",
                "-o",
                "/o",
                "-V",
                "7",
                "-t",
                "1000",
                "-m",
                "none",
                "--",
                "/b/target"
            ]
        );
    }

    #[test]
    fn argv_file_mode_appends_at_at() {
        let argv = afl_qemu_argv(
            Path::new("/b/target"),
            Path::new("/s"),
            Path::new("/o"),
            7,
            1000,
            "none",
            BinaryInputMode::File,
            &[],
        );
        assert_eq!(argv.last().map(String::as_str), Some("@@"));
        assert_eq!(argv.iter().filter(|a| *a == "-Q").count(), 1);
    }

    #[test]
    fn argv_carries_timeout_and_memory_limits() {
        // Issue #44: `--timeout-ms` must reach afl-fuzz as `-t`, and `--mem-mb`
        // as `-m`, so the mutation campaign and the replay oracle agree.
        let argv = afl_qemu_argv(
            Path::new("/b/target"),
            Path::new("/s"),
            Path::new("/o"),
            7,
            2500,
            "1024",
            BinaryInputMode::Stdin,
            &[],
        );
        let t = argv.iter().position(|a| a == "-t").expect("-t present");
        assert_eq!(argv[t + 1], "2500");
        let m = argv.iter().position(|a| a == "-m").expect("-m present");
        assert_eq!(argv[m + 1], "1024");
    }

    #[test]
    fn mem_arg_defaults_to_unlimited_and_parses_mib() {
        // QEMU mode needs an unlimited memory ceiling by default.
        assert_eq!(
            afl_mem_arg("none").unwrap(),
            ("none".to_owned(), json!("none"))
        );
        assert_eq!(
            afl_mem_arg("NONE").unwrap(),
            ("none".to_owned(), json!("none"))
        );
        assert_eq!(
            afl_mem_arg("0").unwrap(),
            ("none".to_owned(), json!("none"))
        );
        assert_eq!(
            afl_mem_arg("512").unwrap(),
            ("512".to_owned(), json!(512u64))
        );
        assert!(afl_mem_arg("garbage").is_err());
    }

    #[test]
    fn trace_candidate_order_is_most_specific_first() {
        let cands = afl_qemu_trace_candidates(
            Some(PathBuf::from("/override/aqt")),
            &[PathBuf::from("/p1"), PathBuf::from("/p2")],
            Some(PathBuf::from("/aflpath")),
        );
        assert_eq!(cands[0], PathBuf::from("/override/aqt"));
        assert_eq!(cands[1], PathBuf::from("/p1/afl-qemu-trace"));
        assert_eq!(cands[2], PathBuf::from("/p2/afl-qemu-trace"));
        assert_eq!(cands[3], PathBuf::from("/aflpath/afl-qemu-trace"));
        assert_eq!(cands[4], PathBuf::from("/usr/lib/afl/afl-qemu-trace"));
        assert_eq!(cands[5], PathBuf::from("/usr/local/lib/afl/afl-qemu-trace"));
    }

    #[test]
    fn trace_override_file_is_picked_first_else_skipped() {
        let dir = std::env::temp_dir().join(format!("bhf-aqt-{}", nonce()));
        fs::create_dir_all(&dir).unwrap();
        let real = dir.join("afl-qemu-trace");
        fs::write(&real, b"x").unwrap();
        // A real override file is selected first.
        let picked = afl_qemu_trace_candidates(Some(real.clone()), &[], None)
            .into_iter()
            .find(|p| p.is_file());
        assert_eq!(picked, Some(real.clone()));
        // A non-existent override is skipped (never returned as the resolved path)
        // — host-independent: it either falls through to a real system trace or None.
        let bogus = dir.join("nope");
        let picked = afl_qemu_trace_candidates(Some(bogus.clone()), &[], None)
            .into_iter()
            .find(|p| p.is_file());
        assert_ne!(picked, Some(bogus));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn budget_prefers_explicit_time_then_iterations_clamped() {
        assert_eq!(afl_qemu_budget_secs(Some("45s"), 100), 45);
        assert_eq!(afl_qemu_budget_secs(Some("2m"), 100), 120);
        // iterations-derived: 100 * 100ms = 10s.
        assert_eq!(afl_qemu_budget_secs(None, 100), 10);
        // clamp floor (5 * 100ms = 0.5s -> 1s) and ceiling (-> 30s).
        assert_eq!(afl_qemu_budget_secs(None, 5), 1);
        assert_eq!(afl_qemu_budget_secs(None, 100_000), 30);
        // malformed --time falls back to the iterations-derived budget.
        assert_eq!(afl_qemu_budget_secs(Some("garbage"), 100), 10);
    }

    #[test]
    fn parse_duration_secs_handles_units() {
        assert_eq!(parse_duration_secs("30s"), Some(30));
        assert_eq!(parse_duration_secs("5m"), Some(300));
        assert_eq!(parse_duration_secs("1h"), Some(3600));
        assert_eq!(parse_duration_secs("500ms"), Some(1)); // sub-second rounds up
        assert_eq!(parse_duration_secs("1500ms"), Some(2));
        assert_eq!(parse_duration_secs("12"), Some(12)); // bare seconds
        assert_eq!(parse_duration_secs("nope"), None);
    }

    #[test]
    fn engine_builtin_is_always_builtin() {
        assert!(matches!(
            resolve_binary_engine(BinaryFuzzEngine::Builtin).unwrap(),
            ResolvedEngine::Builtin
        ));
    }

    #[test]
    fn engine_afl_qemu_tracks_toolchain_presence() {
        // Branch on the real host: explicit afl-qemu must error actionably when
        // the toolchain is absent; auto must silently fall back to builtin.
        let available = resolve_afl_qemu().is_ok();
        let explicit = resolve_binary_engine(BinaryFuzzEngine::AflQemu);
        let auto = resolve_binary_engine(BinaryFuzzEngine::Auto);
        if available {
            assert!(matches!(explicit.unwrap(), ResolvedEngine::AflQemu(_)));
            assert!(matches!(auto.unwrap(), ResolvedEngine::AflQemu(_)));
        } else {
            let err = explicit.unwrap_err().to_string();
            assert!(
                err.contains("afl-qemu-trace") || err.contains("afl-fuzz"),
                "skip reason must name the missing tool: {err}"
            );
            assert!(matches!(auto.unwrap(), ResolvedEngine::Builtin));
        }
    }
}
