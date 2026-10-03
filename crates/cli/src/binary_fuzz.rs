// SPDX-License-Identifier: Apache-2.0

use crate::collector_run;
use crate::minimize::MinimizeStrategy;
use crate::runner::SandboxModeArg;
use crate::runtime_oracles::RuntimeOracles;
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

    /// Load the runtime sink oracles via the LD_PRELOAD runtrace shim (#59) so a
    /// clean-exit semantic violation — a fuzz-controlled command execution, path
    /// escape, dlopen, network egress, or SQL query — becomes a `binary_semantic`
    /// finding even when the target exits zero. `off` (default) is crash-only;
    /// `auto` enables them when the shim and platform (Linux) support it and skips
    /// otherwise; `on` requires them (errors if unavailable). Builtin engine only.
    #[arg(long = "runtime-oracles", value_enum, default_value_t = crate::runtime_oracles::RuntimeOracleMode::Off)]
    pub runtime_oracles: crate::runtime_oracles::RuntimeOracleMode,

    /// Shell command run BEFORE each testcase to prepare a fresh fixture (#55).
    /// Receives the testcase path as `$1` and `BHF_TESTCASE`/`BHF_CASE_DIR` in the
    /// environment. A non-zero exit is an infrastructure error (the case is
    /// skipped, not a finding).
    #[arg(long = "setup-command")]
    pub setup_command: Option<String>,

    /// Shell command run AFTER each testcase to check a user-defined security
    /// postcondition (#55) — e.g. "no file escaped the allowed root", "no
    /// unexpected child process". Receives the testcase path as `$1` plus
    /// `BHF_TESTCASE`, `BHF_CASE_DIR`, `BHF_TARGET_EXIT`, `BHF_TARGET_SIGNAL`,
    /// `BHF_TARGET_TIMEOUT`, and `BHF_TARGET_STDERR` (a file). Exit 0 = clean,
    /// exit 1 = finding (its first stdout line is the classification/signature),
    /// any other exit = infrastructure error. Fires even when the target exits 0.
    #[arg(long = "oracle-command")]
    pub oracle_command: Option<String>,

    /// Shell command run AFTER the oracle to reset state between testcases (#55),
    /// so filesystem/process/session effects do not leak across mutations.
    /// Receives the same `BHF_TESTCASE`/`BHF_CASE_DIR` context.
    #[arg(long = "reset-command")]
    pub reset_command: Option<String>,

    /// Runtime-event collector that observes process, filesystem, and module-load
    /// effects the target performs even on a clean exit (#60). `auto` picks the
    /// built-in provider for this platform (native Windows ETW; inactive on
    /// Linux); a PATH runs an external sidecar that speaks the
    /// bhf.collector-event.v1 JSONL protocol; `none` (default) disables it. A
    /// collected semantic violation — a controlled process exec, a path escaping
    /// the allowed root, or a controlled library load — becomes a
    /// `binary_semantic` finding (no crash needed), with the raw collector session
    /// stored for deterministic replay.
    #[arg(long = "collector", value_parser = crate::collector_run::parse_collector_spec, default_value = "none")]
    pub collector: crate::collector_run::CollectorSpec,

    /// How long, in milliseconds, to keep observing descendant-process effects
    /// after the testcase process exits — the bounded post-exit observation
    /// window (#60).
    #[arg(long = "collector-window-ms", default_value_t = crate::collector_run::DEFAULT_WINDOW_MS)]
    pub collector_window_ms: u64,
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
    let findings_dir = corpus::layout::findings_dir(&args.work_dir);
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
    // #55: user postconditions are a builtin-engine capability; the afl-qemu
    // adapter path is out of scope here.
    if args.oracle_command.is_some() && matches!(engine, ResolvedEngine::AflQemu(_)) {
        return Err(anyhow!(
            "--oracle-command (user postcondition oracles) is supported only with \
             --engine builtin; drop --oracle-command or pass --engine builtin"
        ));
    }
    match engine {
        ResolvedEngine::AflQemu(aq) => {
            return run_afl_qemu(&args, &aq, &seeds, &env, &findings_dir);
        }
        ResolvedEngine::Builtin => {}
    }

    let tmp_dir = args.work_dir.join("binary_fuzz/tmp");
    fs::create_dir_all(&tmp_dir).with_context(|| format!("create {}", tmp_dir.display()))?;

    // #59: resolve the runtime sink oracles for the builtin seed-replay engine.
    // `on` errors if the shim/platform is unavailable; `auto` quietly stays off.
    let oracles = RuntimeOracles::resolve(args.runtime_oracles, "reporting")?;
    let oracle_log = tmp_dir.join("runtrace.jsonl");
    let mut tracker = crate::auto::runtrace::SinkTaintTracker::default();
    // (oracle hit, representative testcase) pairs; deduped at emission.
    let mut semantic_hits: Vec<(finding_rules::oracle_sdk::OracleHit, Vec<u8>)> = Vec::new();

    // #55: user-defined postcondition oracle + per-case fixture hooks.
    let postcondition = Postcondition::from_args(&args);
    let case_dir = tmp_dir.join("case");
    let mut seen_postcondition = std::collections::HashSet::new();

    let mut finding_ids = Vec::new();
    let mut executions = 0usize;
    for seed in seeds.iter().cycle().take(args.iterations.min(seeds.len())) {
        executions += 1;
        // #55: prepare a fresh fixture directory and run the setup hook before the
        // target, so filesystem/process state does not leak across testcases.
        let case_testcase = if let Some(pc) = &postcondition {
            let _ = fs::remove_dir_all(&case_dir);
            fs::create_dir_all(&case_dir)
                .with_context(|| format!("create {}", case_dir.display()))?;
            let testcase_path = case_dir.join("testcase.bin");
            fs::write(&testcase_path, seed)
                .with_context(|| format!("write {}", testcase_path.display()))?;
            if let Some(detail) = pc.run_setup(&case_dir, &testcase_path) {
                bhfeprintln!("bhf binary-fuzz: skipping case (setup failed): {detail}");
                continue;
            }
            Some(testcase_path)
        } else {
            None
        };
        let oracle_arg = oracles.as_ref().map(|o| (o, oracle_log.as_path()));
        // When a postcondition is active the target also sees the per-case dir and
        // testcase path, so it can operate inside the fixture the oracle inspects
        // (keeping fuzz and replay consistent). Otherwise the user env is passed
        // unchanged.
        let run_env = match &case_testcase {
            Some(testcase_path) => {
                let mut e = env.clone();
                e.insert("BHF_CASE_DIR".to_owned(), case_dir.display().to_string());
                e.insert(
                    "BHF_TESTCASE".to_owned(),
                    testcase_path.display().to_string(),
                );
                e
            }
            None => env.clone(),
        };
        let run = run_binary_once(
            &invocation,
            args.input_mode,
            seed,
            &run_env,
            Duration::from_millis(args.timeout_ms),
            &tmp_dir,
            oracle_arg,
        )?;
        if oracles.is_some() {
            // Per-run oracle classes (TOCTOU, insecure perms, resource leak,
            // network egress, format string) fire on a single execution's events;
            // the taint-confirmed classes (command exec, path escape, dlopen, SQL)
            // are accumulated in the tracker and confirmed after the campaign.
            for hit in crate::auto::runtrace::oracle_hits_from_events(&run.oracle_events) {
                semantic_hits.push((hit, seed.clone()));
            }
            tracker.observe(&run.oracle_events, seed);
        }
        // #55: evaluate the user postcondition against the finished run; a finding
        // fires even on a clean target exit. Reset state afterwards.
        if let (Some(pc), Some(testcase_path)) = (&postcondition, &case_testcase) {
            match pc.evaluate(&case_dir, testcase_path, &run) {
                PostconditionVerdict::Clean => {}
                PostconditionVerdict::Infrastructure { detail } => {
                    bhfeprintln!("bhf binary-fuzz: postcondition oracle error: {detail}");
                }
                PostconditionVerdict::Finding { signature, detail } => {
                    if seen_postcondition.insert(signature.clone()) {
                        let id = next_binary_finding_id(&findings_dir)?;
                        let dir = findings_dir.join(&id);
                        fs::create_dir_all(&dir)
                            .with_context(|| format!("create {}", dir.display()))?;
                        fs::write(dir.join("testcase.bin"), seed).with_context(|| {
                            format!("write {}", dir.join("testcase.bin").display())
                        })?;
                        let finding = render_postcondition_finding(
                            &id, &args, seed, &env, &signature, &detail, &run,
                        )?;
                        fs::write(
                            dir.join("finding.json"),
                            serde_json::to_vec_pretty(&finding)?,
                        )
                        .with_context(|| format!("write {}", dir.join("finding.json").display()))?;
                        finding_ids.push(id);
                    }
                }
            }
            pc.run_reset(&case_dir, testcase_path);
        }
        if run.crashed() {
            let id = next_binary_finding_id(&findings_dir)?;
            let dir = findings_dir.join(&id);
            fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
            fs::write(dir.join("testcase.bin"), seed)
                .with_context(|| format!("write {}", dir.join("testcase.bin").display()))?;
            corpus::finding::write_sanitizer_log(&dir, run.stderr.as_bytes())?;
            let mut finding = render_finding(&id, &args, seed, &env, &run)?;
            corpus::finding::stamp_v1(&mut finding, corpus::finding::finding_kind::BINARY);
            fs::write(
                dir.join("finding.json"),
                serde_json::to_vec_pretty(&finding)?,
            )
            .with_context(|| format!("write {}", dir.join("finding.json").display()))?;
            finding_ids.push(id);
            break;
        }
    }

    // #59: emit semantic findings for every distinct oracle violation — these fire
    // even when the target exited zero on every input.
    if oracles.is_some() {
        for confirmed in tracker.into_confirmed() {
            if let Some(hit) = crate::auto::runtrace::confirmed_sink_hit(&confirmed) {
                semantic_hits.push((hit, confirmed.input.clone()));
            }
        }
        let mut seen = std::collections::HashSet::new();
        for (hit, input) in &semantic_hits {
            let signature = crate::runtime_oracles::oracle_signature(hit);
            if !seen.insert(signature.clone()) {
                continue;
            }
            let id = next_binary_finding_id(&findings_dir)?;
            let dir = findings_dir.join(&id);
            fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
            fs::write(dir.join("testcase.bin"), input)
                .with_context(|| format!("write {}", dir.join("testcase.bin").display()))?;
            let finding = render_semantic_finding(
                &id,
                &args,
                input,
                &env,
                hit,
                &signature,
                oracles.as_ref(),
            )?;
            fs::write(
                dir.join("finding.json"),
                serde_json::to_vec_pretty(&finding)?,
            )
            .with_context(|| format!("write {}", dir.join("finding.json").display()))?;
            finding_ids.push(id);
        }
    }

    // #60: run the platform-neutral runtime-event collector. A collected semantic
    // violation (controlled process exec / path escape / controlled library load)
    // becomes a `binary_semantic` finding through the SAME oracle registry, even
    // when every execution exited cleanly. Inactive (default) leaves behaviour
    // unchanged.
    let collector_provenance =
        match collector_run::resolve(&args.collector, args.collector_window_ms)? {
            None => collector_run::inactive_run_provenance(&args.collector),
            Some(resolved) => {
                let representative = seeds.first().cloned().unwrap_or_default();
                let outcome = if let Some(shim) = resolved.runtrace_shim() {
                    // Linux built-in provider: a dedicated observation pass runs the
                    // target once under the LD_PRELOAD runtrace shim and re-expresses
                    // its process/file/library effects as `bhf.collector-event.v1`
                    // via the runtrace→collector adapter. This pass is separate from
                    // the crash-detection loop, so `--runtime-oracles` behaviour is
                    // unchanged; it is an additional, collector-shaped view.
                    let col_log = tmp_dir.join("collector_runtrace.jsonl");
                    let run = run_binary_once(
                        &invocation,
                        args.input_mode,
                        &representative,
                        &env,
                        Duration::from_millis(args.timeout_ms),
                        &tmp_dir,
                        Some((shim, col_log.as_path())),
                    )?;
                    let adapter_ctx = crate::auto::runtrace::CollectorAdapterCtx {
                        testcase: "binary-fuzz".to_owned(),
                        worker: 0,
                        root_pid: 1,
                    };
                    let jsonl = crate::auto::runtrace::collector_jsonl_from_events(
                        &run.oracle_events,
                        &adapter_ctx,
                        &args.binary.display().to_string(),
                    );
                    resolved.evaluate_jsonl(&jsonl, &args.work_dir.display().to_string())
                } else {
                    let params = collector_run::CollectorRunParams {
                        testcase: "binary-fuzz".to_owned(),
                        worker: 0,
                        root: args.work_dir.display().to_string(),
                        root_pid: 0,
                        root_image: args.binary.display().to_string(),
                        input: &representative,
                        tmp_dir: tmp_dir.join("collector"),
                    };
                    resolved.run_once(&params)?
                };
                let target = collector_target(&args)?;
                for finding in &outcome.findings {
                    let id = collector_run::next_collector_finding_id(&findings_dir)?;
                    let dir = findings_dir.join(&id);
                    collector_run::write_finding(
                        &dir,
                        &id,
                        target.clone(),
                        finding,
                        &representative,
                    )?;
                    finding_ids.push(id);
                }
                outcome.run_provenance
            }
        };

    Ok(json!({
        "schema_version": "bhf.binary_fuzz.run.v1",
        "binary": args.binary,
        "input_mode": args.input_mode.as_str(),
        "executions": executions,
        "runtime_oracles": runtime_oracle_provenance(args.runtime_oracles, oracles.as_ref()),
        "collector": collector_provenance,
        "findings": finding_ids
    }))
}

/// Lane-specific target descriptor spliced into a collector finding so a reviewer
/// can see what ran.
fn collector_target(args: &BinaryFuzzArgs) -> anyhow::Result<Value> {
    Ok(json!({
        "kind": "binary",
        "binary": {
            "path": args.binary,
            "sha256": sha256_hex(&fs::read(&args.binary).with_context(|| format!("read {}", args.binary.display()))?),
        },
        "command": {
            "argv": TargetInvocation::from_args(args).provenance_argv(args.input_mode),
            "runner": args.runner,
            "runner_args": args.runner_args,
            "target_args": args.target_args,
            "sandbox": format!("{:?}", args.sandbox).to_ascii_lowercase(),
        }
    }))
}

/// Run-provenance for the runtime-oracle layer (#59): the requested mode, whether
/// it is active, and the shim hash when it is — so a crash-only run (shim/platform
/// unavailable) is distinguishable from one that evaluated the oracles.
fn runtime_oracle_provenance(
    mode: crate::runtime_oracles::RuntimeOracleMode,
    oracles: Option<&RuntimeOracles>,
) -> Value {
    json!({
        "mode": format!("{mode:?}").to_ascii_lowercase(),
        "active": oracles.is_some(),
        "shim_sha256": oracles.map(RuntimeOracles::shim_sha256),
    })
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
                None,
            )?;
            if !run.crashed() || !seen_signatures.insert(run.signature.clone()) {
                continue;
            }
            let id = next_binary_finding_id(findings_dir)?;
            let dir = findings_dir.join(&id);
            fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
            fs::write(dir.join("testcase.bin"), &input)?;
            corpus::finding::write_sanitizer_log(&dir, run.stderr.as_bytes())?;
            let mut finding = render_finding(&id, args, &input, env, &run)?;
            corpus::finding::stamp_v1(&mut finding, corpus::finding::finding_kind::BINARY);
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
            let _ = corpus::finding::touch_last_seen(finding_dir, "replay");
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
    let original = fs::read(finding_dir.join("testcase.bin"))
        .with_context(|| format!("read {}", finding_dir.join("testcase.bin").display()))?;
    let invocation = finding_invocation(&finding, binary);
    let tmp_dir = finding_dir.join("binary_minimize_tmp");
    fs::create_dir_all(&tmp_dir).with_context(|| format!("create {}", tmp_dir.display()))?;
    // Reduce against the finding's OWN oracle: a crash signature, a runtime-oracle
    // signature (#59), or a user postcondition signature (#55).
    let result = match finding.get("kind").and_then(Value::as_str) {
        Some("binary_postcondition") => {
            let want = finding
                .pointer("/postcondition/signature")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("postcondition finding is missing postcondition.signature"))?
                .to_owned();
            let pc = finding_postcondition(&finding)
                .ok_or_else(|| anyhow!("postcondition finding is missing oracle_command"))?;
            let case_dir = tmp_dir.join("case");
            replay_min::ddmin_bytes(&original, |candidate| -> anyhow::Result<bool> {
                let _ = fs::remove_dir_all(&case_dir);
                fs::create_dir_all(&case_dir)?;
                let testcase_path = case_dir.join("testcase.bin");
                fs::write(&testcase_path, candidate)?;
                if pc.run_setup(&case_dir, &testcase_path).is_some() {
                    return Ok(false);
                }
                let mut run_env = env.clone();
                run_env.insert("BHF_CASE_DIR".to_owned(), case_dir.display().to_string());
                run_env.insert(
                    "BHF_TESTCASE".to_owned(),
                    testcase_path.display().to_string(),
                );
                let run = run_binary_once(
                    &invocation,
                    mode,
                    candidate,
                    &run_env,
                    timeout,
                    &tmp_dir,
                    None,
                )?;
                let verdict = pc.evaluate(&case_dir, &testcase_path, &run);
                pc.run_reset(&case_dir, &testcase_path);
                Ok(
                    matches!(verdict, PostconditionVerdict::Finding { ref signature, .. } if *signature == want),
                )
            })?
        }
        Some("binary_semantic") => {
            let want = finding
                .pointer("/oracle/signature")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("semantic finding is missing oracle.signature"))?
                .to_owned();
            let oracles = RuntimeOracles::resolve(
                crate::runtime_oracles::RuntimeOracleMode::On,
                "reporting",
            )?
            .ok_or_else(|| anyhow!("runtime oracles unavailable for semantic minimization"))?;
            let log = tmp_dir.join("runtrace.jsonl");
            replay_min::ddmin_bytes(&original, |candidate| -> anyhow::Result<bool> {
                let run = run_binary_once(
                    &invocation,
                    mode,
                    candidate,
                    &env,
                    timeout,
                    &tmp_dir,
                    Some((&oracles, log.as_path())),
                )?;
                Ok(replay_oracle_signatures(&run.oracle_events, candidate).contains(&want))
            })?
        }
        _ => {
            let expected = finding_signature(&finding)?;
            replay_min::ddmin_bytes(&original, |candidate| -> anyhow::Result<bool> {
                let run =
                    run_binary_once(&invocation, mode, candidate, &env, timeout, &tmp_dir, None)?;
                Ok(signature_matches(&run, &expected))
            })?
        }
    };
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
    let mode = finding_input_mode(&finding)?;
    let env = finding_env(&finding);
    let timeout = finding_timeout(&finding);

    let matched = if finding.get("kind").and_then(Value::as_str) == Some("binary_semantic") {
        // #59: a semantic finding is reproduced by re-running under the runtime
        // oracles and confirming the SAME oracle signature fires — not a crash.
        let want = finding
            .pointer("/oracle/signature")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("semantic finding is missing oracle.signature"))?;
        let oracles =
            RuntimeOracles::resolve(crate::runtime_oracles::RuntimeOracleMode::On, "reporting")
                .with_context(|| {
                    "runtime oracles are required to replay a binary_semantic finding"
                })?
                .ok_or_else(|| {
                    anyhow!("runtime oracles unavailable (shim/platform) for semantic replay")
                })?;
        let log = tmp_dir.join("runtrace.jsonl");
        let run = run_binary_once(
            &invocation,
            mode,
            &input,
            &env,
            timeout,
            &tmp_dir,
            Some((&oracles, log.as_path())),
        )?;
        replay_oracle_signatures(&run.oracle_events, &input)
            .iter()
            .any(|s| s == want)
    } else if finding.get("kind").and_then(Value::as_str) == Some("binary_postcondition") {
        // #55: reproduce by re-running setup -> target -> oracle and confirming
        // the same postcondition signature fires.
        let want = finding
            .pointer("/postcondition/signature")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("postcondition finding is missing postcondition.signature"))?;
        let pc = finding_postcondition(&finding).ok_or_else(|| {
            anyhow!("postcondition finding is missing postcondition.oracle_command")
        })?;
        let case_dir = tmp_dir.join("case");
        fs::create_dir_all(&case_dir).with_context(|| format!("create {}", case_dir.display()))?;
        let testcase_path = case_dir.join("testcase.bin");
        fs::write(&testcase_path, &input)
            .with_context(|| format!("write {}", testcase_path.display()))?;
        if let Some(detail) = pc.run_setup(&case_dir, &testcase_path) {
            let _ = fs::remove_dir_all(&tmp_dir);
            return Err(anyhow!("postcondition replay setup failed: {detail}"));
        }
        let mut run_env = env.clone();
        run_env.insert("BHF_CASE_DIR".to_owned(), case_dir.display().to_string());
        run_env.insert(
            "BHF_TESTCASE".to_owned(),
            testcase_path.display().to_string(),
        );
        let run = run_binary_once(&invocation, mode, &input, &run_env, timeout, &tmp_dir, None)?;
        let verdict = pc.evaluate(&case_dir, &testcase_path, &run);
        pc.run_reset(&case_dir, &testcase_path);
        matches!(verdict, PostconditionVerdict::Finding { ref signature, .. } if signature == want)
    } else {
        let run = run_binary_once(&invocation, mode, &input, &env, timeout, &tmp_dir, None)?;
        signature_matches(&run, &finding_signature(&finding)?)
    };
    let _ = fs::remove_dir_all(&tmp_dir);
    Ok(matched)
}

/// Whether a replayed run reproduces a stored crash signature, in its
/// current (normalized) form or the legacy raw-stderr form.
fn signature_matches(run: &BinaryRun, expected: &str) -> bool {
    run.signature == expected
        || legacy_crash_signature(run.timeout, run.signal, run.exit_code, &run.stderr) == expected
}

/// Every oracle signature one execution's events yield — the per-run oracle
/// classes plus the taint-confirmed sinks (confirmed from this single execution's
/// taint, which is sufficient to reproduce a recorded violation). Used by
/// semantic replay/minimize to match a finding's recorded `oracle.signature`.
fn replay_oracle_signatures(
    events: &[crate::auto::runtrace::RuntraceEvent],
    input: &[u8],
) -> Vec<String> {
    use crate::auto::runtrace;
    let mut sigs: Vec<String> = runtrace::oracle_hits_from_events(events)
        .iter()
        .map(crate::runtime_oracles::oracle_signature)
        .collect();
    let mut tracker = runtrace::SinkTaintTracker::default();
    tracker.observe(events, input);
    for confirmed in tracker.into_confirmed() {
        if let Some(hit) = runtrace::confirmed_sink_hit(&confirmed) {
            sigs.push(crate::runtime_oracles::oracle_signature(&hit));
        }
    }
    sigs
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
    /// Runtrace events captured this execution when runtime oracles were armed
    /// (#59); empty otherwise. Fed to the per-run oracle registry and the
    /// cross-execution taint tracker by the caller.
    oracle_events: Vec<crate::auto::runtrace::RuntraceEvent>,
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

/// Open `path` read-only as an fd the spawned child will INHERIT (no close-on-exec)
/// so the runtrace shim can `mmap` it as the published fuzz input (#59). Returns
/// `None` off Unix or on error.
#[cfg(unix)]
fn open_inheritable_ro(path: &Path) -> Option<i32> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // O_RDONLY with no O_CLOEXEC — the fd survives fork+exec into the child.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
    (fd >= 0).then_some(fd)
}

#[cfg(not(unix))]
fn open_inheritable_ro(_path: &Path) -> Option<i32> {
    None
}

#[cfg(unix)]
fn close_fd(fd: i32) {
    unsafe {
        libc::close(fd);
    }
}

#[cfg(not(unix))]
fn close_fd(_fd: i32) {}

fn run_binary_once(
    inv: &TargetInvocation,
    mode: BinaryInputMode,
    input: &[u8],
    env: &BTreeMap<String, String>,
    timeout: Duration,
    tmp_dir: &Path,
    oracle: Option<(&RuntimeOracles, &Path)>,
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

    // #59: arm the runtime sink oracles for this execution — truncate the per-exec
    // audit log, set LD_PRELOAD/BHF_RUNTRACE_*, and publish the input bytes to the
    // shim through an inherited, mmap-able fd (BHF_FUZZ_INPUT_FD/LEN) so byte-origin
    // taint confirmation stays valid for a black-box target that never calls
    // `bhf_shim_set_fuzz_input` itself.
    let mut published_fd: Option<i32> = None;
    let mut fuzz_input_file: Option<PathBuf> = None;
    if let Some((oracles, log)) = oracle {
        let _ = fs::write(log, b"");
        oracles.apply(&mut cmd, log);
        if !input.is_empty() {
            let fuzz_path = match &input_file {
                Some(path) => path.clone(),
                None => {
                    let path = tmp_dir.join(format!("fuzzinput-{}.bin", nonce()));
                    fs::write(&path, input).with_context(|| format!("write {}", path.display()))?;
                    fuzz_input_file = Some(path.clone());
                    path
                }
            };
            if let Some(fd) = open_inheritable_ro(&fuzz_path) {
                cmd.env("BHF_FUZZ_INPUT_FD", fd.to_string());
                cmd.env("BHF_FUZZ_INPUT_LEN", input.len().to_string());
                published_fd = Some(fd);
            }
        }
    }

    let spawned = cmd.spawn();
    // The child has forked with its own copy of the fd; drop the parent's.
    if let Some(fd) = published_fd {
        close_fd(fd);
    }
    let mut child = spawned.with_context(|| format!("spawn {}", program.display()))?;
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
    let input_path = input_file
        .as_ref()
        .map(|path| path.to_string_lossy().into_owned());
    if let Some(path) = input_file {
        let _ = fs::remove_file(path);
    }
    if let Some(path) = fuzz_input_file {
        let _ = fs::remove_file(path);
    }
    let exit_code = output.status.code();
    let signal = termination_signal(&output.status);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let signature = crash_signature(timed_out, signal, exit_code, &stderr, input_path.as_deref());
    let oracle_events = match oracle {
        Some((_, log)) => {
            let mut events = crate::auto::runtrace::parse_log(log).unwrap_or_default();
            crate::auto::runtrace::dedupe_in_place(&mut events);
            events
        }
        None => Vec::new(),
    };
    Ok(BinaryRun {
        exit_code,
        signal,
        timeout: timed_out,
        stderr,
        signature,
        oracle_events,
    })
}

/// `timeout`, `signal:<n>:<digest>` or `exit:<code>:<digest>`, where the
/// digest is over stderr with run-specific noise removed, so the same crash
/// keeps its signature across runs (replay matching, cross-run identity).
fn crash_signature(
    timed_out: bool,
    signal: Option<i32>,
    exit_code: Option<i32>,
    stderr: &str,
    input_path: Option<&str>,
) -> String {
    let digest = sha256_hex(signature_stderr(stderr, input_path).as_bytes());
    if timed_out {
        "timeout".to_owned()
    } else if let Some(sig) = signal {
        // Distinguish crash signals (SIGSEGV vs SIGABRT ...) instead of
        // collapsing every signal into exit:-1.
        format!("signal:{sig}:{digest}")
    } else {
        format!("exit:{}:{digest}", exit_code.unwrap_or(-1))
    }
}

/// The signature format before stderr was normalized: the digest of the raw
/// stderr. Binary findings recorded then still store it, so replay and
/// minimization accept it too; never written for new findings.
fn legacy_crash_signature(
    timed_out: bool,
    signal: Option<i32>,
    exit_code: Option<i32>,
    stderr: &str,
) -> String {
    let digest = sha256_hex(stderr.as_bytes());
    if timed_out {
        "timeout".to_owned()
    } else if let Some(sig) = signal {
        format!("signal:{sig}:{digest}")
    } else {
        format!("exit:{}:{digest}", exit_code.unwrap_or(-1))
    }
}

/// Stderr as hashed into a crash signature: the run's own input file (a
/// fresh `input-<nanos>.bin` per run, which targets often echo) becomes
/// `<input>`, sanitizer `==<pid>==` markers are removed, and absolute
/// pc/heap/stack addresses are replaced, since all of these change per run.
/// Module offsets (`(/bin/target+0x1a2b3c)`) are kept: they are stable, and
/// in a stripped binary they are the only crash-site identity.
fn signature_stderr(stderr: &str, input_path: Option<&str>) -> String {
    let mut text = stderr.to_owned();
    if let Some(path) = input_path.filter(|path| !path.is_empty()) {
        text = text.replace(path, "<input>");
        if let Some(name) = Path::new(path).file_name().and_then(|name| name.to_str()) {
            text = text.replace(name, "<input>");
        }
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(at) = rest.find("==") {
        let after = &rest[at + 2..];
        let digits = after.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0 && after[digits..].starts_with("==") {
            out.push_str(&rest[..at]);
            rest = &after[digits + 2..];
        } else {
            out.push_str(&rest[..at + 2]);
            rest = after;
        }
    }
    out.push_str(rest);
    results::normalize::strip_addresses_keep_offsets(&out)
}

/// A user-defined postcondition oracle plus fixture hooks for binary fuzz (#55):
/// a `setup` run before each testcase, an `oracle` run after it (whose exit code
/// classifies the outcome), and a `reset` run afterwards. Lets a source-
/// unavailable target be judged against a security invariant it can violate while
/// still exiting 0 (a file escaping an allowed root, an unexpected child process,
/// an unauthorized operation).
#[derive(Debug, Clone)]
struct Postcondition {
    setup: Option<String>,
    oracle: String,
    reset: Option<String>,
}

/// The classification of one testcase's postcondition evaluation, from the
/// oracle command's exit code: 0 = clean, 1 = finding (first stdout line is the
/// signature/classification), anything else = infrastructure error (not a target
/// defect — the oracle itself failed).
enum PostconditionVerdict {
    Clean,
    Finding { signature: String, detail: String },
    Infrastructure { detail: String },
}

impl Postcondition {
    fn from_args(args: &BinaryFuzzArgs) -> Option<Self> {
        args.oracle_command.as_ref().map(|oracle| Self {
            setup: args.setup_command.clone(),
            oracle: oracle.clone(),
            reset: args.reset_command.clone(),
        })
    }

    /// Prepare the fixture. `Some(detail)` is an infrastructure failure (skip the
    /// case); `None` means setup is absent or succeeded.
    fn run_setup(&self, case_dir: &Path, testcase: &Path) -> Option<String> {
        let cmd = self.setup.as_deref()?;
        match run_shell_hook(cmd, case_dir, testcase, &[]) {
            Ok(out) if out.status.success() => None,
            Ok(out) => Some(format!("setup-command exited {}", exit_label(&out.status))),
            Err(e) => Some(format!("setup-command failed to spawn: {e}")),
        }
    }

    /// Evaluate the postcondition against a finished target run.
    fn evaluate(&self, case_dir: &Path, testcase: &Path, run: &BinaryRun) -> PostconditionVerdict {
        let stderr_path = case_dir.join("target.stderr");
        let _ = fs::write(&stderr_path, run.stderr.as_bytes());
        let extra = [
            (
                "BHF_TARGET_EXIT",
                run.exit_code.map(|c| c.to_string()).unwrap_or_default(),
            ),
            (
                "BHF_TARGET_SIGNAL",
                run.signal.map(|s| s.to_string()).unwrap_or_default(),
            ),
            (
                "BHF_TARGET_TIMEOUT",
                if run.timeout { "1" } else { "0" }.to_owned(),
            ),
            ("BHF_TARGET_STDERR", stderr_path.display().to_string()),
        ];
        let out = match run_shell_hook(&self.oracle, case_dir, testcase, &extra) {
            Ok(out) => out,
            Err(e) => {
                return PostconditionVerdict::Infrastructure {
                    detail: format!("oracle-command failed to spawn: {e}"),
                }
            }
        };
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        match out.status.code() {
            Some(0) => PostconditionVerdict::Clean,
            Some(1) => {
                let signature = stdout
                    .lines()
                    .map(str::trim)
                    .find(|l| !l.is_empty())
                    .unwrap_or("postcondition-violation")
                    .to_owned();
                PostconditionVerdict::Finding {
                    signature,
                    detail: stdout,
                }
            }
            other => PostconditionVerdict::Infrastructure {
                detail: format!(
                    "oracle-command exited {} (expected 0=clean, 1=finding)",
                    other
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| exit_label(&out.status))
                ),
            },
        }
    }

    fn run_reset(&self, case_dir: &Path, testcase: &Path) {
        if let Some(cmd) = self.reset.as_deref() {
            let _ = run_shell_hook(cmd, case_dir, testcase, &[]);
        }
    }
}

/// Run a user hook as `sh -c <cmd> sh <testcase>` (so the hook sees the testcase
/// path as `$1`), in `case_dir`, with the fixture/target context in the
/// environment. stdin is closed; stdout/stderr are captured for classification.
fn run_shell_hook(
    cmd: &str,
    case_dir: &Path,
    testcase: &Path,
    extra_env: &[(&str, String)],
) -> std::io::Result<std::process::Output> {
    let mut c = Command::new("sh");
    c.arg("-c")
        .arg(cmd)
        .arg("sh")
        .arg(testcase)
        .current_dir(case_dir)
        .env("BHF_TESTCASE", testcase)
        .env("BHF_CASE_DIR", case_dir)
        .stdin(Stdio::null());
    for (key, value) in extra_env {
        c.env(key, value);
    }
    c.output()
}

/// A short human label for a process exit (signal or code), for diagnostics.
fn exit_label(status: &std::process::ExitStatus) -> String {
    if let Some(sig) = termination_signal(status) {
        format!("signal {sig}")
    } else {
        format!("code {}", status.code().unwrap_or(-1))
    }
}

fn render_finding(
    id: &str,
    args: &BinaryFuzzArgs,
    input: &[u8],
    env: &BTreeMap<String, String>,
    run: &BinaryRun,
) -> anyhow::Result<Value> {
    let build_identity = binary_analysis::build_identity(&args.binary);
    let build_id = build_identity.as_ref().and_then(|id| id.build_id.clone());
    Ok(json!({
        "id": id,
        "kind": "binary_crash",
        "rule_id": "BHF-501",
        "severity": "high",
        "confidence": "high",
        "message": "Binary crashed under BHF binary-fuzz",
        "binary": {
            "path": args.binary,
            "sha256": sha256_hex(&fs::read(&args.binary).with_context(|| format!("read {}", args.binary.display()))?),
            "build_id": build_id
        },
        "build": {
            "binary": build_identity
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
            "testcase": "testcase.bin",
            "sanitizer_log": "sanitizer.log"
        },
        "triage": {
            "replay": format!("bhf replay --harness {} {}", args.binary.display(), id)
        }
    }))
}

/// Render a `binary_semantic` finding (#59) for a runtime sink-oracle violation —
/// a clean-exit defect the crash oracle cannot see. Mirrors the crash finding's
/// command/input/binary provenance and adds the oracle rule, evidence, and the
/// `oracle_signature` that `bhf replay`/`minimize` match on.
fn render_semantic_finding(
    id: &str,
    args: &BinaryFuzzArgs,
    input: &[u8],
    env: &BTreeMap<String, String>,
    hit: &finding_rules::oracle_sdk::OracleHit,
    signature: &str,
    oracles: Option<&RuntimeOracles>,
) -> anyhow::Result<Value> {
    let evidence: serde_json::Map<String, Value> = hit
        .evidence
        .iter()
        .map(|e| (e.key.clone(), Value::String(e.value.clone())))
        .collect();
    Ok(json!({
        "id": id,
        "kind": "binary_semantic",
        "rule_id": hit.rule_id,
        "classification": "oracle_hit",
        "confirmation": "runtime",
        "severity": "high",
        "confidence": "high",
        "message": hit.message,
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
        "oracle": {
            "name": hit.oracle_name,
            "category": hit.category,
            "api": hit.api,
            "message": hit.message,
            "evidence": evidence,
            "signature": signature
        },
        "runtime_oracles": runtime_oracle_provenance(args.runtime_oracles, oracles),
        "paths": {
            "testcase": "testcase.bin"
        },
        "triage": {
            "replay": format!("bhf replay --harness {} {}", args.binary.display(), id)
        }
    }))
}

/// Render a `binary_postcondition` finding (#55): a user-defined security
/// invariant the `--oracle-command` reported violated, even if the target exited
/// cleanly. Records the hook commands + signature so `bhf replay`/`minimize`
/// re-evaluate the postcondition rather than a crash signature.
fn render_postcondition_finding(
    id: &str,
    args: &BinaryFuzzArgs,
    input: &[u8],
    env: &BTreeMap<String, String>,
    signature: &str,
    detail: &str,
    run: &BinaryRun,
) -> anyhow::Result<Value> {
    Ok(json!({
        "id": id,
        "kind": "binary_postcondition",
        "rule_id": "BHF-502",
        "classification": "postcondition_violation",
        "confirmation": "runtime",
        "severity": "high",
        "confidence": "high",
        "message": format!("user postcondition violated: {signature}"),
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
        "postcondition": {
            "setup_command": args.setup_command,
            "oracle_command": args.oracle_command,
            "reset_command": args.reset_command,
            "signature": signature,
            "detail_excerpt": stderr_excerpt(detail)
        },
        "input": {
            "mode": args.input_mode.as_str(),
            "bytes": input.len(),
            "testcase": "testcase.bin"
        },
        "env": env,
        "target_status": {
            "exit_code": run.exit_code,
            "signal": run.signal,
            "timeout": run.timeout
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

/// Rebuild the user postcondition hooks from a `binary_postcondition` finding for
/// replay/minimize. `None` when no oracle command was recorded.
fn finding_postcondition(finding: &Value) -> Option<Postcondition> {
    let oracle = finding
        .pointer("/postcondition/oracle_command")?
        .as_str()?
        .to_owned();
    let hook = |ptr: &str| {
        finding
            .pointer(ptr)
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    Some(Postcondition {
        setup: hook("/postcondition/setup_command"),
        oracle,
        reset: hook("/postcondition/reset_command"),
    })
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
    corpus::finding::append_history(
        &mut value,
        "minimize",
        &["paths.minimized", "minimal_reproducer", "minimization"],
    );
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
            oracle_events: Vec::new(),
        }
    }

    #[test]
    fn collector_flag_parses_auto_none_path_and_window() {
        use clap::Parser;
        #[derive(clap::Parser)]
        struct Wrap {
            #[command(flatten)]
            inner: BinaryFuzzArgs,
        }
        // Default: off, 250ms — a plain run must be byte-for-byte unchanged.
        let w = Wrap::try_parse_from(["bf", "/bin/true"]).unwrap();
        assert_eq!(
            w.inner.collector,
            crate::collector_run::CollectorSpec::Off,
            "collector defaults to none"
        );
        assert_eq!(w.inner.collector_window_ms, 250, "window defaults to 250ms");

        let w = Wrap::try_parse_from(["bf", "/bin/true", "--collector", "auto"]).unwrap();
        assert_eq!(w.inner.collector, crate::collector_run::CollectorSpec::Auto);

        let w = Wrap::try_parse_from([
            "bf",
            "/bin/true",
            "--collector",
            "/opt/probe",
            "--collector-window-ms",
            "500",
        ])
        .unwrap();
        assert_eq!(
            w.inner.collector,
            crate::collector_run::CollectorSpec::Sidecar(PathBuf::from("/opt/probe"))
        );
        assert_eq!(w.inner.collector_window_ms, 500);
    }

    #[test]
    fn crash_signature_ignores_pids_and_addresses() {
        let first = "==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010 at pc 0x55d4c3a1b2c3\n    #0 0x55d4c3a1b2c3 in parse /src/p.c:9\n==12345==ABORTING\n";
        let second = "==999==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x603000000a20 at pc 0x561234abcdef\n    #0 0x561234abcdef in parse /src/p.c:9\n==999==ABORTING\n";
        assert_eq!(
            crash_signature(false, Some(6), None, first, None),
            crash_signature(false, Some(6), None, second, None)
        );
        assert_ne!(
            crash_signature(false, Some(6), None, first, None),
            crash_signature(false, Some(6), None, &first.replace("parse", "other"), None),
            "a different crash site is a different signature"
        );
        assert!(crash_signature(false, Some(11), None, first, None).starts_with("signal:11:"));
        assert!(crash_signature(false, None, Some(1), first, None).starts_with("exit:1:"));
        assert_eq!(crash_signature(true, Some(9), None, first, None), "timeout");
    }

    #[test]
    fn replay_matches_legacy_and_normalized_signatures() {
        let stderr = "==12345==ERROR: AddressSanitizer: SEGV on unknown address 0x602000000010\n==12345==ABORTING\n";
        let run = BinaryRun {
            exit_code: None,
            signal: Some(6),
            timeout: false,
            stderr: stderr.to_owned(),
            signature: crash_signature(false, Some(6), None, stderr, None),
            oracle_events: Vec::new(),
        };
        // Pre-normalization findings stored the digest of the raw stderr.
        let legacy = format!("signal:6:{}", sha256_hex(stderr.as_bytes()));
        assert!(signature_matches(&run, &legacy), "identical raw stderr");

        let earlier = stderr
            .replace("12345", "999")
            .replace("0x602000000010", "0x603000000a20");
        assert!(
            signature_matches(&run, &crash_signature(false, Some(6), None, &earlier, None)),
            "normalized form ignores PIDs and addresses"
        );
        assert!(
            !signature_matches(
                &run,
                &format!("signal:6:{}", sha256_hex(earlier.as_bytes()))
            ),
            "the legacy form still needs identical raw stderr"
        );
        assert!(!signature_matches(
            &run,
            &format!("signal:11:{}", sha256_hex(stderr.as_bytes()))
        ));
    }

    #[test]
    fn crash_signature_keeps_module_offsets() {
        // An unsymbolized frame: the absolute pc moves per run (ASLR), the
        // module offset is the crash site.
        let first = "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x55d4c3a1b2c3 bp 0x7ffd5e8c1234 sp 0x7ffd5e8c1200 T0)\n    #0 0x55d4c3a1b2c3  (/bin/target+0x1a2b3c)\n";
        let other_site = first.replace("+0x1a2b3c", "+0x1a2f00");
        assert_ne!(
            crash_signature(false, Some(11), None, first, None),
            crash_signature(false, Some(11), None, &other_site, None),
            "a different module offset is a different crash"
        );
        let rerun = first
            .replace("==1==", "==4242==")
            .replace("0x55d4c3a1b2c3", "0x561234abcdef")
            .replace("0x7ffd5e8c1234", "0x7fff00001234")
            .replace("0x7ffd5e8c1200", "0x7fff00001200");
        assert_eq!(
            crash_signature(false, Some(11), None, first, None),
            crash_signature(false, Some(11), None, &rerun, None),
            "pid and absolute addresses are run noise"
        );
    }

    #[test]
    fn signature_stderr_keeps_offsets_after_plus() {
        assert_eq!(
            signature_stderr("#0 0x55d4c3a1b2c3 (/bin/t+0x1a2b3c)", None),
            "#0 0x… (/bin/t+0x1a2b3c)"
        );
        assert_eq!(
            signature_stderr("+0xdeadbeef00 0xdeadbeef00", None),
            "+0xdeadbeef00 0x…"
        );
    }

    #[test]
    fn crash_signature_ignores_the_per_run_input_path() {
        let run = |nanos: &str| {
            let path = format!("/w/binary_fuzz/tmp/input-{nanos}.bin");
            let stderr = format!(
                "{path}: bad magic\nopen(input-{nanos}.bin) ok\n==7==ERROR: SEGV in parse\n"
            );
            crash_signature(false, Some(11), None, &stderr, Some(&path))
        };
        assert_eq!(run("111"), run("222"));
        assert_eq!(
            signature_stderr("x /t/input-1.bin y input-1.bin", Some("/t/input-1.bin")),
            "x <input> y <input>"
        );
    }

    #[test]
    fn signature_stderr_drops_only_pid_markers() {
        assert_eq!(signature_stderr("==42==ERROR: boom", None), "ERROR: boom");
        assert_eq!(signature_stderr("x ==7== y ==7==", None), "x  y ");
        assert_eq!(signature_stderr("a == 3 == b", None), "a == 3 == b");
        assert_eq!(signature_stderr("==ab== ====", None), "==ab== ====");
        assert_eq!(signature_stderr("ptr 0xdeadbeef00", None), "ptr 0x…");
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
            None,
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
            runtime_oracles: crate::runtime_oracles::RuntimeOracleMode::Off,
            setup_command: None,
            oracle_command: None,
            reset_command: None,
            collector: crate::collector_run::CollectorSpec::Off,
            collector_window_ms: crate::collector_run::DEFAULT_WINDOW_MS,
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
        let fdir = corpus::layout::findings_dir(&work).join(id);
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

    // --- #59: runtime sink oracles in binary fuzz ---

    /// Runtime oracles need Linux, the runtrace shim built, and `cc` to build the
    /// C fixture. Returns false (skip) when any is missing.
    #[cfg(unix)]
    fn runtime_oracle_e2e_ready() -> bool {
        cfg!(target_os = "linux")
            && crate::auto::shim_path::locate().is_some()
            && Command::new("cc")
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
    }

    /// End-to-end proof of binary-fuzz runtime sink oracles (#59): a C target that
    /// passes its fuzz-controlled input into `system()` exits 0, yet must produce a
    /// `binary_semantic` command-execution finding (BHF-431) — and that finding
    /// must replay to a match under the oracles.
    #[cfg(unix)]
    #[test]
    fn binary_fuzz_runtime_oracle_flags_clean_exit_command_injection() {
        use std::os::unix::fs::PermissionsExt;
        if !runtime_oracle_e2e_ready() {
            eprintln!("skipping binary-fuzz runtime-oracle e2e: shim/cc/Linux unavailable");
            return;
        }
        let dir = std::env::temp_dir().join(format!("bhf-binfuzz-oracle-{}", nonce()));
        fs::create_dir_all(&dir).unwrap();
        let src = dir.join("sink.c");
        // Reads the input file (file mode) and passes it, unsanitized, into
        // system() — a clean-exit command injection the crash oracle cannot see.
        fs::write(
            &src,
            b"#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\
              int main(int argc, char **argv){\n\
              \x20 char buf[256]; buf[0]=0;\n\
              \x20 if(argc>1){ FILE*f=fopen(argv[1],\"rb\"); if(f){ size_t n=fread(buf,1,255,f); buf[n]=0; fclose(f);} }\n\
              \x20 char cmd[512]; snprintf(cmd,sizeof cmd,\"/bin/echo %s\", buf);\n\
              \x20 system(cmd);\n\
              \x20 return 0;\n }\n",
        )
        .unwrap();
        let bin = dir.join("sink");
        let built = Command::new("cc")
            .arg("-O0")
            .arg(&src)
            .arg("-o")
            .arg(&bin)
            .output()
            .expect("cc");
        assert!(
            built.status.success(),
            "cc failed: {}",
            String::from_utf8_lossy(&built.stderr)
        );
        let _ = fs::set_permissions(&bin, fs::Permissions::from_mode(0o755));

        let work = dir.join("work");
        fs::create_dir_all(&work).unwrap();
        let args = BinaryFuzzArgs {
            binary: bin.clone(),
            work_dir: work.clone(),
            input_mode: BinaryInputMode::File,
            iterations: 2,
            // A >=4-byte contiguous run so the shim's taint sees it in the command.
            seed_inputs: vec!["AAAACCCC".to_owned()],
            seed_files: Vec::new(),
            timeout_ms: 10_000,
            mem_mb: "none".to_owned(),
            env: Vec::new(),
            runner: None,
            runner_args: Vec::new(),
            target_args: Vec::new(),
            sandbox: SandboxModeArg::Auto,
            engine: BinaryFuzzEngine::Builtin,
            time: None,
            runtime_oracles: crate::runtime_oracles::RuntimeOracleMode::On,
            setup_command: None,
            oracle_command: None,
            reset_command: None,
            collector: crate::collector_run::CollectorSpec::Off,
            collector_window_ms: crate::collector_run::DEFAULT_WINDOW_MS,
        };
        let summary = run_inner(args).expect("binary fuzz run");
        let ids = summary["findings"].as_array().expect("findings array");
        assert!(
            summary.pointer("/runtime_oracles/active") == Some(&json!(true)),
            "oracles must be active: {summary}"
        );

        // Find a binary_semantic command-execution finding.
        let findings_dir = corpus::layout::findings_dir(&work);
        let mut semantic: Option<PathBuf> = None;
        for id in ids {
            let fdir = findings_dir.join(id.as_str().unwrap());
            let f: Value =
                serde_json::from_slice(&fs::read(fdir.join("finding.json")).unwrap()).unwrap();
            if f.get("kind").and_then(Value::as_str) == Some("binary_semantic")
                && f.get("rule_id").and_then(Value::as_str) == Some("BHF-431")
            {
                // The fuzz input reached a shell-execution API on a clean exit.
                assert_eq!(
                    f.pointer("/oracle/evidence/controlled")
                        .and_then(Value::as_str),
                    Some("true"),
                    "the command-exec finding must be taint-confirmed: {f}"
                );
                semantic = Some(fdir);
                break;
            }
        }
        let fdir = semantic.unwrap_or_else(|| {
            panic!("expected a binary_semantic BHF-431 command-exec finding, got {summary}")
        });

        // The finding replays to a match under the oracles.
        assert_eq!(
            replay_binary_finding(&fdir, &bin),
            0,
            "semantic finding must replay to a match"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// End-to-end proof of the Linux `--collector auto` built-in provider (#60): a
    /// clean-exit C target whose fuzz-controlled input flows into `system()`, a
    /// destructive filesystem op (`remove`) and `dlopen()` must, with
    /// `--collector auto` (and `--runtime-oracles off`), produce three
    /// collector-sourced `binary_semantic` findings — process-exec (BHF-431),
    /// path-control (BHF-440, a fuzz-controlled path reaching a destructive FS API)
    /// and controlled-library-load (BHF-435) — through the runtrace→collector
    /// adapter, with no crash. A fixed-constant variant must produce none of them.
    /// This mirrors the mock-collector contract test on the real shim.
    ///
    /// Note: the file-open path oracle (BHF-405) taints via the shim's
    /// whole-value `taint_span`, which only consults a harness-published
    /// `LIVE_INPUT`; a black-box `bhf binary fuzz` target publishes its input
    /// through the shared memfd instead, which backs the `input_derived_run`
    /// (embedded-run) sinks — command, library, network, SQL and destructive-FS.
    /// So the taint-confirmed path-control class a black-box binary demonstrates is
    /// BHF-440, not BHF-405 (which the mock exercises directly).
    #[cfg(unix)]
    #[test]
    fn binary_fuzz_collector_auto_flags_three_clean_exit_classes_on_linux() {
        use std::os::unix::fs::PermissionsExt;
        if !runtime_oracle_e2e_ready() {
            eprintln!("skipping collector-auto e2e: shim/cc/Linux unavailable");
            return;
        }

        // Collector rule ids -> COL findings for a given target + seed.
        fn collector_rule_ids(bin: &Path, seed: &str, work: &Path) -> Vec<String> {
            let args = BinaryFuzzArgs {
                binary: bin.to_path_buf(),
                work_dir: work.to_path_buf(),
                input_mode: BinaryInputMode::File,
                iterations: 1,
                seed_inputs: vec![seed.to_owned()],
                seed_files: Vec::new(),
                timeout_ms: 10_000,
                mem_mb: "none".to_owned(),
                env: Vec::new(),
                runner: None,
                runner_args: Vec::new(),
                target_args: Vec::new(),
                sandbox: SandboxModeArg::Auto,
                engine: BinaryFuzzEngine::Builtin,
                time: None,
                // Runtime oracles OFF: the collector is an independent view.
                runtime_oracles: crate::runtime_oracles::RuntimeOracleMode::Off,
                setup_command: None,
                oracle_command: None,
                reset_command: None,
                collector: crate::collector_run::CollectorSpec::Auto,
                collector_window_ms: crate::collector_run::DEFAULT_WINDOW_MS,
            };
            let summary = run_inner(args).expect("binary fuzz run");
            assert_eq!(
                summary.pointer("/collector/active"),
                Some(&json!(true)),
                "the Linux built-in collector must be active: {summary}"
            );
            assert_eq!(
                summary.pointer("/collector/mode"),
                Some(&json!("runtrace")),
                "auto must resolve to the runtrace backend on Linux: {summary}"
            );
            // #59 oracle findings must stay off (runtime-oracles off).
            assert_eq!(
                summary.pointer("/runtime_oracles/active"),
                Some(&json!(false)),
                "runtime oracles must be inactive: {summary}"
            );
            let findings_dir = corpus::layout::findings_dir(work);
            let ids = summary["findings"].as_array().expect("findings array");
            let mut rules = Vec::new();
            for id in ids {
                let id = id.as_str().unwrap();
                let fdir = findings_dir.join(id);
                let f: Value =
                    serde_json::from_slice(&fs::read(fdir.join("finding.json")).unwrap()).unwrap();
                // Only collector-sourced semantic findings carry the `collector`
                // provenance block.
                if f.get("kind").and_then(Value::as_str) == Some("binary_semantic")
                    && f.get("collector").is_some()
                {
                    if let Some(rule) = f.get("rule_id").and_then(Value::as_str) {
                        rules.push(rule.to_owned());
                    }
                }
            }
            rules
        }

        let dir = std::env::temp_dir().join(format!("bhf-binfuzz-collector-{}", nonce()));
        fs::create_dir_all(&dir).unwrap();

        // Positive target: fuzz-controlled input reaches exec / open / dlopen.
        let src = dir.join("sinks.c");
        fs::write(
            &src,
            b"#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\
              #include <fcntl.h>\n#include <unistd.h>\n#include <dlfcn.h>\n\
              int main(int argc, char **argv){\n\
              \x20 char buf[256]; buf[0]=0;\n\
              \x20 if(argc>1){ FILE*f=fopen(argv[1],\"rb\"); if(f){ size_t n=fread(buf,1,255,f); buf[n]=0; fclose(f);} }\n\
              \x20 size_t L=strlen(buf); while(L>0 && (buf[L-1]=='\\n'||buf[L-1]=='\\r')) buf[--L]=0;\n\
              \x20 char cmd[512]; snprintf(cmd,sizeof cmd,\"/bin/echo %s\", buf); system(cmd);\n\
              \x20 char p[512]; snprintf(p,sizeof p,\"/tmp/bhf-col-%s\", buf); remove(p);\n\
              \x20 char lb[512]; snprintf(lb,sizeof lb,\"/tmp/%s.so\", buf); void*h=dlopen(lb,RTLD_NOW); if(h) dlclose(h);\n\
              \x20 return 0;\n }\n",
        )
        .unwrap();
        let bin = dir.join("sinks");
        let built = Command::new("cc")
            .arg("-O0")
            .arg(&src)
            .arg("-o")
            .arg(&bin)
            .arg("-ldl")
            .output()
            .expect("cc");
        assert!(
            built.status.success(),
            "cc failed: {}",
            String::from_utf8_lossy(&built.stderr)
        );
        let _ = fs::set_permissions(&bin, fs::Permissions::from_mode(0o755));

        let work = dir.join("work");
        fs::create_dir_all(&work).unwrap();
        let rules = collector_rule_ids(&bin, "AAAACCCCDDDD", &work);
        for want in ["BHF-431", "BHF-440", "BHF-435"] {
            assert!(
                rules.iter().any(|r| r == want),
                "expected a collector {want} finding; got {rules:?}"
            );
        }

        // Negative control: the SAME sink shapes with fixed constants (no input in
        // the sink arguments) must not become taint-confirmed collector findings.
        let nsrc = dir.join("fixed.c");
        fs::write(
            &nsrc,
            b"#include <stdio.h>\n#include <stdlib.h>\n#include <dlfcn.h>\n\
              int main(int argc, char **argv){ (void)argc; (void)argv;\n\
              \x20 system(\"/bin/echo constant\");\n\
              \x20 remove(\"/tmp/bhf-col-fixed-constant\");\n\
              \x20 void*h=dlopen(\"libm.so.6\",RTLD_NOW); if(h) dlclose(h);\n\
              \x20 return 0; }\n",
        )
        .unwrap();
        let nbin = dir.join("fixed");
        let built = Command::new("cc")
            .arg("-O0")
            .arg(&nsrc)
            .arg("-o")
            .arg(&nbin)
            .arg("-ldl")
            .output()
            .expect("cc");
        assert!(built.status.success(), "cc failed (fixed)");
        let _ = fs::set_permissions(&nbin, fs::Permissions::from_mode(0o755));
        let nwork = dir.join("nwork");
        fs::create_dir_all(&nwork).unwrap();
        let neg = collector_rule_ids(&nbin, "AAAACCCCDDDD", &nwork);
        for taint_rule in ["BHF-431", "BHF-440", "BHF-435"] {
            assert!(
                !neg.iter().any(|r| r == taint_rule),
                "fixed constants must not produce a taint-confirmed {taint_rule}; got {neg:?}"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    /// End-to-end proof of user postcondition oracles (#55): a target that writes
    /// a path-traversal file outside its allowed root exits 0, yet the
    /// `--oracle-command` must flag it as a `binary_postcondition` finding — which
    /// then replays to a match by re-running setup -> target -> oracle.
    #[cfg(unix)]
    #[test]
    fn binary_fuzz_postcondition_flags_clean_exit_path_escape() {
        use std::os::unix::fs::PermissionsExt;
        if !Command::new("sh")
            .arg("-c")
            .arg("true")
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            eprintln!("skipping postcondition e2e: no POSIX sh");
            return;
        }
        let dir = std::env::temp_dir().join(format!("bhf-binfuzz-postc-{}", nonce()));
        fs::create_dir_all(&dir).unwrap();
        // Target: writes a file named by its input UNDER $BHF_CASE_DIR/share. With
        // a "../escaped" input it escapes the allowed root — and exits 0.
        let target = dir.join("writer.sh");
        fs::write(
            &target,
            b"#!/bin/sh\nname=$(cat \"$1\")\nmkdir -p \"$BHF_CASE_DIR/share\"\n: > \"$BHF_CASE_DIR/share/$name\"\nexit 0\n",
        )
        .unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();

        let work = dir.join("work");
        fs::create_dir_all(&work).unwrap();
        let args = BinaryFuzzArgs {
            binary: target.clone(),
            work_dir: work.clone(),
            input_mode: BinaryInputMode::File,
            iterations: 2,
            seed_inputs: vec!["../escaped".to_owned()],
            seed_files: Vec::new(),
            timeout_ms: 10_000,
            mem_mb: "none".to_owned(),
            env: Vec::new(),
            runner: None,
            runner_args: Vec::new(),
            target_args: Vec::new(),
            sandbox: SandboxModeArg::Auto,
            engine: BinaryFuzzEngine::Builtin,
            time: None,
            runtime_oracles: crate::runtime_oracles::RuntimeOracleMode::Off,
            setup_command: Some("mkdir -p \"$BHF_CASE_DIR/share\"".to_owned()),
            // Stable signature ("path-escape") so replay matches regardless of the
            // per-run case directory path.
            oracle_command: Some(
                "[ -e \"$BHF_CASE_DIR/escaped\" ] && { echo path-escape; exit 1; }; exit 0"
                    .to_owned(),
            ),
            reset_command: None,
            collector: crate::collector_run::CollectorSpec::Off,
            collector_window_ms: crate::collector_run::DEFAULT_WINDOW_MS,
        };
        let summary = run_inner(args).expect("binary fuzz run");
        let ids = summary["findings"].as_array().expect("findings array");
        let mut found: Option<PathBuf> = None;
        for id in ids {
            let fdir = corpus::layout::findings_dir(&work).join(id.as_str().unwrap());
            let f: Value =
                serde_json::from_slice(&fs::read(fdir.join("finding.json")).unwrap()).unwrap();
            if f.get("kind").and_then(Value::as_str) == Some("binary_postcondition") {
                assert_eq!(f.get("rule_id").and_then(Value::as_str), Some("BHF-502"));
                assert_eq!(
                    f.pointer("/postcondition/signature")
                        .and_then(Value::as_str),
                    Some("path-escape")
                );
                found = Some(fdir);
                break;
            }
        }
        let fdir = found
            .unwrap_or_else(|| panic!("expected a binary_postcondition finding, got {summary}"));

        assert_eq!(
            replay_binary_finding(&fdir, &target),
            0,
            "postcondition finding must replay to a match"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
