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

    /// Work directory the findings are written to.
    #[arg(long, default_value = "bhf_work")]
    pub work_dir: PathBuf,

    /// How each input reaches the executable: on stdin, or as a file whose
    /// path is passed as an argument (see `--target-arg`).
    #[arg(long, value_enum, default_value_t = BinaryInputMode::Stdin)]
    pub input_mode: BinaryInputMode,

    /// Most executions: the seeds first, then mutations of them. With
    /// `afl-qemu`, it also sets the default `--time`.
    #[arg(long, default_value_t = 256)]
    pub iterations: usize,

    /// Literal seed input bytes. Repeatable.
    #[arg(long = "seed-input")]
    pub seed_inputs: Vec<String>,

    /// File containing seed input bytes. Repeatable.
    #[arg(long = "seed-file")]
    pub seed_files: Vec<PathBuf>,

    /// Timeout of one execution, in milliseconds. The afl-qemu campaign
    /// (`afl-fuzz -t`) and the crash replay use the same value.
    #[arg(long, default_value_t = 10_000)]
    pub timeout_ms: u64,

    /// Memory limit of the target process under afl-qemu (`afl-fuzz -m`), in
    /// MiB, or `none`. The default is `none` because QEMU mode maps a large
    /// virtual address space, and a tight limit stops the campaign.
    #[arg(long = "mem-mb", default_value = "none")]
    pub mem_mb: String,

    /// Environment variable passed as KEY=VALUE. Repeatable.
    #[arg(long = "env")]
    pub env: Vec<String>,

    /// Redaction map for secret/handle-backed env keys, set only by `bhf project
    /// run`: maps an env key to the `${secret:NAME}` / `${env:NAME}` handle to
    /// RECORD in its place. The real value in `--env` still reaches the spawned
    /// target, but the handle — never the resolved value — is written into
    /// `finding.json`, and `bhf replay`/`minimize` re-resolve it from the
    /// environment. Empty for a standalone `bhf binary fuzz` invocation (every
    /// `--env` value is recorded verbatim), so this is not a CLI flag.
    #[arg(skip)]
    pub env_redaction: BTreeMap<String, String>,

    /// Program to launch the target under, such as `wine` or `qemu-x86_64`;
    /// the target binary and its `--target-arg`s follow it. Builtin engine
    /// only (afl-qemu runs the target under its own QEMU).
    #[arg(long = "runner")]
    pub runner: Option<String>,

    /// Argument for the `--runner` prefix, placed before the target binary.
    /// Repeatable. Requires `--runner`.
    #[arg(long = "runner-arg")]
    pub runner_args: Vec<String>,

    /// Fixed argument passed to the target before the fuzz input. Repeatable. A
    /// literal `@@` token is replaced by the input-file path (file mode); with no
    /// `@@`, the input file is passed last. With `--runner wine --input-mode
    /// file`, `--target-arg=--mode --target-arg=fuzz --target-arg=@@` runs
    /// `wine <BINARY> --mode fuzz <input-file>`.
    #[arg(long = "target-arg")]
    pub target_args: Vec<String>,

    /// Sandbox label recorded in each finding's provenance. `bhf binary fuzz`
    /// runs the target without a sandbox whatever this says.
    #[arg(long, value_enum, default_value_t = SandboxModeArg::Auto)]
    pub sandbox: SandboxModeArg,

    /// Fuzzing engine. `builtin` runs the seeds, then stacked byte mutations
    /// of them with no coverage feedback, until `--iterations`, `--time` or
    /// the first crash. `afl-qemu` runs AFL++ in QEMU mode (`afl-fuzz -Q`),
    /// which adds edge coverage while QEMU translates the binary, so a target
    /// with no source, or built for another architecture, gets coverage-guided
    /// mutation. `afl-frida` runs AFL++ in Frida mode (`afl-fuzz -O`), which
    /// instruments the binary as it runs on the host CPU, for a native binary
    /// that QEMU mode emulates badly or slowly. `auto` (default) uses afl-qemu
    /// when its tools are installed, else builtin, and the run JSON records
    /// the fallback as `degraded`.
    #[arg(long, value_enum, default_value_t = BinaryFuzzEngine::Auto)]
    pub engine: BinaryFuzzEngine,

    /// QEMU or Frida mode: run the target in a persistent loop from this
    /// address (hex), restoring its registers on each pass, so the binary is
    /// not started again for every input. The loop ends where the function at
    /// the address returns. Sets `AFL_QEMU_PERSISTENT_ADDR` (with
    /// `AFL_QEMU_PERSISTENT_GPR=1`) or `AFL_FRIDA_PERSISTENT_ADDR`. A
    /// position-independent binary's addresses are where the emulator loads
    /// it, not what `nm` prints.
    #[arg(long = "persistent-addr", value_name = "ADDR", value_parser = parse_address)]
    pub persistent_addr: Option<u64>,

    /// QEMU or Frida mode: start the fork server at this address (hex)
    /// instead of the binary's entry point (`AFL_ENTRYPOINT`), so each run
    /// skips the start-up before it.
    #[arg(long = "entrypoint", value_name = "ADDR", value_parser = parse_address)]
    pub entrypoint: Option<u64>,

    /// QEMU or Frida mode: run without CmpLog. By default afl-fuzz runs with
    /// `-c 0`: it logs the target's comparisons and puts their operands into
    /// the input, which solves a magic value the havoc stage rarely guesses.
    #[arg(long = "no-cmplog")]
    pub no_cmplog: bool,

    /// Wall-clock budget, such as 30s or 5m. For afl-qemu the default is about
    /// 100ms per `--iterations`, between 1s and 30s; the builtin engine stops
    /// at it or at `--iterations`, whichever comes first.
    #[arg(long = "time")]
    pub time: Option<String>,

    /// Seed of the builtin engine's mutation, so a run repeats exactly.
    #[arg(long = "rng-seed", default_value_t = 0)]
    pub rng_seed: u64,

    /// Load the runtime sink oracles through the LD_PRELOAD runtrace shim
    /// (Linux), so a semantic violation becomes a `binary_semantic` finding
    /// even when the target exits zero: a command execution, path escape,
    /// dlopen, network connection or SQL query that the fuzz input controls.
    /// `off` (default) loads none, so the findings are crashes; `auto` loads
    /// them when the shim and the platform support it; `on` requires them.
    /// Builtin engine only.
    #[arg(long = "runtime-oracles", value_enum, default_value_t = crate::runtime_oracles::RuntimeOracleMode::Off)]
    pub runtime_oracles: crate::runtime_oracles::RuntimeOracleMode,

    /// Shell command run before each testcase to prepare a fresh fixture. It
    /// gets the testcase path as `$1`, and `BHF_TESTCASE` and `BHF_CASE_DIR` in
    /// its environment. A non-zero exit skips the testcase as a setup error.
    #[arg(long = "setup-command")]
    pub setup_command: Option<String>,

    /// Shell command run after each testcase to check a security condition you
    /// define, such as "no file left the allowed root" or "no unexpected child
    /// process". It gets the testcase path as `$1`, plus `BHF_TESTCASE`,
    /// `BHF_CASE_DIR`, `BHF_TARGET_EXIT`, `BHF_TARGET_SIGNAL`,
    /// `BHF_TARGET_TIMEOUT` and `BHF_TARGET_STDERR` (a file). Exit 0: clean.
    /// Exit 1: a finding, whose classification is the first line the command
    /// prints on stdout. Any other exit: an oracle error. It runs whatever the
    /// target's exit status.
    #[arg(long = "oracle-command")]
    pub oracle_command: Option<String>,

    /// Shell command run after the oracle to reset state between testcases,
    /// so files, processes and sessions one testcase leaves do not affect the
    /// next. It gets the same `BHF_TESTCASE` and `BHF_CASE_DIR`.
    #[arg(long = "reset-command")]
    pub reset_command: Option<String>,

    /// Runtime-event collector that observes process, filesystem, and module-load
    /// effects the target performs even on a clean exit. `auto` selects the
    /// built-in provider for the platform: the native Windows ETW provider
    /// `bhf-collector-win`, or on Linux the in-process `LD_PRELOAD` runtrace
    /// adapter, which arms the runtrace shim for the run (with `--runtime-oracles
    /// off` it writes no runtime-oracle findings) and stays inactive only when the
    /// shim is unavailable. A PATH runs an external sidecar that speaks the
    /// bhf.collector-event.v1 JSONL protocol; `none` (default) disables it. A
    /// collected semantic violation (a process exec or library load the input
    /// controls, or a path outside the allowed root) becomes a
    /// `binary_semantic` finding with no crash needed, and the raw collector
    /// session is stored so the finding replays the same way.
    #[arg(long = "collector", value_parser = crate::collector_run::parse_collector_spec, default_value = "none")]
    pub collector: crate::collector_run::CollectorSpec,

    /// How long, in milliseconds, the collector keeps observing the effects of
    /// descendant processes after the testcase process exits.
    #[arg(long = "collector-window-ms", default_value_t = crate::collector_run::DEFAULT_WINDOW_MS)]
    pub collector_window_ms: u64,

    /// A `bhf binary adapter` report of the binary. The strings its
    /// code references seed the mutation dictionary (the builtin engine's, and
    /// afl-fuzz's `-x`), and its functions are ranked as fuzz entry points;
    /// the run JSON's `adapter_report` records both, with the top-ranked
    /// function as the candidate persistent address.
    #[arg(long = "adapter-report")]
    pub adapter_report: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BinaryFuzzEngine {
    Builtin,
    #[value(name = "afl-qemu")]
    AflQemu,
    #[value(name = "afl-frida")]
    AflFrida,
    Auto,
}

/// A `--persistent-addr` or `--entrypoint` address: hex, with or without
/// `0x`.
fn parse_address(value: &str) -> Result<u64, String> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    u64::from_str_radix(digits, 16)
        .map_err(|_| format!("{value:?} is not a hex address (e.g. 0x401136)"))
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
    fn validate(&self, mode: BinaryInputMode, engine_is_afl: bool) -> anyhow::Result<()> {
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
        if engine_is_afl && self.runner.is_some() {
            return Err(anyhow!(
                "--runner is not supported with the afl-qemu or afl-frida engine (afl-fuzz runs \
                 the binary under QEMU or Frida itself); use --engine builtin to run under a \
                 custom runner, or drop --runner"
            ));
        }
        Ok(())
    }

    /// Get the runner ready before the target's first run (#394): a Wine
    /// runner's prefix is created when it is missing, since Wine creating it
    /// on the first run outlasts the run's timeout.
    fn prepare_runner(&self) -> anyhow::Result<()> {
        match &self.runner {
            Some(runner) => {
                crate::runner::prepare_runner_program(Path::new(runner)).map_err(|e| anyhow!(e))
            }
            None => Ok(()),
        }
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
    // What each seed is, in order, for the lineage of a finding the builtin
    // engine saves: a seed runs as it is, a mutation of one a generation down.
    let lineages = seed_lineages(&args, &seeds);
    let hints = match args.adapter_report.as_deref() {
        Some(report) => Some(crate::binary_adapter::hints::load(report).map_err(|e| anyhow!(e))?),
        None => None,
    };
    let adapter_report = adapter_report_provenance(&args, hints.as_ref());
    let findings_dir = corpus::layout::findings_dir(&args.work_dir);
    fs::create_dir_all(&findings_dir)
        .with_context(|| format!("create {}", findings_dir.display()))?;

    // Engine dispatch. afl-qemu gives coverage-guided mutation for binary-only /
    // foreign-arch targets via QEMU DBT; builtin just replays the seeds.
    let engine = resolve_binary_engine(args.engine)?;
    let invocation = TargetInvocation::from_args(&args);
    invocation.validate(args.input_mode, matches!(engine, ResolvedEngine::Afl(_)))?;
    invocation.prepare_runner()?;
    // #55: user postconditions are a builtin-engine capability; the afl-qemu
    // adapter path is out of scope here.
    if args.oracle_command.is_some() && matches!(engine, ResolvedEngine::Afl(_)) {
        return Err(anyhow!(
            "--oracle-command (user postcondition oracles) is supported only with \
             --engine builtin; drop --oracle-command or pass --engine builtin"
        ));
    }
    let degraded = match engine {
        ResolvedEngine::Afl(afl) => {
            let mut summary =
                run_afl_binary(&args, &afl, &seeds, hints.as_ref(), &env, &findings_dir)?;
            summary["adapter_report"] = adapter_report;
            return Ok(summary);
        }
        ResolvedEngine::Builtin { degraded } => degraded,
    };
    if args.persistent_addr.is_some() || args.entrypoint.is_some() {
        return Err(anyhow!(
            "--persistent-addr and --entrypoint need --engine afl-qemu or afl-frida (the \
             builtin engine starts the binary for every input)"
        ));
    }
    let time_budget = match args.time.as_deref() {
        Some(time) => Some(Duration::from_secs(parse_duration_secs(time).ok_or_else(
            || anyhow!("--time {time:?} is not a duration (e.g. 30s, 5m)"),
        )?)),
        None => None,
    };
    let started = Instant::now();
    let tokens = hints
        .as_ref()
        .map(|hints| hints.tokens.as_slice())
        .unwrap_or_default();
    let mut havoc = BlindHavoc::new(&seeds, args.rng_seed, tokens);

    let tmp_dir = args.work_dir.join("binary_fuzz/tmp");
    fs::create_dir_all(&tmp_dir).with_context(|| format!("create {}", tmp_dir.display()))?;

    // #59: resolve the runtime sink oracles for the builtin engine.
    // `on` errors if the shim/platform is unavailable; `auto` quietly stays off.
    let oracles = RuntimeOracles::resolve(args.runtime_oracles, "reporting")?;
    let oracle_log = tmp_dir.join("runtrace.jsonl");
    let mut tracker = crate::auto::runtrace::SinkTaintTracker::default();
    // Snapshot of the campaign's cross-execution taint evidence, captured before
    // `tracker.into_confirmed()` consumes it, so the #60 collector adapter's gate
    // can reuse the SAME correlation #59 built (empty when runtime oracles are off).
    let mut campaign_gate_tracker = crate::auto::runtrace::SinkTaintTracker::default();
    // (oracle hit, representative testcase) pairs; deduped at emission.
    let mut semantic_hits: Vec<(finding_rules::oracle_sdk::OracleHit, Vec<u8>)> = Vec::new();

    // #60: resolve the runtime-event collector up front so the campaign loop can
    // arm its Linux runtrace shim across the campaign's REAL executions when
    // runtime oracles are off. The collector taint gate is then built from the SAME
    // cross-execution evidence #59 accumulates — a program constant reached
    // untainted on some mutated-but-still-reaching input is suppressed, a genuinely
    // fuzz-controlled sink stays confirmed — rather than from a single seed plus one
    // synthetic contrast run (which a validation-gated target silently defeats: the
    // contrast fails the input's own checks and never reaches the sink).
    let resolved_collector = collector_run::resolve(&args.collector, args.collector_window_ms)?;
    // When oracles are off but `--collector auto` is the Linux runtrace provider,
    // run the campaign loop under this shim purely to feed the collector gate. No
    // #59 oracle findings are emitted from it (that path stays gated on `oracles`).
    // With oracles ON the campaign already runs under the #59 shim, so the gate
    // reuses `campaign_gate_tracker` and this stays `None` (that path is unchanged).
    let collector_campaign_shim = if oracles.is_none() {
        resolved_collector.as_ref().and_then(|r| r.runtrace_shim())
    } else {
        None
    };
    let collector_campaign_log = tmp_dir.join("collector_campaign_runtrace.jsonl");
    // Collector-only cross-execution evidence accumulated across the campaign's real
    // inputs (used only on the oracles-off runtrace path above).
    let mut collector_gate_tracker = crate::auto::runtrace::SinkTaintTracker::default();

    // #55: user-defined postcondition oracle + per-case fixture hooks.
    let postcondition = Postcondition::from_args(&args);
    let case_dir = tmp_dir.join("case");
    let mut seen_postcondition = std::collections::HashSet::new();

    let mut finding_ids = Vec::new();
    // The inputs behind this run's findings, with their lineage: the collector
    // replays them first (#247).
    let mut retained: Vec<(
        collector_run::ReplayTestcase,
        corpus::lineage::FindingLineage,
    )> = Vec::new();
    let mut executions = 0usize;
    let mut mutated = 0usize;
    while executions < args.iterations
        && !time_budget.is_some_and(|budget| started.elapsed() >= budget)
    {
        // The seeds as they are, then blind mutations of them.
        let (input, lineage) = match seeds.get(executions) {
            Some(seed) => (seed.clone(), lineages[executions].clone()),
            None => {
                let (parent, child) = havoc.next();
                mutated += 1;
                let lineage =
                    crate::fuzz_lineage::of_mutation(&lineages[parent], &seeds[parent], &child);
                (child, lineage)
            }
        };
        let (seed, lineage) = (&input, &lineage);
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
        // Arm the #59 oracle shim when runtime oracles are on; otherwise, when
        // `--collector auto` resolved to the Linux runtrace shim, arm THAT shim so
        // this real campaign input contributes to the collector's cross-execution
        // taint evidence (#60). At most one is ever armed.
        let oracle_arg = match (oracles.as_ref(), collector_campaign_shim) {
            (Some(o), _) => Some((o, oracle_log.as_path())),
            (None, Some(c)) => Some((c, collector_campaign_log.as_path())),
            (None, None) => None,
        };
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
        } else if collector_campaign_shim.is_some() {
            // #60: runtime oracles off — fold this real input's sinks into the
            // collector gate ONLY (no #59 findings). Across the campaign's varied
            // inputs this is the cross-execution evidence that suppresses a constant
            // reached untainted on some reaching input while still confirming a
            // genuinely fuzz-controlled sink (each distinct subject tainted-only).
            collector_gate_tracker.observe(&run.oracle_events, seed);
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
                        let mut finding = render_postcondition_finding(
                            &id, &args, seed, &env, &signature, &detail, &run,
                        )?;
                        crate::fuzz_lineage::insert(&mut finding, lineage);
                        fs::write(
                            dir.join("finding.json"),
                            serde_json::to_vec_pretty(&finding)?,
                        )
                        .with_context(|| format!("write {}", dir.join("finding.json").display()))?;
                        retained.push((
                            collector_run::ReplayTestcase::new(id.clone(), seed.clone()),
                            lineage.clone(),
                        ));
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
            crate::fuzz_lineage::insert(&mut finding, lineage);
            fs::write(
                dir.join("finding.json"),
                serde_json::to_vec_pretty(&finding)?,
            )
            .with_context(|| format!("write {}", dir.join("finding.json").display()))?;
            retained.push((
                collector_run::ReplayTestcase::new(id.clone(), seed.clone()),
                lineage.clone(),
            ));
            finding_ids.push(id);
            break;
        }
    }

    // #59: emit semantic findings for every distinct oracle violation — these fire
    // even when the target exited zero on every input.
    if oracles.is_some() {
        // Preserve the campaign's cross-execution evidence for the collector gate
        // (below) before into_confirmed() moves the tracker's retained inputs out.
        campaign_gate_tracker = tracker.clone();
        for confirmed in tracker.into_confirmed() {
            for hit in crate::auto::runtrace::confirmed_sink_hits(&confirmed) {
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
            let mut finding = render_semantic_finding(
                &id,
                &args,
                input,
                &env,
                hit,
                &signature,
                oracles.as_ref(),
            )?;
            let lineage = lineage_of_seed(&seeds, &lineages, input);
            crate::fuzz_lineage::insert(&mut finding, &lineage);
            fs::write(
                dir.join("finding.json"),
                serde_json::to_vec_pretty(&finding)?,
            )
            .with_context(|| format!("write {}", dir.join("finding.json").display()))?;
            retained.push((
                collector_run::ReplayTestcase::new(id.clone(), input.clone()),
                lineage,
            ));
            finding_ids.push(id);
        }
    }

    // #60: run the platform-neutral runtime-event collector. A collected semantic
    // violation (controlled process exec / path escape / controlled library load)
    // becomes a `binary_semantic` finding through the SAME oracle registry, even
    // when every execution exited cleanly. Inactive (default) leaves behaviour
    // unchanged.
    let seed_inputs = seeds
        .iter()
        .zip(&lineages)
        .enumerate()
        .map(|(idx, (seed, lineage))| {
            (
                collector_run::ReplayTestcase::new(format!("seed-{idx:04}"), seed.clone()),
                lineage.clone(),
            )
        });
    let replay_inputs: Vec<_> = retained.into_iter().chain(seed_inputs).collect();
    // #60: with oracles on, the gate starts from the campaign's #59 evidence;
    // with oracles off, from what the campaign loop gathered under the
    // collector's own runtrace shim (see `collector_campaign_shim`).
    let gate_evidence = if oracles.is_some() {
        campaign_gate_tracker
    } else {
        collector_gate_tracker
    };
    let collector_provenance = match &resolved_collector {
        None => collector_run::inactive_run_provenance(&args.collector),
        Some(resolved) => collector_replays(
            &args,
            resolved,
            &CollectorReplayContext {
                invocation: &invocation,
                env: &env,
                tmp_dir: &tmp_dir,
                findings_dir: &findings_dir,
            },
            gate_evidence,
            &replay_inputs,
            &mut finding_ids,
        )?,
    };

    Ok(json!({
        "schema_version": "bhf.binary_fuzz.run.v1",
        "binary": args.binary,
        "input_mode": args.input_mode.as_str(),
        "engine": "builtin",
        "fidelity": {
            "mutation": "blind havoc: stacked byte mutations of the seeds",
            "coverage": "none",
            "seeds_run": executions.min(seeds.len()),
            "mutated_inputs": mutated,
        },
        "degraded": true,
        "degraded_reason": degraded,
        "executions": executions,
        "runtime_oracles": runtime_oracle_provenance(args.runtime_oracles, oracles.as_ref()),
        "collector": collector_provenance,
        "adapter_report": adapter_report,
        "findings": finding_ids
    }))
}

/// The run JSON's `adapter_report`: the report `--adapter-report` named and
/// the hints taken from it, or null.
fn adapter_report_provenance(
    args: &BinaryFuzzArgs,
    hints: Option<&crate::binary_adapter::hints::AdapterHints>,
) -> Value {
    match (args.adapter_report.as_deref(), hints) {
        (Some(report), Some(hints)) => hints.provenance(report),
        _ => Value::Null,
    }
}

/// Where the collector replays run: the target command, its environment, the
/// scratch dir, and the findings dir its findings go to.
struct CollectorReplayContext<'a> {
    invocation: &'a TargetInvocation,
    env: &'a BTreeMap<String, String>,
    tmp_dir: &'a Path,
    findings_dir: &'a Path,
}

/// Replay each of `replay_inputs` (the inputs behind the run's findings, the
/// most interesting first, then the seeds; at most
/// [`collector_run::MAX_REPLAYS`]) under the collector, write a finding for
/// each distinct violation with the input that produced it, and return the run
/// provenance (#76, #247). Each observation is of one replayed execution, not
/// the whole campaign.
fn collector_replays(
    args: &BinaryFuzzArgs,
    resolved: &collector_run::ResolvedCollector,
    ctx: &CollectorReplayContext<'_>,
    mut gate_evidence: crate::auto::runtrace::SinkTaintTracker,
    replay_inputs: &[(
        collector_run::ReplayTestcase,
        corpus::lineage::FindingLineage,
    )],
    finding_ids: &mut Vec<String>,
) -> anyhow::Result<Value> {
    let (replays, dropped) =
        collector_run::bounded_replay_set(replay_inputs.iter().map(|(r, _)| r.clone()));
    let root = args.work_dir.display().to_string();
    let image = args.binary.display().to_string();
    let mut outcomes = Vec::with_capacity(replays.len());
    if let Some(shim) = resolved.runtrace_shim() {
        // Linux built-in provider: each input runs under the LD_PRELOAD runtrace
        // shim, and its process/file/library effects are re-expressed as
        // `bhf.collector-event.v1` via the runtrace→collector adapter. This pass
        // is separate from the crash-detection loop, so `--runtime-oracles`
        // behaviour is unchanged; it is an additional, collector-shaped view.
        let col_log = ctx.tmp_dir.join("collector_runtrace.jsonl");
        let mut runs = Vec::with_capacity(replays.len());
        for replay in replays {
            let _ = fs::remove_file(&col_log);
            let run = run_binary_once(
                ctx.invocation,
                args.input_mode,
                &replay.input,
                ctx.env,
                Duration::from_millis(args.timeout_ms),
                ctx.tmp_dir,
                Some((shim, col_log.as_path())),
            )?;
            gate_evidence.observe(&run.oracle_events, &replay.input);
            runs.push((replay, run));
        }
        // #60: a sink is taint-confirmed ONLY from cross-execution correlation
        // (the SAME #59 gate), never one run's raw taint_offset: the campaign's
        // evidence plus every replay. A sink is confirmed only when real, varied
        // inputs showed it fuzz-controlled (it carried byte-origin taint and was
        // never reached untainted); a constant that some still-reaching input
        // altered is observed untainted there and suppressed.
        //
        // Inherent residual (identical to #59's): a constant whose exact >=4-byte
        // subject appears in EVERY input that reaches the sink is
        // indistinguishable from a fuzz-controlled subject and may remain
        // confirmed. #60's threat model (printable path / command / module
        // constants) is well served: across distinct inputs the echoing bytes
        // vary while the sink is still reached, which suppresses it.
        let gate = gate_evidence.collector_gate();
        for (replay, run) in runs {
            // `run_binary_once` re-executed this input under the shim, so this IS
            // a single-testcase replay with the run's real pids.
            let adapter_ctx = crate::auto::runtrace::CollectorAdapterCtx {
                testcase: replay.testcase.clone(),
                worker: replay.worker,
                // Synthetic anchor for this replayed execution's event tree; the
                // shim events carry the real child pids, which drive attribution.
                root_pid: 1,
            };
            let jsonl = crate::auto::runtrace::collector_jsonl_from_events(
                &run.oracle_events,
                &adapter_ctx,
                &image,
                &gate,
            );
            let outcome = resolved.evaluate_jsonl(&jsonl, &root);
            outcomes.push((replay, outcome));
        }
    } else {
        for replay in replays {
            // Sidecar provider: a genuine REPLAY. The host launches the target
            // with this input UNDER the ready observer (recording its real PID),
            // so the observation is of a process that actually ran. `run_once`
            // bounds the whole capture and degrades to not_observed if it cannot
            // genuinely replay-and-observe (#76).
            let launch: collector_run::ReplayLauncher = Box::new(|| {
                spawn_replay_child(
                    ctx.invocation,
                    args.input_mode,
                    &replay.input,
                    ctx.env,
                    ctx.tmp_dir,
                )
            });
            let params = collector_run::CollectorRunParams {
                testcase: replay.testcase.clone(),
                worker: replay.worker,
                root: root.clone(),
                root_image: image.clone(),
                input: &replay.input,
                tmp_dir: ctx.tmp_dir.join("collector"),
                launch: Some(launch),
            };
            let outcome = resolved.run_once(&params)?;
            drop(params);
            outcomes.push((replay, outcome));
        }
    }
    let merged = collector_run::merge_replays(outcomes, dropped);
    let observation = collector_run::ObservationMode::Replay;
    let target = collector_target(args)?;
    for (finding, replay) in &merged.findings {
        let id = collector_run::next_collector_finding_id(ctx.findings_dir)?;
        let dir = ctx.findings_dir.join(&id);
        collector_run::write_finding(
            &dir,
            &id,
            target.clone(),
            finding,
            &replay.input,
            observation,
        )?;
        let lineage = replay_inputs
            .iter()
            .find(|(candidate, _)| candidate.input_sha256 == replay.input_sha256)
            .map(|(_, lineage)| lineage.clone())
            .unwrap_or_else(|| {
                corpus::lineage::FindingLineage::unknown("the replayed input was not retained")
            });
        corpus::lineage::record_in_finding(&dir, &lineage)
            .with_context(|| format!("record the lineage of {id}"))?;
        finding_ids.push(id);
    }
    let mut provenance = merged.run_provenance;
    observation.stamp(&mut provenance);
    Ok(provenance)
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
    /// The blind havoc loop, and why it runs without coverage.
    Builtin { degraded: String },
    /// AFL++ in QEMU or Frida mode.
    Afl(AflBinary),
}

/// The builtin engine's blind havoc mutator: each input is a seed, picked at
/// random, with 1, 2 or 4 byte-level mutations stacked on it. Nothing guides
/// it, so it finds what is a few random edits from a seed.
struct BlindHavoc<'a> {
    seeds: &'a [Vec<u8>],
    suite: fuzz_engine_builtin::MutatorSuite,
    dictionary: fuzz_engine_builtin::Dictionary,
    rng: fuzz_engine_builtin::MutationRng,
}

impl<'a> BlindHavoc<'a> {
    /// The mutator of `seeds`, its dictionary `tokens` (an adapter report's
    /// strings, or none).
    fn new(seeds: &'a [Vec<u8>], rng_seed: u64, tokens: &[Vec<u8>]) -> Self {
        let longest = seeds.iter().map(Vec::len).max().unwrap_or(0);
        Self {
            seeds,
            suite: fuzz_engine_builtin::MutatorSuite::new(fuzz_engine_builtin::MutatorConfig {
                max_len: longest.saturating_mul(2).clamp(64, 1 << 16),
                ..fuzz_engine_builtin::MutatorConfig::default()
            }),
            dictionary: fuzz_engine_builtin::Dictionary::from_tokens(tokens),
            rng: fuzz_engine_builtin::MutationRng::new(rng_seed),
        }
    }

    /// The next mutated input, with the index of the seed it came from.
    fn next(&mut self) -> (usize, Vec<u8>) {
        let parent = (self.rng.next_u64() % self.seeds.len().max(1) as u64) as usize;
        let mut bytes = self.seeds.get(parent).cloned().unwrap_or_default();
        for _ in 0..1u32 << (self.rng.next_u64() % 3) {
            let input = fuzz_engine_builtin::MutationInput::new(&bytes, &self.dictionary);
            if let Some(result) = self.suite.mutate(&input, &mut self.rng) {
                bytes = result.bytes;
            }
        }
        if bytes.is_empty() {
            bytes.push(self.rng.next_u8());
        }
        (parent, bytes)
    }
}

/// How AFL++ instruments a binary without source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AflBinaryMode {
    /// `afl-fuzz -Q`: QEMU user mode translates the binary and injects edge
    /// coverage as it does.
    Qemu,
    /// `afl-fuzz -O`: Frida instruments the binary as it runs on the host CPU.
    Frida,
}

impl AflBinaryMode {
    /// The afl-fuzz flag that selects the mode.
    fn flag(self) -> &'static str {
        match self {
            Self::Qemu => "-Q",
            Self::Frida => "-O",
        }
    }

    /// The `--engine` value, as the run JSON records it.
    fn engine(self) -> &'static str {
        match self {
            Self::Qemu => "afl-qemu",
            Self::Frida => "afl-frida",
        }
    }

    /// The mode's name in messages.
    fn name(self) -> &'static str {
        match self {
            Self::Qemu => "AFL++ QEMU mode",
            Self::Frida => "AFL++ Frida mode",
        }
    }

    /// Where the coverage comes from, as the run JSON's fidelity says.
    fn coverage(self) -> &'static str {
        match self {
            Self::Qemu => "edges, injected by QEMU as it translates the binary",
            Self::Frida => "edges, instrumented by Frida as the binary runs",
        }
    }

    /// The variable that sets the persistent loop's address.
    fn persistent_var(self) -> &'static str {
        match self {
            Self::Qemu => "AFL_QEMU_PERSISTENT_ADDR",
            Self::Frida => "AFL_FRIDA_PERSISTENT_ADDR",
        }
    }
}

/// AFL++'s toolchain for a binary-only mode: `afl-fuzz`, plus the program
/// (`afl-qemu-trace`) or library (`afl-frida-trace.so`) the mode runs the
/// binary with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AflBinary {
    pub(crate) mode: AflBinaryMode,
    pub(crate) afl_fuzz: PathBuf,
    pub(crate) trace: PathBuf,
}

/// Resolve the concrete engine. An explicit `afl-qemu` or `afl-frida`
/// hard-requires its toolchain (actionable error if missing); `auto` falls
/// back to builtin with a note.
fn resolve_binary_engine(engine: BinaryFuzzEngine) -> anyhow::Result<ResolvedEngine> {
    match engine {
        BinaryFuzzEngine::Builtin => Ok(ResolvedEngine::Builtin {
            degraded: "--engine builtin: no coverage feedback reaches the mutator; \
                       --engine afl-qemu gives coverage-guided mutation"
                .to_owned(),
        }),
        BinaryFuzzEngine::AflQemu => resolve_afl_qemu()
            .map(ResolvedEngine::Afl)
            .map_err(|reason| anyhow!(reason)),
        BinaryFuzzEngine::AflFrida => resolve_afl_frida()
            .map(ResolvedEngine::Afl)
            .map_err(|reason| anyhow!(reason)),
        BinaryFuzzEngine::Auto => match resolve_afl_qemu() {
            Ok(afl) => Ok(ResolvedEngine::Afl(afl)),
            Err(reason) => {
                bhfeprintln!(
                    "bhf binary-fuzz: {reason}; falling back to the builtin engine's \
                     blind mutation (no coverage feedback)"
                );
                Ok(ResolvedEngine::Builtin { degraded: reason })
            }
        },
    }
}

/// `afl-fuzz` on PATH, or an actionable reason it is missing.
fn resolve_afl_fuzz() -> Result<PathBuf, String> {
    which_on_path("afl-fuzz").ok_or_else(|| {
        "afl-fuzz not found on PATH; install AFL++ (apt install afl++, or build AFLplusplus)"
            .to_owned()
    })
}

/// Resolve the AFL++ QEMU-mode toolchain, or an ACTIONABLE reason it's missing.
pub(crate) fn resolve_afl_qemu() -> Result<AflBinary, String> {
    let afl_fuzz = resolve_afl_fuzz()?;
    let trace = resolve_afl_qemu_trace().ok_or_else(|| {
        "afl-qemu-trace not found (AFL++ QEMU mode is built separately); run \
         `AFLplusplus/qemu_mode/build_qemu_support.sh` or set BHF_AFL_QEMU_TRACE to its path"
            .to_owned()
    })?;
    Ok(AflBinary {
        mode: AflBinaryMode::Qemu,
        afl_fuzz,
        trace,
    })
}

/// Resolve the AFL++ Frida-mode toolchain, or an actionable reason it is
/// missing.
pub(crate) fn resolve_afl_frida() -> Result<AflBinary, String> {
    let afl_fuzz = resolve_afl_fuzz()?;
    let override_var = std::env::var_os("BHF_AFL_FRIDA_TRACE").map(PathBuf::from);
    let afl_path = std::env::var_os("AFL_PATH").map(PathBuf::from);
    let trace = afl_frida_trace_candidates(override_var, afl_path, &afl_fuzz)
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            "afl-frida-trace.so not found (AFL++ Frida mode is built separately); run `make` \
             in AFLplusplus/frida_mode or set BHF_AFL_FRIDA_TRACE to its path"
                .to_owned()
        })?;
    Ok(AflBinary {
        mode: AflBinaryMode::Frida,
        afl_fuzz,
        trace,
    })
}

/// Ordered candidate paths for `afl-frida-trace.so`: the explicit override,
/// `AFL_PATH`, the `lib/afl` beside the `afl-fuzz` in use, then the common
/// install dirs. Pure (no FS/env) so the precedence is unit-testable.
fn afl_frida_trace_candidates(
    override_var: Option<PathBuf>,
    afl_path: Option<PathBuf>,
    afl_fuzz: &Path,
) -> Vec<PathBuf> {
    const NAME: &str = "afl-frida-trace.so";
    let mut candidates: Vec<PathBuf> = override_var.into_iter().collect();
    if let Some(afl_path) = afl_path {
        candidates.push(afl_path.join(NAME));
    }
    if let Some(prefix) = afl_fuzz.parent().and_then(Path::parent) {
        candidates.push(prefix.join("lib/afl").join(NAME));
    }
    candidates.push(PathBuf::from("/usr/lib/afl").join(NAME));
    candidates.push(PathBuf::from("/usr/local/lib/afl").join(NAME));
    candidates
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

/// Build the `afl-fuzz -Q` (or `-O`) argv for a binary-only target.
/// File-input mode appends `@@` (AFL substitutes the testcase path); stdin
/// mode omits it (AFL feeds the testcase on stdin). `-t` sets the per-exec
/// timeout (ms) and `-m` the child memory limit so the campaign matches the
/// replay oracle. With `cmplog`, `-c 0` runs CmpLog through the same binary,
/// as the binary-only modes do. Kept pure for testing.
// A flat flag-bundle builder: the inputs are distinct afl-fuzz knobs, and a
// struct would only scatter the same fields without clarifying the one argv.
#[allow(clippy::too_many_arguments)]
fn afl_binary_argv(
    afl_mode: AflBinaryMode,
    cmplog: bool,
    binary: &Path,
    seeds_dir: &Path,
    out_dir: &Path,
    secs: u64,
    timeout_ms: u64,
    mem: &str,
    mode: BinaryInputMode,
    target_args: &[String],
) -> Vec<String> {
    let mut argv = vec![afl_mode.flag().to_owned()];
    if cmplog {
        argv.extend(["-c".to_owned(), "0".to_owned()]);
    }
    argv.extend([
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
    ]);
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

/// A duration flag ([`crate::fuzz::parse_duration`]) in whole seconds, a
/// fraction rounded up (afl-fuzz `-V` is second-granular). `None` on a
/// malformed value.
fn parse_duration_secs(value: &str) -> Option<u64> {
    let duration = crate::fuzz::parse_duration(value).ok()?;
    Some(duration.as_secs() + u64::from(duration.subsec_nanos() > 0))
}

/// The variables that set up a persistent loop or a later fork-server start
/// for `afl_mode`: `--persistent-addr` (with the registers restored on each
/// QEMU pass) and `--entrypoint`. Pure, for testing.
fn afl_binary_env(
    afl_mode: AflBinaryMode,
    persistent_addr: Option<u64>,
    entrypoint: Option<u64>,
) -> Vec<(&'static str, String)> {
    let mut env = Vec::new();
    if let Some(addr) = persistent_addr {
        env.push((afl_mode.persistent_var(), format!("0x{addr:x}")));
        if afl_mode == AflBinaryMode::Qemu {
            env.push(("AFL_QEMU_PERSISTENT_GPR", "1".to_owned()));
        }
    }
    if let Some(addr) = entrypoint {
        env.push(("AFL_ENTRYPOINT", format!("0x{addr:x}")));
    }
    env
}

/// The lineage of a crash AFL++ found in a binary-only mode: unknown, since
/// AFL++ schedules its own queue and bhf does not see what the input was
/// mutated from. Nothing is guessed; the reason names the crash file.
fn afl_binary_lineage(afl_mode: AflBinaryMode, crash: &Path) -> corpus::lineage::FindingLineage {
    let name = crash
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    corpus::lineage::FindingLineage::unknown(format!(
        "found by {}, which schedules its own queue; bhf does not see which input this one \
         was mutated from (AFL++ crash file {name})",
        afl_mode.name()
    ))
}

/// `fuzzer_stats`'s numeric fields, by name (`execs_done`, `edges_found`).
fn afl_fuzzer_stats(path: &Path) -> BTreeMap<String, u64> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            Some((key.trim().to_owned(), value.trim().parse().ok()?))
        })
        .collect()
}

/// Drive AFL++ in QEMU mode (`afl-fuzz -Q`) or Frida mode (`afl-fuzz -O`)
/// against a binary-only target: qemu's DBT, or Frida's instrumentation,
/// gives a no-source binary coverage-guided mutation. Harvest
/// `out/default/crashes/` and confirm+record each as a `binary_crash` finding
/// via the same crash oracle as builtin.
fn run_afl_binary(
    args: &BinaryFuzzArgs,
    afl: &AflBinary,
    seeds: &[Vec<u8>],
    hints: Option<&crate::binary_adapter::hints::AdapterHints>,
    env: &BTreeMap<String, String>,
    findings_dir: &Path,
) -> anyhow::Result<Value> {
    let afl_out = args.work_dir.join(match afl.mode {
        AflBinaryMode::Qemu => "afl_qemu_out",
        AflBinaryMode::Frida => "afl_frida_out",
    });
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
    let cmplog = !args.no_cmplog;
    let mut argv = afl_binary_argv(
        afl.mode,
        cmplog,
        &args.binary,
        &seeds_dir,
        &out_dir,
        secs,
        args.timeout_ms,
        &mem_arg,
        args.input_mode,
        &args.target_args,
    );
    // An adapter report's strings are afl-fuzz's dictionary.
    if let Some(hints) = hints.filter(|hints| !hints.tokens.is_empty()) {
        let dictionary = afl_out.join("adapter.dict");
        fs::write(
            &dictionary,
            crate::binary_adapter::hints::afl_dictionary(&hints.tokens),
        )
        .with_context(|| format!("write {}", dictionary.display()))?;
        let at = argv
            .iter()
            .position(|arg| arg == "--")
            .unwrap_or(argv.len());
        argv.splice(at..at, ["-x".to_owned(), dictionary.display().to_string()]);
    }
    let afl_trace_dir = afl
        .trace
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    // #444: afl-fuzz binds itself to a free core unless told not to. A run
    // bhf is pinned for keeps its pin; one that finds every core bound to
    // another fuzzer runs again, once, unbound.
    let mut no_affinity = crate::fuzz::afl_no_affinity_at_start(env.keys().map(String::as_str));
    let run_afl_fuzz = |unbound: bool| -> anyhow::Result<std::process::Output> {
        let mut cmd = Command::new(&afl.afl_fuzz);
        cmd.args(&argv)
            // afl-fuzz -Q finds afl-qemu-trace, and -O afl-frida-trace.so, via
            // AFL_PATH (then alongside afl-fuzz).
            .env("AFL_PATH", &afl_trace_dir)
            .env("AFL_NO_UI", "1")
            .env("AFL_SKIP_CPUFREQ", "1")
            .env("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in env {
            cmd.env(key, value);
        }
        for (key, value) in afl_binary_env(afl.mode, args.persistent_addr, args.entrypoint) {
            cmd.env(key, value);
        }
        // afl-fuzz refuses a custom `<SAN>_OPTIONS` without `symbolize=0`
        // ("Custom ASAN_OPTIONS set without symbolize=0", afl-fuzz-init.c), as
        // the container image's defaults are: merge it into whatever is set.
        for key in ["ASAN_OPTIONS", "UBSAN_OPTIONS", "LSAN_OPTIONS"] {
            let set = env.get(key).cloned().or_else(|| std::env::var(key).ok());
            if set.is_some() {
                cmd.env(
                    key,
                    multicore_fuzz::merge_sanitizer_options(set.as_deref(), "symbolize=0"),
                );
            }
        }
        if unbound {
            cmd.env("AFL_NO_AFFINITY", "1");
        }
        cmd.output()
            .with_context(|| format!("spawn afl-fuzz '{}'", afl.afl_fuzz.display()))
    };
    let mut output = run_afl_fuzz(no_affinity.is_some())?;
    if no_affinity.is_none()
        && output.status.code().is_some_and(|code| code != 0)
        && (crate::fuzz::afl_output_says_no_free_core(&output.stdout)
            || crate::fuzz::afl_output_says_no_free_core(&output.stderr))
    {
        bhfeprintln!(
            "bhf binary-fuzz: afl-fuzz {} found every CPU core bound to another CPU-locked \
             process (another fuzzer) and did not start; running it again without binding a \
             core (AFL_NO_AFFINITY=1)",
            afl.mode.flag()
        );
        // The output directory afl-fuzz gave up on holds no session.
        fs::remove_dir_all(&out_dir)
            .and_then(|()| fs::create_dir_all(&out_dir))
            .with_context(|| format!("reset {}", out_dir.display()))?;
        output = run_afl_fuzz(true)?;
        no_affinity = Some(crate::fuzz::AflNoAffinity::NoFreeCore);
    }
    // afl-fuzz self-terminates by signal when -V expires (code None) — that's the
    // intended end of a time-boxed run, not a failure. A positive exit is a real
    // error (bad seed, core_pattern, missing afl-qemu-trace, …).
    if output.status.code().is_some_and(|code| code != 0) {
        // afl-fuzz prints its own abort message on stdout.
        let said = if output.stderr.iter().any(|byte| !byte.is_ascii_whitespace()) {
            &output.stderr
        } else {
            &output.stdout
        };
        let tail: String = String::from_utf8_lossy(said)
            .lines()
            .rev()
            .take(12)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
        return Err(anyhow!(
            "afl-fuzz {} exited non-zero ({:?}). Output tail:\n{tail}",
            afl.mode.flag(),
            output.status.code()
        ));
    }

    // Harvest crashes: confirm each against the binary (own crash oracle) so the
    // finding carries a real signature, deduped by signature.
    let crashes_dir = out_dir.join("default").join("crashes");
    let tmp_dir = afl_out.join("replay_tmp");
    fs::create_dir_all(&tmp_dir)?;
    let mut finding_ids = Vec::new();
    let mut retained = Vec::new();
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
            let lineage = afl_binary_lineage(afl.mode, &crash);
            crate::fuzz_lineage::insert(&mut finding, &lineage);
            fs::write(
                dir.join("finding.json"),
                serde_json::to_vec_pretty(&finding)?,
            )?;
            retained.push((
                collector_run::ReplayTestcase::new(id.clone(), input),
                lineage,
            ));
            finding_ids.push(id);
        }
    }
    // #247: the collector replays each confirmed crash, then the queue entries
    // that found new coverage, then the seeds.
    let collector = match collector_run::resolve(&args.collector, args.collector_window_ms)? {
        None => collector_run::inactive_run_provenance(&args.collector),
        Some(resolved) => {
            let queued = afl_queue_replays(afl.mode, &out_dir.join("default").join("queue"))?;
            let seeded = seeds.iter().enumerate().map(|(idx, seed)| {
                (
                    collector_run::ReplayTestcase::new(format!("seed-{idx:04}"), seed.clone()),
                    corpus::lineage::FindingLineage::unknown(format!(
                        "a seed of an {} run",
                        afl.mode.name()
                    )),
                )
            });
            let replay_inputs: Vec<_> = retained.into_iter().chain(queued).chain(seeded).collect();
            collector_replays(
                args,
                &resolved,
                &CollectorReplayContext {
                    invocation: &invocation,
                    env,
                    tmp_dir: &tmp_dir,
                    findings_dir,
                },
                crate::auto::runtrace::SinkTaintTracker::default(),
                &replay_inputs,
                &mut finding_ids,
            )?
        }
    };
    let _ = fs::remove_dir_all(&tmp_dir);

    let stats = afl_fuzzer_stats(&out_dir.join("default").join("fuzzer_stats"));
    let mut summary = json!({
        "schema_version": "bhf.binary_fuzz.run.v1",
        "binary": args.binary,
        "input_mode": args.input_mode.as_str(),
        "engine": afl.mode.engine(),
        "fidelity": {
            "mutation": "AFL++ with coverage feedback",
            "coverage": afl.mode.coverage(),
            "cmplog": cmplog,
            "persistent_addr": args.persistent_addr.map(|addr| format!("0x{addr:x}")),
            "entrypoint": args.entrypoint.map(|addr| format!("0x{addr:x}")),
            "edges_found": stats.get("edges_found"),
        },
        "degraded": false,
        "executions": stats.get("execs_done"),
        "time_secs": secs,
        "timeout_ms": args.timeout_ms,
        "mem_limit_mb": mem_provenance,
        "collector": collector,
        "findings": finding_ids
    });
    let trace_key = match afl.mode {
        AflBinaryMode::Qemu => "afl_qemu_trace",
        AflBinaryMode::Frida => "afl_frida_trace",
    };
    summary[trace_key] = json!(afl.trace);
    // Why afl-fuzz ran without binding a core of its choosing; absent when it
    // bound one.
    if let Some(reason) = no_affinity {
        summary["no_affinity"] = json!(reason);
    }
    Ok(summary)
}

/// The entries of an AFL++ `queue/` dir to replay under the collector: those
/// whose name says they found new coverage (`+cov`) first, then the rest, each
/// in AFL++'s order.
fn afl_queue_replays(
    afl_mode: AflBinaryMode,
    queue: &Path,
) -> anyhow::Result<
    Vec<(
        collector_run::ReplayTestcase,
        corpus::lineage::FindingLineage,
    )>,
> {
    let Ok(entries) = fs::read_dir(queue) else {
        return Ok(Vec::new());
    };
    let mut names: Vec<(bool, String, PathBuf)> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .filter_map(|path| {
            let name = path.file_name()?.to_str()?.to_owned();
            Some((!name.contains("+cov"), name, path))
        })
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|(_, name, path)| {
            let input = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let lineage = corpus::lineage::FindingLineage::unknown(format!(
                "{} queue entry {name}; bhf does not see which input it was mutated from",
                afl_mode.name()
            ));
            // `id:000012,src:000003,...,+cov`: the id names the entry.
            let id = name.split(',').next().unwrap_or(&name).replace(':', "-");
            Ok((
                collector_run::ReplayTestcase::new(format!("queue-{id}"), input),
                lineage,
            ))
        })
        .collect()
}

pub(crate) fn is_binary_finding(finding_dir: &Path) -> bool {
    fs::read(finding_dir.join("finding.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| value.get("kind").and_then(Value::as_str).map(str::to_owned))
        .is_some_and(|kind| kind == "binary_crash")
}

/// `bhf replay` of a binary finding with the default output.
#[cfg(all(test, unix))]
pub(crate) fn replay_binary_finding(finding_dir: &Path, binary: &Path) -> i32 {
    crate::replay::finish_lane(
        finding_dir,
        replay_binary_outcome(finding_dir, binary),
        crate::replay::OutputMode::default(),
    )
}

/// Re-run a binary finding's testcase against `binary` and compare the
/// signature it records (crash, runtime oracle or postcondition).
pub(crate) fn replay_binary_outcome(
    finding_dir: &Path,
    binary: &Path,
) -> Result<crate::replay::LaneReplay, String> {
    let replayed =
        replay_binary_finding_inner(finding_dir, binary).map_err(|error| format!("{error:#}"))?;
    let run = &replayed.run;
    let exit = crate::replay::ExitSummary::process(
        run.exit_code,
        run.signal,
        run.timeout.then_some(replayed.timeout),
        replayed.duration,
    );
    let mut differences = Vec::new();
    if !replayed.matched {
        differences.push(match &replayed.actual {
            Some(actual) => format!(
                "{}: recorded {}, replayed {actual}",
                replayed.compared, replayed.recorded
            ),
            None => format!(
                "{}: recorded {}, not reproduced",
                replayed.compared, replayed.recorded
            ),
        });
    }
    Ok(crate::replay::LaneReplay {
        lane: "binary",
        matched: replayed.matched,
        unverified: false,
        status_line: if replayed.matched {
            "MATCH".to_owned()
        } else {
            format!("MISMATCH binary {} changed", replayed.compared)
        },
        compared: format!("{} {}", replayed.compared, short(&replayed.recorded)),
        differences,
        details: Vec::new(),
        exit: Some(exit),
        output: Some((Vec::new(), run.stderr.clone().into_bytes())),
        binary: Some((binary.to_path_buf(), replayed.mode.as_str().to_owned())),
        history: "replay",
    })
}

/// A recorded signature, shortened for the summary line.
fn short(signature: &str) -> String {
    match signature.char_indices().nth(16) {
        Some((index, _)) => format!("{}...", &signature[..index]),
        None => signature.to_owned(),
    }
}

/// One replay of a binary finding.
struct BinaryReplay {
    matched: bool,
    /// What was compared: `crash signature`, `runtime oracle signature` or
    /// `postcondition signature`.
    compared: &'static str,
    recorded: String,
    /// The replayed run's signature, when it produced one of that kind.
    actual: Option<String>,
    run: BinaryRun,
    mode: BinaryInputMode,
    timeout: Duration,
    duration: Duration,
}

pub(crate) fn minimize_binary_finding(
    finding_dir: &Path,
    binary: &Path,
    strategy: MinimizeStrategy,
) -> anyhow::Result<BinaryMinimizeSummary> {
    if strategy != MinimizeStrategy::Bytes {
        return Err(anyhow!(
            "minimize --strategy typed reduces the arguments a generated harness decodes, by \
             its arg-layout.json; a binary finding's input reaches the binary whole and has \
             none, so minimize it with --strategy bytes"
        ));
    }
    let finding = read_finding(finding_dir)?;
    let mode = finding_input_mode(&finding)?;
    let env = finding_env(&finding)?;
    let timeout = finding_timeout(&finding);
    let original = fs::read(finding_dir.join("testcase.bin"))
        .with_context(|| format!("read {}", finding_dir.join("testcase.bin").display()))?;
    let invocation = finding_invocation(&finding, binary);
    invocation.prepare_runner()?;
    let scratch = crate::minimize::ScratchDir::create(finding_dir.join("binary_minimize_tmp"))?;
    let tmp_dir = scratch.path().to_path_buf();
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
    drop(scratch);
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

fn replay_binary_finding_inner(finding_dir: &Path, binary: &Path) -> anyhow::Result<BinaryReplay> {
    let finding = read_finding(finding_dir)?;
    let input = fs::read(finding_dir.join("testcase.bin"))
        .with_context(|| format!("read {}", finding_dir.join("testcase.bin").display()))?;
    let scratch = crate::minimize::ScratchDir::create(finding_dir.join("binary_replay_tmp"))?;
    let tmp_dir = scratch.path().to_path_buf();
    let invocation = finding_invocation(&finding, binary);
    invocation.prepare_runner()?;
    let mode = finding_input_mode(&finding)?;
    let env = finding_env(&finding)?;
    let timeout = finding_timeout(&finding);
    let started = Instant::now();

    let replayed = if finding.get("kind").and_then(Value::as_str) == Some("binary_semantic") {
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
        let signatures = replay_oracle_signatures(&run.oracle_events, &input);
        let matched = signatures.iter().any(|s| s == want);
        (
            matched,
            "runtime oracle signature",
            want.to_owned(),
            signatures.first().cloned(),
            run,
        )
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
        let actual = match &verdict {
            PostconditionVerdict::Finding { signature, .. } => Some(signature.clone()),
            _ => None,
        };
        (
            actual.as_deref() == Some(want),
            "postcondition signature",
            want.to_owned(),
            actual,
            run,
        )
    } else {
        let run = run_binary_once(&invocation, mode, &input, &env, timeout, &tmp_dir, None)?;
        let want = finding_signature(&finding)?;
        let matched = signature_matches(&run, &want);
        let actual = run.crashed().then(|| run.signature.clone());
        (matched, "crash signature", want, actual, run)
    };
    let duration = started.elapsed();
    let _ = fs::remove_dir_all(&tmp_dir);
    let (matched, compared, recorded, actual, run) = replayed;
    Ok(BinaryReplay {
        matched,
        compared,
        recorded,
        actual,
        run,
        mode,
        timeout,
        duration,
    })
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
        for hit in runtrace::confirmed_sink_hits(&confirmed) {
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
    // Written on a thread, so a target that never reads an input larger than
    // the pipe buffer cannot block the deadline below.
    let writer = (mode == BinaryInputMode::Stdin)
        .then(|| replay_min::process::feed_stdin(&mut child, input.to_vec()))
        .flatten();
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
    // A target that exits before reading all of its input closes the pipe;
    // its exit status, not the write, is the result.
    if let Some(writer) = writer {
        let _ = replay_min::process::join_bounded(writer, replay_min::process::DRAIN_GRACE);
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

/// Spawn the retained target with `input` for the #76 collector REPLAY: a real
/// target process the collector observes while it runs. Delivers the input the
/// same way the campaign does (stdin or a file-mode argv path), inherits `env`,
/// and returns the running child so the host can record its real PID and bound its
/// execution. Unlike [`run_binary_once`], it does NOT arm the runtime-oracle shim
/// (the external collector does the observing) and returns immediately after spawn.
fn spawn_replay_child(
    inv: &TargetInvocation,
    mode: BinaryInputMode,
    input: &[u8],
    env: &BTreeMap<String, String>,
    tmp_dir: &Path,
) -> anyhow::Result<collector_run::LaunchedReplay> {
    let input_file = match mode {
        BinaryInputMode::Stdin => None,
        BinaryInputMode::File => {
            let path = tmp_dir.join(format!("replay-input-{}.bin", nonce()));
            fs::write(&path, input).with_context(|| format!("write {}", path.display()))?;
            Some(path)
        }
    };
    let (program, argv) = inv.command_for(input_file.as_deref());
    let mut cmd = Command::new(&program);
    cmd.args(&argv);
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
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
        .with_context(|| format!("spawn replay target {}", program.display()))?;
    // Deliver stdin on a BACKGROUND thread so this returns immediately. A target
    // that never drains stdin (with an input larger than the pipe buffer) would
    // otherwise block `write_all` here forever, stalling the launch callback before
    // the supervisor's bounded wait could start — bypassing the replay deadline
    // (#76 re-review). The supervisor reaps this thread after the target exits or
    // is killed (the closed pipe unblocks the write); its error is surfaced rather
    // than discarded, though a BrokenPipe from a target that finished early is
    // benign. `stdin` is moved into the thread and dropped there, closing the pipe.
    let delivery = if mode == BinaryInputMode::Stdin {
        child.stdin.take().map(|mut stdin| {
            let input = input.to_vec();
            std::thread::spawn(move || stdin.write_all(&input))
        })
    } else {
        None
    };
    Ok(collector_run::LaunchedReplay { child, delivery })
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
        "env": recorded_env(env, &args.env_redaction),
        "redacted_env_keys": redacted_env_keys(env, &args.env_redaction),
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
        "env": recorded_env(env, &args.env_redaction),
        "redacted_env_keys": redacted_env_keys(env, &args.env_redaction),
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
        "env": recorded_env(env, &args.env_redaction),
        "redacted_env_keys": redacted_env_keys(env, &args.env_redaction),
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

/// The lineage of each of `seeds` (as [`run_inner`] collects them), as the
/// builtin engine runs them before it mutates them: the operator's
/// `--seed-input`s, then `--seed-file`s named by their path, each 0
/// generations down; or, when given none, the empty input bhf made itself.
fn seed_lineages(args: &BinaryFuzzArgs, seeds: &[Vec<u8>]) -> Vec<corpus::lineage::FindingLineage> {
    if args.seed_inputs.is_empty() && args.seed_files.is_empty() {
        return seeds
            .iter()
            .map(|seed| crate::fuzz_lineage::of_generated_input(seed))
            .collect();
    }
    let paths = args
        .seed_inputs
        .iter()
        .map(|_| None)
        .chain(args.seed_files.iter().map(|path| Some(path.as_path())));
    seeds
        .iter()
        .zip(paths)
        .map(|(seed, path)| crate::fuzz_lineage::of_operator_input(seed, path))
        .collect()
}

/// The lineage of `input`, one of the run's `seeds`: the first seed with its
/// bytes.
fn lineage_of_seed(
    seeds: &[Vec<u8>],
    lineages: &[corpus::lineage::FindingLineage],
    input: &[u8],
) -> corpus::lineage::FindingLineage {
    seeds
        .iter()
        .zip(lineages)
        .find(|(seed, _)| seed.as_slice() == input)
        .map(|(_, lineage)| lineage.clone())
        .unwrap_or_else(|| {
            corpus::lineage::FindingLineage::unknown("the input is not one of the run's seeds")
        })
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

/// The env to RECORD in a finding: every key's resolved value verbatim, EXCEPT
/// keys whose value came from a `${secret:NAME}` / `${env:NAME}` handle (per
/// `redaction`, populated only by `bhf project run`), which are recorded as the
/// handle so a secret value never lands in `finding.json`. The real value still
/// reaches the child during the run; replay re-resolves the handle from the
/// environment (see [`finding_env`]).
fn recorded_env(
    env: &BTreeMap<String, String>,
    redaction: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    env.iter()
        .map(|(key, value)| {
            let recorded = redaction.get(key).cloned().unwrap_or_else(|| value.clone());
            (key.clone(), recorded)
        })
        .collect()
}

/// The (sorted) env keys whose recorded value is a redacted handle — the keys
/// `bhf replay`/`minimize` must RE-RESOLVE from the environment instead of
/// trusting the stored value. Empty for a standalone `bhf binary fuzz` finding.
fn redacted_env_keys(
    env: &BTreeMap<String, String>,
    redaction: &BTreeMap<String, String>,
) -> Vec<String> {
    env.keys()
        .filter(|key| redaction.contains_key(*key))
        .cloned()
        .collect()
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

/// Rebuild the real env a finding ran under, for `bhf replay`/`minimize`.
///
/// A key listed in `redacted_env_keys` (a `bhf project run` secret/handle) is
/// RE-RESOLVED from the live environment via the same `BHF_SECRET_<NAME>` /
/// `${env:NAME}` mechanism `project run` used, so its value is NEVER read back
/// from the stored finding (where only the handle is kept). Every other key is a
/// recorded literal, used verbatim. Errors descriptively when a redacted handle
/// cannot be resolved (e.g. `BHF_SECRET_<NAME>` is unset at replay time), so a
/// reproduction never silently runs with a missing secret.
fn finding_env(finding: &Value) -> anyhow::Result<BTreeMap<String, String>> {
    let redacted: std::collections::BTreeSet<String> = finding
        .get("redacted_env_keys")
        .and_then(Value::as_array)
        .map(|keys| {
            keys.iter()
                .filter_map(|k| k.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let Some(env) = finding.get("env").and_then(Value::as_object) else {
        return Ok(BTreeMap::new());
    };
    let mut out = BTreeMap::new();
    for (key, value) in env {
        let Some(value) = value.as_str() else {
            continue;
        };
        if redacted.contains(key) {
            let resolved =
                project_profile::reresolve_env_handle(value, &project_profile::ProcessEnv)
                    .with_context(|| {
                        format!("re-resolve redacted env key `{key}` (`{value}`) for replay")
                    })?;
            out.insert(key.clone(), resolved);
        } else {
            out.insert(key.clone(), value.to_owned());
        }
    }
    Ok(out)
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
    corpus::hex_lower(&hasher.finalize())
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

        let dir = crate::test_support::TestDir::new(&format!("binfuzz-{}", nonce()));
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

    /// A stdin target that never reads an input larger than the pipe buffer
    /// is still stopped at the time limit.
    #[cfg(unix)]
    #[test]
    fn a_binary_target_that_ignores_its_input_still_times_out() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("sleeper.sh");
        fs::write(&script, b"#!/bin/sh\nexec sleep 30\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let invocation = TargetInvocation {
            binary: script,
            runner: None,
            runner_args: Vec::new(),
            target_args: Vec::new(),
        };
        let started = Instant::now();
        let run = run_binary_once(
            &invocation,
            BinaryInputMode::Stdin,
            &vec![0u8; 1 << 20],
            &BTreeMap::new(),
            Duration::from_millis(300),
            dir.path(),
            None,
        )
        .expect("run the target");
        assert!(run.timeout, "the run is a timeout");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
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
        let dir = crate::test_support::TestDir::new(&format!("binfuzz-runner-{}", nonce()));
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
            env_redaction: BTreeMap::new(),
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
            adapter_report: None,
            persistent_addr: None,
            entrypoint: None,
            no_cmplog: false,
            rng_seed: 0,
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

    /// #247: the AFL++ queue entries that found new coverage replay first.
    /// AFL++ runs on Unix, and its queue names hold `:`, which a Windows path
    /// cannot.
    #[cfg(unix)]
    #[test]
    fn new_coverage_queue_entries_replay_first() {
        let dir = crate::test_support::TestDir::new("afl-queue-order");
        for (name, body) in [
            ("id:000000,time:0,execs:0,orig:seed-0000", "seed"),
            (
                "id:000001,src:000000,time:5,execs:9,op:havoc,rep:2",
                "plain",
            ),
            (
                "id:000002,src:000001,time:9,execs:40,op:havoc,rep:4,+cov",
                "cov",
            ),
        ] {
            fs::write(dir.join(name), body).unwrap();
        }
        fs::create_dir(dir.join(".state")).unwrap();
        let replays = afl_queue_replays(AflBinaryMode::Qemu, &dir).unwrap();
        let names: Vec<&str> = replays.iter().map(|(r, _)| r.testcase.as_str()).collect();
        assert_eq!(
            names,
            ["queue-id-000002", "queue-id-000000", "queue-id-000001"]
        );
        assert_eq!(replays[0].0.input, b"cov");
        assert!(afl_queue_replays(AflBinaryMode::Qemu, &dir.join("absent"))
            .unwrap()
            .is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn spawn_replay_child_does_not_block_on_a_target_that_never_reads_stdin() {
        use std::os::unix::fs::PermissionsExt;
        // #76 re-review: a target that keeps stdin open WITHOUT reading it, plus an
        // input larger than the pipe buffer, must not block the launch. stdin is
        // delivered on a background thread, so spawn_replay_child returns promptly
        // and the supervisor's bounded wait runs. The old inline write_all would
        // block here until the target exited, bypassing the replay deadline — so
        // under the old code this call would hang for the target's full lifetime.
        let dir = crate::test_support::TestDir::new(&format!("replay-noread-{}", nonce()));
        let target = dir.join("sleeper.sh");
        std::fs::write(&target, "#!/bin/sh\nsleep 30\n").unwrap();
        let mut perms = std::fs::metadata(&target).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&target, perms).unwrap();

        let inv = TargetInvocation {
            binary: target,
            runner: None,
            runner_args: Vec::new(),
            target_args: Vec::new(),
        };
        let big = vec![0_u8; 256 * 1024]; // >> the ~64 KiB pipe buffer
        let env = std::collections::BTreeMap::new();
        let started = std::time::Instant::now();
        let launched = spawn_replay_child(&inv, BinaryInputMode::Stdin, &big, &env, &dir).unwrap();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "launch must return without blocking on an undrained stdin write"
        );
        // Reap BOTH: killing the target closes the pipe, which unblocks and ends
        // the background delivery thread.
        let mut child = launched.child;
        let _ = child.kill();
        let _ = child.wait();
        if let Some(handle) = launched.delivery {
            let _ = handle.join();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod afl_qemu_tests {
    use super::*;

    #[test]
    fn argv_stdin_mode_has_no_at_at() {
        let argv = afl_binary_argv(
            AflBinaryMode::Qemu,
            false,
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
        let argv = afl_binary_argv(
            AflBinaryMode::Qemu,
            false,
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
        let argv = afl_binary_argv(
            AflBinaryMode::Qemu,
            false,
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
        let dir = crate::test_support::TestDir::new(&format!("aqt-{}", nonce()));
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
        assert_eq!(parse_duration_secs("0.5s"), Some(1));
    }

    /// Frida mode is `afl-fuzz -O`, in place of QEMU mode's `-Q`, with the
    /// same campaign flags (#322).
    #[test]
    fn frida_mode_runs_afl_fuzz_with_o() {
        let argv = afl_binary_argv(
            AflBinaryMode::Frida,
            false,
            Path::new("/b/target"),
            Path::new("/s"),
            Path::new("/o"),
            7,
            1000,
            "none",
            BinaryInputMode::File,
            &[],
        );
        assert_eq!(
            argv,
            [
                "-O",
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
                "/b/target",
                "@@"
            ]
        );
        assert_eq!(AflBinaryMode::Frida.engine(), "afl-frida");
    }

    /// CmpLog runs through the same binary (`-c 0`) unless it is turned off
    /// (#376).
    #[test]
    fn cmplog_is_c_0_unless_turned_off() {
        for afl_mode in [AflBinaryMode::Qemu, AflBinaryMode::Frida] {
            let argv = |cmplog| {
                afl_binary_argv(
                    afl_mode,
                    cmplog,
                    Path::new("/b/target"),
                    Path::new("/s"),
                    Path::new("/o"),
                    7,
                    1000,
                    "none",
                    BinaryInputMode::Stdin,
                    &[],
                )
            };
            let on = argv(true);
            assert_eq!(on[..3], [afl_mode.flag(), "-c", "0"], "{on:?}");
            assert!(!argv(false).iter().any(|arg| arg == "-c"));
        }
        #[derive(clap::Parser)]
        struct Fuzz {
            #[command(flatten)]
            args: BinaryFuzzArgs,
        }
        let parsed = |extra: &[&str]| {
            <Fuzz as clap::Parser>::try_parse_from(["fuzz", "bin"].iter().chain(extra).copied())
                .map(|fuzz| fuzz.args.no_cmplog)
        };
        assert!(!parsed(&[]).unwrap(), "CmpLog is on by default");
        assert!(parsed(&["--no-cmplog"]).unwrap());
    }

    /// #444: afl-fuzz refuses to start in QEMU or Frida mode when every core
    /// is bound to another CPU-locked process, and the pass failed with
    /// "afl-fuzz -Q exited non-zero". It runs again, once, with
    /// `AFL_NO_AFFINITY=1`, and the run JSON says why.
    #[cfg(unix)]
    #[test]
    fn an_afl_fuzz_that_finds_no_free_core_runs_again_without_binding_one() {
        use clap::Parser;
        use std::os::unix::fs::PermissionsExt;
        #[derive(clap::Parser)]
        struct Fuzz {
            #[command(flatten)]
            args: BinaryFuzzArgs,
        }
        let dir = crate::test_support::TestDir::new("binfuzz-no-free-core");
        let work = dir.join("work");
        let calls = dir.join("calls.log");
        let afl_fuzz = dir.join("afl-fuzz");
        std::fs::write(
            &afl_fuzz,
            format!(
                "#!/bin/sh\necho \"AFL_NO_AFFINITY=${{AFL_NO_AFFINITY:-unset}}\" >> '{}'\n\
                 if [ -z \"$AFL_NO_AFFINITY\" ]; then\n\
                 \x20 echo '[-] PROGRAM ABORT : No more free CPU cores'\n\
                 \x20 echo '         Location : bind_to_free_cpu(), src/afl-fuzz-init.c:448'\n\
                 \x20 exit 1\n\
                 fi\nexit 0\n",
                calls.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&afl_fuzz, std::fs::Permissions::from_mode(0o755)).unwrap();
        let args = Fuzz::try_parse_from([
            "fuzz".as_ref(),
            "/bin/true".as_ref(),
            "--work-dir".as_ref(),
            work.as_os_str(),
            "--time".as_ref(),
            "1s".as_ref(),
        ])
        .unwrap()
        .args;
        let findings = work.join("findings");
        std::fs::create_dir_all(&findings).unwrap();
        let afl = AflBinary {
            mode: AflBinaryMode::Qemu,
            afl_fuzz,
            trace: dir.join("afl-qemu-trace"),
        };
        let summary = run_afl_binary(
            &args,
            &afl,
            &[b"seed".to_vec()],
            None,
            &BTreeMap::new(),
            &findings,
        )
        .expect("the AFL pass runs");
        let calls = std::fs::read_to_string(&calls).unwrap();
        let calls: Vec<&str> = calls.lines().collect();
        match crate::fuzz::afl_no_affinity_at_start(std::iter::empty()) {
            // This test runs pinned or with AFL_NO_AFFINITY set: unbound
            // from the start, so no core is looked for.
            Some(reason) => {
                assert_eq!(calls, ["AFL_NO_AFFINITY=1"]);
                assert_eq!(summary["no_affinity"], json!(reason), "{summary:#}");
            }
            None => {
                assert_eq!(
                    calls,
                    ["AFL_NO_AFFINITY=unset", "AFL_NO_AFFINITY=1"],
                    "run again, once, unbound"
                );
                assert_eq!(summary["no_affinity"], "no_free_core", "{summary:#}");
            }
        }
        // A run that binds a core records nothing.
        let bound = dir.join("bound-afl-fuzz");
        std::fs::write(&bound, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&bound, std::fs::Permissions::from_mode(0o755)).unwrap();
        let afl = AflBinary {
            afl_fuzz: bound,
            ..afl
        };
        let summary = run_afl_binary(
            &args,
            &afl,
            &[b"seed".to_vec()],
            None,
            &BTreeMap::new(),
            &findings,
        )
        .unwrap();
        if crate::fuzz::afl_no_affinity_at_start(std::iter::empty()).is_none() {
            assert!(summary.get("no_affinity").is_none(), "{summary:#}");
        }
    }

    /// `--persistent-addr` and `--entrypoint` set each mode's variables, and
    /// QEMU mode's loop restores the registers (#375).
    #[test]
    fn persistent_and_entrypoint_set_the_mode_variables() {
        assert_eq!(
            afl_binary_env(AflBinaryMode::Qemu, Some(0x401136), Some(0x401000)),
            [
                ("AFL_QEMU_PERSISTENT_ADDR", "0x401136".to_owned()),
                ("AFL_QEMU_PERSISTENT_GPR", "1".to_owned()),
                ("AFL_ENTRYPOINT", "0x401000".to_owned()),
            ]
        );
        assert_eq!(
            afl_binary_env(AflBinaryMode::Frida, Some(0x401136), None),
            [("AFL_FRIDA_PERSISTENT_ADDR", "0x401136".to_owned())]
        );
        assert!(afl_binary_env(AflBinaryMode::Qemu, None, None).is_empty());
        assert_eq!(parse_address("0x401136"), Ok(0x401136));
        assert_eq!(parse_address("401136"), Ok(0x401136));
        assert!(parse_address("main").is_err());
    }

    #[test]
    fn frida_trace_is_looked_for_beside_afl_fuzz() {
        let candidates = afl_frida_trace_candidates(
            Some(PathBuf::from("/x/frida.so")),
            Some(PathBuf::from("/afl")),
            Path::new("/opt/aflpp/bin/afl-fuzz"),
        );
        assert_eq!(
            candidates[..3],
            [
                PathBuf::from("/x/frida.so"),
                PathBuf::from("/afl/afl-frida-trace.so"),
                PathBuf::from("/opt/aflpp/lib/afl/afl-frida-trace.so"),
            ]
        );
    }

    #[test]
    fn engine_builtin_is_always_builtin() {
        assert!(matches!(
            resolve_binary_engine(BinaryFuzzEngine::Builtin).unwrap(),
            ResolvedEngine::Builtin { degraded } if degraded.contains("no coverage feedback")
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
            assert!(matches!(
                explicit.unwrap(),
                ResolvedEngine::Afl(AflBinary {
                    mode: AflBinaryMode::Qemu,
                    ..
                })
            ));
            assert!(matches!(
                auto.unwrap(),
                ResolvedEngine::Afl(AflBinary {
                    mode: AflBinaryMode::Qemu,
                    ..
                })
            ));
        } else {
            let err = explicit.unwrap_err().to_string();
            assert!(
                err.contains("afl-qemu-trace") || err.contains("afl-fuzz"),
                "skip reason must name the missing tool: {err}"
            );
            // The fallback says why it has no coverage.
            assert!(matches!(
                auto.unwrap(),
                ResolvedEngine::Builtin { degraded } if degraded == err
            ));
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
        let dir = crate::test_support::TestDir::new(&format!("binfuzz-oracle-{}", nonce()));
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
            env_redaction: BTreeMap::new(),
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
            adapter_report: None,
            persistent_addr: None,
            entrypoint: None,
            no_cmplog: false,
            rng_seed: 0,
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

    /// Run `bhf binary fuzz --collector auto --runtime-oracles off` on `bin` with a
    /// single `seed` and return the rule ids of the collector-sourced
    /// `binary_semantic` (taint-confirmed) findings it produced. Asserts the Linux
    /// built-in runtrace collector was active and the #59 runtime oracles stayed off,
    /// so a returned rule id is unambiguously a taint-confirmed collector finding.
    #[cfg(unix)]
    fn collector_rule_ids(bin: &Path, seed: &str, work: &Path) -> Vec<String> {
        collector_rule_ids_campaign(bin, &[seed], work)
    }

    /// Multi-seed variant of [`collector_rule_ids`]: drives a `bhf binary fuzz
    /// --collector auto --runtime-oracles off` CAMPAIGN over every `seed` (one real
    /// execution each, under the collector's runtrace shim). This is the cross-
    /// execution evidence the #60 collector gate is built from, so a program constant
    /// reached untainted on some seed is suppressed. Same assertions/extraction as the
    /// single-seed helper.
    #[cfg(unix)]
    fn collector_rule_ids_campaign(bin: &Path, seeds: &[&str], work: &Path) -> Vec<String> {
        let args = BinaryFuzzArgs {
            binary: bin.to_path_buf(),
            work_dir: work.to_path_buf(),
            input_mode: BinaryInputMode::File,
            // Run every distinct seed once: the builtin engine caps iterations at the
            // seed count, so the campaign observes each real input under the shim.
            iterations: seeds.len(),
            seed_inputs: seeds.iter().map(|s| (*s).to_owned()).collect(),
            seed_files: Vec::new(),
            timeout_ms: 10_000,
            mem_mb: "none".to_owned(),
            env: Vec::new(),
            env_redaction: BTreeMap::new(),
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
            adapter_report: None,
            persistent_addr: None,
            entrypoint: None,
            no_cmplog: false,
            rng_seed: 0,
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

        let dir = crate::test_support::TestDir::new(&format!("binfuzz-collector-{}", nonce()));

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

    /// #60 validation-gated residual regression (PRODUCTION PATH). The dangerous
    /// case is a program CONSTANT whose bytes a reaching seed echoes: a naive
    /// byte-match sees it tainted, and with no untainted observation to refute it, it
    /// is wrongly taint-confirmed. The REPLACED fix (6ba0795) tried to supply that
    /// untainted observation with a single synthetic "contrast input" (the bitwise
    /// complement of the representative seed). That is the wrong shape: for the common
    /// INPUT-VALIDATING target (a parser/decoder that rejects anything not matching a
    /// magic byte), the complement fails validation and never reaches the sink, so no
    /// untainted observation is recorded and the constant stays FALSELY confirmed.
    ///
    /// This target validates `buf[0] == '{'` BEFORE it (a) `dlopen`s a FIXED library
    /// path (`/opt/plugins/cfg.so`, independent of input) whose token one seed echoes,
    /// and (b) `remove`s a path that genuinely tracks the input. The fix accumulates
    /// collector taint evidence across the CAMPAIGN's real, still-valid inputs: a
    /// second valid seed reaches the dlopen WITHOUT echoing the constant's token, so
    /// the constant is observed untainted and SUPPRESSED (no BHF-435), while the
    /// genuinely fuzz-controlled destructive op stays confirmed (BHF-440) — proving the
    /// cross-execution gate is supplied, not that confirmation was simply disabled.
    ///
    /// Red/green: on 6ba0795 the contrast (complement of `{"lib":"cfg.so"}`) fails the
    /// `buf[0] != '{'` gate, never reaches the dlopen, and the constant stays
    /// taint-confirmed — BHF-435 appears and this test FAILS. On the cross-campaign fix
    /// the second valid seed supplies the untainted sighting and BHF-435 is gone.
    #[cfg(unix)]
    #[test]
    fn binary_fuzz_collector_auto_validation_gated_constant_is_not_confirmed() {
        use std::os::unix::fs::PermissionsExt;
        if !runtime_oracle_e2e_ready() {
            eprintln!("skipping collector-auto validation-gated e2e: shim/cc/Linux unavailable");
            return;
        }

        let dir = crate::test_support::TestDir::new(&format!("binfuzz-valgate-{}", nonce()));

        // Input-validating target: rejects any input whose first byte is not '{' (so
        // 6ba0795's bitwise-complement contrast never reaches the sinks), then loads a
        // FIXED library path and performs a FUZZ-CONTROLLED destructive op.
        let src = dir.join("valgate.c");
        fs::write(
            &src,
            b"#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\
              #include <dlfcn.h>\n\
              int main(int argc, char **argv){\n\
              \x20 char buf[256]; buf[0]=0;\n\
              \x20 if(argc>1){ FILE*f=fopen(argv[1],\"rb\"); if(f){ size_t n=fread(buf,1,255,f); buf[n]=0; fclose(f);} }\n\
              \x20 size_t L=strlen(buf); while(L>0 && (buf[L-1]=='\\n'||buf[L-1]=='\\r')) buf[--L]=0;\n\
              \x20 /* INPUT VALIDATION: reject anything not starting with '{'. The\n\
              \x20    bitwise complement of any valid seed fails this gate, so the\n\
              \x20    replaced single-contrast fix never reaches the sinks below. */\n\
              \x20 if(buf[0] != '{') return 0;\n\
              \x20 /* CONSTANT library load: path is fixed, independent of input. */\n\
              \x20 void*h=dlopen(\"/opt/plugins/cfg.so\",RTLD_NOW); if(h) dlclose(h);\n\
              \x20 /* FUZZ-CONTROLLED destructive op: path tracks the input. */\n\
              \x20 char p[512]; snprintf(p,sizeof p,\"/tmp/bhf-col-%s\", buf); remove(p);\n\
              \x20 return 0;\n }\n",
        )
        .unwrap();
        let bin = dir.join("valgate");
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
        // CAMPAIGN of two valid (magic-byte-passing) inputs. The FIRST — the
        // representative the observation pass re-runs — echoes the constant's token
        // ("cfg.so"), so a single observation would byte-match it as tainted. The
        // SECOND reaches the SAME dlopen but shares no >=4-byte run with
        // "/opt/plugins/cfg.so", supplying the untainted observation that suppresses
        // the constant. Both drive a distinct, genuinely fuzz-controlled remove path.
        let rules = collector_rule_ids_campaign(
            &bin,
            &["{\"lib\":\"cfg.so\"}", "{\"name\":\"report\"}"],
            &work,
        );

        // The fix: a constant library load echoed into one reaching seed but observed
        // untainted on another is NOT taint-confirmed. (6ba0795 FAILS here: its
        // complement contrast fails the magic-byte gate, so the constant stays
        // confirmed and BHF-435 is present.)
        assert!(
            !rules.iter().any(|r| r == "BHF-435"),
            "a validation-gated constant library path must not be taint-confirmed \
             (BHF-435); got {rules:?}"
        );
        // Soundness: the fix did not merely disable confirmation — a sink that
        // genuinely tracks the input is still confirmed on this same campaign.
        assert!(
            rules.iter().any(|r| r == "BHF-440"),
            "a genuinely fuzz-controlled destructive op must still be taint-confirmed \
             (BHF-440); got {rules:?}"
        );

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
        let dir = crate::test_support::TestDir::new(&format!("binfuzz-postc-{}", nonce()));
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
            env_redaction: BTreeMap::new(),
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
            adapter_report: None,
            persistent_addr: None,
            entrypoint: None,
            no_cmplog: false,
            rng_seed: 0,
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
