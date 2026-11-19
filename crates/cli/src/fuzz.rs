// SPDX-License-Identifier: Apache-2.0

use crate::protocol_detect::HarnessProtocol;
use crate::runner::{harness_runner_for, SandboxModeArg};
use clap::ValueEnum;
use corpus::{
    classify, compute_signature, finding_tier, resolve_handler, CorpusManager, FindingEmitter,
    FindingTier, Signature, SignatureClass,
};
use event_log::{group_into_testcases, Event, EventReader, Testcase};
use fuzz_engine_builtin::binframe::FrameCodec;
use fuzz_engine_builtin::{
    generate_symbolic_seeds, Dictionary, Grammar, MutationInput, MutationRng, MutatorConfig,
    MutatorSuite, OperationSequenceLayout, OperationStepSpan, SymbolicSeedSource,
};
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::fresh_rerun::{FreshReruns, Placement, RerunContext};

mod collector_replay;
mod extension_stage;
mod honggfuzz;
mod libafl;
mod libfuzzer;
mod peer_sync;
pub(crate) mod shared_map;
pub(crate) mod typed_spans;
mod winafl;
pub use winafl::{WinaflInstrumentation, WinaflSettings};

/// Belt-and-suspenders kernel rails on every fuzz harness spawn.
///
/// 1. On Linux, `PR_SET_PDEATHSIG(SIGKILL)` — the kernel SIGKILLs the
///    harness if our process dies, so a panicking bhf can't leave orphan
///    workers behind.
/// 2. `RLIMIT_CPU = 600s` — each harness gets at most 10 minutes of
///    CPU time before the kernel reaps it.
///
/// RLIMIT_AS and RLIMIT_NPROC were applied here historically but
/// were removed: AddressSanitizer reserves ~128 TiB of shadow
/// memory and libFuzzer's helper threads exhaust modest NPROC
/// caps, so any VA/thread limit that's tight enough to actually
/// brake a runaway harness also breaks every sanitizer-instrumented
/// build. The crash-rate kill-switch and absolute wall-clock cap in
/// `auto::attempt::attempt` remain the orchestrator-level guard.
///
/// All four calls are best-effort: if the syscall fails (eg. an
/// existing RLIMIT_AS is already lower) we don't propagate. The
/// crash-rate and wall-clock checks in `auto::attempt` are the
/// primary guard; these rails are the last line of defence.
#[cfg(unix)]
fn apply_runaway_rlimits(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    // Give every harness its own process group. Targets routinely spawn shells
    // and helpers; a timeout must reap those descendants too, especially when
    // one inherited a captured stdout/stderr pipe that a drain thread joins.
    cmd.process_group(0);
    unsafe {
        cmd.pre_exec(|| {
            #[cfg(target_os = "linux")]
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            let cpu = libc::rlimit {
                rlim_cur: 600,
                rlim_max: 600,
            };
            libc::setrlimit(libc::RLIMIT_CPU, &cpu);
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn apply_runaway_rlimits(_cmd: &mut std::process::Command) {}

/// SIGKILL a child's entire process group, then the child, for a hard timeout
/// kill. The child must have been spawned with `process_group(0)` so its PID is
/// the group id; `kill(-pid, ...)` then reaps the forked grandchildren (e.g. the
/// persistent harness afl-fuzz forks) that a plain `child.kill()` would orphan.
/// Shared with replay and minimization.
use replay_min::process::kill_process_group;

/// SIGKILL any process still executing `exe`. AFL++'s persistent forkserver
/// `setsid()`s its worker into a fresh session, so a group kill of afl-fuzz can
/// leave that worker orphaned (reparented to init, often SIGSTOP-paused). After a
/// hard-deadline kill we reap by exe path so a hung run leaks no `main_afl`. Each
/// harness has a unique `harnesses/<id>/main_afl` path, so this only ever targets the
/// run's own binary. SIGCONT first in case the orphan is stopped.
#[cfg(target_os = "linux")]
fn kill_processes_by_exe(exe: &Path) {
    let exe = exe.canonicalize().unwrap_or_else(|_| exe.to_path_buf());
    let entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        if pid_str.is_empty() || !pid_str.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if let Ok(target) = fs::read_link(entry.path().join("exe")) {
            if target == exe {
                if let Ok(pid) = pid_str.parse::<i32>() {
                    unsafe {
                        libc::kill(pid, libc::SIGCONT);
                        libc::kill(pid, libc::SIGKILL);
                    }
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn kill_processes_by_exe(_exe: &Path) {}

/// Parse AFL++'s `out/default/fuzzer_stats` for the real execution counters
/// (`execs_done`, `execs_per_sec`). Returns `(execs_done, execs_per_sec)`; either
/// is `None` when the file or key is absent (afl-fuzz never wrote stats). The file
/// is `key : value` lines.
fn parse_afl_fuzzer_stats(out_dir: &Path) -> (Option<u64>, Option<f64>) {
    // Every instance's, summed (#276): `default`, or `main` and `sec1`...
    let mut total: (Option<u64>, Option<f64>) = (None, None);
    for instance in afl_instance_dirs(out_dir) {
        let (execs, per_sec) = parse_afl_instance_stats(&instance);
        if let Some(execs) = execs {
            total.0 = Some(total.0.unwrap_or(0) + execs);
        }
        if let Some(per_sec) = per_sec {
            total.1 = Some(total.1.unwrap_or(0.0) + per_sec);
        }
    }
    total
}

/// `execs_done` and `execs_per_sec` from one afl-fuzz instance's
/// `fuzzer_stats`.
fn parse_afl_instance_stats(instance: &Path) -> (Option<u64>, Option<f64>) {
    let text = match fs::read_to_string(instance.join("fuzzer_stats")) {
        Ok(text) => text,
        Err(_) => return (None, None),
    };
    let mut execs_done = None;
    let mut execs_per_sec = None;
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(':') {
            match key.trim() {
                "execs_done" => execs_done = value.trim().parse::<u64>().ok(),
                "execs_per_sec" => execs_per_sec = value.trim().parse::<f64>().ok(),
                _ => {}
            }
        }
    }
    (execs_done, execs_per_sec)
}

/// A fuzzed target may create files using fuzz-controlled paths (an archive
/// extractor, a `Stream_IO`/`File_Zipstream` writer, a TOML emitter, ...). Run
/// the harness with its working directory inside the run's own work dir so
/// those files land in one clearly-named, throwaway place - `<work>/
/// fuzz_scratch/` - instead of polluting wherever bhf was launched. The
/// whole work dir is the user's to delete, so the junk goes with it.
/// Whether a confirmed sink is bhf operating on its OWN files rather than the
/// target reaching a dangerous API.
///
/// A `ConfirmedSink` records the API and the path, but no frame — so unlike the
/// crash path, which suppresses findings with "no target frame" as harness
/// faults, the sink oracles cannot tell a call made by the TARGET from one made
/// by the driver or the harness around it. Everything the shim sees during an
/// execution becomes a finding attributed to whatever target was being fuzzed.
///
/// That produced a report that bhf could delete a file via a function whose
/// only call is `statvfs` — a read-only stat. `statvfs` cannot appear in the
/// BHF-440 API list at all, so the observed call came from elsewhere in the
/// process while the target merely happened to be the thing under test.
///
/// Confirmed in the field: the observed API was `unlink` and the path was
/// `testcase.bin` — bhf's OWN recorded-input file — reported as "attacker
/// input can delete a file" against a function whose only call is `statvfs`.
///
/// Housekeeping is recognised by the only signal actually available: the path
/// resolves inside bhf's own work directory. A TRAVERSAL still reports — a
/// target that escapes its scratch directory with `..` is the real BHF-440, and
/// suppressing that would trade a false positive for a false negative.
fn sink_subject_is_bhf_housekeeping(
    confirmed: &crate::auto::runtrace::ConfirmedSink,
    work_dir: &Path,
) -> bool {
    use crate::auto::runtrace::SinkClass;
    // DESTRUCTIVE sinks only. An earlier, broader version of this also covered
    // `OpenPath` and immediately broke `auto_confirms_path_controlled_open_bhf405`:
    // a target OPENING an attacker-named file relative to its CWD is a genuine
    // BHF-405, and the fuzz child's CWD is inside the work dir, so a containment
    // test suppressed the real finding. Trading this false positive for a false
    // negative would be the worse bargain.
    if !matches!(confirmed.class, SinkClass::DestructivePath) {
        return false;
    }
    // And only bhf's OWN temp artifacts, by the prefixes it creates them
    // under. Reported in the field: `unlink` on `/tmp/bhf_in032dWa` with
    // `fuzz_input[2..] -> unlink(path)`. `bhf_make_tempfile()` materialises the
    // fuzz bytes at `/tmp/bhf_inXXXXXX` precisely so a `const char *path`
    // parameter can be supplied at all — then bhf removes its own file, and
    // the oracle billed that to the target.
    //
    // Deliberately NOT the scratch/run directories that
    // `is_bhf_owned_resource` also covers: a target creating and deleting an
    // attacker-named file in its own working directory is a real BHF-440, and
    // suppressing by location would hide it.
    let subject = confirmed.subject.trim();
    if subject.contains("..") {
        return false;
    }
    let _ = work_dir;
    BHF_TEMP_PREFIXES
        .iter()
        .any(|prefix| subject.starts_with(prefix))
}

/// Where bhf materialises its own per-input temp files. Kept in step with
/// `runtrace::is_bhf_owned_resource`, which has known about these since the
/// resource-leak oracle — it was simply never consulted on the sink path.
const BHF_TEMP_PREFIXES: &[&str] = &["/tmp/bhf"];

fn ensure_harness_scratch(work_dir: &Path) -> Result<PathBuf, String> {
    let scratch = work_dir.join("fuzz_scratch");
    std::fs::create_dir_all(&scratch)
        .map_err(|error| format!("create fuzz scratch dir {}: {error}", scratch.display()))?;
    Ok(scratch)
}

#[derive(Debug, clap::Args)]
pub struct FuzzArgs {
    /// Path to bhf_work directory containing build/<harness-id>/.
    pub work_dir: PathBuf,

    /// Harness id under build/<harness-id>/.
    #[arg(long)]
    pub harness: String,

    /// Fuzz engine: the built-in coverage-guided engine (default), AFL++ via
    /// subprocess (`afl++`, needs `afl-fuzz`/`afl-clang-fast` on PATH),
    /// libFuzzer (`libfuzzer`, the harness's `main_libfuzzer`, built with
    /// `make libfuzzer` when absent), honggfuzz (`honggfuzz`, on the harness's
    /// `main_honggfuzz`; needs honggfuzz on PATH or in `BHF_HONGGFUZZ_PATH`),
    /// or WinAFL (`winafl`, native Windows only;
    /// needs WinAFL and DynamoRIO, see `--winafl-path` and `--dynamorio-path`).
    #[arg(long, value_enum, default_value_t = FuzzEngine::Builtin)]
    pub engine: FuzzEngine,

    /// WinAFL directory for `--engine winafl`: the one holding `afl-fuzz.exe`
    /// and `winafl.dll` (or a WinAFL checkout with `build64\bin\Release`).
    /// Default: `BHF_WINAFL_PATH`, then `afl-fuzz.exe` on `PATH`.
    #[arg(long = "winafl-path", value_name = "DIR")]
    pub winafl_path: Option<PathBuf>,

    /// DynamoRIO install root (or its `bin64` directory) for `--engine winafl`.
    /// Default: `BHF_DYNAMORIO_PATH`, then `DYNAMORIO_HOME`, then `drrun.exe` on
    /// `PATH`.
    #[arg(long = "dynamorio-path", value_name = "DIR")]
    pub dynamorio_path: Option<PathBuf>,

    /// How WinAFL collects coverage: `dynamorio` (default, `afl-fuzz -D`) or
    /// `intel-pt` (`afl-fuzz -P`; needs an Intel CPU with Processor Trace and
    /// a WinAFL built with `-DINTELPT=1`, and does not run in most VMs).
    #[arg(long = "winafl-instrumentation", value_enum, default_value_t = WinaflInstrumentation::Dynamorio)]
    pub winafl_instrumentation: WinaflInstrumentation,

    /// WinAFL `-fuzz_iterations`: calls of the persistent entry before WinAFL
    /// restarts the harness process. Default 5000.
    #[arg(long = "winafl-iterations", value_name = "N")]
    pub winafl_iterations: Option<u32>,

    /// Another module (a DLL of the target the harness loads) for WinAFL to
    /// measure coverage in, beside the harness executable. Repeatable.
    #[arg(long = "winafl-coverage-module", value_name = "MODULE")]
    pub winafl_coverage_modules: Vec<String>,

    /// Run the WinAFL build under full PageHeap for the run, so a heap overflow
    /// or use after free faults at once and WinAFL saves it as a crash (without
    /// it Windows ends a corrupted heap with a fail-fast WinAFL records as a
    /// hang). WinAFL fuzzes a copy of `main_winafl.exe` under a name only
    /// this run uses, and bhf sets the PageHeap Image File Execution Options key
    /// for that name (it prints the key) and removes key and copy when the run
    /// ends; needs an elevated shell.
    #[arg(long = "winafl-page-heap")]
    pub winafl_page_heap: bool,

    /// AFL++ execution mode for `--engine afl++`: `native` (default, compile-time
    /// instrumentation), `qemu` (`afl-fuzz -Q`), or `frida` (`afl-fuzz -O`).
    /// QEMU/Frida add coverage inside a stripped, source-less dependency the
    /// harness loads; the harness itself is still built as usual. Ignored by the
    /// builtin engine.
    #[arg(long = "afl-mode", value_enum, default_value_t = AflMode::Native)]
    pub afl_mode: AflMode,

    /// Directory of the AFL++ installation. Sets `AFL_PATH` and locates
    /// `afl-fuzz`, so QEMU/Frida mode finds `afl-qemu-trace` / `afl-frida-trace.so`
    /// from a build that is not on `PATH`.
    #[arg(long = "afl-path", value_name = "DIR")]
    pub afl_path: Option<PathBuf>,

    /// Scope binary-only instrumentation to a module or address range, e.g.
    /// `target.so` or `0x555000-0x556000`. Repeatable; joined into
    /// `AFL_QEMU_INST_RANGES` (`--afl-mode qemu`) or `AFL_FRIDA_INST_RANGES`
    /// (`--afl-mode frida`). Requires a binary-only `--afl-mode`.
    #[arg(long = "afl-inst-range", value_name = "RANGE")]
    pub afl_inst_ranges: Vec<String>,

    /// Run multiple fuzz workers. Use a number or `auto`. Each worker fuzzes an
    /// exact copy of the harness dirs in `<work>/worker-<id>-N/` and logs its
    /// stderr there; when every worker fails, the command exits non-zero and
    /// prints each worker's stderr tail.
    #[arg(long, value_parser = parse_worker_count)]
    pub workers: Option<FuzzWorkerCount>,

    /// Maximum number of harness executions. Defaults to 256 when neither this
    /// nor `--time` is given; when `--time` is set and this is omitted, the run
    /// is bounded only by the time budget (not silently capped at 256).
    #[arg(long)]
    pub iterations: Option<usize>,

    /// Optional wall-clock budget such as 30s, 5m, 1h or 1.5h.
    #[arg(long, value_parser = parse_duration)]
    pub time: Option<Duration>,

    /// Maximum generated input length in bytes (libFuzzer's `-max_len`). The
    /// built-in mutator never produces an input longer than this. With adaptive
    /// length control on (the default) this is the *ceiling*; the effective
    /// length starts small and grows as coverage plateaus.
    #[arg(long = "max-len", default_value_t = DEFAULT_MAX_LEN)]
    pub max_len: usize,

    /// Adaptive length control (libFuzzer's `-len_control`). The effective
    /// mutation length starts small and doubles toward `--max-len` after this
    /// many executions without a new corpus signature, so early fuzzing explores
    /// shallow/fast and deepens as it plateaus. `0` disables it (always use the
    /// full `--max-len`).
    #[arg(long = "len-control", default_value_t = DEFAULT_LEN_CONTROL)]
    pub len_control: usize,

    /// Per-input timeout (libFuzzer's `-timeout`): a single C/C++ harness
    /// execution that runs longer than this is killed, and an input that hangs
    /// again when re-run with twice the timeout is a hang finding (BHF-230).
    /// Distinct from `--time`, the whole-campaign budget. Defaults to 10s;
    /// `500ms` and `0.5s` are half a second. (The Ada lane bounds runaway
    /// inputs via CPU rlimits instead.)
    #[arg(long = "timeout", value_parser = parse_duration)]
    pub timeout: Option<Duration>,

    /// Real-time response deadline (the timing oracle, off by default). Distinct
    /// from `--timeout`, the coarse hang-kill backstop that reports only an
    /// input that hangs again at twice it: `--deadline` is a "must respond
    /// within D" budget, and any input whose host-side wall-clock execution
    /// exceeds it is recorded as a *finding* (BHF-555, a CWE-400
    /// timing/availability failure). Use it for watchdog / RTOS / radar
    /// targets where overrunning a budget is a fault, not just "it hung".
    /// Accepts the same duration spec as `--time` (`250ms`, `0.5s`, `2s`).
    #[arg(long = "deadline", value_parser = parse_duration)]
    pub deadline: Option<Duration>,

    /// Print a final-stats line at the end of the run (libFuzzer's
    /// `-print_final_stats`): executions, exec/s, new vs duplicate corpus
    /// signatures, findings, and elapsed time.
    #[arg(long = "print-final-stats")]
    pub print_final_stats: bool,

    /// Print no progress lines. Without it the builtin engine prints a status
    /// line on stderr (executions, exec/s, corpus entries, findings, edges,
    /// elapsed) 2s into the run, then at doubling intervals up to every 30s,
    /// so a long run does not look hung. Workers of `--workers` always run
    /// quiet.
    #[arg(long, short = 'q')]
    pub quiet: bool,

    /// Resident-memory ceiling in MB for a single C/C++ harness execution
    /// (libFuzzer's `-rss_limit_mb`). An execution whose RSS exceeds this is
    /// killed and reported as an out-of-memory finding. `0` (default) disables
    /// it. (RSS is polled rather than an `RLIMIT_AS` cap, which would break
    /// ASan's large virtual-address reservation.)
    #[arg(long = "rss-limit-mb", default_value_t = 0)]
    pub rss_limit_mb: usize,

    /// Force the persistent fork-server execution mode (it is the default for
    /// the builtin engine; this only matters to override `--no-fork-server` or
    /// `BHF_FORK_SERVER=0`). One harness process is kept alive and fed inputs
    /// over a framed protocol, amortizing fork/exec/elaboration (~38x more
    /// execs/sec) while preserving the coverage-guided feedback. Every finding is
    /// replay-validated in a fresh process, so a global-state artifact never
    /// escapes; a hard crash falls back to a per-spawn run and respawns.
    #[arg(long)]
    pub fork_server: bool,

    /// Disable the fork-server and run a fresh process per input. Use for a
    /// target that intentionally carries fuzz-relevant global state across calls
    /// (a stateful state machine), where the per-spawn dynamics are preferred.
    #[arg(long)]
    pub no_fork_server: bool,

    /// Literal seed input; its UTF-8 bytes become a seed. Use `--seed-file` for
    /// a binary seed (any byte value, including NUL).
    #[arg(long = "seed-input")]
    pub seed_inputs: Vec<String>,

    /// File containing seed input bytes, used byte for byte. For a C/C++
    /// harness that decodes fixed-width parameters before its buffer, the
    /// seed is also given behind that many zero bytes, so the buffer starts
    /// with it.
    #[arg(long = "seed-file")]
    pub seed_files: Vec<PathBuf>,

    /// A seed file a multi-worker campaign hands its worker itself: an entry
    /// of the shared queue, or seed bytes the campaign wrote to a file (a
    /// seed's layout-prefixed variant, a programmatic seed). Read like
    /// `--seed-file`, but not a seed given to `bhf fuzz`, so its lineage
    /// names what it was made from, not this copy. Internal.
    #[arg(long = "campaign-seed-file", hide = true)]
    pub campaign_seed_files: Vec<PathBuf>,

    /// qemu-user executable to run a cross-built harness under. Default: the
    /// emulator recorded beside the harness (`bhf_runner.json`, written by a
    /// cross build); a harness built for another architecture with neither is
    /// refused.
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

    /// Raw seed bytes supplied programmatically (`bhf auto`: mined, user and
    /// reseeded corpus inputs). Kept as bytes end to end, so a seed that is not
    /// valid UTF-8 reaches the engine unchanged. Not a CLI flag.
    #[arg(skip)]
    pub seed_bytes: Vec<Vec<u8>>,

    /// The seeds already hold their layout-prefixed variants: a worker of a
    /// multi-worker campaign, whose campaign made them once for the seeds
    /// given to it. Internal.
    #[arg(long = "seeds-layout-prefixed", hide = true)]
    pub seeds_layout_prefixed: bool,

    /// Path to an explicitly-trusted extension manifest (`bhf.extension-manifest.v1`,
    /// TOML). When set, after the campaign the retained corpus is driven through
    /// the extension's out-of-process `oracle.evaluate` so a clean-exit semantic
    /// violation becomes a finding. Explicit load is the trust boundary; an
    /// extension is never auto-discovered. An extension crash/timeout/malformed
    /// reply is a bounded infrastructure result that never aborts the campaign nor
    /// becomes a target finding. (Evaluation runs post-run on retained inputs, not
    /// in the hot mutation loop; supported by the builtin engine.)
    #[arg(long = "extension", value_name = "MANIFEST")]
    pub extension: Option<PathBuf>,

    /// Sanitizer campaign matrix to arm, comma-separated (asan, msan, ubsan, tsan,
    /// lsan, and on an AArch64 host hwasan in place of asan), or the standalone
    /// value `none` (build coverage-only with no `-fsanitize=` — crash-only
    /// fuzzing without ASan/UBSan false positives).
    #[arg(long = "sanitizers", value_delimiter = ',')]
    pub sanitizers: Vec<String>,

    /// Ada source file to mine guarded literals into prototype symbolic seeds.
    #[arg(long = "symbolic-seed-source")]
    pub symbolic_seed_sources: Vec<PathBuf>,

    /// Deterministic RNG seed for built-in mutation.
    #[arg(long, default_value_t = 0x4756_4655_5a5a)]
    pub rng_seed: u64,

    /// Sandbox wrapper for harness execution.
    #[arg(long, value_enum, default_value_t = SandboxModeArg::Auto)]
    pub sandbox: SandboxModeArg,

    /// Actionability profile to optimize for.
    #[arg(long, default_value_t = actionability::RunMode::Reporting)]
    pub mode: actionability::RunMode,

    /// Override sandbox wrapper executable.
    #[arg(long, value_name = "PATH", requires = "sandbox")]
    pub sandbox_tool: Option<PathBuf>,

    /// Fail if the requested sandbox tool is unavailable.
    #[arg(long)]
    pub sandbox_strict: bool,

    /// Extra environment variables to set on the harness Command.
    /// Populated by `bhf auto` to thread BHF_RUNTRACE_MODE,
    /// LD_PRELOAD, and per-finding env injections without polluting
    /// the parent process env. Always empty for the CLI path.
    #[arg(skip)]
    pub extra_env: Vec<(String, String)>,

    /// Load the runtime sink oracles via the LD_PRELOAD runtrace shim (#59), so a
    /// clean-exit semantic violation — a fuzz-controlled command execution, path
    /// escape, dlopen, network egress, or SQL query — becomes a finding even when
    /// the target exits zero. `off` (default) is crash-only, preserving existing
    /// behaviour; `auto` enables them when the shim and platform (Linux) support
    /// it and skips otherwise; `on` requires them (errors if unavailable). A no-op
    /// when `bhf auto` already armed the shim through `extra_env`.
    #[arg(long = "runtime-oracles", value_enum, default_value_t = crate::runtime_oracles::RuntimeOracleMode::Off)]
    pub runtime_oracles: crate::runtime_oracles::RuntimeOracleMode,

    /// Path to a previously captured runtrace audit log produced
    /// with `BHF_CMPLOG=1`. When set, recovered cmplog operands
    /// seed both the mutator dictionary (positional-info-free token
    /// insert) and an offset-aware RedQueen-style splice that
    /// replaces operand_a with operand_b at the exact offset
    /// operand_a appears in the current input.
    #[arg(long, value_name = "PATH")]
    pub cmplog_log: Option<PathBuf>,

    /// Path to a JSON grammar describing the target's input format, for structure-aware
    /// generation plus tree mutation: the builtin engine generates inputs from the
    /// grammar, keeps each one's derivation tree, and mutates a kept input on its tree
    /// (a subtree derived afresh, a recursion repeated, or a subtree spliced in from
    /// another input's tree of the same rule), so those mutants stay sentences of the
    /// grammar. Each rule maps a non-terminal to a list of production strings where
    /// `{NAME}` references another rule; the start symbol is `START` if present, else
    /// the first rule.
    #[arg(long = "grammar", value_name = "PATH")]
    pub grammar_file: Option<PathBuf>,

    /// A binary frame descriptor for the builtin engine: a protocol profile
    /// (TOML, `bhf.protocol.v1`) of one message, whose fields describe each
    /// input of a single-input harness such as `parse_frame(buf, len)`. Every
    /// input is decoded into the message's fields, a mutation edits one field
    /// or the frame's bytes, and every length, checksum, TLV length and offset
    /// the message computes is recomputed before the harness runs it, so a
    /// mutant passes the target's length/CRC gate. The message's own frame is
    /// a seed.
    #[arg(long = "frame", value_name = "PROFILE")]
    pub frame_file: Option<PathBuf>,

    /// An AFL/libFuzzer dictionary (`name="token"` lines, `\xNN` escapes) whose
    /// tokens the mutator splices into inputs, on top of the harness's own
    /// `dictionary.txt`.
    #[arg(long = "dict", value_name = "PATH")]
    pub dict_file: Option<PathBuf>,

    /// Structure-aware input synthesis for the built-in engine.
    #[arg(long = "structured-inputs", value_enum, default_value_t = StructuredInputMode::Auto)]
    pub structured_inputs: StructuredInputMode,

    /// Override the bhf worker binary used by multicore orchestration.
    #[arg(long, value_name = "PATH", hide = true)]
    pub bhf_bin: Option<PathBuf>,

    /// Stop this run as soon as it has emitted this many DISTINCT findings (the
    /// built-in engine's in-process loop breaks the instant the count is hit).
    /// Set programmatically by `auto`'s `--per-target-finding-count` (the count
    /// REMAINING for the current pass); `None` runs to the time/iteration budget.
    /// Not a standalone CLI flag.
    #[arg(skip)]
    pub stop_after_findings: Option<usize>,

    /// Fuzz an off-host / on-target backend through the `target_transport` seam
    /// (HDF-1b) instead of the host libFuzzer/AFL lane. Additive: when this is
    /// absent the default host path runs byte-for-byte as before. Spec forms:
    /// `agent:tcp:HOST:PORT`, `agent:serial:/dev/ttyX[,baud=N]` (on-target agent),
    /// `gdb:HOST:PORT` (debug-probe/emulator gdbstub; needs
    /// `--transport-coverage-map`), and
    /// `qemu-system:qmp=HOST:PORT,gdb=HOST:PORT[,snapshot=TAG]` (full-system;
    /// needs `--transport-coverage-map`), and
    /// `renode:monitor=HOST:PORT,gdb=HOST:PORT[,snapshot=PATH]` (a Renode
    /// board: its telnet monitor saves and loads the baseline; needs
    /// `--transport-coverage-map`). Live agent/gdb/qemu/renode backends are
    /// hardware/emulator-gated; a malformed spec is a descriptive error.
    #[arg(long = "target-transport", value_name = "SPEC")]
    pub target_transport: Option<String>,

    /// Locate the input staging buffer and the on-target coverage ring for the
    /// memory-read transports (`gdb`, `qemu-system`, `renode`) as
    /// `input=<addr>,input_cap=<n>,ring=<addr>,write=<addr>,wrapped=<addr>,cap=<n>`,
    /// plus `input_len=<addr>` when the firmware reads the input's length from
    /// a `u32` there, and `cmplog=<addr>,cmplog_cap=<n>` for the comparison
    /// record the firmware fills for CmpLog (each value decimal or `0x`-hex).
    /// `input_cap` is the
    /// staging buffer's size: no input is written past it. The `agent`
    /// transport carries coverage over its protocol and rejects this option.
    #[arg(long = "transport-coverage-map", value_name = "SPEC")]
    pub transport_coverage_map: Option<String>,

    /// Take `--target-transport` and `--transport-coverage-map` from a board
    /// profile (#293): a TOML file of one board's transport contract, with
    /// `gdb` and `coverage_map` for its debug probe and `serial` for the
    /// reference agent on its UART. See docs/hil-bringup.md.
    #[arg(long = "board-profile", value_name = "PATH")]
    pub board_profile: Option<PathBuf>,

    /// The board profile's lane to run: `gdb` (the debug probe) or `serial`
    /// (the agent on the board's UART).
    #[arg(
        long = "board-lane",
        value_enum,
        default_value = "gdb",
        requires = "board_profile"
    )]
    pub board_lane: crate::board_profile::BoardLane,

    /// Load a versioned protocol profile (TOML, `bhf.protocol.v1`) and fuzz the
    /// target as a response-dependent, multi-message session (HDF-7) instead of
    /// single opaque inputs. Additive: when this is absent the default host /
    /// transport paths run byte-for-byte as before. Presence routes to the
    /// session lane, which needs `--session-transport`. A testcase is a sequence
    /// of structured messages; mutation edits field values AND sequence structure
    /// and a repair pass recomputes derived length/CRC fields and re-resolves
    /// response back-references before send. Findings (a clean-exit protocol
    /// violation, no crash) are written through the usual `results/` layout for
    /// importers / SARIF / vulnerability-management tools.
    #[arg(long = "protocol-profile", value_name = "PATH")]
    pub protocol_profile: Option<PathBuf>,

    /// Request/response backend for the session lane. `tcp:HOST:PORT` connects a
    /// socket per session; `udp:HOST:PORT` sends each message as a datagram from
    /// a socket of its own per session and waits for one reply datagram.
    /// Required when `--protocol-profile` is set.
    #[arg(long = "session-transport", value_name = "SPEC")]
    pub session_transport: Option<String>,

    /// A command that runs the service the session lane fuzzes, through the
    /// shell. bhf starts it (with `ASAN_OPTIONS` set to report and exit on the
    /// first error, unless the environment sets it), waits until it serves the
    /// `--session-transport` port, and after each session checks whether it
    /// exited: a session that crashes it, again on a restart, is a finding,
    /// from the sanitizer report in its stderr when there is one. The service
    /// is started again and the campaign goes on. A service that does not
    /// start is exit 2, with its stderr.
    #[arg(long = "session-server-cmd", value_name = "COMMAND")]
    pub session_server_cmd: Option<String>,

    /// How long the session lane waits for a reply before the target is taken
    /// to have ended the session (default 5s over TCP, 1s over UDP).
    #[arg(long = "session-reply-timeout", value_parser = parse_duration, value_name = "DURATION")]
    pub session_reply_timeout: Option<Duration>,

    /// How a session is reset between testcases: `reconnect` (default; a fresh
    /// connection gives fresh per-session target state, so a new handle / id /
    /// nonce is captured each run) or `none`. Recorded as the run's reset
    /// fidelity.
    #[arg(long = "session-reset", value_enum, default_value_t = crate::session_fuzz::SessionResetMode::Reconnect)]
    pub session_reset: crate::session_fuzz::SessionResetMode,

    /// Bounded cap on messages per session (default 64); a sequence mutation that
    /// would exceed it fails with a diagnostic rather than growing unbounded.
    #[arg(long = "max-session-messages", default_value_t = 64)]
    pub max_session_messages: usize,

    /// Runtime-event collector that observes process, filesystem, and module-load
    /// effects the harness performs even on a clean exit (#60). `auto` selects the
    /// built-in provider for the platform: the native Windows ETW provider
    /// `bhf-collector-win`, or on Linux the in-process `LD_PRELOAD` runtrace
    /// adapter, which arms the runtrace shim for the run (with `--runtime-oracles
    /// off` it writes no runtime-oracle findings) and stays inactive only when the
    /// shim is unavailable. A PATH runs an external sidecar that speaks the
    /// bhf.collector-event.v1 JSONL protocol; `none` (default) disables it. A
    /// collected semantic violation becomes a `binary_semantic` finding (no crash
    /// needed), with the raw collector session stored for deterministic replay.
    #[arg(long = "collector", value_parser = crate::collector_run::parse_collector_spec, default_value = "none")]
    pub collector: crate::collector_run::CollectorSpec,

    /// How long, in milliseconds, to keep observing descendant-process effects
    /// after the testcase process exits — the bounded post-exit observation
    /// window (#60).
    #[arg(long = "collector-window-ms", default_value_t = crate::collector_run::DEFAULT_WINDOW_MS)]
    pub collector_window_ms: u64,
}

impl FuzzArgs {
    /// The execution cap the fuzz loop should use. An explicit `--iterations`
    /// always wins; otherwise a `--time` budget runs unbounded (so a time-based
    /// campaign isn't silently capped at the 256 default), and with neither set
    /// we fall back to 256.
    pub(crate) fn effective_iterations(&self) -> usize {
        resolve_iterations(self.iterations, self.time.is_some())
    }
}

const DEFAULT_ITERATIONS: usize = 256;
const PORTFOLIO_FEEDBACK_FILE: &str = "portfolio-feedback.json";

/// Default maximum generated input length, matching the built-in mutator's
/// historical fixed cap (and libFuzzer's default).
pub(crate) const DEFAULT_MAX_LEN: usize = 4096;

/// Memory/disk retention bounds for one active target's coverage corpus. The byte
/// budget is derived from available host/cgroup memory; the entry count follows
/// from that byte budget and the configured maximum input length. Both have exact
/// operator overrides, so the OOM safeguard never imposes an unchangeable fuzzing
/// ceiling on a larger analysis host.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CorpusLimits {
    pub(crate) entries: usize,
    pub(crate) bytes: usize,
}

/// `bhf auto` publishes its explicit per-target disk/memory corpus budget
/// here because programmatic fuzz passes run on worker threads. Standalone
/// `bhf fuzz` leaves this at zero and retains its memory-derived behavior.
static AUTO_CORPUS_BYTES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub(crate) fn set_auto_corpus_limit_mib(mib: usize) {
    AUTO_CORPUS_BYTES.store(
        mib.saturating_mul(crate::resource_limits::MIB),
        std::sync::atomic::Ordering::SeqCst,
    );
}

pub(crate) fn corpus_limits(max_len: usize) -> CorpusLimits {
    let auto_bytes = AUTO_CORPUS_BYTES.load(std::sync::atomic::Ordering::SeqCst);
    let bytes = if auto_bytes > 0 {
        auto_bytes
    } else {
        crate::resource_limits::dynamic_bytes(
            "BHF_MAX_CORPUS_BYTES",
            64,
            64 * crate::resource_limits::MIB,
            128 * crate::resource_limits::MIB,
            2 * 1024 * crate::resource_limits::MIB,
        )
    };
    let estimated_entry_bytes = max_len.clamp(1024, 64 * 1024);
    let derived_entries = (bytes / estimated_entry_bytes).clamp(4096, 262_144);
    let entries =
        crate::resource_limits::env_usize("BHF_MAX_CORPUS_ENTRIES").unwrap_or(derived_entries);
    CorpusLimits { entries, bytes }
}

fn max_finding_record_bytes() -> u64 {
    crate::resource_limits::env_usize("BHF_MAX_FINDING_RECORD_BYTES")
        .unwrap_or(2 * crate::resource_limits::MIB) as u64
}

fn max_finding_dedup_keys() -> usize {
    if let Some(configured) = crate::resource_limits::env_usize("BHF_MAX_FINDING_DEDUP_KEYS") {
        return configured;
    }
    let bytes = crate::resource_limits::dynamic_bytes(
        "BHF_MAX_FINDING_DEDUP_BYTES",
        1024,
        32 * crate::resource_limits::MIB,
        32 * crate::resource_limits::MIB,
        512 * crate::resource_limits::MIB,
    );
    // Keys include owned signatures/paths and hash-table overhead. 512 bytes is
    // deliberately conservative; this controls retention, not finding emission.
    (bytes / 512).clamp(65_536, 1_048_576)
}
fn max_symbolic_source_bytes() -> usize {
    crate::resource_limits::dynamic_bytes(
        "BHF_MAX_SYMBOLIC_SOURCE_BYTES",
        256,
        16 * crate::resource_limits::MIB,
        16 * crate::resource_limits::MIB,
        256 * crate::resource_limits::MIB,
    )
}

fn max_symbolic_sources_total_bytes() -> usize {
    crate::resource_limits::dynamic_bytes(
        "BHF_MAX_SYMBOLIC_SOURCES_TOTAL_BYTES",
        64,
        64 * crate::resource_limits::MIB,
        64 * crate::resource_limits::MIB,
        2 * 1024 * crate::resource_limits::MIB,
    )
}

fn max_grammar_bytes() -> usize {
    crate::resource_limits::env_usize("BHF_MAX_GRAMMAR_BYTES")
        .unwrap_or(16 * crate::resource_limits::MIB)
}

fn max_dictionary_bytes() -> usize {
    crate::resource_limits::env_usize("BHF_MAX_DICTIONARY_BYTES")
        .unwrap_or(16 * crate::resource_limits::MIB)
}
const BHF_VP_BYTES: usize = 1 << 16;

/// Read at most `cap` bytes from a seed without first allocating the whole file.
/// Returns `(prefix, original_len)` so callers can report truncation honestly.
pub(crate) fn read_seed_file_prefix(path: &Path, cap: usize) -> std::io::Result<(Vec<u8>, u64)> {
    let file = fs::File::open(path)?;
    let len = file.metadata()?.len();
    let mut bytes = Vec::with_capacity((len.min(cap as u64)) as usize);
    file.take(cap as u64).read_to_end(&mut bytes)?;
    Ok((bytes, len))
}

/// A `--seed-file`'s bytes, up to `max_len` (at least 1), saying when the
/// file was longer.
fn read_seed_file_within(seed_file: &Path, max_len: usize) -> Result<Vec<u8>, String> {
    let (bytes, original_len) = read_seed_file_prefix(seed_file, max_len.max(1))
        .map_err(|error| format!("read seed file '{}': {error}", seed_file.display()))?;
    if original_len > bytes.len() as u64 {
        bhfeprintln!(
            "bhf: seed '{}' is {original_len} bytes; using its first {} bytes \
             to honor --max-len",
            seed_file.display(),
            bytes.len()
        );
    }
    Ok(bytes)
}

/// Bound both the count and aggregate bytes of initial seeds. This is applied at
/// the engine boundary as well as during CLI loading, so programmatic `auto` and
/// symbolic-seed callers cannot bypass it.
fn bound_seed_corpus(seeds: &mut Vec<Vec<u8>>, max_len: usize) {
    let limits = corpus_limits(max_len);
    let before = seeds.len();
    let mut kept = Vec::with_capacity(before.min(limits.entries));
    let mut bytes = 0usize;
    for mut seed in seeds.drain(..) {
        seed.truncate(max_len);
        if kept.len() >= limits.entries {
            continue;
        }
        // Always retain the first seed, even when an explicit --max-len larger
        // than our normal byte budget opted into one unusually large sample.
        if !kept.is_empty() && bytes.saturating_add(seed.len()) > limits.bytes {
            continue;
        }
        bytes = bytes.saturating_add(seed.len());
        kept.push(seed);
    }
    let dropped = before.saturating_sub(kept.len());
    if dropped > 0 {
        bhfeprintln!(
            "bhf: seed corpus bounded to {} input(s) / {} MiB; dropped {dropped} \
             seed(s) beyond the in-memory corpus budget (override with \
             BHF_MAX_CORPUS_ENTRIES / BHF_MAX_CORPUS_BYTES)",
            kept.len(),
            bytes / (1024 * 1024),
        );
    }
    if kept.is_empty() {
        kept.push(Vec::new());
    }
    *seeds = kept;
}

/// Default `--len-control`: executions-without-new-coverage before the effective
/// mutation length doubles. Mirrors libFuzzer's default of 100.
pub(crate) const DEFAULT_LEN_CONTROL: usize = 100;

/// Effective mutation length the run starts at when length control is active.
pub(crate) const INITIAL_LEN_CONTROL_LEN: usize = 64;

/// Resolve the fuzz-loop execution cap. An explicit `--iterations` always wins;
/// otherwise a `--time` budget runs unbounded (`usize::MAX`) so the loop is
/// governed by wall-clock, not silently capped at 256; with neither, 256.
fn resolve_iterations(explicit: Option<usize>, has_time_budget: bool) -> usize {
    match (explicit, has_time_budget) {
        (Some(n), _) => n,
        (None, true) => usize::MAX,
        (None, false) => DEFAULT_ITERATIONS,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FuzzEngine {
    Builtin,
    #[value(name = "afl++")]
    AflPlusPlus,
    /// WinAFL on native Windows (DynamoRIO or Intel PT instrumentation).
    Winafl,
    /// libFuzzer, in process (#294): the harness's `main_libfuzzer`, built
    /// with `make libfuzzer` when there is none.
    Libfuzzer,
    /// honggfuzz in persistent mode (#295): the harness's `main_honggfuzz`,
    /// built with `make honggfuzz` (`hfuzz-clang`) when there is none.
    Honggfuzz,
    /// A LibAFL campaign over the harness (#296), in a bhf built with the
    /// `libafl-engine` feature.
    Libafl,
}

/// AFL++ execution mode for `--engine afl++` (issue #45). `native` uses
/// compile-time instrumentation (the historical behavior); `qemu`/`frida` add
/// AFL++'s binary-only modes so coverage is collected inside a stripped,
/// source-less dependency the harness loads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AflMode {
    Native,
    Qemu,
    Frida,
}

impl AflMode {
    /// The afl-fuzz flag that selects this binary-only mode, or `None` for the
    /// default compile-time-instrumented (`native`) run.
    fn flag(self) -> Option<&'static str> {
        match self {
            AflMode::Native => None,
            AflMode::Qemu => Some("-Q"),
            AflMode::Frida => Some("-O"),
        }
    }

    /// The AFL env var that scopes binary-only instrumentation to a module/range,
    /// or `None` for `native` (ranges do not apply without a binary-only mode).
    fn inst_ranges_env(self) -> Option<&'static str> {
        match self {
            AflMode::Native => None,
            AflMode::Qemu => Some("AFL_QEMU_INST_RANGES"),
            AflMode::Frida => Some("AFL_FRIDA_INST_RANGES"),
        }
    }

    /// Resolve `--afl-inst-range` values into the `(env_key, value)` pair to set
    /// on afl-fuzz, or `None` when there is nothing to scope (no ranges, or
    /// `native` mode).
    fn inst_ranges_env_value(self, ranges: &[String]) -> Option<(&'static str, String)> {
        if ranges.is_empty() {
            return None;
        }
        self.inst_ranges_env().map(|key| (key, ranges.join(",")))
    }

    fn as_str(self) -> &'static str {
        match self {
            AflMode::Native => "native",
            AflMode::Qemu => "qemu",
            AflMode::Frida => "frida",
        }
    }
}

/// Parse a comma-separated engine list (`auto --engine builtin,afl++`) into an
/// ordered, de-duplicated `Vec<FuzzEngine>`. Order is preserved as written; the
/// first occurrence of each engine wins. Whitespace around names is tolerated.
/// Empty input or an unknown name is an error. Accepted names mirror the
/// `FuzzEngine` value-enum (`builtin`, `afl++`, `winafl`, `libfuzzer`,
/// `honggfuzz`, `libafl`), plus
/// `afl`/`aflplusplus` synonyms for `afl++`.
pub(crate) fn parse_engine_list(raw: &str) -> Result<Vec<FuzzEngine>, String> {
    let mut out: Vec<FuzzEngine> = Vec::new();
    for tok in raw.split(',') {
        let name = tok.trim();
        if name.is_empty() {
            continue;
        }
        let engine = match name {
            "builtin" => FuzzEngine::Builtin,
            "afl++" | "aflplusplus" | "afl" => FuzzEngine::AflPlusPlus,
            "winafl" => FuzzEngine::Winafl,
            "libfuzzer" => FuzzEngine::Libfuzzer,
            "honggfuzz" => FuzzEngine::Honggfuzz,
            "libafl" => FuzzEngine::Libafl,
            other => {
                return Err(format!(
                    "unknown fuzz engine '{other}' (expected: builtin, afl++, winafl, libfuzzer, \
                     honggfuzz, libafl)"
                ))
            }
        };
        if !out.contains(&engine) {
            out.push(engine);
        }
    }
    if out.is_empty() {
        return Err("no fuzz engine specified (expected: builtin, afl++, winafl, libfuzzer, honggfuzz, libafl)".to_owned());
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
pub enum StructuredInputMode {
    Auto,
    Off,
    Record,
    Json,
    Xml,
    #[value(name = "kv")]
    Kv,
    Url,
    Multipart,
    Csv,
    Http,
    Ini,
    Toml,
    Yaml,
    Recursive,
}

impl StructuredInputMode {
    fn structured_records_enabled(self) -> bool {
        matches!(self, Self::Auto | Self::Record)
    }

    fn structured_json_enabled(self) -> bool {
        matches!(self, Self::Auto | Self::Json)
    }

    fn structured_xml_enabled(self) -> bool {
        matches!(self, Self::Auto | Self::Xml)
    }

    fn structured_key_value_enabled(self) -> bool {
        matches!(self, Self::Auto | Self::Kv)
    }

    fn structured_url_encoded_enabled(self) -> bool {
        matches!(self, Self::Auto | Self::Url)
    }

    fn structured_multipart_enabled(self) -> bool {
        matches!(self, Self::Auto | Self::Multipart)
    }

    fn structured_csv_enabled(self) -> bool {
        matches!(self, Self::Auto | Self::Csv)
    }

    fn structured_http_enabled(self) -> bool {
        matches!(self, Self::Auto | Self::Http)
    }

    fn structured_ini_enabled(self) -> bool {
        matches!(self, Self::Auto | Self::Ini)
    }

    fn structured_toml_enabled(self) -> bool {
        matches!(self, Self::Auto | Self::Toml)
    }

    fn structured_yaml_enabled(self) -> bool {
        matches!(self, Self::Auto | Self::Yaml)
    }

    fn structured_chunked_enabled(self) -> bool {
        // Binary chunked/length-prefixed shape: on in the default `Auto` mode.
        matches!(self, Self::Auto)
    }

    fn structured_recursive_enabled(self) -> bool {
        // Recursive/nested-grammar shape: on in `Auto`, or selectable on its own.
        matches!(self, Self::Auto | Self::Recursive)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzWorkerCount {
    Auto,
    Fixed(u32),
}

#[derive(Debug, Serialize)]
pub(crate) struct FuzzRunSummary {
    pub(crate) schema_version: u32,
    pub(crate) harness_id: String,
    pub(crate) engine: String,
    pub(crate) mode: actionability::RunMode,
    pub(crate) harness_path: PathBuf,
    pub(crate) sandbox: replay_min::SandboxMetadata,
    pub(crate) iterations_requested: usize,
    pub(crate) executions: usize,
    /// True only when a language harness emitted its checkpoint immediately
    /// before the selected project endpoint. Driver executions and driver-only
    /// coverage do not satisfy this proof.
    #[serde(default)]
    pub(crate) target_entry_observed: bool,
    pub(crate) corpus_new: usize,
    pub(crate) corpus_duplicates: usize,
    /// #401: number of coverage-guided corpus inputs flushed to
    /// `corpus/<hid>/queue/` at the end of the run (content-hash-named, seeds
    /// included). 0 for an empty pool. Makes the explored corpus replayable for
    /// neutral coverage measurement / `corpus minimize` instead of lost on exit.
    #[serde(default)]
    pub(crate) corpus_persisted: usize,
    pub(crate) execution: ExecutionRunSummary,
    pub(crate) cmplog: CmpLogRunSummary,
    pub(crate) sanitizers: SanitizerRunSummary,
    pub(crate) coverage: CoverageRunSummary,
    pub(crate) findings: Vec<String>,
    /// Findings recorded for this harness before the run (sorted ids) that a
    /// crash in this run matched, so the crash was not recorded again.
    #[serde(default)]
    pub(crate) duplicates_of_existing: Vec<String>,
    /// How many crashing executions matched one of `duplicates_of_existing`.
    #[serde(default)]
    pub(crate) duplicate_crashes_of_existing: usize,
    /// #405: actual wall-clock seconds this run spent fuzzing — the engine's
    /// measured run time, NOT the requested budget (a run can finish early or
    /// lose time to setup). 0.0 only when no measurable time elapsed.
    #[serde(default)]
    pub(crate) elapsed_secs: f64,
    /// #405: built-in-engine throughput — `executions / elapsed_secs` — for
    /// head-to-head parity with libFuzzer `average_exec_per_sec` / honggfuzz
    /// `speed`. 0.0 when no measurable time elapsed, and 0.0 for the AFL++
    /// engine (whose `executions` is the saved-crash count, not target execs;
    /// its real throughput is in AFL's own `fuzzer_stats`).
    #[serde(default)]
    pub(crate) executions_per_sec: f64,
    /// AFL++ binary-only run provenance (issue #45): the effective `--afl-mode`,
    /// `--afl-path`, and instrumentation ranges. `None` for the builtin engine
    /// and omitted from `run.json` for a plain `native` afl++ run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) afl: Option<AflRunProvenance>,
    /// WinAFL run provenance (`--engine winafl`): the tools, the uninstrumented
    /// binary WinAFL fuzzed and the sanitized one its saved inputs were
    /// replayed through, WinAFL's own statistics and the replay outcomes.
    /// Omitted for the other engines.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) winafl: Option<winafl::WinaflRunProvenance>,
    /// #57: out-of-process extension `oracle.evaluate` provenance for a
    /// `--extension` run — the negotiated protocol/capabilities, the extension's
    /// executable/config hashes, how many retained inputs were evaluated, how many
    /// semantic findings were emitted, and any bounded infrastructure errors. An
    /// additive, optional field: `schema_version` is unchanged, and it is omitted
    /// from `run.json` when no `--extension` was given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) extension: Option<serde_json::Value>,
    /// Later sanitizer crashes folded into an already-reported root cause, by
    /// dedupe key (`cluster_key_full` of the finding they matched): the hits
    /// that were not emitted as findings of their own. An additive, optional
    /// field, omitted when no crash was folded.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub(crate) duplicate_sanitizer_hits: std::collections::BTreeMap<String, usize>,
    /// Sanitizer crashes whose root cause never reproduced in a fresh process
    /// and so was never reported, by dedupe key: the failed confirmations plus
    /// the later hits that were no longer re-run. Not counted in
    /// `duplicate_sanitizer_hits`. An additive, optional field, omitted when
    /// empty.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub(crate) unreproduced_sanitizer_hits: std::collections::BTreeMap<String, usize>,
    /// The fork-server pass's fresh-process re-runs of new corpus inputs (the
    /// check for crashes only a fresh process sees). Omitted when none ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) fresh_reruns: Option<FreshRerunSummary>,
    /// The builtin pass's executions killed at the per-input timeout and
    /// their confirmation (#207). Omitted when none was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) hangs: Option<HangRunSummary>,
    /// The persistent engine's stability calibration of new corpus entries
    /// (#232). Omitted when none was calibrated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) stability: Option<StabilitySummary>,
    /// #331: what the pass's SymCC stage did: its rounds, the entries it ran
    /// and the inputs it gave the pass. Omitted when the pass had none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) symcc: Option<crate::symcc::SymccRunSummary>,
}

/// Fresh-process re-runs of new corpus inputs during one fork-server pass.
#[derive(Debug, Default, Serialize)]
pub(crate) struct FreshRerunSummary {
    /// Inputs queued for a re-run, including ones carried over from the last
    /// pass.
    pub(crate) submitted: usize,
    /// Re-runs that completed.
    pub(crate) checked: usize,
    /// Re-runs that produced a crash report the fork-server run did not.
    pub(crate) reports: usize,
    /// Inputs still unchecked when the pass ended. They stay in the corpus and
    /// are saved in `unchecked_dir`; the next pass on this work dir re-runs
    /// them first.
    pub(crate) unchecked: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) unchecked_dir: Option<PathBuf>,
}

/// AFL++ binary-only settings recorded in `run.json` so a run is reproducible
/// (issue #45). Serialized only when non-default.
#[derive(Debug, Serialize)]
pub(crate) struct AflRunProvenance {
    pub(crate) mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) afl_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) inst_ranges: Vec<String>,
    /// The CmpLog binary afl-fuzz ran with `-c` (#274), when there was one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cmplog_binary: Option<PathBuf>,
    /// The `-M`/`-S` instances `--workers` ran (#276); absent for one.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) instances: Vec<String>,
}

/// How many afl-fuzz instances a run of `engine` with `--workers` runs
/// (#276): `--workers N` for AFL++, `auto` one per core; one otherwise.
fn afl_worker_count(engine: FuzzEngine, workers: Option<FuzzWorkerCount>) -> usize {
    match (engine, workers) {
        (FuzzEngine::AflPlusPlus, Some(FuzzWorkerCount::Fixed(n))) => {
            usize::try_from(n).unwrap_or(1).max(1)
        }
        (FuzzEngine::AflPlusPlus, Some(FuzzWorkerCount::Auto)) => {
            std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
        }
        _ => 1,
    }
}

/// The CmpLog build beside `main_afl` that afl-fuzz runs with `-c` (#274):
/// `main_afl_cmplog`, for a compile-time-instrumented run, when it is at
/// least as new as `main_afl` (an older one was built from other sources).
fn afl_cmplog_binary(main_afl: &Path, mode: AflMode) -> Option<PathBuf> {
    if mode != AflMode::Native {
        return None;
    }
    let cmplog = main_afl.with_file_name(crate::auto::layout::harness_exe_name(
        crate::build::AFL_CMPLOG_BINARY,
    ));
    let modified = |path: &Path| fs::metadata(path).and_then(|meta| meta.modified()).ok();
    match (modified(&cmplog), modified(main_afl)) {
        (Some(cmplog_time), Some(afl_time)) if cmplog_time >= afl_time => Some(cmplog),
        (Some(_), _) => {
            bhfeprintln!(
                "bhf: {} is older than {}, so afl-fuzz runs without CmpLog (-c); rebuild it \
                 with `make afl_cmplog`",
                cmplog.display(),
                main_afl.display()
            );
            None
        }
        (None, _) => None,
    }
}

/// Throughput in executions/sec, guarding the zero-elapsed case (returns 0.0
/// rather than NaN/inf). Shared by every #405 emission site.
pub(crate) fn executions_per_sec(executions: usize, elapsed_secs: f64) -> f64 {
    if elapsed_secs > 0.0 {
        executions as f64 / elapsed_secs
    } else {
        0.0
    }
}

/// Edge-coverage measured during the run. The bhf driver (and the other lanes'
/// runtimes) set one byte per hit edge in a shared bitmap (#385); `edges` is
/// the popcount. Zero for harnesses without such a runtime (Ada event-log lane,
/// generated `-fsanitize=fuzzer` wrappers) or when BHF_COV_SHM was unset.
/// `source` names the instrumentation that fed the map, read from the harness
/// binary ([`crate::coverage_kind`]): `sancov-trace-pc-guard` (clang),
/// `sancov-trace-pc` (GCC), `go-cover`, `edge-bitmap` when the binary does not
/// say, or `none` without a map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CoverageRunSummary {
    pub(crate) edges: usize,
    pub(crate) source: String,
}

impl CoverageRunSummary {
    /// [`Self::source`] when an edge map was armed, else `None`.
    pub(crate) fn instrumentation(&self) -> Option<String> {
        (self.source != "none").then(|| self.source.clone())
    }
}

/// Read the bhf driver's edge-coverage bitmap (one byte per hit edge) from the
/// path in `BHF_COV_SHM`, counting distinct edges. The bitmap is MAP_SHARED so
/// it accumulates across every per-spawn child and within a persistent process.
/// Parse the driver's value-profile token log written at `path`
/// (`[u32 cursor][ {u8 len}{len bytes} ... ]`, native-endian cursor), returning
/// the mined comparison-operand tokens for the mutator dictionary (#398).
fn read_vp_tokens(path: &Path) -> Vec<Vec<u8>> {
    let Ok((bytes, _)) = read_seed_file_prefix(path, BHF_VP_BYTES) else {
        return Vec::new();
    };
    if bytes.len() < 4 {
        return Vec::new();
    }
    let cursor = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let end = (4 + cursor).min(bytes.len());
    let mut out = Vec::new();
    let mut i = 4usize;
    while i < end {
        let len = bytes[i] as usize;
        i += 1;
        if len == 0 || len > 8 || i + len > end {
            break;
        }
        out.push(bytes[i..i + len].to_vec());
        i += len;
    }
    out
}

fn coverage_from_env(extra_env: &[(String, String)], harness: &Path) -> CoverageRunSummary {
    let Some((_, path)) = extra_env.iter().find(|(k, _)| k == "BHF_COV_SHM") else {
        return CoverageRunSummary {
            edges: 0,
            source: "none".to_owned(),
        };
    };
    let edges = read_seed_file_prefix(Path::new(path), BHF_COV_BITS)
        .map(|(bytes, _)| bytes)
        .map(|bytes| bytes.iter().filter(|&&b| b != 0).count())
        .unwrap_or(0);
    CoverageRunSummary {
        edges,
        source: coverage_source_label(harness).to_owned(),
    }
}

/// The `coverage.source` label for a run of `harness` with an edge map armed.
fn coverage_source_label(harness: &Path) -> &'static str {
    crate::coverage_kind::of_binary(harness).map_or(
        crate::coverage_kind::UNIDENTIFIED_EDGE_MAP,
        crate::coverage_kind::CoverageInstrumentation::label,
    )
}

/// The harness binary's identity for `finding.json` `build.binary`, with the
/// coverage instrumentation it was built with (`coverage_instrumentation`)
/// when the binary shows one.
fn build_binary_record(harness: &Path) -> Option<serde_json::Value> {
    let mut identity = binary_analysis::build_identity(harness)
        .and_then(|identity| serde_json::to_value(identity).ok())?;
    if let (Some(kind), Some(object)) = (
        crate::coverage_kind::of_binary(harness),
        identity.as_object_mut(),
    ) {
        object.insert(
            "coverage_instrumentation".to_owned(),
            serde_json::json!(kind.label()),
        );
    }
    Some(identity)
}

fn target_entry_path(extra_env: &[(String, String)]) -> Option<&Path> {
    extra_env
        .iter()
        .find(|(key, _)| key == "BHF_TARGET_ENTRY_SHM")
        .map(|(_, value)| Path::new(value))
}

fn reset_target_entry(extra_env: &[(String, String)]) {
    if let Some(path) = target_entry_path(extra_env) {
        let _ = fs::write(path, [0u8]);
    }
}

fn target_entry_from_env(extra_env: &[(String, String)]) -> bool {
    target_entry_path(extra_env)
        .and_then(|path| read_seed_file_prefix(path, 1).ok())
        .is_some_and(|(bytes, _)| bytes.first().is_some_and(|byte| *byte != 0))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ExecutionRunSummary {
    pub(crate) harness_protocol: String,
    pub(crate) forkserver: bool,
    pub(crate) persistent: bool,
    pub(crate) persistent_iterations: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CmpLogRunSummary {
    pub(crate) enabled: bool,
    pub(crate) status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) log_path: Option<PathBuf>,
    pub(crate) entries: usize,
    pub(crate) dictionary_tokens: usize,
    pub(crate) seed_splice_candidates: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SanitizerRunSummary {
    pub(crate) requested: Vec<String>,
    pub(crate) active_env: Vec<EnvVarSummary>,
    pub(crate) composition_campaign: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct EnvVarSummary {
    pub(crate) key: String,
    pub(crate) value: String,
}

struct PreparedFuzzRun {
    work_dir: PathBuf,
    harness_id: String,
    harness_path: PathBuf,
    runner: replay_min::HarnessRunner,
    /// Whether the loop reads the runtrace log for runtime-oracle findings:
    /// false when only `--collector auto` armed the shim.
    runtrace_oracles: bool,
    seeds: Vec<Vec<u8>>,
    /// sha256 (and path, for a file) of each seed this `bhf fuzz` was given
    /// (`--seed-input`, `--seed-file`), which its lineage names as user seeds.
    operator_seeds: Vec<(corpus::lineage::Digest, Option<String>)>,
    iterations: usize,
    time: Option<Duration>,
    /// Stop the in-process loop once this many distinct findings are emitted
    /// (`--per-target-finding-count`). `None` = run to the time/iteration budget.
    stop_after_findings: Option<usize>,
    rng_seed: u64,
    engine: FuzzEngine,
    /// AFL++ binary-only mode (issue #45); `Native` for the default source run.
    afl_mode: AflMode,
    /// Explicit AFL++ install directory (`--afl-path`), or `None` for `PATH`.
    afl_path: Option<PathBuf>,
    /// Instrumentation ranges for `--afl-mode qemu|frida`.
    afl_inst_ranges: Vec<String>,
    /// `--engine winafl` settings (tool paths, instrumentation, iterations).
    winafl: WinaflSettings,
    /// The explicit `--timeout`, which becomes WinAFL's `-t`; `None` keeps
    /// WinAFL's default per-iteration timeout.
    winafl_timeout: Option<Duration>,
    mode: actionability::RunMode,
    extra_env: Vec<(String, String)>,
    /// `extra_env` for the builtin loop's own executions (the fork server and
    /// the per-spawn runs): the sanitizers neither symbolize nor abort
    /// ([`in_loop_env`]). Re-runs and confirmations use `extra_env`.
    loop_env: Vec<(String, String)>,
    /// Keeps the standalone builtin driver's coverage bitmap alive for the run.
    _local_coverage_map: Option<shared_map::SharedMapFile>,
    /// Keeps the RedQueen (#400) per-input cmplog operand map alive for the run.
    _local_cmp_map: Option<shared_map::SharedMapFile>,
    /// Keeps the value-profile (#398) map alive for the run.
    _local_vp_map: Option<shared_map::SharedMapFile>,
    /// Keeps the stack-depth (#220) word alive for the run.
    _local_stack_map: Option<shared_map::SharedMapFile>,
    /// Keeps the per-exec edge hit-count map (#420, #401) alive for the run.
    _local_count_map: Option<shared_map::SharedMapFile>,
    cmplog_log: Option<PathBuf>,
    grammar_file: Option<PathBuf>,
    frame_file: Option<PathBuf>,
    dict_file: Option<PathBuf>,
    structured_inputs: StructuredInputMode,
    sanitizers: Vec<multicore_fuzz::Sanitizer>,
    sanitizer_env: Vec<(String, String)>,
    fork_server: bool,
    max_len: usize,
    len_control: usize,
    per_input_timeout: Duration,
    /// Real-time response deadline (the timing oracle). `None` (default) leaves
    /// hang handling unchanged; `Some(d)` records any host-side execution longer
    /// than `d` as a BHF-555 finding instead of discarding it as a slow unit.
    deadline: Option<Duration>,
    print_final_stats: bool,
    rss_limit_mb: usize,
    /// `-G` (maximum generated input length) for afl-fuzz. Set only by the
    /// `bhf auto` AFL++ stage, from the run's resolved `--max-len`.
    afl_max_len: Option<usize>,
    /// afl-fuzz instances `--workers` asks for (#276): one `-M`, the rest `-S`.
    afl_workers: usize,
    /// Explicitly-trusted extension manifest (`--extension`). When set, the
    /// builtin engine drives `oracle.evaluate` over the retained corpus after the
    /// run. `None` leaves fuzzing byte-for-byte unchanged.
    extension_manifest: Option<PathBuf>,
    /// #331: the SymCC stage of a builtin pass, which runs the corpus entries
    /// of a plateau through `main_symcc` and runs the inputs it solves.
    /// `None` unless the run asked for SymCC and the harness has the lane.
    symcc: Option<crate::symcc::SymccConfig>,
}

#[derive(Clone)]
struct HarnessRun {
    events: Vec<Event>,
    testcases: Vec<Testcase>,
    /// Populated when the harness exited non-zero AND a sanitizer report was
    /// recognized in its stderr. The C/C++ fuzz path uses this to emit
    /// findings without an Ada event log.
    sanitizer: Option<corpus::SanitizerReport>,
    /// Raw stderr of the run that produced `sanitizer`, for `sanitizer.log`.
    stderr: Option<String>,
    /// #15: the target REJECTED this input (diagnosed assertion/panic or a non-zero error
    /// return on malformed bytes) — a clean no-finding run that the pass skips and
    /// continues past. Tracked so `run_builtin` can tell a target that rejected
    /// EVERY input (incl. the empty seed — a gate/seed/harness problem, reported as
    /// built-not-fuzzed) from one that genuinely fuzzed.
    rejected: bool,
    /// The per-input timeout the run was killed at, when it did not finish
    /// within it (#207): a hang to confirm, not yet a finding.
    hung: Option<Duration>,
}

/// Classify a non-success harness exit (called only when `!status.success()` and
/// NO sanitizer report was found): is it the target REJECTING this input, or a
/// real crash? Genuine crash signals — silent SIGABRT, SIGSEGV, SIGBUS, SIGILL,
/// SIGFPE — are NOT a rejection; without a sanitizer report they become BHF-210
/// findings so a real crash on a non-instrumented harness isn't silently
/// swallowed. Everything else is a rejection (#15: skip + continue):
///   - SIGABRT accompanied by a recognizable assertion/panic diagnostic,
///   - a plain non-zero exit code — an error return,
///   - SIGPIPE (13) — benign plumbing: the harness wrote to a closed pipe (e.g.
///     a `--comparison-progress` / stats pipe whose reader went away). It is
///     NEVER an attacker-triggerable memory-safety bug and does not reproduce
///     standalone, so misclassifying it manufactures a phantom BHF-210 "reachable
///     crash" (a valid glTF that exits 0 on replay) — exactly the false positive
///     that undermines triage,
///   - SIGTERM/SIGINT/SIGHUP/SIGALRM — external termination (timeout-kill, etc.),
///     handled by the timeout/hang path, not a code defect in the target.
///
/// Use an allow-list of the real crash signals so any other signal a runtime may
/// raise can never become a phantom finding. A silent SIGABRT is a crash because
/// there is no evidence that the target intentionally rejected malformed input.
///
/// EXCEPTION — the Windows (mingw + wine) path: a guest hardware fault is NOT
/// delivered as a POSIX signal; the driver's vectored exception handler reports it
/// by exiting with [`crate::fatal_signal::BHF_WIN_CRASH_EXIT`]. That specific exit code is a genuine
/// crash, not a rejection — any OTHER nonzero exit stays a rejection as before.
///
/// The exit code the Windows (mingw) driver's vectored exception handler uses to
/// report a fatal hardware fault when fuzzing under wine. MUST match
/// `BHF_WIN_CRASH_EXIT` in `c_runtime/bhf_driver.c` and the
/// `direct_harness.{c,cpp}.tera` templates.
fn is_input_rejection(status: &std::process::ExitStatus, stderr: &str) -> bool {
    crate::fatal_signal::classify(status, stderr).is_none()
}

/// How the error of a pass whose harness's sanitizer runtime could not start
/// begins ([`runtime_start_failure_error`]), so `bhf auto` can tell that
/// environment error from a pass that failed for another reason
/// ([`is_runtime_start_failure`]).
const RUNTIME_START_FAILURE: &str = "sanitizer runtime could not start: ";

/// Whether a fuzz pass `error` says the harness's sanitizer runtime could
/// not start on this host: every input dies that way before reaching the
/// target, so another pass would only fail the same way. A caller that
/// prefixes the error with its own context keeps it recognisable.
pub(crate) fn is_runtime_start_failure(error: &str) -> bool {
    error.contains(RUNTIME_START_FAILURE)
}

/// The compiler the harness in `dir` was last built with, as its toolchain
/// stamp records it (`bhf_toolchain.stamp` begins with the compiler).
fn recorded_harness_compiler(dir: &Path) -> Option<String> {
    let stamp = fs::read_to_string(dir.join("bhf_toolchain.stamp")).ok()?;
    let compilers = stamp.lines().next()?.split(" | ").next()?;
    crate::generate_harness::split_compile_command(compilers)
        .into_iter()
        .next()
}

/// The error a run whose sanitizer runtime could not start ends the pass
/// with: the harness dies that way before `main` on every input, which says
/// nothing about the target, so it is an environment error and never a
/// finding. It names the runtime's line and the compiler the harness was
/// built with.
fn runtime_start_failure_error(runner: &replay_min::HarnessRunner, stderr: &str) -> Option<String> {
    let line = crate::fatal_signal::sanitizer_runtime_start_failure(stderr)?;
    let harness = runner.harness_path();
    let built_with = harness
        .parent()
        .and_then(recorded_harness_compiler)
        .map(|compiler| format!(" (built with {compiler})"))
        .unwrap_or_default();
    Some(format!(
        "{RUNTIME_START_FAILURE}'{}'{built_with} printed \"{line}\" before reaching the target. \
         That is an environment problem on this host, not a finding: build the harness with \
         `--sanitizers none` (coverage and crash detection, no sanitizer runtime), with \
         sanitizers whose runtime starts here (`--sanitizers` checks that it does), or with a \
         compiler whose sanitizer runtime starts here",
        harness.display()
    ))
}

/// Synthesize the BHF-210 "reachable crash (fatal signal, no sanitizer report)"
/// finding for a non-rejection crash on an input.
pub(crate) fn fatal_signal_report(
    status: &std::process::ExitStatus,
    stderr: &str,
) -> corpus::SanitizerReport {
    let crash = crate::fatal_signal::classify(status, stderr)
        .expect("fatal_signal_report requires a classified fatal signal");
    // Funnel through the shared crash-report builder so the host-signal lane and
    // the HDF-2 transport-fault lane produce one finding shape with a catalog
    // `rule_id` (see `crate::transport_fault`).
    let mut report = crate::transport_fault::crash_report(
        crate::fatal_signal::RULE_ID,
        "fatal-signal".to_owned(),
        format!(
            "harness crashed with {} and no sanitizer report — a reachable crash",
            crash.name
        ),
    );
    report.pc_offset = fatal_signal_pc_offset(stderr, &crash.name);
    // The signal is the check that failed: it is part of the signature and of
    // the root-cause key, so an abort and an illegal instruction with no frames
    // are two findings, and replay compares it.
    if crash.name.starts_with("SIG") {
        report.check = Some(crash.name.clone());
    }
    report
}

/// The faulting instruction's offset in the executable from the line bhf's
/// driver prints before a fatal signal kills a harness built without a
/// sanitizer runtime (`bhf: fatal signal SIGSEGV pc=0x... addr=0x...
/// exe_offset=0x13c4`), when it names `signal`. The last such line wins.
pub(crate) fn fatal_signal_pc_offset(stderr: &str, signal: &str) -> Option<u64> {
    let line = stderr
        .lines()
        .rev()
        .filter_map(|line| line.trim().strip_prefix("bhf: fatal signal "))
        .find(|rest| rest.split_whitespace().next() == Some(signal))?;
    line.split_whitespace()
        .find_map(|field| field.strip_prefix("exe_offset=0x"))
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
}

pub fn run(mut args: FuzzArgs) -> i32 {
    if let Err(error) = crate::board_profile::apply(&mut args) {
        bhfeprintln!("{error}");
        return 2;
    }
    // The transport and session lanes are the builtin engine's own loops: an
    // AFL++ or WinAFL run asked for with them would silently not happen.
    if let Some(error) = engine_lane_conflict(&args) {
        bhfeprintln!("{error}");
        return 3;
    }
    // Each lane names the flags it does not wire; a run that would silently
    // drop them (a single blind mutator instead of the asked-for workers,
    // grammar or CmpLog log) is refused instead.
    if let Some(error) = lane_flag_conflict(&args) {
        bhfeprintln!("{error}");
        return 2;
    }
    if let Some(error) = frame_conflict(&args) {
        bhfeprintln!("{error}");
        return 2;
    }
    // A `--frame` profile the loop cannot apply fails here, once, before a
    // harness or worker starts.
    if let Err(error) = load_frame_for_run(args.frame_file.as_deref()) {
        bhfeprintln!("{error}");
        return 2;
    }
    if let Err(error) = parse_sanitizer_args(&args.sanitizers) {
        bhfeprintln!("{error}");
        return 2;
    }
    // HDF-1b: when a target transport is requested, drive the additive
    // transport-fuzz path (a separate loop over the `target_transport` seam) and
    // leave the host libFuzzer/AFL path below untouched.
    if crate::transport_fuzz::should_use_transport(&args) {
        return crate::transport_fuzz::run(args);
    }

    // HDF-7: when a protocol profile is supplied, drive the additive session lane
    // (a separate response-dependent, multi-message loop) and leave the host
    // libFuzzer/AFL path below untouched.
    if crate::session_fuzz::should_use_session(&args) {
        return crate::session_fuzz::run(args);
    }

    if args.engine == FuzzEngine::Winafl {
        if let Err(error) = winafl::host_supported().and_then(|()| {
            winafl::check_page_heap_here(&WinaflSettings {
                page_heap: args.winafl_page_heap,
                ..WinaflSettings::default()
            })
        }) {
            bhfeprintln!("{error}");
            return 3;
        }
        if multicore_requested(&args) {
            bhfeprintln!(
                "--engine winafl runs one WinAFL instance; --workers and a sanitizer matrix \
                 (several --sanitizers) are not supported with it"
            );
            return 3;
        }
    }
    if matches!(
        args.engine,
        FuzzEngine::Libfuzzer | FuzzEngine::Honggfuzz | FuzzEngine::Libafl
    ) && multicore_requested(&args)
    {
        bhfeprintln!(
            "--engine {} runs one fuzzer process; --workers and a sanitizer matrix (several \
             --sanitizers) are not supported with it",
            engine_arg_name(args.engine)
        );
        return 3;
    }
    // #276: AFL++ runs `--workers` as its own -M/-S instances, which sync
    // as they run; a sanitizer matrix still runs one worker per sanitizer.
    let afl_instances = args.engine == FuzzEngine::AflPlusPlus && args.sanitizers.len() <= 1;
    if multicore_requested(&args) && !afl_instances {
        if let Some(error) = multicore_flag_conflict(&args) {
            bhfeprintln!("{error}");
            return 2;
        }
        return run_multicore_campaign(args);
    }

    // #60: capture the collector spec before `prepare` consumes `args`, so a
    // collected clean-exit semantic violation can be emitted after the fuzz run.
    let collector_spec = args.collector.clone();
    let collector_window_ms = args.collector_window_ms;
    let collector_work_dir = args.work_dir.clone();
    let collector_harness_id = args.harness.clone();
    let quiet = args.quiet;

    let prepared = match prepare(args) {
        Ok(prepared) => prepared,
        Err(error) => {
            bhfeprintln!("{error}");
            return 3;
        }
    };
    // The runtrace log this run armed and truncated, if any: the collector
    // reads that one, never a log an earlier run left in the work dir.
    let runtrace_log = prepared
        .extra_env
        .iter()
        .find(|(key, _)| key == "BHF_RUNTRACE_LOG")
        .map(|(_, value)| PathBuf::from(value));
    // #246: the collector replays the campaign's retained inputs on this
    // harness, the way the campaign's re-runs run it.
    let collector_harness = collector_replay::CollectorHarness::new(
        prepared.runner.clone(),
        &prepared.work_dir,
        &prepared.extra_env,
        prepared.per_input_timeout,
    );

    let progress_lines = (!quiet).then(ProgressLines::new);
    let print_progress = |tick: &FuzzTick| {
        if let Some(line) = progress_lines.as_ref().and_then(|lines| lines.line(tick)) {
            bhfeprintln!("{line}");
        }
    };
    let result = match prepared.engine {
        FuzzEngine::Builtin => run_builtin_with_progress(prepared, Some(&print_progress)),
        FuzzEngine::AflPlusPlus => run_afl_plus_plus(prepared),
        FuzzEngine::Winafl => winafl::run(prepared),
        FuzzEngine::Libfuzzer => libfuzzer::run(prepared),
        FuzzEngine::Honggfuzz => honggfuzz::run(prepared),
        FuzzEngine::Libafl => libafl::run(prepared),
    };

    match result {
        Ok(summary) => {
            let mut value = match serde_json::to_value(&summary) {
                Ok(value) => value,
                Err(error) => {
                    bhfeprintln!("failed to render fuzz summary: {error}");
                    return 1;
                }
            };
            // #60: run the platform-neutral collector (inactive by default, leaving
            // behaviour unchanged) and attach its provenance + any findings.
            match run_collector_for_fuzz(
                &collector_spec,
                collector_window_ms,
                &collector_work_dir,
                &collector_harness_id,
                runtrace_log.as_deref(),
                Some(&collector_harness),
            ) {
                Ok(provenance) => {
                    value["collector"] = provenance;
                }
                Err(error) => {
                    bhfeprintln!("collector: {error:#}");
                    return 1;
                }
            }
            match serde_json::to_string_pretty(&value) {
                Ok(json) => println!("{json}"),
                Err(error) => {
                    bhfeprintln!("failed to render fuzz summary: {error}");
                    return 1;
                }
            }
            if let Some(note) = duplicates_of_existing_note(
                &summary.duplicates_of_existing,
                summary.duplicate_crashes_of_existing,
                &summary.harness_id,
            ) {
                bhfeprintln!("{note}");
            }
            0
        }
        Err(error) => {
            bhfeprintln!("{error}");
            1
        }
    }
}

/// The stderr note for crashes that matched findings recorded before the run
/// (`ids`, `crashes` of them): they are left out of `findings`, and without a
/// note the run reads as clean.
fn duplicates_of_existing_note(ids: &[String], crashes: usize, harness_id: &str) -> Option<String> {
    const SHOWN: usize = 10;
    if ids.is_empty() {
        return None;
    }
    let mut listed = ids[..ids.len().min(SHOWN)].join(", ");
    if ids.len() > SHOWN {
        listed.push_str(&format!(" and {} more", ids.len() - SHOWN));
    }
    Some(format!(
        "bhf fuzz: {crashes} crashing input(s) matched finding(s) already recorded for \
         {harness_id} ({listed}); they were not recorded again (see \"duplicates_of_existing\")"
    ))
}

/// Run the platform-neutral runtime-event collector (#60) for a `bhf fuzz`
/// invocation and return its run-manifest provenance (including the ids of any
/// collector-sourced `binary_semantic` findings written to the results tree).
/// Inactive (the default, or no built-in provider on this platform) is a no-op
/// that returns inactive provenance, so the historical behaviour is unchanged.
///
/// #246: the collector replays the campaign's retained inputs (this harness's
/// crash findings, then its persisted corpus; at most
/// [`crate::collector_run::MAX_REPLAYS`]) one by one on `harness`: under a
/// sidecar, which observes the launched process, or on Linux under the
/// runtrace shim. Each finding keeps the input whose replay produced it. On
/// Linux a sink only the campaign's other inputs reached is still reported
/// from the campaign's runtrace log, as an aggregate finding with no input.
fn run_collector_for_fuzz(
    spec: &crate::collector_run::CollectorSpec,
    window_ms: u64,
    work_dir: &Path,
    harness_id: &str,
    runtrace_log: Option<&Path>,
    harness: Option<&collector_replay::CollectorHarness>,
) -> anyhow::Result<serde_json::Value> {
    use crate::collector_run::{CollectorOutcome, ObservationMode, ReplayTestcase};
    use anyhow::Context;
    let Some(resolved) = crate::collector_run::resolve(spec, window_ms)? else {
        return Ok(crate::collector_run::inactive_run_provenance(spec));
    };
    let findings_dir = corpus::layout::findings_dir(work_dir);
    std::fs::create_dir_all(&findings_dir)
        .with_context(|| format!("create {}", findings_dir.display()))?;
    let root = work_dir.display().to_string();
    // The oracle lane already wrote these with their own testcases.
    let mut reported = oracle_lane_rules(&findings_dir, harness_id);
    let (replays, dropped) = match harness {
        Some(_) => crate::collector_run::bounded_replay_set(
            crate::collector_run::retained_replay_testcases(work_dir, harness_id),
        ),
        None => (Vec::new(), 0),
    };
    // The campaign's runtrace log, written only when the shim was armed.
    let campaign_events = match (resolved.runtrace_shim(), runtrace_log) {
        (Some(_), Some(log)) if log.is_file() => {
            let mut events = crate::auto::runtrace::parse_log(log).unwrap_or_default();
            crate::auto::runtrace::dedupe_in_place(&mut events);
            Some(events)
        }
        _ => None,
    };

    let mut replayed: Option<crate::collector_run::ReplaySetOutcome> = None;
    if let (Some(harness), false) = (harness, replays.is_empty()) {
        let mut outcomes: Vec<(ReplayTestcase, CollectorOutcome)> = Vec::new();
        if let Some(shim) = resolved.runtrace_shim() {
            let mut runs = Vec::with_capacity(replays.len());
            for replay in replays {
                let events = harness.run_under_shim(shim, &replay.testcase, &replay.input)?;
                runs.push((replay, events));
            }
            // A sink is taint-confirmed only from cross-execution correlation:
            // the campaign's events (when its log was written) and every replay.
            let mut evidence = campaign_events.clone().unwrap_or_default();
            for (_, events) in &runs {
                evidence.extend(events.iter().cloned());
            }
            let gate = crate::auto::runtrace::CollectorTaintGate::from_events(&evidence);
            for (replay, events) in runs {
                let adapter_ctx = crate::auto::runtrace::CollectorAdapterCtx {
                    testcase: replay.testcase.clone(),
                    worker: replay.worker,
                    // Synthetic anchor for this replayed execution's event tree;
                    // the shim events carry the real pids, which drive attribution.
                    root_pid: 1,
                };
                let jsonl = crate::auto::runtrace::collector_jsonl_from_events(
                    &events,
                    &adapter_ctx,
                    harness_id,
                    &gate,
                );
                let outcome = resolved.evaluate_jsonl(&jsonl, &root);
                outcomes.push((replay, outcome));
            }
        } else {
            for replay in replays {
                // A genuine REPLAY: the host launches the harness on this input
                // UNDER the ready observer and records its real PID; `run_once`
                // bounds the capture and degrades to not_observed otherwise (#76).
                let launch: crate::collector_run::ReplayLauncher =
                    Box::new(|| harness.launch(&replay.testcase, &replay.input));
                let params = crate::collector_run::CollectorRunParams {
                    testcase: replay.testcase.clone(),
                    worker: replay.worker,
                    root: root.clone(),
                    root_image: harness_id.to_owned(),
                    input: &replay.input,
                    tmp_dir: work_dir.join("fuzz_scratch").join("collector"),
                    launch: Some(launch),
                };
                let outcome = resolved.run_once(&params)?;
                drop(params);
                outcomes.push((replay, outcome));
            }
        }
        replayed = Some(crate::collector_run::merge_replays(outcomes, dropped));
    }

    let target = serde_json::json!({ "kind": "harness", "harness": harness_id });
    let mut ids = Vec::new();
    let mut provenance = match &replayed {
        Some(merged) => {
            for (finding, replay) in &merged.findings {
                if reported.contains(&finding.hit.rule_id) {
                    continue;
                }
                let id = crate::collector_run::next_collector_finding_id(&findings_dir)?;
                crate::collector_run::write_finding_with_evidence(
                    &findings_dir.join(&id),
                    &id,
                    target.clone(),
                    finding,
                    &replay.input,
                    ObservationMode::Replay,
                    None,
                )?;
                reported.insert(finding.hit.rule_id.clone());
                ids.push(id);
            }
            let mut provenance = merged.run_provenance.clone();
            ObservationMode::Replay.stamp(&mut provenance);
            provenance
        }
        None => serde_json::Value::Null,
    };

    // Linux: what the campaign's other inputs reached, from its runtrace log,
    // as one aggregate session; a rule a replay or the oracle lane reported is
    // left out. Without a log (the shim was not armed) and without a replay
    // the collector observed nothing.
    if resolved.runtrace_shim().is_some() {
        let aggregate = match &campaign_events {
            Some(events) => {
                // Route sink confirmation through the SAME cross-execution
                // correlation #59 uses: the log spans every execution, so no sink
                // is single-run taint-confirmed.
                let gate = crate::auto::runtrace::CollectorTaintGate::from_events(events);
                let adapter_ctx = crate::auto::runtrace::CollectorAdapterCtx {
                    testcase: "campaign-aggregate".to_owned(),
                    worker: 0,
                    // Synthetic anchor for the aggregate event tree; the shim
                    // events carry the real pids. Not a per-case OS pid claim.
                    root_pid: 1,
                };
                let jsonl = crate::auto::runtrace::collector_jsonl_from_events(
                    events,
                    &adapter_ctx,
                    harness_id,
                    &gate,
                );
                Some(resolved.evaluate_aggregate_jsonl(&jsonl, &root, &reported))
            }
            None if replayed.is_none() => {
                // #60 AC6: the shim was NOT armed, so the collector observed
                // nothing this run. Record a degraded, not-observed run rather
                // than evaluating an empty stream and claiming a clean assurance.
                Some(resolved.not_observed("runtime_shim_not_armed"))
            }
            None => None,
        };
        if let Some(aggregate) = aggregate {
            // One session, the whole campaign: written once, beside the
            // findings, for all of them.
            let shared_evidence = match aggregate.findings.first() {
                Some(first) => {
                    use sha2::Digest;
                    let digest =
                        corpus::hex_lower(&sha2::Sha256::digest(first.session_jsonl.as_bytes()));
                    let name = format!("aggregate-{}.jsonl", &digest[..16]);
                    let dir = findings_dir.with_file_name("collector");
                    std::fs::create_dir_all(&dir)
                        .with_context(|| format!("create {}", dir.display()))?;
                    std::fs::write(dir.join(&name), first.session_jsonl.as_bytes())
                        .with_context(|| format!("write {}", dir.join(&name).display()))?;
                    Some(format!("../../collector/{name}"))
                }
                None => None,
            };
            let mut aggregate_ids = Vec::new();
            for finding in &aggregate.findings {
                let id = crate::collector_run::next_collector_finding_id(&findings_dir)?;
                // Aggregate: no single triggering input, so the finding is
                // campaign-level (its `coverage` says so), not reproducible from one.
                crate::collector_run::write_finding_with_evidence(
                    &findings_dir.join(&id),
                    &id,
                    target.clone(),
                    finding,
                    &[],
                    ObservationMode::Aggregate,
                    shared_evidence.as_deref(),
                )?;
                aggregate_ids.push(id);
            }
            let mut aggregate_provenance = aggregate.run_provenance;
            ObservationMode::Aggregate.stamp(&mut aggregate_provenance);
            if provenance.is_null() {
                provenance = aggregate_provenance;
            } else {
                aggregate_provenance["findings"] = serde_json::json!(aggregate_ids);
                provenance["aggregate"] = aggregate_provenance;
            }
            ids.extend(aggregate_ids);
        }
    } else if provenance.is_null() {
        // A sidecar with nothing retained to replay: a degraded, not-observed
        // run, never a clean assurance over a run it did not watch (#76).
        let reason = if harness.is_none() {
            "harness_sidecar_replay_unsupported"
        } else {
            "no_retained_testcase_to_replay"
        };
        provenance = resolved.not_observed(reason).run_provenance;
        ObservationMode::Replay.stamp(&mut provenance);
    }
    provenance["findings"] = serde_json::json!(ids);
    Ok(provenance)
}

/// `bhf auto --collector` (#278): observe `harness_id`'s retained inputs under
/// the collector after its fuzz passes, as `bhf fuzz --collector` does, and
/// return the run provenance. `wrapper` is the emulator a cross-built harness
/// runs under; `runtrace_log` the last pass's shim log, read for the sinks no
/// replay reaches.
pub(crate) fn observe_with_collector(
    work_dir: &Path,
    harness_id: &str,
    spec: &crate::collector_run::CollectorSpec,
    window_ms: u64,
    wrapper: Option<crate::runner::HarnessWrapper>,
    env: &[(String, String)],
    runtrace_log: Option<&Path>,
) -> anyhow::Result<serde_json::Value> {
    let harness = find_harness_executable(work_dir, harness_id, FuzzEngine::Builtin)
        .map_err(anyhow::Error::msg)?;
    let runner = crate::runner::harness_runner_with_wrapper(
        harness,
        wrapper,
        crate::runner::SandboxModeArg::Auto,
        None,
        false,
    );
    let harness =
        collector_replay::CollectorHarness::new(runner, work_dir, env, Duration::from_secs(10));
    run_collector_for_fuzz(
        spec,
        window_ms,
        work_dir,
        harness_id,
        runtrace_log,
        Some(&harness),
    )
}

/// The rules of the runtime-oracle findings already written for `harness_id`
/// in `findings_dir`: the oracle lane's own findings, with their testcases, so
/// the campaign-aggregate collector view does not repeat them.
fn oracle_lane_rules(findings_dir: &Path, harness_id: &str) -> std::collections::BTreeSet<String> {
    let Ok(entries) = std::fs::read_dir(findings_dir) else {
        return Default::default();
    };
    entries
        .flatten()
        .filter_map(|entry| std::fs::read(entry.path().join("finding.json")).ok())
        .filter_map(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .filter(|raw| {
            raw["classification"] == "oracle_hit"
                && raw.get("collector").is_none()
                && raw["harness_id"] == harness_id
        })
        .filter_map(|raw| raw["rule_id"].as_str().map(str::to_owned))
        .collect()
}

/// Programmatic fuzz entry used by `bhf auto`. Builds a
/// [`FuzzArgs`] for the requested harness id under `work_dir`, runs
/// [`prepare`] + [`run_builtin`], and returns the resulting summary
/// without serialising it. Errors bubble up as `String` (same shape as
/// [`prepare`] / [`run_builtin`]) so the caller can downgrade them to a
/// `Built` outcome without losing the original message.
/// Periodic live-progress callback for the builtin fuzz loop, sampled at most
/// every 500ms so the hot loop stays hot.
pub(crate) type FuzzProgressFn<'a> = &'a dyn Fn(&FuzzTick);

/// A live sample of the builtin fuzz loop. `edges` is the live distinct-edge
/// count from the coverage tracker (0 for harnesses with no edge runtime): the
/// dashboard needs coverage growth WHILE a pass runs, not only in the pass
/// summary, because "no new edge for four minutes" is the signal that the rest
/// of this target's budget is being wasted.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct FuzzTick {
    pub(crate) executions: usize,
    pub(crate) findings: usize,
    pub(crate) edges: usize,
    /// Inputs in the in-memory corpus the mutator draws from.
    pub(crate) corpus: usize,
    pub(crate) elapsed: Duration,
    /// The stability calibration has measured so far (#232).
    pub(crate) stability_pct: Option<f64>,
}

/// When `bhf fuzz` prints its progress lines: 2s into the run, then after
/// as long again as the run has taken, at most 30s apart.
struct ProgressLines {
    next: std::cell::Cell<Duration>,
}

impl ProgressLines {
    const FIRST: Duration = Duration::from_secs(2);
    const MAX_GAP: Duration = Duration::from_secs(30);

    fn new() -> Self {
        Self {
            next: std::cell::Cell::new(Self::FIRST),
        }
    }

    /// The line to print for `tick`, if one is due.
    fn line(&self, tick: &FuzzTick) -> Option<String> {
        if tick.elapsed < self.next.get() {
            return None;
        }
        let gap = tick.elapsed.clamp(Self::FIRST, Self::MAX_GAP);
        self.next.set(tick.elapsed + gap);
        Some(format_progress_line(tick))
    }
}

fn format_progress_line(tick: &FuzzTick) -> String {
    let secs = tick.elapsed.as_secs_f64();
    let stability = tick
        .stability_pct
        .map(|pct| format!(" | stability: {pct:.1}%"))
        .unwrap_or_default();
    format!(
        "bhf: fuzz: {} execs ({:.0}/s) | corpus: {} | findings: {} | edges: {}{stability} | elapsed: {:.1}s",
        tick.executions,
        executions_per_sec(tick.executions, secs),
        tick.corpus,
        tick.findings,
        tick.edges,
        secs,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_one_target_programmatic(
    work_dir: &Path,
    harness_id: &str,
    seeds: Vec<Vec<u8>>,
    iterations: usize,
    time_budget: Option<Duration>,
    stop_after_findings: Option<usize>,
    rss_limit_mb: usize,
    extra_env: &[(String, String)],
    mode: actionability::RunMode,
    cmplog_log: Option<PathBuf>,
    sanitizers: &[multicore_fuzz::Sanitizer],
    progress: Option<FuzzProgressFn<'_>>,
) -> Result<FuzzRunSummary, String> {
    run_one_target_programmatic_with_runner(
        work_dir,
        harness_id,
        seeds,
        iterations,
        time_budget,
        stop_after_findings,
        rss_limit_mb,
        extra_env,
        mode,
        cmplog_log,
        None,
        sanitizers,
        progress,
    )
}

/// As [`run_one_target_programmatic`], but with an optional pre-built runner
/// that REPLACES the default direct/host runner — `bhf auto` passes a
/// qemu-user / wine runner for a foreign-platform/arch harness so the cross-built
/// binary runs under emulation. `runner == None` is identical to the host path.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_one_target_programmatic_with_runner(
    work_dir: &Path,
    harness_id: &str,
    seeds: Vec<Vec<u8>>,
    iterations: usize,
    time_budget: Option<Duration>,
    stop_after_findings: Option<usize>,
    rss_limit_mb: usize,
    extra_env: &[(String, String)],
    mode: actionability::RunMode,
    cmplog_log: Option<PathBuf>,
    runner: Option<replay_min::HarnessRunner>,
    // Sanitizers requested by `bhf auto --sanitizers`. The auto path builds the
    // harness with the matching `-fsanitize=` flags (attempt.rs); naming them here
    // makes `prepare` inject the run-time `<SAN>_OPTIONS` env (abort_on_error /
    // halt_on_error / detect_leaks) and record them in the run's sanitizer summary,
    // exactly as the standalone `bhf fuzz --sanitizers` path does. Empty for
    // every existing caller, so the run record / env are byte-identical to before.
    sanitizers: &[multicore_fuzz::Sanitizer],
    progress: Option<FuzzProgressFn<'_>>,
) -> Result<FuzzRunSummary, String> {
    // `auto --max-len` / `--timeout` publish their choice via env (BHF_MAX_LEN /
    // BHF_EXEC_TIMEOUT); resolve them here where the seed sizes are known (so a
    // large seed is never truncated). Unset (non-auto callers / tests) keeps the
    // historical defaults.
    let largest_seed = seeds.iter().map(Vec::len).max().unwrap_or(0);
    let args = FuzzArgs {
        work_dir: work_dir.to_path_buf(),
        harness: harness_id.to_owned(),
        engine: FuzzEngine::Builtin,
        afl_mode: AflMode::Native,
        afl_path: None,
        afl_inst_ranges: Vec::new(),
        winafl_path: None,
        dynamorio_path: None,
        winafl_instrumentation: WinaflInstrumentation::Dynamorio,
        winafl_iterations: None,
        winafl_coverage_modules: Vec::new(),
        winafl_page_heap: false,
        workers: None,
        iterations: Some(iterations),
        time: time_budget,
        timeout: resolve_env_timeout(),
        deadline: resolve_env_deadline(),
        max_len: resolve_env_max_len(largest_seed),
        len_control: DEFAULT_LEN_CONTROL,
        print_final_stats: false,
        quiet: true,
        // Per-harness memory cap so a fuzzer-controlled huge allocation is caught
        // as an OOM finding (BHF-209) instead of OOM-killing the host (#386).
        rss_limit_mb,
        fork_server: false,
        no_fork_server: false,
        seed_inputs: Vec::new(),
        seed_files: Vec::new(),
        campaign_seed_files: Vec::new(),
        qemu_user: None,
        qemu_args: Vec::new(),
        seed_bytes: seeds,
        seeds_layout_prefixed: false,
        sanitizers: sanitizers
            .iter()
            .map(|s| sanitizer_name(*s).to_owned())
            .collect(),
        symbolic_seed_sources: Vec::new(),
        rng_seed: 0x4756_4655_5a5a,
        sandbox: crate::runner::SandboxModeArg::Auto,
        mode,
        sandbox_tool: None,
        sandbox_strict: false,
        extra_env: extra_env.to_vec(),
        runtime_oracles: crate::runtime_oracles::RuntimeOracleMode::Off,
        cmplog_log,
        grammar_file: None,
        frame_file: None,
        dict_file: None,
        structured_inputs: StructuredInputMode::Auto,
        bhf_bin: None,
        stop_after_findings,
        target_transport: None,
        transport_coverage_map: None,
        board_profile: None,
        board_lane: crate::board_profile::BoardLane::Gdb,
        protocol_profile: None,
        session_transport: None,
        session_reset: crate::session_fuzz::SessionResetMode::Reconnect,
        max_session_messages: 64,
        session_reply_timeout: None,
        session_server_cmd: None,
        collector: crate::collector_run::CollectorSpec::Off,
        collector_window_ms: crate::collector_run::DEFAULT_WINDOW_MS,
        extension: None,
    };
    // A caller-supplied cross runner replaces the runner `prepare` would
    // resolve from the harness path (qemu-user / wine emulation).
    let prepared = prepare_with_runner(args, runner)?;
    run_builtin_with_progress(prepared, progress)
}

/// Drive AFL++ against an already-built `main_afl` for `bhf auto`'s attempt
/// loop, returning the SAME [`FuzzRunSummary`] the builtin programmatic runner
/// returns so AFL crashes fold into the shared findings pipeline (BHF-210 /
/// sanitizer-report / replay-verify) — no separate report path. Reuses
/// [`prepare`] (which resolves the `main_afl` path for the AFL engine, builds the
/// runner, and arms the sanitizer env) and the existing [`run_afl_plus_plus`]
/// drive + crash harvest. Errors (no `main_afl`, afl-fuzz failure) propagate to
/// the caller, which records a warning and continues — it must NOT abort the
/// target. `iterations` is unused by AFL (it runs on a wall-clock `-V` budget).
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_afl_plus_plus_programmatic(
    work_dir: &Path,
    harness_id: &str,
    seeds: Vec<Vec<u8>>,
    time_budget: Option<Duration>,
    extra_env: &[(String, String)],
    mode: actionability::RunMode,
    rss_limit_mb: usize,
    sanitizers: &[multicore_fuzz::Sanitizer],
) -> Result<FuzzRunSummary, String> {
    let prepared = prepare_afl_programmatic(
        work_dir,
        harness_id,
        seeds,
        time_budget,
        extra_env,
        mode,
        rss_limit_mb,
        sanitizers,
        std::env::var("BHF_MAX_LEN").ok().as_deref(),
    )?;
    run_afl_plus_plus(prepared)
}

/// Refuse `--engine winafl` off native Windows, locate WinAFL and DynamoRIO for
/// the architecture harnesses are built for (`--vs-arch`, x64 by default), and
/// refuse `--winafl-page-heap` in a shell that is not elevated, so a run fails
/// before its sweep with the error naming what to do.
pub(crate) fn check_winafl_available(settings: &WinaflSettings) -> Result<(), String> {
    winafl::check_available(settings)
}

/// The WinAFL build `make winafl` writes beside `main` (`main_winafl.exe`).
pub(crate) const WINAFL_BINARY: &str = winafl::FUZZ_BINARY_STEM;

/// Drive WinAFL against an already-built `main_winafl` for `bhf auto`'s attempt
/// loop, returning the same [`FuzzRunSummary`] as the other engines so its
/// findings (each saved crash or hang replayed through the sanitized `main`)
/// fold into the shared findings pipeline. Errors (no WinAFL or DynamoRIO, no
/// `main_winafl`, afl-fuzz failure) go to the caller, which warns and keeps the
/// target's other results. `iterations` is unused: WinAFL runs on the time
/// budget, which bhf enforces since WinAFL has none of its own.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_winafl_programmatic(
    work_dir: &Path,
    harness_id: &str,
    seeds: Vec<Vec<u8>>,
    time_budget: Option<Duration>,
    extra_env: &[(String, String)],
    mode: actionability::RunMode,
    rss_limit_mb: usize,
    sanitizers: &[multicore_fuzz::Sanitizer],
    settings: &WinaflSettings,
) -> Result<FuzzRunSummary, String> {
    let largest_seed = seeds.iter().map(Vec::len).max().unwrap_or(0);
    let max_len = resolve_max_len_spec(std::env::var("BHF_MAX_LEN").ok().as_deref(), largest_seed);
    let mut args = afl_programmatic_args(
        work_dir,
        harness_id,
        seeds,
        time_budget,
        extra_env,
        mode,
        rss_limit_mb,
        sanitizers,
        max_len,
    );
    args.engine = FuzzEngine::Winafl;
    args.timeout = resolve_env_timeout();
    args.winafl_path = settings.winafl_path.clone();
    args.dynamorio_path = settings.dynamorio_path.clone();
    args.winafl_instrumentation = settings.instrumentation;
    args.winafl_iterations = settings.fuzz_iterations;
    args.winafl_coverage_modules = settings.coverage_modules.clone();
    args.winafl_page_heap = settings.page_heap;
    winafl::run(prepare(args)?)
}

/// The prepared AFL++ run behind [`run_afl_plus_plus_programmatic`], for the
/// run's `--max-len` spec (`BHF_MAX_LEN`: a number, `auto`, or unset).
#[allow(clippy::too_many_arguments)]
fn prepare_afl_programmatic(
    work_dir: &Path,
    harness_id: &str,
    seeds: Vec<Vec<u8>>,
    time_budget: Option<Duration>,
    extra_env: &[(String, String)],
    mode: actionability::RunMode,
    rss_limit_mb: usize,
    sanitizers: &[multicore_fuzz::Sanitizer],
    max_len_spec: Option<&str>,
) -> Result<PreparedFuzzRun, String> {
    // Resolve the length cap exactly as the builtin programmatic runner does, so
    // `auto --max-len` governs AFL++ seeds too instead of a fixed 4096 bytes.
    let largest_seed = seeds.iter().map(Vec::len).max().unwrap_or(0);
    let max_len = resolve_max_len_spec(max_len_spec, largest_seed);
    let args = afl_programmatic_args(
        work_dir,
        harness_id,
        seeds,
        time_budget,
        extra_env,
        mode,
        rss_limit_mb,
        sanitizers,
        max_len,
    );
    let mut prepared = prepare(args)?;
    prepared.afl_max_len = afl_generated_max_len(max_len);
    Ok(prepared)
}

/// AFL++'s own default (and compiled maximum) generated-input length.
const AFL_DEFAULT_MAX_LEN: usize = 1024 * 1024;

/// The `-G` value to hand afl-fuzz for a resolved `max_len`: only a cap tighter
/// than AFL++'s own default is passed, since afl-fuzz cannot generate past its
/// compiled maximum anyway (and older afl-fuzz builds lack `-G`).
fn afl_generated_max_len(max_len: usize) -> Option<usize> {
    (max_len < AFL_DEFAULT_MAX_LEN).then_some(max_len.max(1))
}

/// Whether this afl-fuzz takes `-G` (maximum generated input length, added in
/// AFL++ 4.00c). Probed from `afl-fuzz -h` once per afl-fuzz path.
fn afl_fuzz_supports_max_len(afl_fuzz: &Path) -> bool {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static PROBED: OnceLock<Mutex<HashMap<PathBuf, bool>>> = OnceLock::new();
    let probed = PROBED.get_or_init(Default::default);
    if let Some(&known) = probed
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(afl_fuzz)
    {
        return known;
    }
    let mut probe = std::process::Command::new(afl_fuzz);
    probe.arg("-h").stdin(Stdio::null());
    let supported = crate::command_output::output_with_timeout(&mut probe, Duration::from_secs(10))
        .is_ok_and(|out| {
            afl_help_lists_max_len(&out.stdout) || afl_help_lists_max_len(&out.stderr)
        });
    probed
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(afl_fuzz.to_path_buf(), supported);
    supported
}

/// `afl-fuzz -h` usage lists `-G maxlength` among its mutator settings.
fn afl_help_lists_max_len(help: &[u8]) -> bool {
    String::from_utf8_lossy(help)
        .lines()
        .any(|line| line.trim_start().starts_with("-G "))
}

/// The [`FuzzArgs`] behind [`run_afl_plus_plus_programmatic`], with the length
/// cap already resolved.
#[allow(clippy::too_many_arguments)]
fn afl_programmatic_args(
    work_dir: &Path,
    harness_id: &str,
    seeds: Vec<Vec<u8>>,
    time_budget: Option<Duration>,
    extra_env: &[(String, String)],
    mode: actionability::RunMode,
    rss_limit_mb: usize,
    sanitizers: &[multicore_fuzz::Sanitizer],
    max_len: usize,
) -> FuzzArgs {
    FuzzArgs {
        work_dir: work_dir.to_path_buf(),
        harness: harness_id.to_owned(),
        engine: FuzzEngine::AflPlusPlus,
        afl_mode: AflMode::Native,
        afl_path: None,
        afl_inst_ranges: Vec::new(),
        winafl_path: None,
        dynamorio_path: None,
        winafl_instrumentation: WinaflInstrumentation::Dynamorio,
        winafl_iterations: None,
        winafl_coverage_modules: Vec::new(),
        winafl_page_heap: false,
        workers: None,
        iterations: Some(0),
        time: time_budget,
        timeout: None,
        deadline: None,
        max_len,
        len_control: DEFAULT_LEN_CONTROL,
        print_final_stats: false,
        quiet: true,
        rss_limit_mb,
        fork_server: false,
        no_fork_server: false,
        seed_inputs: Vec::new(),
        seed_files: Vec::new(),
        campaign_seed_files: Vec::new(),
        qemu_user: None,
        qemu_args: Vec::new(),
        seed_bytes: seeds,
        seeds_layout_prefixed: false,
        sanitizers: sanitizers
            .iter()
            .map(|s| sanitizer_name(*s).to_owned())
            .collect(),
        symbolic_seed_sources: Vec::new(),
        rng_seed: 0x4756_4655_5a5a,
        sandbox: crate::runner::SandboxModeArg::Auto,
        mode,
        sandbox_tool: None,
        sandbox_strict: false,
        extra_env: extra_env.to_vec(),
        runtime_oracles: crate::runtime_oracles::RuntimeOracleMode::Off,
        cmplog_log: None,
        grammar_file: None,
        frame_file: None,
        dict_file: None,
        structured_inputs: StructuredInputMode::Auto,
        bhf_bin: None,
        stop_after_findings: None,
        target_transport: None,
        transport_coverage_map: None,
        board_profile: None,
        board_lane: crate::board_profile::BoardLane::Gdb,
        protocol_profile: None,
        session_transport: None,
        session_reset: crate::session_fuzz::SessionResetMode::Reconnect,
        max_session_messages: 64,
        session_reply_timeout: None,
        session_server_cmd: None,
        collector: crate::collector_run::CollectorSpec::Off,
        collector_window_ms: crate::collector_run::DEFAULT_WINDOW_MS,
        extension: None,
    }
}

/// Every `bhf fuzz` flag this run gives a value other than its default, by
/// its command-line name. The transport and session lanes check theirs
/// against the flags they wire ([`crate::transport_fuzz::unsupported_flags`],
/// [`crate::session_fuzz::unsupported_flags`]).
pub(crate) fn given_flags(args: &FuzzArgs) -> Vec<&'static str> {
    use crate::collector_run::CollectorSpec;
    use crate::runner::SandboxModeArg;
    use crate::runtime_oracles::RuntimeOracleMode;
    let given = [
        ("--workers", args.workers.is_some()),
        ("--grammar", args.grammar_file.is_some()),
        ("--frame", args.frame_file.is_some()),
        ("--dict", args.dict_file.is_some()),
        ("--cmplog-log", args.cmplog_log.is_some()),
        ("--len-control", args.len_control != DEFAULT_LEN_CONTROL),
        ("--rss-limit-mb", args.rss_limit_mb != 0),
        ("--fork-server", args.fork_server),
        ("--no-fork-server", args.no_fork_server),
        ("--qemu-user", args.qemu_user.is_some()),
        ("--qemu-arg", !args.qemu_args.is_empty()),
        ("--extension", args.extension.is_some()),
        ("--sanitizers", !args.sanitizers.is_empty()),
        (
            "--symbolic-seed-source",
            !args.symbolic_seed_sources.is_empty(),
        ),
        ("--sandbox", !matches!(args.sandbox, SandboxModeArg::Auto)),
        ("--sandbox-tool", args.sandbox_tool.is_some()),
        ("--sandbox-strict", args.sandbox_strict),
        (
            "--runtime-oracles",
            !matches!(args.runtime_oracles, RuntimeOracleMode::Off),
        ),
        (
            "--structured-inputs",
            !matches!(args.structured_inputs, StructuredInputMode::Auto),
        ),
        ("--print-final-stats", args.print_final_stats),
        ("--collector", !matches!(args.collector, CollectorSpec::Off)),
        (
            "--collector-window-ms",
            args.collector_window_ms != crate::collector_run::DEFAULT_WINDOW_MS,
        ),
        ("--seed-input", !args.seed_inputs.is_empty()),
        ("--seed-file", !args.seed_files.is_empty()),
        ("--max-len", args.max_len != DEFAULT_MAX_LEN),
        ("--timeout", args.timeout.is_some()),
        ("--deadline", args.deadline.is_some()),
        ("--target-transport", args.target_transport.is_some()),
        (
            "--transport-coverage-map",
            args.transport_coverage_map.is_some(),
        ),
        ("--protocol-profile", args.protocol_profile.is_some()),
        ("--session-transport", args.session_transport.is_some()),
        (
            "--session-reset",
            args.session_reset != crate::session_fuzz::SessionResetMode::default(),
        ),
        ("--max-session-messages", args.max_session_messages != 64),
        (
            "--session-reply-timeout",
            args.session_reply_timeout.is_some(),
        ),
        ("--session-server-cmd", args.session_server_cmd.is_some()),
    ];
    given
        .into_iter()
        .filter_map(|(flag, set)| set.then_some(flag))
        .collect()
}

/// Why this run's flags cannot all apply: the transport or session lane it
/// dispatches to does not wire some of them.
fn lane_flag_conflict(args: &FuzzArgs) -> Option<String> {
    let (lane, ignored) = if crate::transport_fuzz::should_use_transport(args) {
        (
            "--target-transport",
            crate::transport_fuzz::unsupported_flags(args),
        )
    } else if crate::session_fuzz::should_use_session(args) {
        (
            "--protocol-profile",
            crate::session_fuzz::unsupported_flags(args),
        )
    } else {
        return None;
    };
    (!ignored.is_empty()).then(|| {
        format!(
            "bhf fuzz {lane}: {} {} not apply to the {lane} lane, which would ignore {}; \
             remove {}",
            ignored.join(", "),
            if ignored.len() == 1 { "does" } else { "do" },
            if ignored.len() == 1 { "it" } else { "them" },
            if ignored.len() == 1 { "it" } else { "them" },
        )
    })
}

/// Why `--frame` cannot apply to this run: only the builtin engine's
/// single-input loop decodes and repairs its inputs against a frame.
fn frame_conflict(args: &FuzzArgs) -> Option<String> {
    args.frame_file.as_ref()?;
    let other = if args.engine != FuzzEngine::Builtin {
        format!("--engine {}", engine_arg_name(args.engine))
    } else if crate::transport_fuzz::should_use_transport(args) {
        "--target-transport".to_owned()
    } else if crate::session_fuzz::should_use_session(args) {
        "--protocol-profile".to_owned()
    } else {
        return None;
    };
    Some(format!(
        "bhf fuzz --frame: only the builtin engine's single-input loop repairs its inputs \
         against a frame, and {other} runs another one, which would ignore it; remove --frame \
         or {other}"
    ))
}

/// Why `--engine` cannot run with `--target-transport` or
/// `--protocol-profile`, which drive the builtin engine's transport and
/// session lanes.
fn engine_lane_conflict(args: &FuzzArgs) -> Option<String> {
    if args.engine == FuzzEngine::Builtin {
        return None;
    }
    let flag = if args.target_transport.is_some() {
        "--target-transport"
    } else if args.protocol_profile.is_some() {
        "--protocol-profile"
    } else {
        return None;
    };
    Some(format!(
        "--engine {} cannot run with {flag}: {flag} drives the builtin engine's own loop, so \
         the {} engine would not run at all; use --engine builtin with {flag}, or leave {flag} \
         out",
        engine_arg_name(args.engine),
        engine_arg_name(args.engine)
    ))
}

/// The flags a multi-worker or sanitizer-matrix run carries out: its own, and
/// those [`worker_passthrough_args`] gives every worker.
const MULTICORE_FLAGS: &[&str] = &[
    "--workers",
    "--sanitizers",
    "--grammar",
    "--frame",
    "--dict",
    "--cmplog-log",
    "--len-control",
    "--rss-limit-mb",
    "--fork-server",
    "--no-fork-server",
    "--qemu-user",
    "--qemu-arg",
    "--symbolic-seed-source",
    "--sandbox",
    "--sandbox-tool",
    "--sandbox-strict",
    "--runtime-oracles",
    "--structured-inputs",
    "--seed-input",
    "--seed-file",
    "--max-len",
    "--timeout",
    "--deadline",
];

/// Why a multi-worker or sanitizer-matrix run cannot carry out every flag it
/// was given. Its workers are single-worker runs in their own work dirs, and
/// the parent merges only their findings: a collector's evidence and
/// provenance, an extension's verdicts or a final-stats line would stay in a
/// worker's dir or log.
fn multicore_flag_conflict(args: &FuzzArgs) -> Option<String> {
    let dropped: Vec<&str> = given_flags(args)
        .into_iter()
        .filter(|flag| !MULTICORE_FLAGS.contains(flag))
        .collect();
    if dropped.is_empty() {
        return None;
    }
    let lane = if args.sanitizers.len() > 1 {
        "a sanitizer matrix (several --sanitizers)"
    } else {
        "--workers"
    };
    let one = dropped.len() == 1;
    Some(format!(
        "bhf fuzz: {} {} not apply to {lane}, whose workers would ignore {}; remove {}, or run \
         one worker with one sanitizer",
        dropped.join(", "),
        if one { "does" } else { "do" },
        if one { "it" } else { "them" },
        if one { "it" } else { "them" },
    ))
}

fn multicore_requested(args: &FuzzArgs) -> bool {
    if args.sanitizers.len() > 1 {
        return true;
    }
    matches!(args.workers, Some(FuzzWorkerCount::Auto))
        || matches!(args.workers, Some(FuzzWorkerCount::Fixed(n)) if n > 1)
}

fn run_multicore_campaign(mut args: FuzzArgs) -> i32 {
    // Resolve the harness once, through the same layout lookup a single-worker
    // run uses, and give every worker that layout. Without a harness there is
    // nothing for the workers to run, so fail as the single-worker path does.
    let harness_path = match find_harness_executable(&args.work_dir, &args.harness, args.engine) {
        Ok(path) => path,
        Err(error) => {
            bhfeprintln!("{error}");
            return 3;
        }
    };
    // Each worker's stderr goes to its own log, so what a single-worker run
    // says about the harness is said here, once.
    for note in multicore_harness_notes(&args, &harness_path) {
        bhfeprintln!("note: {note}");
    }
    // Every worker loads the runtime oracles it is given; one it cannot load
    // fails here, once, as a single-worker run does, before any worker starts.
    let mode_label = args.mode.to_string().to_ascii_lowercase();
    if let Err(error) =
        crate::runtime_oracles::RuntimeOracles::resolve(args.runtime_oracles, &mode_label)
    {
        bhfeprintln!("{error}");
        return 3;
    }
    let (harness_dirs, harness_executable) =
        worker_harness_layout(&args.work_dir, &args.harness, &harness_path);
    if let Err(error) = worker_seed_files(&mut args, &harness_path) {
        bhfeprintln!("{error}");
        return 1;
    }
    let sanitizers = match parse_sanitizer_args(&args.sanitizers) {
        Ok(sanitizers) => sanitizers,
        Err(error) => {
            bhfeprintln!("{error}");
            return 3;
        }
    };
    let min_workers = sanitizers.runtime_set().len().max(1) as u32;
    let workers = match args.workers {
        Some(FuzzWorkerCount::Auto) => multicore_fuzz::WorkerCount::Auto,
        Some(FuzzWorkerCount::Fixed(n)) => multicore_fuzz::WorkerCount::Fixed(n.max(min_workers)),
        None => multicore_fuzz::WorkerCount::Fixed(min_workers),
    };
    let bhf_bin = match args.bhf_bin.clone() {
        Some(path) => path,
        None => match std::env::current_exe() {
            Ok(path) => path,
            Err(error) => {
                bhfeprintln!("resolve current bhf executable: {error}");
                return 3;
            }
        },
    };
    let config = multicore_fuzz::MulticoreConfig {
        work_dir: args.work_dir.clone(),
        harness_id: args.harness.clone(),
        workers,
        // Pass the raw Option through: an explicit cap reaches each worker as
        // `--iterations N`; when omitted under `--time`, workers receive no
        // `--iterations` and resolve to time-bounded themselves.
        per_worker_iterations: args.iterations.map(|n| n as u64),
        time_budget: args.time.unwrap_or(Duration::ZERO),
        bhf_bin,
        per_worker_env: multicore_fuzz::sanitizer_envs(sanitizers.runtime_set()),
        extra_worker_args: worker_passthrough_args(&args),
        kill_grace: None,
        harness_dirs,
        harness_executable,
        // The cap each worker's pass trims its lineage to, so the merge
        // keeps no more.
        lineage_record_cap: corpus::lineage::record_cap(corpus_limits(args.max_len.max(1)).entries),
    };

    match multicore_fuzz::run_multicore(&config) {
        Ok(summary) => {
            report_failed_workers(&summary);
            // Merge before printing, so the summary says what the merge did.
            let (merged, merge) = merge_worker_findings(&config.work_dir, &summary);
            let (duplicates_of_existing, duplicate_crashes_of_existing) =
                campaign_duplicates_of_existing(&config.work_dir, &summary, merge.as_ref());
            let printed = MulticoreRunSummary {
                summary: &summary,
                runtime_oracles: runtime_oracle_mode_arg_name(args.runtime_oracles),
                merged_findings: merge.map(|merge| merge.merged).unwrap_or_default(),
                duplicates_of_existing,
                duplicate_crashes_of_existing,
            };
            match serde_json::to_string_pretty(&printed) {
                Ok(json) => println!("{json}"),
                Err(error) => {
                    bhfeprintln!("failed to render multicore fuzz summary: {error}");
                    return 1;
                }
            }
            if let Some(note) = duplicates_of_existing_note(
                &printed.duplicates_of_existing,
                printed.duplicate_crashes_of_existing,
                &summary.harness_id,
            ) {
                bhfeprintln!("{note}");
            }
            if summary.dropped_duplicates > 0 {
                bhfeprintln!(
                    "bhf fuzz: dropped {} duplicate(s) earlier campaigns left in worker dirs; \
                     the findings they duplicated are no longer in {}",
                    summary.dropped_duplicates,
                    corpus::layout::findings_dir(&config.work_dir).display()
                );
            }
            let Some(outcome) = no_worker_completed(&summary) else {
                return merged;
            };
            let started = summary.workers_started;
            let log = multicore_fuzz::WORKER_STDERR_LOG;
            match outcome {
                NoWorkerCompleted::Stopped { stopped, recorded } if recorded > 0 => {
                    bhfeprintln!(
                        "warning: no worker finished on its own; {stopped} of {started} were \
                         stopped at the time limit, and the {recorded} finding(s) recorded until \
                         then were merged"
                    );
                }
                NoWorkerCompleted::Stopped { stopped, .. } => {
                    bhfeprintln!(
                        "error: no worker finished: {stopped} of {started} were stopped at the \
                         time limit and none recorded a finding; each worker's full stderr is \
                         in its {log}"
                    );
                }
                NoWorkerCompleted::Failed { recorded: 0, .. } => {
                    bhfeprintln!(
                        "error: none of the {started} worker(s) completed, so this campaign \
                         fuzzed nothing; each worker's full stderr is in its {log}"
                    );
                }
                NoWorkerCompleted::Failed { recorded, .. } => {
                    bhfeprintln!(
                        "error: none of the {started} worker(s) completed; the {recorded} \
                         finding(s) they recorded before failing were merged; each worker's \
                         full stderr is in its {log}"
                    );
                }
            }
            incomplete_campaign_exit(outcome, merged)
        }
        Err(error) => {
            bhfeprintln!("{error}");
            match error {
                multicore_fuzz::MulticoreError::WorkDirMissing(_)
                | multicore_fuzz::MulticoreError::BinMissing(_)
                | multicore_fuzz::MulticoreError::InvalidWorkerCount => 3,
                _ => 1,
            }
        }
    }
}

/// The notes a single-worker run prints about its harness that a
/// multi-worker campaign prints once for all workers: that a builtin-engine
/// harness is a libFuzzer binary without bhf's driver.
fn multicore_harness_notes(args: &FuzzArgs, harness: &Path) -> Vec<String> {
    if args.engine != FuzzEngine::Builtin {
        return Vec::new();
    }
    let detection = crate::protocol_detect::detect(harness, &[&args.work_dir]);
    libfuzzer_binary_note(&detection, harness)
        .into_iter()
        .collect()
}

/// What a multi-worker `bhf fuzz` prints: the campaign summary plus what the
/// merge into the parent's findings did.
#[derive(Serialize)]
struct MulticoreRunSummary<'a> {
    #[serde(flatten)]
    summary: &'a multicore_fuzz::MulticoreSummary,
    /// The `--runtime-oracles` mode every worker ran with; their oracle
    /// findings are among `merged_findings`.
    runtime_oracles: &'static str,
    /// Parent ids the workers' new findings were merged under.
    merged_findings: Vec<String>,
    /// Findings recorded before the campaign that its crashes matched (sorted
    /// parent ids), so those crashes were not recorded again.
    duplicates_of_existing: Vec<String>,
    /// How many crashes matched one of `duplicates_of_existing`.
    duplicate_crashes_of_existing: usize,
}

/// The parent findings recorded before this campaign that its crashes matched,
/// and how many crashes did: worker findings the merge found to duplicate
/// them, and crashes a worker did not record because its own tree still held
/// a duplicate an earlier merge marked as one of them.
fn campaign_duplicates_of_existing(
    work_dir: &Path,
    summary: &multicore_fuzz::MulticoreSummary,
    merge: Option<&multicore_fuzz::MergeReport>,
) -> (Vec<String>, usize) {
    let mut ids: std::collections::BTreeSet<String> = merge
        .map(|merge| merge.duplicates_of_existing.iter().cloned().collect())
        .unwrap_or_default();
    let mut crashes = merge.map_or(0, |merge| merge.duplicate_findings_of_existing);
    for worker in &summary.per_worker {
        let parents: Vec<String> = worker
            .duplicates_of_existing
            .iter()
            .filter_map(|id| multicore_fuzz::marked_duplicate_of(work_dir, &worker.work_dir, id))
            .collect();
        if !parents.is_empty() {
            crashes += worker.duplicate_crashes_of_existing.max(1);
            ids.extend(parents);
        }
    }
    (ids.into_iter().collect(), crashes)
}

/// The harness layout to mirror into each worker tree: every work-dir-relative
/// harness dir a worker's lookup reads (`build/<id>` and the `bhf auto` layouts
/// under `harnesses/`, `auto/` and `generated_harnesses/`), whether or not the
/// parent has it, so a worker's copy of one the parent lacks is removed; plus
/// the executable the parent resolved, relative to the work dir.
fn worker_harness_layout(
    work_dir: &Path,
    harness_id: &str,
    executable: &Path,
) -> (Vec<PathBuf>, Option<PathBuf>) {
    let mut candidates = vec![work_dir.join("build").join(harness_id)];
    candidates.extend(crate::auto::layout::harness_dir_candidates(
        work_dir, harness_id,
    ));
    let dirs = candidates
        .iter()
        .filter_map(|dir| dir.strip_prefix(work_dir).ok().map(Path::to_path_buf))
        .collect();
    let executable = executable
        .strip_prefix(work_dir)
        .ok()
        .map(Path::to_path_buf);
    (dirs, executable)
}

/// Name each worker that did not complete, with the tail of its stderr: the
/// summary alone only shows an exit code.
fn report_failed_workers(summary: &multicore_fuzz::MulticoreSummary) {
    for worker in summary
        .per_worker
        .iter()
        .filter(|worker| !worker.completed())
    {
        let how = match worker.exit_code {
            Some(code) => format!("exited {code}"),
            None if worker.stopped_at_deadline => "was stopped at the time limit".to_owned(),
            None => "was killed by a signal".to_owned(),
        };
        match &worker.stderr_tail {
            Some(tail) => {
                bhfeprintln!(
                    "bhf fuzz: worker {} {how} ({}); last stderr lines:",
                    worker.worker_id,
                    worker.work_dir.display()
                );
                for line in tail.lines() {
                    bhfeprintln!("  | {line}");
                }
            }
            None => bhfeprintln!(
                "bhf fuzz: worker {} {how} ({}) with no stderr output",
                worker.worker_id,
                worker.work_dir.display()
            ),
        }
    }
}

/// How a campaign in which no worker completed ended. `recorded` counts the
/// findings the workers recorded during this campaign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoWorkerCompleted {
    /// Every worker exited non-zero or was killed by a signal. `exit_code` is
    /// the workers' shared exit code when they agree (3, for instance, when none
    /// found its harness), else 1.
    Failed { exit_code: i32, recorded: usize },
    /// `stopped` workers were still running at the time limit and were stopped;
    /// they fuzzed until then.
    Stopped { stopped: usize, recorded: usize },
}

/// `None` when at least one worker completed (or none started).
fn no_worker_completed(summary: &multicore_fuzz::MulticoreSummary) -> Option<NoWorkerCompleted> {
    if summary.workers_started == 0 || summary.workers_completed > 0 {
        return None;
    }
    let recorded = summary
        .per_worker
        .iter()
        .map(|worker| worker.new_findings)
        .sum();
    let stopped = summary
        .per_worker
        .iter()
        .filter(|worker| worker.stopped_at_deadline)
        .count();
    if stopped > 0 {
        return Some(NoWorkerCompleted::Stopped { stopped, recorded });
    }
    let first = summary
        .per_worker
        .first()
        .and_then(|worker| worker.exit_code);
    let shared = first.filter(|&code| {
        code != 0
            && summary
                .per_worker
                .iter()
                .all(|worker| worker.exit_code == Some(code))
    });
    Some(NoWorkerCompleted::Failed {
        exit_code: shared.unwrap_or(1),
        recorded,
    })
}

/// The exit code of a campaign in which no worker completed. Workers stopped
/// at the time limit after recording findings fuzzed: that campaign keeps the
/// merge's exit code. Stopped workers that recorded nothing exit 1, and failed
/// workers exit with their shared code.
fn incomplete_campaign_exit(outcome: NoWorkerCompleted, merged: i32) -> i32 {
    match outcome {
        NoWorkerCompleted::Stopped { recorded, .. } if recorded > 0 => merged,
        NoWorkerCompleted::Stopped { .. } => 1,
        NoWorkerCompleted::Failed { exit_code, .. } => exit_code,
    }
}

/// Move the workers' findings into the campaign's own results/findings, so
/// the results bracket around this command indexes them. Returns the exit
/// code and, when the merge ran, its report.
fn merge_worker_findings(
    work_dir: &Path,
    summary: &multicore_fuzz::MulticoreSummary,
) -> (i32, Option<multicore_fuzz::MergeReport>) {
    let workers: Vec<PathBuf> = summary
        .per_worker
        .iter()
        .map(|worker| worker.work_dir.clone())
        .collect();
    match multicore_fuzz::merge_worker_findings(work_dir, &workers) {
        Ok(merge) => {
            let code = merge_outcome(work_dir, &merge);
            (code, Some(merge))
        }
        Err(error) => {
            bhfeprintln!(
                "error: worker findings not merged into {}: {error}",
                work_dir.display()
            );
            (1, None)
        }
    }
}

/// The number of zero bytes to put in front of a seed of `harness_id`'s
/// input format ([`harness_gen::arg_layout::ArgLayout::seed_prefix_len`],
/// from the `arg-layout.json` beside the harness or in its harness dir):
/// `None` when its layout has no such prefix or it has no layout.
pub(crate) fn layout_seed_prefix(
    harness: &Path,
    work_dir: &Path,
    harness_id: &str,
) -> Option<usize> {
    harness
        .parent()
        .map(Path::to_path_buf)
        .into_iter()
        .chain(crate::auto::layout::harness_dir_candidates(
            work_dir, harness_id,
        ))
        .find_map(|dir| harness_gen::arg_layout::ArgLayout::read(&dir).and_then(Result::ok))
        .and_then(|layout| layout.seed_prefix_len())
}

/// Each of `seeds` again behind `prefix` zero bytes, for a harness that
/// decodes that many bytes into fixed-width parameters before its buffer.
/// The seeds themselves stay as they are. A variant already among the seeds
/// is not repeated, and a seed that is itself the variant of another (a
/// worker handed both) gets none, so applying this twice adds nothing.
pub(crate) fn layout_prefixed_seeds(seeds: &[Vec<u8>], prefix: usize) -> Vec<Vec<u8>> {
    if prefix == 0 {
        return Vec::new();
    }
    let present: std::collections::HashSet<&[u8]> = seeds.iter().map(Vec::as_slice).collect();
    let mut variants: Vec<Vec<u8>> = Vec::new();
    for seed in seeds {
        let is_variant = seed.len() >= prefix
            && seed[..prefix].iter().all(|&byte| byte == 0)
            && present.contains(&seed[prefix..]);
        if is_variant {
            continue;
        }
        let mut variant = vec![0u8; prefix];
        variant.extend_from_slice(seed);
        if !present.contains(variant.as_slice()) && !variants.contains(&variant) {
            variants.push(variant);
        }
    }
    variants
}

/// Report a merge on stderr; its exit code.
fn merge_outcome(work_dir: &Path, merge: &multicore_fuzz::MergeReport) -> i32 {
    if !merge.merged.is_empty() || merge.duplicates > 0 {
        bhfeprintln!(
            "bhf fuzz: merged {} worker finding(s) into {} ({} duplicate(s) left in worker dirs)",
            merge.merged.len(),
            corpus::layout::findings_dir(work_dir).display(),
            merge.duplicates
        );
    }
    if merge.dropped > 0 {
        bhfeprintln!(
            "bhf fuzz: dropped {} worker duplicate(s) of findings no longer in {}",
            merge.dropped,
            corpus::layout::findings_dir(work_dir).display()
        );
    }
    if merge.unreadable > 0 {
        bhfeprintln!(
            "warning: {} worker finding(s) without a readable finding.json were not merged",
            merge.unreadable
        );
    }
    if merge.failed == 0 {
        return 0;
    }
    bhfeprintln!(
        "error: {} worker finding(s) could not be merged; they stay in their worker dirs and the next merge resumes them",
        merge.failed
    );
    for error in &merge.errors {
        bhfeprintln!("  {error}");
    }
    1
}

/// Workers receive their seeds through argv, which cannot carry arbitrary bytes
/// (a NUL ends an argument; a non-UTF-8 `--seed-input` is rejected). Write the
/// programmatic seed bytes to content-named files under the campaign dir and
/// hand them over as `--campaign-seed-file`, which every worker reads byte for
/// byte and does not take for a seed given to it: these files are bhf's
/// copies, and the lineage names the seed each was made from.
fn materialize_seed_bytes(args: &mut FuzzArgs) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    if args.seed_bytes.is_empty() {
        return Ok(());
    }
    let dir = args
        .work_dir
        .join("fuzz_campaigns")
        .join(&args.harness)
        .join("seed_bytes");
    fs::create_dir_all(&dir)
        .map_err(|error| format!("create seed dir '{}': {error}", dir.display()))?;
    for bytes in std::mem::take(&mut args.seed_bytes) {
        let path = dir.join(format!(
            "{}.bin",
            corpus::hex_lower(&Sha256::digest(&bytes))
        ));
        fs::write(&path, &bytes)
            .map_err(|error| format!("write seed '{}': {error}", path.display()))?;
        args.campaign_seed_files.push(path);
    }
    Ok(())
}

/// Hand a multi-worker campaign's seeds to its workers as files: the seeds
/// given to `bhf fuzz` as they were given, and as campaign seed files the
/// prefixed variants of those seeds (see [`layout_prefixed_seeds`]), made
/// once here, and every programmatic seed ([`materialize_seed_bytes`]). The
/// workers are told the variants are made, so none prefixes the seeds it is
/// handed, the programmatic and shared-queue ones included.
fn worker_seed_files(args: &mut FuzzArgs, harness: &Path) -> Result<(), String> {
    if !args.seeds_layout_prefixed {
        if let Some(prefix) = layout_seed_prefix(harness, &args.work_dir, &args.harness) {
            let mut given: Vec<Vec<u8>> = args
                .seed_inputs
                .iter()
                .map(|seed| seed.as_bytes().to_vec())
                .collect();
            for seed_file in &args.seed_files {
                let (bytes, _) =
                    read_seed_file_prefix(seed_file, args.max_len.max(1)).map_err(|error| {
                        format!("read seed file '{}': {error}", seed_file.display())
                    })?;
                given.push(bytes);
            }
            let variants = layout_prefixed_seeds(&given, prefix);
            args.seed_bytes.extend(variants);
        }
        args.seeds_layout_prefixed = true;
    }
    materialize_seed_bytes(args)
}

fn worker_passthrough_args(args: &FuzzArgs) -> Vec<String> {
    let mut out = vec![
        // A worker's stderr is its log, whose tail a failed campaign prints.
        "--quiet".to_owned(),
        "--engine".to_owned(),
        engine_arg_name(args.engine).to_owned(),
        "--mode".to_owned(),
        args.mode.to_string(),
        "--sandbox".to_owned(),
        sandbox_arg_name(args.sandbox).to_owned(),
    ];
    if let Some(tool) = &args.sandbox_tool {
        out.push("--sandbox-tool".to_owned());
        out.push(tool.display().to_string());
    }
    if args.sandbox_strict {
        out.push("--sandbox-strict".to_owned());
    }
    for seed in &args.seed_inputs {
        out.push("--seed-input".to_owned());
        out.push(seed.clone());
    }
    for seed_file in &args.seed_files {
        out.push("--seed-file".to_owned());
        out.push(seed_file.display().to_string());
    }
    for seed_file in &args.campaign_seed_files {
        out.push("--campaign-seed-file".to_owned());
        out.push(seed_file.display().to_string());
    }
    if args.seeds_layout_prefixed {
        out.push("--seeds-layout-prefixed".to_owned());
    }
    for source in &args.symbolic_seed_sources {
        out.push("--symbolic-seed-source".to_owned());
        out.push(source.display().to_string());
    }
    if let Some(cmplog_log) = &args.cmplog_log {
        out.push("--cmplog-log".to_owned());
        out.push(cmplog_log.display().to_string());
    }
    out.push("--structured-inputs".to_owned());
    out.push(structured_input_mode_arg_name(args.structured_inputs).to_owned());
    out.push("--max-len".to_owned());
    out.push(args.max_len.to_string());
    out.push("--len-control".to_owned());
    out.push(args.len_control.to_string());
    if let Some(timeout) = args.timeout {
        out.push("--timeout".to_owned());
        out.push(duration_arg(timeout.max(Duration::from_millis(1))));
    }
    if args.rss_limit_mb > 0 {
        out.push("--rss-limit-mb".to_owned());
        out.push(args.rss_limit_mb.to_string());
    }
    if let Some(qemu) = &args.qemu_user {
        out.push("--qemu-user".to_owned());
        out.push(qemu.display().to_string());
        for arg in &args.qemu_args {
            out.push(format!("--qemu-arg={arg}"));
        }
    }
    if let Some(deadline) = args.deadline {
        out.push("--deadline".to_owned());
        out.push(duration_arg(deadline));
    }
    if args.fork_server {
        out.push("--fork-server".to_owned());
    }
    if args.no_fork_server {
        out.push("--no-fork-server".to_owned());
    }
    if let Some(grammar) = &args.grammar_file {
        out.push("--grammar".to_owned());
        out.push(grammar.display().to_string());
    }
    if let Some(frame) = &args.frame_file {
        out.push("--frame".to_owned());
        out.push(frame.display().to_string());
    }
    if let Some(dict) = &args.dict_file {
        out.push("--dict".to_owned());
        out.push(dict.display().to_string());
    }
    out.push("--runtime-oracles".to_owned());
    out.push(runtime_oracle_mode_arg_name(args.runtime_oracles).to_owned());
    out
}

fn runtime_oracle_mode_arg_name(mode: crate::runtime_oracles::RuntimeOracleMode) -> &'static str {
    use crate::runtime_oracles::RuntimeOracleMode;
    match mode {
        RuntimeOracleMode::Auto => "auto",
        RuntimeOracleMode::On => "on",
        RuntimeOracleMode::Off => "off",
    }
}

fn engine_arg_name(engine: FuzzEngine) -> &'static str {
    match engine {
        FuzzEngine::Builtin => "builtin",
        FuzzEngine::AflPlusPlus => "afl++",
        FuzzEngine::Winafl => "winafl",
        FuzzEngine::Libfuzzer => "libfuzzer",
        FuzzEngine::Honggfuzz => "honggfuzz",
        FuzzEngine::Libafl => "libafl",
    }
}

fn sandbox_arg_name(sandbox: SandboxModeArg) -> &'static str {
    match sandbox {
        SandboxModeArg::None => "none",
        SandboxModeArg::Auto => "auto",
        SandboxModeArg::Firejail => "firejail",
        SandboxModeArg::Bubblewrap => "bubblewrap",
    }
}

fn structured_input_mode_arg_name(mode: StructuredInputMode) -> &'static str {
    match mode {
        StructuredInputMode::Auto => "auto",
        StructuredInputMode::Off => "off",
        StructuredInputMode::Record => "record",
        StructuredInputMode::Json => "json",
        StructuredInputMode::Xml => "xml",
        StructuredInputMode::Kv => "kv",
        StructuredInputMode::Url => "url",
        StructuredInputMode::Multipart => "multipart",
        StructuredInputMode::Csv => "csv",
        StructuredInputMode::Http => "http",
        StructuredInputMode::Ini => "ini",
        StructuredInputMode::Toml => "toml",
        StructuredInputMode::Yaml => "yaml",
        StructuredInputMode::Recursive => "recursive",
    }
}

/// Create a zero-filled, `bytes`-sized file in `<work_dir>/fuzz_shm/` to back
/// a harness shared-memory channel, returning the handle that keeps it and its
/// path string (for the child's `*_SHM` env var). The file is unlinked when the
/// handle drops, so it lives exactly as long as the prepared run, or when a
/// stopping signal ends the process ([`shared_map`]).
fn arm_shared_map(
    work_dir: &Path,
    bytes: usize,
) -> Result<(shared_map::SharedMapFile, String), String> {
    shared_map::SharedMapFile::create(work_dir, bytes)
}

fn prepare(args: FuzzArgs) -> Result<PreparedFuzzRun, String> {
    prepare_with_runner(args, None)
}

/// [`prepare`], running the harness under `runner` when the caller supplies
/// one (`bhf auto`'s qemu-user / wine runner for a cross-built harness)
/// instead of the runner resolved from `--qemu-user` or the one recorded
/// beside the harness.
fn prepare_with_runner(
    args: FuzzArgs,
    runner: Option<replay_min::HarnessRunner>,
) -> Result<PreparedFuzzRun, String> {
    let iterations = args.effective_iterations();
    let sanitizers = parse_sanitizer_args(&args.sanitizers)?
        .runtime_set()
        .to_vec();
    let sanitizer_env = sanitizer_env_for(&sanitizers);

    let work_dir = absolutize(&args.work_dir)?;
    if !work_dir.is_dir() {
        return Err(format!("work dir '{}' does not exist", work_dir.display()));
    }

    let harness_path = find_harness_executable(&work_dir, &args.harness, args.engine)?;
    // #331: the SymCC stage's runs take the harness's sandbox.
    let sandbox = crate::symcc::Sandbox {
        mode: args.sandbox,
        tool: args.sandbox_tool.clone(),
        strict: args.sandbox_strict,
    };
    let runner = match runner {
        Some(runner) => runner,
        None => harness_runner_for(
            harness_path.clone(),
            args.qemu_user,
            args.qemu_args,
            args.sandbox,
            args.sandbox_tool,
            args.sandbox_strict,
        )?,
    };
    let mut operator_seeds: Vec<(corpus::lineage::Digest, Option<String>)> = args
        .seed_inputs
        .iter()
        .map(|seed| (corpus::lineage::digest(seed.as_bytes()), None))
        .collect();
    let mut seeds = args
        .seed_inputs
        .into_iter()
        .map(String::into_bytes)
        .collect::<Vec<_>>();
    for seed_file in args.seed_files {
        let bytes = read_seed_file_within(&seed_file, args.max_len)?;
        let named = std::path::absolute(&seed_file).unwrap_or_else(|_| seed_file.clone());
        operator_seeds.push((
            corpus::lineage::digest(&bytes),
            Some(named.display().to_string()),
        ));
        seeds.push(bytes);
    }
    // A `--seed-file`/`--seed-input` seed is a sample of the target's input
    // format; where the harness decodes fixed-width parameters before the
    // buffer, it is also given behind that many zero bytes, so the buffer
    // starts with it. A campaign's worker is handed the variants with the
    // rest of its seeds.
    if !args.seeds_layout_prefixed {
        if let Some(prefix) = layout_seed_prefix(&harness_path, &work_dir, &args.harness) {
            let variants = layout_prefixed_seeds(&seeds, prefix);
            seeds.extend(variants);
        }
    }
    seeds.extend(args.seed_bytes);
    // The campaign's own copies: not seeds given to this `bhf fuzz`, so not
    // `operator_seeds`, and not prefixed again.
    for seed_file in &args.campaign_seed_files {
        seeds.push(read_seed_file_within(seed_file, args.max_len)?);
    }
    let mut symbolic_sources = Vec::new();
    let mut symbolic_source_bytes = 0usize;
    let symbolic_source_limit = max_symbolic_source_bytes();
    let symbolic_sources_total_limit = max_symbolic_sources_total_bytes();
    for path in &args.symbolic_seed_sources {
        let (bytes, original_len) = read_seed_file_prefix(path, symbolic_source_limit)
            .map_err(|error| format!("read symbolic seed source '{}': {error}", path.display()))?;
        if original_len > bytes.len() as u64 {
            return Err(format!(
                "symbolic seed source '{}' is {original_len} bytes, above the {} MiB safety limit",
                path.display(),
                symbolic_source_limit / (1024 * 1024)
            ));
        }
        if symbolic_source_bytes.saturating_add(bytes.len()) > symbolic_sources_total_limit {
            return Err(format!(
                "symbolic seed sources exceed the {} MiB aggregate safety limit",
                symbolic_sources_total_limit / (1024 * 1024)
            ));
        }
        let contents = String::from_utf8(bytes).map_err(|error| {
            format!(
                "symbolic seed source '{}' is not UTF-8: {error}",
                path.display()
            )
        })?;
        symbolic_source_bytes = symbolic_source_bytes.saturating_add(contents.len());
        symbolic_sources.push((path.display().to_string(), contents));
    }
    let symbolic_sources = symbolic_sources
        .iter()
        .map(|(path, contents)| SymbolicSeedSource::new(path, contents))
        .collect::<Vec<_>>();
    seeds.extend(
        generate_symbolic_seeds(symbolic_sources)
            .into_iter()
            .map(|seed| seed.bytes),
    );
    seeds.extend(crate::auto::go_build::load_structured_seed_inputs(
        &crate::auto::layout::harness_dir(&work_dir, &args.harness),
    )?);
    bound_seed_corpus(&mut seeds, args.max_len.max(1));
    let mut extra_env = args.extra_env;
    extra_env.extend(sanitizer_env.clone());
    apply_fuzz_child_env_overrides(&mut extra_env);
    // Under an emulator a sanitizer report must not abort: qemu-user dumps
    // its own address space on a guest abort, which takes minutes.
    if runner.qemu_prefix().is_some() {
        no_abort_on_error(&mut extra_env);
    }
    // #59: arm the runtime sink oracles on the manual path. `bhf auto` already
    // threads LD_PRELOAD + BHF_RUNTRACE_LOG through `extra_env`, so this only
    // fires for a direct `bhf fuzz` invocation (guarded: skip when already armed).
    // The builtin loop already reads BHF_RUNTRACE_LOG, evaluates the oracle
    // registry + cross-execution taint tracker, and emits oracle findings — we
    // only supply the env that was missing on this path.
    //
    // Without them, `--collector auto` on Linux is the runtrace adapter, which
    // reads the same log: arm the shim for it alone, and keep the runtime
    // oracles' findings off, as `--runtime-oracles off` asks.
    let mut runtrace_oracles = extra_env.iter().any(|(k, _)| k == "BHF_RUNTRACE_LOG");
    if !runtrace_oracles {
        let mode_label = args.mode.to_string().to_ascii_lowercase();
        let oracles =
            crate::runtime_oracles::RuntimeOracles::resolve(args.runtime_oracles, &mode_label)
                .map_err(|e| e.to_string())?;
        runtrace_oracles = oracles.is_some();
        let shim = match oracles {
            Some(oracles) => Some(oracles),
            None if !cfg!(windows)
                && matches!(args.collector, crate::collector_run::CollectorSpec::Auto) =>
            {
                crate::runtime_oracles::RuntimeOracles::resolve(
                    crate::runtime_oracles::RuntimeOracleMode::Auto,
                    &mode_label,
                )
                .map_err(|e| e.to_string())?
            }
            None => None,
        };
        if let Some(shim) = shim {
            let oracle_log = work_dir.join("runtrace.jsonl");
            let _ = std::fs::write(&oracle_log, b"");
            extra_env.extend(shim.env_pairs(&oracle_log));
        }
    }
    // The shim records comparisons (`BHF_CMPLOG`) only in the harness's image,
    // not in a shell or tool the harness runs.
    if !extra_env.iter().any(|(key, _)| key == TARGET_EXE_ENV) {
        if let Some(target) = native_target_exe(&harness_path) {
            extra_env.push((TARGET_EXE_ENV.to_owned(), target.display().to_string()));
        }
    }
    // Only the standalone bhf-framed C/C++ driver carries the runtime that
    // writes these shared-memory channels; other engines/protocols ignore them.
    let builtin_framed = args.engine == FuzzEngine::Builtin
        && resolve_harness_protocol(&runner, &work_dir) == HarnessProtocol::BhfFramed;

    // Edge-coverage bitmap (#385). Armed unless a caller (e.g. `bhf auto`)
    // already provided one.
    let local_coverage_map =
        if builtin_framed && !extra_env.iter().any(|(key, _)| key == "BHF_COV_SHM") {
            let (path, value) = arm_shared_map(&work_dir, BHF_COV_BITS)?;
            extra_env.push(("BHF_COV_SHM".to_owned(), value));
            Some(path)
        } else {
            None
        };

    // #401: the per-exec edge hit-count map, so a loop or recursion run more
    // times on known edges is new coverage here as in `bhf auto` (#420).
    let local_count_map =
        if builtin_framed && !extra_env.iter().any(|(key, _)| key == "BHF_COV_CNT_SHM") {
            let (path, value) = arm_shared_map(&work_dir, BHF_COV_BITS)?;
            extra_env.push(("BHF_COV_CNT_SHM".to_owned(), value));
            Some(path)
        } else {
            None
        };

    // #220 stack depth: the driver records each exec's deepest stack, and a
    // deeper one is novelty, so recursion depth compounds toward exhaustion.
    // `BHF_DISABLE_STACK_DEPTH=1` turns the channel off.
    let local_stack_map = if builtin_framed
        && !extra_env
            .iter()
            .any(|(key, _)| key == "BHF_STACK_DEPTH_SHM")
        && std::env::var("BHF_DISABLE_STACK_DEPTH").as_deref() != Ok("1")
    {
        let (path, value) = arm_shared_map(&work_dir, BHF_STACK_DEPTH_BYTES)?;
        extra_env.push(("BHF_STACK_DEPTH_SHM".to_owned(), value));
        Some(path)
    } else {
        None
    };

    // In-campaign input-to-state channels — armed BY DEFAULT for the raw
    // `bhf fuzz` path so the built-in engine solves magic-value / integer
    // comparison gates out of the box, matching what `bhf auto` already wires
    // (crates/cli/src/auto/attempt.rs) and the AFL++ cmplog / libFuzzer
    // value-profile lanes it is benchmarked against. Without this the engine
    // ran blind against `redqueen_int`-style integer gates (2^-32 by chance).
    //
    // #398 value profile: the driver mines comparison operands the engine folds
    // into the mutator dictionary. Ignored by harnesses without the runtime.
    let local_vp_map = if builtin_framed && !extra_env.iter().any(|(key, _)| key == "BHF_VP_SHM") {
        let (path, value) = arm_shared_map(&work_dir, BHF_VP_BYTES)?;
        extra_env.push(("BHF_VP_SHM".to_owned(), value));
        Some(path)
    } else {
        None
    };

    // #400 RedQueen per-input operand capture (offset-aware splice), gated on the
    // same `BHF_DISABLE_REDQUEEN=1` kill-switch `auto` honors. Only wired on the
    // platforms whose `CmpShmReader` is a live mmap (linux/windows); a no-op stub
    // elsewhere, so arming it there would be inert.
    #[cfg(any(target_os = "linux", windows))]
    let local_cmp_map = if builtin_framed
        && !extra_env.iter().any(|(key, _)| key == "BHF_CMP_SHM")
        && std::env::var("BHF_DISABLE_REDQUEEN").as_deref() != Ok("1")
    {
        let (path, value) = arm_shared_map(&work_dir, BHF_CMP_BYTES)?;
        extra_env.push(("BHF_CMP_SHM".to_owned(), value));
        Some(path)
    } else {
        None
    };
    #[cfg(not(any(target_os = "linux", windows)))]
    let local_cmp_map: Option<shared_map::SharedMapFile> = None;

    let afl_workers = afl_worker_count(args.engine, args.workers);
    let symcc = if args.engine == FuzzEngine::Builtin {
        crate::symcc::SymccConfig::for_run(
            &harness_path,
            runner.qemu_prefix().is_some(),
            &sandbox,
            args.rss_limit_mb,
        )
    } else {
        None
    };
    Ok(PreparedFuzzRun {
        work_dir,
        harness_id: args.harness,
        harness_path,
        runner,
        runtrace_oracles,
        seeds,
        operator_seeds,
        iterations,
        time: args.time,
        stop_after_findings: args.stop_after_findings,
        rng_seed: args.rng_seed,
        engine: args.engine,
        afl_mode: args.afl_mode,
        afl_path: args.afl_path,
        afl_inst_ranges: args.afl_inst_ranges,
        winafl: WinaflSettings {
            winafl_path: args.winafl_path,
            dynamorio_path: args.dynamorio_path,
            instrumentation: args.winafl_instrumentation,
            fuzz_iterations: args.winafl_iterations,
            coverage_modules: args.winafl_coverage_modules,
            page_heap: args.winafl_page_heap,
        },
        winafl_timeout: args.timeout,
        mode: args.mode,
        loop_env: in_loop_env(&extra_env, in_loop_symbolize()),
        extra_env,
        _local_coverage_map: local_coverage_map,
        _local_cmp_map: local_cmp_map,
        _local_vp_map: local_vp_map,
        _local_stack_map: local_stack_map,
        _local_count_map: local_count_map,
        cmplog_log: args.cmplog_log,
        grammar_file: args.grammar_file,
        frame_file: args.frame_file,
        dict_file: args.dict_file,
        structured_inputs: args.structured_inputs,
        sanitizers,
        sanitizer_env,
        fork_server: resolve_fork_server(args.fork_server, args.no_fork_server),
        max_len: args.max_len.max(1),
        len_control: args.len_control,
        per_input_timeout: args.timeout.unwrap_or(PER_INPUT_TIMEOUT),
        deadline: args.deadline,
        print_final_stats: args.print_final_stats,
        rss_limit_mb: args.rss_limit_mb,
        afl_max_len: None,
        afl_workers,
        extension_manifest: args.extension,
        symcc,
    })
}

/// Resident set size (MB) of a running process, from `/proc/<pid>/statm`.
/// Returns `None` when unavailable (non-Linux, or the process already exited).
/// Size (bytes) of the driver's shared edge-coverage bitmap. MUST match
/// `BHF_COV_BITS` in the passthrough harness template
/// (`crates/harness_gen/src/templates/direct_harness.c.tera`) — the driver and
/// this reader map the same file.
const BHF_COV_BITS: usize = 1 << 16;

/// Size (bytes) of the driver's comparison-progress map (#421 laf-intel). One
/// byte per hashed compare site, holding this exec's MAX leading-byte-match count
/// for that site. MUST match `BHF_CMPP_BITS` in BOTH
/// `direct_harness.c.tera` and `direct_harness.cpp.tera` — the driver and this
/// reader map the same file. Same size as the edge bitmap so site hashing has
/// the same collision envelope.
#[cfg(any(target_os = "linux", windows))]
const BHF_CMPP_BITS: usize = 1 << 16;

/// Map a per-input edge hit count to an AFL-style logarithmic bucket (#420) so a
/// loop run N+1 vs N is distinguishable across a bucket boundary but identical
/// within one. REPLICATED from the canonical `count_to_bucket` in
/// `crates/fuzz_engine/builtin/src/coverage.rs` (the in-process engine's #381
/// channel) — keep the two IDENTICAL: 1->0, 2->1, 3->2, 4..=7->3, 8..=15->4,
/// 16..=31->5, 32..=127->6, 128..->7. The argument is a saturating `u8` map byte,
/// so 255 lands in the top bucket exactly like 128+.
#[cfg(any(target_os = "linux", windows))]
fn count_to_bucket(count: u8) -> u8 {
    match count {
        0 | 1 => 0,
        2 => 1,
        3 => 2,
        4..=7 => 3,
        8..=15 => 4,
        16..=31 => 5,
        32..=127 => 6,
        _ => 7,
    }
}

/// Reads the bhf driver's cumulative SanitizerCoverage edge bitmap so the
/// engine can tell, per exec, whether an input grew coverage and should be kept
/// in the corpus (#398). The driver writes the bitmap via a MAP_SHARED mapping of
/// `BHF_COV_SHM`; this maps the same file read-only, so reads are pure memory
/// (no syscall per exec) and stay cheap at fork-server exec rates.
/// Minimal `kernel32` file-mapping FFI so the coverage/cmplog SHM readers work on
/// native Windows without an external crate. The driver writes these maps via the
/// same Win32 file mapping (`bhf_map_shared` in the C driver), so engine + harness
/// share the bytes — the Windows analogue of the Linux `mmap(MAP_SHARED)` path.
#[cfg(windows)]
mod win_shm {
    use std::os::windows::io::AsRawHandle;
    type Handle = *mut core::ffi::c_void;
    const PAGE_READWRITE: u32 = 0x04;
    const FILE_MAP_ALL_ACCESS: u32 = 0x000F_001F;
    extern "system" {
        fn CreateFileMappingW(
            file: Handle,
            attrs: *mut core::ffi::c_void,
            protect: u32,
            max_hi: u32,
            max_lo: u32,
            name: *const u16,
        ) -> Handle;
        fn MapViewOfFile(
            map: Handle,
            access: u32,
            hi: u32,
            lo: u32,
            bytes: usize,
        ) -> *mut core::ffi::c_void;
        fn UnmapViewOfFile(addr: *const core::ffi::c_void) -> i32;
    }
    /// Map `len` bytes of `file` as a shared read+write view, or `None`. The
    /// section handle is intentionally leaked for the process lifetime (the view
    /// stays valid even after `file` is dropped; the OS reclaims it at exit),
    /// mirroring the Linux mmap-outlives-fd contract.
    pub fn map(file: &std::fs::File, len: usize) -> Option<*mut u8> {
        // SAFETY: `file` is a valid open handle; we map exactly `len` bytes of the
        // section it backs and never read/write beyond `len`.
        unsafe {
            let m = CreateFileMappingW(
                file.as_raw_handle() as Handle,
                core::ptr::null_mut(),
                PAGE_READWRITE,
                ((len as u64) >> 32) as u32,
                (len & 0xffff_ffff) as u32,
                core::ptr::null(),
            );
            if m.is_null() {
                return None;
            }
            let p = MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, len);
            if p.is_null() {
                None
            } else {
                Some(p as *mut u8)
            }
        }
    }
    pub fn unmap(ptr: *mut u8) {
        // SAFETY: `ptr` was returned by `MapViewOfFile` for this process.
        unsafe {
            UnmapViewOfFile(ptr as *const core::ffi::c_void);
        }
    }
}

/// Open (creating + sizing) the file at `path` and map `len` bytes of it as a
/// shared read+write region the driver also maps, returning the base pointer or
/// `None`. The mapping outlives the file handle on both platforms (Linux kernel
/// keeps the mmap; Windows keeps the section). This is the one place the
/// coverage/cmplog readers touch platform shared-memory APIs.
#[cfg(any(target_os = "linux", windows))]
fn map_shared_file(path: &str, len: usize) -> Option<*mut u8> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .ok()?;
    file.set_len(len as u64).ok()?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: mapping `len` bytes of a file sized to `len`; the kernel keeps
        // the mapping valid past `file`'s drop.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if p == libc::MAP_FAILED {
            None
        } else {
            Some(p as *mut u8)
        }
    }
    #[cfg(windows)]
    {
        win_shm::map(&file, len)
    }
}

/// Release a region from [`map_shared_file`].
#[cfg(any(target_os = "linux", windows))]
fn unmap_shared(ptr: *mut u8, _len: usize) {
    if ptr.is_null() {
        return;
    }
    #[cfg(target_os = "linux")]
    // SAFETY: `ptr`/`_len` are the region returned by our mmap.
    unsafe {
        libc::munmap(ptr as *mut libc::c_void, _len);
    }
    #[cfg(windows)]
    win_shm::unmap(ptr);
}

#[cfg(any(target_os = "linux", windows))]
struct CoverageTracker {
    map: *mut u8,
    len: usize,
    last_count: usize,
    /// #420 hit-count buckets: a SEPARATE, PARALLEL channel to the presence map
    /// above. `cnt_map` is the driver's per-exec edge hit-count map
    /// (`BHF_COV_CNT_SHM`); null when that env is unset (e.g. the Ada
    /// trace-pc path), in which case the bucket channel is inert and presence
    /// behavior is byte-for-byte unchanged. `virgin_buckets` is the engine-side
    /// cumulative per-edge bitmask of AFL log-buckets ever observed.
    cnt_map: *mut u8,
    cnt_len: usize,
    virgin_buckets: Vec<u8>,
    /// #421 laf-intel comparison-progress: a THIRD parallel channel. `cmpp_map` is
    /// the driver's per-exec map of MAX leading-byte-match per hashed compare site
    /// (`BHF_CMP_PROGRESS_SHM`); null when that env is unset (flag off, or the
    /// Ada trace-pc path), in which case the channel is inert. `virgin_progress`
    /// is the engine-side cumulative per-site bitmask of leading-match LEVELS ever
    /// observed, so an input that matches more leading bytes of a gate than any
    /// prior input registers as new coverage — laf-intel's gradient without an
    /// LLVM split pass.
    cmpp_map: *mut u8,
    cmpp_len: usize,
    virgin_progress: Vec<u8>,
    /// #220 stack depth: a FOURTH channel. `stack_map` is the driver's 8-byte
    /// word of the deepest stack (bytes) this exec reached
    /// (`BHF_STACK_DEPTH_SHM`); null when unset. `deepest` is the highest
    /// [`stack_depth_bucket`] any input has reached, so an input that recurses
    /// deeper than every prior one is novel on the same edges.
    stack_map: *mut u8,
    deepest: u32,
}

/// The bytes of the driver's stack-depth word (#220).
const BHF_STACK_DEPTH_BYTES: usize = 8;

/// A stack depth's novelty bucket: four per doubling (the two bits after the
/// leading one), so a recursion a quarter deeper again than any before is new,
/// while a few frames' jitter within one is not. 0 for no depth.
fn stack_depth_bucket(depth: u64) -> u32 {
    if depth == 0 {
        return 0;
    }
    let log = 63 - depth.leading_zeros();
    let fraction = if log >= 2 {
        ((depth >> (log - 2)) & 3) as u32
    } else {
        ((depth << (2 - log)) & 3) as u32
    };
    1 + log * 4 + fraction
}

#[cfg(any(target_os = "linux", windows))]
impl CoverageTracker {
    fn new(extra_env: &[(String, String)]) -> Option<Self> {
        let (_, path) = extra_env.iter().find(|(k, _)| k == "BHF_COV_SHM")?;
        // The edge bitmap, shared with the driver. Mapped read+write so
        // colorization (#400) can snapshot/zero/restore it around probe execs
        // without polluting the cumulative #398 feedback.
        let map = map_shared_file(path, BHF_COV_BITS)?;
        // #420: optionally map the driver's per-exec hit-count map (a parallel
        // channel to the presence bitmap). Absent (null) when BHF_COV_CNT_SHM
        // is unset — the Ada trace-pc path and any harness without the #420
        // runtime — leaving the bucket channel inert. Same BHF_COV_BITS size,
        // one saturating byte per edge; mapped read+write so the engine can zero
        // it before each exec (the harness only ever increments it).
        let mut cnt_map: *mut u8 = std::ptr::null_mut();
        let mut cnt_len = 0usize;
        if let Some((_, cnt_path)) = extra_env.iter().find(|(k, _)| k == "BHF_COV_CNT_SHM") {
            if let Some(m) = map_shared_file(cnt_path, BHF_COV_BITS) {
                cnt_map = m;
                cnt_len = BHF_COV_BITS;
            }
        }
        let virgin_buckets = if cnt_map.is_null() {
            Vec::new()
        } else {
            vec![0u8; BHF_COV_BITS]
        };
        // #421: optionally map the driver's per-exec comparison-progress map (a
        // third parallel channel). Absent (null) when BHF_CMP_PROGRESS_SHM is
        // unset — the flag is off, or a harness without the #421 runtime — leaving
        // the channel inert. `BHF_CMPP_BITS`-sized, one byte per hashed site;
        // mapped read+write so the engine can zero it before each exec (the harness
        // only ever raises a site's value via a `max`-write).
        let mut cmpp_map: *mut u8 = std::ptr::null_mut();
        let mut cmpp_len = 0usize;
        if let Some((_, cmpp_path)) = extra_env.iter().find(|(k, _)| k == "BHF_CMP_PROGRESS_SHM") {
            if let Some(m) = map_shared_file(cmpp_path, BHF_CMPP_BITS) {
                cmpp_map = m;
                cmpp_len = BHF_CMPP_BITS;
            }
        }
        let virgin_progress = if cmpp_map.is_null() {
            Vec::new()
        } else {
            vec![0u8; BHF_CMPP_BITS]
        };
        // #220: optionally map the driver's stack-depth word, a fourth channel;
        // null (inert) when BHF_STACK_DEPTH_SHM is unset.
        let stack_map = extra_env
            .iter()
            .find(|(k, _)| k == "BHF_STACK_DEPTH_SHM")
            .and_then(|(_, path)| map_shared_file(path, BHF_STACK_DEPTH_BYTES))
            .unwrap_or(std::ptr::null_mut());
        let mut tracker = Self {
            map,
            len: BHF_COV_BITS,
            last_count: 0,
            cnt_map,
            cnt_len,
            virgin_buckets,
            cmpp_map,
            cmpp_len,
            virgin_progress,
            stack_map,
            deepest: 0,
        };
        // Start from whatever coverage already exists (so a later pass only counts
        // edges beyond the earlier passes' accumulated bitmap as "new").
        tracker.last_count = tracker.count();
        Some(tracker)
    }

    /// Number of distinct edges hit so far (set bytes in the bitmap). Scanned as
    /// u64 words so a mostly-empty map costs ~O(edges), not O(map size).
    fn count(&self) -> usize {
        // SAFETY: `self.map` is a valid `self.len`-byte read-only mapping for the
        // tracker's lifetime; `self.len` is a multiple of 8.
        let words = unsafe { std::slice::from_raw_parts(self.map as *const u64, self.len / 8) };
        let mut count = 0usize;
        for &w in words {
            if w != 0 {
                count += w.to_ne_bytes().iter().filter(|&&b| b != 0).count();
            }
        }
        count
    }

    /// Number of edges the just-executed input added. Stateful: updates the
    /// running maximum, so call exactly once per exec.
    fn input_increased_coverage(&mut self) -> usize {
        let now = self.count();
        let added = now.saturating_sub(self.last_count);
        if added > 0 {
            self.last_count = now;
        }
        added
    }

    /// Take the cumulative edge count as the baseline without crediting an
    /// input: calibration re-runs hit edges that are no new input's.
    fn absorb_coverage(&mut self) {
        self.last_count = self.count();
    }

    /// Copy the raw edge bitmap (#400 colorization). Used to save the cumulative
    /// state before colorization probes and to compare per-exec footprints.
    fn snapshot(&self) -> Vec<u8> {
        // SAFETY: `self.map` is a valid `self.len`-byte mapping.
        unsafe { std::slice::from_raw_parts(self.map as *const u8, self.len) }.to_vec()
    }

    /// Zero the edge bitmap so the next exec records its footprint in isolation.
    fn zero(&self) {
        // SAFETY: `self.map`/`self.len` are our writable mapping.
        unsafe { std::ptr::write_bytes(self.map, 0, self.len) }
    }

    /// Restore the edge bitmap from a [`snapshot`](Self::snapshot). Called after
    /// colorization so its probe execs never alter the cumulative #398 feedback.
    fn restore(&self, snapshot: &[u8]) {
        let n = snapshot.len().min(self.len);
        // SAFETY: copying `n <= self.len` bytes into our writable mapping.
        unsafe { std::ptr::copy_nonoverlapping(snapshot.as_ptr(), self.map, n) }
    }

    /// Zero the per-exec hit-count map (#420) so the NEXT exec records its edge
    /// hit counts in isolation; the harness only ever increments it. Called
    /// before EVERY main exec. No-op when the count map is absent (Ada/legacy).
    fn zero_counts(&self) {
        if self.cnt_map.is_null() {
            return;
        }
        // SAFETY: when non-null, `self.cnt_map`/`self.cnt_len` is our writable mapping.
        unsafe { std::ptr::write_bytes(self.cnt_map, 0, self.cnt_len) }
    }

    /// Whether the just-executed input pushed any edge into an AFL hit-count
    /// BUCKET not previously seen for that edge (#420) — the loop/recursion-depth
    /// novelty that edge-presence cannot register (a loop run deeper than any
    /// prior input crosses a bucket boundary; noise WITHIN a bucket does not).
    /// Stateful: folds each newly-seen `(edge, bucket)` into `virgin_buckets`, so
    /// call exactly once per main exec, AFTER the exec and BEFORE `zero_counts`
    /// for the next one. No-op (false) when the count map is absent.
    fn input_grew_buckets(&mut self) -> usize {
        if self.cnt_map.is_null() {
            return 0;
        }
        // SAFETY: when non-null, `self.cnt_map`/`self.cnt_len` is a valid mapping
        // for the tracker's lifetime; `virgin_buckets` is sized to `cnt_len`.
        let counts = unsafe { std::slice::from_raw_parts(self.cnt_map as *const u8, self.cnt_len) };
        let mut novel = 0usize;
        for (edge, &count) in counts.iter().enumerate() {
            // count 0 == edge not hit this exec; only bucket edges actually run.
            if count == 0 {
                continue;
            }
            let bit = 1u8 << count_to_bucket(count);
            let seen = &mut self.virgin_buckets[edge];
            if *seen & bit == 0 {
                *seen |= bit;
                novel += 1;
            }
        }
        novel
    }

    /// Zero the stack-depth word (#220) so the next exec records its own
    /// deepest stack; the driver only raises it. No-op when it is absent.
    fn zero_stack(&self) {
        if self.stack_map.is_null() {
            return;
        }
        // SAFETY: when non-null, `self.stack_map` is our writable 8-byte mapping.
        unsafe { std::ptr::write_bytes(self.stack_map, 0, BHF_STACK_DEPTH_BYTES) }
    }

    /// 1 when the just-executed input reached a deeper stack bucket than any
    /// input before it (#220), else 0: deeper recursion over the same edges is
    /// progress toward stack exhaustion. Stateful; call once per main exec,
    /// after it and before [`Self::zero_stack`] for the next. 0 without the word.
    fn input_deepened_stack(&mut self) -> usize {
        if self.stack_map.is_null() {
            return 0;
        }
        // SAFETY: when non-null, `self.stack_map` is a valid 8-byte mapping the
        // driver writes with one aligned store between execs.
        let depth = unsafe { std::ptr::read_volatile(self.stack_map as *const u64) };
        let bucket = stack_depth_bucket(depth);
        if bucket > self.deepest {
            self.deepest = bucket;
            1
        } else {
            0
        }
    }

    /// Zero the per-exec comparison-progress map (#421) so the NEXT exec records
    /// its per-site leading-byte-match in isolation; the harness only ever raises
    /// a site via a `max`-write. Called before EVERY main exec. No-op when the
    /// progress map is absent (flag off / Ada / legacy).
    fn zero_progress(&self) {
        if self.cmpp_map.is_null() {
            return;
        }
        // SAFETY: when non-null, `self.cmpp_map`/`self.cmpp_len` is our writable mapping.
        unsafe { std::ptr::write_bytes(self.cmpp_map, 0, self.cmpp_len) }
    }

    /// Whether the just-executed input matched MORE leading bytes of some compare
    /// than any prior input — laf-intel's gradient (#421). For each hashed compare
    /// site the harness recorded a per-exec MAX leading-byte-match LEVEL; the first
    /// time a site reaches a given level is novel (folded into `virgin_progress`),
    /// so an input that gets one more byte of a multi-byte gate correct is retained
    /// and energized exactly like new edge coverage. Stateful: call exactly once
    /// per main exec, AFTER the exec and BEFORE `zero_progress` for the next one.
    /// No-op (false) when the progress map is absent.
    fn input_advanced_comparisons(&mut self) -> usize {
        if self.cmpp_map.is_null() {
            return 0;
        }
        // SAFETY: when non-null, `self.cmpp_map`/`self.cmpp_len` is a valid mapping
        // for the tracker's lifetime; `virgin_progress` is sized to `cmpp_len`.
        let progress =
            unsafe { std::slice::from_raw_parts(self.cmpp_map as *const u8, self.cmpp_len) };
        let mut novel = 0usize;
        for (site, &level) in progress.iter().enumerate() {
            // level 0 == no leading-byte match (or site not hit this exec); only a
            // positive leading-match is a gradient signal.
            if level == 0 {
                continue;
            }
            // Cap at 7 so `1 << level` fits a u8 (a full 8-byte match passes the
            // gate and lights a real edge — the progress channel need not encode it).
            let bit = 1u8 << level.min(7);
            let seen = &mut self.virgin_progress[site];
            if *seen & bit == 0 {
                *seen |= bit;
                novel += 1;
            }
        }
        novel
    }
}

#[cfg(any(target_os = "linux", windows))]
impl Drop for CoverageTracker {
    fn drop(&mut self) {
        unmap_shared(self.map, self.len);
        unmap_shared(self.cnt_map, self.cnt_len);
        unmap_shared(self.cmpp_map, self.cmpp_len);
        unmap_shared(self.stack_map, BHF_STACK_DEPTH_BYTES);
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
struct CoverageTracker;

#[cfg(not(any(target_os = "linux", windows)))]
impl CoverageTracker {
    fn new(_extra_env: &[(String, String)]) -> Option<Self> {
        None
    }
    fn count(&self) -> usize {
        0
    }
    fn input_increased_coverage(&mut self) -> usize {
        0
    }
    fn absorb_coverage(&mut self) {}
    fn snapshot(&self) -> Vec<u8> {
        Vec::new()
    }
    fn zero(&self) {}
    fn restore(&self, _snapshot: &[u8]) {}
    fn zero_counts(&self) {}
    fn input_grew_buckets(&mut self) -> usize {
        0
    }
    fn zero_progress(&self) {}
    fn input_advanced_comparisons(&mut self) -> usize {
        0
    }
    fn zero_stack(&self) {}
    fn input_deepened_stack(&mut self) -> usize {
        0
    }
}

/// One corpus entry in the builtin engine's mutation pool. Replaces the prior
/// three length-synced `Vec`s (#382 energy/selections) so each entry can also
/// cache its per-input RedQueen cmplog (#400): the comparison operand pairs
/// captured by running this entry once with `BHF_CMP_SHM` capture armed.
/// Cached so the capture exec is paid once per base, then reused across all the
/// children mutated from it.
struct PoolEntry {
    bytes: Vec<u8>,
    /// #382 entropic energy: coverage novelty this entry contributed.
    energy: u32,
    /// #382: how many times this entry has seeded a mutation.
    selections: u64,
    /// #400: operand pairs observed while running this entry (driver path only),
    /// `None` until it is first selected for mutation (and on non-driver paths).
    cmplog: Option<cmplog::CmpLog>,
    /// #400 colorization: a coverage-equivalent variant of `bytes` whose
    /// don't-care positions hold near-unique values, so `cmplog` operands splice
    /// at the offset they were compared instead of every occurrence of a common
    /// byte. `None` until captured; mutation draws from it when present.
    colored: Option<Vec<u8>>,
    /// The spans of the mutation base's decoded scalar arguments (#299),
    /// from the harness's `arg-layout.json`; `None` until first selected.
    typed_spans: Option<Vec<fuzz_engine_builtin::TypedSpan>>,
    /// A fresh-process re-run showed this input crashes (#416): it is a
    /// finding, so it is neither mutated from nor saved in the queue. Kept in
    /// place so every other entry keeps its pool index.
    retired: bool,
    /// The `--grammar` derivation tree whose sentence `bytes` is (#329), for
    /// an input a grammar derivation or tree mutation made: its children are
    /// mostly tree mutations, which keep them sentences of the grammar.
    tree: Option<fuzz_engine_builtin::grammar::Derivation>,
}

/// Quantitative marginal feedback from one execution. Keeping the channel
/// counts (instead of collapsing them to a boolean) lets the entropic scheduler
/// distinguish a portfolio lane that opens hundreds of new target edges from a
/// lane that contributes one incidental bucket.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct CoverageNovelty {
    new_edges: usize,
    new_buckets: usize,
    comparison_advances: usize,
    /// #220: the input reached a deeper stack than any before it.
    deeper_stack: usize,
}

impl CoverageNovelty {
    fn made_progress(self) -> bool {
        self.new_edges > 0
            || self.new_buckets > 0
            || self.comparison_advances > 0
            || self.deeper_stack > 0
    }

    fn scheduling_energy(self) -> u32 {
        self.new_edges
            .saturating_mul(8)
            .saturating_add(self.new_buckets.saturating_mul(2))
            .saturating_add(self.comparison_advances)
            .saturating_add(self.deeper_stack.saturating_mul(4))
            .clamp(1, 4096) as u32
    }
}

/// Write `input` into the live corpus dir (#256) as `<sha256>.bin`, the
/// queue's naming. Best effort: the dir is an observer's, not the run's.
fn write_live_corpus_entry(dir: &Path, input: &[u8]) {
    use sha2::Digest;
    let name = corpus::hex_lower(&sha2::Sha256::digest(input));
    let path = dir.join(format!("{name}.bin"));
    if !path.exists() {
        let _ = fs::write(path, input);
    }
}

/// How many times the persistent engine re-runs a new corpus entry to see
/// whether it hits the same edges each time (#232).
const CALIBRATION_RERUNS: usize = 4;

/// Below this stability the run says the harness carries state between
/// executions (AFL++ colours its stability figure at the same mark).
const STABILITY_HINT_PCT: f64 = 90.0;

/// Stability calibration of the persistent engine's new corpus entries
/// (#232), as AFL++ calibrates its queue: one process runs input after input,
/// so a target that keeps state from one execution to the next hits edges
/// that depend on what ran before rather than on the input.
#[derive(Debug, Default)]
struct Calibration {
    /// Edges any calibration run hit.
    observed: HashSet<u32>,
    /// Edges one run of an input hit and another run of it did not.
    variable: HashSet<u32>,
    /// Edges every run of some calibrated input hit.
    stable: HashSet<u32>,
    entries: usize,
    dropped: usize,
}

impl Calibration {
    /// Fold the edge sets of one input's runs. Whether it keeps its place in
    /// the corpus: it hit the same edges every time, or it hit, every time,
    /// an edge no calibrated input hit every time before. Otherwise its new
    /// coverage was edges that vary from run to run.
    fn calibrate(&mut self, runs: &[Vec<u32>]) -> bool {
        let Some((first, rest)) = runs.split_first() else {
            return true;
        };
        let mut every: HashSet<u32> = first.iter().copied().collect();
        let mut any = every.clone();
        for run in rest {
            let edges: HashSet<u32> = run.iter().copied().collect();
            every.retain(|edge| edges.contains(edge));
            any.extend(edges);
        }
        self.entries += 1;
        self.variable.extend(any.difference(&every).copied());
        let stable_input = any.len() == every.len();
        let adds_a_stable_edge = every
            .iter()
            .any(|edge| !self.stable.contains(edge) && !self.variable.contains(edge));
        self.observed.extend(any);
        self.stable.extend(every);
        let keep = stable_input || adds_a_stable_edge;
        if !keep {
            self.dropped += 1;
        }
        keep
    }

    /// The share of observed edges no run varied on, in percent; `None`
    /// before any entry was calibrated.
    fn stability_pct(&self) -> Option<f64> {
        if self.entries == 0 {
            return None;
        }
        if self.observed.is_empty() {
            return Some(100.0);
        }
        let steady = self.observed.len() - self.variable.len();
        Some((steady as f64 * 1000.0 / self.observed.len() as f64).round() / 10.0)
    }

    fn summary(&self) -> Option<StabilitySummary> {
        Some(StabilitySummary {
            stability_pct: self.stability_pct()?,
            calibrated_entries: self.entries,
            reruns_per_entry: CALIBRATION_RERUNS,
            observed_edges: self.observed.len(),
            variable_edges: self.variable.len(),
            unstable_entries_dropped: self.dropped,
        })
    }
}

/// The run's stability calibration (#232).
#[derive(Debug, Clone, Serialize)]
pub(crate) struct StabilitySummary {
    /// The share of the edges calibration runs hit that every run of the
    /// same input hit, in percent: 100 for a target whose coverage depends
    /// on its input alone.
    pub(crate) stability_pct: f64,
    /// New corpus entries that were re-run.
    pub(crate) calibrated_entries: usize,
    /// The re-runs of each.
    pub(crate) reruns_per_entry: usize,
    pub(crate) observed_edges: usize,
    /// Edges one run of an input hit and another run of it did not.
    pub(crate) variable_edges: usize,
    /// Entries left out of the corpus because their new coverage was only
    /// edges that vary from run to run.
    pub(crate) unstable_entries_dropped: usize,
}

impl StabilitySummary {
    /// What a stability below [`STABILITY_HINT_PCT`] means, and what to do.
    fn hint(&self) -> Option<String> {
        (self.stability_pct < STABILITY_HINT_PCT).then(|| {
            format!(
                "bhf fuzz: stability {:.1}%: {} of the {} edges calibration saw differ between \
                 runs of the same input, so the harness keeps state from one execution to the \
                 next and coverage follows what ran before. {} new corpus entr{} whose only new \
                 coverage was such edges {} left out. Run with --no-fork-server to give each \
                 input a fresh process, or reset the target's state at the start of each call.",
                self.stability_pct,
                self.variable_edges,
                self.observed_edges,
                self.unstable_entries_dropped,
                if self.unstable_entries_dropped == 1 {
                    "y"
                } else {
                    "ies"
                },
                if self.unstable_entries_dropped == 1 {
                    "was"
                } else {
                    "were"
                },
            )
        })
    }
}

impl PoolEntry {
    fn seed(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            energy: 1,
            selections: 0,
            cmplog: None,
            colored: None,
            typed_spans: None,
            retired: false,
            tree: None,
        }
    }

    /// The bytes to mutate from: the colorized variant once captured, else the
    /// raw corpus bytes.
    fn mutation_base(&self) -> &[u8] {
        self.colored.as_deref().unwrap_or(&self.bytes)
    }
}

/// Shared-memory layout of the driver's per-exec cmplog ring. MUST match the
/// `BHF_CMP_*` macros in the harness template
/// (`crates/harness_gen/src/templates/direct_harness.c.tera`): header
/// `[u32 armed][u32 count]` then `BHF_CMP_CAP` records of
/// `[u8 len_a][u8 len_b][u8 a[OPMAX]][u8 b[OPMAX]]`.
// Used by the mmap/file-mapping CmpShmReader on linux + windows (and its tests);
// the reader is a no-op stub on other platforms, so gate these to match.
#[cfg(any(target_os = "linux", windows))]
const BHF_CMP_CAP: usize = 2048;
#[cfg(any(target_os = "linux", windows))]
const BHF_CMP_OPMAX: usize = 32;
#[cfg(any(target_os = "linux", windows))]
const BHF_CMP_REC: usize = 2 + 2 * BHF_CMP_OPMAX;
#[cfg(any(target_os = "linux", windows))]
const BHF_CMP_BYTES: usize = 8 + BHF_CMP_CAP * BHF_CMP_REC;

/// Reads (and arms) the driver's per-exec cmplog operand ring (#400). RedQueen
/// input-to-state: the engine arms capture for the one corpus entry it is about
/// to mutate, runs it once (the driver records the comparison operand pairs that
/// run produced), then builds a `CmpLog` whose `splice_candidates` find those
/// operands at the offsets they were compared in *that* input. Mapped
/// `MAP_SHARED` read+write so the engine can set `armed` and zero `count`.
#[cfg(any(target_os = "linux", windows))]
struct CmpShmReader {
    map: *mut u8,
    len: usize,
}

#[cfg(any(target_os = "linux", windows))]
impl CmpShmReader {
    fn new(extra_env: &[(String, String)]) -> Option<Self> {
        let (_, path) = extra_env.iter().find(|(k, _)| k == "BHF_CMP_SHM")?;
        let map = map_shared_file(path, BHF_CMP_BYTES)?;
        Some(Self {
            map,
            len: BHF_CMP_BYTES,
        })
    }

    /// Zero `count` and set `armed` so the next exec records into the ring. The
    /// driver does not reset the ring itself; pipe ordering (this store -> frame
    /// write -> child read) makes the store visible before the child appends.
    fn arm(&self) {
        // SAFETY: `self.map` is a valid `BHF_CMP_BYTES` rw mapping; header is
        // the first 8 bytes.
        unsafe {
            std::ptr::write_volatile(self.map, 1u8);
            for i in 1..8 {
                std::ptr::write_volatile(self.map.add(i), 0u8);
            }
        }
    }

    /// Clear `armed` so subsequent (child) execs do not record.
    fn disarm(&self) {
        // SAFETY: as above.
        unsafe {
            for i in 0..4 {
                std::ptr::write_volatile(self.map.add(i), 0u8);
            }
        }
    }

    /// Build a `CmpLog` from the operand pairs recorded since the last `arm`.
    /// Deduped; `count` and operand lengths are clamped to the shared capacity so
    /// a corrupt header (untrusted child) can never drive an out-of-bounds read.
    fn read_log(&self) -> cmplog::CmpLog {
        let mut log = cmplog::CmpLog::new();
        // SAFETY: the 8-byte header is within the mapping.
        let count = unsafe {
            (std::ptr::read_volatile(self.map.add(4)) as usize)
                | ((std::ptr::read_volatile(self.map.add(5)) as usize) << 8)
                | ((std::ptr::read_volatile(self.map.add(6)) as usize) << 16)
                | ((std::ptr::read_volatile(self.map.add(7)) as usize) << 24)
        }
        .min(BHF_CMP_CAP);
        let mut seen = HashSet::<(Vec<u8>, Vec<u8>)>::new();
        for i in 0..count {
            let off = 8 + i * BHF_CMP_REC;
            // SAFETY: `off + BHF_CMP_REC <= len` for every `i < BHF_CMP_CAP`,
            // and the operand lengths are clamped to `BHF_CMP_OPMAX`.
            let (la, lb) = unsafe {
                (
                    (*self.map.add(off) as usize).min(BHF_CMP_OPMAX),
                    (*self.map.add(off + 1) as usize).min(BHF_CMP_OPMAX),
                )
            };
            let a = unsafe { std::slice::from_raw_parts(self.map.add(off + 2), la) }.to_vec();
            let b =
                unsafe { std::slice::from_raw_parts(self.map.add(off + 2 + BHF_CMP_OPMAX), lb) }
                    .to_vec();
            if a.is_empty() && b.is_empty() {
                continue;
            }
            if seen.insert((a.clone(), b.clone())) {
                log.record(cmplog::CmpEntry {
                    site_id: i as u64,
                    operand_a: a,
                    operand_b: b,
                    kind: cmplog::CmpKind::IntegerCompare,
                });
            }
        }
        log
    }
}

#[cfg(any(target_os = "linux", windows))]
impl Drop for CmpShmReader {
    fn drop(&mut self) {
        unmap_shared(self.map, self.len);
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
struct CmpShmReader;

#[cfg(not(any(target_os = "linux", windows)))]
impl CmpShmReader {
    fn new(_extra_env: &[(String, String)]) -> Option<Self> {
        None
    }
    fn arm(&self) {}
    fn disarm(&self) {}
    fn read_log(&self) -> cmplog::CmpLog {
        cmplog::CmpLog::new()
    }
}

/// The report an input that ran past `--rss-limit-mb` is recorded with
/// (BHF-209), and that a replay under the same limit reproduces.
pub(crate) fn rss_limit_report() -> corpus::SanitizerReport {
    corpus::SanitizerReport {
        // A synthesized out-of-memory report: no sanitizer produced it, so the
        // provenance is None rather than a false `asan` (#78).
        sanitizer: None,
        kind: "out-of-memory".to_owned(),
        // A real catalog rule (CWE-789) so the OOM classifies as a finding
        // like any sanitizer crash, not an unmapped "oom" tag.
        rule_id: "BHF-209",
        stack: Vec::new(),
        message: "harness exceeded the configured RSS limit (--rss-limit-mb)".to_owned(),
        ..Default::default()
    }
}

/// Record on finding `id` the `--rss-limit-mb` its input ran past, which
/// `bhf replay` and `bhf minimize` apply again. Best-effort.
fn record_rss_limit(work_dir: &Path, id: &str, rss_limit_mb: usize) {
    let path = corpus::layout::finding_dir(work_dir, id).join("finding.json");
    let Some(mut raw) = std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
    else {
        return;
    };
    if let Some(obj) = raw.as_object_mut() {
        obj.insert("rss_limit_mb".to_owned(), serde_json::json!(rss_limit_mb));
    }
    if let Ok(bytes) = serde_json::to_vec_pretty(&raw) {
        let _ = std::fs::write(&path, bytes);
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn process_rss_mb(pid: u32) -> Option<usize> {
    let statm = std::fs::read_to_string(format!("/proc/{pid}/statm")).ok()?;
    let resident_pages: usize = statm.split_whitespace().nth(1)?.parse().ok()?;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page_size = if page_size > 0 {
        page_size as usize
    } else {
        4096
    };
    Some(resident_pages.saturating_mul(page_size) / (1024 * 1024))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn process_rss_mb(_pid: u32) -> Option<usize> {
    None
}

/// One-line end-of-run summary for `--print-final-stats` (libFuzzer parity).
fn format_final_stats(
    executions: usize,
    corpus_new: usize,
    corpus_duplicates: usize,
    findings: usize,
    elapsed: Duration,
) -> String {
    let secs = elapsed.as_secs_f64().max(1e-9);
    let per_sec = executions as f64 / secs;
    format!(
        "bhf: final stats — execs: {executions} ({per_sec:.0}/s) | corpus: {corpus_new} new, \
         {corpus_duplicates} dup | findings: {findings} | elapsed: {:.1}s",
        elapsed.as_secs_f64()
    )
}

fn run_builtin_with_progress(
    mut prepared: PreparedFuzzRun,
    progress: Option<FuzzProgressFn<'_>>,
) -> Result<FuzzRunSummary, String> {
    // A single persistent-harness input must never outlive the entire fuzz pass.
    // This matters most for interpreted lanes: a target such as cloc can block in
    // one call, and the fork-server used to wait its fixed 30s repeatedly even
    // when `--per-target-time` gave the pass only a few seconds.  The outer loop
    // cannot observe its wall-clock budget while blocked in that protocol wait.
    if let Some(pass_budget) = prepared.time {
        prepared.per_input_timeout = prepared.per_input_timeout.min(pass_budget);
    }
    reset_target_entry(&prepared.extra_env);
    // `--frame`: every input the loop runs is a frame of the profile's message,
    // its seeds included.
    let frame = load_frame_for_run(prepared.frame_file.as_deref())?;
    if let Some(codec) = &frame {
        frame_seeds(codec, &mut prepared.seeds);
    }
    bound_seed_corpus(&mut prepared.seeds, prepared.max_len);
    let corpus_limits = corpus_limits(prepared.max_len);
    let finding_dedup_limit = max_finding_dedup_keys();
    let start = Instant::now();
    let pass_deadline = prepared.time.map(|budget| start + budget);
    let mut last_tick = Instant::now();
    let mut corpus = CorpusManager::new(prepared.work_dir.clone())
        .with_retention_limits(corpus_limits.entries, corpus_limits.bytes);
    // Interpreted lanes (Python/Perl) run the target under an interpreter whose OWN
    // file activity the shim traces; there the resource-leak oracle is taint-gated
    // to avoid flagging the interpreter's fixed env/stdlib opens as target leaks.
    // Detected once from the launcher `main` marker.
    let interpreted_lane = read_bounded_marker_text(&prepared.harness_path, true)
        .map(|s| {
            s.contains("BHF_PY_LAUNCHER")
                || s.contains("BHF_PL_LAUNCHER")
                || s.contains("BHF_RB_LAUNCHER")
                || s.contains("BHF_LUA_LAUNCHER")
                || s.contains("BHF_PHP_LAUNCHER")
        })
        .unwrap_or(false);
    // The harness's language names the resource-leak oracle (an Ada harness's
    // leak is `resource-leak-ada`, any other's `resource-leak`).
    let harness_language = if is_instrumented_ada_harness(&prepared.runner) {
        "ada".to_owned()
    } else {
        let dirs: Vec<PathBuf> = prepared
            .harness_path
            .parent()
            .map(Path::to_path_buf)
            .into_iter()
            .chain(crate::auto::layout::harness_dir_candidates(
                &prepared.work_dir,
                &prepared.harness_id,
            ))
            .collect();
        crate::repro_lane::harness_language(&dirs, &prepared.harness_id).unwrap_or_default()
    };
    let sandbox_metadata = prepared.runner.sandbox_metadata();
    let build_binary_identity = build_binary_record(&prepared.harness_path);
    let mut emitter = with_harness_format(
        FindingEmitter::with_metadata_and_sandbox(
            prepared.work_dir.clone(),
            prepared.harness_id.clone(),
            "unknown".to_owned(),
            prepared.harness_path.display().to_string(),
            serde_json::to_value(&sandbox_metadata)
                .map_err(|error| format!("serialize sandbox metadata: {error}"))?,
        )
        .with_mode(prepared.mode)
        .with_shim_env(crate::runtime_oracles::shim_mode_gates(&prepared.extra_env))
        .with_line_maps_dir(&prepared.work_dir.join("src_instrumented")),
        &prepared.harness_path,
        &prepared.work_dir,
        &prepared.harness_id,
    );
    // A corpus this pass creates carries the harness's input format from
    // its first input on.
    emitter.start_corpus_format();
    if let Some(identity) = build_binary_identity {
        emitter = emitter.with_build_binary(identity);
    }
    let mut rng = MutationRng::new(prepared.rng_seed);
    // The mutation pool. Each entry carries its #382 entropic energy + selection
    // count (selection favors high-novelty, under-explored seeds) and its #400
    // per-input RedQueen cmplog (captured lazily on first selection).
    let (cmplog_log, cmplog_summary) =
        load_cmplog_for_run(prepared.cmplog_log.as_deref(), &prepared.seeds);
    // Move (rather than clone) seeds into the pool. Large structured seeds used
    // to remain duplicated in `prepared.seeds` for the full campaign.
    let initial_seed_count = prepared.seeds.len();
    let mut pool: Vec<PoolEntry> = std::mem::take(&mut prepared.seeds)
        .into_iter()
        .map(PoolEntry::seed)
        .collect();
    let mut pool_bytes: usize = pool.iter().map(|entry| entry.bytes.len()).sum();
    // What each pool entry descends from, kept beside the queue.
    let mut lineage = crate::fuzz_lineage::QueueLineage::start(
        &prepared.work_dir,
        &prepared.harness_id,
        &prepared.operator_seeds,
        layout_seed_prefix(
            &prepared.harness_path,
            &prepared.work_dir,
            &prepared.harness_id,
        ),
        pool.iter().map(|entry| entry.bytes.as_slice()),
        corpus::lineage::record_cap(corpus_limits.entries),
    );
    // `fuzz --grammar` sets prepared.grammar_file directly; `auto --grammar` publishes
    // the path via BHF_GRAMMAR (inherited by multicore workers), so fall back to it.
    let grammar_path = prepared.grammar_file.clone().or_else(|| {
        std::env::var_os("BHF_GRAMMAR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    });
    let grammar = load_grammar_for_run(grammar_path.as_deref())?;
    let mut dictionary_tokens = run_dictionary_tokens(
        &prepared.work_dir,
        &prepared.harness_id,
        prepared.dict_file.as_deref(),
    )?;
    if let Some(log) = &cmplog_log {
        for token in log.dictionary_tokens() {
            if !dictionary_tokens.contains(&token) {
                dictionary_tokens.push(token);
            }
        }
    }
    // Value-profile (#398): the driver mines comparison operands into a shared log
    // during the run; fold newly seen tokens into the dictionary on a cadence so a
    // later input can splice the magic byte and reach gated code. Track membership
    // so re-merges stay cheap; `None` path for harnesses without the driver runtime.
    let vp_path = prepared
        .extra_env
        .iter()
        .find(|(k, _)| k == "BHF_VP_SHM")
        .map(|(_, v)| PathBuf::from(v));
    let mut dictionary_token_set: HashSet<Vec<u8>> = dictionary_tokens.iter().cloned().collect();
    let mut dictionary = Dictionary::from_tokens(dictionary_tokens.clone());
    // Op-program geometry for a sequence harness, if this is one. Present only
    // when the generator wrote the sidecar, so a direct harness is unaffected.
    let sequence_geometry = prepared
        .harness_path
        .parent()
        .and_then(SequenceGeometry::load);
    // #299: the harness's argument layout, for typed mutation of the
    // arguments it decodes.
    let arg_layout = typed_spans::find_arg_layout(
        &prepared.work_dir,
        &prepared.harness_id,
        Some(&prepared.harness_path),
    );
    let mut portfolio_feedback = sequence_geometry
        .filter(|geometry| geometry.portfolio_lanes > 1)
        .map(|geometry| {
            (0..geometry.portfolio_lanes)
                .map(|lane| PortfolioLaneFeedback {
                    lane,
                    ..PortfolioLaneFeedback::default()
                })
                .collect::<Vec<_>>()
        });
    let mut corpus_new = 0_usize;
    let mut corpus_duplicates = 0_usize;
    let mut non_reproducible = 0_usize;
    let mut calibration = Calibration::default();
    // #256: `BHF_LIVE_CORPUS_DIR` gets each input as the pool keeps it, so a
    // harness that watches the corpus over a campaign (the engine trade
    // study's coverage-over-time snapshots) sees it grow. The queue is
    // written when the pass ends, after its re-run checks.
    let live_corpus_dir = std::env::var_os("BHF_LIVE_CORPUS_DIR")
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from);
    if let Some(dir) = live_corpus_dir.as_deref() {
        let _ = fs::create_dir_all(dir);
    }
    // #277: a worker of a `--workers` campaign shares the entries its pool
    // keeps with the other workers as it runs, and runs theirs.
    let mut peer_sync = peer_sync::PeerSync::from_env(
        &prepared.work_dir,
        pool.iter().map(|entry| entry.bytes.as_slice()),
        prepared.max_len,
    );
    if let Some(sync) = peer_sync.as_mut() {
        sync.skip_seeds(pool.len());
    }
    // #331: on a plateau, the pool's newest entries run through SymCC and the
    // inputs it solves run next.
    let mut symcc_stage = prepared.symcc.take().map(|config| {
        crate::symcc::SymccStage::new(
            config,
            &prepared.work_dir,
            &prepared.harness_id,
            prepared.max_len,
            Instant::now(),
        )
    });
    let mut hangs = HangRunSummary {
        timeout_ms: u64::try_from(prepared.per_input_timeout.as_millis()).unwrap_or(u64::MAX),
        ..HangRunSummary::default()
    };
    // Sanitizer crashes dropped as libFuzzer/sanitizer driver glue (#388).
    let mut driver_glue_drops = 0_usize;
    // LSan leaks suppressed as bhf decode/harness scaffolding (#49): the
    // decoder buffer the harness would have freed, left dangling only because an
    // exit()/abort()-only target died before the harness's free() ran.
    let mut scaffolding_leak_drops = 0_usize;
    let mut finding_ids = Vec::new();
    // #35: pre-seed the within-pass dedup sets from findings already on disk so the
    // NEXT cascade pass (Empty/Rng/FuzzDriven) over the SAME harness does not
    // re-emit a byte-identical finding it already wrote (~2-3x inflation otherwise).
    let existing_findings = ExistingFindings::load(&prepared.work_dir, &prepared.harness_id);
    let mut seen_oracle_hits =
        HashSet::<String>::from_iter(existing_findings.oracles.keys().cloned());
    // Sanitizer-crash dedup (#389): one finding per root cause, not one per
    // crashing input.
    let mut in_loop_symbolization = InLoopSymbolization::default();
    let mut sanitizer_dedup = SanitizerClusterDedup::new(
        existing_findings.clusters.keys().cloned(),
    )
    .with_scope(run_crash_scope(
        &prepared.harness_path,
        &prepared.work_dir,
        &prepared.harness_id,
    ));
    // A crash dropped because it matches one of those findings is counted
    // here (finding id -> crashing executions) and reported, never silent.
    let mut duplicates_of_existing = std::collections::BTreeMap::<String, usize>::new();
    // Replay-verify + driver-glue filtering only apply to passthrough C/C++
    // libFuzzer harnesses (the class that crashes in driver glue); the Ada
    // event-log lane validates findings separately via per-spawn replay.
    let detection =
        crate::protocol_detect::detect(prepared.runner.harness_path(), &[&prepared.work_dir]);
    if let Some(note) = libfuzzer_binary_note(&detection, prepared.runner.harness_path()) {
        bhfeprintln!("note: {note}");
    }
    let protocol = detection.protocol;
    let c_libfuzzer_harness = protocol == HarnessProtocol::LibFuzzerSingleInput;
    // `LLVMFuzzerTestOneInput` (and the other hooks a fuzz target defines) is
    // driver code only in a harness bhf generated around a target of its own,
    // or that a lane's glue defines around the project's routine (the Fortran
    // and COBOL lanes, built on the passthrough driver path); in a hand-built
    // libFuzzer binary, or bhf's driver around a project's fuzz entry, a crash
    // or leak in it is the project's.
    let bhf_entry = {
        let mut dirs = crate::replay::harness_source_dirs(
            None,
            &serde_json::Value::Null,
            &prepared.harness_path,
            Some(&detection),
        );
        dirs.extend(crate::auto::layout::harness_dir_candidates(
            &prepared.work_dir,
            &prepared.harness_id,
        ));
        (harness_format_for(
            &prepared.harness_path,
            &prepared.work_dir,
            &prepared.harness_id,
        )
        .is_some()
            && !crate::replay::is_passthrough_harness(&dirs))
            || crate::replay::has_generated_entry(&dirs)
    };
    // #416: crash inputs (this run's, plus any recorded by an earlier pass) are
    // excluded from the persisted corpus so a crashing input is never left in the
    // clean coverage queue. Seeded from the durable findings dir for cross-pass
    // correctness; the C/C++ sanitizer path is the one that can mask a crash on
    // the warm fork-server, so scope the read there (Ada faults surface via the
    // event log and are validated separately).
    let mut crashing_inputs: HashSet<u64> = if c_libfuzzer_harness {
        existing_crash_testcases(&prepared.work_dir, &prepared.harness_id, prepared.max_len)
    } else {
        HashSet::new()
    };
    let mut executions = 0_usize;
    let mut target_entry_observed = false;
    // #15: count inputs the target REJECTED (assert/abort/non-zero return). If
    // EVERY executed input rejected — including the empty seed run first — the
    // harness couldn't actually fuzz (a magic/format gate with no valid seed, or a
    // broken harness), reported as built-not-fuzzed rather than silent success.
    let mut rejected_count = 0_usize;
    // Adaptive length control (libFuzzer `-len_control`): start short and double
    // the effective mutation length toward `--max-len` after a plateau of
    // executions with no new corpus signature. `len_control == 0` disables it.
    let mut effective_max_len = if prepared.len_control == 0 {
        prepared.max_len
    } else {
        INITIAL_LEN_CONTROL_LEN.min(prepared.max_len)
    };
    // Adaptive ceiling: the effective length grows toward `current_ceiling`, which
    // itself only rises past the default (4096) when the target is length-sensitive.
    // Below AUTO_SOFT_CEILING the raise is free (covers most large-object formats);
    // above it, the ceiling rises only while a prior rise produced new coverage, so a
    // small-format target is never grown into huge inputs pointlessly. When
    // `prepared.max_len == DEFAULT_MAX_LEN` (the `fuzz` default and every existing
    // test) this never triggers — behavior is identical to before.
    let mut current_ceiling = if prepared.len_control == 0 {
        prepared.max_len
    } else {
        DEFAULT_MAX_LEN.min(prepared.max_len)
    };
    let mut productive_since_ceiling_raise = false;
    let mut execs_since_new_signature = 0_usize;
    let mut runtrace_cursor = if prepared.runtrace_oracles {
        RuntraceLogCursor::from_extra_env(&prepared.extra_env)
    } else {
        RuntraceLogCursor::none()
    };
    // #422: unified cross-execution byte-origin taint correlation for every
    // taint-confirmed sink oracle (path-open BHF-405, process-exec BHF-431, SSRF
    // BHF-433, library-load BHF-435, SQL BHF-441, destructive-fs BHF-440). Fed each
    // input's events below; queried once after the loop so a fuzz-controlled
    // sink is confirmed exactly once (no per-input flood) and a program constant
    // the dictionary echoed into some inputs is suppressed (no FP).
    let mut sink_taint = crate::auto::runtrace::SinkTaintTracker::default();
    // Persistent execution. The fork-server protocol is spoken by the Ada AdaFuzz
    // runtime AND by the passthrough bhf driver (its BHF_FRAMED loop), so
    // either drives in one long-lived process at fork-server rates; a generated
    // `-fsanitize=fuzzer` C harness does not speak it and stays per-spawn. The
    // ForkServer::spawn handshake is the backstop — it returns Err -> None for
    // anything that doesn't complete the protocol.
    let driver_harness = protocol == HarnessProtocol::BhfFramed;
    let speaks_framed =
        crate::protocol_detect::speaks_framed(prepared.runner.harness_path(), &detection);
    let handshake_timeout =
        fork_handshake_timeout(prepared.per_input_timeout, prepared.time, speaks_framed);
    let mut fork_server = if prepared.fork_server && !c_libfuzzer_harness {
        start_fork_server(&prepared, handshake_timeout, speaks_framed)
    } else {
        None
    };
    let mut forkserver_started = fork_server.is_some();

    // Coverage-guided corpus (#398, #412): a SanitizerCoverage edge bitmap is
    // shared via BHF_COV_SHM by the C/C++ bhf driver (trace-pc-guard) AND,
    // since #412, by an instrumented Ada harness (trace-pc + the AdaFuzz callback).
    // Tracking it lets the engine retain only inputs that grow coverage instead of
    // pushing every exec into the pool, and makes the fuzz_driven pass coverage-
    // guided. `None` for harnesses with no edge runtime (uninstrumented Ada/legacy,
    // generated `-fsanitize=fuzzer` C), whose feedback is the event log / signatures.
    let ada_cov_harness = is_instrumented_ada_harness(&prepared.runner);
    let mut cov_tracker = if driver_harness || ada_cov_harness {
        CoverageTracker::new(&prepared.extra_env)
    } else {
        None
    };

    // RedQueen per-input cmplog capture (#400): on the driver path the harness
    // writes comparison operand pairs to BHF_CMP_SHM. This reader arms
    // capture for the base it is about to mutate and reads the operands back.
    // `None` when the feature is disabled (BHF_DISABLE_REDQUEEN=1, so the env
    // var is absent) or for non-driver harnesses.
    let cmp_reader = if driver_harness {
        CmpShmReader::new(&prepared.extra_env)
    } else {
        None
    };

    // The sanitizer half of the finding path: dedup, replay-verify and emit.
    // Shared by an input's own run and by its fresh-process re-run, which may
    // finish later, in the background (see `crate::fresh_rerun`).
    macro_rules! emit_sanitizer_report {
        ($input:expr, $report:expr, $stderr:expr, $lineage:expr) => {{
            let input: &[u8] = $input;
            let report: &corpus::SanitizerReport = $report;
            let stderr: Option<&str> = $stderr;
            'emit: {
                // The loop's executions do not symbolize (#230): a crash whose
                // signature was reported is counted, and a new one is re-run in
                // a fresh process, symbolized, and that report goes on.
                let symbolized_rerun;
                let (report, stderr) =
                    match in_loop_symbolization.classify(report, stderr, &mut sanitizer_dedup) {
                        InLoopCrash::AsIs => (report, stderr),
                        InLoopCrash::Duplicate => break 'emit,
                        InLoopCrash::Symbolize(signature) => {
                            symbolized_rerun = run_harness_with_protocol(
                                &prepared.runner,
                                &prepared.work_dir,
                                input,
                                &prepared.extra_env,
                                prepared.per_input_timeout,
                                prepared.rss_limit_mb,
                                protocol,
                                prepared.deadline,
                            )
                            .ok()
                            .and_then(|rerun| Some((rerun.sanitizer?, rerun.stderr)));
                            match &symbolized_rerun {
                                Some((fresh, fresh_stderr)) => {
                                    in_loop_symbolization
                                        .symbolized(signature, sanitizer_dedup.key(fresh));
                                    (fresh, fresh_stderr.as_deref())
                                }
                                None => {
                                    sanitizer_dedup.unconfirmed(signature);
                                    non_reproducible += 1;
                                    break 'emit;
                                }
                            }
                        }
                    };
                // (#49) An LSan leak whose entire allocation stack is bhf's own
                // decode/harness scaffolding (no target frame) is the decoder buffer the
                // harness would have freed — left dangling only because an exit()/abort()-
                // only target terminated before the harness free(). bhf manufactured
                // it, so SUPPRESS it (don't emit/count a phantom CWE-401).
                if corpus::cluster::is_harness_scaffolding_leak(report, bhf_entry) {
                    scaffolding_leak_drops += 1;
                }
                // (#388) A crash entirely in libFuzzer/sanitizer/allocator driver
                // glue with no target frame is a harness fault, not a target bug.
                else if c_libfuzzer_harness
                    && corpus::cluster::is_driver_glue_crash(report, bhf_entry)
                {
                    driver_glue_drops += 1;
                } else if let Some(key) = sanitizer_dedup.first_sighting(report) {
                    // First sighting of this cluster (#389 dedups the rest). For a
                    // passthrough libFuzzer harness, replay-verify before emitting
                    // (#388): re-run in a fresh process and drop non-reproducing
                    // faults (allocator-state corruption across inputs). The key is
                    // consumed only once the finding is emitted, so a first hit that
                    // does not reproduce does not hide a later one that does.
                    // A response-deadline overrun is a finding when most of
                    // its fresh re-runs overrun the deadline too (#209).
                    let deadline_check = prepared
                        .deadline
                        .filter(|_| report.rule_id == RESPONSE_DEADLINE_RULE)
                        .map(|deadline| {
                            confirm_deadline(
                                &prepared.runner,
                                &prepared.work_dir,
                                input,
                                &prepared.extra_env,
                                prepared.per_input_timeout,
                                prepared.rss_limit_mb,
                                deadline,
                                pass_deadline,
                            )
                        });
                    let confirmed = match &deadline_check {
                        Some(check) => check.confirmed(),
                        // A hang report comes from its own fresh-process
                        // re-run (`confirm_hang`).
                        None => {
                            !c_libfuzzer_harness
                                || report.rule_id == HANG_RULE
                                || sanitizer_crash_reproduces(
                                    &prepared.runner,
                                    &prepared.work_dir,
                                    input,
                                    report,
                                    &prepared.extra_env,
                                    prepared.per_input_timeout,
                                    prepared.rss_limit_mb,
                                    prepared.deadline,
                                )
                        }
                    };
                    if let Some(check) = deadline_check.as_ref().filter(|check| !check.confirmed())
                    {
                        bhfeprintln!(
                            "bhf fuzz: note: an input {}, but {}: not a finding",
                            deadline_overrun_of(report),
                            check.describe()
                        );
                    }
                    if confirmed {
                        // UBSan's object-size check reports an overflow ASan
                        // would have reported first: emit ASan's report then.
                        // Asked once per root cause: the key is consumed below.
                        let opinion = object_size_second_opinion(
                            &prepared.work_dir,
                            report,
                            &prepared.extra_env,
                            prepared.per_input_timeout,
                            pass_deadline,
                            |env, timeout| {
                                // No response deadline: the re-run asks only what
                                // ASan reports.
                                run_c_libfuzzer_single_input(
                                    &prepared.runner,
                                    &prepared.work_dir,
                                    input,
                                    env,
                                    timeout,
                                    prepared.rss_limit_mb,
                                    None,
                                )
                                .map(|rerun| (rerun.sanitizer, rerun.stderr))
                            },
                        );
                        let (report, stderr) = match opinion.as_ref().and_then(|o| o.asan.as_ref())
                        {
                            Some((view, stderr)) => (view, stderr.as_deref()),
                            None => (report, stderr),
                        };
                        if opinion.as_ref().is_some_and(|o| o.asan.is_some()) {
                            match sanitizer_dedup.first_sighting(report) {
                                Some(view_key) => sanitizer_dedup.consumed(view_key),
                                None => {
                                    // That ASan report is a finding already.
                                    sanitizer_dedup.consumed(key);
                                    note_duplicate_of_existing(
                                        &mut duplicates_of_existing,
                                        existing_findings
                                            .clusters
                                            .get(&sanitizer_dedup.key(report)),
                                    );
                                    // Out of this block only: the caller still
                                    // keeps the input out of the corpus.
                                    break 'emit;
                                }
                            }
                        }
                        // A .NET report names its source lines from the
                        // uninstrumented build (#212).
                        let symbolized = dotnet_symbolized_report(
                            &prepared.runner,
                            &prepared.work_dir,
                            input,
                            report,
                            &prepared.extra_env,
                            prepared.per_input_timeout,
                            prepared.rss_limit_mb,
                        );
                        let (report, stderr) = match &symbolized {
                            Some((report, stderr)) => (report, Some(stderr.as_str())),
                            None => (report, stderr),
                        };
                        let id = emitter
                            .emit_sanitizer_crash_with_log(input, report, stderr.map(str::as_bytes))
                            .map_err(|error| format!("emit sanitizer finding: {error}"))?;
                        if report.rule_id == "BHF-209" && prepared.rss_limit_mb > 0 {
                            record_rss_limit(&prepared.work_dir, &id.0, prepared.rss_limit_mb);
                        }
                        if let Some(check) = &deadline_check {
                            announce_deadline_finding(&format!(
                                "{}, and {}",
                                deadline_overrun_of(report),
                                check.describe()
                            ));
                            check.record(&prepared.work_dir, &id.0);
                        }
                        if let Some(opinion) = &opinion {
                            opinion.record(&prepared.work_dir, &id.0, &key);
                        }
                        let descent = $lineage;
                        crate::fuzz_lineage::record(&prepared.work_dir, &id.0, &descent);
                        sanitizer_dedup.consumed(key);
                        record_finding_arguments(
                            &prepared.work_dir,
                            &id.0,
                            prepared.runner.harness_path(),
                            input,
                            TraceInput::ArgvFile,
                            &prepared.extra_env,
                            prepared.per_input_timeout,
                            prepared.runner.qemu_prefix(),
                        );
                        finding_ids.push(id.0);
                    } else {
                        sanitizer_dedup.unconfirmed(key);
                        non_reproducible += 1;
                    }
                } else {
                    // A hit of a root cause pre-seeded from an on-disk finding is
                    // reported against that finding's id.
                    note_duplicate_of_existing(
                        &mut duplicates_of_existing,
                        existing_findings.clusters.get(&sanitizer_dedup.key(report)),
                    );
                }
            }
        }};
    }
    // #416 AC2 fresh-process re-runs of new corpus inputs, run in the
    // background. An input reaches the saved queue only once its re-run has
    // come back clean; one still unchecked when the pass ends is kept in
    // `corpus/<harness>/unchecked/` instead. Inputs a previous pass left there
    // go first: a clean one joins the queue, a crashing one is reported.
    let mut fresh_reruns: Option<FreshReruns<FreshRerunResult>> = None;
    let mut fresh_rerun_summary = FreshRerunSummary::default();
    let unchecked_dir = corpus::manager::unchecked_dir(&prepared.work_dir, &prepared.harness_id);
    let carried_over = if driver_harness && fork_server.is_some() {
        read_unchecked_inputs(&unchecked_dir)
    } else {
        Vec::new()
    };
    // The files of the carried-over inputs not settled yet, by input.
    let mut carried_over_files: HashMap<u64, PathBuf> = carried_over
        .iter()
        .map(|(path, input)| (crash_input_key(input), path.clone()))
        .collect();
    // Re-run results waiting to be taken in at the end of an iteration.
    let mut arrived: Vec<crate::fresh_rerun::Checked<FreshRerunResult>> = Vec::new();
    // The inputs this pass has sent for a re-run, by key. An input whose
    // coverage varies from run to run can make progress twice: its second
    // re-run would only repeat the first, and the pass would count it twice.
    let mut sent_for_rerun: HashSet<u64> = HashSet::new();
    // Inputs this pass leaves unchecked: still running when it ended, cut
    // short by its end, or held back once the finding cap was reached.
    let mut unchecked_inputs: Vec<Vec<u8>> = Vec::new();
    macro_rules! finding_cap_reached {
        () => {
            prepared
                .stop_after_findings
                .is_some_and(|cap| finding_ids.len() >= cap)
        };
    }
    macro_rules! adopt_fresh_reruns {
        ($checked:expr) => {
            for checked in $checked {
                let crate::fresh_rerun::Checked {
                    input,
                    result,
                    placement,
                } = checked;
                let mut fresh = result?;
                // A deadline report from a re-run that ran at a lower priority
                // beside the loop may only say it waited for a CPU: confirm it
                // with a re-run at the loop's own priority first.
                if placement == Placement::Background
                    && fresh
                        .as_ref()
                        .and_then(|run| run.sanitizer.as_ref())
                        .is_some_and(|report| report.rule_id == RESPONSE_DEADLINE_RULE)
                {
                    if let Some(reruns) = fresh_reruns.as_ref() {
                        let overrun = fresh
                            .as_ref()
                            .and_then(|run| run.sanitizer.as_ref())
                            .map(|report| deadline_overrun_of(report).to_owned())
                            .unwrap_or_default();
                        fresh = reruns.run_inline(&input)?;
                        if fresh.as_ref().is_some_and(|run| run.sanitizer.is_none()) {
                            bhfeprintln!(
                                "bhf fuzz: note: an input's background fresh-process re-run \
                                 {overrun}, but met it when re-run at normal priority: not a \
                                 finding"
                            );
                        }
                    }
                }
                let Some(fresh) = fresh else {
                    unchecked_inputs.push(input);
                    continue;
                };
                let key = crash_input_key(&input);
                match &fresh.sanitizer {
                    None => {
                        fresh_rerun_summary.checked += 1;
                        if carried_over_files.contains_key(&key) {
                            let _ = corpus
                                .persist_coverage_corpus(&prepared.harness_id, [input.as_slice()]);
                        }
                    }
                    // Held back once the run has its findings: never queued,
                    // reported by the next pass.
                    Some(_) if finding_cap_reached!() => {
                        unchecked_inputs.push(input);
                        continue;
                    }
                    Some(report) => {
                        fresh_rerun_summary.checked += 1;
                        fresh_rerun_summary.reports += 1;
                        emit_sanitizer_report!(
                            &input,
                            report,
                            fresh.stderr.as_deref(),
                            lineage.of_bytes(&input)
                        );
                        if crashing_inputs.len() < finding_dedup_limit {
                            crashing_inputs.insert(key);
                        }
                        retire_from_pool(&mut pool, &input);
                        forget_queued_input(&prepared.work_dir, &prepared.harness_id, &input);
                    }
                }
                if let Some(path) = carried_over_files.remove(&key) {
                    let _ = fs::remove_file(path);
                }
            }
        };
    }
    if !carried_over.is_empty() {
        let reruns =
            fresh_reruns.get_or_insert_with(|| start_fresh_reruns(&prepared, pass_deadline));
        for (_, input) in carried_over {
            if sent_for_rerun.insert(crash_input_key(&input)) {
                arrived.extend(reruns.submit(input));
            }
        }
        adopt_fresh_reruns!(std::mem::take(&mut arrived));
    }
    // In this last part of the pass, the loop stops early enough for the
    // outstanding re-runs to finish inside `--time`.
    let drain_window = prepared.time.map(fresh_rerun_drain_window);
    // The empty input always runs in a fresh process (an empty frame ends the
    // framed loop in some drivers). Run it once per pass and reuse the result.
    let mut empty_input_run: Option<HarnessRun> = None;
    // #314, #373, #374: an extension's mutation, codec and lifecycle stages,
    // set up before the first case (a failed setup stops the pass).
    let mut extension_stage = match prepared.extension_manifest.as_deref() {
        Some(manifest) => {
            let root = prepared
                .work_dir
                .join("fuzz_scratch")
                .join(format!("extension-{}", prepared.harness_id));
            fs::create_dir_all(&root)
                .map_err(|error| format!("create {}: {error}", root.display()))?;
            extension_stage::ExtensionStage::open(
                manifest,
                &prepared.harness_id,
                &root,
                prepared.time,
            )?
        }
        None => None,
    };
    for iteration in 0..prepared.iterations {
        if prepared
            .time
            .is_some_and(|budget| start.elapsed() >= budget)
        {
            break;
        }
        // Near the end, stop issuing inputs once the re-runs still out need
        // the time that is left.
        if let (Some(deadline), Some(window), Some(reruns)) =
            (pass_deadline, drain_window, fresh_reruns.as_ref())
        {
            let left = deadline.saturating_duration_since(Instant::now());
            if left <= window && left <= reruns.drain_estimate(prepared.per_input_timeout) {
                break;
            }
        }

        let mut parents = crate::fuzz_lineage::InputParents::Queued(iteration);
        // The derivation tree of a grammar-made child (#329).
        let mut input_tree = None;
        // A peer's entry runs as it is, once the seeds have run.
        let imported = match peer_sync.as_mut() {
            Some(sync) if iteration >= initial_seed_count => {
                sync.tick(
                    pool.iter()
                        .map(|entry| (entry.bytes.as_slice(), entry.retired)),
                );
                sync.next_import()
            }
            _ => None,
        };
        // Then an input SymCC solved, once the seeds have run.
        let imported = imported.or_else(|| match symcc_stage.as_mut() {
            Some(stage) if iteration >= initial_seed_count => {
                stage.tick(
                    Instant::now(),
                    pool.len(),
                    |index| (pool[index].bytes.as_slice(), pool[index].retired),
                    pass_deadline,
                );
                stage.next_import()
            }
            _ => None,
        });
        let input = if let Some(imported) = imported {
            parents = crate::fuzz_lineage::InputParents::Generated;
            imported
        } else if iteration < initial_seed_count {
            pool[iteration].bytes.clone()
        } else {
            // #382: pick a base weighted by coverage energy / under-exploration.
            let base_index = choose_entropic_index_pool(&pool, &mut rng);
            if let Some(entry) = pool.get_mut(base_index) {
                entry.selections = entry.selections.saturating_add(1);
            }
            // #400 RedQueen: the first time a base is mutated, colorize it (so its
            // operands splice at the right offset), run it once with cmplog capture
            // armed, and cache the operand pairs + colorized base. The mutator then
            // biases this base's children toward CmpLogSplice, injecting the
            // captured value at the offset it was compared. Paid once per base.
            if let (Some(reader), Some(fork)) = (cmp_reader.as_ref(), fork_server.as_mut()) {
                if pool
                    .get(base_index)
                    .is_some_and(|e| e.cmplog.is_none() && !e.bytes.is_empty())
                {
                    let base_bytes = pool[base_index].bytes.clone();
                    let colored = match cov_tracker.as_mut() {
                        Some(cov) => colorize_base(cov, fork, &base_bytes, &mut rng, pass_deadline),
                        None => base_bytes,
                    };
                    let log = if pass_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                        cmplog::CmpLog::default()
                    } else {
                        let mut log = capture_cmplog(reader, fork, &colored);
                        log.retain_spliceable(&colored);
                        log
                    };
                    if let Some(entry) = pool.get_mut(base_index) {
                        entry.cmplog = Some(log);
                        entry.colored = Some(colored);
                    }
                }
            }
            if let (Some(layout), Some(entry)) = (arg_layout.as_ref(), pool.get_mut(base_index)) {
                if entry.typed_spans.is_none() {
                    entry.typed_spans = Some(typed_spans::arg_layout_typed_spans(
                        layout,
                        entry.mutation_base(),
                    ));
                }
            }
            // One child in four is an extension stage's, when the extension
            // has one (#314, #373).
            let from_extension = extension_stage.as_mut().and_then(|stage| {
                let base = pool.get(base_index).map(PoolEntry::mutation_base)?;
                stage.child(base, &mut rng)
            });
            if let Some(bytes) = from_extension {
                parents = crate::fuzz_lineage::InputParents::Mutated {
                    base: base_index,
                    donor: None,
                };
                bytes
            } else if let Some(codec) = frame.as_ref() {
                let base = pool
                    .get(base_index)
                    .map(|entry| entry.bytes.clone())
                    .unwrap_or_default();
                let mut made_from = None;
                let (bytes, field_edit) =
                    frame_child(codec, &base, effective_max_len, &mut rng, |rng| {
                        let (bytes, parents, tree) = mutate_from_pool(
                            &pool,
                            base_index,
                            &dictionary,
                            cmplog_log.as_ref(),
                            grammar.as_ref(),
                            mutator_config(prepared.structured_inputs, effective_max_len),
                            sequence_geometry,
                            rng,
                        );
                        made_from = Some((parents, tree));
                        bytes
                    });
                parents = match made_from {
                    Some((made_from, tree)) if !field_edit => {
                        input_tree = tree;
                        made_from
                    }
                    _ => crate::fuzz_lineage::InputParents::Mutated {
                        base: base_index,
                        donor: None,
                    },
                };
                bytes
            } else {
                let (bytes, made_from, tree) = mutate_from_pool(
                    &pool,
                    base_index,
                    &dictionary,
                    cmplog_log.as_ref(),
                    grammar.as_ref(),
                    mutator_config(prepared.structured_inputs, effective_max_len),
                    sequence_geometry,
                    &mut rng,
                );
                parents = made_from;
                input_tree = tree;
                bytes
            }
        };
        // `--frame`: an input from another worker or an extension stage is
        // repaired too (a frame comes back unchanged).
        let input = match frame.as_ref() {
            Some(codec) => codec.repair(&input),
            None => input,
        };
        // RedQueen colorization can execute up to 65 probes before the main
        // input. Slow interpreted targets used to multiply a one-second pass
        // into more than a minute inside that setup work. Do not start another
        // execution after setup has consumed the pass budget.
        if pass_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            break;
        }
        let portfolio_lane = sequence_geometry.and_then(|geometry| geometry.portfolio_lane(&input));
        // Empty inputs end the harness loop (an empty frame is the degenerate
        // "no input"), so they always go through the per-spawn path; everything
        // else uses the persistent fork-server when enabled, falling back to a
        // per-spawn run (and respawning the server) on a hard crash.
        // #374: the extension's `lifecycle.reset` between cases; a failed
        // reset stops the campaign.
        if let Some(stage) = extension_stage.as_mut() {
            stage.before_case()?;
        }
        // #420: zero the per-exec hit-count map so THIS exec's edge hit counts
        // are recorded in isolation, then read back via `input_grew_buckets()`
        // after the exec. Placed AFTER #400 colorization / cmplog capture (which
        // run their own probe execs and dirty the count map) and before BOTH the
        // fork-server and per-spawn main-exec paths below. No-op when there is no
        // count map (Ada/legacy targets). The harness only ever increments it, so
        // the post-exec read sees exactly this input's per-edge loop counts.
        if let Some(cov) = cov_tracker.as_ref() {
            cov.zero_counts();
            // #421: likewise zero the comparison-progress map so THIS exec's
            // per-site leading-byte-match is recorded in isolation (the harness
            // only ever `max`-raises it). No-op when the progress map is absent.
            cov.zero_progress();
            // #220: and the stack-depth word.
            cov.zero_stack();
        }
        // Whether this run came from the persistent fork-server (vs a fresh
        // per-spawn process). Fork-server findings are replay-validated below so
        // an artifact of accumulated global state never escapes as a finding.
        let mut from_fork_server = false;
        let mut run = if !input.is_empty() && fork_server.is_some() {
            match fork_server
                .as_mut()
                .expect("fork_server checked is_some")
                .run_one(&input)
            {
                ForkOutcome::Ran(run) => {
                    from_fork_server = true;
                    *run
                }
                ForkOutcome::Died => {
                    // Drop (kill/reap) the dead server, isolate the crash via the
                    // proven per-spawn path, then respawn for subsequent inputs.
                    drop(fork_server.take());
                    let run = run_harness_with_protocol(
                        &prepared.runner,
                        &prepared.work_dir,
                        &input,
                        &prepared.loop_env,
                        prepared.per_input_timeout,
                        prepared.rss_limit_mb,
                        protocol,
                        prepared.deadline,
                    )?;
                    // Never wait past the end of the pass for the new server.
                    let left = pass_deadline
                        .map_or(handshake_timeout, |deadline| {
                            deadline.saturating_duration_since(Instant::now())
                        })
                        .min(handshake_timeout);
                    fork_server = if left.is_zero() {
                        None
                    } else {
                        start_fork_server(
                            &prepared,
                            left,
                            speaks_framed && left == handshake_timeout,
                        )
                    };
                    forkserver_started |= fork_server.is_some();
                    run
                }
            }
        } else if let (true, Some(cached)) = (input.is_empty(), &empty_input_run) {
            cached.clone()
        } else {
            let run = run_harness_with_protocol(
                &prepared.runner,
                &prepared.work_dir,
                &input,
                &prepared.loop_env,
                prepared.per_input_timeout,
                prepared.rss_limit_mb,
                protocol,
                prepared.deadline,
            )?;
            if input.is_empty() {
                empty_input_run = Some(run.clone());
            }
            run
        };
        executions += 1;
        // An execution killed at the per-input timeout is a hang finding once
        // a fresh process with twice the timeout hangs on it too (#207).
        if run.hung.is_some() && run.sanitizer.is_none() {
            hangs.observed += 1;
            let confirmation = if hangs.confirmed + hangs.cleared >= MAX_HANG_CONFIRMATIONS {
                HangConfirmation::NotRerun
            } else {
                confirm_hang(
                    &prepared.runner,
                    &prepared.work_dir,
                    &input,
                    &prepared.extra_env,
                    prepared.per_input_timeout,
                    prepared.rss_limit_mb,
                    pass_deadline,
                )?
            };
            match confirmation {
                HangConfirmation::Hung(report, stderr) => {
                    hangs.confirmed += 1;
                    run.sanitizer = Some(*report);
                    run.stderr = Some(stderr);
                }
                HangConfirmation::Crashed(report, stderr) => {
                    hangs.cleared += 1;
                    run.sanitizer = Some(*report);
                    run.stderr = Some(stderr);
                }
                HangConfirmation::Finished => {
                    hangs.cleared += 1;
                    bhfeprintln!(
                        "bhf fuzz: note: an input ran past the {} per-input timeout but \
                         finished when re-run with {}: a slow execution, not a hang",
                        duration_arg(prepared.per_input_timeout),
                        duration_arg(prepared.per_input_timeout.saturating_mul(2))
                    );
                }
                HangConfirmation::NotRerun => hangs.not_rerun += 1,
            }
        }
        target_entry_observed |= run.testcases.iter().any(|testcase| testcase.target_entered);
        if run.rejected {
            rejected_count += 1;
        }
        // Did this input grow edge coverage (#398 presence) OR push an edge into a
        // new AFL hit-count bucket (#420 loop/recursion depth) OR match more leading
        // bytes of some compare than any prior input (#421 laf-intel gradient)?
        // (driver path only.) All THREE are read exactly once per main exec since
        // the tracker is stateful; call all unconditionally (no `||` short-circuit)
        // so every virgin map is folded even when an earlier channel didn't grow.
        // The three channels are OR'd into the same progress signal, so a
        // comparison-progress advance retains the input in the corpus and feeds the
        // scheduler (`input_energy`) exactly like edge novelty does.
        let input_novelty = cov_tracker
            .as_mut()
            .map(|t| {
                let new_edges = t.input_increased_coverage();
                let new_buckets = t.input_grew_buckets();
                let comparison_advances = t.input_advanced_comparisons();
                let deeper_stack = t.input_deepened_stack();
                CoverageNovelty {
                    new_edges,
                    new_buckets,
                    comparison_advances,
                    deeper_stack,
                }
            })
            .unwrap_or_default();
        let input_new_coverage = input_novelty.made_progress();
        // Fold newly-mined value-profile operands into the dictionary every 2048
        // execs so the mutator can splice magic bytes it just observed (#398).
        if let Some(vp) = &vp_path {
            if executions.is_multiple_of(2048) {
                let mut added = false;
                for token in read_vp_tokens(vp) {
                    if dictionary_token_set.insert(token.clone()) {
                        dictionary_tokens.push(token);
                        added = true;
                    }
                }
                if added {
                    dictionary = Dictionary::from_tokens(dictionary_tokens.clone());
                }
            }
        }
        let runtrace_events = runtrace_cursor.read_new_events();
        // #422: record this execution's sink taint for end-of-run correlation
        // (before the finding loop drains anything) across all sink classes.
        sink_taint.observe(&runtrace_events, &input);
        if let Some(tick) = progress {
            if last_tick.elapsed() >= Duration::from_millis(500) {
                tick(&FuzzTick {
                    executions,
                    findings: finding_ids.len(),
                    edges: cov_tracker.as_ref().map_or(0, |cov| cov.count()),
                    corpus: pool.len(),
                    elapsed: start.elapsed(),
                    stability_pct: calibration.stability_pct(),
                });
                last_tick = Instant::now();
            }
        }

        let records = corpus
            .record(&prepared.harness_id, &input, &run.events)
            .map_err(|error| format!("record corpus entry: {error}"))?;
        let mut new_signatures = HashSet::<Signature>::new();
        for record in records {
            match record.class {
                SignatureClass::New => {
                    corpus_new += 1;
                    new_signatures.insert(record.signature);
                }
                SignatureClass::Duplicate => corpus_duplicates += 1,
            }
        }
        // Edge-coverage growth is a corpus-progress signal (#398, #412): count it
        // as a new corpus entry. The C/C++ driver path produces no event
        // signatures, but an instrumented Ada harness produces both, so only count
        // coverage growth when it wasn't already counted as a new signature — one
        // retained pool entry, one increment.
        if input_new_coverage && new_signatures.is_empty() {
            corpus_new += 1;
        }
        let made_progress = !new_signatures.is_empty() || input_new_coverage;
        // #416: a persistent fork-server `Ran` cannot observe a fault that the warm
        // process masks but a fresh process aborts on — a crash gated on per-process
        // state (lazy-init globals, allocator / container-annotation state: the
        // jsoncpp container-overflow class). The server's stderr is discarded, so
        // such an input returns `Ran` with no sanitizer report and would otherwise be
        // coverage-credited and corpus-enqueued with no finding at all (the engine
        // silently misses a real memory-safety bug). Every input we are about to
        // ENQUEUE — it grew coverage, so it is the rare, worth-saving input — is
        // re-run once in a fresh per-spawn process here, so a crashing input is never
        // enqueued-without-a-finding (#416 AC2). Bounded by edge count (coverage is
        // monotonic), so this adds ~corpus-many extra spawns over a whole run, like
        // AFL++ calibrating each new corpus entry; the captured report flows into the
        // dedup / replay-verify emission path below exactly like a per-spawn crash.
        // The re-run goes to a background worker (`crate::fresh_rerun`): a fresh
        // process costs seconds on a loaded host, and waiting for it here used
        // to stall the loop on every new corpus entry. Its report, when it
        // arrives, takes the same finding path and retires the input from the
        // pool. Until a clean result arrives the input is only a mutation base:
        // the queue saved at the end of the pass leaves it out, and one still
        // unchecked then is kept in `corpus/<harness>/unchecked/` for the next
        // pass. Where it runs, and at what priority: `fresh_rerun_placement`.
        if from_fork_server
            && made_progress
            && driver_harness
            && run.sanitizer.is_none()
            && !input.is_empty()
            && sent_for_rerun.insert(crash_input_key(&input))
        {
            let reruns =
                fresh_reruns.get_or_insert_with(|| start_fresh_reruns(&prepared, pass_deadline));
            arrived.extend(reruns.submit(input.clone()));
        } else if let Some(reruns) = fresh_reruns.as_mut() {
            arrived.extend(reruns.take_checked());
        }
        // #382: this input's coverage novelty — new corpus signatures plus (on the
        // driver path) new edge coverage — is its scheduling energy, captured here
        // before the finding loop drains the set. Rare-coverage seeds get more
        // mutation energy.
        let input_energy = input_novelty
            .scheduling_energy()
            .saturating_add((new_signatures.len() as u32).saturating_mul(16))
            .clamp(1, 4096);
        if let Some(lane) = portfolio_lane.and_then(|lane| {
            portfolio_feedback
                .as_mut()
                .and_then(|stats| stats.get_mut(lane))
        }) {
            lane.executions = lane.executions.saturating_add(1);
            lane.new_edges = lane.new_edges.saturating_add(input_novelty.new_edges);
            lane.new_buckets = lane.new_buckets.saturating_add(input_novelty.new_buckets);
            lane.comparison_advances = lane
                .comparison_advances
                .saturating_add(input_novelty.comparison_advances);
            lane.scheduling_energy_awarded = lane
                .scheduling_energy_awarded
                .saturating_add(u64::from(input_energy));
        }

        // New coverage found while fuzzing in the EXTENDED zone (past the default cap)
        // proves this target is length-sensitive, so the last ceiling raise paid off.
        if made_progress && effective_max_len > DEFAULT_MAX_LEN {
            productive_since_ceiling_raise = true;
        }
        // Length control: progress (a new signature or new edge coverage) resets the
        // plateau; otherwise, after `len_control` flat executions, double the effective
        // length toward the current ceiling.
        (effective_max_len, execs_since_new_signature) = len_control_step(
            effective_max_len,
            current_ceiling,
            prepared.len_control,
            execs_since_new_signature,
            made_progress,
        );
        // Adaptive ceiling: stuck at the current ceiling with room below the hard cap.
        // Raise it when still in the free zone (below AUTO_SOFT_CEILING) or when the
        // last raise produced new coverage; otherwise stay capped — the target does not
        // benefit from longer inputs.
        if prepared.len_control != 0
            && effective_max_len >= current_ceiling
            && current_ceiling < prepared.max_len
            && execs_since_new_signature >= prepared.len_control
            && (current_ceiling < AUTO_SOFT_CEILING.min(prepared.max_len)
                || productive_since_ceiling_raise)
        {
            current_ceiling = current_ceiling.saturating_mul(2).min(prepared.max_len);
            effective_max_len = current_ceiling;
            productive_since_ceiling_raise = false;
            execs_since_new_signature = 0; // fresh plateau window at the larger length
        }

        for testcase in &run.testcases {
            // Emit a finding for every classified event with a fresh signature.
            // This includes UNHANDLED_HANDLER_INDEX — an exception that escaped
            // the target to the harness top level (a real fault) — which was
            // previously dropped here, hiding genuine crashes while reporting
            // exceptions the target caught itself. `resolve_handler` yields a
            // synthetic handler for that case so it signatures like any other.
            for (handler_index, classification) in classify(testcase) {
                let Some(handler) = resolve_handler(testcase, handler_index) else {
                    continue;
                };
                // A target rejecting malformed input via its OWN declared exception
                // (e.g. XML/Ada's `XML_Fatal_Error`, caught by the harness or escaped
                // uncaught) is intended handling, not a defect — `finding_tier` marks
                // it `IntendedRejection`. Emitting one floods the findings list with a
                // false positive on every malformed input. Skip it: only real faults
                // (uncaught predefined checks) and swallowed predefined checks
                // (potential masked memory-safety bugs) are worth a finding.
                if finding_tier(classification, &handler.as_ref().exception_name)
                    == FindingTier::IntendedRejection
                {
                    continue;
                }
                // Force-fuzz: a `raise` from a synthesized offline-unbuildable stub
                // body (a placeholder, not the real code) carries a marker message.
                // The target merely reached the stub — not a genuine defect — so it
                // must not be reported as a finding.
                if handler
                    .as_ref()
                    .exception_message
                    .contains(crate::auto::ada_body_stub::STUB_RAISE_MARKER)
                {
                    continue;
                }
                let signature = compute_signature(testcase, handler.as_ref());
                if new_signatures.remove(&signature) {
                    // Safety net for the persistent fork-server: a fault could be
                    // an artifact of global state accumulated across prior inputs
                    // and so not reproduce from this testcase alone (the canonical
                    // replay). Re-run the input in a fresh process and only emit
                    // findings that reproduce, keeping every finding actionable.
                    if from_fork_server
                        && !finding_reproduces_per_spawn(&prepared, &input, &signature)?
                    {
                        non_reproducible += 1;
                        continue;
                    }
                    let id = emitter
                        .emit(&input, testcase, handler_index)
                        .map_err(|error| format!("emit finding: {error}"))?;
                    let descent = lineage.of(&input, parents);
                    crate::fuzz_lineage::record(&prepared.work_dir, &id.0, &descent);
                    finding_ids.push(id.0);
                } else {
                    note_duplicate_of_existing(
                        &mut duplicates_of_existing,
                        existing_findings.signatures.get(&signature.hex()),
                    );
                }
            }
        }

        if let Some(report) = &run.sanitizer {
            emit_sanitizer_report!(
                &input,
                report,
                run.stderr.as_deref(),
                lineage.of(&input, parents)
            );
        }

        for hit in crate::auto::runtrace::oracle_hits_for_harness(
            &runtrace_events,
            interpreted_lane,
            &harness_language,
        ) {
            let key = oracle_hit_dedupe_key(&hit);
            if !seen_oracle_hits.insert(key.clone()) {
                note_duplicate_of_existing(
                    &mut duplicates_of_existing,
                    existing_findings.oracles.get(&key),
                );
                continue;
            }
            let id = emitter
                .emit_oracle_hit(&input, &hit)
                .map_err(|error| format!("emit oracle finding: {error}"))?;
            let descent = lineage.of(&input, parents);
            crate::fuzz_lineage::record(&prepared.work_dir, &id.0, &descent);
            finding_ids.push(id.0);
        }

        // Corpus retention (#398, #412). Keep only inputs that made progress —
        // a fresh corpus signature or new edge coverage (`made_progress`, the same
        // signal that incremented `corpus_new` above) — and hard-cap the pool at
        // the derived corpus entry budget. It is the backstop for any path where coverage
        // feedback is absent or reads zero (uninstrumented Ada/legacy targets):
        // without it the gate degenerated to "keep every non-empty input" and the
        // end-of-run flush wrote ~every executed input to disk (#412: 402k files /
        // 1.6 GB). Seeds are pre-loaded into `pool` and never removed, so the seed
        // corpus is always retained regardless of this gate.
        //
        // #416: an input that produced a sanitizer crash is saved as a finding
        // testcase, never enqueued into the (clean) coverage corpus — it must not
        // sit in the queue as if it were a benign coverage seed, and mutating a
        // known crasher as a base is wasted energy. Record it so the end-of-run
        // persist also drops it when it entered the pool as a pre-loaded seed
        // (seeds bypass this `keep` gate). This is the retention half of "a
        // crashing input is never enqueued-without-a-finding": it is emitted as a
        // finding above and excluded from the corpus here.
        if run.sanitizer.is_some() && crashing_inputs.len() < finding_dedup_limit {
            crashing_inputs.insert(crash_input_key(&input));
        }
        let mut keep = made_progress
            && run.sanitizer.is_none()
            && pool.len() < corpus_limits.entries
            && pool_bytes.saturating_add(input.len()) <= corpus_limits.bytes;
        // #232: re-run an input the persistent process would enqueue, each
        // run from a zeroed edge bitmap, and leave it out when its new
        // coverage was only edges that vary from run to run (state the target
        // kept from earlier inputs). The bitmap is put back with the re-runs'
        // edges added, without crediting any input, so a state-dependent edge
        // they reach is not new coverage later.
        if let (true, true, Some(cov), Some(fork)) = (
            keep && !input.is_empty(),
            input_new_coverage && from_fork_server,
            cov_tracker.as_mut(),
            fork_server.as_mut(),
        ) {
            let mut seen = cov.snapshot();
            let mut runs = Vec::with_capacity(CALIBRATION_RERUNS);
            for _ in 0..CALIBRATION_RERUNS {
                cov.zero();
                cov.zero_counts();
                cov.zero_progress();
                cov.zero_stack();
                let _ = fork.run_one(&input);
                let hit = cov.snapshot();
                runs.push(
                    hit.iter()
                        .enumerate()
                        .filter(|(_, byte)| **byte != 0)
                        .map(|(edge, _)| edge as u32)
                        .collect::<Vec<u32>>(),
                );
                for (into, byte) in seen.iter_mut().zip(&hit) {
                    *into |= *byte;
                }
            }
            cov.restore(&seen);
            cov.absorb_coverage();
            let steady = calibration.calibrate(&runs);
            let other_progress = !new_signatures.is_empty()
                || input_novelty.comparison_advances > 0
                || input_novelty.deeper_stack > 0;
            if !steady && !other_progress {
                keep = false;
                corpus_new = corpus_new.saturating_sub(1);
            }
        }
        if !input.is_empty() && keep {
            if let Some(lane) = portfolio_lane.and_then(|lane| {
                portfolio_feedback
                    .as_mut()
                    .and_then(|stats| stats.get_mut(lane))
            }) {
                lane.retained_inputs = lane.retained_inputs.saturating_add(1);
            }
            lineage.retain(&input, parents);
            if let Some(dir) = live_corpus_dir.as_deref() {
                write_live_corpus_entry(dir, &input);
            }
            pool_bytes = pool_bytes.saturating_add(input.len());
            // The tree is kept while it still derives the input (a `--frame`
            // repair may have changed it) and fits the pool's byte budget.
            let tree = input_tree.take().filter(|tree| {
                grammar.as_ref().is_some_and(|g| g.sentence(tree) == input)
                    && pool_bytes.saturating_add(tree.footprint()) <= corpus_limits.bytes
            });
            pool_bytes = pool_bytes.saturating_add(tree.as_ref().map_or(0, |t| t.footprint()));
            pool.push(PoolEntry {
                bytes: input,
                energy: input_energy,
                selections: 0,
                cmplog: None,
                colored: None,
                typed_spans: None,
                retired: false,
                tree,
            });
        }

        // The re-run results that came in during this iteration, after its own
        // findings, so the cap below holds for them too.
        adopt_fresh_reruns!(std::mem::take(&mut arrived));

        // Per-target finding cap (`auto --per-target-finding-count`): stop this
        // run the instant it has emitted the requested number of DISTINCT findings
        // (`finding_ids` is signature/cluster-deduped above) so the cascade can
        // move on. The caller passes the count REMAINING for this pass; `None`
        // (default) never breaks early.
        if finding_cap_reached!() {
            break;
        }
    }

    // End of pass: wait for the outstanding re-runs while the pass has time
    // left (all of them when it has no `--time`, none once it has its
    // findings), then keep what is still unchecked for the next pass, out of
    // the queue.
    adopt_fresh_reruns!(std::mem::take(&mut arrived));
    let wait = if finding_cap_reached!() {
        Some(Duration::ZERO)
    } else {
        pass_deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()))
    };
    if let Some(finished) = fresh_reruns.as_mut().map(|reruns| reruns.finish(wait)) {
        adopt_fresh_reruns!(finished.checked);
        unchecked_inputs.extend(finished.unchecked);
    }
    let mut unchecked_keys = HashSet::new();
    unchecked_inputs.retain(|input| unchecked_keys.insert(crash_input_key(input)));
    if let Some(reruns) = fresh_reruns.take() {
        fresh_rerun_summary.submitted = reruns.submitted();
        fresh_rerun_summary.unchecked = unchecked_inputs.len();
        match save_unchecked_inputs(&unchecked_dir, &unchecked_inputs) {
            Ok(0) => {}
            Ok(left_out) => bhfeprintln!(
                "bhf fuzz: {left_out} unchecked input(s) did not fit in {} (at most \
                 {MAX_SAVED_UNCHECKED_INPUTS}) and were left out of the corpus",
                unchecked_dir.display()
            ),
            Err(error) => {
                bhfeprintln!("bhf fuzz: warning: could not save unchecked inputs: {error}");
            }
        }
        if !unchecked_inputs.is_empty() {
            fresh_rerun_summary.unchecked_dir = Some(unchecked_dir.clone());
            bhfeprintln!(
                "bhf fuzz: {} new corpus input(s) were not re-run in a fresh process \
                 before the pass ended; they are kept out of the corpus queue, in {}, \
                 for the next pass to check first",
                unchecked_inputs.len(),
                unchecked_dir.display()
            );
        }
    }
    // An empty unchecked dir is gone.
    let _ = fs::remove_dir(&unchecked_dir);

    // #422: emit a taint-confirmed sink finding for each cross-execution-
    // confirmed fuzz-controlled sink (path-open BHF-405, process-exec BHF-431,
    // SSRF BHF-433, library-load BHF-435, SQL BHF-441, destructive-fs BHF-440).
    // Done at run end (not per-input) so a sink is confirmed exactly once and a
    // program constant the auto-dictionary echoed into some inputs — reached
    // untainted on other inputs — is suppressed. Distinct subjects dedupe to
    // one finding per (rule | oracle | api); the cap is a backstop against a
    // target that reaches a fresh input-derived sink every execution.
    let max_sink_taint_findings = crate::resource_limits::env_usize("BHF_MAX_SINK_TAINT_FINDINGS")
        .unwrap_or_else(|| {
            crate::resource_limits::dynamic_bytes(
                "BHF_MAX_SINK_TAINT_FINDING_BYTES",
                2048,
                2 * crate::resource_limits::MIB,
                2 * crate::resource_limits::MIB,
                64 * crate::resource_limits::MIB,
            )
            .saturating_div(32 * 1024)
            .clamp(50, 2048)
        });
    // A shell command with shell syntax that ran without input bytes in it
    // is a program constant, which BHF-304 does not report: the run notes it
    // once.
    {
        let constants = sink_taint.constant_shell_commands();
        if let Some((api, command)) = constants.first() {
            let shown: String = command.chars().take(80).collect();
            bhfeprintln!(
                "bhf fuzz: note: {} shell command(s) with shell metacharacters ran without \
                 fuzz-input bytes in them, such as {api}({shown:?}); a program constant is not \
                 reported as command injection (BHF-304)",
                constants.len()
            );
        }
    }
    let dropped_sink_entries = sink_taint.dropped_entries();
    let sink_taint_limit = sink_taint.entry_limit();
    let confirmed_sinks = sink_taint.into_confirmed();
    let confirmed_sinks_total = confirmed_sinks.len();
    for confirmed in confirmed_sinks.into_iter().take(max_sink_taint_findings) {
        if sink_subject_is_bhf_housekeeping(&confirmed, &prepared.work_dir) {
            continue;
        }
        // A `system`/`popen` command with shell syntax is also the
        // shell-metacharacter heuristic's (BHF-304).
        for hit in crate::auto::runtrace::confirmed_sink_hits(&confirmed) {
            let key = oracle_hit_dedupe_key(&hit);
            if !seen_oracle_hits.insert(key.clone()) {
                note_duplicate_of_existing(
                    &mut duplicates_of_existing,
                    existing_findings.oracles.get(&key),
                );
                continue;
            }
            let id = emitter
                .emit_oracle_hit(&confirmed.input, &hit)
                .map_err(|error| format!("emit oracle finding: {error}"))?;
            let descent = lineage.of_bytes(&confirmed.input);
            crate::fuzz_lineage::record(&prepared.work_dir, &id.0, &descent);
            finding_ids.push(id.0);
        }
    }
    if confirmed_sinks_total > max_sink_taint_findings {
        bhfeprintln!(
            "bhf fuzz: {confirmed_sinks_total} fuzz-controlled sink(s) confirmed (#422); \
             emitted the first {max_sink_taint_findings} (raise \
             BHF_MAX_SINK_TAINT_FINDINGS if intended)"
        );
    }
    if dropped_sink_entries > 0 {
        bhfeprintln!(
            "bhf fuzz: sink-taint tracking reached its {}-subject memory cap; \
             ignored {} later distinct sink observation(s) (raise \
             BHF_MAX_SINK_SUBJECTS or BHF_MAX_SINK_TRACKING_BYTES if intended)",
            sink_taint_limit,
            dropped_sink_entries
        );
    }

    if non_reproducible > 0 {
        bhfeprintln!(
            "bhf fuzz: {non_reproducible} fault(s) did not reproduce in a fresh \
             process (global-state artifacts) and were not emitted"
        );
    }
    let skipped_unreproduced = sanitizer_dedup.skipped_unreproduced_hits();
    if skipped_unreproduced > 0 {
        bhfeprintln!(
            "bhf fuzz: {skipped_unreproduced} later sanitizer crash(es) hit a root \
             cause that failed {MAX_UNCONFIRMED_SANITIZER_ATTEMPTS} fresh-process \
             confirmations; they were not re-run or emitted (per key: \
             `unreproduced_sanitizer_hits` in fuzz_runs/<harness>-latest.json)"
        );
    }
    let folded: usize = sanitizer_dedup.duplicate_hits().values().sum();
    if folded > 0 {
        bhfeprintln!(
            "bhf fuzz: {folded} later sanitizer crash(es) matched an already-reported \
             root cause and were counted, not emitted (per key: \
             `duplicate_sanitizer_hits` in fuzz_runs/<harness>-latest.json)"
        );
    }
    if driver_glue_drops > 0 {
        bhfeprintln!(
            "bhf fuzz: {driver_glue_drops} crash(es) in libFuzzer/sanitizer driver glue \
             (no target frame) were treated as harness faults and not emitted"
        );
    }
    if scaffolding_leak_drops > 0 {
        bhfeprintln!(
            "bhf fuzz: {scaffolding_leak_drops} LSan leak(s) whose entire stack was bhf \
             decode/harness scaffolding (no target frame) were suppressed (not target leaks)"
        );
    }

    // #401/#412: flush the coverage-guided corpus (the in-memory pool — seeds plus
    // every retained input) to `corpus/<hid>/queue/`, content-hash named, so the
    // explored corpus is replayable for neutral coverage measurement /
    // `corpus minimize` instead of lost on exit. The pool is retention-gated
    // (coverage-or-signature progress) and bounded by the derived corpus budget, so
    // `corpus_persisted` tracks `corpus_new` and stays bounded even when coverage
    // reads zero. Best-effort: a persistence I/O error must not fail an otherwise-
    // successful run.
    //
    // The corpus is about to hold this pass's inputs, of this harness's input
    // format, whether or not the pass found anything: record that format.
    emitter.record_corpus_format();
    //
    // #416 AC2: a crasher (known by a finding, or retired from the pool by a
    // fresh re-run) and an input whose fresh re-run has not come back are
    // left out.
    // So is a seed a fork-server pass never ran (its time went to the
    // re-runs, or it stopped at its findings): nothing checked it here.
    let unrun_seeds = if forkserver_started && driver_harness {
        executions.min(initial_seed_count)..initial_seed_count
    } else {
        0..0
    };
    let queueable = |(index, entry): &(usize, &PoolEntry)| {
        let key = crash_input_key(&entry.bytes);
        !entry.retired
            && !unrun_seeds.contains(index)
            && !crashing_inputs.contains(&key)
            && !unchecked_keys.contains(&key)
    };
    let corpus_persisted = match corpus.persist_coverage_corpus(
        &prepared.harness_id,
        pool.iter()
            .enumerate()
            .filter(|entry| queueable(entry))
            .map(|(_, entry)| &entry.bytes),
    ) {
        Ok(count) => count,
        Err(error) => {
            bhfeprintln!("bhf fuzz: warning: could not persist coverage corpus: {error}");
            0
        }
    };
    lineage.persist();
    if let (Some(harness_dir), Some(lanes)) = (prepared.harness_path.parent(), portfolio_feedback) {
        let payload = serde_json::json!({
            "schema_version": 1,
            "strategy": "marginal_coverage_entropic",
            "lanes": lanes,
        });
        if let Ok(bytes) = serde_json::to_vec_pretty(&payload) {
            let _ = crate::auto::report::atomic_write(
                &harness_dir.join(PORTFOLIO_FEEDBACK_FILE),
                &bytes,
            );
        }
    }

    // #15: the harness REJECTED every input it executed (incl. the empty seed run
    // first) — it never actually fuzzed (an input gate with no valid seed, or a
    // broken harness). Surface a hard error so the auto loop reports it as
    // built-not-fuzzed, not a silent clean run. A target that genuinely fuzzed has
    // at least one non-rejected execution (a finding or a clean/coverage run).
    //
    // #477: but a target where EVERY input crashes (a callback struct cast from
    // raw bytes, a parser that aborts on malformed input) rejects all executions
    // AND emits real crash findings. Those findings are already persisted to the
    // findings/ tree; returning Err here would make the attempt loop discard them
    // and downgrade the target to a finding-less `Built`. A run that produced any
    // finding produced signal — return Ok so the crashes survive into the report.
    if executions > 0 && rejected_count == executions && finding_ids.is_empty() {
        return Err(format!(
            "harness rejected all {executions} executed input(s) (assert/abort/non-zero exit, \
             including the empty seed) — it cannot fuzz: it needs a valid seed past its input \
             gate, or the harness is broken"
        ));
    }

    // ── #57: extension oracle.evaluate post-run pass (fenced) ───────────────
    // When `--extension <manifest>` is set, drive the just-retained corpus
    // through the explicitly-trusted extension's out-of-process
    // `oracle.evaluate`. Runs AFTER the campaign; the loop's own extension
    // stages (mutation, codec, lifecycle) are torn down first and reported
    // beside it as `stages`. An extension fault is bounded infrastructure that
    // never aborts the run nor becomes a target finding. Reuses the run's
    // finding emitter so an extension finding carries the harness identity.
    let stages = extension_stage.map(extension_stage::ExtensionStage::finish);
    let extension_block = prepared.extension_manifest.as_deref().map(|manifest| {
        let mut block = crate::extension::drive_fuzz_extension(
            manifest,
            &emitter,
            &prepared.harness_id,
            pool.iter()
                .enumerate()
                .filter(|entry| queueable(entry))
                .map(|(_, entry)| entry.bytes.as_slice()),
        );
        if let Some(stages) = stages {
            block["stages"] = stages;
        }
        block
    });

    let elapsed_secs = start.elapsed().as_secs_f64();
    let coverage = coverage_from_env(&prepared.extra_env, &prepared.harness_path);
    let summary = FuzzRunSummary {
        schema_version: 1,
        harness_id: prepared.harness_id,
        engine: "builtin".to_owned(),
        mode: prepared.mode,
        harness_path: prepared.harness_path,
        sandbox: sandbox_metadata,
        iterations_requested: prepared.iterations,
        executions,
        target_entry_observed: target_entry_observed || target_entry_from_env(&prepared.extra_env),
        corpus_new,
        corpus_duplicates,
        corpus_persisted,
        execution: builtin_execution_summary(protocol, forkserver_started),
        cmplog: cmplog_summary,
        sanitizers: sanitizer_summary(&prepared.sanitizers, &prepared.sanitizer_env, false),
        coverage,
        findings: finding_ids,
        duplicate_crashes_of_existing: duplicates_of_existing.values().sum(),
        duplicates_of_existing: duplicates_of_existing.into_keys().collect(),
        elapsed_secs,
        executions_per_sec: executions_per_sec(executions, elapsed_secs),
        afl: None,
        winafl: None,
        extension: extension_block,
        duplicate_sanitizer_hits: sanitizer_dedup.duplicate_hits(),
        unreproduced_sanitizer_hits: sanitizer_dedup.unreproduced_hits(),
        fresh_reruns: (fresh_rerun_summary.submitted > 0).then_some(fresh_rerun_summary),
        hangs: (hangs.observed > 0).then_some(hangs),
        stability: calibration.summary(),
        symcc: symcc_stage.as_ref().map(|stage| stage.summary().clone()),
    };
    if let Some(hint) = summary.stability.as_ref().and_then(StabilitySummary::hint) {
        bhfeprintln!("{hint}");
    }
    if prepared.print_final_stats {
        bhfeprintln!(
            "{}",
            format_final_stats(
                summary.executions,
                summary.corpus_new,
                summary.corpus_duplicates,
                summary.findings.len(),
                start.elapsed(),
            )
        );
    }
    write_run_summary(&prepared.work_dir, &summary)?;
    Ok(summary)
}

struct RuntraceLogCursor {
    path: Option<PathBuf>,
    offset: u64,
}

impl RuntraceLogCursor {
    /// A cursor that reads no events.
    fn none() -> Self {
        Self {
            path: None,
            offset: 0,
        }
    }

    fn from_extra_env(extra_env: &[(String, String)]) -> Self {
        let path = extra_env
            .iter()
            .find_map(|(key, value)| (key == "BHF_RUNTRACE_LOG").then(|| PathBuf::from(value)));
        let offset = path
            .as_ref()
            .and_then(|path| fs::metadata(path).ok())
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        Self { path, offset }
    }

    fn read_new_events(&mut self) -> Vec<crate::auto::runtrace::RuntraceEvent> {
        let Some(path) = &self.path else {
            return Vec::new();
        };
        let Ok(mut file) = fs::File::open(path) else {
            return Vec::new();
        };
        let Ok(metadata) = file.metadata() else {
            return Vec::new();
        };
        let len = metadata.len();
        if len < self.offset {
            self.offset = 0;
        }
        if len == self.offset {
            return Vec::new();
        }
        if len.saturating_sub(self.offset) > max_event_delta_bytes() {
            self.offset = len;
            return Vec::new();
        }
        if file.seek(SeekFrom::Start(self.offset)).is_err() {
            self.offset = len;
            return Vec::new();
        }
        let mut buf = Vec::new();
        if file.read_to_end(&mut buf).is_err() {
            return Vec::new();
        }
        self.offset = len;
        crate::auto::runtrace::parse_str(&String::from_utf8_lossy(&buf))
    }
}

/// Fresh-process confirmations a sanitizer crash's root cause gets before a
/// crash that never reproduces stops costing a re-run per hit.
const MAX_UNCONFIRMED_SANITIZER_ATTEMPTS: u32 = 3;

/// Per-run sanitizer-crash deduplication (#389): one finding per distinct crash
/// root cause with a hit count, instead of one per crashing input (cJSON
/// produced 2211 findings collapsing to 3 clusters). Keys are
/// [`corpus::finding::sanitizer_dedupe_key_scoped`] in the run's
/// [`run_crash_scope`]: the root-cause cluster key, which for a report without
/// an informative frame is its reported site, else its rule, kind, check and
/// faulting pc offset in that scope, so different rules, checks and sites stay
/// separate.
///
/// A key is consumed only once a finding is emitted for it: a first hit that
/// does not reproduce in a fresh process must not hide a later reproducible
/// hit of the same root cause. After [`MAX_UNCONFIRMED_SANITIZER_ATTEMPTS`]
/// failed confirmations the key is given up: later hits are no longer re-run,
/// and they are counted as unreproduced, not as duplicates of a finding.
struct SanitizerClusterDedup {
    /// The scope frame-less crashes are keyed in ([`run_crash_scope`]).
    scope: String,
    /// Consumed key -> hits (the emitted or pre-seeded finding, plus later
    /// duplicates).
    seen: HashMap<String, usize>,
    /// Key -> failed fresh-process confirmations, for keys not yet consumed.
    unconfirmed: HashMap<String, u32>,
    /// Given-up key -> later hits that were not re-run. No finding was ever
    /// emitted for these keys.
    abandoned: HashMap<String, usize>,
    limit: usize,
    warned_cap: bool,
}

impl SanitizerClusterDedup {
    /// Start from the keys of findings an earlier pass already wrote (#35).
    fn new(seed: impl IntoIterator<Item = String>) -> Self {
        Self {
            scope: String::new(),
            seen: seed.into_iter().map(|key| (key, 1)).collect(),
            unconfirmed: HashMap::new(),
            abandoned: HashMap::new(),
            limit: max_finding_dedup_keys(),
            warned_cap: false,
        }
    }

    /// The dedupe key when `report`'s root cause has not been reported yet: the
    /// caller confirms it and then calls [`Self::consumed`] or
    /// [`Self::unconfirmed`]. `None` for a duplicate or a given-up root cause
    /// (either way its hit is counted), or once the key memory cap is reached.
    fn first_sighting(&mut self, report: &corpus::SanitizerReport) -> Option<String> {
        let key = self.key(report);
        if let Some(count) = self.seen.get_mut(&key) {
            *count = count.saturating_add(1);
            return None;
        }
        if let Some(later) = self.abandoned.get_mut(&key) {
            *later = later.saturating_add(1);
            return None;
        }
        let tracked = self
            .seen
            .len()
            .saturating_add(self.unconfirmed.len())
            .saturating_add(self.abandoned.len());
        if tracked >= self.limit {
            if !self.warned_cap {
                self.warned_cap = true;
                bhfeprintln!(
                    "bhf: sanitizer-cluster tracking reached its {}-key \
                     memory cap; suppressing later distinct clusters (raise \
                     BHF_MAX_FINDING_DEDUP_KEYS if intended)",
                    self.limit
                );
            }
            return None;
        }
        Some(key)
    }

    /// Key the run's crashes in `scope`, as the run's emitter does.
    fn with_scope(mut self, scope: String) -> Self {
        self.scope = scope;
        self
    }

    /// The key `report` is deduplicated on.
    fn key(&self, report: &corpus::SanitizerReport) -> String {
        corpus::finding::sanitizer_dedupe_key_scoped(report, &self.scope)
    }

    /// Count a hit of `key` when its root cause is settled: reported (or
    /// pre-seeded) or given up. `false` when it is neither, so the hit still
    /// needs its confirmation.
    fn note_settled_hit(&mut self, key: &str) -> bool {
        if let Some(count) = self.seen.get_mut(key) {
            *count = count.saturating_add(1);
            return true;
        }
        if let Some(later) = self.abandoned.get_mut(key) {
            *later = later.saturating_add(1);
            return true;
        }
        false
    }

    /// A finding was emitted for `key`: later hits are duplicates.
    fn consumed(&mut self, key: String) {
        self.unconfirmed.remove(&key);
        self.seen.entry(key).or_insert(1);
    }

    /// A crash with `key` did not reproduce in a fresh process. The key stays
    /// open for a later hit until it has failed
    /// [`MAX_UNCONFIRMED_SANITIZER_ATTEMPTS`] times, then it is given up.
    fn unconfirmed(&mut self, key: String) {
        let attempts = self.unconfirmed.entry(key.clone()).or_insert(0);
        *attempts = attempts.saturating_add(1);
        if *attempts >= MAX_UNCONFIRMED_SANITIZER_ATTEMPTS {
            self.unconfirmed.remove(&key);
            self.abandoned.insert(key, 0);
        }
    }

    /// Later hits folded into each already-reported root cause.
    fn duplicate_hits(&self) -> std::collections::BTreeMap<String, usize> {
        self.seen
            .iter()
            .filter(|(_, count)| **count > 1)
            .map(|(key, count)| (key.clone(), count - 1))
            .collect()
    }

    /// Hits of each root cause that never reproduced in a fresh process and so
    /// was never reported: its failed confirmations, plus, once it was given
    /// up, the later hits that were not re-run.
    fn unreproduced_hits(&self) -> std::collections::BTreeMap<String, usize> {
        let given_up = self.abandoned.iter().map(|(key, later)| {
            let tries = MAX_UNCONFIRMED_SANITIZER_ATTEMPTS as usize;
            (key.clone(), tries.saturating_add(*later))
        });
        let open = self
            .unconfirmed
            .iter()
            .map(|(key, tries)| (key.clone(), *tries as usize));
        given_up.chain(open).collect()
    }

    /// Hits of given-up root causes that were not re-run.
    fn skipped_unreproduced_hits(&self) -> usize {
        self.abandoned.values().sum()
    }
}

/// AFL++ crash ingestion's first-sighting test: the same root-cause key the
/// builtin loop uses, so the two engines dedupe a crash identically. AFL++ has
/// already confirmed the crash, so a first sighting is consumed at once.
fn afl_crash_is_new(dedup: &mut SanitizerClusterDedup, report: &corpus::SanitizerReport) -> bool {
    match dedup.first_sighting(report) {
        Some(key) => {
            dedup.consumed(key);
            true
        }
        None => false,
    }
}

/// Run the AFL++ persistent-mode harness `harness` on `input`. Such a harness
/// reads its testcase from stdin (the `__AFL_LOOP` /
/// `__AFL_FUZZ_TESTCASE_BUF` macros), so the bytes are piped: passing them as
/// argv[1] has no effect. With a `timeout` a run still going then is killed,
/// and its output carries no sanitizer report.
fn replay_afl_input(
    harness: &Path,
    work_dir: &Path,
    input: &[u8],
    env: &[(String, String)],
    timeout: Option<Duration>,
) -> Result<std::process::Output, String> {
    let mut command = std::process::Command::new(harness);
    command
        .current_dir(ensure_harness_scratch(work_dir)?)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (key, value) in env {
        command.env(key, value);
    }
    apply_runaway_rlimits(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| format!("spawn '{}': {error}", harness.display()))?;
    let stderr_reader = drain_child_stderr(child.stderr.take());
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input);
    }
    let wait_error = |error: std::io::Error| format!("wait for '{}': {error}", harness.display());
    let Some(timeout) = timeout else {
        let status = child.wait().map_err(wait_error)?;
        return Ok(collected_child_output(status, stderr_reader));
    };
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(collected_child_output(status, stderr_reader)),
            Ok(None) if Instant::now() >= deadline => {
                kill_process_group(&mut child);
                let status = child.wait().map_err(wait_error)?;
                let _ = stderr_reader.and_then(|reader| reader.join().ok());
                return Ok(std::process::Output {
                    status,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                });
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                kill_process_group(&mut child);
                let _ = child.wait();
                let _ = stderr_reader.and_then(|reader| reader.join().ok());
                return Err(wait_error(error));
            }
        }
    }
}

/// Count one crash that matched an existing finding (`None`: the match was a
/// finding emitted earlier in this same run, which is not reported).
fn note_duplicate_of_existing(
    duplicates: &mut std::collections::BTreeMap<String, usize>,
    existing_id: Option<&String>,
) {
    if let Some(id) = existing_id {
        *duplicates.entry(id.clone()).or_default() += 1;
    }
}

fn oracle_hit_dedupe_key(hit: &finding_rules::oracle_sdk::OracleHit) -> String {
    // Dedup at the DEFECT level: rule + oracle + dangerous API. Evidence values
    // (an opened file path / fd, an injected command, ...) are PER-INPUT, so
    // including them made every input that re-triggers the same defect a distinct
    // "finding" — a resource-leak oracle that fires on every testcase emitted 600+
    // identical findings (mpack). One defect → one finding (with its first example
    // testcase + evidence preserved on the emitted finding); a genuinely different
    // dangerous API or oracle still keys distinctly.
    format!("{}|{}|{}", hit.rule_id, hit.oracle_name, hit.api)
}

#[cfg(test)]
mod oracle_dedupe_tests {
    use super::oracle_hit_dedupe_key;
    use finding_rules::oracle_sdk::{OracleEvidence, OracleHit};

    fn hit(api: &str, resource: &str) -> OracleHit {
        OracleHit {
            oracle_name: "resource-leak-ada".into(),
            rule_id: "BHF-306".into(),
            category: "logic".into(),
            api: api.into(),
            message: "leak".into(),
            evidence: vec![OracleEvidence::new("resource", resource)],
        }
    }

    #[test]
    fn same_defect_different_per_input_evidence_dedupes() {
        // A resource-leak oracle that fires on every input (a different opened
        // path/fd each time) must collapse to ONE finding, not one per input
        // (mpack emitted 600+ identical BHF-306 findings before this).
        assert_eq!(
            oracle_hit_dedupe_key(&hit("open", "/tmp/bhf_inAAA")),
            oracle_hit_dedupe_key(&hit("open", "/tmp/bhf_inBBB"))
        );
    }

    #[test]
    fn different_dangerous_api_keys_distinctly() {
        assert_ne!(
            oracle_hit_dedupe_key(&hit("open", "/x")),
            oracle_hit_dedupe_key(&hit("openat", "/x"))
        );
    }
}

/// afl-fuzz's per-execution limit (`-t 1000+`), past which it saves the
/// input as a hang.
const AFL_EXEC_TIMEOUT: Duration = Duration::from_millis(1000);

/// The instance directory a single afl-fuzz writes in its `-o` directory.
const AFL_INSTANCE: &str = "default";

/// One afl-fuzz of a run: its instance name (its directory in `-o`), its
/// `-M`/`-S` role (none for a run of one), whether it runs CmpLog, and the
/// file its console output goes to.
struct AflInstance {
    name: String,
    role: Option<&'static str>,
    cmplog: bool,
    log: PathBuf,
}

/// The afl-fuzz instances of a run of `workers` (#276): `default` alone, or
/// a `-M main` and `-S sec1`..: one shared output directory, in which each
/// syncs the others' queues as AFL++ does. CmpLog runs on the main instance,
/// as AFL++ advises for one or two of a campaign's instances.
fn afl_instances(workers: usize, afl_out: &Path) -> Vec<AflInstance> {
    if workers <= 1 {
        return vec![AflInstance {
            name: AFL_INSTANCE.to_owned(),
            role: None,
            cmplog: true,
            log: afl_out.join("afl-fuzz.log"),
        }];
    }
    (0..workers)
        .map(|index| {
            let name = if index == 0 {
                "main".to_owned()
            } else {
                format!("sec{index}")
            };
            AflInstance {
                log: afl_out.join(format!("afl-fuzz-{name}.log")),
                role: Some(if index == 0 { "-M" } else { "-S" }),
                cmplog: index == 0,
                name,
            }
        })
        .collect()
}

/// The minutes between the syncs of a `-M`/`-S` campaign of `budget`:
/// a quarter of it, from 1 to AFL++'s default of 30.
fn afl_sync_minutes(budget: Duration) -> u64 {
    (budget.as_secs() / 60 / 4).clamp(1, 30)
}

/// Why an afl-fuzz exited with `status`, from the tail of its log; empty when
/// every seed aborts the harness, which skips the lane for the target.
fn afl_failure(status: &std::process::ExitStatus, log: &Path) -> String {
    // afl-fuzz's console output was redirected to a file (not an undrained
    // pipe), so read it back for the diagnostic hints.
    let afl_log_bytes =
        read_bounded_file_head_tail(log, max_captured_stderr_bytes()).unwrap_or_default();
    let buf = String::from_utf8_lossy(&afl_log_bytes);
    // Strip ANSI sequences so the error is readable on dumb stderr.
    let cleaned: String = buf
        .chars()
        .filter(|ch| {
            let c = *ch as u32;
            ch.is_ascii_graphic() || ch.is_ascii_whitespace() || c >= 0x80
        })
        .collect();
    if cleaned.contains("at least one valid input seed that does not crash") {
        return String::new();
    }
    let mut hint = String::new();
    if cleaned.contains("core_pattern") {
        hint.push_str(
            "\nHint: AFL detected a host `core_pattern` that would swallow \
             crashes. Run `sudo sysctl kernel.core_pattern=core` or set \
             AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 (bhf already sets \
             this; check the harness env).",
        );
    }
    format!(
        "afl-fuzz exited non-zero ({:?}). Output tail:\n{}{}",
        status.code(),
        cleaned
            .lines()
            .rev()
            .take(10)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n"),
        hint
    )
}

/// Whether `instance` holds a session afl-fuzz can resume: a queue.
fn afl_session_exists(instance: &Path) -> bool {
    !afl_entries(&instance.join("queue")).is_empty()
}

/// The `id:` entries AFL++ wrote in `dir` (a queue, a `crashes` or a `hangs`
/// directory), sorted; its other files (`README.txt`, `.state/`) are not
/// inputs.
fn afl_entries(dir: &Path) -> Vec<PathBuf> {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("id:") || name.starts_with("id_"))
        })
        .collect();
    entries.sort();
    entries
}

/// The afl-fuzz instance directories in `out_dir`: `default`, or one per
/// `-M`/`-S` instance; each holds what afl-fuzz writes there (a queue, saved
/// crashes or hangs, its stats).
fn afl_instance_dirs(out_dir: &Path) -> Vec<PathBuf> {
    let mut instances: Vec<PathBuf> = fs::read_dir(out_dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.path())
        .filter(|path| {
            ["queue", "crashes", "hangs", "fuzzer_stats"]
                .iter()
                .any(|name| path.join(name).exists())
        })
        .collect();
    instances.sort();
    instances
}

/// The inputs afl-fuzz saved as `kind` (`crashes` or `hangs`) in every
/// instance: its `<kind>/` and the `<kind>.<date>/` a resumed session moved
/// the last one's to (#275).
fn afl_saved_inputs(out_dir: &Path, kind: &str) -> Vec<PathBuf> {
    let backup = format!("{kind}.");
    afl_instance_dirs(out_dir)
        .iter()
        .flat_map(|instance| {
            let mut dirs: Vec<PathBuf> = fs::read_dir(instance)
                .into_iter()
                .flatten()
                .flatten()
                .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name == kind || name.starts_with(&backup))
                })
                .map(|entry| entry.path())
                .collect();
            dirs.sort();
            dirs
        })
        .flat_map(|dir| afl_entries(&dir))
        .collect()
}

/// Remove the `crashes.<date>/` and `hangs.<date>/` a resumed session moved
/// the last one's saved inputs to, once they are harvested.
fn remove_afl_backups(out_dir: &Path) {
    for instance in afl_instance_dirs(out_dir) {
        for entry in fs::read_dir(&instance).into_iter().flatten().flatten() {
            let backup = entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("crashes.") || name.starts_with("hangs."));
            if backup && entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }
}

/// The seeds an AFL++ session was given, by [`afl_seed_hash`], beside its
/// output directory: a seed AFL++ trimmed is no longer in its queue as it
/// was given, and is not given again.
const AFL_OFFERED_SEEDS: &str = "offered-seeds.txt";

/// A seed's name in [`AFL_OFFERED_SEEDS`] and in `orig:bhf-seed-<hash>`: the
/// first 8 bytes of its SHA-256, in hex.
fn afl_seed_hash(seed: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(seed)
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn read_offered_seeds(path: &Path) -> HashSet<String> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

fn write_offered_seeds(path: &Path, offered: &HashSet<String>) {
    let mut lines: Vec<&str> = offered.iter().map(String::as_str).collect();
    lines.sort_unstable();
    let mut text = lines.join("\n");
    text.push('\n');
    if let Err(error) = fs::write(path, text) {
        bhfeprintln!(
            "bhf: warning: could not record the seeds given to afl-fuzz in '{}': {error}",
            path.display()
        );
    }
}

/// Add the seeds a resumed session was not given and its queue does not
/// hold to that queue (#275): afl-fuzz reads a resumed session's inputs from
/// its queue, not from `-i`. Each is named as a queue entry
/// (`id:999999,orig:bhf-seed-<hash>`), which AFL++ renumbers on resume and
/// cleans up after, and joins `offered`. The number added.
fn add_resume_seeds(
    queue: &Path,
    seeds: &[Vec<u8>],
    offered: &mut HashSet<String>,
) -> Result<usize, String> {
    let mut held: HashSet<String> = afl_entries(queue)
        .iter()
        .filter_map(|path| fs::read(path).ok())
        .map(|bytes| afl_seed_hash(&bytes))
        .collect();
    let mut added = 0;
    for seed in seeds.iter().filter(|seed| !seed.is_empty()) {
        let digest = afl_seed_hash(seed);
        if !held.insert(digest.clone()) || !offered.insert(digest.clone()) {
            continue;
        }
        let path = queue.join(format!("id:999999,orig:bhf-seed-{digest}"));
        fs::write(&path, seed)
            .map_err(|error| format!("add seed '{}': {error}", path.display()))?;
        added += 1;
    }
    Ok(added)
}

/// Take the inputs afl-fuzz keeps in its instances' queues into the
/// harness's bhf corpus (`corpus/<id>/queue`, #275), by content hash and
/// within the corpus limits, so the builtin engine, `bhf corpus` and a later
/// AFL++ session start from them. The number newly kept.
fn import_afl_queues(work_dir: &Path, harness_id: &str, out_dir: &Path, max_len: usize) -> usize {
    let limits = corpus_limits(max_len);
    let mut corpus = CorpusManager::new(work_dir.to_path_buf())
        .with_retention_limits(limits.entries, limits.bytes);
    let inputs = afl_instance_dirs(out_dir)
        .into_iter()
        .flat_map(|instance| afl_entries(&instance.join("queue")))
        .filter_map(|path| fs::read(path).ok());
    match corpus.persist_coverage_corpus(harness_id, inputs) {
        Ok(count) => count,
        Err(error) => {
            bhfeprintln!("bhf: warning: could not import the AFL++ queue into the corpus: {error}");
            0
        }
    }
}

/// Re-run an input an external engine saved as a hang (#275, #294) through
/// `main_afl` (the input on stdin, or as a file argument, as `feed` says) with
/// twice the engine's per-execution `limit`, and ask it for the stack it is in
/// if it hangs again ([`signal_for_stack`]). Not re-run when `deadline`
/// leaves less time than that.
fn confirm_external_hang(
    main_afl: &Path,
    work_dir: &Path,
    input: &[u8],
    extra_env: &[(String, String)],
    deadline: Instant,
    limit: Duration,
    feed: TraceInput,
) -> Result<HangConfirmation, String> {
    let confirm = limit.saturating_mul(2);
    let left = deadline.saturating_duration_since(Instant::now());
    if left < confirm {
        return Ok(HangConfirmation::NotRerun);
    }
    let grace = HANG_STACK_GRACE.min(left - confirm);
    let scratch = ensure_harness_scratch(work_dir)?;
    let input_file = scratch.join(format!("hang-{}.bin", std::process::id()));
    let mut command = std::process::Command::new(main_afl);
    if feed == TraceInput::ArgvFile {
        fs::write(&input_file, input)
            .map_err(|error| format!("write '{}': {error}", input_file.display()))?;
        command.arg(&input_file);
    }
    command
        .current_dir(&scratch)
        .stdin(if feed == TraceInput::Stdin {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (key, value) in hang_stack_env(extra_env, confirm) {
        command.env(key, value);
    }
    apply_runaway_rlimits(&mut command);
    replay_min::process::isolate_process_group(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| format!("spawn '{}': {error}", main_afl.display()))?;
    let stderr_reader = drain_child_stderr(child.stderr.take());
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input);
    }
    let until = Instant::now() + confirm;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = collected_child_output(status, stderr_reader);
                let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
                let _ = fs::remove_file(&input_file);
                return Ok(match corpus::parse_sanitizer_report(&stderr) {
                    Some(report) => HangConfirmation::Crashed(Box::new(report), stderr),
                    None => HangConfirmation::Finished,
                });
            }
            Ok(None) if Instant::now() >= until => {
                signal_for_stack(&mut child, grace);
                kill_process_group(&mut child);
                let _ = child.wait();
                let stderr = stderr_reader
                    .and_then(|reader| reader.join().ok())
                    .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                    .unwrap_or_default();
                let report = hang_report(&stderr, limit, confirm);
                let _ = fs::remove_file(&input_file);
                return Ok(HangConfirmation::Hung(Box::new(report), stderr));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                kill_process_group(&mut child);
                let _ = child.wait();
                return Err(format!("wait for '{}': {error}", main_afl.display()));
            }
        }
    }
}

/// Run a C harness under AFL++. Expects:
///
/// - `<work_dir>/build/<harness_id>/main_afl` produced by
///   `make afl` (afl-clang-fast -DBHF_AFL).
/// - `<work_dir>/build/<harness_id>/main` (the libFuzzer/asan/ubsan
///   build) for replaying each crash artifact so we get a sanitizer
///   report to map onto the rule catalog.
///
/// We drive `afl-fuzz -i seeds -o out -- ./main_afl` for either the
/// requested time budget or `prepared.iterations * 0.1s` (afl-fuzz
/// runs in seconds, not iterations), then walk the
/// `out/default/crashes/` directory to collect crash artifacts, replay
/// each against the libFuzzer binary, parse the resulting stderr, and
/// emit one finding per unique rule_signature.
/// How an external engine's saved input is re-run: the input, the
/// environment and an optional time limit, to the child's output.
type ExternalReplay<'r> = dyn Fn(&[u8], &[(String, String)], Option<Duration>) -> Result<std::process::Output, String>
    + 'r;

/// The crashes and hangs an external engine (AFL++, libFuzzer) saved, re-run
/// on bhf's side and recorded as the run's findings (#294): each is
/// deduplicated on the run's crash clusters, a crash is given the builtin
/// engine's object-size second opinion and its decoded arguments, and each
/// finding's lineage says the engine scheduled it.
struct ExternalIngest<'a> {
    prepared: &'a PreparedFuzzRun,
    /// The engine, as the lineage names it: `AFL++`, `libFuzzer`.
    engine: &'static str,
    /// What the engine schedules: `its own queue`.
    schedule: &'static str,
    /// How the harness takes an input for the argument trace.
    feed: TraceInput,
    emitter: FindingEmitter,
    dedup: SanitizerClusterDedup,
    /// Event signatures (hex) reported already: the harness's earlier
    /// findings, then each this ingest emits (#304).
    event_signatures: HashSet<String>,
    finding_ids: Vec<String>,
}

impl<'a> ExternalIngest<'a> {
    fn new(
        prepared: &'a PreparedFuzzRun,
        engine: &'static str,
        schedule: &'static str,
        feed: TraceInput,
    ) -> Result<Self, String> {
        let sandbox_metadata = prepared.runner.sandbox_metadata();
        // An Ada finding replays and minimizes through the harness's own
        // build, as the builtin engine's do (#304).
        let fixture =
            ada_main_beside_afl(&prepared.harness_path).unwrap_or(prepared.harness_path.clone());
        let mut emitter = with_harness_format(
            FindingEmitter::with_metadata_and_sandbox(
                prepared.work_dir.clone(),
                prepared.harness_id.clone(),
                "unknown".to_owned(),
                fixture.display().to_string(),
                serde_json::to_value(&sandbox_metadata)
                    .map_err(|error| format!("serialize sandbox metadata: {error}"))?,
            )
            .with_mode(prepared.mode)
            .with_shim_env(crate::runtime_oracles::shim_mode_gates(&prepared.extra_env))
            .with_line_maps_dir(&prepared.work_dir.join("src_instrumented")),
            &fixture,
            &prepared.work_dir,
            &prepared.harness_id,
        );
        if let Some(identity) = build_binary_record(&fixture) {
            emitter = emitter.with_build_binary(identity);
        }
        let dedup = SanitizerClusterDedup::new(Vec::new()).with_scope(run_crash_scope(
            &prepared.harness_path,
            &prepared.work_dir,
            &prepared.harness_id,
        ));
        let event_signatures = ExistingFindings::load(&prepared.work_dir, &prepared.harness_id)
            .signatures
            .into_keys()
            .collect();
        Ok(Self {
            prepared,
            engine,
            schedule,
            feed,
            emitter,
            dedup,
            event_signatures,
            finding_ids: Vec::new(),
        })
    }

    /// The findings an Ada harness's crashing `input` shows when it runs
    /// again with the event log (#304): an exception that escaped the target,
    /// or a predefined check the target swallowed, as the builtin engine
    /// reports them. Under AFL++ the harness aborted on it
    /// (`BHF_CRASH_ON_FINDING`), with no report of its own. Whether any was
    /// new.
    fn ada_findings(&mut self, input: &[u8], artifact: &str) -> Result<bool, String> {
        let prepared = self.prepared;
        let run = run_harness(
            &prepared.runner,
            &prepared.work_dir,
            input,
            &prepared.extra_env,
            prepared.per_input_timeout,
            prepared.rss_limit_mb,
            prepared.deadline,
        )?;
        let mut emitted = false;
        for testcase in &run.testcases {
            for (handler_index, classification) in classify(testcase) {
                let Some(handler) = resolve_handler(testcase, handler_index) else {
                    continue;
                };
                // As the builtin engine filters them: a target rejecting an
                // input with its own exception, or a stub body it reached.
                if finding_tier(classification, &handler.as_ref().exception_name)
                    == FindingTier::IntendedRejection
                    || handler
                        .as_ref()
                        .exception_message
                        .contains(crate::auto::ada_body_stub::STUB_RAISE_MARKER)
                {
                    continue;
                }
                let signature = compute_signature(testcase, handler.as_ref());
                if !self.event_signatures.insert(signature.hex()) {
                    continue;
                }
                let id = self
                    .emitter
                    .emit(input, testcase, handler_index)
                    .map_err(|error| format!("emit {} finding: {error}", self.engine))?;
                self.record_lineage(&id.0, artifact);
                self.finding_ids.push(id.0);
                emitted = true;
            }
        }
        Ok(emitted)
    }

    /// Record the crashing `input` the engine saved as `artifact` (`crash
    /// file id:000001,...`), re-run through `replay`, unless its sanitizer
    /// report is not new or it does not crash again.
    fn crash(
        &mut self,
        input: &[u8],
        artifact: &str,
        hard_deadline: Instant,
        replay: &ExternalReplay<'_>,
    ) -> Result<(), String> {
        let prepared = self.prepared;
        // An Ada harness aborts on an exception's top-level catch, which its
        // event log describes and a signal does not.
        if is_instrumented_ada_harness(&prepared.runner) && self.ada_findings(input, artifact)? {
            return Ok(());
        }
        let replayed = replay(input, &prepared.extra_env, None)
            .map_err(|error| format!("replay {artifact}: {error}"))?;
        let stderr = String::from_utf8_lossy(&replayed.stderr);
        // As in the builtin engine, a crash signal with no sanitizer report
        // that is not the target rejecting the input is a reachable crash: a
        // COBOL program's libcob runtime reports its own errors and faults
        // (#302).
        let report = corpus::parse_sanitizer_report(&stderr).or_else(|| {
            (crate::fatal_signal::classify(&replayed.status, &stderr).is_some()
                && !is_input_rejection(&replayed.status, &stderr))
            .then(|| fatal_signal_report(&replayed.status, &stderr))
        });
        let Some(report) = report else {
            return Ok(());
        };
        let key = self.dedup.key(&report);
        if !afl_crash_is_new(&mut self.dedup, &report) {
            return Ok(());
        }
        // A clang build's UBSan object-size check reports a member access
        // through an undersized heap block before ASan does: the builtin
        // engine's second opinion, once per root cause (afl_crash_is_new
        // consumed its key), within the per-input timeout and the pass's hard
        // deadline.
        let opinion = object_size_second_opinion(
            &prepared.work_dir,
            &report,
            &prepared.extra_env,
            prepared.per_input_timeout,
            Some(hard_deadline),
            |env, timeout| {
                let rerun = replay(input, env, Some(timeout))?;
                let stderr = String::from_utf8_lossy(&rerun.stderr).into_owned();
                Ok((corpus::parse_sanitizer_report(&stderr), Some(stderr)))
            },
        );
        let (report, log) = match opinion.as_ref().and_then(|o| o.asan.as_ref()) {
            Some((view, log)) => (view, log.as_deref().unwrap_or_default()),
            None => (&report, stderr.as_ref()),
        };
        if opinion.as_ref().is_some_and(|o| o.asan.is_some())
            && !afl_crash_is_new(&mut self.dedup, report)
        {
            // That ASan report is a finding already.
            return Ok(());
        }
        let id = self
            .emitter
            .emit_sanitizer_crash_with_log(input, report, Some(log.as_bytes()))
            .map_err(|error| format!("emit {} finding: {error}", self.engine))?;
        if let Some(opinion) = &opinion {
            opinion.record(&prepared.work_dir, &id.0, &key);
        }
        self.record_lineage(&id.0, artifact);
        record_finding_arguments(
            &prepared.work_dir,
            &id.0,
            &prepared.harness_path,
            input,
            self.feed,
            &prepared.extra_env,
            AFL_REPLAY_TRACE_TIMEOUT,
            None,
        );
        self.finding_ids.push(id.0);
        Ok(())
    }

    /// Record a hang the engine saved as `artifact` that hung again
    /// ([`confirm_external_hang`]), unless its report is not new.
    fn hang(
        &mut self,
        input: &[u8],
        report: &corpus::SanitizerReport,
        log: &str,
        artifact: &str,
    ) -> Result<(), String> {
        if !afl_crash_is_new(&mut self.dedup, report) {
            return Ok(());
        }
        let id = self
            .emitter
            .emit_sanitizer_crash_with_log(input, report, Some(log.as_bytes()))
            .map_err(|error| format!("emit {} hang finding: {error}", self.engine))?;
        self.record_lineage(&id.0, artifact);
        self.finding_ids.push(id.0);
        Ok(())
    }

    fn record_lineage(&self, id: &str, artifact: &str) {
        crate::fuzz_lineage::record(
            &self.prepared.work_dir,
            id,
            &corpus::lineage::FindingLineage::unknown(format!(
                "found by {engine}, which schedules {schedule}; bhf does not see which \
                 input this one was mutated from ({engine} {artifact})",
                engine = self.engine,
                schedule = self.schedule,
            )),
        );
    }
}

fn run_afl_plus_plus(prepared: PreparedFuzzRun) -> Result<FuzzRunSummary, String> {
    use std::process::Command;
    use std::time::Instant;

    reset_target_entry(&prepared.extra_env);
    if !prepared.afl_inst_ranges.is_empty() && prepared.afl_mode.inst_ranges_env().is_none() {
        return Err("--afl-inst-range requires --afl-mode qemu or frida".to_owned());
    }
    let (_, cmplog_summary) = load_cmplog_for_run(prepared.cmplog_log.as_deref(), &prepared.seeds);
    let afl_fuzz = resolve_afl_fuzz(prepared.afl_path.as_deref())?;
    let generated_dictionary = find_generated_dictionary(&prepared.work_dir, &prepared.harness_id);
    // find_harness_executable already preferred main_afl for the AFL
    // engine. If we landed on a libFuzzer `main` because main_afl was
    // missing, fail with a clear message - libFuzzer binaries don't
    // wire up afl-fuzz's persistent-mode handshake and afl-fuzz will
    // hang or behave unpredictably.
    let main_afl = prepared.harness_path.clone();
    let cmplog_binary = afl_cmplog_binary(&main_afl, prepared.afl_mode);
    let staged_name = main_afl
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if staged_name != "main_afl" && staged_name != "main_afl.exe" {
        return Err(format!(
            "AFL build not found at '{}'. Run `bhf build --c-engine afl++ ...` (or `make afl` against the harness Makefile) first.",
            main_afl.with_file_name("main_afl").display()
        ));
    }

    // Seed corpus directory required by afl-fuzz.
    let afl_out = prepared.work_dir.join("afl_out").join(&prepared.harness_id);
    let seeds_dir = afl_out.join("seeds");
    // This run's seeds only: an earlier run's are in AFL++'s queue.
    let _ = fs::remove_dir_all(&seeds_dir);
    fs::create_dir_all(&seeds_dir)
        .map_err(|error| format!("create AFL seeds dir '{}': {error}", seeds_dir.display()))?;
    // #275: AFL++'s output directory is kept between runs, and afl-fuzz
    // resumes the session in it (`AFL_AUTORESUME`): its queue, its coverage
    // map and its stats.
    let out_dir = afl_out.join("out");
    fs::create_dir_all(&out_dir)
        .map_err(|error| format!("create AFL out dir '{}': {error}", out_dir.display()))?;
    let mut seed_count = 0_usize;
    for (idx, seed) in prepared.seeds.iter().enumerate() {
        if seed.is_empty() {
            continue;
        }
        let seed_path = seeds_dir.join(format!("seed-{idx:04}"));
        fs::write(&seed_path, seed)
            .map_err(|error| format!("write seed '{}': {error}", seed_path.display()))?;
        seed_count += 1;
    }
    if seed_count == 0 {
        // afl-fuzz refuses to start with an empty seed dir; supply one.
        let seed_path = seeds_dir.join("seed-default");
        fs::write(&seed_path, b"AAAA").map_err(|error| format!("write default seed: {error}"))?;
    }
    // A resumed session reads its queue, not `-i`: the seeds it does not hold
    // yet (a builtin pass's corpus, new operator seeds) join that queue.
    // #276: `--workers N` is one `-M` instance and N-1 `-S` instances in the
    // one output directory, which sync their queues as they run.
    let instances = afl_instances(prepared.afl_workers, &afl_out);
    let first_instance = out_dir.join(&instances[0].name);
    let mut resuming = afl_session_exists(&first_instance);
    let offered_path = afl_out.join(AFL_OFFERED_SEEDS);
    let mut offered = if resuming {
        read_offered_seeds(&offered_path)
    } else {
        HashSet::new()
    };
    if resuming {
        // The main instance shares them with the others.
        add_resume_seeds(&first_instance.join("queue"), &prepared.seeds, &mut offered)?;
    } else {
        offered.extend(prepared.seeds.iter().map(|seed| afl_seed_hash(seed)));
    }
    write_offered_seeds(&offered_path, &offered);

    let time_budget = prepared.time.unwrap_or_else(|| {
        // 100 ms per requested iteration, capped at 30s for safety.
        let ms = (prepared.iterations as u64).saturating_mul(100).min(30_000);
        Duration::from_millis(ms.max(1_000))
    });

    let start = Instant::now();
    let build_afl_command = |instance: &AflInstance| -> Result<Command, String> {
        // afl-fuzz's console output goes to a file instead of an undrained
        // pipe (see the stdout/stderr redirect below — a piped, undrained
        // child deadlocks).
        let afl_log_file = std::fs::File::create(&instance.log)
            .map_err(|error| format!("create afl log '{}': {error}", instance.log.display()))?;
        // AFL stops at the first of -V or -E; pass only the time budget so the
        // caller's `--time` (or our iterations-derived default) actually applies.
        let mut afl_cmd = Command::new(&afl_fuzz);
        afl_cmd
            .current_dir(ensure_harness_scratch(&prepared.work_dir)?)
            .arg("-i")
            .arg(&seeds_dir)
            .arg("-o")
            .arg(&out_dir)
            .arg("-V")
            .arg(time_budget.as_secs().to_string())
            // Per-exec timeout. WITHOUT this, a single fuzzed input that hangs the
            // target (e.g. parson's recursive JSON parser on a deeply-nested array)
            // wedges the whole run — afl-fuzz's internal `run_time` stays 0, its `-V`
            // budget never fires, and the run deadlocks (observed: stuck at 20 execs
            // forever; the hard-deadline kill above is only the backstop). A 1s cap is
            // ~25000x a normal parser exec, so it catches hangs without flagging
            // legitimately-fast inputs. The `+` suffix keeps initial seed calibration
            // lenient (a slow seed is skipped, not treated as a fatal hang).
            .arg("-t")
            .arg(format!("{}+", AFL_EXEC_TIMEOUT.as_millis()));
        // Issue #45: binary-only modes add `-Q` (QEMU) or `-O` (Frida) so a stripped,
        // source-less dependency still gets coverage. `native` adds nothing.
        if let Some(mode_flag) = prepared.afl_mode.flag() {
            afl_cmd.arg(mode_flag);
        }
        if let Some(role) = instance.role {
            afl_cmd.arg(role).arg(&instance.name);
            // Instances sync at start and then every AFL_SYNC_TIME minutes,
            // 30 by default: a quarter of a shorter budget, at least one,
            // unless the caller set it.
            if std::env::var_os("AFL_SYNC_TIME").is_none() {
                afl_cmd.env("AFL_SYNC_TIME", afl_sync_minutes(time_budget).to_string());
            }
        }
        // #274: AFL++'s input-to-state stage over the CmpLog build's comparison
        // operands, with arithmetic and transform solving (`-l 2AT`), as AFL++
        // recommends for a CmpLog binary.
        if let Some(cmplog) = cmplog_binary.as_ref().filter(|_| instance.cmplog) {
            afl_cmd.arg("-c").arg(cmplog).arg("-l").arg("2AT");
        }
        if let Some(dictionary) = &generated_dictionary {
            afl_cmd.arg("-x").arg(dictionary);
        }
        // AFL++ takes up to four `-x` dictionaries; the learned one goes second.
        if let Some(learned) = find_learned_dictionary(&prepared.work_dir, &prepared.harness_id) {
            afl_cmd.arg("-x").arg(learned);
        }
        if let Some(max_len) = prepared.afl_max_len {
            if afl_fuzz_supports_max_len(&afl_fuzz) {
                afl_cmd.arg("-G").arg(max_len.to_string());
            } else {
                bhfeprintln!(
                    "bhf: {} has no -G option (AFL++ 4.00c or newer), so its generated inputs \
                 are not held to --max-len {max_len}; the seeds are still cut to {max_len} bytes",
                    afl_fuzz.display()
                );
            }
        }
        // An Ada harness catches every exception at its top level, which
        // AFL++ would see as a clean run: it aborts there instead (#304).
        if is_instrumented_ada_harness(&prepared.runner) {
            afl_cmd.env("BHF_CRASH_ON_FINDING", "1");
        }
        afl_cmd
            .arg("--")
            .arg(&main_afl)
            .env("AFL_NO_UI", "1")
            .env("AFL_SKIP_CPUFREQ", "1")
            .env("AFL_AUTORESUME", "1")
            // AFL refuses to start on hosts where /proc/sys/kernel/core_pattern
            // pipes to a userland handler (apport, systemd-coredump). Acknowledge
            // we may miss the rare crash that gets intercepted by the handler;
            // most C target crashes are SIGSEGV/SIGABRT seen via waitpid anyway.
            .env("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
            // Sanitizers default to "report and continue" which hides findings
            // from AFL's exit-code-based crash detection. abort_on_error turns
            // the first sanitizer report into a SIGABRT that AFL will save.
            // symbolize=0 is required by AFL's pre-flight check so the sanitizer
            // doesn't fork llvm-symbolizer in the hot loop; we re-symbolize
            // ourselves when replaying each crash artifact against the
            // libFuzzer binary later. The operator's inherited `<SAN>_OPTIONS`
            // (suppressions / FP-killers, #435) are MERGED in first; bhf's
            // required keys go last so they win.
            .env(
                "ASAN_OPTIONS",
                multicore_fuzz::merge_sanitizer_options(
                    std::env::var("ASAN_OPTIONS").ok().as_deref(),
                    "abort_on_error=1:halt_on_error=1:symbolize=0",
                ),
            )
            .env(
                "UBSAN_OPTIONS",
                multicore_fuzz::merge_sanitizer_options(
                    std::env::var("UBSAN_OPTIONS").ok().as_deref(),
                    "abort_on_error=1:halt_on_error=1:symbolize=0",
                ),
            )
            .env(
                "LSAN_OPTIONS",
                multicore_fuzz::merge_sanitizer_options(
                    std::env::var("LSAN_OPTIONS").ok().as_deref(),
                    "abort_on_error=1:symbolize=0",
                ),
            )
            // CRITICAL: redirect afl-fuzz's stdout+stderr to a FILE, not a pipe. A
            // piped child blocks on write() once the ~64KB pipe buffer fills, and we
            // only drain it after wait() — so afl-fuzz (which keeps printing status
            // even under AFL_NO_UI) deadlocks after ~20 execs and `auto` hangs forever
            // (the original 69-min wedge). A file never blocks; we read it afterward
            // for the diagnostic hints below. stderr shares the stdout handle (a dup,
            // so they share one file offset and interleave instead of clobbering).
            .stdout(Stdio::from(
                afl_log_file
                    .try_clone()
                    .map_err(|error| format!("dup afl log handle: {error}"))?,
            ))
            .stderr(Stdio::from(afl_log_file));
        for (k, v) in &prepared.extra_env {
            afl_cmd.env(k, v);
        }
        // #412: afl-fuzz stops at its first crash when AFL_BENCH_UNTIL_CRASH is
        // set, whatever its value, so it never runs the rest of its budget.
        afl_cmd.env_remove("AFL_BENCH_UNTIL_CRASH");
        // `symbolize=0` must be re-asserted AFTER `extra_env`, because that map
        // carries the builtin engine's sanitizer options — which deliberately keep
        // symbolization so a crash's file:line can be joined to the static finding at
        // the same line — and it would otherwise overwrite the value set above. AFL++
        // v4 aborts in pre-flight on a custom `ASAN_OPTIONS` without it ("Custom
        // ASAN_OPTIONS set without symbolize=0 - please fix!", afl-fuzz-init.c), so
        // this is the one child that needs the opposite setting. Merging keeps every
        // other key the operator or the builtin path supplied.
        for key in ["ASAN_OPTIONS", "UBSAN_OPTIONS", "LSAN_OPTIONS"] {
            let inherited = prepared
                .extra_env
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .or_else(|| std::env::var(key).ok());
            afl_cmd.env(
                key,
                multicore_fuzz::merge_sanitizer_options(inherited.as_deref(), "symbolize=0"),
            );
        }
        // Issue #45: point `-Q`/`-O` at a non-PATH AFL++ build and scope binary-only
        // instrumentation to the module/ranges of interest.
        if let Some(dir) = &prepared.afl_path {
            afl_cmd.env("AFL_PATH", dir);
        }
        if let Some((env_key, value)) = prepared
            .afl_mode
            .inst_ranges_env_value(&prepared.afl_inst_ranges)
        {
            afl_cmd.env(env_key, value);
        }
        apply_runaway_rlimits(&mut afl_cmd);
        // Run afl-fuzz in its own process group so a hard-deadline kill can take down
        // the WHOLE group — afl-fuzz plus the persistent harness it forked — instead
        // of orphaning the harness (`child.kill()` alone leaves `main_afl` running).
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            afl_cmd.process_group(0);
        }
        Ok(afl_cmd)
    };
    let (statuses, hard_deadline) = loop {
        let mut children = Vec::with_capacity(instances.len());
        for instance in &instances {
            let mut afl_cmd = build_afl_command(instance)?;
            match afl_cmd.spawn() {
                Ok(child) => children.push(child),
                Err(error) => {
                    for child in &mut children {
                        kill_process_group(child);
                        let _ = child.wait();
                    }
                    return Err(format!("spawn afl-fuzz '{}': {error}", afl_fuzz.display()));
                }
            }
        }
        // afl-fuzz is supposed to self-terminate at its `-V` budget, but a
        // fork-server / persistent-mode handshake wedge can leave its internal
        // `run_time` stuck at 0 so the `-V` check never fires and afl-fuzz hangs
        // forever (observed: 20 execs, 69 min wall). A bare `child.wait()` would then
        // block `auto` indefinitely, blowing past `--per-target-time`. Bound the wait
        // with a hard wall-clock deadline (generous margin over the budget) and kill
        // the process groups if exceeded; any crashes found before the wedge are
        // still harvested from each instance's `crashes/` below.
        let hard_deadline =
            Instant::now() + time_budget.saturating_mul(2) + Duration::from_secs(30);
        let mut timed_out = false;
        let mut statuses: Vec<Option<std::process::ExitStatus>> = vec![None; children.len()];
        while statuses.iter().any(Option::is_none) {
            for (child, status) in children.iter_mut().zip(statuses.iter_mut()) {
                if status.is_none() {
                    *status = child
                        .try_wait()
                        .map_err(|error| format!("wait afl-fuzz: {error}"))?;
                }
            }
            if statuses.iter().all(Option::is_some) {
                break;
            }
            if Instant::now() >= hard_deadline {
                timed_out = true;
                for (child, status) in children.iter_mut().zip(statuses.iter_mut()) {
                    if status.is_none() {
                        kill_process_group(child);
                        *status = Some(
                            child
                                .wait()
                                .map_err(|error| format!("reap timed-out afl-fuzz: {error}"))?,
                        );
                    }
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let statuses: Vec<std::process::ExitStatus> = statuses.into_iter().flatten().collect();
        if timed_out {
            // Reap any persistent-mode worker that setsid()'d out of the killed group.
            kill_processes_by_exe(&main_afl);
            bhfeprintln!(
                "bhf: afl-fuzz exceeded its hard deadline ({:?}) and was killed — \
             likely a fork-server/persistent-mode hang; harvesting any crashes found so far",
                time_budget.saturating_mul(2) + Duration::from_secs(30)
            );
        }
        // #275: a session afl-fuzz cannot resume is started over, once, after
        // its queue is taken into bhf's corpus.
        let failed_resume = statuses
            .iter()
            .zip(&instances)
            .find(|(status, _)| status.code().is_some_and(|code| code != 0));
        if let (true, false, Some((_, instance))) = (resuming, timed_out, failed_resume) {
            import_afl_queues(
                &prepared.work_dir,
                &prepared.harness_id,
                &out_dir,
                prepared.max_len,
            );
            bhfeprintln!(
                "bhf: afl-fuzz could not resume the session in {} (see {}); starting it over, \
             with its queue kept in bhf's corpus",
                out_dir.display(),
                instance.log.display()
            );
            fs::remove_dir_all(&out_dir)
                .and_then(|()| fs::create_dir_all(&out_dir))
                .map_err(|error| format!("reset AFL out dir '{}': {error}", out_dir.display()))?;
            resuming = false;
            continue;
        }
        break (statuses, hard_deadline);
    };
    // AFL terminates itself with a signal when the -V time budget expires (or when
    // we hard-kill a hung run above), surfacing as status.code() == None. Treat
    // that as success - it's the *intended* end of a time-bounded run. Real
    // failures show up as a positive exit code.
    let failures: Vec<(String, &AflInstance)> = statuses
        .iter()
        .zip(&instances)
        .filter(|(status, _)| !status.success() && status.code().is_some())
        .map(|(status, instance)| (afl_failure(status, &instance.log), instance))
        .collect();
    let every_seed_aborts = |message: &String| message.is_empty();
    if failures.len() == instances.len()
        && !failures
            .iter()
            .all(|(message, _)| every_seed_aborts(message))
    {
        let (message, _) = failures
            .iter()
            .find(|(message, _)| !every_seed_aborts(message))
            .expect("a failure that is not every seed aborting");
        return Err(message.clone());
    }
    if failures
        .iter()
        .any(|(message, _)| every_seed_aborts(message))
    {
        // GRACEFUL SKIP, not an error: every seed aborts the harness, so
        // afl-fuzz can't start. This is a property of the TARGET (a pervasive
        // sanitizer finding that fires on every input — e.g. a UBSan
        // member-access on tinyexpr's over-allocated nodes), not a bhf
        // failure. afl-fuzz already skips individual crashing seeds; it only
        // aborts when ALL crash. Returning an Err here would emit a scary
        // warning and lose the target; instead fall through to an empty
        // summary. The builtin engine surfaces such crashes directly, so
        // `--engine builtin,afl++` still reports them.
        bhfeprintln!(
            "bhf: afl-fuzz could not start for {} — every seed aborts the \
             harness (a pervasive sanitizer finding that fires on all inputs); \
             skipping AFL for this target. Use `--engine builtin,afl++` so the \
             builtin engine surfaces the crash.",
            prepared.harness_id
        );
    }
    // Some instances ran: the others are reported, and what the ones that
    // ran found is harvested.
    if failures.len() < instances.len() {
        for (message, instance) in failures
            .iter()
            .filter(|(message, _)| !every_seed_aborts(message))
        {
            bhfeprintln!(
                "bhf: warning: afl-fuzz instance {} failed, and the others ran: {message}",
                instance.name
            );
        }
    }
    let elapsed = start.elapsed();

    let sandbox_metadata = prepared.runner.sandbox_metadata();
    let mut ingest = ExternalIngest::new(&prepared, "AFL++", "its own queue", TraceInput::Stdin)?;
    let mut crash_count = 0_usize;
    for path in afl_saved_inputs(&out_dir, "crashes") {
        crash_count += 1;
        let input = fs::read(&path)
            .map_err(|error| format!("read crash artifact '{}': {error}", path.display()))?;
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        ingest.crash(
            &input,
            &format!("crash file {name}"),
            hard_deadline,
            &|input, env, timeout| {
                replay_afl_input(
                    &prepared.harness_path,
                    &prepared.work_dir,
                    input,
                    env,
                    timeout,
                )
            },
        )?;
    }
    // #275: the inputs afl-fuzz saved as hangs. Each is re-run through
    // main_afl with twice afl-fuzz's limit, and one that hangs again is a
    // BHF-230 finding, as a builtin pass's confirmed hang is.
    let mut hangs = HangRunSummary {
        timeout_ms: u64::try_from(AFL_EXEC_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
        ..HangRunSummary::default()
    };
    for path in afl_saved_inputs(&out_dir, "hangs") {
        hangs.observed += 1;
        if hangs.confirmed + hangs.cleared >= MAX_HANG_CONFIRMATIONS {
            hangs.not_rerun += 1;
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_owned();
        let input = fs::read(&path)
            .map_err(|error| format!("read hang artifact '{}': {error}", path.display()))?;
        let (report, log) = match confirm_external_hang(
            &prepared.harness_path,
            &prepared.work_dir,
            &input,
            &prepared.extra_env,
            hard_deadline,
            AFL_EXEC_TIMEOUT,
            TraceInput::Stdin,
        )? {
            HangConfirmation::Hung(report, log) => {
                hangs.confirmed += 1;
                (report, log)
            }
            // Given the time, it crashed: that crash is the finding.
            HangConfirmation::Crashed(report, log) => {
                hangs.cleared += 1;
                (report, log)
            }
            HangConfirmation::Finished => {
                hangs.cleared += 1;
                continue;
            }
            HangConfirmation::NotRerun => {
                hangs.not_rerun += 1;
                continue;
            }
        };
        ingest.hang(&input, &report, &log, &format!("hang file {name}"))?;
    }
    // What a resumed session moved aside has been harvested with the rest.
    remove_afl_backups(&out_dir);
    let corpus_persisted = import_afl_queues(
        &prepared.work_dir,
        &prepared.harness_id,
        &out_dir,
        prepared.max_len,
    );

    let elapsed_secs = elapsed.as_secs_f64();
    // Surface AFL's REAL throughput from its own stats file rather than reporting
    // `executions` as the crash count (which made run.json show afl++ passes as
    // `execs=1, edges=0` even on a productive run). Fall back to the crash count
    // only when afl-fuzz wrote no stats (e.g. it aborted before the first cycle).
    let (afl_execs_done, afl_execs_per_sec) = parse_afl_fuzzer_stats(&out_dir);
    let coverage = coverage_from_env(&prepared.extra_env, &prepared.harness_path);
    let summary = FuzzRunSummary {
        schema_version: 1,
        harness_id: prepared.harness_id.clone(),
        engine: "afl++".to_owned(),
        mode: prepared.mode,
        harness_path: prepared.harness_path.clone(),
        sandbox: sandbox_metadata,
        iterations_requested: prepared.iterations,
        executions: afl_execs_done.map(|n| n as usize).unwrap_or(crash_count),
        target_entry_observed: target_entry_from_env(&prepared.extra_env),
        corpus_new: crash_count,
        corpus_duplicates: 0,
        // AFL++'s queue, taken into the bhf corpus (#275).
        corpus_persisted,
        execution: afl_execution_summary(),
        cmplog: cmplog_summary,
        sanitizers: sanitizer_summary(&prepared.sanitizers, &prepared.sanitizer_env, false),
        coverage,
        findings: ingest.finding_ids.clone(),
        duplicates_of_existing: Vec::new(),
        duplicate_crashes_of_existing: 0,
        elapsed_secs,
        // AFL++ owns its own loop; its real per-second throughput comes from
        // `out/default/fuzzer_stats` (`execs_per_sec`). 0.0 only when afl-fuzz
        // wrote no stats.
        executions_per_sec: afl_execs_per_sec.unwrap_or(0.0),
        afl: Some(AflRunProvenance {
            mode: prepared.afl_mode.as_str().to_owned(),
            afl_path: prepared.afl_path.clone(),
            inst_ranges: prepared.afl_inst_ranges.clone(),
            cmplog_binary,
            instances: if instances.len() > 1 {
                instances
                    .iter()
                    .map(|instance| instance.name.clone())
                    .collect()
            } else {
                Vec::new()
            },
        }),
        winafl: None,
        // The extension `oracle.evaluate` pass is a builtin-engine feature
        // (it iterates the builtin pool's retained corpus); AFL++ owns its own
        // on-disk queue, so `--extension` is not driven here.
        extension: None,
        duplicate_sanitizer_hits: ingest.dedup.duplicate_hits(),
        unreproduced_sanitizer_hits: ingest.dedup.unreproduced_hits(),
        fresh_reruns: None,
        hangs: (hangs.observed > 0).then_some(hangs),
        stability: None,
        symcc: None,
    };
    write_run_summary(&prepared.work_dir, &summary)?;
    Ok(summary)
}

const MAX_HARNESS_MARKER_TEXT_BYTES: u64 = 1024 * 1024;

/// Inspect only bounded text. The executable probe rejects binary-looking
/// prefixes before decoding, so a large ELF is never loaded as a UTF-8 string.
fn read_bounded_marker_text(path: &Path, executable: bool) -> Option<String> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_HARNESS_MARKER_TEXT_BYTES {
        return None;
    }
    let mut file = fs::File::open(path).ok()?;
    if executable {
        let mut prefix = [0u8; 4096];
        let read = file.read(&mut prefix).ok()?;
        if prefix[..read].contains(&0) || std::str::from_utf8(&prefix[..read]).is_err() {
            return None;
        }
        file.seek(SeekFrom::Start(0)).ok()?;
    }
    let mut bytes = Vec::new();
    file.take(MAX_HARNESS_MARKER_TEXT_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_HARNESS_MARKER_TEXT_BYTES {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// Resolve the protocol with the detector `bhf replay` and `bhf minimize` share
/// ([`crate::protocol_detect::detect`]). BHF's generated C source defines
/// `LLVMFuzzerTestOneInput` *and* its own `BHF_FRAMED` main, so source
/// existence alone never overrides the marker.
fn resolve_harness_protocol(
    runner: &replay_min::HarnessRunner,
    work_dir: &Path,
) -> HarnessProtocol {
    crate::protocol_detect::detect(runner.harness_path(), &[work_dir]).protocol
}

/// What to tell the operator about a `-fsanitize=fuzzer` binary that has no bhf
/// driver: bhf runs it on one input file per process (so a crash it finds is
/// the input that caused it), but without bhf's runtime there is no coverage
/// guidance. Wrapping the fuzz target in bhf's driver gives both.
fn libfuzzer_binary_note(
    detection: &crate::protocol_detect::Detection,
    harness: &Path,
) -> Option<String> {
    (detection.basis == crate::protocol_detect::ProtocolBasis::LibFuzzerBinary).then(|| {
        format!(
            "{} is a libFuzzer (-fsanitize=fuzzer) binary without bhf's driver: bhf runs it \
             on one input file per process, without coverage guidance. For coverage-guided \
             fuzzing, wrap the fuzz target with `bhf generate-harness <fuzz_target.cc> \
             --target LLVMFuzzerTestOneInput`, build that harness and fuzz it instead.",
            harness.display()
        )
    })
}

/// Whether this is an Ada harness whose target+harness compile was instrumented
/// with `-fsanitize-coverage=trace-pc` and linked against the AdaFuzz trace-pc
/// callback (#412). `build.rs` writes a sentinel into the harness `build/<id>`
/// dir exactly when it added the flag, so this is true iff the AdaFuzz runtime is
/// actively writing the BHF_COV_SHM edge bitmap. The harness binary lives at
/// `build/<id>/obj/main`, so the sentinel is two levels up. Keyed on the sentinel
/// (not the C-driver markers) so it can never flip C/C++ harness behavior, and so
/// a GNAT that lacks trace-pc (no sentinel) cleanly degrades to no coverage.
/// The Ada harness's own build (`build/<id>/obj/main`) beside its AFL++ build
/// (`build/<id>/main_afl`, #304), if `harness` is one.
fn ada_main_beside_afl(harness: &Path) -> Option<PathBuf> {
    let build_dir = harness.parent()?;
    let main = build_dir.join("obj").join("main");
    (harness.file_name().is_some_and(|name| name == "main_afl")
        && build_dir.join(crate::build::ADA_COV_SENTINEL).is_file()
        && main.is_file())
    .then_some(main)
}

fn is_instrumented_ada_harness(runner: &replay_min::HarnessRunner) -> bool {
    // `build/<id>/obj/main`, or the AFL++ build staged in `build/<id>/` (#304).
    runner
        .harness_path()
        .ancestors()
        .skip(1)
        .take(2)
        .any(|dir| dir.join(crate::build::ADA_COV_SENTINEL).is_file())
}

/// Hard cap on a single libFuzzer-binary invocation. A fuzz input that
/// causes the target to loop forever (algorithmic complexity, parser
/// backtracking blowup) would otherwise hang the whole \`bhf fuzz\`
/// run indefinitely. 10s is generous - any well-behaved input
/// completes in milliseconds, and the harness is invoked once per
/// iteration so the overall fuzz budget caps total wall time anyway.
pub(crate) const PER_INPUT_TIMEOUT: Duration = Duration::from_secs(10);

/// A target controls its own diagnostics. Keep enough from both ends for a
/// sanitizer header and final stack/summary, but never let a chatty execution
/// grow the parent process without bound.
fn max_captured_stderr_bytes() -> usize {
    crate::resource_limits::dynamic_bytes(
        "BHF_MAX_HARNESS_OUTPUT_BYTES",
        1024,
        4 * crate::resource_limits::MIB,
        4 * crate::resource_limits::MIB,
        64 * crate::resource_limits::MIB,
    )
}

/// Maximum event-log data admitted from one execution. The event runtime is
/// normally tiny, but the scanned program is untrusted and can inherit or write
/// the advertised path itself.
fn max_event_delta_bytes() -> u64 {
    crate::resource_limits::dynamic_bytes(
        "BHF_MAX_EVENT_DELTA_BYTES",
        512,
        16 * crate::resource_limits::MIB,
        16 * crate::resource_limits::MIB,
        256 * crate::resource_limits::MIB,
    ) as u64
}

fn read_bounded_head_tail(mut reader: impl Read, cap: usize) -> Vec<u8> {
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
                let remove = excess.min(tail.len());
                tail.drain(..remove);
                truncated = true;
                if bytes.len() > tail_cap {
                    bytes = &bytes[bytes.len() - tail_cap..];
                }
            }
            tail.extend(bytes);
        }
    }
    if truncated {
        head.extend_from_slice(b"\n[bhf: diagnostic output truncated]\n");
    }
    head.extend(tail);
    head
}

fn read_bounded_file_head_tail(path: &Path, cap: usize) -> std::io::Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len <= cap as u64 {
        let mut bytes = Vec::with_capacity(len as usize);
        (&mut file).take(cap as u64).read_to_end(&mut bytes)?;
        return Ok(bytes);
    }

    let head_cap = cap / 2;
    let tail_cap = cap.saturating_sub(head_cap);
    let mut bytes = Vec::with_capacity(cap.saturating_add(48));
    (&mut file).take(head_cap as u64).read_to_end(&mut bytes)?;
    bytes.extend_from_slice(b"\n[bhf: AFL output truncated]\n");
    file.seek(SeekFrom::Start(len.saturating_sub(tail_cap as u64)))?;
    (&mut file).take(tail_cap as u64).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn drain_child_stderr(
    stderr: Option<std::process::ChildStderr>,
) -> Option<std::thread::JoinHandle<Vec<u8>>> {
    let limit = max_captured_stderr_bytes();
    stderr.map(|pipe| std::thread::spawn(move || read_bounded_head_tail(pipe, limit)))
}

fn collected_child_output(
    status: std::process::ExitStatus,
    stderr: Option<std::thread::JoinHandle<Vec<u8>>>,
) -> std::process::Output {
    std::process::Output {
        status,
        stdout: Vec::new(),
        stderr: stderr
            .and_then(|reader| reader.join().ok())
            .unwrap_or_default(),
    }
}

/// How often a per-spawn run samples the child's RSS when `--rss-limit-mb` is
/// set. Without a limit the wait blocks until the child exits.
const PER_SPAWN_RSS_SAMPLE_INTERVAL: Duration = Duration::from_millis(20);
/// How often a cancellable per-spawn run (a background fresh re-run) checks
/// whether it was cancelled.
const PER_SPAWN_CANCEL_CHECK_INTERVAL: Duration = Duration::from_millis(50);

/// How a per-spawn run starts and waits for its process, beyond the plain run.
#[derive(Clone, Copy, Default)]
struct SpawnTweaks<'a> {
    /// Start the process at a lower priority than bhf's (nice +10 on Unix,
    /// below-normal priority class on Windows).
    low_priority: bool,
    /// Kill the process and return an error once this is set.
    cancel: Option<&'a std::sync::atomic::AtomicBool>,
    /// Once this is set, return a lowered process to normal priority where
    /// the platform allows it (Windows; an unprivileged Unix process cannot
    /// undo a nice).
    restore_priority: Option<&'a std::sync::atomic::AtomicBool>,
    /// At the timeout, first ask the process for its stack (#207): on Unix,
    /// SIGABRT, which a sanitizer runtime armed with `handle_abort=1` answers
    /// with the stack it was interrupted at, then up to this long for it to
    /// finish printing before the process group is killed.
    stack_on_timeout: Option<Duration>,
}

/// How much lower than bhf's own a background re-run's process runs on Unix.
#[cfg(unix)]
const LOWER_PRIORITY_NICE: libc::c_int = 10;

/// Start `command`'s process at a lower priority than bhf's: it then takes
/// a CPU only when the fuzz loop and the harness it drives leave one idle.
#[cfg(unix)]
fn lower_spawn_priority(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: nice(2) is async-signal-safe and touches only the new process.
    unsafe {
        command.pre_exec(|| {
            libc::nice(LOWER_PRIORITY_NICE);
            Ok(())
        });
    }
}

/// Windows priority classes, lowest first, and what bhf does with them: a
/// background re-run starts one class below bhf's own and is returned to
/// bhf's own, so it gives way to the fuzz loop whatever class bhf runs at. A
/// BelowNormal bhf (the GitHub runner's worker starts its steps there) made a
/// fixed BelowNormal re-run no lower than the loop, and a fixed Normal restore
/// raised it above bhf.
#[cfg(any(windows, test))]
mod priority_class {
    pub(super) const IDLE: u32 = 0x0000_0040;
    pub(super) const BELOW_NORMAL: u32 = 0x0000_4000;
    pub(super) const NORMAL: u32 = 0x0000_0020;
    pub(super) const ABOVE_NORMAL: u32 = 0x0000_8000;
    pub(super) const HIGH: u32 = 0x0000_0080;
    pub(super) const REALTIME: u32 = 0x0000_0100;
    const ORDER: [u32; 6] = [IDLE, BELOW_NORMAL, NORMAL, ABOVE_NORMAL, HIGH, REALTIME];

    /// The class one below `class` (Idle stays Idle); an unknown class is
    /// taken for Normal.
    pub(super) fn lowered(class: u32) -> u32 {
        match ORDER.iter().position(|known| *known == class) {
            Some(at) => ORDER[at.saturating_sub(1)],
            None => BELOW_NORMAL,
        }
    }

    /// The class Windows gives a process created without a class flag by a
    /// parent of `class`: the parent's when it is Idle or BelowNormal, else
    /// Normal.
    #[cfg(test)]
    pub(super) fn inherited(class: u32) -> u32 {
        if class == IDLE || class == BELOW_NORMAL {
            class
        } else {
            NORMAL
        }
    }

    /// `class` as `Get-Process` names it.
    #[cfg(test)]
    pub(super) fn name(class: u32) -> &'static str {
        match class {
            IDLE => "Idle",
            BELOW_NORMAL => "BelowNormal",
            ABOVE_NORMAL => "AboveNormal",
            HIGH => "High",
            REALTIME => "RealTime",
            _ => "Normal",
        }
    }
}

/// This process's priority class.
#[cfg(windows)]
fn own_priority_class() -> u32 {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut std::ffi::c_void;
        fn GetPriorityClass(process: *mut std::ffi::c_void) -> u32;
    }
    // SAFETY: the pseudo-handle of this process needs no closing.
    match unsafe { GetPriorityClass(GetCurrentProcess()) } {
        0 => priority_class::NORMAL,
        class => class,
    }
}

#[cfg(windows)]
fn lower_spawn_priority(command: &mut std::process::Command) {
    use std::os::windows::process::CommandExt;
    command.creation_flags(priority_class::lowered(own_priority_class()));
}

#[cfg(not(any(unix, windows)))]
fn lower_spawn_priority(_command: &mut std::process::Command) {}

/// Return a process [`lower_spawn_priority`] started to bhf's own priority
/// class: on Windows, before it is killed (a starved process is slow to
/// finish dying) and once the loop it gave way to has stopped. A Unix process
/// cannot raise a nice value back without privilege, so there it stays
/// lowered.
#[cfg(windows)]
fn restore_spawn_priority(child: &std::process::Child) {
    use std::os::windows::io::AsRawHandle;
    #[link(name = "kernel32")]
    extern "system" {
        fn SetPriorityClass(process: *mut std::ffi::c_void, class: u32) -> i32;
    }
    let class = own_priority_class();
    // SAFETY: the handle is the live child's, owned by `child`.
    let restored = unsafe { SetPriorityClass(child.as_raw_handle().cast(), class) };
    if restored == 0 {
        // A re-run left lowered only finishes later; say why, once per
        // process, rather than fail the run.
        static WARNED: std::sync::Once = std::sync::Once::new();
        let error = std::io::Error::last_os_error();
        WARNED.call_once(|| {
            bhfeprintln!(
                "bhf fuzz: warning: could not return a background re-run (pid {}) to bhf's priority: {error}",
                child.id()
            );
        });
    }
}

#[cfg(not(windows))]
fn restore_spawn_priority(_child: &std::process::Child) {}

/// The longest a timed-out process has, once asked for its stack, to print
/// it and exit before it is killed. A sanitizer symbolizes the stack first.
const HANG_STACK_GRACE: Duration = Duration::from_secs(5);

/// Ask a timed-out process for the stack it is running (SIGABRT, which a
/// sanitizer runtime with `handle_abort=1` reports with its stack), and wait
/// up to `grace` for it to exit. The child is left unreaped, so
/// its pid, which is also its process group's id, cannot be reused before the
/// caller kills the group.
#[cfg(target_os = "linux")]
fn signal_for_stack(child: &mut std::process::Child, grace: Duration) {
    let Ok(pid) = libc::pid_t::try_from(child.id()) else {
        return;
    };
    // SAFETY: kill(2) on the child's pid, which is not reaped yet.
    if unsafe { libc::kill(pid, libc::SIGABRT) } != 0 {
        return;
    }
    let until = Instant::now() + grace;
    while Instant::now() < until {
        // SAFETY: an all-zero siginfo_t is valid; waitid(2) with WNOWAIT only
        // reports the child's state.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        // SAFETY: waitid filled `info` (or left it zeroed: still running).
        if rc != 0 || unsafe { info.si_pid() } != 0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// [`signal_for_stack`] where `waitid(WNOWAIT)` is not available: the wait
/// reaps the child.
#[cfg(all(unix, not(target_os = "linux")))]
fn signal_for_stack(child: &mut std::process::Child, grace: Duration) {
    let Ok(pid) = libc::pid_t::try_from(child.id()) else {
        return;
    };
    // SAFETY: kill(2) on the child's pid, which is not reaped yet.
    if unsafe { libc::kill(pid, libc::SIGABRT) } == 0 {
        let _ = replay_min::process::wait_exit_within(child, grace);
    }
}

/// Windows has no signal a process can answer with its stack: the hang is
/// reported without one.
#[cfg(not(unix))]
fn signal_for_stack(_child: &mut std::process::Child, _grace: Duration) {}

/// Run `harness_path <input_path>` with a wall-clock timeout. On
/// timeout, kill the process and return a synthetic exit status plus
/// a marker on stderr so the caller can distinguish hang-vs-crash. A run
/// whose MSan runtime could not start (see
/// [`crate::auto::msan::msan_could_not_start`]) never ran the input, and is
/// run again.
#[allow(clippy::too_many_arguments)]
fn run_with_timeout(
    harness_path: &Path,
    input_path: &Path,
    timeout: Duration,
    extra_env: &[(String, String)],
    scratch: &Path,
    rss_limit_mb: usize,
    qemu_prefix: Option<(&Path, &[String])>,
    tweaks: SpawnTweaks<'_>,
) -> Result<std::process::Output, String> {
    let mut attempt = 1;
    loop {
        let output = run_with_timeout_once(
            harness_path,
            input_path,
            timeout,
            extra_env,
            scratch,
            rss_limit_mb,
            qemu_prefix,
            tweaks,
        )?;
        if attempt == crate::auto::msan::MSAN_START_ATTEMPTS
            || !crate::auto::msan::msan_could_not_start(&output.stderr)
        {
            return Ok(output);
        }
        attempt += 1;
    }
}

/// One run of [`run_with_timeout`].
#[allow(clippy::too_many_arguments)]
fn run_with_timeout_once(
    harness_path: &Path,
    input_path: &Path,
    timeout: Duration,
    extra_env: &[(String, String)],
    scratch: &Path,
    rss_limit_mb: usize,
    qemu_prefix: Option<(&Path, &[String])>,
    tweaks: SpawnTweaks<'_>,
) -> Result<std::process::Output, String> {
    // A foreign-arch harness runs under qemu-user (`qemu-aarch64 [args] harness
    // input`); the host path keeps the exact direct `harness input` invocation.
    let mut timeout_cmd = match qemu_prefix {
        Some((program, args)) => {
            let mut cmd = std::process::Command::new(program);
            cmd.args(args).arg(harness_path);
            // A crash under the emulator must not make it dump its own
            // address space.
            replay_min::process::disable_core_dumps(&mut cmd);
            cmd
        }
        // An interpreted lane's harness where its launcher cannot run (#305).
        None => match crate::launch_spec::launch_for(harness_path) {
            Some(launch) => {
                let mut cmd = std::process::Command::new(&launch.program);
                cmd.args(&launch.args);
                cmd.envs(launch.env.iter().map(|(key, value)| (key, value)));
                cmd
            }
            None => std::process::Command::new(harness_path),
        },
    };
    timeout_cmd
        .current_dir(scratch)
        .arg(input_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        timeout_cmd.env(k, v);
    }
    apply_runaway_rlimits(&mut timeout_cmd);
    if tweaks.low_priority {
        lower_spawn_priority(&mut timeout_cmd);
    }
    let mut child = timeout_cmd.spawn().map_err(|error| {
        format!(
            "failed to start harness '{}': {error}",
            harness_path.display()
        )
    })?;
    let stderr_reader = drain_child_stderr(child.stderr.take());
    let mut lowered = tweaks.low_priority;

    let deadline = Instant::now() + timeout;
    loop {
        // Block until the child exits, or until the next check is due: the
        // deadline, the next RSS sample when a limit is set, or the next look
        // at the cancel and priority flags when there are any.
        let mut wait = deadline.saturating_duration_since(Instant::now());
        if rss_limit_mb > 0 {
            wait = wait.min(PER_SPAWN_RSS_SAMPLE_INTERVAL);
        }
        if tweaks.cancel.is_some() || (lowered && tweaks.restore_priority.is_some()) {
            wait = wait.min(PER_SPAWN_CANCEL_CHECK_INTERVAL);
        }
        match replay_min::process::wait_exit_within(&mut child, wait) {
            Ok(Some(status)) => return Ok(collected_child_output(status, stderr_reader)),
            Ok(None) => {
                if lowered
                    && tweaks
                        .restore_priority
                        .is_some_and(|restore| restore.load(std::sync::atomic::Ordering::SeqCst))
                {
                    restore_spawn_priority(&child);
                    lowered = false;
                }
                if tweaks
                    .cancel
                    .is_some_and(|cancel| cancel.load(std::sync::atomic::Ordering::SeqCst))
                {
                    if lowered {
                        restore_spawn_priority(&child);
                    }
                    kill_process_group(&mut child);
                    let _ = child.wait();
                    let _ = stderr_reader.and_then(|reader| reader.join().ok());
                    return Err(format!(
                        "the run of harness '{}' was cancelled",
                        harness_path.display()
                    ));
                }
                if Instant::now() >= deadline {
                    if lowered {
                        restore_spawn_priority(&child);
                    }
                    if let Some(grace) = tweaks.stack_on_timeout {
                        signal_for_stack(&mut child, grace);
                    }
                    kill_process_group(&mut child);
                    let status = child.wait().map_err(|error| {
                        format!(
                            "failed to reap timed-out harness '{}': {error}",
                            harness_path.display()
                        )
                    })?;
                    let mut output = collected_child_output(status, stderr_reader);
                    let marker = format!(
                        "\nbhf: harness exceeded per-input timeout of {:?} - killed\n",
                        timeout
                    );
                    output.stderr.extend_from_slice(marker.as_bytes());
                    return Ok(output);
                }
                if rss_limit_mb > 0 {
                    if let Some(rss) = process_rss_mb(child.id()) {
                        if rss > rss_limit_mb {
                            kill_process_group(&mut child);
                            let status = child.wait().map_err(|error| {
                                format!(
                                    "failed to reap OOM harness '{}': {error}",
                                    harness_path.display()
                                )
                            })?;
                            let mut output = collected_child_output(status, stderr_reader);
                            let marker = format!(
                                "\nbhf: harness exceeded RSS limit of {rss_limit_mb} MB \
                                 (used {rss} MB) - killed\n"
                            );
                            output.stderr.extend_from_slice(marker.as_bytes());
                            return Ok(output);
                        }
                    }
                }
            }
            Err(error) => {
                kill_process_group(&mut child);
                let _ = child.wait();
                let _ = stderr_reader.and_then(|reader| reader.join().ok());
                return Err(format!(
                    "failed to poll harness '{}': {error}",
                    harness_path.display()
                ));
            }
        }
    }
}

/// Write `input` to a file of its own under `work_dir/fuzz_inputs`, for a
/// harness that reads its input from the file named on its command line.
fn write_fuzz_input(work_dir: &Path, input: &[u8]) -> Result<PathBuf, String> {
    let tmp_dir = work_dir.join("fuzz_inputs");
    fs::create_dir_all(&tmp_dir)
        .map_err(|error| format!("create fuzz inputs dir '{}': {error}", tmp_dir.display()))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // A sequence number too: fresh-process re-runs write inputs from a second
    // thread, and two writes can share a clock reading.
    static INPUT_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = INPUT_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let input_path = tmp_dir.join(format!("input-{}-{}-{seq}.bin", std::process::id(), nonce));
    fs::write(&input_path, input)
        .map_err(|error| format!("write fuzz input '{}': {error}", input_path.display()))?;
    Ok(input_path)
}

fn run_c_libfuzzer_single_input(
    runner: &replay_min::HarnessRunner,
    work_dir: &Path,
    input: &[u8],
    extra_env: &[(String, String)],
    per_input_timeout: Duration,
    rss_limit_mb: usize,
    deadline: Option<Duration>,
) -> Result<HarnessRun, String> {
    run_c_libfuzzer_single_input_in(
        runner,
        work_dir,
        &ensure_harness_scratch(work_dir)?,
        input,
        extra_env,
        per_input_timeout,
        rss_limit_mb,
        deadline,
        SpawnTweaks::default(),
    )
}

/// [`run_c_libfuzzer_single_input`] with the process started in `scratch`
/// and with `tweaks`.
#[allow(clippy::too_many_arguments)]
fn run_c_libfuzzer_single_input_in(
    runner: &replay_min::HarnessRunner,
    work_dir: &Path,
    scratch: &Path,
    input: &[u8],
    extra_env: &[(String, String)],
    per_input_timeout: Duration,
    rss_limit_mb: usize,
    deadline: Option<Duration>,
    tweaks: SpawnTweaks<'_>,
) -> Result<HarnessRun, String> {
    let input_path = write_fuzz_input(work_dir, input)?;

    // Measure the host-side wall clock for the deadline oracle (deliverable 1).
    // `run_with_timeout` already enforces `per_input_timeout` as the hang-kill
    // backstop; the deadline oracle is a *finer* "must respond within D" budget
    // (D <= per_input_timeout) whose overrun is a finding rather than a discard.
    let exec_start = Instant::now();
    let output = run_with_timeout(
        runner.harness_path(),
        &input_path,
        per_input_timeout,
        extra_env,
        scratch,
        rss_limit_mb,
        runner.qemu_prefix(),
        tweaks,
    );
    let elapsed = exec_start.elapsed();
    let output = output.inspect_err(|_| {
        let _ = fs::remove_file(&input_path);
    })?;
    let _ = fs::remove_file(&input_path);

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Deadline oracle (opt-in; unchanged when `deadline` is None). A run that
    // overran the response budget D is a real BHF-555 timing finding, NOT the
    // silent kill-and-skip the hang backstop applies. This fires whether the run
    // completed slowly (status success, past the `!success()` branch below) or was
    // killed at the hang backstop (which also means it overran D, since
    // D <= per_input_timeout). A genuine sanitizer crash keeps priority: a real
    // memory-safety report is higher-fidelity than "it was slow", so the deadline
    // finding is only synthesized when there is no sanitizer report to surface.
    if let Some(deadline) = deadline {
        if elapsed > deadline && corpus::parse_sanitizer_report(&stderr).is_none() {
            // Announced only once fresh re-runs confirm it (#209).
            let overrun = deadline_overrun(deadline, elapsed);
            return Ok(HarnessRun {
                events: Vec::new(),
                testcases: Vec::new(),
                sanitizer: Some(corpus::SanitizerReport {
                    // Synthesized like the RSS-limit OOM report: the rule_id is what
                    // classifies it, and there is no real sanitizer stack to attach.
                    // No sanitizer ran, so the provenance is None — not a false
                    // `asan` tag (#78).
                    sanitizer: None,
                    kind: "response-deadline-exceeded".to_owned(),
                    // A real catalog rule (CWE-400 timing/availability) so it dedups,
                    // replays, and reports like any other finding.
                    rule_id: RESPONSE_DEADLINE_RULE,
                    stack: Vec::new(),
                    message: format!("harness {overrun}"),
                    ..Default::default()
                }),
                stderr: None,
                rejected: false,
                hung: None,
            });
        }
    }
    if !output.status.success() {
        if let Some(error) = runtime_start_failure_error(runner, &stderr) {
            return Err(error);
        }
        if let Some(report) = corpus::parse_sanitizer_report(&stderr) {
            return Ok(HarnessRun {
                events: Vec::new(),
                testcases: Vec::new(),
                sanitizer: Some(report),
                stderr: Some(stderr.to_string()),
                rejected: false,
                hung: None,
            });
        }
        // A timed-out input is not a fuzz failure - it just means this
        // particular input didn't produce a useful signal in the budget.
        // Skip it and let the next iteration mutate further. Real
        // non-zero exits without a sanitizer report still bubble up.
        // An input that blew past the RSS ceiling is a reportable out-of-memory
        // finding (libFuzzer saves OOM units), surfaced via a synthesized report.
        if stderr.contains("exceeded RSS limit") {
            return Ok(HarnessRun {
                events: Vec::new(),
                testcases: Vec::new(),
                sanitizer: Some(rss_limit_report()),
                stderr: None,
                rejected: false,
                hung: None,
            });
        }
        if stderr.contains("exceeded per-input timeout") {
            bhfeprintln!("bhf: input hung beyond {:?}", per_input_timeout);
            return Ok(HarnessRun {
                events: Vec::new(),
                testcases: Vec::new(),
                sanitizer: None,
                stderr: None,
                rejected: false,
                hung: Some(per_input_timeout),
            });
        }
        // Hands-off robustness (#15): a diagnosed assertion/panic SIGABRT or a
        // non-zero error return with NO sanitizer report is the target REJECTING
        // this input (e.g. cute_aseprite's `assert(magic == 0xA5E0)`). Treat it
        // like a timeout — a clean no-finding run flagged `rejected` so the pass
        // keeps exploring past the bad input.
        if is_input_rejection(&output.status, &stderr) {
            return Ok(HarnessRun {
                events: Vec::new(),
                testcases: Vec::new(),
                sanitizer: None,
                stderr: None,
                rejected: true,
                hung: None,
            });
        }
        // A genuine crash SIGNAL (silent SIGABRT/SIGSEGV/SIGBUS/SIGILL/SIGFPE) with no sanitizer
        // report is still a reachable crash on THIS input — record it as a BHF-210
        // finding so it surfaces and the cascade keeps fuzzing, rather than a hard
        // error that aborts the whole pass (which left targets whose empty/early
        // seed crashes, e.g. cute_tiled, reported "built, not fuzzed" with the
        // crash lost). A real ASan/UBSan bug is still classified precisely by its
        // report above; this is the fallback for an unlocalized signal crash.
        return Ok(HarnessRun {
            events: Vec::new(),
            testcases: Vec::new(),
            sanitizer: Some(fatal_signal_report(&output.status, &stderr)),
            stderr: Some(stderr.to_string()),
            rejected: false,
            hung: None,
        });
    }
    Ok(HarnessRun {
        events: Vec::new(),
        testcases: Vec::new(),
        sanitizer: None,
        stderr: None,
        rejected: false,
        hung: None,
    })
}

fn load_cmplog_for_run(
    path: Option<&Path>,
    seeds: &[Vec<u8>],
) -> (Option<cmplog::CmpLog>, CmpLogRunSummary) {
    let Some(path) = path else {
        return (
            None,
            CmpLogRunSummary {
                enabled: false,
                status: "disabled".to_owned(),
                log_path: None,
                entries: 0,
                dictionary_tokens: 0,
                seed_splice_candidates: 0,
            },
        );
    };
    match cmplog::ingest_from_jsonl_log(path) {
        Ok(log) => {
            let dictionary_tokens = log.dictionary_tokens().len();
            let seed_splice_candidates = seeds
                .iter()
                .map(|seed| log.splice_candidates(seed).len())
                .sum();
            let entries = log.entries.len();
            (
                Some(log),
                CmpLogRunSummary {
                    enabled: true,
                    status: "loaded".to_owned(),
                    log_path: Some(path.to_path_buf()),
                    entries,
                    dictionary_tokens,
                    seed_splice_candidates,
                },
            )
        }
        Err(error) => {
            bhfeprintln!(
                "warning: failed to ingest cmplog log {}: {error}; falling back to empty dictionary",
                path.display()
            );
            (
                None,
                CmpLogRunSummary {
                    enabled: true,
                    status: "failed".to_owned(),
                    log_path: Some(path.to_path_buf()),
                    entries: 0,
                    dictionary_tokens: 0,
                    seed_splice_candidates: 0,
                },
            )
        }
    }
}

fn builtin_execution_summary(
    protocol: HarnessProtocol,
    forkserver_started: bool,
) -> ExecutionRunSummary {
    let harness_protocol = match protocol {
        HarnessProtocol::BhfFramed => "bhf_framed",
        HarnessProtocol::LibFuzzerSingleInput => "libfuzzer_single_input",
        HarnessProtocol::StdinEventLog => "stdin_event_log",
    };
    ExecutionRunSummary {
        harness_protocol: harness_protocol.to_owned(),
        forkserver: forkserver_started,
        persistent: forkserver_started,
        persistent_iterations: None,
    }
}

fn afl_execution_summary() -> ExecutionRunSummary {
    ExecutionRunSummary {
        harness_protocol: "afl++_persistent_stdin".to_owned(),
        forkserver: true,
        persistent: true,
        persistent_iterations: Some(10_000),
    }
}

pub(crate) fn parse_sanitizer_args(
    values: &[String],
) -> Result<multicore_fuzz::SanitizerSelection, String> {
    use multicore_fuzz::SanitizerSelection;
    // `none` (#434): build native crash-only + coverage with no `-fsanitize=`.
    // It is a standalone choice — mixing it with real sanitizers is contradictory.
    if values.iter().any(|v| v.eq_ignore_ascii_case("none")) {
        if values.len() > 1 {
            return Err("`--sanitizers none` cannot be combined with other sanitizers".to_owned());
        }
        return Ok(SanitizerSelection::None);
    }
    if values.is_empty() {
        return Ok(SanitizerSelection::Default);
    }
    let mut out = Vec::new();
    for value in values {
        if let Some(lane) = crate::auto::sanitizer_replay::ReplayLane::parse(value) {
            return Err(format!(
                "--sanitizers {lane}: it runs as a corpus replay through a build of its own, \
                 which `bhf auto --sanitizers {lane}` does after its fuzz passes; `bhf fuzz` \
                 fuzzes one build",
                lane = lane.as_str()
            ));
        }
        let Some(sanitizer) = multicore_fuzz::Sanitizer::parse(value) else {
            return Err(format!(
                "unknown sanitizer '{value}' (expected asan, hwasan, msan, ubsan, tsan, lsan, or \
                 none; `bhf auto` also takes cfi and realtime)"
            ));
        };
        if !out.contains(&sanitizer) {
            out.push(sanitizer);
        }
    }
    hwasan_host_check(&out, std::env::consts::ARCH)?;
    // HWASan replaces ASan's shadow memory with pointer tags: clang refuses
    // `-fsanitize=address,hwaddress`.
    if out.contains(&multicore_fuzz::Sanitizer::Hwasan)
        && out.contains(&multicore_fuzz::Sanitizer::Asan)
    {
        return Err(
            "--sanitizers: hwasan cannot be combined with asan: it finds the same memory \
             errors with pointer tags in place of ASan's shadow memory; pick one"
                .to_owned(),
        );
    }
    // MemorySanitizer and ThreadSanitizer each need a build of their own: no
    // other sanitizer links beside either (clang refuses
    // `-fsanitize=address,memory`), so every target would fail to build.
    for exclusive in [
        multicore_fuzz::Sanitizer::Msan,
        multicore_fuzz::Sanitizer::Tsan,
    ] {
        if out.contains(&exclusive) && out.len() > 1 {
            let others: Vec<&str> = out
                .iter()
                .filter(|sanitizer| **sanitizer != exclusive)
                .map(|sanitizer| sanitizer.as_str())
                .collect();
            return Err(format!(
                "--sanitizers: {} cannot be combined with {}: it needs a build of its own; \
                 run it as a separate campaign (`--sanitizers {}`)",
                exclusive.as_str(),
                others.join(", "),
                exclusive.as_str()
            ));
        }
    }
    Ok(SanitizerSelection::Set(out))
}

/// HWAddressSanitizer (#333) needs an AArch64 host: it keeps a tag in each
/// pointer's top byte, which AArch64 ignores on every load and store (Top
/// Byte Ignore) and other architectures do not, so its build fails or its
/// runtime does not start anywhere else. `arch` is the host's.
fn hwasan_host_check(sanitizers: &[multicore_fuzz::Sanitizer], arch: &str) -> Result<(), String> {
    if !sanitizers.contains(&multicore_fuzz::Sanitizer::Hwasan) || arch == "aarch64" {
        return Ok(());
    }
    Err(format!(
        "--sanitizers hwasan needs an AArch64 host: HWAddressSanitizer keeps a tag in each \
         pointer's top byte, which AArch64 ignores on every access and {arch} does not. Use \
         --sanitizers asan on this host, or run on an AArch64 host"
    ))
}

fn sanitizer_env_for(sanitizers: &[multicore_fuzz::Sanitizer]) -> Vec<(String, String)> {
    multicore_fuzz::sanitizer_envs(sanitizers)
        .into_iter()
        .flatten()
        .collect()
}

/// Environment overrides applied to EVERY builtin fuzz child, independent of
/// `--sanitizers` (the C/C++ harness is always ASan-built).
///
/// Neutralizes the network debuginfod client: on a crash ASan's in-process
/// symbolizer consults the system debuginfod server (`DEBUGINFOD_URLS`, set by
/// default on stock Ubuntu) over HTTPS. For a target where most inputs crash —
/// e.g. a callback struct cast straight from fuzz bytes, whose garbage function
/// pointer faults on the first byte — that round-trip runs on every crash, and
/// the X.509/TLS strcmp traffic libcurl→OpenSSL drives through our cmplog hooks
/// floods the runtrace; together they blow past the per-target wall cap (a 2.7s
/// run became 182s). A fuzz child never wants a network debuginfo fetch in the
/// hot loop; local symbolization still works, so finding stack frames stay
/// symbolized. An explicit caller-supplied value is respected.
fn apply_fuzz_child_env_overrides(extra_env: &mut Vec<(String, String)>) {
    if !extra_env.iter().any(|(k, _)| k == "DEBUGINFOD_URLS") {
        extra_env.push(("DEBUGINFOD_URLS".to_owned(), String::new()));
    }
    // The default C/C++ harness is built with `-fsanitize=address,undefined`, but
    // UBSan defaults to print-and-CONTINUE with exit 0, and the crash path only
    // inspects a sanitizer report on a NON-success exit — so on the default
    // `auto` run (SanitizerSelection::Default, whose runtime_set() is empty) every
    // UBSan-class fault (signed overflow, out-of-bounds index, shift error, null
    // deref, ...) is printed and then SILENTLY MISSED. Arm the runtime options so
    // a sanitizer report becomes a detectable abort, matching the AFL child env.
    // The operator's own inherited `<SAN>_OPTIONS` (suppressions / FP-killers) are
    // merged first so they still win; an explicit value already threaded through
    // `--sanitizers` / `--env` is in `extra_env` and left untouched (so an
    // explicit selection or MSan/TSan build is not overridden here). ASan already
    // aborts by default; arming it too is belt-and-suspenders and harmless for
    // non-sanitized (interpreted-lane) children, which ignore the vars.
    //
    // `symbolize=0` is deliberately NOT set here. AFL++ v4 refuses to start when
    // it inherits a custom `ASAN_OPTIONS` without it, and the afl-fuzz spawn sets
    // it on its own child env for that reason — but this env goes to BUILTIN
    // children, whose sanitizer reports must stay symbolized: the file and line
    // in the report are what join a crash to the static finding on the same line.
    // Adding it here to appease AFL turned every `fuzz_confirmed` static finding
    // into `fuzz_exercised`.
    //
    // UBSan additionally prints its stack (`print_stacktrace=1`) and the name of
    // the failed check (`report_error_type=1`): without them a UBSan report is a
    // single `file:line:col: runtime error:` line with no function to name as
    // the sink and nothing but its rule to tell one defect from another.
    for (key, value) in sanitizer_child_env(false) {
        if !extra_env.iter().any(|(k, _)| *k == key) {
            extra_env.push((key, value));
        }
    }
}

/// The `ASAN_OPTIONS` and `UBSAN_OPTIONS` of a builtin fuzz child (see
/// [`apply_fuzz_child_env_overrides`]), for every child that must reproduce a
/// crash the way the fuzz loop saw it: `bhf replay`, minimization,
/// `bhf report --backfill`, and the direct harness command `bhf explain` and
/// the capsule refusals print. The operator's inherited values are merged first
/// and bhf's keys win. `leak` adds `detect_leaks=1`, the key the
/// `--sanitizers` lanes require, so a leak finding replays with leak detection
/// on whatever the operator's `ASAN_OPTIONS` says; leak detection is never
/// turned off.
pub(crate) fn sanitizer_child_env(leak: bool) -> Vec<(String, String)> {
    sanitizer_child_env_for(leak, false)
}

/// [`sanitizer_child_env`] for a child that runs under an emulator
/// (`emulated`, a qemu-user runner) or natively. Under qemu-user a guest
/// abort makes qemu re-raise SIGABRT and dump its own huge address space,
/// which takes minutes, so an emulated child gets `abort_on_error=0` in place
/// of `abort_on_error=1`: the sanitizer exits non-zero after its report,
/// which classifies it.
pub(crate) fn sanitizer_child_env_for(leak: bool, emulated: bool) -> Vec<(String, String)> {
    let mut env = sanitizer_child_env_with(
        std::env::var("ASAN_OPTIONS").ok().as_deref(),
        std::env::var("UBSAN_OPTIONS").ok().as_deref(),
        leak,
        emulated,
    );
    // A HWASan build (#333) exists only on an AArch64 host, and runs natively
    // there; it takes ASan's keys.
    if cfg!(target_arch = "aarch64") && !emulated {
        env.push((
            "HWASAN_OPTIONS".to_owned(),
            corpus::sanitizer_options::merge(
                std::env::var("HWASAN_OPTIONS").ok().as_deref(),
                &corpus::sanitizer_options::asan_required(leak, emulated),
            ),
        ));
    }
    env
}

/// [`sanitizer_child_env_for`] with the inherited `asan` and `ubsan` values:
/// each kept as it is, followed by the required keys
/// ([`corpus::sanitizer_options`], which each finding's `replay.py` embeds
/// too).
fn sanitizer_child_env_with(
    asan: Option<&str>,
    ubsan: Option<&str>,
    leak: bool,
    emulated: bool,
) -> Vec<(String, String)> {
    use corpus::sanitizer_options::{asan_required, merge, ubsan_required};
    // An emulated child's `abort_on_error=0` takes the place of
    // `abort_on_error=1`, so each of bhf's keys appears once in the direct
    // harness command bhf prints.
    vec![
        (
            "ASAN_OPTIONS".to_owned(),
            merge(asan, &asan_required(leak, emulated)),
        ),
        (
            "UBSAN_OPTIONS".to_owned(),
            merge(ubsan, &ubsan_required(emulated)),
        ),
    ]
}

/// Whether the builtin loop's own executions symbolize sanitizer reports:
/// only with `BHF_IN_LOOP_SYMBOLIZE=1`. Symbolizing a report (llvm-symbolizer)
/// and aborting through the kernel's core pattern take most of a second, which
/// on a target where most inputs crash left a few executions a second for a
/// crash already reported.
fn in_loop_symbolize() -> bool {
    std::env::var("BHF_IN_LOOP_SYMBOLIZE").is_ok_and(|value| value == "1")
}

/// `env` for the builtin loop's own executions. Unless `symbolize`, each
/// sanitizer's options get `symbolize=0` (a report names `module+offset`
/// frames, which [`InLoopSymbolization`] tells crashes apart by) and
/// `abort_on_error=0` (the sanitizer exits non-zero after its report, which
/// classifies it, instead of aborting through the core pattern). bhf's keys
/// go last, so these win.
fn in_loop_env(env: &[(String, String)], symbolize: bool) -> Vec<(String, String)> {
    let mut env = env.to_vec();
    if symbolize {
        return env;
    }
    for (key, value) in env.iter_mut() {
        if matches!(
            key.as_str(),
            "ASAN_OPTIONS" | "HWASAN_OPTIONS" | "UBSAN_OPTIONS" | "MSAN_OPTIONS" | "TSAN_OPTIONS"
        ) {
            *value = corpus::sanitizer_options::merge(Some(value), "symbolize=0:abort_on_error=0");
        }
    }
    env
}

/// What to do with an unsymbolized sanitizer report from the loop.
#[derive(Debug, Clone, PartialEq, Eq)]
enum InLoopCrash {
    /// The report is symbolized already, or names no frames: report it.
    AsIs,
    /// A crash an earlier one with the same signature was reported (or given
    /// up) for: counted, not re-run.
    Duplicate,
    /// A new signature: re-run the input symbolized and report that.
    Symbolize(String),
}

/// The builtin loop's view of its unsymbolized crashes: the signature of each
/// (rule, kind and the top frames' `module+offset`) and the root-cause key its
/// symbolized re-run was reported under, so a crash with a signature seen
/// before costs no re-run.
#[derive(Default)]
struct InLoopSymbolization {
    keys: HashMap<String, String>,
}

impl InLoopSymbolization {
    /// Frames of the signature: enough to tell two call paths apart.
    const FRAMES: usize = 5;

    fn signature(report: &corpus::SanitizerReport, stderr: Option<&str>) -> Option<String> {
        let frames = corpus::sanitizer::unsymbolized_frames(stderr?);
        if frames.is_empty() || !report.stack.is_empty() {
            return None;
        }
        let top = &frames[..frames.len().min(Self::FRAMES)];
        Some(format!(
            "unsymbolized:{}:{}:{}",
            report.rule_id,
            report.kind,
            top.join(",")
        ))
    }

    fn classify(
        &self,
        report: &corpus::SanitizerReport,
        stderr: Option<&str>,
        dedup: &mut SanitizerClusterDedup,
    ) -> InLoopCrash {
        let Some(signature) = Self::signature(report, stderr) else {
            return InLoopCrash::AsIs;
        };
        let settled = |key: &str, dedup: &mut SanitizerClusterDedup| dedup.note_settled_hit(key);
        if settled(&signature, dedup) {
            return InLoopCrash::Duplicate;
        }
        match self.keys.get(&signature) {
            Some(key) if settled(key, dedup) => InLoopCrash::Duplicate,
            _ => InLoopCrash::Symbolize(signature),
        }
    }

    /// The re-run of `signature`'s input was reported under `key`.
    fn symbolized(&mut self, signature: String, key: String) {
        self.keys.insert(signature, key);
    }
}

/// Turn `abort_on_error` off in the `ASAN_OPTIONS` and `UBSAN_OPTIONS` of
/// `env` (bhf's keys go last, so the appended one wins).
pub(crate) fn no_abort_on_error(env: &mut [(String, String)]) {
    for (key, value) in env.iter_mut() {
        if key == "ASAN_OPTIONS" || key == "UBSAN_OPTIONS" {
            value.push_str(":abort_on_error=0");
        }
    }
}

/// The `UBSAN_OPTIONS` of every child that must report UBSan findings the way
/// the fuzz loop does — builtin fuzz children, minimization and `bhf replay`:
/// the first report halts the run as a crash (`abort_on_error=1`,
/// `halt_on_error=1`) and carries its stack and check name
/// ([`corpus::sanitizer_options::ubsan_required`]). The operator's inherited
/// `UBSAN_OPTIONS` is kept first; bhf's keys go last and win.
pub(crate) fn ubsan_child_options() -> String {
    corpus::sanitizer_options::merge(
        std::env::var("UBSAN_OPTIONS").ok().as_deref(),
        &corpus::sanitizer_options::ubsan_required(false),
    )
}

fn sanitizer_summary(
    sanitizers: &[multicore_fuzz::Sanitizer],
    env: &[(String, String)],
    composition_campaign: bool,
) -> SanitizerRunSummary {
    SanitizerRunSummary {
        requested: sanitizers
            .iter()
            .map(|s| sanitizer_name(*s).to_owned())
            .collect(),
        active_env: env
            .iter()
            .map(|(key, value)| EnvVarSummary {
                key: key.clone(),
                value: value.clone(),
            })
            .collect(),
        composition_campaign,
    }
}

fn sanitizer_name(sanitizer: multicore_fuzz::Sanitizer) -> &'static str {
    match sanitizer {
        multicore_fuzz::Sanitizer::Asan => "asan",
        multicore_fuzz::Sanitizer::Msan => "msan",
        multicore_fuzz::Sanitizer::Ubsan => "ubsan",
        multicore_fuzz::Sanitizer::Tsan => "tsan",
        multicore_fuzz::Sanitizer::Lsan => "lsan",
        multicore_fuzz::Sanitizer::Hwasan => "hwasan",
    }
}

/// Locate `afl-fuzz`, preferring an explicit `--afl-path` install directory
/// (issue #45) before falling back to a `PATH` search.
fn resolve_afl_fuzz(afl_path: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(dir) = afl_path {
        for name in ["afl-fuzz", "afl-fuzz.exe"] {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    which_executable("afl-fuzz")
}

fn which_executable(name: &str) -> Result<PathBuf, String> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(format!(
        "'{name}' not found on PATH; install AFL++ (apt install afl++ or build from source) before using --engine afl++"
    ))
}

/// Entropic seed weight (#382): a seed's selection weight rises with the
/// coverage novelty it contributed (`energy`) and decays with how many times it
/// has already been chosen (`selections`), so the mutator pours energy into
/// high-yield, under-explored seeds and backs off ones it has already mined.
fn entropic_weight(energy: u32, selections: u64) -> u64 {
    (u64::from(energy) + 1).saturating_mul(1024) / (selections + 1)
}

/// Pick a pool index weighted by [`entropic_weight`] (#382). Falls back to
/// uniform choice when all weights are zero, and 0 for an empty pool.
fn choose_entropic_index_pool(pool: &[PoolEntry], rng: &mut MutationRng) -> usize {
    if pool.is_empty() {
        return 0;
    }
    // A retired entry (a known crasher) is never picked while another is left.
    let weights: Vec<u64> = pool
        .iter()
        .map(|entry| {
            if entry.retired {
                0
            } else {
                entropic_weight(entry.energy, entry.selections)
            }
        })
        .collect();
    let total: u64 = weights.iter().sum();
    if total == 0 {
        return rng.choose_index(pool.len()).unwrap_or(0);
    }
    let mut r = rng.next_u64() % total;
    for (index, weight) in weights.iter().enumerate() {
        if r < *weight {
            return index;
        }
        r -= *weight;
    }
    pool.len() - 1
}

/// The pool entry a mutation of `base_index` splices from: the next one that
/// is not retired (a known crasher), else the base itself.
fn splice_peer(pool: &[PoolEntry], base_index: usize) -> usize {
    (1..pool.len())
        .map(|step| (base_index + step) % pool.len())
        .find(|index| !pool[*index].retired)
        .unwrap_or(base_index)
}

/// Max byte positions a colorization pass probes per base (#400). Bounds the
/// extra execs (each probe is one fork-server run) so colorization stays once-per-
/// base overhead rather than scaling with arbitrarily long inputs.
const MAX_COLORIZE_PROBES: usize = 64;
/// Don't colorize inputs shorter than this — too little to gain offset precision.
const MIN_COLORIZE_LEN: usize = 4;

/// RedQueen colorization (#400). Replace as many of `base`'s bytes as possible
/// with random values that do **not** change its edge-coverage footprint, so each
/// don't-care position holds a near-unique value. Then `cmplog`'s single-byte /
/// short operands splice at the exact offset they were compared instead of at
/// every occurrence of a common byte (0x00, ' ') — the precision fix RedQueen
/// needs on parsers full of repeated bytes (cJSON's `*c=='{'` char gates).
///
/// Coverage is measured in isolation by zeroing the shared bitmap before each
/// probe and reading the exact footprint; the cumulative #398 feedback is saved
/// up front and **restored** at the end, so colorization's probe execs never
/// leak edges into corpus retention. Returns the original base unchanged if the
/// fork-server dies mid-pass (the caller's next real run respawns it).
fn colorize_base(
    cov: &mut CoverageTracker,
    fork: &mut ForkServer,
    base: &[u8],
    rng: &mut MutationRng,
    deadline: Option<Instant>,
) -> Vec<u8> {
    if base.len() < MIN_COLORIZE_LEN {
        return base.to_vec();
    }
    let backup = cov.snapshot();
    cov.zero();
    if matches!(fork.run_one(base), ForkOutcome::Died) {
        cov.restore(&backup);
        return base.to_vec();
    }
    let base_cov = cov.snapshot();
    let mut colored = base.to_vec();
    let probes = base.len().min(MAX_COLORIZE_PROBES);
    for i in 0..probes {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            break;
        }
        let original = colored[i];
        let candidate = rng.next_u8();
        if candidate == original {
            continue;
        }
        colored[i] = candidate;
        cov.zero();
        match fork.run_one(&colored) {
            ForkOutcome::Died => {
                // The probe crashed or hung; revert it and stop (the colored
                // input must stay coverage-equivalent and non-crashing).
                colored[i] = original;
                break;
            }
            ForkOutcome::Ran(_) => {
                if cov.snapshot() != base_cov {
                    // This byte affects control flow — keep the original value.
                    colored[i] = original;
                }
            }
        }
    }
    cov.restore(&backup);
    colored
}

/// Run `base` once with RedQueen cmplog capture armed and return the comparison
/// operand pairs it produced (#400). The capture exec's findings/coverage are
/// intentionally ignored — this is pure input-to-state evidence-gathering, paid
/// once per base and then cached on its [`PoolEntry`].
fn capture_cmplog(reader: &CmpShmReader, fork: &mut ForkServer, base: &[u8]) -> cmplog::CmpLog {
    reader.arm();
    // The driver fills the ring as a side effect of running `base`; whether the
    // run produced events / a crash is irrelevant to operand capture.
    let _ = fork.run_one(base);
    let log = reader.read_log();
    reader.disarm();
    log
}

/// Load a `--grammar` JSON file into a [`Grammar`]. The file is a JSON object mapping
/// each non-terminal name to a list of production strings, where `{NAME}` references
/// another rule. `None` → `Ok(None)` (no grammar in play). A malformed grammar is a
/// hard error so a typo is surfaced rather than silently fuzzing without structure.
pub(crate) fn load_grammar_for_run(path: Option<&Path>) -> Result<Option<Grammar>, String> {
    let Some(path) = path else {
        return Ok(None);
    };
    let grammar_limit = max_grammar_bytes();
    let (bytes, original_len) = read_seed_file_prefix(path, grammar_limit)
        .map_err(|e| format!("read grammar {}: {e}", path.display()))?;
    if original_len > bytes.len() as u64 {
        return Err(format!(
            "grammar {} is {original_len} bytes, above the {} MiB safety limit",
            path.display(),
            grammar_limit / (1024 * 1024)
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("grammar {} is not valid JSON: {e}", path.display()))?;
    let obj = value.as_object().ok_or_else(|| {
        format!(
            "grammar {} must be a JSON object of name -> productions",
            path.display()
        )
    })?;
    let mut rules: Vec<(String, Vec<String>)> = Vec::new();
    for (name, prods) in obj {
        let alts = prods.as_array().ok_or_else(|| {
            format!("grammar rule {name:?} must be a JSON array of production strings")
        })?;
        let mut productions = Vec::with_capacity(alts.len());
        for prod in alts {
            let s = prod
                .as_str()
                .ok_or_else(|| format!("a production in grammar rule {name:?} must be a string"))?;
            productions.push(s.to_owned());
        }
        rules.push((name.clone(), productions));
    }
    Grammar::from_rules(&rules, None).map(Some)
}

/// The largest `--frame` profile read: a profile is a few fields of TOML.
const MAX_FRAME_PROFILE_BYTES: usize = 1024 * 1024;

/// Load a `--frame` profile into the [`FrameCodec`] the builtin loop decodes,
/// mutates and repairs each input with. The profile is a `bhf.protocol.v1`
/// protocol profile of one binary message, the session lane's message schema
/// for a single frame. `None` → `Ok(None)`. A profile the codec cannot apply
/// to a single input (several messages, a GIOP message, an optional field or
/// a reference to a response) is an error that says why.
pub(crate) fn load_frame_for_run(path: Option<&Path>) -> Result<Option<FrameCodec>, String> {
    let Some(path) = path else {
        return Ok(None);
    };
    let fail = |reason: String| format!("--frame {}: {reason}", path.display());
    let (bytes, original_len) = read_seed_file_prefix(path, MAX_FRAME_PROFILE_BYTES)
        .map_err(|e| fail(format!("read: {e}")))?;
    if original_len > bytes.len() as u64 {
        return Err(fail(format!(
            "{original_len} bytes, above the {} MiB limit for a profile",
            MAX_FRAME_PROFILE_BYTES / (1024 * 1024)
        )));
    }
    let text = String::from_utf8(bytes).map_err(|e| fail(format!("not UTF-8: {e}")))?;
    let profile = protocol_session::Profile::from_toml(&text).map_err(|e| fail(e.to_string()))?;
    if profile.kind() != protocol_session::ProfileKind::Binary {
        return Err(fail(
            "a frame is a binary message; a giop profile's messages are GIOP requests the \
             session lane sends"
                .to_owned(),
        ));
    }
    let model =
        protocol_session::ProtocolModel::from_profile(&profile).map_err(|e| fail(e.to_string()))?;
    let message = match model.messages() {
        [message] => message,
        messages => {
            let names: Vec<&str> = messages.iter().map(|m| m.name.as_str()).collect();
            return Err(fail(format!(
                "a frame profile declares one [[message]]; this one declares {} ({})",
                names.len(),
                names.join(", ")
            )));
        }
    };
    frame_codec_for(message).map(Some).map_err(fail)
}

/// The [`FrameCodec`] of one compiled profile message: its seed frame's field
/// values as the template, an integer or enum field at its width (an enum's
/// variants as the codes a field edit favours), and a `bytes` field at most
/// its `max`.
fn frame_codec_for(message: &protocol_session::CompiledMessage) -> Result<FrameCodec, String> {
    use fuzz_engine_builtin::binframe::{encode_uint, FieldShape};
    use fuzz_engine_builtin::{Field, Message};
    use protocol_session::{ComputedSpec, DataSpec, FieldRole};

    // What a single input cannot carry is refused before the seed frame is
    // built, which would fail on it with a less telling error.
    for field in &message.fields {
        let name = &field.name;
        if field.optional {
            return Err(format!(
                "field {name:?} is optional, and a single input carries no sign of whether it \
                 is there; make it required"
            ));
        }
        if let FieldRole::Ref { source, .. } = &field.role {
            return Err(format!(
                "field {name:?} is the response value {source}, and a single input has no \
                 reply to take it from"
            ));
        }
    }
    let seed = message
        .build_frame(
            &message.seed_values(),
            &protocol_session::Bindings::default(),
        )
        .map_err(|e| format!("message {}: {e}", message.name))?;
    let mut fields = Vec::with_capacity(message.fields.len());
    let mut shapes = std::collections::BTreeMap::new();
    for field in &message.fields {
        let name = field.name.clone();
        let value = |header: usize| {
            seed.span(&name)
                .map(|span| seed.bytes()[span][header..].to_vec())
                .ok_or_else(|| format!("field {name:?} is not in the message's frame"))
        };
        match &field.role {
            FieldRole::Ref { .. } => unreachable!("refused above"),
            FieldRole::Computed(ComputedSpec::Length {
                width,
                endian,
                covers,
            }) => fields.push(Field::Length {
                name,
                width: *width,
                endian: *endian,
                covers: covers.clone(),
            }),
            FieldRole::Computed(ComputedSpec::Checksum {
                kind,
                endian,
                covers,
            }) => fields.push(Field::Checksum {
                name,
                kind: *kind,
                endian: *endian,
                covers: covers.clone(),
            }),
            FieldRole::Computed(ComputedSpec::Offset {
                width,
                endian,
                target,
            }) => fields.push(Field::Offset {
                name,
                width: *width,
                endian: *endian,
                target: target.clone(),
            }),
            FieldRole::Data(DataSpec::Bytes { max }) => {
                shapes.insert(name.clone(), FieldShape::Variable { max: *max });
                fields.push(Field::bytes(&name, value(0)?));
            }
            FieldRole::Data(DataSpec::Int { .. }) => {
                shapes.insert(name.clone(), FieldShape::Fixed { codes: Vec::new() });
                fields.push(Field::bytes(&name, value(0)?));
            }
            FieldRole::Data(DataSpec::Enum {
                width,
                endian,
                variants,
            }) => {
                let bits = 8 * width.size() as u32;
                let codes = variants
                    .values()
                    .filter(|&&code| code >> bits == 0)
                    .map(|&code| encode_uint(*width, *endian, code))
                    .collect();
                shapes.insert(name.clone(), FieldShape::Fixed { codes });
                fields.push(Field::bytes(&name, value(0)?));
            }
            FieldRole::Data(DataSpec::Tlv {
                tag,
                tag_width,
                len_width,
                endian,
            }) => fields.push(Field::Tlv {
                tag: u32::try_from(*tag)
                    .map_err(|_| format!("field {name:?}: tag {tag} is wider than 32 bits"))?,
                tag_width: *tag_width,
                len_width: *len_width,
                endian: *endian,
                value: value(tag_width.size() + len_width.size())?,
                name,
            }),
        }
    }
    FrameCodec::new(Message::new(fields).with_max_len(message.max_len), &shapes)
        .map_err(|e| format!("message {}: {e}", message.name))
}

/// `--frame`: each seed decoded and re-encoded as a frame, once, and the
/// profile's own frame among them.
fn frame_seeds(codec: &FrameCodec, seeds: &mut Vec<Vec<u8>>) {
    let mut framed: Vec<Vec<u8>> = Vec::with_capacity(seeds.len() + 1);
    for seed in seeds.drain(..) {
        let frame = codec.repair(&seed);
        if !framed.contains(&frame) {
            framed.push(frame);
        }
    }
    if !framed.iter().any(|frame| frame == codec.seed()) {
        framed.push(codec.seed().to_vec());
    }
    *seeds = framed;
}

/// A `--frame` child of `base`: half the time a field edit
/// ([`FrameCodec::mutate`]), otherwise `byte_child` (a byte mutation of the
/// whole frame, made only when it is used) repaired. A byte mutation the repair
/// undoes, one that changed only a stored length or checksum, becomes a field
/// edit, so the loop does not run its base again. The second value is whether
/// the child is a field edit.
fn frame_child(
    codec: &FrameCodec,
    base: &[u8],
    max_len: usize,
    rng: &mut MutationRng,
    byte_child: impl FnOnce(&mut MutationRng) -> Vec<u8>,
) -> (Vec<u8>, bool) {
    if rng.coin() {
        let repaired = codec.repair(&byte_child(rng));
        if repaired != base {
            return (repaired, false);
        }
    }
    (codec.mutate(base, max_len, rng), true)
}

/// The op program's geometry, read from the sidecar a sequence harness writes.
///
/// The harness reserves a fixed-stride control block at the END of every input:
/// one count byte followed by one selector byte per possible step. Knowing that
/// shape lets the engine hand the mutator ordered, non-overlapping spans for the
/// program itself, so a structure-aware edit can reorder or retarget an
/// operation instead of corrupting the encoding by accident.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SequenceGeometry {
    operation_count: usize,
    max_steps: usize,
    control_len: usize,
    portfolio_lanes: usize,
}

impl SequenceGeometry {
    fn load(harness_dir: &Path) -> Option<Self> {
        let text = std::fs::read_to_string(
            harness_dir.join(harness_gen::c_generate::SEQUENCE_LAYOUT_FILE),
        )
        .ok()?;
        let field = |name: &str| -> Option<usize> {
            let key = format!("\"{name}\"");
            let start = text.find(&key)? + key.len();
            let rest = text[start..].trim_start().strip_prefix(':')?;
            rest.trim_start()
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse()
                .ok()
        };
        let geometry = Self {
            operation_count: field("operation_count")?,
            max_steps: field("max_steps")?,
            control_len: field("control_len")?,
            portfolio_lanes: field("portfolio_lanes").unwrap_or(1).max(1),
        };
        (geometry.operation_count > 0 && geometry.max_steps > 0).then_some(geometry)
    }

    /// Describe `input`'s op program as byte spans. Returns `None` when the
    /// input is too short to carry a control block, in which case there is no
    /// program to preserve and flat-byte mutation is correct.
    fn layout_for(&self, input: &[u8]) -> Option<OperationSequenceLayout> {
        if input.len() < self.control_len {
            return None;
        }
        let base = input.len() - self.control_len;
        // One slot per possible step: selector byte plus a 4-byte value, the
        // encoding the engine's bounded-value decoder understands and the
        // harness's `bhf_ctrl_bounded` mirrors byte for byte.
        const SLOT: usize = 5;
        let program_prefix = 1 + usize::from(self.portfolio_lanes > 1);
        let steps = (0..self.max_steps)
            .map(|step| {
                let at = base + program_prefix + step * SLOT;
                OperationStepSpan::new(at..at + SLOT, at..at + SLOT)
            })
            .collect();
        // No step-count range: the engine's decoder for that field expects a
        // 5-byte selector-plus-value encoding, while the harness spends a single
        // byte on it. Describing it wrongly invalidates the WHOLE layout (the
        // validator rejects it, and the op program silently reverts to opaque
        // bytes), and widening the harness's count to 5 bytes would cost four
        // bytes of every input to describe a value the fixed-stride block
        // already bounds. The selector spans are the part worth describing.
        Some(OperationSequenceLayout::new(
            None,
            0,
            self.max_steps,
            self.operation_count,
            steps,
        ))
    }

    fn expand_portfolio_seeds(&self, seeds: &mut Vec<Vec<u8>>) {
        if self.portfolio_lanes <= 1 || self.portfolio_lanes > u8::MAX as usize {
            return;
        }
        let original = std::mem::take(seeds);
        let mut expanded = Vec::with_capacity(original.len() * self.portfolio_lanes);
        for seed in original {
            for lane in 0..self.portfolio_lanes {
                let mut variant = Vec::with_capacity(seed.len() + self.control_len);
                variant.extend_from_slice(&seed);
                variant.resize(seed.len() + self.control_len, 0);
                variant[seed.len()] = lane as u8;
                if !expanded.contains(&variant) {
                    expanded.push(variant);
                }
            }
        }
        *seeds = expanded;
    }

    fn portfolio_lane(&self, input: &[u8]) -> Option<usize> {
        if self.portfolio_lanes <= 1 || input.len() < self.control_len {
            return None;
        }
        let base = input.len() - self.control_len;
        Some(usize::from(input[base]) % self.portfolio_lanes)
    }
}

#[derive(Debug, Clone, Default, Serialize)]
struct PortfolioLaneFeedback {
    lane: usize,
    executions: usize,
    retained_inputs: usize,
    new_edges: usize,
    new_buckets: usize,
    comparison_advances: usize,
    scheduling_energy_awarded: u64,
}

pub(crate) fn expand_sequence_portfolio_seeds(harness_dir: &Path, seeds: &mut Vec<Vec<u8>>) {
    if let Some(geometry) = SequenceGeometry::load(harness_dir) {
        geometry.expand_portfolio_seeds(seeds);
    }
}

/// Build one mutated child from pool entry `base_index`. Prefers that entry's
/// per-input RedQueen cmplog (#400) so `CmpLogSplice` injects the operands it
/// observed at the offsets they were compared; falls back to the global
/// pre-mined log (`global_cmplog`) so non-driver paths keep their behavior.
/// Returns the child, what it descends from and, for a `--grammar`
/// derivation or tree mutation (#329), the child's derivation tree.
#[allow(clippy::too_many_arguments)]
fn mutate_from_pool(
    pool: &[PoolEntry],
    base_index: usize,
    dictionary: &Dictionary,
    global_cmplog: Option<&cmplog::CmpLog>,
    grammar: Option<&Grammar>,
    config: MutatorConfig,
    sequence: Option<SequenceGeometry>,
    rng: &mut MutationRng,
) -> (
    Vec<u8>,
    crate::fuzz_lineage::InputParents,
    Option<fuzz_engine_builtin::grammar::Derivation>,
) {
    let suite = MutatorSuite::new(config);
    let full_base = pool
        .get(base_index)
        .map(PoolEntry::mutation_base)
        .unwrap_or(&[]);
    let base = &full_base[..full_base.len().min(config.max_len)];
    let peer_index = splice_peer(pool, base_index);
    let full_peer = pool
        .get(peer_index)
        .map(PoolEntry::mutation_base)
        .unwrap_or(&[]);
    let peer = &full_peer[..full_peer.len().min(config.max_len)];
    let mut mutation_input = MutationInput::new(base, dictionary).with_peer(peer);
    if let Some(spans) = pool
        .get(base_index)
        .and_then(|entry| entry.typed_spans.as_deref())
    {
        mutation_input = mutation_input.with_typed_spans(spans);
    }
    let cmplog = pool
        .get(base_index)
        .and_then(|entry| entry.cmplog.as_ref())
        .or(global_cmplog);
    if let Some(log) = cmplog {
        mutation_input = mutation_input.with_cmplog(log);
    }
    if let Some(g) = grammar {
        // #329: the base's and the peer's derivation trees, for the tree
        // mutations.
        mutation_input = mutation_input.with_grammar(g).with_grammar_trees(
            pool.get(base_index).and_then(|entry| entry.tree.as_ref()),
            pool.get(peer_index).and_then(|entry| entry.tree.as_ref()),
        );
    }
    // A sequence harness's op program lives in a fixed-stride control block, so
    // it can be described to the mutator as ordered spans instead of being
    // edited blind. Computed per base: the block sits at the end, so its offsets
    // move with the input's length.
    let sequence_layout = sequence.and_then(|geometry| geometry.layout_for(base));
    if let Some(layout) = sequence_layout.as_ref() {
        mutation_input = mutation_input.with_operation_sequence(layout);
    }

    let (bytes, kind, tree) = match suite.mutate(&mutation_input, rng) {
        Some(result) => (result.bytes, Some(result.kind), result.tree),
        None => (vec![rng.next_u8()], None, None),
    };
    // AdaFuzz.Input.Load_From_Stdin exits the harness loop on empty input,
    // which leaves no event log behind and breaks first-run dogfooding when
    // no --seed-input is supplied. Guarantee at least one byte every time.
    if bytes.is_empty() {
        (
            vec![rng.next_u8()],
            crate::fuzz_lineage::InputParents::Generated,
            None,
        )
    } else {
        let parents =
            crate::fuzz_lineage::InputParents::from_mutation(base_index, peer_index, kind);
        (bytes, parents, tree)
    }
}

/// One adaptive length-control update. Returns the next effective mutation
/// length and plateau counter. With `len_control == 0` (disabled) or once the
/// ceiling is reached, the length is held; a new corpus signature resets the
/// plateau; otherwise the length doubles toward `max_len` every `len_control`
/// flat executions.
/// One adaptive-length step (libFuzzer `-len_control`): after `len_control` executions
/// with no new coverage, double the effective mutation length toward `ceiling`. Unlike
/// plain libFuzzer control, when the effective length has REACHED the ceiling the
/// plateau counter is HELD at the threshold (rather than reset) so the caller can
/// detect "stuck at the ceiling" and decide whether to raise it (the adaptive ceiling).
fn len_control_step(
    effective: usize,
    ceiling: usize,
    len_control: usize,
    execs_since_new: usize,
    found_new_signature: bool,
) -> (usize, usize) {
    if len_control == 0 {
        return (effective, 0);
    }
    if found_new_signature {
        return (effective, 0);
    }
    let plateau = execs_since_new + 1;
    if plateau >= len_control && effective < ceiling {
        (effective.saturating_mul(2).min(ceiling), 0)
    } else {
        // Below threshold, or stuck at the ceiling: hold the plateau (capped at the
        // threshold) so a stuck-at-ceiling caller sees the signal and can raise it.
        (effective, plateau.min(len_control))
    }
}

fn mutator_config(structured_inputs: StructuredInputMode, max_len: usize) -> MutatorConfig {
    MutatorConfig {
        max_len,
        structured_records: structured_inputs.structured_records_enabled(),
        structured_json: structured_inputs.structured_json_enabled(),
        structured_xml: structured_inputs.structured_xml_enabled(),
        structured_key_value: structured_inputs.structured_key_value_enabled(),
        structured_url_encoded: structured_inputs.structured_url_encoded_enabled(),
        structured_multipart: structured_inputs.structured_multipart_enabled(),
        structured_csv: structured_inputs.structured_csv_enabled(),
        structured_http: structured_inputs.structured_http_enabled(),
        structured_ini: structured_inputs.structured_ini_enabled(),
        structured_toml: structured_inputs.structured_toml_enabled(),
        structured_yaml: structured_inputs.structured_yaml_enabled(),
        structured_chunked: structured_inputs.structured_chunked_enabled(),
        structured_recursive: structured_inputs.structured_recursive_enabled(),
    }
}

fn find_generated_dictionary(work_dir: &Path, harness_id: &str) -> Option<PathBuf> {
    [
        crate::auto::layout::harness_dir(work_dir, harness_id).join("dictionary.txt"),
        crate::auto::layout::legacy_auto_harness_dir(work_dir, harness_id).join("dictionary.txt"),
        work_dir
            .join("generated_harnesses")
            .join(harness_id)
            .join("dictionary.txt"),
        work_dir
            .join("build")
            .join(harness_id)
            .join("dictionary.txt"),
        work_dir.join("fake_corba").join("dictionary.txt"),
    ]
    .into_iter()
    .find(|path| path.is_file())
}

/// The harness's `learned_dictionary.txt` (see [`write_learned_dictionary`]),
/// looked up in the same harness dirs as its `dictionary.txt`.
fn find_learned_dictionary(work_dir: &Path, harness_id: &str) -> Option<PathBuf> {
    crate::auto::layout::harness_dir_candidates(work_dir, harness_id)
        .into_iter()
        .chain([work_dir.join("build").join(harness_id)])
        .map(|dir| dir.join(LEARNED_DICTIONARY_FILE))
        .find(|path| path.is_file())
}

/// The tokens a fuzz run starts with: those of `--dict`, then the harness's
/// ([`load_generated_dictionary_tokens`]), each once. A `--dict` that cannot
/// be read is an error: the operator asked for it.
pub(crate) fn run_dictionary_tokens(
    work_dir: &Path,
    harness_id: &str,
    dict_file: Option<&Path>,
) -> Result<Vec<Vec<u8>>, String> {
    let mut tokens = match dict_file {
        Some(path) => load_afl_dictionary_tokens(path)?,
        None => Vec::new(),
    };
    for token in load_generated_dictionary_tokens(work_dir, harness_id)? {
        if !tokens.contains(&token) {
            tokens.push(token);
        }
    }
    Ok(tokens)
}

/// The tokens a fuzz run starts with: the harness's source-mined
/// `dictionary.txt`, then its runtime-learned `learned_dictionary.txt`, each
/// token once. A `bhf auto` pass also reads `cmplog.jsonl`, the learned
/// dictionary's source, and skips the tokens already loaded here.
fn load_generated_dictionary_tokens(
    work_dir: &Path,
    harness_id: &str,
) -> Result<Vec<Vec<u8>>, String> {
    let mut tokens = match find_generated_dictionary(work_dir, harness_id) {
        Some(path) => load_afl_dictionary_tokens(&path)?,
        None => Vec::new(),
    };
    if let Some(path) = find_learned_dictionary(work_dir, harness_id) {
        // A damaged learned dictionary costs only its hints, never the run.
        match load_afl_dictionary_tokens(&path) {
            Ok(learned) => {
                for token in learned {
                    if !tokens.contains(&token) {
                        tokens.push(token);
                    }
                }
            }
            Err(error) => bhfeprintln!("bhf: warning: {error}; learned tokens not loaded"),
        }
    }
    Ok(tokens)
}

/// The runtime-learned dictionary written beside a harness's `dictionary.txt`.
pub(crate) const LEARNED_DICTIONARY_FILE: &str = "learned_dictionary.txt";
/// Most tokens `learned_dictionary.txt` keeps.
pub(crate) const LEARNED_DICTIONARY_MAX_TOKENS: usize = 256;
/// Longest operand, in bytes, `learned_dictionary.txt` keeps.
pub(crate) const LEARNED_TOKEN_MAX_LEN: usize = 64;
/// The line that marks a `learned_dictionary.txt` written with only the
/// comparison constants; a file without it (an earlier release's) held every
/// operand, mutated inputs included.
pub(crate) const LEARNED_CONSTANTS_MARKER: &str =
    "# Tokens: the comparison constants, not the inputs compared with them.";
/// The first lines of `learned_dictionary.txt`.
pub(crate) const LEARNED_DICTIONARY_HEADER: &str = "\
# Comparison operands observed at runtime while this harness was fuzzed
# (the strcmp/memcmp-family operands and integer comparison constants
# recorded in cmplog.jsonl beside this file), not mined from the source like
# dictionary.txt. An integer constant is written little-endian, then
# big-endian. Any other token is an operand
# that met more distinct values at one comparison site than any of them met
# there (the constant stays, the input compared with it varies), or one that
# dictionary.txt also lists; a record that names no site only confirms a
# dictionary.txt token, and a one-byte variant of a stronger token is left
# out. Rewritten after each fuzz pass that recorded any: that run's constants
# first, then the tokens an earlier run learned, deduplicated, at most 256
# tokens of at most 64 bytes.
# Tokens: the comparison constants, not the inputs compared with them.
";

/// Rewrite `<harness_dir>/learned_dictionary.txt` from the comparison
/// operands in `<harness_dir>/cmplog.jsonl`: the comparison constants among
/// them ([`cmplog::CmpLog::constant_operands`], with the harness's
/// `dictionary.txt` corroborating an operand the records alone do not) of at most
/// [`LEARNED_TOKEN_MAX_LEN`] bytes, then the tokens the file already held, up
/// to [`LEARNED_DICTIONARY_MAX_TOKENS`]. A file an earlier release wrote,
/// without [`LEARNED_CONSTANTS_MARKER`], held every operand: of its tokens
/// only those this run found constant or `dictionary.txt` lists are kept; and
/// an earlier token that is a one-byte edit of one already kept is dropped.
/// Returns how many tokens were written; with no constant (no
/// `cmplog.jsonl`, or none in it) the file is left as it was and 0 returned.
pub(crate) fn write_learned_dictionary(harness_dir: &Path) -> std::io::Result<usize> {
    let Ok(log) = cmplog::ingest_from_jsonl_log(&harness_dir.join("cmplog.jsonl")) else {
        return Ok(0);
    };
    let mined = load_afl_dictionary_tokens(&harness_dir.join("dictionary.txt")).unwrap_or_default();
    let mut tokens: Vec<Vec<u8>> = Vec::new();
    let push = |tokens: &mut Vec<Vec<u8>>, token: Vec<u8>| {
        if !token.is_empty()
            && token.len() <= LEARNED_TOKEN_MAX_LEN
            && tokens.len() < LEARNED_DICTIONARY_MAX_TOKENS
            && !tokens.contains(&token)
        {
            tokens.push(token);
        }
    };
    let constants = log.constant_operands(&mined);
    // An integer constant is also written big-endian, for a target that
    // compares a field it read in network order.
    let integers = log.integer_constants();
    for token in &constants {
        push(&mut tokens, token.clone());
        if integers.contains(&token.as_slice()) {
            push(&mut tokens, token.iter().rev().copied().collect());
        }
    }
    if tokens.is_empty() {
        return Ok(0);
    }
    let path = harness_dir.join(LEARNED_DICTIONARY_FILE);
    let filtered = std::fs::read_to_string(&path)
        .is_ok_and(|text| text.lines().any(|line| line == LEARNED_CONSTANTS_MARKER));
    if let Ok(earlier) = load_afl_dictionary_tokens(&path) {
        for token in earlier {
            let trusted = filtered || constants.contains(&token) || mined.contains(&token);
            let variant = tokens
                .iter()
                .any(|kept| kept != &token && cmplog::one_byte_edit(kept, &token));
            if trusted && !variant {
                push(&mut tokens, token);
            }
        }
    }
    let mut out = String::from(LEARNED_DICTIONARY_HEADER);
    for token in &tokens {
        out.push('"');
        out.push_str(&crate::generate_harness::escape_afl_dictionary_token(token));
        out.push_str("\"\n");
    }
    crate::auto::report::atomic_write(&path, out.as_bytes())?;
    Ok(tokens.len())
}

fn load_afl_dictionary_tokens(path: &Path) -> Result<Vec<Vec<u8>>, String> {
    let dictionary_limit = max_dictionary_bytes();
    let (bytes, original_len) = read_seed_file_prefix(path, dictionary_limit)
        .map_err(|error| format!("read dictionary '{}': {error}", path.display()))?;
    if original_len > dictionary_limit as u64 {
        return Err(format!(
            "dictionary '{}' is {original_len} bytes, above the {} MiB safety limit",
            path.display(),
            dictionary_limit / (1024 * 1024)
        ));
    }
    let contents = String::from_utf8(bytes)
        .map_err(|error| format!("dictionary '{}' is not UTF-8: {error}", path.display()))?;
    let mut tokens = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        // The dictionary is a best-effort optimization. A single malformed line
        // must never abort the fuzz run — skip it with a warning and keep the
        // tokens we could parse, rather than dropping the whole campaign.
        match parse_afl_dictionary_line(line) {
            Ok(Some(token)) => {
                if !tokens.contains(&token) {
                    tokens.push(token);
                }
            }
            Ok(None) => {}
            Err(error) => {
                bhfeprintln!(
                    "bhf: warning: skipping dictionary '{}:{}': {error}",
                    path.display(),
                    index + 1
                );
            }
        }
    }
    Ok(tokens)
}

pub(crate) fn parse_afl_dictionary_line(line: &str) -> Result<Option<Vec<u8>>, String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }
    // The token value is the quoted span. An optional AFL `name=` / `name@level=`
    // prefix may precede it, but a dictionary name never contains a quote, so the
    // value reliably begins at the first `"`. Splitting on `=` to strip the prefix
    // would corrupt any token that legitimately contains `=` — e.g. printf format
    // strings such as `"len of TF\t = %d"` lifted verbatim from the target source.
    let Some(open_quote) = trimmed.find('"') else {
        return Err("expected quoted token".to_owned());
    };
    let rest = &trimmed[open_quote + 1..];
    let mut out = Vec::new();
    let mut chars = rest.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => return Ok(Some(out)),
            '\\' => match chars.next() {
                Some('n') => out.push(b'\n'),
                Some('r') => out.push(b'\r'),
                Some('t') => out.push(b'\t'),
                Some('\\') => out.push(b'\\'),
                Some('"') => out.push(b'"'),
                Some('x') => {
                    let hi = chars
                        .next()
                        .and_then(|c| c.to_digit(16))
                        .ok_or_else(|| "invalid hex escape".to_owned())?;
                    let lo = chars
                        .next()
                        .and_then(|c| c.to_digit(16))
                        .ok_or_else(|| "invalid hex escape".to_owned())?;
                    out.push(((hi << 4) | lo) as u8);
                }
                Some(other) => {
                    let mut buf = [0; 4];
                    out.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
                }
                None => return Err("unterminated escape".to_owned()),
            },
            other => {
                let mut buf = [0; 4];
                out.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    Err("unterminated quoted token".to_owned())
}

/// Write one framed input (`u32` little-endian length + bytes) to the harness
/// stdin, matching `AdaFuzz.Input.Load_From_Stdin`'s framing.
/// The framed fork-server harness reads at most this many bytes of a frame into
/// its fixed input buffer. All runtimes use a 1 MiB buffer (direct_harness.{c,cpp}
/// .tera, c_runtime/bhf_driver.c, ada_runtime/adafuzz-input.adb).
pub(crate) const FRAMED_INPUT_CAP: usize = 1 << 20;

/// Write one `{u32 LE length}{length bytes}` frame to the child's stdin.
///
/// The declared length is CLAMPED to the harness's fixed input buffer
/// ([`FRAMED_INPUT_CAP`]). Sending a larger frame desyncs the protocol: the
/// harness reads only the first `cap` bytes and leaves the tail in the pipe, so
/// the next frame's length prefix is read from the middle of this input —
/// yielding garbage lengths (nonsense coverage for the whole window) or a huge
/// garbage length that makes the harness block forever waiting for bytes the
/// engine never sends (fork-server deadlock until the 30 s run timeout). The
/// harness only ever consumes the first `cap` bytes anyway, so clamping here
/// keeps the stream aligned with no loss of tested input.
fn write_input_frame(stdin: &mut impl std::io::Write, input: &[u8]) -> std::io::Result<()> {
    let capped = input.len().min(FRAMED_INPUT_CAP);
    stdin.write_all(&(capped as u32).to_le_bytes())?;
    stdin.write_all(&input[..capped])
}

/// The ready byte of a harness whose standard input stays in text mode
/// (Lua's on Windows, which no Lua code can switch to binary): the C runtime
/// turns CR LF into LF and ends the stream at a Ctrl-Z, so every frame it is
/// sent is hex ([`write_hex_frame`]). Other harnesses send `\x01`.
const TEXT_FRAMES_READY: u8 = b'H';

/// Write one input as a hex frame, for a harness that asked for them
/// ([`TEXT_FRAMES_READY`]): the length clamped as [`write_input_frame`]
/// clamps it, in eight lowercase hex digits, then two per byte. No byte of
/// it is one a text-mode reader translates.
fn write_hex_frame(stdin: &mut impl std::io::Write, input: &[u8]) -> std::io::Result<()> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let capped = input.len().min(FRAMED_INPUT_CAP);
    let mut frame = Vec::with_capacity(8 + 2 * capped);
    frame.extend(format!("{capped:08x}").into_bytes());
    for byte in &input[..capped] {
        frame.push(DIGITS[usize::from(byte >> 4)]);
        frame.push(DIGITS[usize::from(byte & 0xf)]);
    }
    stdin.write_all(&frame)
}

/// The variable naming the image the runtrace shim records comparisons in.
const TARGET_EXE_ENV: &str = "BHF_TARGET_EXE";

/// `harness` as an absolute path when it is a native executable (ELF), the
/// image its process runs; `None` for a script or launcher, whose process
/// runs an interpreter.
fn native_target_exe(harness: &Path) -> Option<PathBuf> {
    use std::io::Read;
    let mut magic = [0u8; 4];
    std::fs::File::open(harness)
        .and_then(|mut file| file.read_exact(&mut magic))
        .ok()?;
    if magic != *b"\x7fELF" {
        return None;
    }
    std::path::absolute(harness).ok()
}

/// The directory of the `BHF_RUNTRACE_LOG` path in `extra_env`, if set, so
/// it can be bound into the sandbox for the harness to write runtrace events.
fn runtrace_log_dir(extra_env: &[(String, String)]) -> Option<PathBuf> {
    extra_env
        .iter()
        .find(|(key, _)| key == "BHF_RUNTRACE_LOG")
        .and_then(|(_, value)| Path::new(value).parent().map(Path::to_path_buf))
}

/// #416: inputs already recorded as crash findings, read from
/// `<work>/findings/*/testcase.bin`. A crashing input is a finding, not a clean
/// coverage seed, so it must be kept out of the persisted corpus — even when a
/// later pass re-introduces it as a built-in/reseeded seed and the cumulative,
/// pass-shared coverage map means it grows no new edges to re-trigger in-pass
/// detection. Reading the durable findings dir makes the exclusion cross-pass
/// correct without re-running every seed.
fn existing_crash_testcases(work_dir: &Path, harness_id: &str, max_len: usize) -> HashSet<u64> {
    let finding_record_limit = max_finding_record_bytes();
    let dedup_limit = max_finding_dedup_keys();
    let mut set = HashSet::new();
    let Ok(entries) = fs::read_dir(corpus::layout::findings_dir(work_dir)) else {
        return set;
    };
    for entry in entries.flatten() {
        let finding_path = entry.path().join("finding.json");
        if fs::metadata(&finding_path).is_ok_and(|metadata| metadata.len() > finding_record_limit) {
            continue;
        }
        let Ok(bytes) = fs::read(&finding_path) else {
            continue;
        };
        let Ok(record) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        if record.get("harness_id").and_then(|value| value.as_str()) != Some(harness_id) {
            continue;
        }
        if set.len() >= dedup_limit {
            break;
        }
        if let Some(key) = crash_testcase_key(&entry.path().join("testcase.bin"), max_len) {
            set.insert(key);
        }
    }
    set
}

/// Compact, allocation-free identity for crash inputs retained only to keep them
/// out of the clean corpus. A collision merely drops one clean corpus entry; it
/// cannot fabricate or suppress the already-emitted crash finding.
fn crash_input_key(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn crash_testcase_key(path: &Path, max_len: usize) -> Option<u64> {
    let metadata = fs::metadata(path).ok()?;
    if metadata.len() == 0 || metadata.len() > max_len as u64 {
        return None;
    }
    let mut file = fs::File::open(path).ok()?;
    let mut hash = 0xcbf29ce484222325_u64;
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buf).ok()?;
        if read == 0 {
            break;
        }
        for byte in &buf[..read] {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    Some(hash)
}

/// Pre-seed the within-pass dedup sets from findings already written to disk so a
/// later cascade pass (Empty/Rng/FuzzDriven) over the SAME harness does not
/// re-emit a finding it already produced (#35: the cascade otherwise wrote the
/// same root cause once per pass, inflating findings.csv / the findings dir /
/// summary counts ~2-3x). Holds the sanitizer-cluster and oracle-hit keys,
/// reconstructed to match the runtime keys [`SanitizerClusterDedup`]
/// ([`corpus::finding::sanitizer_dedupe_key`]) and `oracle_hit_dedupe_key`
/// compute, and each finding's event signature, all mapped to the finding id,
/// so a crash dropped as one of them is reported as a duplicate of that
/// finding. Mirrors `existing_crash_testcases`.
#[derive(Debug, Default)]
struct ExistingFindings {
    /// Sanitizer-crash dedupe key -> finding id.
    clusters: HashMap<String, String>,
    /// Oracle-hit dedupe key -> finding id.
    oracles: HashMap<String, String>,
    /// Event signature (hex) -> finding id, for the event-log lane.
    signatures: HashMap<String, String>,
}

impl ExistingFindings {
    fn load(work_dir: &Path, harness_id: &str) -> Self {
        let finding_record_limit = max_finding_record_bytes();
        let dedup_limit = max_finding_dedup_keys();
        let mut existing = Self::default();
        let Ok(entries) = fs::read_dir(corpus::layout::findings_dir(work_dir)) else {
            return existing;
        };
        for entry in entries.flatten() {
            if existing
                .clusters
                .len()
                .saturating_add(existing.oracles.len())
                >= dedup_limit
                || existing.signatures.len() >= dedup_limit
            {
                break;
            }
            let finding_path = entry.path().join("finding.json");
            if fs::metadata(&finding_path)
                .is_ok_and(|metadata| metadata.len() > finding_record_limit)
            {
                continue;
            }
            let Ok(bytes) = fs::read(finding_path) else {
                continue;
            };
            let Ok(record) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
                continue;
            };
            if record.get("harness_id").and_then(|value| value.as_str()) != Some(harness_id) {
                continue;
            }
            let id = record
                .get("id")
                .and_then(|value| value.as_str())
                .map(str::to_owned)
                .unwrap_or_else(|| entry.file_name().to_string_lossy().into_owned());
            if let Some(signature) = record.get("signature").and_then(|value| value.as_str()) {
                keep_lowest_id(&mut existing.signatures, signature.to_owned(), &id);
            }
            // Oracle hits key on rule_id|oracle_name|api (oracle_hit_dedupe_key),
            // sanitizer crashes on the record's cluster_key_full: the root-cause
            // key the emitter wrote in the harness's crash scope, which is the
            // key corpus::finding::sanitizer_dedupe_key_scoped gives the report
            // at runtime (an older fallback record's is its signature).
            match corpus::finding::run_dedupe_key(&record) {
                Some(corpus::finding::RunDedupeKey::Oracle(key)) => {
                    keep_lowest_id(&mut existing.oracles, key, &id);
                }
                Some(corpus::finding::RunDedupeKey::Cluster(key)) => {
                    keep_lowest_id(&mut existing.clusters, key, &id);
                }
                None => {}
            }
            // A finding that carries ASan's report of an access UBSan's
            // object-size check reported first stands for that UBSan report
            // too: a later hit of it is a duplicate, not a new re-run.
            if let Some(key) = record
                .pointer("/sanitizer_second_opinion/replaced_cluster_key")
                .and_then(|value| value.as_str())
            {
                keep_lowest_id(&mut existing.clusters, key.to_owned(), &id);
            }
        }
        existing
    }
}

/// Map `key` to the lowest finding id that carries it, so the reported
/// duplicate does not depend on directory order.
fn keep_lowest_id(map: &mut HashMap<String, String>, key: String, id: &str) {
    map.entry(key)
        .and_modify(|current| {
            if id < current.as_str() {
                id.clone_into(current);
            }
        })
        .or_insert_with(|| id.to_owned());
}

#[allow(clippy::too_many_arguments)]
fn run_harness(
    runner: &replay_min::HarnessRunner,
    work_dir: &Path,
    input: &[u8],
    extra_env: &[(String, String)],
    per_input_timeout: Duration,
    rss_limit_mb: usize,
    deadline: Option<Duration>,
) -> Result<HarnessRun, String> {
    let protocol = resolve_harness_protocol(runner, work_dir);
    run_harness_with_protocol(
        runner,
        work_dir,
        input,
        extra_env,
        per_input_timeout,
        rss_limit_mb,
        protocol,
        deadline,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_harness_with_protocol(
    runner: &replay_min::HarnessRunner,
    work_dir: &Path,
    input: &[u8],
    extra_env: &[(String, String)],
    per_input_timeout: Duration,
    rss_limit_mb: usize,
    protocol: HarnessProtocol,
    deadline: Option<Duration>,
) -> Result<HarnessRun, String> {
    // The external BHF driver also accepts one input by filename when it is
    // spawned outside its framed loop. In particular, a fork-server crash must
    // be isolated through that argv path; raw stdin makes the driver exit
    // without ever calling the target.
    if protocol == HarnessProtocol::LibFuzzerSingleInput
        || (protocol == HarnessProtocol::BhfFramed
            && read_bounded_marker_text(runner.harness_path(), true).is_none())
    {
        return run_c_libfuzzer_single_input(
            runner,
            work_dir,
            input,
            extra_env,
            per_input_timeout,
            rss_limit_mb,
            deadline,
        );
    }
    let events_path = temp_event_path(work_dir)?;
    let scratch = ensure_harness_scratch(work_dir)?;
    // When a runtrace log is configured (the executable oracles read it), bind
    // its directory read-write into the sandbox so the harness can write events
    // from inside it. No-op when not sandboxed or when it is the events dir.
    let runner_owned;
    let runner = match runtrace_log_dir(extra_env) {
        Some(dir) => {
            runner_owned = runner.clone().with_rw_binds([dir]);
            &runner_owned
        }
        None => runner,
    };
    let mut command = runner
        .command_for_events(&events_path)
        .map_err(|error| error.to_string())?;
    command
        .current_dir(&scratch)
        .env("BHF_EVENTS_PATH", &events_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        command.env(k, v);
    }
    apply_runaway_rlimits(&mut command);
    let mut child = command.spawn().map_err(|error| {
        format!(
            "failed to start harness '{}': {error}",
            runner.harness_path().display()
        )
    })?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| "failed to open harness stdin".to_owned())?;
        // Raw input: per-spawn feeds the whole input as stdin (the AdaFuzz
        // runtime reads framed stdin only under BHF_FRAMED, set by the
        // fork-server). Closing stdin afterwards is the harness loop's EOF.
        //
        // A harness that exits (or stops reading) before consuming the whole
        // input closes the pipe, so `write_all` returns BrokenPipe. That is NOT a
        // harness error — the process ran, and its exit code / stderr below are
        // the real signal (an immediate `exit N` rejection, or a sanitizer crash
        // on the first bytes). Swallow BrokenPipe; only a genuine I/O error aborts.
        if let Err(error) = stdin.write_all(input) {
            if error.kind() != std::io::ErrorKind::BrokenPipe {
                kill_process_group(&mut child);
                let _ = child.wait();
                return Err(format!("write harness stdin: {error}"));
            }
        }
    }
    // Signal EOF to the harness's read loop. `wait_with_output` used to drop the
    // stdin handle implicitly; we poll for exit below (to enforce a wall-clock
    // timeout), so close it explicitly here or the harness blocks awaiting EOF.
    drop(child.stdin.take());
    // Drain stderr on a thread so a chatty harness cannot fill the pipe buffer
    // and stall on write. The collector itself is bounded because target output
    // is untrusted and this path executes once per fuzz input.
    let stderr_reader = drain_child_stderr(child.stderr.take());
    // Enforce `per_input_timeout` as a WALL-CLOCK bound. A hung harness sits at
    // 0% CPU blocked on I/O, so `apply_runaway_rlimits`' RLIMIT_CPU (CPU-time)
    // never fires for it — `wait_with_output` here would block the engine
    // forever. The C/libFuzzer lane already wall-clock-bounds its wait in
    // `run_c_libfuzzer_single_input`; this is the matching guard for the
    // event-log per-spawn lane (the #412 deadlock class).
    let exit_status = match replay_min::process::wait_exit_within(&mut child, per_input_timeout) {
        Ok(Some(status)) => Some(status),
        Ok(None) => {
            kill_process_group(&mut child);
            let _ = child.wait();
            None
        }
        Err(error) => {
            return Err(format!(
                "wait for harness '{}': {error}",
                runner.harness_path().display()
            ));
        }
    };
    let stderr_bytes = stderr_reader
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    let Some(status) = exit_status else {
        // Timed out: a hung input produces no coverage. Discard any partial
        // event log and return a no-event run marked hung, rather than
        // hanging the engine; the pass confirms the hang (#207).
        let _ = fs::remove_file(&events_path);
        return Ok(HarnessRun {
            events: Vec::new(),
            testcases: Vec::new(),
            sanitizer: None,
            stderr: None,
            rejected: false,
            hung: Some(per_input_timeout),
        });
    };
    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr_bytes);
        if let Some(error) = runtime_start_failure_error(runner, &stderr) {
            let _ = fs::remove_file(&events_path);
            return Err(error);
        }
        // C / C++ libFuzzer + AFL++ harnesses do not write an Ada event log -
        // they exit with a non-zero status and a sanitizer report in stderr.
        // Surface that as a structured HarnessRun instead of a hard error so
        // the fuzz loop can emit a finding.
        if let Some(report) = corpus::parse_sanitizer_report(&stderr) {
            let _ = fs::remove_file(&events_path);
            return Ok(HarnessRun {
                events: Vec::new(),
                testcases: Vec::new(),
                sanitizer: Some(report),
                stderr: Some(stderr.to_string()),
                rejected: false,
                hung: None,
            });
        }
        // Hands-off robustness (#15): a diagnosed assertion/panic SIGABRT or a
        // return with NO sanitizer report is the target REJECTING this input — a
        // clean no-event run flagged `rejected` so the pass CONTINUES exploring
        // past the bad input instead of aborting.
        let _ = fs::remove_file(&events_path);
        if is_input_rejection(&status, &stderr) {
            return Ok(HarnessRun {
                events: Vec::new(),
                testcases: Vec::new(),
                sanitizer: None,
                stderr: None,
                rejected: true,
                hung: None,
            });
        }
        // A genuine crash SIGNAL (silent SIGABRT/SIGSEGV/SIGBUS/SIGILL/SIGFPE) with no report is a
        // reachable crash on this input — record it as a BHF-210 finding (surfaces
        // it + keeps the cascade fuzzing) rather than a hard error that aborts the
        // whole pass. Precise ASan/UBSan bugs still classify via their report above.
        return Ok(HarnessRun {
            events: Vec::new(),
            testcases: Vec::new(),
            sanitizer: Some(fatal_signal_report(&status, &stderr)),
            stderr: Some(stderr.to_string()),
            rejected: false,
            hung: None,
        });
    }

    let event_delta_limit = max_event_delta_bytes();
    if fs::metadata(&events_path).is_ok_and(|metadata| metadata.len() > event_delta_limit) {
        let _ = fs::remove_file(&events_path);
        return Err(format!(
            "event log exceeded the {} MiB per-execution memory cap (raise \
             BHF_MAX_EVENT_DELTA_BYTES if intended)",
            event_delta_limit / (1024 * 1024)
        ));
    }
    let event_bytes = match fs::read(&events_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // The harness exited without ever calling Begin_Testcase (typical
            // when stdin was empty and the AdaFuzz.Input loop exited
            // immediately). Treat as a zero-event clean run rather than a
            // hard error.
            return Ok(HarnessRun {
                events: Vec::new(),
                testcases: Vec::new(),
                sanitizer: None,
                stderr: None,
                rejected: false,
                hung: None,
            });
        }
        Err(error) => {
            return Err(format!(
                "read event log '{}': {error}",
                events_path.display()
            ));
        }
    };
    let _ = fs::remove_file(&events_path);
    let events = EventReader::new(event_bytes.as_slice())
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("read event log '{}': {error}", events_path.display()))?;
    let testcases = group_into_testcases(EventReader::new(event_bytes.as_slice()))
        .map_err(|error| format!("group event log '{}': {error}", events_path.display()))?;

    Ok(HarnessRun {
        events,
        testcases,
        sanitizer: None,
        stderr: None,
        rejected: false,
        hung: None,
    })
}

/// An edge-coverage map for replaying inputs one at a time (#282): the
/// `BHF_COV_SHM` file every lane's driver writes the edges an input reaches
/// to. Removed when it drops.
pub(crate) struct ReplayCoverageMap {
    _map: shared_map::SharedMapFile,
    path: String,
}

impl ReplayCoverageMap {
    pub(crate) fn create(work_dir: &Path) -> Result<Self, String> {
        let (map, path) = arm_shared_map(work_dir, BHF_COV_BITS)?;
        Ok(Self { _map: map, path })
    }

    /// Replay `input` in a fresh process of `runner`'s harness with the map
    /// cleared: the event-log testcases it gives (Ada's) and the edges its
    /// driver wrote to the map.
    pub(crate) fn replay(
        &self,
        runner: &replay_min::HarnessRunner,
        work_dir: &Path,
        input: &[u8],
    ) -> Result<(Vec<Testcase>, Vec<u32>), String> {
        fs::write(&self.path, vec![0u8; BHF_COV_BITS])
            .map_err(|error| format!("clear the coverage map {}: {error}", self.path))?;
        let env = [("BHF_COV_SHM".to_owned(), self.path.clone())];
        let run = run_harness(runner, work_dir, input, &env, PER_INPUT_TIMEOUT, 0, None)?;
        let map = fs::read(&self.path)
            .map_err(|error| format!("read the coverage map {}: {error}", self.path))?;
        let edges = map
            .iter()
            .enumerate()
            .filter(|(_, byte)| **byte != 0)
            .filter_map(|(index, _)| u32::try_from(index).ok())
            .collect();
        Ok((run.testcases, edges))
    }
}

/// Replay-verify a C/C++ sanitizer crash (#388): re-run the input in a fresh
/// process and confirm it reproduces the same sanitizer crash (rule, kind and
/// sink or reported site, see [`crate::crash_identity::same_crash`]).
/// A passthrough libFuzzer harness can corrupt allocator state across inputs
/// and crash in driver glue even on empty input; those faults do not reproduce
/// and must not be reported (libFuzzer/AFL find zero on that class).
#[allow(clippy::too_many_arguments)]
fn sanitizer_crash_reproduces(
    runner: &replay_min::HarnessRunner,
    work_dir: &Path,
    input: &[u8],
    report: &corpus::SanitizerReport,
    extra_env: &[(String, String)],
    per_input_timeout: Duration,
    rss_limit_mb: usize,
    deadline: Option<Duration>,
) -> bool {
    // Replay-verify MUST reconstruct the same environment the crash occurred
    // under — the runtrace shim's LD_PRELOAD + BHF_RUNTRACE_MODE that inject
    // env vars / fake resources. Re-running with an empty env spuriously fails to
    // reproduce env-triggered crashes (e.g. getenv-gated faults) and drops real
    // findings. The deadline is threaded through so a BHF-555 timing finding
    // replays under the same budget it was recorded with (else its re-run, seeing
    // no crash, would spuriously fail to reproduce and be dropped).
    match run_c_libfuzzer_single_input(
        runner,
        work_dir,
        input,
        extra_env,
        per_input_timeout,
        rss_limit_mb,
        deadline,
    ) {
        // The same crash: rule, kind and sink (or reported site), compared
        // the way `bhf replay` compares a reproduction with its finding.
        Ok(rerun) => rerun
            .sanitizer
            .as_ref()
            .is_some_and(|fresh| crate::crash_identity::same_crash(report, fresh)),
        Err(_) => false,
    }
}

/// The catalog rule of an input that hangs the target (#207).
const HANG_RULE: &str = "BHF-230";

/// Whether `function` is instrumentation a stop signal can interrupt inside a
/// loop (a coverage or comparison callback, a sanitizer hook or interceptor,
/// bhf's driver runtime), not the code that loops.
fn is_instrumentation_frame(function: &str) -> bool {
    [
        "__sanitizer_",
        "__asan",
        "__ubsan",
        "__msan",
        "__tsan",
        "__lsan",
        "__interceptor_",
        "bhf_",
    ]
    .iter()
    .any(|prefix| function.starts_with(prefix))
}

/// How many hangs one pass re-runs to confirm. A re-run costs twice the
/// per-input timeout, and an input that hangs a loop is usually one of many
/// mutants that do: past this many, later hangs are counted, not re-run.
const MAX_HANG_CONFIRMATIONS: usize = 4;

/// The executions of one builtin pass that were killed at the per-input
/// timeout, and what their confirmation re-runs showed (#207).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct HangRunSummary {
    /// The per-input timeout, in milliseconds.
    pub timeout_ms: u64,
    /// Executions killed at the per-input timeout.
    pub observed: usize,
    /// Hangs that hung again when re-run in a fresh process with twice the
    /// timeout. Each is a finding, or a later hit of one.
    pub confirmed: usize,
    /// Hangs whose re-run finished: one slow execution, not a finding.
    pub cleared: usize,
    /// Hangs not re-run: the pass had already re-run
    /// [`MAX_HANG_CONFIRMATIONS`], or too little of its time was left.
    pub not_rerun: usize,
}

/// What re-running a hung input showed.
enum HangConfirmation {
    /// It hung again: the hang report and the stderr it was made from.
    Hung(Box<corpus::SanitizerReport>, String),
    /// Given the time, it crashed: that report and its stderr (deep recursion
    /// under an interpreter's coverage hook can outlast the timeout).
    Crashed(Box<corpus::SanitizerReport>, String),
    /// It finished: one slow execution.
    Finished,
    /// It was not re-run: too little of the pass's time was left.
    NotRerun,
}

/// The environment a hang confirmation runs under: `extra_env`, its
/// `<SAN>_OPTIONS` with `handle_abort=1`, so the runtime answers
/// [`signal_for_stack`] with the stack the target is looping in, and
/// `BHF_HANG_REPORT_MS`, when an interpreted lane's driver prints the frames
/// its target is running and halts ([`HANG_REPORT_ENV`]).
fn hang_stack_env(extra_env: &[(String, String)], confirm: Duration) -> Vec<(String, String)> {
    let mut env = extra_env.to_vec();
    env.retain(|(name, _)| name != HANG_REPORT_ENV);
    env.push((HANG_REPORT_ENV.to_owned(), confirm.as_millis().to_string()));
    for key in [
        "ASAN_OPTIONS",
        "HWASAN_OPTIONS",
        "UBSAN_OPTIONS",
        "MSAN_OPTIONS",
        "TSAN_OPTIONS",
    ] {
        match env.iter_mut().find(|(name, _)| name == key) {
            Some((_, value)) => {
                *value = corpus::sanitizer_options::merge(Some(value), "handle_abort=1");
            }
            None => env.push((
                key.to_owned(),
                corpus::sanitizer_options::merge(
                    std::env::var(key).ok().as_deref(),
                    "handle_abort=1",
                ),
            )),
        }
    }
    env
}

/// When an interpreted lane's driver reports the frames its target is
/// running: at the re-run's `confirm` limit. An interpreter answers no signal
/// while its target loops in bytecode, so the driver keeps the time, and bhf
/// stops the re-run only [`hang_report_slack`] after the limit.
const HANG_REPORT_ENV: &str = "BHF_HANG_REPORT_MS";

/// How long past its limit a hang confirmation runs, so a driver that reports
/// at the limit is not stopped first: half the limit, at most 2s.
fn hang_report_slack(confirm: Duration) -> Duration {
    (confirm / 2).min(Duration::from_secs(2))
}

/// Re-run an input that hung at `per_input_timeout` in a fresh process with
/// twice that (and [`hang_report_slack`] more, for an interpreted lane's
/// driver to report the frames it is running), asking the process for its
/// stack if it hangs again: it has up to [`HANG_STACK_GRACE`] to print it, or
/// what is left of the pass after the re-run if that is less. Not re-run when
/// the pass has less time left than the re-run itself.
fn confirm_hang(
    runner: &replay_min::HarnessRunner,
    work_dir: &Path,
    input: &[u8],
    extra_env: &[(String, String)],
    per_input_timeout: Duration,
    rss_limit_mb: usize,
    pass_deadline: Option<Instant>,
) -> Result<HangConfirmation, String> {
    let confirm = per_input_timeout.saturating_mul(2);
    let limit = confirm + hang_report_slack(confirm);
    let grace = match pass_deadline {
        Some(deadline) => {
            let left = deadline.saturating_duration_since(Instant::now());
            if left < limit {
                return Ok(HangConfirmation::NotRerun);
            }
            HANG_STACK_GRACE.min(left - limit)
        }
        None => HANG_STACK_GRACE,
    };
    let input_path = write_fuzz_input(work_dir, input)?;
    let output = run_with_timeout(
        runner.harness_path(),
        &input_path,
        limit,
        &hang_stack_env(extra_env, confirm),
        &ensure_harness_scratch(work_dir)?,
        rss_limit_mb,
        runner.qemu_prefix(),
        SpawnTweaks {
            stack_on_timeout: Some(grace),
            ..SpawnTweaks::default()
        },
    );
    let _ = fs::remove_file(&input_path);
    let stderr = String::from_utf8_lossy(&output?.stderr).into_owned();
    // Stopped at the limit, or a driver reported its target still running.
    let hung = stderr.contains("exceeded per-input timeout")
        || stderr.contains(corpus::sanitizer::HANG_MARKER);
    if !hung {
        return Ok(match corpus::parse_sanitizer_report(&stderr) {
            Some(report) => HangConfirmation::Crashed(Box::new(report), stderr),
            None => HangConfirmation::Finished,
        });
    }
    let report = hang_report(&stderr, per_input_timeout, confirm);
    Ok(HangConfirmation::Hung(Box::new(report), stderr))
}

/// The BHF-230 report of a confirmed hang. Its stack is the one the re-run
/// gave ([`corpus::sanitizer::hang_frames`]: an interpreted lane's driver
/// frames, the Go runtime's goroutine dump, or the sanitizer runtime's report
/// when [`signal_for_stack`] stopped it), from the first frame that is not
/// instrumentation; the signal's own report is not the finding. Keyed on the
/// stack's functions alone, so two inputs looping on different lines of one
/// loop are one finding.
fn hang_report(stderr: &str, timeout: Duration, confirm: Duration) -> corpus::SanitizerReport {
    let mut stack = corpus::sanitizer::hang_frames(stderr);
    if let Some(looping) = stack
        .iter()
        .position(|frame| !is_instrumentation_frame(&frame.function))
    {
        stack.drain(..looping);
    }
    corpus::SanitizerReport {
        sanitizer: None,
        kind: "timeout".to_owned(),
        rule_id: HANG_RULE,
        stack,
        message: format!(
            "harness did not finish within the per-input timeout ({}), and hung again when \
             re-run with twice that ({})",
            duration_arg(timeout),
            duration_arg(confirm)
        ),
        ..Default::default()
    }
}

/// The launcher beside a .NET harness's `main` that runs its build as it was
/// before SharpFuzz instrumented it, with the debug symbols the instrumented
/// assembly lost (#212).
pub(crate) const DOTNET_SYMBOLS_LAUNCHER: &str = "main_symbols";

/// `report` with the source lines of its frames, when it names none and the
/// harness has [`DOTNET_SYMBOLS_LAUNCHER`]: the input re-run through the
/// uninstrumented build, whose report must be the same exception. Its stderr
/// comes with it, as the finding's log. `None` otherwise.
fn dotnet_symbolized_report(
    runner: &replay_min::HarnessRunner,
    work_dir: &Path,
    input: &[u8],
    report: &corpus::SanitizerReport,
    extra_env: &[(String, String)],
    per_input_timeout: Duration,
    rss_limit_mb: usize,
) -> Option<(corpus::SanitizerReport, String)> {
    if report.stack.is_empty() || report.stack.iter().any(|frame| frame.line.is_some()) {
        return None;
    }
    let launcher = runner
        .harness_path()
        .with_file_name(DOTNET_SYMBOLS_LAUNCHER);
    if !launcher.is_file() {
        return None;
    }
    let input_path = write_fuzz_input(work_dir, input).ok()?;
    let output = run_with_timeout(
        &launcher,
        &input_path,
        per_input_timeout,
        extra_env,
        &ensure_harness_scratch(work_dir).ok()?,
        rss_limit_mb,
        None,
        SpawnTweaks::default(),
    );
    let _ = fs::remove_file(&input_path);
    let stderr = String::from_utf8_lossy(&output.ok()?.stderr).into_owned();
    let symbolized = corpus::parse_sanitizer_report(&stderr)?;
    (symbolized.rule_id == report.rule_id
        && symbolized.kind == report.kind
        && symbolized.stack.iter().any(|frame| frame.line.is_some()))
    .then_some((symbolized, stderr))
}

/// The UBSan suppressions that turn its `object-size` check off at run time.
const OBJECT_SIZE_SUPPRESSIONS: &str = "object-size:*\n";

/// What re-running a UBSan insufficient-object-size report's input with that
/// check suppressed showed, which decides the report a finding carries.
#[derive(Debug)]
struct ObjectSizeSecondOpinion {
    /// ASan's report of the same access and the stderr it came in, when ASan
    /// reported it: the finding carries it instead.
    asan: Option<(corpus::SanitizerReport, Option<String>)>,
    /// Why the finding carries the report it does.
    reason: String,
}

impl ObjectSizeSecondOpinion {
    /// The finding's `sanitizer_second_opinion`: the check, the report it
    /// carries (`asan` or `ubsan`) and why. When it carries ASan's, also the
    /// dedupe key of the UBSan report it replaced (`replaced_key`), so a later
    /// pass counts a hit of that report against this finding without re-running
    /// it ([`ExistingFindings::load`]).
    fn to_json(&self, replaced_key: &str) -> serde_json::Value {
        let mut opinion = serde_json::json!({
            "check": "object-size",
            "used": if self.asan.is_some() { "asan" } else { "ubsan" },
            "reason": self.reason,
        });
        if self.asan.is_some() {
            opinion["replaced_cluster_key"] = serde_json::json!(replaced_key);
        }
        opinion
    }

    /// Record [`Self::to_json`] in the finding `finding_id`.
    fn record(&self, work_dir: &Path, finding_id: &str, replaced_key: &str) {
        let path = corpus::layout::finding_dir(work_dir, finding_id).join("finding.json");
        let recorded = fs::read(&path)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                let mut finding: serde_json::Value =
                    serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
                finding["sanitizer_second_opinion"] = self.to_json(replaced_key);
                let bytes =
                    serde_json::to_vec_pretty(&finding).map_err(|error| error.to_string())?;
                crate::auto::report::atomic_write(&path, &bytes).map_err(|error| error.to_string())
            });
        if let Err(error) = recorded {
            bhfeprintln!(
                "warning: could not record the sanitizer second opinion of {finding_id}: {error}"
            );
        }
    }
}

/// The second opinion on a UBSan insufficient-object-size `report`, or `None`
/// for any other report. UBSan's object-size check guards the same access as
/// ASan's own check and fires first when the compiler knows the object's size:
/// in a gcc build for a heap or stack overflow, in a clang build for a member
/// access through an undersized heap block. Either is the overflow ASan
/// reports with clang. `rerun` runs the input once more in a fresh process
/// with the environment and time limit it is given: the check suppressed, and
/// the per-input timeout or what is left before `deadline` when that is less.
/// An ASan report of the same sink and access direction is the overflow as
/// ASan reports it. When ASan stays silent the UBSan report
/// stands: memory ASan does not track (a pool allocator's chunks, which gcc's
/// check sees through `alloc_size`), or an object smaller than its type whose
/// accessed bytes are in bounds. The caller asks only for the first sighting
/// of a root cause.
fn object_size_second_opinion(
    work_dir: &Path,
    report: &corpus::SanitizerReport,
    extra_env: &[(String, String)],
    per_input_timeout: Duration,
    deadline: Option<Instant>,
    rerun: impl FnOnce(
        &[(String, String)],
        Duration,
    ) -> Result<(Option<corpus::SanitizerReport>, Option<String>), String>,
) -> Option<ObjectSizeSecondOpinion> {
    if report.sanitizer != Some(corpus::Sanitizer::UndefinedBehaviorSanitizer)
        || report.kind != "insufficient-object-size"
    {
        return None;
    }
    let stands = |why: String| {
        Some(ObjectSizeSecondOpinion {
            asan: None,
            reason: format!("UBSan's object-size report stands: {why}"),
        })
    };
    let timeout = match deadline {
        Some(deadline) => per_input_timeout.min(deadline.saturating_duration_since(Instant::now())),
        None => per_input_timeout,
    };
    if timeout.is_zero() {
        return stands(
            "the pass's time ran out before a re-run with the check suppressed".to_owned(),
        );
    }
    let suppressions = work_dir.join("fuzz_inputs").join("bhf-object-size.supp");
    let written = suppressions
        .parent()
        .map_or(Ok(()), fs::create_dir_all)
        .and_then(|()| fs::write(&suppressions, OBJECT_SIZE_SUPPRESSIONS));
    if let Err(error) = written {
        return stands(format!(
            "the suppressions file for a re-run could not be written: {error}"
        ));
    }
    let mut env = extra_env.to_vec();
    let option = format!("suppressions=\"{}\"", suppressions.display());
    match env.iter_mut().find(|(key, _)| key == "UBSAN_OPTIONS") {
        Some((_, value)) => {
            value.push(':');
            value.push_str(&option);
        }
        None => env.push((
            "UBSAN_OPTIONS".to_owned(),
            format!("{}:{option}", ubsan_child_options()),
        )),
    }
    let started = Instant::now();
    let (view, stderr) = match rerun(&env, timeout) {
        Ok(rerun) => rerun,
        Err(error) => {
            return stands(format!(
                "the re-run with the check suppressed failed: {error}"
            ))
        }
    };
    let direction = |report: &corpus::SanitizerReport| match &report.access {
        Some(access) => access.direction,
        None if report.message.contains("runtime error: store to ") => {
            corpus::sanitizer::AccessDirection::Write
        }
        None if report.message.contains("runtime error: load of ") => {
            corpus::sanitizer::AccessDirection::Read
        }
        None => corpus::sanitizer::AccessDirection::Unknown,
    };
    let sink = crate::crash_identity::replayed_sink(report);
    let same_access = |view: &corpus::SanitizerReport| {
        let unknown = corpus::sanitizer::AccessDirection::Unknown;
        view.sanitizer == Some(corpus::Sanitizer::AddressSanitizer)
            && sink.is_some()
            && crate::crash_identity::replayed_sink(view) == sink
            && (direction(report) == unknown
                || direction(view) == unknown
                || direction(report) == direction(view))
    };
    match view {
        Some(view) if same_access(&view) => Some(ObjectSizeSecondOpinion {
            reason: format!(
                "UBSan's object-size check reported this access before ASan; with the check \
                 suppressed, AddressSanitizer reported {} at the same sink",
                view.kind
            ),
            asan: Some((view, stderr)),
        }),
        Some(other) => stands(format!(
            "with the check suppressed, the re-run reported {} ({}), not ASan's report of \
             the same access",
            other.kind, other.rule_id
        )),
        None if started.elapsed() >= timeout => stands(format!(
            "the re-run with the check suppressed reached its {timeout:?} time limit"
        )),
        None => stands(
            "with the check suppressed, the re-run reported no error: ASan saw no \
             access outside the memory it tracks"
                .to_owned(),
        ),
    }
}

/// The input format of the generated harness at `harness`: the
/// `generation-metadata.json` beside the binary, else in the work dir's harness
/// dirs for `harness_id` (a binary `bhf build` staged alone into `build/<id>/`).
/// `None` for a harness bhf did not generate.
pub(crate) fn harness_format_for(
    harness: &Path,
    work_dir: &Path,
    harness_id: &str,
) -> Option<crate::generate_harness::RecordedHarnessFormat> {
    let beside = harness.parent().map(Path::to_path_buf);
    beside
        .into_iter()
        .chain(crate::auto::layout::harness_dir_candidates(
            work_dir, harness_id,
        ))
        .filter(|dir| dir.join("generation-metadata.json").is_file())
        .find_map(|dir| crate::generate_harness::recorded_harness_format(&dir))
}

/// Stamp the generated harness's input format (its version, and the explicit
/// buffer-length dimension when on) on every finding `emitter` writes.
fn with_harness_format(
    emitter: FindingEmitter,
    harness: &Path,
    work_dir: &Path,
    harness_id: &str,
) -> FindingEmitter {
    let format = harness_format_for(harness, work_dir, harness_id);
    emitter
        .with_harness_format_version(format.as_ref().map(|format| format.version))
        .with_buffer_len_dimension(format.is_some_and(|format| format.buffer_len_dimension))
        .with_crash_scope(run_crash_scope(harness, work_dir, harness_id))
}

/// What this run's crashes without frames or a source position are grouped
/// by ([`corpus::cluster::crash_scope`]): the harness id and the function its
/// generation metadata names, read beside the binary or in the harness's dirs
/// of the work dir (for a binary `bhf build` staged into `build/<id>/`). The
/// emitter and the run's dedupe use the same scope.
pub(crate) fn run_crash_scope(harness: &Path, work_dir: &Path, harness_id: &str) -> String {
    let target = harness
        .parent()
        .map(Path::to_path_buf)
        .into_iter()
        .chain(crate::auto::layout::harness_dir_candidates(
            work_dir, harness_id,
        ))
        .find_map(|dir| crate::generate_harness::recorded_target_function(&dir));
    corpus::cluster::crash_scope(harness_id, target.as_deref())
}

/// Bounds on the argument-trace re-run of a new finding: the run's per-input
/// timeout, but never less than a sanitized harness needs to start and never
/// more than a single replay is allowed.
const ARG_TRACE_TIMEOUT_MIN: Duration = Duration::from_secs(5);
const ARG_TRACE_TIMEOUT_MAX: Duration = Duration::from_secs(30);
/// The AFL++ lane has no per-input timeout of its own here.
const AFL_REPLAY_TRACE_TIMEOUT: Duration = Duration::from_secs(10);

/// How a C/C++ harness takes the testcase for an argument-trace run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TraceInput {
    /// `./harness <file>`: generated harnesses, the bhf driver, libFuzzer.
    ArgvFile,
    /// The bytes on stdin: AFL++ persistent-mode harnesses.
    Stdin,
}

/// Whether a harness binary was generated with the argument trace: the name of
/// the `BHF_TRACE_ARGS` switch is compiled into every harness that has one.
pub(crate) fn harness_has_arg_trace(harness: &Path) -> bool {
    let Ok(bytes) = fs::read(harness) else {
        return false;
    };
    let needle = corpus::decoded_args::TRACE_ARGS_ENV.as_bytes();
    bytes.windows(needle.len()).any(|window| window == needle)
}

/// Run `harness` once on `input` with its argument trace on and parse the
/// `BHF_ARG` lines it prints. A harness without the trace, a failed run or a
/// run that prints no trace lines is `Unavailable`, saying why. With it comes
/// the trace run's own sanitizer report, when it printed one: the traced
/// pointers are addresses in that run, not in the finding's (see
/// [`corpus::decoded_args::record_trace_of_run`]).
#[allow(clippy::too_many_arguments)]
pub(crate) fn trace_arguments(
    harness: &Path,
    work_dir: &Path,
    input: &[u8],
    mode: TraceInput,
    extra_env: &[(String, String)],
    timeout: Duration,
    qemu_prefix: Option<(&Path, &[String])>,
) -> (
    corpus::decoded_args::TraceOutcome,
    Option<corpus::sanitizer::SanitizerReport>,
) {
    use corpus::decoded_args::TraceOutcome;
    // A harness that hands the input to the project's own
    // `LLVMFuzzerTestOneInput` has no parameters to decode.
    let mut source_dirs: Vec<PathBuf> = harness
        .parent()
        .map(Path::to_path_buf)
        .into_iter()
        .collect();
    if let Some(id) = harness
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
    {
        source_dirs.extend(crate::auto::layout::harness_dir_candidates(work_dir, id));
    }
    if crate::replay::is_passthrough_harness(&source_dirs) {
        return (
            TraceOutcome::Unavailable(crate::replay::PASSTHROUGH_NO_ARGUMENTS.to_owned()),
            None,
        );
    }
    if !harness_has_arg_trace(harness) {
        return (
            TraceOutcome::Unavailable(
                "the harness was built without the argument trace; regenerate it with this bhf \
                 (or read the arguments under a debugger, see the C/C++ guide)"
                    .to_owned(),
            ),
            None,
        );
    }
    let mut env = extra_env.to_vec();
    env.retain(|(key, _)| key != corpus::decoded_args::TRACE_ARGS_ENV);
    env.push((
        corpus::decoded_args::TRACE_ARGS_ENV.to_owned(),
        "1".to_owned(),
    ));
    let stderr = match mode {
        TraceInput::ArgvFile => {
            run_traced_argv(harness, work_dir, input, &env, timeout, qemu_prefix)
        }
        TraceInput::Stdin => run_traced_stdin(harness, work_dir, input, &env, timeout),
    };
    match stderr {
        Ok(stderr) => {
            let text = String::from_utf8_lossy(&stderr);
            let args = corpus::decoded_args::parse_arg_trace(&text);
            if args.is_empty() {
                (
                    TraceOutcome::Unavailable(
                        "the argument-trace run printed no BHF_ARG lines (the harness takes no \
                         decoded arguments, or failed before decoding them)"
                            .to_owned(),
                    ),
                    None,
                )
            } else {
                let report = corpus::sanitizer::parse_sanitizer_report(&text);
                (TraceOutcome::Traced(args), report)
            }
        }
        Err(error) => (
            TraceOutcome::Unavailable(format!("the argument-trace run failed: {error}")),
            None,
        ),
    }
}

fn run_traced_argv(
    harness: &Path,
    work_dir: &Path,
    input: &[u8],
    env: &[(String, String)],
    timeout: Duration,
    qemu_prefix: Option<(&Path, &[String])>,
) -> Result<Vec<u8>, String> {
    let dir = work_dir.join("fuzz_inputs");
    fs::create_dir_all(&dir)
        .map_err(|error| format!("create fuzz inputs dir '{}': {error}", dir.display()))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = dir.join(format!("trace-{}-{nonce}.bin", std::process::id()));
    fs::write(&path, input)
        .map_err(|error| format!("write trace input '{}': {error}", path.display()))?;
    let output = run_with_timeout(
        harness,
        &path,
        timeout,
        env,
        &ensure_harness_scratch(work_dir)?,
        0,
        qemu_prefix,
        SpawnTweaks::default(),
    );
    let _ = fs::remove_file(&path);
    Ok(output?.stderr)
}

fn run_traced_stdin(
    harness: &Path,
    work_dir: &Path,
    input: &[u8],
    env: &[(String, String)],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let mut command = std::process::Command::new(harness);
    command
        .current_dir(ensure_harness_scratch(work_dir)?)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (key, value) in env {
        command.env(key, value);
    }
    apply_runaway_rlimits(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| format!("spawn '{}': {error}", harness.display()))?;
    let stderr_reader = drain_child_stderr(child.stderr.take());
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input);
    }
    match replay_min::process::wait_exit_within(&mut child, timeout) {
        Ok(Some(status)) => Ok(collected_child_output(status, stderr_reader).stderr),
        Ok(None) => {
            kill_process_group(&mut child);
            let status = child
                .wait()
                .map_err(|error| format!("reap '{}': {error}", harness.display()))?;
            Ok(collected_child_output(status, stderr_reader).stderr)
        }
        Err(error) => {
            kill_process_group(&mut child);
            let _ = child.wait();
            Err(format!("poll '{}': {error}", harness.display()))
        }
    }
}

/// Record the decoded arguments of a new C/C++ finding: re-run its testcase
/// once with the argument trace on and write them to its `decoded.json` and
/// `finding.json` (see [`corpus::decoded_args::record_trace`]). Called once per
/// emitted finding, which is once per new crash cluster.
#[allow(clippy::too_many_arguments)]
fn record_finding_arguments(
    work_dir: &Path,
    finding_id: &str,
    harness: &Path,
    input: &[u8],
    mode: TraceInput,
    extra_env: &[(String, String)],
    per_input_timeout: Duration,
    qemu_prefix: Option<(&Path, &[String])>,
) {
    let timeout = per_input_timeout.clamp(ARG_TRACE_TIMEOUT_MIN, ARG_TRACE_TIMEOUT_MAX);
    let (outcome, run_report) = trace_arguments(
        harness,
        work_dir,
        input,
        mode,
        extra_env,
        timeout,
        qemu_prefix,
    );
    let finding_dir = corpus::layout::finding_dir(work_dir, finding_id);
    if let Err(error) = corpus::decoded_args::record_trace_of_run(
        &finding_dir,
        input,
        &outcome,
        run_report.as_ref(),
    ) {
        bhfeprintln!("warning: could not record the decoded arguments of {finding_id}: {error}");
    }
}

/// Re-run `input` in a fresh per-spawn process and report whether the finding
/// `signature` reproduces. Used to validate fork-server findings so an artifact
/// of accumulated global state is never emitted as a finding (it would not
/// reproduce from the testcase alone, the canonical replay).
fn finding_reproduces_per_spawn(
    prepared: &PreparedFuzzRun,
    input: &[u8],
    signature: &Signature,
) -> Result<bool, String> {
    let run = run_harness(
        &prepared.runner,
        &prepared.work_dir,
        input,
        &prepared.extra_env,
        prepared.per_input_timeout,
        prepared.rss_limit_mb,
        prepared.deadline,
    )?;
    if run.sanitizer.is_some() {
        return Ok(true);
    }
    for testcase in &run.testcases {
        for (handler_index, _) in classify(testcase) {
            if let Some(handler) = resolve_handler(testcase, handler_index) {
                if compute_signature(testcase, handler.as_ref()) == *signature {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// Resolve whether the persistent fork-server runs. It is the **default** (it
/// keeps the coverage-guided feedback while amortizing fork/exec/elaboration,
/// and replay-validates every finding so it is safe). `--fork-server` forces it
/// on; `--no-fork-server` or `BHF_FORK_SERVER=0` turn it off.
fn resolve_fork_server(force_on: bool, force_off: bool) -> bool {
    if force_on {
        return true;
    }
    if force_off {
        return false;
    }
    std::env::var("BHF_FORK_SERVER").as_deref() != Ok("0")
}

/// A persistent harness process driven one input at a time over the framed
/// stdin protocol. Used only for the common clean path; a hard crash falls back
/// to per-spawn `run_harness` (which isolates and reports it precisely) and the
/// caller respawns the server.
struct ForkServer {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: std::process::ChildStdout,
    events_path: PathBuf,
    events_offset: u64,
    /// Per-input RSS ceiling (MB), mirrored from the run so the persistent
    /// process enforces `--rss-limit-mb` too. 0 disables. Without this the
    /// fork-server path (the common driver path since #399) silently ignored the
    /// limit — only the per-spawn fallback enforced it.
    rss_limit_mb: usize,
    /// Per-input protocol wait, inherited from the run's effective timeout.
    /// Keeping this on the server prevents its persistent fast path from using a
    /// looser timeout than the per-spawn fallback or the enclosing pass budget.
    run_timeout_ms: i32,
    /// The harness asked for hex frames ([`TEXT_FRAMES_READY`]).
    text_frames: bool,
}

enum ForkOutcome {
    /// Boxed: a run result carries the parsed sanitizer report.
    Ran(Box<HarnessRun>),
    /// The process exited/crashed/hung handling this input; respawn + re-run.
    Died,
}

/// How long a harness that may not speak the framed protocol gets to write its
/// "ready" sync byte. Anything that does not speak it (a stale build, a test
/// mock) never does, so spawn bails to per-spawn after this short probe.
const FORK_HANDSHAKE_PROBE: Duration = Duration::from_secs(2);
/// The least time a harness known to speak the framed protocol gets to start.
/// Startup can take far longer than one input (a runtime to load, static
/// initialisers, a loaded machine), and a missed handshake drops the rest of
/// the run to a fresh process per input.
const FORK_STARTUP_FLOOR: Duration = Duration::from_secs(10);

/// The last part of a pass (one over this share of `--time`) in which the loop
/// stops issuing inputs once the fresh re-runs still out need the time left.
const FRESH_RERUN_DRAIN_SHARE: u32 = 4;
/// The least of a pass the loop may give to its fresh re-runs: all of a
/// shorter pass. A quarter of a pass of a few seconds is too little to check
/// the handful of inputs it finds, and an input left unchecked stays out of the
/// queue. A re-run started in that window is not lowered either: beside busy
/// processes a lowered one waits seconds for a CPU (a 2 s re-run took 8 s at
/// nice +10 next to eight busy loops on two CPUs, 3 s at normal priority), so
/// it would outlast a short pass.
const FRESH_RERUN_DRAIN_FLOOR: Duration = Duration::from_secs(5);

/// How much of the end of a `budget`-long pass the loop may give to the fresh
/// re-runs still out: [`FRESH_RERUN_DRAIN_SHARE`] of it, but at least
/// [`FRESH_RERUN_DRAIN_FLOOR`], and all of a pass shorter than that. Within it
/// the loop stops issuing inputs once their measured re-run time
/// ([`FreshReruns::drain_estimate`]) needs what is left.
fn fresh_rerun_drain_window(budget: Duration) -> Duration {
    (budget / FRESH_RERUN_DRAIN_SHARE).max(budget.min(FRESH_RERUN_DRAIN_FLOOR))
}

#[cfg(test)]
#[test]
fn a_short_pass_may_give_all_its_time_to_its_fresh_reruns() {
    let window = |millis| fresh_rerun_drain_window(Duration::from_millis(millis));
    // A pass of `bhf auto --per-target-time 2`, split three ways.
    assert_eq!(window(333), Duration::from_millis(333));
    assert_eq!(window(4_000), Duration::from_secs(4));
    assert_eq!(window(5_000), Duration::from_secs(5));
    assert_eq!(window(8_000), Duration::from_secs(5));
    // A longer pass keeps three quarters of its time for fuzzing.
    assert_eq!(window(20_000), Duration::from_secs(5));
    assert_eq!(window(60_000), Duration::from_secs(15));
}

/// The rule of a response-deadline (`--deadline`) report.
const RESPONSE_DEADLINE_RULE: &str = "BHF-555";

/// How a run overran the response deadline, as its BHF-555 report and the
/// stderr line put it.
fn deadline_overrun(deadline: Duration, elapsed: Duration) -> String {
    format!("exceeded the response deadline of {deadline:?} (took {elapsed:?})")
}

/// [`deadline_overrun`] read back from a BHF-555 report's message.
fn deadline_overrun_of(report: &corpus::SanitizerReport) -> &str {
    report
        .message
        .strip_prefix("harness ")
        .unwrap_or(&report.message)
}

/// How many fresh runs re-check a response-deadline overrun (#209). It is a
/// finding when most of them overrun the deadline too: one run slowed by a
/// loaded host is not.
const DEADLINE_CONFIRM_RUNS: usize = 3;

/// The fresh re-runs of an input that overran `--deadline`, timed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DeadlineConfirmation {
    deadline: Duration,
    /// Each re-run's wall-clock time, in order.
    runs: Vec<Duration>,
}

impl DeadlineConfirmation {
    fn overruns(&self) -> usize {
        self.runs
            .iter()
            .filter(|took| **took > self.deadline)
            .count()
    }

    /// Whether most of [`DEADLINE_CONFIRM_RUNS`] re-runs overran the deadline.
    fn confirmed(&self) -> bool {
        self.overruns() * 2 > DEADLINE_CONFIRM_RUNS
    }

    /// `2 of 2 fresh re-runs overran it too (took 1.0s, 1.0s)`.
    fn describe(&self) -> String {
        let took: Vec<String> = self.runs.iter().map(|took| duration_arg(*took)).collect();
        format!(
            "{} of {} fresh re-runs overran it too (took {})",
            self.overruns(),
            self.runs.len(),
            if took.is_empty() {
                "-".to_owned()
            } else {
                took.join(", ")
            }
        )
    }

    fn to_json(&self) -> serde_json::Value {
        let ms = |took: &Duration| u64::try_from(took.as_millis()).unwrap_or(u64::MAX);
        serde_json::json!({
            "deadline_ms": ms(&self.deadline),
            "rerun_ms": self.runs.iter().map(ms).collect::<Vec<_>>(),
            "overruns": self.overruns(),
        })
    }

    /// Record [`Self::to_json`] as the finding's `deadline_confirmation`.
    fn record(&self, work_dir: &Path, finding_id: &str) {
        let path = corpus::layout::finding_dir(work_dir, finding_id).join("finding.json");
        let recorded = fs::read(&path)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                let mut finding: serde_json::Value =
                    serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
                finding["deadline_confirmation"] = self.to_json();
                let bytes =
                    serde_json::to_vec_pretty(&finding).map_err(|error| error.to_string())?;
                crate::auto::report::atomic_write(&path, &bytes).map_err(|error| error.to_string())
            });
        if let Err(error) = recorded {
            bhfeprintln!(
                "warning: could not record the deadline confirmation of {finding_id}: {error}"
            );
        }
    }
}

/// Re-run an input that overran `deadline` in fresh processes, timing each,
/// until a majority of [`DEADLINE_CONFIRM_RUNS`] has decided, the pass's time
/// runs out, or a run fails to start. Each run is bounded by the per-input
/// timeout; one killed at it overran the deadline.
#[allow(clippy::too_many_arguments)]
fn confirm_deadline(
    runner: &replay_min::HarnessRunner,
    work_dir: &Path,
    input: &[u8],
    extra_env: &[(String, String)],
    per_input_timeout: Duration,
    rss_limit_mb: usize,
    deadline: Duration,
    pass_deadline: Option<Instant>,
) -> DeadlineConfirmation {
    let mut check = DeadlineConfirmation {
        deadline,
        runs: Vec::new(),
    };
    let needed = DEADLINE_CONFIRM_RUNS / 2 + 1;
    while check.runs.len() < DEADLINE_CONFIRM_RUNS
        && check.overruns() < needed
        && check.runs.len() - check.overruns() < needed
    {
        let timeout = match pass_deadline {
            Some(end) => per_input_timeout.min(end.saturating_duration_since(Instant::now())),
            None => per_input_timeout,
        };
        let (Ok(input_path), Ok(scratch)) = (
            write_fuzz_input(work_dir, input),
            ensure_harness_scratch(work_dir),
        ) else {
            break;
        };
        if timeout <= deadline {
            let _ = fs::remove_file(&input_path);
            break;
        }
        let started = Instant::now();
        let output = run_with_timeout(
            runner.harness_path(),
            &input_path,
            timeout,
            extra_env,
            &scratch,
            rss_limit_mb,
            runner.qemu_prefix(),
            SpawnTweaks::default(),
        );
        let took = started.elapsed();
        let _ = fs::remove_file(&input_path);
        if output.is_err() {
            break;
        }
        check.runs.push(took);
    }
    check
}

/// Say on stderr that a run's deadline overrun is being recorded as a BHF-555
/// finding.
fn announce_deadline_finding(overrun: &str) {
    bhfeprintln!("bhf: input {overrun} - recording BHF-555 finding");
}

/// How long `ForkServer::spawn` waits for the ready byte: the per-input
/// timeout, but at least [`FORK_STARTUP_FLOOR`], for a harness known to speak
/// the framed protocol, and the short [`FORK_HANDSHAKE_PROBE`] for any other.
/// Never longer than the pass itself.
fn fork_handshake_timeout(
    run_timeout: Duration,
    pass_budget: Option<Duration>,
    speaks_framed: bool,
) -> Duration {
    let wait = if speaks_framed {
        run_timeout.max(FORK_STARTUP_FLOOR)
    } else {
        run_timeout.min(FORK_HANDSHAKE_PROBE)
    };
    pass_budget.map_or(wait, |budget| wait.min(budget))
}

#[cfg(test)]
#[test]
fn fork_handshake_waits_for_a_slow_start_of_a_framed_harness() {
    let secs = Duration::from_secs;
    // A known framed harness gets the per-input timeout, at least the floor.
    assert_eq!(fork_handshake_timeout(secs(10), None, true), secs(10));
    assert_eq!(fork_handshake_timeout(secs(1), None, true), secs(10));
    assert_eq!(fork_handshake_timeout(secs(30), None, true), secs(30));
    // Never past the pass budget.
    assert_eq!(
        fork_handshake_timeout(secs(10), Some(secs(4)), true),
        secs(4)
    );
    // Any other harness keeps the short probe.
    assert_eq!(fork_handshake_timeout(secs(10), None, false), secs(2));
    assert_eq!(
        fork_handshake_timeout(Duration::from_millis(750), None, false),
        Duration::from_millis(750)
    );
}
/// Convert a run timeout to the bounded millisecond value accepted by `poll(2)`.
/// A zero/sub-millisecond budget still receives one millisecond so the protocol
/// gets a chance to observe an already-readable sync byte.
fn fork_run_timeout_ms(timeout: Duration) -> i32 {
    timeout.as_millis().clamp(1, i32::MAX as u128) as i32
}

/// What waiting for one sync byte from the harness gave.
#[derive(Debug, PartialEq, Eq)]
enum SyncByte {
    /// The byte arrived.
    Received,
    /// The pipe closed: the harness exited or died.
    Closed,
    /// Nothing arrived in time; the harness is still running.
    TimedOut,
}

/// A child's stdout yields the sync byte once it writes, reads as closed once
/// it exits, and times out while it is alive and silent, so a harness that
/// never answers the fork-server handshake (or hangs on an input) times out
/// instead of blocking the run.
#[cfg(all(test, any(unix, windows)))]
#[test]
fn fork_server_pipe_wait_times_out_on_a_silent_child() {
    use std::process::{Command, Stdio};
    let shell = |script_unix: &str, script_windows: &str| {
        let mut command = if cfg!(windows) {
            let mut command = Command::new("cmd");
            command.args(["/c", script_windows]);
            command
        } else {
            let mut command = Command::new("sh");
            command.args(["-c", script_unix]);
            command
        };
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    };

    let mut silent = shell(
        "sleep 5",
        r"%SystemRoot%\System32\ping.exe -n 6 127.0.0.1 > nul",
    );
    let started = Instant::now();
    assert_eq!(
        read_sync_byte(silent.stdout.as_mut().unwrap(), Duration::from_millis(200)),
        SyncByte::TimedOut
    );
    let waited = started.elapsed();
    assert!(waited >= Duration::from_millis(150), "{waited:?}");
    assert!(waited < Duration::from_secs(3), "{waited:?}");
    let _ = silent.kill();
    let _ = silent.wait();

    let mut writer = shell("echo ready", "echo ready");
    assert_eq!(
        read_sync_byte(writer.stdout.as_mut().unwrap(), Duration::from_secs(3)),
        SyncByte::Received
    );
    let _ = writer.wait();

    // An exited child's pipe reads as closed, which the caller reports as the
    // harness's death.
    let mut exited = shell("exit 0", "exit 0");
    let _ = exited.wait();
    assert_eq!(
        read_sync_byte(exited.stdout.as_mut().unwrap(), Duration::from_secs(3)),
        SyncByte::Closed
    );
}

#[cfg(test)]
#[test]
fn fork_server_wait_inherits_short_pass_budget() {
    assert_eq!(fork_run_timeout_ms(Duration::ZERO), 1);
    assert_eq!(fork_run_timeout_ms(Duration::from_millis(750)), 750);
    assert_eq!(fork_run_timeout_ms(Duration::from_secs(3)), 3_000);
}

/// Wait at most `timeout` for the harness's next sync byte on its stdout. The
/// thread blocks until the harness writes or exits (`poll` on Unix, one
/// overlapped read on Windows), so a reply wakes it at once even on a loaded
/// machine.
fn read_sync_byte(stdout: &mut std::process::ChildStdout, timeout: Duration) -> SyncByte {
    match read_harness_byte(stdout, timeout) {
        Ok(_) => SyncByte::Received,
        Err(outcome) => outcome,
    }
}

/// [`read_sync_byte`], keeping the byte: the ready byte says how the harness
/// reads its frames ([`TEXT_FRAMES_READY`]). `Err` is never `Received`.
fn read_harness_byte(
    stdout: &mut std::process::ChildStdout,
    timeout: Duration,
) -> Result<u8, SyncByte> {
    use std::io::Read;
    #[cfg(windows)]
    if let Some(outcome) = win_pipe::read_byte_within(stdout, timeout) {
        return outcome;
    }
    if !stdout_readable_within(stdout, fork_run_timeout_ms(timeout)) {
        return Err(SyncByte::TimedOut);
    }
    let mut byte = [0u8; 1];
    match stdout.read_exact(&mut byte) {
        Ok(()) => Ok(byte[0]),
        Err(_) => Err(SyncByte::Closed),
    }
}

/// One overlapped read of the harness's sync byte, waited for on an event.
/// Rust opens its own end of a child's pipe for overlapped I/O. Polling the
/// pipe instead wakes on every timer tick, and on a loaded machine each
/// wakeup then waits behind the busy threads for a CPU, while a thread whose
/// read completes is boosted and runs at once.
#[cfg(windows)]
mod win_pipe {
    use super::SyncByte;
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    use std::time::Duration;

    #[repr(C)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        event: *mut c_void,
    }

    #[repr(C)]
    struct IoStatusBlock {
        status: usize,
        information: usize,
    }

    const ERROR_IO_PENDING: u32 = 997;
    const ERROR_OPERATION_ABORTED: u32 = 995;
    const WAIT_OBJECT_0: u32 = 0;
    const FILE_MODE_INFORMATION: u32 = 16;
    const FILE_SYNCHRONOUS_IO: u32 = 0x10 | 0x20;

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateEventW(
            attributes: *mut c_void,
            manual_reset: i32,
            initial_state: i32,
            name: *const u16,
        ) -> *mut c_void;
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn ReadFile(
            file: *mut c_void,
            buffer: *mut c_void,
            to_read: u32,
            read: *mut u32,
            overlapped: *mut Overlapped,
        ) -> i32;
        fn GetOverlappedResult(
            file: *mut c_void,
            overlapped: *mut Overlapped,
            transferred: *mut u32,
            wait: i32,
        ) -> i32;
        fn CancelIoEx(file: *mut c_void, overlapped: *mut Overlapped) -> i32;
        fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
        fn GetLastError() -> u32;
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtQueryInformationFile(
            file: *mut c_void,
            io_status: *mut IoStatusBlock,
            information: *mut c_void,
            length: u32,
            class: u32,
        ) -> i32;
    }

    /// Whether `handle` was opened for overlapped I/O. An overlapped read on a
    /// synchronous handle would block past the timeout.
    fn is_overlapped(handle: *mut c_void) -> bool {
        let mut io_status = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let mut mode = 0u32;
        // SAFETY: valid out-pointers; FILE_MODE_INFORMATION is one ULONG.
        let status = unsafe {
            NtQueryInformationFile(
                handle,
                &mut io_status,
                (&mut mode as *mut u32).cast(),
                4,
                FILE_MODE_INFORMATION,
            )
        };
        status >= 0 && mode & FILE_SYNCHRONOUS_IO == 0
    }

    /// Read one byte from `stdout`, waiting at most `timeout`; `None` when the
    /// handle is not overlapped or no event could be made.
    pub(super) fn read_byte_within(
        stdout: &std::process::ChildStdout,
        timeout: Duration,
    ) -> Option<Result<u8, SyncByte>> {
        let handle = stdout.as_raw_handle();
        if !is_overlapped(handle) {
            return None;
        }
        // SAFETY: a fresh unnamed manual-reset event, closed below.
        let event = unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return None;
        }
        let mut overlapped = Overlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            event,
        };
        let mut byte = 0u8;
        let mut transferred = 0u32;
        // SAFETY: `handle` is the live read end `stdout` owns. `byte` and
        // `overlapped` outlive the read: unless it fails to start, it is waited
        // for (`GetOverlappedResult` with wait set) before they go out of scope.
        let outcome = unsafe {
            let started = ReadFile(
                handle,
                (&mut byte as *mut u8).cast(),
                1,
                std::ptr::null_mut(),
                &mut overlapped,
            );
            if started == 0 && GetLastError() != ERROR_IO_PENDING {
                Err(SyncByte::Closed)
            } else {
                if started == 0 {
                    let millis = timeout.as_millis().clamp(1, u128::from(u32::MAX - 1)) as u32;
                    if WaitForSingleObject(event, millis) != WAIT_OBJECT_0 {
                        CancelIoEx(handle, &mut overlapped);
                    }
                }
                if GetOverlappedResult(handle, &mut overlapped, &mut transferred, 1) != 0 {
                    if transferred == 1 {
                        Ok(byte)
                    } else {
                        Err(SyncByte::Closed)
                    }
                } else if GetLastError() == ERROR_OPERATION_ABORTED {
                    Err(SyncByte::TimedOut)
                } else {
                    Err(SyncByte::Closed)
                }
            }
        };
        // SAFETY: `event` is the handle created above, no longer in use.
        unsafe { CloseHandle(event) };
        Some(outcome)
    }
}

/// Block until the child's `stdout` is readable (it wrote, or it exited) or
/// `timeout_ms` elapses. Returns true if readable, false on timeout/error
/// (caller treats either as "no response").
#[cfg(unix)]
fn stdout_readable_within(stdout: &std::process::ChildStdout, timeout_ms: i32) -> bool {
    use std::os::unix::io::AsRawFd;
    let mut pfd = libc::pollfd {
        fd: stdout.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `pfd` is a valid initialized pollfd for the duration of the call.
    unsafe { libc::poll(&mut pfd, 1, timeout_ms) > 0 }
}

/// Windows has no `poll` for an anonymous pipe; `PeekNamedPipe` reports the
/// bytes waiting in it, and fails once the writer has closed it. Polled: a
/// short spin first, as a fork-server answer usually comes within
/// microseconds, then millisecond sleeps.
#[cfg(windows)]
fn stdout_readable_within(stdout: &std::process::ChildStdout, timeout_ms: i32) -> bool {
    use std::os::windows::io::AsRawHandle;
    #[link(name = "kernel32")]
    extern "system" {
        fn PeekNamedPipe(
            pipe: *mut std::ffi::c_void,
            buffer: *mut std::ffi::c_void,
            buffer_size: u32,
            bytes_read: *mut u32,
            bytes_available: *mut u32,
            bytes_left_this_message: *mut u32,
        ) -> i32;
    }
    let handle = stdout.as_raw_handle();
    let started = Instant::now();
    let timeout = Duration::from_millis(u64::try_from(timeout_ms).unwrap_or(0));
    loop {
        let mut available = 0u32;
        // SAFETY: `handle` is the live read end of the child's stdout pipe,
        // owned by `stdout` for the duration of the call; no buffer is passed.
        let peeked = unsafe {
            PeekNamedPipe(
                handle,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        // A failed peek is a closed pipe: the read that follows reports it.
        if peeked == 0 || available > 0 {
            return true;
        }
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return false;
        }
        if elapsed < Duration::from_millis(2) {
            std::thread::yield_now();
        } else {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn stdout_readable_within(_stdout: &std::process::ChildStdout, _timeout_ms: i32) -> bool {
    true
}

/// What one fresh-process re-run came to: `Ok(None)` when the pass ended (or
/// gave up on it) before it finished, so the input is still unchecked.
type FreshRerunResult = Result<Option<HarnessRun>, String>;

/// Start the fresh-process re-runs for this pass (see `crate::fresh_rerun`),
/// placed by [`fresh_rerun_placement`].
fn start_fresh_reruns(
    prepared: &PreparedFuzzRun,
    pass_deadline: Option<Instant>,
) -> FreshReruns<FreshRerunResult> {
    let runner = prepared.runner.clone();
    let work_dir = prepared.work_dir.clone();
    let env = fresh_rerun_env(&prepared.extra_env);
    let (timeout, rss_limit_mb, deadline) = (
        prepared.per_input_timeout,
        prepared.rss_limit_mb,
        prepared.deadline,
    );
    let placement = fresh_rerun_placement(usable_cpus(), deadline.is_some());
    let drain_from = pass_deadline.zip(prepared.time).map(|(end, budget)| {
        end.checked_sub(fresh_rerun_drain_window(budget))
            .unwrap_or(end)
    });
    FreshReruns::start(
        move |input: &[u8], context: &RerunContext<'_>| {
            run_fresh_rerun(
                &runner,
                &work_dir,
                input,
                &env,
                FreshRerunLimits {
                    timeout,
                    rss_limit_mb,
                    deadline,
                    pass_deadline,
                    lower_priority: placement.lower_priority,
                    drain_from,
                },
                context,
            )
        },
        placement.workers,
        crate::fresh_rerun::MAX_OUTSTANDING_INPUTS,
        crate::fresh_rerun::MAX_OUTSTANDING_BYTES,
    )
}

/// Where a pass's fresh re-runs run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FreshRerunPlacement {
    /// Background workers; none runs each re-run inline, as the loop's step.
    workers: usize,
    /// Start a background re-run's process at a lower priority.
    lower_priority: bool,
}

/// How a pass on `cpus` usable CPUs places its fresh re-runs (#416):
/// - Two or more CPUs: one background worker, its processes at a lower
///   priority (nice +10; below-normal on Windows, back to normal once the
///   loop stops). On a busy machine they take a CPU only when the loop
///   leaves one idle.
/// - One CPU with `--deadline`: inline, as the loop's own step. A re-run
///   sharing the only CPU with the loop takes longer than the input does.
/// - One CPU without a deadline: one background worker at the loop's
///   priority. The loop keeps fuzzing while a re-run waits for its process
///   to start; lowered, the re-run would never finish under load.
///
/// Whatever the placement, a deadline (BHF-555) report from a background
/// re-run is re-checked inline, at the loop's priority, before it is a
/// finding (see `adopt_fresh_reruns!`).
fn fresh_rerun_placement(cpus: usize, response_deadline: bool) -> FreshRerunPlacement {
    match (cpus > 1, response_deadline) {
        (true, _) => FreshRerunPlacement {
            workers: 1,
            lower_priority: true,
        },
        (false, true) => FreshRerunPlacement {
            workers: 0,
            lower_priority: false,
        },
        (false, false) => FreshRerunPlacement {
            workers: 1,
            lower_priority: false,
        },
    }
}

#[cfg(test)]
#[test]
fn fresh_reruns_run_inline_only_on_one_cpu_with_a_response_deadline() {
    let placement = |cpus, deadline| {
        let placed = fresh_rerun_placement(cpus, deadline);
        (placed.workers, placed.lower_priority)
    };
    assert_eq!(placement(1, true), (0, false));
    assert_eq!(placement(1, false), (1, false));
    assert_eq!(placement(2, false), (1, true));
    assert_eq!(placement(8, true), (1, true));
}

/// The CPUs this process may run on: its affinity and CPU quota (a cgroup's
/// `cpu.max` on Linux), and on Windows its affinity mask.
fn usable_cpus() -> usize {
    let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    #[cfg(windows)]
    if let Some(allowed) = windows_affinity_cpus() {
        return cpus.min(allowed);
    }
    cpus
}

/// How many CPUs this process's affinity mask allows (Windows).
#[cfg(windows)]
fn windows_affinity_cpus() -> Option<usize> {
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn GetProcessAffinityMask(
            process: *mut c_void,
            process_mask: *mut usize,
            system_mask: *mut usize,
        ) -> i32;
    }
    let (mut process_mask, mut system_mask) = (0usize, 0usize);
    // SAFETY: the out-pointers are valid for the call; the pseudo-handle of
    // the current process needs no closing.
    let ok =
        unsafe { GetProcessAffinityMask(GetCurrentProcess(), &mut process_mask, &mut system_mask) };
    (ok != 0 && process_mask != 0).then(|| process_mask.count_ones() as usize)
}

/// The bounds of one fresh re-run.
#[derive(Clone, Copy)]
struct FreshRerunLimits {
    timeout: Duration,
    rss_limit_mb: usize,
    /// `--deadline`.
    deadline: Option<Duration>,
    /// When the pass ends: a re-run never runs past it.
    pass_deadline: Option<Instant>,
    /// Start a background re-run's process at a lower priority.
    lower_priority: bool,
    /// When the pass enters its drain window ([`fresh_rerun_drain_window`]).
    drain_from: Option<Instant>,
}

/// Whether a re-run starting at `now` starts its process at a lower priority.
/// Only a background one does, where the placement lowers re-runs, and only
/// before the pass's drain window and while the loop still runs (`draining`
/// unset). Once either has come, the loop may be about to wait for the re-run
/// and has nothing left to give way to, and an unprivileged Unix process could
/// not raise a nice back later: lowered then, a re-run on a busy machine takes
/// many times as long and the pass ends before it is checked.
fn fresh_rerun_starts_lowered(
    background: bool,
    limits: &FreshRerunLimits,
    draining: bool,
    now: Instant,
) -> bool {
    background
        && limits.lower_priority
        && !draining
        && limits.drain_from.is_none_or(|from| now < from)
}

#[cfg(test)]
#[test]
fn a_fresh_rerun_the_pass_may_wait_for_runs_at_normal_priority() {
    let now = Instant::now();
    let limits = |lower_priority, drain_from| FreshRerunLimits {
        timeout: Duration::from_secs(10),
        rss_limit_mb: 0,
        deadline: None,
        pass_deadline: None,
        lower_priority,
        drain_from,
    };
    let later = Some(now + Duration::from_secs(5));
    let earlier = Some(now - Duration::from_millis(1));
    let lowered = |background, lower_priority, drain_from, draining| {
        fresh_rerun_starts_lowered(
            background,
            &limits(lower_priority, drain_from),
            draining,
            now,
        )
    };
    // Before the drain window, beside the running loop: lowered.
    assert!(lowered(true, true, later, false));
    assert!(lowered(true, true, None, false));
    // The loop has stopped, or the pass is in its drain window: normal.
    assert!(!lowered(true, true, later, true));
    assert!(!lowered(true, true, None, true));
    assert!(!lowered(true, true, earlier, false));
    // Never lowered where the placement does not lower, or inline.
    assert!(!lowered(true, false, later, false));
    assert!(!lowered(false, true, later, false));
}

/// Re-run `input` in a fresh process, in a scratch directory of its own (a
/// target can keep files in its working directory, and a background re-run
/// runs beside the fork-server), within what is left of the pass. A re-run the
/// end of the pass cuts short, or that the pass cancels, is `Ok(None)`.
fn run_fresh_rerun(
    runner: &replay_min::HarnessRunner,
    work_dir: &Path,
    input: &[u8],
    env: &[(String, String)],
    limits: FreshRerunLimits,
    context: &RerunContext<'_>,
) -> FreshRerunResult {
    use std::sync::atomic::Ordering;
    let left = limits
        .pass_deadline
        .map(|deadline| deadline.saturating_duration_since(Instant::now()));
    let timeout = left.map_or(limits.timeout, |left| limits.timeout.min(left));
    if timeout.is_zero() || context.cancelled.load(Ordering::SeqCst) {
        return Ok(None);
    }
    let scratch = fresh_rerun_scratch(work_dir)?;
    let mut env: Vec<(String, String)> = env
        .iter()
        .filter(|(key, _)| !SCRATCH_TEMP_VARS.contains(&key.as_str()))
        .cloned()
        .collect();
    for key in SCRATCH_TEMP_VARS {
        env.push(((*key).to_owned(), scratch.display().to_string()));
    }
    let background = context.placement == Placement::Background;
    let low_priority = fresh_rerun_starts_lowered(
        background,
        &limits,
        context.draining.load(Ordering::SeqCst),
        Instant::now(),
    );
    let started = Instant::now();
    let run = run_c_libfuzzer_single_input_in(
        runner,
        work_dir,
        &scratch,
        input,
        &env,
        timeout,
        limits.rss_limit_mb,
        limits.deadline,
        SpawnTweaks {
            low_priority,
            cancel: background.then_some(context.cancelled),
            restore_priority: background.then_some(context.draining),
            ..SpawnTweaks::default()
        },
    );
    let _ = fs::remove_dir_all(&scratch);
    if context.cancelled.load(Ordering::SeqCst) {
        return Ok(None);
    }
    let run = run?;
    // Killed at the end of the pass rather than at its own timeout: the input
    // was not checked.
    if run.sanitizer.is_none() && timeout < limits.timeout && started.elapsed() >= timeout {
        return Ok(None);
    }
    Ok(Some(run))
}

/// The temp-dir variables a fresh re-run points at its own scratch directory.
const SCRATCH_TEMP_VARS: &[&str] = if cfg!(windows) {
    &["TMP", "TEMP"]
} else {
    &["TMPDIR"]
};

/// A new, empty scratch directory for one fresh re-run, under `fuzz_scratch/`.
fn fresh_rerun_scratch(work_dir: &Path) -> Result<PathBuf, String> {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir =
        ensure_harness_scratch(work_dir)?.join(format!(".rerun-{}-{seq}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)
        .map_err(|error| format!("create re-run scratch dir {}: {error}", dir.display()))?;
    Ok(dir)
}

/// The environment of a background re-run: the run's own, without the
/// coverage, comparison and value-profile maps and with the runtrace log sent
/// nowhere. Those are shared with the fork-server, which reads them after each
/// of its inputs; a re-run running at the same time would be credited to the
/// fork-server's next input.
fn fresh_rerun_env(extra_env: &[(String, String)]) -> Vec<(String, String)> {
    const SHARED_WITH_THE_FORK_SERVER: &[&str] = &[
        "BHF_COV_SHM",
        "BHF_COV_CNT_SHM",
        "BHF_STACK_DEPTH_SHM",
        "BHF_CMP_PROGRESS_SHM",
        "BHF_CMP_SHM",
        "BHF_VP_SHM",
        "BHF_TARGET_ENTRY_SHM",
        "BHF_CMPLOG",
        "BHF_CMP_EVIDENCE",
    ];
    let null_device = if cfg!(windows) { "NUL" } else { "/dev/null" };
    extra_env
        .iter()
        .filter(|(key, _)| !SHARED_WITH_THE_FORK_SERVER.contains(&key.as_str()))
        .map(|(key, value)| {
            if key == "BHF_RUNTRACE_LOG" {
                (key.clone(), null_device.to_owned())
            } else {
                (key.clone(), value.clone())
            }
        })
        .collect()
}

/// The most inputs kept unchecked for one harness. Past it a pass leaves the
/// rest out, which never queues them: nothing unchecked reaches the queue.
const MAX_SAVED_UNCHECKED_INPUTS: usize = 4 * crate::fresh_rerun::MAX_OUTSTANDING_INPUTS;

/// The file an unchecked input is kept in: named by its sha256, like a queue
/// entry, so saving it twice keeps one copy.
fn unchecked_input_path(dir: &Path, input: &[u8]) -> PathBuf {
    dir.join(format!(
        "{}.bin",
        corpus::lineage::hex(&corpus::lineage::digest(input))
    ))
}

/// Up to one re-run queue's worth of the inputs an earlier pass left
/// unchecked in `dir`, with their files, by file name.
fn read_unchecked_inputs(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "bin") && path.is_file())
        .collect();
    paths.sort();
    paths
        .into_iter()
        .take(crate::fresh_rerun::MAX_OUTSTANDING_INPUTS)
        .filter_map(|path| fs::read(&path).ok().map(|bytes| (path, bytes)))
        .collect()
}

/// Keep `inputs` in `dir` for the next pass, up to
/// [`MAX_SAVED_UNCHECKED_INPUTS`] files in all. Returns how many did not fit.
fn save_unchecked_inputs(dir: &Path, inputs: &[Vec<u8>]) -> std::io::Result<usize> {
    if inputs.is_empty() {
        return Ok(0);
    }
    fs::create_dir_all(dir)?;
    let mut held = fs::read_dir(dir)?.flatten().count();
    let mut left_out = 0;
    for input in inputs {
        let path = unchecked_input_path(dir, input);
        if path.exists() {
            continue;
        }
        if held >= MAX_SAVED_UNCHECKED_INPUTS {
            left_out += 1;
            continue;
        }
        fs::write(&path, input)?;
        held += 1;
    }
    Ok(left_out)
}

/// A pool entry that crashed in a fresh process is a finding, not a mutation
/// base or a queue entry: mark every copy of `input` in the pool so.
fn retire_from_pool(pool: &mut [PoolEntry], input: &[u8]) {
    for entry in pool.iter_mut().filter(|entry| entry.bytes == input) {
        entry.retired = true;
    }
}

/// Remove `input` from the harness's saved queue, where an earlier pass (or an
/// older bhf) may have put it before a fresh run showed that it crashes.
fn forget_queued_input(work_dir: &Path, harness_id: &str, input: &[u8]) {
    let queue = work_dir.join("corpus").join(harness_id).join("queue");
    let _ = fs::remove_file(unchecked_input_path(&queue, input));
}

/// Start the run's fork-server, or `None` to run a fresh process per input. A
/// harness known to speak the protocol that still misses the handshake says
/// so, since every later input then pays a full process start.
fn start_fork_server(
    prepared: &PreparedFuzzRun,
    handshake_timeout: Duration,
    speaks_framed: bool,
) -> Option<ForkServer> {
    match ForkServer::spawn(
        &prepared.runner,
        &prepared.work_dir,
        &prepared.loop_env,
        prepared.rss_limit_mb,
        prepared.per_input_timeout,
        handshake_timeout,
    ) {
        Ok(server) => Some(server),
        Err(error) => {
            if speaks_framed {
                bhfeprintln!(
                    "bhf: {error}; running a fresh process per input instead (slower). \
                     A target that is slow to start needs a longer --timeout."
                );
            }
            None
        }
    }
}

impl ForkServer {
    fn spawn(
        runner: &replay_min::HarnessRunner,
        work_dir: &Path,
        extra_env: &[(String, String)],
        rss_limit_mb: usize,
        run_timeout: Duration,
        handshake_timeout: Duration,
    ) -> Result<Self, String> {
        let events_path = temp_event_path(work_dir)?;
        // Fresh, empty events file; we read deltas from it per input.
        fs::File::create(&events_path)
            .map_err(|error| format!("create fork-server event log: {error}"))?;
        let scratch = ensure_harness_scratch(work_dir)?;
        let runner_owned;
        let runner = match runtrace_log_dir(extra_env) {
            Some(dir) => {
                runner_owned = runner.clone().with_rw_binds([dir]);
                &runner_owned
            }
            None => runner,
        };
        let mut command = runner
            .command_for_events(&events_path)
            .map_err(|error| error.to_string())?;
        command
            .current_dir(&scratch)
            .env("BHF_EVENTS_PATH", &events_path)
            // Switch the AdaFuzz runtime into framed-stdin + sync mode.
            .env("BHF_FRAMED", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for (k, v) in extra_env {
            command.env(k, v);
        }
        apply_runaway_rlimits(&mut command);
        let mut child = command
            .spawn()
            .map_err(|error| format!("spawn fork-server harness: {error}"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "fork-server: no stdin".to_owned())?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| "fork-server: no stdout".to_owned())?;
        // Handshake: a conforming harness writes a "ready" sync byte at startup.
        // No byte within the timeout means this harness does not speak the framed
        // protocol (a C/libFuzzer harness, a stale build, a test mock) -> bail so
        // the caller uses the per-spawn path.
        let ready = match read_harness_byte(&mut stdout, handshake_timeout) {
            Ok(byte) => byte,
            Err(outcome) => {
                kill_process_group(&mut child);
                let _ = child.wait();
                let _ = fs::remove_file(&events_path);
                return Err(match outcome {
                    SyncByte::TimedOut => format!(
                        "fork-server: harness sent no ready byte within {handshake_timeout:?}"
                    ),
                    _ => "fork-server: harness exited before completing the protocol handshake"
                        .to_owned(),
                });
            }
        };
        Ok(Self {
            child,
            stdin,
            stdout,
            events_path,
            events_offset: 0,
            rss_limit_mb,
            run_timeout_ms: fork_run_timeout_ms(run_timeout),
            text_frames: ready == TEXT_FRAMES_READY,
        })
    }

    /// Whether the persistent child's RSS now exceeds the configured ceiling.
    /// Polling `/proc/<pid>/statm` mirrors the per-spawn path; `false` when no
    /// limit is set or the stat is unavailable.
    fn rss_exceeded(&self) -> bool {
        self.rss_limit_mb > 0
            && process_rss_mb(self.child.id()).is_some_and(|rss| rss > self.rss_limit_mb)
    }

    fn run_one(&mut self, input: &[u8]) -> ForkOutcome {
        // Write the framed input, then await the harness's sync byte (sent from
        // its next Load_From_Stdin once it has flushed this input's events). A
        // broken pipe / EOF means the process died; a timeout means this input
        // hung the persistent process — both isolate via the per-spawn path.
        let framed = if self.text_frames {
            write_hex_frame(&mut self.stdin, input)
        } else {
            write_input_frame(&mut self.stdin, input)
        };
        if framed.and_then(|()| self.stdin.flush()).is_err() {
            return ForkOutcome::Died;
        }
        match self.await_sync_within_rss_limit() {
            SyncByte::Received => {}
            SyncByte::Closed => return ForkOutcome::Died,
            SyncByte::TimedOut => {
                // Either the input hung the process or it blew past the RSS
                // ceiling; kill the child and isolate via the per-spawn path,
                // which polls RSS and synthesizes the BHF-209 out-of-memory
                // finding.
                kill_process_group(&mut self.child);
                return ForkOutcome::Died;
            }
        }
        // The input may have driven RSS over the ceiling and only then sent its
        // sync byte (the harness frees nothing mid-loop); catch that too.
        if self.rss_exceeded() {
            kill_process_group(&mut self.child);
            return ForkOutcome::Died;
        }
        match self.read_event_delta() {
            Ok(run) => ForkOutcome::Ran(Box::new(run)),
            Err(_) => ForkOutcome::Died,
        }
    }

    /// Wait for the harness's sync byte. With no RSS limit this is a single
    /// bounded wait; with a limit it waits in short slices, giving up
    /// (`TimedOut`) if the child's RSS breaches the ceiling or the whole-input
    /// timeout elapses, so the caller can isolate it.
    fn await_sync_within_rss_limit(&mut self) -> SyncByte {
        let run_timeout = Duration::from_millis(self.run_timeout_ms as u64);
        if self.rss_limit_mb == 0 {
            return read_sync_byte(&mut self.stdout, run_timeout);
        }
        const RSS_POLL_INTERVAL: Duration = Duration::from_millis(25);
        let deadline = Instant::now() + run_timeout;
        loop {
            match read_sync_byte(&mut self.stdout, RSS_POLL_INTERVAL) {
                SyncByte::TimedOut if !self.rss_exceeded() && Instant::now() < deadline => {}
                outcome => return outcome,
            }
        }
    }

    fn read_event_delta(&mut self) -> Result<HarnessRun, String> {
        use std::io::{Read, Seek, SeekFrom};
        let mut file = fs::File::open(&self.events_path)
            .map_err(|error| format!("open fork-server event log: {error}"))?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        if size <= self.events_offset {
            return Ok(HarnessRun {
                events: Vec::new(),
                testcases: Vec::new(),
                sanitizer: None,
                stderr: None,
                rejected: false,
                hung: None,
            });
        }
        let event_delta_limit = max_event_delta_bytes();
        if size.saturating_sub(self.events_offset) > event_delta_limit {
            self.events_offset = size;
            return Err(format!(
                "fork-server event delta exceeded the {} MiB memory cap (raise \
                 BHF_MAX_EVENT_DELTA_BYTES if intended)",
                event_delta_limit / (1024 * 1024)
            ));
        }
        file.seek(SeekFrom::Start(self.events_offset))
            .map_err(|error| format!("seek fork-server event log: {error}"))?;
        let mut bytes = Vec::with_capacity((size - self.events_offset) as usize);
        file.read_to_end(&mut bytes)
            .map_err(|error| format!("read fork-server event log: {error}"))?;
        self.events_offset = size;
        let events = EventReader::new(bytes.as_slice())
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("parse fork-server events: {error}"))?;
        let testcases = group_into_testcases(EventReader::new(bytes.as_slice()))
            .map_err(|error| format!("group fork-server events: {error}"))?;
        Ok(HarnessRun {
            events,
            testcases,
            sanitizer: None,
            stderr: None,
            rejected: false,
            hung: None,
        })
    }
}

impl Drop for ForkServer {
    fn drop(&mut self) {
        // Closing stdin is the EOF that ends the harness loop; then reap.
        kill_process_group(&mut self.child);
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.events_path);
    }
}

/// Startup and per-spawn waits under CPU contention: a slow start is not a
/// failed handshake, and waiting for a child adds no fixed polling latency.
#[cfg(all(test, unix))]
mod exec_wait_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch_dir(name: &str) -> crate::test_support::TestDir {
        crate::test_support::TestDir::new(&format!("exec-wait-{name}"))
    }

    fn script(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("main");
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// A framed harness that takes longer than the old fixed 2 s to send its
    /// ready byte (a slow start, as under CPU contention) still gets its
    /// fork-server instead of dropping the run to a process per input.
    #[test]
    fn slow_starting_framed_harness_completes_the_handshake() {
        let work = scratch_dir("slow-start");
        let harness = script(
            &work,
            "#!/bin/sh\n# BHF_FRAMED\nsleep 2.5\nprintf '\\001'\nexec cat >/dev/null\n",
        );
        let runner = replay_min::HarnessRunner::direct(harness);
        let run_timeout = Duration::from_secs(10);
        let handshake = fork_handshake_timeout(run_timeout, None, true);
        let server = ForkServer::spawn(&runner, &work, &[], 0, run_timeout, handshake);
        assert!(
            server.is_ok(),
            "a slow framed start must not fail the handshake: {:?}",
            server.err()
        );
        drop(server);
        let _ = fs::remove_dir_all(&work);
    }

    /// A harness that never sends its ready byte is still abandoned, at the
    /// handshake deadline, with a message that says how long it waited.
    #[test]
    fn silent_harness_is_abandoned_at_the_handshake_deadline() {
        let work = scratch_dir("silent-start");
        let harness = script(&work, "#!/bin/sh\n# BHF_FRAMED\nexec sleep 30\n");
        let runner = replay_min::HarnessRunner::direct(harness);
        let started = Instant::now();
        let error = ForkServer::spawn(
            &runner,
            &work,
            &[],
            0,
            Duration::from_secs(10),
            Duration::from_secs(1),
        )
        .err()
        .expect("a silent harness fails the handshake");
        let waited = started.elapsed();
        assert!(error.contains("no ready byte within 1s"), "{error}");
        assert!(waited >= Duration::from_secs(1), "{waited:?}");
        assert!(waited < Duration::from_secs(8), "{waited:?}");
        let _ = fs::remove_dir_all(&work);
    }

    /// An input that hangs the persistent harness is still given up on at the
    /// per-input timeout, not at the more generous handshake deadline.
    #[test]
    fn an_input_that_hangs_the_fork_server_times_out_at_the_run_timeout() {
        let work = scratch_dir("hung-input");
        let harness = script(
            &work,
            "#!/bin/sh\n# BHF_FRAMED\nprintf '\\001'\nexec sleep 30\n",
        );
        let runner = replay_min::HarnessRunner::direct(harness);
        let mut server = ForkServer::spawn(
            &runner,
            &work,
            &[],
            0,
            Duration::from_secs(1),
            Duration::from_secs(10),
        )
        .expect("the harness sends its ready byte");
        let started = Instant::now();
        assert!(matches!(server.run_one(b"input"), ForkOutcome::Died));
        let waited = started.elapsed();
        assert!(waited >= Duration::from_secs(1), "{waited:?}");
        assert!(waited < Duration::from_secs(8), "{waited:?}");
        drop(server);
        let _ = fs::remove_dir_all(&work);
    }

    /// A harness whose ready byte asks for hex frames is sent each input in
    /// hex digits, so a text-mode reader gets the CR LF and Ctrl-Z intact.
    #[test]
    fn a_harness_that_asks_for_hex_frames_is_sent_them() {
        let work = scratch_dir("hex-frames");
        let frame = work.join("frame.txt");
        let harness = script(
            &work,
            &format!(
                "#!/bin/sh\n# BHF_FRAMED\nprintf H\n\
                 hdr=$(dd bs=1 count=8 2>/dev/null)\n\
                 dd bs=1 count=$((2 * 0x$hdr)) of='{}' 2>/dev/null\n\
                 printf '\\001'\nexec sleep 30\n",
                frame.display()
            ),
        );
        let runner = replay_min::HarnessRunner::direct(harness);
        let mut server = ForkServer::spawn(
            &runner,
            &work,
            &[],
            0,
            Duration::from_secs(10),
            Duration::from_secs(10),
        )
        .expect("the harness sends its ready byte");
        assert!(server.text_frames);
        assert!(matches!(server.run_one(b"\r\n\x1a"), ForkOutcome::Ran(_)));
        assert_eq!(fs::read_to_string(&frame).unwrap(), "0d0a1a");
        drop(server);
        let _ = fs::remove_dir_all(&work);
    }

    /// Voluntary context switches of the calling thread so far. A thread that
    /// blocks until a child exits switches out about once; one that polls with
    /// sleeps switches out on every tick, however fast the machine is.
    #[cfg(target_os = "linux")]
    fn voluntary_switches() -> i64 {
        // SAFETY: `usage` is a valid out-pointer for the duration of the call.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::getrusage(libc::RUSAGE_THREAD, &mut usage) },
            0
        );
        usage.ru_nvcsw
    }

    /// How many more times the calling thread wakes when `run`'s child lives
    /// 2 s longer: about none for a wait that blocks until the child exits, one
    /// per tick for a sleep-poll. Spawning, pipes and files cost the same for
    /// both children, so the difference isolates the wait even on a loaded
    /// machine.
    #[cfg(target_os = "linux")]
    fn extra_wakeups_for_a_longer_child(run: impl Fn(&str)) -> i64 {
        let wakeups = |secs: &str| {
            let before = voluntary_switches();
            run(secs);
            voluntary_switches() - before
        };
        let short = wakeups("0.1");
        let long = wakeups("2.1");
        long - short
    }

    /// Waiting for a per-spawn harness blocks until it exits: no sleep tick
    /// sits between the child's exit and bhf noticing it.
    #[cfg(target_os = "linux")]
    #[test]
    fn per_spawn_wait_blocks_instead_of_polling() {
        let work = scratch_dir("per-spawn-wait");
        let scratch = ensure_harness_scratch(&work).unwrap();
        let input = work.join("input.sh");
        let extra = extra_wakeups_for_a_longer_child(|secs| {
            fs::write(&input, format!("sleep {secs}\n")).unwrap();
            let output = run_with_timeout(
                Path::new("/bin/sh"),
                &input,
                Duration::from_secs(10),
                &[],
                &scratch,
                0,
                None,
                SpawnTweaks::default(),
            )
            .unwrap();
            assert!(output.status.success());
        });
        assert!(
            extra <= 40,
            "2 s more of the child cost {extra} more wakeups"
        );
        let _ = fs::remove_dir_all(&work);
    }

    /// A background re-run's process starts at a lower priority than bhf's
    /// own (nice +10), so it takes a CPU only when the fuzz loop leaves one.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_low_priority_spawn_starts_its_process_niced() {
        let work = scratch_dir("nice");
        let scratch = ensure_harness_scratch(&work).unwrap();
        let input = work.join("input.sh");
        fs::write(&input, "nice >&2\n").unwrap();
        let niceness = |low_priority| {
            let output = run_with_timeout(
                Path::new("/bin/sh"),
                &input,
                Duration::from_secs(10),
                &[],
                &scratch,
                0,
                None,
                SpawnTweaks {
                    low_priority,
                    ..SpawnTweaks::default()
                },
            )
            .unwrap();
            let text = String::from_utf8_lossy(&output.stderr).into_owned();
            text.trim()
                .parse::<i32>()
                .unwrap_or_else(|_| panic!("nice printed {text:?}"))
        };
        // SAFETY: getpriority reads this process's nice value.
        let own = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
        assert_eq!(niceness(false), own);
        assert_eq!(niceness(true), (own + LOWER_PRIORITY_NICE).min(19));
        let _ = fs::remove_dir_all(&work);
    }

    /// A cancelled per-spawn run stops its process at once instead of waiting
    /// out its timeout.
    #[test]
    fn a_cancelled_spawn_stops_its_process() {
        let work = scratch_dir("cancel");
        let scratch = ensure_harness_scratch(&work).unwrap();
        let input = work.join("input.sh");
        fs::write(&input, "exec sleep 30\n").unwrap();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(300));
                cancel.store(true, std::sync::atomic::Ordering::SeqCst);
            });
            let started = Instant::now();
            let result = run_with_timeout(
                Path::new("/bin/sh"),
                &input,
                Duration::from_secs(60),
                &[],
                &scratch,
                0,
                None,
                SpawnTweaks {
                    cancel: Some(&cancel),
                    ..SpawnTweaks::default()
                },
            );
            let waited = started.elapsed();
            assert!(result.is_err(), "a cancelled run is not a result");
            assert!(waited >= Duration::from_millis(300), "{waited:?}");
            assert!(waited < Duration::from_secs(5), "{waited:?}");
        });
        let _ = fs::remove_dir_all(&work);
    }

    /// The same for the event-log lane's per-spawn run.
    #[cfg(target_os = "linux")]
    #[test]
    fn event_log_per_spawn_wait_blocks_instead_of_polling() {
        let work = scratch_dir("event-log-wait");
        let harness = script(&work, "#!/bin/sh\ncat >/dev/null\nsleep \"$WAIT_SECS\"\n");
        let runner = replay_min::HarnessRunner::direct(harness);
        let extra = extra_wakeups_for_a_longer_child(|secs| {
            let env = [("WAIT_SECS".to_owned(), secs.to_owned())];
            let run = run_harness(
                &runner,
                &work,
                b"input",
                &env,
                Duration::from_secs(10),
                0,
                None,
            )
            .unwrap();
            assert!(run.sanitizer.is_none());
        });
        assert!(
            extra <= 40,
            "2 s more of the child cost {extra} more wakeups"
        );
        let _ = fs::remove_dir_all(&work);
    }
}

#[cfg(test)]
mod priority_class_tests {
    use super::priority_class::*;

    #[test]
    fn a_background_rerun_runs_one_class_below_bhf() {
        assert_eq!(lowered(NORMAL), BELOW_NORMAL);
        assert_eq!(lowered(BELOW_NORMAL), IDLE);
        assert_eq!(lowered(IDLE), IDLE);
        assert_eq!(lowered(ABOVE_NORMAL), NORMAL);
        assert_eq!(lowered(HIGH), ABOVE_NORMAL);
        assert_eq!(lowered(REALTIME), HIGH);
        assert_eq!(lowered(0x1234), BELOW_NORMAL);
    }

    #[test]
    fn a_child_without_a_class_flag_gets_an_idle_or_below_normal_parents_class() {
        assert_eq!(inherited(BELOW_NORMAL), BELOW_NORMAL);
        assert_eq!(inherited(IDLE), IDLE);
        assert_eq!(inherited(NORMAL), NORMAL);
        assert_eq!(inherited(HIGH), NORMAL);
        assert_eq!(name(lowered(BELOW_NORMAL)), "Idle");
    }
}

/// A background re-run's process starts one priority class below bhf's, and
/// is returned to bhf's once the loop it gave way to has stopped.
#[cfg(all(test, windows))]
mod spawn_priority_windows_tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn a_low_priority_spawn_runs_below_bhf_until_restored() {
        // Relative to this process's class: the GitHub runner's worker starts
        // its steps BelowNormal (CI raises the test step to Normal).
        let own = own_priority_class();
        let work = crate::test_support::TestDir::new("spawn-priority");
        let scratch = ensure_harness_scratch(&work).unwrap();
        // The script prints its own priority class `samples` times, 250 ms
        // apart.
        let powershell = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
        let classes = |low_priority, restore: Option<&AtomicBool>, samples: u32| {
            let script = work.join(format!("class-{samples}.ps1"));
            fs::write(
                &script,
                format!(
                    "for ($i = 0; $i -lt {samples}; $i++) {{\r\n\
                     if ($i -gt 0) {{ Start-Sleep -Milliseconds 250 }}\r\n\
                     [Console]::Error.WriteLine((Get-Process -Id $PID).PriorityClass)\r\n\
                     }}\r\n"
                ),
            )
            .unwrap();
            let output = run_with_timeout(
                &powershell,
                &script,
                Duration::from_secs(60),
                &[],
                &scratch,
                0,
                None,
                SpawnTweaks {
                    low_priority,
                    restore_priority: restore,
                    ..SpawnTweaks::default()
                },
            )
            .unwrap();
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .map(|line| line.trim().to_owned())
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>()
        };
        let name = |class| priority_class::name(class).to_owned();
        assert_eq!(
            classes(false, None, 1),
            [name(priority_class::inherited(own))]
        );
        assert_eq!(classes(true, None, 1), [name(priority_class::lowered(own))]);
        // Raised to bhf's class as soon as the loop that it gave way to has
        // stopped (here, from the start): within the 5 s the script samples,
        // whatever the load on the host, and it stays raised.
        let restore = AtomicBool::new(true);
        let seen = classes(true, Some(&restore), 20);
        let raised = seen.iter().position(|class| *class == name(own));
        assert!(
            raised.is_some_and(|at| seen[at..].iter().all(|class| *class == name(own))),
            "the re-run was not returned to bhf's {} priority: {seen:?}",
            name(own)
        );
    }
}

pub(crate) fn find_harness_executable(
    work_dir: &Path,
    harness_id: &str,
    engine: FuzzEngine,
) -> Result<PathBuf, String> {
    if engine == FuzzEngine::Libfuzzer {
        return libfuzzer::ensure_binary(work_dir, harness_id);
    }
    if engine == FuzzEngine::Honggfuzz {
        return honggfuzz::ensure_binary(work_dir, harness_id);
    }
    let build_dir = work_dir.join("build").join(harness_id);
    let harness_dir = crate::auto::layout::harness_dir(work_dir, harness_id);
    let legacy_auto_dir = crate::auto::layout::legacy_auto_harness_dir(work_dir, harness_id);
    if !build_dir.is_dir() && !harness_dir.is_dir() && !legacy_auto_dir.is_dir() {
        return Err(format!(
            "work dir malformed: harness build directory '{}' (or harness layout '{}') not found",
            build_dir.display(),
            harness_dir.display()
        ));
    }

    // For the AFL++ engine, prefer the AFL-instrumented binary (built by
    // `bhf build --c-engine afl++`). Fall back to `main` so that
    // legacy workflows where the user manually copied a single binary
    // continue to work. The `<work>/harnesses/<id>/` layout is produced by
    // `bhf auto` (try_run_c_make_build_with_extras) which builds
    // in-place; check it as well so the auto attempt loop can locate
    // the binary it just built.
    // Each name with and without `.exe`, the platform's own spelling first: a
    // Windows build writes `main.exe` (an extensionless `main` beside it is
    // left from an older build), a MinGW cross build elsewhere `main.exe` too.
    let spellings = |dir: &Path, stem: &str| {
        let bare = dir.join(stem);
        let exe = dir.join(format!("{stem}.exe"));
        if cfg!(windows) {
            [exe, bare]
        } else {
            [bare, exe]
        }
    };
    let (stems, dirs): (&[&str], Vec<PathBuf>) = match engine {
        FuzzEngine::AflPlusPlus => (
            &["main_afl", "main"],
            vec![
                build_dir.clone(),
                harness_dir.clone(),
                legacy_auto_dir.clone(),
            ],
        ),
        // WinAFL fuzzes `main_winafl` beside the sanitized `main`, which every
        // saved input is replayed through and which the findings name.
        FuzzEngine::Builtin
        | FuzzEngine::Winafl
        | FuzzEngine::Libfuzzer
        | FuzzEngine::Honggfuzz
        | FuzzEngine::Libafl => (
            &["main"],
            vec![
                build_dir.clone(),
                build_dir.join("obj"),
                harness_dir.clone(),
                legacy_auto_dir.clone(),
            ],
        ),
    };
    let candidates: Vec<PathBuf> = dirs
        .iter()
        .flat_map(|dir| stems.iter().flat_map(|stem| spellings(dir, stem)))
        .collect();

    for candidate in candidates {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    Err(format!(
        "work dir malformed: no built harness executable found under {}, {}, or {}",
        build_dir.display(),
        harness_dir.display(),
        legacy_auto_dir.display()
    ))
}

fn write_run_summary(work_dir: &Path, summary: &FuzzRunSummary) -> Result<(), String> {
    let runs_dir = work_dir.join("fuzz_runs");
    fs::create_dir_all(&runs_dir).map_err(|error| {
        format!(
            "create fuzz run directory '{}': {error}",
            runs_dir.display()
        )
    })?;
    let json = serde_json::to_string_pretty(summary)
        .map_err(|error| format!("render fuzz run summary: {error}"))?;
    let latest = runs_dir.join(format!("{}-latest.json", summary.harness_id));
    fs::write(&latest, format!("{json}\n"))
        .map_err(|error| format!("write fuzz run summary '{}': {error}", latest.display()))
}

fn temp_event_path(work_dir: &Path) -> Result<PathBuf, String> {
    let events_dir = work_dir.join("events");
    fs::create_dir_all(&events_dir).map_err(|error| {
        format!(
            "create events directory '{}': {error}",
            events_dir.display()
        )
    })?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    Ok(events_dir.join(format!("fuzz-events-{}-{nonce}.bin", std::process::id())))
}

fn absolutize(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|error| format!("resolve current directory: {error}"))
    }
}

/// Free-growth ceiling for the `auto` "auto" mode: adaptive length control grows the
/// effective length up to here WITHOUT needing to prove productivity (covers the vast
/// majority of "large object" formats — images, documents, configs, small firmware).
pub(crate) const AUTO_SOFT_CEILING: usize = 1024 * 1024;
/// Hard ceiling for the `auto` "auto" mode: growth PAST [`AUTO_SOFT_CEILING`] toward
/// this only continues while it keeps producing new coverage (genuinely large targets
/// like firmware/video), so a small-format target is never grown here pointlessly.
pub(crate) const AUTO_MAX_LEN_CEILING: usize = 64 * 1024 * 1024;

/// Resolve the per-target hard max input length for the `auto` path from the
/// `BHF_MAX_LEN` env it sets: `auto` uses the adaptive ceiling (and never truncates
/// a larger seed), a number is a fixed cap, and unset keeps the fixed default (so
/// non-auto callers and tests are unchanged). `largest_seed` is the largest seed's
/// byte length, so even a huge sample is honored rather than truncated.
pub(crate) fn resolve_env_max_len(largest_seed: usize) -> usize {
    resolve_max_len_spec(std::env::var("BHF_MAX_LEN").ok().as_deref(), largest_seed)
}

/// Pure resolution of a max-len spec (`None`/`"auto"`/a number) against the largest
/// seed, split out so it is testable without touching process env.
fn resolve_max_len_spec(spec: Option<&str>, largest_seed: usize) -> usize {
    match spec {
        Some(spec) if spec.eq_ignore_ascii_case("auto") => AUTO_MAX_LEN_CEILING.max(largest_seed),
        Some(spec) => spec
            .parse::<usize>()
            .ok()
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_MAX_LEN),
        None => DEFAULT_MAX_LEN,
    }
}

/// Resolve the per-exec timeout for the `auto` path from the `BHF_EXEC_TIMEOUT`
/// env (milliseconds) it sets; `None` keeps the engine's default (`PER_INPUT_TIMEOUT`).
pub(crate) fn resolve_env_timeout() -> Option<Duration> {
    std::env::var("BHF_EXEC_TIMEOUT")
        .ok()
        .and_then(|ms| ms.trim().parse::<u64>().ok())
        .map(Duration::from_millis)
}

/// Resolve the real-time response deadline (the timing oracle) for the `auto`
/// path from the `BHF_DEADLINE_MS` env (milliseconds) it sets; `None` (the
/// default, and every current caller) leaves the oracle OFF so hang handling is
/// unchanged. Milliseconds so a sub-second watchdog budget is expressible, and a
/// `0`/unparsable value disables it rather than flagging every input.
pub(crate) fn resolve_env_deadline() -> Option<Duration> {
    std::env::var("BHF_DEADLINE_MS")
        .ok()
        .and_then(|ms| ms.trim().parse::<u64>().ok())
        .filter(|&ms| ms > 0)
        .map(Duration::from_millis)
}

/// Parse a duration flag: a number with an optional unit, `ms`, `s`, `m` or
/// `h` (seconds when bare). The number may be fractional (`0.5s`, `1.5m`), and
/// `500ms` is half a second, as the docs write it.
pub(crate) fn parse_duration(value: &str) -> Result<Duration, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("duration must not be empty".to_owned());
    }
    let lower = trimmed.to_ascii_lowercase();
    let (number, unit_millis): (&str, u64) = if let Some(number) = lower.strip_suffix("ms") {
        (number, 1)
    } else if let Some(number) = lower.strip_suffix('s') {
        (number, 1_000)
    } else if let Some(number) = lower.strip_suffix('m') {
        (number, 60_000)
    } else if let Some(number) = lower.strip_suffix('h') {
        (number, 3_600_000)
    } else {
        (lower.as_str(), 1_000)
    };
    let number = number.trim();
    let invalid = || {
        format!(
            "invalid duration '{value}': use a number with ms, s, m or h (500ms, 0.5s, 10s, 5m)"
        )
    };
    if number.is_empty()
        || number.matches('.').count() > 1
        || !number.chars().all(|c| c.is_ascii_digit() || c == '.')
        || number.starts_with('.') && number.len() == 1
    {
        return Err(invalid());
    }
    if let Ok(whole) = number.parse::<u64>() {
        return Ok(Duration::from_millis(whole.saturating_mul(unit_millis)));
    }
    let amount: f64 = number.parse().map_err(|_| invalid())?;
    Duration::try_from_secs_f64(amount * unit_millis as f64 / 1_000.0).map_err(|_| invalid())
}

/// A duration as a flag value a child `bhf` parses back exactly: whole
/// seconds as `Ns`, anything finer as `Nms`.
pub(crate) fn duration_arg(duration: Duration) -> String {
    if duration.subsec_millis() == 0 {
        format!("{}s", duration.as_secs())
    } else {
        format!("{}ms", duration.as_millis())
    }
}

fn parse_worker_count(value: &str) -> Result<FuzzWorkerCount, String> {
    if value.eq_ignore_ascii_case("auto") {
        return Ok(FuzzWorkerCount::Auto);
    }
    let workers = value
        .parse::<u32>()
        .map_err(|error| format!("invalid worker count '{value}': {error}"))?;
    if workers == 0 {
        return Err("worker count must be at least 1".to_owned());
    }
    Ok(FuzzWorkerCount::Fixed(workers))
}

#[cfg(all(test, unix))]
mod signal_classification_tests {
    use super::is_input_rejection;
    use crate::fatal_signal::BHF_WIN_CRASH_EXIT;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    #[test]
    fn only_memory_safety_signals_are_crashes_benign_signals_are_rejections() {
        // A wait-status terminated by signal N is encoded with N in the low 7 bits.
        let by_signal = |sig: i32| ExitStatus::from_raw(sig);

        // Genuine memory-safety crash signals -> NOT a rejection (surface as BHF-210).
        for sig in [
            4,  /*ILL*/
            7,  /*BUS*/
            8,  /*FPE*/
            11, /*SEGV*/
        ] {
            assert!(
                !is_input_rejection(&by_signal(sig), ""),
                "signal {sig} is a genuine crash and must not be treated as a rejection",
            );
        }

        // A silent SIGABRT gives no evidence of intentional rejection.
        assert!(
            !is_input_rejection(&by_signal(6), ""),
            "silent SIGABRT must surface as BHF-210",
        );
        assert!(
            is_input_rejection(
                &by_signal(6),
                "parser.c:12: parse: Assertion 'magic == expected' failed."
            ),
            "an assertion diagnostic identifies an intended rejection",
        );
        assert!(
            is_input_rejection(&by_signal(6), "thread 'main' panicked at src/lib.rs:4:2"),
            "a panic diagnostic identifies an intended rejection",
        );

        // Benign / external signals -> rejections (never a BHF-210).
        // SIGPIPE (13) is the regression under test: a closed progress/stats pipe
        // killed the harness, bhf reported a phantom high-severity "reachable
        // crash" on a valid glTF that exits 0 on replay.
        for sig in [
            13, // SIGPIPE — wrote to a closed pipe (plumbing, not a target bug)
            15, // SIGTERM — external termination
            2,  // SIGINT
            1,  // SIGHUP
            14, // SIGALRM — timeout path, not a code defect
        ] {
            assert!(
                is_input_rejection(&by_signal(sig), ""),
                "signal {sig} is benign/external and must be a rejection, not a crash",
            );
        }

        // A plain non-zero exit code (error return on malformed input) -> rejection.
        assert!(
            is_input_rejection(&ExitStatus::from_raw(1 << 8), ""),
            "a non-signal error exit is an input rejection",
        );
    }

    /// A fatal signal names its signal as the report's check, so an abort and
    /// an illegal instruction with no frames are two signatures, two
    /// root-cause keys and two findings.
    #[test]
    fn fatal_signal_reports_of_different_signals_have_different_identities() {
        let abort = super::fatal_signal_report(&ExitStatus::from_raw(6), "");
        let illegal = super::fatal_signal_report(&ExitStatus::from_raw(4), "");
        assert_eq!(abort.check.as_deref(), Some("SIGABRT"));
        assert_eq!(illegal.check.as_deref(), Some("SIGILL"));
        assert_ne!(
            corpus::finding::sanitizer_signature(&abort),
            corpus::finding::sanitizer_signature(&illegal)
        );
        assert_ne!(
            corpus::finding::sanitizer_dedupe_key_scoped(&abort, "H-1"),
            corpus::finding::sanitizer_dedupe_key_scoped(&illegal, "H-1")
        );
    }

    #[test]
    fn windows_crash_sentinel_exit_is_a_crash_not_a_rejection() {
        // Under wine a guest fault carries NO POSIX signal; the driver's vectored
        // exception handler reports it via the BHF_WIN_CRASH_EXIT exit code.
        // That code must classify as a crash; any other nonzero exit stays a
        // rejection.
        let crash = ExitStatus::from_raw(BHF_WIN_CRASH_EXIT << 8);
        assert_eq!(crash.code(), Some(BHF_WIN_CRASH_EXIT));
        assert!(
            !is_input_rejection(&crash, ""),
            "the Windows crash sentinel exit must be a crash, not a rejection",
        );
        assert!(
            is_input_rejection(&ExitStatus::from_raw(2 << 8), ""),
            "an ordinary nonzero exit remains an input rejection",
        );
    }
}

/// bhf's driver in a build without a sanitizer runtime reports where a fatal
/// signal hit before it dies by that signal, so frame-less crashes of one
/// harness can be told apart.
#[cfg(all(test, target_os = "linux"))]
mod fatal_signal_driver_tests {
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    const TARGET: &str = r#"
#include <stdint.h>
#include <stddef.h>
#include <signal.h>
__attribute__((noinline)) static void copy_at(volatile char *p) { *p = 1; }
__attribute__((noinline)) static int bit_index(const volatile int *p) { return *p >> 3; }
int bhf_run_one(const uint8_t *data, size_t size) {
    if (size > 0 && data[0] == 'A') copy_at((volatile char *)0);
    if (size > 0 && data[0] == 'B') return bit_index((const volatile int *)8);
    if (size > 0 && data[0] == 'T') raise(SIGTRAP);
    return 0;
}
"#;

    /// Build the target with bhf's driver and no sanitizer, as a cross build
    /// without a sanitizer runtime is.
    fn build(dir: &Path) -> Option<PathBuf> {
        let driver = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime/bhf_driver.c");
        std::fs::write(dir.join("target.c"), TARGET).unwrap();
        let output = Command::new("cc")
            .current_dir(dir)
            .args(["-O1", "-g", "-o", "main", "target.c"])
            .arg(&driver)
            .output()
            .ok()?;
        output.status.success().then(|| dir.join("main"))
    }

    fn run(harness: &Path, dir: &Path, input: &[u8]) -> (std::process::ExitStatus, String) {
        let testcase = dir.join("testcase.bin");
        std::fs::write(&testcase, input).unwrap();
        let output = Command::new(harness).arg(&testcase).output().unwrap();
        (
            output.status,
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    #[test]
    fn a_fault_prints_the_signal_and_pc_and_still_dies_by_the_signal() {
        let dir = tempfile::tempdir().unwrap();
        let Some(harness) = build(dir.path()) else {
            eprintln!("skipping: no C compiler");
            return;
        };
        let (status, stderr) = run(&harness, dir.path(), b"A");
        assert_eq!(status.signal(), Some(11), "{stderr}");
        let line = stderr
            .lines()
            .find(|line| line.starts_with("bhf: fatal signal SIGSEGV pc=0x"))
            .unwrap_or_else(|| panic!("no fatal-signal line in {stderr:?}"));
        assert!(line.contains(" addr=0x0"), "{line}");
        assert!(line.contains(" exe_offset=0x"), "{line}");

        let copy_at = super::fatal_signal_report(&status, &stderr);
        let offset = copy_at
            .pc_offset
            .expect("the pc offset is read from the line");
        let (status, stderr) = run(&harness, dir.path(), b"B");
        assert_eq!(status.signal(), Some(11), "{stderr}");
        let bit_index = super::fatal_signal_report(&status, &stderr);
        assert_ne!(bit_index.pc_offset, Some(offset), "two sites, two offsets");
        assert_ne!(
            corpus::finding::sanitizer_signature(&copy_at),
            corpus::finding::sanitizer_signature(&bit_index)
        );
        // The same input faults at the same offset in every run (ASLR moves
        // the absolute pc, not the offset).
        let (status, stderr) = run(&harness, dir.path(), b"A");
        assert_eq!(
            super::fatal_signal_report(&status, &stderr).pc_offset,
            Some(offset)
        );
        // No crash, no line.
        let (status, stderr) = run(&harness, dir.path(), b"ok");
        assert!(status.success(), "{stderr}");
        assert!(!stderr.contains("bhf: fatal signal"), "{stderr}");
    }
}

#[cfg(test)]
mod engine_list_tests {
    use super::{
        afl_cmplog_binary, parse_engine_list, read_bounded_head_tail, read_seed_file_prefix,
        resolve_afl_fuzz, AflMode, FuzzEngine,
    };
    use std::path::Path;

    #[test]
    fn diagnostic_capture_keeps_both_ends_under_a_fixed_bound() {
        let input: Vec<u8> = (0_u8..100).collect();
        let output = read_bounded_head_tail(input.as_slice(), 16);
        assert!(output.starts_with(&input[..8]));
        assert!(output.ends_with(&input[92..]));
        assert!(output
            .windows("diagnostic output truncated".len())
            .any(|window| window == b"diagnostic output truncated"));
        assert!(output.len() <= 16 + 64);
    }

    #[test]
    fn seed_file_reader_never_allocates_past_requested_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large-seed.bin");
        std::fs::write(&path, vec![7_u8; 4096]).unwrap();
        let (bytes, original_len) = read_seed_file_prefix(&path, 32).unwrap();
        assert_eq!(original_len, 4096);
        assert_eq!(bytes, vec![7_u8; 32]);
    }

    #[test]
    fn parse_engine_list_dedupes_and_orders() {
        assert_eq!(
            parse_engine_list("builtin").unwrap(),
            vec![FuzzEngine::Builtin]
        );
        assert_eq!(
            parse_engine_list("afl++").unwrap(),
            vec![FuzzEngine::AflPlusPlus]
        );
        // order preserved, duplicates collapsed
        assert_eq!(
            parse_engine_list("builtin,afl++,builtin").unwrap(),
            vec![FuzzEngine::Builtin, FuzzEngine::AflPlusPlus]
        );
        // whitespace tolerated, order as written
        assert_eq!(
            parse_engine_list(" afl++ , builtin ").unwrap(),
            vec![FuzzEngine::AflPlusPlus, FuzzEngine::Builtin]
        );
        // synonyms map to afl++
        assert_eq!(
            parse_engine_list("afl").unwrap(),
            vec![FuzzEngine::AflPlusPlus]
        );
        // The external engines parse, so `bhf auto` can say why it refuses them.
        assert_eq!(
            parse_engine_list("libfuzzer,honggfuzz,libafl").unwrap(),
            vec![
                FuzzEngine::Libfuzzer,
                FuzzEngine::Honggfuzz,
                FuzzEngine::Libafl
            ]
        );
        assert!(parse_engine_list("").is_err());
        assert!(parse_engine_list("nyx").is_err());
    }

    #[test]
    fn afl_mode_maps_to_binary_only_fuzz_flags() {
        // Issue #45: native adds nothing; qemu/frida select AFL's binary-only modes.
        assert_eq!(AflMode::Native.flag(), None);
        assert_eq!(AflMode::Qemu.flag(), Some("-Q"));
        assert_eq!(AflMode::Frida.flag(), Some("-O"));
    }

    #[test]
    fn afl_inst_ranges_use_mode_specific_env() {
        let ranges = vec!["target.so".to_owned(), "0x1000-0x2000".to_owned()];
        assert_eq!(
            AflMode::Qemu.inst_ranges_env_value(&ranges),
            Some(("AFL_QEMU_INST_RANGES", "target.so,0x1000-0x2000".to_owned()))
        );
        assert_eq!(
            AflMode::Frida.inst_ranges_env_value(&ranges),
            Some((
                "AFL_FRIDA_INST_RANGES",
                "target.so,0x1000-0x2000".to_owned()
            ))
        );
        // No ranges, or native mode, never sets an env var.
        assert_eq!(AflMode::Qemu.inst_ranges_env_value(&[]), None);
        assert_eq!(AflMode::Native.inst_ranges_env_value(&ranges), None);
    }

    #[test]
    fn resolve_afl_fuzz_prefers_afl_path_then_falls_back() {
        let dir = crate::test_support::TestDir::new("aflpath");
        let bin = dir.join(if cfg!(windows) {
            "afl-fuzz.exe"
        } else {
            "afl-fuzz"
        });
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        assert_eq!(resolve_afl_fuzz(Some(&dir)).unwrap(), bin);
        // A directory without afl-fuzz falls through to the PATH search (which may
        // or may not find one — either way it must not return the missing path).
        let empty = dir.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        assert_ne!(
            resolve_afl_fuzz(Some(&empty)).ok(),
            Some(empty.join("afl-fuzz"))
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// #276: `--workers N` is one `-M main` running CmpLog and N-1 `-S`
    /// instances, each logging to its own file; one worker is `default`, with
    /// no role. Only the AFL++ engine takes the count, and its instances sync
    /// every quarter of the budget, between 1 and 30 minutes.
    #[test]
    fn afl_workers_are_one_main_and_secondary_instances() {
        use super::{afl_instances, afl_sync_minutes, afl_worker_count, FuzzWorkerCount};
        let dir = Path::new("/w/afl_out/H");
        let one = afl_instances(1, dir);
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].name, "default");
        assert_eq!(one[0].role, None);
        assert!(one[0].cmplog);
        assert_eq!(one[0].log, dir.join("afl-fuzz.log"));
        let three = afl_instances(3, dir);
        let plan: Vec<(&str, Option<&str>, bool)> = three
            .iter()
            .map(|instance| (instance.name.as_str(), instance.role, instance.cmplog))
            .collect();
        assert_eq!(
            plan,
            [
                ("main", Some("-M"), true),
                ("sec1", Some("-S"), false),
                ("sec2", Some("-S"), false)
            ]
        );
        assert_eq!(three[2].log, dir.join("afl-fuzz-sec2.log"));
        assert_eq!(
            afl_worker_count(FuzzEngine::AflPlusPlus, Some(FuzzWorkerCount::Fixed(4))),
            4
        );
        assert_eq!(afl_worker_count(FuzzEngine::AflPlusPlus, None), 1);
        assert_eq!(
            afl_worker_count(FuzzEngine::Builtin, Some(FuzzWorkerCount::Fixed(4))),
            1
        );
        assert!(afl_worker_count(FuzzEngine::AflPlusPlus, Some(FuzzWorkerCount::Auto)) >= 1);
        assert_eq!(afl_sync_minutes(std::time::Duration::from_secs(60)), 1);
        assert_eq!(
            afl_sync_minutes(std::time::Duration::from_secs(40 * 60)),
            10
        );
        assert_eq!(
            afl_sync_minutes(std::time::Duration::from_secs(24 * 3600)),
            30
        );
    }

    /// #275: the crashes and hangs of every instance are harvested with the
    /// `<kind>.<date>/` a resumed session moved the last one's to, and those
    /// backups are removed after; AFL++'s README is not an input.
    #[cfg(unix)]
    #[test]
    fn saved_afl_inputs_include_a_resumed_sessions_backups() {
        use super::{afl_saved_inputs, remove_afl_backups};
        let dir = crate::test_support::TestDir::new("afl-saved");
        let out = dir.join("out");
        let write = |relative: &str| {
            let path = out.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"x").unwrap();
        };
        write("default/queue/id:000000,orig:seed");
        write("default/crashes/id:000000,sig:06");
        write("default/crashes/README.txt");
        write("default/crashes.2026-01-01-00:00:00/id:000000,sig:11");
        write("default/hangs/id:000000,src:000000");
        write("_resume/id:000000");
        let names = |paths: Vec<std::path::PathBuf>| -> Vec<String> {
            paths
                .iter()
                .map(|path| {
                    path.strip_prefix(&out)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect()
        };
        assert_eq!(
            names(afl_saved_inputs(&out, "crashes")),
            [
                "default/crashes/id:000000,sig:06",
                "default/crashes.2026-01-01-00:00:00/id:000000,sig:11"
            ]
        );
        assert_eq!(
            names(afl_saved_inputs(&out, "hangs")),
            ["default/hangs/id:000000,src:000000"]
        );
        remove_afl_backups(&out);
        assert!(!out.join("default/crashes.2026-01-01-00:00:00").exists());
        assert!(out.join("default/crashes/id:000000,sig:06").is_file());
    }

    /// #275: a resumed session's queue gets a seed it does not hold, once:
    /// one it holds, or was given before (and trimmed since), is not added.
    #[cfg(unix)]
    #[test]
    fn a_resumed_queue_gets_each_new_seed_once() {
        use super::{add_resume_seeds, afl_seed_hash};
        let dir = crate::test_support::TestDir::new("afl-resume-seeds");
        let queue = dir.join("queue");
        std::fs::create_dir_all(&queue).unwrap();
        std::fs::write(queue.join("id:000000,orig:seed"), b"held").unwrap();
        let mut offered = std::collections::HashSet::from([afl_seed_hash(b"trimmed-away")]);
        let seeds = [
            b"held".to_vec(),
            b"new".to_vec(),
            b"new".to_vec(),
            Vec::new(),
            b"trimmed-away".to_vec(),
        ];
        assert_eq!(add_resume_seeds(&queue, &seeds, &mut offered).unwrap(), 1);
        let added = queue.join(format!("id:999999,orig:bhf-seed-{}", afl_seed_hash(b"new")));
        assert_eq!(std::fs::read(&added).unwrap(), b"new");
        assert_eq!(add_resume_seeds(&queue, &seeds, &mut offered).unwrap(), 0);
    }

    /// #274: afl-fuzz runs `-c` on the CmpLog build beside `main_afl` in a
    /// compile-time-instrumented run, unless it is older than `main_afl`.
    #[test]
    fn the_cmplog_build_beside_main_afl_is_used_unless_it_is_stale() {
        let dir = crate::test_support::TestDir::new("afl-cmplog");
        let main_afl = dir.join(crate::auto::layout::harness_exe_name("main_afl"));
        let cmplog = dir.join(crate::auto::layout::harness_exe_name("main_afl_cmplog"));
        std::fs::write(&main_afl, b"afl").unwrap();
        assert_eq!(afl_cmplog_binary(&main_afl, AflMode::Native), None);
        std::fs::write(&cmplog, b"cmplog").unwrap();
        let at = |path: &Path, secs: u64| {
            std::fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs))
                .unwrap();
        };
        at(&main_afl, 1_000);
        at(&cmplog, 1_001);
        assert_eq!(
            afl_cmplog_binary(&main_afl, AflMode::Native),
            Some(cmplog.clone())
        );
        assert_eq!(afl_cmplog_binary(&main_afl, AflMode::Qemu), None);
        at(&cmplog, 999);
        assert_eq!(afl_cmplog_binary(&main_afl, AflMode::Native), None);
    }

    #[test]
    fn parse_afl_fuzzer_stats_reads_execs() {
        let tmp = tempfile::tempdir().unwrap();
        let instance = |name: &str, execs: u64, per_sec: f64| {
            let dir = tmp.path().join(name);
            std::fs::create_dir_all(dir.join("queue")).unwrap();
            std::fs::write(
                dir.join("fuzzer_stats"),
                format!(
                    "start_time        : 1000\n\
                     execs_done        : {execs}\n\
                     execs_per_sec     : {per_sec:.2}\n\
                     cycles_done       : 2\n"
                ),
            )
            .unwrap();
        };
        instance("default", 443314, 73873.50);
        let (execs, per_sec) = super::parse_afl_fuzzer_stats(tmp.path());
        assert_eq!(execs, Some(443314));
        assert_eq!(per_sec, Some(73873.50));
        // #276: a -M/-S campaign's instances add up.
        std::fs::remove_dir_all(tmp.path().join("default")).unwrap();
        instance("main", 1000, 10.0);
        instance("sec1", 500, 5.5);
        assert_eq!(
            super::parse_afl_fuzzer_stats(tmp.path()),
            (Some(1500), Some(15.5))
        );
        // Missing file -> (None, None), never a panic.
        let missing = tempfile::tempdir().unwrap();
        assert_eq!(super::parse_afl_fuzzer_stats(missing.path()), (None, None));
    }

    #[test]
    fn afl_programmatic_errors_without_main_afl() {
        // No main_afl (empty work dir) -> clear error, no panic. Confirms the
        // programmatic AFL entry fails closed for the attempt loop to handle.
        let tmp = tempfile::tempdir().unwrap();
        let result = super::run_afl_plus_plus_programmatic(
            tmp.path(),
            "H-NONE",
            vec![b"seed".to_vec()],
            Some(std::time::Duration::from_secs(1)),
            &[],
            actionability::RunMode::Reporting,
            2048,
            &[],
        );
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod dedup_seed_tests {
    use super::{ExistingFindings, SanitizerClusterDedup};

    #[test]
    fn seeds_sanitizer_cluster_and_oracle_keys_from_findings_dir() {
        // #35: a later cascade pass must reconstruct the dedup keys of findings a
        // prior pass already wrote, so it does not re-emit byte-identical findings.
        let work = tempfile::tempdir().unwrap();
        let findings = work.path().join("results").join("findings");
        // A sanitizer-crash finding (clustered).
        let c = findings.join("F-0001-aaaa");
        std::fs::create_dir_all(&c).unwrap();
        std::fs::write(
            c.join("finding.json"),
            serde_json::to_vec(&serde_json::json!({
                "id": "F-0001-aaaa",
                "harness_id": "H-TEST",
                "rule_id": "BHF-201",
                "cluster_key_full": "deadbeef",
                "cluster_fallback": false,
            }))
            .unwrap(),
        )
        .unwrap();
        // A fallback sanitizer-crash finding: keyed by its own cluster key (its
        // signature), not by one `rule:<id>` shared by every crash of the rule.
        let f = findings.join("F-0002-bbbb");
        std::fs::create_dir_all(&f).unwrap();
        std::fs::write(
            f.join("finding.json"),
            serde_json::to_vec(&serde_json::json!({
                "id": "F-0002-bbbb",
                "harness_id": "H-TEST",
                "rule_id": "BHF-210",
                "cluster_key_full": "f00d",
                "cluster_fallback": true,
            }))
            .unwrap(),
        )
        .unwrap();
        // An oracle-hit finding.
        let o = findings.join("F-0003-cccc");
        std::fs::create_dir_all(&o).unwrap();
        std::fs::write(
            o.join("finding.json"),
            serde_json::to_vec(&serde_json::json!({
                "id": "F-0003-cccc",
                "harness_id": "H-TEST",
                "rule_id": "BHF-405",
                "oracle": { "name": "path-traversal", "api": "open" },
            }))
            .unwrap(),
        )
        .unwrap();

        let existing = ExistingFindings::load(work.path(), "H-TEST");
        assert_eq!(
            existing.clusters.get("deadbeef").map(String::as_str),
            Some("F-0001-aaaa")
        );
        assert_eq!(
            existing.clusters.get("f00d").map(String::as_str),
            Some("F-0002-bbbb")
        );
        assert!(!existing.clusters.keys().any(|key| key.starts_with("rule:")));
        assert_eq!(
            existing
                .oracles
                .get("BHF-405|path-traversal|open")
                .map(String::as_str),
            Some("F-0003-cccc")
        );
    }

    #[test]
    fn a_key_shared_by_several_findings_maps_to_the_lowest_id() {
        let work = tempfile::tempdir().unwrap();
        let findings = work.path().join("results").join("findings");
        for id in ["F-0007-ffff", "F-0002-eeee", "F-0009-dddd"] {
            let dir = findings.join(id);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("finding.json"),
                serde_json::to_vec(&serde_json::json!({
                    "id": id,
                    "harness_id": "H-TEST",
                    "rule_id": "BHF-201",
                    "cluster_key_full": "c0ffee",
                    "signature": "5151",
                }))
                .unwrap(),
            )
            .unwrap();
        }
        let existing = ExistingFindings::load(work.path(), "H-TEST");
        assert_eq!(
            existing.clusters.get("c0ffee").map(String::as_str),
            Some("F-0002-eeee")
        );
        assert_eq!(
            existing.signatures.get("5151").map(String::as_str),
            Some("F-0002-eeee")
        );
    }

    /// A later pass re-seeds exactly the key the loop computes for the crash a
    /// prior pass emitted, and nothing that would hide a different site.
    #[test]
    fn seeded_keys_match_the_runtime_key_of_an_emitted_finding() {
        let work = tempfile::tempdir().unwrap();
        let report = |line: u32| {
            corpus::parse_sanitizer_report(&format!(
                "/src/widget/a.c:{line}:5: runtime error: execution reached the end of a value-returning function without returning a value\n"
            ))
            .unwrap()
        };
        corpus::finding::FindingEmitter::with_metadata(
            work.path().to_path_buf(),
            "H-TEST".to_owned(),
            "c".to_owned(),
            String::new(),
        )
        .emit_sanitizer_crash(b"x", &report(3))
        .unwrap();
        let existing = ExistingFindings::load(work.path(), "H-TEST");
        let clusters: Vec<&String> = existing.clusters.keys().collect();
        assert_eq!(
            clusters,
            vec![&corpus::finding::sanitizer_dedupe_key(&report(3))]
        );
        assert!(!existing
            .clusters
            .contains_key(&corpus::finding::sanitizer_dedupe_key(&report(9))));
    }

    /// A frame-less crash written by an earlier pass is a duplicate for a run
    /// keyed in the same scope, and a new root cause for another harness.
    #[test]
    fn a_frameless_crash_from_disk_is_a_duplicate_only_in_its_scope() {
        let work = tempfile::tempdir().unwrap();
        let report = corpus::SanitizerReport {
            kind: "fatal-signal".to_owned(),
            rule_id: "BHF-210",
            message: "harness crashed with SIGSEGV and no sanitizer report".to_owned(),
            ..Default::default()
        };
        let scope = corpus::cluster::crash_scope("H-TEST", Some("parse_record"));
        corpus::finding::FindingEmitter::with_metadata(
            work.path().to_path_buf(),
            "H-TEST".to_owned(),
            "c".to_owned(),
            String::new(),
        )
        .with_crash_scope(scope.clone())
        .emit_sanitizer_crash(b"x", &report)
        .unwrap();
        let existing = ExistingFindings::load(work.path(), "H-TEST");
        let mut same =
            SanitizerClusterDedup::new(existing.clusters.keys().cloned()).with_scope(scope.clone());
        assert_eq!(same.first_sighting(&report), None);
        let mut other = SanitizerClusterDedup::new(existing.clusters.keys().cloned())
            .with_scope(corpus::cluster::crash_scope("H-OTHER", None));
        assert!(other.first_sighting(&report).is_some());
    }

    #[test]
    fn missing_findings_dir_yields_empty_seeds() {
        let work = tempfile::tempdir().unwrap();
        let existing = ExistingFindings::load(work.path(), "H-TEST");
        assert!(existing.clusters.is_empty() && existing.oracles.is_empty());
        assert!(existing.signatures.is_empty());
    }
}

#[cfg(test)]
mod entropic_tests {
    use super::{
        choose_entropic_index_pool, entropic_weight, retire_from_pool, splice_peer,
        CoverageNovelty, PoolEntry,
    };
    use fuzz_engine_builtin::MutationRng;

    #[test]
    fn entropic_weight_rises_with_energy_and_decays_with_selections() {
        // Baseline: no novelty, never selected.
        assert_eq!(entropic_weight(0, 0), 1024);
        // More coverage novelty -> strictly higher weight.
        assert_eq!(entropic_weight(4, 0), 5120);
        assert!(entropic_weight(4, 0) > entropic_weight(1, 0));
        // Repeated selection decays the weight (entropic back-off): a 4-energy
        // seed picked 4 times sinks back to the unselected baseline, and a
        // fresh seed eventually outweighs an over-mined one.
        assert_eq!(entropic_weight(4, 4), 1024);
        assert!(entropic_weight(0, 0) > entropic_weight(4, 9));
    }

    /// A pool entry a fresh re-run showed to crash is a finding: it is never
    /// picked to mutate from, however much energy it had, nor spliced from.
    #[test]
    fn a_retired_entry_is_neither_a_base_nor_a_splice_peer() {
        let mut pool = vec![
            PoolEntry::seed(b"crash".to_vec()),
            PoolEntry::seed(b"clean-1".to_vec()),
            PoolEntry::seed(b"clean-2".to_vec()),
        ];
        pool[0].energy = 4096;
        assert_eq!(splice_peer(&pool, 2), 0, "before: the next entry");
        retire_from_pool(&mut pool, b"crash");
        let mut rng = MutationRng::new(7);
        for _ in 0..500 {
            assert_ne!(choose_entropic_index_pool(&pool, &mut rng), 0);
        }
        assert_eq!(splice_peer(&pool, 2), 1, "the retired entry is skipped");
        assert_eq!(splice_peer(&pool, 1), 2);
    }

    #[test]
    fn choose_entropic_index_favors_high_weight_seed() {
        // A far-rarer/under-explored seed (index 1) must be picked far more
        // often than a zero-novelty, heavily-mined one (index 0).
        let mut pool = vec![PoolEntry::seed(vec![0]), PoolEntry::seed(vec![1])];
        pool[0].energy = 0;
        pool[0].selections = 50;
        pool[1].energy = 100;
        pool[1].selections = 0;
        let mut rng = MutationRng::new(0xC0FFEE);
        let mut counts = [0usize; 2];
        for _ in 0..2000 {
            counts[choose_entropic_index_pool(&pool, &mut rng)] += 1;
        }
        assert!(
            counts[1] > counts[0] * 10,
            "entropic choice should strongly favor the rare seed: {counts:?}"
        );
    }

    #[test]
    fn marginal_coverage_awards_more_energy_than_incidental_progress() {
        let broad_lane = CoverageNovelty {
            new_edges: 40,
            new_buckets: 3,
            comparison_advances: 1,
            deeper_stack: 0,
        };
        let narrow_lane = CoverageNovelty {
            new_edges: 0,
            new_buckets: 1,
            comparison_advances: 0,
            deeper_stack: 0,
        };
        assert!(broad_lane.scheduling_energy() > narrow_lane.scheduling_energy() * 100);
        assert!(broad_lane.made_progress());
        assert!(!CoverageNovelty::default().made_progress());
    }
}

#[cfg(test)]
mod grammar_tree_tests {
    use super::{mutate_from_pool, PoolEntry};
    use fuzz_engine_builtin::{Dictionary, Grammar, MutationRng, MutatorConfig};

    fn grammar() -> Grammar {
        Grammar::from_rules(
            &[(
                "S".to_owned(),
                ["({S})", "[{S}]", "{S}{S}", "x", "y"]
                    .map(str::to_owned)
                    .to_vec(),
            )],
            None,
        )
        .unwrap()
    }

    /// #329: a pool entry that keeps its derivation tree is mutated mostly on
    /// the tree, and each such child comes back with the tree that derives it;
    /// an entry without one gets a tree only from a fresh derivation.
    #[test]
    fn a_grammar_entry_is_mutated_on_its_tree() {
        let grammar = grammar();
        let mut rng = MutationRng::new(3);
        let tree = loop {
            let tree = grammar.generate_tree(64, &mut rng).unwrap();
            if tree.len() > 6 {
                break tree;
            }
        };
        let mut entry = PoolEntry::seed(grammar.sentence(&tree));
        entry.tree = Some(tree);
        let pool = vec![entry];
        let plain = vec![PoolEntry::seed(pool[0].bytes.clone())];
        let config = MutatorConfig {
            max_len: 64,
            ..MutatorConfig::default()
        };
        let dictionary = Dictionary::default();
        let children_with_trees = |pool: &[PoolEntry], rng: &mut MutationRng| {
            let mut count = 0;
            for _ in 0..300 {
                let (bytes, _, tree) = mutate_from_pool(
                    pool,
                    0,
                    &dictionary,
                    None,
                    Some(&grammar),
                    config,
                    None,
                    rng,
                );
                if let Some(tree) = tree {
                    assert_eq!(grammar.sentence(&tree), bytes);
                    count += 1;
                }
            }
            count
        };
        let on_tree = children_with_trees(&pool, &mut rng);
        let fresh = children_with_trees(&plain, &mut rng);
        assert!(on_tree > 150, "{on_tree} of 300 children carry a tree");
        assert!(fresh < on_tree / 2, "{fresh} fresh derivations");
    }
}

#[cfg(test)]
mod typed_span_tests {
    use super::{mutate_from_pool, typed_spans, PoolEntry};
    use fuzz_engine_builtin::{Dictionary, MutationRng, MutatorConfig};

    /// The 32-bit boundary values the first argument of `outputs` took,
    /// little-endian at offset 0, with the rest of the base kept.
    fn int32_boundaries_at_the_span(outputs: &[Vec<u8>], base: &[u8]) -> Vec<i32> {
        let mut seen: Vec<i32> = [0, 1, -1, i32::MIN, i32::MAX]
            .into_iter()
            .filter(|value| {
                outputs.iter().any(|out| {
                    out.len() == base.len()
                        && out[..4] == value.to_le_bytes()
                        && out[4..] == base[4..]
                })
            })
            .collect();
        seen.sort_unstable();
        seen
    }

    fn mutate(entry: &PoolEntry) -> Vec<Vec<u8>> {
        let pool = [PoolEntry {
            typed_spans: entry.typed_spans.clone(),
            ..PoolEntry::seed(entry.bytes.clone())
        }];
        let dictionary = Dictionary::default();
        let config = MutatorConfig {
            max_len: 64,
            ..MutatorConfig::default()
        };
        let mut rng = MutationRng::new(299);
        (0..4000)
            .map(|_| mutate_from_pool(&pool, 0, &dictionary, None, None, config, None, &mut rng).0)
            .collect()
    }

    /// #299: the loop hands the mutator the spans the harness's
    /// `arg-layout.json` gives the base's decoded arguments, so the typed
    /// mutation writes an `int32_t` argument's boundary values into its
    /// bytes, little-endian, keeping the rest. Without the spans the same
    /// seeded run does not.
    #[test]
    fn fuzz_loop_passes_typed_spans_from_arg_layout() {
        let base = vec![9u8; 13];
        let layout = typed_spans::tests::packet_layout();
        let mut entry = PoolEntry::seed(base.clone());
        entry.typed_spans = Some(typed_spans::arg_layout_typed_spans(&layout, &base));
        assert_eq!(entry.typed_spans.as_ref().map(Vec::len), Some(3));
        assert_eq!(
            int32_boundaries_at_the_span(&mutate(&entry), &base),
            [i32::MIN, -1, 0, 1, i32::MAX]
        );

        entry.typed_spans = None;
        assert_ne!(
            int32_boundaries_at_the_span(&mutate(&entry), &base),
            [i32::MIN, -1, 0, 1, i32::MAX]
        );
    }
}

#[cfg(test)]
mod calibration_tests {
    use super::{Calibration, CALIBRATION_RERUNS};

    /// A target whose coverage follows its input alone: every entry keeps its
    /// place and stability is 100%, with no hint.
    #[test]
    fn a_deterministic_target_is_fully_stable() {
        let mut calibration = Calibration::default();
        assert_eq!(calibration.stability_pct(), None);
        assert!(calibration.summary().is_none());
        for edges in [vec![1, 2, 3], vec![1, 2, 4, 5]] {
            assert!(calibration.calibrate(&vec![edges; CALIBRATION_RERUNS]));
        }
        let summary = calibration.summary().unwrap();
        assert_eq!(summary.stability_pct, 100.0);
        assert_eq!((summary.observed_edges, summary.variable_edges), (5, 0));
        assert_eq!(summary.calibrated_entries, 2);
        assert_eq!(summary.unstable_entries_dropped, 0);
        assert_eq!(summary.hint(), None);
    }

    /// A static counter picks the edge: runs of one input differ, the edges
    /// that differ are variable, and an entry whose only news is such an
    /// edge is left out, while the first one, whose shared edges are new,
    /// stays.
    #[test]
    fn edges_that_vary_between_runs_of_an_input_lower_stability() {
        let mut calibration = Calibration::default();
        let shared = [1, 2, 3];
        let runs = |cases: [u32; 4]| -> Vec<Vec<u32>> {
            cases
                .iter()
                .map(|case| shared.iter().copied().chain([100 + case]).collect())
                .collect()
        };
        assert!(
            calibration.calibrate(&runs([0, 1, 2, 3])),
            "new shared edges"
        );
        assert!(
            !calibration.calibrate(&runs([4, 5, 6, 7])),
            "only a varying edge"
        );
        // An unstable input that also reaches a new edge every time stays.
        let mut deeper = runs([8, 9, 10, 11]);
        for run in &mut deeper {
            run.push(50);
        }
        assert!(calibration.calibrate(&deeper));

        let summary = calibration.summary().unwrap();
        assert_eq!(summary.observed_edges, 3 + 12 + 1);
        assert_eq!(summary.variable_edges, 12);
        assert_eq!(summary.stability_pct, 25.0);
        assert_eq!(summary.unstable_entries_dropped, 1);
        let hint = summary.hint().expect("a hint below 90%");
        assert!(hint.contains("stability 25.0%"), "{hint}");
        assert!(hint.contains("12 of the 16 edges"), "{hint}");
        assert!(hint.contains("1 new corpus entry whose"), "{hint}");
        assert!(hint.contains("--no-fork-server"), "{hint}");
    }

    /// 90% is the mark: at it, no hint; just under, one.
    #[test]
    fn the_hint_starts_below_ninety_percent() {
        let mut calibration = Calibration::default();
        let mut runs = vec![(0..10).collect::<Vec<u32>>(); CALIBRATION_RERUNS];
        runs[1].pop();
        calibration.calibrate(&runs);
        let summary = calibration.summary().unwrap();
        assert_eq!(summary.stability_pct, 90.0);
        assert_eq!(summary.hint(), None);
        let mut lower = summary;
        lower.stability_pct = 89.9;
        assert!(lower.hint().is_some());
    }
}

#[cfg(test)]
mod vp_tokens_tests {
    use super::read_vp_tokens;
    use std::io::Write;

    #[test]
    fn parses_driver_value_profile_log() {
        // Layout the driver writes: [u32 cursor][ {u8 len}{len bytes} ... ].
        let dir = crate::test_support::TestDir::new("vp");
        let path = dir.join("vp.shm");
        let mut body = Vec::new();
        for tok in [b"{".as_slice(), b"true", &[0x50, 0x4b, 0x03, 0x04]] {
            body.push(tok.len() as u8);
            body.extend_from_slice(tok);
        }
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&(body.len() as u32).to_ne_bytes()).unwrap();
        f.write_all(&body).unwrap();
        // Trailing zeroes (the driver sizes the file past the cursor) are ignored.
        f.write_all(&[0u8; 64]).unwrap();
        drop(f);

        let tokens = read_vp_tokens(&path);
        assert_eq!(
            tokens,
            vec![
                b"{".to_vec(),
                b"true".to_vec(),
                vec![0x50, 0x4b, 0x03, 0x04],
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_or_empty_log_yields_no_tokens() {
        assert!(read_vp_tokens(std::path::Path::new("/nonexistent/vp.shm")).is_empty());
    }
}

#[cfg(test)]
mod resolve_iterations_tests {
    use super::resolve_iterations;

    #[test]
    fn explicit_iterations_always_win() {
        assert_eq!(resolve_iterations(Some(10), false), 10);
        assert_eq!(resolve_iterations(Some(10), true), 10);
    }

    #[test]
    fn time_budget_without_explicit_iterations_runs_unbounded() {
        // The bug: a `--time` campaign was silently capped at the 256 default.
        assert_eq!(resolve_iterations(None, true), usize::MAX);
    }

    #[test]
    fn neither_falls_back_to_default() {
        assert_eq!(resolve_iterations(None, false), 256);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod coverage_tracker_tests {
    use super::{
        count_to_bucket, stack_depth_bucket, CoverageNovelty, CoverageTracker, BHF_COV_BITS,
    };
    use std::io::{Seek, SeekFrom, Write};

    // Set one bitmap byte (an "edge") the way the driver's coverage runtime would.
    // A write() to the file shares the page cache with the tracker's MAP_SHARED
    // mapping, so the change is visible to the reader.
    fn set_edge(path: &std::path::Path, offset: u64) {
        let mut f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.seek(SeekFrom::Start(offset)).unwrap();
        f.write_all(&[1u8]).unwrap();
        f.flush().unwrap();
    }

    // Write one edge's per-exec hit COUNT into the #420 count map the way the
    // driver's saturating increment would. Shares the page cache with the
    // tracker's MAP_SHARED count mapping, so the value is visible to the reader.
    fn set_count(path: &std::path::Path, offset: u64, value: u8) {
        let mut f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.seek(SeekFrom::Start(offset)).unwrap();
        f.write_all(&[value]).unwrap();
        f.flush().unwrap();
    }

    #[test]
    fn coverage_tracker_keeps_only_coverage_increasing_inputs() {
        let dir = crate::test_support::TestDir::new("cov");
        let path = dir.join("coverage.shm");
        let env = vec![("BHF_COV_SHM".to_owned(), path.display().to_string())];

        let mut tracker = CoverageTracker::new(&env).expect("tracker maps the bitmap");
        // Empty bitmap: the first exec hit nothing new.
        assert_eq!(tracker.input_increased_coverage(), 0);

        // An input that lights two fresh edges is interesting (retained).
        set_edge(&path, 10);
        set_edge(&path, 4096);
        assert_eq!(tracker.input_increased_coverage(), 2);

        // A redundant input (no new edges) is not retained.
        assert_eq!(tracker.input_increased_coverage(), 0);

        // One more new edge is interesting again.
        set_edge(&path, BHF_COV_BITS as u64 - 1);
        assert_eq!(tracker.input_increased_coverage(), 1);
        assert_eq!(tracker.input_increased_coverage(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // #420: the engine-side bucket table MUST stay identical to the canonical
    // `count_to_bucket` in crates/fuzz_engine/builtin/src/coverage.rs. This guards
    // against the two drifting apart (the layout-sync hazard called out in #420).
    #[test]
    fn count_to_bucket_matches_afl_log_buckets() {
        assert_eq!(count_to_bucket(0), 0);
        assert_eq!(count_to_bucket(1), 0);
        assert_eq!(count_to_bucket(2), 1);
        assert_eq!(count_to_bucket(3), 2);
        assert_eq!(count_to_bucket(4), 3);
        assert_eq!(count_to_bucket(7), 3);
        assert_eq!(count_to_bucket(8), 4);
        assert_eq!(count_to_bucket(15), 4);
        assert_eq!(count_to_bucket(16), 5);
        assert_eq!(count_to_bucket(31), 5);
        assert_eq!(count_to_bucket(32), 6);
        assert_eq!(count_to_bucket(127), 6);
        assert_eq!(count_to_bucket(128), 7);
        assert_eq!(count_to_bucket(255), 7);
        // Adjacent counts straddling a boundary differ; within a bucket match.
        assert_ne!(count_to_bucket(7), count_to_bucket(8));
        assert_eq!(count_to_bucket(5), count_to_bucket(6));
    }

    // #420 AC2: a per-input hit-count crossing into a higher AFL bucket
    // (1->2->4->8 ...) registers as novelty exactly once; noise WITHIN a bucket
    // (4->5->6->7, all bucket 3) does not. This is the loop/recursion-depth signal
    // edge-presence cannot see. The engine zeroes the count map before each exec
    // (modelled by `zero_counts`), so each call observes one exec's counts.
    #[test]
    fn coverage_tracker_buckets_register_transitions_not_within_bucket_noise() {
        let dir = crate::test_support::TestDir::new("cov-cnt");
        let cov = dir.join("coverage.shm");
        let cnt = dir.join("coverage_cnt.shm");
        let env = vec![
            ("BHF_COV_SHM".to_owned(), cov.display().to_string()),
            ("BHF_COV_CNT_SHM".to_owned(), cnt.display().to_string()),
        ];
        let mut tracker = CoverageTracker::new(&env).expect("tracker maps both maps");
        let edge = 100u64; // arbitrary instrumented edge

        // The engine zeroes the count map, the harness writes this exec's counts,
        // the engine reads bucket novelty. First time edge 100 reaches each bucket
        // is novel; a repeat within the same bucket is not.
        let exec = |tracker: &mut CoverageTracker, count: u8| -> usize {
            tracker.zero_counts();
            set_count(&cnt, edge, count);
            tracker.input_grew_buckets()
        };

        // Bucket transitions 1->2->4->8 each register exactly once.
        assert!(
            exec(&mut tracker, 1) > 0,
            "count 1 (bucket 0) is novel the first time"
        );
        assert!(
            exec(&mut tracker, 1) == 0,
            "count 1 again is within-bucket noise"
        );
        assert!(exec(&mut tracker, 2) > 0, "count 2 crosses into bucket 1");
        assert!(
            exec(&mut tracker, 2) == 0,
            "count 2 again is within-bucket noise"
        );
        assert!(exec(&mut tracker, 4) > 0, "count 4 crosses into bucket 3");
        // Noise WITHIN bucket 3 (4..=7) does not register.
        assert_eq!(exec(&mut tracker, 5), 0, "count 5 stays in bucket 3");
        assert_eq!(exec(&mut tracker, 6), 0, "count 6 stays in bucket 3");
        assert_eq!(exec(&mut tracker, 7), 0, "count 7 stays in bucket 3");
        // Crossing into bucket 4 (8..=15) registers again.
        assert!(exec(&mut tracker, 8) > 0, "count 8 crosses into bucket 4");
        assert_eq!(exec(&mut tracker, 15), 0, "count 15 stays in bucket 4");
        // A deeper loop crossing into the top bucket registers once more.
        assert!(
            exec(&mut tracker, 200) > 0,
            "count 200 crosses into bucket 7"
        );
        assert_eq!(exec(&mut tracker, 255), 0, "count 255 stays in bucket 7");

        // Re-visiting a LOWER, already-seen bucket is not novel (virgin is a
        // per-edge bitmask of every bucket ever seen, not a high-water mark only).
        assert!(
            exec(&mut tracker, 1) == 0,
            "bucket 0 was already seen for this edge"
        );

        // A DIFFERENT edge is tracked independently: its first hit is novel.
        tracker.zero_counts();
        set_count(&cnt, 7777, 9); // edge 7777, bucket 4
        assert!(
            tracker.input_grew_buckets() > 0,
            "a fresh edge's first bucket is novel regardless of other edges"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // Write one compare site's per-exec MAX leading-byte-match count into the #421
    // comparison-progress map the way the driver's `max`-write would. Shares the
    // page cache with the tracker's MAP_SHARED progress mapping.
    fn set_progress(path: &std::path::Path, site: u64, value: u8) {
        let mut f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.seek(SeekFrom::Start(site)).unwrap();
        f.write_all(&[value]).unwrap();
        f.flush().unwrap();
    }

    // #421 laf-intel: an input that matches MORE leading bytes of a compare than
    // any prior input (a higher progress LEVEL at that site) registers as novel
    // coverage exactly once — the gradient that lets the fuzzer hill-climb a
    // multi-byte gate one byte at a time. A re-seen level is not novel; progress 0
    // (no leading-byte match) never registers; levels cap at 7; sites are tracked
    // independently. The engine zeroes the progress map before each exec (modelled
    // by `zero_progress`), so each call observes one exec's per-site progress.
    #[test]
    fn coverage_tracker_progress_registers_new_leading_match_levels() {
        let dir = crate::test_support::TestDir::new("cmpp");
        let cov = dir.join("coverage.shm");
        let cmpp = dir.join("cmp_progress.shm");
        let env = vec![
            ("BHF_COV_SHM".to_owned(), cov.display().to_string()),
            (
                "BHF_CMP_PROGRESS_SHM".to_owned(),
                cmpp.display().to_string(),
            ),
        ];
        let mut tracker = CoverageTracker::new(&env).expect("tracker maps progress map");
        let site = 100u64; // arbitrary hashed compare site

        let exec = |tracker: &mut CoverageTracker, progress: u8| -> usize {
            tracker.zero_progress();
            set_progress(&cmpp, site, progress);
            tracker.input_advanced_comparisons()
        };

        // Matching one leading byte is novel the first time; the same level again
        // is not (no new gradient).
        assert!(
            exec(&mut tracker, 1) > 0,
            "first 1-byte leading match is novel"
        );
        assert!(
            exec(&mut tracker, 1) == 0,
            "same match level again is not novel"
        );
        // Matching deeper (2, then 3 leading bytes) each registers once.
        assert!(exec(&mut tracker, 2) > 0, "2-byte leading match is novel");
        assert!(exec(&mut tracker, 3) > 0, "3-byte leading match is novel");
        // Re-seeing an intermediate level already observed is not novel.
        assert_eq!(exec(&mut tracker, 2), 0, "level 2 was already seen");
        // Progress 0 (no leading-byte match) is indistinguishable from "site not
        // hit" and never registers novelty.
        assert!(
            exec(&mut tracker, 0) == 0,
            "zero leading-byte match is not progress"
        );
        // Levels saturate at 7 (an 8-byte compare matching all 8 passes the gate
        // and lights a real edge): 7 is novel once, and a >7 value maps to 7.
        assert!(exec(&mut tracker, 7) > 0, "level 7 is novel the first time");
        assert_eq!(exec(&mut tracker, 8), 0, "level >7 caps to 7, already seen");

        // A DIFFERENT compare site is tracked independently.
        tracker.zero_progress();
        set_progress(&cmpp, 7777, 4);
        assert!(
            tracker.input_advanced_comparisons() > 0,
            "a fresh site's first leading match is novel regardless of other sites"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The stack-depth buckets: four per doubling, so depth a quarter beyond
    /// a bucket is the next one, and nothing below that is.
    #[test]
    fn stack_depth_buckets_split_each_doubling_in_four() {
        assert_eq!(stack_depth_bucket(0), 0);
        let buckets: Vec<u32> = [1, 2, 3, 4, 5, 6, 7, 8].map(stack_depth_bucket).to_vec();
        assert_eq!(buckets, [1, 5, 7, 9, 10, 11, 12, 13]);
        assert_eq!(stack_depth_bucket(4096), stack_depth_bucket(5119));
        assert_eq!(stack_depth_bucket(5120), stack_depth_bucket(4096) + 1);
        assert_eq!(stack_depth_bucket(8192), stack_depth_bucket(4096) + 4);
        assert_eq!(stack_depth_bucket(u64::MAX), 1 + 63 * 4 + 3);
    }

    // #220: an input that recursed deeper than every input before it is novel
    // with no new edge, once per bucket; a shallower or equal one is not.
    #[test]
    fn a_deeper_stack_on_the_same_edges_is_novelty() {
        let dir = crate::test_support::TestDir::new("stack-depth");
        let cov = dir.join("coverage.shm");
        let stack = dir.join("stack.shm");
        let env = vec![
            ("BHF_COV_SHM".to_owned(), cov.display().to_string()),
            (
                "BHF_STACK_DEPTH_SHM".to_owned(),
                stack.display().to_string(),
            ),
        ];
        let mut tracker = CoverageTracker::new(&env).expect("tracker maps the stack word");
        set_edge(&cov, 42);
        assert_eq!(tracker.input_increased_coverage(), 1);

        let exec = |tracker: &mut CoverageTracker, depth: u64| -> CoverageNovelty {
            tracker.zero_stack();
            assert_eq!(std::fs::read(&stack).unwrap(), [0; 8]);
            std::fs::write(&stack, depth.to_ne_bytes()).unwrap();
            CoverageNovelty {
                new_edges: tracker.input_increased_coverage(),
                deeper_stack: tracker.input_deepened_stack(),
                ..CoverageNovelty::default()
            }
        };
        let first = exec(&mut tracker, 4096);
        assert_eq!((first.new_edges, first.deeper_stack), (0, 1));
        assert!(first.made_progress());
        assert!(!exec(&mut tracker, 4096).made_progress());
        assert!(
            !exec(&mut tracker, 5000).made_progress(),
            "within the bucket"
        );
        assert!(!exec(&mut tracker, 512).made_progress(), "shallower");
        assert!(exec(&mut tracker, 5120).made_progress());
        let deep = exec(&mut tracker, 1 << 20);
        assert_eq!(deep.deeper_stack, 1);
        assert!(deep.scheduling_energy() > 1);
    }

    /// Without the stack word (a harness built before it, or a lane that
    /// does not arm it) the channel reports nothing.
    #[test]
    fn coverage_tracker_without_stack_word_is_inert() {
        let dir = crate::test_support::TestDir::new("stack-absent");
        let cov = dir.join("coverage.shm");
        let env = vec![("BHF_COV_SHM".to_owned(), cov.display().to_string())];
        let mut tracker = CoverageTracker::new(&env).expect("tracker maps the bitmap");
        tracker.zero_stack();
        assert_eq!(tracker.input_deepened_stack(), 0);
    }

    // #421: the comparison-progress channel is inert (always false) when its map
    // is absent (no BHF_CMP_PROGRESS_SHM — the flag is off, or the Ada
    // trace-pc path), rather than fabricating novelty.
    #[test]
    fn coverage_tracker_without_progress_map_is_inert() {
        let dir = crate::test_support::TestDir::new("cmpp-absent");
        let cov = dir.join("coverage.shm");
        // No BHF_CMP_PROGRESS_SHM: the progress channel must stay inert.
        let env = vec![("BHF_COV_SHM".to_owned(), cov.display().to_string())];
        let mut tracker = CoverageTracker::new(&env).expect("tracker maps the bitmap");

        assert_eq!(tracker.input_advanced_comparisons(), 0);
        tracker.zero_progress(); // no panic, no effect
        assert_eq!(tracker.input_advanced_comparisons(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // #420: edge-PRESENCE behavior is byte-for-byte unchanged when the count map
    // is absent (no BHF_COV_CNT_SHM — the Ada trace-pc path), and the bucket
    // channel is inert (always false) rather than fabricating novelty.
    #[test]
    fn coverage_tracker_without_count_map_is_presence_only() {
        let dir = crate::test_support::TestDir::new("cov-nocnt");
        let cov = dir.join("coverage.shm");
        // No BHF_COV_CNT_SHM: the bucket channel must stay inert.
        let env = vec![("BHF_COV_SHM".to_owned(), cov.display().to_string())];
        let mut tracker = CoverageTracker::new(&env).expect("tracker maps the bitmap");

        // Bucket channel is a no-op without a count map.
        assert_eq!(tracker.input_grew_buckets(), 0);
        tracker.zero_counts(); // no panic, no effect

        // Presence still works exactly as before.
        set_edge(&cov, 42);
        assert_eq!(tracker.input_increased_coverage(), 1);
        assert_eq!(tracker.input_increased_coverage(), 0);
        // Still inert after presence growth.
        assert_eq!(tracker.input_grew_buckets(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod frame_tests {
    use super::write_input_frame;

    #[test]
    fn write_input_frame_prepends_little_endian_length() {
        let mut out = Vec::new();
        write_input_frame(&mut out, b"abc").unwrap();
        assert_eq!(out, vec![3, 0, 0, 0, b'a', b'b', b'c']);
    }

    #[test]
    fn write_input_frame_handles_empty() {
        let mut out = Vec::new();
        write_input_frame(&mut out, b"").unwrap();
        assert_eq!(out, vec![0, 0, 0, 0]);
    }
}

#[cfg(test)]
mod parse_sanitizer_args_tests {
    use super::parse_sanitizer_args;
    use multicore_fuzz::{Sanitizer, SanitizerSelection};

    fn parse(values: &[&str]) -> Result<SanitizerSelection, String> {
        parse_sanitizer_args(&values.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn empty_is_default() {
        assert_eq!(parse(&[]).unwrap(), SanitizerSelection::Default);
    }

    #[test]
    fn none_is_standalone_none() {
        assert_eq!(parse(&["none"]).unwrap(), SanitizerSelection::None);
        assert_eq!(parse(&["NONE"]).unwrap(), SanitizerSelection::None);
    }

    /// #297: `cfi` is `bhf auto`'s corpus replay, and `bhf fuzz` says so.
    #[test]
    fn cfi_is_refused_with_the_auto_lane_named() {
        let error = parse(&["asan", "cfi"]).unwrap_err();
        assert!(error.contains("bhf auto --sanitizers cfi"), "{error}");
    }

    /// #333: HWASan needs an AArch64 host; on any other the selection is
    /// refused with the reason and what to use instead.
    #[test]
    fn hwasan_is_refused_off_aarch64_and_never_beside_asan() {
        use super::hwasan_host_check;
        let error =
            hwasan_host_check(&[Sanitizer::Hwasan, Sanitizer::Ubsan], "x86_64").unwrap_err();
        assert!(error.contains("needs an AArch64 host"), "{error}");
        assert!(error.contains("x86_64 does not"), "{error}");
        assert!(error.contains("--sanitizers asan"), "{error}");
        assert_eq!(hwasan_host_check(&[Sanitizer::Hwasan], "aarch64"), Ok(()));
        assert_eq!(hwasan_host_check(&[Sanitizer::Asan], "x86_64"), Ok(()));
        if std::env::consts::ARCH == "aarch64" {
            assert_eq!(
                parse(&["hwaddress", "ubsan"]).unwrap(),
                SanitizerSelection::Set(vec![Sanitizer::Hwasan, Sanitizer::Ubsan])
            );
            let error = parse(&["hwasan", "asan"]).unwrap_err();
            assert!(
                error.contains("hwasan cannot be combined with asan"),
                "{error}"
            );
        } else {
            let error = parse(&["hwaddress"]).unwrap_err();
            assert!(error.contains("needs an AArch64 host"), "{error}");
        }
    }

    #[test]
    fn none_mixed_with_a_sanitizer_is_an_error() {
        // `none` is contradictory with a real sanitizer — reject, don't silently
        // pick one (#434).
        assert!(parse(&["none", "asan"]).is_err());
        assert!(parse(&["asan", "none"]).is_err());
    }

    #[test]
    fn set_dedups_and_preserves_order() {
        assert_eq!(
            parse(&["asan", "ubsan", "asan"]).unwrap(),
            SanitizerSelection::Set(vec![Sanitizer::Asan, Sanitizer::Ubsan])
        );
    }

    #[test]
    fn unknown_name_is_an_error_mentioning_none() {
        let err = parse(&["garbage"]).unwrap_err();
        assert!(err.contains("none"), "help should list `none`: {err}");
    }

    #[test]
    fn none_arms_no_runtime_env_and_overrides_build() {
        let sel = parse(&["none"]).unwrap();
        assert!(sel.runtime_set().is_empty());
        assert!(sel.overrides_build());
    }
}

#[cfg(test)]
mod framed_input_tests {
    use super::{write_hex_frame, write_input_frame, FRAMED_INPUT_CAP};

    /// A hex frame carries the bytes a text-mode reader would translate (CR
    /// LF, Ctrl-Z, NUL) as digits only, after the length in eight.
    #[test]
    fn a_hex_frame_spells_every_byte_in_digits() {
        let mut out: Vec<u8> = Vec::new();
        write_hex_frame(&mut out, b"\r\n\x1a\x00\xffA").unwrap();
        assert_eq!(out, b"000000060d0a1a00ff41");
        let big = vec![0x1au8; FRAMED_INPUT_CAP + 1];
        out.clear();
        write_hex_frame(&mut out, &big).unwrap();
        assert_eq!(
            &out[..8],
            b"00100000",
            "the length is clamped as a binary frame's is"
        );
        assert_eq!(out.len(), 8 + 2 * FRAMED_INPUT_CAP);
    }

    #[test]
    fn frame_is_clamped_to_the_harness_buffer_so_the_protocol_stays_aligned() {
        // A > 1 MiB input must be sent as a cap-sized frame: declared length ==
        // bytes written == FRAMED_INPUT_CAP, so the harness reads the whole frame
        // and the next frame's length prefix is not misread from a leftover tail.
        let big = vec![0xABu8; FRAMED_INPUT_CAP + 4096];
        let mut out: Vec<u8> = Vec::new();
        write_input_frame(&mut out, &big).unwrap();
        let declared = u32::from_le_bytes([out[0], out[1], out[2], out[3]]) as usize;
        assert_eq!(
            declared, FRAMED_INPUT_CAP,
            "declared length must be clamped"
        );
        assert_eq!(
            out.len(),
            4 + FRAMED_INPUT_CAP,
            "exactly cap bytes follow the length prefix — no orphaned tail"
        );
    }

    #[test]
    fn a_normal_input_is_framed_verbatim() {
        let input = b"hello world";
        let mut out: Vec<u8> = Vec::new();
        write_input_frame(&mut out, input).unwrap();
        let declared = u32::from_le_bytes([out[0], out[1], out[2], out[3]]) as usize;
        assert_eq!(declared, input.len());
        assert_eq!(&out[4..], input);
    }
}

#[cfg(test)]
mod fuzz_child_env_tests {
    use super::apply_fuzz_child_env_overrides;

    #[test]
    fn neutralizes_debuginfod_for_every_fuzz_child() {
        // A fuzz child must never make a network debuginfo fetch in the hot loop:
        // ASan's crash symbolizer would consult the system debuginfod server and
        // a crash-heavy target blows past the per-target wall cap (182s regression).
        let mut env = vec![("BHF_COV_SHM".to_owned(), "/tmp/x".to_owned())];
        apply_fuzz_child_env_overrides(&mut env);
        assert_eq!(
            env.iter().find(|(k, _)| k == "DEBUGINFOD_URLS"),
            Some(&("DEBUGINFOD_URLS".to_owned(), String::new()))
        );
    }

    #[test]
    fn respects_an_explicit_caller_debuginfod_value() {
        let mut env = vec![("DEBUGINFOD_URLS".to_owned(), "https://example/".to_owned())];
        apply_fuzz_child_env_overrides(&mut env);
        // Exactly one entry, unchanged — no silent override of an explicit value.
        let hits: Vec<_> = env.iter().filter(|(k, _)| k == "DEBUGINFOD_URLS").collect();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, "https://example/");
    }

    #[test]
    fn arms_ubsan_halt_on_error_for_the_default_builtin_child() {
        // The default C/C++ harness is ASan+UBSan-built but UBSan is print-and-
        // continue; without arming halt_on_error every UBSan-class fault exits 0
        // and is silently missed. Every builtin child must get the halt options.
        let mut env: Vec<(String, String)> = Vec::new();
        apply_fuzz_child_env_overrides(&mut env);
        for key in ["ASAN_OPTIONS", "UBSAN_OPTIONS"] {
            let value = env
                .iter()
                .find(|(k, _)| k == key)
                .unwrap_or_else(|| panic!("{key} must be armed"));
            assert!(
                value.1.contains("halt_on_error=1") && value.1.contains("abort_on_error=1"),
                "{key} must halt+abort on a sanitizer report: {}",
                value.1
            );
            // ...but NOT symbolize=0. AFL++ needs that on its own child; setting
            // it here stripped file:line from every builtin child's report, and
            // file:line is what joins a crash to the static finding at the same
            // line, so fuzz_confirmed silently became fuzz_exercised. The
            // child turns it on explicitly instead.
            assert!(
                !value.1.contains("symbolize=0") && value.1.contains("symbolize=1"),
                "{key} must leave symbolization on for the fuzz-confirmation join: {}",
                value.1
            );
        }
    }

    #[test]
    fn arms_ubsan_stack_traces_and_check_names_for_the_default_builtin_child() {
        // Without print_stacktrace=1 a UBSan report has no frames: no function
        // name for the sink and nothing but rule|kind for its identity.
        // report_error_type=1 makes the SUMMARY name the failed check.
        let mut env: Vec<(String, String)> = Vec::new();
        apply_fuzz_child_env_overrides(&mut env);
        let value = |key: &str| {
            env.iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        let ubsan = value("UBSAN_OPTIONS");
        for key in [
            "print_stacktrace=1",
            "report_error_type=1",
            "halt_on_error=1",
        ] {
            assert!(ubsan.contains(key), "UBSAN_OPTIONS lacks {key}: {ubsan}");
        }
        // They are UBSan flags; ASAN_OPTIONS keeps only its own keys.
        assert!(!value("ASAN_OPTIONS").contains("print_stacktrace"));
    }

    #[test]
    fn does_not_override_an_explicit_sanitizer_selection() {
        // When `--sanitizers` / `--env` already threaded a value into the child
        // env (e.g. an MSan/TSan build or operator suppressions), leave it alone.
        let mut env = vec![("UBSAN_OPTIONS".to_owned(), "print_stacktrace=1".to_owned())];
        apply_fuzz_child_env_overrides(&mut env);
        let hits: Vec<_> = env.iter().filter(|(k, _)| k == "UBSAN_OPTIONS").collect();
        assert_eq!(hits.len(), 1, "no duplicate UBSAN_OPTIONS");
        assert_eq!(hits[0].1, "print_stacktrace=1", "explicit value preserved");
    }

    /// A reproducing child gets the shared required keys after the inherited
    /// value, which is kept as it was.
    #[test]
    fn the_child_env_is_the_shared_required_keys_after_the_inherited_value() {
        use corpus::sanitizer_options::{asan_required, ubsan_required};
        let env = super::sanitizer_child_env_with(
            Some("verbosity=0:symbolize=0"),
            Some("suppressions=/dev/null"),
            false,
            false,
        );
        assert_eq!(
            env,
            vec![
                (
                    "ASAN_OPTIONS".to_owned(),
                    format!("verbosity=0:symbolize=0:{}", asan_required(false, false))
                ),
                (
                    "UBSAN_OPTIONS".to_owned(),
                    format!("suppressions=/dev/null:{}", ubsan_required(false))
                ),
            ]
        );
        assert_eq!(
            env,
            [
                (
                    "ASAN_OPTIONS".to_owned(),
                    "verbosity=0:symbolize=0:abort_on_error=1:halt_on_error=1:symbolize=1"
                        .to_owned()
                ),
                (
                    "UBSAN_OPTIONS".to_owned(),
                    "suppressions=/dev/null:abort_on_error=1:halt_on_error=1:symbolize=1:\
                     print_stacktrace=1:report_error_type=1"
                        .to_owned()
                ),
            ]
        );
        let leak = super::sanitizer_child_env_with(None, None, true, false);
        assert_eq!(leak[0].1, asan_required(true, false));
        assert_eq!(
            leak[0].1,
            "abort_on_error=1:halt_on_error=1:symbolize=1:detect_leaks=1"
        );
    }

    /// An emulated child's options name each of bhf's keys once:
    /// `abort_on_error=0` in place of `abort_on_error=1`, not after it.
    #[test]
    fn an_emulated_child_names_each_bhf_key_once() {
        let env = super::sanitizer_child_env_with(None, None, false, true);
        let value = |key: &str| {
            env.iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.clone())
                .unwrap()
        };
        assert_eq!(
            value("ASAN_OPTIONS"),
            "abort_on_error=0:halt_on_error=1:symbolize=1"
        );
        let ubsan = value("UBSAN_OPTIONS");
        let aborts: Vec<&str> = ubsan
            .split(':')
            .filter(|item| item.starts_with("abort_on_error="))
            .collect();
        assert_eq!(aborts, ["abort_on_error=0"], "{ubsan}");
    }
}

#[cfg(test)]
mod auto_path_tests {

    /// The reported false positive, pinned.
    ///
    /// bhf unlinks its own `testcase.bin` while a target is under test. The
    /// sink oracles carry no frame, so that call was billed to whatever was being
    /// fuzzed — producing "attacker input can delete a file" against a function
    /// whose only call is `statvfs`, which cannot appear in BHF-440's API list at
    /// all. A relative subject must be resolved against the fuzz child's CWD
    /// before it can be recognised as bhf's own housekeeping.
    #[test]
    fn bhf_deleting_its_own_testcase_is_not_a_target_finding() {
        use crate::auto::runtrace::{ConfirmedSink, SinkClass};
        let work = std::path::Path::new("/tmp/bhf-work");
        let own_testcase = ConfirmedSink {
            class: SinkClass::DestructivePath,
            api: "unlink".to_owned(),
            // The path from the reported finding.
            subject: "/tmp/bhf_in032dWa".to_owned(),
            taint_offset: 0,
            input: vec![b'a'],
        };
        assert!(
            sink_subject_is_bhf_housekeeping(&own_testcase, work),
            "unlinking the temp file bhf itself created for the input is \
             housekeeping, not a target finding"
        );

        // A target deleting an attacker-named file OUTSIDE the work dir is the
        // real BHF-440 and must survive.
        let real = ConfirmedSink {
            subject: "/etc/passwd".to_owned(),
            ..own_testcase.clone()
        };
        assert!(!sink_subject_is_bhf_housekeeping(&real, work));

        // So must an escape from the scratch directory — suppressing traversal
        // would trade this false positive for a false negative.
        let traversal = ConfirmedSink {
            subject: "../../etc/passwd".to_owned(),
            ..own_testcase.clone()
        };
        assert!(!sink_subject_is_bhf_housekeeping(&traversal, work));

        // Non-filesystem sinks are never housekeeping.
        // A target deleting a file in its own scratch directory still reports:
        // suppressing by LOCATION would hide a real BHF-440.
        let in_scratch = ConfirmedSink {
            // Deliberately NOT under `/tmp/bhf*`: that whole subtree is bhf's
            // own temp namespace and IS housekeeping. This case is about a
            // scratch dir that belongs to the target.
            subject: "/tmp/scan-work/fuzz_scratch/victim.txt".to_owned(),
            ..own_testcase.clone()
        };
        assert!(!sink_subject_is_bhf_housekeeping(&in_scratch, work));

        let exec = ConfirmedSink {
            class: SinkClass::ProcessExec,
            subject: "/tmp/bhf_in032dWa".to_owned(),
            ..own_testcase
        };
        assert!(!sink_subject_is_bhf_housekeeping(&exec, work));
    }
    use super::*;
    use std::fs;
    use std::io::Write;

    fn tmpdir() -> crate::test_support::TestDir {
        crate::test_support::TestDir::new("find")
    }

    fn sanitizer_report(rule_id: &'static str, frames: Vec<&str>) -> corpus::SanitizerReport {
        corpus::SanitizerReport {
            sanitizer: Some(corpus::Sanitizer::AddressSanitizer),
            kind: "heap-buffer-overflow".to_owned(),
            rule_id,
            stack: frames
                .into_iter()
                .map(|f| corpus::sanitizer::StackFrame {
                    function: f.to_owned(),
                    file: None,
                    line: None,
                })
                .collect(),
            message: "boom".to_owned(),
            ..Default::default()
        }
    }

    /// Report and consume in one step, as the loop does for a crash it does not
    /// need to confirm.
    fn sighted(dedup: &mut SanitizerClusterDedup, report: &corpus::SanitizerReport) -> bool {
        match dedup.first_sighting(report) {
            Some(key) => {
                dedup.consumed(key);
                true
            }
            None => false,
        }
    }

    #[test]
    fn sanitizer_cluster_dedup_emits_once_per_root_cause() {
        let mut dedup = SanitizerClusterDedup::new(Vec::new());
        // Same target frames, different scaffolding -> one cluster.
        let a1 = sanitizer_report(
            "BHF-201",
            vec!["real_parse", "real_dispatch", "LLVMFuzzerTestOneInput"],
        );
        let a2 = sanitizer_report("BHF-201", vec!["real_parse", "real_dispatch", "main"]);
        // Different target frame -> a second cluster.
        let b = sanitizer_report("BHF-201", vec!["other_fn", "LLVMFuzzerTestOneInput"]);

        assert!(sighted(&mut dedup, &a1));
        assert!(!sighted(&mut dedup, &a2));
        assert!(sighted(&mut dedup, &b));
        // Two clusters, three total hits: one later hit folded into `a`.
        let duplicates = dedup.duplicate_hits();
        assert_eq!(duplicates.len(), 1);
        assert_eq!(
            duplicates.get(&corpus::finding::sanitizer_dedupe_key(&a1)),
            Some(&1)
        );
    }

    /// An unsymbolized ASan report whose crash stack is `frames`.
    fn unsymbolized(frames: &[&str]) -> (corpus::SanitizerReport, String) {
        let mut stderr = "==9==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n\
                          WRITE of size 9 at 0x1 thread T0\n"
            .to_owned();
        for (index, frame) in frames.iter().enumerate() {
            stderr.push_str(&format!("    #{index} 0x55d0c3a1b2c4  (/w/main+{frame})\n"));
        }
        stderr.push_str("\nSUMMARY: AddressSanitizer: heap-buffer-overflow (/w/main+0x1)\n");
        (corpus::parse_sanitizer_report(&stderr).unwrap(), stderr)
    }

    #[test]
    fn a_crash_with_a_reported_signature_is_not_symbolized_again() {
        let mut dedup = SanitizerClusterDedup::new(Vec::new());
        let mut symbolization = InLoopSymbolization::default();
        let (first, first_stderr) = unsymbolized(&["0x12b1b2", "0x13f001"]);
        let InLoopCrash::Symbolize(signature) =
            symbolization.classify(&first, Some(&first_stderr), &mut dedup)
        else {
            panic!("a new signature is symbolized");
        };
        // Its symbolized re-run is reported under the root cause's key.
        let symbolized = sanitizer_report("BHF-201", vec!["copy_record", "bhf_run_one"]);
        let key = dedup.first_sighting(&symbolized).unwrap();
        dedup.consumed(key.clone());
        symbolization.symbolized(signature, key.clone());

        let (again, again_stderr) = unsymbolized(&["0x12b1b2", "0x13f001"]);
        assert_eq!(
            symbolization.classify(&again, Some(&again_stderr), &mut dedup),
            InLoopCrash::Duplicate
        );
        assert_eq!(dedup.duplicate_hits().get(&key), Some(&1));
        // Another call path is a new signature.
        let (other, other_stderr) = unsymbolized(&["0x12b1b2", "0x140aa0"]);
        assert!(matches!(
            symbolization.classify(&other, Some(&other_stderr), &mut dedup),
            InLoopCrash::Symbolize(_)
        ));
        // A symbolized report goes on as it is.
        assert_eq!(
            symbolization.classify(&symbolized, None, &mut dedup),
            InLoopCrash::AsIs
        );
    }

    #[test]
    fn a_signature_whose_rerun_never_crashes_is_given_up() {
        let mut dedup = SanitizerClusterDedup::new(Vec::new());
        let symbolization = InLoopSymbolization::default();
        let (report, stderr) = unsymbolized(&["0x4242"]);
        for _ in 0..MAX_UNCONFIRMED_SANITIZER_ATTEMPTS {
            let InLoopCrash::Symbolize(signature) =
                symbolization.classify(&report, Some(&stderr), &mut dedup)
            else {
                panic!("re-run until given up");
            };
            dedup.unconfirmed(signature);
        }
        assert_eq!(
            symbolization.classify(&report, Some(&stderr), &mut dedup),
            InLoopCrash::Duplicate
        );
    }

    #[test]
    fn the_loops_children_neither_symbolize_nor_abort() {
        let env = vec![
            (
                "ASAN_OPTIONS".to_owned(),
                "detect_leaks=1:symbolize=1".to_owned(),
            ),
            ("UBSAN_OPTIONS".to_owned(), "halt_on_error=1".to_owned()),
            ("BHF_COV_SHM".to_owned(), "/w/cov".to_owned()),
        ];
        let loop_env = in_loop_env(&env, false);
        assert_eq!(
            loop_env[0].1,
            "detect_leaks=1:symbolize=1:symbolize=0:abort_on_error=0"
        );
        assert_eq!(
            loop_env[1].1,
            "halt_on_error=1:symbolize=0:abort_on_error=0"
        );
        assert_eq!(loop_env[2], env[2]);
        // BHF_IN_LOOP_SYMBOLIZE=1 keeps the loop as it was.
        assert_eq!(in_loop_env(&env, true), env);
    }

    fn missing_return_at(line: u32) -> corpus::SanitizerReport {
        corpus::parse_sanitizer_report(&format!(
            "/src/widget/classify.c:{line}:5: runtime error: execution reached the end of a value-returning function without returning a value\n\
             SUMMARY: UndefinedBehaviorSanitizer: missing-return /src/widget/classify.c:{line}:5 \n"
        ))
        .unwrap()
    }

    /// A harness used to emit at most one stackless finding per rule for its
    /// whole run: every later, different UB site was a "duplicate".
    #[test]
    fn frameless_ubsan_reports_at_distinct_sites_are_each_reported() {
        let mut dedup = SanitizerClusterDedup::new(Vec::new());
        assert!(sighted(&mut dedup, &missing_return_at(3)));
        assert!(sighted(&mut dedup, &missing_return_at(9)));
        assert!(!sighted(&mut dedup, &missing_return_at(3)));
    }

    /// The key is consumed only by an emitted finding: a first hit that does not
    /// reproduce in a fresh process must not hide a later, reproducible one.
    #[test]
    fn a_crash_that_does_not_reproduce_does_not_consume_its_key() {
        let mut dedup = SanitizerClusterDedup::new(Vec::new());
        let report = missing_return_at(3);
        let key = dedup.first_sighting(&report).expect("first sighting");
        dedup.unconfirmed(key);
        let key = dedup
            .first_sighting(&report)
            .expect("still unreported after a failed confirmation");
        dedup.consumed(key);
        assert!(dedup.first_sighting(&report).is_none());
    }

    /// ...but a crash that never reproduces stops costing a fresh re-run per hit.
    #[test]
    fn a_crash_that_never_reproduces_stops_being_retried() {
        let mut dedup = SanitizerClusterDedup::new(Vec::new());
        let report = missing_return_at(3);
        for _ in 0..MAX_UNCONFIRMED_SANITIZER_ATTEMPTS {
            let key = dedup.first_sighting(&report).expect("retried");
            dedup.unconfirmed(key);
        }
        assert!(dedup.first_sighting(&report).is_none());
    }

    /// A root cause given up after failed confirmations was never reported, so
    /// its later hits are not duplicates of a finding.
    #[test]
    fn hits_of_a_root_cause_that_never_reproduced_are_not_duplicates() {
        let mut dedup = SanitizerClusterDedup::new(Vec::new());
        let report = missing_return_at(3);
        for _ in 0..MAX_UNCONFIRMED_SANITIZER_ATTEMPTS {
            let key = dedup.first_sighting(&report).expect("retried");
            dedup.unconfirmed(key);
        }
        assert!(dedup.first_sighting(&report).is_none());
        assert!(dedup.first_sighting(&report).is_none());
        assert!(
            dedup.duplicate_hits().is_empty(),
            "{:?}",
            dedup.duplicate_hits()
        );
        let key = corpus::finding::sanitizer_dedupe_key(&report);
        let tries = MAX_UNCONFIRMED_SANITIZER_ATTEMPTS as usize;
        assert_eq!(dedup.unreproduced_hits().get(&key), Some(&(tries + 2)));
        assert_eq!(dedup.skipped_unreproduced_hits(), 2);

        // A root cause still open after one failed confirmation is listed too.
        let other = missing_return_at(9);
        let key = dedup.first_sighting(&other).expect("first sighting");
        dedup.unconfirmed(key.clone());
        assert_eq!(dedup.unreproduced_hits().get(&key), Some(&1));
        // ...until a later hit reproduces and is reported.
        let key = dedup.first_sighting(&other).expect("still open");
        dedup.consumed(key.clone());
        assert_eq!(dedup.unreproduced_hits().get(&key), None);
    }

    /// AFL++ crash ingestion keys on the same root-cause key as the builtin
    /// loop; its old `rule_id|frames` key made every stackless report of a rule
    /// one crash.
    #[test]
    fn afl_ingestion_keeps_distinct_frameless_sites() {
        let mut dedup = SanitizerClusterDedup::new(Vec::new());
        assert!(afl_crash_is_new(&mut dedup, &missing_return_at(3)));
        assert!(afl_crash_is_new(&mut dedup, &missing_return_at(9)));
        assert!(!afl_crash_is_new(&mut dedup, &missing_return_at(9)));
        assert_eq!(dedup.duplicate_hits().values().sum::<usize>(), 1);
    }

    #[test]
    #[cfg(unix)]
    fn sanitizer_crash_reproduces_true_for_crashing_false_for_clean() {
        use std::os::unix::fs::PermissionsExt;
        let work = tmpdir();

        // A fake C harness that reports an ASan heap-buffer-overflow (rule_id
        // BHF-201) on every input and exits non-zero — a reproducing crash.
        let crashing = work.join("crashing");
        fs::write(
            &crashing,
            "#!/bin/sh\n>&2 echo 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1'\n\
             >&2 echo '    #0 0x1 in real_parse /src/p.c:9'\nexit 1\n",
        )
        .unwrap();
        fs::set_permissions(&crashing, fs::Permissions::from_mode(0o755)).unwrap();

        // A clean harness that never crashes.
        let clean = work.join("clean");
        fs::write(&clean, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&clean, fs::Permissions::from_mode(0o755)).unwrap();

        let report = sanitizer_report("BHF-201", vec!["real_parse"]);

        let crashing_runner = replay_min::HarnessRunner::direct(crashing);
        assert!(sanitizer_crash_reproduces(
            &crashing_runner,
            &work,
            b"x",
            &report,
            &[],
            Duration::from_secs(5),
            0,
            None,
        ));

        let clean_runner = replay_min::HarnessRunner::direct(clean);
        assert!(!sanitizer_crash_reproduces(
            &clean_runner,
            &work,
            b"x",
            &report,
            &[],
            Duration::from_secs(5),
            0,
            None,
        ));
    }

    /// The fresh-process confirmation is a reproduction only when the re-run
    /// crashes at the same sink, not merely with the same rule.
    #[test]
    #[cfg(unix)]
    fn sanitizer_crash_reproduces_requires_the_same_sink() {
        use std::os::unix::fs::PermissionsExt;
        let work = tmpdir();
        let elsewhere = work.join("elsewhere");
        fs::write(
            &elsewhere,
            "#!/bin/sh\n>&2 echo 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1'\n\
             >&2 echo '    #0 0x1 in other_parse /src/p.c:30'\nexit 1\n",
        )
        .unwrap();
        fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o755)).unwrap();
        let report = sanitizer_report("BHF-201", vec!["real_parse"]);
        assert!(!sanitizer_crash_reproduces(
            &replay_min::HarnessRunner::direct(elsewhere),
            &work,
            b"x",
            &report,
            &[],
            Duration::from_secs(5),
            0,
            None,
        ));
    }

    /// gcc's UBSan report of a store at `fill` (record.c:15).
    fn object_size_report() -> corpus::SanitizerReport {
        corpus::parse_sanitizer_report(
            "/src/record.c:15:5: runtime error: store to address 0x602000000014 with insufficient space for an object of type 'char'\n\
             \x20   #0 0x1 in fill /src/record.c:15:5\n\
             \x20   #1 0x2 in LLVMFuzzerTestOneInput /src/h.c:20:3\n\
             SUMMARY: UndefinedBehaviorSanitizer: insufficient-object-size /src/record.c:15:5\n",
        )
        .expect("ubsan report")
    }

    /// ASan's report of the store [`object_size_report`] reports, at `function`,
    /// and the stderr it came in.
    fn asan_store_at(function: &str) -> (Option<corpus::SanitizerReport>, Option<String>) {
        let stderr = format!(
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014 at pc 0x1 bp 0x2 sp 0x3\n\
             WRITE of size 1 at 0x602000000014 thread T0\n\
             \x20   #0 0x1 in {function} /src/record.c:15:5\n\
             \x20   #1 0x2 in LLVMFuzzerTestOneInput /src/h.c:20:3\n\
             SUMMARY: AddressSanitizer: heap-buffer-overflow /src/record.c:15:5 in {function}\n"
        );
        (corpus::parse_sanitizer_report(&stderr), Some(stderr))
    }

    /// Once the pass's time is spent the input is not re-run, and the finding
    /// records that UBSan's report stands for that reason. Before then the
    /// re-run gets what is left of the pass, at most the per-input timeout.
    #[test]
    fn an_expired_pass_deadline_skips_the_object_size_re_run_and_records_why() {
        let work = tmpdir();
        let report = object_size_report();
        let reruns = std::cell::Cell::new(0);
        let opinion = object_size_second_opinion(
            &work,
            &report,
            &[],
            Duration::from_secs(5),
            Some(Instant::now()),
            |_, _| {
                reruns.set(reruns.get() + 1);
                Ok(asan_store_at("fill"))
            },
        )
        .expect("an object-size report gets a second opinion");
        assert_eq!(reruns.get(), 0, "no re-run once the pass's time is spent");
        assert!(opinion.asan.is_none(), "{opinion:?}");

        let id = "F-0000-0badc0de";
        let dir = corpus::layout::finding_dir(&work, id);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("finding.json"),
            r#"{"id": "F-0000-0badc0de", "rule_id": "BHF-227"}"#,
        )
        .unwrap();
        opinion.record(&work, id, "object-size-key");
        let record: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("finding.json")).unwrap()).unwrap();
        assert_eq!(record["rule_id"], "BHF-227", "{record:#}");
        let recorded = &record["sanitizer_second_opinion"];
        assert_eq!(recorded["check"], "object-size", "{record:#}");
        assert_eq!(recorded["used"], "ubsan", "{record:#}");
        assert!(
            recorded["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("time ran out")),
            "{record:#}"
        );
        assert!(recorded.get("replaced_cluster_key").is_none(), "{record:#}");

        for (per_input, left, bound) in [
            (
                Duration::from_secs(30),
                Duration::from_secs(2),
                Duration::from_secs(2),
            ),
            (
                Duration::from_secs(1),
                Duration::from_secs(60),
                Duration::from_secs(1),
            ),
        ] {
            let mut given = None;
            object_size_second_opinion(
                &work,
                &report,
                &[],
                per_input,
                Some(Instant::now() + left),
                |env, timeout| {
                    given = Some(timeout);
                    assert!(
                        env.iter().any(|(key, value)| key == "UBSAN_OPTIONS"
                            && value.contains("bhf-object-size.supp")),
                        "{env:?}"
                    );
                    Ok((None, None))
                },
            );
            let given = given.expect("the input is re-run while time is left");
            assert!(
                given <= bound && given > bound / 2,
                "{given:?} for {per_input:?}/{left:?}"
            );
        }
    }

    /// The report a finding carries after the object-size re-run, and the
    /// reason it records: ASan's of the same access, else UBSan's, saying what
    /// the re-run showed.
    #[test]
    fn the_object_size_second_opinion_names_the_report_it_keeps_and_why() {
        type Rerun<'a> =
            &'a dyn Fn(
                Duration,
            )
                -> Result<(Option<corpus::SanitizerReport>, Option<String>), String>;
        let work = tmpdir();
        let report = object_size_report();
        let opinion = |rerun: Rerun| {
            object_size_second_opinion(
                &work,
                &report,
                &[],
                Duration::from_millis(50),
                None,
                |_, timeout| rerun(timeout),
            )
            .expect("an object-size report gets a second opinion")
        };

        let asan = opinion(&|_| Ok(asan_store_at("fill")));
        let (view, stderr) = asan.asan.as_ref().expect("ASan's report is used");
        assert_eq!(view.rule_id, "BHF-201");
        assert!(stderr
            .as_deref()
            .is_some_and(|log| log.contains("AddressSanitizer")));
        assert!(
            asan.reason.contains("heap-buffer-overflow"),
            "{}",
            asan.reason
        );
        let json = asan.to_json("object-size-key");
        assert_eq!(json["used"], "asan");
        assert_eq!(json["replaced_cluster_key"], "object-size-key");

        let cases: [(Rerun, &str); 4] = [
            (&|_| Ok((None, None)), "reported no error"),
            (
                &|_| Ok(asan_store_at("other_function")),
                "not ASan's report",
            ),
            (
                &|timeout| {
                    std::thread::sleep(timeout);
                    Ok((None, None))
                },
                "time limit",
            ),
            (&|_| Err("no such harness".to_owned()), "no such harness"),
        ];
        for (rerun, why) in cases {
            let stands = opinion(rerun);
            assert!(stands.asan.is_none(), "{stands:?}");
            assert!(
                stands
                    .reason
                    .starts_with("UBSan's object-size report stands: ")
                    && stands.reason.contains(why),
                "{why}: {}",
                stands.reason
            );
            assert_eq!(stands.to_json("object-size-key")["used"], "ubsan");
        }

        // Any other report gets no second opinion, and no re-run.
        let other = sanitizer_report("BHF-201", vec!["fill"]);
        assert!(object_size_second_opinion(
            &work,
            &other,
            &[],
            Duration::from_secs(1),
            None,
            |_, _| panic!("re-ran a report that is not an object-size report"),
        )
        .is_none());
    }

    #[cfg(unix)]
    fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        fs::write(&p, body).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    // #15: a non-zero exit / fatal signal with NO sanitizer report is the target
    // REJECTING the input (assert/abort/non-zero-return on malformed bytes). It
    // must be a clean no-finding run (so the fuzz pass keeps exploring), NOT a hard
    // error that aborts the whole pass.
    #[test]
    #[cfg(unix)]
    fn nonzero_exit_without_sanitizer_is_input_rejection_not_error() {
        let work = tmpdir();
        let h = write_script(&work, "reject_exit.sh", "#!/bin/sh\nexit 1\n");
        let run = run_c_libfuzzer_single_input(
            &replay_min::HarnessRunner::direct(h),
            &work,
            b"bad-input",
            &[],
            Duration::from_secs(5),
            0,
            None,
        )
        .expect("a non-zero exit must be a rejection (Ok), not a hard error (Err)");
        assert!(run.sanitizer.is_none(), "rejection must not be a finding");
        assert!(run.testcases.is_empty());
        assert!(run.rejected, "flagged rejected for the all-reject signal");
    }

    /// A harness whose sanitizer runtime cannot start dies the same way on
    /// every input, before `main`: an environment error that names the
    /// runtime's line and ends the pass, never a finding. An abort with that
    /// line used to be a HIGH BHF-210 "reachable crash".
    #[test]
    #[cfg(unix)]
    fn a_sanitizer_runtime_start_failure_is_an_error_not_a_finding() {
        let work = tmpdir();
        let h = write_script(
            &work,
            "runtime_start.sh",
            "#!/bin/sh\n>&2 echo 'FATAL: ThreadSanitizer: unexpected memory mapping 0x10-0x20'\n\
             kill -ABRT $$\n",
        );
        // The harness's toolchain stamp names the compiler it was built with.
        std::fs::write(
            h.with_file_name("bhf_toolchain.stamp"),
            "widget-g++ gcc widget-gcc | -O1 -g -fsanitize=thread | \n",
        )
        .unwrap();
        let Err(error) = run_c_libfuzzer_single_input(
            &replay_min::HarnessRunner::direct(h),
            &work,
            b"x",
            &[],
            Duration::from_secs(5),
            0,
            None,
        ) else {
            panic!("a runtime that cannot start is an environment error, not a run");
        };
        assert!(
            error.contains("FATAL: ThreadSanitizer: unexpected memory mapping 0x10-0x20")
                && error.contains("could not start")
                && error.contains("runtime_start.sh")
                && error.contains("built with widget-g++"),
            "{error}"
        );
        // bhf auto tells it from any other pass error, and the advice does
        // not claim a compiler switch that never happened.
        assert!(super::is_runtime_start_failure(&error), "{error}");
        assert!(super::is_runtime_start_failure(&format!(
            "pass `empty`: {error}"
        )));
        assert!(!error.contains("picks clang"), "{error}");
        assert!(!super::is_runtime_start_failure(
            "harness exited with status 1"
        ));
    }

    #[test]
    #[cfg(unix)]
    fn diagnosed_assertion_abort_without_sanitizer_is_input_rejection() {
        // The cute_aseprite case: assert() writes a diagnostic, then SIGABRT.
        let work = tmpdir();
        let h = write_script(
            &work,
            "reject_abort.sh",
            "#!/bin/sh\n>&2 echo \"parser.c:12: parse: Assertion 'magic == expected' failed.\"\nkill -ABRT $$\n",
        );
        let run = run_c_libfuzzer_single_input(
            &replay_min::HarnessRunner::direct(h),
            &work,
            b"x",
            &[],
            Duration::from_secs(5),
            0,
            None,
        )
        .expect("a diagnosed assertion must be a rejection, not a pass-aborting error");
        assert!(run.sanitizer.is_none());
        assert!(run.rejected);
    }

    #[test]
    #[cfg(unix)]
    fn silent_abort_without_sanitizer_is_a_bhf210_crash_finding() {
        let work = tmpdir();
        let h = write_script(&work, "silent_abort.sh", "#!/bin/sh\nkill -ABRT $$\n");
        let run = run_c_libfuzzer_single_input(
            &replay_min::HarnessRunner::direct(h),
            &work,
            b"crashing-seed",
            &[],
            Duration::from_secs(5),
            0,
            None,
        )
        .expect("silent SIGABRT must become a finding");
        let report = run.sanitizer.expect("BHF-210 report");
        assert_eq!(report.rule_id, "BHF-210");
        assert!(report.message.contains("SIGABRT"));
        assert!(!run.rejected);
    }

    #[test]
    #[cfg(unix)]
    fn fatal_signal_without_sanitizer_report_is_a_bhf210_crash_finding() {
        // A SIGSEGV (or SIGILL/SIGBUS/SIGFPE) with no sanitizer report is a
        // reachable crash on this input — NOT a rejection, and NOT a hard error
        // that aborts the pass. It is recorded as a BHF-210 finding so it surfaces
        // and the cascade keeps fuzzing (the cute_tiled empty-seed-crash blocker).
        let work = tmpdir();
        let h = write_script(&work, "segv.sh", "#!/bin/sh\nkill -SEGV $$\n");
        let run = run_c_libfuzzer_single_input(
            &replay_min::HarnessRunner::direct(h),
            &work,
            b"x",
            &[],
            Duration::from_secs(5),
            0,
            None,
        )
        .expect("a fatal signal must be a finding (Ok), not a pass-aborting Err");
        let report = run
            .sanitizer
            .expect("fatal signal must produce a synthesized crash report");
        assert_eq!(report.rule_id, "BHF-210", "fatal-signal crash is BHF-210");
        assert!(!run.rejected, "a crash is not a rejection");
        assert!(
            report.message.contains("SIGSEGV"),
            "names the signal: {}",
            report.message
        );
        // SIGILL (the cute_tiled empty-seed case) is also a BHF-210 finding.
        let h2 = write_script(&work, "ill.sh", "#!/bin/sh\nkill -ILL $$\n");
        let run2 = run_c_libfuzzer_single_input(
            &replay_min::HarnessRunner::direct(h2),
            &work,
            b"",
            &[],
            Duration::from_secs(5),
            0,
            None,
        )
        .expect("SIGILL must be a finding too");
        assert_eq!(run2.sanitizer.expect("report").rule_id, "BHF-210");
    }

    // HDF-8 deliverable 1: the deadline oracle. A "must respond within D" budget
    // turns a slow-but-completing input into a real BHF-555 finding instead of the
    // silent kill-and-skip the hang backstop applies — and a fast input under the
    // same D is NOT flagged.
    #[test]
    #[cfg(unix)]
    fn deadline_oracle_reports_a_slow_input_as_a_bhf555_finding_but_not_a_fast_one() {
        let work = tmpdir();
        // The backstop (per_input_timeout) is generous (5s) so the slow target
        // COMPLETES; the deadline (400ms) is the finer budget it overruns. `sleep 1`
        // is ~2.5x the deadline and ~1/5 the backstop, so the classification is
        // unambiguous and the test is non-flaky under load.
        let deadline = Some(Duration::from_millis(400));
        let backstop = Duration::from_secs(5);

        let slow = write_script(&work, "slow.sh", "#!/bin/sh\nsleep 1\nexit 0\n");
        let run = run_c_libfuzzer_single_input(
            &replay_min::HarnessRunner::direct(slow),
            &work,
            b"slow-input",
            &[],
            backstop,
            0,
            deadline,
        )
        .expect("a slow-but-completing input under a deadline is a finding, not an error");
        let report = run
            .sanitizer
            .expect("an over-deadline input must be recorded as a finding");
        assert_eq!(
            report.rule_id, "BHF-555",
            "a missed response deadline is the BHF-555 timing finding"
        );
        assert!(
            report.message.contains("deadline"),
            "the finding names the deadline it missed: {}",
            report.message
        );
        assert!(
            !run.rejected,
            "a deadline violation is a finding, not a rejection"
        );

        // A fast target under the SAME deadline must NOT be flagged.
        let fast = write_script(&work, "fast.sh", "#!/bin/sh\nexit 0\n");
        let fast_run = run_c_libfuzzer_single_input(
            &replay_min::HarnessRunner::direct(fast),
            &work,
            b"fast-input",
            &[],
            backstop,
            0,
            deadline,
        )
        .expect("a fast input is a clean run");
        assert!(
            fast_run.sanitizer.is_none(),
            "a target that answered within the deadline must not be a finding"
        );
    }

    // Regression guard: with NO deadline (the default) a slow input keeps the
    // historical kill-and-skip behavior — no finding — so enabling the oracle is
    // purely additive.
    #[test]
    #[cfg(unix)]
    fn without_a_deadline_a_slow_input_is_not_a_finding() {
        let work = tmpdir();
        let slow = write_script(&work, "slow_nodl.sh", "#!/bin/sh\nsleep 1\nexit 0\n");
        let run = run_c_libfuzzer_single_input(
            &replay_min::HarnessRunner::direct(slow),
            &work,
            b"slow-input",
            &[],
            Duration::from_secs(5),
            0,
            None,
        )
        .expect("clean run");
        assert!(
            run.sanitizer.is_none(),
            "no deadline set: a slow input must NOT be flagged (default behavior unchanged)"
        );
        assert!(!run.rejected);
    }

    #[test]
    #[cfg(unix)]
    fn run_harness_nonzero_exit_without_sanitizer_is_rejection() {
        // Exercises the event-log per-spawn path (run_harness) too.
        let work = tmpdir();
        let h = write_script(&work, "reject_harness.sh", "#!/bin/sh\nexit 3\n");
        let run = run_harness(
            &replay_min::HarnessRunner::direct(h),
            &work,
            b"x",
            &[],
            Duration::from_secs(5),
            0,
            None,
        )
        .expect("run_harness must treat a non-zero exit without a sanitizer report as a rejection");
        assert!(run.sanitizer.is_none());
        assert!(run.rejected);
    }

    #[test]
    #[cfg(unix)]
    fn genuine_sanitizer_crash_still_surfaces_after_rejection_change() {
        // Real memory bugs must still become findings: an ASan report on a non-zero
        // exit yields a sanitizer HarnessRun, not a silent rejection.
        let work = tmpdir();
        let h = write_script(
            &work,
            "asan.sh",
            "#!/bin/sh\n>&2 echo 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1'\n\
             >&2 echo '    #0 0x1 in real_parse /src/p.c:9'\nexit 1\n",
        );
        let run = run_c_libfuzzer_single_input(
            &replay_min::HarnessRunner::direct(h),
            &work,
            b"x",
            &[],
            Duration::from_secs(5),
            0,
            None,
        )
        .expect("ok");
        assert!(
            run.sanitizer.is_some(),
            "an ASan report must still surface as a sanitizer finding"
        );
    }

    #[test]
    #[cfg(unix)]
    fn harness_that_rejects_every_input_is_built_not_fuzzed() {
        // #15 part B: a harness that exits non-zero on EVERY input never actually
        // fuzzed — the run must Err (so the auto loop reports built-not-fuzzed),
        // not return a clean (but empty) success that masks a gate/seed/harness
        // problem.
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        write_c_libfuzzer_harness(&work_dir, "H-ALLREJECT", "#!/bin/sh\nexit 1\n");
        let result = run_one_target_programmatic(
            &work_dir,
            "H-ALLREJECT",
            vec![b"seed".to_vec()],
            5,
            None,
            None,
            0,
            &[],
            actionability::RunMode::Reporting,
            None,
            &[],
            None,
        );
        let err = result.expect_err("all-reject must not report a clean fuzz");
        assert!(
            err.contains("rejected all") && err.contains("cannot fuzz"),
            "built-not-fuzzed reason must be explicit: {err}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn supplied_silent_abort_seed_becomes_a_finding() {
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        write_c_libfuzzer_harness(
            &work_dir,
            "H-ABORT-SEED",
            "#!/bin/sh\ninput=$(cat \"$1\")\nif [ \"$input\" = BOMB ]; then kill -ABRT $$; fi\nexit 0\n",
        );
        let summary = run_one_target_programmatic(
            &work_dir,
            "H-ABORT-SEED",
            vec![b"clean".to_vec(), b"BOMB".to_vec()],
            2,
            None,
            None,
            0,
            &[],
            actionability::RunMode::Reporting,
            None,
            &[],
            None,
        )
        .expect("the supplied abort seed must not fail the pass");
        assert_eq!(
            summary.executions, 2,
            "both supplied seeds run before mutation"
        );
        assert_eq!(
            summary.findings.len(),
            1,
            "the silent SIGABRT seed must emit one deduplicated finding"
        );
    }

    #[test]
    #[cfg(unix)]
    fn sanitizer_crash_writes_sanitizer_log_next_to_the_finding() {
        // Task 25: the full captured stderr of a real sanitizer crash must land
        // as `sanitizer.log` next to `finding.json`, not just the truncated
        // excerpt that was already in the record.
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        write_c_libfuzzer_harness(
            &work_dir,
            "H-SANLOG",
            "#!/bin/sh\n>&2 echo 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1'\n\
             >&2 echo '    #0 0x1 in real_parse /src/p.c:9'\nexit 1\n",
        );
        let summary = run_one_target_programmatic(
            &work_dir,
            "H-SANLOG",
            vec![b"seed".to_vec()],
            1,
            None,
            None,
            0,
            &[],
            actionability::RunMode::Reporting,
            None,
            &[],
            None,
        )
        .expect("a crash on every input is signal, not an all-reject failure");
        assert_eq!(summary.findings.len(), 1);
        let finding_dir = corpus::layout::finding_dir(&work_dir, &summary.findings[0]);
        let log = fs::read_to_string(finding_dir.join("sanitizer.log"))
            .expect("sanitizer.log must be written next to the finding");
        assert!(
            log.contains("AddressSanitizer: heap-buffer-overflow"),
            "{log}"
        );
        assert!(log.contains("real_parse /src/p.c:9"), "{log}");
        let finding: serde_json::Value =
            serde_json::from_slice(&fs::read(finding_dir.join("finding.json")).unwrap()).unwrap();
        assert_eq!(finding["paths"]["sanitizer_log"], "sanitizer.log");
    }

    /// The shell harness of the argument-trace tests: with BHF_TRACE_ARGS=1
    /// it prints a trace line first, and it always reports a heap overflow one
    /// byte past the traced buffer.
    #[cfg(unix)]
    const TRACING_CRASH_SCRIPT: &str = "#!/bin/sh\n\
        if [ \"$BHF_TRACE_ARGS\" = 1 ]; then >&2 echo 'BHF_ARG {\"call\":\"target\",\"i\":0,\"role\":\"param\",\"name\":\"buffer\",\"type\":\"const char *\",\"span\":[0,2],\"ptr\":\"0x502000000030\",\"alloc_size\":1,\"len\":0,\"preview_hex\":\"\"}'; fi\n\
        >&2 echo '==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000031 at pc 0x1 bp 0x2 sp 0x3'\n\
        >&2 echo 'READ of size 4 at 0x502000000031 thread T0'\n\
        >&2 echo '    #0 0x1 in real_parse /src/p.c:9'\n\
        >&2 echo '0x502000000031 is located 0 bytes after 1-byte region [0x502000000030,0x502000000031)'\n\
        exit 1\n";

    /// A pass records its harness's input format in the corpus it fills,
    /// even when it finds nothing, so a later run can tell the corpus's
    /// format.
    #[test]
    #[cfg(unix)]
    fn a_pass_without_findings_records_the_corpus_format() {
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        let harness = write_c_libfuzzer_harness(
            &work_dir,
            "H-QUIET",
            "#!/bin/sh
exit 0
",
        );
        fs::write(
            harness.with_file_name("generation-metadata.json"),
            r#"{"schema_version":1,"harness_format_version":4,"language":"c"}"#,
        )
        .unwrap();
        let summary = run_one_target_programmatic(
            &work_dir,
            "H-QUIET",
            vec![b"seed".to_vec()],
            1,
            None,
            None,
            0,
            &[],
            actionability::RunMode::Reporting,
            None,
            &[],
            None,
        )
        .expect("a clean pass");
        assert!(summary.findings.is_empty());
        let format = corpus::finding::recorded_corpus_format(&work_dir, "H-QUIET")
            .expect("the corpus records its format");
        assert_eq!(format.version, 4);
        assert!(!format.buffer_len_dimension);
    }

    /// A new finding is re-run once with the argument trace on, and its
    /// decoded arguments land in decoded.json and finding.json, with the
    /// overflowed parameter named on the access.
    #[test]
    #[cfg(unix)]
    fn a_new_finding_records_its_traced_arguments() {
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        let harness = write_c_libfuzzer_harness(&work_dir, "H-ARGTRACE", TRACING_CRASH_SCRIPT);
        fs::write(
            harness.with_file_name("generation-metadata.json"),
            r#"{"schema_version":1,"harness_format_version":3,"buffer_len_dimension":true,"language":"c"}"#,
        )
        .unwrap();
        let summary = run_one_target_programmatic(
            &work_dir,
            "H-ARGTRACE",
            vec![b"seed".to_vec()],
            1,
            None,
            None,
            0,
            &[],
            actionability::RunMode::Reporting,
            None,
            &[],
            None,
        )
        .expect("the crash is a finding");
        assert_eq!(summary.findings.len(), 1);
        let finding_dir = corpus::layout::finding_dir(&work_dir, &summary.findings[0]);
        let decoded: serde_json::Value =
            serde_json::from_slice(&fs::read(finding_dir.join("decoded.json")).unwrap()).unwrap();
        assert_eq!(decoded["schema_version"], "bhf.decoded.v1");
        assert_eq!(decoded["arguments_source"], "harness_trace");
        assert_eq!(decoded["arguments"][0]["ptr"], "0x502000000030");
        assert_eq!(decoded["arguments"][0]["alloc_size"], 1);
        let finding: serde_json::Value =
            serde_json::from_slice(&fs::read(finding_dir.join("finding.json")).unwrap()).unwrap();
        assert_eq!(
            finding["decoded_args"],
            serde_json::json!([{"name": "buffer", "type": "const char *", "role": "param",
                                "len": 0, "span": [0, 2], "preview_hex": ""}])
        );
        assert_eq!(
            finding["exception"]["access"]["parameter"]["name"],
            "buffer"
        );
        assert_eq!(finding["exception"]["access"]["parameter"]["offset"], 1);
        // The harness's input format, its buffer-length dimension included.
        assert_eq!(finding["harness_format_version"], 3);
        assert_eq!(finding["buffer_len_dimension"], true);
        assert_eq!(finding["harness"]["format_version"], 3);
        assert_eq!(finding["harness"]["buffer_len_dimension"], true);
        // The sanitizer log is the crashing run's, not the trace run's.
        let log = fs::read_to_string(finding_dir.join("sanitizer.log")).unwrap();
        assert!(!log.contains("BHF_ARG"), "{log}");
    }

    /// A harness built without the argument trace is never re-run for it, and
    /// decoded.json says why it has no arguments.
    #[test]
    #[cfg(unix)]
    fn a_harness_without_the_trace_records_why_it_has_no_arguments() {
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        let counter = root.join("runs");
        write_c_libfuzzer_harness(
            &work_dir,
            "H-NOTRACE",
            &format!(
                "#!/bin/sh\necho run >> '{}'\n\
                 >&2 echo 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1'\n\
                 >&2 echo '    #0 0x1 in real_parse /src/p.c:9'\nexit 1\n",
                counter.display()
            ),
        );
        let summary = run_one_target_programmatic(
            &work_dir,
            "H-NOTRACE",
            vec![b"seed".to_vec()],
            1,
            None,
            None,
            0,
            &[],
            actionability::RunMode::Reporting,
            None,
            &[],
            None,
        )
        .expect("the crash is a finding");
        let finding_dir = corpus::layout::finding_dir(&work_dir, &summary.findings[0]);
        let decoded: serde_json::Value =
            serde_json::from_slice(&fs::read(finding_dir.join("decoded.json")).unwrap()).unwrap();
        assert_eq!(decoded["arguments_source"], "none");
        assert!(decoded["arguments_unavailable"]
            .as_str()
            .unwrap()
            .contains("without the argument trace"));
        let finding: serde_json::Value =
            serde_json::from_slice(&fs::read(finding_dir.join("finding.json")).unwrap()).unwrap();
        assert!(finding.get("decoded_args").is_none());
        let runs_before = fs::read_to_string(&counter).unwrap().lines().count();
        assert!(runs_before >= 1);
    }

    /// The AFL++ lane's harness reads the testcase from stdin; its trace run
    /// feeds it the same way.
    #[test]
    #[cfg(unix)]
    fn the_argument_trace_feeds_stdin_harnesses_their_input() {
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        let harness = write_c_libfuzzer_harness(
            &work_dir,
            "H-AFLTRACE",
            "#!/bin/sh\n# BHF_TRACE_ARGS\nbytes=$(od -An -tu1 | tr -s ' ' | sed 's/^ //;s/ $//')\n\
             [ \"$BHF_TRACE_ARGS\" = 1 ] && >&2 echo \"BHF_ARG {\\\"call\\\":\\\"target\\\",\\\"i\\\":0,\\\"role\\\":\\\"param\\\",\\\"name\\\":\\\"first\\\",\\\"type\\\":\\\"int\\\",\\\"value\\\":\\\"$bytes\\\"}\"\n\
             exit 0\n",
        );
        let (outcome, _) = trace_arguments(
            &harness,
            &work_dir,
            &[42],
            TraceInput::Stdin,
            &[],
            Duration::from_secs(10),
            None,
        );
        let corpus::decoded_args::TraceOutcome::Traced(args) = outcome else {
            panic!("no trace: {outcome:?}");
        };
        assert_eq!(args[0].value.as_deref(), Some("42"));
    }

    #[test]
    #[cfg(unix)]
    fn harness_that_crashes_on_every_input_keeps_its_findings() {
        // #477: a target where EVERY input crashes (a callback struct cast from raw
        // bytes; a parser that aborts on malformed input) rejects all executions AND
        // emits real crash findings. The reject-all guard must NOT discard them by
        // returning Err — a run that produced any finding produced signal, so it must
        // return Ok with the findings, not downgrade to a finding-less `Built`.
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        write_c_libfuzzer_harness(
            &work_dir,
            "H-ALLCRASH",
            "#!/bin/sh\n>&2 echo 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1'\n\
             >&2 echo '    #0 0x1 in real_parse /src/p.c:9'\nexit 1\n",
        );
        let summary = run_one_target_programmatic(
            &work_dir,
            "H-ALLCRASH",
            vec![b"seed".to_vec()],
            5,
            None,
            None,
            0,
            &[],
            actionability::RunMode::Reporting,
            None,
            &[],
            None,
        )
        .expect("a crash on every input is signal, not an all-reject failure");
        assert!(
            !summary.findings.is_empty(),
            "the crash findings must survive into the summary"
        );
    }

    #[test]
    #[cfg(unix)]
    fn harness_that_runs_clean_fuzzes_normally() {
        // Contrast to the all-reject case: a harness that exits 0 fuzzes fine.
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        write_c_libfuzzer_harness(&work_dir, "H-CLEAN15", "#!/bin/sh\nexit 0\n");
        let summary = run_one_target_programmatic(
            &work_dir,
            "H-CLEAN15",
            vec![b"seed".to_vec()],
            5,
            None,
            None,
            0,
            &[],
            actionability::RunMode::Reporting,
            None,
            &[],
            None,
        )
        .expect("a clean harness must fuzz, not be flagged built-not-fuzzed");
        assert!(summary.executions > 0);
    }

    #[test]
    #[cfg(unix)]
    fn file_creating_harness_writes_into_scratch_not_launch_cwd() {
        use std::os::unix::fs::PermissionsExt;
        let work = tmpdir();
        let scratch = ensure_harness_scratch(&work).unwrap();
        // A fake harness that, like a fuzzed archive/stream writer fed fuzz
        // bytes, creates a file with a fuzz-controlled name in its CWD.
        let fake = work.join("fake_harness.sh");
        fs::write(&fake, "#!/bin/sh\ntouch 'junk-from-fuzz=0644'\n").unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        let input = work.join("in.bin");
        fs::write(&input, b"x").unwrap();
        let launch_cwd = std::env::current_dir().unwrap();

        let _ = run_with_timeout(
            &fake,
            &input,
            Duration::from_secs(5),
            &[],
            &scratch,
            0,
            None,
            SpawnTweaks::default(),
        );

        assert!(
            scratch.join("junk-from-fuzz=0644").is_file(),
            "a file-creating harness must write into the run's fuzz_scratch dir"
        );
        assert!(
            !launch_cwd.join("junk-from-fuzz=0644").exists(),
            "a file-creating harness must not pollute the directory bhf was launched from"
        );
    }

    #[test]
    #[cfg(unix)]
    fn hanging_event_log_harness_is_reaped_at_per_input_timeout() {
        use std::os::unix::fs::PermissionsExt;
        // A non-C harness (no main.c/main.cpp in the dir, so it takes the
        // event-log per-spawn lane) that hangs forever, ignoring stdin. Its
        // descendant inherits stderr: killing only the shell leaves the pipe
        // open and blocks the stderr drain thread forever. The timeout must kill
        // the whole harness process group.
        let work = tmpdir();
        let hang = work.join("hang.sh");
        fs::write(&hang, "#!/bin/sh\nsleep 3600 &\nwait\n").unwrap();
        fs::set_permissions(&hang, fs::Permissions::from_mode(0o755)).unwrap();
        let runner = replay_min::HarnessRunner::direct(hang);

        let started = Instant::now();
        let run = run_harness(
            &runner,
            &work,
            b"input",
            &[],
            Duration::from_secs(1),
            0,
            None,
        )
        .expect("a hung harness must be reaped and return a clean run, not block or error");
        let elapsed = started.elapsed();

        // With the fix this returns in ~1s; without it the test would hang for
        // ~an hour. Generous bound to stay non-flaky under load.
        assert!(
            elapsed < Duration::from_secs(30),
            "engine must recover within the per-input timeout, took {elapsed:?}"
        );
        // A timed-out (hung) input yields no events and no finding.
        assert!(
            run.events.is_empty() && run.sanitizer.is_none(),
            "a reaped hung harness must produce a no-event run"
        );
    }

    #[test]
    fn find_harness_executable_finds_harnesses_layout_binary() {
        let root = tmpdir();
        let auto_main = root.join("harnesses/H-X/main");
        fs::create_dir_all(auto_main.parent().unwrap()).unwrap();
        fs::write(&auto_main, b"\x7fELF").unwrap();
        let p = find_harness_executable(&root, "H-X", FuzzEngine::Builtin).unwrap();
        assert_eq!(p, auto_main);
    }

    #[test]
    fn find_harness_executable_finds_harnesses_layout_afl_binary() {
        let root = tmpdir();
        let auto_main = root.join("harnesses/H-X/main_afl");
        fs::create_dir_all(auto_main.parent().unwrap()).unwrap();
        fs::write(&auto_main, b"\x7fELF").unwrap();
        let p = find_harness_executable(&root, "H-X", FuzzEngine::AflPlusPlus).unwrap();
        assert_eq!(p, auto_main);
    }

    #[test]
    fn find_harness_executable_still_finds_legacy_build_dir() {
        let root = tmpdir();
        let legacy = root.join("build/H-X/main");
        fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        fs::write(&legacy, b"\x7fELF").unwrap();
        let p = find_harness_executable(&root, "H-X", FuzzEngine::Builtin).unwrap();
        assert_eq!(p, legacy);
    }

    #[test]
    fn generated_dictionary_loader_prefers_harnesses_layout() {
        let root = tmpdir();
        let auto_dict = root.join("harnesses/H-X/dictionary.txt");
        let generated_dict = root.join("generated_harnesses/H-X/dictionary.txt");
        fs::create_dir_all(auto_dict.parent().unwrap()).unwrap();
        fs::create_dir_all(generated_dict.parent().unwrap()).unwrap();
        fs::write(&auto_dict, "\"AUTO\\nTOKEN\"\n").unwrap();
        fs::write(&generated_dict, "\"LEGACY\"\n").unwrap();

        let path = find_generated_dictionary(&root, "H-X").unwrap();
        assert_eq!(path, auto_dict);
        let tokens = load_generated_dictionary_tokens(&root, "H-X").unwrap();
        assert_eq!(tokens, vec![b"AUTO\nTOKEN".to_vec()]);
    }

    #[test]
    fn generated_dictionary_loader_finds_legacy_generated_harness_layout() {
        let root = tmpdir();
        let generated_dict = root.join("generated_harnesses/H-X/dictionary.txt");
        fs::create_dir_all(generated_dict.parent().unwrap()).unwrap();
        fs::write(&generated_dict, "\"GIF89a\"\n\"MODE_FAST\"\n").unwrap();

        let path = find_generated_dictionary(&root, "H-X").unwrap();
        assert_eq!(path, generated_dict);
        let tokens = load_generated_dictionary_tokens(&root, "H-X").unwrap();
        assert_eq!(tokens, vec![b"GIF89a".to_vec(), b"MODE_FAST".to_vec()]);
    }

    #[test]
    fn generated_dictionary_loader_finds_fake_corba_idl_dictionary() {
        let root = tmpdir();
        let fake_corba_dict = root.join("fake_corba/dictionary.txt");
        fs::create_dir_all(fake_corba_dict.parent().unwrap()).unwrap();
        fs::write(&fake_corba_dict, "\"READY\"\n\"MODE_FAST\"\n").unwrap();

        let path = find_generated_dictionary(&root, "H-X").unwrap();
        assert_eq!(path, fake_corba_dict);
        let tokens = load_generated_dictionary_tokens(&root, "H-X").unwrap();
        assert_eq!(tokens, vec![b"READY".to_vec(), b"MODE_FAST".to_vec()]);
    }

    /// The comparison constants recorded at runtime become
    /// learned_dictionary.txt: at each site, the operand that met more
    /// distinct values than any of the mutated inputs compared with it,
    /// deduplicated and bounded, under a header saying how they were chosen.
    /// The input fragments they were compared against are not written, nor
    /// are an unsited record's operands absent from dictionary.txt, nor those
    /// an earlier, unfiltered file held; a file written with the filter keeps
    /// its tokens after this run's.
    #[test]
    fn learned_dictionary_keeps_runtime_constants_not_input_fragments() {
        let root = tmpdir();
        let harness = root.join("harnesses/H-L");
        fs::create_dir_all(&harness).unwrap();
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let record = |site: &str, a: &[u8], b: &[u8]| {
            format!(
                "{{\"e\":\"cmplog\",\"k\":\"memcmp\",\"s\":\"{site}\",\"a\":\"{}\",\"b\":\"{}\"}}\n",
                hex(a),
                hex(b)
            )
        };
        let mut log = String::new();
        for fragment in [&b"abcd"[..], b"x\x01yz", b"~~~~"] {
            log.push_str(&record("00000010.00000100", fragment, b"WGT1"));
        }
        for fragment in [&b"0q7z"[..], b"q\x91"] {
            log.push_str(&record("00000020.00000100", fragment, b"zz\n"));
        }
        // Seen once: kept only because the mined dictionary has it.
        log.push_str(&record("00000030.00000100", b"pppp", b"HDR1"));
        log.push_str(&record("00000031.00000100", b"oooo", b"NOPE"));
        // A record without a site (the runtrace shim writes those) only
        // confirms a mined token, however many values its operands met.
        for fragment in [&b"u1u1"[..], b"u2u2", b"u3u3"] {
            log.push_str(&format!(
                "{{\"e\":\"cmplog\",\"k\":\"memcmp\",\"a\":\"{}\",\"b\":\"{}\"}}\n",
                hex(fragment),
                hex(b"UNS1")
            ));
        }
        let long = vec![b'x'; LEARNED_TOKEN_MAX_LEN + 1];
        for fragment in [&b"aa"[..], b"bb"] {
            log.push_str(&record("00000040.00000100", fragment, &long));
        }
        log.push_str("{\"e\":\"getenv\",\"name\":\"HOME\"}\n");
        fs::write(harness.join("cmplog.jsonl"), &log).unwrap();
        fs::write(harness.join("dictionary.txt"), "\"HDR1\"\n").unwrap();
        // A file an earlier release wrote, with every operand in it.
        fs::write(
            harness.join(LEARNED_DICTIONARY_FILE),
            "# Comparison operands observed at runtime\n\"OLD1\"\n\"~~~~\"\n",
        )
        .unwrap();

        assert_eq!(write_learned_dictionary(&harness).unwrap(), 3);
        let text = fs::read_to_string(harness.join(LEARNED_DICTIONARY_FILE)).unwrap();
        assert!(text.starts_with(LEARNED_DICTIONARY_HEADER), "{text}");
        assert!(LEARNED_DICTIONARY_HEADER.contains("observed at runtime"));
        let tokens = load_afl_dictionary_tokens(&harness.join(LEARNED_DICTIONARY_FILE)).unwrap();
        assert_eq!(
            tokens,
            vec![b"WGT1".to_vec(), b"zz\n".to_vec(), b"HDR1".to_vec()],
            "constants only, strongest first; no input fragment and no unfiltered earlier token"
        );

        // A later run's constants come first, then the filtered file's.
        let next: String = [&b"m1m1"[..], b"m2m2"]
            .iter()
            .map(|fragment| record("00000050.00000100", fragment, b"NEW1"))
            .collect();
        fs::write(harness.join("cmplog.jsonl"), next).unwrap();
        assert_eq!(write_learned_dictionary(&harness).unwrap(), 4);
        assert_eq!(
            load_afl_dictionary_tokens(&harness.join(LEARNED_DICTIONARY_FILE)).unwrap(),
            vec![
                b"NEW1".to_vec(),
                b"WGT1".to_vec(),
                b"zz\n".to_vec(),
                b"HDR1".to_vec()
            ]
        );

        // Bounded: never more than LEARNED_DICTIONARY_MAX_TOKENS.
        let many: String = (0..LEARNED_DICTIONARY_MAX_TOKENS + 40)
            .flat_map(|i| {
                let site = format!("{i:08x}.00000100");
                let constant = format!("T{i:04}");
                [b"in-1".to_vec(), b"in-2".to_vec()]
                    .into_iter()
                    .map(move |fragment| record(&site, &fragment, constant.as_bytes()))
                    .collect::<Vec<_>>()
            })
            .collect();
        fs::write(harness.join("cmplog.jsonl"), many).unwrap();
        assert_eq!(
            write_learned_dictionary(&harness).unwrap(),
            LEARNED_DICTIONARY_MAX_TOKENS
        );

        // No operands this time: the learned tokens are kept as they were.
        let before = fs::read_to_string(harness.join(LEARNED_DICTIONARY_FILE)).unwrap();
        fs::remove_file(harness.join("cmplog.jsonl")).unwrap();
        assert_eq!(write_learned_dictionary(&harness).unwrap(), 0);
        assert_eq!(
            fs::read_to_string(harness.join(LEARNED_DICTIONARY_FILE)).unwrap(),
            before
        );
    }

    /// An integer comparison's constant (#221) is learned from one record,
    /// little-endian as compared and big-endian beside it.
    #[test]
    fn a_learned_integer_constant_is_written_in_both_byte_orders() {
        let root = tmpdir();
        let harness = root.join("harnesses/H-INT");
        fs::create_dir_all(&harness).unwrap();
        fs::write(
            harness.join("cmplog.jsonl"),
            "{\"e\":\"cmplog\",\"k\":\"int\",\"s\":\"00000010.00000000\",\"a\":\"5b3e0f69\",\"b\":\"\"}\n",
        )
        .unwrap();
        assert_eq!(write_learned_dictionary(&harness).unwrap(), 2);
        assert_eq!(
            load_afl_dictionary_tokens(&harness.join(LEARNED_DICTIONARY_FILE)).unwrap(),
            vec![vec![0x5b, 0x3e, 0x0f, 0x69], vec![0x69, 0x0f, 0x3e, 0x5b]]
        );
    }

    /// A runtime constant holding a protocol delimiter (`\r\n`) is written
    /// with `\xNN` escapes, which AFL++ loads, and reads back as the same
    /// bytes.
    #[test]
    fn a_learned_crlf_operand_is_written_with_hex_escapes() {
        let root = tmpdir();
        let harness = root.join("harnesses/H-CRLF");
        fs::create_dir_all(&harness).unwrap();
        fs::write(
            harness.join("cmplog.jsonl"),
            "{\"e\":\"cmplog\",\"k\":\"memcmp\",\"s\":\"00000010.00000000\",\"a\":\"410d0a42\",\"b\":\"0941\"}\n\
             {\"e\":\"cmplog\",\"k\":\"memcmp\",\"s\":\"00000010.00000000\",\"a\":\"410d0a42\",\"b\":\"0942\"}\n",
        )
        .unwrap();
        assert_eq!(write_learned_dictionary(&harness).unwrap(), 1);
        let text = fs::read_to_string(harness.join(LEARNED_DICTIONARY_FILE)).unwrap();
        assert!(text.contains("\"A\\x0d\\x0aB\"\n"), "{text}");
        assert!(!text.contains("\\r") && !text.contains("\\n\""), "{text}");
        assert_eq!(
            load_afl_dictionary_tokens(&harness.join(LEARNED_DICTIONARY_FILE)).unwrap(),
            vec![b"A\r\nB".to_vec()]
        );
    }

    /// A fuzz run loads the learned tokens with the mined ones, each once.
    #[test]
    fn learned_dictionary_tokens_are_loaded_with_the_mined_ones() {
        let root = tmpdir();
        let harness = root.join("harnesses/H-M");
        fs::create_dir_all(&harness).unwrap();
        fs::write(harness.join("dictionary.txt"), "\"MINED\"\n\"BOTH\"\n").unwrap();
        fs::write(
            harness.join(LEARNED_DICTIONARY_FILE),
            format!("{LEARNED_DICTIONARY_HEADER}\"BOTH\"\n\"SEEN\"\n"),
        )
        .unwrap();
        assert_eq!(
            load_generated_dictionary_tokens(&root, "H-M").unwrap(),
            vec![b"MINED".to_vec(), b"BOTH".to_vec(), b"SEEN".to_vec()]
        );
        // A harness with only learned tokens still gets them.
        let only = root.join("harnesses/H-N");
        fs::create_dir_all(&only).unwrap();
        fs::write(
            only.join(LEARNED_DICTIONARY_FILE),
            format!("{LEARNED_DICTIONARY_HEADER}\"SEEN\"\n"),
        )
        .unwrap();
        assert_eq!(
            load_generated_dictionary_tokens(&root, "H-N").unwrap(),
            vec![b"SEEN".to_vec()]
        );
        assert_eq!(
            find_learned_dictionary(&root, "H-N"),
            Some(only.join(LEARNED_DICTIONARY_FILE))
        );
    }

    #[test]
    fn dictionary_token_may_contain_equals_sign() {
        // printf format strings lifted from real source routinely contain `=`.
        // The token value must survive verbatim and not be split on the `=`.
        let token = parse_afl_dictionary_line("\"len of TF\\t = %d\"")
            .expect("token with '=' parses")
            .expect("token is not a comment/blank");
        assert_eq!(token, b"len of TF\t = %d");
    }

    #[test]
    fn dictionary_named_token_strips_prefix_but_keeps_equals_in_value() {
        let token = parse_afl_dictionary_line("fmt@1=\"a = b\"")
            .expect("named token parses")
            .expect("token is not a comment/blank");
        assert_eq!(token, b"a = b");
    }

    #[test]
    fn malformed_dictionary_line_is_skipped_not_fatal() {
        // A generated dictionary must never abort the campaign: one bad line is
        // skipped and the valid tokens around it still load.
        let root = tmpdir();
        let dict = root.join("harnesses/H-Y/dictionary.txt");
        fs::create_dir_all(dict.parent().unwrap()).unwrap();
        fs::write(&dict, "\"good_one\"\nthis is not quoted\n\"good = two\"\n").unwrap();
        let tokens =
            load_generated_dictionary_tokens(&root, "H-Y").expect("loads despite bad line");
        assert_eq!(tokens, vec![b"good_one".to_vec(), b"good = two".to_vec()]);
    }

    #[test]
    fn len_control_grows_on_plateau_resets_on_new_and_caps_at_max() {
        // Disabled (0): never grows.
        assert_eq!(len_control_step(64, 4096, 0, 50, false), (64, 0));
        // Plateau below threshold: counter ticks, length held.
        assert_eq!(len_control_step(64, 4096, 100, 40, false), (64, 41));
        // Plateau reaches threshold: length doubles, counter resets.
        assert_eq!(len_control_step(64, 4096, 100, 99, false), (128, 0));
        // A new corpus signature resets the plateau without growing.
        assert_eq!(len_control_step(64, 4096, 100, 99, true), (64, 0));
        // Growth never exceeds the ceiling.
        assert_eq!(len_control_step(4000, 4096, 100, 99, false), (4096, 0));
    }

    #[test]
    fn resolve_max_len_spec_handles_auto_number_and_default() {
        // "auto" never truncates a larger seed and otherwise uses the adaptive ceiling.
        assert_eq!(resolve_max_len_spec(Some("auto"), 0), AUTO_MAX_LEN_CEILING);
        assert_eq!(
            resolve_max_len_spec(Some("AUTO"), 1024),
            AUTO_MAX_LEN_CEILING
        );
        let huge = AUTO_MAX_LEN_CEILING + 1;
        assert_eq!(resolve_max_len_spec(Some("auto"), huge), huge);
        // A number is a fixed cap; a bogus value falls back to the default.
        assert_eq!(resolve_max_len_spec(Some("65536"), 0), 65536);
        assert_eq!(resolve_max_len_spec(Some("0"), 0), DEFAULT_MAX_LEN);
        assert_eq!(resolve_max_len_spec(Some("nope"), 0), DEFAULT_MAX_LEN);
        // Unset keeps the historical default (no regression for non-auto callers).
        assert_eq!(resolve_max_len_spec(None, 999), DEFAULT_MAX_LEN);
    }

    #[test]
    fn len_control_holds_plateau_at_ceiling_for_the_adaptive_raise() {
        // At the ceiling the length is held, but the plateau counter is now HELD at
        // the threshold (not zeroed) so the loop can detect "stuck at ceiling" and
        // decide whether to raise it. Below the threshold it still just ticks.
        assert_eq!(len_control_step(4096, 4096, 100, 5, false), (4096, 6));
        assert_eq!(len_control_step(4096, 4096, 100, 99, false), (4096, 100));
        // Stuck at the ceiling: the counter is capped at the threshold, not unbounded.
        assert_eq!(len_control_step(4096, 4096, 100, 500, false), (4096, 100));
        // A new signature at the ceiling still clears the plateau.
        assert_eq!(len_control_step(4096, 4096, 100, 500, true), (4096, 0));
    }

    #[test]
    fn worker_passthrough_includes_rss_limit_only_when_set() {
        let args_dir = tmpdir();
        let mut args = fuzz_args_for_worker_passthrough(&args_dir, StructuredInputMode::Auto);
        args.rss_limit_mb = 0;
        assert!(!worker_passthrough_args(&args)
            .iter()
            .any(|a| a == "--rss-limit-mb"));
        args.rss_limit_mb = 2048;
        let passthrough = worker_passthrough_args(&args);
        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--rss-limit-mb" && pair[1] == "2048"));
    }

    #[test]
    fn worker_passthrough_includes_timeout_only_when_set() {
        let args_dir = tmpdir();
        let mut args = fuzz_args_for_worker_passthrough(&args_dir, StructuredInputMode::Auto);
        args.timeout = None;
        assert!(
            !worker_passthrough_args(&args)
                .iter()
                .any(|a| a == "--timeout"),
            "no --timeout passthrough when unset (workers use the default)"
        );
        args.timeout = Some(Duration::from_secs(30));
        let passthrough = worker_passthrough_args(&args);
        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--timeout" && pair[1] == "30s"));
    }

    /// MemorySanitizer and ThreadSanitizer each need a build of their own;
    /// ASan, UBSan and LSan combine.
    #[test]
    fn exclusive_sanitizers_are_refused_in_a_set() {
        let set = |values: &[&str]| {
            parse_sanitizer_args(&values.iter().map(|v| v.to_string()).collect::<Vec<_>>())
        };
        for (values, named) in [
            (&["msan", "asan"][..], "msan cannot be combined with asan"),
            (&["tsan", "ubsan"][..], "tsan cannot be combined with ubsan"),
            (
                &["asan", "tsan", "lsan"][..],
                "tsan cannot be combined with asan, lsan",
            ),
            (&["msan", "tsan"][..], "msan cannot be combined with tsan"),
        ] {
            let error = set(values).expect_err(&format!("{values:?}"));
            assert!(error.contains(named), "{values:?}: {error}");
        }
        for ok in [&["asan", "ubsan", "lsan"][..], &["msan"][..], &["tsan"][..]] {
            assert!(set(ok).is_ok(), "{ok:?}");
        }
    }

    /// A confirmed hang's report starts at the looping frame, below the
    /// instrumentation callback the stop signal interrupted, and carries no
    /// sanitizer of its own: the signal's report is not the finding.
    #[test]
    fn a_hang_report_starts_at_the_looping_frame() {
        let stderr = "AddressSanitizer:DEADLYSIGNAL\n\
            =================================================================\n\
            ==7==ERROR: AddressSanitizer: ABRT on unknown address 0x03e800000007 (pc 0x55 bp 0x7f sp 0x7f T0)\n\
            \x20   #0 0x55 in __sanitizer_cov_trace_pc_guard /src/c_runtime/bhf_driver.c:830:5\n\
            \x20   #1 0x56 in walk_tlv /w/harnesses/H-TLV/target.c:6:14\n\
            \x20   #2 0x57 in bhf_run_one_bytes /src/c_runtime/bhf_driver.c:1131:5\n\
            \x20   #3 0x58 in main /src/c_runtime/bhf_driver.c:1280:9\n\
            \n\
            SUMMARY: AddressSanitizer: ABRT /src/c_runtime/bhf_driver.c:830:5 in __sanitizer_cov_trace_pc_guard\n\
            bhf: harness exceeded per-input timeout of 400ms - killed\n";
        let report = hang_report(
            stderr,
            Duration::from_millis(200),
            Duration::from_millis(400),
        );
        assert_eq!(report.rule_id, HANG_RULE);
        assert_eq!(report.kind, "timeout");
        assert_eq!(report.sanitizer, None);
        assert_eq!(report.location, None);
        let functions: Vec<_> = report.stack.iter().map(|f| f.function.as_str()).collect();
        assert_eq!(functions, ["walk_tlv", "bhf_run_one_bytes", "main"]);
        assert_eq!(report.stack[0].line, Some(6));
        assert!(
            report.message.contains("200ms") && report.message.contains("400ms"),
            "{}",
            report.message
        );

        // Without a sanitizer's stack the report has none.
        let bare = hang_report(
            "bhf: harness exceeded per-input timeout of 400ms - killed\n",
            Duration::from_millis(200),
            Duration::from_millis(400),
        );
        assert!(bare.stack.is_empty());
    }

    /// The confirmation run asks every sanitizer runtime to answer SIGABRT
    /// with its stack, after the options the run already had.
    #[test]
    fn hang_confirmations_arm_handle_abort_after_the_run_options() {
        let env = hang_stack_env(
            &[
                (
                    "ASAN_OPTIONS".to_owned(),
                    "abort_on_error=1:symbolize=1".to_owned(),
                ),
                ("BHF_COV_SHM".to_owned(), "/dev/shm/x".to_owned()),
            ],
            Duration::from_secs(20),
        );
        let value = |key: &str| {
            env.iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(
            value("ASAN_OPTIONS"),
            Some("abort_on_error=1:symbolize=1:handle_abort=1")
        );
        assert_eq!(value("BHF_COV_SHM"), Some("/dev/shm/x"));
        for key in [
            "HWASAN_OPTIONS",
            "UBSAN_OPTIONS",
            "MSAN_OPTIONS",
            "TSAN_OPTIONS",
        ] {
            assert!(
                value(key).is_some_and(|options| options.ends_with("handle_abort=1")),
                "{key}: {env:?}"
            );
        }
        // An interpreted lane's driver reports its frames at the 20s limit,
        // and the re-run is stopped 2s later.
        assert_eq!(value(HANG_REPORT_ENV), Some("20000"));
        assert_eq!(
            hang_report_slack(Duration::from_secs(20)),
            Duration::from_secs(2)
        );
        assert_eq!(
            hang_report_slack(Duration::from_secs(1)),
            Duration::from_millis(500)
        );
    }

    /// A driver's frames make the report's stack.
    #[test]
    fn an_interpreted_lanes_hang_is_keyed_on_the_frames_its_driver_printed() {
        let report = hang_report(
            "== bhf hang: python\n== bhf frame: spin @ /src/t.py:3\n",
            Duration::from_secs(1),
            Duration::from_secs(2),
        );
        assert_eq!(report.stack[0].function, "spin");
        assert_eq!(report.stack[0].file.as_deref(), Some("/src/t.py"));
    }

    /// `500ms` and `0.5s` are half a second, and a value with another unit
    /// is refused.
    #[test]
    fn durations_take_milliseconds_and_fractions() {
        for (text, millis) in [
            ("500ms", 500),
            ("0.5s", 500),
            ("10s", 10_000),
            ("10", 10_000),
            ("1.5m", 90_000),
            ("2h", 7_200_000),
            (" 250MS ", 250),
        ] {
            assert_eq!(
                parse_duration(text),
                Ok(Duration::from_millis(millis)),
                "{text}"
            );
        }
        for bad in ["5x", "", "ms", ".s", "1.2.3s", "-1s", "1e3s"] {
            assert!(parse_duration(bad).is_err(), "{bad:?}");
        }
        assert_eq!(duration_arg(Duration::from_millis(500)), "500ms");
        assert_eq!(duration_arg(Duration::from_secs(3)), "3s");
        for value in [Duration::from_millis(1500), Duration::from_secs(30)] {
            assert_eq!(parse_duration(&duration_arg(value)), Ok(value));
        }
    }

    /// A native executable is named as the shim's target image, by absolute
    /// path; a script, whose process runs an interpreter, is not.
    #[test]
    fn native_target_exe_names_only_an_elf_harness() {
        let dir = tmpdir();
        let elf = dir.join("main");
        fs::write(&elf, b"\x7fELF\x02\x01\x01").unwrap();
        let script = dir.join("run.sh");
        fs::write(&script, b"#!/bin/sh\nexec ./main\n").unwrap();
        assert_eq!(native_target_exe(&elf), Some(elf.clone()));
        assert!(native_target_exe(&elf).unwrap().is_absolute());
        assert_eq!(native_target_exe(&script), None);
        assert_eq!(native_target_exe(&dir.join("missing")), None);
    }

    /// Every flag a multi-worker run accepts, but the two the parent carries
    /// out itself, reaches its workers.
    #[test]
    fn every_flag_a_multicore_run_accepts_reaches_its_workers() {
        use crate::runner::SandboxModeArg;
        use crate::runtime_oracles::RuntimeOracleMode;
        let args_dir = tmpdir();
        let mut args = fuzz_args_for_worker_passthrough(&args_dir, StructuredInputMode::Json);
        args.grammar_file = Some(args_dir.join("grammar.json"));
        args.frame_file = Some(args_dir.join("frame.toml"));
        args.dict_file = Some(args_dir.join("tokens.dict"));
        args.cmplog_log = Some(args_dir.join("cmplog.txt"));
        args.len_control = DEFAULT_LEN_CONTROL + 1;
        args.rss_limit_mb = 64;
        args.fork_server = true;
        args.no_fork_server = true;
        args.qemu_user = Some(PathBuf::from("qemu-arm"));
        args.qemu_args = vec!["-L".to_owned()];
        args.symbolic_seed_sources = vec![args_dir.join("p.adb")];
        args.sandbox = SandboxModeArg::None;
        args.sandbox_tool = Some(PathBuf::from("fj"));
        args.sandbox_strict = true;
        args.runtime_oracles = RuntimeOracleMode::On;
        args.seed_inputs = vec!["A".to_owned()];
        args.seed_files = vec![args_dir.join("seed.bin")];
        args.max_len = DEFAULT_MAX_LEN + 1;
        args.timeout = Some(Duration::from_secs(1));
        args.deadline = Some(Duration::from_secs(2));

        let given = given_flags(&args);
        let passthrough = worker_passthrough_args(&args);
        for flag in MULTICORE_FLAGS
            .iter()
            .filter(|flag| !matches!(**flag, "--workers" | "--sanitizers"))
        {
            assert!(given.contains(flag), "this test does not set {flag}");
            assert!(
                passthrough
                    .iter()
                    .any(|arg| arg == flag || arg.starts_with(&format!("{flag}="))),
                "{flag} does not reach the workers: {passthrough:?}"
            );
        }
        for (flag, value) in [
            ("--runtime-oracles", "on"),
            ("--deadline", "2s"),
            (
                "--dict",
                &*args_dir.join("tokens.dict").display().to_string(),
            ),
        ] {
            assert!(
                passthrough
                    .windows(2)
                    .any(|pair| pair[0] == flag && pair[1] == value),
                "{flag} {value}: {passthrough:?}"
            );
        }
        assert!(multicore_flag_conflict(&args).is_none());
    }

    /// A flag whose output the merge would not carry back is refused, by
    /// name, for a multi-worker run and a sanitizer matrix.
    #[test]
    fn a_multicore_run_refuses_the_flags_its_workers_would_ignore() {
        use crate::runtime_oracles::RuntimeOracleMode;
        let args_dir = tmpdir();
        let mut args = fuzz_args_for_worker_passthrough(&args_dir, StructuredInputMode::Auto);
        args.workers = Some(FuzzWorkerCount::Fixed(2));
        args.runtime_oracles = RuntimeOracleMode::On;
        assert_eq!(multicore_flag_conflict(&args), None);

        args.collector = crate::collector_run::parse_collector_spec("auto").unwrap();
        let error = multicore_flag_conflict(&args).expect("--collector is refused");
        assert!(
            error.starts_with("bhf fuzz: --collector does not apply to --workers"),
            "{error}"
        );

        args.print_final_stats = true;
        args.workers = None;
        args.sanitizers = vec!["asan".to_owned(), "ubsan".to_owned()];
        let error = multicore_flag_conflict(&args).expect("both are refused");
        assert!(
            error.starts_with(
                "bhf fuzz: --print-final-stats, --collector do not apply to a sanitizer matrix"
            ),
            "{error}"
        );
    }

    #[test]
    fn multicore_workers_receive_seed_bytes_as_byte_exact_seed_files() {
        let args_dir = tmpdir();
        let mut args = fuzz_args_for_worker_passthrough(&args_dir, StructuredInputMode::Auto);
        let seed = non_utf8_seed();
        args.seed_bytes = vec![seed.clone()];
        materialize_seed_bytes(&mut args).unwrap();
        assert!(args.seed_bytes.is_empty());

        let passthrough = worker_passthrough_args(&args);
        // bhf's copy, so not a seed given to the worker (`--seed-file`).
        let files: Vec<&String> = passthrough
            .windows(2)
            .filter(|pair| pair[0] == "--campaign-seed-file")
            .map(|pair| &pair[1])
            .collect();
        assert_eq!(files.len(), 1, "{passthrough:?}");
        assert_eq!(fs::read(files[0]).unwrap(), seed);
        assert!(
            !passthrough.iter().any(|a| a == "--seed-file"),
            "{passthrough:?}"
        );
        assert!(
            !passthrough.iter().any(|a| a == "--seed-input"),
            "raw bytes never travel as a UTF-8 --seed-input: {passthrough:?}"
        );
    }

    #[test]
    fn workers_mirror_every_harness_layout_dir_the_lookup_reads() {
        // Dirs the parent lacks are listed too: the mirror removes a worker's
        // copy of them, so it cannot outrank the harness the parent resolved.
        let work = tmpdir();
        fs::create_dir_all(work.join("harnesses/H-L")).unwrap();
        let (dirs, executable) =
            worker_harness_layout(&work, "H-L", &work.join("harnesses/H-L/main"));
        assert_eq!(
            dirs,
            vec![
                PathBuf::from("build/H-L"),
                PathBuf::from("harnesses/H-L"),
                PathBuf::from("auto/H-L"),
                PathBuf::from("generated_harnesses/H-L")
            ]
        );
        assert_eq!(executable, Some(PathBuf::from("harnesses/H-L/main")));
    }

    #[test]
    fn a_campaign_fails_only_when_its_workers_failed_or_brought_nothing_back() {
        let worker = |worker_id: u32, exit_code: Option<i32>| multicore_fuzz::WorkerReport {
            worker_id,
            exit_code,
            ..multicore_fuzz::WorkerReport::default()
        };
        let stopped = |worker_id: u32, new_findings: usize| multicore_fuzz::WorkerReport {
            stopped_at_deadline: true,
            new_findings,
            ..worker(worker_id, None)
        };
        let summary =
            |per_worker: Vec<multicore_fuzz::WorkerReport>| multicore_fuzz::MulticoreSummary {
                harness_id: "H".to_owned(),
                workers_started: per_worker.len() as u32,
                workers_completed: per_worker.iter().filter(|w| w.completed()).count() as u32,
                total_findings: 0,
                unique_findings: 0,
                campaign_dir: PathBuf::new(),
                sync_manifest_path: PathBuf::new(),
                sync: multicore_fuzz::CorpusSyncReport {
                    shared_queue: PathBuf::new(),
                    seed_inputs_loaded: 0,
                    imported_inputs: 0,
                    duplicate_inputs: 0,
                    unchecked_inputs: 0,
                },
                per_worker,
                dropped_duplicates: 0,
            };
        let exit = |per_worker| no_worker_completed(&summary(per_worker));
        // Every worker failed the same way: keep its exit code.
        let failed = exit(vec![worker(0, Some(3)), worker(1, Some(3))]).unwrap();
        assert_eq!(
            failed,
            NoWorkerCompleted::Failed {
                exit_code: 3,
                recorded: 0
            }
        );
        assert_eq!(incomplete_campaign_exit(failed, 0), 3);
        // Mixed failures, or a worker killed by a signal: 1.
        for per_worker in [
            vec![worker(0, Some(3)), worker(1, Some(2))],
            vec![worker(0, Some(3)), worker(1, None)],
        ] {
            let outcome = exit(per_worker).unwrap();
            assert_eq!(incomplete_campaign_exit(outcome, 0), 1, "{outcome:?}");
        }
        // Workers failing after they recorded something still fail.
        let late = multicore_fuzz::WorkerReport {
            new_findings: 1,
            ..worker(1, Some(4))
        };
        let outcome = exit(vec![worker(0, Some(4)), late]).unwrap();
        assert_eq!(
            outcome,
            NoWorkerCompleted::Failed {
                exit_code: 4,
                recorded: 1
            }
        );
        // Stopped at the time limit after recording findings: the campaign
        // fuzzed and keeps the merge's code.
        let outcome = exit(vec![stopped(0, 1), stopped(1, 0)]).unwrap();
        assert_eq!(
            outcome,
            NoWorkerCompleted::Stopped {
                stopped: 2,
                recorded: 1
            }
        );
        assert_eq!(incomplete_campaign_exit(outcome, 0), 0);
        // Stopped, and nothing came back.
        let outcome = exit(vec![worker(0, Some(3)), stopped(1, 0)]).unwrap();
        assert_eq!(
            outcome,
            NoWorkerCompleted::Stopped {
                stopped: 1,
                recorded: 0
            }
        );
        assert_eq!(incomplete_campaign_exit(outcome, 0), 1);
        // One completed worker is a campaign that ran.
        assert_eq!(exit(vec![worker(0, Some(3)), worker(1, Some(0))]), None);
    }

    #[test]
    fn worker_passthrough_includes_len_control() {
        let args_dir = tmpdir();
        let mut args = fuzz_args_for_worker_passthrough(&args_dir, StructuredInputMode::Auto);
        args.len_control = 7;
        let passthrough = worker_passthrough_args(&args);
        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--len-control" && pair[1] == "7"));
    }

    #[test]
    fn progress_lines_come_two_seconds_in_then_at_doubling_gaps_up_to_thirty_seconds() {
        let lines = ProgressLines::new();
        let at = |secs: u64| {
            lines.line(&FuzzTick {
                executions: 400 * secs as usize,
                findings: 1,
                edges: 37,
                corpus: 5,
                elapsed: Duration::from_secs(secs),
                stability_pct: None,
            })
        };
        assert_eq!(at(1), None);
        let first = at(2).expect("a line 2s in");
        assert_eq!(
            first,
            "bhf: fuzz: 800 execs (400/s) | corpus: 5 | findings: 1 | edges: 37 | elapsed: 2.0s"
        );
        assert_eq!(at(3), None);
        assert!(at(4).is_some());
        assert_eq!(at(7), None);
        assert!(at(8).is_some());
        assert!(at(16).is_some());
        assert!(at(32).is_some());
        // From here at most 30s apart.
        assert_eq!(at(61), None);
        assert!(at(62).is_some());
        assert!(at(92).is_some());
    }

    /// Once an entry was calibrated (#232), the status line gives stability.
    #[test]
    fn the_progress_line_gives_stability_once_measured() {
        let line = format_progress_line(&FuzzTick {
            executions: 800,
            findings: 0,
            edges: 37,
            corpus: 5,
            elapsed: Duration::from_secs(2),
            stability_pct: Some(41.7),
        });
        assert_eq!(
            line,
            "bhf: fuzz: 800 execs (400/s) | corpus: 5 | findings: 0 | edges: 37 | stability: 41.7% \
             | elapsed: 2.0s"
        );
    }

    #[test]
    fn workers_run_quiet() {
        let args_dir = tmpdir();
        let args = fuzz_args_for_worker_passthrough(&args_dir, StructuredInputMode::Auto);
        assert!(worker_passthrough_args(&args).contains(&"--quiet".to_owned()));
    }

    #[test]
    fn final_stats_line_reports_execs_rate_corpus_findings() {
        let line = format_final_stats(1000, 12, 988, 3, Duration::from_secs(2));
        assert!(line.contains("execs: 1000 (500/s)"), "{line}");
        assert!(line.contains("corpus: 12 new, 988 dup"), "{line}");
        assert!(line.contains("findings: 3"), "{line}");
        assert!(line.contains("elapsed: 2.0s"), "{line}");
    }

    #[test]
    fn mutator_config_honors_max_len() {
        assert_eq!(mutator_config(StructuredInputMode::Auto, 64).max_len, 64);
        assert_eq!(
            mutator_config(StructuredInputMode::Auto, DEFAULT_MAX_LEN).max_len,
            DEFAULT_MAX_LEN
        );
    }

    #[test]
    fn worker_passthrough_includes_max_len() {
        let args_dir = tmpdir();
        let mut args = fuzz_args_for_worker_passthrough(&args_dir, StructuredInputMode::Auto);
        args.max_len = 128;
        let passthrough = worker_passthrough_args(&args);
        assert!(
            passthrough
                .windows(2)
                .any(|pair| pair[0] == "--max-len" && pair[1] == "128"),
            "workers must inherit --max-len: {passthrough:?}"
        );
    }

    #[test]
    fn worker_passthrough_preserves_structured_input_mode() {
        let args_dir = tmpdir();
        let args = fuzz_args_for_worker_passthrough(&args_dir, StructuredInputMode::Record);

        let passthrough = worker_passthrough_args(&args);

        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--structured-inputs" && pair[1] == "record"));
    }

    #[test]
    fn worker_passthrough_preserves_structured_json_mode() {
        let args_dir = tmpdir();
        let args = fuzz_args_for_worker_passthrough(&args_dir, StructuredInputMode::Json);

        let passthrough = worker_passthrough_args(&args);

        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--structured-inputs" && pair[1] == "json"));
    }

    #[test]
    fn worker_passthrough_preserves_structured_xml_mode() {
        let args_dir = tmpdir();
        let args = fuzz_args_for_worker_passthrough(&args_dir, StructuredInputMode::Xml);

        let passthrough = worker_passthrough_args(&args);

        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--structured-inputs" && pair[1] == "xml"));
    }

    #[test]
    fn worker_passthrough_preserves_structured_key_value_mode() {
        let args_dir = tmpdir();
        let args = fuzz_args_for_worker_passthrough(&args_dir, StructuredInputMode::Kv);

        let passthrough = worker_passthrough_args(&args);

        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--structured-inputs" && pair[1] == "kv"));
    }

    #[test]
    fn worker_passthrough_preserves_structured_url_encoded_mode() {
        let args_dir = tmpdir();
        let args = fuzz_args_for_worker_passthrough(&args_dir, StructuredInputMode::Url);

        let passthrough = worker_passthrough_args(&args);

        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--structured-inputs" && pair[1] == "url"));
    }

    #[test]
    fn worker_passthrough_preserves_structured_multipart_mode() {
        let args_dir = tmpdir();
        let args = fuzz_args_for_worker_passthrough(&args_dir, StructuredInputMode::Multipart);

        let passthrough = worker_passthrough_args(&args);

        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--structured-inputs" && pair[1] == "multipart"));
    }

    #[test]
    fn worker_passthrough_preserves_structured_csv_mode() {
        let args_dir = tmpdir();
        let args = fuzz_args_for_worker_passthrough(&args_dir, StructuredInputMode::Csv);

        let passthrough = worker_passthrough_args(&args);

        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--structured-inputs" && pair[1] == "csv"));
    }

    #[test]
    fn worker_passthrough_preserves_structured_http_mode() {
        let args_dir = tmpdir();
        let args = fuzz_args_for_worker_passthrough(&args_dir, StructuredInputMode::Http);

        let passthrough = worker_passthrough_args(&args);

        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--structured-inputs" && pair[1] == "http"));
    }

    #[test]
    fn worker_passthrough_preserves_structured_ini_mode() {
        let args_dir = tmpdir();
        let args = fuzz_args_for_worker_passthrough(&args_dir, StructuredInputMode::Ini);

        let passthrough = worker_passthrough_args(&args);

        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--structured-inputs" && pair[1] == "ini"));
    }

    #[test]
    fn worker_passthrough_preserves_structured_toml_mode() {
        let args_dir = tmpdir();
        let args = fuzz_args_for_worker_passthrough(&args_dir, StructuredInputMode::Toml);

        let passthrough = worker_passthrough_args(&args);

        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--structured-inputs" && pair[1] == "toml"));
    }

    #[test]
    fn worker_passthrough_preserves_structured_yaml_mode() {
        let args_dir = tmpdir();
        let args = fuzz_args_for_worker_passthrough(&args_dir, StructuredInputMode::Yaml);

        let passthrough = worker_passthrough_args(&args);

        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--structured-inputs" && pair[1] == "yaml"));
    }

    #[test]
    fn runtrace_cursor_reads_only_appended_events() {
        let root = tmpdir();
        let log = root.join("runtrace.jsonl");
        fs::write(&log, "").unwrap();
        let mut cursor = RuntraceLogCursor::from_extra_env(&[(
            "BHF_RUNTRACE_LOG".to_owned(),
            log.display().to_string(),
        )]);

        fs::write(
            &log,
            "{\"e\":\"open\",\"p\":\"../secret\",\"r\":-1,\"n\":2}\n",
        )
        .unwrap();
        let first = cursor.read_new_events();
        assert_eq!(first.len(), 1);
        assert!(matches!(
            &first[0],
            crate::auto::runtrace::RuntraceEvent::FileMissing { path, .. }
                if path == "../secret"
        ));

        assert!(cursor.read_new_events().is_empty());
        fs::OpenOptions::new()
            .append(true)
            .open(&log)
            .unwrap()
            .write_all(b"{\"e\":\"getenv\",\"n\":\"ACME_HOME\",\"r\":null}\n")
            .unwrap();
        let second = cursor.read_new_events();
        assert_eq!(
            second,
            vec![crate::auto::runtrace::RuntraceEvent::EnvVarMissing {
                api: "getenv".to_owned(),
                name: "ACME_HOME".to_owned(),
            }]
        );
    }

    #[test]
    #[cfg(unix)]
    fn builtin_fuzz_emits_oracle_finding_from_runtrace_event() {
        use std::os::unix::fs::PermissionsExt;

        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        let harness_id = "H-ORACLE";
        let harness_dir = work_dir.join("build").join(harness_id);
        fs::create_dir_all(&harness_dir).unwrap();
        let harness = harness_dir.join("main");
        fs::write(
            &harness,
            "#!/bin/sh\n\
             input=$(cat)\n\
             if [ -n \"$BHF_RUNTRACE_LOG\" ]; then\n\
               printf '{\"e\":\"open\",\"p\":\"%s\",\"r\":-1,\"n\":2}\\n' \"$input\" >> \"$BHF_RUNTRACE_LOG\"\n\
             fi\n\
             exit 0\n",
        )
        .unwrap();
        let mut perms = fs::metadata(&harness).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&harness, perms).unwrap();
        let runtrace_log = root.join("runtrace.jsonl");

        // The harness is a shell subprocess. Under heavy parallel test load (the
        // full `cargo test --workspace` runs ~16 test binaries at once) it can be
        // starved past the 10s per-input timeout (PER_INPUT_TIMEOUT) and get killed,
        // yielding a no-event (0-finding) run. The fuzz logic here is deterministic
        // (iterations=1 over a fixed seed), so retry the transient-starvation case
        // with generous headroom; a persistent 0 across all attempts is a real
        // regression. Each non-starved attempt returns in well under a second, so
        // the retries cost wall-clock only on the (rare) starved path.
        let do_run = || {
            fs::write(&runtrace_log, "").unwrap();
            run_one_target_programmatic(
                &work_dir,
                harness_id,
                vec![b"../secret".to_vec()],
                1,
                None,
                None,
                0,
                &[(
                    "BHF_RUNTRACE_LOG".to_owned(),
                    runtrace_log.display().to_string(),
                )],
                actionability::RunMode::Reporting,
                None, // cmplog_log
                &[],
                None,
            )
            .unwrap()
        };
        let mut summary = do_run();
        for _ in 0..15 {
            if !summary.findings.is_empty() {
                break;
            }
            summary = do_run();
        }

        assert_eq!(
            summary.findings.len(),
            1,
            "expected exactly one oracle finding after retries (transient subprocess \
             starvation should not persist): {:?}",
            summary.findings
        );
        let finding_dir = work_dir
            .join("results")
            .join("findings")
            .join(&summary.findings[0]);
        let finding: serde_json::Value =
            serde_json::from_slice(&fs::read(finding_dir.join("finding.json")).unwrap()).unwrap();
        assert_eq!(finding["classification"], "oracle_hit");
        assert_eq!(finding["rule_id"], "BHF-101");
        assert_eq!(finding["oracle"]["name"], "path-traversal-ada");
        assert_eq!(finding["oracle"]["api"], "open");
        assert_eq!(finding["oracle"]["evidence"][0]["value"], "../secret");
        assert_eq!(
            fs::read(finding_dir.join("testcase.bin")).unwrap(),
            b"../secret"
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_crash_matching_a_recorded_sanitizer_finding_is_reported_not_dropped() {
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        write_c_libfuzzer_harness(
            &work_dir,
            "H-DUP",
            "#!/bin/sh\n\
             if [ \"$(head -c1 \"$1\")\" = A ]; then\n\
               >&2 echo 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x501 at pc 0x111'\n\
               >&2 echo '    #0 0x111 in parse_record /src/record.c:10'\n\
               >&2 echo '    #1 0x112 in LLVMFuzzerTestOneInput /src/h.c:20'\n\
               exit 1\n\
             fi\n\
             exit 0\n",
        );
        let run = || {
            run_one_target_programmatic(
                &work_dir,
                "H-DUP",
                vec![b"A".to_vec(), b"AB".to_vec()],
                2,
                None,
                None,
                0,
                &[],
                actionability::RunMode::Reporting,
                None,
                &[],
                None,
            )
            .unwrap()
        };
        let first = run();
        assert_eq!(first.findings.len(), 1, "{:?}", first.findings);
        assert!(first.duplicates_of_existing.is_empty());

        let second = run();
        assert!(second.findings.is_empty(), "{:?}", second.findings);
        assert_eq!(second.duplicates_of_existing, first.findings);
        assert!(second.duplicate_crashes_of_existing >= 2);
        let note = duplicates_of_existing_note(
            &second.duplicates_of_existing,
            second.duplicate_crashes_of_existing,
            &second.harness_id,
        )
        .expect("a note");
        assert!(note.contains(&first.findings[0]), "{note}");
        assert!(note.contains("H-DUP"), "{note}");
    }

    #[test]
    #[cfg(unix)]
    fn an_oracle_hit_matching_a_recorded_finding_is_reported_not_dropped() {
        use std::os::unix::fs::PermissionsExt;

        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        let harness_dir = work_dir.join("build").join("H-ODUP");
        fs::create_dir_all(&harness_dir).unwrap();
        let harness = harness_dir.join("main");
        fs::write(
            &harness,
            "#!/bin/sh\n\
             input=$(cat)\n\
             if [ -n \"$BHF_RUNTRACE_LOG\" ]; then\n\
               printf '{\"e\":\"open\",\"p\":\"%s\",\"r\":-1,\"n\":2}\\n' \"$input\" >> \"$BHF_RUNTRACE_LOG\"\n\
             fi\n\
             exit 0\n",
        )
        .unwrap();
        fs::set_permissions(&harness, fs::Permissions::from_mode(0o755)).unwrap();
        let runtrace_log = root.join("runtrace.jsonl");
        let run = || {
            fs::write(&runtrace_log, "").unwrap();
            run_one_target_programmatic(
                &work_dir,
                "H-ODUP",
                vec![b"../secret".to_vec()],
                1,
                None,
                None,
                0,
                &[(
                    "BHF_RUNTRACE_LOG".to_owned(),
                    runtrace_log.display().to_string(),
                )],
                actionability::RunMode::Reporting,
                None,
                &[],
                None,
            )
            .unwrap()
        };
        // A starved shell subprocess can miss its event (see
        // builtin_fuzz_emits_oracle_finding_from_runtrace_event); retry that case.
        let mut first = run();
        for _ in 0..15 {
            if !first.findings.is_empty() {
                break;
            }
            first = run();
        }
        assert_eq!(first.findings.len(), 1, "{:?}", first.findings);
        let mut second = run();
        for _ in 0..15 {
            if !second.duplicates_of_existing.is_empty() {
                break;
            }
            second = run();
        }
        assert!(second.findings.is_empty(), "{:?}", second.findings);
        assert_eq!(second.duplicates_of_existing, first.findings);
    }

    #[cfg(unix)]
    fn write_c_libfuzzer_harness(work_dir: &Path, id: &str, script: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = work_dir.join("build").join(id);
        fs::create_dir_all(&dir).unwrap();
        // The sibling main.c is what is_c_libfuzzer_harness() keys on.
        fs::write(dir.join("main.c"), "// marker for libFuzzer detection\n").unwrap();
        let harness = dir.join("main");
        fs::write(&harness, script).unwrap();
        fs::set_permissions(&harness, fs::Permissions::from_mode(0o755)).unwrap();
        harness
    }

    #[test]
    fn protocol_resolution_prefers_framed_marker_across_build_and_generated_layouts() {
        let work = tmpdir();
        let id = "H-PROTOCOL";
        let build = work.join("build").join(id);
        let generated = work.join("generated_harnesses").join(id);
        fs::create_dir_all(&build).unwrap();
        fs::create_dir_all(&generated).unwrap();
        let binary = build.join("main");
        fs::write(&binary, b"\x7fELF\0not textual BHF_FRAMED").unwrap();
        fs::write(build.join("main.c"), "// stale libFuzzer source\n").unwrap();
        fs::write(
            generated.join("main.c"),
            "int LLVMFuzzerTestOneInput(void); // BHF_FRAMED loop\n",
        )
        .unwrap();
        let runner = replay_min::HarnessRunner::direct(binary.clone());

        assert!(read_bounded_marker_text(&binary, true).is_none());
        assert_eq!(
            resolve_harness_protocol(&runner, &work),
            HarnessProtocol::BhfFramed
        );
        assert_eq!(
            builtin_execution_summary(HarnessProtocol::BhfFramed, true).harness_protocol,
            "bhf_framed"
        );
    }

    #[test]
    fn protocol_resolution_preserves_auto_scripts_libfuzzer_and_stdin_layouts() {
        let work = tmpdir();
        let auto_dir = work.join("harnesses/H-AUTO");
        fs::create_dir_all(&auto_dir).unwrap();
        let auto_binary = auto_dir.join("main");
        fs::write(&auto_binary, b"\x7fELF\0").unwrap();
        fs::write(auto_dir.join("main.cpp"), "// BHF_FRAMED driver\n").unwrap();
        assert_eq!(
            resolve_harness_protocol(&replay_min::HarnessRunner::direct(auto_binary), &work),
            HarnessProtocol::BhfFramed
        );

        let script_dir = work.join("auto/H-SCRIPT");
        fs::create_dir_all(&script_dir).unwrap();
        let script = script_dir.join("main");
        fs::write(&script, "#!/bin/sh\n# BHF_FRAMED launcher\n").unwrap();
        assert_eq!(
            resolve_harness_protocol(&replay_min::HarnessRunner::direct(script), &work),
            HarnessProtocol::BhfFramed
        );

        let lib_dir = work.join("build/H-LIB");
        fs::create_dir_all(&lib_dir).unwrap();
        let lib_binary = lib_dir.join("main");
        fs::write(&lib_binary, b"\x7fELF\0").unwrap();
        fs::write(
            lib_dir.join("main.c"),
            "int LLVMFuzzerTestOneInput(const unsigned char *, unsigned long);\n",
        )
        .unwrap();
        assert_eq!(
            resolve_harness_protocol(&replay_min::HarnessRunner::direct(lib_binary), &work),
            HarnessProtocol::LibFuzzerSingleInput
        );

        let plain = work.join("build/H-PLAIN/main");
        fs::create_dir_all(plain.parent().unwrap()).unwrap();
        fs::write(
            &plain,
            vec![0u8; MAX_HARNESS_MARKER_TEXT_BYTES as usize + 1],
        )
        .unwrap();
        assert!(read_bounded_marker_text(&plain, true).is_none());
        assert_eq!(
            resolve_harness_protocol(&replay_min::HarnessRunner::direct(plain), &work),
            HarnessProtocol::StdinEventLog
        );
    }

    /// A binary with `marker` compiled in, past the first 4 KiB.
    fn binary_with(marker: &[u8]) -> Vec<u8> {
        let mut bytes = b"\x7fELF\x02\x01\x01\0".to_vec();
        bytes.resize(64 * 1024, 0);
        bytes.extend_from_slice(marker);
        bytes
    }

    /// A bhf driver binary staged alone (no `main.c`/`main.cpp` anywhere) still
    /// gets the framed protocol, and with it the coverage map.
    #[test]
    fn protocol_resolution_reads_the_marker_compiled_into_a_staged_binary() {
        let work = tmpdir();
        let dir = work.join("build/H-PREBUILT");
        fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("main");
        fs::write(&binary, binary_with(b"BHF_FRAMED\0BHF_COV_SHM\0")).unwrap();
        assert_eq!(
            resolve_harness_protocol(&replay_min::HarnessRunner::direct(binary), &work),
            HarnessProtocol::BhfFramed
        );
    }

    /// A hand-compiled `-fsanitize=fuzzer` binary takes one input file per
    /// process; on stdin it would run libFuzzer's own loop.
    #[test]
    fn protocol_resolution_runs_a_libfuzzer_binary_on_one_input_file() {
        let work = tmpdir();
        let dir = work.join("build/H-LF");
        fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("main");
        fs::write(
            &binary,
            binary_with(b"INFO: libFuzzer ignores flags that start with '--'\0"),
        )
        .unwrap();
        assert_eq!(
            resolve_harness_protocol(&replay_min::HarnessRunner::direct(binary), &work),
            HarnessProtocol::LibFuzzerSingleInput
        );
    }

    /// A multi-worker campaign's parent prints the libFuzzer-binary note
    /// itself (its workers' stderr goes to their logs), for the builtin
    /// engine only, which is the one that runs such a binary on one input.
    #[test]
    fn a_multicore_campaign_notes_a_libfuzzer_binary_once() {
        let args_dir = tmpdir();
        let mut args = fuzz_args_for_worker_passthrough(&args_dir, StructuredInputMode::Auto);
        let dir = args.work_dir.join("build/H-X");
        fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("main");
        fs::write(&binary, binary_with(b"libFuzzer ignores flags\0")).unwrap();
        let notes = multicore_harness_notes(&args, &binary);
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(
            notes[0].contains("--target LLVMFuzzerTestOneInput"),
            "{notes:?}"
        );
        args.engine = FuzzEngine::AflPlusPlus;
        assert!(multicore_harness_notes(&args, &binary).is_empty());
        args.engine = FuzzEngine::Builtin;
        fs::write(&binary, binary_with(b"BHF_FRAMED\0")).unwrap();
        assert!(multicore_harness_notes(&args, &binary).is_empty());
    }

    /// The operator is told why a libFuzzer binary gets no coverage and how to
    /// wrap it; a bhf harness gets no such note.
    #[test]
    fn libfuzzer_binary_note_names_the_wrapping_command() {
        let work = tmpdir();
        let dir = work.join("build/H-LFNOTE");
        fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("main");
        fs::write(&binary, binary_with(b"libFuzzer ignores flags\0")).unwrap();
        let detection = crate::protocol_detect::detect(&binary, &[&work]);
        let note = libfuzzer_binary_note(&detection, &binary).expect("note");
        assert!(note.contains("without coverage guidance"), "{note}");
        assert!(note.contains("--target LLVMFuzzerTestOneInput"), "{note}");
        // A bhf driver source in the work dir is not what this binary runs.
        let sources = work.join("harnesses/H-LFNOTE");
        fs::create_dir_all(&sources).unwrap();
        fs::write(sources.join("main.cpp"), "// BHF_FRAMED driver\n").unwrap();
        let detection = crate::protocol_detect::detect(&binary, &[&work]);
        assert!(
            libfuzzer_binary_note(&detection, &binary).is_some(),
            "{detection:?}"
        );
        fs::write(&binary, binary_with(b"BHF_FRAMED\0")).unwrap();
        let detection = crate::protocol_detect::detect(&binary, &[&work]);
        assert!(libfuzzer_binary_note(&detection, &binary).is_none());
    }

    /// A `bhf.project.v1` native target declares the framed input mode; the
    /// fuzz lane uses it instead of guessing from a stripped binary.
    #[test]
    fn protocol_resolution_honours_a_declared_framed_input_mode() {
        let work = tmpdir();
        let dir = work.join("build/attrs");
        fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("main");
        fs::write(&binary, b"\x7fELF\0stripped").unwrap();
        fs::write(
            dir.join("harness-protocol.json"),
            r#"{"schema_version":1,"input_mode":"framed"}"#,
        )
        .unwrap();
        assert_eq!(
            resolve_harness_protocol(&replay_min::HarnessRunner::direct(binary), &work),
            HarnessProtocol::BhfFramed
        );
    }

    #[test]
    #[cfg(unix)]
    fn passthrough_libfuzzer_glue_crash_is_not_reported() {
        // A passthrough libFuzzer harness that SEGVs entirely inside ASan /
        // libFuzzer driver glue (no target frame) — the cJSON class from #388.
        // Without the driver-glue filter this floods the user with phantom
        // findings; ground truth (libFuzzer/AFL) is zero.
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        write_c_libfuzzer_harness(
            &work_dir,
            "H-GLUE",
            "#!/bin/sh\n\
             >&2 echo 'ERROR: AddressSanitizer: SEGV on unknown address 0xfffffffffffffff1'\n\
             >&2 echo '    #0 0x1 in __asan::Allocator::Deallocate /asan/a.cpp:1'\n\
             >&2 echo '    #1 0x2 in free /asan/i.cpp:2'\n\
             >&2 echo '    #2 0x3 in fuzzer::RunOneTest /fuzzer/d.cpp:3'\n\
             exit 1\n",
        );

        let summary = run_one_target_programmatic(
            &work_dir,
            "H-GLUE",
            vec![b"seed".to_vec()],
            8,
            None,
            None,
            0,
            &[],
            actionability::RunMode::Reporting,
            None, // cmplog_log
            &[],
            None,
        )
        .unwrap();

        assert_eq!(
            summary.findings.len(),
            0,
            "a crash with no target frame (driver glue) must not be reported"
        );
    }

    /// A libFuzzer harness bhf did not generate (no generation metadata):
    /// its `LLVMFuzzerTestOneInput` is the project's fuzz target, so a crash
    /// in its body is a finding, not driver glue.
    #[test]
    #[cfg(unix)]
    fn a_crash_in_an_external_libfuzzer_entry_is_reported() {
        let script = "#!/bin/sh\n\
             >&2 echo 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000031 at pc 0x1 bp 0x2 sp 0x3'\n\
             >&2 echo 'WRITE of size 1 at 0x602000000031 thread T0'\n\
             >&2 echo '    #0 0x1 in LLVMFuzzerTestOneInput /src/f.c:9:5'\n\
             >&2 echo '    #1 0x2 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /fuzzer/d.cpp:3'\n\
             >&2 echo 'SUMMARY: AddressSanitizer: heap-buffer-overflow /src/f.c:9:5 in LLVMFuzzerTestOneInput'\n\
             exit 1\n";
        let findings = |generated: bool| {
            let root = tmpdir();
            let work_dir = root.join("bhf_work");
            let harness = write_c_libfuzzer_harness(&work_dir, "H-ENTRY", script);
            if generated {
                // bhf generated this harness around a target of its own, so
                // its LLVMFuzzerTestOneInput is bhf's driver code.
                fs::write(
                    harness.parent().unwrap().join("generation-metadata.json"),
                    r#"{"schema_version":1,"language":"c","target_function":"parse_record"}"#,
                )
                .unwrap();
            }
            run_one_target_programmatic(
                &work_dir,
                "H-ENTRY",
                vec![b"seed".to_vec()],
                8,
                None,
                None,
                0,
                &[],
                actionability::RunMode::Reporting,
                None, // cmplog_log
                &[],
                None,
            )
            .unwrap()
            .findings
            .len()
        };
        assert_eq!(
            findings(false),
            1,
            "a crash in the project's own fuzz entry is a finding"
        );
        assert_eq!(
            findings(true),
            0,
            "a crash in bhf's own entry with no target frame is driver glue"
        );
    }

    /// Findings of a run whose harness is bhf's passthrough driver (no
    /// generation metadata, as the Fortran and COBOL lanes build it) and which
    /// reports a leak allocated in `LLVMFuzzerTestOneInput`, in `entry_file`
    /// (`None`: a frame that names no source file), with `glue` written beside
    /// the driver.
    #[cfg(unix)]
    fn glue_entry_leak_findings(glue: Option<(&str, String)>, entry_file: Option<&str>) -> usize {
        let entry = match entry_file {
            Some(file) => format!("LLVMFuzzerTestOneInput {file}:12:3"),
            None => "LLVMFuzzerTestOneInput (/w/build/H-GLUE/main+0x1234)".to_owned(),
        };
        let script = format!(
            "#!/bin/sh\n\
             >&2 echo '==1==ERROR: LeakSanitizer: detected memory leaks'\n\
             >&2 echo ''\n\
             >&2 echo 'Direct leak of 16 byte(s) in 1 object(s) allocated from:'\n\
             >&2 echo '    #0 0x1 in malloc'\n\
             >&2 echo '    #1 0x2 in {entry}'\n\
             >&2 echo '    #2 0x3 in bhf_run_one_bytes /rt/bhf_driver.c:88:5'\n\
             >&2 echo '    #3 0x4 in main /rt/bhf_driver.c:120:5'\n\
             >&2 echo ''\n\
             >&2 echo 'SUMMARY: AddressSanitizer: 16 byte(s) leaked in 1 allocation(s).'\n\
             exit 23\n"
        );
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        let harness = write_c_libfuzzer_harness(&work_dir, "H-GLUE", &script);
        let dir = harness.parent().unwrap();
        fs::write(
            dir.join("main.c"),
            "/* bhf driver for a passthrough libFuzzer entrypoint. */\n",
        )
        .unwrap();
        if let Some((name, source)) = glue {
            fs::write(dir.join(name), source).unwrap();
        }
        run_one_target_programmatic(
            &work_dir,
            "H-GLUE",
            vec![b"seed".to_vec()],
            8,
            None,
            None,
            0,
            &[],
            actionability::RunMode::Reporting,
            None, // cmplog_log
            &[],
            None,
        )
        .unwrap()
        .findings
        .len()
    }

    /// The Fortran lane calls the routine through an `LLVMFuzzerTestOneInput`
    /// glue of bhf's own. A leak of a buffer that glue allocated (a Fortran
    /// `STOP` ended the process before the glue's free) is bhf's, not the
    /// target's, whether the report names the glue file or the glue says so.
    #[test]
    #[cfg(unix)]
    fn a_leak_in_the_fortran_glue_entry_is_not_a_finding() {
        let glue = crate::auto::fortran_build::glue_source(
            "scan_",
            &[],
            crate::auto::fortran::FortranResult::NonChar,
            false,
        );
        assert_eq!(
            glue_entry_leak_findings(None, Some("/w/harnesses/H-GLUE/fortran_glue.c")),
            0,
            "a leak in the glue file is bhf's"
        );
        assert_eq!(
            glue_entry_leak_findings(Some(("fortran_glue.c", glue)), None),
            0,
            "the glue records that bhf generated the entry"
        );
        assert_eq!(
            glue_entry_leak_findings(None, Some("/src/fuzz/f.c")),
            1,
            "a project's own fuzz entry still reports its leak"
        );
    }

    /// The COBOL lane's `LLVMFuzzerTestOneInput` glue is bhf's too (a COBOL
    /// program that exits before the glue's free leaves its buffer).
    #[test]
    #[cfg(unix)]
    fn a_leak_in_the_cobol_glue_entry_is_not_a_finding() {
        let glue = crate::auto::cobol_build::multi_param_glue("BLOCKS", &[]);
        assert_eq!(
            glue_entry_leak_findings(None, Some("/w/harnesses/H-GLUE/cobol_glue.c")),
            0,
            "a leak in the glue file is bhf's"
        );
        assert_eq!(
            glue_entry_leak_findings(Some(("cobol_glue.c", glue)), None),
            0,
            "the glue records that bhf generated the entry"
        );
        assert_eq!(
            glue_entry_leak_findings(None, Some("/src/fuzz/f.c")),
            1,
            "a project's own fuzz entry still reports its leak"
        );
    }

    #[test]
    #[cfg(unix)]
    fn per_target_finding_count_stops_after_n_distinct_findings() {
        // A harness that emits TWO distinct sanitizer crash signatures keyed on
        // the first input byte ('A' -> func_a, 'B' -> func_b), each with a real
        // target frame (not driver glue). Seeded with both crashing inputs (seeds
        // run first), so uncapped the run surfaces 2 distinct findings; with
        // `stop_after_findings = Some(1)` the in-process loop breaks the instant
        // the first finding lands -> exactly 1.
        let script = "#!/bin/sh\n\
             b=$(head -c1 \"$1\")\n\
             if [ \"$b\" = A ]; then\n\
               >&2 echo 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x501 at pc 0x111'\n\
               >&2 echo '    #0 0x111 in func_a /src/a.c:10'\n\
               >&2 echo '    #1 0x112 in LLVMFuzzerTestOneInput /src/h.c:20'\n\
               exit 1\n\
             fi\n\
             if [ \"$b\" = B ]; then\n\
               >&2 echo 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502 at pc 0x222'\n\
               >&2 echo '    #0 0x222 in func_b /src/b.c:10'\n\
               >&2 echo '    #1 0x223 in LLVMFuzzerTestOneInput /src/h.c:20'\n\
               exit 1\n\
             fi\n\
             exit 0\n";
        let run = |cap: Option<usize>| {
            let root = tmpdir();
            let work_dir = root.join("bhf_work");
            write_c_libfuzzer_harness(&work_dir, "H-FCAP", script);
            run_one_target_programmatic(
                &work_dir,
                "H-FCAP",
                vec![b"A".to_vec(), b"B".to_vec()],
                50,
                None,
                cap,
                0,
                &[],
                actionability::RunMode::Reporting,
                None,
                &[],
                None,
            )
            .unwrap()
            .findings
            .len()
        };

        assert_eq!(run(None), 2, "uncapped: both distinct findings surface");
        assert_eq!(
            run(Some(1)),
            1,
            "--per-target-finding-count 1 stops the run at the first distinct finding"
        );
    }

    /// Two distinct crashes only fresh processes see, whose background re-run
    /// results come back together while the loop runs a slow input, still
    /// stop a one-finding run at one finding. The crasher left over is kept
    /// for the next pass, and neither is queued.
    #[test]
    #[cfg(unix)]
    fn reruns_that_report_together_do_not_overshoot_the_finding_count() {
        let clang = std::process::Command::new("clang")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success());
        let cpus = std::thread::available_parallelism().map_or(1, |cpus| cpus.get());
        if !clang || cpus < 2 {
            eprintln!("skipping: needs clang and a second CPU");
            return;
        }
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        let dir = work_dir.join("harnesses/H-RCAP");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("target.c"),
            "#include <stdlib.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <time.h>\n\
             static int fresh(void) {\n\
                 static int f = -1;\n\
                 if (f < 0) f = getenv(\"BHF_FRAMED\") == NULL;\n\
                 return f;\n\
             }\n\
             __attribute__((noinline)) int read_past(size_t n) {\n\
                 volatile char *p = malloc(n); int r = p[n + 2]; free((void *)p); return r;\n\
             }\n\
             __attribute__((noinline)) int write_past(size_t n) {\n\
                 volatile char *p = malloc(n); p[n + 3] = 1; free((void *)p); return 0;\n\
             }\n\
             int bhf_run_one(const uint8_t *d, size_t n) {\n\
                 if (n >= 2 && d[0] == 'R' && d[1] == '1' && fresh()) return read_past(n);\n\
                 if (n >= 2 && d[0] == 'R' && d[1] == '2' && fresh()) return write_past(n);\n\
                 if (n >= 1 && d[0] == 'S' && !fresh()) {\n\
                     struct timespec t = { 1, 500000000 };\n\
                     nanosleep(&t, 0);\n\
                 }\n\
                 return 0;\n\
             }\n",
        )
        .unwrap();
        let driver = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime/bhf_driver.c");
        let built = std::process::Command::new("clang")
            .current_dir(&dir)
            .args(["-O1", "-g", "-fsanitize=address"])
            .args(["-fsanitize-coverage=trace-pc-guard,trace-cmp"])
            .args(["-o", "main", "target.c"])
            .arg(&driver)
            .output()
            .unwrap();
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );

        // R1 and R2 are re-run in fresh processes while the fork-server
        // spends 1.5 s on S; both reports are there when the loop picks
        // its re-run results up again.
        let summary = run_one_target_programmatic(
            &work_dir,
            "H-RCAP",
            vec![b"R1".to_vec(), b"R2".to_vec(), b"S".to_vec()],
            1000,
            Some(Duration::from_secs(20)),
            Some(1),
            0,
            &[],
            actionability::RunMode::Reporting,
            None,
            &[],
            None,
        )
        .unwrap();
        assert_eq!(summary.findings.len(), 1, "{:?}", summary.findings);
        let read = |dir: &Path| -> Vec<Vec<u8>> {
            fs::read_dir(dir)
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|entry| fs::read(entry.path()).ok())
                .collect()
        };
        let queued = read(&work_dir.join("corpus/H-RCAP/queue"));
        assert!(
            !queued.iter().any(|input| input == b"R1" || input == b"R2"),
            "a crasher was queued: {queued:?}"
        );
        let pending = read(&work_dir.join("corpus/H-RCAP/unchecked"));
        assert!(
            pending.iter().any(|input| input == b"R1" || input == b"R2"),
            "the crasher left over is kept for the next pass: {pending:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn run_one_target_programmatic_honors_cmplog_log() {
        // #378: a cmplog log passed to the auto fuzz path must be ingested and
        // fed to the mutator (CmpLogRunSummary reflects it), so operands mined
        // in an earlier pass guide later passes.
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        write_c_libfuzzer_harness(&work_dir, "H-CMPLOG", "#!/bin/sh\nexit 0\n");

        // A pre-mined cmplog log with one memcmp operand pair ("MAGIC").
        let cmplog_log = root.join("cmplog.jsonl");
        let magic_hex: String = "MAGIC".bytes().map(|b| format!("{b:02x}")).collect();
        fs::write(
            &cmplog_log,
            format!("{{\"e\":\"cmplog\",\"k\":\"memcmp\",\"a\":\"{magic_hex}\",\"b\":\"{magic_hex}\"}}\n"),
        )
        .unwrap();

        let summary = run_one_target_programmatic(
            &work_dir,
            "H-CMPLOG",
            vec![b"seed".to_vec()],
            4,
            None,
            None,
            0,
            &[],
            actionability::RunMode::Reporting,
            Some(cmplog_log.clone()),
            &[],
            None,
        )
        .unwrap();

        assert!(
            summary.cmplog.enabled,
            "cmplog must be enabled: {:?}",
            summary.cmplog
        );
        assert_eq!(summary.cmplog.status, "loaded");
        assert!(
            summary.cmplog.entries >= 1,
            "cmplog entries: {:?}",
            summary.cmplog
        );
        assert!(
            summary.cmplog.dictionary_tokens >= 1,
            "cmplog dictionary tokens: {:?}",
            summary.cmplog
        );
    }

    #[test]
    #[cfg(unix)]
    fn clean_libfuzzer_harness_yields_no_findings() {
        // Acceptance regression (#388): a known-clean libFuzzer harness yields
        // zero bhf findings, matching libFuzzer/AFL.
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        write_c_libfuzzer_harness(&work_dir, "H-CLEAN", "#!/bin/sh\nexit 0\n");

        let summary = run_one_target_programmatic(
            &work_dir,
            "H-CLEAN",
            vec![b"seed".to_vec()],
            8,
            None,
            None,
            0,
            &[],
            actionability::RunMode::Reporting,
            None, // cmplog_log
            &[],
            None,
        )
        .unwrap();

        assert_eq!(summary.findings.len(), 0);
    }

    #[test]
    #[cfg(unix)]
    fn clean_run_persists_coverage_corpus_even_with_no_findings() {
        // #401 regression: a clean run that raises no classified event must still
        // flush the explored corpus (seeds + coverage-increasing inputs) to
        // corpus/<hid>/queue/, instead of leaving it empty and lost on exit.
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        write_c_libfuzzer_harness(&work_dir, "H-CORPUS", "#!/bin/sh\nexit 0\n");

        let summary = run_one_target_programmatic(
            &work_dir,
            "H-CORPUS",
            vec![b"seed-input".to_vec()],
            8,
            None,
            None,
            0,
            &[],
            actionability::RunMode::Reporting,
            None, // cmplog_log
            &[],
            None,
        )
        .unwrap();

        assert_eq!(summary.findings.len(), 0, "harness is clean");
        assert!(
            summary.corpus_persisted >= 1,
            "no-event run must persist >=1 corpus input, got {}",
            summary.corpus_persisted
        );
        let queue = work_dir.join("corpus/H-CORPUS/queue");
        let files: Vec<_> = fs::read_dir(&queue)
            .expect("queue dir exists")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "bin"))
            .collect();
        assert!(
            !files.is_empty(),
            "corpus/<hid>/queue must be non-empty after a clean coverage-producing run"
        );
        // The seed must be among the persisted corpus.
        let contents: Vec<Vec<u8>> = files.iter().map(|e| fs::read(e.path()).unwrap()).collect();
        assert!(
            contents.iter().any(|c| c == b"seed-input"),
            "the seed must be persisted into the corpus"
        );
    }

    /// A seed that is not valid UTF-8: every byte value, a lone continuation
    /// byte, two bytes that never appear in UTF-8, an embedded NUL and a
    /// truncated multi-byte lead at the very end.
    fn non_utf8_seed() -> Vec<u8> {
        let mut seed: Vec<u8> = (0..=255u8).collect();
        seed.extend_from_slice(&[0x80, 0xff, 0xfe, 0x00, 0x4d, 0x5a, 0x90, 0xc3]);
        seed
    }

    /// A libFuzzer-style harness that reports a sanitizer crash only when its
    /// input is byte-identical to `expected`, so a finding proves the engine ran
    /// that exact input.
    #[cfg(unix)]
    fn write_exact_match_harness(work_dir: &Path, id: &str, expected: &Path) {
        let script = format!(
            "#!/bin/sh\n\
             if cmp -s \"$1\" '{}'; then\n\
               >&2 echo 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x601 at pc 0x333'\n\
               >&2 echo '    #0 0x333 in copy_at /src/record.c:15'\n\
               >&2 echo '    #1 0x334 in LLVMFuzzerTestOneInput /src/h.c:20'\n\
               exit 1\n\
             fi\n\
             exit 0\n",
            expected.display()
        );
        write_c_libfuzzer_harness(work_dir, id, &script);
    }

    /// #331: once a builtin pass's corpus stops growing, its SymCC stage runs
    /// the entries through `main_symcc`, and the input the solver writes runs
    /// in the pass: here the only input on which the harness crashes, which
    /// no mutation of the seed finds in a short pass, becomes a finding. The
    /// run summary says what the stage did.
    #[test]
    #[cfg(unix)]
    fn a_plateaued_pass_runs_the_input_symcc_solves() {
        use std::os::unix::fs::PermissionsExt;
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        let solved: Vec<u8> = (0..24u8).map(|n| n.wrapping_mul(37) ^ 0xa5).collect();
        let expected = root.join("expected.bin");
        fs::write(&expected, &solved).unwrap();
        write_exact_match_harness(&work_dir, "H-SYMCC", &expected);
        let recorded = root.join("recorded");
        fs::create_dir_all(&recorded).unwrap();
        fs::write(recorded.join("000000"), &solved).unwrap();
        let solver = work_dir.join("build/H-SYMCC/main_symcc");
        fs::write(
            &solver,
            format!(
                "#!/bin/sh\ncp '{}'/* \"$SYMCC_OUTPUT_DIR\"/\n",
                recorded.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&solver, fs::Permissions::from_mode(0o755)).unwrap();
        let mut args = afl_programmatic_args(
            &work_dir,
            "H-SYMCC",
            vec![b"parse_record".to_vec()],
            Some(Duration::from_secs(20)),
            &[],
            actionability::RunMode::Reporting,
            0,
            &[],
            4096,
        );
        args.engine = FuzzEngine::Builtin;
        args.iterations = Some(64);
        args.stop_after_findings = Some(1);
        let mut prepared = prepare(args).unwrap();
        prepared.symcc = Some(crate::symcc::SymccConfig {
            binary: solver.clone(),
            runner: replay_min::HarnessRunner::direct(solver.clone()),
            rss_limit_mb: 0,
            plateau: Duration::ZERO,
            run_timeout: Duration::from_secs(10),
            entries_per_round: 8,
        });
        let summary = run_builtin_with_progress(prepared, None).unwrap();
        assert_eq!(summary.findings.len(), 1, "{:?}", summary.findings);
        let testcase = fs::read(
            corpus::layout::finding_dir(&work_dir, &summary.findings[0]).join("testcase.bin"),
        )
        .unwrap();
        assert_eq!(testcase, solved);
        let symcc = summary.symcc.as_ref().expect("the stage's summary");
        assert_eq!(symcc.binary, solver);
        assert!(symcc.rounds >= 1, "{symcc:?}");
        assert_eq!(symcc.inputs_imported, 1, "{symcc:?}");
        let json = fs::read_to_string(work_dir.join("fuzz_runs/H-SYMCC-latest.json")).unwrap();
        let recorded: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(recorded["symcc"]["inputs_imported"], 1, "{json}");
    }

    /// Without the SymCC stage the same short pass does not find that input:
    /// the finding above is the stage's.
    #[test]
    #[cfg(unix)]
    fn without_symcc_the_short_pass_misses_that_input() {
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        let solved: Vec<u8> = (0..24u8).map(|n| n.wrapping_mul(37) ^ 0xa5).collect();
        let expected = root.join("expected.bin");
        fs::write(&expected, &solved).unwrap();
        write_exact_match_harness(&work_dir, "H-NOSYMCC", &expected);
        let mut args = afl_programmatic_args(
            &work_dir,
            "H-NOSYMCC",
            vec![b"parse_record".to_vec()],
            Some(Duration::from_secs(20)),
            &[],
            actionability::RunMode::Reporting,
            0,
            &[],
            4096,
        );
        args.engine = FuzzEngine::Builtin;
        args.iterations = Some(64);
        let prepared = prepare(args).unwrap();
        assert!(prepared.symcc.is_none(), "the run did not ask for SymCC");
        let summary = run_builtin_with_progress(prepared, None).unwrap();
        assert!(summary.findings.is_empty(), "{:?}", summary.findings);
        assert!(summary.symcc.is_none());
        let json = fs::read_to_string(work_dir.join("fuzz_runs/H-NOSYMCC-latest.json")).unwrap();
        assert!(!json.contains("\"symcc\""), "{json}");
    }

    #[test]
    #[cfg(unix)]
    fn programmatic_run_feeds_non_utf8_seed_bytes_unchanged() {
        // `bhf auto` hands every seed (mined, --seed-file, --seed-dir, reseeded
        // queue entries) to this runner. The harness crashes only on the exact
        // seed bytes, so a finding whose testcase equals the seed proves no byte
        // was rewritten on the way to the engine.
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        let seed = non_utf8_seed();
        let expected = root.join("expected.bin");
        fs::write(&expected, &seed).unwrap();
        write_exact_match_harness(&work_dir, "H-BYTES", &expected);

        let summary = run_one_target_programmatic(
            &work_dir,
            "H-BYTES",
            vec![seed.clone()],
            4,
            None,
            None,
            0,
            &[],
            actionability::RunMode::Reporting,
            None,
            &[],
            None,
        )
        .unwrap();

        assert_eq!(
            summary.findings.len(),
            1,
            "the exact seed must reach the harness: {:?}",
            summary.findings
        );
        let testcase = fs::read(
            corpus::layout::finding_dir(&work_dir, &summary.findings[0]).join("testcase.bin"),
        )
        .unwrap();
        assert_eq!(
            testcase, seed,
            "testcase.bin must be the seed, byte for byte"
        );
    }

    /// Write an `arg-layout.json` beside `harness` that decodes two 4-byte
    /// scalars before the buffer taking the bytes left: an 8-byte seed
    /// prefix. Its callers run shell-script harnesses, so Unix only.
    #[cfg(unix)]
    fn write_scalars_first_layout(harness: &Path) {
        let scalar = |name: &str| {
            serde_json::json!({
                "step": "param", "call": "target", "role": "param", "index": 1,
                "name": name, "type": "uint32_t", "order": 0, "input": "cursor",
                "decoder": "scalar", "primitive": "bhf_i32", "width": 4, "static_decode": true
            })
        };
        let layout = serde_json::json!({
            "schema_version": "bhf.arg-layout.v1", "harness_format_version": 4,
            "language": "c", "harness": "direct", "static_decode": true,
            "steps": [
                scalar("a"),
                scalar("b"),
                {"step": "remainder", "call": "target", "sized": false},
                {"step": "param", "call": "target", "role": "param", "index": 0,
                 "name": "buf", "type": "const uint8_t *", "order": 2, "input": "remainder",
                 "decoder": "input_buffer", "copied": true, "static_decode": true}
            ]
        });
        fs::write(
            harness.with_file_name("arg-layout.json"),
            serde_json::to_vec(&layout).unwrap(),
        )
        .unwrap();
    }

    /// A seed file of `bhf fuzz` is also given behind the bytes the harness
    /// decodes into fixed-width parameters before its buffer, and stays as
    /// it is; seeds handed over programmatically are not.
    #[test]
    #[cfg(unix)]
    fn seed_files_are_also_given_behind_the_layout_prefix() {
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        let harness = write_c_libfuzzer_harness(&work_dir, "H-PREFIX", "#!/bin/sh\nexit 0\n");
        write_scalars_first_layout(&harness);
        let seed_file = root.join("magic.bin");
        fs::write(&seed_file, b"MAGC").unwrap();
        let args_dir = tmpdir();
        let mut args = fuzz_args_for_worker_passthrough(&args_dir, StructuredInputMode::Off);
        args.work_dir = work_dir.clone();
        args.harness = "H-PREFIX".to_owned();
        args.seed_files = vec![seed_file];
        args.seed_bytes = vec![b"QUEUED".to_vec()];
        let prepared = prepare(args).unwrap();
        assert!(
            prepared.seeds.contains(&b"MAGC".to_vec()),
            "{:?}",
            prepared.seeds
        );
        assert!(
            prepared.seeds.contains(&b"\0\0\0\0\0\0\0\0MAGC".to_vec()),
            "{:?}",
            prepared.seeds
        );
        assert!(!prepared.seeds.contains(&b"\0\0\0\0\0\0\0\0QUEUED".to_vec()));
    }

    /// In a multi-worker campaign only the seed files and inputs given to
    /// `bhf fuzz` get a prefixed variant, made once by the campaign: a
    /// worker, handed every seed as a seed file (the programmatic ones and
    /// the shared queue's included), adds none of its own.
    #[test]
    #[cfg(unix)]
    fn multicore_workers_get_prefixed_variants_of_the_given_seeds_only() {
        use clap::Parser;
        #[derive(clap::Parser)]
        struct Wrap {
            #[command(flatten)]
            inner: FuzzArgs,
        }
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        let harness = write_c_libfuzzer_harness(&work_dir, "H-PREFIX-MC", "#!/bin/sh\nexit 0\n");
        write_scalars_first_layout(&harness);
        let seed_file = root.join("magic.bin");
        fs::write(&seed_file, b"MAGC").unwrap();
        let args_dir = tmpdir();
        let mut args = fuzz_args_for_worker_passthrough(&args_dir, StructuredInputMode::Off);
        args.work_dir = work_dir.clone();
        args.harness = "H-PREFIX-MC".to_owned();
        args.seed_files = vec![seed_file];
        args.seed_bytes = vec![b"QUEUED".to_vec()];
        worker_seed_files(&mut args, &harness).unwrap();
        let work = work_dir.display().to_string();
        let mut argv = vec!["fuzz", work.as_str(), "--harness", "H-PREFIX-MC"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        argv.extend(worker_passthrough_args(&args));
        let worker = Wrap::try_parse_from(&argv).unwrap().inner;
        let seeds = prepare(worker).unwrap().seeds;
        let count = |seed: &[u8]| seeds.iter().filter(|s| s.as_slice() == seed).count();
        assert_eq!(count(b"MAGC"), 1, "{seeds:?}");
        assert_eq!(count(b"\0\0\0\0\0\0\0\0MAGC"), 1, "{seeds:?}");
        assert_eq!(count(b"QUEUED"), 1, "{seeds:?}");
        assert_eq!(count(b"\0\0\0\0\0\0\0\0QUEUED"), 0, "{seeds:?}");
    }

    /// Of a worker's seeds only the ones given to `bhf fuzz` are the
    /// operator's. The prefixed variants and programmatic seeds the campaign
    /// wrote to files, and the shared queue's entries, are copies bhf handed
    /// over: the lineage names the seed they were made from, or their own
    /// record, never the copy.
    #[test]
    #[cfg(unix)]
    fn a_worker_names_only_the_seeds_given_to_bhf_fuzz_as_the_operators() {
        use clap::Parser;
        #[derive(clap::Parser)]
        struct Wrap {
            #[command(flatten)]
            inner: FuzzArgs,
        }
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        let harness = write_c_libfuzzer_harness(&work_dir, "H-OPERATOR", "#!/bin/sh\nexit 0\n");
        write_scalars_first_layout(&harness);
        let seed_file = root.join("magic.bin");
        fs::write(&seed_file, b"MAGC").unwrap();
        let queued = work_dir.join("corpus/H-OPERATOR/queue/entry.bin");
        fs::create_dir_all(queued.parent().unwrap()).unwrap();
        fs::write(&queued, b"ENTRY").unwrap();
        let args_dir = tmpdir();
        let mut args = fuzz_args_for_worker_passthrough(&args_dir, StructuredInputMode::Off);
        args.work_dir = work_dir.clone();
        args.harness = "H-OPERATOR".to_owned();
        args.seed_files = vec![seed_file.clone()];
        args.seed_bytes = vec![b"QUEUED".to_vec()];
        worker_seed_files(&mut args, &harness).unwrap();
        let work = work_dir.display().to_string();
        let queued_arg = queued.display().to_string();
        // What the campaign adds for each shared-queue entry.
        let mut argv = vec![
            "fuzz",
            work.as_str(),
            "--harness",
            "H-OPERATOR",
            "--campaign-seed-file",
            queued_arg.as_str(),
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        argv.extend(worker_passthrough_args(&args));
        let worker = Wrap::try_parse_from(&argv).unwrap().inner;
        let prepared = prepare(worker).unwrap();
        for seed in [&b"MAGC"[..], b"\0\0\0\0\0\0\0\0MAGC", b"QUEUED", b"ENTRY"] {
            assert!(
                prepared.seeds.iter().any(|s| s.as_slice() == seed),
                "{seed:?} in {:?}",
                prepared.seeds
            );
        }
        let named = std::path::absolute(&seed_file)
            .unwrap()
            .display()
            .to_string();
        assert_eq!(
            prepared.operator_seeds,
            vec![(corpus::lineage::digest(b"MAGC"), Some(named))]
        );
    }

    #[test]
    fn prefixed_seed_variants_are_added_once() {
        let seeds = vec![b"MZ".to_vec(), b"".to_vec()];
        let variants = layout_prefixed_seeds(&seeds, 4);
        assert_eq!(variants, vec![b"\0\0\0\0MZ".to_vec(), vec![0; 4]]);
        // Handed the seeds and their variants (a fuzz worker), nothing new.
        let mut both = seeds.clone();
        both.extend(variants);
        assert!(layout_prefixed_seeds(&both, 4).is_empty());
        assert!(layout_prefixed_seeds(&seeds, 0).is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn afl_programmatic_seeds_keep_their_bytes_and_honor_the_resolved_max_len() {
        // The AFL++ stage of `bhf auto` used a fixed 4096-byte cap, so every
        // seed handed to afl-fuzz was cut short whatever `--max-len` said.
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        write_c_libfuzzer_harness(&work_dir, "H-AFLSEED", "#!/bin/sh\nexit 0\n");
        let mut big = Vec::new();
        while big.len() < 10 * 1024 {
            big.extend_from_slice(&non_utf8_seed());
        }
        let max_len = resolve_max_len_spec(Some("auto"), big.len());
        let args = afl_programmatic_args(
            &work_dir,
            "H-AFLSEED",
            vec![big.clone(), non_utf8_seed()],
            Some(Duration::from_secs(1)),
            &[],
            actionability::RunMode::Reporting,
            0,
            &[],
            max_len,
        );
        let prepared = prepare(args).unwrap();
        assert!(prepared.seeds.contains(&big), "10 KiB seed kept whole");
        assert!(prepared.seeds.contains(&non_utf8_seed()));

        // A numeric cap still bounds the seeds, and is what afl-fuzz gets as -G.
        let capped = afl_programmatic_args(
            &work_dir,
            "H-AFLSEED",
            vec![big.clone()],
            Some(Duration::from_secs(1)),
            &[],
            actionability::RunMode::Reporting,
            0,
            &[],
            resolve_max_len_spec(Some("8192"), big.len()),
        );
        let prepared = prepare(capped).unwrap();
        assert_eq!(prepared.seeds, vec![big[..8192].to_vec()]);
        assert_eq!(afl_generated_max_len(8192), Some(8192));
        assert_eq!(
            afl_generated_max_len(max_len),
            None,
            "the adaptive ceiling leaves afl-fuzz at its own default"
        );
    }

    #[test]
    #[cfg(unix)]
    fn afl_programmatic_prepare_keeps_a_numeric_max_len_for_afl_fuzz() {
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        write_c_libfuzzer_harness(&work_dir, "H-AFLCAP", "#!/bin/sh\nexit 0\n");
        let prepare_with = |spec: &str| {
            prepare_afl_programmatic(
                &work_dir,
                "H-AFLCAP",
                vec![non_utf8_seed()],
                Some(Duration::from_secs(1)),
                &[],
                actionability::RunMode::Reporting,
                0,
                &[],
                Some(spec),
            )
            .unwrap()
        };
        assert_eq!(prepare_with("8192").afl_max_len, Some(8192));
        assert_eq!(
            prepare_with("auto").afl_max_len,
            None,
            "the adaptive ceiling leaves afl-fuzz at its own default"
        );
    }

    /// An `afl-fuzz` stand-in: `-h` prints a usage text (with or without the
    /// `-G` line), anything else records its argv to `argv.txt` beside it.
    #[cfg(unix)]
    fn fake_afl_fuzz(dir: &Path, lists_max_len: bool) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        fs::create_dir_all(dir).unwrap();
        let usage = if lists_max_len {
            "  -g minlength  - set min length of generated fuzz input (default: 1)\n  \
             -G maxlength  - set max length of generated fuzz input (default: 1048576)\n"
        } else {
            "  -x dict_file  - fuzzer dictionary\n"
        };
        let argv = dir.join("argv.txt");
        let script = dir.join("afl-fuzz");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nif [ \"$1\" = -h ]; then\n  printf '\\033[0;36mafl-fuzz\\033[0m usage\\n{}'\n  exit 1\nfi\n\
                 printf '%s\\n' \"$@\" > '{}'\nexit 0\n",
                usage.replace('\n', "\\n"),
                argv.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        argv
    }

    #[test]
    #[cfg(unix)]
    fn afl_fuzz_gets_the_max_len_as_g_only_when_it_has_the_option() {
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        let dir = work_dir.join("build").join("H-AFLG");
        write_c_libfuzzer_harness(&work_dir, "H-AFLG", "#!/bin/sh\nexit 0\n");
        fs::copy(dir.join("main"), dir.join("main_afl")).unwrap();
        for lists_max_len in [true, false] {
            let afl_dir = root.join(format!("afl-{lists_max_len}"));
            let argv = fake_afl_fuzz(&afl_dir, lists_max_len);
            let mut prepared = prepare_afl_programmatic(
                &work_dir,
                "H-AFLG",
                vec![non_utf8_seed()],
                Some(Duration::from_secs(1)),
                &[],
                actionability::RunMode::Reporting,
                0,
                &[],
                Some("8192"),
            )
            .unwrap();
            prepared.afl_path = Some(afl_dir.clone());
            run_afl_plus_plus(prepared).unwrap();
            let args: Vec<String> = fs::read_to_string(&argv)
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect();
            let g = args.iter().position(|arg| arg == "-G");
            if lists_max_len {
                let g = g.unwrap_or_else(|| panic!("-G passed: {args:?}"));
                assert_eq!(args[g + 1], "8192");
                assert!(g < args.iter().position(|arg| arg == "--").unwrap());
            } else {
                assert_eq!(g, None, "an afl-fuzz without -G must not get it: {args:?}");
            }
        }
    }

    #[test]
    fn afl_help_parsing_finds_the_g_option_line_only() {
        let current = b"\x1b[0;36mafl-fuzz++4.09c\x1b[0m based on afl\n\nMutator settings:\n  \
            -a            - target input format\n  \
            -g minlength  - set min length of generated fuzz input (default: 1)\n  \
            -G maxlength  - set max length of generated fuzz input (default: 1048576)\n";
        assert!(afl_help_lists_max_len(current));
        let older = b"afl-fuzz++3.14c\n  -x dict_file  - fuzzer dictionary\n  \
            -s seed       - use a fixed seed for the RNG\n  \
            Note: -G is not an option here\n";
        assert!(!afl_help_lists_max_len(older));
        assert!(!afl_help_lists_max_len(b""));
    }

    #[test]
    #[cfg(unix)]
    fn non_driver_zero_coverage_run_persists_bounded_corpus() {
        // #412 regression: a non-driver harness (no BHF_FRAMED main.c — the
        // exact shape of every Ada/legacy target) has `cov_tracker == None`, so the
        // engine never sees edge coverage. Pre-fix the retention gate degenerated to
        // "keep every non-empty input" and the end-of-run flush wrote ~every
        // executed input to disk (corpus_persisted ~= iterations, e.g. ~5000 here),
        // a disk/inode-exhaustion hazard. Post-fix retention is progress-gated and
        // bounded by the memory-aware corpus limit, so a clean zero-coverage run persists
        // only the seed(s).
        let root = tmpdir();
        let work_dir = root.join("bhf_work");
        write_c_libfuzzer_harness(&work_dir, "H-BOUND", "#!/bin/sh\nexit 0\n");

        let summary = run_one_target_programmatic(
            &work_dir,
            "H-BOUND",
            vec![b"seed".to_vec()],
            5000,
            None,
            None,
            0,
            &[],
            actionability::RunMode::Reporting,
            None, // cmplog_log
            &[],
            None,
        )
        .unwrap();

        // No coverage feedback and no classified events => no corpus novelty.
        assert_eq!(
            summary.corpus_new, 0,
            "a clean zero-coverage harness grows no corpus signatures"
        );
        // The pool is hard-bounded regardless of the gate.
        let entry_limit = corpus_limits(DEFAULT_MAX_LEN).entries;
        assert!(
            summary.corpus_persisted <= entry_limit,
            "corpus_persisted {} must be capped at the derived entry limit {}",
            summary.corpus_persisted,
            entry_limit
        );
        assert!(
            summary.corpus_persisted < 10_000,
            "corpus_persisted {} must not blow up (pre-fix ~5000)",
            summary.corpus_persisted
        );
        // Concretely: only the seed survives retention (nothing made progress).
        assert!(
            summary.corpus_persisted <= 1,
            "only the seed should persist on a zero-coverage no-event run, got {}",
            summary.corpus_persisted
        );
    }

    #[test]
    fn afl_execution_summary_marks_forkserver_and_persistent_mode() {
        let summary = afl_execution_summary();
        assert_eq!(summary.harness_protocol, "afl++_persistent_stdin");
        assert!(summary.forkserver);
        assert!(summary.persistent);
        assert_eq!(summary.persistent_iterations, Some(10_000));
    }

    #[test]
    fn parse_worker_count_accepts_auto_and_fixed_counts() {
        assert_eq!(parse_worker_count("auto"), Ok(FuzzWorkerCount::Auto));
        assert_eq!(parse_worker_count("3"), Ok(FuzzWorkerCount::Fixed(3)));
        assert!(parse_worker_count("0").is_err());
    }

    #[test]
    fn load_grammar_for_run_parses_json_and_generates_conformant_bytes() {
        let dir = tmpdir();
        let path = dir.join("grammar.json");
        std::fs::write(
            &path,
            br#"{"START": ["{DIGIT}{DIGIT}"], "DIGIT": ["0", "1"]}"#,
        )
        .unwrap();

        let grammar = load_grammar_for_run(Some(&path))
            .unwrap()
            .expect("grammar should load");
        let mut rng = MutationRng::new(42);
        let out = grammar
            .generate(16, &mut rng)
            .expect("grammar should generate");
        assert_eq!(out.len(), 2, "START expands to two DIGITs");
        assert!(
            out.iter().all(|b| matches!(b, b'0' | b'1')),
            "only grammar terminals, got {out:?}"
        );

        // No path -> no grammar in play.
        assert!(load_grammar_for_run(None).unwrap().is_none());
        // Malformed JSON is a hard error, not a silent skip.
        std::fs::write(&path, b"not json").unwrap();
        assert!(load_grammar_for_run(Some(&path)).is_err());
        // A reference to an undefined non-terminal is rejected.
        std::fs::write(&path, br#"{"START": ["{MISSING}"]}"#).unwrap();
        assert!(load_grammar_for_run(Some(&path)).is_err());
    }

    /// A `--frame` profile of one message, lowered field by field: an enum
    /// at its width with its variants as codes, a TLV with its tag, a length
    /// over a fixed and a variable field, and a CRC-16 over the frame.
    #[test]
    fn load_frame_for_run_lowers_each_field_kind_of_a_profile_message() {
        let dir = tmpdir();
        let path = dir.join("frame.toml");
        std::fs::write(
            &path,
            r#"
schema = "bhf.protocol.v1"

[[message]]
name = "cmd"

[[message.field]]
name = "op"
type = "enum"
variants = { READ = 1, WRITE = 2, ERASE = 0x30 }
value = "WRITE"

[[message.field]]
name = "len"
type = "u16"
endian = "little"
computed = "length(seq, body)"

[[message.field]]
name = "seq"
type = "u16"
endian = "little"
value = 7

[[message.field]]
name = "body"
type = "bytes"
value = "abc"

[[message.field]]
name = "opt"
type = "tlv"
tag = 9
value = "xy"

[[message.field]]
name = "crc"
type = "u16"
computed = "crc16(op, len, seq, body, opt)"
"#,
        )
        .unwrap();
        let codec = load_frame_for_run(Some(&path)).unwrap().expect("a codec");
        let mut expected = vec![0x02, 0x05, 0x00, 0x07, 0x00, b'a', b'b', b'c'];
        expected.extend_from_slice(&[0x00, 0x09, 0x00, 0x02, b'x', b'y']);
        let crc = fuzz_engine_builtin::crc16_ccitt(&expected);
        expected.extend_from_slice(&crc.to_be_bytes());
        assert_eq!(codec.seed(), expected.as_slice());
        assert_eq!(codec.repair(&expected), expected, "a valid frame is kept");

        // `body` is the only variable field `len` covers, so its length comes
        // from `len` (less `seq`'s two bytes); the TLV's from its own prefix.
        let mut input = vec![0x30, 0x06, 0x00, 0x01, 0x00, b'w', b'x', b'y', b'z'];
        input.extend_from_slice(&[0xFF, 0xFF, 0x00, 0x01, b'q', 0, 0]);
        let repaired = codec.repair(&input);
        let mut want = vec![0x30, 0x06, 0x00, 0x01, 0x00, b'w', b'x', b'y', b'z'];
        want.extend_from_slice(&[0x00, 0x09, 0x00, 0x01, b'q']);
        let crc = fuzz_engine_builtin::crc16_ccitt(&want);
        want.extend_from_slice(&crc.to_be_bytes());
        assert_eq!(repaired, want);

        // A field edit of `op` favours the declared codes.
        let mut rng = MutationRng::new(11);
        let ops: HashSet<u8> = (0..300)
            .map(|_| codec.mutate(codec.seed(), 4096, &mut rng)[0])
            .collect();
        for code in [0x01, 0x02, 0x30] {
            assert!(ops.contains(&code), "{code:#x} in {ops:?}");
        }
    }

    #[test]
    fn load_frame_for_run_refuses_what_a_single_input_cannot_carry() {
        let dir = tmpdir();
        let path = dir.join("frame.toml");
        let cases = [
            (
                "[[message]]\nname = \"a\"\n[[message.field]]\nname = \"tok\"\ntype = \"u32\"\n\
                 ref = \"b.response.token\"\n\n[[message]]\nname = \"b\"\n\
                 [[message.response.capture]]\nname = \"token\"\ntype = \"u32\"\nat = 0\n",
                "declares 2 (a, b)",
            ),
            ("kind = \"giop\"\n[[message]]\nname = \"op\"\n", "giop"),
            ("[[message]]\nname = \"m\"\n", "no fields"),
            (
                "[[message]]\nname = \"a\"\n[[message.field]]\nname = \"tok\"\ntype = \"u32\"\n\
                 ref = \"a.response.token\"\n[[message.response.capture]]\nname = \"token\"\n\
                 type = \"u32\"\nat = 0\n",
                "no reply",
            ),
        ];
        for (body, expected) in cases {
            std::fs::write(&path, format!("schema = \"bhf.protocol.v1\"\n{body}")).unwrap();
            let error = load_frame_for_run(Some(&path)).expect_err(expected);
            assert!(error.starts_with("--frame "), "{error}");
            assert!(error.contains(expected), "{expected}: {error}");
        }
        std::fs::write(&path, b"schema = [").unwrap();
        assert!(load_frame_for_run(Some(&path)).is_err());
        assert!(load_frame_for_run(None).unwrap().is_none());
    }

    #[test]
    fn frame_seeds_repairs_each_seed_once_and_adds_the_profiles_frame() {
        use fuzz_engine_builtin::binframe::FrameCodec;
        use fuzz_engine_builtin::{ChecksumKind, Endian, Field, IntWidth, Message};
        let codec = FrameCodec::new(
            Message::new(vec![
                Field::length("len", IntWidth::U8, Endian::Big, &["body"]),
                Field::bytes("body", b"seed".to_vec()),
                Field::checksum("sum", ChecksumKind::Sum8, Endian::Big, &["body"]),
            ]),
            &std::collections::BTreeMap::new(),
        )
        .unwrap();
        let mut seeds = vec![b"\x00ab\x00".to_vec(), b"\x09ab\x07".to_vec()];
        frame_seeds(&codec, &mut seeds);
        let ab = vec![2, b'a', b'b', b'a'.wrapping_add(b'b')];
        assert_eq!(seeds, vec![ab, codec.seed().to_vec()]);
    }

    /// A byte mutation the repair undoes is no child: the field edit runs
    /// instead, and the loop never runs the base again.
    #[test]
    fn frame_child_never_hands_back_its_base() {
        use fuzz_engine_builtin::binframe::FrameCodec;
        use fuzz_engine_builtin::{ChecksumKind, Endian, Field, IntWidth, Message};
        let codec = FrameCodec::new(
            Message::new(vec![
                Field::length("len", IntWidth::U16, Endian::Big, &["body"]),
                Field::bytes("body", b"payload".to_vec()),
                Field::checksum("crc", ChecksumKind::Crc32, Endian::Big, &["body"]),
            ]),
            &std::collections::BTreeMap::new(),
        )
        .unwrap();
        let base = codec.seed().to_vec();
        let mut rng = MutationRng::new(5);
        let (mut byte_children, mut field_edits) = (0, 0);
        for _ in 0..200 {
            // A byte mutation of the stored CRC alone.
            let (child, field_edit) = frame_child(&codec, &base, 4096, &mut rng, |_| {
                let mut stale = base.clone();
                *stale.last_mut().unwrap() ^= 0x55;
                stale
            });
            assert!(field_edit, "the repair undid the byte mutation");
            assert_eq!(codec.repair(&child), child, "a frame");
            field_edits += 1;
            // A byte mutation of the body: repaired, and kept.
            let (child, field_edit) = frame_child(&codec, &base, 4096, &mut rng, |_| {
                let mut grown = base.clone();
                grown.insert(3, b'!');
                grown
            });
            if !field_edit {
                byte_children += 1;
                assert_eq!(&child[2..10], b"p!ayload");
                assert_eq!(codec.repair(&child), child);
            }
        }
        assert!(byte_children > 50 && field_edits == 200, "{byte_children}");
    }

    #[test]
    fn collector_flag_parses_auto_none_path_and_window() {
        use clap::Parser;
        #[derive(clap::Parser)]
        struct Wrap {
            #[command(flatten)]
            inner: FuzzArgs,
        }
        // Default: off, 250ms — a plain `bhf fuzz` stays unchanged.
        let w = Wrap::try_parse_from(["fuzz", "wd", "--harness", "h"]).unwrap();
        assert_eq!(w.inner.collector, crate::collector_run::CollectorSpec::Off);
        assert_eq!(w.inner.collector_window_ms, 250);

        let w =
            Wrap::try_parse_from(["fuzz", "wd", "--harness", "h", "--collector", "auto"]).unwrap();
        assert_eq!(w.inner.collector, crate::collector_run::CollectorSpec::Auto);

        let w = Wrap::try_parse_from([
            "fuzz",
            "wd",
            "--harness",
            "h",
            "--collector",
            "/opt/probe",
            "--collector-window-ms",
            "750",
        ])
        .unwrap();
        assert_eq!(
            w.inner.collector,
            crate::collector_run::CollectorSpec::Sidecar(std::path::PathBuf::from("/opt/probe"))
        );
        assert_eq!(w.inner.collector_window_ms, 750);
    }

    /// #60 AC6 regression: `bhf fuzz --collector auto` with the runtrace shim NOT
    /// armed (no `runtrace.jsonl` — the default `--runtime-oracles off`) must never
    /// report `clean_assurance=true` over an unobserved run. The Linux built-in
    /// relies on the loop's shim log; absent it, the collector observed nothing and
    /// must record a degraded, not-observed run.
    #[cfg(unix)]
    #[test]
    fn collector_auto_without_shim_log_is_not_reported_clean() {
        let work = crate::test_support::TestDir::new("fuzz-col-noobs");

        // This run armed no shim. An earlier run's runtrace.jsonl is still in
        // the work dir, and the collector must not read it as this run's.
        std::fs::write(
            work.join("runtrace.jsonl"),
            "{\"e\":\"exec\",\"c\":\"/bin/sh -c id\",\"t\":0}\n",
        )
        .unwrap();
        let prov = run_collector_for_fuzz(
            &crate::collector_run::CollectorSpec::Auto,
            crate::collector_run::DEFAULT_WINDOW_MS,
            &work,
            "harness",
            None,
            None,
        )
        .expect("collector provenance");

        if prov.pointer("/active") == Some(&serde_json::json!(true)) {
            // The runtrace built-in resolved (shim available) but observed nothing:
            // it must be degraded, never a clean assurance over an empty stream.
            assert_eq!(prov.pointer("/mode"), Some(&serde_json::json!("runtrace")));
            assert_eq!(
                prov.pointer("/observed"),
                Some(&serde_json::json!(false)),
                "a not-observed collector run must be marked observed:false: {prov}"
            );
            assert_ne!(
                prov.pointer("/clean_assurance"),
                Some(&serde_json::json!(true)),
                "a collector that observed nothing must NOT report clean_assurance=true: {prov}"
            );
        } else {
            // Shim unavailable on this host: the collector is inactive, so the
            // false-clean claim cannot arise at all.
            assert_eq!(prov.pointer("/active"), Some(&serde_json::json!(false)));
        }

        let _ = std::fs::remove_dir_all(&work);
    }

    fn fuzz_args_for_worker_passthrough(
        work_dir: &Path,
        structured_inputs: StructuredInputMode,
    ) -> FuzzArgs {
        FuzzArgs {
            work_dir: work_dir.to_path_buf(),
            harness: "H-X".to_owned(),
            engine: FuzzEngine::Builtin,
            afl_mode: AflMode::Native,
            afl_path: None,
            afl_inst_ranges: Vec::new(),
            winafl_path: None,
            dynamorio_path: None,
            winafl_instrumentation: WinaflInstrumentation::Dynamorio,
            winafl_iterations: None,
            winafl_coverage_modules: Vec::new(),
            winafl_page_heap: false,
            workers: None,
            iterations: Some(1),
            time: None,
            timeout: None,
            deadline: None,
            max_len: DEFAULT_MAX_LEN,
            len_control: DEFAULT_LEN_CONTROL,
            print_final_stats: false,
            quiet: true,
            rss_limit_mb: 0,
            fork_server: false,
            no_fork_server: false,
            seed_inputs: Vec::new(),
            seed_files: Vec::new(),
            campaign_seed_files: Vec::new(),
            qemu_user: None,
            qemu_args: Vec::new(),
            seed_bytes: Vec::new(),
            seeds_layout_prefixed: false,
            sanitizers: Vec::new(),
            symbolic_seed_sources: Vec::new(),
            rng_seed: 1,
            sandbox: SandboxModeArg::None,
            mode: actionability::RunMode::Reporting,
            sandbox_tool: None,
            sandbox_strict: false,
            extra_env: Vec::new(),
            runtime_oracles: crate::runtime_oracles::RuntimeOracleMode::Off,
            cmplog_log: None,
            grammar_file: None,
            frame_file: None,
            dict_file: None,
            structured_inputs,
            bhf_bin: None,
            stop_after_findings: None,
            target_transport: None,
            transport_coverage_map: None,
            board_profile: None,
            board_lane: crate::board_profile::BoardLane::Gdb,
            protocol_profile: None,
            session_transport: None,
            session_reset: crate::session_fuzz::SessionResetMode::Reconnect,
            max_session_messages: 64,
            session_reply_timeout: None,
            session_server_cmd: None,
            collector: crate::collector_run::CollectorSpec::Off,
            collector_window_ms: crate::collector_run::DEFAULT_WINDOW_MS,
            extension: None,
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod redqueen_cmplog_tests {
    use super::{
        CmpShmReader, CoverageTracker, BHF_CMP_BYTES, BHF_CMP_CAP, BHF_CMP_OPMAX, BHF_CMP_REC,
    };

    /// A path for a shared-memory image, in a dir removed when the guard drops.
    fn tmp_path(tag: &str) -> (crate::test_support::TestDir, std::path::PathBuf) {
        let dir = crate::test_support::TestDir::new(&format!("rq-{tag}"));
        let path = dir.join("shm");
        (dir, path)
    }

    /// Write a `BHF_CMP_SHM` image with the given (count, records) and the
    /// usual header, then return its dir's guard + an env vec pointing
    /// `CmpShmReader` at it.
    fn write_cmp_image(
        tag: &str,
        count: u32,
        records: &[(u8, u8, Vec<u8>, Vec<u8>)],
    ) -> (crate::test_support::TestDir, Vec<(String, String)>) {
        let mut buf = vec![0u8; BHF_CMP_BYTES];
        // header: [u32 armed=0][u32 count]
        buf[4..8].copy_from_slice(&count.to_le_bytes());
        for (i, (la, lb, a, b)) in records.iter().enumerate() {
            let off = 8 + i * BHF_CMP_REC;
            buf[off] = *la;
            buf[off + 1] = *lb;
            let a_end = (a.len()).min(BHF_CMP_OPMAX);
            buf[off + 2..off + 2 + a_end].copy_from_slice(&a[..a_end]);
            let b_end = (b.len()).min(BHF_CMP_OPMAX);
            buf[off + 2 + BHF_CMP_OPMAX..off + 2 + BHF_CMP_OPMAX + b_end]
                .copy_from_slice(&b[..b_end]);
        }
        let (dir, path) = tmp_path(tag);
        std::fs::write(&path, &buf).unwrap();
        let env = vec![("BHF_CMP_SHM".to_owned(), path.display().to_string())];
        (dir, env)
    }

    #[test]
    fn read_log_round_trips_planted_pairs_with_dedup_and_skips() {
        let records = vec![
            // a planted scalar pair
            (
                4u8,
                4u8,
                vec![0x44, 0x33, 0x22, 0x11],
                vec![0x88, 0x77, 0x66, 0x55],
            ),
            // an exact duplicate -> deduped away
            (
                4,
                4,
                vec![0x44, 0x33, 0x22, 0x11],
                vec![0x88, 0x77, 0x66, 0x55],
            ),
            // a distinct two-byte pair
            (2, 2, vec![0xAB, 0xCD], vec![0xEF, 0x01]),
            // both operands empty -> skipped
            (0, 0, vec![], vec![]),
        ];
        let (_dir, env) = write_cmp_image("roundtrip", records.len() as u32, &records);
        let reader = CmpShmReader::new(&env).expect("map cmp shm");
        let log = reader.read_log();

        // dup collapsed, empty skipped -> exactly two unique entries.
        assert_eq!(log.entries.len(), 2);
        assert!(log
            .entries
            .iter()
            .any(|e| e.operand_a == vec![0x44, 0x33, 0x22, 0x11]
                && e.operand_b == vec![0x88, 0x77, 0x66, 0x55]));
        assert!(log
            .entries
            .iter()
            .any(|e| e.operand_a == vec![0xAB, 0xCD] && e.operand_b == vec![0xEF, 0x01]));
        // splice_candidates must locate the planted operand in a matching input.
        let input = b"\x44\x33\x22\x11....".to_vec();
        let cands = log.splice_candidates(&input);
        assert!(
            cands
                .iter()
                .any(|c| c.offset == 0 && c.replacement == vec![0x88, 0x77, 0x66, 0x55]),
            "splice candidate at the planted offset must be found"
        );
    }

    #[test]
    fn read_log_clamps_corrupt_count_and_operand_lengths() {
        // A corrupt child could write count > CAP and len > OPMAX; the reader must
        // clamp both rather than read out of bounds.
        let records = vec![(
            200u8, // len_a far over OPMAX
            200u8, // len_b far over OPMAX
            vec![0x5A; BHF_CMP_OPMAX],
            vec![0xA5; BHF_CMP_OPMAX],
        )];
        let (_dir, env) = write_cmp_image("clamp", (BHF_CMP_CAP as u32) + 9999, &records);
        let reader = CmpShmReader::new(&env).expect("map cmp shm");
        let log = reader.read_log();
        // Only one real record was written; the rest of the (clamped-to-CAP) range
        // is zeroed -> empty -> skipped. Operand lengths clamp to OPMAX.
        assert_eq!(log.entries.len(), 1);
        assert_eq!(log.entries[0].operand_a.len(), BHF_CMP_OPMAX);
        assert_eq!(log.entries[0].operand_b.len(), BHF_CMP_OPMAX);
    }

    #[test]
    fn arm_zeroes_count_and_sets_armed_disarm_clears() {
        let (dir, env) = write_cmp_image("arm", 7, &[(2, 2, vec![1, 2], vec![3, 4])]);
        let path = dir.join("shm");
        let reader = CmpShmReader::new(&env).expect("map cmp shm");
        reader.arm();
        let after_arm = std::fs::read(&path).unwrap();
        assert_ne!(after_arm[0], 0, "armed byte set");
        assert_eq!(&after_arm[4..8], &[0, 0, 0, 0], "count zeroed by arm");
        reader.disarm();
        let after_disarm = std::fs::read(&path).unwrap();
        assert_eq!(
            &after_disarm[0..4],
            &[0, 0, 0, 0],
            "armed cleared by disarm"
        );
    }

    /// The edge map of a GCC `trace-pc` harness is labelled with that
    /// instrumentation, not clang's `trace-pc-guard`, in `run.json` and in the
    /// binary record a finding carries.
    #[test]
    fn coverage_source_names_the_instrumentation_the_harness_was_built_with() {
        let dir = tempfile::tempdir().unwrap();
        let map = dir.path().join("coverage.shm");
        let mut bitmap = vec![0u8; crate::fuzz::BHF_COV_BITS];
        bitmap[7] = 1;
        std::fs::write(&map, bitmap).unwrap();
        let env = vec![("BHF_COV_SHM".to_owned(), map.display().to_string())];
        let program = "void __sanitizer_cov_trace_pc(void) {}\n\
             void __sanitizer_cov_trace_pc_guard_init(unsigned *a, unsigned *b) { (void)a; (void)b; }\n\
             void __sanitizer_cov_trace_pc_guard(unsigned *g) { (void)g; }\n\
             int parse_record(int v) { return v > 1 ? v : -v; }\n\
             int main(int argc, char **argv) { (void)argv; return parse_record(argc); }\n";
        let source = dir.path().join("widget.c");
        std::fs::write(&source, program).unwrap();
        let build = |compiler: &str, coverage: &str| {
            let out = dir.path().join(format!("widget-{compiler}"));
            let ok = std::process::Command::new(compiler)
                .args(["-O1", "-g", coverage])
                .arg(&source)
                .arg("-o")
                .arg(&out)
                .status()
                .is_ok_and(|status| status.success());
            ok.then_some(out)
        };
        if let Some(gcc) = build("gcc", "-fsanitize-coverage=trace-pc") {
            let summary = crate::fuzz::coverage_from_env(&env, &gcc);
            assert_eq!(summary.edges, 1);
            assert_eq!(summary.source, "sancov-trace-pc");
            let record = crate::fuzz::build_binary_record(&gcc).expect("binary record");
            assert_eq!(record["coverage_instrumentation"], "sancov-trace-pc");
        } else {
            eprintln!("skip: gcc unavailable");
        }
        if let Some(clang) = build("clang", "-fsanitize-coverage=trace-pc-guard") {
            assert_eq!(
                crate::fuzz::coverage_from_env(&env, &clang).source,
                "sancov-trace-pc-guard"
            );
        }
        // Defining the hook is not using it: a build without coverage is not
        // labelled with any instrumentation.
        if let Some(plain) = build("gcc", "-fno-sanitize-coverage=trace-pc") {
            assert_eq!(
                crate::fuzz::coverage_from_env(&env, &plain).source,
                "edge-bitmap"
            );
        }
        // A harness the binary does not identify (a launcher script) is not
        // given a SanitizerCoverage label; without a map there is none.
        let script = dir.path().join("launcher");
        std::fs::write(&script, "#!/bin/sh\n").unwrap();
        assert_eq!(
            crate::fuzz::coverage_from_env(&env, &script).source,
            "edge-bitmap"
        );
        assert!(crate::fuzz::build_binary_record(&script)
            .expect("record")
            .get("coverage_instrumentation")
            .is_none());
        assert_eq!(crate::fuzz::coverage_from_env(&[], &script).source, "none");
    }

    #[test]
    fn coverage_tracker_snapshot_zero_restore_round_trips() {
        let (_dir, path) = tmp_path("cov");
        std::fs::write(&path, vec![0u8; crate::fuzz::BHF_COV_BITS]).unwrap();
        let env = vec![("BHF_COV_SHM".to_owned(), path.display().to_string())];
        let tracker = CoverageTracker::new(&env).expect("map cov shm");
        // Simulate an exec setting some edges, snapshot it.
        tracker.restore(&{
            let mut m = vec![0u8; super::BHF_COV_BITS];
            m[10] = 1;
            m[20] = 1;
            m
        });
        assert_eq!(tracker.count(), 2);
        let snap = tracker.snapshot();
        // Zero wipes the bitmap (isolated per-probe measurement).
        tracker.zero();
        assert_eq!(tracker.count(), 0);
        // Restore brings the cumulative state back exactly -> no #398 pollution.
        tracker.restore(&snap);
        assert_eq!(tracker.count(), 2);
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod sequence_layout_tests {
    use super::*;

    fn geometry() -> SequenceGeometry {
        // What the generator writes for a 3-op harness with the default cap.
        SequenceGeometry {
            operation_count: 3,
            max_steps: 8,
            control_len: 41,
            portfolio_lanes: 1,
        }
    }

    #[test]
    fn the_layout_describes_the_control_block_and_validates() {
        // The mutator rejects overlapping or out-of-range spans outright, so a
        // layout that does not validate is the same as no layout at all — the
        // op program would silently go back to being mutated as opaque bytes.
        let geometry = geometry();
        let input = vec![0xAB_u8; 64];
        let layout = geometry
            .layout_for(&input)
            .expect("an input longer than the control block has a program");
        layout
            .validate_for_input(&input)
            .expect("spans must be ascending, non-overlapping and in range");

        // The count byte opens the control block; the selectors follow it, one
        // per step, ascending — the same geometry `bhf_ctrl_op` reads.
        let base = input.len() - geometry.control_len;
        assert_eq!(layout.step_count_range, None);
        assert_eq!(layout.steps.len(), geometry.max_steps);
        assert_eq!(layout.steps[0].range, base + 1..base + 6);
        assert_eq!(
            layout.steps[geometry.max_steps - 1].range,
            input.len() - 5..input.len()
        );
        assert_eq!(layout.operation_count, 3);
    }

    #[test]
    fn the_engine_and_the_harness_select_the_same_operations() {
        // The whole point of describing the control block is that the engine's
        // structure-aware edits land on the operation the HARNESS will actually
        // run. If the two decoders disagreed, the mutator would be retargeting
        // operations that are never selected — silently worse than leaving the
        // program as opaque bytes.
        //
        // Expected values produced by compiling c_runtime/bhf_decode.h and
        // printing `bhf_ctrl_op` for this exact buffer (see the C runtime's
        // bhf_ctrl_bounded, which mirrors `decode_bounded_range`).
        let geometry = geometry();
        let input: Vec<u8> = (0..128u32).map(|i| (i * 37 + 11) as u8).collect();
        let layout = geometry.layout_for(&input).expect("program present");
        layout.validate_for_input(&input).expect("valid layout");

        let harness_selected = [1u32, 0, 0, 1, 1, 0, 2, 1];
        for (step, expected) in harness_selected.iter().enumerate() {
            let span = &layout.steps[step].op_index_range;
            let selector = input[span.start];
            let decoded = if selector.is_multiple_of(4) {
                let raw: u32 = match selector % 6 {
                    0 => 0,
                    1 => 1,
                    2 => geometry.operation_count as u32 - 2,
                    3 => geometry.operation_count as u32 - 1,
                    4 => 0,
                    _ => u32::MAX,
                };
                raw.clamp(0, geometry.operation_count as u32 - 1)
            } else {
                let raw =
                    u32::from_le_bytes(input[span.start + 1..span.start + 5].try_into().unwrap());
                raw % geometry.operation_count as u32
            };
            assert_eq!(
                decoded, *expected,
                "step {step}: engine decodes {decoded}, harness runs {expected}"
            );
        }
    }

    #[test]
    fn portfolio_seeds_cover_every_ranked_lane_without_polluting_argument_bytes() {
        let geometry = SequenceGeometry {
            operation_count: 3,
            max_steps: 8,
            control_len: 42,
            portfolio_lanes: 4,
        };
        let mut seeds = vec![b"<x/>".to_vec()];
        geometry.expand_portfolio_seeds(&mut seeds);
        assert_eq!(seeds.len(), 4);
        for (lane, seed) in seeds.iter().enumerate() {
            assert_eq!(&seed[..4], b"<x/>");
            assert_eq!(seed[4], lane as u8);
            assert_eq!(seed.len(), 46);
            let layout = geometry.layout_for(seed).expect("portfolio control tail");
            assert_eq!(layout.steps[0].range, 6..11);
            layout.validate_for_input(seed).expect("portfolio layout");
            assert_eq!(geometry.portfolio_lane(seed), Some(lane));
        }
        assert_eq!(geometry.portfolio_lane(b"tiny"), None);
    }

    #[test]
    fn an_input_too_short_for_a_control_block_has_no_program() {
        // Below the control length there is no mutable program to describe, so
        // flat-byte mutation is correct. The sequence harness still executes
        // its slot-zero TARGET once as a bootstrap default; that implicit call
        // has no control span for the structure-aware mutator to preserve.
        assert!(geometry().layout_for(&[0u8; 4]).is_none());
    }
}
