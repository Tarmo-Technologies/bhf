// SPDX-License-Identifier: Apache-2.0

//! SymCC, the concolic engine `bhf auto --symcc` runs beside the fuzzer
//! (#324, #331). SymCC is a compiler pass: a harness compiled with its
//! `symcc` (C) or `sym++` (C++) wrapper solves, on every run, the conditions
//! of the branches the input reached and writes an input for each branch it
//! can flip. That reaches what input-to-state and comparison progress cannot:
//! a comparison against a value the input holds only after hashing, modular
//! arithmetic or decoding.
//!
//! `bhf auto --symcc` builds that variant of each native C/C++ harness, the
//! `symcc` lane ([`build_lane`]), and each builtin pass runs a SymCC stage
//! ([`SymccStage`]): when the pass's corpus stops growing, its newest entries
//! run through `main_symcc`, and the inputs SymCC solves run in the pass.
//!
//! SymCC is GPL-3.0. bhf never links it: `make symcc`, which drives SymCC's
//! compiler, and the `main_symcc` binary it builds run as subprocesses, and
//! only under a license profile that allows the `symcc` subprocess
//! (`external-tools`, `research-lab`). An explicit `BHF_PROFILE` wins;
//! without one, asking for SymCC opts into `external-tools`, as
//! `--external-tools` does for the external static analyzers.

use std::collections::{HashSet, VecDeque};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::auto::lanes::LaneStatus;

/// The lane's name in a harness's `lanes.json` and run.json's
/// `targets[].lanes`.
pub(crate) const LANE: &str = "symcc";
/// The Makefile goal that builds the lane.
pub(crate) const MAKE_GOAL: &str = "symcc";
/// The binary the lane builds, beside the harness's `main`.
pub(crate) const BINARY: &str = "main_symcc";
/// The subprocess id a license profile allows SymCC by.
pub(crate) const SUBPROCESS_ID: &str = "symcc";
/// `1` asks for SymCC: `bhf auto --symcc` sets it for its run once the
/// license profile and the tools allow it.
pub(crate) const ENABLE_ENV: &str = "BHF_SYMCC";
/// The Makefile's variables naming SymCC's C and C++ compiler wrappers.
pub(crate) const CC_ENV: &str = "SYMCC_CC";
pub(crate) const CXX_ENV: &str = "SYMCC_CXX";

/// Whether the run asked for SymCC (`BHF_SYMCC=1`).
pub(crate) fn requested() -> bool {
    std::env::var(ENABLE_ENV).is_ok_and(|value| value.trim() == "1")
}

/// The license profile SymCC runs under: the one `BHF_PROFILE` names, else
/// `external-tools`, which asking for SymCC opts into.
pub(crate) fn license_profile() -> config::Profile {
    profile_from(std::env::var("BHF_PROFILE").ok().as_deref())
}

fn profile_from(value: Option<&str>) -> config::Profile {
    value
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(config::Profile::ExternalTools)
}

/// Whether `profile` lets bhf run SymCC.
pub(crate) fn profile_allows(profile: config::Profile) -> bool {
    let allowed = profile.allowed_subprocesses();
    allowed.contains(&"*") || allowed.contains(&SUBPROCESS_ID)
}

/// SymCC's compiler wrappers, where they were found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Compilers {
    /// `symcc`, for C harnesses.
    pub(crate) cc: Option<PathBuf>,
    /// `sym++`, for C++ harnesses.
    pub(crate) cxx: Option<PathBuf>,
}

/// SymCC's compiler wrappers: the ones `SYMCC_CC` and `SYMCC_CXX` name (a
/// path, or a program on PATH), else `symcc` and `sym++` on PATH.
pub(crate) fn find_compilers() -> Compilers {
    Compilers {
        cc: find_compiler(CC_ENV, "symcc"),
        cxx: find_compiler(CXX_ENV, "sym++"),
    }
}

fn find_compiler(var: &str, default: &str) -> Option<PathBuf> {
    let named = std::env::var_os(var)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.into());
    which::which(named).ok()
}

/// Whether a run that asked for SymCC gets it: `Ok` with what the lane
/// builds with, `Err` with why the run goes without it.
pub(crate) fn run_gate(profile: config::Profile, compilers: &Compilers) -> Result<String, String> {
    if !profile_allows(profile) {
        return Err(format!(
            "the `{}` license profile does not allow SymCC (GPL-3.0) to run; set \
             BHF_PROFILE=external-tools or research-lab to allow it",
            profile.as_str()
        ));
    }
    let show = |compiler: &Option<PathBuf>, name: &str| match compiler {
        Some(path) => path.display().to_string(),
        None => format!("none (no `{name}` on PATH, so their SymCC lane is not built)"),
    };
    if compilers.cc.is_none() && compilers.cxx.is_none() {
        return Err(
            "SymCC's compilers are not installed: no `symcc` or `sym++` on PATH, and \
             SYMCC_CC/SYMCC_CXX name none"
                .to_owned(),
        );
    }
    Ok(format!(
        "SymCC lane on (license profile `{}`): C harnesses build main_symcc with {}, C++ \
         harnesses with {}",
        profile.as_str(),
        show(&compilers.cc, "symcc"),
        show(&compilers.cxx, "sym++"),
    ))
}

/// Turn SymCC on for this run, or off, as `bhf auto --symcc` (or
/// `BHF_SYMCC=1`) asks and the license profile and the tools allow. When it
/// is on, `BHF_SYMCC=1` tells the harness builds and the fuzz passes, and
/// `SYMCC_CC`/`SYMCC_CXX` give `make symcc` the compilers found. Returns the
/// line to print.
pub(crate) fn configure_run(asked: bool) -> Option<String> {
    if !asked {
        return None;
    }
    let compilers = find_compilers();
    match run_gate(license_profile(), &compilers) {
        Ok(note) => {
            // Set before any build or worker starts (edition 2021: safe).
            std::env::set_var(ENABLE_ENV, "1");
            if let Some(cc) = &compilers.cc {
                std::env::set_var(CC_ENV, cc);
            }
            if let Some(cxx) = &compilers.cxx {
                std::env::set_var(CXX_ENV, cxx);
            }
            Some(note)
        }
        Err(reason) => {
            std::env::remove_var(ENABLE_ENV);
            Some(format!("--symcc: {reason}; this run fuzzes without SymCC"))
        }
    }
}

/// Build the SymCC lane (`make symcc`, `main_symcc`) of a native C/C++
/// harness that built, when the run asked for SymCC, and record in the
/// harness's `lanes.json` whether it built. `standard` is the language
/// standard the harness's `main` built with (`CXX_STD` for C++, `C_STD` for
/// C, such as a `gnu89` rung of the C dialect ladder), which the lane
/// builds with too. `None` when the run did not ask.
pub(crate) fn build_lane(
    work_dir: &Path,
    harness_id: &str,
    harness_dir: &Path,
    cpp: bool,
    extra_sources: &[PathBuf],
    extra_includes: &[PathBuf],
    standard: Option<&str>,
) -> Option<LaneStatus> {
    if !requested() {
        return None;
    }
    let status = build_lane_in(
        license_profile(),
        &find_compilers(),
        &LaneBuild {
            work_dir,
            harness_id,
            harness_dir,
            cpp,
            extra_sources,
            extra_includes,
            standard,
        },
    );
    if let Some(reason) = status.reason.as_deref().filter(|_| !status.built) {
        bhfeprintln!("bhf auto: note: {harness_id}: {reason}; it fuzzes without SymCC");
    }
    Some(status)
}

/// The harness whose SymCC lane [`build_lane_in`] builds, and what its
/// `main` built with.
struct LaneBuild<'a> {
    work_dir: &'a Path,
    harness_id: &'a str,
    harness_dir: &'a Path,
    cpp: bool,
    extra_sources: &'a [PathBuf],
    extra_includes: &'a [PathBuf],
    standard: Option<&'a str>,
}

/// [`build_lane`] once the run asked for SymCC: `make symcc` in the
/// harness's dir, with the sources, includes and language standard its
/// `main` built with.
fn build_lane_in(profile: config::Profile, compilers: &Compilers, lane: &LaneBuild) -> LaneStatus {
    build_lane_with(profile, compilers, lane.cpp, lane.harness_dir, || {
        crate::build::try_run_c_make_build_with_target(
            lane.work_dir,
            lane.harness_id,
            lane.extra_sources,
            lane.extra_includes,
            None,
            Some(MAKE_GOAL),
            lane.standard,
        )
    })
}

/// [`build_lane`] once the run asked for SymCC: `make` runs the build only
/// when `profile` allows SymCC and `compilers` has the harness language's.
fn build_lane_with(
    profile: config::Profile,
    compilers: &Compilers,
    cpp: bool,
    harness_dir: &Path,
    make: impl FnOnce() -> std::process::Output,
) -> LaneStatus {
    let (compiler, name, var) = if cpp {
        (&compilers.cxx, "sym++", CXX_ENV)
    } else {
        (&compilers.cc, "symcc", CC_ENV)
    };
    let status = if !profile_allows(profile) {
        not_built(format!(
            "the `{}` license profile does not allow SymCC",
            profile.as_str()
        ))
    } else if compiler.is_none() {
        not_built(format!(
            "SymCC's `{name}` is not on PATH and {var} names none"
        ))
    } else {
        let output = make();
        let binary = crate::auto::layout::harness_exe(harness_dir, BINARY);
        if output.status.success() && binary.is_file() {
            LaneStatus::built()
        } else {
            let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&output.stderr));
            LaneStatus::failed(BINARY, &text)
        }
    };
    crate::auto::lanes::record(harness_dir, LANE, status.clone());
    status
}

fn not_built(reason: String) -> LaneStatus {
    LaneStatus {
        built: false,
        reason: Some(reason),
        recorded_at: None,
    }
}

/// Milliseconds without a new corpus entry before a builtin pass runs its
/// newest entries through SymCC (#331).
pub(crate) const PLATEAU_ENV: &str = "BHF_SYMCC_PLATEAU_MS";
/// Milliseconds one SymCC run may take before it is killed.
pub(crate) const TIMEOUT_ENV: &str = "BHF_SYMCC_TIMEOUT_MS";
/// Corpus entries one plateau's round runs through SymCC.
pub(crate) const ENTRIES_ENV: &str = "BHF_SYMCC_ENTRIES";
/// The log, in the run's work dir, of the inputs SymCC gave the pass: one
/// line per input, `<ms since the pass started> <sha256 of the entry SymCC
/// ran> <sha256 of the input>`.
pub(crate) const IMPORT_LOG: &str = "symcc-import.log";

const DEFAULT_PLATEAU: Duration = Duration::from_secs(5);
const DEFAULT_RUN_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_ENTRIES_PER_ROUND: usize = 8;
/// The most inputs one SymCC run may give the pass.
const MAX_INPUTS_PER_RUN: usize = 256;
/// Runs in a row that fail without writing an input before the stage stops:
/// a binary that cannot run would otherwise cost every plateau's budget.
const MAX_FAILED_RUNS_IN_A_ROW: usize = 3;

/// How a builtin pass runs its plateaued corpus entries through SymCC
/// (#331): the `main_symcc` beside the harness, how it runs (under the
/// sandbox the harness runs under, and the pass's memory limit), how long
/// the pass's corpus must stop growing first, how long one run may take, and
/// how many entries a round runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SymccConfig {
    pub(crate) binary: PathBuf,
    /// The runner of `binary`: the harness's sandbox (`--sandbox`), with
    /// SymCC's own directories bound read-only for its runtime library.
    pub(crate) runner: replay_min::HarnessRunner,
    /// The pass's `--rss-limit-mb`, which a SymCC run takes as its
    /// address-space limit (`RLIMIT_AS`): `main_symcc` carries no
    /// sanitizer's shadow reservation, so that limit bounds what it and the
    /// solver allocate. `0` sets none.
    pub(crate) rss_limit_mb: usize,
    pub(crate) plateau: Duration,
    pub(crate) run_timeout: Duration,
    pub(crate) entries_per_round: usize,
}

/// The sandbox a pass runs its harness under (`--sandbox`,
/// `--sandbox-tool`, `--sandbox-strict`), which its SymCC runs take too.
#[derive(Debug, Clone)]
pub(crate) struct Sandbox {
    pub(crate) mode: crate::runner::SandboxModeArg,
    pub(crate) tool: Option<PathBuf>,
    pub(crate) strict: bool,
}

impl SymccConfig {
    /// The SymCC stage of a builtin pass over `harness`, when the run asked
    /// for SymCC, the license profile allows it, the harness runs natively
    /// (`emulated` is false) and the SymCC lane built beside it: its
    /// `main_symcc` is there, and the harness's `lanes.json` does not say
    /// the lane failed (a binary an earlier build left). Its runs take the
    /// pass's `sandbox` and `rss_limit_mb`.
    pub(crate) fn for_run(
        harness: &Path,
        emulated: bool,
        sandbox: &Sandbox,
        rss_limit_mb: usize,
    ) -> Option<Self> {
        if cfg!(windows) || emulated || !requested() || !profile_allows(license_profile()) {
            return None;
        }
        Self::for_harness(harness, sandbox, rss_limit_mb)
    }

    /// [`Self::for_run`] once the run may run SymCC.
    fn for_harness(harness: &Path, sandbox: &Sandbox, rss_limit_mb: usize) -> Option<Self> {
        let dir = harness.parent()?;
        let binary = crate::auto::layout::harness_exe(dir, BINARY);
        if !binary.is_file()
            || crate::auto::lanes::read(dir)
                .get(LANE)
                .is_some_and(|lane| !lane.built)
        {
            return None;
        }
        let env_number = |name: &str| {
            std::env::var(name)
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
        };
        let runner = crate::runner::harness_runner_with_wrapper(
            binary.clone(),
            None,
            sandbox.mode,
            sandbox.tool.clone(),
            sandbox.strict,
        )
        .with_ro_binds(runtime_dirs(&find_compilers()));
        Some(Self {
            binary,
            runner,
            rss_limit_mb,
            plateau: env_number(PLATEAU_ENV)
                .map(Duration::from_millis)
                .unwrap_or(DEFAULT_PLATEAU),
            run_timeout: env_number(TIMEOUT_ENV)
                .filter(|&ms| ms > 0)
                .map(Duration::from_millis)
                .unwrap_or(DEFAULT_RUN_TIMEOUT),
            entries_per_round: env_number(ENTRIES_ENV)
                .and_then(|n| usize::try_from(n).ok())
                .filter(|&n| n > 0)
                .unwrap_or(DEFAULT_ENTRIES_PER_ROUND),
        })
    }
}

/// The directories a sandboxed `main_symcc` reads besides the harness's:
/// SymCC's build, where its compiler wrappers are and which holds the
/// runtime library they link with an rpath, and the runtime and libc++
/// directories `SYMCC_RUNTIME_DIR` and `SYMCC_LIBCXX_PATH` name.
fn runtime_dirs(compilers: &Compilers) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let found = [&compilers.cc, &compilers.cxx]
        .into_iter()
        .flatten()
        .filter_map(|compiler| {
            compiler
                .canonicalize()
                .ok()?
                .parent()
                .map(Path::to_path_buf)
        });
    let named = ["SYMCC_RUNTIME_DIR", "SYMCC_LIBCXX_PATH"]
        .into_iter()
        .filter_map(std::env::var_os)
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from);
    for dir in found.chain(named) {
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    dirs
}

/// Cap the address space of the process `command` starts at `mb` MiB
/// (`RLIMIT_AS`, soft and hard, never above the hard limit it inherits),
/// which the sandbox tool it may run passes on. `0` caps nothing.
#[cfg(unix)]
fn limit_address_space(command: &mut std::process::Command, mb: usize) {
    use std::os::unix::process::CommandExt;
    if mb == 0 {
        return;
    }
    let bytes = u64::try_from(mb)
        .unwrap_or(u64::MAX)
        .saturating_mul(1024 * 1024);
    let bytes = libc::rlim_t::try_from(bytes).unwrap_or(libc::rlim_t::MAX);
    // SAFETY: the closure makes only the async-signal-safe getrlimit and
    // setrlimit calls between fork and exec.
    unsafe {
        command.pre_exec(move || {
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::getrlimit(libc::RLIMIT_AS, &mut limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let cap = bytes.min(limit.rlim_max);
            limit.rlim_cur = cap;
            limit.rlim_max = cap;
            if libc::setrlimit(libc::RLIMIT_AS, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn limit_address_space(_command: &mut std::process::Command, _mb: usize) {}

/// What a pass's SymCC stage did, in its run summary (`symcc`).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub(crate) struct SymccRunSummary {
    /// The `main_symcc` the pass ran.
    pub(crate) binary: PathBuf,
    /// The plateau that started each round, in milliseconds.
    pub(crate) plateau_ms: u64,
    /// Plateaus on which entries ran through SymCC.
    pub(crate) rounds: usize,
    /// Corpus entries SymCC ran.
    pub(crate) entries_solved: usize,
    /// Inputs SymCC wrote.
    pub(crate) inputs_generated: usize,
    /// Of those, the ones the pass did not have and ran.
    pub(crate) inputs_imported: usize,
    /// Runs that exited with an error or a signal (the inputs they wrote
    /// before still count).
    pub(crate) failed_runs: usize,
    /// Runs killed at the run timeout.
    pub(crate) timed_out_runs: usize,
    /// Why the stage stopped before the pass did, when it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) stopped: Option<String>,
}

/// The SymCC stage of one builtin pass (#331), the solver loop AFL++'s
/// SymCC mutator and LibAFL's concolic stage run: once the pass's corpus
/// has stopped growing for the plateau, its newest entries that SymCC has
/// not run yet run through `main_symcc`, and each input SymCC writes that
/// the pass does not have runs next, and stays in the corpus if it adds
/// coverage there. A pass's rounds share one SymCC coverage map
/// (`SYMCC_AFL_COVERAGE_MAP`), so a branch SymCC has flipped once is not
/// solved again.
pub(crate) struct SymccStage {
    config: SymccConfig,
    scratch: PathBuf,
    started: Instant,
    /// When the pool last grew (or a round ended).
    last_growth: Instant,
    /// The pool's length at the last tick.
    pool_len: usize,
    /// sha256 of each pool entry, by index, and whether it is retired.
    pool: Vec<(String, bool)>,
    /// Content hashes the pass has: pool entries and imports.
    known: HashSet<String>,
    /// Pool entries SymCC has run.
    solved: HashSet<String>,
    pending: VecDeque<Vec<u8>>,
    max_len: usize,
    failed_in_a_row: usize,
    summary: SymccRunSummary,
    log: Option<std::fs::File>,
}

fn digest(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    corpus::hex_lower(&sha2::Sha256::digest(bytes))
}

impl SymccStage {
    /// The stage of a pass in `work_dir` over `harness_id`, whose corpus
    /// takes inputs of at most `max_len` bytes, started at `now`.
    pub(crate) fn new(
        config: SymccConfig,
        work_dir: &Path,
        harness_id: &str,
        max_len: usize,
        now: Instant,
    ) -> Self {
        let scratch = work_dir
            .join("fuzz_scratch")
            .join(format!("symcc-{harness_id}"));
        let _ = std::fs::remove_dir_all(&scratch);
        let _ = std::fs::create_dir_all(&scratch);
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(work_dir.join(IMPORT_LOG))
            .ok();
        let summary = SymccRunSummary {
            binary: config.binary.clone(),
            plateau_ms: u64::try_from(config.plateau.as_millis()).unwrap_or(u64::MAX),
            ..SymccRunSummary::default()
        };
        Self {
            config,
            scratch,
            started: now,
            last_growth: now,
            pool_len: 0,
            pool: Vec::new(),
            known: HashSet::new(),
            solved: HashSet::new(),
            pending: VecDeque::new(),
            max_len: max_len.max(1),
            failed_in_a_row: 0,
            summary,
            log,
        }
    }

    /// Look at the pool at `now`: its `len` entries, with `entry(i)` the
    /// bytes of entry `i` and whether it is retired (a known crasher). When
    /// the pool has not grown for the plateau and no input SymCC gave is
    /// still waiting, run a round: the newest entries SymCC has not run,
    /// newest first. No run starts within 50 ms of `deadline`, and none runs
    /// past it.
    pub(crate) fn tick<'a>(
        &mut self,
        now: Instant,
        len: usize,
        entry: impl Fn(usize) -> (&'a [u8], bool),
        deadline: Option<Instant>,
    ) {
        if self.summary.stopped.is_some() {
            return;
        }
        if len < self.pool.len() {
            self.pool.truncate(len);
        }
        for index in self.pool.len()..len {
            let (bytes, retired) = entry(index);
            let hash = digest(bytes);
            self.known.insert(hash.clone());
            self.pool.push((hash, retired));
        }
        if len > self.pool_len {
            self.pool_len = len;
            self.last_growth = now;
            return;
        }
        self.pool_len = len;
        if !self.pending.is_empty()
            || now.saturating_duration_since(self.last_growth) < self.config.plateau
        {
            return;
        }
        for (index, slot) in self.pool.iter_mut().enumerate() {
            slot.1 = entry(index).1;
        }
        let picks: Vec<usize> = (0..len)
            .rev()
            .filter(|&index| {
                let (hash, retired) = &self.pool[index];
                !retired && !entry(index).0.is_empty() && !self.solved.contains(hash)
            })
            .take(self.config.entries_per_round)
            .collect();
        let mut ran = 0;
        for index in picks {
            let left = deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
            if left.is_some_and(|left| left < Duration::from_millis(50)) {
                break;
            }
            let timeout = left.map_or(self.config.run_timeout, |left| {
                left.min(self.config.run_timeout)
            });
            let hash = self.pool[index].0.clone();
            self.solved.insert(hash.clone());
            self.solve(entry(index).0, &hash, timeout);
            ran += 1;
            if self.summary.stopped.is_some() {
                break;
            }
        }
        if ran > 0 {
            self.summary.rounds += 1;
        }
        // The next round waits for another plateau, which the inputs this one
        // gave may end.
        self.last_growth = now.max(Instant::now());
    }

    /// The next input SymCC gave that the pass has not run.
    pub(crate) fn next_import(&mut self) -> Option<Vec<u8>> {
        self.pending.pop_front()
    }

    /// What the stage did.
    pub(crate) fn summary(&self) -> &SymccRunSummary {
        &self.summary
    }

    /// Run `entry` (sha256 `hash`) through SymCC once, for at most `timeout`,
    /// and queue the inputs it writes that the pass does not have.
    fn solve(&mut self, entry: &[u8], hash: &str, timeout: Duration) {
        let input = self.scratch.join("input.bin");
        let out = self.scratch.join("out");
        let _ = std::fs::remove_dir_all(&out);
        if std::fs::create_dir_all(&out).is_err() || std::fs::write(&input, entry).is_err() {
            self.summary.stopped = Some(format!(
                "could not write SymCC's input under {}",
                self.scratch.display()
            ));
            return;
        }
        // Under the harness's sandbox, which binds the scratch dir (the
        // input's, and SymCC's output dir and coverage map under it)
        // read-write: a strict sandbox that cannot run stops the stage.
        let mut command = match self.config.runner.command_wrapped(&input) {
            Ok(command) => command,
            Err(error) => {
                self.summary.stopped = Some(format!(
                    "{} cannot run under the harness's sandbox: {error}",
                    self.config.binary.display()
                ));
                return;
            }
        };
        limit_address_space(&mut command, self.config.rss_limit_mb);
        command
            .arg(&input)
            .env("SYMCC_INPUT_FILE", &input)
            .env("SYMCC_OUTPUT_DIR", &out)
            .env("SYMCC_AFL_COVERAGE_MAP", self.scratch.join("coverage.map"))
            .env("SYMCC_ENABLE_LINEARIZATION", "1")
            .stdin(std::process::Stdio::null());
        // SymCC's run is not one of the pass's executions: it writes into
        // none of the engine's maps and loads no shim.
        for name in DRIVER_CHANNELS {
            command.env_remove(name);
        }
        self.summary.entries_solved += 1;
        let run = crate::command_output::capture_with_timeout(&mut command, timeout, 64 * 1024);
        let (failed, timed_out) = match &run {
            Ok(run) => (
                !run.output.status.success() && !run.timed_out,
                run.timed_out,
            ),
            Err(_) => (true, false),
        };
        if failed {
            self.summary.failed_runs += 1;
        }
        if timed_out {
            self.summary.timed_out_runs += 1;
        }
        let mut files: Vec<PathBuf> = std::fs::read_dir(&out)
            .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
            .unwrap_or_default();
        files.sort();
        let written = files.len().min(MAX_INPUTS_PER_RUN);
        self.summary.inputs_generated += written;
        let millis = self.started.elapsed().as_millis();
        for file in files.into_iter().take(MAX_INPUTS_PER_RUN) {
            let Ok(mut bytes) = std::fs::read(&file) else {
                continue;
            };
            bytes.truncate(self.max_len);
            let new = digest(&bytes);
            if bytes.is_empty() || !self.known.insert(new.clone()) {
                continue;
            }
            if let Some(log) = self.log.as_mut() {
                let _ = writeln!(log, "{millis} {hash} {new}");
            }
            self.summary.inputs_imported += 1;
            self.pending.push_back(bytes);
        }
        let _ = std::fs::remove_dir_all(&out);
        if (failed || timed_out) && written == 0 {
            self.failed_in_a_row += 1;
            if self.failed_in_a_row >= MAX_FAILED_RUNS_IN_A_ROW {
                let why = match &run {
                    Ok(run) if run.timed_out => format!(
                        "{} runs in a row ran past the {} ms run timeout ({TIMEOUT_ENV}) and \
                         wrote no input",
                        self.failed_in_a_row,
                        self.config.run_timeout.as_millis()
                    ),
                    Ok(run) => {
                        let stderr = String::from_utf8_lossy(&run.output.stderr);
                        let last = stderr.lines().rev().find(|line| !line.trim().is_empty());
                        format!(
                            "{} runs in a row failed and wrote no input ({}{})",
                            self.failed_in_a_row,
                            run.output.status,
                            last.map(|line| format!(": {}", line.trim()))
                                .unwrap_or_default()
                        )
                    }
                    Err(error) => {
                        format!("{} could not run: {error}", self.config.binary.display())
                    }
                };
                self.summary.stopped = Some(why);
            }
        } else {
            self.failed_in_a_row = 0;
        }
    }
}

/// What a pass's SymCC stage did, for the line `bhf auto` prints after the
/// pass; `None` when it ran no round and did not stop.
pub(crate) fn pass_note(summary: Option<&SymccRunSummary>) -> Option<String> {
    let summary = summary?;
    let entries = if summary.entries_solved == 1 {
        "entry"
    } else {
        "entries"
    };
    let mut note = (summary.rounds > 0).then(|| {
        format!(
            "SymCC ran {} plateaued corpus {entries} in {} round(s) and gave the pass {} new \
             input(s)",
            summary.entries_solved, summary.rounds, summary.inputs_imported
        )
    });
    if let Some(stopped) = &summary.stopped {
        let stop = format!("SymCC stopped: {stopped}");
        note = Some(match note {
            Some(note) => format!("{note}; {stop}"),
            None => stop,
        });
    }
    note
}

/// The variables that point bhf's driver at the engine's shared maps and
/// preload the runtrace shim, which a SymCC run must not inherit.
const DRIVER_CHANNELS: &[&str] = &[
    "BHF_FRAMED",
    "BHF_COV_SHM",
    "BHF_COV_CNT_SHM",
    "BHF_CMP_SHM",
    "BHF_CMP_PROGRESS_SHM",
    "BHF_VP_SHM",
    "BHF_STACK_DEPTH_SHM",
    "BHF_TARGET_ENTRY_SHM",
    "BHF_RUNTRACE_LOG",
    "BHF_CMPLOG",
    "LD_PRELOAD",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn exit(code: i32) -> std::process::ExitStatus {
        #[cfg(unix)]
        {
            std::os::unix::process::ExitStatusExt::from_raw(code << 8)
        }
        #[cfg(windows)]
        {
            std::os::windows::process::ExitStatusExt::from_raw(code as u32)
        }
    }

    fn output(code: i32, stderr: &str) -> std::process::Output {
        std::process::Output {
            status: exit(code),
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    fn found() -> Compilers {
        Compilers {
            cc: Some(PathBuf::from("/opt/symcc/symcc")),
            cxx: Some(PathBuf::from("/opt/symcc/sym++")),
        }
    }

    #[test]
    fn an_explicit_profile_wins_and_none_opts_into_external_tools() {
        use config::Profile;
        assert_eq!(profile_from(None), Profile::ExternalTools);
        assert_eq!(
            profile_from(Some("strict-permissive")),
            Profile::StrictPermissive
        );
        assert_eq!(profile_from(Some("research-lab")), Profile::ResearchLab);
        assert_eq!(profile_from(Some("widget")), Profile::ExternalTools);
        assert!(!profile_allows(Profile::StrictPermissive));
        assert!(profile_allows(Profile::ExternalTools));
        assert!(profile_allows(Profile::ResearchLab));
    }

    #[test]
    fn the_gate_refuses_a_strict_profile_and_missing_compilers() {
        use config::Profile;
        let strict = run_gate(Profile::StrictPermissive, &found()).unwrap_err();
        assert!(strict.contains("`strict-permissive`"), "{strict}");
        assert!(strict.contains("BHF_PROFILE=external-tools"), "{strict}");
        let none = run_gate(Profile::ExternalTools, &Compilers::default()).unwrap_err();
        assert!(none.contains("no `symcc` or `sym++` on PATH"), "{none}");
        let c_only = Compilers {
            cc: Some(PathBuf::from("/opt/symcc/symcc")),
            cxx: None,
        };
        let note = run_gate(Profile::ResearchLab, &c_only).unwrap();
        assert!(note.contains("C harnesses build main_symcc with /opt/symcc/symcc"));
        assert!(note.contains("C++ harnesses with none (no `sym++` on PATH"));
    }

    /// The lane is recorded in the harness's lanes.json, built or not; make
    /// runs only when the profile allows SymCC and its compiler was found.
    #[test]
    fn the_lane_is_built_only_when_allowed_and_recorded_either_way() {
        use config::Profile;
        let dir = tempfile::tempdir().unwrap();
        let harness = dir.path();
        let mut ran = 0;
        let status = build_lane_with(Profile::StrictPermissive, &found(), false, harness, || {
            ran += 1;
            output(0, "")
        });
        assert!(!status.built);
        assert_eq!(ran, 0, "make ran under strict-permissive");
        assert_eq!(
            crate::auto::lanes::read(harness)[LANE].reason.as_deref(),
            Some("the `strict-permissive` license profile does not allow SymCC")
        );

        let c_only = Compilers {
            cc: Some(PathBuf::from("/opt/symcc/symcc")),
            cxx: None,
        };
        let status = build_lane_with(Profile::ExternalTools, &c_only, true, harness, || {
            ran += 1;
            output(0, "")
        });
        assert_eq!(ran, 0, "make ran without sym++");
        assert_eq!(
            status.reason.as_deref(),
            Some("SymCC's `sym++` is not on PATH and SYMCC_CXX names none")
        );

        let status = build_lane_with(Profile::ExternalTools, &found(), false, harness, || {
            ran += 1;
            output(
                2,
                "main.c:3:10: error: unknown type name 'widget_t'\n\
                 make: *** [Makefile:481: main_symcc] Error 1\n",
            )
        });
        assert_eq!(ran, 1);
        assert_eq!(
            status.reason.as_deref(),
            Some("make main_symcc failed: main.c:3:10: error: unknown type name 'widget_t'")
        );
        assert!(!crate::auto::lanes::read(harness)[LANE].built);

        // make succeeding without leaving the binary is no lane either.
        let status = build_lane_with(Profile::ExternalTools, &found(), false, harness, || {
            output(0, "")
        });
        assert!(!status.built);
        std::fs::write(
            crate::auto::layout::harness_exe(harness, BINARY),
            b"#!/bin/sh\n",
        )
        .unwrap();
        let status = build_lane_with(Profile::ExternalTools, &found(), false, harness, || {
            output(0, "")
        });
        assert!(status.built, "{status:?}");
        let recorded = &crate::auto::lanes::read(harness)[LANE];
        assert!(recorded.built && recorded.recorded_at.is_some());
    }

    /// The lane builds at the language standard the harness's `main` built
    /// with: a C harness that needed a `gnu89` rung of the dialect ladder
    /// gets `C_STD=gnu89`, a C++ one its `CXX_STD`. The stand-in Makefiles
    /// build `main_symcc` only at that standard.
    #[cfg(unix)]
    #[test]
    fn the_lane_builds_at_the_standard_main_built_with() {
        use config::Profile;
        if which::which("make").is_err() {
            eprintln!("skip: make unavailable");
            return;
        }
        let work = tempfile::tempdir().unwrap();
        for (id, cpp, var, standard) in [
            ("H-LEGACY", false, "C_STD", "gnu89"),
            ("H-WIDGET", true, "CXX_STD", "gnu++14"),
        ] {
            let harness = crate::auto::layout::harness_dir(work.path(), id);
            std::fs::create_dir_all(&harness).unwrap();
            if cpp {
                std::fs::write(harness.join("main.cpp"), "").unwrap();
            }
            std::fs::write(
                harness.join("Makefile"),
                format!(
                    "{var} ?=\nsymcc:\n\
                     \t@test \"$({var})\" = {standard} || {{ echo \"{var}='$({var})'\" >&2; exit 1; }}\n\
                     \t@touch main_symcc\n"
                ),
            )
            .unwrap();
            let status = build_lane_in(
                Profile::ExternalTools,
                &found(),
                &LaneBuild {
                    work_dir: work.path(),
                    harness_id: id,
                    harness_dir: &harness,
                    cpp,
                    extra_sources: &[],
                    extra_includes: &[],
                    standard: Some(standard),
                },
            );
            assert!(status.built, "{id}: {status:?}");
        }
    }

    #[test]
    fn the_pass_note_says_what_the_stage_solved() {
        assert_eq!(pass_note(None), None);
        let mut summary = SymccRunSummary::default();
        assert_eq!(pass_note(Some(&summary)), None);
        summary.rounds = 2;
        summary.entries_solved = 1;
        summary.inputs_imported = 3;
        assert_eq!(
            pass_note(Some(&summary)).as_deref(),
            Some(
                "SymCC ran 1 plateaued corpus entry in 2 round(s) and gave the pass 3 new input(s)"
            )
        );
        summary.entries_solved = 4;
        summary.stopped = Some("3 runs in a row failed".to_owned());
        assert_eq!(
            pass_note(Some(&summary)).as_deref(),
            Some(
                "SymCC ran 4 plateaued corpus entries in 2 round(s) and gave the pass 3 new \
                 input(s); SymCC stopped: 3 runs in a row failed"
            )
        );
    }

    /// A stand-in for `main_symcc` that logs each run (its argument, then
    /// SYMCC_INPUT_FILE, then the input's bytes in hex) and copies the
    /// recorded solver outputs in `recorded` into SYMCC_OUTPUT_DIR. It fails
    /// when SymCC's coverage map is not set, as the stage must set it.
    #[cfg(unix)]
    fn recorded_solver(dir: &Path, recorded: &Path) -> (PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let log = dir.join("solver.log");
        let solver = dir.join("main_symcc");
        std::fs::write(
            &solver,
            format!(
                "#!/bin/sh\n[ -n \"$SYMCC_AFL_COVERAGE_MAP\" ] || exit 9\n\
                 printf '%s %s %s\\n' \"$1\" \"$SYMCC_INPUT_FILE\" \
                 \"$(od -An -tx1 \"$1\" | tr -d ' \\n')\" >> '{}'\n\
                 cp '{}'/* \"$SYMCC_OUTPUT_DIR\"/\n",
                log.display(),
                recorded.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&solver, std::fs::Permissions::from_mode(0o755)).unwrap();
        (solver, log)
    }

    #[cfg(unix)]
    fn config(binary: PathBuf, plateau_ms: u64, entries_per_round: usize) -> SymccConfig {
        SymccConfig {
            runner: replay_min::HarnessRunner::direct(binary.clone()),
            binary,
            rss_limit_mb: 0,
            plateau: Duration::from_millis(plateau_ms),
            run_timeout: Duration::from_secs(5),
            entries_per_round,
        }
    }

    #[cfg(unix)]
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[cfg(unix)]
    fn runs(log: &Path) -> Vec<Vec<String>> {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .map(|line| line.split(' ').map(str::to_owned).collect())
            .collect()
    }

    /// #331: a round waits until the corpus has not grown for the plateau,
    /// runs the newest entry SymCC has not run, and the recorded solver
    /// output becomes the pass's next input, once.
    #[cfg(unix)]
    #[test]
    fn a_plateau_runs_the_newest_entries_and_imports_the_solver_outputs() {
        let dir = tempfile::tempdir().unwrap();
        let recorded = dir.path().join("recorded");
        std::fs::create_dir_all(&recorded).unwrap();
        std::fs::write(recorded.join("000000"), b"solved").unwrap();
        let (solver, log) = recorded_solver(dir.path(), &recorded);
        let work = dir.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let t0 = Instant::now();
        let ms = |ms: u64| t0 + Duration::from_millis(ms);
        let mut stage = SymccStage::new(config(solver, 1000, 1), &work, "H-1", 64, t0);
        let pool: Vec<Vec<u8>> = vec![b"first".to_vec(), b"second".to_vec()];
        let entry = |index: usize| (pool[index].as_slice(), false);

        stage.tick(t0, 1, entry, None);
        stage.tick(ms(900), 1, entry, None);
        // A new entry restarts the plateau.
        stage.tick(ms(950), 2, entry, None);
        stage.tick(ms(1500), 2, entry, None);
        assert!(runs(&log).is_empty(), "ran before the plateau");
        assert_eq!(stage.summary().rounds, 0);

        stage.tick(ms(2000), 2, entry, None);
        let ran = runs(&log);
        assert_eq!(ran.len(), 1, "{ran:?}");
        assert_eq!(ran[0][0], ran[0][1], "argv[1] is SYMCC_INPUT_FILE");
        assert_eq!(ran[0][2], hex(b"second"), "the newest entry runs first");
        assert_eq!(stage.next_import(), Some(b"solved".to_vec()));
        assert_eq!(stage.next_import(), None);

        // The next round waits for another plateau, and runs the entry SymCC
        // has not run; its output, which the pass has now, is not run again.
        stage.tick(ms(2500), 2, entry, None);
        assert_eq!(runs(&log).len(), 1);
        stage.tick(ms(3100), 2, entry, None);
        let ran = runs(&log);
        assert_eq!(ran.len(), 2, "{ran:?}");
        assert_eq!(ran[1][2], hex(b"first"));
        assert_eq!(stage.next_import(), None);
        // Every entry has run: a later plateau runs nothing.
        stage.tick(ms(4200), 2, entry, None);
        assert_eq!(runs(&log).len(), 2);

        let summary = stage.summary();
        assert_eq!(summary.rounds, 2);
        assert_eq!(summary.entries_solved, 2);
        assert_eq!(summary.inputs_generated, 2);
        assert_eq!(summary.inputs_imported, 1);
        assert_eq!(summary.plateau_ms, 1000);
        let imports = std::fs::read_to_string(work.join(IMPORT_LOG)).unwrap();
        let line: Vec<&str> = imports.lines().collect();
        assert_eq!(line.len(), 1, "{imports}");
        let fields: Vec<&str> = line[0].split(' ').collect();
        assert_eq!(fields[1], digest(b"second"));
        assert_eq!(fields[2], digest(b"solved"));
    }

    /// Solver outputs the pass already has, empty ones and repeats are
    /// dropped; one longer than the corpus takes is cut to fit. Retired
    /// entries (known crashers) never run.
    #[cfg(unix)]
    #[test]
    fn known_empty_and_repeated_solver_outputs_are_dropped_and_long_ones_cut() {
        let dir = tempfile::tempdir().unwrap();
        let recorded = dir.path().join("recorded");
        std::fs::create_dir_all(&recorded).unwrap();
        std::fs::write(recorded.join("000000"), b"parse_record").unwrap();
        std::fs::write(recorded.join("000001"), vec![b'x'; 100]).unwrap();
        let mut longer = vec![b'x'; 100];
        longer.push(b'y');
        std::fs::write(recorded.join("000002"), longer).unwrap();
        std::fs::write(recorded.join("000003"), b"").unwrap();
        let (solver, log) = recorded_solver(dir.path(), &recorded);
        let t0 = Instant::now();
        let mut stage = SymccStage::new(config(solver, 0, 8), dir.path(), "H-2", 16, t0);
        let pool: Vec<Vec<u8>> = vec![b"parse_record".to_vec(), b"crasher".to_vec()];
        let entry = |index: usize| (pool[index].as_slice(), index == 1);
        stage.tick(t0, 2, entry, None);
        stage.tick(t0 + Duration::from_millis(1), 2, entry, None);
        let ran = runs(&log);
        assert_eq!(ran.len(), 1, "the retired entry ran: {ran:?}");
        assert_eq!(ran[0][2], hex(b"parse_record"));
        assert_eq!(stage.next_import(), Some(vec![b'x'; 16]));
        assert_eq!(stage.next_import(), None);
        assert_eq!(stage.summary().inputs_generated, 4);
        assert_eq!(stage.summary().inputs_imported, 1);
    }

    /// No run starts at the pass's deadline.
    #[cfg(unix)]
    #[test]
    fn no_solver_run_starts_at_the_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let recorded = dir.path().join("recorded");
        std::fs::create_dir_all(&recorded).unwrap();
        let (solver, log) = recorded_solver(dir.path(), &recorded);
        let t0 = Instant::now();
        let mut stage = SymccStage::new(config(solver, 0, 8), dir.path(), "H-3", 64, t0);
        let pool: Vec<Vec<u8>> = vec![b"entry".to_vec()];
        let entry = |index: usize| (pool[index].as_slice(), false);
        stage.tick(t0, 1, entry, Some(t0));
        stage.tick(t0, 1, entry, Some(Instant::now()));
        assert!(runs(&log).is_empty());
        assert_eq!(stage.summary().entries_solved, 0);
        assert_eq!(stage.summary().rounds, 0);
    }

    /// A solver that cannot do its job stops the stage after three runs in a
    /// row that wrote nothing, saying why, and a run past the run timeout is
    /// killed.
    #[cfg(unix)]
    #[test]
    fn a_failing_or_hanging_solver_stops_the_stage() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let failing = dir.path().join("failing");
        std::fs::write(
            &failing,
            "#!/bin/sh\necho 'cannot load widget' >&2\nexit 3\n",
        )
        .unwrap();
        let hanging = dir.path().join("hanging");
        std::fs::write(&hanging, "#!/bin/sh\nexec sleep 30\n").unwrap();
        for script in [&failing, &hanging] {
            std::fs::set_permissions(script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let pool: Vec<Vec<u8>> = (0..5).map(|n| vec![b'a' + n; 4]).collect();
        let entry = |index: usize| (pool[index].as_slice(), false);
        let t0 = Instant::now();

        let mut stage = SymccStage::new(config(failing, 0, 8), dir.path(), "H-4", 64, t0);
        stage.tick(t0, 5, entry, None);
        stage.tick(t0, 5, entry, None);
        let summary = stage.summary();
        assert_eq!(summary.entries_solved, 3);
        assert_eq!(summary.failed_runs, 3);
        assert_eq!(
            summary.stopped.as_deref(),
            Some("3 runs in a row failed and wrote no input (exit status: 3: cannot load widget)")
        );
        stage.tick(t0 + Duration::from_secs(1), 5, entry, None);
        assert_eq!(
            stage.summary().entries_solved,
            3,
            "a stopped stage runs nothing"
        );

        let mut hang = config(hanging, 0, 1);
        hang.run_timeout = Duration::from_millis(200);
        let mut stage = SymccStage::new(hang, dir.path(), "H-5", 64, t0);
        stage.tick(t0, 5, entry, None);
        let started = Instant::now();
        stage.tick(t0, 5, entry, None);
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(stage.summary().timed_out_runs, 1);
        assert_eq!(stage.summary().failed_runs, 0);
    }

    /// #331: the SymCC stage runs `main_symcc` as the pass runs its harness:
    /// under the harness's sandbox (here a stand-in firejail, which logs how
    /// it was called and runs the rest), and under the pass's memory limit,
    /// which the solver sees as its address-space limit. The inputs it
    /// writes still reach the pass.
    #[cfg(unix)]
    #[test]
    fn the_solver_runs_under_the_harness_sandbox_and_memory_limit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let harness_dir = dir.path().join("harnesses/H-6");
        std::fs::create_dir_all(&harness_dir).unwrap();
        let recorded = dir.path().join("recorded");
        std::fs::create_dir_all(&recorded).unwrap();
        std::fs::write(recorded.join("000000"), b"solved").unwrap();
        let limit_log = dir.path().join("limit.log");
        let solver = crate::auto::layout::harness_exe(&harness_dir, BINARY);
        std::fs::write(
            &solver,
            format!(
                "#!/bin/sh\nulimit -v > '{}'\ncp '{}'/* \"$SYMCC_OUTPUT_DIR\"/\n",
                limit_log.display(),
                recorded.display()
            ),
        )
        .unwrap();
        let wrapper_log = dir.path().join("firejail.log");
        let firejail = dir.path().join("firejail");
        std::fs::write(
            &firejail,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n\
                 while [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"\n",
                wrapper_log.display()
            ),
        )
        .unwrap();
        for script in [&solver, &firejail] {
            std::fs::set_permissions(script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let sandbox = Sandbox {
            mode: crate::runner::SandboxModeArg::Firejail,
            tool: Some(firejail.clone()),
            strict: true,
        };
        let config = SymccConfig::for_harness(&harness_dir.join("main"), &sandbox, 256)
            .expect("main_symcc is beside the harness");
        assert_eq!(config.runner.sandbox_metadata().mode, "firejail");
        let mut config = config;
        config.plateau = Duration::ZERO;
        config.entries_per_round = 1;
        let work = dir.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let t0 = Instant::now();
        let mut stage = SymccStage::new(config, &work, "H-6", 64, t0);
        let pool: Vec<Vec<u8>> = vec![b"parse_record".to_vec()];
        let entry = |index: usize| (pool[index].as_slice(), false);
        stage.tick(t0, 1, entry, None);
        stage.tick(t0, 1, entry, None);
        let calls = std::fs::read_to_string(&wrapper_log).unwrap_or_default();
        let input = work.join("fuzz_scratch/symcc-H-6/input.bin");
        assert_eq!(
            calls.trim(),
            format!(
                "--quiet --net=none -- {} {}",
                solver.display(),
                input.display()
            ),
            "the solver did not run under the sandbox"
        );
        assert_eq!(
            std::fs::read_to_string(&limit_log).unwrap().trim(),
            (256 * 1024).to_string(),
            "the solver ran without the memory limit"
        );
        assert_eq!(stage.next_import(), Some(b"solved".to_vec()));
        assert_eq!(stage.summary().failed_runs, 0);
    }

    /// A strict sandbox that cannot run stops the stage before any SymCC run
    /// starts outside it.
    #[cfg(unix)]
    #[test]
    fn a_sandbox_that_cannot_run_stops_the_stage_before_any_run() {
        let dir = tempfile::tempdir().unwrap();
        let recorded = dir.path().join("recorded");
        std::fs::create_dir_all(&recorded).unwrap();
        let (solver, log) = recorded_solver(dir.path(), &recorded);
        let mut config = config(solver.clone(), 0, 8);
        config.runner = replay_min::HarnessRunner::direct(solver)
            .with_sandbox(replay_min::SandboxConfig::bubblewrap("/nonexistent/bwrap"));
        let t0 = Instant::now();
        let mut stage = SymccStage::new(config, dir.path(), "H-7", 64, t0);
        let pool: Vec<Vec<u8>> = vec![b"parse_record".to_vec()];
        let entry = |index: usize| (pool[index].as_slice(), false);
        stage.tick(t0, 1, entry, None);
        stage.tick(t0, 1, entry, None);
        assert!(runs(&log).is_empty(), "SymCC ran outside the sandbox");
        assert_eq!(stage.summary().entries_solved, 0);
        let stopped = stage.summary().stopped.clone().unwrap_or_default();
        assert!(
            stopped.contains("cannot run under the harness's sandbox")
                && stopped.contains("/nonexistent/bwrap"),
            "{stopped}"
        );
    }
}
