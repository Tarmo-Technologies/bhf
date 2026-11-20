// SPDX-License-Identifier: Apache-2.0

use crate::finding_arg::resolve_finding_arg;
use crate::runner::{detect_harness_engine_in, harness_runner_for, HarnessEngine, SandboxModeArg};
use anyhow::{anyhow, Context};
use clap::ValueEnum;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, clap::Args)]
pub struct MinimizeArgs {
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

    /// Harness binary path. Optional: when omitted it is resolved from the
    /// finding's recorded `fixture_path` or `harness_id` the way `bhf replay`
    /// resolves it (`<work>/{harnesses,auto,generated_harnesses,build}/<harness_id>/main`).
    /// Not used for a session finding (HDF-7), which minimizes by re-driving
    /// the recorded multi-message session rather than re-running a harness
    /// binary.
    #[arg(long)]
    pub harness: Option<PathBuf>,

    /// qemu-user executable for ELF-Linux cross-target minimization. Default:
    /// the emulator recorded beside the harness (`bhf_runner.json`, written by
    /// a cross build); a harness built for another architecture with neither
    /// is refused.
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

    /// Minimization strategy.
    #[arg(long, value_enum, default_value_t = MinimizeStrategy::Bytes)]
    pub strategy: MinimizeStrategy,

    /// The JSON grammar (`bhf fuzz --grammar`'s format) a `--strategy grammar`
    /// minimization parses the testcase with.
    #[arg(
        long = "grammar",
        value_name = "PATH",
        required_if_eq("strategy", "grammar")
    )]
    pub grammar: Option<PathBuf>,

    /// Minimize against the crash the harness reports even when it is not
    /// the one the finding records, as after an intentional rebuild whose
    /// inlining, line numbers or symbolizer moved the sink. bhf prints a
    /// warning naming what differs and records it in the finding's
    /// `minimization` block (`other_crash`). Without it such a harness is
    /// refused with exit 3.
    #[arg(long)]
    pub allow_other_crash: bool,

    /// Relocate an on-target transport finding's endpoint to `HOST:PORT`, as
    /// `bhf replay --transport-endpoint` does. Applies to agent:tcp / gdb
    /// transport findings.
    #[arg(long = "transport-endpoint", value_name = "HOST:PORT")]
    pub transport_endpoint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MinimizeStrategy {
    /// Delta-debug the input's bytes.
    Bytes,
    /// Reduce each decoded argument's value, keeping the input's layout: to
    /// 0, 1, -1 or its type's limits, then an integer to the value nearest
    /// zero that still crashes. For Ada harnesses and generated C/C++
    /// harnesses, from their `arg-layout.json`.
    Typed,
    /// Reduce a grammar finding on its derivation tree, parsed from the
    /// testcase with `--grammar`: each subtree, outermost first, is replaced
    /// by its rule's smallest derivation, by a same-rule subtree inside it,
    /// or by a smaller production of its rule that keeps its children, while
    /// the finding reproduces. The minimized input is a sentence of the
    /// grammar, where a byte-wise reduction breaks its structure.
    Grammar,
}

impl MinimizeStrategy {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Typed => "typed",
            Self::Grammar => "grammar",
        }
    }
}

/// The most candidates a grammar minimization runs.
const MAX_GRAMMAR_RUNS: usize = 4096;

/// The derivation tree of a `--strategy grammar` finding's testcase, or why
/// it has none.
fn grammar_tree(
    grammar: &fuzz_engine_builtin::Grammar,
    testcase: &[u8],
    testcase_path: &Path,
) -> anyhow::Result<fuzz_engine_builtin::grammar::Derivation> {
    grammar.parse(testcase).map_err(|error| {
        anyhow!(
            "minimize --strategy grammar reduces a testcase the grammar derives, on its \
             derivation tree; {} ({} bytes) has none: {error}, so minimize it with --strategy \
             bytes",
            testcase_path.display(),
            testcase.len()
        )
    })
}

/// The grammar of the `bhf auto --grammar` campaign a finding came from
/// (`grammar_path`, its `BHF_GRAMMAR`), when it derives the finding's
/// testcase: the auto pass then minimizes the finding on its tree. A
/// testcase the grammar does not derive (a seed, a byte mutation) is
/// minimized byte-wise.
fn auto_grammar(
    grammar_path: Option<&std::ffi::OsStr>,
    finding_dir: &Path,
) -> Option<fuzz_engine_builtin::Grammar> {
    let path = Path::new(grammar_path.filter(|path| !path.is_empty())?);
    let grammar = crate::fuzz::load_grammar_for_run(Some(path)).ok()??;
    let testcase = fs::read(finding_dir.join("testcase.bin")).ok()?;
    grammar.parse(&testcase).is_ok().then_some(grammar)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MinimizeSummary {
    strategy: MinimizeStrategy,
    original_len: usize,
    minimized_len: usize,
    removed_bytes: usize,
    pub(crate) reduced: bool,
    /// What could not be compared when the original testcase's crash could
    /// not be shown to be the recorded one (`not_compared` fields); `None`
    /// when it was, or nothing was compared (a lane without a crash record).
    pub(crate) unverified: Option<String>,
}

/// How a candidate input is delivered to the harness's main().
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CEngineIo {
    /// libFuzzer single-input mode: \`./harness <input-file>\`.
    ArgvFile,
    /// AFL persistent-mode: pipe input bytes via stdin.
    Stdin,
}

/// Minimize a C/C++ harness crash by delta-debugging the recorded
/// testcase. The predicate runs the harness via the engine-specific
/// I/O contract (argv file for libFuzzer, stdin for AFL), parses
/// stderr for a sanitizer report (or classifies an undiagnosed fatal
/// signal), and accepts the candidate only when it is the original's crash
/// ([`crate::crash_identity::same_crash`]: same rule, kind, signal, and
/// sink, site or pc).
///
/// The original testcase's crash is first compared with the finding the way
/// `bhf replay` compares it, run with the same environment
/// ([`crate::replay::replay_env`]). Another crash is refused
/// ([`BaselineMismatch`]) unless `allow_other_crash`, which minimizes against
/// it with a warning.
fn minimize_c_engine(
    finding_dir: &Path,
    runner: &replay_min::HarnessRunner,
    strategy: MinimizeStrategy,
    io: CEngineIo,
    allow_other_crash: bool,
    grammar: Option<&fuzz_engine_builtin::Grammar>,
) -> anyhow::Result<MinimizeSummary> {
    minimize_c_engine_until(
        finding_dir,
        runner,
        strategy,
        io,
        None,
        allow_other_crash,
        grammar,
    )
}

/// Like [`minimize_c_engine`], but stops accepting further reductions once
/// `deadline` has passed (the baseline reproduction check still runs once,
/// unconditionally: an unreproducible testcase must still error). Used by the
/// bounded `auto` minimization pass to cap wall-clock time per finding.
/// A scratch directory inside a finding's evidence directory, removed when it
/// goes out of scope, so no return path leaves it in the bundle.
pub(crate) struct ScratchDir(PathBuf);

impl ScratchDir {
    pub(crate) fn create(path: PathBuf) -> anyhow::Result<Self> {
        fs::create_dir_all(&path)
            .with_context(|| format!("create scratch dir {}", path.display()))?;
        Ok(Self(path))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn minimize_c_engine_until(
    finding_dir: &Path,
    runner: &replay_min::HarnessRunner,
    strategy: MinimizeStrategy,
    io: CEngineIo,
    deadline: Option<std::time::Instant>,
    allow_other_crash: bool,
    grammar: Option<&fuzz_engine_builtin::Grammar>,
) -> anyhow::Result<MinimizeSummary> {
    let harness = runner.harness_path();
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    let testcase_path = finding_dir.join("testcase.bin");
    let original_input =
        fs::read(&testcase_path).with_context(|| format!("read {}", testcase_path.display()))?;
    let raw = fs::read(finding_dir.join("finding.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .unwrap_or(serde_json::Value::Null);
    // #279: the typed strategy reduces the arguments the harness decodes,
    // which its `arg-layout.json` locates in the input.
    let typed_spans = match strategy {
        MinimizeStrategy::Bytes | MinimizeStrategy::Grammar => None,
        MinimizeStrategy::Typed => {
            let work_dir = corpus::layout::work_dir_for_finding(finding_dir).unwrap_or_default();
            let harness_id = raw["harness_id"].as_str().unwrap_or_default();
            let layout =
                crate::fuzz::typed_spans::find_arg_layout(&work_dir, harness_id, Some(harness))
                    .ok_or_else(|| {
                        anyhow!(
                            "minimize --strategy typed reduces the arguments a harness decodes, \
                             by the arg-layout.json a generated C/C++ harness has; {} has none \
                             ({}), so minimize it with --strategy bytes",
                            crate::corpus::harness_lane(harness),
                            harness.display()
                        )
                    })?;
            let spans = crate::fuzz::typed_spans::arg_layout_typed_spans(&layout, &original_input);
            if spans.is_empty() {
                return Err(anyhow!(
                    "minimize --strategy typed: the testcase decodes no integer or flag \
                     argument of {} ({} bytes), so there is no value to reduce; minimize it \
                     with --strategy bytes",
                    harness.display(),
                    original_input.len()
                ));
            }
            Some(spans)
        }
    };
    // #369: the grammar strategy reduces the testcase's derivation tree.
    let tree = match (strategy, grammar) {
        (MinimizeStrategy::Grammar, Some(grammar)) => Some((
            grammar,
            grammar_tree(grammar, &original_input, &testcase_path)?,
        )),
        (MinimizeStrategy::Grammar, None) => {
            return Err(anyhow!("minimize --strategy grammar needs --grammar"));
        }
        _ => None,
    };

    let scratch = ScratchDir::create(finding_dir.join("minimize_tmp"))?;
    let tmp_dir = scratch.path();
    let input = match io {
        CEngineIo::ArgvFile => crate::replay::CInput::ArgvFile,
        CEngineIo::Stdin => crate::replay::CInput::Stdin,
    };
    // `bhf replay`'s environment, for the testcase and every reduction: the
    // fuzz child's sanitizer options (UBSan prints and continues by default)
    // and, for an argv harness, the recorded runtime mode and injected env,
    // so a finding reproduces as the crash it was recorded as.
    let mut env = crate::replay::replay_env(&raw, runner, input);
    // An oracle, assertion or capability finding is shown again by what the
    // run does, which the runtrace shim records, as `bhf replay` decides it.
    let recorded_oracle = crate::replay_oracle::Recorded::from_finding(&raw);
    let runtrace_log = recorded_oracle
        .as_ref()
        .map(|_| crate::replay_oracle::RuntraceLog::create())
        .transpose()
        .map_err(|error| anyhow!(error))?;
    if let Some(log) = &runtrace_log {
        env.push((
            "BHF_RUNTRACE_LOG".to_owned(),
            log.path().display().to_string(),
        ));
    }
    // The memory cap the finding's input ran past: a reduction that runs past
    // it reproduces an out-of-memory finding, and none may take the host's.
    let rss_limit = crate::replay::recorded_rss_limit_mb(&raw);
    let run_once = |bytes: &[u8]| -> anyhow::Result<CEngineRun> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = tmp_dir.join(format!("input-{}-{}.bin", std::process::id(), nonce));
        fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))?;
        if let Some(log) = &runtrace_log {
            // The shim appends: each run's log holds that run alone.
            fs::write(log.path(), "").with_context(|| format!("reset {}", log.path().display()))?;
        }
        // Its own process group: a timeout kills whatever the harness started.
        let run = crate::replay::run_c_harness(
            runner,
            input,
            &path,
            Duration::from_secs(10),
            &env,
            rss_limit,
        );
        let _ = fs::remove_file(&path);
        let run = run.map_err(|error| anyhow!(error))?;
        let observed =
            recorded_oracle
                .as_ref()
                .zip(runtrace_log.as_ref())
                .map(|(recorded, log)| {
                    crate::replay_oracle::observe(
                        recorded,
                        &log.events(),
                        &String::from_utf8_lossy(&run.stderr),
                        &path,
                    )
                });
        let report = if run.timed_out || run.status.is_some_and(|status| status.success()) {
            None
        } else {
            // Attributed the way the finding was (a COBOL harness's libcob error).
            run.report_for(&raw)
        };
        Ok(CEngineRun { report, observed })
    };

    let baseline_run = run_once(&original_input)?;
    let oracle_reproduced = baseline_run
        .observed
        .as_ref()
        .is_some_and(crate::replay_oracle::Observed::reproduced);
    let mut unverified = None;
    let mut other_crash = None;
    // What every reduction must still do: the testcase's own crash, or, for
    // a finding that is not a crash (and a format-string crash whose crash
    // does not come back), the oracle or capability the finding records.
    let same_binary = crate::replay::recorded_build_matches(&raw, harness);
    let crash_comes_back = |report: &corpus::SanitizerReport| {
        crate::crash_identity::compare_with(&raw, report, same_binary).verdict()
            != crate::crash_identity::Verdict::Mismatch
    };
    let held = match (&recorded_oracle, baseline_run.report) {
        (Some(recorded), _) if !recorded.is_crash() => {
            if !oracle_reproduced {
                let shown = baseline_run
                    .observed
                    .map(|observed| {
                        crate::crash_identity::Comparison {
                            checks: observed.checks,
                            same_binary,
                        }
                        .difference_lines()
                        .join("; ")
                    })
                    .unwrap_or_default();
                return Err(BaselineMismatch(format!(
                    "the original testcase does not show what the finding records against {} \
                     ({shown}); nothing was minimized. `bhf replay` shows the comparison",
                    harness.display(),
                ))
                .into());
            }
            Held::Oracle
        }
        (Some(_), report)
            if oracle_reproduced && !report.as_ref().is_some_and(crash_comes_back) =>
        {
            Held::Oracle
        }
        (_, None) => {
            return Err(anyhow!(
                "original testcase {} does not reproduce a sanitizer crash against {}",
                testcase_path.display(),
                harness.display()
            ));
        }
        (_, Some(report)) => Held::Crash(report),
    };
    if let Held::Crash(baseline) = &held {
        check_baseline_crash(
            &raw,
            baseline,
            harness,
            same_binary,
            allow_other_crash,
            &mut unverified,
            &mut other_crash,
        )?;
    }

    let holds = |candidate: &[u8]| -> anyhow::Result<bool> {
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Ok(false); // budget spent: reject further reductions, keep best-so-far
        }
        let run = run_once(candidate)?;
        Ok(match &held {
            Held::Crash(baseline) => run
                .report
                .is_some_and(|report| crate::crash_identity::same_crash(baseline, &report)),
            Held::Oracle => run.observed.is_some_and(|observed| observed.reproduced()),
        })
    };
    let mut typed_record = None;
    let mut grammar_record = None;
    let result = match (&typed_spans, tree) {
        (None, Some((grammar, tree))) => {
            let reduced = grammar.minimize(&tree, MAX_GRAMMAR_RUNS, holds)?;
            grammar_record = Some(json!({
                "nodes_before": tree.node_count(),
                "nodes_after": reduced.tree.node_count(),
                "candidates_tried": reduced.tried,
                "candidates_kept": reduced.kept,
            }));
            replay_min::ByteMinimization {
                original_len: original_input.len(),
                minimized: grammar.sentence(&reduced.tree),
                predicate_runs: reduced.tried,
            }
        }
        (None, None) => replay_min::ddmin_bytes(&original_input, holds)?,
        (Some(spans), _) => {
            let typed = minimize_decoded_values(&original_input, spans, holds)?;
            typed_record = Some(json!({
                "spans": spans.len(),
                "values_tried": typed.tried,
                "values_kept": typed.kept,
            }));
            replay_min::ByteMinimization {
                original_len: original_input.len(),
                minimized: typed.minimized,
                predicate_runs: typed.tried,
            }
        }
    };
    drop(scratch);
    drop(runtrace_log);

    let min_path = finding_dir.join("min_testcase.bin");
    fs::write(&min_path, &result.minimized)
        .with_context(|| format!("write minimized testcase to {}", min_path.display()))?;

    let removed = result.original_len.saturating_sub(result.minimized.len());
    let reduced = removed > 0;
    let mut metadata = json!({
        "strategy": strategy.as_str(),
        "original_len": result.original_len,
        "minimized_len": result.minimized.len(),
        "removed_bytes": removed,
        "reduced": reduced,
        "predicate_runs": result.predicate_runs,
        "engine": match io {
            CEngineIo::ArgvFile => "libfuzzer-c",
            CEngineIo::Stdin => "afl-c",
        },
    });
    if let Some(differences) = other_crash {
        // The minimized input reproduces this crash, not the recorded one.
        metadata["other_crash"] = json!(differences);
    }
    if let Some(typed) = typed_record {
        metadata["typed"] = typed;
    }
    if let Some(record) = grammar_record {
        metadata["grammar"] = record;
    }
    update_finding_record(
        finding_dir,
        &MinimizeOutput {
            strategy,
            original_len: result.original_len,
            minimized: result.minimized.clone(),
            metadata,
            reduced,
        },
    )?;

    Ok(MinimizeSummary {
        strategy,
        original_len: result.original_len,
        minimized_len: result.minimized.len(),
        removed_bytes: removed,
        reduced,
        unverified,
    })
}

/// What the typed reduction of a C/C++ testcase did.
struct DecodedValueMinimization {
    minimized: Vec<u8>,
    /// Values run.
    tried: usize,
    /// Values kept: the reduction still crashed as the testcase does.
    kept: usize,
}

/// Reduce the value of each decoded argument in `spans` (#279), keeping its
/// width so the arguments after it decode where they did: first to the
/// first of 0, 1, -1 and the type's limits ([`decoded_arg_candidates`]) that
/// `holds`, then an integer to the value nearest zero that `holds`, by
/// bisection between it and zero, the boundary the crash starts at.
///
/// [`decoded_arg_candidates`]: fuzz_engine_builtin::decoded_arg_candidates
fn minimize_decoded_values(
    input: &[u8],
    spans: &[fuzz_engine_builtin::TypedSpan],
    mut holds: impl FnMut(&[u8]) -> anyhow::Result<bool>,
) -> anyhow::Result<DecodedValueMinimization> {
    use fuzz_engine_builtin::TypedValueKind;
    let mut current = input.to_vec();
    let (mut tried, mut kept) = (0, 0);
    for span in spans {
        let range = span.range.clone();
        if range.end > current.len() || range.is_empty() {
            continue;
        }
        let width = range.len();
        let with = |current: &[u8], value: &[u8]| {
            let mut candidate = current.to_vec();
            candidate[range.clone()].copy_from_slice(value);
            candidate
        };
        let dictionary = fuzz_engine_builtin::Dictionary::default();
        for value in fuzz_engine_builtin::decoded_arg_candidates(span.kind, width, &dictionary) {
            if value.len() != width || value == current[range.clone()] {
                continue;
            }
            let candidate = with(&current, &value);
            tried += 1;
            if holds(&candidate)? {
                current = candidate;
                kept += 1;
                break;
            }
        }
        let signed = match span.kind {
            TypedValueKind::SignedInteger => true,
            TypedValueKind::UnsignedInteger => false,
            _ => continue,
        };
        if width > 8 {
            continue;
        }
        // The value as the decoder reads it: little-endian at its width.
        let bits = (width * 8) as u32;
        let mut raw = [0u8; 8];
        raw[..width].copy_from_slice(&current[range.clone()]);
        let unsigned = u64::from_le_bytes(raw);
        let value: i128 = if signed && bits < 64 {
            i128::from(((unsigned << (64 - bits)) as i64) >> (64 - bits))
        } else if signed {
            i128::from(unsigned as i64)
        } else {
            i128::from(unsigned)
        };
        let encode = |value: i128| -> Vec<u8> { (value as u64).to_le_bytes()[..width].to_vec() };
        // Bisect between zero (taken not to hold) and the value (holds) for
        // the one nearest zero that holds.
        let (mut near, mut far) = (0_i128, value);
        while (far - near).abs() > 1 {
            let mid = near + (far - near) / 2;
            let candidate = with(&current, &encode(mid));
            tried += 1;
            if holds(&candidate)? {
                far = mid;
            } else {
                near = mid;
            }
        }
        if far != value {
            let candidate = with(&current, &encode(far));
            current = candidate;
            kept += 1;
        }
    }
    Ok(DecodedValueMinimization {
        minimized: current,
        tried,
        kept,
    })
}

/// One run of a C/C++ harness while minimizing: the crash it reported, and,
/// for a finding a replay shows by its oracle or capability, what it showed.
struct CEngineRun {
    report: Option<corpus::SanitizerReport>,
    observed: Option<crate::replay_oracle::Observed>,
}

/// What every reduction of a C/C++ testcase must still do.
enum Held {
    /// Crash as the testcase does ([`crate::crash_identity::same_crash`]).
    Crash(corpus::SanitizerReport),
    /// Show the oracle hit or capability the finding records.
    Oracle,
}

/// Hold the testcase's crash `baseline` to the one the finding `raw`
/// records, compared the way `bhf replay` compares it; else the reduction
/// would follow another bug. With `allow_other_crash`, another crash is
/// minimized against (recorded in `other_crash`); a crash whose place could
/// not be compared is minimized against too (recorded in `unverified`).
fn check_baseline_crash(
    raw: &serde_json::Value,
    baseline: &corpus::SanitizerReport,
    harness: &Path,
    same_binary: Option<bool>,
    allow_other_crash: bool,
    unverified: &mut Option<String>,
    other_crash: &mut Option<String>,
) -> anyhow::Result<()> {
    let comparison = crate::crash_identity::compare_with(raw, baseline, same_binary);
    match comparison.verdict() {
        crate::crash_identity::Verdict::Match => {}
        crate::crash_identity::Verdict::Mismatch if allow_other_crash => {
            let differences = comparison.difference_lines().join("; ");
            bhfeprintln!(
                "warning: the original testcase crashes {} with another crash than the finding \
                 records ({differences}); minimizing against the crash this harness reports, as \
                 --allow-other-crash asks",
                harness.display()
            );
            *other_crash = Some(differences);
        }
        crate::crash_identity::Verdict::Mismatch => {
            return Err(BaselineMismatch(format!(
                "the original testcase crashes {} with another crash than the finding records \
                 ({}); nothing was minimized. Minimize against the finding's own harness; \
                 `bhf replay` shows the comparison",
                harness.display(),
                comparison.difference_lines().join("; ")
            ))
            .into());
        }
        // The reductions are held to the testcase's own crash (`same_crash`),
        // so the minimized input is no less trustworthy than the testcase.
        // The caller says so: `bhf minimize` per finding, the auto pass in one
        // line for all of them.
        crate::crash_identity::Verdict::Unverified => {
            *unverified = Some(comparison.not_compared_fields());
        }
    }
    Ok(())
}

/// Classify `harness` with the detector fuzz and replay use, searching the
/// harness dirs of the work dir that holds `finding_dir` for its sources.
fn engine_for_finding(harness: &Path, finding_dir: &Path) -> HarnessEngine {
    let work = corpus::layout::work_dir_for_finding(finding_dir);
    let work_dirs: Vec<&Path> = work.iter().map(PathBuf::as_path).collect();
    detect_harness_engine_in(harness, &work_dirs)
}

/// The work dir that owns the finding being minimized, when it lives in a
/// results layout (so the dispatcher can rebuild results/ afterwards).
pub fn work_dir_hint(args: &MinimizeArgs) -> Option<std::path::PathBuf> {
    let dir = resolve_finding_arg(args.finding_dir.clone(), args.finding.clone());
    // Strict: only a real results-layout work dir, never a lexical guess,
    // because the dispatcher writes (migrate, manifest, rebuild) to it.
    corpus::layout::results_work_dir_for_finding(&dir)
}

/// Minimize a C/C++ harness finding within `deadline`. Ada/stdin harnesses are
/// out of scope for the auto pass (returns `Ok(None)`).
pub(crate) fn minimize_for_auto(
    finding_dir: &Path,
    harness: &Path,
    deadline: std::time::Instant,
) -> anyhow::Result<Option<MinimizeSummary>> {
    // A cross-built harness runs under the emulator recorded beside it.
    let runner = match crate::runner::recorded_runner_for(harness) {
        Some(recorded) => {
            replay_min::HarnessRunner::qemu_user(recorded.program, recorded.args, harness)
        }
        None => replay_min::HarnessRunner::direct(harness),
    };
    // #369: a finding of a `--grammar` campaign whose testcase the grammar
    // derives is minimized on its tree.
    let grammar = auto_grammar(std::env::var_os("BHF_GRAMMAR").as_deref(), finding_dir);
    let strategy = match grammar {
        Some(_) => MinimizeStrategy::Grammar,
        None => MinimizeStrategy::Bytes,
    };
    let io = match engine_for_finding(harness, finding_dir) {
        HarnessEngine::CAfl => CEngineIo::Stdin,
        HarnessEngine::CLibFuzzer => CEngineIo::ArgvFile,
        // #281: an Ada finding is minimized as `bhf minimize` does it, on its
        // event-log signature, within the group's deadline.
        HarnessEngine::AdaStdin => {
            let result = minimize(
                finding_dir,
                &runner,
                strategy,
                Some(deadline),
                grammar.as_ref(),
            )?;
            return write_minimization(finding_dir, &result).map(Some);
        }
    };
    minimize_c_engine_until(
        finding_dir,
        &runner,
        strategy,
        io,
        Some(deadline),
        false,
        grammar.as_ref(),
    )
    .map(Some)
}

pub fn run(args: MinimizeArgs) -> i32 {
    let finding_dir = resolve_finding_arg(args.finding_dir.clone(), args.finding.clone());
    if let Some(error) = crate::finding_arg::missing_finding(&finding_dir) {
        bhfeprintln!("error: {error}");
        return 1;
    }
    // HDF-7: a session finding minimizes by shrinking the recorded multi-message
    // session (re-repairing computed fields / re-resolving bindings each
    // candidate), not by delta-debugging a flat testcase against a harness.
    if crate::session_fuzz::is_session_finding(&finding_dir) {
        return crate::session_fuzz::minimize_session_finding(&finding_dir);
    }
    // A kernel crash ran in a kernel, not a harness: say what replays it.
    if let Some(refusal) = crate::kernel::harness_command_refusal("minimize", &finding_dir) {
        bhfeprintln!("error: {refusal}");
        return 1;
    }
    match run_inner(args) {
        Ok(summary) => {
            if let Some(fields) = &summary.unverified {
                bhfeprintln!(
                    "note: the original testcase's crash could not be shown to be the recorded \
                     one ({fields} not compared); the minimized input reproduces the crash this \
                     harness reports"
                );
            }
            println!(
                "MINIMIZED strategy={} original_len={} minimized_len={} removed_bytes={} reduced={} path=min_testcase.bin",
                summary.strategy.as_str(),
                summary.original_len,
                summary.minimized_len,
                summary.removed_bytes,
                summary.reduced
            );
            0
        }
        Err(error) => {
            bhfeprintln!("error: {error:#}");
            if error.downcast_ref::<BaselineMismatch>().is_some() {
                3
            } else {
                1
            }
        }
    }
}

/// The original testcase crashes the harness with another crash than the
/// finding records (a replay MISMATCH): nothing is minimized, and `bhf
/// minimize` exits 3 as `bhf replay` does.
#[derive(Debug)]
pub(crate) struct BaselineMismatch(String);

impl std::fmt::Display for BaselineMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BaselineMismatch {}

fn run_inner(args: MinimizeArgs) -> anyhow::Result<MinimizeSummary> {
    let finding_dir = resolve_finding_arg(args.finding_dir, args.finding);
    let grammar = match (&args.grammar, args.strategy) {
        (Some(path), MinimizeStrategy::Grammar) => Some(
            crate::fuzz::load_grammar_for_run(Some(path))
                .map_err(|error| anyhow!(error))?
                .ok_or_else(|| anyhow!("--grammar {} loaded no grammar", path.display()))?,
        ),
        (Some(_), strategy) => {
            return Err(anyhow!(
                "--grammar is the grammar a --strategy grammar minimization parses the \
                 testcase with; --strategy {} does not use it",
                strategy.as_str()
            ));
        }
        (None, _) => None,
    };
    // #60: a collector-sourced finding is reproduced from provider-captured
    // evidence that does not vary with the testcase bytes, so there is nothing to
    // delta-debug under deterministic replay. Re-confirm it reproduces and report
    // an honest no-op; this needs no harness, so it dispatches first.
    if crate::collector_run::is_collector_finding(&finding_dir) {
        let result = crate::collector_run::minimize_collector_finding(&finding_dir)?;
        return Ok(MinimizeSummary {
            strategy: args.strategy,
            original_len: result.original_len,
            minimized_len: result.original_len,
            removed_bytes: 0,
            reduced: result.reduced,
            unverified: None,
        });
    }
    // #280: an on-target transport finding has no host harness: it is
    // minimized through the transport it was found on, rebuilt from its
    // profile as `bhf replay` does, on the same fault rule and site.
    if crate::transport_replay::is_transport_finding(&finding_dir) {
        if args.strategy == MinimizeStrategy::Grammar {
            return Err(anyhow!(
                "--strategy grammar minimizes a host harness's finding; an on-target transport \
                 finding is minimized through its transport, so minimize it with --strategy \
                 bytes"
            ));
        }
        if args.strategy == MinimizeStrategy::Typed {
            return Err(anyhow!(
                "--strategy typed reduces a host harness's arguments by its \
                 arg-layout.json; an on-target transport finding has none, so minimize it \
                 with --strategy bytes"
            ));
        }
        let result = crate::transport_replay::minimize_transport_finding(
            &finding_dir,
            args.transport_endpoint.as_deref(),
        )
        .map_err(|error| anyhow!(error))?;
        let reduced = result.minimized.len() < result.original_len;
        let output = MinimizeOutput {
            strategy: MinimizeStrategy::Bytes,
            original_len: result.original_len,
            metadata: json!({
                "strategy": "bytes",
                "lane": "transport",
                "original_len": result.original_len,
                "minimized_len": result.minimized.len(),
                "removed_bytes": result.original_len.saturating_sub(result.minimized.len()),
                "reduced": reduced,
                "predicate_runs": result.predicate_runs,
            }),
            minimized: result.minimized,
            reduced,
        };
        return write_minimization(&finding_dir, &output);
    }
    let explicit = args.harness.is_some();
    let harness = finding_harness(&finding_dir, args.harness)?;
    if !explicit {
        bhfeprintln!(
            "bhf: minimizing against the finding's harness {}",
            harness.display()
        );
    }
    // A testcase recorded against another harness input format decodes into
    // other argument values here, and may not reproduce at all.
    if let Some(note) = std::fs::read(finding_dir.join("finding.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .zip(harness.parent())
        .and_then(|(raw, dir)| crate::generate_harness::finding_format_note(&raw, dir))
    {
        bhfeprintln!("note: {note}");
    }
    if crate::binary_fuzz::is_binary_finding(&finding_dir) {
        if args.strategy == MinimizeStrategy::Grammar {
            return Err(anyhow!(
                "--strategy grammar minimizes a harness's finding; a binary finding is \
                 minimized with --strategy bytes"
            ));
        }
        let result =
            crate::binary_fuzz::minimize_binary_finding(&finding_dir, &harness, args.strategy)?;
        return Ok(MinimizeSummary {
            strategy: args.strategy,
            original_len: result.original_len,
            minimized_len: result.minimized_len,
            removed_bytes: result.removed_bytes,
            reduced: result.reduced,
            unverified: None,
        });
    }
    // One runner for every engine, so --qemu-user, the emulator recorded
    // beside a cross-built harness, and the sandbox apply to all of them.
    let runner = harness_runner_for(
        harness,
        args.qemu_user,
        args.qemu_args,
        args.sandbox,
        args.sandbox_tool,
        args.sandbox_strict,
    )
    .map_err(|error| anyhow!(error))?;
    // Dispatch by engine, with the protocol detector fuzz and replay use (the
    // harness's sources are searched in every harness dir of the work dir
    // holding the finding). Both C engines reuse the same delta-debug
    // skeleton but differ in how a candidate input reaches main():
    // libFuzzer takes argv[1], AFL persistent-mode reads stdin (the
    // generated template falls back to `bhf_afl_read_stdin`).
    match engine_for_finding(runner.harness_path(), &finding_dir) {
        HarnessEngine::CAfl => {
            return minimize_c_engine(
                &finding_dir,
                &runner,
                args.strategy,
                CEngineIo::Stdin,
                args.allow_other_crash,
                grammar.as_ref(),
            );
        }
        HarnessEngine::CLibFuzzer => {
            return minimize_c_engine(
                &finding_dir,
                &runner,
                args.strategy,
                CEngineIo::ArgvFile,
                args.allow_other_crash,
                grammar.as_ref(),
            );
        }
        HarnessEngine::AdaStdin => {}
    }
    let result = minimize(&finding_dir, &runner, args.strategy, None, grammar.as_ref())
        .with_context(|| {
            let work = corpus::layout::work_dir_for_finding(&finding_dir);
            let work_dirs: Vec<&Path> = work.iter().map(PathBuf::as_path).collect();
            let detection = crate::protocol_detect::detect(runner.harness_path(), &work_dirs);
            format!(
                "minimizing {} as an Ada stdin harness ({}); if it is a C/C++ harness, pass the \
             binary next to its main.c/main.cpp with --harness, or rebuild it with this bhf",
                runner.harness_path().display(),
                detection.basis.describe()
            )
        })?;
    write_minimization(&finding_dir, &result)
}

/// Write a finding's minimized input to `min_testcase.bin` and record the
/// minimization in its `finding.json` (an Ada or a transport finding; the C
/// engines write their own).
fn write_minimization(
    finding_dir: &Path,
    result: &MinimizeOutput,
) -> anyhow::Result<MinimizeSummary> {
    let min_path = finding_dir.join("min_testcase.bin");
    fs::write(&min_path, &result.minimized)
        .with_context(|| format!("write minimized testcase to {}", min_path.display()))?;
    update_finding_record(finding_dir, result)?;
    Ok(MinimizeSummary {
        strategy: result.strategy,
        original_len: result.original_len,
        minimized_len: result.minimized.len(),
        removed_bytes: result.original_len.saturating_sub(result.minimized.len()),
        reduced: result.reduced,
        unverified: None,
    })
}

/// The harness to minimize against: `explicit` (`--harness`), else the one
/// the finding records, resolved in its work dir the way `bhf replay` does
/// (`fixture_path`, then `harness_id` under `harnesses/`, `auto/`,
/// `generated_harnesses/` and `build/`).
fn finding_harness(finding_dir: &Path, explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    match explicit {
        Some(harness) => Ok(crate::replay::explicit_harness(harness)),
        None => crate::replay::recorded_harness(finding_dir).map_err(|error| anyhow!(error)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MinimizeOutput {
    strategy: MinimizeStrategy,
    original_len: usize,
    minimized: Vec<u8>,
    metadata: serde_json::Value,
    reduced: bool,
}

fn minimize(
    finding_dir: &Path,
    runner: &replay_min::HarnessRunner,
    strategy: MinimizeStrategy,
    deadline: Option<std::time::Instant>,
    grammar: Option<&fuzz_engine_builtin::Grammar>,
) -> anyhow::Result<MinimizeOutput> {
    match strategy {
        MinimizeStrategy::Grammar => {
            let grammar =
                grammar.ok_or_else(|| anyhow!("minimize --strategy grammar needs --grammar"))?;
            minimize_event_log_on_grammar(finding_dir, runner, grammar, deadline)
        }
        MinimizeStrategy::Bytes => {
            let result = replay_min::minimize_finding_bytes_with_runner_until(
                finding_dir,
                runner,
                deadline,
            )?;
            let reduced = result.removed_bytes() > 0;
            let metadata = json!({
                "strategy": strategy.as_str(),
                "original_len": result.original_len,
                "minimized_len": result.minimized_len(),
                "removed_bytes": result.removed_bytes(),
                "reduced": reduced,
                "predicate_runs": result.predicate_runs,
            });
            Ok(MinimizeOutput {
                strategy,
                original_len: result.original_len,
                minimized: result.minimized,
                metadata,
                reduced,
            })
        }
        MinimizeStrategy::Typed => {
            let result =
                replay_min::minimize_finding_typed_values_with_runner(finding_dir, runner)?;
            let reduced = result.removed_bytes() > 0;
            let metadata = json!({
                "strategy": strategy.as_str(),
                "original_len": result.original_len,
                "minimized_len": result.minimized_len(),
                "removed_bytes": result.removed_bytes(),
                "reduced": reduced,
                "attempted_replacements": result.attempted_replacements,
                "accepted_replacements": result.accepted_replacements,
            });
            Ok(MinimizeOutput {
                strategy,
                original_len: result.original_len,
                minimized: result.minimized,
                metadata,
                reduced,
            })
        }
    }
}

/// #369: an event-log (Ada) finding minimized on its derivation tree. Each
/// candidate is replayed as `bhf replay` replays the testcase, from a scratch
/// copy of the finding, and holds when it raises the recorded signature.
fn minimize_event_log_on_grammar(
    finding_dir: &Path,
    runner: &replay_min::HarnessRunner,
    grammar: &fuzz_engine_builtin::Grammar,
    deadline: Option<std::time::Instant>,
) -> anyhow::Result<MinimizeOutput> {
    let testcase_path = finding_dir.join("testcase.bin");
    let original =
        fs::read(&testcase_path).with_context(|| format!("read {}", testcase_path.display()))?;
    let tree = grammar_tree(grammar, &original, &testcase_path)?;
    let scratch = ScratchDir::create(finding_dir.join("minimize_tmp"))?;
    let copy = scratch.path().join("finding.json");
    fs::copy(finding_dir.join("finding.json"), &copy)
        .with_context(|| format!("copy finding.json to {}", copy.display()))?;
    let reproduces = |candidate: &[u8]| -> anyhow::Result<bool> {
        let path = scratch.path().join("testcase.bin");
        fs::write(&path, candidate).with_context(|| format!("write {}", path.display()))?;
        match replay_min::replay_with_runner(scratch.path(), runner) {
            Ok(result) => Ok(result == replay_min::ReplayResult::Match),
            Err(error @ replay_min::ReplayError::HarnessFailedToStart { .. }) => Err(error.into()),
            Err(_) => Ok(false),
        }
    };
    // The testcase itself must reproduce, whatever the deadline.
    if !reproduces(&original)? {
        return Err(anyhow!(
            "original testcase {} does not reproduce the finding's signature against {}",
            testcase_path.display(),
            runner.harness_path().display()
        ));
    }
    let reduced = grammar.minimize(&tree, MAX_GRAMMAR_RUNS, |candidate| {
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            return Ok(false);
        }
        reproduces(candidate)
    })?;
    drop(scratch);
    let minimized = grammar.sentence(&reduced.tree);
    let removed = original.len().saturating_sub(minimized.len());
    let reduced_any = removed > 0;
    Ok(MinimizeOutput {
        strategy: MinimizeStrategy::Grammar,
        original_len: original.len(),
        metadata: json!({
            "strategy": "grammar",
            "original_len": original.len(),
            "minimized_len": minimized.len(),
            "removed_bytes": removed,
            "reduced": reduced_any,
            "predicate_runs": reduced.tried,
            "grammar": {
                "nodes_before": tree.node_count(),
                "nodes_after": reduced.tree.node_count(),
                "candidates_tried": reduced.tried,
                "candidates_kept": reduced.kept,
            },
        }),
        minimized,
        reduced: reduced_any,
    })
}

fn update_finding_record(finding_dir: &Path, result: &MinimizeOutput) -> anyhow::Result<()> {
    let path = finding_dir.join("finding.json");
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let mut value: serde_json::Value =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| anyhow!("{} must contain a JSON object", path.display()))?;
    let paths = object.entry("paths").or_insert_with(|| json!({}));
    let paths = paths
        .as_object_mut()
        .ok_or_else(|| anyhow!("{}.paths must contain a JSON object", path.display()))?;

    paths.insert("minimized".to_owned(), json!("min_testcase.bin"));
    object.insert("minimal_reproducer".to_owned(), json!("min_testcase.bin"));
    object.insert("minimization".to_owned(), result.metadata.clone());

    corpus::finding::append_history(
        &mut value,
        "minimize",
        &["paths.minimized", "minimal_reproducer", "minimization"],
    );
    fs::write(&path, serde_json::to_vec_pretty(&value)?)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod harness_tests {
    /// #279: a decoded integer is reduced to the boundary its crash starts
    /// at, each value at its own width, and the bytes outside the arguments
    /// are left as they were.
    #[test]
    fn decoded_values_are_reduced_to_the_boundary_of_the_crash() {
        use fuzz_engine_builtin::{TypedSpan, TypedValueKind};
        let mut input = Vec::new();
        input.extend_from_slice(&5000_i32.to_le_bytes()); // crashes from 101
        input.push(200); // u8: crashes from 7
        input.extend_from_slice(&(-9_i32).to_le_bytes()); // irrelevant: to 0
        input.extend_from_slice(b"tail");
        let spans = [
            TypedSpan::new(0..4, TypedValueKind::SignedInteger),
            TypedSpan::new(4..5, TypedValueKind::UnsignedInteger),
            TypedSpan::new(5..9, TypedValueKind::SignedInteger),
        ];
        let result = super::minimize_decoded_values(&input, &spans, |candidate| {
            let idx = i32::from_le_bytes(candidate[0..4].try_into().unwrap());
            Ok(candidate.len() == input.len() && idx > 100 && candidate[4] >= 7)
        })
        .unwrap();
        let minimized = result.minimized;
        assert_eq!(i32::from_le_bytes(minimized[0..4].try_into().unwrap()), 101);
        assert_eq!(minimized[4], 7);
        assert_eq!(i32::from_le_bytes(minimized[5..9].try_into().unwrap()), 0);
        assert_eq!(&minimized[9..], b"tail");
        assert!(result.kept >= 3 && result.tried > result.kept);
    }

    /// Without `--harness`, minimize resolves the finding's harness the way
    /// replay does, including a binary `bhf build` staged into
    /// `build/<id>/main`.
    #[test]
    fn the_harness_is_resolved_from_the_finding() {
        let work = tempfile::tempdir().unwrap();
        let finding = work.path().join("results/findings/F-0001-aaaaaaaa");
        std::fs::create_dir_all(&finding).unwrap();
        std::fs::write(finding.join("finding.json"), r#"{"harness_id":"H-1"}"#).unwrap();
        let staged = work.path().join("build/H-1/main");
        std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
        std::fs::write(&staged, b"\x7fELF").unwrap();
        assert_eq!(super::finding_harness(&finding, None).unwrap(), staged);
        let explicit = work.path().join("elsewhere/main");
        assert_eq!(
            super::finding_harness(&finding, Some(explicit.clone())).unwrap(),
            explicit
        );
        // A relative `--harness` is a path in the current directory.
        assert_eq!(
            super::finding_harness(&finding, Some("main".into())).unwrap(),
            std::env::current_dir().unwrap().join("main")
        );
        std::fs::remove_file(&staged).unwrap();
        let error = super::finding_harness(&finding, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("--harness"), "{error}");
    }
}

#[cfg(all(test, unix))]
mod silent_abort_tests {
    use super::{minimize_c_engine, minimize_c_engine_until, CEngineIo, MinimizeStrategy};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;

    fn write_silent_abort_harness(dir: &Path) -> PathBuf {
        let harness = dir.join("abort-on-crash.sh");
        fs::write(
            &harness,
            "#!/bin/sh\ncase \"$(cat \"$1\")\" in *CRASH*) kill -ABRT $$;; esac\n",
        )
        .expect("harness");
        let mut permissions = fs::metadata(&harness).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&harness, permissions).expect("chmod");
        harness
    }

    /// A JSON grammar of `[word]` items and `(...)` groups, written to `dir`.
    fn write_list_grammar(dir: &Path) -> PathBuf {
        let path = dir.join("list.json");
        fs::write(
            &path,
            r#"{"START": ["{LIST}"], "LIST": ["{ITEM}", "{ITEM},{LIST}"],
                "ITEM": ["[{WORD}]", "({LIST})"],
                "WORD": ["alpha", "beta", "BHFMAGIC", "gamma"]}"#,
        )
        .expect("grammar");
        path
    }

    fn write_magic_abort_harness(dir: &Path) -> PathBuf {
        let harness = dir.join("abort-on-magic.sh");
        fs::write(
            &harness,
            "#!/bin/sh\ncase \"$(cat \"$1\")\" in *BHFMAGIC*) kill -ABRT $$;; esac\n",
        )
        .expect("harness");
        fs::set_permissions(&harness, fs::Permissions::from_mode(0o755)).expect("chmod");
        harness
    }

    fn magic_finding(root: &Path, testcase: &[u8]) -> PathBuf {
        let finding = root.join("finding");
        fs::create_dir_all(&finding).expect("finding dir");
        fs::write(
            finding.join("finding.json"),
            r#"{"rule_id":"BHF-210","paths":{}}"#,
        )
        .expect("finding");
        fs::write(finding.join("testcase.bin"), testcase).expect("testcase");
        finding
    }

    /// #369: a grammar finding of a C/C++ harness minimizes to a smaller
    /// sentence that still crashes, where the byte strategy leaves an input
    /// that is no sentence.
    #[test]
    fn a_grammar_finding_minimizes_to_a_smaller_sentence_that_still_crashes() {
        let root = tempdir().expect("tempdir");
        let testcase = b"[alpha],([beta],[BHFMAGIC]),[gamma]";
        let finding = magic_finding(root.path(), testcase);
        let harness = write_magic_abort_harness(root.path());
        let grammar = crate::fuzz::load_grammar_for_run(Some(&write_list_grammar(root.path())))
            .unwrap()
            .unwrap();
        let runner = replay_min::HarnessRunner::direct(&harness);

        let summary = minimize_c_engine_until(
            &finding,
            &runner,
            MinimizeStrategy::Grammar,
            CEngineIo::ArgvFile,
            None,
            false,
            Some(&grammar),
        )
        .expect("minimize");
        let minimized = fs::read(finding.join("min_testcase.bin")).unwrap();
        assert_eq!(minimized, b"[BHFMAGIC]");
        assert!(summary.reduced && summary.minimized_len < testcase.len());
        assert!(grammar.parse(&minimized).is_ok(), "a sentence");
        let record: serde_json::Value =
            serde_json::from_slice(&fs::read(finding.join("finding.json")).unwrap()).unwrap();
        assert_eq!(record["minimization"]["strategy"], "grammar");
        assert!(
            record["minimization"]["grammar"]["candidates_kept"]
                .as_u64()
                .is_some_and(|kept| kept >= 1),
            "{record:#}"
        );
        assert!(!finding.join("minimize_tmp").exists());

        // Byte-wise, the same finding loses its structure.
        minimize_c_engine(
            &finding,
            &runner,
            MinimizeStrategy::Bytes,
            CEngineIo::ArgvFile,
            false,
            None,
        )
        .expect("minimize");
        let bytes = fs::read(finding.join("min_testcase.bin")).unwrap();
        assert_eq!(bytes, b"BHFMAGIC");
        assert!(grammar.parse(&bytes).is_err(), "no sentence");
    }

    #[test]
    fn a_testcase_the_grammar_does_not_derive_is_refused_by_name() {
        let root = tempdir().expect("tempdir");
        let finding = magic_finding(root.path(), b"[alpha]BHFMAGIC");
        let harness = write_magic_abort_harness(root.path());
        let grammar = crate::fuzz::load_grammar_for_run(Some(&write_list_grammar(root.path())))
            .unwrap()
            .unwrap();
        let error = minimize_c_engine_until(
            &finding,
            &replay_min::HarnessRunner::direct(&harness),
            MinimizeStrategy::Grammar,
            CEngineIo::ArgvFile,
            None,
            false,
            Some(&grammar),
        )
        .expect_err("not a sentence");
        let message = format!("{error:#}");
        assert!(
            message.contains("not a sentence") && message.contains("--strategy bytes"),
            "{message}"
        );
        assert!(!finding.join("min_testcase.bin").exists());
    }

    /// The auto pass minimizes on the tree only a finding its campaign's
    /// grammar derives.
    #[test]
    fn the_auto_pass_takes_the_campaign_grammar_for_a_testcase_it_derives() {
        let root = tempdir().expect("tempdir");
        let grammar = write_list_grammar(root.path());
        let sentence = magic_finding(&root.path().join("a"), b"[BHFMAGIC],[beta]");
        let bytes = magic_finding(&root.path().join("b"), b"BHFMAGIC");
        assert!(super::auto_grammar(Some(grammar.as_os_str()), &sentence).is_some());
        assert!(super::auto_grammar(Some(grammar.as_os_str()), &bytes).is_none());
        assert!(super::auto_grammar(None, &sentence).is_none());
        assert!(super::auto_grammar(Some(std::ffi::OsStr::new("")), &sentence).is_none());
    }

    #[test]
    fn libfuzzer_minimizer_reduces_silent_abort_finding() {
        let root = tempdir().expect("tempdir");
        let finding = root.path().join("finding");
        fs::create_dir(&finding).expect("finding dir");
        fs::write(
            finding.join("finding.json"),
            r#"{"rule_id":"BHF-210","paths":{}}"#,
        )
        .expect("finding");
        fs::write(finding.join("testcase.bin"), b"prefix-CRASH-suffix").expect("testcase");

        let harness = write_silent_abort_harness(root.path());

        let result = minimize_c_engine(
            &finding,
            &replay_min::HarnessRunner::direct(&harness),
            MinimizeStrategy::Bytes,
            CEngineIo::ArgvFile,
            false,
            None,
        )
        .expect("minimize");

        assert!(result.reduced);
        assert_eq!(
            fs::read(finding.join("min_testcase.bin")).unwrap(),
            b"CRASH"
        );
        assert!(!finding.join("minimize_tmp").exists());
    }

    /// A testcase that no longer crashes the harness is not minimized, and the
    /// scratch directory goes with the error instead of staying in the bundle.
    #[test]
    fn a_testcase_that_does_not_reproduce_leaves_no_scratch_dir() {
        let root = tempdir().expect("tempdir");
        let finding = root.path().join("finding");
        fs::create_dir(&finding).expect("finding dir");
        fs::write(
            finding.join("finding.json"),
            serde_json::json!({"rule_id": "BHF-415", "paths": {}}).to_string(),
        )
        .expect("finding");
        fs::write(finding.join("testcase.bin"), b"no crash here").expect("testcase");
        let harness = root.path().join("clean.sh");
        fs::write(&harness, "#!/bin/sh\nexit 0\n").expect("harness");
        fs::set_permissions(&harness, fs::Permissions::from_mode(0o755)).expect("chmod");

        let error = minimize_c_engine(
            &finding,
            &replay_min::HarnessRunner::direct(&harness),
            MinimizeStrategy::Bytes,
            CEngineIo::ArgvFile,
            false,
            None,
        )
        .expect_err("nothing to minimize");
        assert!(
            error.to_string().contains("does not reproduce"),
            "{error:#}"
        );
        assert!(!finding.join("minimize_tmp").exists());
        assert!(!finding.join("min_testcase.bin").exists());
    }

    /// UBSan prints its report and CONTINUES (exit 0) unless told to halt, the
    /// way the fuzz child is. A minimizer child without those options saw no
    /// crash and refused to minimize every UBSan finding.
    #[test]
    fn libfuzzer_minimizer_reproduces_ubsan_findings_like_the_fuzz_child() {
        const SHIFT: &str = "/src/w.c:2:15: runtime error: shift exponent 40 is too large for \
                             32-bit type 'int'";
        let root = tempdir().expect("tempdir");
        let finding = root.path().join("finding");
        fs::create_dir(&finding).expect("finding dir");
        let rule = corpus::parse_sanitizer_report(&format!("{SHIFT}\n"))
            .expect("a UBSan report")
            .rule_id;
        fs::write(
            finding.join("finding.json"),
            serde_json::json!({"rule_id": rule, "paths": {}}).to_string(),
        )
        .expect("finding");
        fs::write(finding.join("testcase.bin"), b"prefix-UB-suffix").expect("testcase");
        let harness = root.path().join("ubsan-like.sh");
        fs::write(
            &harness,
            "#!/bin/sh\ncase \"$(cat \"$1\")\" in *UB*)\n\
             echo \"/src/w.c:2:15: runtime error: shift exponent 40 is too large for 32-bit type 'int'\" >&2\n\
             case \"$UBSAN_OPTIONS\" in *halt_on_error=1*) exit 1;; esac;;\nesac\nexit 0\n",
        )
        .expect("harness");
        let mut permissions = fs::metadata(&harness).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&harness, permissions).expect("chmod");

        let result = minimize_c_engine(
            &finding,
            &replay_min::HarnessRunner::direct(&harness),
            MinimizeStrategy::Bytes,
            CEngineIo::ArgvFile,
            false,
            None,
        )
        .expect("a UBSan finding reproduces under the fuzz child's options");
        assert!(result.reduced);
        assert_eq!(fs::read(finding.join("min_testcase.bin")).unwrap(), b"UB");
    }

    /// The original testcase must crash the harness with the crash the
    /// finding records: a harness that reports another crash is refused, and
    /// nothing is written.
    #[test]
    fn a_harness_whose_crash_is_not_the_recorded_one_is_not_minimized() {
        let root = tempdir().expect("tempdir");
        let finding = root.path().join("finding");
        fs::create_dir(&finding).expect("finding dir");
        let record = serde_json::json!({
            "rule_id": "BHF-201",
            "exception": {
                "name": "ASAN_HEAP_BUFFER_OVERFLOW",
                "sanitizer": "asan",
                "stack": [{"function": "parse_a", "file": "/src/a.c", "line": 3}],
            },
            "paths": {},
        });
        let record = serde_json::to_vec_pretty(&record).unwrap();
        fs::write(finding.join("finding.json"), &record).expect("finding");
        fs::write(finding.join("testcase.bin"), b"prefix-CRASH-suffix").expect("testcase");
        let harness = root.path().join("other-crash.sh");
        fs::write(
            &harness,
            "#!/bin/sh\ncase \"$(cat \"$1\")\" in *CRASH*)\ncat >&2 <<'REPORT'\n\
             ==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000031 at pc 0x1 bp 0x2 sp 0x3\n\
             WRITE of size 1 at 0x602000000031 thread T0\n\
             \x20   #0 0x1 in parse_b /src/b.c:4:5\n\
             SUMMARY: AddressSanitizer: heap-buffer-overflow /src/b.c:4:5 in parse_b\n\
             REPORT\nkill -ABRT $$;;\nesac\nexit 0\n",
        )
        .expect("harness");
        fs::set_permissions(&harness, fs::Permissions::from_mode(0o755)).expect("chmod");

        let error = minimize_c_engine(
            &finding,
            &replay_min::HarnessRunner::direct(&harness),
            MinimizeStrategy::Bytes,
            CEngineIo::ArgvFile,
            false,
            None,
        )
        .expect_err("another crash is not minimized");
        assert!(
            error.downcast_ref::<super::BaselineMismatch>().is_some(),
            "{error:#}"
        );
        assert!(error.to_string().contains("sink"), "{error:#}");
        assert!(!finding.join("min_testcase.bin").exists());
        assert!(!finding.join("minimize_tmp").exists());
        assert_eq!(fs::read(finding.join("finding.json")).unwrap(), record);
    }

    #[test]
    fn expired_deadline_stops_reduction_but_keeps_a_valid_result() {
        let root = tempdir().expect("tempdir");
        let finding = root.path().join("finding");
        fs::create_dir(&finding).expect("finding dir");
        fs::write(
            finding.join("finding.json"),
            r#"{"rule_id":"BHF-210","paths":{}}"#,
        )
        .expect("finding");
        fs::write(finding.join("testcase.bin"), b"prefix-CRASH-suffix").expect("testcase");
        let harness = write_silent_abort_harness(root.path());
        let past = std::time::Instant::now();

        let summary = minimize_c_engine_until(
            &finding,
            &replay_min::HarnessRunner::direct(&harness),
            MinimizeStrategy::Bytes,
            CEngineIo::ArgvFile,
            Some(past),
            false,
            None,
        )
        .expect("minimize");

        assert!(
            !summary.reduced,
            "an already-expired deadline must not reduce"
        );
        assert!(finding.join("min_testcase.bin").is_file());
    }

    /// A reduction must be the recorded crash, not merely a crash of the same
    /// rule: an abort is not minimized into an input that dies of SIGSEGV.
    #[test]
    fn a_reduction_that_crashes_with_another_signal_is_rejected() {
        let root = tempdir().expect("tempdir");
        let finding = root.path().join("finding");
        fs::create_dir(&finding).expect("finding dir");
        fs::write(
            finding.join("finding.json"),
            r#"{"rule_id":"BHF-210","paths":{}}"#,
        )
        .expect("finding");
        fs::write(finding.join("testcase.bin"), b"AB").expect("testcase");
        // "AB..." aborts; anything else ending in B dies of SIGSEGV.
        let harness = root.path().join("two-signals.sh");
        fs::write(
            &harness,
            "#!/bin/sh\ncase \"$(cat \"$1\")\" in\n  AB*) kill -ABRT $$;;\n  *B) kill -SEGV $$;;\nesac\nexit 0\n",
        )
        .expect("harness");
        let mut permissions = fs::metadata(&harness).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&harness, permissions).expect("chmod");

        let summary = minimize_c_engine(
            &finding,
            &replay_min::HarnessRunner::direct(&harness),
            MinimizeStrategy::Bytes,
            CEngineIo::ArgvFile,
            false,
            None,
        )
        .expect("minimize");

        assert!(!summary.reduced, "{summary:?}");
        assert_eq!(fs::read(finding.join("min_testcase.bin")).unwrap(), b"AB");
    }

    /// A bhf-protocol script harness that aborts on an input containing
    /// `CRASH`, only when `WIDGET_HOME` is set.
    fn write_env_gated_harness(dir: &Path) -> PathBuf {
        let harness = dir.join("env-gated.sh");
        fs::write(
            &harness,
            "#!/bin/sh\n# BHF_FRAMED test driver\n[ -n \"$WIDGET_HOME\" ] || exit 0\n\
             case \"$(cat \"$1\")\" in *CRASH*) kill -ABRT $$;; esac\nexit 0\n",
        )
        .expect("harness");
        fs::set_permissions(&harness, fs::Permissions::from_mode(0o755)).expect("chmod");
        harness
    }

    /// The auto pass runs the harness with the environment the finding
    /// recorded as injected, as `bhf replay` does, for the testcase and for
    /// every reduction.
    #[test]
    fn the_auto_pass_runs_the_harness_with_the_recorded_environment() {
        let root = tempdir().expect("tempdir");
        let finding = root.path().join("finding");
        fs::create_dir(&finding).expect("finding dir");
        fs::write(
            finding.join("finding.json"),
            r#"{"rule_id":"BHF-210","paths":{},
                "runtime_mode":{"pass":"rng","env_injected":{"WIDGET_HOME":"/x"}}}"#,
        )
        .expect("finding");
        fs::write(finding.join("testcase.bin"), b"prefix-CRASH-suffix").expect("testcase");
        let harness = write_env_gated_harness(root.path());

        let summary = super::minimize_for_auto(
            &finding,
            &harness,
            std::time::Instant::now() + std::time::Duration::from_secs(60),
        )
        .expect("the testcase reproduces with the recorded environment")
        .expect("a C harness");
        assert!(summary.reduced, "{summary:?}");
        assert_eq!(
            fs::read(finding.join("min_testcase.bin")).unwrap(),
            b"CRASH"
        );
    }

    /// A crash that cannot be shown to be the recorded one is minimized, and
    /// the summary says what was not compared, for the caller to report (the
    /// auto pass sums these up in one line).
    #[test]
    fn an_unverified_baseline_is_reported_in_the_summary() {
        let root = tempdir().expect("tempdir");
        let finding = root.path().join("finding");
        fs::create_dir(&finding).expect("finding dir");
        fs::write(
            finding.join("finding.json"),
            r#"{"rule_id":"BHF-210","paths":{}}"#,
        )
        .expect("finding");
        fs::write(finding.join("testcase.bin"), b"prefix-CRASH-suffix").expect("testcase");
        let harness = write_silent_abort_harness(root.path());

        let summary = minimize_c_engine(
            &finding,
            &replay_min::HarnessRunner::direct(&harness),
            MinimizeStrategy::Bytes,
            CEngineIo::ArgvFile,
            false,
            None,
        )
        .expect("minimize");
        assert_eq!(summary.unverified.as_deref(), Some("location"));
    }
}
