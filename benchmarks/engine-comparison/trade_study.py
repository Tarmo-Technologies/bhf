# SPDX-License-Identifier: Apache-2.0
"""Large multi-engine fuzzing trade study.

Compares BHF's builtin engine against three leading open-source coverage-guided
fuzzers — AFL++ (pinned 5.03c), libFuzzer, and honggfuzz — on controlled
coverage-gated bug fixtures. It reuses the reviewed helpers in ``run.py`` (source
wrapping, seed corpus, process monitor, tool metadata) and adds:

* honggfuzz and an explicit pinned-AFL++ toolchain,
* a single, engine-neutral coverage oracle: every engine's FINAL corpus is
  replayed through ONE shared libFuzzer-sancov binary, so ``cov`` (edges) and
  ``ft`` (features) are measured identically for all four engines rather than
  trusting each engine's own counter, and
* an independent ASan/UBSan replay oracle that confirms each saved crash.

Every trial pins the derived-source hash, the shared oracle/coverage-binary
hashes, the exact commands, and separates build/setup time from campaign time.
Raw per-(engine,target,trial) rows and an aggregated summary are written to the
output JSON. Native throughput counters are recorded but flagged not directly
comparable across engines (different definitions of an "execution").

The target set is PLUGGABLE (see ``targets.py`` and ``METHODOLOGY.md``). With no
``--manifest`` it runs the four controlled toy gates exactly as before; with a
manifest it runs pinned real-code targets through the identical harness/oracle/
coverage/censoring machinery. The aggregate step reports repeated-trial
DISTRIBUTIONS (median + IQR + range + a bootstrap/Wilson CI), per-target AND
across targets, and keeps every failed/censored/incomplete/unsupported trial
visible so the effective sample size is never hidden. This is Experiment 1
(engine quality) of issue #85; Experiment 2 (auto-harness productivity) lives in
``benchmarks/harness-parity-20/``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import run  # reviewed helpers: sha256, monitor, fixture_source, make_corpus, CASES, ...
import stats  # deterministic distribution/CI summaries (unit-tested in CI)
import targets  # pluggable real-code target set + manifest schema

ROOT = run.ROOT
HARNESS_ROOT = run.HARNESS_ROOT
FIXTURE_ROOT = run.FIXTURE_ROOT
SEED = run.SEED

ENGINES = ("bhf", "aflpp", "libfuzzer", "honggfuzz")

# Per-trial outcome classes. Confirmed crashes count as solves; censored and
# failed/incomplete trials are retained and reported so the denominator is never
# silently shrunk to only the runs that worked.
OUTCOME_CONFIRMED = "confirmed_crash"
OUTCOME_CENSORED = "censored_no_crash"
OUTCOME_BUILD_FAILED = "build_failed"
OUTCOME_TIMEOUT = "supervisor_timeout"
OUTCOME_INCOMPLETE = "incomplete"
OUTCOME_UNSUPPORTED = "unsupported"
OUTCOME_CLASSES = (
    OUTCOME_CONFIRMED,
    OUTCOME_CENSORED,
    OUTCOME_BUILD_FAILED,
    OUTCOME_TIMEOUT,
    OUTCOME_INCOMPLETE,
    OUTCOME_UNSUPPORTED,
)


def sha256(path: Path) -> str:
    return run.sha256(path)


# --- pluggable target materialization --------------------------------------


def materialize_target(spec: targets.TargetSpec, dest: Path) -> tuple[list[Path], str]:
    """Realize a target's compilable source(s) under ``dest``.

    Returns ``(sources, derived_sha256)``. For a builtin fixture this writes the
    wrapped fixture source (identical to the historical path). For a self-
    contained real-code target it copies each pinned source in, preserving its
    name, and the derived hash is computed over the sorted (name, content-hash)
    pairs so the exact source set is pinned per trial.
    """
    dest.mkdir(parents=True, exist_ok=True)
    if spec.kind == targets.KIND_BUILTIN:
        assert spec.fixture_case is not None
        run_source = dest / f"{spec.fixture_case}.c"
        run_source.write_text(run.fixture_source(spec.fixture_case))
        return [run_source], sha256(run_source)
    copied: list[Path] = []
    pairs: list[str] = []
    for src in spec.sources:
        target_path = dest / src.name
        shutil.copy(src, target_path)
        copied.append(target_path)
        pairs.append(f"{src.name}:{sha256(target_path)}")
    derived = hashlib.sha256("\n".join(sorted(pairs)).encode()).hexdigest()
    return copied, derived


def source_build_args(
    target_sources: list[Path], spec: targets.TargetSpec
) -> list[str]:
    """clang/afl-cc/hfuzz-cc argument fragment for a target's sources + flags."""
    args: list[str] = []
    for inc in spec.include_dirs:
        args.extend(["-I", str(inc)])
    args.extend(spec.extra_cflags)
    args.extend(str(s) for s in target_sources)
    return args


def sanitizer_flags(spec: targets.TargetSpec) -> str:
    """Oracle/fuzz sanitizer selection from the target's pinned policy."""
    return "address,undefined" if spec.sanitizer_policy == "asan_ubsan" else "address"


def classify_trade_outcome(row: dict) -> str:
    """Pure, deterministic per-row outcome class (safe to unit-test in CI).

    Mirrors the fields ``run_engine`` records so the aggregate step and the
    renderer agree on what a trial was. Unsupported (not-yet-runnable) rows are
    labeled by ``run_engine``/the main loop and passed through here unchanged.
    """
    if row.get("outcome") == OUTCOME_UNSUPPORTED:
        return OUTCOME_UNSUPPORTED
    if row.get("build_rc"):
        return OUTCOME_BUILD_FAILED
    if row.get("supervisor_timeout"):
        return OUTCOME_TIMEOUT
    if row.get("crash_confirmed"):
        return OUTCOME_CONFIRMED
    # A run that neither built-failed, timed out, nor crashed is censored only if
    # the campaign actually ran to its budget; otherwise it is an incomplete run
    # that must stay visible rather than be counted as a clean no-crash.
    if row.get("campaign_wall_s") is None:
        return OUTCOME_INCOMPLETE
    return OUTCOME_CENSORED


def any_sanitizer_crash(stderr: str) -> tuple[bool, str | None]:
    """A general oracle: any ASan/UBSan/LSan diagnostic counts as a real crash."""
    markers = (
        "ERROR: AddressSanitizer",
        "SUMMARY: AddressSanitizer",
        "ERROR: LeakSanitizer",
        "runtime error:",
        "SUMMARY: UndefinedBehaviorSanitizer",
    )
    for line in stderr.splitlines():
        if any(m in line for m in markers):
            sig = next(
                (
                    ln.strip()
                    for ln in stderr.splitlines()
                    if "Sanitizer:" in ln or "runtime error:" in ln
                ),
                line.strip(),
            )
            return True, sig
    return False, None


def replay_oracle(binary: Path, input_path: Path) -> dict:
    """Run the saved crash input through the independent ASan/UBSan oracle."""
    try:
        with input_path.open("rb") as stream:
            result = subprocess.run(
                [str(binary)],
                stdin=stream,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:symbolize=0",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=0",
                },
            )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"confirmed": False, "error": str(error)}
    confirmed, sig = any_sanitizer_crash(result.stderr or "")
    return {"confirmed": confirmed, "returncode": result.returncode, "signature": sig}


def build(command: list[str], cpu, log_path: Path, env=None) -> tuple[float, int, bool]:
    return run.compile_command(command, cpu, log_path, env=env)


# --- final-corpus locators -------------------------------------------------


def bhf_corpus(work: Path) -> list[Path]:
    return [p for p in work.glob("corpus/*/queue/*") if p.is_file()]


def afl_corpus(output: Path) -> list[Path]:
    return [p for p in (output / "default/queue").glob("id:*") if p.is_file()]


def libfuzzer_corpus(corpus: Path) -> list[Path]:
    return [p for p in corpus.iterdir() if p.is_file()]


def hongg_corpus(output: Path) -> list[Path]:
    return [p for p in output.glob("*") if p.is_file() and not p.name.endswith(".txt")]


# --- shared coverage oracle ------------------------------------------------


def common_coverage(cov_binary: Path, corpus_files: list[Path], cpu, tmp: Path) -> dict:
    """Replay a corpus through the shared libFuzzer-sancov binary; report cov/ft.

    This is the engine-neutral coverage metric: identical instrumentation for
    every engine, so numbers are directly comparable. Uses libFuzzer ``-merge=1``
    (each input is executed in a subprocess), which is robust to a corpus input
    that crashes the binary — several engines keep the crasher in their corpus.
    """
    if not corpus_files:
        return {"edges": 0, "features": 0, "corpus_size": 0, "replayed": True}
    staged = tmp / "cov-corpus"
    staged.mkdir(parents=True, exist_ok=True)
    for i, f in enumerate(corpus_files):
        try:
            shutil.copy(f, staged / f"c{i:06d}")
        except OSError:
            pass
    merged = tmp / "cov-merged"
    merged.mkdir(parents=True, exist_ok=True)
    log = tmp / "cov-replay.log"
    command = [
        str(cov_binary),
        "-merge=1",
        str(merged),
        str(staged),
        "-close_fd_mask=3",
    ]
    try:
        with log.open("wb") as fh:
            proc = subprocess.Popen(
                run.prefixed(command, cpu),
                stdout=fh,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                proc.wait(timeout=180)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, 9)
                proc.wait()
    except OSError as error:
        return {
            "edges": None,
            "features": None,
            "corpus_size": len(corpus_files),
            "replayed": False,
            "error": str(error),
        }
    text = log.read_text(errors="replace")
    edges = None
    features = None
    m = re.search(r"(\d+)\s+new features added;\s*(\d+)\s+new coverage edges", text)
    if m:
        features, edges = int(m.group(1)), int(m.group(2))
    return {
        "edges": edges,
        "features": features,
        "corpus_size": len(corpus_files),
        "replayed": True,
    }


def corpus_reaches_bug(oracle: Path, corpus_files: list[Path], cap: int = 600) -> dict:
    """Engine-neutral crash backstop: does ANY final-corpus input trip the oracle?

    honggfuzz keeps a coverage-increasing crasher in its corpus without recording
    it as a crash; AFL/libFuzzer/BHF quarantine crashers separately. Replaying the
    corpus through the independent ASan/UBSan oracle detects bug REACHABILITY for
    every engine uniformly, independent of each engine's own crash classifier.
    """
    for f in corpus_files[:cap]:
        verdict = replay_oracle(oracle, f)
        if verdict.get("confirmed"):
            return {"confirmed": True, "signature": verdict.get("signature")}
    return {"confirmed": False, "signature": None}


def parse_honggfuzz(log_path: Path) -> dict:
    text = log_path.read_text(errors="replace") if log_path.exists() else ""
    execs = None
    for m in re.finditer(r"[Ii]terations[^\d]*(\d+)", text):
        execs = int(m.group(1))
    return {"executions_native": execs}


# --- one engine on one target for one trial --------------------------------


def run_engine(
    engine,
    args,
    spec: targets.TargetSpec,
    trial_seed,
    target_sources,
    primary_source,
    trial_dir,
    oracle,
    cov_binary,
    budget,
    max_len,
):
    case = spec.name
    engine_dir = trial_dir / engine
    engine_dir.mkdir()
    corpus = engine_dir / "seed-corpus"
    if spec.seed_dir and spec.seed_dir.is_dir():
        corpus.mkdir(parents=True, exist_ok=True)
        for seed in sorted(spec.seed_dir.iterdir()):
            if seed.is_file():
                shutil.copy(seed, corpus / seed.name)
    if not corpus.is_dir() or not any(corpus.iterdir()):
        run.make_corpus(corpus)
    row = {
        "engine": engine,
        "case": case,
        "target": case,
        "trial_seed": trial_seed,
        "budget_s": budget,
        "max_len": max_len,
        "sanitizer_policy": spec.sanitizer_policy,
        "bhf_harness_mode": spec.bhf_harness_mode,
    }
    src_suffix = source_build_args(target_sources, spec)
    build_s = 0.0
    build_rc = 0
    measure = None
    native = {}
    final_corpus: list[Path] = []
    crash_artifact = None

    # The engine-quality comparison is only honest when every engine drives the
    # same fixed harness. bhf's "provided" mode (fuzz a supplied harness rather
    # than generate one) is the correct real-code mode but its exact CLI is a
    # documented maintainer step, so record a visible unsupported row instead of
    # fabricating an invocation.
    if engine == "bhf" and spec.bhf_harness_mode == targets.BHF_PROVIDED:
        row.update(
            {
                "outcome": OUTCOME_UNSUPPORTED,
                "build_rc": None,
                "build_s": None,
                "campaign_wall_s": None,
                "supervisor_timeout": None,
                "crash_found": False,
                "crash_confirmed": False,
                "crash_source": None,
                "time_to_first_crash_s": None,
                "crash_within_budget": None,
                "crash_signature": None,
                "common_cov_edges": None,
                "common_cov_features": None,
                "final_corpus_size": None,
                "native_executions": None,
                "native_execs_per_s": None,
                "right_censor_s": None,
                "unsupported_reason": (
                    "bhf provided-harness mode is not wired to a CLI invocation; "
                    "supply the exact `bhf fuzz` command for a pre-written harness"
                ),
            }
        )
        return row

    if engine == "libfuzzer":
        binary = engine_dir / "target"
        libcxx = run.find_libstdcxx_dir()
        link = ["-L", libcxx] if libcxx else []
        cmd = [
            "clang",
            "-O1",
            "-g",
            "-fno-omit-frame-pointer",
            f"-fsanitize=fuzzer,{sanitizer_flags(spec)}",
            *link,
            str(HARNESS_ROOT / "libfuzzer.c"),
            *src_suffix,
            "-o",
            str(binary),
        ]
        build_s, build_rc, _ = build(cmd, args.cpu, engine_dir / "build.log")
        artifacts = engine_dir / "artifacts"
        artifacts.mkdir()
        libcorp = engine_dir / "corpus"
        libcorp.mkdir()
        for index, seed in enumerate(
            sorted(p for p in corpus.iterdir() if p.is_file())
        ):
            shutil.copy(seed, libcorp / f"seed-{index:04d}")
        cmd_run = [
            str(binary),
            str(libcorp),
            f"-max_total_time={budget}",
            f"-timeout={max(1, (args.timeout_ms + 999) // 1000)}",
            f"-max_len={max_len}",
            f"-seed={trial_seed}",
            "-use_value_profile=1",
            "-print_final_stats=1",
            f"-artifact_prefix={artifacts}/",
        ]
        if build_rc == 0:
            measure = run.monitor(
                cmd_run,
                engine_dir / "run.log",
                cpu=args.cpu,
                timeout_s=budget + 20,
                crash_probe=lambda: run.libfuzzer_crash_artifact(artifacts),
            )
            native = (
                run.parse_libfuzzer(Path(measure["log"])) if measure.get("log") else {}
            )
            final_corpus = libfuzzer_corpus(libcorp)
            crash_artifact = run.libfuzzer_crash_artifact(artifacts)

    elif engine == "aflpp":
        afl_path = args.afl_path
        afl_cc = str(afl_path / "afl-cc")
        afl_fuzz = str(afl_path / "afl-fuzz")
        binary = engine_dir / "target"
        cmp_binary = engine_dir / "target.cmplog"
        base = [
            afl_cc,
            "-O1",
            "-g",
            f"-fsanitize={sanitizer_flags(spec)}",
            str(HARNESS_ROOT / "afl_persistent.c"),
            *src_suffix,
            "-o",
        ]
        env = {**os.environ, "AFL_PATH": str(afl_path), "AFL_QUIET": "1"}
        b1, rc1, _ = build(
            [*base, str(binary)], args.cpu, engine_dir / "build.log", env=env
        )
        b2, rc2, _ = build(
            [*base, str(cmp_binary)],
            args.cpu,
            engine_dir / "build-cmplog.log",
            env={**env, "AFL_LLVM_CMPLOG": "1"},
        )
        build_s, build_rc = b1 + b2, (rc1 or rc2)
        output = engine_dir / "afl-output"
        cmd_run = [
            afl_fuzz,
            "-i",
            str(corpus),
            "-o",
            str(output),
            "-V",
            str(budget),
            "-t",
            str(args.timeout_ms),
            "-m",
            "none",
            "-s",
            str(trial_seed),
            "-G",
            str(max_len),
            "-c",
            str(cmp_binary),
            "--",
            str(binary),
        ]
        if build_rc == 0:
            renv = {
                **os.environ,
                "AFL_PATH": str(afl_path),
                "AFL_SKIP_CPUFREQ": "1",
                "AFL_NO_UI": "1",
                "AFL_QUIET": "1",
                "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
                "AFL_BENCH_UNTIL_CRASH": "0",
            }
            measure = run.monitor(
                cmd_run,
                engine_dir / "run.log",
                cpu=args.cpu,
                timeout_s=budget + 25,
                crash_probe=lambda: run.afl_crash_artifact(output),
                env=renv,
            )
            native = run.parse_afl(output)
            final_corpus = afl_corpus(output)
            crash_artifact = run.afl_crash_artifact(output)

    elif engine == "honggfuzz":
        hfcc = str(args.honggfuzz_dir / "hfuzz_cc/hfuzz-cc")
        hfuzz = str(args.honggfuzz_dir / "honggfuzz")
        binary = engine_dir / "target"
        cmd = [
            hfcc,
            "-O1",
            "-g",
            f"-fsanitize={sanitizer_flags(spec)}",
            str(HARNESS_ROOT / "libfuzzer.c"),
            *src_suffix,
            "-o",
            str(binary),
        ]
        build_s, build_rc, _ = build(cmd, args.cpu, engine_dir / "build.log")
        outcorp = engine_dir / "hf-corpus"
        outcorp.mkdir()
        crashdir = engine_dir / "hf-crashes"
        crashdir.mkdir()
        cmd_run = [
            hfuzz,
            "--run_time",
            str(budget),
            "-i",
            str(corpus),
            "-o",
            str(outcorp),
            "--crashdir",
            str(crashdir),
            "-F",
            str(max_len),
            "-n",
            "1",
            "-t",
            str(max(1, (args.timeout_ms + 999) // 1000)),
            "--",
            str(binary),
        ]

        def hf_crash():
            found = [p for p in crashdir.glob("*") if p.is_file()]
            return sorted(found)[0] if found else None

        if build_rc == 0:
            renv = {
                **os.environ,
                "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:symbolize=0",
            }
            measure = run.monitor(
                cmd_run,
                engine_dir / "run.log",
                cpu=args.cpu,
                timeout_s=budget + 25,
                crash_probe=hf_crash,
                env=renv,
            )
            native = parse_honggfuzz(engine_dir / "run.log")
            final_corpus = hongg_corpus(outcorp)
            crash_artifact = hf_crash()

    else:  # bhf
        work = engine_dir / "work"
        work.mkdir()
        generated = work / "generated_harnesses"
        generated.mkdir()
        gen = [
            str(args.bhf),
            "generate-harness",
            str(primary_source),
            "--target",
            "target_one_input",
            "--output",
            str(generated),
        ]
        gen_s, gen_rc, _ = build(gen, args.cpu, engine_dir / "build-generate.log")
        harnesses = sorted(p for p in generated.iterdir() if p.is_dir())
        hid = harnesses[0].name if harnesses else None
        build_s, build_rc = gen_s, gen_rc
        if build_rc == 0 and hid:
            bcmd = [str(args.bhf), "build", str(work), "--harness", hid]
            bs, brc, _ = build(bcmd, args.cpu, engine_dir / "build-native.log")
            build_s += bs
            build_rc = brc
            binary = work / "build" / hid / "main"
            seed_file = next(corpus.iterdir())
            if build_rc == 0:
                fcmd = [
                    str(args.bhf),
                    "fuzz",
                    str(work),
                    "--harness",
                    hid,
                    "--engine",
                    "builtin",
                    "--time",
                    f"{budget}s",
                    "--seed-file",
                    str(seed_file),
                    "--rng-seed",
                    str(trial_seed),
                    "--max-len",
                    str(max_len),
                    "--len-control",
                    "0",
                    "--timeout",
                    f"{max(1, (args.timeout_ms + 999) // 1000)}s",
                    "--workers",
                    "1",
                    "--sandbox",
                    "none",
                    "--print-final-stats",
                ]

                def bhf_crash():
                    return run.bhf_crash_artifact(work)

                measure = run.monitor(
                    fcmd,
                    engine_dir / "run.log",
                    cpu=args.cpu,
                    timeout_s=budget + 25,
                    crash_probe=bhf_crash,
                )
                native = (
                    run.parse_bhf_fuzz(Path(measure["log"]), work)
                    if measure.get("log")
                    else {}
                )
                final_corpus = bhf_corpus(work)
                crash_artifact = bhf_crash()

    # Confirm the crash through the independent oracle. First the engine's own
    # saved artifact (gives a precise time-to-first-crash), then a corpus backstop.
    native_confirmed = False
    signature = None
    if crash_artifact is not None:
        verdict = replay_oracle(oracle, Path(crash_artifact))
        native_confirmed = bool(verdict.get("confirmed"))
        signature = verdict.get("signature")
    crash_source = "native" if native_confirmed else None
    if not native_confirmed:
        backstop = corpus_reaches_bug(oracle, final_corpus)
        if backstop["confirmed"]:
            crash_source = "corpus"
            signature = backstop["signature"]
    confirmed = native_confirmed or crash_source == "corpus"

    # Engine-neutral coverage of the FINAL corpus.
    cov = common_coverage(cov_binary, final_corpus, args.cpu, engine_dir / "cov")

    # Precise TTFC only from the engine's native crash artifact (honggfuzz's
    # persistent+ASan loop does not record one, so its TTFC is null even when the
    # corpus backstop confirms bug reachability).
    ttfc = (
        measure.get("first_crash_from_process_s")
        if (measure and native_confirmed)
        else None
    )
    within_budget = ttfc is not None and ttfc <= budget + 2
    row.update(
        {
            "build_s": round(build_s, 3),
            "build_rc": build_rc,
            "campaign_wall_s": round(measure["process_wall_s"], 3) if measure else None,
            "supervisor_timeout": measure.get("timed_out") if measure else None,
            "crash_found": confirmed,
            "crash_confirmed": confirmed,
            "crash_source": crash_source,
            "time_to_first_crash_s": round(ttfc, 3) if ttfc is not None else None,
            "crash_within_budget": within_budget,
            "crash_signature": signature,
            "common_cov_edges": cov.get("edges"),
            "common_cov_features": cov.get("features"),
            "final_corpus_size": cov.get("corpus_size"),
            "native_executions": native.get("executions_native"),
        }
    )
    if row["native_executions"] and measure and measure.get("process_wall_s"):
        row["native_execs_per_s"] = round(
            row["native_executions"] / measure["process_wall_s"], 1
        )
    else:
        row["native_execs_per_s"] = None
    # Native counters are retained but explicitly NOT a cross-engine unit.
    row["native_executions_comparable_across_engines"] = False
    row["outcome"] = classify_trade_outcome(row)
    row["right_censor_s"] = (
        row["campaign_wall_s"] if row["outcome"] == OUTCOME_CENSORED else None
    )
    return row


def unsupported_rows(spec: targets.TargetSpec, engines, trial_seed) -> list[dict]:
    """Visible placeholder rows for a target the simple compile model can't run.

    A ``requires_build_recipe``/``manual`` target still appears in the evidence —
    with its upstream pin and the reason — so a maintainer sees exactly which
    real-code targets remain to be wired, rather than the target vanishing.
    """
    reason = (
        f"target status={spec.status!r}: the single-invocation compile model "
        f"cannot build this target; supply a per-target build recipe"
    )
    rows = []
    for engine in engines:
        rows.append(
            {
                "engine": engine,
                "case": spec.name,
                "target": spec.name,
                "trial_seed": trial_seed,
                "outcome": OUTCOME_UNSUPPORTED,
                "crash_found": False,
                "crash_confirmed": False,
                "time_to_first_crash_s": None,
                "common_cov_edges": None,
                "common_cov_features": None,
                "final_corpus_size": None,
                "native_executions": None,
                "native_execs_per_s": None,
                "native_executions_comparable_across_engines": False,
                "build_rc": None,
                "right_censor_s": None,
                "crash_signature": None,
                "unsupported_reason": reason,
                "target_provenance": spec.provenance(),
            }
        )
    return rows


def one_trial(args, spec: targets.TargetSpec, trial_seed, trial_dir) -> list[dict]:
    src_dir = trial_dir / "source"
    target_sources, derived_sha = materialize_target(spec, src_dir)
    primary_source = target_sources[0]
    budget = spec.budget_s if spec.budget_s is not None else args.budget
    max_len = spec.max_len if spec.max_len is not None else args.max_len
    src_suffix = source_build_args(target_sources, spec)

    oracle = trial_dir / "replay-oracle"
    ob, orc, _ = build(
        [
            "clang",
            "-O1",
            "-g",
            "-fno-omit-frame-pointer",
            f"-fsanitize={sanitizer_flags(spec)}",
            str(HARNESS_ROOT / "replay_stdin.c"),
            *src_suffix,
            "-o",
            str(oracle),
        ],
        args.cpu,
        trial_dir / "oracle-build.log",
    )
    if orc != 0:
        raise RuntimeError(
            f"replay oracle build failed; see {trial_dir / 'oracle-build.log'}"
        )

    cov_binary = trial_dir / "cov-binary"
    libcxx = run.find_libstdcxx_dir()
    link = ["-L", libcxx] if libcxx else []
    cb, cbrc, _ = build(
        [
            "clang",
            "-O1",
            "-g",
            "-fsanitize=fuzzer,address",
            *link,
            str(HARNESS_ROOT / "libfuzzer.c"),
            *src_suffix,
            "-o",
            str(cov_binary),
        ],
        args.cpu,
        trial_dir / "covbin-build.log",
    )
    if cbrc != 0:
        raise RuntimeError(
            f"coverage binary build failed; see {trial_dir / 'covbin-build.log'}"
        )

    rows = []
    for engine in args.engines:
        r = run_engine(
            engine,
            args,
            spec,
            trial_seed,
            target_sources,
            primary_source,
            trial_dir,
            oracle,
            cov_binary,
            budget,
            max_len,
        )
        r.update(
            {
                "derived_source_sha256": derived_sha,
                "oracle_sha256": sha256(oracle),
                "coverage_binary_sha256": sha256(cov_binary),
                "target_provenance": spec.provenance(),
            }
        )
        rows.append(r)
        print(
            f"  [{spec.name} t{trial_seed} {engine:9}] "
            f"outcome={r.get('outcome')} "
            f"crash={r.get('crash_found')}({'ok' if r.get('crash_confirmed') else '-'}) "
            f"ttfc={r.get('time_to_first_crash_s')} cov_edges={r.get('common_cov_edges')} "
            f"ft={r.get('common_cov_features')} corpus={r.get('final_corpus_size')}",
            flush=True,
        )
    return rows


def aggregate(rows: list[dict], engines, cases) -> dict:
    summary = {}
    for case in cases:
        summary[case] = {}
        for engine in engines:
            sub = [r for r in rows if r["case"] == case and r["engine"] == engine]
            if sub:
                summary[case][engine] = engine_summary(sub)
    aggregate_by_engine = {}
    for engine in engines:
        sub = [r for r in rows if r["engine"] == engine]
        if sub:
            aggregate_by_engine[engine] = engine_summary(sub)
    return {
        "schema": "bhf-trade-study-summary-v2",
        "per_target": summary,
        "aggregate_by_engine": aggregate_by_engine,
        "metric_notes": {
            "crash_find": (
                "Wilson 95% CI over VALID campaigns only (confirmed + censored); "
                "build_failed/timeout/incomplete/unsupported trials are reported "
                "separately in 'outcomes' so the effective n stays visible."
            ),
            "ttfc_s": "distribution over oracle-confirmed trials with a native TTFC",
            "common_cov_edges": "engine-neutral shared-sancov edges; median + IQR + range + bootstrap CI",
            "native_execs_per_s": "per-engine only; NOT comparable across engines (counter semantics differ)",
        },
    }


def engine_summary(sub: list[dict]) -> dict:
    """Distribution-aware summary for one engine over a set of trial rows.

    Keeps every outcome class visible, reports a binomial CI for the crash-find
    rate over valid campaigns, distribution+CI for the continuous metrics, and
    the distinct confirmed-defect signature count. Native throughput is reported
    per-engine with an explicit non-comparability flag.
    """
    outcomes = {
        cls: sum(1 for r in sub if r.get("outcome") == cls) for cls in OUTCOME_CLASSES
    }
    confirmed = [r for r in sub if r.get("outcome") == OUTCOME_CONFIRMED]
    censored = [r for r in sub if r.get("outcome") == OUTCOME_CENSORED]
    valid = outcomes[OUTCOME_CONFIRMED] + outcomes[OUTCOME_CENSORED]
    ttfcs = [
        r["time_to_first_crash_s"]
        for r in confirmed
        if r.get("time_to_first_crash_s") is not None
    ]
    edges = [
        r["common_cov_edges"] for r in sub if r.get("common_cov_edges") is not None
    ]
    fts = [
        r["common_cov_features"]
        for r in sub
        if r.get("common_cov_features") is not None
    ]
    execs = [
        r["native_execs_per_s"] for r in sub if r.get("native_execs_per_s") is not None
    ]
    builds = [r["build_s"] for r in sub if r.get("build_s") is not None]
    signatures = {
        r.get("crash_signature") for r in confirmed if r.get("crash_signature")
    }
    return {
        "trials": len(sub),
        "valid_campaigns": valid,
        "outcomes": outcomes,
        "crash_find": stats.wilson_interval(
            outcomes[OUTCOME_CONFIRMED], valid
        ).as_dict(),
        "distinct_defect_signatures": len(signatures),
        "ttfc_s": stats.summarize(ttfcs).as_dict(),
        "common_cov_edges": stats.summarize(edges, round_to=1).as_dict(),
        "common_cov_features": stats.summarize(fts, round_to=1).as_dict(),
        "build_s": stats.summarize(builds).as_dict(),
        "native_execs_per_s": {
            "comparable_across_engines": False,
            "distribution": stats.summarize(execs, round_to=1).as_dict(),
        },
        "right_censored_s": sorted(
            r["right_censor_s"] for r in censored if r.get("right_censor_s") is not None
        ),
    }


def load_targets(args) -> list[targets.TargetSpec]:
    """Resolve the pluggable target set: builtin fixtures or a manifest."""
    if args.manifest:
        specs = targets.load_manifest(args.manifest, resolve_sources=not args.dry_run)
    else:
        specs = targets.builtin_fixture_targets(run.CASES)
    if args.cases:
        wanted = set(args.cases)
        specs = [s for s in specs if s.name in wanted]
        missing = wanted - {s.name for s in specs}
        if missing:
            raise SystemExit(f"--cases named unknown targets: {sorted(missing)}")
    if not specs:
        raise SystemExit("no targets selected")
    return specs


def describe_plan(specs: list[targets.TargetSpec], args) -> None:
    for spec in specs:
        budget = spec.budget_s if spec.budget_s is not None else args.budget
        max_len = spec.max_len if spec.max_len is not None else args.max_len
        pin = f" @ {spec.upstream.commit[:12]}" if spec.upstream else ""
        print(f"- {spec.name} [{spec.kind}/{spec.status}]{pin}")
        print(
            f"    budget={budget}s max_len={max_len} sanitizer={spec.sanitizer_policy} "
            f"bhf_harness={spec.bhf_harness_mode}"
        )
        if spec.sources:
            print(f"    sources: {', '.join(p.name for p in spec.sources)}")
        if spec.source_sha256:
            for name, digest in spec.source_sha256.items():
                print(f"      {name}: {digest[:16]}")
        if spec.notes:
            print(f"    notes: {spec.notes}")


def build_evidence(all_rows, specs, args, started) -> dict:
    manifest_sha = (
        sha256(args.manifest) if args.manifest and args.manifest.is_file() else None
    )
    return {
        "schema": "bhf-trade-study-v2",
        "experiment": "engine-quality",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git_commit": run.command_output(["git", "rev-parse", "HEAD"]),
        "host": {"cpu": run.cpu_model(), "nproc": os.cpu_count()},
        "config": {
            k: (str(v) if isinstance(v, Path) else v) for k, v in vars(args).items()
        },
        "manifest": {
            "path": str(args.manifest) if args.manifest else None,
            "sha256": manifest_sha,
        },
        "targets": [s.provenance() for s in specs],
        "tool_versions": {
            "bhf": run.command_output([str(args.bhf), "--version"]),
            "afl_cc": run.command_output([str(args.afl_path / "afl-cc"), "--version"]),
            "afl_fuzz_dir": str(args.afl_path),
            "clang": run.command_output(["clang", "--version"]),
            "honggfuzz_dir": str(args.honggfuzz_dir),
        },
        "rows": all_rows,
        "summary": aggregate(all_rows, args.engines, [s.name for s in specs]),
        "elapsed_s": round(time.time() - started, 1),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--engines", nargs="+", choices=ENGINES, default=list(ENGINES))
    p.add_argument(
        "--cases",
        nargs="+",
        default=None,
        help="restrict to these target names (default: all targets in the set)",
    )
    p.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="real-code target manifest (.json/.toml); default = the 4 builtin fixtures",
    )
    p.add_argument(
        "--sources",
        type=Path,
        default=None,
        help="checkout root for --fetch (default: <workdir>/sources)",
    )
    p.add_argument(
        "--fetch",
        action="store_true",
        help="clone manifest upstreams at their pins, then exit",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="validate + print the target plan without building",
    )
    p.add_argument(
        "--list-targets",
        action="store_true",
        help="print the resolved target set and exit",
    )
    p.add_argument("--trials", type=int, default=10)
    p.add_argument("--budget", type=int, default=60, help="fuzz wall seconds per trial")
    p.add_argument("--timeout-ms", type=int, default=1000)
    p.add_argument("--max-len", type=int, default=64)
    p.add_argument("--cpu", default="0", help="taskset CPU/list; 'none' to disable")
    p.add_argument("--bhf", type=Path, default=run.DEFAULT_BHF)
    p.add_argument("--afl-path", type=Path, default=Path("/tmp/bhf-afl503c.NoHEOu/src"))
    p.add_argument("--honggfuzz-dir", type=Path, default=Path("/tmp/honggfuzz"))
    p.add_argument("--workdir", type=Path, default=Path("/tmp/bhf-trade-study"))
    p.add_argument("--output", type=Path, default=None)
    args = p.parse_args()
    if args.cpu.lower() == "none":
        args.cpu = None

    specs = load_targets(args)

    if args.fetch:
        sources_root = (args.sources or args.workdir / "sources").resolve()
        log_dir = args.workdir / "fetch-logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        for spec in specs:
            if spec.upstream is None:
                print(f"- {spec.name}: no upstream pin, skipped")
                continue
            checkout = targets.fetch_sources(spec, sources_root, log_dir=log_dir)
            print(
                f"- {spec.name}: checked out {spec.upstream.commit[:12]} -> {checkout}"
            )
        print(
            "Fetched. Point each target's 'sources'/'include_dirs' at these "
            "checkouts, add a target_one_input adapter, and set status=runnable."
        )
        return 0

    if args.list_targets or args.dry_run:
        print(f"{len(specs)} target(s):")
        describe_plan(specs, args)
        runnable = sum(1 for s in specs if s.status == targets.RUNNABLE)
        print(
            f"\nrunnable: {runnable}/{len(specs)} (others emit visible unsupported rows)"
        )
        return 0

    if args.output is None:
        p.error("--output is required when running a study")

    args.workdir.mkdir(parents=True, exist_ok=True)
    all_rows: list[dict] = []
    started = time.time()
    for spec in specs:
        if spec.status != targets.RUNNABLE:
            all_rows.extend(unsupported_rows(spec, args.engines, None))
            print(
                f"[{spec.name}] status={spec.status} -> {len(args.engines)} unsupported rows"
            )
            args.output.write_text(
                json.dumps(build_evidence(all_rows, specs, args, started), indent=2)
            )
            continue
        for t in range(args.trials):
            trial_seed = 1000 + t
            trial_dir = args.workdir / spec.name / f"trial-{t:03d}"
            if trial_dir.exists():
                shutil.rmtree(trial_dir)
            trial_dir.mkdir(parents=True)
            all_rows.extend(one_trial(args, spec, trial_seed, trial_dir))
            # Persist incrementally so a long run is never lost.
            args.output.write_text(
                json.dumps(build_evidence(all_rows, specs, args, started), indent=2)
            )
    print(
        f"\nDONE: {len(all_rows)} rows in {time.time() - started:.0f}s -> {args.output}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
