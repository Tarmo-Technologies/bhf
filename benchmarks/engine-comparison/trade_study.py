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
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path

import run  # reviewed helpers: sha256, monitor, fixture_source, make_corpus, CASES, ...

ROOT = run.ROOT
HARNESS_ROOT = run.HARNESS_ROOT
FIXTURE_ROOT = run.FIXTURE_ROOT
SEED = run.SEED

ENGINES = ("bhf", "aflpp", "libfuzzer", "honggfuzz")


def sha256(path: Path) -> str:
    return run.sha256(path)


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
    engine, args, case, trial_seed, run_source, trial_dir, oracle, cov_binary
):
    engine_dir = trial_dir / engine
    engine_dir.mkdir()
    corpus = engine_dir / "seed-corpus"
    run.make_corpus(corpus)
    budget = args.budget
    row = {
        "engine": engine,
        "case": case,
        "trial_seed": trial_seed,
        "budget_s": budget,
        "max_len": args.max_len,
    }
    build_s = 0.0
    build_rc = 0
    measure = None
    native = {}
    final_corpus: list[Path] = []
    crash_artifact = None

    if engine == "libfuzzer":
        binary = engine_dir / "target"
        libcxx = run.find_libstdcxx_dir()
        link = ["-L", libcxx] if libcxx else []
        cmd = [
            "clang",
            "-O1",
            "-g",
            "-fno-omit-frame-pointer",
            "-fsanitize=fuzzer,address,undefined",
            *link,
            str(HARNESS_ROOT / "libfuzzer.c"),
            str(run_source),
            "-o",
            str(binary),
        ]
        build_s, build_rc, _ = build(cmd, args.cpu, engine_dir / "build.log")
        artifacts = engine_dir / "artifacts"
        artifacts.mkdir()
        libcorp = engine_dir / "corpus"
        libcorp.mkdir()
        shutil.copy(next(corpus.iterdir()), libcorp / "seed")
        cmd_run = [
            str(binary),
            str(libcorp),
            f"-max_total_time={budget}",
            f"-timeout={max(1, (args.timeout_ms + 999) // 1000)}",
            f"-max_len={args.max_len}",
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
            "-fsanitize=address,undefined",
            str(HARNESS_ROOT / "afl_persistent.c"),
            str(run_source),
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
            str(args.max_len),
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
            "-fsanitize=address,undefined",
            str(HARNESS_ROOT / "libfuzzer.c"),
            str(run_source),
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
            str(args.max_len),
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
            str(run_source),
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
                    str(args.max_len),
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
    return row


def one_trial(args, case, trial_seed, trial_dir) -> list[dict]:
    src_dir = trial_dir / "source"
    src_dir.mkdir(parents=True)
    run_source = src_dir / f"{case}.c"
    run_source.write_text(run.fixture_source(case))
    derived_sha = sha256(run_source)

    oracle = trial_dir / "replay-oracle"
    ob, orc, _ = build(
        [
            "clang",
            "-O1",
            "-g",
            "-fno-omit-frame-pointer",
            "-fsanitize=address,undefined",
            str(HARNESS_ROOT / "replay_stdin.c"),
            str(run_source),
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
            str(run_source),
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
            engine, args, case, trial_seed, run_source, trial_dir, oracle, cov_binary
        )
        r.update(
            {
                "derived_source_sha256": derived_sha,
                "oracle_sha256": sha256(oracle),
                "coverage_binary_sha256": sha256(cov_binary),
            }
        )
        rows.append(r)
        print(
            f"  [{case} t{trial_seed} {engine:9}] "
            f"crash={r['crash_found']}({'ok' if r['crash_confirmed'] else '-'}) "
            f"ttfc={r['time_to_first_crash_s']} cov_edges={r['common_cov_edges']} "
            f"ft={r['common_cov_features']} corpus={r['final_corpus_size']}",
            flush=True,
        )
    return rows


def aggregate(rows: list[dict], engines, cases) -> dict:
    summary = {}
    for case in cases:
        summary[case] = {}
        for engine in engines:
            sub = [r for r in rows if r["case"] == case and r["engine"] == engine]
            if not sub:
                continue
            confirmed = [r for r in sub if r["crash_confirmed"]]
            ttfcs = [
                r["time_to_first_crash_s"]
                for r in confirmed
                if r["time_to_first_crash_s"] is not None
            ]
            edges = [
                r["common_cov_edges"] for r in sub if r["common_cov_edges"] is not None
            ]
            fts = [
                r["common_cov_features"]
                for r in sub
                if r["common_cov_features"] is not None
            ]
            execs = [
                r["native_execs_per_s"]
                for r in sub
                if r["native_execs_per_s"] is not None
            ]
            builds = [r["build_s"] for r in sub if r["build_s"] is not None]
            summary[case][engine] = {
                "trials": len(sub),
                "crash_find_rate": round(len(confirmed) / len(sub), 3),
                "median_ttfc_s": round(statistics.median(ttfcs), 3) if ttfcs else None,
                "min_ttfc_s": round(min(ttfcs), 3) if ttfcs else None,
                "median_cov_edges": statistics.median(edges) if edges else None,
                "max_cov_edges": max(edges) if edges else None,
                "median_cov_features": statistics.median(fts) if fts else None,
                "median_native_execs_per_s": round(statistics.median(execs), 1)
                if execs
                else None,
                "median_build_s": round(statistics.median(builds), 3)
                if builds
                else None,
            }
    return summary


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--engines", nargs="+", choices=ENGINES, default=list(ENGINES))
    p.add_argument("--cases", nargs="+", default=list(run.CASES))
    p.add_argument("--trials", type=int, default=10)
    p.add_argument("--budget", type=int, default=60, help="fuzz wall seconds per trial")
    p.add_argument("--timeout-ms", type=int, default=1000)
    p.add_argument("--max-len", type=int, default=64)
    p.add_argument("--cpu", default="0", help="taskset CPU/list; 'none' to disable")
    p.add_argument("--bhf", type=Path, default=run.DEFAULT_BHF)
    p.add_argument("--afl-path", type=Path, default=Path("/tmp/bhf-afl503c.NoHEOu/src"))
    p.add_argument("--honggfuzz-dir", type=Path, default=Path("/tmp/honggfuzz"))
    p.add_argument("--workdir", type=Path, default=Path("/tmp/bhf-trade-study"))
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if args.cpu.lower() == "none":
        args.cpu = None

    args.workdir.mkdir(parents=True, exist_ok=True)
    all_rows: list[dict] = []
    started = time.time()
    for case in args.cases:
        for t in range(args.trials):
            trial_seed = 1000 + t
            trial_dir = args.workdir / case / f"trial-{t:03d}"
            if trial_dir.exists():
                shutil.rmtree(trial_dir)
            trial_dir.mkdir(parents=True)
            all_rows.extend(one_trial(args, case, trial_seed, trial_dir))
            # Persist incrementally so a long run is never lost.
            args.output.write_text(
                json.dumps(
                    {
                        "schema": "bhf-trade-study-v1",
                        "generated_utc": time.strftime(
                            "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
                        ),
                        "host": {"cpu": run.cpu_model(), "nproc": os.cpu_count()},
                        "config": {
                            k: (str(v) if isinstance(v, Path) else v)
                            for k, v in vars(args).items()
                        },
                        "tool_versions": {
                            "bhf": run.command_output([str(args.bhf), "--version"]),
                            "afl_cc": run.command_output(
                                [str(args.afl_path / "afl-cc"), "--version"]
                            ),
                            "afl_fuzz_dir": str(args.afl_path),
                            "clang": run.command_output(["clang", "--version"]),
                            "honggfuzz_dir": str(args.honggfuzz_dir),
                        },
                        "rows": all_rows,
                        "summary": aggregate(all_rows, args.engines, args.cases),
                        "elapsed_s": round(time.time() - started, 1),
                    },
                    indent=2,
                )
            )
    print(
        f"\nDONE: {len(all_rows)} rows in {time.time() - started:.0f}s -> {args.output}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
