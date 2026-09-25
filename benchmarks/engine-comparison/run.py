# SPDX-License-Identifier: Apache-2.0
"""Small, reproducible BHF/AFL++/libFuzzer comparison on shared C callbacks.

This runner is a smoke-study tool. It keeps raw trial rows and logs so a larger
experiment can reuse the protocol without turning a toy result into a parity
claim. Build time and fuzz time are recorded separately; no-solve trials remain
right-censored observations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = ROOT / "tests/fixtures/engine_parity"
HARNESS_ROOT = ROOT / "benchmarks/harnesses"
DEFAULT_BHF = ROOT / "target/release/bhf"
CASES = {
    "magic_byte": "parse_frame",
    "const_gate": "check_magic",
    "len_field": "read_record",
    "redqueen_int": "redqueen_int",
}
SEED = bytes(8)
POLL_INTERVAL_S = 0.01


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def command_output(command: list[str]) -> str | None:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return (result.stdout or result.stderr).strip().splitlines()[0]
    except (OSError, subprocess.TimeoutExpired, IndexError):
        pass
    return None


def cpu_model() -> str | None:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or None


def prefixed(command: list[str], cpu: str | None) -> list[str]:
    if cpu is None:
        return command
    taskset = shutil.which("taskset")
    if not taskset:
        raise RuntimeError("--cpu requires taskset, which is unavailable")
    return [taskset, "-c", cpu, *command]


def fixture_source(case: str) -> str:
    source = (FIXTURE_ROOT / case / f"{case}.c").read_text()
    callback = CASES[case]
    return source + f"\nint target_one_input(const unsigned char *data, size_t size) {{\n    return {callback}(data, size);\n}}\n"


def make_corpus(path: Path) -> str:
    path.mkdir(parents=True, exist_ok=True)
    seed = path / "seed-zero-8"
    seed.write_bytes(SEED)
    return sha256(seed)


def bhf_crash_artifact(work: Path) -> Path | None:
    findings = sorted((work / "findings").glob("*/testcase.bin"))
    return findings[0] if findings else None


def libfuzzer_crash_artifact(artifacts: Path) -> Path | None:
    crashes = sorted(artifacts.glob("crash-*"))
    return crashes[0] if crashes else None


def afl_crash_artifact(output: Path) -> Path | None:
    crash_dir = output / "default/crashes"
    if not crash_dir.is_dir():
        return None
    crashes = sorted(path for path in crash_dir.iterdir() if path.name.startswith("id:"))
    return crashes[0] if crashes else None


def required_tools(engines: list[str], cpu: str | None) -> set[str]:
    # A separate clang/ASan replay oracle validates every candidate crash.
    required: set[str] = {"clang"}
    if "afl++" in engines:
        required.update(("afl-clang-fast", "afl-fuzz"))
    if cpu is not None:
        required.add("taskset")
    return required


def classify_outcome(
    build_returncode: int,
    run: dict,
    artifact: Path | None,
    replay: dict | None,
) -> str:
    if build_returncode != 0:
        return "build_failed"
    if run.get("timed_out"):
        return "supervisor_timeout"
    if artifact is not None:
        if replay and replay.get("expected_sanitizer_crash"):
            return "confirmed_crash" if run.get("artifact_within_budget", True) else "out_of_budget_crash"
        return "unconfirmed_crash_artifact"
    if run.get("returncode") != 0 or not run.get("campaign_completed"):
        return "runner_error"
    return "censored_no_crash"


def replay_expected_crash(binary: Path, input_path: Path) -> dict:
    try:
        with input_path.open("rb") as input_stream:
            result = subprocess.run(
                [str(binary)],
                stdin=input_stream,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                # Symbolizer subprocess startup can wedge a short isolated
                # replay in constrained containers; the signature remains
                # available without a source-symbolized backtrace.
                env={**os.environ, "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:symbolize=0"},
            )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {
            "expected_sanitizer_crash": False,
            "error": str(error),
            "returncode": None,
        }
    stderr = result.stderr or ""
    return {
        "expected_sanitizer_crash": "AddressSanitizer: stack-buffer-overflow" in stderr,
        "returncode": result.returncode,
        "sanitizer_signature": next(
            (line.strip() for line in stderr.splitlines() if "AddressSanitizer:" in line),
            None,
        ),
    }


def monitor(
    command: list[str],
    log_path: Path,
    *,
    cpu: str | None,
    timeout_s: float,
    crash_probe: Callable[[], Path | None],
    env: dict | None = None,
) -> dict:
    started = time.monotonic()
    first_crash_s = None
    crash_artifact = None
    timed_out = False
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            prefixed(command, cpu),
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env=env,
        )
        while process.poll() is None:
            elapsed = time.monotonic() - started
            found_artifact = crash_probe()
            if first_crash_s is None and found_artifact is not None:
                first_crash_s = elapsed
                crash_artifact = found_artifact
            if elapsed >= timeout_s:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                break
            time.sleep(POLL_INTERVAL_S)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        if first_crash_s is None:
            found_artifact = crash_probe()
            if found_artifact is not None:
                first_crash_s = time.monotonic() - started
                crash_artifact = found_artifact
    wall_s = time.monotonic() - started
    return {
        "returncode": process.returncode,
        "timed_out": timed_out,
        "process_wall_s": wall_s,
        "first_crash_from_process_s": first_crash_s,
        "crash_artifact": str(crash_artifact) if crash_artifact else None,
        "ttfc_poll_resolution_ms": int(POLL_INTERVAL_S * 1000),
        "log": str(log_path),
    }


def parse_bhf_fuzz(log_path: Path, work: Path) -> dict:
    text = log_path.read_text(errors="replace")
    executions = re.search(r"final stats\s+[—-]+\s+execs:\s*(\d+)", text)
    findings = sum(1 for _ in (work / "findings").glob("*/finding.json"))
    summaries = sorted((work / "fuzz_runs").glob("*-latest.json"))
    summary = None
    if len(summaries) == 1:
        try:
            summary = json.loads(summaries[0].read_text())
        except (OSError, ValueError):
            pass
    return {
        "run_json": str(summaries[0]) if summary is not None else None,
        "executions_native": summary.get("executions") if summary is not None else (int(executions.group(1)) if executions else None),
        "engine_fuzz_s": summary.get("elapsed_secs") if summary is not None else None,
        "coverage_edges": summary.get("coverage", {}).get("edges") if summary is not None else None,
        "harness_protocol": summary.get("execution", {}).get("harness_protocol") if summary is not None else None,
        "forkserver": summary.get("execution", {}).get("forkserver") if summary is not None else None,
        "finding_count": findings,
    }


def parse_libfuzzer(log_path: Path) -> dict:
    text = log_path.read_text(errors="replace")
    match = re.findall(r"stat::number_of_executed_units:\s*(\d+)", text)
    return {"executions_native": int(match[-1]) if match else None}


def find_libstdcxx_dir() -> str | None:
    candidates = sorted(Path("/usr/lib/gcc/x86_64-linux-gnu").glob("*/libstdc++.so"))
    return str(candidates[-1].parent) if candidates else None


def parse_afl(output: Path) -> dict:
    stats_path = output / "default/fuzzer_stats"
    if not stats_path.is_file():
        return {"executions_native": None, "execs_per_sec_native": None, "saved_crashes": None}
    stats = {}
    for line in stats_path.read_text(errors="replace").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            stats[key.strip()] = value.strip()
    try:
        executions = int(stats["execs_done"])
    except (KeyError, ValueError):
        executions = None
    try:
        execs_per_sec = float(stats["execs_per_sec"])
    except (KeyError, ValueError):
        execs_per_sec = None
    try:
        crashes = int(stats["saved_crashes"])
    except (KeyError, ValueError):
        crashes = None
    return {
        "executions_native": executions,
        "execs_per_sec_native": execs_per_sec,
        "saved_crashes": crashes,
        "stats_path": str(stats_path),
        "afl_version": stats.get("afl_version"),
    }


def tool_versions(engines: list[str], bhf: Path) -> dict:
    afl_text = ""
    if "afl++" in engines and shutil.which("afl-fuzz"):
        try:
            afl_help = subprocess.run(
                ["afl-fuzz", "-h"], capture_output=True, text=True, timeout=5
            )
            afl_text = re.sub(r"\x1b\[[0-9;]*m", "", afl_help.stderr + afl_help.stdout)
        except (OSError, subprocess.TimeoutExpired):
            pass
    afl_match = re.search(r"afl-fuzz\+\+[^\n]+", afl_text)
    return {
        "bhf": command_output([str(bhf), "--version"]),
        "clang": command_output(["clang", "--version"]) if shutil.which("clang") else None,
        "afl_clang_fast": command_output(["afl-clang-fast", "--version"]) if shutil.which("afl-clang-fast") else None,
        "afl_fuzz": afl_match.group(0).strip() if afl_match else None,
        "rustc": command_output(["rustc", "--version"]),
    }


def compile_command(
    command: list[str], cpu: str | None, log_path: Path, env: dict | None = None
) -> tuple[float, int, bool]:
    started = time.monotonic()
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            prefixed(command, cpu),
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        timed_out = False
        try:
            process.wait(timeout=300)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
    return time.monotonic() - started, process.returncode, timed_out


def one_trial(args, case: str, trial_seed: int, source_path: Path, source_sha: str, seed_sha: str, trial_dir: Path) -> list[dict]:
    rows = []
    source_dir = trial_dir / "source"
    source_dir.mkdir()
    run_source = source_dir / f"{case}.c"
    run_source.write_text(fixture_source(case))
    local_source_sha = sha256(run_source)
    canonical_seed = trial_dir / "canonical-seed"
    canonical_seed.mkdir()
    actual_seed_sha = make_corpus(canonical_seed)
    assert actual_seed_sha == seed_sha
    replay_binary = trial_dir / "replay-oracle"
    replay_build_command = [
        "clang", "-O1", "-g", "-fno-omit-frame-pointer",
        "-fsanitize=address,undefined",
        str(HARNESS_ROOT / "replay_stdin.c"), str(run_source), "-o", str(replay_binary),
    ]
    replay_build_s, replay_build_rc, replay_build_timeout = compile_command(
        replay_build_command, args.cpu, trial_dir / "replay-build.log"
    )
    if replay_build_rc != 0 or replay_build_timeout:
        raise RuntimeError(f"independent replay oracle build failed; see {trial_dir / 'replay-build.log'}")
    replay_binary_sha = sha256(replay_binary)

    for engine in args.engines:
        engine_dir = trial_dir / engine.replace("+", "p")
        engine_dir.mkdir()
        corpus = engine_dir / "corpus"
        make_corpus(corpus)
        common = {
            "case": case,
            "target_callback": CASES[case],
            "engine": engine,
            "trial_seed": trial_seed,
            "target_source_sha256": source_sha,
            "derived_source_sha256": local_source_sha,
            "seed_sha256": seed_sha,
            "seed_bytes": len(SEED),
            "budget_s": args.budget,
            "timeout_ms": args.timeout_ms,
            "effective_timeout_ms": max(1000, ((args.timeout_ms + 999) // 1000) * 1000)
            if engine in ("builtin", "libfuzzer") else args.timeout_ms,
            "max_len": args.max_len,
            "cpu_affinity": args.cpu,
        }
        builtin_dictionary = None
        build_s = 0.0
        build_returncode = 0
        build_commands = []
        build_logs = []
        secondary_binary = None
        artifact_dir = engine_dir / "artifacts"
        artifact_dir.mkdir()

        if engine == "libfuzzer":
            binary = engine_dir / "target"
            libstdcxx = find_libstdcxx_dir()
            link_args = ["-L", libstdcxx] if libstdcxx else []
            build_command = [
                    "clang", "-O1", "-g", "-fno-omit-frame-pointer",
                    "-fsanitize=fuzzer,address,undefined",
                    *link_args, str(HARNESS_ROOT / "libfuzzer.c"), str(run_source), "-o", str(binary),
                ]
            build_commands.append(build_command)
            build_logs.append(str(engine_dir / "build.log"))
            build_s, build_returncode, build_timeout = compile_command(build_command, args.cpu, engine_dir / "build.log")
            command = [
                str(binary), str(corpus), f"-max_total_time={args.budget}",
                f"-timeout={max(1, (args.timeout_ms + 999) // 1000)}", f"-max_len={args.max_len}",
                f"-seed={trial_seed}", "-use_value_profile=1", "-print_final_stats=1",
                f"-artifact_prefix={artifact_dir}/",
            ]
            measure = monitor(
                command, engine_dir / "run.log", cpu=args.cpu,
                timeout_s=args.budget + 15,
                crash_probe=lambda: libfuzzer_crash_artifact(artifact_dir),
            ) if build_returncode == 0 else {"returncode": build_returncode, "timed_out": False, "process_wall_s": 0.0, "first_crash_from_process_s": None, "ttfc_poll_resolution_ms": None, "log": None}
            native = parse_libfuzzer(Path(measure["log"])) if measure.get("log") else {"executions_native": None}
        elif engine == "afl++":
            binary = engine_dir / "target"
            cmp_binary = engine_dir / "target.cmplog"
            secondary_binary = cmp_binary
            common_compile = [
                "afl-clang-fast", "-O1", "-g", "-fsanitize=address,undefined",
                str(HARNESS_ROOT / "afl_persistent.c"), str(run_source), "-o",
            ]
            primary_build = [*common_compile, str(binary)]
            cmplog_build = [*common_compile, str(cmp_binary)]
            build_commands.extend([primary_build, cmplog_build])
            build_logs.extend([str(engine_dir / "build-primary.log"), str(engine_dir / "build-cmplog.log")])
            one, rc1, timeout1 = compile_command(
                primary_build, args.cpu, engine_dir / "build-primary.log",
                env={**os.environ, "AFL_QUIET": "1"},
            )
            two, rc2, timeout2 = compile_command(
                cmplog_build, args.cpu, engine_dir / "build-cmplog.log",
                env={**os.environ, "AFL_LLVM_CMPLOG": "1", "AFL_QUIET": "1"},
            )
            build_s, build_returncode = one + two, rc1 if rc1 != 0 else rc2
            build_timeout = timeout1 or timeout2
            output = engine_dir / "afl-output"
            command = [
                "afl-fuzz", "-i", str(corpus), "-o", str(output), "-V", str(args.budget),
                "-t", str(args.timeout_ms), "-m", "none", "-s", str(trial_seed),
                "-G", str(args.max_len), "-c", str(cmp_binary), "--", str(binary),
            ]
            measure = monitor(
                command, engine_dir / "run.log", cpu=args.cpu,
                timeout_s=args.budget + 15,
                crash_probe=lambda: afl_crash_artifact(output),
                env={**os.environ, "AFL_SKIP_CPUFREQ": "1", "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1", "AFL_NO_UI": "1", "AFL_QUIET": "1"},
            ) if build_returncode == 0 else {"returncode": build_returncode, "timed_out": False, "process_wall_s": 0.0, "first_crash_from_process_s": None, "ttfc_poll_resolution_ms": None, "log": None}
            native = parse_afl(output)
        else:
            work = engine_dir / "work"
            generated = work / "generated_harnesses"
            work.mkdir()
            generated.mkdir()
            seed_file = next(corpus.iterdir())
            generate_command = [str(args.bhf), "generate-harness", str(run_source), "--target", "target_one_input", "--output", str(generated)]
            build_commands.append(generate_command)
            build_logs.append(str(engine_dir / "build-generate.log"))
            generate_s, generate_rc, generate_timeout = compile_command(
                generate_command,
                args.cpu, engine_dir / "build-generate.log",
            )
            harnesses = sorted(path for path in generated.iterdir() if path.is_dir())
            harness_id = harnesses[0].name if harnesses else None
            builtin_dictionary = generated / (harness_id or "MISSING") / "dictionary.txt"
            binary = work / "build" / (harness_id or "MISSING") / "main"
            build_s = generate_s
            build_returncode = generate_rc
            build_timeout = generate_timeout
            if build_returncode == 0 and harness_id:
                native_build_command = [str(args.bhf), "build", str(work), "--harness", harness_id]
                build_commands.append(native_build_command)
                build_logs.append(str(engine_dir / "build-native.log"))
                native_build_s, native_build_rc, native_build_timeout = compile_command(
                    native_build_command,
                    args.cpu, engine_dir / "build-native.log",
                )
                build_s += native_build_s
                build_returncode = native_build_rc
                build_timeout = build_timeout or native_build_timeout
            else:
                native_build_s = None
                build_returncode = build_returncode or 1
            command = [
                str(args.bhf), "fuzz", str(work), "--harness", harness_id or "MISSING",
                "--engine", "builtin", "--time", f"{args.budget}s",
                "--seed-file", str(seed_file), "--rng-seed", str(trial_seed),
                "--max-len", str(args.max_len), "--len-control", "0",
                # BHF's CLI accepts whole seconds; round up to avoid imposing
                # a stricter timeout than the millisecond-granular AFL++ lane.
                "--timeout", f"{max(1, (args.timeout_ms + 999) // 1000)}s", "--workers", "1",
                "--sandbox", "none", "--print-final-stats",
            ]
            measure = monitor(
                command, engine_dir / "run.log", cpu=args.cpu,
                timeout_s=args.budget + 20,
                crash_probe=lambda: bhf_crash_artifact(work),
            ) if build_returncode == 0 else {"returncode": build_returncode, "timed_out": False, "process_wall_s": 0.0, "first_crash_from_process_s": None, "ttfc_poll_resolution_ms": None, "log": None}
            native = parse_bhf_fuzz(Path(measure["log"]), work) if measure.get("log") else {"executions_native": None, "finding_count": 0}

        artifact_path = Path(measure["crash_artifact"]) if measure.get("crash_artifact") else None
        replay_result = (
            replay_expected_crash(replay_binary, artifact_path) if artifact_path else None
        )
        observed_at = measure.get("first_crash_from_process_s")
        measure["artifact_within_budget"] = (
            observed_at is not None and observed_at <= args.budget
        ) if artifact_path else None
        measure["campaign_completed"] = (
            measure.get("returncode") == 0
            and not measure.get("timed_out")
            and native.get("executions_native") is not None
        )
        outcome = classify_outcome(build_returncode, measure, artifact_path, replay_result)
        solved = outcome == "confirmed_crash"
        ttfc_from_fuzz_start = measure.get("first_crash_from_process_s") if solved else None
        source_to_crash = None
        if solved:
            source_to_crash = build_s + measure["first_crash_from_process_s"]
        row = {
            **common,
            "outcome": outcome,
            "solved": solved,
            "ttfc_s": ttfc_from_fuzz_start,
            "ttfc_source_to_crash_s": source_to_crash,
            "right_censor_s": (
                measure.get("process_wall_s") if outcome == "censored_no_crash" else None
            ),
            "requested_fuzz_budget_s": args.budget,
            "build_wall_s": build_s,
            "build_returncode": build_returncode,
            "build_timed_out": build_timeout,
            "build_commands": build_commands,
            "engine_binary_sha256": sha256(binary) if binary.is_file() else None,
            "secondary_binary_sha256": sha256(secondary_binary)
            if secondary_binary and secondary_binary.is_file() else None,
            "engine_dictionary_path": str(builtin_dictionary)
            if builtin_dictionary and builtin_dictionary.is_file() else None,
            "engine_dictionary_sha256": sha256(builtin_dictionary)
            if builtin_dictionary and builtin_dictionary.is_file() else None,
            "engine_dictionary_tokens": sum(
                bool(line.strip()) and not line.lstrip().startswith("#")
                for line in builtin_dictionary.read_text(errors="replace").splitlines()
            ) if builtin_dictionary and builtin_dictionary.is_file() else 0,
            "build_logs": build_logs,
            "fuzz_process_wall_s": measure.get("process_wall_s"),
            "fuzz_start_after_process_s": 0.0,
            "returncode": measure.get("returncode"),
            "campaign_completed": measure.get("campaign_completed"),
            "native_exec_counter": native.get("executions_native"),
            "native_exec_counter_name": {"builtin": "BHF final-stats executions", "afl++": "AFL++ fuzzer_stats execs_done", "libfuzzer": "libFuzzer stat::number_of_executed_units"}[engine],
            "executions_comparable_across_tools": False,
            "native_metrics": native,
            "artifact_observed_wall_s": measure.get("first_crash_from_process_s"),
            "artifact_replay": replay_result,
            "replay_oracle_binary_sha256": replay_binary_sha,
            "replay_oracle_build_wall_s": replay_build_s,
            "replay_oracle_build_command": replay_build_command,
            "ttfc_observation": "poll-detected crash artifact, independently replayed under ASan; 10 ms poll resolution",
            "command": command,
            "run_log": measure.get("log"),
        }
        rows.append(row)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=[*CASES, "all"], default="magic_byte")
    parser.add_argument("--engines", nargs="+", choices=["builtin", "afl++", "libfuzzer"], default=["builtin", "afl++", "libfuzzer"])
    parser.add_argument("--trials", type=int, default=1)
    parser.add_argument("--budget", type=int, default=10, help="fuzzing wall seconds per trial")
    parser.add_argument("--timeout-ms", type=int, default=1000)
    parser.add_argument("--max-len", type=int, default=64)
    parser.add_argument("--cpu", default="0", help="CPU or CPU-list passed to taskset; use 'none' to disable")
    parser.add_argument("--bhf", type=Path, default=DEFAULT_BHF)
    parser.add_argument("--output", type=Path, required=True, help="machine-readable JSON evidence path")
    args = parser.parse_args()
    if args.cpu == "none":
        args.cpu = None
    if args.trials < 1 or args.budget < 1 or args.timeout_ms < 1000 or args.max_len < len(SEED):
        parser.error("trials, budget, timeout-ms must be positive; max-len must fit the 8-byte seed")
    if not args.bhf.is_file():
        parser.error(f"BHF executable not found: {args.bhf}; build it first with cargo build --release -p bhf")
    required = required_tools(args.engines, args.cpu)
    missing = sorted(tool for tool in required if shutil.which(tool) is None)
    if missing:
        parser.error(f"required local tools missing: {', '.join(missing)}")
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    cases = list(CASES) if args.case == "all" else [args.case]
    source_hashes = {
        case: sha256(FIXTURE_ROOT / case / f"{case}.c") for case in cases
    }
    records = []
    if output.exists():
        parser.error(f"output already exists; choose a new path to preserve prior evidence: {output}")
    run_root = output.parent / f"{output.stem}-runs"
    try:
        run_root.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        parser.error(f"run directory already exists; choose a new output stem: {run_root}")
    seed_sha = hashlib.sha256(SEED).hexdigest()
    for case in cases:
        for trial_index in range(args.trials):
            trial_seed = trial_index + 1
            trial_dir = run_root / case / f"trial-{trial_seed}"
            trial_dir.mkdir(parents=True, exist_ok=True)
            records.extend(one_trial(args, case, trial_seed, FIXTURE_ROOT / case / f"{case}.c", source_hashes[case], seed_sha, trial_dir))
    commit = command_output(["git", "rev-parse", "HEAD"])
    evidence = {
        "schema_version": 1,
        "experiment_id": output.stem,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": commit,
        "tool_versions": tool_versions(args.engines, args.bhf),
        "bhf_binary_sha256": sha256(args.bhf),
        "host": {
            "platform": platform.platform(),
            "cpu_model": cpu_model(),
            "logical_cpus_visible": os.cpu_count(),
            "affinity": args.cpu,
        },
        "protocol": {
            "trials_per_case_engine": args.trials,
            "budget_s": args.budget,
            "per_input_timeout_ms": args.timeout_ms,
            "max_len": args.max_len,
            "seed_hex": SEED.hex(),
            "seed_sha256": seed_sha,
            "seed_corpus_shared_bytes": "one 8-byte all-zero seed copied byte-for-byte to every engine/trial corpus",
            "instrumentation": {
                "builtin": "BHF generated C harness, builtin engine; explicit supplied corpus and RNG seed",
                "afl++": "afl-clang-fast persistent harness + CMPLOG binary (-c)",
                "libfuzzer": "clang libFuzzer harness + -use_value_profile=1",
            },
            "note": "AFL++ and libFuzzer use hand-written ABI adapters around the exact same target_one_input callback; BHF discovers and generates its wrapper. The base input corpus is byte-identical, but engine-native guidance differs by design: BHF can load its source-mined dictionary, AFL++ uses CMPLOG, and libFuzzer uses value profiling; paths/hashes/token counts and commands are recorded per lane. Per-input timeout is rounded up to whole seconds for BHF/libFuzzer because their interfaces are second-granular. Native execution counters are retained but not compared across engines because counter semantics differ. Candidate crashes are replayed through an independent ASan oracle and counted only for the fixture's expected stack-buffer-overflow. This short smoke runner is not a substitute for a statistically powered real-code benchmark.",
        },
        "source_hashes_sha256": source_hashes,
        "derived_source_hashes_sha256": {
            case: hashlib.sha256(fixture_source(case).encode()).hexdigest() for case in cases
        },
        "records": records,
    }
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "output": str(output),
        "records": len(records),
        "solved": sum(1 for record in records if record["solved"]),
        "censored": sum(1 for record in records if record["outcome"] == "censored_no_crash"),
        "build_failed": sum(1 for record in records if record["outcome"] == "build_failed"),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
