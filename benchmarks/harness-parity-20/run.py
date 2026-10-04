#!/usr/bin/env python3
"""Run the pinned, blind auto-vs-expert harness comparison.

This is Experiment 2 of issue #85 — auto-harness productivity. It measures the
end-to-end path from a clean upstream source checkout to a built, target-body-
executing harness and a comparable expert measurement, and it keeps every
attempted project visible (projects that fail to check out or build are counted,
not dropped). Two timings are recorded separately per project: ``setup_wall_s``
(clone/fetch/checkout of the pinned revision) and ``auto_wall_s`` (the single
``bhf auto`` invocation, which itself covers discovery, build recovery, harness
generation, and the fuzz-driven coverage pass). The coarse setup-vs-campaign
split is wall-clock; a finer build-vs-fuzz split is surfaced when ``bhf`` emits
it in ``result.json``.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_ARGS = {
    # The canonical SQLite repository is a generated-source tree: its checked-in
    # configure script must run before sqlite3.h/Makefile/compile commands exist.
    "sqlite": ["--unsafe-search-and-run-build-commands"],
}


def load_projects() -> list[dict[str, str]]:
    with (HERE / "projects.tsv").open(newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def command(argv: list[str], *, cwd: Path | None = None, env=None, log=None) -> int:
    with log.open("wb") if log else open(os.devnull, "wb") as output:
        return subprocess.run(
            argv, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT, check=False
        ).returncode


def ensure_source(
    project: dict[str, str], sources: Path, logs: Path
) -> tuple[Path, str | None]:
    root = sources / project["project"]
    log = logs / f"{project['project']}-clone.log"
    if not (root / ".git").is_dir():
        root.parent.mkdir(parents=True, exist_ok=True)
        rc = command(
            [
                "git",
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                project["url"],
                str(root),
            ],
            log=log,
        )
        if rc:
            return root, f"clone exited {rc}"
    if command(
        ["git", "fetch", "--depth", "1", "origin", project["commit"]], cwd=root, log=log
    ):
        return root, "fetch failed"
    if command(["git", "checkout", "--detach", project["commit"]], cwd=root, log=log):
        return root, "checkout failed"
    actual = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()
    return root, None if actual == project["commit"] else f"revision mismatch: {actual}"


def read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def run_one(
    project: dict[str, str], args, sources: Path, work_root: Path, logs: Path
) -> dict[str, object]:
    name = project["project"]
    setup_started = time.monotonic()
    source, source_error = ensure_source(project, sources, logs)
    setup_wall_s = round(time.monotonic() - setup_started, 3)
    row: dict[str, object] = {
        "project": name,
        "commit": project["commit"],
        "target": project["target"],
        "setup_wall_s": setup_wall_s,
        "auto_wall_s": None,
    }
    if source_error:
        # A checkout/setup failure is a real outcome, not a reason to drop the
        # project: it stays in the funnel denominator with its diagnostic.
        row.update(status="source_error", diagnostic=source_error)
        return row
    work = work_root / name
    expert = (HERE / project["expert"]).resolve()
    env = os.environ.copy()
    env["BHF_BLIND_EXPERT_HARNESSES"] = "1"
    env["BHF_EXPERT_HARNESS"] = str(expert)
    argv = [
        str(args.bhf),
        "auto",
        str(source),
        "--work-dir",
        str(work),
        "--target",
        project["target"],
        "--target-file",
        project["target_file"],
        "--max-targets",
        "1",
        "--max-attempts",
        "1",
        "--single-pass",
        "--per-target-time",
        str(args.seconds),
        "--jobs",
        "1",
        "--probe-build",
        "--comparison-progress",
        "--sanitizers",
        "none",
    ]
    argv.extend(PROJECT_ARGS.get(name, []))
    argv.append("--resume" if args.resume else "--fresh-discovery")
    auto_started = time.monotonic()
    rc = command(argv, env=env, log=logs / f"{name}.log")
    row["auto_wall_s"] = round(time.monotonic() - auto_started, 3)
    results = [
        value
        for path in work.glob("harnesses/*/result.json")
        if (value := read_json(path)) and value.get("name") == project["target"]
    ]
    if not results:
        row.update(
            status="no_result",
            exit_code=rc,
            diagnostic="target was not discovered or no attempt result was written",
        )
        return row
    result = results[0]
    # Surface a finer build-vs-fuzz split only if bhf recorded one; the coarse
    # setup-vs-auto wall split above is always available.
    outcome_timing = (result.get("outcome") or {}).get("timing") or {}
    row["build_recovery_s"] = result.get("build_seconds") or outcome_timing.get(
        "build_s"
    )
    row["campaign_s"] = result.get("fuzz_seconds") or outcome_timing.get("fuzz_s")
    harness = next(
        path.parent
        for path in work.glob("harnesses/*/result.json")
        if read_json(path) == result
    )
    oracle = read_json(harness / "expert-oracle.json")
    feedback = read_json(harness / "portfolio-feedback.json")
    outcome = result.get("outcome") or {}
    outcome_diagnostic = outcome.get("reason")
    if not outcome_diagnostic and outcome.get("last_errors"):
        outcome_diagnostic = json.dumps(outcome["last_errors"], separators=(",", ":"))
    row.update(
        status=outcome.get("outcome", "unknown"),
        exit_code=rc,
        harness_id=result.get("harness_id", harness.name),
        diagnostic=outcome_diagnostic
        or result.get("reason")
        or result.get("diagnostic")
        or "-",
        portfolio_lanes=len((feedback or {}).get("lanes", [])),
    )
    if oracle:
        row.update(
            verdict=oracle.get("verdict", ""),
            generated_lines=oracle.get("generated_covered_lines", 0),
            expert_lines=oracle.get("expert_covered_lines", 0),
            overlap_lines=oracle.get("overlap_lines", 0),
            expert_only_lines=oracle.get("expert_only_lines", 0),
            generated_only_lines=oracle.get("generated_only_lines", 0),
            ratio=oracle.get("generated_to_expert_ratio"),
            common_files=oracle.get("common_instrumented_files", 0),
        )
    else:
        row.update(
            verdict="not_measured",
            diagnostic=(
                row["diagnostic"]
                or "generated coverage or expert build/replay unavailable"
            ),
        )
    return row


MEASURED_EXCLUDED = (None, "", "not_measured", "expert_build_unavailable")
PARITY_VERDICTS = ("expert_parity", "generated_exceeds_expert")


def productivity_funnel(rows: list[dict[str, object]]) -> dict[str, int]:
    """Count every attempted project at each productivity stage.

    The denominator is always the number of projects attempted; checkout and
    build failures are a stage that drops out, never a project that is removed
    from the study. ``body_executed`` is the issue's "valid target-body
    execution" (non-zero generated coverage), and ``expert_comparable`` is a
    usable auto-vs-expert coverage measurement.
    """

    def entered(r: dict[str, object]) -> bool:
        gen = r.get("generated_lines")
        return isinstance(gen, (int, float)) and gen > 0

    measured = [r for r in rows if r.get("verdict") not in MEASURED_EXCLUDED]
    return {
        "attempted": len(rows),
        "checkout_ok": sum(1 for r in rows if r.get("status") != "source_error"),
        "produced_result": sum(
            1 for r in rows if r.get("status") not in ("source_error", "no_result")
        ),
        "body_executed": sum(1 for r in rows if entered(r)),
        "expert_comparable": len(measured),
        "parity_or_better": sum(
            1 for r in measured if r.get("verdict") in PARITY_VERDICTS
        ),
    }


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return round(ordered[mid], 3)
    return round((ordered[mid - 1] + ordered[mid]) / 2, 3)


def write_results(rows: list[dict[str, object]], output: Path) -> None:
    fields = [
        "project",
        "commit",
        "target",
        "status",
        "verdict",
        "generated_lines",
        "expert_lines",
        "overlap_lines",
        "expert_only_lines",
        "generated_only_lines",
        "ratio",
        "common_files",
        "portfolio_lanes",
        "setup_wall_s",
        "auto_wall_s",
        "build_recovery_s",
        "campaign_s",
        "exit_code",
        "diagnostic",
    ]
    with (output / "results.tsv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fields, delimiter="\t", extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    (output / "results.json").write_text(json.dumps(rows, indent=2) + "\n")

    funnel = productivity_funnel(rows)
    measured = [r for r in rows if r.get("verdict") not in MEASURED_EXCLUDED]
    ratios = [float(r["ratio"]) for r in measured if r.get("ratio") is not None]
    attempted = funnel["attempted"] or 1
    setup_times = [
        float(r["setup_wall_s"]) for r in rows if r.get("setup_wall_s") is not None
    ]
    auto_times = [
        float(r["auto_wall_s"]) for r in rows if r.get("auto_wall_s") is not None
    ]

    lines = [
        "# Auto-harness productivity (Experiment 2)",
        "",
        "## Funnel (denominator = projects attempted; failures stay visible)",
        "",
        "| Stage | Projects | Of attempted |",
        "|---|---:|---:|",
    ]
    for stage in (
        "attempted",
        "checkout_ok",
        "produced_result",
        "body_executed",
        "expert_comparable",
        "parity_or_better",
    ):
        count = funnel[stage]
        lines.append(
            f"| {stage.replace('_', ' ')} | {count} | {count / attempted:.0%} |"
        )
    lines += [
        "",
        "## Timing (setup separated from campaign)",
        "",
        f"- Median checkout/setup wall: {_median(setup_times)}s",
        f"- Median `bhf auto` wall (discovery + build recovery + fuzz): {_median(auto_times)}s",
        "- Per-project build-recovery/campaign split is in results.json when bhf emits it.",
        "",
        "## Coverage parity (over expert-comparable projects only)",
        "",
        f"- Expert parity or better: {funnel['parity_or_better']}/{funnel['expert_comparable'] or 0}",
        "- Mean generated/expert covered-line ratio: "
        + (f"{sum(ratios) / len(ratios):.3f}" if ratios else "n/a"),
        "",
        "## Per project",
        "",
        "| Project | Status | Verdict | Auto | Expert | Ratio | Expert-only | Setup s | Auto s |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        ratio = row.get("ratio")
        ratio_cell = f"{float(ratio):.3f}" if ratio is not None else "—"
        lines.append(
            f"| {row['project']} | {row.get('status', '—')} | {row.get('verdict', '—')} "
            f"| {row.get('generated_lines', '—')} | {row.get('expert_lines', '—')} "
            f"| {ratio_cell} | {row.get('expert_only_lines', '—')} "
            f"| {row.get('setup_wall_s', '—')} | {row.get('auto_wall_s', '—')} |"
        )
    (output / "summary.md").write_text("\n".join(lines) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--bhf", type=Path, default=HERE.parents[1] / "target/release/bhf"
    )
    parser.add_argument(
        "--output", type=Path, default=Path("/tmp/bhf-harness-parity-20")
    )
    parser.add_argument("--sources", type=Path)
    parser.add_argument("--seconds", type=int, default=15)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--only", action="append", default=[])
    args = parser.parse_args()
    args.bhf = args.bhf.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    sources = (args.sources or output / "sources").resolve()
    work = output / "work"
    logs = output / "logs"
    sources.mkdir(parents=True, exist_ok=True)
    work.mkdir(exist_ok=True)
    logs.mkdir(exist_ok=True)
    projects = [
        p for p in load_projects() if not args.only or p["project"] in args.only
    ]
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {
            pool.submit(run_one, p, args, sources, work, logs): p for p in projects
        }
        rows = []
        for future in as_completed(futures):
            row = future.result()
            rows.append(row)
            print(
                f"{row['project']}: {row.get('verdict', row.get('status'))}", flush=True
            )
    rows.sort(key=lambda row: row["project"])
    write_results(rows, output)
    write_metadata(args, projects, output)
    print(output / "summary.md")


def _command_output(argv: list[str]) -> str | None:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return (
        (result.stdout or result.stderr).strip().splitlines()[0]
        if (result.stdout or result.stderr).strip()
        else None
    )


def _sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_metadata(args, projects: list[dict[str, str]], output: Path) -> None:
    """Pin the exact binary, revision, host, and config behind this run."""
    metadata = {
        "experiment": "auto-harness-productivity",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": _command_output(["git", "rev-parse", "HEAD"]),
        "bhf_binary": str(args.bhf),
        "bhf_binary_sha256": _sha256(args.bhf),
        "bhf_version": _command_output([str(args.bhf), "--version"]),
        "host": {"platform": platform.platform(), "logical_cpus": os.cpu_count()},
        "config": {"seconds": args.seconds, "jobs": args.jobs, "resume": args.resume},
        "projects_pinned": {p["project"]: p["commit"] for p in projects},
    }
    (output / "run-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")


if __name__ == "__main__":
    main()
