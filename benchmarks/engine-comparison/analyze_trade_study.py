# SPDX-License-Identifier: Apache-2.0
"""Render a trade-study JSON (from trade_study.py) into a Markdown report.

Reads the raw rows and the aggregated summary and writes per-target tables with
repeated-trial distributions (median, interquartile range) and confidence
intervals, an all-targets-pooled table per engine, and each table's outcome
breakdown (how many trials failed, were censored or were unsupported). It only
renders, so it can be re-run on a completed or an in-progress evidence file.

A new report gets the methodology and scope prose below. The results go
between two markers, and re-rendering into an existing report replaces only
what is between them, so prose edited after the first render stays. A report
without the markers was written or rewritten by hand; it is left as it is.

Supports the v2 summary shape (``{per_target, aggregate_by_engine, ...}``) with
distribution/CI fields; a v1 file predates this script's rewrite and should be
re-rendered by re-running the study.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ENGINE_LABEL = {
    "bhf": "BHF (builtin)",
    "aflpp": "AFL++ 5.03c",
    "libfuzzer": "libFuzzer",
    "honggfuzz": "honggfuzz",
}
ENGINE_NAME = {"bhf": "BHF", "aflpp": "AFL++", "libfuzzer": "libFuzzer", "honggfuzz": "honggfuzz"}
# The generated results sit between these markers; a re-render replaces only them.
BEGIN = "<!-- analyze_trade_study.py: generated results begin -->"
END = "<!-- analyze_trade_study.py: generated results end -->"

METHODOLOGY = """## Methodology

- **Targets:** each target has one fixed harness, and every engine drives the same source.
- **Independent crash oracle:** each engine's saved crash artifacts and its final corpus are replayed through one ASan+UBSan binary the engines never see; only oracle-confirmed crashes count.
- **Engine-neutral coverage:** every engine's final corpus is merged through one shared libFuzzer-sancov binary, so `edges` use identical instrumentation and are directly comparable across engines.
- **Crash-find rate:** a Wilson 95% interval over valid campaigns only. Build failures, supervisor timeouts, incomplete and unsupported trials are counted in each table's outcome breakdown, so every rate shows the sample behind it.
- **Distributions:** the median, the interquartile range `[q1–q3]` and a percentile-bootstrap confidence interval, which is left out when every trial measured the same value.
- **Setup and build time are separate from campaign time.** Native exec/s uses each engine's own definition of an execution, so compare it within one engine only.
"""

SCOPE = """## Scope

- A crash-find interval is only as narrow as the trial count allows; a wide Wilson interval is not evidence of parity.
- Controlled micro-fixtures measure mutator reach and magic-value solving, not throughput on production code. Real-code targets need a pinned manifest, and a target that needs a full project build shows as `unsupported` until it has a build recipe.
- Native exec/s uses each engine's own definition and is reported for context.
- No licensed engine, Mayhem for example, was run.
"""


def dist(d: dict | None, suffix: str = "") -> str:
    """Render a Distribution dict as 'median [q1–q3] (CI lo–hi, n=N)'."""
    if not d or d.get("n", 0) == 0 or d.get("median") is None:
        return "—"
    median = f"{d['median']:g}{suffix}"
    iqr = f"[{d['q1']:g}–{d['q3']:g}]"
    ci = ""
    if d.get("ci_low") is not None and d.get("ci_method") != "degenerate":
        ci = f" (CI {d['ci_low']:g}–{d['ci_high']:g})"
    return f"{median} {iqr}{ci} n={d['n']}"


def prop(d: dict | None) -> str:
    """Render a Proportion dict as 'rate% (k/n, CI lo–hi%)'."""
    if not d or d.get("trials", 0) == 0 or d.get("rate") is None:
        return "— (0 valid)"
    out = f"{d['rate']:.0%} ({d['successes']}/{d['trials']}"
    if d.get("ci_low") is not None:
        out += f", CI {d['ci_low']:.0%}–{d['ci_high']:.0%}"
    return out + ")"


def outcome_cell(outcomes: dict) -> str:
    parts = [f"{k.replace('_', ' ')}: {v}" for k, v in outcomes.items() if v]
    return ", ".join(parts) if parts else "—"


def render_engine_rows(block: dict, engines: list[str]) -> list[str]:
    out = [
        "| Engine | In-budget crash-find (Wilson 95%) | Normalized diagnostic "
        "variants (a grouping aid, not a defect count) | Median in-budget TTFC (s) "
        "| Common cov edges | Native exec/s (per engine) |",
        "|---|---|---|---|---|---|",
    ]
    for e in engines:
        s = block.get(e)
        if not s:
            continue
        out.append(
            f"| {ENGINE_LABEL.get(e, e)} | {prop(s['crash_find'])} "
            f"| {s['normalized_diagnostic_variants']} | {dist(s['ttfc_s'])} "
            f"| {dist(s['common_cov_edges'])} "
            f"| {dist(s['native_execs_per_s']['distribution'])} |"
        )
    return out


def render_outcomes(block: dict, engines: list[str]) -> list[str]:
    out = [
        "",
        "Every trial's outcome:",
        "",
        "| Engine | Trials | Valid campaigns | Outcome breakdown |",
        "|---|---|---|---|",
    ]
    for e in engines:
        s = block.get(e)
        if not s:
            continue
        out.append(
            f"| {ENGINE_LABEL.get(e, e)} | {s['trials']} | {s['valid_campaigns']} "
            f"| {outcome_cell(s['outcomes'])} |"
        )
    return out


def render_results(d: dict) -> list[str]:
    """The generated part of a report: the run's metadata and every table."""
    rows = d["rows"]
    summary = d["summary"]
    cfg = d["config"]
    engines = (
        cfg["engines"] if isinstance(cfg.get("engines"), list) else list(ENGINE_LABEL)
    )
    out = [
        f"Generated: {d.get('generated_utc', '?')} · elapsed {d.get('elapsed_s', '?')}s · "
        f"{len(rows)} raw trial rows · commit `{(d.get('git_commit') or '?')[:12]}`.\n"
    ]
    host = d.get("host", {})
    out.append(
        f"**Host:** {host.get('cpu', '?')} ({host.get('nproc', '?')} cores; each "
        f"campaign pinned to one core via taskset).\n"
    )
    out.append(
        f"**Budget:** {cfg.get('budget')}s wall per trial (per-target overrides "
        f"allowed) · **trials:** {cfg.get('trials')} per (engine,target) · "
        f"**max_len:** {cfg.get('max_len')}.\n"
    )
    manifest = d.get("manifest", {})
    if manifest.get("path"):
        out.append(
            f"**Target manifest:** `{manifest['path']}` (sha256 `{(manifest.get('sha256') or '?')[:16]}`)\n"
        )
    else:
        out.append("**Target set:** the checked-in controlled fixtures (no manifest).\n")

    per_target = summary["per_target"]
    for case in per_target:
        out.append(f"## Target: `{case}`\n")
        out.extend(render_engine_rows(per_target[case], engines))
        out.extend(render_outcomes(per_target[case], engines))
        out.append("")

    out.append("## All targets pooled, per engine\n")
    agg = summary.get("aggregate_by_engine", {})
    out.extend(render_engine_rows(agg, engines))
    out.extend(render_outcomes(agg, engines))
    return out


def render_report(d: dict, results: str) -> str:
    """A new report: the title, the methodology, the results and the scope."""
    cfg = d["config"]
    engines = cfg["engines"] if isinstance(cfg.get("engines"), list) else list(ENGINE_LABEL)
    names = [ENGINE_NAME.get(e, e) for e in engines]
    title = names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]
    return (
        "<!-- SPDX-License-Identifier: Apache-2.0 -->\n"
        f"# Multi-engine fuzzing trade study: {title}\n\n"
        f"{METHODOLOGY}\n{BEGIN}\n{results}\n{END}\n\n{SCOPE}"
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=Path, required=True)
    ap.add_argument(
        "--output",
        type=Path,
        required=True,
        help="report to write; an existing one gets only its generated results replaced",
    )
    args = ap.parse_args()
    d = json.loads(args.input.read_text())
    if "per_target" not in d["summary"]:
        raise SystemExit(
            "input is a pre-v2 summary without distribution fields; re-run "
            "trade_study.py to regenerate it"
        )
    results = "\n".join(render_results(d)).rstrip("\n")
    if args.output.exists():
        text = args.output.read_text()
        if text.count(BEGIN) != 1 or text.count(END) != 1 or text.index(BEGIN) > text.index(END):
            raise SystemExit(
                f"{args.output} has no generated results section (between {BEGIN} and "
                f"{END}): it was written by hand, so it is left as it is. Pass a new --output."
            )
        before, rest = text.split(BEGIN, 1)
        after = rest.split(END, 1)[1]
        args.output.write_text(f"{before}{BEGIN}\n{results}\n{END}{after}")
    else:
        args.output.write_text(render_report(d, results))
    print(
        f"wrote {args.output} ({len(d['rows'])} rows, {len(d['summary']['per_target'])} targets)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
