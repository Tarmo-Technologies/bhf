# SPDX-License-Identifier: Apache-2.0
"""Render a trade-study JSON (from trade_study.py) into a Markdown report.

Reads the raw rows + aggregated summary and emits per-target comparison tables
with repeated-trial distributions (median, IQR, range) and confidence intervals,
a cross-target rollup, an all-targets-pooled per-engine aggregate, an explicit
outcome-visibility table (how many trials failed/were censored/were unsupported),
and the honest caveats. Pure rendering — no measurement — so it can be re-run on
any completed or in-progress evidence file.

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
        "| Engine | Crash-find (Wilson 95%) | Distinct defects | Median TTFC (s) "
        "| Common cov edges | Native exec/s (not comparable) |",
        "|---|---|---|---|---|---|",
    ]
    for e in engines:
        s = block.get(e)
        if not s:
            continue
        out.append(
            f"| {ENGINE_LABEL.get(e, e)} | {prop(s['crash_find'])} "
            f"| {s['distinct_defect_signatures']} | {dist(s['ttfc_s'])} "
            f"| {dist(s['common_cov_edges'])} "
            f"| {dist(s['native_execs_per_s']['distribution'])} |"
        )
    return out


def render_outcomes(block: dict, engines: list[str]) -> list[str]:
    out = [
        "",
        "Outcome visibility (every trial accounted for):",
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    d = json.loads(args.input.read_text())
    rows = d["rows"]
    summary = d["summary"]
    if "per_target" not in summary:
        raise SystemExit(
            "input is a pre-v2 summary without distribution fields; re-run "
            "trade_study.py to regenerate it"
        )
    cfg = d["config"]
    engines = (
        cfg["engines"] if isinstance(cfg.get("engines"), list) else list(ENGINE_LABEL)
    )
    per_target = summary["per_target"]
    cases = list(per_target)

    out: list[str] = ["<!-- SPDX-License-Identifier: Apache-2.0 -->"]
    out.append("# Engine-quality trade study (Experiment 1) — distribution report\n")
    out.append(
        f"Generated: {d.get('generated_utc', '?')} · elapsed {d.get('elapsed_s', '?')}s · "
        f"{len(rows)} raw trial rows · commit `{(d.get('git_commit') or '?')[:12]}`.\n"
    )
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
        out.append(
            "**Target set:** the four checked-in controlled fixtures (no manifest).\n"
        )

    out.append("## Methodology (unchanged from the reviewed machinery)\n")
    out.append(
        "- One fixed harness per target drives EVERY engine; each engine's final "
        "corpus is merged through ONE shared libFuzzer-sancov binary so coverage "
        "edges are directly comparable, and each saved crash + final corpus is "
        "replayed through ONE independent ASan/UBSan oracle.\n"
        "- **Crash-find** is a Wilson 95% interval over VALID campaigns only; "
        "build-failed/timeout/incomplete/unsupported trials are shown separately so "
        "the effective sample size is never hidden.\n"
        "- **Distributions**: median with interquartile range `[q1–q3]`, and a "
        "percentile-bootstrap (or degenerate) CI. Native exec/s is per-engine only "
        "and is NOT comparable across engines (counter semantics differ).\n"
    )

    for case in cases:
        out.append(f"## Target: `{case}`\n")
        out.extend(render_engine_rows(per_target[case], engines))
        out.extend(render_outcomes(per_target[case], engines))
        out.append("")

    out.append("## All targets pooled — per engine\n")
    agg = summary.get("aggregate_by_engine", {})
    out.extend(render_engine_rows(agg, engines))
    out.extend(render_outcomes(agg, engines))
    out.append("")

    out.append("## Caveats\n")
    out.append(
        "- Crash-find CIs are only as meaningful as the trial count; a wide Wilson "
        "interval (small n) is not evidence of parity.\n"
        "- Controlled micro-fixtures isolate mutator reach/magic-value solving, not "
        "whole-program throughput on production code. Real-code targets require a "
        "pinned manifest; targets that need a full project build are shown as "
        "`unsupported` rows until a build recipe is supplied.\n"
        "- Native exec/s differs in definition per engine and is reported for "
        "context only.\n"
        "- No licensed-tool (e.g. Mayhem) comparison is included; none has been run.\n"
    )
    args.output.write_text("\n".join(out) + "\n")
    print(f"wrote {args.output} ({len(rows)} rows, {len(cases)} targets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
