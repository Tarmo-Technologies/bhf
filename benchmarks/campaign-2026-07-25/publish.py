#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fill the results section of docs/site/sweep-500.md from the sweep rows.

Keeping this a script rather than hand-edited prose means the published
numbers cannot drift from `results/`: re-run the sweep, re-run this, and the
page is current. The section counts the repositories pinned in `corpus.tsv`
only; a results directory also holds rows for repositories the lane check
later replaced from the pool. Its wording is the page's reviewed wording, so
re-running this over the same rows leaves the page unchanged.

Usage:
  publish.py [--results results] [--corpus corpus.tsv] [--page ../../docs/site/sweep-500.md]
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
MARKER = "## Results"
# The generated region ENDS here. Everything from this heading on is written by
# hand — the interpretation of the blocker table and the honest-limits section —
# so the end marker has to be the first hand-written heading after the tables,
# not the last one on the page. Pointing it at "## Honest limits" silently
# deleted the interpretation section on the next publish.
NEXT_SECTION = "## Reading the blocker table"

STATUSES = [
    "built_and_fuzzed",
    "fuzzed_stub_only",
    "failed_build",
    "unsupported_params",
    "report_only",
    "unrecoverable_link",
    "unrecoverable_runtime",
    "skipped",
]

# The blocker table ranks why bhf could not drive a discovered target, which
# the hand-written "Reading the blocker table" interprets (packages that are
# not installed, and bhf's own limits). A build failure (`failed_build`) is
# the project's build stopping; that reading does not cover it, so it stays
# out of the table, and the Attempted column still counts it.
TABLE_LEAVES_OUT = {"failed_build"}

LANE_NAMES = {
    "c": "C", "cpp": "C++", "rust": "Rust", "go": "Go", "python": "Python",
    "java": "Java", "js": "JavaScript", "ts": "TypeScript", "csharp": "C#",
    "php": "PHP", "ruby": "Ruby", "perl": "Perl", "ada": "Ada", "lua": "Lua",
    "fortran": "Fortran", "cobol": "COBOL",
}


def load(results: Path) -> list[dict]:
    rows = []
    for path in sorted(results.glob("*.json")):
        try:
            rows.append(json.loads(path.read_text()))
        except json.JSONDecodeError:
            continue
    return rows


def load_corpus(corpus: Path) -> set[tuple[str, str]]:
    """The (lane, repository) pairs pinned in `corpus.tsv`."""
    pinned = set()
    for line in corpus.read_text().splitlines():
        if line.startswith("#") or not line.strip():
            continue
        lane, repo = line.split("\t")[:2]
        pinned.add((lane, repo))
    return pinned


def summarize(rows: list[dict]) -> tuple[dict, dict]:
    per_lane: dict[str, dict] = defaultdict(
        lambda: {
            "projects": 0, "measured": 0, "discovered": 0, "attempted": 0,
            "findings": 0, "sloc": 0, "no_targets": 0, "majority": 0,
            **{s: 0 for s in STATUSES},
        }
    )
    totals = Counter()
    for row in rows:
        lane = row.get("lane", "?")
        bucket = per_lane[lane]
        bucket["projects"] += 1
        surfaces = row.get("surfaces") or {}
        sloc = (surfaces.get("sloc") or {}).get("sloc_total") or 0
        bucket["sloc"] += sloc
        summary = (surfaces.get("auto") or {}).get("summary") or {}
        if not summary:
            continue
        bucket["measured"] += 1
        bucket["discovered"] += summary.get("discovered_total", 0)
        bucket["findings"] += summary.get("findings", 0)
        attempted = 0
        for status in STATUSES:
            n = summary.get(status, 0) or 0
            bucket[status] += n
            attempted += n
        bucket["attempted"] += attempted
        if attempted == 0:
            bucket["no_targets"] += 1
        elif summary.get("built_and_fuzzed", 0) * 2 > attempted:
            bucket["majority"] += 1
    for bucket in per_lane.values():
        for key, value in bucket.items():
            totals[key] += value
    return dict(per_lane), dict(totals)


def render(per_lane: dict, totals: dict, rows: list[dict], pinned: int) -> str:
    """The results section for the pinned `rows`, `pinned` the corpus size."""
    # One vendored or generated monster can dominate a corpus-wide line count,
    # so name it rather than letting it quietly carry the headline.
    biggest = max(
        (
            ((row.get("surfaces") or {}).get("sloc") or {}).get("sloc_total") or 0,
            row.get("repo", "?"),
        )
        for row in rows
    )
    lines = [
        "",
        f"{totals['measured']} projects measured out of {pinned} pinned, "
        f"{totals['sloc']:,} lines of code, "
        f"{totals['discovered']:,} fuzzable targets discovered, "
        "with no harness written by hand.",
        "",
        "`Projects` counts pinned repositories that produced a result row; `Measured` counts "
        "those that produced an `auto` run to roll up. `Rate` is fuzzed over attempted.",
        "",
        "| Language | Projects | Measured | SLOC | Targets found | Attempted | Fuzzed | Rate | Findings |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for lane in sorted(per_lane, key=lambda k: -per_lane[k]["discovered"]):
        b = per_lane[lane]
        rate = f"{b['built_and_fuzzed'] / b['attempted'] * 100:.0f}%" if b["attempted"] else "—"
        lines.append(
            f"| {LANE_NAMES.get(lane, lane)} | {b['projects']} | {b['measured']} | {b['sloc']:,} | "
            f"{b['discovered']:,} | {b['attempted']} | {b['built_and_fuzzed']} | "
            f"{rate} | {b['findings']} |"
        )
    rate = (
        f"{totals['built_and_fuzzed'] / totals['attempted'] * 100:.1f}%"
        if totals["attempted"]
        else "—"
    )
    lines.append(
        f"| **All {len(per_lane)}** | **{totals['projects']}** | **{totals['measured']}** | "
        f"**{totals['sloc']:,}** | **{totals['discovered']:,}** | **{totals['attempted']}** | "
        f"**{totals['built_and_fuzzed']}** | **{rate}** | **{totals['findings']}** |"
    )
    if totals["sloc"] and biggest[0] > totals["sloc"] * 0.1:
        share = biggest[0] / totals["sloc"] * 100
        lines += [
            "",
            f"One repository, `{biggest[1]}`, contributes {biggest[0]:,} of those lines "
            f"({share:.0f}% of the corpus) at roughly 46,000 lines per file: generated "
            f"or amalgamated content rather than written code. Without it the corpus is "
            f"{totals['sloc'] - biggest[0]:,} lines, which is the figure to reason about; "
            f"it is left in because the corpus is star-ranked, not curated.",
        ]

    surfaces = [
        surface
        for row in rows
        for surface in (row.get("surfaces") or {}).values()
        if isinstance(surface, dict)
    ]
    panics = sum(1 for surface in surfaces if surface.get("panic"))
    timeouts = sum(1 for surface in surfaces if surface.get("timed_out"))
    lines += [
        "",
        "### Robustness",
        "",
        f"Across the {totals['projects']} pinned projects and {len(surfaces):,} surface "
        f"invocations: **{panics} panics**, **{timeouts} timeouts**.",
        "",
        "### What blocked the rest",
        "",
    ]
    blockers: Counter = Counter()
    for row in rows:
        auto = (row.get("surfaces") or {}).get("auto") or {}
        for entry in auto.get("blockers") or []:
            if entry.get("category") in TABLE_LEAVES_OUT:
                continue
            blockers[(entry.get("language", "?"), (entry.get("detail") or "")[:70])] += entry.get(
                "count", 0
            )
    lines += ["| Targets | Language | Cause |", "|---:|---|---|"]
    for (lang, detail), count in blockers.most_common(12):
        lines.append(f"| {count} | {lang} | {detail} |")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, default=HERE / "results")
    ap.add_argument("--corpus", type=Path, default=HERE / "corpus.tsv")
    ap.add_argument("--page", type=Path, default=HERE.parent.parent / "docs/site/sweep-500.md")
    args = ap.parse_args()

    pinned = load_corpus(args.corpus)
    rows = [row for row in load(args.results) if (row.get("lane"), row.get("repo")) in pinned]
    if not rows:
        print("no results for the pinned corpus yet")
        return
    per_lane, totals = summarize(rows)
    section = render(per_lane, totals, rows, len(pinned))

    text = args.page.read_text()
    start = text.index(MARKER) + len(MARKER)
    end = text.index(NEXT_SECTION)
    args.page.write_text(text[:start] + "\n" + section + "\n" + text[end:])
    print(f"filled {args.page} from {len(rows)} project(s)")


if __name__ == "__main__":
    main()
