#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Re-run, by name and at the commit the before run measured, every Go target
a results dir skipped as one class (Go-1, unsupported parameter type, unless
`--class` names another), and write each target's outcome now. A capped sweep
attempts the top-ranked targets, which change with the ranking; this answers
how many of the skipped targets a current bhf drives.

  BHF_BIN=... go1_rerun.py results-0728 results-1116-go1
  BHF_BIN=... go1_rerun.py results-0728 results-1116-go3 --class Go-3 --all-lanes

`--all-lanes` reads every lane's rows, not only the Go lane's: a project the
sweep chose for another language can hold Go code too.
"""

import argparse
import collections
import json
import shutil
import subprocess
import sys
from pathlib import Path

import build_corpus as bc
from go_resweep_compare import go_class
from run_sweep import BHF, WORK_ROOT, distil_run


def wanted_targets(
    before: Path, klass: str, all_lanes: bool
) -> dict[str, tuple[dict, collections.Counter]]:
    """Each row's Go targets of class `klass`, by row file: how many targets of
    each (source, name) it has. A row's `source` is a file's base name, so the
    same function in two dirs (`en/build.go`, `zh/build.go`) is one key twice."""
    wanted: dict[str, tuple[dict, collections.Counter]] = {}
    for path in sorted(before.glob("*.json" if all_lanes else "go__*.json")):
        row = json.loads(path.read_text())
        auto = (row.get("surfaces") or {}).get("auto") or {}
        for t in auto.get("targets") or []:
            if str(t.get("source", "")).endswith(".go") and go_class(t).startswith(klass):
                key = (t["source"], t["name"])
                wanted.setdefault(path.name, (row, collections.Counter()))[1][key] += 1
    return wanted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("before", type=Path)
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--class", dest="klass", default="Go-1")
    parser.add_argument("--all-lanes", action="store_true")
    args = parser.parse_args()
    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    urls = {row["repo"]: row["url"] for row in bc.read_tsv(bc.CORPUS_TSV)}
    wanted = wanted_targets(args.before, args.klass, args.all_lanes)
    total = sum(targets.total() for _, targets in wanted.values())
    print(f"{total} {args.klass} targets in {len(wanted)} projects", flush=True)
    for name, (row, targets) in sorted(wanted.items()):
        lane = row.get("lane") or "go"
        tree, _ = bc.clone_repo(lane, row["repo"], urls[row["repo"]], sha=row["sha"])
        work = WORK_ROOT / f"{args.klass.lower()}-{path_slug(name)}"
        shutil.rmtree(work, ignore_errors=True)
        cmd = [
            str(BHF), "auto", str(tree), "--work-dir", str(work), "--languages", "go",
            "--per-target-time", "3", "--max-repair-rounds", "4", "--jobs", "1",
            "--profile", "external-tools",
        ]  # fmt: skip
        for function in sorted({function for _, function in targets}):
            cmd += ["--target", function]
        try:
            rc = subprocess.run(cmd, capture_output=True, timeout=1800).returncode
        except subprocess.TimeoutExpired:
            rc = "timeout"
        got = distil_run(work)
        rows = []
        for (source, function), before_count in sorted(targets.items()):
            match = [
                t for t in got.get("targets", [])
                if t["source"] == source and t["name"] == function
            ]  # fmt: skip
            rows.append(
                {
                    "source": source,
                    "name": function,
                    "outcome": match[0]["outcome"] if match else "not_discovered",
                    "reason": match[0]["reason"] if match else None,
                    "class": go_class(match[0]) if match else "not discovered",
                    # Every target of this (source, name) now, and before.
                    "before": before_count,
                    "classes": [go_class(t) for t in match],
                }
            )
        result = {
            "repo": row["repo"],
            "sha": row["sha"],
            "rc": rc,
            "targets": rows,
            "summary": got.get("summary", {}),
            "findings_detail": got.get("findings_detail", []),
        }
        (out_dir / name).write_text(json.dumps(result, indent=1) + "\n")
        classes = collections.Counter(r["class"] for r in rows)
        print(name, rc, classes.most_common(), flush=True)
        shutil.rmtree(work, ignore_errors=True)
    return 0


def path_slug(name: str) -> str:
    return name.removesuffix(".json")


if __name__ == "__main__":
    sys.exit(main())
