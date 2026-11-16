#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Re-run, by name and at the commit the before run measured, every Go target
a results dir skipped as Go-1 (unsupported parameter type), and write each
target's outcome now. A capped sweep attempts the top-ranked targets, which
change with the ranking; this answers how many of the skipped targets a
current bhf drives.

  BHF_BIN=... go1_rerun.py results-0728 results-1116-go1
"""

import collections
import json
import shutil
import subprocess
import sys
from pathlib import Path

import build_corpus as bc
from go_resweep_compare import go_class
from run_sweep import BHF, WORK_ROOT, distil_run


def main() -> int:
    before, out_dir = Path(sys.argv[1]), Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    urls = {row["repo"]: row["url"] for row in bc.read_tsv(bc.CORPUS_TSV)}
    wanted: dict[str, tuple[dict, set]] = {}
    for path in sorted(before.glob("go__*.json")):
        row = json.loads(path.read_text())
        auto = (row.get("surfaces") or {}).get("auto") or {}
        for t in auto.get("targets") or []:
            if str(t.get("source", "")).endswith(".go") and go_class(t).startswith("Go-1"):
                wanted.setdefault(path.name, (row, set()))[1].add((t["source"], t["name"]))
    total = sum(len(targets) for _, targets in wanted.values())
    print(f"{total} Go-1 targets in {len(wanted)} projects", flush=True)
    for name, (row, targets) in sorted(wanted.items()):
        tree, _ = bc.clone_repo("go", row["repo"], urls[row["repo"]], sha=row["sha"])
        work = WORK_ROOT / f"go1-{path_slug(name)}"
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
        for source, function in sorted(targets):
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
