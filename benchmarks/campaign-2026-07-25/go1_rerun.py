#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Re-run, by name and at the commit the before run measured, every target
of one language a results dir skipped as one class (Go-1, unsupported
parameter type, unless `--lang` and `--class` name another), and write each
target's outcome now. A capped sweep attempts the top-ranked targets, which
change with the ranking; this answers how many of the skipped targets a
current bhf drives.

  BHF_BIN=... go1_rerun.py results-0728 results-1116-go1
  BHF_BIN=... go1_rerun.py results-0728 results-1116-go3 --class Go-3 --all-lanes
  BHF_BIN=... go1_rerun.py results-0728 results-1116-java1 --lang java --class Java-1 \\
      --all-lanes --jobs 2
  BHF_BIN=... go1_rerun.py results-0728 results-1117-rust4 --lang rust --class Rust-4 \\
      --all-lanes --run-untrusted

`--all-lanes` reads every lane's rows, not only the language's own: a project
the sweep chose for another language can hold its code too. `--jobs` re-runs
that many projects at once, `--only` names the rows to re-run, and
`--run-untrusted` lets bhf run a project's own build.
"""

import argparse
import collections
import concurrent.futures
import json
import shutil
import subprocess
import sys
from pathlib import Path

import build_corpus as bc
from go_resweep_compare import go_class
from run_sweep import BHF, WORK_ROOT, distil_run


def java_class(target):
    """The expected-gaps.md class of a Java target's outcome."""
    outcome = target.get("outcome") or ""
    reason = target.get("reason") or ""
    if outcome == "built_and_fuzzed":
        return "built and fuzzed"
    if "has an unsupported type" in reason:
        return "Java-1 unsupported parameter type"
    if "no no-arg constructor" in reason:
        return "Java-2 instance method, no no-arg constructor"
    if outcome == "failed_build":
        return "failed build"
    return outcome or "other"


def rust_class(target):
    """The expected-gaps.md class of a Rust target's outcome."""
    outcome = target.get("outcome") or ""
    reason = target.get("reason") or ""
    if outcome == "built_and_fuzzed":
        return "built and fuzzed"
    if "has no bhf-native byte decoder" in reason:
        return "Rust-1 no byte decoder"
    if "static method of a non-in-crate trait impl" in reason:
        return "Rust-4 static method of an outside trait impl"
    if "trait impl on a generic type" in reason:
        return "Rust-4 static method of an impl on a generic type"
    if "takes no input" in reason:
        return "no input"
    if outcome == "consent_required":
        return "consent required"
    if outcome == "failed_build":
        return "failed build"
    return outcome or "other"


# Per language: its source suffix and its classifier.
LANGS = {
    "go": (".go", go_class),
    "java": (".java", java_class),
    "rust": (".rs", rust_class),
}


def wanted_targets(
    before: Path, klass: str, all_lanes: bool, lang: str = "go"
) -> dict[str, tuple[dict, collections.Counter]]:
    """Each row's `lang` targets of class `klass`, by row file: how many targets
    of each (source, name) it has. A row's `source` is a file's base name, so
    the same function in two dirs (`en/build.go`, `zh/build.go`) is one key
    twice."""
    suffix, classify = LANGS[lang]
    wanted: dict[str, tuple[dict, collections.Counter]] = {}
    for path in sorted(before.glob("*.json" if all_lanes else f"{lang}__*.json")):
        row = json.loads(path.read_text())
        auto = (row.get("surfaces") or {}).get("auto") or {}
        for t in auto.get("targets") or []:
            if str(t.get("source", "")).endswith(suffix) and classify(t).startswith(klass):
                key = (t["source"], t["name"])
                wanted.setdefault(path.name, (row, collections.Counter()))[1][key] += 1
    return wanted


def rerun(name, row, targets, args, url) -> str:
    """Re-run one project's targets, write its row, and return a summary line."""
    _, classify = LANGS[args.lang]
    lane = row.get("lane") or args.lang
    tree, _ = bc.clone_repo(lane, row["repo"], url, sha=row["sha"])
    work = WORK_ROOT / f"{args.klass.lower()}-{path_slug(name)}"
    shutil.rmtree(work, ignore_errors=True)
    cmd = [
        str(BHF), "auto", str(tree), "--work-dir", str(work), "--languages", args.lang,
        "--per-target-time", "3", "--max-repair-rounds", "4", "--jobs", "1",
        "--profile", "external-tools",
    ]  # fmt: skip
    if args.run_untrusted:
        cmd.append("--run-untrusted")
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
                "class": classify(match[0]) if match else "not discovered",
                # Every target of this (source, name) now, and before.
                "before": before_count,
                "classes": [classify(t) for t in match],
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
    (args.out_dir / name).write_text(json.dumps(result, indent=1) + "\n")
    shutil.rmtree(work, ignore_errors=True)
    classes = collections.Counter(r["class"] for r in rows)
    return f"{name} {rc} {classes.most_common()}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("before", type=Path)
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--lang", choices=sorted(LANGS), default="go")
    parser.add_argument("--class", dest="klass", default="Go-1")
    parser.add_argument("--all-lanes", action="store_true")
    parser.add_argument("--jobs", type=int, default=1)
    # Let bhf run the project's own build (Maven, Gradle), which the sweep
    # does not consent to.
    parser.add_argument("--run-untrusted", action="store_true")
    parser.add_argument("--only", action="append", default=[], help="a row file to re-run")
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    urls = {row["repo"]: row["url"] for row in bc.read_tsv(bc.CORPUS_TSV)}
    wanted = wanted_targets(args.before, args.klass, args.all_lanes, args.lang)
    if args.only:
        wanted = {name: value for name, value in wanted.items() if name in args.only}
    total = sum(targets.total() for _, targets in wanted.values())
    print(f"{total} {args.klass} targets in {len(wanted)} projects", flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [
            # A repo the lane check later replaced is no longer in corpus.tsv.
            pool.submit(
                rerun,
                name,
                row,
                targets,
                args,
                urls.get(row["repo"], f"https://github.com/{row['repo']}.git"),
            )
            for name, (row, targets) in sorted(wanted.items())
        ]
        for future in concurrent.futures.as_completed(futures):
            print(future.result(), flush=True)
    return 0


def path_slug(name: str) -> str:
    return name.removesuffix(".json")


if __name__ == "__main__":
    sys.exit(main())
