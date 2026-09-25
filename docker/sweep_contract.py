# SPDX-License-Identifier: Apache-2.0
"""Fail-closed contracts shared by the container sweep and corpus fetcher."""

import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys


def manifest_rows(path):
    rows, seen = [], set()
    for number, line in enumerate(Path(path).read_text().splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 6:
            raise ValueError(f"manifest line {number}: expected six TSV columns")
        lang, name, url, revision, subpath, extra = fields
        if not all(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", x) for x in (lang, name)):
            raise ValueError(f"manifest line {number}: unsafe project identifier")
        if (lang, name) in seen:
            raise ValueError(f"manifest line {number}: duplicate project")
        seen.add((lang, name))
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError(f"manifest line {number}: revision must be full lowercase SHA-1")
        if not url or url.startswith("-") or any(ord(c) < 32 for c in url):
            raise ValueError(f"manifest line {number}: invalid repository URL")
        if subpath not in ("", "-") and (PurePosixPath(subpath).is_absolute()
                or ".." in PurePosixPath(subpath).parts or "\\" in subpath):
            raise ValueError(f"manifest line {number}: unsafe source subpath")
        if any(ord(c) < 32 for c in subpath + extra):
            raise ValueError(f"manifest line {number}: control character")
        # Do not let extra arguments redirect/delete evidence or replace the
        # selected project. Flags without quotes are split identically by bash.
        if extra not in ("", "-"):
            if shlex.split(extra) != extra.split():
                raise ValueError(f"manifest line {number}: quoted flags are not supported")
            reserved = ("--work-dir", "--resume", "--clean", "--config", "--profile")
            if any(x.split("=", 1)[0] in reserved for x in extra.split()):
                raise ValueError(f"manifest line {number}: reserved sweep argument")
        rows.append(fields)
    if not rows:
        raise ValueError("manifest contains no projects")
    return rows


def check_checkout(root, revision, subpath="-"):
    root = Path(root)
    if root.is_symlink() or not (root / ".git").is_dir() or (root / ".git").is_symlink():
        raise ValueError(f"not an owned ordinary checkout: {root}")
    def git(*args):
        return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()
    if git("rev-parse", "HEAD") != revision:
        raise ValueError(f"checkout differs from pinned revision: {root}")
    changes = git("status", "--porcelain", "--untracked-files=all", "--ignored=matching")
    # Old fetchers wrote this marker. It is harmless only if it matches HEAD.
    changes = "\n".join(line for line in changes.splitlines()
                        if not (line == "?? .bhf-rev" and not (root / ".bhf-rev").is_symlink()
                                and (root / ".bhf-rev").read_text().strip() == revision))
    if changes:
        raise ValueError(f"checkout contains modified/untracked/ignored inputs: {root}")
    source = root if subpath in ("", "-") else root / subpath
    if not source.is_dir() or not source.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"source path missing or escapes checkout: {source}")


def number(value):
    if type(value) is not int or value < 0:
        raise ValueError("invalid nonnegative report counter")
    return value


def report_stats(path):
    report = json.loads(Path(path).read_text())
    if report.get("schema_version") != 1 or report.get("partial") is not False:
        raise ValueError("unsupported or incomplete run report")
    real, executions, edges, findings, stub, unentered = 0, 0, 0, 0, 0, 0
    for target in report["targets"]:
        outcome = target["outcome"]
        if outcome["outcome"] != "built_and_fuzzed":
            continue
        # Missing stub metadata is not positive evidence of real execution.
        if target.get("stub_execution", {}).get("stub_only") is not False:
            stub += 1
            continue
        passes = [p for p in outcome["passes"] if p.get("target_entry_observed") is True
                  and number(p["executions"]) > 0]
        if not passes:
            unentered += 1
            continue
        real += 1
        executions += sum(number(p["executions"]) for p in passes)
        # This is a sum of per-target peak edge counts, NOT a global union.
        edges += max(number(p["coverage_edges"]) for p in passes)
        findings += sum(len(p["findings"]) for p in passes)
    status = "PASS" if real else "STUB-ONLY" if stub else "NOT-ENTERED" if unentered else "NO-TARGETS"
    return status, real, executions, edges, findings


def main():
    action, *args = sys.argv[1:]
    if action in ("manifest", "rows"):
        rows = manifest_rows(args[0])
        selected = os.environ.get("BHF_LANGS", "").split()
        available = {r[0] for r in rows}
        if set(selected) - available:
            raise ValueError("BHF_LANGS contains unknown/unselected languages")
        if action == "rows":
            for row in rows:
                print("\t".join(value or "-" for value in row))
    elif action == "checkout":
        check_checkout(*args)
    elif action == "stats":
        print("\t".join(map(str, report_stats(args[0]))))
    elif action == "prepare":
        root = Path(args[0])
        root.mkdir(parents=True, exist_ok=True)
        # Atomic reservation serializes concurrent starts; never remove this
        # marker or old artifacts automatically, even after an interrupted run.
        (root / ".bhf-sweep-lock").mkdir()
        if any(p.name != ".bhf-sweep-lock" for p in root.iterdir()):
            raise ValueError("results directory is nonempty; select a fresh directory")
    else:
        raise ValueError("unknown contract operation")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"sweep contract: {error}", file=sys.stderr)
        sys.exit(2)
