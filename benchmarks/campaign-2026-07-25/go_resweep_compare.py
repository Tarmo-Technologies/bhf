#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare the Go lane's outcomes between two sweep result directories.

  go_resweep_compare.py results-0728 results-<date>

Counts only targets in `.go` sources, per expected-gaps.md's Go classes.
"""
import collections
import glob
import json
import os
import sys


def go_class(target):
    outcome = target.get("outcome") or ""
    reason = target.get("reason") or ""
    if outcome == "built_and_fuzzed":
        return "built and fuzzed"
    if "unsupported Go parameter type" in reason:
        return "Go-1 undrivable parameter type"
    if "needs a receiver value" in reason:
        return "Go-2 method needs a receiver"
    if "is not nameable from the harness package" in reason:
        return "Go-2 receiver type unexported or generic"
    if "not inside a Go module" in reason:
        return "Go-3 no go.mod"
    if "requires go >=" in reason:
        return "Go-4 requires a newer go (environment)"
    if "missing module" in reason:
        return "missing module (dependency)"
    if outcome == "failed_build":
        return "failed build"
    return outcome or "other"


def summarize(directory):
    classes = collections.Counter()
    projects = findings = attempted = 0
    for path in sorted(glob.glob(os.path.join(directory, "go__*.json"))):
        row = json.load(open(path))
        auto = (row.get("surfaces") or {}).get("auto") or {}
        if not auto:
            continue
        projects += 1
        findings += (auto.get("summary") or {}).get("findings", 0) or 0
        for target in auto.get("targets") or []:
            if not str(target.get("source", "")).endswith(".go"):
                continue
            attempted += 1
            classes[go_class(target)] += 1
    return projects, attempted, findings, classes


def main():
    before, after = sys.argv[1], sys.argv[2]
    b = summarize(before)
    a = summarize(after)
    print(f"| | {os.path.basename(before)} | {os.path.basename(after)} |")
    print("|---|---:|---:|")
    print(f"| projects measured | {b[0]} | {a[0]} |")
    print(f"| Go targets attempted | {b[1]} | {a[1]} |")
    print(f"| findings (all lanes) | {b[2]} | {a[2]} |")
    for name in sorted(set(b[3]) | set(a[3]), key=lambda n: (-b[3][n] - a[3][n], n)):
        print(f"| {name} | {b[3][name]} | {a[3][name]} |")


if __name__ == "__main__":
    main()
