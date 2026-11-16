#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Summarize cargo-nextest JUnit reports in the job summary.

Lists every FLAKY test (failed, then passed on a retry), every test killed by
the profile's slow-timeout (TIMEOUT) and every other failure, with counts, in
$GITHUB_STEP_SUMMARY (stdout when it is unset), and prints a warning
annotation for each flaky test so a flake is tracked rather than hidden by
its retry. A report path that does not exist is named in the summary (its
run did not get as far as writing one); the script fails only when none of
them exists. The run's own exit status is nextest's: this only reports.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import sys
import xml.etree.ElementTree as ElementTree

ROWS = 100
TIMEOUT = "test timeout"


@dataclass
class Outcome:
    test: str
    status: str  # passed, flaky, failed, timeout, skipped
    tries: int
    detail: str


def first_line(text: str | None) -> str:
    line = (text or "").strip().splitlines()
    return line[0][:200].replace("|", "\\|") if line else ""


def outcome(case: ElementTree.Element) -> Outcome:
    test = f"{case.get('classname')}::{case.get('name')}"
    if case.find("skipped") is not None:
        return Outcome(test, "skipped", 0, "")
    final = next((child for child in case if child.tag in ("failure", "error")), None)
    if final is not None:
        reruns = [child for child in case if child.tag in ("rerunFailure", "rerunError")]
        tries = 1 + len(reruns)
        if final.get("type") == TIMEOUT:
            every = all(child.get("type") == TIMEOUT for child in reruns)
            detail = f"killed on every try ({tries})" if every else f"killed on the last of {tries} tries"
            return Outcome(test, "timeout", tries, detail)
        message = first_line(final.get("message") or final.text)
        return Outcome(test, "failed", tries, f"failed on every try ({tries})" + (f": {message}" if message else ""))
    flakes = [child for child in case if child.tag in ("flakyFailure", "flakyError")]
    if flakes:
        tries = len(flakes) + 1
        return Outcome(test, "flaky", tries, f"passed on try {tries} of {tries}")
    return Outcome(test, "passed", 1, "")


def report(path: Path) -> tuple[str, list[Outcome]]:
    if not path.is_file():
        return f"- no report at `{path}`: that run did not write one\n", []
    outcomes = [outcome(case) for case in ElementTree.parse(path).iter("testcase")]
    count = {status: sum(o.status == status for o in outcomes)
             for status in ("passed", "flaky", "failed", "timeout", "skipped")}
    lines = [f"- `{path}`: {len(outcomes)} tests: {count['passed']} passed, {count['flaky']} flaky, "
             f"{count['failed'] + count['timeout']} failed ({count['timeout']} timed out), {count['skipped']} skipped"]
    return "\n".join(lines) + "\n", outcomes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--title", default="Test report")
    parser.add_argument("reports", nargs="+", type=Path, help="nextest JUnit files (junit.xml)")
    args = parser.parse_args(argv)
    if not any(path.is_file() for path in args.reports):
        print("no JUnit report at " + ", ".join(map(str, args.reports)), file=sys.stderr)
        return 1
    heads, outcomes = [], []
    for path in args.reports:
        head, found = report(path)
        heads.append(head)
        outcomes.extend(found)
    flagged = [o for o in outcomes if o.status in ("flaky", "timeout", "failed")]
    order = {"flaky": 0, "timeout": 1, "failed": 2}
    flagged.sort(key=lambda o: (order[o.status], o.test))
    text = [f"### {args.title}\n", *heads]
    if flagged:
        text.append("\n| Result | Test | Detail |\n| --- | --- | --- |\n")
        for o in flagged[:ROWS]:
            label = "FAIL" if o.status == "failed" else o.status.upper()
            text.append(f"| {label} | `{o.test}` | {o.detail} |\n")
        if len(flagged) > ROWS:
            text.append(f"\n... and {len(flagged) - ROWS} more in the JUnit report.\n")
    body = "".join(text) + "\n"
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as output:
            output.write(body)
    else:
        sys.stdout.write(body)
    for o in flagged:
        if o.status == "flaky":
            print(f"::warning title=Flaky test::{o.test} {o.detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
