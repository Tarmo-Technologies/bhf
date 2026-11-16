#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail when a test printed a skip line that the allowlist does not allow.

The bhf integration tests return early, and pass, when a tool they need is
missing, printing a line that starts with `skip`, `skipping`, `skipped` or
`SKIP`. In the nightly, which installs the lanes' toolchains, such a line
means a lane that ran nothing. This reads the captured stdout and stderr of
each test's final try from nextest JUnit reports (the `ci` profile keeps
passing tests' output), and fails on every skip line that no entry of the
allowlist allows.

An allowlist entry is one line, `TEST_GLOB LINE_GLOB`: fnmatch globs matched,
ignoring case, against `<binary id>::<test name>` and the stripped skip line
(LINE_GLOB may contain spaces). `#` starts a comment line. Exit status: 0
when every skip line is allowed, 1 when one is not or no report exists, 2
for a malformed allowlist.
"""
from __future__ import annotations

import argparse
from collections import Counter
from fnmatch import fnmatchcase
import os
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ElementTree

SKIP_LINE = re.compile(r"^\s*skip(?:ping|ped)?\b", re.IGNORECASE)
ROWS = 200


class AllowlistError(ValueError):
    pass


def load_allowlist(path: Path) -> list[tuple[str, str, int]]:
    """The (test glob, line glob, line number) entries of `path`, lowercased."""
    entries = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split(None, 1)
        if len(fields) != 2:
            raise AllowlistError(f"{path}:{number}: expected `TEST_GLOB LINE_GLOB`, got {raw!r}")
        entries.append((fields[0].lower(), fields[1].strip().lower(), number))
    return entries


def allowing(entries: list[tuple[str, str, int]], test: str, line: str) -> int | None:
    """The line number of the first entry that allows `line` from `test`."""
    test, line = test.lower(), line.strip().lower()
    for test_glob, line_glob, number in entries:
        if fnmatchcase(test, test_glob) and fnmatchcase(line, line_glob):
            return number
    return None


def allowed(entries: list[tuple[str, str, int]], test: str, line: str) -> bool:
    return allowing(entries, test, line) is not None


def skip_lines(report: Path) -> list[tuple[str, str]]:
    """(test, line) for every skip line in `report`'s tests' final tries."""
    found = []
    for case in ElementTree.parse(report).iter("testcase"):
        test = f"{case.get('classname')}::{case.get('name')}"
        for stream in ("system-out", "system-err"):
            # Direct children only: a flaky or rerun try's output is nested
            # in its own element.
            for element in case.findall(stream):
                for line in (element.text or "").splitlines():
                    if SKIP_LINE.match(line):
                        found.append((test, line.strip()))
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--allowlist", required=True, type=Path)
    parser.add_argument("reports", nargs="+", type=Path, help="nextest JUnit files (junit.xml)")
    args = parser.parse_args(argv)
    try:
        entries = load_allowlist(args.allowlist)
    except (OSError, AllowlistError) as error:
        print(f"check-no-skips: {error}", file=sys.stderr)
        return 2
    missing = [path for path in args.reports if not path.is_file()]
    if missing:
        print("check-no-skips: no JUnit report at " + ", ".join(map(str, missing)), file=sys.stderr)
        return 1
    unexpected, used = [], Counter()
    for report in args.reports:
        for test, line in skip_lines(report):
            number = allowing(entries, test, line)
            if number is None:
                unexpected.append((test, line))
            else:
                used[number] += 1
    text = [f"### Skip lines\n\n{len(unexpected)} unexpected skip line{'s' if len(unexpected) != 1 else ''}, "
            f"{sum(used.values())} allowed by {args.allowlist}.\n"]
    if unexpected:
        text.append("\n| Test | Skip line |\n| --- | --- |\n")
        for test, line in unexpected[:ROWS]:
            escaped = line.replace("|", "\\|")
            text.append(f"| `{test}` | {escaped} |\n")
        if len(unexpected) > ROWS:
            text.append(f"\n... and {len(unexpected) - ROWS} more.\n")
        text.append("\nInstall what the test needs in the nightly, or allow the line, with its reason, "
                    f"in {args.allowlist}.\n")
    body = "".join(text) + "\n"
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as output:
            output.write(body)
    else:
        sys.stdout.write(body)
    for test, line in unexpected:
        print(f"::error title=Unexpected skip::{test}: {line}")
    return 1 if unexpected else 0


if __name__ == "__main__":
    raise SystemExit(main())
