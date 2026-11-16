#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Open, or update, the one open GitHub issue that tracks a recurring CI problem.

Each tracked problem has a key, which the issue body carries in a hidden
marker, so a later run edits that issue instead of opening another. The body
also carries a fingerprint of what was found (a digest of a blocker list, or
the failing commit): when a run's fingerprint differs from the one recorded,
it adds a comment as well, since a body edit notifies no one.

Calls the GitHub CLI (`gh`, or the program $GH names), authenticated by
GH_TOKEN as in a workflow step. Prints a JSON line saying what it did.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

SAFE = re.compile(r"[A-Za-z0-9._:/@+-]{1,128}")
FINGERPRINT = re.compile(r"<!-- bhf-tracking-fingerprint: (\S+) -->")


def marker(key: str) -> str:
    return f"<!-- bhf-tracking-issue: {key} -->"


def gh(*args: str) -> str:
    result = subprocess.run([os.environ.get("GH") or "gh", *args], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args[:2])} failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout


def find(repo: str, label: str, key: str) -> dict | None:
    """The oldest open issue labelled `label` whose body carries `key`'s marker."""
    listed = json.loads(gh("issue", "list", "--repo", repo, "--state", "open", "--label", label,
                           "--limit", "200", "--json", "number,body,url"))
    tagged = [issue for issue in listed if marker(key) in (issue.get("body") or "")]
    return min(tagged, key=lambda issue: issue["number"]) if tagged else None


def compose(body: str, key: str, fingerprint: str | None) -> str:
    lines = [body.rstrip(), "", marker(key)]
    if fingerprint:
        lines.append(f"<!-- bhf-tracking-fingerprint: {fingerprint} -->")
    return "\n".join(lines) + "\n"


def sync(*, repo: str, key: str, title: str, label: str, body: str,
         fingerprint: str | None = None, comment: str | None = None) -> dict:
    existing = find(repo, label, key)
    with tempfile.TemporaryDirectory(prefix="bhf-tracking-") as scratch:
        body_file = Path(scratch, "body.md")
        body_file.write_text(compose(body, key, fingerprint), encoding="utf-8")
        if existing is None:
            gh("label", "create", label, "--repo", repo, "--force", "--color", "B60205",
               "--description", "Opened and updated by a scheduled CI workflow")
            url = gh("issue", "create", "--repo", repo, "--title", title, "--label", label,
                     "--body-file", str(body_file)).strip()
            return {"action": "opened", "url": url}
        number = str(existing["number"])
        recorded = FINGERPRINT.search(existing.get("body") or "")
        changed = fingerprint is not None and (recorded is None or recorded[1] != fingerprint)
        gh("issue", "edit", number, "--repo", repo, "--body-file", str(body_file))
        commented = bool(changed and comment)
        if commented:
            comment_file = Path(scratch, "comment.md")
            comment_file.write_text(comment, encoding="utf-8")
            gh("issue", "comment", number, "--repo", repo, "--body-file", str(comment_file))
        return {"action": "updated", "number": existing["number"], "url": existing.get("url"),
                "commented": commented}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True, help="OWNER/NAME")
    parser.add_argument("--key", required=True, help="identifies the tracked problem across runs")
    parser.add_argument("--label", required=True, help="label of the tracking issue (created if missing)")
    parser.add_argument("--title", required=True, help="title of a newly opened issue")
    parser.add_argument("--body-file", required=True, type=Path)
    parser.add_argument("--fingerprint", help="what this run found; a change adds the comment")
    parser.add_argument("--comment-file", type=Path, help="comment to add when the fingerprint changed")
    args = parser.parse_args(argv)
    for name in ("key", "fingerprint", "label"):
        value = getattr(args, name)
        if value is not None and not SAFE.fullmatch(value):
            parser.error(f"--{name} must be 1-128 characters of [A-Za-z0-9._:/@+-]")
    try:
        report = sync(repo=args.repo, key=args.key, title=args.title, label=args.label,
                      body=args.body_file.read_text(encoding="utf-8"), fingerprint=args.fingerprint,
                      comment=args.comment_file.read_text(encoding="utf-8") if args.comment_file else None)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"tracking-issue: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
