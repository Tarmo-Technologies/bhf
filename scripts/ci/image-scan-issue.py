#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Turn the scheduled image scan's reviews into the body of its tracking issue.

`render REVIEW...` reads release-review.json files (each in a directory named
after its image, as the scan's artifacts are downloaded) and writes the issue
body, a comment for when the blocker list changed, and `blockers=N` and
`fingerprint=SHA256` lines on stdout and in $GITHUB_OUTPUT. The fingerprint is
a digest of the sorted blocker identities, so it changes only when a blocker
appears or goes away.

`seed EVIDENCE` adds one synthetic, plainly named blocker to EVIDENCE's
grype.json, so a manual run can check that the tracking issue opens, and that
a second run updates it. Never use it on evidence a release is built from.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("review_image_scan", HERE / "review-image-scan.py")
REVIEW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REVIEW)

SEEDED_ID = "SEEDED-IMAGE-SCAN-BLOCKER"
PREFIX = "image-scan-"
ROWS_PER_IMAGE = 100


def seed(evidence: Path) -> None:
    path = evidence / "grype.json"
    scan = json.loads(path.read_text())
    matches = scan.setdefault("matches", [])
    if not any(match.get("vulnerability", {}).get("id") == SEEDED_ID for match in matches):
        matches.append({
            "vulnerability": {"id": SEEDED_ID, "severity": "Critical", "fix": {"state": "not-fixed"},
                              "dataSource": "seeded by a manual image-scan run; not a real vulnerability"},
            "artifact": {"name": "seeded-blocker", "version": "0", "purl": None},
        })
    path.write_text(json.dumps(scan, indent=2) + "\n")


def image_name(review_path: Path) -> str:
    name = review_path.parent.name
    return name[len(PREFIX):] if name.startswith(PREFIX) else name


def identity(finding: dict) -> str:
    return "\t".join((finding["vulnerability"], finding["package"], finding["version"]))


def render(reviews: list[Path], run_url: str) -> tuple[str, str, int, str]:
    """The issue body, the change comment, the blocker count and fingerprint."""
    images = []
    keys = set()
    for path in sorted(reviews, key=image_name):
        result = json.loads(path.read_text())
        blockers = sorted(result["blockers"], key=identity)
        keys.update(f"{image_name(path)}\t{identity(finding)}" for finding in blockers)
        images.append((image_name(path), result, blockers))
    count = sum(len(blockers) for _, _, blockers in images)
    fingerprint = hashlib.sha256("\n".join(sorted(keys)).encode()).hexdigest()
    lines = [
        f"The scheduled container image scan found **{count} blockers**: Critical, High or",
        "unknown-severity matches, and Medium matches that have a fix. Pull request and",
        "branch CI only report these; tag, release and container-release runs fail on them,",
        "so they must be fixed (or the base snapshot refreshed) before the next release.",
        "",
        f"Last scan: {run_url}",
        "",
    ]
    for name, result, blockers in images:
        database = result.get("database", {})
        lines.append(f"### `{name}` image: {len(blockers)} blockers")
        lines.append("")
        lines.append(f"Image `{result.get('image_id', 'unknown')}`, vulnerability database built "
                     f"{database.get('built', 'unknown')}.")
        lines.append("")
        if blockers:
            lines.append(REVIEW.blocker_table(blockers, ROWS_PER_IMAGE))
    body = "\n".join(lines).rstrip() + "\n"
    comment = f"The blocker list changed: {count} blockers in {run_url}\n"
    return body, comment, count, fingerprint


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    seeding = commands.add_parser("seed", help="add a synthetic blocker to EVIDENCE/grype.json")
    seeding.add_argument("evidence", type=Path)
    rendering = commands.add_parser("render", help="write the tracking issue body")
    rendering.add_argument("--run-url", required=True)
    rendering.add_argument("--body", required=True, type=Path)
    rendering.add_argument("--comment", required=True, type=Path)
    rendering.add_argument("reviews", nargs="+", type=Path)
    args = parser.parse_args(argv)
    if args.command == "seed":
        seed(args.evidence)
        return 0
    body, comment, count, fingerprint = render(args.reviews, args.run_url)
    args.body.write_text(body, encoding="utf-8")
    args.comment.write_text(comment, encoding="utf-8")
    outputs = f"blockers={count}\nfingerprint={fingerprint}\n"
    print(outputs, end="")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write(outputs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
