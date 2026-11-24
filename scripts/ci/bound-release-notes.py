#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bound generated GitHub release notes without producing invalid UTF-8."""

from __future__ import annotations

import argparse
from pathlib import Path
from urllib.parse import quote

MAX_BODY_BYTES = 120_000


def bound_notes(body: str, repository: str, tag: str) -> str:
    encoded = body.encode("utf-8")
    if len(encoded) <= MAX_BODY_BYTES:
        return body

    suffix = (
        "\n\n---\n"
        "These generated notes were shortened to fit GitHub's release-body limit. "
        f"See the [full changelog](https://github.com/{repository}/blob/"
        f"{quote(tag, safe='')}/CHANGELOG.md).\n"
    )
    budget = MAX_BODY_BYTES - len(suffix.encode("utf-8"))
    prefix = encoded[:budget].decode("utf-8", errors="ignore")
    if "\n" in prefix:
        prefix = prefix.rsplit("\n", 1)[0]
    return prefix.rstrip() + suffix


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("repository")
    parser.add_argument("tag")
    args = parser.parse_args()

    bounded = bound_notes(args.input.read_text(encoding="utf-8"), args.repository, args.tag)
    args.output.write_text(bounded, encoding="utf-8")


if __name__ == "__main__":
    main()
