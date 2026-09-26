#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed aggregation of the CI workflow's own GitHub Actions `needs`.

This is a CI policy check, not a signature verifier or an enterprise-readiness
certification. JSON supplied outside the workflow is an untrusted assertion.
Only PASS_FULL_CI records a complete run of the jobs listed below; a permitted
documentation-only skip is deliberately reported as PASS_DOCS_ONLY instead.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any

HEAVY_JOBS = (
    "minimum-rust",
    "build-test",
    "integration-tests",
    "rhel7-build",
    "rhel-family-smoke",
    "ubuntu-release-smoke",
    "windows-build",
    "windows-current-build",
)
ALWAYS_REQUIRED = ("changes", "ci-policy")
EXPECTED_JOBS = frozenset((*ALWAYS_REQUIRED, *HEAVY_JOBS))
MAX_INPUT_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 16


class InvalidInput(ValueError):
    """The caller did not provide a complete, unambiguous CI observation."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidInput("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise InvalidInput(f"non-JSON numeric constant: {value}")


def parse_observation(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_INPUT_BYTES:
        raise InvalidInput("CI observation exceeds the 1 MiB input limit")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except InvalidInput:
        raise
    except (UnicodeError, ValueError, RecursionError) as error:
        raise InvalidInput("CI observation is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise InvalidInput("CI observation must be a JSON object")
    pending = [(value, 1)]
    while pending:
        item, depth = pending.pop()
        if depth > MAX_JSON_DEPTH:
            raise InvalidInput("CI observation exceeds the JSON nesting limit")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return value


def _valid_sha(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{40}", value)) and value != "0" * 40


def evaluate(
    needs: dict[str, Any], *, commit: str, event: str, require_full: bool = False
) -> dict[str, Any]:
    if not _valid_sha(commit):
        raise InvalidInput("commit must be a nonzero, lowercase, full Git commit SHA")
    if event not in {"push", "pull_request", "workflow_dispatch"}:
        raise InvalidInput("unsupported workflow event")
    if not isinstance(needs, dict):
        raise InvalidInput("CI observation must be a JSON object")
    if any(not isinstance(key, str) for key in needs):
        raise InvalidInput("job identifiers must be strings")

    blockers: list[str] = []
    for job in sorted(EXPECTED_JOBS - needs.keys()):
        blockers.append(f"missing required job: {job}")
    if needs.keys() - EXPECTED_JOBS:
        # Do not silently exclude a new CI job from the acceptance policy.
        blockers.append("unexpected job identifiers; update the acceptance policy")

    results: dict[str, str] = {}
    for job in (*ALWAYS_REQUIRED, *HEAVY_JOBS):
        observation = needs.get(job)
        if not isinstance(observation, dict):
            results[job] = "missing" if job not in needs else "invalid"
            if job in needs:
                blockers.append(f"{job}: job observation must be an object")
            continue
        result = observation.get("result")
        if result not in ("success", "failure", "cancelled", "skipped"):
            results[job] = "invalid"
            blockers.append(f"{job}: missing or unknown result")
        else:
            results[job] = result

    changes = needs.get("changes")
    outputs = changes.get("outputs") if isinstance(changes, dict) else None
    heavy = outputs.get("heavy") if isinstance(outputs, dict) else None
    # GitHub workflow outputs are strings, not booleans. Missing, empty, or
    # malformed classifier output must never authorize a documentation skip.
    scope = "full" if heavy == "true" else "docs_only" if heavy == "false" else "unknown"
    if scope == "unknown":
        blockers.append("changes: heavy output must be exactly 'true' or 'false'")
    if (require_full or event == "workflow_dispatch") and scope != "full":
        blockers.append("this invocation requires a full CI run; documentation skips are not accepted")

    for job in ALWAYS_REQUIRED:
        if results[job] != "success":
            blockers.append(f"{job}: required success, observed {results[job]}")
    for job in HEAVY_JOBS:
        allowed = ("success", "skipped") if scope == "docs_only" else ("success",)
        if results[job] not in allowed:
            blockers.append(f"{job}: observed {results[job]}, expected {' or '.join(allowed)}")

    accepted = not blockers
    return {
        "schema_version": 1,
        "commit": commit,
        "event": event,
        "scope": scope,
        "decision": "BLOCKED" if blockers else "PASS_FULL_CI" if scope == "full" else "PASS_DOCS_ONLY",
        "accepted": accepted,
        "full_ci_passed": accepted and scope == "full",
        "enterprise_readiness": "not_assessed",
        "jobs": results,
        "blockers": blockers,
    }


def write_report(path: Path, report: dict[str, Any]) -> None:
    """Replace an old receipt atomically, including when the new run fails."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as output:
            temporary = output.name
            json.dump(report, output, indent=2, sort_keys=True, allow_nan=False)
            output.write("\n")
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True, help="exact checked-out commit, not a branch name")
    parser.add_argument("--event", required=True)
    parser.add_argument("--needs-file", type=Path, help="otherwise read the NEEDS_JSON environment variable")
    parser.add_argument("--require-full", action="store_true", help="reject documentation-only exemptions")
    parser.add_argument("--output", type=Path, help="write a JSON receipt even when validation fails")
    args = parser.parse_args(argv)

    try:
        if args.needs_file is not None:
            with args.needs_file.open("rb") as source:
                raw = source.read(MAX_INPUT_BYTES + 1)
        else:
            value = os.environ.get("NEEDS_JSON")
            if value is None:
                raise InvalidInput("NEEDS_JSON is missing; no job results were supplied")
            raw = value.encode("utf-8")
        report = evaluate(
            parse_observation(raw), commit=args.commit, event=args.event, require_full=args.require_full
        )
    except (OSError, InvalidInput, UnicodeError) as error:
        report = {
            "schema_version": 1,
            "commit": args.commit if _valid_sha(args.commit) else None,
            "decision": "BLOCKED",
            "accepted": False,
            "full_ci_passed": False,
            "enterprise_readiness": "not_assessed",
            "blockers": [str(error)[:512]],
        }

    if args.output is not None:
        try:
            write_report(args.output, report)
        except OSError as error:
            print(f"Unable to write CI acceptance receipt: {error}", file=sys.stderr)
            return 2
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return 0 if report["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
