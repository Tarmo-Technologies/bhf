#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Gate release side effects on this run's full-CI result for the exact revision.

The workflow supplies authenticated `needs` outputs. Outside that workflow,
JSON is only an assertion: this CLI does not authenticate GitHub observations,
verify a signature, inspect repository rules, or authorize a deployment.
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

MAX_INPUT_BYTES = 64 * 1024
MAX_JSON_DEPTH = 8
OUTPUT_KEYS = frozenset({"decision", "commit", "run_id", "run_attempt"})
SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
ID_PATTERN = re.compile(r"[1-9][0-9]{0,19}")
REPO_PATTERN = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


class InvalidObservation(ValueError):
    """A missing or ambiguous observation cannot authorize release side effects."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidObservation("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise InvalidObservation("non-JSON numeric constant")


def parse_observation(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_INPUT_BYTES:
        raise InvalidObservation("release observation exceeds 64 KiB")
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                            parse_constant=_reject_constant)
    except InvalidObservation:
        raise
    except (ValueError, UnicodeError, RecursionError) as error:
        raise InvalidObservation("release observation is not valid UTF-8 JSON") from error
    if not isinstance(result, dict):
        raise InvalidObservation("release observation must be a JSON object")
    stack = [(result, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise InvalidObservation("release observation exceeds the nesting limit")
        if isinstance(item, dict):
            stack.extend((value, depth + 1) for value in item.values())
        elif isinstance(item, list):
            stack.extend((value, depth + 1) for value in item)
    return result


def _valid_sha(value: Any) -> bool:
    return isinstance(value, str) and SHA_PATTERN.fullmatch(value) is not None and value != "0" * 40


def _valid_id(value: Any) -> bool:
    return isinstance(value, str) and ID_PATTERN.fullmatch(value) is not None


def _valid_tag_ref(value: Any) -> bool:
    # Match Git's relevant ref restrictions without invoking a shell. This
    # policy is deliberately narrower than Git's full ref syntax. cargo-dist
    # remains responsible for checking the version format itself.
    if not isinstance(value, str) or not value.startswith("refs/tags/") or len(value) > 256:
        return False
    tag = value[len("refs/tags/"):]
    if not tag or tag.startswith("-") or any(c in tag for c in "~^:?*[\\"):
        return False
    if ".." in tag or "@{" in tag or any(ord(c) < 33 or ord(c) > 126 for c in tag):
        return False
    return all(part and not part.startswith(".") and not part.endswith((".", ".lock"))
               for part in tag.split("/"))


def evaluate(observation: dict[str, Any], *, commit: str, event: str, ref: str,
             repository: str, run_id: str, run_attempt: str) -> dict[str, Any]:
    if not _valid_sha(commit):
        raise InvalidObservation("expected commit must be a nonzero lowercase full Git SHA")
    if not _valid_id(run_id) or not _valid_id(run_attempt):
        raise InvalidObservation("run ID and attempt must be canonical positive decimal strings")
    if not isinstance(repository, str) or not REPO_PATTERN.fullmatch(repository):
        raise InvalidObservation("repository must be an owner/name identifier")
    blockers: list[str] = []
    if event != "push" or not _valid_tag_ref(ref):
        blockers.append("release authorization requires a push to a valid tag ref")
    if not isinstance(observation, dict) or set(observation) != {"result", "outputs"}:
        raise InvalidObservation("expected exactly the reusable workflow result and outputs")
    if observation.get("result") != "success":
        blockers.append("full-CI workflow did not complete successfully")
    outputs = observation.get("outputs")
    if not isinstance(outputs, dict) or set(outputs) != OUTPUT_KEYS:
        raise InvalidObservation("missing or unexpected full-CI output fields")
    if outputs.get("decision") != "PASS_FULL_CI":
        blockers.append("full-CI decision must be PASS_FULL_CI, not a documentation exemption")
    if outputs.get("commit") != commit:
        blockers.append("CI commit differs from the release commit")
    if outputs.get("run_id") != run_id or outputs.get("run_attempt") != run_attempt:
        blockers.append("CI evidence is not from this workflow run and attempt")
    accepted = not blockers
    return {
        "schema_version": 1,
        "kind": "release_ci_acceptance",
        "repository": repository,
        "commit": commit,
        "ref": ref if _valid_tag_ref(ref) else None,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "decision": "PASS_RELEASE_CI" if accepted else "BLOCKED",
        "accepted": accepted,
        "full_ci_passed": accepted,
        "evidence_source": "same_run_reusable_workflow_outputs",
        "artifact_authenticity": "not_assessed",
        "deployment_authorization": "not_assessed",
        "enterprise_readiness": "not_assessed",
        "blockers": blockers,
    }


def write_report(path: Path, report: dict[str, Any]) -> None:
    """Atomically replace stale success with failure as well as success."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=f".{path.name}.", delete=False) as output:
            temporary = output.name
            json.dump(report, output, indent=2, sort_keys=True, allow_nan=False)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("commit", "event", "ref", "repository", "run-id", "run-attempt"):
        parser.add_argument(f"--{field}", required=True)
    parser.add_argument("--needs-file", type=Path,
                        help="otherwise read CI_VALIDATION_JSON supplied by the workflow")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.needs_file is not None:
            with args.needs_file.open("rb") as source:
                raw = source.read(MAX_INPUT_BYTES + 1)
        else:
            value = os.environ.get("CI_VALIDATION_JSON")
            if value is None:
                raise InvalidObservation("CI_VALIDATION_JSON is missing")
            raw = value.encode("utf-8")
        report = evaluate(parse_observation(raw), commit=args.commit, event=args.event,
                          ref=args.ref, repository=args.repository,
                          run_id=args.run_id, run_attempt=args.run_attempt)
    except (OSError, UnicodeError, InvalidObservation) as error:
        # Do not echo arbitrary input JSON, credentials, ref names, or filesystem
        # paths in failure receipts. Static validation errors are safe to retain.
        reason = str(error) if isinstance(error, InvalidObservation) else "cannot read release observation"
        report = {"schema_version": 1, "kind": "release_ci_acceptance",
                  "commit": args.commit if _valid_sha(args.commit) else None,
                  "decision": "BLOCKED", "accepted": False, "full_ci_passed": False,
                  "enterprise_readiness": "not_assessed", "blockers": [reason]}
    try:
        write_report(args.output, report)
    except OSError:
        print("cannot write release acceptance receipt", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return 0 if report["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
