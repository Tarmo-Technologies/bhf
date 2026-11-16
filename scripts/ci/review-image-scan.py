#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare a release review; never treat scanner silence as human approval.

Critical/High, unknown severity, fixable Medium, and stale/invalid databases
block signing. Remaining findings are retained for the protected release
reviewer to accept or reject; none are automatically marked not_affected.

Blockers fail the run in enforce mode, which tag, release and
container-release runs always use, as does any run outside GitHub Actions.
Pull request and branch push runs are report-only: they write the same
review and annotate its blockers but exit 0, so a CVE published upstream
after a change does not fail that change's CI. The scheduled image scan
tracks those blockers in an issue. A scan that did not run, or ran against
an invalid or stale database, fails in every mode.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib

MODES = ("auto", "enforce", "report-only")
# Events whose runs only report blockers when the mode is `auto`.
REPORT_ONLY_EVENTS = frozenset(("pull_request", "push"))
# Workflows whose runs prepare a release, wherever they were started from. A
# reusable workflow sees its caller's GITHUB_WORKFLOW_REF.
RELEASE_WORKFLOWS = ("/.github/workflows/release.yml@", "/.github/workflows/container-release.yml@")
SUMMARY_ROWS = 50


def review(scan, now):
    db = scan.get("descriptor", {}).get("db", {}).get("status", {})
    built = dt.datetime.fromisoformat(db.get("built", "").replace("Z", "+00:00"))
    if not db.get("valid") or built.tzinfo is None or not dt.timedelta(0) <= now - built <= dt.timedelta(days=7):
        raise ValueError("invalid, future, or older-than-seven-days vulnerability database")
    if "matches" not in scan or not isinstance(scan["matches"], list):
        raise ValueError("missing vulnerability matches")
    blockers, residual = [], []
    for match in scan["matches"]:
        v, a = match["vulnerability"], match["artifact"]
        severity, fix = v["severity"], v.get("fix", {})
        finding = {"vulnerability": v["id"], "package": a["name"], "version": a["version"],
                   "purl": a.get("purl"), "severity": severity, "fix": fix,
                   "source": v.get("dataSource"), "status": "under_investigation"}
        if severity not in ("Medium", "Low", "Negligible") or (severity == "Medium" and fix.get("state") == "fixed"):
            blockers.append(finding)
        else:
            residual.append(finding)
    return {"schema_version": 1, "database": db,
            "decision": "BLOCK" if blockers else "REQUIRES_PROTECTED_REVIEW",
            "blockers": blockers, "residual_findings": residual,
            "review_requirement": "Production environment reviewer must review the exact archive and residual findings before signing."}


def release_run(env):
    """Why this run prepares a release (and so must enforce), or None."""
    if env.get("GITHUB_REF_TYPE") == "tag" or env.get("GITHUB_REF", "").startswith("refs/tags/"):
        return "a tag run"
    if env.get("GITHUB_EVENT_NAME") == "release":
        return "a release run"
    workflow = env.get("GITHUB_WORKFLOW_REF", "")
    if any(name in workflow for name in RELEASE_WORKFLOWS):
        return "a release workflow run"
    return None


def select_mode(requested, env):
    """`enforce` or `report-only` for a run with environment `env`.

    A release run always enforces, whatever was requested. Otherwise an
    explicit request wins, and `auto` reports only on GitHub Actions pull
    request and branch push runs.
    """
    if requested not in MODES:
        raise ValueError(f"unknown image scan mode {requested!r}; use one of {', '.join(MODES)}")
    if release_run(env):
        return "enforce"
    if requested != "auto":
        return requested
    if env.get("GITHUB_ACTIONS") == "true" and env.get("GITHUB_EVENT_NAME") in REPORT_ONLY_EVENTS:
        return "report-only"
    return "enforce"


def fix_text(fix):
    versions = fix.get("versions") or []
    if fix.get("state") == "fixed" and versions:
        return "fixed in " + ", ".join(str(version) for version in versions)
    return str(fix.get("state") or "unknown")


def cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def blocker_table(blockers, limit=SUMMARY_ROWS):
    """The blockers as a Markdown table of at most `limit` rows."""
    lines = ["| Vulnerability | Package | Version | Severity | Fix |", "| --- | --- | --- | --- | --- |"]
    for finding in blockers[:limit]:
        lines.append("| " + " | ".join(cell(value) for value in (
            finding["vulnerability"], finding["package"], finding["version"],
            finding["severity"], fix_text(finding["fix"]))) + " |")
    if len(blockers) > limit:
        lines.append(f"\n... and {len(blockers) - limit} more in release-review.json.")
    return "\n".join(lines) + "\n"


def report_blockers(result, evidence, env):
    """Annotate a report-only run's blockers in the job log and summary."""
    count = len(result["blockers"])
    print(f"::warning title=Container image scan::{count} image blockers in {evidence}; "
          "report-only on this run, enforced for tags and releases")
    summary = env.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as output:
            output.write(f"### Container image scan: {count} blockers (report-only)\n\n"
                         f"`{evidence}`: this run reports image blockers without failing; "
                         "tag, release and container-release runs fail on them.\n\n")
            output.write(blocker_table(result["blockers"]) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", default=os.environ.get("BHF_IMAGE_SCAN_MODE") or "auto",
                        help="auto (the default, or $BHF_IMAGE_SCAN_MODE), enforce, or report-only")
    parser.add_argument("evidence", type=pathlib.Path)
    args = parser.parse_args()
    try:
        mode = select_mode(args.mode, os.environ)
    except ValueError as error:
        parser.error(str(error))
    scan_bytes = (args.evidence / "grype.json").read_bytes()
    result = review(json.loads(scan_bytes), dt.datetime.now(dt.timezone.utc))
    result["enforcement"] = mode
    result["scan_sha256"] = hashlib.sha256(scan_bytes).hexdigest()
    result["image_id"] = json.loads((args.evidence / "image-inspect.json").read_text())[0]["Id"]
    (args.evidence / "release-review.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f'{result["decision"]}: {len(result["blockers"])} blockers, {len(result["residual_findings"])} residual matches')
    if result["blockers"] and mode == "report-only":
        report_blockers(result, args.evidence, os.environ)
        raise SystemExit(0)
    raise SystemExit(1 if result["blockers"] else 0)


if __name__ == "__main__":
    main()
