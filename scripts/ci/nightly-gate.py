#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Decide whether the nightly integration suite needs to run at a commit.

It skips only when an earlier run of the workflow at the same commit ran
every integration shard and all of them passed. A failed nightly therefore
runs again while the commit is unchanged, and a skipped run, which GitHub
records as a success, never counts as tested. A manual dispatch always runs,
and so does a run whose earlier runs cannot be read (with a warning): an
unreadable history must not skip the suite.

Writes `changed=true` or `changed=false` to $GITHUB_OUTPUT. Calls the GitHub
CLI (`gh`, or the program $GH names), authenticated by GH_TOKEN.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.parse

INTEGRATION_JOB = "Integration tests (bhf)"


def api(path: str, **query: str) -> dict:
    url = path + ("?" + urllib.parse.urlencode(query) if query else "")
    result = subprocess.run([os.environ.get("GH") or "gh", "api", url], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"gh api {path} failed ({result.returncode}): {result.stderr.strip()}")
    return json.loads(result.stdout)


def fully_tested(jobs: list[dict]) -> bool:
    """Whether a run's jobs include integration shards and every one passed."""
    shards = [job for job in jobs if job.get("name", "").startswith(INTEGRATION_JOB)]
    return bool(shards) and all(job.get("conclusion") == "success" for job in shards)


def tested_run(repo: str, workflow: str, sha: str, current_run: int) -> dict | None:
    """The newest earlier run at `sha` that ran every shard and passed."""
    listed = api(f"repos/{repo}/actions/workflows/{workflow}/runs",
                 head_sha=sha, status="success", per_page="100")
    for run in sorted(listed.get("workflow_runs", []), key=lambda run: run["id"], reverse=True):
        if run["id"] == current_run or run.get("head_sha") != sha or run.get("conclusion") != "success":
            continue
        jobs = api(f"repos/{repo}/actions/runs/{run['id']}/jobs", filter="latest", per_page="100")
        if fully_tested(jobs.get("jobs", [])):
            return run
    return None


def decide(args: argparse.Namespace) -> tuple[bool, str]:
    if args.event == "workflow_dispatch":
        return True, "manual dispatch: running"
    try:
        run = tested_run(args.repo, args.workflow, args.sha, args.run_id)
    except (RuntimeError, ValueError, KeyError) as error:
        print(f"::warning title=Nightly gate::cannot read earlier runs, running the suite: {error}")
        return True, "earlier runs could not be read: running"
    if run is None:
        return True, f"no earlier run fully tested {args.sha} and passed: running"
    return False, f"{run.get('html_url', run['id'])} fully tested {args.sha} and passed: skipping"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True, help="OWNER/NAME")
    parser.add_argument("--workflow", required=True, help="workflow file name, e.g. integration-nightly.yml")
    parser.add_argument("--sha", required=True, help="the commit this run tests")
    parser.add_argument("--event", required=True, help="the event that started this run")
    parser.add_argument("--run-id", required=True, type=int, help="this run, which is never its own evidence")
    args = parser.parse_args(argv)
    changed, reason = decide(args)
    print(reason)
    line = f"changed={'true' if changed else 'false'}\n"
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write(line)
    else:
        sys.stdout.write(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
