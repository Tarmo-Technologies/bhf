# SPDX-License-Identifier: Apache-2.0
"""The nightly's gate and failure report, run against a stand-in `gh` that
answers the Actions API from a list of earlier runs.

The gate skips only when an earlier run at the same commit ran every
integration shard and all of them passed, so a failed nightly runs again
while the commit is unchanged, and a skip never reports success over a
failure. A failed nightly opens, or updates, one tracking issue."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[3]
GATE = ROOT / "scripts/ci/nightly-gate.py"
WORKFLOW = ROOT / ".github/workflows/integration-nightly.yml"
SHA = "f35f8b3" + "0" * 33
OTHER = "e077001" + "0" * 33

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_tracking_issue import FAKE_GH  # noqa: E402

# Answers `gh api` from FAKE_RUNS: {"runs": [{"id", "head_sha", "conclusion",
# "jobs": [{"name", "conclusion"}]}]}, filtering as the API does.
FAKE_API = r'''#!/usr/bin/env python3
import json, os, re, sys, urllib.parse
args = sys.argv[1:]
with open(os.environ["FAKE_API_LOG"], "a") as log:
    log.write(json.dumps(args) + "\n")
if os.environ.get("FAKE_API_FAIL"):
    print("HTTP 401: Bad credentials", file=sys.stderr)
    sys.exit(1)
assert args[0] == "api", args
url = urllib.parse.urlsplit(args[-1])
query = dict(urllib.parse.parse_qsl(url.query))
runs = json.loads(os.environ["FAKE_RUNS"])["runs"]
if m := re.fullmatch(r"repos/owner/repo/actions/workflows/integration-nightly\.yml/runs", url.path):
    found = [r for r in runs if r["head_sha"] == query.get("head_sha", r["head_sha"])
             and r["conclusion"] == query.get("status", r["conclusion"])]
    print(json.dumps({"total_count": len(found), "workflow_runs": [
        {"id": r["id"], "head_sha": r["head_sha"], "status": "completed", "conclusion": r["conclusion"],
         "html_url": f"https://github.com/owner/repo/actions/runs/{r['id']}"} for r in found]}))
elif m := re.fullmatch(r"repos/owner/repo/actions/runs/(\d+)/jobs", url.path):
    run = next(r for r in runs if r["id"] == int(m[1]))
    print(json.dumps({"total_count": len(run["jobs"]), "jobs": run["jobs"]}))
else:
    print(f"unexpected path {url.path}", file=sys.stderr)
    sys.exit(2)
'''

SHARDS = [f"Integration tests (bhf) ({n})" for n in list(range(1, 13)) + ["build-recovery-scenarios"]]


def full_run(run_id: int, sha: str, conclusion: str = "success", failed_shard: str | None = None) -> dict:
    jobs = [{"name": "Gate on an untested commit", "conclusion": "success"}]
    jobs += [{"name": name, "conclusion": "failure" if name == failed_shard else "success"} for name in SHARDS]
    return {"id": run_id, "head_sha": sha, "conclusion": conclusion, "jobs": jobs}


def skipped_run(run_id: int, sha: str) -> dict:
    """A run whose gate skipped the suite: GitHub calls it a success."""
    return {"id": run_id, "head_sha": sha, "conclusion": "success", "jobs": [
        {"name": "Gate on an untested commit", "conclusion": "success"},
        {"name": "Integration tests (bhf)", "conclusion": "skipped"}]}


class NightlyGateTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.gh = self.root / "gh"
        self.gh.write_text(FAKE_API)
        self.gh.chmod(0o755)
        self.log = self.root / "api.log"

    def gate(self, runs: list[dict], *, event: str = "schedule", fail: bool = False) -> tuple[str, str]:
        output = self.root / "github-output"
        output.write_text("")
        env = dict(os.environ, GH=str(self.gh), FAKE_RUNS=json.dumps({"runs": runs}), FAKE_API_LOG=str(self.log),
                   FAKE_API_FAIL="1" if fail else "", GITHUB_OUTPUT=str(output))
        result = subprocess.run(
            [sys.executable, str(GATE), "--repo", "owner/repo", "--workflow", "integration-nightly.yml",
             "--sha", SHA, "--event", event, "--run-id", "999"],
            env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return output.read_text(), result.stdout

    def test_a_commit_with_no_earlier_run_is_tested(self):
        self.assertEqual(self.gate([])[0], "changed=true\n")

    def test_a_nightly_that_failed_at_this_commit_runs_again(self):
        runs = [full_run(1, SHA, "failure", failed_shard=SHARDS[3])]
        output, stdout = self.gate(runs)
        self.assertEqual(output, "changed=true\n")
        self.assertIn("no earlier run", stdout)

    def test_a_skipped_run_does_not_count_as_tested(self):
        # The old gate's skip reported success over a failure at the same SHA.
        runs = [full_run(1, SHA, "failure", failed_shard=SHARDS[0]), skipped_run(2, SHA)]
        self.assertEqual(self.gate(runs)[0], "changed=true\n")

    def test_a_full_successful_run_at_this_commit_skips(self):
        runs = [full_run(1, SHA, "failure", failed_shard=SHARDS[0]), full_run(2, SHA), skipped_run(3, SHA)]
        output, stdout = self.gate(runs)
        self.assertEqual(output, "changed=false\n")
        self.assertIn("https://github.com/owner/repo/actions/runs/2", stdout)

    def test_a_full_success_at_another_commit_does_not_count(self):
        self.assertEqual(self.gate([full_run(1, OTHER)])[0], "changed=true\n")

    def test_a_run_with_a_skipped_shard_does_not_count(self):
        run = full_run(1, SHA)
        run["jobs"][5]["conclusion"] = "skipped"
        self.assertEqual(self.gate([run])[0], "changed=true\n")

    def test_this_run_is_not_its_own_evidence(self):
        self.assertEqual(self.gate([full_run(999, SHA)])[0], "changed=true\n")

    def test_a_manual_dispatch_always_runs_without_asking_the_api(self):
        self.assertEqual(self.gate([full_run(1, SHA)], event="workflow_dispatch")[0], "changed=true\n")
        self.assertFalse(self.log.exists())

    def test_an_api_failure_runs_the_suite_instead_of_skipping_it(self):
        output, stdout = self.gate([full_run(1, SHA)], fail=True)
        self.assertEqual(output, "changed=true\n")
        self.assertIn("::warning", stdout)

    def test_it_asks_only_for_successful_runs_of_this_commit(self):
        self.gate([full_run(1, SHA)])
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        listing = calls[0][-1]
        self.assertIn(f"head_sha={SHA}", listing)
        self.assertIn("status=success", listing)


def workflow_job(name: str) -> str:
    block = WORKFLOW.read_text().split(f"\n  {name}:\n", 1)[1]
    return re.split(r"\n  [a-z][a-z0-9-]*:\n", block, maxsplit=1)[0]


def step_script(job_text: str, name: str) -> str:
    step = job_text.split(f"      - name: {name}\n", 1)[1].split("\n      - name:", 1)[0]
    body = step.split("        run: |\n", 1)[1]
    lines = []
    for line in body.splitlines():
        if line.strip() and not line.startswith("          "):
            break
        lines.append(line)
    return textwrap.dedent("\n".join(lines)) + "\n"


class NightlyWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.source = WORKFLOW.read_text()
        self.gate = workflow_job("gate")
        self.report = workflow_job("report-failure")

    def test_the_gate_reads_runs_with_a_read_only_token(self):
        self.assertIn("    permissions:\n      contents: read\n      actions: read\n", self.gate)
        script = step_script(self.gate, "Look for a full successful run at this commit")
        self.assertIn("scripts/ci/nightly-gate.py", script)
        self.assertIn('--sha "$GITHUB_SHA"', script)
        self.assertNotIn("90000", self.source)
        self.assertNotIn("git log -1 --format=%ct", self.source)

    def test_only_the_failure_report_can_write_issues(self):
        self.assertEqual(self.source.count("issues: write"), 1)
        self.assertIn("    permissions:\n      contents: read\n      issues: write\n", self.report)
        self.assertIn("    needs: [gate, build, integration, winafl]\n", self.report)
        condition = re.search(r"(?m)^    if: (.+)$", self.report)[1]
        # Runs after a failed or timed-out shard, or a failed archive build,
        # not after the whole run was cancelled by a newer one, nor after a
        # skip or a pass.
        self.assertIn("!cancelled()", condition)
        self.assertIn("needs.build.result == 'failure'", condition)
        self.assertIn("needs.integration.result == 'failure'", condition)
        self.assertIn("needs.integration.result == 'cancelled'", condition)
        self.assertIn("needs.gate.result == 'failure'", condition)
        self.assertIn("needs.winafl.result == 'failure'", condition)
        self.assertIn("needs.winafl.result == 'cancelled'", condition)

    def report_failure(self, state: Path, sha: str, run_id: int) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            gh = Path(scratch, "gh")
            gh.write_text(FAKE_GH)
            gh.chmod(0o755)
            env = dict(os.environ, GH=str(gh), FAKE_GH_STATE=str(state), RUNNER_TEMP=scratch,
                       GITHUB_REPOSITORY="owner/repo", GITHUB_SHA=sha, GITHUB_REF_NAME="main",
                       EVENT_NAME="schedule",
                       RUN_URL=f"https://github.com/owner/repo/actions/runs/{run_id}")
            result = subprocess.run(["bash", "-e", "-o", "pipefail", "-c",
                                     step_script(self.report, "Open or update the failure issue")],
                                    cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_failures_open_one_issue_and_a_new_failing_commit_comments_on_it(self):
        with tempfile.TemporaryDirectory() as scratch:
            state = Path(scratch, "state.json")
            self.report_failure(state, SHA, 1)
            self.report_failure(state, SHA, 2)
            [issue] = json.loads(state.read_text())["issues"]
            self.assertIn(SHA, issue["body"])
            self.assertIn("actions/runs/2", issue["body"])
            self.assertEqual(issue["comments"], [], "the same commit failing again does not notify again")
            self.report_failure(state, OTHER, 3)
            [issue] = json.loads(state.read_text())["issues"]
            self.assertIn(OTHER, issue["body"])
            self.assertEqual(len(issue["comments"]), 1)
            self.assertIn(OTHER, issue["comments"][0])


if __name__ == "__main__":
    unittest.main()
