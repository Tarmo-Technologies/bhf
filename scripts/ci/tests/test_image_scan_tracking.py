# SPDX-License-Identifier: Apache-2.0
"""The scheduled image scan: its seeded blocker, the tracking issue body, and
the workflow's own review and tracking steps run twice against a stand-in
`gh`, which must leave one issue, opened by the first run and updated by the
second."""
from __future__ import annotations

import datetime as dt
import importlib.util
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
WORKFLOW = ROOT / ".github/workflows/image-scan.yml"
ISSUE = ROOT / "scripts/ci/image-scan-issue.py"
REVIEW = ROOT / "scripts/ci/review-image-scan.py"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_tracking_issue import FAKE_GH  # noqa: E402


def job(name: str) -> str:
    block = WORKFLOW.read_text().split(f"\n  {name}:\n", 1)[1]
    return re.split(r"\n  [a-z][a-z0-9-]*:\n", block, maxsplit=1)[0]


def step(job_text: str, name: str) -> str:
    return job_text.split(f"      - name: {name}\n", 1)[1].split("\n      - name:", 1)[0]


def step_script(step_text: str) -> str:
    if "        run: |\n" in step_text:
        body = step_text.split("        run: |\n", 1)[1]
        lines = []
        for line in body.splitlines():
            if line.strip() and not line.startswith("          "):
                break
            lines.append(line)
        return textwrap.dedent("\n".join(lines)) + "\n"
    return re.search(r"(?m)^        run: (.+)$", step_text)[1] + "\n"


def grype_scan(matches: list) -> dict:
    built = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"descriptor": {"db": {"status": {"valid": True, "built": built}}}, "matches": matches}


def blocker(cve: str, package: str = "widget") -> dict:
    return {"vulnerability": {"id": cve, "severity": "High", "fix": {"state": "fixed", "versions": ["2"]}},
            "artifact": {"name": package, "version": "1"}}


class ImageScanIssueTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        spec = importlib.util.spec_from_file_location("image_scan_issue", ISSUE)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def review_file(self, image: str, blockers: list, residual: int = 0) -> Path:
        path = self.root / f"image-scan-{image}" / "release-review.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        findings = [{"vulnerability": b["vulnerability"]["id"], "package": b["artifact"]["name"],
                     "version": b["artifact"]["version"], "severity": "High", "fix": b["vulnerability"]["fix"]}
                    for b in blockers]
        path.write_text(json.dumps({"decision": "BLOCK" if findings else "REQUIRES_PROTECTED_REVIEW",
                                    "blockers": findings, "residual_findings": [{}] * residual,
                                    "image_id": f"sha256:{image}", "database": {"built": "2026-11-15T00:00:00Z"}}))
        return path

    def test_a_seeded_blocker_is_a_blocker_to_the_review(self):
        evidence = self.root / "evidence"
        evidence.mkdir()
        (evidence / "grype.json").write_text(json.dumps(grype_scan([])))
        self.module.seed(evidence)
        self.module.seed(evidence)
        scan = json.loads((evidence / "grype.json").read_text())
        result = self.module.REVIEW.review(scan, dt.datetime.now(dt.timezone.utc))
        self.assertEqual([b["vulnerability"] for b in result["blockers"]], [self.module.SEEDED_ID])

    def test_the_body_lists_each_images_blockers(self):
        reviews = [self.review_file("full", [blocker("CVE-2026-2"), blocker("CVE-2026-1")]),
                   self.review_file("core", [])]
        body, comment, count, _ = self.module.render(reviews, "https://example.test/run/7")
        self.assertEqual(count, 2)
        self.assertIn("**2 blockers**", body)
        self.assertIn("Last scan: https://example.test/run/7", body)
        self.assertIn("### `core` image: 0 blockers", body)
        self.assertIn("### `full` image: 2 blockers", body)
        self.assertLess(body.index("| CVE-2026-1 | widget | 1 | High | fixed in 2 |"),
                        body.index("| CVE-2026-2 | widget | 1 | High | fixed in 2 |"))
        self.assertIn("https://example.test/run/7", comment)

    def test_the_fingerprint_changes_only_with_the_blocker_list(self):
        def fingerprint(blockers, residual=0, run="https://example.test/run/1"):
            return self.module.render([self.review_file("full", blockers, residual)], run)[3]
        first = fingerprint([blocker("CVE-2026-1"), blocker("CVE-2026-2")])
        self.assertEqual(first, fingerprint([blocker("CVE-2026-2"), blocker("CVE-2026-1")], residual=9,
                                            run="https://example.test/run/2"))
        self.assertNotEqual(first, fingerprint([blocker("CVE-2026-1")]))
        self.assertNotEqual(first, fingerprint([blocker("CVE-2026-1"), blocker("CVE-2026-2", "gadget")]))

    def test_render_writes_the_step_outputs(self):
        output = self.root / "github-output"
        result = subprocess.run(
            [sys.executable, str(ISSUE), "render", "--run-url", "https://example.test/run/1",
             "--body", str(self.root / "body.md"), "--comment", str(self.root / "comment.md"),
             str(self.review_file("core", []))],
            env=dict(os.environ, GITHUB_OUTPUT=str(output)), capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(output.read_text(), r"\Ablockers=0\nfingerprint=[0-9a-f]{64}\n\Z")


class ImageScanWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.source = WORKFLOW.read_text()
        self.scan = job("scan")
        self.track = job("track")

    def test_it_runs_on_a_schedule_and_by_hand_with_a_seed_option(self):
        self.assertRegex(self.source, r"(?m)^  schedule:\n    - cron: \"[^\"]+\"")
        dispatch = self.source.split("  workflow_dispatch:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertIn("      seed_blocker:\n", dispatch)
        self.assertIn("        type: boolean\n        default: false\n", dispatch)
        self.assertIn("\npermissions:\n  contents: read\n\n", self.source)

    def test_every_release_image_is_scanned_report_only_and_the_seed_is_opt_in(self):
        self.assertEqual(re.findall(r"(?m)^          - image: (\S+)$", self.scan), ["core", "ada", "full"])
        self.assertIn("      fail-fast: false\n", self.scan)
        seed = step(self.scan, "Seed a synthetic blocker")
        self.assertIn("        if: ${{ inputs.seed_blocker }}\n", seed)
        review = step_script(step(self.scan, "Review the scan"))
        self.assertIn("review-image-scan.py --mode report-only", review)
        self.assertIn("        if: ${{ always() }}\n", step(self.scan, "Retain the review"))

    def test_only_the_tracking_job_can_write_issues_and_it_runs_after_failures(self):
        self.assertEqual(self.source.count("issues: write"), 1)
        self.assertIn("    permissions:\n      contents: read\n      issues: write\n", self.track)
        self.assertIn("    needs: scan\n    if: ${{ always() }}\n", self.track)
        self.assertIn("SCAN_RESULT: ${{ needs.scan.result }}", step(self.track, "Require every image to have been scanned"))

    def test_runner_jobs_are_bounded_and_actions_are_pinned(self):
        for block in (self.scan, self.track):
            self.assertRegex(block, r"(?m)^    timeout-minutes: [1-9][0-9]*$")
        for use in re.findall(r"(?m)^\s+uses: (\S+)", self.source):
            self.assertRegex(use, r"@[0-9a-f]{40}$")


class SeededRunTests(unittest.TestCase):
    """The workflow's seed, review and tracking steps for two manual seeded
    runs, against a stand-in `gh` that keeps its issues in a file."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.gh = self.root / "bin/gh"
        self.gh.parent.mkdir()
        self.gh.write_text(FAKE_GH)
        self.gh.chmod(0o755)
        self.state = self.root / "gh-state.json"
        self.scan = job("scan")
        self.track = job("track")

    def run_step(self, script: str, env: dict) -> dict[str, str]:
        output = Path(env["RUNNER_TEMP"]) / "github-output"
        output.write_text("")
        inherited = {key: value for key, value in os.environ.items()
                     if not key.startswith("GITHUB_") and key != "BHF_IMAGE_SCAN_MODE"}
        result = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", script], cwd=ROOT,
                                env={**inherited, **env, "GITHUB_OUTPUT": str(output)},
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return dict(line.split("=", 1) for line in output.read_text().splitlines() if "=" in line)

    def seeded_run(self, number: int) -> None:
        temp = self.root / f"run-{number}"
        evidence = temp / "image-scan-core"
        evidence.mkdir(parents=True)
        (evidence / "grype.json").write_text(json.dumps(grype_scan([])))
        (evidence / "image-inspect.json").write_text(json.dumps([{"Id": "sha256:" + "c" * 64}]))
        env = {"RUNNER_TEMP": str(temp), "IMAGE": "core", "GITHUB_ACTIONS": "true",
               "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF_TYPE": "branch",
               "GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/image-scan.yml@refs/heads/main",
               "GITHUB_STEP_SUMMARY": str(temp / "summary.md"), "GITHUB_REPOSITORY": "owner/repo",
               "RUN_URL": f"https://github.com/owner/repo/actions/runs/{number}",
               "GH": str(self.gh), "FAKE_GH_STATE": str(self.state)}
        self.run_step(step_script(step(self.scan, "Seed a synthetic blocker")), env)
        self.run_step(step_script(step(self.scan, "Review the scan")), env)
        # download-artifact puts each image's review in a directory of its name.
        downloaded = temp / "reviews/image-scan-core"
        downloaded.mkdir(parents=True)
        (downloaded / "release-review.json").write_bytes((evidence / "release-review.json").read_bytes())
        outputs = self.run_step(step_script(step(self.track, "Summarize the blockers")), env)
        self.assertEqual(outputs["blockers"], "1")
        self.run_step(step_script(step(self.track, "Open or update the tracking issue")),
                      {**env, "FINGERPRINT": outputs["fingerprint"]})

    def test_a_seeded_run_opens_one_issue_and_a_second_run_updates_it(self):
        self.seeded_run(1)
        [opened] = json.loads(self.state.read_text())["issues"]
        self.assertIn("SEEDED-IMAGE-SCAN-BLOCKER", opened["body"])
        self.assertIn("actions/runs/1", opened["body"])
        self.seeded_run(2)
        state = json.loads(self.state.read_text())
        [updated] = state["issues"]
        self.assertEqual(updated["number"], opened["number"])
        self.assertIn("actions/runs/2", updated["body"])
        self.assertEqual(updated["comments"], [], "the same blocker does not notify again")
        self.assertEqual(sum(call[:2] == ["issue", "create"] for call in state["calls"]), 1)
        self.assertEqual(sum(call[:2] == ["issue", "edit"] for call in state["calls"]), 1)


if __name__ == "__main__":
    unittest.main()
