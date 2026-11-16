# SPDX-License-Identifier: Apache-2.0
import datetime as dt
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "review-image-scan.py"
ROOT = pathlib.Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("scan_review", SCRIPT)
review_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review_module)


class ScanReviewTests(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime(2026, 10, 4, 12, tzinfo=dt.timezone.utc)
        self.scan = {"descriptor": {"db": {"status": {"valid": True, "built": "2026-10-04T08:00:00Z"}}}, "matches": []}

    def add(self, severity, state="not-fixed"):
        self.scan["matches"].append({"vulnerability": {"id": "CVE-example", "severity": severity, "fix": {"state": state}},
                                     "artifact": {"name": "example", "version": "1"}})

    def test_no_matches_still_requires_review(self):
        self.assertEqual(review_module.review(self.scan, self.now)["decision"], "REQUIRES_PROTECTED_REVIEW")

    def test_high_and_unknown_block_without_fix(self):
        for severity in ("High", "Critical", "Unknown"):
            with self.subTest(severity=severity):
                self.scan["matches"] = []
                self.add(severity)
                self.assertEqual(review_module.review(self.scan, self.now)["decision"], "BLOCK")

    def test_fixable_medium_blocks(self):
        self.add("Medium", "fixed")
        self.assertEqual(review_module.review(self.scan, self.now)["decision"], "BLOCK")

    def test_unfixed_medium_is_retained_under_investigation(self):
        self.add("Medium")
        result = review_module.review(self.scan, self.now)
        self.assertEqual(result["residual_findings"][0]["status"], "under_investigation")
        self.assertEqual(result["decision"], "REQUIRES_PROTECTED_REVIEW")

    def test_stale_database_blocks(self):
        self.scan["descriptor"]["db"]["status"]["built"] = "2026-09-01T00:00:00Z"
        with self.assertRaises(ValueError):
            review_module.review(self.scan, self.now)

    def test_missing_scan_does_not_mean_zero_findings(self):
        del self.scan["matches"]
        with self.assertRaises(ValueError):
            review_module.review(self.scan, self.now)


def github_env(event, summary, **extra):
    """The variables GitHub Actions sets for a run of `event` on a branch."""
    return {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": event, "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/ci.yml@refs/heads/main",
            "GITHUB_STEP_SUMMARY": str(summary), **extra}


TAG = {"GITHUB_REF_TYPE": "tag", "GITHUB_REF": "refs/tags/v1.2.3",
       "GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/release.yml@refs/tags/v1.2.3"}
CONTAINER_RELEASE = {"GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/container-release.yml@refs/heads/main"}


class ScanGateModeTests(unittest.TestCase):
    """The scan's exit code: blockers fail tag, release and container-release
    runs (and any run outside GitHub Actions), but only report on pull
    requests and branch pushes, so an upstream CVE published after a change
    does not fail that change's CI."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.summary = self.root / "summary.md"
        built = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.scan = {"descriptor": {"db": {"status": {"valid": True, "built": built}}}, "matches": []}
        self.write_scan(blocker=True)
        (self.evidence / "image-inspect.json").write_text(json.dumps([{"Id": "sha256:" + "a" * 64}]))

    def write_scan(self, *, blocker):
        self.scan["matches"] = [{"vulnerability": {"id": "CVE-2026-0001", "severity": "High", "fix": {"state": "fixed", "versions": ["1.1"]}},
                                 "artifact": {"name": "widget", "version": "1.0", "purl": "pkg:deb/ubuntu/widget@1.0"}}] if blocker else []
        (self.evidence / "grype.json").write_text(json.dumps(self.scan))

    def run_review(self, *args, **env):
        inherited = {key: value for key, value in os.environ.items()
                     if not key.startswith("GITHUB_") and key != "BHF_IMAGE_SCAN_MODE"}
        return subprocess.run([sys.executable, str(SCRIPT), *args, str(self.evidence)],
                              env={**inherited, **env}, capture_output=True, text=True, timeout=60)

    def review(self):
        return json.loads((self.evidence / "release-review.json").read_text())

    def test_enforce_mode_fails_on_blockers(self):
        result = self.run_review("--mode", "enforce")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("BLOCK: 1 blockers, 0 residual matches", result.stdout)
        self.assertEqual(self.review()["decision"], "BLOCK")
        self.assertEqual(self.review()["enforcement"], "enforce")

    def test_enforce_mode_passes_a_scan_without_blockers(self):
        self.write_scan(blocker=False)
        result = self.run_review("--mode", "enforce")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.review()["decision"], "REQUIRES_PROTECTED_REVIEW")

    def test_report_only_mode_records_and_annotates_blockers_but_exits_zero(self):
        result = self.run_review("--mode", "report-only", **github_env("pull_request", self.summary))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        review = self.review()
        self.assertEqual(review["decision"], "BLOCK")
        self.assertEqual(review["enforcement"], "report-only")
        self.assertEqual([b["vulnerability"] for b in review["blockers"]], ["CVE-2026-0001"])
        self.assertIn("::warning title=Container image scan::", result.stdout)
        summary = self.summary.read_text()
        self.assertIn("report-only", summary)
        self.assertIn("| CVE-2026-0001 | widget | 1.0 | High | fixed in 1.1 |", summary)

    def test_pull_requests_and_branch_pushes_are_report_only(self):
        for event in ("pull_request", "push"):
            with self.subTest(event=event):
                (self.evidence / "release-review.json").unlink(missing_ok=True)
                result = self.run_review(**github_env(event, self.summary))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.review()["enforcement"], "report-only")
                self.assertEqual(self.review()["decision"], "BLOCK")

    def test_tag_release_and_container_release_runs_enforce_and_fail_on_blockers(self):
        cases = {
            "tag push": github_env("push", self.summary, **TAG),
            "release event": github_env("release", self.summary, **TAG),
            "untagged release event": github_env("release", self.summary),
            "container release": github_env("workflow_dispatch", self.summary, **CONTAINER_RELEASE),
            "container release on a tag": github_env("workflow_dispatch", self.summary, **CONTAINER_RELEASE, GITHUB_REF_TYPE="tag"),
        }
        for name, env in cases.items():
            # An explicit report-only request cannot relax a release gate.
            for request in ([], ["--mode", "auto"], ["--mode", "report-only"]):
                with self.subTest(run=name, request=request):
                    result = self.run_review(*request, **env)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertEqual(self.review()["enforcement"], "enforce")
            with self.subTest(run=name, request="BHF_IMAGE_SCAN_MODE=report-only"):
                result = self.run_review(**env, BHF_IMAGE_SCAN_MODE="report-only")
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_other_runs_enforce_by_default(self):
        cases = {
            "outside GitHub Actions": {},
            "manual CI run": github_env("workflow_dispatch", self.summary),
            "scheduled run": github_env("schedule", self.summary),
            "unknown event": github_env("merge_group", self.summary),
        }
        for name, env in cases.items():
            with self.subTest(run=name):
                result = self.run_review(**env)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(self.review()["enforcement"], "enforce")

    def test_mode_comes_from_the_environment_when_not_given(self):
        result = self.run_review(**github_env("schedule", self.summary), BHF_IMAGE_SCAN_MODE="report-only")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.review()["enforcement"], "report-only")

    def test_an_unknown_mode_is_refused(self):
        result = self.run_review(BHF_IMAGE_SCAN_MODE="warn")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.evidence / "release-review.json").exists())

    def test_a_scan_that_did_not_run_fails_in_report_only_mode(self):
        del self.scan["matches"]
        (self.evidence / "grype.json").write_text(json.dumps(self.scan))
        result = self.run_review("--mode", "report-only", **github_env("pull_request", self.summary))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing vulnerability matches", result.stderr)

    def test_ci_container_lanes_enforce_when_called_for_a_release(self):
        # release.yml and container-release.yml call ci.yml with force_full;
        # a tag run of it is a release too.
        source = (ROOT / ".github/workflows/ci.yml").read_text()
        for job in ("container-core", "container-full"):
            block = source.split(f"\n  {job}:\n", 1)[1].split("\n  container-", 1)[0].split("\n  rhel7-build:", 1)[0]
            with self.subTest(job=job):
                self.assertIn(
                    "      BHF_IMAGE_SCAN_MODE: ${{ (inputs.force_full || github.ref_type == 'tag') && 'enforce' || 'auto' }}\n",
                    block)
        for caller in ("release.yml", "container-release.yml"):
            with self.subTest(caller=caller):
                text = (ROOT / ".github/workflows" / caller).read_text()
                self.assertIn("    uses: ./.github/workflows/ci.yml\n", text)
                self.assertIn("      force_full: true\n", text)


if __name__ == "__main__":
    unittest.main()
