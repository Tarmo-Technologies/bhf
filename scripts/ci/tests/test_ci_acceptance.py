# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the fail-closed CI acceptance policy (stdlib only)."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "check-ci-acceptance.py"
SPEC = importlib.util.spec_from_file_location("ci_acceptance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)
SHA = "1234567890abcdef1234567890abcdef12345678"


def observation(heavy: str = "true") -> dict:
    jobs = {job: {"result": "success", "outputs": {}} for job in GATE.EXPECTED_JOBS}
    jobs["changes"]["outputs"]["heavy"] = heavy
    if heavy == "false":
        for job in GATE.HEAVY_JOBS:
            jobs[job]["result"] = "skipped"
    return jobs


class PolicyTests(unittest.TestCase):
    def evaluate(self, jobs: dict, **kwargs) -> dict:
        return GATE.evaluate(jobs, commit=SHA, event=kwargs.pop("event", "push"), **kwargs)

    def assert_blocked(self, jobs: dict, **kwargs) -> None:
        report = self.evaluate(jobs, **kwargs)
        self.assertEqual(report["decision"], "BLOCKED")
        self.assertFalse(report["accepted"])
        self.assertFalse(report["full_ci_passed"])
        self.assertTrue(report["blockers"])

    def test_full_success_is_not_enterprise_certification(self):
        report = self.evaluate(observation())
        self.assertEqual(report["decision"], "PASS_FULL_CI")
        self.assertTrue(report["full_ci_passed"])
        self.assertEqual(report["enterprise_readiness"], "not_assessed")
        self.assertEqual(report["commit"], SHA)
        self.assertFalse(report["blockers"])

    def test_docs_skip_is_not_a_full_pass(self):
        for event in ("push", "pull_request"):
            with self.subTest(event=event):
                report = self.evaluate(observation("false"), event=event)
                self.assertEqual(report["decision"], "PASS_DOCS_ONLY")
                self.assertTrue(report["accepted"])
                self.assertFalse(report["full_ci_passed"])

    def test_docs_scope_does_not_infer_full_pass_from_successes(self):
        jobs = observation()
        jobs["changes"]["outputs"]["heavy"] = "false"
        self.assertEqual(self.evaluate(jobs)["decision"], "PASS_DOCS_ONLY")

    def test_full_requirement_rejects_docs(self):
        self.assert_blocked(observation("false"), require_full=True)
        self.assert_blocked(observation("false"), event="workflow_dispatch")

    def test_manual_full_run_succeeds(self):
        self.assertEqual(self.evaluate(observation(), event="workflow_dispatch")["decision"], "PASS_FULL_CI")

    def test_every_required_job_blocks_on_failure_cancel_or_skip(self):
        for job in GATE.EXPECTED_JOBS:
            for result in ("failure", "cancelled", "skipped"):
                with self.subTest(job=job, result=result):
                    jobs = observation()
                    jobs[job]["result"] = result
                    self.assert_blocked(jobs)

    def test_docs_never_excuse_a_failed_or_cancelled_job(self):
        for job in GATE.EXPECTED_JOBS:
            for result in ("failure", "cancelled"):
                with self.subTest(job=job, result=result):
                    jobs = observation("false")
                    jobs[job]["result"] = result
                    self.assert_blocked(jobs)

    def test_docs_require_successful_classifier_and_policy_tests(self):
        for job in GATE.ALWAYS_REQUIRED:
            jobs = observation("false")
            jobs[job]["result"] = "skipped"
            self.assert_blocked(jobs)

    def test_every_missing_job_blocks_even_for_docs(self):
        for heavy in ("true", "false"):
            for job in GATE.EXPECTED_JOBS:
                with self.subTest(heavy=heavy, job=job):
                    jobs = observation(heavy)
                    del jobs[job]
                    self.assert_blocked(jobs)

    def test_new_jobs_require_a_policy_update(self):
        jobs = observation()
        jobs["new-platform"] = {"result": "success", "outputs": {}}
        self.assert_blocked(jobs)

    def test_malformed_job_observations_block(self):
        for malformed in (None, False, "success", [], 1):
            jobs = observation()
            jobs["build-test"] = malformed
            self.assert_blocked(jobs)

    def test_unknown_or_missing_job_results_block(self):
        for result in (None, "", "neutral", "pending", "in_progress", True, {}, []):
            jobs = observation()
            jobs["build-test"]["result"] = result
            self.assert_blocked(jobs)
        jobs = observation()
        jobs["build-test"].pop("result")
        self.assert_blocked(jobs)

    def test_invalid_classifier_outputs_cannot_authorize_skips(self):
        for heavy in (None, "", "False", False, True, 0, [], {}):
            jobs = observation("false")
            jobs["changes"]["outputs"]["heavy"] = heavy
            self.assert_blocked(jobs)
        for outputs in (None, False, [], "false", {}):
            jobs = observation("false")
            jobs["changes"]["outputs"] = outputs
            self.assert_blocked(jobs)

    def test_invalid_or_placeholder_commit_is_rejected(self):
        for commit in ("main", SHA[:7], "0" * 40, SHA.upper(), "g" * 40, SHA + "\n"):
            with self.subTest(commit=commit):
                with self.assertRaises(GATE.InvalidInput):
                    GATE.evaluate(observation(), commit=commit, event="push")

    def test_unknown_event_is_rejected(self):
        with self.assertRaises(GATE.InvalidInput):
            self.evaluate(observation(), event="workflow_run")

    def test_input_is_not_modified(self):
        jobs = observation()
        original = copy.deepcopy(jobs)
        self.evaluate(jobs)
        self.assertEqual(jobs, original)


class ParserTests(unittest.TestCase):
    def test_valid_object_roundtrip(self):
        jobs = observation()
        self.assertEqual(GATE.parse_observation(json.dumps(jobs).encode()), jobs)

    def test_malformed_or_ambiguous_json_is_rejected(self):
        for raw in (b"", b"[", b"[]", b"null", b"false", b"\xff", b'{"a":1,"a":2}',
                    b'{"a":{"result":"failure","result":"success"}}',
                    b'{"a":NaN}', b'{"a":Infinity}'):
            with self.subTest(raw=raw):
                with self.assertRaises(GATE.InvalidInput):
                    GATE.parse_observation(raw)

    def test_oversized_json_is_rejected(self):
        with self.assertRaises(GATE.InvalidInput):
            GATE.parse_observation(b" " * GATE.MAX_INPUT_BYTES + b"{}")

    def test_excessively_nested_json_is_rejected(self):
        with self.assertRaises(GATE.InvalidInput):
            GATE.parse_observation(b'{"a":' * 2000 + b"0" + b"}" * 2000)


class CliTests(unittest.TestCase):
    def invoke(self, *arguments: str, raw: str | None = None):
        env = dict(os.environ)
        env.pop("NEEDS_JSON", None)
        if raw is not None:
            env["NEEDS_JSON"] = raw
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--commit", SHA, "--event", "push", *arguments],
            env=env, capture_output=True, text=True, check=False, timeout=10,
        )

    def test_full_run_writes_a_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            result = self.invoke("--output", str(output), raw=json.dumps(observation()))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_text())["decision"], "PASS_FULL_CI")

    def test_failure_replaces_a_stale_success_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            output.write_text('{"accepted":true}')
            result = self.invoke("--output", str(output), raw="not-json")
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(json.loads(output.read_text())["decision"], "BLOCKED")
            self.assertEqual(list(Path(directory).iterdir()), [output])

    def test_missing_environment_is_not_success(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["decision"], "BLOCKED")

    def test_missing_file_writes_blocked_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            result = self.invoke("--needs-file", str(Path(directory) / "missing"), "--output", str(output))
            self.assertEqual(result.returncode, 1)
            self.assertFalse(json.loads(output.read_text())["accepted"])

    def test_file_input_and_require_full(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "jobs.json"
            source.write_text(json.dumps(observation("false")))
            self.assertEqual(self.invoke("--needs-file", str(source)).returncode, 0)
            self.assertEqual(self.invoke("--needs-file", str(source), "--require-full").returncode, 1)

    def test_oversized_file_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "jobs.json"
            source.write_bytes(b" " * (GATE.MAX_INPUT_BYTES + 1))
            result = self.invoke("--needs-file", str(source))
            self.assertEqual(result.returncode, 1)
            self.assertIn("input limit", result.stdout)

    def test_receipt_write_failure_is_nonzero(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.invoke("--output", directory, raw=json.dumps(observation()))
            self.assertEqual(result.returncode, 2)
            self.assertIn("Unable to write", result.stderr)


if __name__ == "__main__":
    unittest.main()
