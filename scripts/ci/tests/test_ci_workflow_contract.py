# SPDX-License-Identifier: Apache-2.0
"""Guard this workflow's deliberately simple block-layout policy contract.

These are targeted source-contract checks, not a general YAML parser. A change
to the job-key/needs layout must update this helper rather than silently omitting
jobs from the policy. Shell behavior is tested by executing the actual step.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("ci_gate_contract", ROOT / "scripts/ci/check-ci-acceptance.py")
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def job_blocks(text: str) -> dict[str, str]:
    blocks: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.split("\njobs:\n", 1)[1].splitlines():
        if line and not line.startswith(" ") and not line.startswith("#"):
            raise AssertionError("unexpected top-level content after jobs; update contract parser")
        if line.startswith("  ") and not line.startswith("   ") and line.strip() and not line.lstrip().startswith("#"):
            match = re.fullmatch(r"  ([a-z][a-z0-9-]*):", line)
            if not match or match[1] in blocks:
                raise AssertionError("unsupported or duplicate job declaration; update contract parser")
            current = match[1]
            blocks[current] = []
        elif current is not None:
            blocks[current].append(line)
    return {key: "\n".join(value) for key, value in blocks.items()}


class WorkflowContractTests(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT / ".github/workflows/ci.yml").read_text()
        self.jobs = job_blocks(self.source)

    def test_every_job_is_in_the_acceptance_policy_and_needs(self):
        self.assertEqual(set(self.jobs) - {"ci-acceptance"}, GATE.EXPECTED_JOBS)
        gate = self.jobs["ci-acceptance"]
        needs = gate.split("    needs:\n", 1)[1].split("    runs-on:", 1)[0]
        ids = []
        for line in needs.splitlines():
            match = re.fullmatch(r"      - ([a-z][a-z0-9-]*)", line)
            self.assertIsNotNone(match, f"unsupported needs layout: {line!r}")
            ids.append(match[1])
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(ids), GATE.EXPECTED_JOBS)

    def test_gate_runs_after_failure_and_uses_same_run_observations(self):
        gate = self.jobs["ci-acceptance"]
        self.assertIn("    if: ${{ always() }}", gate)
        self.assertIn("NEEDS_JSON: ${{ toJSON(needs) }}", gate)
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', gate)
        self.assertIn('--commit "$GITHUB_SHA"', gate)
        self.assertIn("          if-no-files-found: error", gate)

    def test_policy_tests_cannot_be_documentation_skipped(self):
        self.assertNotRegex(self.jobs["ci-policy"], r"(?m)^    (if|needs):")
        self.assertIn("python3 -m unittest discover -s scripts/ci/tests -v", self.jobs["ci-policy"])

    def test_branch_push_and_manual_triggers_are_present(self):
        self.assertIn("    branches: [main, rtos-radar-fuzzing]", self.source)
        self.assertIn("  workflow_dispatch:\n", self.source)

    def test_all_ci_cargo_commands_use_the_lockfile(self):
        commands = re.findall(r"(?m)^\s*(?:run: )?cargo (?:\+\S+ )?(?:build|check|test|clippy) (.*)$", self.source)
        self.assertTrue(commands)
        for command in commands:
            self.assertIn("--locked", command)

    def test_windows_test_failures_are_checked_immediately(self):
        block = self.source.split("      - name: Test Windows-specific logic and daemon\n", 1)[1].split("      - name:", 1)[0]
        lines = block.splitlines()
        commands = 0
        for index, line in enumerate(lines):
            if line.strip().startswith("cargo test "):
                commands += 1
                self.assertEqual(lines[index + 1].strip(), "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }")
        self.assertEqual(commands, 3)

    def test_runner_jobs_are_bounded(self):
        for name, block in self.jobs.items():
            if "    runs-on:" in block:
                self.assertRegex(block, r"(?m)^    timeout-minutes: [1-9][0-9]*$", name)

    def test_no_continue_on_error_is_added(self):
        self.assertNotIn("continue-on-error:", self.source)


class ClassificationStepTests(unittest.TestCase):
    def run_step(self, *, event="push", diff_status=0, paths=("README.md",), refs_exist=True, base="a" * 40):
        workflow = (ROOT / ".github/workflows/classify-ci-scope.yml").read_text()
        step = workflow.split("      - name: Classify changed paths\n", 1)[1]
        script = textwrap.dedent(step.split("        run: |\n", 1)[1])
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "bin").mkdir()
            (work / "scripts/ci").mkdir(parents=True)
            classifier = work / "scripts/ci/should-run-heavy-ci.sh"
            classifier.write_bytes((ROOT / "scripts/ci/should-run-heavy-ci.sh").read_bytes())
            classifier.chmod(0o755)
            data = work / "paths.bin"
            data.write_bytes(b"".join(path.encode() + b"\0" for path in paths))
            git = work / "bin/git"
            git.write_text('''#!/usr/bin/env bash
set -eu
if [[ "$1" == cat-file ]]; then
  exit "$FAKE_REFS_STATUS"
fi
if [[ "$1" == diff ]]; then
  cat "$FAKE_PATHS"
  exit "$FAKE_DIFF_STATUS"
fi
exit 99
''')
            git.chmod(0o755)
            output = work / "output"
            summary = work / "summary"
            env = dict(os.environ, PATH=str(work / "bin") + os.pathsep + os.environ["PATH"],
                       EVENT_NAME=event, BASE_SHA=base, HEAD_SHA="b" * 40,
                       GITHUB_OUTPUT=str(output), GITHUB_STEP_SUMMARY=str(summary),
                       FAKE_REFS_STATUS="0" if refs_exist else "1", FAKE_DIFF_STATUS=str(diff_status),
                       FAKE_PATHS=str(data))
            result = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", script], cwd=work,
                                    env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            return output.read_text(), summary.read_text()

    def test_successful_docs_comparison_skips_heavy_jobs(self):
        output, _ = self.run_step()
        self.assertEqual(output, "heavy=false\n")

    def test_partial_failed_diff_cannot_authorize_docs_skip(self):
        for event in ("push", "pull_request"):
            with self.subTest(event=event):
                output, summary = self.run_step(event=event, diff_status=1, paths=("README.md",))
                self.assertEqual(output, "heavy=true\n")
                self.assertIn("comparison failed", summary)

    def test_manual_run_always_selects_full_ci(self):
        output, _ = self.run_step(event="workflow_dispatch", refs_exist=False)
        self.assertEqual(output, "heavy=true\n")

    def test_missing_refs_and_new_branch_select_full_ci(self):
        self.assertEqual(self.run_step(refs_exist=False)[0], "heavy=true\n")
        self.assertEqual(self.run_step(base="0" * 40)[0], "heavy=true\n")

    def test_empty_diff_selects_full_ci(self):
        self.assertEqual(self.run_step(paths=())[0], "heavy=true\n")

    def test_nul_delimited_names_are_preserved(self):
        output, _ = self.run_step(paths=("docs/a file.md", "tests/fixtures/two\nlines.md"))
        self.assertEqual(output, "heavy=true\n")


if __name__ == "__main__":
    unittest.main()
