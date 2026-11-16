# SPDX-License-Identifier: Apache-2.0
"""Every CI job that runs nextest uses the `ci` profile, summarizes its JUnit
report (FLAKY and TIMEOUT tests included) and uploads it, even after a test
failure. The summary steps are run against a real nextest report."""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = Path(__file__).resolve().parent / "fixtures/nextest-junit.xml"
CI = ROOT / ".github/workflows/ci.yml"
NIGHTLY = ROOT / ".github/workflows/integration-nightly.yml"
UPLOAD = "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9"

# The jobs that run nextest, and the report each of their runs writes.
JOBS = {
    (CI, "build-test"): {"ci": "target/nextest/ci/junit.xml", "ci-release": "target/nextest/ci-release/junit.xml"},
    (CI, "doc-contracts"): {"ci": "target/nextest/ci/junit.xml"},
    (NIGHTLY, "integration"): {"ci": "target/nextest/ci/junit.xml"},
}


def job(workflow: Path, name: str) -> str:
    block = workflow.read_text().split(f"\n  {name}:\n", 1)[1]
    return re.split(r"\n  [a-z][a-z0-9-]*:\n", block, maxsplit=1)[0]


def steps(job_text: str) -> dict[str, str]:
    parts = re.split(r"(?m)^      - name: (.+)\n", job_text)
    return dict(zip(parts[1::2], parts[2::2]))


def run_script(step: str) -> str:
    body = step.split("        run: |\n", 1)[1] if "        run: |\n" in step else None
    if body is None:
        return re.search(r"(?m)^        run: (.+)$", step)[1] + "\n"
    lines = []
    for line in body.splitlines():
        if line.strip() and not line.startswith("          "):
            break
        lines.append(line)
    return textwrap.dedent("\n".join(lines)) + "\n"


class NextestReportTests(unittest.TestCase):
    def test_every_nextest_run_uses_a_ci_profile(self):
        for (workflow, name), reports in JOBS.items():
            text = job(workflow, name)
            profiles = re.findall(r"cargo nextest run [^\n]*?--profile (\S+)", text)
            runs = re.findall(r"cargo nextest run ", text)
            with self.subTest(job=name):
                self.assertEqual(len(profiles), len(runs), "a nextest run without --profile")
                self.assertEqual(set(profiles), set(reports))

    def test_reports_are_summarized_and_uploaded_after_failures_too(self):
        for (workflow, name), reports in JOBS.items():
            job_steps = steps(job(workflow, name))
            names = list(job_steps)
            with self.subTest(job=name):
                [summary] = [s for s in names if s.startswith("Summarize the nextest report")]
                [upload] = [s for s in names if s.startswith("Retain the nextest report")]
                tests = [i for i, s in enumerate(names) if "cargo nextest run " in job_steps[s]]
                self.assertGreater(names.index(summary), max(tests))
                self.assertGreater(names.index(upload), max(tests))
                for step in (summary, upload):
                    self.assertIn("        if: ${{ always() }}\n", job_steps[step])
                script = run_script(job_steps[summary])
                self.assertIn("scripts/ci/junit-summary.py", script)
                for path in reports.values():
                    self.assertIn(path, script)
                upload_step = job_steps[upload]
                self.assertIn(f"        uses: {UPLOAD}", upload_step)
                self.assertRegex(upload_step, r"(?m)^          path: target/nextest/\*/junit\.xml$")
                self.assertRegex(upload_step, r"(?m)^          name: junit-[a-z0-9{}$. -]+\$\{\{ github\.run_id \}\}")

    def test_the_nightly_names_each_shards_report(self):
        upload = steps(job(NIGHTLY, "integration"))["Retain the nextest report"]
        self.assertIn("${{ matrix.shard }}", re.search(r"(?m)^          name: (.+)$", upload)[1])

    def test_the_summary_step_lists_flaky_tests(self):
        for (workflow, name), reports in JOBS.items():
            job_steps = steps(job(workflow, name))
            [summary] = [s for s in job_steps if s.startswith("Summarize the nextest report")]
            with self.subTest(job=name), tempfile.TemporaryDirectory() as scratch:
                work = Path(scratch)
                (work / "scripts/ci").mkdir(parents=True)
                shutil.copy(ROOT / "scripts/ci/junit-summary.py", work / "scripts/ci/junit-summary.py")
                first = work / next(iter(reports.values()))
                first.parent.mkdir(parents=True)
                shutil.copy(FIXTURE, first)
                step_summary = work / "summary.md"
                result = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", run_script(job_steps[summary])],
                                        cwd=work, capture_output=True, text=True, timeout=30,
                                        env=dict(os.environ, GITHUB_STEP_SUMMARY=str(step_summary)))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("| FLAKY | `widget::cases::copy_at_is_flaky` |", step_summary.read_text())


if __name__ == "__main__":
    unittest.main()
