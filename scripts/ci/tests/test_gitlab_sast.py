# SPDX-License-Identifier: Apache-2.0
"""bhf's GitLab SAST report validates against GitLab's security report schema.

`tests/fixtures/gitlab/gl-sast-report.json` is the report of the golden
findings document (`crates/results/tests/golden.rs` keeps it current), and
`sast-report-format.json` is GitLab's schema for the version it declares
(MIT, see the LICENSE.md beside it).
"""

import json
import unittest
from pathlib import Path

import jsonschema  # CI: pip install jsonschema (see .github/workflows/ci.yml)

ROOT = Path(__file__).resolve().parents[3]
GITLAB = ROOT / "tests" / "fixtures" / "gitlab"


def _validator():
    schema = json.loads((GITLAB / "sast-report-format.json").read_text())
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    return cls(schema, format_checker=cls.FORMAT_CHECKER)


def _errors(doc) -> list[str]:
    return [f"{'/'.join(map(str, e.absolute_path))}: {e.message}" for e in _validator().iter_errors(doc)]


class GitlabSastReportTest(unittest.TestCase):
    def setUp(self):
        self.report = json.loads((GITLAB / "gl-sast-report.json").read_text())

    def test_the_report_validates_against_gitlabs_schema(self):
        self.assertEqual(_errors(self.report), [])
        self.assertTrue(self.report["vulnerabilities"])

    def test_it_declares_the_vendored_schemas_version(self):
        schema = json.loads((GITLAB / "sast-report-format.json").read_text())
        self.assertEqual(self.report["version"], schema["self"]["version"])

    def test_a_report_without_identifiers_or_with_another_time_format_is_refused(self):
        bad = json.loads(json.dumps(self.report))
        bad["vulnerabilities"][0]["identifiers"] = []
        bad["scan"]["start_time"] = "2026-10-01T11:58:00Z"
        errors = " ".join(_errors(bad))
        self.assertIn("identifiers", errors)
        self.assertIn("start_time", errors)


class GitlabTemplateTest(unittest.TestCase):
    """The GitLab CI template runs `bhf ci` for the SAST widget and caches
    the corpus between pipelines."""

    def setUp(self):
        import yaml

        self.template = yaml.safe_load((ROOT / "ci" / "gitlab" / "bhf.gitlab-ci.yml").read_text())
        self.job = self.template["bhf"]
        self.script = "\n".join(self.job["script"])

    def test_the_job_writes_the_sast_report_gitlab_reads(self):
        self.assertIn("bhf ci", self.script)
        self.assertIn('--gitlab-sast "$CI_PROJECT_DIR/gl-sast-report.json"', self.script)
        self.assertEqual(self.job["artifacts"]["reports"]["sast"], "gl-sast-report.json")
        self.assertEqual(self.job["artifacts"]["when"], "always")

    def test_a_merge_request_is_scoped_to_its_changes(self):
        self.assertIn('--changed-since "origin/$target"', self.script)
        self.assertEqual(self.job["variables"]["GIT_DEPTH"], "0")
        sources = [rule["if"] for rule in self.job["rules"]]
        self.assertIn('$CI_PIPELINE_SOURCE == "merge_request_event"', sources)

    def test_the_cache_keeps_what_the_next_pipeline_continues(self):
        paths = self.job["cache"]["paths"]
        for kept in ("corpus", "discovery-cache.json", "regressions", "results/findings"):
            self.assertIn(f".bhf_work/{kept}", paths)
        self.assertEqual(self.job["cache"]["when"], "always")

    def test_a_scheduled_pipeline_sweeps_the_whole_tree_without_gating(self):
        schedule = next(rule for rule in self.job["rules"] if "schedule" in rule["if"])
        self.assertEqual(schedule["variables"], {"BHF_MODE": "batch", "BHF_PR_GATE": "never"})


if __name__ == "__main__":
    unittest.main()
