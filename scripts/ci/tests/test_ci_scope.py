# SPDX-License-Identifier: Apache-2.0
"""Test actual shell classifier behavior, including test-fixture Markdown."""
from pathlib import Path
import subprocess
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "should-run-heavy-ci.sh"


class ScopeTests(unittest.TestCase):
    def classify(self, *paths: str) -> str:
        result = subprocess.run(
            ["bash", str(SCRIPT), *paths], capture_output=True, text=True,
            check=True, timeout=5,
        )
        self.assertEqual(result.stderr, "")
        return result.stdout.strip()

    def test_unknown_comparison_runs_full_ci(self):
        self.assertEqual(self.classify(), "true")

    def test_root_markdown_and_documentation_can_skip_heavy_ci(self):
        self.assertEqual(self.classify("README.md", "CHANGELOG.md", "docs/site/install.md"), "false")

    def test_website_builder_retains_its_existing_exemption(self):
        self.assertEqual(self.classify("scripts/docs/build-site.py", "docs/site/install.md"), "false")

    def test_source_fixture_and_benchmark_markdown_runs_full_ci(self):
        for path in ("crates/demo/README.md", "tests/fixtures/case.md", "benchmarks/result.md",
                     "vendor/example/readme.md", "python_runtime/input.md", "examples/input.md"):
            with self.subTest(path=path):
                self.assertEqual(self.classify(path), "true")

    def test_ci_files_always_run_full_ci(self):
        for path in (".github/workflows/ci.yml", ".github/actions/custom/README.md",
                     "scripts/ci/check-ci-acceptance.py"):
            with self.subTest(path=path):
                self.assertEqual(self.classify(path), "true")

    def test_code_and_machine_readable_evidence_under_docs_run_full_ci(self):
        for path in ("docs/test.py", "docs/acceptance.json", "docs/schema.yml", "docs/fixture.bin"):
            with self.subTest(path=path):
                self.assertEqual(self.classify(path), "true")

    def test_mixed_paths_run_full_ci_in_either_order(self):
        self.assertEqual(self.classify("README.md", "Cargo.toml"), "true")
        self.assertEqual(self.classify("Cargo.toml", "README.md"), "true")

    def test_spaces_and_newlines_do_not_split_arguments(self):
        self.assertEqual(self.classify("docs/a file.md"), "false")
        self.assertEqual(self.classify("tests/fixtures/two\nlines.md"), "true")

    def test_unknown_extensions_and_empty_names_run_full_ci(self):
        for path in ("", "new.file", "docs/new.format", "new_directory/readme.md"):
            with self.subTest(path=path):
                self.assertEqual(self.classify(path), "true")


if __name__ == "__main__":
    unittest.main()
