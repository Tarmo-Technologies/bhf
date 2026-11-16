# SPDX-License-Identifier: Apache-2.0
"""The fast release and documentation contract tests run on every change.

These tests read README.md, INSTALL.md, docs/site/*.md and the release
workflows, and finish in seconds, but used to run only in the nightly: a
contract broke main twice, and a documentation-only change skipped them
entirely. build-test runs them for a code change; the doc-contracts lane runs
them for a documentation-only change. The classifier step is run with a
stand-in git, so the lane a path selects is the workflow's own answer.
"""
from __future__ import annotations

import fnmatch
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[3]
CI = ROOT / ".github/workflows/ci.yml"
TESTS = ROOT / "crates/cli/tests"

# Each fast contract and the repository file it reads, which a change to that
# file alone must still test.
CONTRACTS = {
    "m19_docs_cli_examples": "docs/site/cli.md",
    "m19_signed_releases": "docs/site/install.md",
    "m19_docs_site": "docs/site/index.md",
    "offline_dist_scripts": "docs/site/offline-auto-runbook.md",
    "release_bundle_manifest": "README.md",
}
# Tests in other binaries that read a guide.
GUIDE_TESTS = {
    "custom_harness_flow": ("the_guides_do_not_repeat_retired_claims",
                            "the_sanitizer_guide_says_which_emulated_children_name_each_key_once"),
}
LIB_GUIDE_TESTS = ("the_docs_list_every_config_key", "the_help_and_docs_list_every_cross_lane")


def job(name: str) -> str:
    block = CI.read_text().split(f"\n  {name}:\n", 1)[1]
    return re.split(r"\n  [a-z][a-z0-9-]*:\n", block, maxsplit=1)[0]


def nextest_filter(job_text: str) -> str:
    [command] = re.findall(r"(?m)^\s+run: cargo nextest run --locked (?:--workspace|-p bhf) .*$", job_text)
    return re.search(r"-E '([^']+)'", command)[1]


def selected(job_text: str, heavy: str) -> bool:
    """Whether `job_text`'s `if:` runs the job for classifier output `heavy`."""
    condition = re.search(r"(?m)^    if: (.+)$", job_text)[1]
    match = re.fullmatch(r"needs\.changes\.outputs\.heavy == '(true|false)'", condition)
    assert match, f"unsupported lane condition: {condition}"
    return heavy == match[1]


def binary_matches(term: str, binary: str) -> bool:
    if term.startswith("="):
        return term[1:] == binary
    assert term.startswith("/") and term.endswith("/"), term
    return re.search(term[1:-1], binary) is not None


def filter_selects(expression: str, binary: str, test: str | None = None) -> bool:
    """Whether one of `expression`'s alternatives (as these lanes write them:
    `binary(...)`, or `(binary(...) & test(...))`, or `(kind(lib) & test(...))`)
    selects `test` in `binary`, or every test of `binary` when `test` is None."""
    for alternative in re.split(r" \| (?![^()]*\))", expression):
        alternative = alternative.strip()
        if alternative.startswith("(") and alternative.endswith(")"):
            alternative = alternative[1:-1]
        terms = dict(re.findall(r"([a-z]+)\(([^()]*)\)", alternative))
        if "binary" in terms and not binary_matches(terms["binary"], binary):
            continue
        if "kind" in terms and not (terms["kind"] == "lib" and binary == "bhf"):
            continue
        if "binary" not in terms and "kind" not in terms:
            continue
        if "test" in terms and (test is None or not binary_matches(terms["test"], test)):
            continue
        return True
    return False


def classify(*paths: str) -> str:
    """The `heavy` output the classifier step writes for a change to `paths`."""
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
        (work / "paths.bin").write_bytes(b"".join(path.encode() + b"\0" for path in paths))
        git = work / "bin/git"
        git.write_text('#!/usr/bin/env bash\nif [[ "$1" == diff ]]; then cat "$FAKE_PATHS"; fi\n')
        git.chmod(0o755)
        output = work / "output"
        env = dict(os.environ, PATH=f"{work / 'bin'}{os.pathsep}{os.environ['PATH']}", EVENT_NAME="pull_request",
                   BASE_SHA="a" * 40, HEAD_SHA="b" * 40, GITHUB_OUTPUT=str(output),
                   GITHUB_STEP_SUMMARY=str(work / "summary"), FAKE_PATHS=str(work / "paths.bin"))
        subprocess.run(["bash", "-e", "-o", "pipefail", "-c", script], cwd=work, env=env,
                       check=True, capture_output=True, timeout=10)
        return re.fullmatch(r"heavy=(true|false)\n", output.read_text())[1]


class DocContractLaneTests(unittest.TestCase):
    def setUp(self):
        self.build_test = job("build-test")
        self.docs = job("doc-contracts")
        self.pr_filter = nextest_filter(self.build_test)
        self.doc_filter = nextest_filter(self.docs)

    def test_a_change_to_only_docs_site_cli_md_selects_the_doc_contract_lane(self):
        heavy = classify("docs/site/cli.md")
        self.assertEqual(heavy, "false")
        self.assertTrue(selected(self.docs, heavy))
        self.assertFalse(selected(self.build_test, heavy))
        self.assertTrue(filter_selects(self.doc_filter, "m19_docs_cli_examples"))

    def test_each_contract_runs_for_a_change_to_only_the_file_it_reads(self):
        for binary, path in CONTRACTS.items():
            with self.subTest(binary=binary, path=path):
                self.assertTrue((ROOT / path).is_file(), path)
                self.assertIn(path, (TESTS / f"{binary}.rs").read_text())
                heavy = classify(path)
                lane = self.docs if selected(self.docs, heavy) else self.build_test
                self.assertTrue(selected(lane, heavy))
                self.assertTrue(filter_selects(nextest_filter(lane), binary), (binary, heavy))

    def test_a_code_change_runs_the_contracts_in_build_test(self):
        heavy = classify("crates/cli/src/lib.rs")
        self.assertEqual(heavy, "true")
        self.assertTrue(selected(self.build_test, heavy))
        self.assertFalse(selected(self.docs, heavy))

    def test_the_per_pr_filter_includes_the_fast_contract_binaries(self):
        binaries = sorted(path.stem for path in TESTS.glob("m19_*.rs")) + ["offline_dist_scripts",
                                                                           "release_bundle_manifest"]
        self.assertGreaterEqual(len(binaries), 6)
        for lane_filter in (self.pr_filter, self.doc_filter):
            for binary in binaries:
                with self.subTest(binary=binary, lane=lane_filter[:40]):
                    self.assertTrue(filter_selects(lane_filter, binary))
            for binary, tests in GUIDE_TESTS.items():
                source = (TESTS / f"{binary}.rs").read_text()
                for test in tests:
                    with self.subTest(binary=binary, test=test):
                        self.assertIn(f"fn {test}()", source)
                        self.assertTrue(filter_selects(lane_filter, binary, f"linux::{test}"))
                        self.assertFalse(filter_selects(lane_filter, binary, "linux::fuzz_to_finding_x"))
        # The heavy lane already runs every bhf library test; the doc lane
        # runs the two that read a guide.
        config = (ROOT / "crates/cli/src/auto/config.rs").read_text()
        for test in LIB_GUIDE_TESTS:
            with self.subTest(test=test):
                self.assertIn(f"fn {test}()", config)
                self.assertTrue(filter_selects(self.doc_filter, "bhf", f"auto::config::tests::{test}"))
        self.assertFalse(filter_selects(self.doc_filter, "bhf", "auto::config::tests::list_and_selection_keys"))
        self.assertFalse(filter_selects(self.doc_filter, "auto_c_common_cli"))

    def test_the_doc_lane_builds_only_and_every_contract_binary(self):
        [command] = re.findall(r"(?m)^\s+run: (cargo nextest run --locked -p bhf .*)$", self.docs)
        words = shlex.split(command.split(" -E ", 1)[0])
        targets = [words[i + 1] for i, word in enumerate(words) if word == "--test"]
        self.assertIn("--lib", words)
        self.assertNotIn("--workspace", words)
        binaries = [path.stem for path in TESTS.glob("*.rs")]
        built = sorted(binary for binary in binaries if any(fnmatch.fnmatchcase(binary, t) for t in targets))
        wanted = sorted(binary for binary in binaries if filter_selects(self.doc_filter, binary)
                        or binary in GUIDE_TESTS)
        self.assertEqual(built, wanted)
        self.assertLess(len(built), 20, "the lane builds a handful of binaries, not the suite")

    def test_the_doc_lane_is_bounded_and_has_its_tools(self):
        self.assertIn("    needs: changes\n", self.docs)
        self.assertRegex(self.docs, r"(?m)^    timeout-minutes: [1-9][0-9]*$")
        steps = re.findall(r"(?m)^      - name: (.+)$", self.docs)
        self.assertLess(steps.index("Install cargo-nextest"), steps.index("Test the release and docs contracts"))
        self.assertIn("toolchain: 1.99.0", self.docs)


if __name__ == "__main__":
    unittest.main()
