# SPDX-License-Identifier: Apache-2.0
"""Run with python3 -m unittest discover -s docker -p 'test_*.py'."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from sweep_contract import manifest_rows, report_stats

DOCKER = Path(__file__).resolve().parent


def run_report(*, entered=True, stub=False, executions=3, partial=False):
    return {"schema_version": 1, "partial": partial, "targets": [{
        "stub_execution": {"stub_only": stub}, "outcome": {
            "outcome": "built_and_fuzzed", "passes": [{
                "executions": executions, "target_entry_observed": entered,
                "coverage_edges": 2, "findings": []}]}}]}


class SweepContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bhf-sweep-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = self.root / "manifest.tsv"
        self.revision = "a" * 40
        self.write_manifest()

    def write_manifest(self, name="fixture", revision=None, subpath="-", extra="-"):
        self.manifest.write_text("\t".join(("c", name, str(self.root / "origin"),
            revision or self.revision, subpath, extra)) + "\n")

    def stats(self, value):
        path = self.root / "report.json"
        path.write_text(json.dumps(value))
        return report_stats(path)

    def test_positive_evidence_and_zero_feedback(self):
        self.assertEqual(self.stats(run_report()), ("PASS", 1, 3, 2, 0))
        value = run_report()
        value["targets"][0]["outcome"]["passes"][0]["coverage_edges"] = 0
        self.assertEqual(self.stats(value), ("PASS", 1, 3, 0, 0))

    def test_stub_unentered_empty_and_zero_execution_do_not_pass(self):
        for value in (run_report(stub=True), run_report(entered=False),
                      run_report(executions=0), {"schema_version": 1, "partial": False, "targets": []}):
            with self.subTest(value=value):
                self.assertNotEqual(self.stats(value)[0], "PASS")

    def test_missing_stub_evidence_does_not_pass(self):
        value = run_report()
        del value["targets"][0]["stub_execution"]
        self.assertNotEqual(self.stats(value)[0], "PASS")

    def test_bad_counters_partial_and_unknown_schema_fail(self):
        for value in (run_report(executions=-1), run_report(executions=True), run_report(partial=True)):
            with self.assertRaises(ValueError):
                self.stats(value)
        value = run_report()
        value["schema_version"] = 2
        with self.assertRaises(ValueError):
            self.stats(value)

    def test_manifest_rejects_traversal_duplicates_and_unpinned_revisions(self):
        for kwargs in ({"name": "../../sentinel"}, {"subpath": "../outside"},
                       {"subpath": "/tmp"}, {"revision": "main"},
                       {"extra": "--work-dir /tmp/elsewhere"}):
            with self.subTest(kwargs=kwargs):
                self.write_manifest(**kwargs)
                with self.assertRaises(ValueError):
                    manifest_rows(self.manifest)
        self.write_manifest()
        self.manifest.write_text(self.manifest.read_text() * 2)
        with self.assertRaises(ValueError):
            manifest_rows(self.manifest)

    def command(self, script, **env):
        environment = dict(os.environ, BHF_SWEEP_MANIFEST=str(self.manifest),
            BHF_CORPUS=str(self.root / "corpus"), BHF_SWEEP_RESULTS=str(self.root / "results"),
            BHF_PER_TARGET_TIME="1", BHF_MAX_TARGETS="1", BHF_CAMPAIGN_TIME="1", BHF_JOBS="1",
            BHF_LANGS="")
        environment.update(env)
        return subprocess.run(["bash", str(DOCKER / script)], env=environment,
                              text=True, capture_output=True, timeout=30)

    def init_repo(self):
        origin = self.root / "origin"
        origin.mkdir()
        def git(*args):
            return subprocess.check_output(["git", "-C", str(origin), *args], stderr=subprocess.DEVNULL, text=True).strip()
        git("init")
        (origin / "target.c").write_text("int target(void) {return 0;}\n")
        git("add", "target.c")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "fixture")
        self.revision = git("rev-parse", "HEAD")
        self.write_manifest(subpath="", extra="")  # Empty TSV columns stay aligned.
        result = self.command("fetch-corpus.sh")
        self.assertEqual(result.returncode, 0, result.stderr)

    def install_fake_bhf(self, value):
        binary = self.root / "bin"
        binary.mkdir()
        report = self.root / "fixture.json"
        report.write_text(json.dumps(value))
        exe = binary / "bhf"
        exe.write_text("#!/usr/bin/env python3\nimport pathlib,sys,shutil\n"
            "if '--version' in sys.argv: print('bhf test fixture'); sys.exit(0)\n"
            "work=pathlib.Path(sys.argv[sys.argv.index('--work-dir')+1])\n"
            "(work/'auto').mkdir()\n"
            f"shutil.copyfile({str(report)!r},work/'auto'/'run.json')\n"
            "(work/'auto'/'summary.txt').write_text('0 stub-only; Executions: 999999')\n")
        exe.chmod(0o755)
        return str(binary) + os.pathsep + os.environ["PATH"]

    def test_real_fetch_preserves_existing_and_rejects_modified_checkout(self):
        self.init_repo()
        self.assertEqual(self.command("fetch-corpus.sh").returncode, 0)
        target = self.root / "corpus/c__fixture/target.c"
        target.write_text("user change")
        self.assertNotEqual(self.command("fetch-corpus.sh").returncode, 0)
        self.assertEqual(target.read_text(), "user change")

    def test_fetch_rejects_wrong_revision_without_checkout_or_delete(self):
        self.init_repo()
        self.write_manifest(revision="b" * 40)
        self.assertNotEqual(self.command("fetch-corpus.sh").returncode, 0)
        self.assertTrue((self.root / "corpus/c__fixture/target.c").is_file())

    def test_fetch_rejects_untracked_input_without_deleting_it(self):
        self.init_repo()
        extra = self.root / "corpus/c__fixture/extra.c"
        extra.write_text("untracked input")
        self.assertNotEqual(self.command("fetch-corpus.sh").returncode, 0)
        self.assertEqual(extra.read_text(), "untracked input")

    def test_sweep_uses_json_and_preserves_results_on_rerun(self):
        self.init_repo()
        path = self.install_fake_bhf(run_report())
        result = self.command("bhf-sweep.sh", PATH=path)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = self.root / "results/sweep-report.tsv"
        before = report.read_text()
        self.assertIn("\tPASS\t1\t3\t2\t0\t", before)
        self.assertNotEqual(self.command("bhf-sweep.sh", PATH=path).returncode, 0)
        self.assertEqual(report.read_text(), before)

    def test_sweep_stub_only_fails_even_with_large_text_execution_count(self):
        self.init_repo()
        result = self.command("bhf-sweep.sh", PATH=self.install_fake_bhf(run_report(stub=True)))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("STUB-ONLY", result.stdout)

    def test_empty_and_unknown_language_selection_fail_before_writes(self):
        self.manifest.write_text("# empty\n")
        self.assertNotEqual(self.command("bhf-sweep.sh").returncode, 0)
        self.assertFalse((self.root / "results").exists())
        self.write_manifest()
        result = self.command("bhf-sweep.sh", BHF_LANGS="bogus")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "results").exists())


if __name__ == "__main__":
    unittest.main()
