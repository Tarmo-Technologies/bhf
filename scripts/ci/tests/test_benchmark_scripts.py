# SPDX-License-Identifier: Apache-2.0
"""The benchmark scripts count the findings where `bhf auto` writes them.

`bhf auto` writes each finding to `<work>/results/findings/<id>/`. Each
script under benchmarks/ (the head-to-head `run_*.sh` and the CWE ones under
`cwe/`) is run here from a copy of the directory, against a stand-in `bhf`
that writes one finding the way the real one does, with the other fuzzers'
compilers replaced by ones that fail, so each script records its bhf row
and a build failure for the rest within seconds.
"""
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

# Writes one finding under the work dir's results/findings/, then the run
# summary, as `bhf auto` does; it stays running for a second in between so
# the scripts' polling sees the finding while bhf runs.
FAKE_BHF = textwrap.dedent("""\
    #!/usr/bin/env bash
    work=
    while [ $# -gt 0 ]; do
      case "$1" in --work-dir) work=$2; shift 2 ;; *) shift ;; esac
    done
    finding="$work/results/findings/F-0001"
    mkdir -p "$finding" "$work/auto"
    printf '%s' '{"id":"F-0001","harness_id":"H-PARSE-RECORD","classification":"crash","oracle":{"name":"native-assertion-contract"}}' >"$finding/finding.json"
    printf 'A' >"$finding/testcase.bin"
    sleep 1
    printf '%s' '{"targets":[{"outcome":{"passes":[{"findings":["F-0001"],"executions":100,"elapsed_secs":1.0}]}}]}' >"$work/auto/run.json"
    echo "parse_record: built+fuzzed, 1 finding"
""")
# The other fuzzers' build commands fail, so their rows read as build
# failures; gnatmake only has to be on PATH.
FAILING_TOOLS = ("clang", "afl-clang-fast", "afl-fuzz", "cargo", "javac")
NUMBER = re.compile(r"^\d*\.?\d+$")


class BenchmarkScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="bhf benchmark scripts ")
        work = Path(cls.tmp.name)
        cls.benchmarks = work / "benchmarks"
        shutil.copytree(ROOT / "benchmarks", cls.benchmarks,
                        ignore=shutil.ignore_patterns("campaign-*", "harness-parity-*", "engine-comparison"))
        bhf = work / "target/debug/bhf"
        bhf.parent.mkdir(parents=True)
        bhf.write_text(FAKE_BHF)
        bhf.chmod(0o755)
        tools = work / "tools"
        tools.mkdir()
        for name in FAILING_TOOLS:
            (tools / name).write_text("#!/bin/sh\nexit 1\n")
            (tools / name).chmod(0o755)
        (tools / "gnatmake").write_text("#!/bin/sh\nexit 0\n")
        (tools / "gnatmake").chmod(0o755)
        cls.env = dict(os.environ, PATH=f"{tools}{os.pathsep}{os.environ['PATH']}", BUDGET="1")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_script(self, script: str, result: str) -> list[list[str]]:
        """Run benchmarks/`script` and return the rows of its `result` TSV."""
        run = subprocess.run(["bash", str(self.benchmarks / script)], env=self.env,
                             capture_output=True, text=True, timeout=300)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        text = (self.benchmarks / "results" / result if "/" not in script
                else self.benchmarks / script.split("/")[0] / "results" / result).read_text()
        return [line.split("\t") for line in text.splitlines()]

    def assert_found_with_a_time(self, row: list[str]) -> None:
        self.assertEqual(row[3], "1", f"no finding counted: {row}")
        self.assertRegex(row[4], NUMBER, f"no time to first finding: {row}")

    def test_run_c_counts_each_engines_finding_and_its_time(self):
        rows = self.run_script("run_c.sh", "c.tsv")
        bhf = [row for row in rows if row[1].startswith("bhf(")]
        targets = sorted(path.stem for path in (ROOT / "benchmarks/targets/c").glob("*.c"))
        self.assertEqual(sorted({row[0] for row in bhf}), targets)
        self.assertEqual(sorted({row[1] for row in bhf}), ["bhf(afl++)", "bhf(builtin)"])
        for row in bhf:
            with self.subTest(row=row):
                self.assert_found_with_a_time(row)
                self.assertEqual(row[5], "100")

    def test_run_rust_counts_the_finding(self):
        rows = self.run_script("run_rust.sh", "rust.tsv")
        [row] = [row for row in rows if row[0].startswith("bhf")]
        self.assertEqual(row[0], "bhf(builtin)")
        self.assertEqual(row[:3], ["bhf(builtin)", "0", "1"])
        self.assertRegex(row[3], NUMBER)
        self.assertEqual(row[4], "100")

    def test_run_java_counts_the_finding_and_names_bhfs_engine(self):
        rows = self.run_script("run_java.sh", "java.tsv")
        [row] = [row for row in rows if row[0].startswith("bhf")]
        self.assertEqual(row[:3], ["bhf(builtin)", "0", "1"])
        self.assertRegex(row[3], NUMBER)

    def test_run_ada_counts_the_finding(self):
        rows = self.run_script("run_ada.sh", "ada.tsv")
        [row] = [row for row in rows if row[0].startswith("bhf")]
        self.assertEqual(row[:3], ["bhf(builtin)", "0", "1"])
        self.assertRegex(row[3], NUMBER)
        self.assertEqual(row[4], "100")

    def test_the_cwe_scripts_count_the_findings(self):
        for script, result, metric in [
            ("cwe/run_rust.sh", "rust_cwe.tsv", "buggy functions found (of 3)"),
            ("cwe/run_java.sh", "java_cwe.tsv", "buggy methods found (of 3)"),
            ("cwe/run_ada.sh", "ada_cwe.tsv", "buggy subprograms found (of 2)"),
        ]:
            with self.subTest(script=script):
                rows = {row[0]: row for row in self.run_script(script, result)}
                self.assertEqual(rows[metric][1], "1", rows[metric])

    def test_the_cwe_c_script_maps_the_finding_to_its_cwe(self):
        rows = {row[1]: row for row in self.run_script("cwe/run_c.sh", "c_cwe.tsv") if len(row) > 2}
        # The finding's oracle, native-assertion-contract, is CWE-617.
        self.assertEqual(rows["set_level"][:3], ["CWE-617", "set_level", "1"])
        self.assertEqual(rows["parse_header"][2], "0")

    def test_the_cwe_timing_script_times_the_first_finding(self):
        rows = self.run_script("cwe/run_timing.sh", "timing.tsv")[1:]
        self.assertEqual(len(rows), 2, rows)
        for row in rows:
            with self.subTest(row=row[0]):
                self.assertRegex(row[1], NUMBER, row)
                self.assertRegex(row[2], NUMBER, row)


if __name__ == "__main__":
    unittest.main()
