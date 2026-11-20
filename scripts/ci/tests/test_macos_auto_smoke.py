# SPDX-License-Identifier: Apache-2.0
"""Run the macOS auto smoke against a stand-in bhf.

The stand-in writes the run outputs a real `bhf auto` would, so what is under
test is the smoke's own checks: the planted overflow was found, and the run,
its fuzzed target and the finding all record that no runtrace shim is built
for macOS.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/ci/macos-auto-smoke.sh"
REASON = ("the runtrace shim is built for Linux only (it is loaded with LD_PRELOAD), "
          "so on macos bhf runs native harnesses without it")
SHIM_GAP = {"status": "not_exercised", "reason": REASON}

PROGRAM = """#!/bin/bash
set -eu
work=""
while [ $# -gt 0 ]; do
  case "$1" in --work-dir) work=$2; shift ;; esac
  shift
done
mkdir -p "$work"
cp -R "$FAKE_WORK/." "$work"
"""


def outputs() -> dict[str, object]:
    """What `bhf auto` writes for the planted overflow on macOS."""
    return {
        "auto/run.json": {
            "summary": {
                "built_and_fuzzed": 1,
                "fidelity": {"dimensions": {"runtime_shim": SHIM_GAP}},
            },
            "targets": [
                {"harness_id": "H-RECORD", "fidelity": {"runtime_shim": SHIM_GAP}},
                {"harness_id": "H-SKIPPED"},
            ],
        },
        "results/findings.json": {"findings": [{"rule": {"id": "BHF-203"}}]},
        "results/findings/F-0001/finding.json": {
            "id": "F-0001",
            "rule_id": "BHF-203",
            "fidelity": {"runtime_shim": SHIM_GAP},
            "runtime_mode": {"pass": "empty", "shim_armed": False},
        },
    }


class MacosAutoSmokeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.bhf = self.bin / "bhf"
        self.bhf.write_text(PROGRAM)
        self.bhf.chmod(0o755)

    def smoke(self, files: dict[str, object]) -> subprocess.CompletedProcess[str]:
        work = self.root / "fake-work"
        for name, value in files.items():
            path = work / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value))
        env = dict(os.environ, FAKE_WORK=str(work))
        return subprocess.run(["bash", str(SCRIPT), str(self.bhf)], env=env,
                              capture_output=True, text=True, timeout=60)

    def test_an_overflow_found_without_the_shim_passes(self):
        result = self.smoke(outputs())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("found without the runtrace shim: BHF-203", result.stdout)

    def test_no_planted_overflow_fails(self):
        files = outputs()
        files["results/findings.json"] = {"findings": [{"rule": {"id": "BHF-999"}}]}
        self.assertNotEqual(self.smoke(files).returncode, 0)

    def test_a_record_without_the_shim_unavailable_fidelity_fails(self):
        for where in ("target", "summary", "finding"):
            with self.subTest(where=where):
                files = copy.deepcopy(outputs())
                run = files["auto/run.json"]
                if where == "target":
                    del run["targets"][0]["fidelity"]["runtime_shim"]
                elif where == "summary":
                    run["summary"]["fidelity"]["dimensions"] = {}
                else:
                    del files["results/findings/F-0001/finding.json"]["fidelity"]["runtime_shim"]
                self.assertNotEqual(self.smoke(files).returncode, 0)

    def test_a_reason_that_is_not_the_platform_fails(self):
        files = copy.deepcopy(outputs())
        files["auto/run.json"]["targets"][0]["fidelity"]["runtime_shim"]["reason"] = (
            "the runtrace shim was not found beside /opt/bhf/bin")
        self.assertNotEqual(self.smoke(files).returncode, 0)

    def test_a_finding_fuzzed_with_the_shim_fails(self):
        files = copy.deepcopy(outputs())
        files["results/findings/F-0001/finding.json"]["runtime_mode"]["shim_armed"] = True
        self.assertNotEqual(self.smoke(files).returncode, 0)

    def test_a_shim_beside_bhf_fails(self):
        (self.bin / "libbhf_runtrace_shim.so").write_text("shim")
        result = self.smoke(outputs())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no shim is built for macOS", result.stderr)


if __name__ == "__main__":
    unittest.main()
