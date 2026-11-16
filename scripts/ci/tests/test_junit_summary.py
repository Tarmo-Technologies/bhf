# SPDX-License-Identifier: Apache-2.0
"""The nextest `ci` profile and the JUnit job summary.

The summary is checked against a real nextest JUnit report (the fixture), and
where cargo-nextest is installed the repository's own `ci` profile is run on a
scratch crate, with only its slow-timeout period shortened, to show that a
retried flaky test is reported FLAKY, a hung test is killed and reported, and
every test's captured output is kept.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
import xml.etree.ElementTree as ElementTree

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/ci/junit-summary.py"
FIXTURE = Path(__file__).resolve().parent / "fixtures/nextest-junit.xml"
NEXTEST_CONFIG = ROOT / ".config/nextest.toml"


def summarize(*paths: Path, env: dict | None = None) -> subprocess.CompletedProcess:
    inherited = {key: value for key, value in os.environ.items() if key != "GITHUB_STEP_SUMMARY"}
    return subprocess.run([sys.executable, str(SCRIPT), *map(str, paths)], env={**inherited, **(env or {})},
                          capture_output=True, text=True, timeout=30)


class JunitSummaryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.summary = self.root / "summary.md"

    def test_flaky_and_timed_out_tests_appear_in_the_job_summary(self):
        result = summarize(FIXTURE, env={"GITHUB_STEP_SUMMARY": str(self.summary)})
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = self.summary.read_text()
        self.assertIn("4 tests: 2 passed, 1 flaky, 1 failed (1 timed out), 0 skipped", summary)
        self.assertIn("| FLAKY | `widget::cases::copy_at_is_flaky` | passed on try 2 of 2 |", summary)
        self.assertIn("| TIMEOUT | `widget::cases::widget_hangs` | killed on every try (2) |", summary)
        self.assertNotIn("parse_record_passes", summary)
        self.assertIn("::warning title=Flaky test::widget::cases::copy_at_is_flaky passed on try 2 of 2", result.stdout)

    def test_without_a_step_summary_it_prints_the_summary(self):
        result = summarize(FIXTURE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("| FLAKY | `widget::cases::copy_at_is_flaky` |", result.stdout)

    def test_a_missing_report_is_named_and_only_all_missing_fails(self):
        missing = self.root / "never-written/junit.xml"
        result = summarize(FIXTURE, missing, env={"GITHUB_STEP_SUMMARY": str(self.summary)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"no report at `{missing}`", self.summary.read_text())
        result = summarize(missing)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no JUnit report", result.stderr)

    def test_a_clean_run_says_so(self):
        clean = self.root / "junit.xml"
        tree = ElementTree.parse(FIXTURE)
        suite = tree.getroot().find("testsuite")
        for case in list(suite):
            if case.get("name") != "parse_record_passes":
                suite.remove(case)
        tree.write(clean)
        result = summarize(clean, env={"GITHUB_STEP_SUMMARY": str(self.summary)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("1 tests: 1 passed, 0 flaky, 0 failed (0 timed out), 0 skipped", self.summary.read_text())
        self.assertNotIn("::warning", result.stdout)


class CiProfileTests(unittest.TestCase):
    def setUp(self):
        self.config = tomllib.loads(NEXTEST_CONFIG.read_text())
        self.ci = self.config["profile"]["ci"]

    def test_the_ci_profile_retries_kills_hangs_and_keeps_all_output(self):
        self.assertGreaterEqual(self.ci["retries"], 1)
        timeout = self.ci["slow-timeout"]
        period = int(re.fullmatch(r"(\d+)s", timeout["period"])[1])
        self.assertGreater(timeout["terminate-after"], 0)
        # A hang is killed well inside the 40-minute job, with time to retry.
        self.assertLessEqual(period * timeout["terminate-after"], 20 * 60)
        junit = self.ci["junit"]
        self.assertEqual(junit["path"], "junit.xml")
        self.assertIs(junit["store-success-output"], True)
        self.assertIs(junit["store-failure-output"], True)

    def test_the_slowest_test_gets_a_limit_inside_its_shards_timeout(self):
        [override] = [o for o in self.ci.get("overrides", [])
                      if o["filter"] == "binary(=build_recovery) & test(=build_recovery_scenarios)"]
        timeout = override["slow-timeout"]
        limit = int(timeout["period"].rstrip("s")) * timeout["terminate-after"]
        self.assertGreaterEqual(limit, 40 * 60)
        self.assertLess(limit, 55 * 60)
        self.assertEqual(override["retries"], 0)

    def test_the_heavy_test_group_still_applies(self):
        # Default-profile overrides apply to every profile.
        self.assertIn({"filter": "package(bhf) & kind(test)", "test-group": "heavy-bhf"},
                      self.config["profile"]["default"]["overrides"])
        self.assertNotIn("test-groups", self.ci)


def nextest_installed() -> bool:
    try:
        subprocess.run(["cargo", "nextest", "--version"], check=True, capture_output=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return False
    return True


SCRATCH_TESTS = r'''
use std::time::Duration;
#[test]
fn parse_record_passes() { println!("parse_record stdout"); eprintln!("parse_record stderr"); }
#[test]
fn copy_at_is_flaky() {
    let marker = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tried-once");
    if !marker.exists() { std::fs::write(&marker, b"").unwrap(); panic!("first try fails"); }
}
#[test]
fn widget_hangs() { std::thread::sleep(Duration::from_secs(120)); }
'''


def scratch_config() -> str:
    """The repository's nextest config for a crate that has none of bhf's test
    binaries: the overrides, which name them, are left out, and the `ci`
    profile's slow-timeout period is 1s."""
    kept, skipping = [], False
    for line in NEXTEST_CONFIG.read_text().splitlines():
        if line.startswith("["):
            skipping = line.strip().endswith(".overrides]]")
        if not skipping:
            kept.append(line)
    config, count = re.subn(r'(?m)^(slow-timeout = \{ period = )"\d+s"(, terminate-after = \d+ \})$',
                            r'\1"1s"\2', "\n".join(kept) + "\n")
    assert count == 1, config
    tomllib.loads(config)
    return config


@unittest.skipUnless(nextest_installed(), "cargo-nextest is not installed")
class CiProfileRunTests(unittest.TestCase):
    """The repository's `ci` profile on a scratch crate. Only the slow-timeout
    period is shortened (to 1s), so a hang is killed after `terminate-after`
    seconds instead of minutes."""

    def test_a_hang_is_killed_a_flake_is_flaky_and_output_is_kept(self):
        with tempfile.TemporaryDirectory() as scratch:
            crate = Path(scratch, "widget")
            (crate / "tests").mkdir(parents=True)
            (crate / "src").mkdir()
            (crate / "Cargo.toml").write_text('[package]\nname = "widget"\nversion = "0.1.0"\nedition = "2021"\n[workspace]\n')
            (crate / "src/lib.rs").write_text("")
            (crate / "tests/cases.rs").write_text(SCRATCH_TESTS)
            (crate / ".config").mkdir()
            (crate / ".config/nextest.toml").write_text(scratch_config())
            env = {key: value for key, value in os.environ.items() if not key.startswith("NEXTEST_")}
            env["CARGO_TARGET_DIR"] = str(crate / "target")
            run = subprocess.run(["cargo", "nextest", "run", "--profile", "ci"], cwd=crate, env=env,
                                 capture_output=True, text=True, timeout=600)
            self.assertNotEqual(run.returncode, 0, "a killed test fails the run")
            report = crate / "target/nextest/ci/junit.xml"
            self.assertTrue(report.is_file(), run.stderr)
            cases = {case.get("name"): case for case in ElementTree.parse(report).iter("testcase")}
            self.assertEqual(cases["widget_hangs"].find("failure").get("type"), "test timeout")
            self.assertIsNotNone(cases["copy_at_is_flaky"].find("flakyFailure"))
            self.assertIsNone(cases["copy_at_is_flaky"].find("failure"))
            passing = cases["parse_record_passes"]
            self.assertIn("parse_record stdout", passing.findtext("system-out"))
            self.assertIn("parse_record stderr", passing.findtext("system-err"))
            summary = Path(scratch, "summary.md")
            result = summarize(report, env={"GITHUB_STEP_SUMMARY": str(summary)})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("| FLAKY | `widget::cases::copy_at_is_flaky` |", summary.read_text())
            self.assertIn("| TIMEOUT | `widget::cases::widget_hangs` |", summary.read_text())
            shutil.rmtree(crate / "target", ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
