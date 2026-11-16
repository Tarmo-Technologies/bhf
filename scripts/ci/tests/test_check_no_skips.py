# SPDX-License-Identifier: Apache-2.0
"""check-no-skips.py: a test that prints a skip line fails the nightly unless
scripts/ci/allowed-skips.txt allows that line for that test.

A skip line is a captured stdout or stderr line that starts with `skip`,
`skipping`, `skipped` or `SKIP`, the form the bhf integration tests print when
a tool they need is missing and they return early as a pass. The reports
below are built from a real nextest JUnit report (the fixture)."""
from __future__ import annotations

import copy
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ElementTree

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/ci/check-no-skips.py"
ALLOWLIST = ROOT / "scripts/ci/allowed-skips.txt"
FIXTURE = Path(__file__).resolve().parent / "fixtures/nextest-junit.xml"
NIGHTLY = ROOT / ".github/workflows/integration-nightly.yml"


def junit(cases: dict[str, tuple[str, str]], path: Path) -> Path:
    """A nextest report whose `bhf::<binary>` suite has one passing test per
    entry of `cases` ("binary::test" -> (stdout, stderr)), in the fixture's
    shape."""
    tree = ElementTree.parse(FIXTURE)
    root = tree.getroot()
    template = root.find("testsuite/testcase[@name='parse_record_passes']")
    for suite in list(root):
        root.remove(suite)
    suites: dict[str, ElementTree.Element] = {}
    for key, (stdout, stderr) in cases.items():
        binary, name = key.rsplit("::", 1)
        suite = suites.get(binary)
        if suite is None:
            suite = suites[binary] = ElementTree.SubElement(root, "testsuite", name=f"bhf::{binary}")
        case = copy.deepcopy(template)
        case.set("name", name)
        case.set("classname", f"bhf::{binary}")
        case.find("system-out").text = stdout
        case.find("system-err").text = stderr
        suite.append(case)
    tree.write(path, encoding="utf-8", xml_declaration=True)
    return path


class CheckNoSkipsTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.summary = self.root / "summary.md"
        self.allowlist = self.root / "allowed-skips.txt"
        self.allowlist.write_text(
            "# The widget lane is not installed yet.\n"
            "bhf::widget_lane::*      skipping: no widget compiler*\n"
            "\n"
            "# Any test may skip for want of the gadget tool.\n"
            "*                        *gadget-cc*\n")
        (self.root / "empty.txt").write_text("")

    def check(self, *reports: Path, allowlist: Path | None = None) -> subprocess.CompletedProcess:
        env = dict(os.environ, GITHUB_STEP_SUMMARY=str(self.summary))
        return subprocess.run([sys.executable, str(SCRIPT), "--allowlist", str(allowlist or self.allowlist),
                               *map(str, reports)], env=env, capture_output=True, text=True, timeout=30)

    def test_a_non_allowlisted_skip_line_fails(self):
        report = junit({"auto_lua_lane::auto_builds_fuzzes_and_finds_divide_by_zero_cwe369":
                        ("running 1 test\n", "skipping: no lua on PATH (GNAT-less rule)\n")},
                       self.root / "junit.xml")
        result = self.check(report)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("::error title=Unexpected skip::bhf::auto_lua_lane::"
                      "auto_builds_fuzzes_and_finds_divide_by_zero_cwe369: skipping: no lua on PATH", result.stdout)
        self.assertIn("1 unexpected skip line", self.summary.read_text())

    def test_an_allowlisted_skip_line_passes(self):
        report = junit({"widget_lane::builds_the_widget": ("", "skipping: no widget compiler on PATH\n"),
                        "copy_at::copies": ("", "SKIP: gadget-cc not installed\n"),
                        "parse_record::parses": ("parse_record ok\n", "")},
                       self.root / "junit.xml")
        result = self.check(report)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("::error", result.stdout)
        summary = self.summary.read_text()
        self.assertIn("0 unexpected skip lines", summary)
        self.assertIn("2 allowed", summary)

    def test_the_allowlist_is_per_test_and_per_line(self):
        report = junit({"other_lane::builds": ("", "skipping: no widget compiler on PATH\n"),
                        "widget_lane::builds_the_widget": ("", "skip: widget runtime unavailable\n")},
                       self.root / "junit.xml")
        result = self.check(report)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.count("::error title=Unexpected skip::"), 2, result.stdout)

    def test_every_skip_line_form_is_caught_and_other_lines_are_not(self):
        lines = ["skip: a", "skipping: b", "SKIP: c", "Skipping d", "SKIP cli_widget: set BHF_WIDGET=1",
                 "  skipped e", "skipping widget e2e: f"]
        report = junit({f"widget_forms::form_{i}": ("", line + "\n") for i, line in enumerate(lines)} |
                       {"widget_forms::not_skips": ("test widget ... ok\nnot skipped: 0 targets\n",
                                                    "[2/3] parse_record ... skipped: could not auto-harness\n"
                                                    "skipper: a tool name\n")},
                       self.root / "junit.xml")
        result = self.check(report, allowlist=self.root / "empty.txt")
        self.assertEqual(result.returncode, 1)
        flagged = re.findall(r"::error title=Unexpected skip::bhf::widget_forms::(\w+):", result.stdout)
        self.assertEqual(sorted(flagged), sorted(f"form_{i}" for i in range(len(lines))))

    def test_a_flaky_tests_final_try_is_what_counts(self):
        # The fixture's flaky test skips nothing; its widget_skips test skips.
        result = self.check(FIXTURE, allowlist=self.root / "empty.txt")
        self.assertEqual(result.returncode, 1)
        self.assertIn("widget::cases::widget_skips: skipping: widget tool not installed", result.stdout)
        self.assertNotIn("copy_at_is_flaky", result.stdout)

    def test_a_missing_report_fails_rather_than_passing_vacuously(self):
        result = self.check(self.root / "never-written.xml")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no JUnit report", result.stderr)

    def test_a_malformed_allowlist_entry_is_refused(self):
        bad = self.root / "bad.txt"
        bad.write_text("bhf::widget_lane::*\n")
        result = self.check(FIXTURE, allowlist=bad)
        self.assertEqual(result.returncode, 2)
        self.assertIn("bad.txt:1", result.stderr)


class AllowlistTests(unittest.TestCase):
    """The repository's allowlist: the lanes the nightly does not install yet,
    and the tests other workflows run, and nothing broader."""

    def setUp(self):
        spec = importlib.util.spec_from_file_location("check_no_skips", SCRIPT)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.entries = self.module.load_allowlist(ALLOWLIST)

    def allowed(self, test: str, line: str) -> bool:
        return self.module.allowed(self.entries, test, line)

    def test_it_allows_the_lanes_the_next_slices_install(self):
        for test, line in (
            ("bhf::auto_ada_coverage::ada_lane", "SKIP: gnatmake/gprbuild not installed — Ada lane unavailable"),
            ("bhf::fork_server::ada_case", "skipping: no Ada compiler on PATH"),
            ("bhf::auto_afl_engine::auto_engine_afl_only", "skipping auto_engine_afl_only: afl-fuzz/afl-clang-fast not on PATH"),
            ("bhf::auto_cobol::cobol_lane", "skip: needs cobc (GnuCOBOL) + clang + make"),
            ("bhf::windows_cross_fixture::wine_case", "skipping: requires x86_64-w64-mingw32-gcc and wine"),
            ("bhf::toolchain_config_cli::cross_case", "skip: aarch64-linux-gnu-gcc/qemu-aarch64/make unavailable"),
        ):
            with self.subTest(line=line):
                self.assertTrue(self.allowed(test, line))

    def test_it_does_not_allow_the_lanes_the_nightly_installs(self):
        for test, line in (
            ("bhf::auto_lua_lane::lua_case", "skipping: no lua on PATH (GNAT-less rule)"),
            ("bhf::auto_php_lane::php_case", "skipping: no php on PATH (GNAT-less rule)"),
            ("bhf::auto_ruby_lane::ruby_case", "skipping: no ruby on PATH (GNAT-less rule)"),
            ("bhf::auto_perl_lane::perl_case", "skipping: no perl on PATH (GNAT-less rule)"),
            ("bhf::auto_java_fuzz::java_case", "skip: no JDK (native Java lane needs javac/java)"),
            ("bhf::auto_ts_toolchain::ts_case", "skipping: node unavailable"),
            ("bhf::capsule_lanes_cli::typescript_case", "skipping: esbuild not installed"),
            ("bhf::transport_fuzz_qemu_cli::cli_qemu_system_transport_persists_a_classified_fault_finding",
             "SKIP cli_qemu_system_transport_persists_a_classified_fault_finding: qemu-system-arm not on PATH"),
            ("bhf::env_capsule_cli::env_capsule_replays_environment_driven_crash", "skipping: runtrace shim not built in /x"),
            ("bhf::auto_go_lane::go_case", "skipping: no go toolchain on PATH (GNAT-less rule)"),
            ("bhf::auto_c_common_cli::c_case", "skip: clang/make unavailable"),
        ):
            with self.subTest(line=line):
                self.assertFalse(self.allowed(test, line))

    def test_every_entry_has_a_reason_and_names_a_specific_line(self):
        lines = ALLOWLIST.read_text().splitlines()
        for number, line in enumerate(lines, 1):
            if not line.strip() or line.startswith("#"):
                continue
            with self.subTest(line=line):
                block = lines[:number - 1]
                self.assertTrue(any(previous.startswith("# ") for previous in block[-6:]), line)
                test_glob, line_glob = line.split(None, 1)
                self.assertNotIn(line_glob.strip(), ("*", "*skip*", "*skipping*"))


class NightlySkipCheckTests(unittest.TestCase):
    def setUp(self):
        source = NIGHTLY.read_text()
        block = source.split("\n  integration:\n", 1)[1]
        self.job = re.split(r"\n  [a-z][a-z0-9-]*:\n", block, maxsplit=1)[0]
        self.steps = re.findall(r"(?m)^      - name: (.+)$", self.job)

    def step(self, name: str) -> str:
        return self.job.split(f"      - name: {name}\n", 1)[1].split("\n      - name:", 1)[0]

    def test_the_nightly_fails_on_unexpected_skip_lines_after_the_tests(self):
        name = "Fail on unexpected skip lines"
        self.assertLess(self.steps.index("Integration tests (shard ${{ matrix.shard }})"), self.steps.index(name))
        step = self.step(name)
        self.assertIn("        if: ${{ always() }}\n", step)
        self.assertIn("python3 scripts/ci/check-no-skips.py --allowlist scripts/ci/allowed-skips.txt "
                      "target/nextest/ci/junit.xml", step)

    def test_the_nightly_installs_the_interpreter_and_emulator_toolchains(self):
        install = self.step("Install the interpreter and emulator toolchains")
        for package in ("lua5.4", "php-cli", "php-pcov", "ruby", "perl", "qemu-system-arm", "qemu-utils",
                        "gcc-arm-none-eabi", "libnewlib-arm-none-eabi"):
            with self.subTest(package=package):
                self.assertRegex(install, rf"(?m)(^|\s){re.escape(package)}(\s|$)")
        self.assertLess(self.steps.index("Install the interpreter and emulator toolchains"),
                        self.steps.index("Integration tests (shard ${{ matrix.shard }})"))
        for tool in ("lua5.4", "php", "ruby", "perl", "java", "javac", "node", "esbuild",
                     "qemu-system-arm", "qemu-img", "arm-none-eabi-gcc"):
            with self.subTest(tool=tool):
                self.assertIn(tool, self.step("Check the installed toolchains"))
        self.assertIn("pcov", self.step("Check the installed toolchains"))
        self.assertIn("java-version: 21", self.step("Install a JDK"))
        self.assertIn("node-version: 24", self.step("Install Node"))

    def test_the_tests_run_with_the_tools_required(self):
        shard = self.step("Integration tests (shard ${{ matrix.shard }})")
        self.assertIn('          BHF_REQUIRE_TOOLS: "1"\n', shard)


if __name__ == "__main__":
    unittest.main()
