# SPDX-License-Identifier: Apache-2.0
"""Source contract for the nightly integration shards.

The nightly runs every bhf integration test once, split across matrix shards
that each have to finish inside the job timeout. These checks run the shard
step's real script with a recording stand-in for `cargo`, so a change to the
matrix or the split cannot silently drop tests, run one twice, or put the
slowest test back into a shard with others. Where cargo-nextest is installed,
the recorded commands are also handed to `cargo nextest list`, so what each
shard selects is nextest's own answer, not a reading of the filter strings.
"""
from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github/workflows/integration-nightly.yml"
SLOW = "binary(=build_recovery) & test(=build_recovery_scenarios)"
DEDICATED = "build-recovery-scenarios"
# The shard that runs the #[ignore]d tests the nightly owns, and their filter.
IGNORED = "ignored"
IGNORED_FILTER = "binary(=auto_lua_hook)"


def integration_job() -> str:
    source = WORKFLOW.read_text()
    block = source.split("\n  integration:\n", 1)[1]
    return re.split(r"\n  [a-z][a-z0-9-]*:\n", block, maxsplit=1)[0]


def shard_step(job: str) -> str:
    return job.split("      - name: Integration tests (shard ${{ matrix.shard }})\n", 1)[1].split(
        "\n      - name:", 1
    )[0]


def matrix_shards(job: str) -> list[str]:
    match = re.search(r"\n        shard: \[([^\]]*)\]\n", job)
    assert match, "the integration job lists its shards on one `shard: [...]` line"
    return [value.strip().strip('"') for value in match[1].split(",")]


def step_env(step: str) -> dict[str, str]:
    env_block = step.split("        env:\n", 1)[1].split("        run: |\n", 1)[0]
    return {
        key: value.strip().strip('"')
        for key, value in re.findall(r"^          ([A-Z_]+): (.+)$", env_block, re.M)
    }


def step_script(step: str) -> str:
    body = step.split("        run: |\n", 1)[1]
    lines = []
    for line in body.splitlines():
        if line.strip() and not line.startswith("          "):
            break
        lines.append(line[10:])
    return "\n".join(lines) + "\n"


def run_shard_argv(script: str, env: dict[str, str], shard: str) -> list[list[str]]:
    """The arguments the step hands to `cargo` for `shard`, one list per call."""
    with tempfile.TemporaryDirectory() as scratch:
        bin_dir = Path(scratch, "bin")
        bin_dir.mkdir()
        log = Path(scratch, "cargo.log")
        stub = bin_dir / "cargo"
        stub.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "with open(os.environ['CARGO_LOG'], 'a') as log:\n"
            "    log.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        values = {
            key: value.replace("${{ matrix.shard }}", shard) for key, value in env.items()
        }
        subprocess.run(
            ["bash", "-c", script],
            check=True,
            env={
                **os.environ,
                **values,
                "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
                "CARGO_LOG": str(log),
            },
        )
        return [json.loads(line) for line in log.read_text().splitlines()]


def run_shard(script: str, env: dict[str, str], shard: str) -> list[str]:
    """The command lines the step hands to `cargo` for `shard`, one per call."""
    return [" ".join(argv) for argv in run_shard_argv(script, env, shard)]


def nextest_installed() -> bool:
    try:
        subprocess.run(
            ["cargo", "nextest", "--version"], check=True, capture_output=True, timeout=120
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def nextest_selection(argv: list[str]) -> set[str]:
    """The tests the `cargo nextest run` call `argv` runs, as `cargo nextest
    list` with the same arguments reports them (`<binary id>::<test>`)."""
    assert argv[:2] == ["nextest", "run"], argv
    args = ["nextest", "list"] + [arg for arg in argv[2:] if arg != "--no-fail-fast"]
    listed = subprocess.run(
        ["cargo", *args, "--message-format", "json"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=3600,
    )
    document = json.loads(listed.stdout)
    return {
        f"{suite}::{name}"
        for suite, tests in document["rust-suites"].items()
        for name, case in tests["testcases"].items()
        if case["filter-match"]["status"] == "matches"
    }


class IntegrationNightlyShardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.job = integration_job()
        self.step = shard_step(self.job)
        self.env = step_env(self.step)
        self.script = step_script(self.step)
        self.shards = matrix_shards(self.job)

    def test_the_matrix_is_every_hash_shard_once_plus_the_dedicated_one(self) -> None:
        count = int(self.env["HASH_SHARDS"])
        self.assertGreaterEqual(count, 12, "the suite outgrew 6 shards of 40 minutes")
        self.assertEqual(
            self.shards, [str(n) for n in range(1, count + 1)] + [DEDICATED, IGNORED]
        )
        self.assertEqual(self.env["SHARD"], "${{ matrix.shard }}")

    def test_each_hash_shard_runs_its_partition_of_everything_but_the_slowest_test(self) -> None:
        count = int(self.env["HASH_SHARDS"])
        for shard in self.shards[:-2]:
            with self.subTest(shard=shard):
                calls = run_shard(self.script, self.env, shard)
                self.assertEqual(len(calls), 1, calls)
                call = calls[0]
                self.assertTrue(call.startswith("nextest run --locked --workspace --no-fail-fast --profile ci "), call)
                self.assertIn(f"-E package(bhf) & kind(test) & !({SLOW})", call)
                self.assertTrue(call.endswith(f" --partition hash:{shard}/{count}"), call)

    def test_the_slowest_test_runs_alone_in_its_own_shard(self) -> None:
        calls = run_shard(self.script, self.env, DEDICATED)
        self.assertEqual(
            calls,
            [f"nextest run --locked -p bhf --test build_recovery --no-fail-fast --profile ci -E {SLOW}"],
        )

    def test_the_ignored_shard_runs_only_the_ignored_tests_it_names(self) -> None:
        calls = run_shard(self.script, self.env, IGNORED)
        self.assertEqual(
            calls,
            [
                "nextest run --locked -p bhf --no-fail-fast --profile ci --run-ignored only "
                f"-E {IGNORED_FILTER}"
            ],
        )

    def test_an_unknown_shard_fails_instead_of_running_nothing(self) -> None:
        with self.assertRaises(subprocess.CalledProcessError):
            run_shard(self.script, self.env, "0")

    def test_the_job_timeout_stays_the_backstop(self) -> None:
        # 40 minutes for a hash shard; the dedicated shard's one test can take
        # more than 25 minutes on its own, so it alone gets 55.
        self.assertIn(
            f"\n    timeout-minutes: ${{{{ matrix.shard == '{DEDICATED}' && 55 || 40 }}}}\n",
            self.job,
        )
        self.assertIn("\n      fail-fast: false\n", self.job)
        self.assertIn('RAYON_NUM_THREADS: "1"', self.step)


class IntegrationNightlyShimTests(unittest.TestCase):
    """Every shard builds the runtrace shim and the compiler intercept, which
    nextest's build of the test binaries does not produce (both are cdylibs),
    before it runs a test: bhf preloads them from beside itself, and without
    them each fuzz runs with the runtime audit off and the env-capsule tests
    skip."""

    STEP = "Build the runtrace shim and compiler intercept"

    def setUp(self) -> None:
        self.job = integration_job()
        steps = re.findall(r"(?m)^      - name: (.+)$", self.job)
        self.assertIn(self.STEP, steps)
        self.assertLess(steps.index(self.STEP), steps.index("Integration tests (shard ${{ matrix.shard }})"))
        self.step = self.job.split(f"      - name: {self.STEP}\n", 1)[1].split("\n      - name:", 1)[0]

    def build(self, *, produce: tuple[str, ...]) -> tuple[subprocess.CompletedProcess, list[list[str]]]:
        """Run the build step with a stand-in cargo that writes `produce`."""
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch)
            bin_dir = work / "bin"
            bin_dir.mkdir()
            log = work / "cargo.log"
            stub = bin_dir / "cargo"
            stub.write_text(
                f"#!{sys.executable}\n"
                "import json, os, pathlib, sys\n"
                "with open(os.environ['CARGO_LOG'], 'a') as log:\n"
                "    log.write(json.dumps(sys.argv[1:]) + '\\n')\n"
                "for name in os.environ['PRODUCE'].split():\n"
                "    path = pathlib.Path('target/debug', name)\n"
                "    path.parent.mkdir(parents=True, exist_ok=True)\n"
                "    path.write_bytes(b'')\n"
            )
            stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
            result = subprocess.run(
                ["bash", "-e", "-o", "pipefail", "-c", step_script(self.step)],
                cwd=work, capture_output=True, text=True, timeout=30,
                env={**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
                     "CARGO_LOG": str(log), "PRODUCE": " ".join(produce)},
            )
            calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            return result, calls

    def test_each_shard_builds_both_libraries_before_its_tests(self) -> None:
        self.assertNotRegex(self.step, r"(?m)^        if:")
        result, calls = self.build(produce=("libbhf_runtrace_shim.so", "libbhf_cc_intercept.so"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [["build", "--locked", "-p", "bhf_runtrace_shim", "-p", "bhf_cc_intercept"]])

    def test_a_build_that_leaves_a_library_out_fails_the_shard(self) -> None:
        for produced in (("libbhf_runtrace_shim.so",), ("libbhf_cc_intercept.so",)):
            with self.subTest(produced=produced):
                result, _ = self.build(produce=produced)
                self.assertNotEqual(result.returncode, 0)

    def test_the_tests_require_the_shim(self) -> None:
        # BHF_REQUIRE_TOOLS=1 turns a test's "runtrace shim not built" skip
        # into a failure.
        self.assertEqual(step_env(shard_step(self.job)).get("BHF_REQUIRE_TOOLS"), "1")



@unittest.skipUnless(nextest_installed(), "cargo-nextest is not installed")
class IntegrationNightlySelectionTests(unittest.TestCase):
    """What nextest itself selects for each shard's command. Listing builds the
    workspace's test binaries, so this runs where cargo-nextest is installed
    and is skipped elsewhere (the CI policy job installs no cargo-nextest)."""

    def test_the_shards_run_every_bhf_integration_test_exactly_once(self) -> None:
        job = integration_job()
        step = shard_step(job)
        env = step_env(step)
        script = step_script(step)
        selections: dict[str, set[str]] = {}
        for shard in matrix_shards(job):
            calls = run_shard_argv(script, env, shard)
            self.assertEqual(len(calls), 1, calls)
            selections[shard] = nextest_selection(calls[0])
        everything = nextest_selection(
            ["nextest", "run", "--locked", "--workspace", "-E", "package(bhf) & kind(test)"]
        )

        self.assertEqual(
            selections.pop(DEDICATED), {"bhf::build_recovery::build_recovery_scenarios"}
        )
        # The ignored shard runs tests the others skip, and nothing else.
        ignored = selections.pop(IGNORED)
        self.assertTrue(ignored, "the ignored shard runs tests")
        self.assertEqual(ignored & everything, set())
        empty = [shard for shard, tests in selections.items() if not tests]
        self.assertEqual(empty, [], "every hash shard runs tests")
        counts = Counter(test for tests in selections.values() for test in tests)
        self.assertEqual([test for test, n in counts.items() if n > 1], [])
        self.assertEqual(
            set(counts) | {"bhf::build_recovery::build_recovery_scenarios"}, everything
        )
        self.assertNotIn("bhf::build_recovery::build_recovery_scenarios", counts)


if __name__ == "__main__":
    unittest.main()
