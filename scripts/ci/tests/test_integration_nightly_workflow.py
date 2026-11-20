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
# Every shard runs from the test archive the build job uploads.
ARCHIVE = "--archive-file nightly-tests.tar.zst --workspace-remap . --extract-to ."
IGNORED_FILTER = (
    "binary(=auto_lua_hook) | binary(=redqueen_cmplog) | binary(=engine_parity) | "
    "binary(=fuzz_crash_throughput)"
)


def job_block(name: str) -> str:
    source = WORKFLOW.read_text()
    block = source.split(f"\n  {name}:\n", 1)[1]
    return re.split(r"\n  [a-z][a-z0-9-]*:\n", block, maxsplit=1)[0]


def integration_job() -> str:
    return job_block("integration")


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
    # A shard runs from the archive; list what its build would hold instead.
    rest: list[str] = []
    skip = False
    for arg in argv[2:]:
        if skip:
            skip = False
        elif arg in ("--archive-file", "--workspace-remap", "--extract-to"):
            skip = True
        elif arg != "--no-fail-fast":
            rest.append(arg)
    build = [flag for flag in ("--locked", "--workspace") if flag not in rest]
    args = ["nextest", "list", *build, *rest]
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
                self.assertTrue(call.startswith(f"nextest run {ARCHIVE} --no-fail-fast --profile ci "), call)
                self.assertIn(f"-E package(bhf) & kind(test) & !({SLOW})", call)
                self.assertTrue(call.endswith(f" --partition hash:{shard}/{count}"), call)

    def test_the_slowest_test_runs_alone_in_its_own_shard(self) -> None:
        calls = run_shard(self.script, self.env, DEDICATED)
        self.assertEqual(
            calls,
            [f"nextest run {ARCHIVE} --no-fail-fast --profile ci -E {SLOW}"],
        )

    def test_the_ignored_shard_runs_only_the_ignored_tests_it_names(self) -> None:
        calls = run_shard(self.script, self.env, IGNORED)
        self.assertEqual(
            calls,
            [
                f"nextest run {ARCHIVE} --no-fail-fast --profile ci --run-ignored only "
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


class IntegrationNightlyArchiveTests(unittest.TestCase):
    """One build job compiles every test binary, the runtrace shim and the
    compiler intercept (cdylibs no test binary links, which bhf preloads from
    beside itself) and the release bhf the heavy tests run, into one nextest
    archive; every shard runs from it instead of building its own."""

    STEP = "Build the cdylibs, the release bhf and the test archive"

    def setUp(self) -> None:
        self.build_job = job_block("build")
        self.job = integration_job()
        self.step = self.build_job.split(f"      - name: {self.STEP}\n", 1)[1].split(
            "\n      - name:", 1
        )[0]

    def test_the_build_job_builds_the_cdylibs_and_the_release_bhf_into_the_archive(self) -> None:
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
            subprocess.run(
                ["bash", "-c", step_script(self.step)], check=True, cwd=scratch,
                env={**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
                     "CARGO_LOG": str(log)},
            )
            calls = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(
            calls,
            [
                ["build", "--locked", "-p", "bhf_runtrace_shim", "-p", "bhf_cc_intercept"],
                ["build", "--locked", "--release", "-p", "bhf", "-p", "bhf_runtrace_shim"],
                ["nextest", "archive", "--locked", "--workspace", "--profile", "ci",
                 "--archive-file", "nightly-tests.tar.zst"],
            ],
        )

    def test_the_archive_must_carry_the_cdylibs_and_the_release_bhf(self) -> None:
        import tomllib

        config = tomllib.loads((ROOT / ".config/nextest.toml").read_text())
        include = config["profile"]["ci"]["archive"]["include"]
        self.assertEqual(
            {entry["path"] for entry in include},
            {
                "debug/libbhf_runtrace_shim.so",
                "debug/libbhf_cc_intercept.so",
                "release/bhf",
                "release/libbhf_runtrace_shim.so",
            },
        )
        for entry in include:
            self.assertEqual((entry["relative-to"], entry["on-missing"]), ("target", "error"))

    def test_every_shard_runs_from_the_archive_the_build_job_uploads(self) -> None:
        self.assertIn("    needs: [gate, build]\n", self.job)
        # Named by the run alone, so a rerun of a failed shard, which does not
        # rebuild the archive, still finds it; a rebuild replaces it.
        name = "nightly-tests-${{ github.run_id }}"
        self.assertIn(
            f"          name: {name}\n          overwrite: true\n          path: nightly-tests.tar.zst\n",
            self.build_job,
        )
        self.assertIn(f"          name: {name}\n", self.job.split("Download the test archive", 1)[1])
        self.assertNotIn("nightly-tests-${{ github.run_id }}-", self.build_job + self.job)
        env = step_env(shard_step(self.job))
        self.assertEqual(env["BHF_TEST_BIN"], "${{ github.workspace }}/target/release/bhf")
        self.assertNotIn("cargo build", self.job, "a shard builds nothing")

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


class IntegrationNightlyWinaflTests(unittest.TestCase):
    """The WinAFL campaigns run nightly against a cached pinned build (#268)."""

    def setUp(self) -> None:
        self.job = job_block("winafl")

    def test_the_job_counts_as_an_integration_shard(self) -> None:
        # scripts/ci/nightly-gate.py counts a run as tested only when every
        # job named like an integration shard passed.
        self.assertIn("name: Integration tests (bhf) (WinAFL, Windows)", self.job)
        self.assertIn("runs-on: windows-2022", self.job)
        report = job_block("report-failure")
        self.assertIn("needs: [gate, build, integration, binary-analyzers, ossfuzz-sandbox, winafl]", report)
        self.assertIn("needs.winafl.result == 'failure'", report)

    def test_a_cache_hit_skips_the_build(self) -> None:
        restore = self.job.index("uses: actions/cache/restore@")
        build = self.job.index("run: scripts/ci/build-winafl.ps1 -Root C:\\tools\\bhf-winafl")
        save = self.job.index("uses: actions/cache/save@")
        self.assertLess(restore, build)
        self.assertLess(build, save)
        skip = "if: steps.winafl-build.outputs.cache-hit != 'true'"
        self.assertEqual(self.job.count(skip), 2, self.job)
        # The key names the pinned versions and the script that builds them.
        self.assertIn("key: winafl-fd85f38548-dynamorio-11.91.20763-${{ hashFiles('scripts/ci/build-winafl.ps1') }}", self.job)
        script = (ROOT / "scripts/ci/build-winafl.ps1").read_text()
        for pin in ("fd85f38548b14352f4b70ad414f364ea6dc1a769", "11.91.20763",
                    "EA3DAD4AE6E39228FE87B5D4D7BC3A53FAFDB6161EE5BA6A2E98FB64F8A7E0D4"):
            self.assertIn(pin, script)
        self.assertIn("'build32'; Arch = 'Win32'", script)

    def test_the_ignored_winafl_campaigns_run(self) -> None:
        self.assertIn("cargo test --locked -p bhf --test winafl_engine -- --ignored --test-threads 1", self.job)
        self.assertIn("BHF_WINAFL_PATH: C:\\tools\\bhf-winafl\\winafl", self.job)
        self.assertIn("BHF_DYNAMORIO_PATH: C:\\tools\\bhf-winafl\\DynamoRIO-Windows-11.91.20763", self.job)


class IntegrationNightlyBinaryAnalyzerTests(unittest.TestCase):
    """The binary adapters run nightly against the real Rizin, Ghidra and angr
    (#264, #265, #266), pinned by digest."""

    def setUp(self) -> None:
        self.job = job_block("binary-analyzers")

    def test_the_job_counts_as_an_integration_shard_and_reports_its_failure(self) -> None:
        self.assertIn("name: Integration tests (bhf) (binary analyzers)", self.job)
        self.assertIn("    needs: [gate, build]\n", self.job)
        report = job_block("report-failure")
        self.assertIn("needs.binary-analyzers.result == 'failure'", report)
        self.assertIn("needs.binary-analyzers.result == 'cancelled'", report)

    def test_it_runs_the_analyzer_tests_from_the_archive_with_the_tools_required(self) -> None:
        self.assertIn(f"cargo nextest run {ARCHIVE} \\\n", self.job)
        self.assertIn("-E 'binary(=binary_adapter_tools)'", self.job)
        self.assertIn('BHF_BINARY_ANALYZERS: "1"', self.job)
        self.assertIn('BHF_REQUIRE_TOOLS: "1"', self.job)
        self.assertIn("java-version: 25", self.job)
        self.assertIn(
            'run: bash scripts/ci/install-binary-analyzers.sh "$RUNNER_TEMP/analyzers" >> "$GITHUB_ENV"',
            self.job,
        )

    def test_every_download_is_pinned_by_digest(self) -> None:
        script = (ROOT / "scripts/ci/install-binary-analyzers.sh").read_text()
        self.assertEqual(script.count('"$here/fetch.sh" \\\n'), 2, script)
        for pin in (
            "rizin_sha256=9102249a9f0b6319c5334a2e5cf8d9cc3f2035e1d3def027c41f6a90f647e8cf",
            "ghidra_sha256=2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67",
            "angr_version=10.0.7",
        ):
            self.assertIn(pin, script)
        self.assertNotIn("curl", script)

    def test_the_hash_shards_may_skip_only_the_analyzer_tests(self) -> None:
        allowed = (ROOT / "scripts/ci/allowed-skips.txt").read_text()
        self.assertIn(
            "bhf::binary_adapter_tools::*  skip binary_adapter_tools: set BHF_BINARY_ANALYZERS=1",
            allowed,
        )
        tests = (ROOT / "crates/cli/tests/binary_adapter_tools.rs").read_text()
        self.assertIn('eprintln!("skip binary_adapter_tools: set BHF_BINARY_ANALYZERS=1");', tests)


class IntegrationNightlyOssfuzzSandboxTests(unittest.TestCase):
    """The OSS-Fuzz import's sandbox tests run nightly under a bubblewrap
    allowed its namespaces on that job's runner only (#334), and under
    firejail (#443)."""

    def setUp(self) -> None:
        self.job = job_block("ossfuzz-sandbox")

    def test_the_job_counts_as_an_integration_shard_and_reports_its_failure(self) -> None:
        self.assertIn("name: Integration tests (bhf) (OSS-Fuzz import sandbox)", self.job)
        self.assertIn("    needs: [gate, build]\n", self.job)
        report = job_block("report-failure")
        self.assertIn("needs.ossfuzz-sandbox.result == 'failure'", report)
        self.assertIn("needs.ossfuzz-sandbox.result == 'cancelled'", report)

    def test_it_gives_bubblewrap_its_namespaces_before_the_tests_require_it(self) -> None:
        install = self.job.index("sudo apt-get install -y -q --no-install-recommends bubblewrap")
        sysctl = self.job.index("sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0")
        probe = self.job.index("bwrap --die-with-parent --unshare-all --ro-bind / / -- true")
        tests = self.job.index("-E 'binary(=ossfuzz_import)'")
        self.assertLess(install, sysctl)
        self.assertLess(sysctl, probe)
        self.assertLess(probe, tests)
        self.assertIn(f"cargo nextest run {ARCHIVE} \\\n", self.job)
        self.assertIn('BHF_OSSFUZZ_SANDBOX: "1"', self.job)
        self.assertIn('BHF_REQUIRE_TOOLS: "1"', self.job)
        # Only this job's runner: no other job lifts the restriction.
        source = WORKFLOW.read_text()
        self.assertEqual(source.count("apparmor_restrict_unprivileged_userns=0"), 1)

    def test_it_installs_firejail_and_checks_it_before_the_tests_require_it(self) -> None:
        install = self.job.index(
            "sudo apt-get install -y -q --no-install-recommends bubblewrap firejail"
        )
        probe = self.job.index("firejail --quiet --noprofile --net=none -- true")
        tests = self.job.index("-E 'binary(=ossfuzz_import)'")
        self.assertLess(install, probe)
        self.assertLess(probe, tests)
        # BHF_OSSFUZZ_SANDBOX=1 requires both, so neither one's tests skip.
        tests_source = (ROOT / "crates/cli/tests/ossfuzz_import.rs").read_text()
        for sandbox in ("bubblewrap", "firejail"):
            for test in (
                "build_sh_builds_the_fixture_under_",
                "build_sh_has_no_network_under_",
                "build_sh_cannot_write_outside_src_work_and_out_under_",
                "build_sh_cannot_see_the_hosts_files_under_",
                "build_sh_cannot_reach_the_host_through_ipc_devices_or_its_terminal_under_",
            ):
                self.assertIn(f"fn {test}{sandbox}()", tests_source)

    def test_the_hash_shards_may_skip_only_the_sandbox_tests(self) -> None:
        allowed = (ROOT / "scripts/ci/allowed-skips.txt").read_text()
        for sandbox in ("bubblewrap", "firejail"):
            self.assertIn(
                f"bhf::ossfuzz_import::build_sh_*  skip build_sh_*: {sandbox} does not work "
                "here (set BHF_OSSFUZZ_SANDBOX=1 to require it)",
                allowed,
            )
        self.assertNotIn("no working bubblewrap or firejail", allowed)
        tests = (ROOT / "crates/cli/tests/ossfuzz_import.rs").read_text()
        self.assertIn('const SANDBOX_REQUIRED: &str = "BHF_OSSFUZZ_SANDBOX";', tests)
        self.assertIn(
            '"skip {test}: {} does not work here (set {SANDBOX_REQUIRED}=1 to require it)"', tests
        )


class RenodeLaneTests(unittest.TestCase):
    """The Renode transport's CLI test skips in the hash shards, which do not
    install Renode, and runs in hil-emu against a pinned Renode (#340)."""

    def test_the_hash_shards_may_skip_only_the_renode_cli_test(self) -> None:
        allowed = (ROOT / "scripts/ci/allowed-skips.txt").read_text()
        entry = (
            "bhf::transport_fuzz_renode_cli::*  skip transport_fuzz_renode_cli: renode is not "
            "installed (set BHF_RENODE_CLI=1*"
        )
        self.assertIn(entry, allowed)
        tests = (ROOT / "crates/cli/tests/transport_fuzz_renode_cli.rs").read_text()
        self.assertIn('const RENODE_REQUIRED: &str = "BHF_RENODE_CLI";', tests)
        self.assertIn(
            '"skip transport_fuzz_renode_cli: renode is not installed (set {RENODE_REQUIRED}=1',
            tests,
        )

    def test_renode_is_pinned_by_digest(self) -> None:
        script = (ROOT / "scripts/ci/install-renode.sh").read_text()
        self.assertIn("renode_version=1.17.0\n", script)
        self.assertIn(
            "renode_sha256=4ba7c68b59e2447f188ef4b4b112fcccd2802582c460beedceb63b84e5605a5f\n",
            script,
        )
        self.assertEqual(script.count('"$here/fetch.sh" \\\n'), 1, script)
        self.assertNotIn("curl", script)
        self.assertIn('echo "BHF_RENODE=$dir/renode/renode"', script)

    def test_hil_emu_installs_renode_and_requires_both_live_tests(self) -> None:
        workflow = (ROOT / ".github/workflows/hil-emu.yml").read_text()
        install = workflow.index('bash scripts/ci/install-renode.sh "$HOME/.local/opt/renode-ci" >> "$GITHUB_ENV"')
        run = workflow.index("run: scripts/hil-emu.sh")
        self.assertLess(install, run)
        lane = (ROOT / "scripts/hil-emu.sh").read_text()
        self.assertIn(
            "BHF_REQUIRE_TOOLS=1 cargo test --locked -p target_transport --test live_renode", lane
        )
        self.assertIn("BHF_REQUIRE_TOOLS=1 BHF_RENODE_CLI=1 cargo test --locked \\\n", lane)
        self.assertIn("-p bhf --test transport_fuzz_renode_cli", lane)

    def test_the_lane_fails_without_renode(self) -> None:
        lane = (ROOT / "scripts/hil-emu.sh").read_text()
        start = lane.index('[ -n "${BHF_RENODE:-}" ]')
        guard = lane[start : lane.index("\n}\n", start) + 3]
        with tempfile.TemporaryDirectory() as empty:
            env = {"PATH": empty, "BHF_RENODE": ""}
            missing = subprocess.run(
                ["/bin/bash", "-c", guard + "echo ran"], env=env, capture_output=True, text=True
            )
            self.assertEqual(missing.returncode, 1, missing)
            self.assertIn("RV-7 needs Renode", missing.stderr)
            launcher = Path(empty) / "renode"
            launcher.write_text("#!/bin/sh\n")
            launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR)
            env["BHF_RENODE"] = str(launcher)
            found = subprocess.run(
                ["/bin/bash", "-c", guard + "echo ran"], env=env, capture_output=True, text=True
            )
            self.assertEqual(found.stdout.strip(), "ran", found)



class KernelGuestLaneTests(unittest.TestCase):
    """The kernel guest tests skip in the hash shards, which build no guest
    kernel, and run in hil-emu against the one the recipe builds (#350)."""

    def test_the_hash_shards_may_skip_only_the_kernel_guest_tests(self) -> None:
        allowed = (ROOT / "scripts/ci/allowed-skips.txt").read_text()
        self.assertIn(
            "bhf::kernel_guest_cli::*  skip kernel_guest_cli: set BHF_KERNEL_GUEST=1*", allowed
        )
        tests = (ROOT / "crates/cli/tests/kernel_guest_cli.rs").read_text()
        self.assertIn('"skip kernel_guest_cli: set BHF_KERNEL_GUEST=1 and BHF_KERNEL_IMAGE', tests)

    def test_the_kernel_is_a_pinned_release_fetched_by_digest(self) -> None:
        script = (ROOT / "scripts/ci/build-kcov-guest-kernel.sh").read_text()
        self.assertIn("version=6.12.118\n", script)
        self.assertIn(
            "sha256=08308460320e852ac0745b2be3c7ae1cd81bdad713506ed7d817ba1ec9e1a5a5\n", script
        )
        self.assertEqual(script.count('"$here/fetch.sh" \\\n'), 1, script)
        self.assertNotIn("curl", script)
        for option in ["CONFIG_KCOV=y", "CONFIG_KCOV_ENABLE_COMPARISONS=y", "CONFIG_KASAN=y"]:
            self.assertIn(option, script)
        self.assertIn("make \"${make_args[@]}\" kvm_guest.config", script)

    def test_an_output_the_recipe_built_is_used_as_it_is(self) -> None:
        script = ROOT / "scripts/ci/build-kcov-guest-kernel.sh"
        fixture = ROOT / "tests/fixtures/kernel_widget/linux"
        recipe = __import__("hashlib").sha256(
            script.read_bytes()
            + (fixture / "drivers/misc/widget.c").read_bytes()
            + (fixture / "include/uapi/linux/widget.h").read_bytes()
        ).hexdigest()
        with tempfile.TemporaryDirectory() as out, tempfile.TemporaryDirectory() as bin_dir:
            # Only what the script runs before its tool check: a rebuild
            # finds no compiler and stops.
            for tool in ["cat", "sha256sum", "cut", "dirname", "mkdir", "rm", "getconf"]:
                found = subprocess.run(["which", tool], capture_output=True, text=True)
                os.symlink(found.stdout.strip(), Path(bin_dir) / tool)
            env = {"PATH": bin_dir, "HOME": out}
            (Path(out) / "bzImage").write_bytes(b"kernel")
            (Path(out) / "widget.ko").write_bytes(b"module")
            (Path(out) / "recipe.sha256").write_text(recipe + "\n")
            done = subprocess.run(
                ["/bin/bash", str(script), out], env=env, capture_output=True, text=True
            )
            self.assertEqual(done.returncode, 0, done)
            self.assertEqual(
                done.stdout.splitlines(),
                [f"BHF_KERNEL_IMAGE={out}/bzImage", f"BHF_KERNEL_MODULE={out}/widget.ko"],
            )
            # Another recipe's output is rebuilt, not used.
            (Path(out) / "recipe.sha256").write_text("0" * 64 + "\n")
            stale = subprocess.run(
                ["/bin/bash", str(script), out], env=env, capture_output=True, text=True
            )
            self.assertEqual(stale.returncode, 1, stale)
            self.assertIn("gcc is not installed", stale.stderr)
            self.assertEqual(stale.stdout, "")
            self.assertFalse((Path(out) / "recipe.sha256").exists())

    def test_hil_emu_builds_the_kernel_and_requires_the_guest_tests(self) -> None:
        workflow = (ROOT / ".github/workflows/hil-emu.yml").read_text()
        build = workflow.index(
            'bash scripts/ci/build-kcov-guest-kernel.sh "$HOME/.local/opt/kcov-guest" >> "$GITHUB_ENV"'
        )
        run = workflow.index("run: scripts/hil-emu.sh")
        self.assertLess(build, run)
        for package in ["qemu-system-x86", "flex", "bison", "libelf-dev"]:
            self.assertIn(f"            {package}", workflow)
        lane = (ROOT / "scripts/hil-emu.sh").read_text()
        self.assertIn("BHF_REQUIRE_TOOLS=1 BHF_KERNEL_GUEST=1 cargo test --locked \\\n", lane)
        self.assertIn("-p bhf --test kernel_guest_cli", lane)

    def test_the_lane_fails_without_the_guest_kernel(self) -> None:
        lane = (ROOT / "scripts/hil-emu.sh").read_text()
        start = lane.index('[ -f "${BHF_KERNEL_IMAGE:-}" ]')
        guard = lane[start : lane.index("\n}\n", start) + 3]
        with tempfile.TemporaryDirectory() as empty:
            env = {"PATH": empty, "BHF_KERNEL_IMAGE": "", "BHF_KERNEL_MODULE": ""}
            missing = subprocess.run(
                ["/bin/bash", "-c", guard + "echo ran"], env=env, capture_output=True, text=True
            )
            self.assertEqual(missing.returncode, 1, missing)
            self.assertIn("RV-8 needs qemu-system-x86_64", missing.stderr)
            for name in ["bzImage", "widget.ko", "qemu-system-x86_64"]:
                (Path(empty) / name).write_text("#!/bin/sh\n")
            qemu = Path(empty) / "qemu-system-x86_64"
            qemu.chmod(qemu.stat().st_mode | stat.S_IXUSR)
            env["BHF_KERNEL_IMAGE"] = str(Path(empty) / "bzImage")
            env["BHF_KERNEL_MODULE"] = str(Path(empty) / "widget.ko")
            found = subprocess.run(
                ["/bin/bash", "-c", guard + "echo ran"], env=env, capture_output=True, text=True
            )
            self.assertEqual(found.stdout.strip(), "ran", found)


class PersistentLoopBenchmarkTests(unittest.TestCase):
    """The reset=persistent and reset=fast benchmarks run in hil-emu on the
    nightly schedule and by hand, not on a pull request or a push (#346,
    #347)."""

    def test_the_benchmark_runs_on_the_schedule_and_by_hand_only(self) -> None:
        lane = (ROOT / "scripts/hil-emu.sh").read_text()
        start = lane.index("rv3_benchmark_runs() {")
        guard = lane[start : lane.index("\n}\n", start) + 3]
        runs = {}
        for event in ["schedule", "workflow_dispatch", "pull_request", "push", ""]:
            env = {"PATH": os.environ.get("PATH", "")}
            if event:
                env["GITHUB_EVENT_NAME"] = event
            result = subprocess.run(
                ["/bin/bash", "-c", guard + "rv3_benchmark_runs && echo run || echo skip"],
                env=env,
                capture_output=True,
                text=True,
            )
            runs[event] = result.stdout.strip()
        self.assertEqual(
            runs,
            {
                "schedule": "run",
                "workflow_dispatch": "run",
                "pull_request": "skip",
                "push": "skip",
                "": "run",
            },
        )
        self.assertIn(
            "if rv3_benchmark_runs; then\n"
            "  echo \"== RV-3 benchmarks against a loadvm per input: reset=persistent (needs 3x "
            "the runs), reset=fast (needs a tenth of the reset latency) ==\"\n"
            "  BHF_HIL_REQUIRE=1 cargo test --locked -p target_transport --test live_fullsystem -- \\\n"
            "    --ignored --nocapture\n",
            lane,
        )
        workflow = (ROOT / ".github/workflows/hil-emu.yml").read_text()
        self.assertIn("  schedule:\n", workflow)
        self.assertIn("run: scripts/hil-emu.sh", workflow)

    def test_the_lane_has_the_compiler_the_fast_snapshot_plugin_needs(self) -> None:
        lane = (ROOT / "scripts/hil-emu.sh").read_text()
        start = lane.index("required_tools=(")
        tools = lane[start + len("required_tools=(") : lane.index(")", start)].split()
        self.assertIn("cc", tools)
        live = (ROOT / "crates/target_transport/tests/live_fullsystem.rs").read_text()
        self.assertIn("fn live_fullsystem_fast_snapshot_resets_ten_times_faster_than_loadvm", live)
        self.assertIn('#[ignore = "benchmark: run with --ignored (nightly, live QEMU)"]', live)


if __name__ == "__main__":
    unittest.main()
