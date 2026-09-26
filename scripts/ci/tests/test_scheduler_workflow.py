# SPDX-License-Identifier: Apache-2.0
"""Source-contract guards for required scheduler and EL7 prerequisite steps."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]


def job(name: str) -> str:
    source = (ROOT / ".github/workflows/ci.yml").read_text()
    block = source.split(f"\n  {name}:\n", 1)[1]
    return re.split(r"\n  [a-z][a-z0-9-]*:\n", block, maxsplit=1)[0]


class SchedulerWorkflowTests(unittest.TestCase):
    def test_linux_scheduler_regressions_run_before_the_long_workspace_suite(self):
        source = job("build-test")
        command = "run: cargo test --locked -p continuous_daemon --lib\n"
        self.assertIn(command, source)
        self.assertLess(source.index(command), source.index("run: cargo nextest run --locked --workspace"))
        step = source.split("      - name: Test scheduler runtime reliability\n", 1)[1].split("      - name:", 1)[0]
        self.assertNotIn("if:", step)
        self.assertNotIn("continue-on-error", step)

    def test_windows_runs_the_portable_scheduler_suite_as_a_required_step(self):
        source = job("windows-build")
        step = source.split("      - name: Test portable scheduler runtime reliability\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("run: cargo test --locked -p continuous_daemon --lib health::tests", step)
        self.assertNotIn("if:", step)
        self.assertNotIn("continue-on-error", step)

    def test_el7_preserves_prior_crypto_setup_and_all_required_tests(self):
        source = job("rhel7-build")
        for required in (
            "test -x /opt/python/cp312-cp312/bin/python3",
            "bash scripts/ci/build-test-openssl.sh /tmp/bhf-ci-openssl",
            "cargo test --locked -p continuous_daemon --lib",
            "cargo test --locked -p governance --lib",
            "cargo test --locked -p bhf --test offline_dist_scripts -- --nocapture",
            'scripts/check-linux-release-abi.sh "$CARGO_TARGET_DIR/release"',
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)
        self.assertLess(source.index("bash scripts/ci/build-test-openssl.sh"),
                        source.index("cargo test --locked -p bhf --test offline_dist_scripts"))
        self.assertNotIn("--skip", source)
        self.assertNotIn("continue-on-error", source)
        self.assertNotIn("--nogpgcheck", source)
        self.assertIn("Test offline signature verifier", job("build-test"))


if __name__ == "__main__":
    unittest.main()
