# SPDX-License-Identifier: Apache-2.0
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from run import classify_outcome, parse_bhf_fuzz, required_tools


class RunnerClassificationTests(unittest.TestCase):
    def test_only_completed_no_crash_trials_are_censored(self):
        run = {"returncode": 0, "timed_out": False, "campaign_completed": True}
        self.assertEqual(classify_outcome(0, run, None, None), "censored_no_crash")
        self.assertEqual(
            classify_outcome(1, run, None, None), "build_failed"
        )
        self.assertEqual(
            classify_outcome(0, {"returncode": 2, "timed_out": False}, None, None),
            "runner_error",
        )
        self.assertEqual(
            classify_outcome(
                0,
                {"returncode": 0, "timed_out": False, "campaign_completed": False},
                None,
                None,
            ),
            "runner_error",
        )
        self.assertEqual(
            classify_outcome(0, {"returncode": -9, "timed_out": True}, None, None),
            "supervisor_timeout",
        )

    def test_only_independent_expected_sanitizer_replay_is_a_solve(self):
        run = {"returncode": 0, "timed_out": False, "campaign_completed": True}
        artifact = Path("crash-artifact")
        self.assertEqual(
            classify_outcome(0, run, artifact, {"expected_sanitizer_crash": True}),
            "confirmed_crash",
        )
        self.assertEqual(
            classify_outcome(0, run, artifact, {"expected_sanitizer_crash": False}),
            "unconfirmed_crash_artifact",
        )
        self.assertEqual(
            classify_outcome(
                0,
                {**run, "artifact_within_budget": False},
                artifact,
                {"expected_sanitizer_crash": True},
            ),
            "out_of_budget_crash",
        )
        self.assertEqual(
            classify_outcome(
                0,
                {**run, "timed_out": True},
                artifact,
                {"expected_sanitizer_crash": True},
            ),
            "supervisor_timeout",
        )

    def test_bhf_native_metrics_come_from_run_summary(self):
        with TemporaryDirectory() as directory:
            work = Path(directory)
            summary_dir = work / "fuzz_runs"
            summary_dir.mkdir()
            (summary_dir / "H-X-latest.json").write_text(
                '{"executions": 12, "elapsed_secs": 1.5, '
                '"coverage": {"edges": 7}, '
                '"execution": {"harness_protocol": "bhf_framed", "forkserver": true}}'
            )
            log = work / "run.log"
            log.write_text("bhf: final stats — execs: 12")
            metrics = parse_bhf_fuzz(log, work)
            self.assertEqual(metrics["coverage_edges"], 7)
            self.assertEqual(metrics["harness_protocol"], "bhf_framed")
            self.assertEqual(metrics["executions_native"], 12)

    def test_required_tools_follow_selected_engines_and_oracle(self):
        self.assertEqual(required_tools(["builtin"], None), {"clang"})
        self.assertEqual(
            required_tools(["builtin", "afl++"], "0"),
            {"clang", "afl-clang-fast", "afl-fuzz", "taskset"},
        )
        self.assertEqual(
            required_tools(["libfuzzer"], None),
            {"clang"},
        )


if __name__ == "__main__":
    unittest.main()
