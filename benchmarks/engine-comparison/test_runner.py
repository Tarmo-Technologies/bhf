# SPDX-License-Identifier: Apache-2.0
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import stats
import targets
import trade_study
from run import classify_outcome, parse_bhf_fuzz, required_tools


class RunnerClassificationTests(unittest.TestCase):
    def test_only_completed_no_crash_trials_are_censored(self):
        run = {"returncode": 0, "timed_out": False, "campaign_completed": True}
        self.assertEqual(classify_outcome(0, run, None, None), "censored_no_crash")
        self.assertEqual(classify_outcome(1, run, None, None), "build_failed")
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


class StatsTests(unittest.TestCase):
    def test_wilson_interval_endpoints_and_bounds(self):
        empty = stats.wilson_interval(0, 0)
        self.assertEqual((empty.rate, empty.ci_low, empty.ci_high), (None, None, None))
        perfect = stats.wilson_interval(10, 10)
        self.assertEqual(perfect.rate, 1.0)
        self.assertLess(
            perfect.ci_low, 1.0
        )  # Wilson never claims a point estimate at n=10
        self.assertLessEqual(perfect.ci_high, 1.0)
        half = stats.wilson_interval(5, 10)
        self.assertEqual(half.rate, 0.5)
        self.assertLess(half.ci_low, 0.5)
        self.assertGreater(half.ci_high, 0.5)
        self.assertGreaterEqual(half.ci_low, 0.0)

    def test_wilson_rejects_impossible_counts(self):
        with self.assertRaises(ValueError):
            stats.wilson_interval(5, 3)
        with self.assertRaises(ValueError):
            stats.wilson_interval(-1, 3)

    def test_summarize_is_deterministic_with_spread_and_ci(self):
        values = [1, 2, 2, 3, 100]
        first = stats.summarize(values)
        second = stats.summarize(values)
        self.assertEqual(first.as_dict(), second.as_dict())  # fixed-seed bootstrap
        self.assertEqual(first.n, 5)
        self.assertEqual(first.median, 2.0)
        self.assertEqual(first.minimum, 1.0)
        self.assertEqual(first.maximum, 100.0)
        self.assertGreaterEqual(first.iqr, 0.0)
        self.assertLessEqual(first.ci_low, first.median)
        self.assertGreaterEqual(first.ci_high, first.median)

    def test_summarize_handles_empty_and_singleton(self):
        empty = stats.summarize([None, None])
        self.assertEqual(empty.n, 0)
        self.assertIsNone(empty.median)
        one = stats.summarize([7])
        self.assertEqual(
            (one.n, one.median, one.ci_low, one.ci_high), (1, 7.0, 7.0, 7.0)
        )
        self.assertEqual(one.ci_method, "degenerate")


class TargetManifestTests(unittest.TestCase):
    def test_builtin_fixture_targets_cover_every_case(self):
        specs = targets.builtin_fixture_targets({"magic_byte": "parse_frame"})
        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0].kind, targets.KIND_BUILTIN)
        self.assertEqual(specs[0].status, targets.RUNNABLE)
        self.assertEqual(specs[0].primary_source, None)

    def test_example_manifest_loads_and_pins_upstream(self):
        manifest = (
            Path(__file__).resolve().parent / "experiment1-real-code.example.json"
        )
        specs = targets.load_manifest(manifest, resolve_sources=False)
        self.assertTrue(specs)
        names = {s.name for s in specs}
        self.assertIn("cjson", names)
        for spec in specs:
            self.assertIsNotNone(spec.upstream, f"{spec.name} must pin an upstream")
            self.assertEqual(len(spec.upstream.commit), 40)
            self.assertIn(spec.status, targets._STATUSES)
            self.assertIn(spec.bhf_harness_mode, targets._BHF_MODES)

    def test_manifest_rejects_malformed_entries(self):
        with TemporaryDirectory() as directory:
            base = Path(directory)

            def write(doc):
                path = base / "m.json"
                path.write_text(json.dumps(doc))
                return path

            with self.assertRaises(targets.ManifestError):
                targets.load_manifest(write({"nope": []}), resolve_sources=False)
            with self.assertRaises(targets.ManifestError):
                targets.load_manifest(write({"targets": []}), resolve_sources=False)
            with self.assertRaises(targets.ManifestError):  # real-code needs upstream
                targets.load_manifest(
                    write({"targets": [{"name": "x", "kind": "self_contained"}]}),
                    resolve_sources=False,
                )
            with self.assertRaises(targets.ManifestError):  # duplicate names
                targets.load_manifest(
                    write(
                        {
                            "targets": [
                                {
                                    "name": "x",
                                    "status": "requires_build_recipe",
                                    "upstream": {"url": "u", "commit": "c"},
                                },
                                {
                                    "name": "x",
                                    "status": "requires_build_recipe",
                                    "upstream": {"url": "u", "commit": "c"},
                                },
                            ]
                        }
                    ),
                    resolve_sources=False,
                )
            with self.assertRaises(targets.ManifestError):  # unknown status
                targets.load_manifest(
                    write(
                        {
                            "targets": [
                                {
                                    "name": "x",
                                    "status": "bogus",
                                    "upstream": {"url": "u", "commit": "c"},
                                }
                            ]
                        }
                    ),
                    resolve_sources=False,
                )

    def test_missing_source_for_runnable_target_is_an_error(self):
        with TemporaryDirectory() as directory:
            base = Path(directory)
            path = base / "m.json"
            path.write_text(
                json.dumps(
                    {
                        "targets": [
                            {
                                "name": "x",
                                "status": "runnable",
                                "upstream": {"url": "u", "commit": "c"},
                                "sources": ["does-not-exist.c"],
                            }
                        ]
                    }
                )
            )
            with self.assertRaises(targets.ManifestError):
                targets.load_manifest(path, resolve_sources=True)

    def test_materialize_builtin_fixture_writes_wrapped_source(self):
        spec = targets.builtin_fixture_targets({"magic_byte": "parse_frame"})[0]
        with TemporaryDirectory() as directory:
            sources, sha = trade_study.materialize_target(spec, Path(directory) / "src")
            self.assertEqual(len(sources), 1)
            self.assertTrue(sources[0].is_file())
            self.assertIn("target_one_input", sources[0].read_text())
            self.assertEqual(len(sha), 64)


class TradeOutcomeTests(unittest.TestCase):
    def test_classify_covers_every_class(self):
        self.assertEqual(
            trade_study.classify_trade_outcome(
                {"outcome": trade_study.OUTCOME_UNSUPPORTED}
            ),
            trade_study.OUTCOME_UNSUPPORTED,
        )
        self.assertEqual(
            trade_study.classify_trade_outcome({"build_rc": 1}),
            trade_study.OUTCOME_BUILD_FAILED,
        )
        self.assertEqual(
            trade_study.classify_trade_outcome(
                {"build_rc": 0, "supervisor_timeout": True}
            ),
            trade_study.OUTCOME_TIMEOUT,
        )
        self.assertEqual(
            trade_study.classify_trade_outcome(
                {"build_rc": 0, "crash_confirmed": True, "campaign_wall_s": 5.0}
            ),
            trade_study.OUTCOME_CONFIRMED,
        )
        self.assertEqual(
            trade_study.classify_trade_outcome(
                {"build_rc": 0, "crash_confirmed": False, "campaign_wall_s": 5.0}
            ),
            trade_study.OUTCOME_CENSORED,
        )
        self.assertEqual(
            trade_study.classify_trade_outcome(
                {"build_rc": 0, "crash_confirmed": False, "campaign_wall_s": None}
            ),
            trade_study.OUTCOME_INCOMPLETE,
        )

    def test_engine_summary_keeps_failures_visible_and_reports_ci(self):
        rows = [
            {
                "outcome": "confirmed_crash",
                "crash_confirmed": True,
                "crash_signature": "ASan: oob",
                "time_to_first_crash_s": 1.0,
                "common_cov_edges": 10,
                "common_cov_features": 12,
                "native_execs_per_s": 1000.0,
                "build_s": 0.4,
                "right_censor_s": None,
            },
            {
                "outcome": "confirmed_crash",
                "crash_confirmed": True,
                "crash_signature": "ASan: oob",
                "time_to_first_crash_s": 2.0,
                "common_cov_edges": 11,
                "common_cov_features": 13,
                "native_execs_per_s": 1100.0,
                "build_s": 0.5,
                "right_censor_s": None,
            },
            {
                "outcome": "censored_no_crash",
                "crash_confirmed": False,
                "crash_signature": None,
                "time_to_first_crash_s": None,
                "common_cov_edges": 9,
                "common_cov_features": 10,
                "native_execs_per_s": 900.0,
                "build_s": 0.4,
                "right_censor_s": 30.0,
            },
            {
                "outcome": "build_failed",
                "crash_confirmed": False,
                "crash_signature": None,
                "time_to_first_crash_s": None,
                "common_cov_edges": None,
                "common_cov_features": None,
                "native_execs_per_s": None,
                "build_s": None,
                "right_censor_s": None,
            },
        ]
        summary = trade_study.engine_summary(rows)
        self.assertEqual(summary["trials"], 4)
        self.assertEqual(summary["valid_campaigns"], 3)  # 2 confirmed + 1 censored
        self.assertEqual(summary["outcomes"]["build_failed"], 1)
        self.assertEqual(summary["crash_find"]["successes"], 2)
        self.assertEqual(
            summary["crash_find"]["trials"], 3
        )  # build_failed excluded from denom
        self.assertEqual(summary["distinct_defect_signatures"], 1)  # deduped
        self.assertEqual(summary["ttfc_s"]["n"], 2)
        self.assertEqual(summary["right_censored_s"], [30.0])
        self.assertFalse(summary["native_execs_per_s"]["comparable_across_engines"])

    def test_aggregate_builds_per_target_and_pooled(self):
        rows = [
            {
                "case": "a",
                "engine": "bhf",
                "outcome": "confirmed_crash",
                "crash_confirmed": True,
                "crash_signature": "s",
                "time_to_first_crash_s": 1.0,
                "common_cov_edges": 5,
                "common_cov_features": 6,
                "native_execs_per_s": 10.0,
                "build_s": 0.1,
                "right_censor_s": None,
            },
            {
                "case": "a",
                "engine": "aflpp",
                "outcome": "censored_no_crash",
                "crash_confirmed": False,
                "crash_signature": None,
                "time_to_first_crash_s": None,
                "common_cov_edges": 4,
                "common_cov_features": 5,
                "native_execs_per_s": 20.0,
                "build_s": 0.2,
                "right_censor_s": 30.0,
            },
        ]
        summary = trade_study.aggregate(rows, ["bhf", "aflpp"], ["a"])
        self.assertIn("per_target", summary)
        self.assertIn("aggregate_by_engine", summary)
        self.assertEqual(summary["per_target"]["a"]["bhf"]["crash_find"]["rate"], 1.0)
        self.assertEqual(
            summary["aggregate_by_engine"]["aflpp"]["outcomes"]["censored_no_crash"], 1
        )


if __name__ == "__main__":
    unittest.main()
