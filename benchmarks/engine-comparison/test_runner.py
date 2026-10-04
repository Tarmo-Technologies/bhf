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
        # An in-budget confirmed crash is a solve.
        self.assertEqual(
            trade_study.classify_trade_outcome(
                {
                    "build_rc": 0,
                    "crash_confirmed": True,
                    "crash_within_budget": True,
                    "time_to_first_crash_s": 5.0,
                    "campaign_wall_s": 60.0,
                }
            ),
            trade_study.OUTCOME_CONFIRMED,
        )
        # A clean full-budget run that exited cleanly is a valid censored campaign.
        self.assertEqual(
            trade_study.classify_trade_outcome(
                {
                    "build_rc": 0,
                    "crash_confirmed": False,
                    "campaign_wall_s": 60.0,
                    "campaign_rc": 0,
                    "budget_s": 60,
                }
            ),
            trade_study.OUTCOME_CENSORED,
        )
        self.assertEqual(
            trade_study.classify_trade_outcome(
                {"build_rc": 0, "crash_confirmed": False, "campaign_wall_s": None}
            ),
            trade_study.OUTCOME_INCOMPLETE,
        )

    def test_classify_rejects_out_of_budget_and_early_abort(self):
        # Review case A: an engine that aborts early (0.1s of a 60s budget) with a
        # NONZERO exit and no crash is NOT a valid censored no-crash — it lacks
        # completion evidence and is an incomplete trial.
        self.assertEqual(
            trade_study.classify_trade_outcome(
                {
                    "build_rc": 0,
                    "supervisor_timeout": False,
                    "crash_confirmed": False,
                    "campaign_wall_s": 0.1,
                    "campaign_rc": 2,
                    "budget_s": 60,
                }
            ),
            trade_study.OUTCOME_INCOMPLETE,
        )
        # A nonzero engine exit with no crash is a runner failure, not a clean run,
        # even when the wall time reached the budget.
        self.assertEqual(
            trade_study.classify_trade_outcome(
                {
                    "build_rc": 0,
                    "supervisor_timeout": False,
                    "crash_confirmed": False,
                    "campaign_wall_s": 60.0,
                    "campaign_rc": 1,
                    "budget_s": 60,
                }
            ),
            trade_study.OUTCOME_INCOMPLETE,
        )
        # Completion evidence is the engine's clean exit (rc 0), not a wall-clock
        # fraction: a clean-exit no-crash run is a valid censored campaign.
        self.assertEqual(
            trade_study.classify_trade_outcome(
                {
                    "build_rc": 0,
                    "supervisor_timeout": False,
                    "crash_confirmed": False,
                    "campaign_wall_s": 59.8,
                    "campaign_rc": 0,
                    "budget_s": 60,
                }
            ),
            trade_study.OUTCOME_CENSORED,
        )
        # Review case B: a native crash first observed at 64s with a 60s budget is
        # confirmed-but-late — kept as evidence, NOT an in-budget solve.
        self.assertEqual(
            trade_study.classify_trade_outcome(
                {
                    "build_rc": 0,
                    "crash_confirmed": True,
                    "crash_within_budget": False,
                    "time_to_first_crash_s": 64.0,
                    "budget_s": 60,
                }
            ),
            trade_study.OUTCOME_CONFIRMED_LATE,
        )
        # A corpus-backstop confirmation has no known time: reachability, distinct
        # from a known-late native artifact.
        self.assertEqual(
            trade_study.classify_trade_outcome(
                {
                    "build_rc": 0,
                    "crash_confirmed": True,
                    "crash_within_budget": False,
                    "time_to_first_crash_s": None,
                    "budget_s": 60,
                }
            ),
            trade_study.OUTCOME_REACHABLE,
        )

    def test_is_within_budget_uses_the_stated_budget_without_grace(self):
        # #85 re-review: the 61s/60s boundary must NOT count as in-budget (the old
        # `<= budget + 2` grace over-counted it); the stated budget is the line.
        self.assertTrue(trade_study.is_within_budget(60.0, 60))
        self.assertTrue(trade_study.is_within_budget(59.9, 60))
        self.assertFalse(trade_study.is_within_budget(61.0, 60))
        self.assertFalse(trade_study.is_within_budget(None, 60))

    def test_corpus_reachability_from_an_aborted_run_is_not_a_valid_campaign(self):
        # #85 re-review case A: a 0.1s, nonzero-exit campaign whose corpus happens
        # to reach the bug is REACHABILITY evidence (kept visible) but is NOT valid
        # budget exposure — it must not enter the rate denominator.
        reachable_but_aborted = {
            "outcome": "reachable_time_unknown",
            "crash_confirmed": True,
            "time_to_first_crash_s": None,  # corpus backstop; no native crash time
            "campaign_wall_s": 0.1,
            "campaign_rc": 2,  # aborted early, nonzero exit
            "budget_s": 60,
            "defect_identity": "t::x",
        }
        eligible_clean = {
            "outcome": "censored_no_crash",
            "crash_confirmed": False,
            "time_to_first_crash_s": None,
            "campaign_wall_s": 60.0,
            "campaign_rc": 0,
        }
        self.assertFalse(trade_study.campaign_eligible(reachable_but_aborted))
        self.assertTrue(trade_study.campaign_eligible(eligible_clean))
        summary = trade_study.engine_summary([reachable_but_aborted, eligible_clean])
        # Reachability stays VISIBLE in the outcome breakdown...
        self.assertEqual(summary["outcomes"]["reachable_time_unknown"], 1)
        # ...but only the eligible clean campaign is a valid-campaign datapoint.
        self.assertEqual(summary["valid_campaigns"], 1)

    def test_engine_summary_keeps_failures_visible_and_reports_ci(self):
        rows = [
            {
                "outcome": "confirmed_crash",
                "crash_confirmed": True,
                "crash_signature": "ASan: oob",
                "defect_identity": "tgt::asan: oob",
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
                "defect_identity": "tgt::asan: oob",
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
                # Clean completion evidence makes this an eligible campaign.
                "campaign_rc": 0,
                "campaign_wall_s": 60.0,
                "common_cov_edges": 9,
                "common_cov_features": 10,
                "native_execs_per_s": 900.0,
                "build_s": 0.4,
                "right_censor_s": 30.0,
            },
            {
                "outcome": "build_failed",
                "build_rc": 1,
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
        self.assertEqual(summary["normalized_diagnostic_variants"], 1)  # deduped
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
                "campaign_rc": 0,
                "campaign_wall_s": 60.0,
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


class SeedCorpusEqualityTests(unittest.TestCase):
    def test_bhf_seed_args_pass_every_seed_sorted(self):
        # Two distinct seeds must yield two --seed-file arguments (bhf's --seed-file
        # is repeatable), so bhf fuzzes from the SAME corpus as the other engines
        # instead of only the first seed. Order is deterministic (sorted).
        seeds = [Path("/corpus/b-second"), Path("/corpus/a-first")]
        args = trade_study.seed_file_args(seeds)
        self.assertEqual(args.count("--seed-file"), 2)
        self.assertEqual(
            args,
            [
                "--seed-file",
                "/corpus/a-first",
                "--seed-file",
                "/corpus/b-second",
            ],
        )

    def test_verify_equal_seed_corpora_accepts_matching_sets(self):
        rows = [
            {
                "engine": "bhf",
                "outcome": "censored_no_crash",
                "seed_sha256s": ["a", "b"],
            },
            {
                "engine": "aflpp",
                "outcome": "confirmed_crash",
                "seed_sha256s": ["a", "b"],
            },
        ]
        trade_study.verify_equal_seed_corpora(rows)  # must not raise

    def test_verify_equal_seed_corpora_rejects_divergent_sets(self):
        rows = [
            {"engine": "bhf", "outcome": "censored_no_crash", "seed_sha256s": ["a"]},
            {
                "engine": "aflpp",
                "outcome": "censored_no_crash",
                "seed_sha256s": ["a", "b"],
            },
        ]
        with self.assertRaises(RuntimeError):
            trade_study.verify_equal_seed_corpora(rows)

    def test_verify_equal_seed_corpora_exempts_unsupported_rows(self):
        # An unsupported row runs no campaign, so its (absent) corpus is exempt.
        rows = [
            {"engine": "bhf", "outcome": "unsupported", "seed_sha256s": None},
            {"engine": "aflpp", "outcome": "censored_no_crash", "seed_sha256s": ["a"]},
        ]
        trade_study.verify_equal_seed_corpora(rows)  # must not raise


class DefectIdentityTests(unittest.TestCase):
    def test_same_defect_different_pid_and_address_is_one_identity(self):
        a = trade_study.normalize_defect_signature(
            "==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef",
            "tgt",
        )
        b = trade_study.normalize_defect_signature(
            "==9999==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xcafef00d",
            "tgt",
        )
        self.assertIsNotNone(a)
        self.assertEqual(a, b)

    def test_same_diagnostic_different_target_is_distinct(self):
        line = "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1"
        self.assertNotEqual(
            trade_study.normalize_defect_signature(line, "tgtA"),
            trade_study.normalize_defect_signature(line, "tgtB"),
        )

    def test_missing_signature_is_none(self):
        self.assertIsNone(trade_study.normalize_defect_signature(None, "tgt"))
        self.assertIsNone(trade_study.normalize_defect_signature("", "tgt"))

    def test_engine_summary_namespaces_defects_by_target(self):
        # Identical generic diagnostics from UNRELATED targets must not merge into
        # one defect; the normalized identity is target-scoped.
        rows = [
            {
                "outcome": "confirmed_crash",
                "crash_confirmed": True,
                "defect_identity": trade_study.normalize_defect_signature(
                    "ERROR: AddressSanitizer: SEGV on unknown address 0x0", "targetA"
                ),
                "time_to_first_crash_s": 1.0,
            },
            {
                "outcome": "confirmed_crash",
                "crash_confirmed": True,
                "defect_identity": trade_study.normalize_defect_signature(
                    "ERROR: AddressSanitizer: SEGV on unknown address 0x0", "targetB"
                ),
                "time_to_first_crash_s": 1.0,
            },
        ]
        summary = trade_study.engine_summary(rows)
        self.assertEqual(summary["normalized_diagnostic_variants"], 2)


if __name__ == "__main__":
    unittest.main()
