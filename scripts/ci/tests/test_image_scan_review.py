# SPDX-License-Identifier: Apache-2.0
import datetime as dt
import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location("scan_review", pathlib.Path(__file__).resolve().parents[1] / "review-image-scan.py")
review_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review_module)


class ScanReviewTests(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime(2026, 10, 4, 12, tzinfo=dt.timezone.utc)
        self.scan = {"descriptor": {"db": {"status": {"valid": True, "built": "2026-10-04T08:00:00Z"}}}, "matches": []}

    def add(self, severity, state="not-fixed"):
        self.scan["matches"].append({"vulnerability": {"id": "CVE-example", "severity": severity, "fix": {"state": state}},
                                     "artifact": {"name": "example", "version": "1"}})

    def test_no_matches_still_requires_review(self):
        self.assertEqual(review_module.review(self.scan, self.now)["decision"], "REQUIRES_PROTECTED_REVIEW")

    def test_high_and_unknown_block_without_fix(self):
        for severity in ("High", "Critical", "Unknown"):
            with self.subTest(severity=severity):
                self.scan["matches"] = []
                self.add(severity)
                self.assertEqual(review_module.review(self.scan, self.now)["decision"], "BLOCK")

    def test_fixable_medium_blocks(self):
        self.add("Medium", "fixed")
        self.assertEqual(review_module.review(self.scan, self.now)["decision"], "BLOCK")

    def test_unfixed_medium_is_retained_under_investigation(self):
        self.add("Medium")
        result = review_module.review(self.scan, self.now)
        self.assertEqual(result["residual_findings"][0]["status"], "under_investigation")
        self.assertEqual(result["decision"], "REQUIRES_PROTECTED_REVIEW")

    def test_stale_database_blocks(self):
        self.scan["descriptor"]["db"]["status"]["built"] = "2026-09-01T00:00:00Z"
        with self.assertRaises(ValueError):
            review_module.review(self.scan, self.now)

    def test_missing_scan_does_not_mean_zero_findings(self):
        del self.scan["matches"]
        with self.assertRaises(ValueError):
            review_module.review(self.scan, self.now)
