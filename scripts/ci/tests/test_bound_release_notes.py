# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/ci/bound-release-notes.py"
SPEC = importlib.util.spec_from_file_location("bound_release_notes", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BoundReleaseNotesTests(unittest.TestCase):
    def test_short_notes_are_unchanged(self):
        self.assertEqual(MODULE.bound_notes("short notes\n", "owner/repo", "1.2.3"), "short notes\n")

    def test_long_unicode_notes_fit_and_link_to_full_changelog(self):
        result = MODULE.bound_notes("release entry é\n" * 20_000, "owner/repo", "1.2.3/rc1")
        self.assertLessEqual(len(result.encode("utf-8")), MODULE.MAX_BODY_BYTES)
        self.assertIn("generated notes were shortened", result)
        self.assertIn("owner/repo/blob/1.2.3%2Frc1/CHANGELOG.md", result)
        result.encode("utf-8")


if __name__ == "__main__":
    unittest.main()
