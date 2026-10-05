# SPDX-License-Identifier: Apache-2.0
"""A resumed image matrix must retain its identity and verified evidence."""
import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / 'container-selection-matrix.py'
SPEC = importlib.util.spec_from_file_location('selection_matrix', SCRIPT)
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)


class ResumeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        (self.root / '0').mkdir()
        log = self.root / '0/build.log'
        log.write_text('completed image build\n')
        self.report = {'schema_version': 2, 'source_commit': 'c' * 40,
                       'source_archive_sha256': 'a' * 64,
                       'selections': ['c', 'java'], 'remaining': ['java'],
                       'results': [{'requested': 'c', 'status': 'passed',
                                    'evidence': {'0/build.log': hashlib.sha256(log.read_bytes()).hexdigest()}}]}

    def validate(self, **overrides):
        return MATRIX.validate_resume(self.report, self.root,
                                      overrides.get('commit', 'c' * 40),
                                      overrides.get('source_sha', 'a' * 64),
                                      overrides.get('selections'))

    def test_resume_retains_completed_rows_and_remaining_selection(self):
        MATRIX.persist(self.report, self.root)
        saved = json.loads((self.root / 'matrix.json').read_text())
        result = MATRIX.validate_resume(saved, self.root, 'c' * 40, 'a' * 64)
        self.assertEqual(result['remaining'], ['java'])
        self.assertEqual(len(result['results']), 1)
        self.assertFalse((self.root / 'matrix.json.tmp').exists())

    def test_rejects_changed_source_or_reordered_selections(self):
        for overrides in ({'commit': 'b' * 40}, {'source_sha': 'b' * 64},
                          {'selections': ['java', 'c']}):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                self.validate(**overrides)

    def test_rejects_modified_and_missing_evidence(self):
        log = self.root / '0/build.log'
        log.write_text('changed\n')
        with self.assertRaisesRegex(ValueError, 'hash differs'):
            self.validate()
        log.unlink()
        with self.assertRaisesRegex(ValueError, 'missing'):
            self.validate()

    def test_rejects_evidence_outside_directory(self):
        self.report['results'][0]['evidence'] = {'../outside': 'a' * 64}
        with self.assertRaisesRegex(ValueError, 'invalid evidence'):
            self.validate()

    def test_rejects_corrupt_progress_and_legacy_checkpoint(self):
        self.report['remaining'] = ['c', 'java']
        with self.assertRaisesRegex(ValueError, 'progress differs'):
            self.validate()
        self.report.pop('schema_version')
        with self.assertRaisesRegex(ValueError, 'predates'):
            self.validate()


if __name__ == '__main__':
    unittest.main()
