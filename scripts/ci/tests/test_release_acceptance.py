# SPDX-License-Identifier: Apache-2.0
"""Exercise the release policy and real CLI using only the Python stdlib."""
from __future__ import annotations
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / 'scripts/ci/check-release-acceptance.py'
SPEC = importlib.util.spec_from_file_location('release_acceptance', SCRIPT)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)
SHA = 'a' * 40
CONTEXT = dict(commit=SHA, event='push', ref='refs/tags/v1.2.3',
               repository='Tarmo-Technologies/bhf', run_id='1234', run_attempt='2')


def observation():
    return {'result': 'success', 'outputs': {'decision': 'PASS_FULL_CI',
            'commit': SHA, 'run_id': '1234', 'run_attempt': '2'}}


class ReleaseAcceptanceTests(unittest.TestCase):
    def assert_blocked(self, value=None, **context):
        try:
            result = GATE.evaluate(observation() if value is None else value,
                                   **(CONTEXT | context))
        except GATE.InvalidObservation:
            return
        self.assertFalse(result['accepted'])
        self.assertFalse(result['full_ci_passed'])
        self.assertEqual(result['decision'], 'BLOCKED')
        self.assertTrue(result['blockers'])

    def test_exact_same_run_full_ci_passes(self):
        report = GATE.evaluate(observation(), **CONTEXT)
        self.assertTrue(report['accepted'])
        self.assertTrue(report['full_ci_passed'])
        self.assertEqual(report['decision'], 'PASS_RELEASE_CI')
        self.assertEqual(report['commit'], SHA)

    def test_no_artifact_or_enterprise_claim(self):
        result = GATE.evaluate(observation(), **CONTEXT)
        for key in ('artifact_authenticity', 'deployment_authorization', 'enterprise_readiness'):
            self.assertEqual(result[key], 'not_assessed')

    def test_docs_only_is_not_release_ci(self):
        value = observation(); value['outputs']['decision'] = 'PASS_DOCS_ONLY'
        self.assert_blocked(value)

    def test_unsuccessful_job_cannot_be_rescued_by_pass_output(self):
        for status in ('failure', 'cancelled', 'skipped', 'in_progress', None, True, 1, {}, []):
            with self.subTest(status=status):
                value = observation(); value['result'] = status
                self.assert_blocked(value)

    def test_unknown_decisions_fail(self):
        for decision in ('', 'BLOCKED', 'PASS_RELEASE_CI', 'pass_full_ci', None, True):
            with self.subTest(decision=decision):
                value = observation(); value['outputs']['decision'] = decision
                self.assert_blocked(value)

    def test_wrong_revision_rejected(self):
        value = observation(); value['outputs']['commit'] = 'b' * 40
        self.assert_blocked(value)

    def test_branch_name_cannot_replace_sha(self):
        value = observation(); value['outputs']['commit'] = 'rtos-radar-fuzzing'
        self.assert_blocked(value)

    def test_old_run_rejected(self):
        value = observation(); value['outputs']['run_id'] = '1233'
        self.assert_blocked(value)

    def test_old_attempt_rejected(self):
        value = observation(); value['outputs']['run_attempt'] = '1'
        self.assert_blocked(value)

    def test_numeric_not_string_output_ids_rejected(self):
        for field, value in (('run_id', 1234), ('run_attempt', 2)):
            item = observation(); item['outputs'][field] = value
            self.assert_blocked(item)

    def test_every_export_is_required(self):
        for field in GATE.OUTPUT_KEYS:
            with self.subTest(field=field):
                value = observation(); del value['outputs'][field]
                self.assert_blocked(value)

    def test_unexpected_export_rejected(self):
        value = observation(); value['outputs']['new_requirement'] = 'failure'
        self.assert_blocked(value)

    def test_missing_and_wrong_outer_fields_rejected(self):
        for value in ({}, {'result': 'success'}, {'outputs': {}},
                      observation() | {'unlisted_job': 'failure'}):
            self.assert_blocked(value)

    def test_wrong_outputs_shapes_rejected(self):
        for outputs in (None, [], 'PASS_FULL_CI', False, 0):
            self.assert_blocked({'result': 'success', 'outputs': outputs})

    def test_non_tag_push_rejected(self):
        self.assert_blocked(ref='refs/heads/main')

    def test_wrong_events_rejected(self):
        for event in ('pull_request', 'workflow_dispatch', 'workflow_run', '', None):
            self.assert_blocked(event=event)

    def test_malformed_tag_refs_rejected(self):
        for ref in ('refs/tags/', 'refs/tags/-v1', 'refs/tags/a..b', 'refs/tags/a b',
                    'refs/tags/a\nb', 'refs/tags/a.lock', 'refs/tags/a/.hidden',
                    'refs/tags/a//b', 'refs/tags/a\\b', 'refs/tags/a@{b',
                    'refs/tags/a*', 'refs/tags/' + 'a' * 300, 'refs/tags/a/'):
            with self.subTest(ref=ref): self.assert_blocked(ref=ref)

    def test_supported_nested_version_tag_accepted(self):
        self.assertTrue(GATE.evaluate(observation(), **(CONTEXT | {'ref': 'refs/tags/releases/v1.2.3-rc.1'}))['accepted'])

    def test_invalid_expected_sha_rejected(self):
        for sha in ('0' * 40, 'A' * 40, 'a' * 39, 'a' * 41, 'main', None):
            with self.subTest(sha=sha): self.assert_blocked(commit=sha)

    def test_invalid_expected_ids_rejected(self):
        for value in ('0', '01', '-1', '+1', '1.0', ' 1', '1\n', True, 2, '9' * 21):
            with self.subTest(value=value):
                self.assert_blocked(run_id=value)
                self.assert_blocked(run_attempt=value)

    def test_invalid_repository_rejected(self):
        for repo in ('', 'bhf', 'org/repo/more', 'org/repo\n', None):
            self.assert_blocked(repository=repo)

    def test_parser_accepts_valid_object(self):
        self.assertEqual(GATE.parse_observation(json.dumps(observation()).encode()), observation())

    def test_parser_rejects_duplicate_keys_at_both_levels(self):
        for raw in (b'{"result":"success","result":"failure"}',
                    b'{"outputs":{"commit":"a","commit":"b"}}'):
            with self.assertRaises(GATE.InvalidObservation): GATE.parse_observation(raw)

    def test_parser_rejects_invalid_json_utf8_and_non_objects(self):
        for raw in (b'[]', b'null', b'false', b'3', b'{', b'\xff', b'{} garbage'):
            with self.assertRaises(GATE.InvalidObservation): GATE.parse_observation(raw)

    def test_parser_rejects_non_json_constants(self):
        for constant in ('NaN', 'Infinity', '-Infinity'):
            with self.assertRaises(GATE.InvalidObservation):
                GATE.parse_observation(('{"x":' + constant + '}').encode())

    def test_input_size_exact_boundary_and_over(self):
        raw = b'{}' + b' ' * (GATE.MAX_INPUT_BYTES - 2)
        self.assertEqual(GATE.parse_observation(raw), {})
        with self.assertRaises(GATE.InvalidObservation): GATE.parse_observation(raw + b' ')

    def test_nested_input_is_bounded(self):
        raw = b'{"x":' * 12 + b'0' + b'}' * 12
        with self.assertRaises(GATE.InvalidObservation): GATE.parse_observation(raw)
        with self.assertRaises(GATE.InvalidObservation): GATE.parse_observation(b'{"x":' * 2000 + b'0' + b'}' * 2000)


class ReleaseCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.output = self.root / 'receipt.json'
        self.command = [sys.executable, str(SCRIPT), '--output', str(self.output)]
        for field, value in CONTEXT.items(): self.command += ['--' + field.replace('_', '-'), value]

    def run_cli(self, raw=None, extra=(), env_changes=None):
        env = dict(os.environ); env.pop('CI_VALIDATION_JSON', None)
        if raw is not None: env['CI_VALIDATION_JSON'] = raw
        env.update(env_changes or {})
        return subprocess.run(self.command + list(extra), env=env, capture_output=True, text=True, timeout=10)

    def test_real_cli_success_and_json(self):
        run = self.run_cli(json.dumps(observation()))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(json.loads(run.stdout)['accepted'])
        self.assertEqual(json.loads(run.stdout), json.loads(self.output.read_text()))

    def test_real_cli_failure_overwrites_stale_success(self):
        self.assertEqual(self.run_cli(json.dumps(observation())).returncode, 0)
        run = self.run_cli('{')
        self.assertEqual(run.returncode, 1)
        self.assertFalse(json.loads(self.output.read_text())['accepted'])
        self.assertEqual(list(self.root.glob('.receipt.json.*')), [])

    def test_missing_env_blocks(self):
        run = self.run_cli()
        self.assertEqual(run.returncode, 1)
        self.assertFalse(json.loads(self.output.read_text())['accepted'])

    def test_missing_file_blocks_and_redacts_path(self):
        missing = self.root / 'private-customer-name.json'
        run = self.run_cli(extra=['--needs-file', str(missing)])
        self.assertEqual(run.returncode, 1)
        self.assertNotIn('private-customer-name', run.stdout)

    def test_file_input_works_without_env(self):
        source = self.root / 'needs.json'; source.write_text(json.dumps(observation()))
        run = self.run_cli(extra=['--needs-file', str(source)])
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_write_failure_is_not_success(self):
        self.output.mkdir()
        run = self.run_cli(json.dumps(observation()))
        self.assertEqual(run.returncode, 2)
        self.assertNotIn('PASS_RELEASE_CI', run.stdout)
        self.assertEqual(list(self.root.glob('.receipt.json.*')), [])

    def test_untrusted_json_text_is_not_echoed(self):
        run = self.run_cli('{"secret-customer-token": "DO_NOT_ECHO"}')
        self.assertEqual(run.returncode, 1)
        self.assertNotIn('DO_NOT_ECHO', run.stdout + run.stderr)


if __name__ == '__main__': unittest.main()
