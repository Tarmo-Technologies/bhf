# SPDX-License-Identifier: Apache-2.0
"""Source contracts for the checked-in workflow layout, plus actual shell steps.

This deliberately parses only this repository's simple job layout. It is not a
GitHub Actions emulator; hosted runs remain necessary for release acceptance.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[3]


def job_blocks(text):
    matches = list(re.finditer(r'^  ([a-z][a-z0-9-]*):\s*$', text.split('\njobs:\n', 1)[1], re.M))
    body = text.split('\njobs:\n', 1)[1]
    result = {}
    for i, match in enumerate(matches):
        if match[1] in result: raise AssertionError('duplicate job')
        result[match[1]] = body[match.end():matches[i+1].start() if i+1 < len(matches) else len(body)]
    return result


def needs(block):
    match = re.search(r'^    needs:(.*)$', block, re.M)
    if not match: return set()
    if match[1].strip(): return set(match[1].strip().strip('[]').replace(' ', '').split(','))
    tail = block[match.end():]
    result = []
    for line in tail.splitlines():
        if not line.strip(): continue
        if not line.startswith('      - '): break
        result.append(line.strip()[2:])
    return set(result)


class ReleaseWorkflowContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.release = (ROOT / '.github/workflows/release.yml').read_text()
        cls.jobs = job_blocks(cls.release)
        cls.ci = (ROOT / '.github/workflows/ci.yml').read_text()
        cls.ci_jobs = job_blocks(cls.ci)
        cls.classifier = (ROOT / '.github/workflows/classify-ci-scope.yml').read_text()

    def test_default_release_permissions_are_read_only(self):
        self.assertIn('permissions:\n  contents: read\n', self.release.split('\njobs:\n')[0])

    def test_only_gated_tag_jobs_have_write_permissions(self):
        writers = {name for name, block in self.jobs.items() if '      contents: write' in block}
        self.assertEqual(writers, {'release-plan', 'host'})
        for name in writers:
            block = self.jobs[name]
            self.assertIn('release-acceptance', needs(block))
            self.assertIn("needs.release-acceptance.result == 'success'", block)
            self.assertIn("github.event_name == 'push'", block)
            self.assertIn("github.ref_type == 'tag'", block)

    def test_release_ci_uses_exact_local_workflow_with_force_full(self):
        block = self.jobs['validate-release-ci']
        self.assertIn('uses: ./.github/workflows/ci.yml', block)
        self.assertIn('force_full: true', block)
        self.assertNotIn('secrets:', block)
        self.assertIn('contents: read', block)

    def test_release_gate_executes_on_upstream_failure(self):
        block = self.jobs['release-acceptance']
        self.assertIn('${{ always() &&', block)
        self.assertEqual(needs(block), {'validate-release-ci'})
        self.assertIn('CI_VALIDATION_JSON: ${{ toJSON(needs.validate-release-ci) }}', block)
        for name in ('GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_REF', 'GITHUB_REPOSITORY'):
            self.assertIn('"$' + name + '"', block)
        self.assertIn('check-release-acceptance.py', block)

    def test_gate_keeps_failure_receipt(self):
        block = self.jobs['release-acceptance']
        self.assertIn('if: ${{ always() }}', block)
        self.assertIn('if-no-files-found: error', block)
        self.assertIn('release-ci-acceptance-${{ github.run_id }}-${{ github.run_attempt }}', block)

    def test_signing_requires_gate_and_protected_environment(self):
        block = self.jobs['sign-linux-bundle']
        self.assertIn('release-acceptance', needs(block))
        self.assertIn("needs.release-acceptance.result == 'success'", block)
        self.assertIn('environment: production-release', block)
        self.assertIn('contents: read', block)

    def test_signing_key_only_exists_in_signing_job(self):
        for name, block in self.jobs.items():
            if name != 'sign-linux-bundle':
                self.assertNotIn('secrets.BHF_RELEASE_SIGNING_KEY', block)
        self.assertNotIn('secrets: inherit', self.release)

    def test_pr_planning_is_read_only_and_preserves_dist_plan(self):
        block = self.jobs['pull-request-plan']
        self.assertIn("github.event_name == 'pull_request'", block)
        self.assertIn('contents: read', block)
        self.assertIn('dist plan --output-format=json', block)
        self.assertNotIn('dist host ', block)
        self.assertNotIn('gh release ', block)
        self.assertEqual(needs(block), set())

    def test_release_plan_preserves_existing_create_semantics(self):
        block = self.jobs['release-plan']
        self.assertIn('dist host --steps=create --tag="$RELEASE_TAG"', block)
        self.assertIn('RELEASE_TAG: ${{ github.ref_name }}', block)

    def test_every_release_checkout_is_pinned_and_does_not_persist_credentials(self):
        lines = self.release.splitlines()
        for index, line in enumerate(lines):
            if 'uses: actions/checkout@' in line:
                tail = '\n'.join(lines[index+1:index+6])
                self.assertIn('ref: ${{ github.sha }}', tail)
                self.assertIn('persist-credentials: false', tail)

    def test_all_release_runner_jobs_are_bounded(self):
        for name, block in self.jobs.items():
            if re.search(r'^    runs-on:', block, re.M):
                self.assertRegex(block, r'(?m)^    timeout-minutes: [1-9][0-9]*$', name)

    def test_no_acceptance_bypass_constructs(self):
        for source in (self.release, self.ci):
            self.assertNotIn('continue-on-error:', source)
            self.assertNotIn('pull_request_target:', source)

    def test_concurrency_groups_cannot_self_cancel_release(self):
        self.assertIn('group: release-${{ github.ref }}', self.release)
        self.assertIn('cancel-in-progress: false', self.release.split('\njobs:\n')[0])
        self.assertIn('group: ci-${{ github.workflow }}-${{ github.ref }}', self.ci)

    def test_ci_exports_exact_revision_run_and_attempt(self):
        for field in ('decision', 'commit', 'run_id', 'run_attempt'):
            self.assertIn('value: ${{ jobs.ci-acceptance.outputs.' + field + ' }}', self.ci)
            self.assertIn('${{ steps.acceptance.outputs.' + field + ' }}', self.ci_jobs['ci-acceptance'])
        self.assertIn('id: acceptance', self.ci_jobs['ci-acceptance'])

    def test_forced_full_is_checked_at_classifier_and_final_gate(self):
        self.assertIn('force_full: ${{ inputs.force_full || false }}', self.ci_jobs['changes'])
        self.assertIn("REQUIRE_FULL_CI: ${{ inputs.force_full || github.ref_type == 'tag' }}", self.ci_jobs['ci-acceptance'])
        self.assertIn('full_args+=(--require-full)', self.ci_jobs['ci-acceptance'])
        self.assertIn('${FORCE_FULL_CI-false}', self.classifier)

    def test_original_ci_lanes_remain_required(self):
        expected = {'changes', 'ci-policy', 'minimum-rust', 'build-test', 'rhel7-build',
                    'rhel-family-smoke', 'ubuntu-release-smoke', 'windows-build', 'windows-current-build'}
        self.assertEqual(set(self.ci_jobs) - {'ci-acceptance'}, expected)
        self.assertEqual(needs(self.ci_jobs['ci-acceptance']), expected)

    def test_legacy_preflight_precedes_tests_and_tests_are_kept(self):
        block = self.ci_jobs['rhel7-build']
        preflight = block.index('bash scripts/ci/build-test-openssl.sh /tmp/bhf-ci-openssl')
        for command in ('cargo test --locked -p continuous_daemon --lib',
                        'cargo test --locked -p governance --lib',
                        'cargo test --locked -p bhf --test offline_dist_scripts',
                        'cargo build --locked --release --workspace', 'scripts/check-linux-release-abi.sh'):
            self.assertLess(preflight, block.index(command))
        self.assertIn('manylinux2014_x86_64@sha256:0d25b049964b2549b83384036abdff06789a8c0b1e9ff003ec80f0d531f79e50', block)

    def test_new_verifier_tests_are_in_full_ci(self):
        self.assertIn("python3 -m unittest discover -s scripts/tests -p 'test_offline_verifier.py' -v", self.ci_jobs['build-test'])

    def test_no_tag_interpolation_in_shell_programs(self):
        for forbidden in ('dist host ${{', 'dist build ${{ needs.plan.outputs.tag',
                          'gh release create "${{', 'dist build $DIST_TAG_FLAG'):
            self.assertNotIn(forbidden, self.release)

    def test_all_needs_refer_to_declared_jobs(self):
        for name, block in self.jobs.items():
            self.assertTrue(needs(block) <= self.jobs.keys(), name)


class ForcedClassificationShellTests(unittest.TestCase):
    def run_step(self, force=None, ref_type='branch', event='push'):
        workflow = (ROOT / '.github/workflows/classify-ci-scope.yml').read_text()
        step = workflow.split('      - name: Classify changed paths\n', 1)[1]
        script = textwrap.dedent(step.split('        run: |\n', 1)[1])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'bin').mkdir(); (root / 'scripts/ci').mkdir(parents=True)
            # The old helper's content-based decision is not under test here.
            # A docs-only result cannot override the new forced/tag branch.
            classifier = root / 'scripts/ci/should-run-heavy-ci.sh'
            classifier.write_text('#!/bin/bash\nprintf false\n'); classifier.chmod(0o755)
            git = root / 'bin/git'
            git.write_text('#!/bin/bash\nif [[ "$1" == cat-file ]]; then exit 0; fi\nif [[ "$1" == diff ]]; then printf "README.md\\0"; exit 0; fi\nexit 99\n'); git.chmod(0o755)
            env = dict(os.environ, PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'],
                       EVENT_NAME=event, BASE_SHA='a' * 40, HEAD_SHA='b' * 40,
                       REF_TYPE=ref_type, GITHUB_OUTPUT=str(root / 'output'),
                       GITHUB_STEP_SUMMARY=str(root / 'summary'))
            env.pop('FORCE_FULL_CI', None)
            if force is not None: env['FORCE_FULL_CI'] = force
            run = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script], cwd=root,
                                 env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            return (root / 'output').read_text()

    def test_forced_true_overrides_docs_change(self):
        self.assertEqual(self.run_step(force='true'), 'heavy=true\n')

    def test_tag_push_overrides_docs_change(self):
        self.assertEqual(self.run_step(force='false', ref_type='tag'), 'heavy=true\n')

    def test_manual_run_remains_full(self):
        self.assertEqual(self.run_step(force='false', event='workflow_dispatch'), 'heavy=true\n')

    def test_unset_and_false_preserve_ordinary_docs_classification(self):
        for force in (None, 'false'): self.assertEqual(self.run_step(force=force), 'heavy=false\n')

    def test_malformed_force_values_fail_closed(self):
        for force in ('', 'False', '0', 'unknown'):
            self.assertEqual(self.run_step(force=force), 'heavy=true\n')


class CiExportStepTests(unittest.TestCase):
    def export(self, receipt, **env_changes):
        ci = (ROOT / '.github/workflows/ci.yml').read_text()
        code = textwrap.dedent(ci.split("          python3 - <<'PYTHON'\n", 1)[1].split('          PYTHON', 1)[0])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'ci-acceptance.json').write_text(json.dumps(receipt))
            env = dict(os.environ, GITHUB_SHA='a' * 40, GITHUB_RUN_ID='1234', GITHUB_RUN_ATTEMPT='2', GITHUB_OUTPUT=str(root / 'out'))
            env.update(env_changes)
            run = subprocess.run([sys.executable, '-c', code], cwd=root, env=env,
                                 capture_output=True, text=True, timeout=10)
            return run.returncode, (root / 'out').read_text() if (root / 'out').exists() else ''

    def test_success_exports_only_expected_fields(self):
        status, output = self.export(dict(accepted=True, commit='a' * 40, decision='PASS_FULL_CI'))
        self.assertEqual(status, 0)
        self.assertEqual(output.splitlines(), ['decision=PASS_FULL_CI', 'commit='+'a'*40, 'run_id=1234', 'run_attempt=2'])

    def test_docs_export_is_labelled_docs_not_full(self):
        status, output = self.export(dict(accepted=True, commit='a' * 40, decision='PASS_DOCS_ONLY'))
        self.assertEqual(status, 0); self.assertIn('decision=PASS_DOCS_ONLY', output)

    def test_malformed_or_failed_export_writes_nothing(self):
        for receipt in ({'accepted': False}, {'accepted': True, 'commit': 'b' * 40, 'decision': 'PASS_FULL_CI'},
                        {'accepted': True, 'commit': 'a' * 40, 'decision': 'PASS_FULL_CI\nforged=true'}):
            status, output = self.export(receipt)
            self.assertNotEqual(status, 0); self.assertEqual(output, '')

    def test_optimized_python_does_not_disable_export_checks(self):
        status, output = self.export(dict(accepted=False, commit='a' * 40, decision='PASS_FULL_CI'), PYTHONOPTIMIZE='1')
        self.assertNotEqual(status, 0); self.assertEqual(output, '')

    def test_injected_run_id_does_not_write_workflow_output(self):
        status, output = self.export(dict(accepted=True, commit='a' * 40, decision='PASS_FULL_CI'), GITHUB_RUN_ID='1234\nextra=true')
        self.assertNotEqual(status, 0); self.assertEqual(output, '')


if __name__ == '__main__': unittest.main()
