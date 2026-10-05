# SPDX-License-Identifier: Apache-2.0
"""Exercise the packaging guard and tag arguments from the real workflow."""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest

from test_release_workflow_contract import job_blocks, needs


ROOT = Path(__file__).resolve().parents[3]


class ReleasePackagingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.block = job_blocks((ROOT / '.github/workflows/release.yml').read_text())['build-local-artifacts']
        cls.guard = textwrap.dedent(
            cls.block.split('        run: |\n', 1)[1].split('      - name:', 1)[0]
        )

    def guard_result(self, **overrides):
        env = dict(os.environ, RELEASE_ACCEPTANCE_RESULT='success',
                   RELEASE_PLAN_RESULT='success', RELEASE_PUBLISHING='true',
                   RELEASE_TAG='0.3.0', GITHUB_REF_NAME='0.3.0')
        env.update(overrides)
        return subprocess.run(['bash', '-c', self.guard], env=env,
                              capture_output=True, text=True, timeout=5)

    def test_packaging_requires_the_acceptance_job_directly(self):
        self.assertEqual(needs(self.block), {'plan', 'release-acceptance'})
        self.assertLess(self.block.index('Require accepted release plan before packaging'),
                        self.block.index('uses: actions/checkout@'))

    def test_matching_accepted_publishing_plan_passes(self):
        self.assertEqual(self.guard_result().returncode, 0)

    def test_failed_cancelled_skipped_or_missing_upstream_result_stops_packaging(self):
        for field in ('RELEASE_ACCEPTANCE_RESULT', 'RELEASE_PLAN_RESULT'):
            for value in ('failure', 'cancelled', 'skipped', ''):
                with self.subTest(field=field, value=value):
                    self.assertNotEqual(self.guard_result(**{field: value}).returncode, 0)

    def test_nonpublishing_missing_or_wrong_tag_plan_stops_packaging(self):
        for overrides in ({'RELEASE_PUBLISHING': 'false'}, {'RELEASE_PUBLISHING': ''},
                          {'RELEASE_TAG': ''}, {'RELEASE_TAG': '0.2.34'}):
            with self.subTest(overrides=overrides):
                self.assertNotEqual(self.guard_result(**overrides).returncode, 0)

    def test_local_builds_use_mandatory_tag_without_empty_array_expansion(self):
        self.assertNotIn('tag_args', self.block)
        commands = re.findall(r'^\s*dist build .*$', self.block, re.M)
        self.assertEqual(len(commands), 2)
        for command in commands:
            self.assertIn('"--tag=$RELEASE_TAG"', command)
            # Execute the actual command with a harmless dist function so tag
            # whitespace/metacharacters must remain one argument under nounset.
            with tempfile.TemporaryDirectory() as directory:
                tag = '0.3.0; printf injected'
                env = dict(os.environ, RELEASE_TAG=tag,
                           DIST_ARGS='--artifacts=local --target=x86_64-unknown-linux-gnu')
                script = ('set -euo pipefail\n'
                          'dist() { printf "%s\\n" "$@"; }\n' + command)
                result = subprocess.run(['bash', '-c', script], cwd=directory, env=env,
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                args = (Path(directory) / 'dist-manifest.json').read_text().splitlines()
                self.assertEqual(args[:2], ['build', '--tag=' + tag])
                self.assertIn('--artifacts=local', args)


if __name__ == '__main__':
    unittest.main()
