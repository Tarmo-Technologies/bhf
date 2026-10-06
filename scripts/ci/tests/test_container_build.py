# SPDX-License-Identifier: Apache-2.0
"""Release builds preserve platform identity and never publish implicitly."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class ContainerBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'scripts').mkdir()
        for name in ('build-container-release.sh', 'language-selection.sh'):
            shutil.copy(ROOT / 'scripts' / name, self.root / 'scripts' / name)
        (self.root / 'Cargo.toml').write_text('[workspace.package]\nversion = "0.3.0"\n')
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        subprocess.run(['git', 'add', '.'], cwd=self.root, check=True)
        subprocess.run(['git', '-c', 'user.name=Local Test', '-c', 'user.email=test@example.invalid',
                        '-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'test fixture'], cwd=self.root, check=True)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.log = self.root / 'calls.jsonl'
        docker = self.bin / 'docker'
        docker.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['MOCK_DOCKER_LOG'], 'a') as f:
    f.write(json.dumps(args) + '\\n')
if args[0] == 'version':
    print(os.environ.get('MOCK_ARCH', 'amd64'))
elif args[0] == 'image':
    if '{{.Id}}' in args: print('sha256:test-image')
    else: print(os.environ.get('MOCK_PLATFORM', 'linux/amd64'))
else:
    data = sys.stdin.buffer.read()
    pathlib.Path(os.environ['MOCK_CONTEXT']).write_bytes(data)
    if '--output' in args:
        dest = args[args.index('--output') + 1].split('dest=', 1)[1]
        pathlib.Path(dest).write_bytes(b'oci-test-archive')
''')
        docker.chmod(0o755)
        # Keep mock files outside the tracked build context.
        (self.root / '.git/info').mkdir(exist_ok=True)
        (self.root / '.git/info/exclude').write_text('bin/\ncalls.jsonl\ncontext.tar\n*.oci.tar\n')
        self.env = dict(os.environ, PATH=str(self.bin) + ':' + os.environ['PATH'],
                        MOCK_DOCKER_LOG=str(self.log), MOCK_CONTEXT=str(self.root / 'context.tar'))

    def build(self, *args, **env):
        return subprocess.run(['bash', str(self.root / 'scripts/build-container-release.sh'), *args],
                              cwd=self.root, env=dict(self.env, **env), capture_output=True, text=True)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_native_arm_build_uses_daemon_architecture_and_exact_context(self):
        result = self.build('bhf:test', MOCK_ARCH='arm64', MOCK_PLATFORM='linux/arm64')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('platform=linux/arm64', result.stdout)
        build = next(c for c in self.calls() if c[0] == 'build')
        self.assertEqual(build[build.index('--platform') + 1], 'linux/arm64')
        source = subprocess.check_output(['git', 'archive', '--format=tar', 'HEAD'], cwd=self.root)
        self.assertEqual((self.root / 'context.tar').read_bytes(), source)
        self.assertIn(hashlib.sha256(source).hexdigest(), result.stdout)

    def test_multi_platform_output_is_local_and_digest_is_recorded(self):
        result = self.build('bhf:test', '--platform', 'linux/amd64,linux/arm64', '--output', 'both.oci.tar')
        self.assertEqual(result.returncode, 0, result.stderr)
        build = next(c for c in self.calls() if c[:2] == ['buildx', 'build'])
        self.assertNotIn('--push', build)
        self.assertIn('type=oci,dest=' + str(self.root / 'both.oci.tar'), build)
        self.assertFalse(any(c[0] == 'image' for c in self.calls()))
        self.assertIn(hashlib.sha256(b'oci-test-archive').hexdigest(), result.stdout)

    def test_rejects_unsupported_platform_and_multi_platform_without_output(self):
        for platform in ('windows/amd64', 'linux/386', 'linux/amd64,linux/arm64'):
            with self.subTest(platform=platform):
                result = self.build('--platform', platform)
                self.assertEqual(result.returncode, 2)
        self.assertFalse(self.calls())

    def test_does_not_overwrite_output_or_build_dirty_sources(self):
        archive = self.root / 'existing.oci.tar'
        archive.write_bytes(b'keep')
        result = self.build('--platform', 'linux/arm64', '--output', str(archive))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(archive.read_bytes(), b'keep')
        (self.root / 'Cargo.toml').write_text('dirty source\n')
        result = self.build('--platform', 'linux/arm64')
        self.assertEqual(result.returncode, 2)
        self.assertIn('clean source checkout', result.stderr)
        self.assertFalse(self.calls())

    def test_wrong_loaded_platform_fails(self):
        result = self.build('--platform', 'linux/arm64', MOCK_PLATFORM='linux/amd64')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('platform mismatch', result.stderr)


if __name__ == '__main__':
    unittest.main()
