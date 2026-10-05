from pathlib import Path
import re
import subprocess
import sys

root = Path('/home/ubuntu/vuln_research/tools/bhf')
sys.path.insert(0, str(root / 'scripts/ci/tests'))
from test_release_workflow_contract import job_blocks

block = job_blocks((root / '.github/workflows/release.yml').read_text())['build-local-artifacts']
commands = re.findall(r'^\s*dist build .*$', block, re.M)
guards = re.findall(r'^\s*: "\$\{RELEASE_TAG:\?release tag is required\}"$', block, re.M)
assert len(commands) == len(guards) == 2
image = 'bash@sha256:233f59779725ea9bb8096d7773e4ae7b4a0db866364f7775a78b6eb42bf0fb23'
for command, guard in zip(commands, guards):
    for tag in ['0.3.0', '0.3.0; printf injected', '']:
        script = ('set -euo pipefail\n'
                  'dist() { printf "%s\\n" "$@"; }\n' + guard + '\n' + command +
                  '\ncat dist-manifest.json\n')
        result = subprocess.run([
            'docker', 'run', '--rm', '--memory', '256m', '--cpus', '1',
            '--pids-limit', '32', '--network', 'none', '--read-only',
            '--tmpfs', '/work:rw,nosuid,size=1m', '--workdir', '/work',
            '-e', 'RELEASE_TAG=' + tag,
            '-e', 'DIST_ARGS=--artifacts=local --target=x86_64-unknown-linux-gnu',
            image, 'bash', '-c', script,
        ], capture_output=True, text=True, timeout=20)
        if tag:
            assert result.returncode == 0, result.stderr
            assert result.stdout.splitlines()[:2] == ['build', '--tag=' + tag], result.stdout
        else:
            assert result.returncode != 0 and 'release tag is required' in result.stderr, result.stderr
print('PASS: both real packaging commands on pinned Bash 4.2; matching/metacharacter tags and missing-tag rejection')
