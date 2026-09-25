# SPDX-License-Identifier: Apache-2.0
"""Apply the reviewed, hash-pinned maintenance payload; never execute its text."""
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys

expected = sys.argv[1]
head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
if head != expected:
    raise SystemExit('unexpected checkout revision')
blob = Path('scripts/maintenance/enterprise-edits.json.gz').read_bytes()
if hashlib.sha256(blob).hexdigest() != '43503be4fcc41e3eabc0d7d6ddd6f37a425c072633bcb156c60abeb89bb707ee':
    raise SystemExit('maintenance payload digest mismatch')
payload = json.loads(gzip.decompress(blob))
for path, expected_blob in payload['original_blobs'].items():
    original = subprocess.check_output(['git', 'cat-file', 'blob', expected_blob])
    actual = Path(path).read_bytes()
    if actual != original and actual.replace(b'\r\n', b'\n') != original:
        raise SystemExit('source blob mismatch: ' + path)
    Path(path).write_bytes(original)
allowed = {'crates/governance/src/vex.rs', 'crates/cli/tests/sbom_assurance_cli.rs', 'scripts/tests/test_offline_verifier.py'}
if set(payload['files']) != allowed:
    raise SystemExit('unexpected replacement file')
patch = Path('.git/bhf-enterprise-reviewed.patch')
patch.write_bytes(payload['patch'].encode('utf-8'))
subprocess.run(['git', 'apply', '--check', str(patch)], check=True)
subprocess.run(['git', 'apply', str(patch)], check=True)
for path, text in payload['files'].items():
    target = Path(path)
    if path not in payload['original_blobs'] and target.exists():
        raise SystemExit('new file already exists: ' + path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(text.encode('utf-8'))
subprocess.run(['git', 'diff', '--check'], check=True)
print('Applied reviewed source, test, verifier and CI edits to exact original blobs.')
