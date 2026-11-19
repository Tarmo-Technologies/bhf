# SPDX-License-Identifier: Apache-2.0
"""Run the Linux archive smoke against stand-in component archives.

The programs in the archives are shell stand-ins for bhf and bhf-daemon, so
what is under test is the smoke's own checks: the checksum sidecars, the
manual co-location layout, the source identity and the fuzz evidence.
"""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
TARGET = "aarch64-unknown-linux-gnu"
COMMIT = "c" * 40

PROGRAM = """#!/bin/bash
set -eu
case "$1" in
  --version) printf 'bhf v%s\\ncommit: %s\\n' "$FAKE_VERSION" "${FAKE_COMMIT:-$EXPECTED_COMMIT}" ;;
  --help) echo "Usage: bhf-daemon" ;;
  scan) ;;
  auto)
    work=""; list=false
    while [ $# -gt 0 ]; do
      case "$1" in --work-dir) work=$2; shift ;; --list-targets) list=true ;; esac
      shift
    done
    if [ "$list" = false ]; then
      mkdir -p "$work/auto" "$work/harness"
      printf '{"summary": {"built_and_fuzzed": 1}}\\n' > "$work/auto/run.json"
      # Like bhf, find the runtrace shim beside the CLI.
      if [ -f "$(dirname "$0")/libbhf_runtrace_shim.so" ]; then
        echo '{"event": "shim_loaded"}' > "$work/harness/runtrace.jsonl"
      fi
    fi ;;
esac
"""


class LinuxArchiveSmokeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "scripts/ci").mkdir(parents=True)
        shutil.copy2(ROOT / "scripts/ci/linux-archive-smoke.sh", self.root / "scripts/ci")
        (self.root / "Cargo.toml").write_text('[workspace]\n\n[workspace.package]\nversion = "9.8.7"\n')
        (self.root / "tests/fixtures/engine_parity/magic_byte").mkdir(parents=True)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.stub("git", '[[ "$*" == "-C "*" rev-parse HEAD" ]] || exit 2\necho "$EXPECTED_COMMIT"')
        self.stub("clang", 'echo "clang version 18"')
        self.stub("ldd", 'echo "  libc.so.6 => /lib/libc.so.6"')
        self.distrib = self.root / "distrib"
        self.distrib.mkdir()
        for component, member, content in (
                ("bhf", "bhf", PROGRAM), ("bhf-daemon", "bhf-daemon", PROGRAM),
                ("bhf_runtrace_shim", "libbhf_runtrace_shim.so", "shim"),
                ("bhf_cc_intercept", "libbhf_cc_intercept.so", "intercept")):
            self.archive(component, member, content.encode())

    def stub(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/bash\n" + body + "\n")
        path.chmod(0o755)

    def archive(self, component, member, content):
        name = f"{component}-{TARGET}.tar.xz"
        with tarfile.open(self.distrib / name, "w:xz") as bundle:
            for entry, data in ((member, content), ("INSTALL.md", b"guide\n")):
                info = tarfile.TarInfo(f"{component}-{TARGET}/{entry}")
                info.size, info.mode = len(data), 0o755
                bundle.addfile(info, io.BytesIO(data))
        digest = hashlib.sha256((self.distrib / name).read_bytes()).hexdigest()
        (self.distrib / f"{name}.sha256").write_text(f"{digest}  {name}\n")

    def smoke(self, **env_changes):
        env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                   EXPECTED_COMMIT=COMMIT, FAKE_VERSION="9.8.7")
        env.update(env_changes)
        return subprocess.run(["bash", str(self.root / "scripts/ci/linux-archive-smoke.sh"),
                               str(self.distrib), TARGET],
                              env=env, capture_output=True, text=True, timeout=60)

    def test_matching_archives_pass(self):
        result = self.smoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"linux archive smoke: {TARGET} archives passed", result.stdout)

    def test_another_commit_or_version_fails(self):
        for change in ({"FAKE_COMMIT": "d" * 40}, {"FAKE_VERSION": "9.8.6"}):
            with self.subTest(change=change):
                self.assertNotEqual(self.smoke(**change).returncode, 0)

    def test_archive_that_disagrees_with_its_sidecar_fails(self):
        sidecar = self.distrib / f"bhf_cc_intercept-{TARGET}.tar.xz.sha256"
        sidecar.write_text("0" * 64 + sidecar.read_text()[64:])
        self.assertNotEqual(self.smoke().returncode, 0)

    def test_missing_shim_archive_fails(self):
        (self.distrib / f"bhf_runtrace_shim-{TARGET}.tar.xz").unlink()
        self.assertNotEqual(self.smoke().returncode, 0)

    def test_unresolved_library_fails(self):
        self.stub("ldd", 'echo "  libfoo.so.1 => not found"')
        result = self.smoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("archives passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
