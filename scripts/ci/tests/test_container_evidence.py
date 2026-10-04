# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "container-evidence.py"
spec = importlib.util.spec_from_file_location("container_evidence", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ContainerEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        for name in module.COMMON | module.FLAVOR_LOGS["core"]:
            (self.root / name).write_text("test evidence")
        (self.root / "image-inspect.json").write_text(json.dumps([{
            "Id": "sha256:example", "Config": {"Labels": {
                "io.tarmo.bhf.flavor": "core", "org.opencontainers.image.revision": "a" * 40}}}]))
        (self.root / "build-receipt.json").write_text(json.dumps({"source_commit": "a" * 40}))

    def command(self, mode):
        return subprocess.run([sys.executable, str(SCRIPT), mode, str(self.root)], capture_output=True)

    def test_only_completed_unchanged_evidence_verifies(self):
        self.assertNotEqual(self.command("verify").returncode, 0)
        self.assertEqual(self.command("record").returncode, 0)
        self.assertEqual(self.command("verify").returncode, 0)
        self.assertNotEqual(self.command("record").returncode, 0)
        (self.root / "auto.log").write_text("changed")
        self.assertNotEqual(self.command("verify").returncode, 0)

    def test_missing_check_or_mismatched_source_cannot_be_recorded(self):
        (self.root / "build-receipt.json").write_text(json.dumps({"source_commit": "b" * 40}))
        self.assertNotEqual(self.command("record").returncode, 0)
        (self.root / "build-receipt.json").write_text(json.dumps({"source_commit": "a" * 40}))
        (self.root / "termination.log").unlink()
        self.assertNotEqual(self.command("record").returncode, 0)
