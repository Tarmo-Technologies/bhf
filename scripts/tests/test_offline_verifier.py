# SPDX-License-Identifier: Apache-2.0
"""Exercise the actual detached verifier with real Ed25519 signatures."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verify-offline-dist.sh"
DOMAIN = b"BHF.DIST.TARBALL.ED25519.V1\0"


class OfflineVerifierTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.openssl = shutil.which("openssl")
        self.assertIsNotNone(self.openssl, "OpenSSL with Ed25519 support is required")
        self.archive = self.root / "bundle with spaces.tar.gz"
        # The verifier must authenticate opaque bytes, not extract/run them.
        self.archive.write_bytes(b"not an executable archive\0test bytes")
        self.key = self.root / "private.pem"
        self.public = self.root / "trusted.hex"
        self.sig = self.root / "archive.sig"
        self.message = self.root / "message.bin"
        self.crypto("genpkey", "-algorithm", "Ed25519", "-out", str(self.key))
        public_der = self.crypto("pkey", "-in", str(self.key), "-pubout", "-outform", "DER").stdout
        self.assertEqual(public_der[:12].hex(), "302a300506032b6570032100")
        self.public.write_text(public_der[-32:].hex() + "\n", encoding="ascii")
        self.message.write_bytes(DOMAIN + hashlib.sha256(self.archive.read_bytes()).digest())
        self.crypto("pkeyutl", "-sign", "-inkey", str(self.key), "-rawin", "-in", str(self.message), "-out", str(self.sig))
        # Deliberately exclude xxd and all other unlisted utilities.
        bindir = self.root / "minimal-bin"
        bindir.mkdir()
        for name in ("bash", "openssl", "wc", "tr", "mktemp", "rm", "rmdir", "cat"):
            binary = shutil.which(name)
            self.assertIsNotNone(binary, name)
            (bindir / name).symlink_to(binary)
        self.env = dict(os.environ, PATH=str(bindir))

    def crypto(self, *args):
        return subprocess.run([self.openssl, *args], capture_output=True, check=True, timeout=15)

    def verify(self):
        return subprocess.run(["bash", str(SCRIPT), "--archive", str(self.archive),
            "--signature", str(self.sig), "--trusted-public-key", str(self.public)],
            env=self.env, capture_output=True, timeout=15)

    def test_valid_signature_works_without_xxd_and_without_extracting_archive(self):
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"Verified distribution signature:", result.stdout)
        self.assertIsNone(shutil.which("xxd", path=self.env["PATH"]))

    def test_tampered_archive_is_rejected(self):
        self.archive.write_bytes(self.archive.read_bytes() + b"changed")
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b"Verified distribution", result.stdout)

    def test_wrong_signature_is_rejected(self):
        sig = bytearray(self.sig.read_bytes())
        sig[0] ^= 1
        self.sig.write_bytes(sig)
        self.assertNotEqual(self.verify().returncode, 0)

    def test_wrong_but_well_formed_trusted_key_is_rejected(self):
        self.public.write_text("00" * 32 + "\n")
        self.assertNotEqual(self.verify().returncode, 0)

    def test_truncated_signature_is_rejected(self):
        self.sig.write_bytes(self.sig.read_bytes()[:-1])
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"exactly 64 bytes", result.stderr)

    def test_malformed_or_oversized_public_key_is_rejected(self):
        for key in ("A" * 64, "0" * 63, "g" * 64, "00" * 10000):
            with self.subTest(length=len(key)):
                self.public.write_text(key)
                self.assertNotEqual(self.verify().returncode, 0)

    def test_symlink_signature_is_rejected(self):
        real = self.root / "real.sig"
        self.sig.rename(real)
        self.sig.symlink_to(real)
        self.assertNotEqual(self.verify().returncode, 0)

    def test_a_signature_without_domain_separation_is_rejected(self):
        self.message.write_bytes(hashlib.sha256(self.archive.read_bytes()).digest())
        self.crypto("pkeyutl", "-sign", "-inkey", str(self.key), "-rawin", "-in", str(self.message), "-out", str(self.sig))
        self.assertNotEqual(self.verify().returncode, 0)


if __name__ == "__main__":
    unittest.main()
