# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]


class ContainerSigningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.archive = self.root / "candidate.tar.gz"
        self.archive.write_bytes(b"archive-byte-signature-acceptance\n")
        self.key = self.root / "private.der"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-outform", "DER", "-out", str(self.key)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        public = subprocess.check_output(["openssl", "pkey", "-inform", "DER", "-in", str(self.key), "-pubout", "-outform", "DER"])
        self.public = self.root / "public.hex"
        self.public.write_text(public[-32:].hex() + "\n")
        self.digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()

    def sign(self, digest=None):
        return subprocess.run(["python3", str(ROOT / "scripts/sign-container-candidate.py"),
                               "--archive", str(self.archive), "--expected-sha256", digest or self.digest,
                               "--signing-key", str(self.key), "--trusted-public-key", str(self.public)],
                              capture_output=True, text=True)

    def test_independent_verifier_accepts_signed_candidate(self):
        signed = self.sign()
        self.assertEqual(signed.returncode, 0, signed.stderr)
        verified = subprocess.check_output(["python3", str(ROOT / "scripts/verify-offline-dist.py"),
                                            "--archive", str(self.archive), "--signature", str(self.archive) + ".sig",
                                            "--trusted-public-key", str(self.public), "--json"], text=True)
        self.assertEqual(json.loads(verified)["archive_sha256"], self.digest)

    def test_modified_candidate_is_not_signed(self):
        self.archive.write_bytes(b"changed after build")
        self.assertNotEqual(self.sign().returncode, 0)
        self.assertFalse(pathlib.Path(str(self.archive) + ".sig").exists())

    def test_wrong_publisher_key_is_not_signed(self):
        self.public.write_text("01" * 32 + "\n")
        self.assertNotEqual(self.sign().returncode, 0)
        self.assertFalse(pathlib.Path(str(self.archive) + ".sig").exists())

    def test_existing_signature_cannot_be_replaced(self):
        self.assertEqual(self.sign().returncode, 0)
        before = pathlib.Path(str(self.archive) + ".sig").read_bytes()
        self.assertNotEqual(self.sign().returncode, 0)
        self.assertEqual(pathlib.Path(str(self.archive) + ".sig").read_bytes(), before)
