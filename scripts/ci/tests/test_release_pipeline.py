# SPDX-License-Identifier: Apache-2.0
"""Execute the actual gate/export and verified-copy extraction shell fragments.

GitHub event/job observations are fixtures, not hosted runs. Cryptographic
signatures, both policy CLIs, archive copying, and tar extraction are real.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[3]
SHA = "a" * 40
JOBS = ("changes", "ci-policy", "minimum-rust", "build-test", "rhel7-build",
        "rhel-family-smoke", "ubuntu-release-smoke", "windows-build", "windows-current-build")


def ci_observation(heavy="true"):
    observation = {job: {"result": "success", "outputs": {}} for job in JOBS}
    observation["changes"]["outputs"]["heavy"] = heavy
    if heavy == "false":
        for job in JOBS[2:]:
            observation[job]["result"] = "skipped"
    return observation


def ci_acceptance_shell():
    source = (ROOT / ".github/workflows/ci.yml").read_text()
    step = source.split("      - name: Require complete successful CI or an explicit documentation exemption\n", 1)[1]
    return textwrap.dedent(step.split("        run: |\n", 1)[1].split("      - name:", 1)[0])


class GateChainTests(unittest.TestCase):
    def execute_chain(self, observation, require_full="true", exported_changes=None,
                      expected_sha=SHA, checked_out_sha=SHA, run_attempt="2"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts/ci").mkdir(parents=True)
            (root / "bin").mkdir()
            # The gate scripts use only stdlib. Isolate interpreter startup
            # from local site/customization hooks, not from the gate logic.
            python = root / "bin/python3"
            python.write_text("#!/bin/bash\nexec " + shlex.quote(sys.executable) + " -S \"$@\"\n")
            python.chmod(0o755)
            for name in ("check-ci-acceptance.py", "check-release-acceptance.py"):
                shutil.copy2(ROOT / "scripts/ci" / name, root / "scripts/ci" / name)
            git = root / "bin/git"
            git.write_text("#!/bin/bash\n[[ \"$*\" == 'rev-parse HEAD' ]] || exit 2\nprintf '%s\\n' \"$FIXTURE_SHA\"\n")
            git.chmod(0o755)
            env = dict(os.environ, PATH=str(root / "bin") + os.pathsep + os.environ["PATH"],
                       FIXTURE_SHA=checked_out_sha, GITHUB_SHA=expected_sha,
                       EVENT_NAME="push", REQUIRE_FULL_CI=require_full,
                       NEEDS_JSON=json.dumps(observation), GITHUB_RUN_ID="1234",
                       GITHUB_RUN_ATTEMPT=run_attempt, GITHUB_OUTPUT=str(root / "ci-output"))
            ci = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", ci_acceptance_shell()],
                                cwd=root, env=env, capture_output=True, text=True, timeout=15)
            exports = {}
            if (root / "ci-output").exists():
                exports = dict(line.split("=", 1) for line in (root / "ci-output").read_text().splitlines())
            if exported_changes:
                exports.update(exported_changes)
            env["CI_VALIDATION_JSON"] = json.dumps({"result": "success" if ci.returncode == 0 else "failure", "outputs": exports})
            release = subprocess.run([sys.executable, "-S", str(root / "scripts/ci/check-release-acceptance.py"),
                "--commit", expected_sha, "--event", "push", "--ref", "refs/tags/v1.2.3",
                "--repository", "Tarmo-Technologies/bhf", "--run-id", "1234", "--run-attempt", "2",
                "--output", str(root / "release.json")],
                env=env, capture_output=True, text=True, timeout=15)
            return ci.returncode, exports, release.returncode, json.loads((root / "release.json").read_text())

    def test_full_chain_accepts_only_matching_success(self):
        ci, exports, release, report = self.execute_chain(ci_observation())
        self.assertEqual(ci, 0)
        self.assertEqual(exports["decision"], "PASS_FULL_CI")
        self.assertEqual(release, 0)
        self.assertEqual(report["decision"], "PASS_RELEASE_CI")

    def test_each_failed_skipped_or_cancelled_lane_prevents_export_and_release(self):
        for job in JOBS:
            for result in ("failure", "skipped", "cancelled"):
                with self.subTest(job=job, result=result):
                    observation = ci_observation()
                    observation[job]["result"] = result
                    ci, exports, release, report = self.execute_chain(observation)
                    self.assertNotEqual(ci, 0)
                    self.assertEqual(exports, {})
                    self.assertNotEqual(release, 0)
                    self.assertFalse(report["accepted"])

    def test_missing_lane_prevents_export_and_release(self):
        observation = ci_observation()
        del observation["windows-current-build"]
        ci, exports, release, report = self.execute_chain(observation)
        self.assertNotEqual(ci, 0)
        self.assertEqual(exports, {})
        self.assertNotEqual(release, 0)
        self.assertFalse(report["accepted"])

    def test_docs_exemption_cannot_become_release_authorization(self):
        ci, exports, release, report = self.execute_chain(ci_observation("false"), require_full="false")
        self.assertEqual(ci, 0)
        self.assertEqual(exports["decision"], "PASS_DOCS_ONLY")
        self.assertNotEqual(release, 0)
        self.assertFalse(report["accepted"])

    def test_forced_docs_run_cannot_export_a_pass(self):
        ci, exports, release, report = self.execute_chain(ci_observation("false"))
        self.assertNotEqual(ci, 0)
        self.assertEqual(exports, {})
        self.assertNotEqual(release, 0)
        self.assertFalse(report["accepted"])

    def test_wrong_checked_out_revision_stops_before_export(self):
        ci, exports, release, report = self.execute_chain(ci_observation(), checked_out_sha="b" * 40)
        self.assertNotEqual(ci, 0)
        self.assertEqual(exports, {})
        self.assertNotEqual(release, 0)
        self.assertFalse(report["accepted"])

    def test_previous_gate_attempt_is_not_reused(self):
        ci, exports, release, report = self.execute_chain(ci_observation(), run_attempt="1")
        self.assertEqual(ci, 0)
        self.assertEqual(exports["run_attempt"], "1")
        self.assertNotEqual(release, 0)
        self.assertFalse(report["accepted"])

    def test_wrong_exported_revision_is_not_reused(self):
        ci, _, release, report = self.execute_chain(ci_observation(), exported_changes={"commit": "b" * 40})
        self.assertEqual(ci, 0)
        self.assertNotEqual(release, 0)
        self.assertFalse(report["accepted"])


class VerifiedExtractionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.crypto = shutil.which("openssl")
        self.tar = shutil.which("tar")
        self.assertIsNotNone(self.crypto, "OpenSSL with Ed25519 is required")
        self.assertIsNotNone(self.tar, "tar is required for release extraction tests")
        (self.root / "scripts").mkdir()
        (self.root / "target/distrib").mkdir(parents=True)
        (self.root / "signing").mkdir()
        (self.root / "tmp").mkdir()
        (self.root / "bin").mkdir()
        python = self.root / "bin/python3"
        python.write_text("#!/bin/bash\nexec " + shlex.quote(sys.executable) + " -S \"$@\"\n")
        python.chmod(0o755)
        shutil.copy2(ROOT / "scripts/verify-offline-dist.py", self.root / "scripts/verify-offline-dist.py")
        self.archive = self.root / "original.tar.gz"
        self.signature = self.root / "original.tar.gz.sig"
        self.private = self.root / "signing/temporary-test-key.pem"
        self.public = self.root / "signing/public.hex"
        payload = b"authenticated fixture, not a BHF executable\n"
        with tarfile.open(self.archive, "w:gz") as archive:
            info = tarfile.TarInfo("fixture/payload.txt")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        self.expected_archive = self.archive.read_bytes()
        self.expected_payload = payload
        self.command("genpkey", "-algorithm", "Ed25519", "-out", str(self.private))
        der = self.command("pkey", "-in", str(self.private), "-pubout", "-outform", "DER").stdout
        self.assertEqual(der[:12].hex(), "302a300506032b6570032100")
        self.public.write_text(der[-32:].hex() + "\n")
        message = self.root / "message.bin"
        message.write_bytes(b"BHF.DIST.TARBALL.ED25519.V1\0" + hashlib.sha256(self.expected_archive).digest())
        self.command("pkeyutl", "-sign", "-inkey", str(self.private), "-rawin",
                     "-in", str(message), "-out", str(self.signature))
        # Interpose only at the actual tar call. Mutating the original here
        # proves that extraction consumes the accepted private copy instead.
        wrapper = self.root / "bin/tar"
        wrapper.write_text("#!/bin/bash\nset -eu\nprintf '%s' \"$2\" > \"$TAR_PATH_RECORD\"\n"
            "if [[ \"$MUTATE_ORIGINAL\" == true ]]; then printf changed > \"$archive\"; fi\n"
            "exec \"$REAL_TAR\" \"$@\"\n")
        wrapper.chmod(0o755)

    def command(self, *arguments):
        return subprocess.run([self.crypto, *arguments], capture_output=True, check=True, timeout=15)

    def execute(self, mutate=False):
        source = (ROOT / ".github/workflows/release.yml").read_text()
        fragment = '          verify_root="$(mktemp -d)"\n' + source.split('          verify_root="$(mktemp -d)"\n', 1)[1].split('          bundle_root=', 1)[0]
        script = "set -euo pipefail\n" + textwrap.dedent(fragment)
        script += 'printf "%s" "$verify_root" > "$ACCEPTED_ROOT_RECORD"\n'
        env = dict(os.environ, PATH=str(self.root / "bin") + os.pathsep + os.environ["PATH"],
            TMPDIR=str(self.root / "tmp"), archive=str(self.archive), signature=str(self.signature),
            signing_dir=str(self.root / "signing"), bundle_name="fixture", REAL_TAR=self.tar,
            MUTATE_ORIGINAL="true" if mutate else "false", TAR_PATH_RECORD=str(self.root / "tar-path"),
            ACCEPTED_ROOT_RECORD=str(self.root / "accepted-root"))
        return subprocess.run(["bash", "-e", "-o", "pipefail", "-c", script], cwd=self.root,
                              env=env, capture_output=True, text=True, timeout=20)

    def test_release_fragment_extracts_exact_authenticated_copy(self):
        result = self.execute()
        self.assertEqual(result.returncode, 0, result.stderr)
        root = Path((self.root / "accepted-root").read_text())
        copy = root / "fixture.tar.gz"
        self.assertEqual(copy.read_bytes(), self.expected_archive)
        self.assertEqual((root / "fixture/payload.txt").read_bytes(), self.expected_payload)
        self.assertEqual((self.root / "tar-path").read_text(), str(copy))
        receipt = json.loads((self.root / "target/distrib/linux-bundle-verification.json").read_text())
        self.assertEqual(receipt["status"], "verified")
        self.assertEqual(receipt["archive_sha256"], hashlib.sha256(self.expected_archive).hexdigest())

    def test_mutating_original_after_verification_does_not_change_extraction(self):
        result = self.execute(mutate=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.archive.read_bytes(), b"changed")
        root = Path((self.root / "accepted-root").read_text())
        self.assertEqual((root / "fixture.tar.gz").read_bytes(), self.expected_archive)
        self.assertEqual((root / "fixture/payload.txt").read_bytes(), self.expected_payload)

    def test_tampering_stops_before_tar(self):
        self.archive.write_bytes(self.expected_archive + b"changed")
        result = self.execute()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "tar-path").exists())
        self.assertFalse((self.root / "accepted-root").exists())
        self.assertFalse(list((self.root / "tmp").rglob("payload.txt")))

    def test_wrong_signature_stops_before_tar(self):
        self.signature.write_bytes(b"\0" * 64)
        result = self.execute()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "tar-path").exists())

    def test_unsupported_crypto_stops_before_tar(self):
        crypto = self.root / "bin/openssl"
        crypto.write_text("#!/bin/bash\nexit 1\n")
        crypto.chmod(0o755)
        result = self.execute()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "tar-path").exists())

    def test_workflow_keeps_verification_receipt_separate_from_signature(self):
        source = (ROOT / ".github/workflows/release.yml").read_text()
        upload = source.split("      - name: Upload authenticated Linux bundle\n", 1)[1].split("\n  build-global-artifacts:", 1)[0]
        self.assertIn("target/distrib/linux-bundle-verification.json", upload)
        self.assertIn("target/distrib/bhf-dist-*.tar.gz.sig", upload)
        self.assertIn("if-no-files-found: error", upload)


if __name__ == "__main__":
    unittest.main()
