# SPDX-License-Identifier: Apache-2.0
"""Real OpenSSL integration and filesystem tests; no third-party Python modules."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("bhf_verify", SCRIPTS / "verify-offline-dist.py")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)
OPENSSL = shutil.which("openssl")


def command(*args):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)


class VerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if OPENSSL is None:
            raise RuntimeError("OpenSSL is required; signature tests must not silently skip")
        cls.shared = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.shared.cleanup)
        cls.root = Path(cls.shared.name)
        cls.private = cls.root / "private.pem"
        command(OPENSSL, "genpkey", "-algorithm", "ED25519", "-out", str(cls.private))
        der = command(OPENSSL, "pkey", "-in", str(cls.private), "-pubout", "-outform", "DER").stdout
        if len(der) != 44 or not der.startswith(VERIFY.SPKI_PREFIX):
            raise AssertionError("unexpected Ed25519 SubjectPublicKeyInfo encoding")
        cls.public = der[12:]
        with tempfile.TemporaryDirectory() as directory:
            VERIFY.check_crypto(OPENSSL, directory, 15)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.archive = self.directory / "archive.tar.gz"
        self.signature = self.directory / "archive.tar.gz.sig"
        self.key = self.directory / "publisher.hex"
        self.destination = self.directory / "verified.tar.gz"
        self.original = b"a signed test artifact; no extraction or execution\n"
        self.archive.write_bytes(self.original)
        self.key.write_text(self.public.hex() + "\n", encoding="ascii")
        self.sign(self.original)

    def sign(self, content, domain=VERIFY.DOMAIN):
        message = self.directory / "to-sign.bin"
        message.write_bytes(domain + hashlib.sha256(content).digest())
        command(OPENSSL, "pkeyutl", "-sign", "-inkey", str(self.private), "-rawin",
                "-in", str(message), "-out", str(self.signature))
        message.unlink()

    def verify(self, **kwargs):
        return VERIFY.verify_archive(self.archive, self.signature, self.key, openssl=kwargs.pop("openssl", OPENSSL), **kwargs)

    def cli(self, *extra):
        return subprocess.run(
            [sys.executable, str(SCRIPTS / "verify-offline-dist.py"),
             "--archive", str(self.archive), "--signature", str(self.signature),
             "--trusted-public-key", str(self.key), *extra],
            capture_output=True, text=True, check=False, timeout=20,
        )

    def assert_no_staging(self):
        self.assertEqual(list(self.directory.glob("bhf-verify-*")), [])

    def test_valid_signature_and_digest(self):
        result = self.verify()
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["archive_sha256"], hashlib.sha256(self.original).hexdigest())
        self.assertEqual(result["archive_bytes"], len(self.original))
        self.assertIsNone(result["verified_copy"])
        self.assertEqual(result["trusted_public_key_sha256"], hashlib.sha256(self.public).hexdigest())
        self.assert_no_staging()

    def test_verified_copy_is_exact(self):
        result = self.verify(verified_copy=self.destination)
        self.assertEqual(self.destination.read_bytes(), self.original)
        self.assertEqual(result["verified_copy"], str(self.destination))
        self.assertEqual(result["publication_directory_sync"], "synced" if os.name == "posix" else "not_supported")
        self.assert_no_staging()

    def test_copy_does_not_inherit_executable_bits(self):
        self.archive.chmod(0o755)
        self.verify(verified_copy=self.destination)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o600)

    def test_source_mutation_after_hash_cannot_change_verified_copy(self):
        original_verify = VERIFY.verify_signature
        def mutate_after_verification(openssl, key, message, signature, directory, timeout):
            valid = original_verify(openssl, key, message, signature, directory, timeout)
            if message.startswith(VERIFY.DOMAIN):
                self.archive.write_bytes(b"changed by another process")
            return valid
        with mock.patch.object(VERIFY, "verify_signature", side_effect=mutate_after_verification):
            self.verify(verified_copy=self.destination)
        self.assertEqual(self.destination.read_bytes(), self.original)
        self.assertNotEqual(self.archive.read_bytes(), self.original)

    def test_tampered_archive_is_rejected_without_publication(self):
        self.archive.write_bytes(self.original + b"tampered")
        with self.assertRaises(VERIFY.VerificationError) as caught:
            self.verify(verified_copy=self.destination)
        self.assertTrue(caught.exception.rejected)
        self.assertFalse(self.destination.exists())
        self.assert_no_staging()

    def test_tampered_signature_is_rejected(self):
        signature = self.signature.read_bytes()
        self.signature.write_bytes(bytes([signature[0] ^ 1]) + signature[1:])
        with self.assertRaises(VERIFY.VerificationError) as caught:
            self.verify()
        self.assertTrue(caught.exception.rejected)

    def test_wrong_key_is_rejected(self):
        self.key.write_text(VERIFY.SELF_TEST_KEY.hex() + "\n")
        with self.assertRaises(VERIFY.VerificationError) as caught:
            self.verify()
        self.assertTrue(caught.exception.rejected)

    def test_wrong_domain_signature_is_rejected(self):
        self.sign(self.original, b"not-the-bhf-domain\0")
        with self.assertRaises(VERIFY.VerificationError) as caught:
            self.verify()
        self.assertTrue(caught.exception.rejected)

    def test_hash_only_signature_is_rejected(self):
        self.sign(self.original, b"")
        with self.assertRaises(VERIFY.VerificationError) as caught:
            self.verify()
        self.assertTrue(caught.exception.rejected)

    def test_empty_signed_archive_is_authenticated_not_declared_installable(self):
        self.archive.write_bytes(b"")
        self.sign(b"")
        result = self.verify(verified_copy=self.destination)
        self.assertEqual(result["archive_bytes"], 0)
        self.assertEqual(result["verification_scope"], "archive_integrity_and_supplied_key_authentication_only")

    def test_signature_length_is_exact(self):
        for length in (0, 1, 63, 65, 1000):
            with self.subTest(length=length):
                self.signature.write_bytes(b"x" * length)
                with self.assertRaises(VERIFY.VerificationError):
                    self.verify()

    def test_key_accepts_only_optional_single_trailing_newline(self):
        for ending in (b"", b"\n", b"\r\n"):
            with self.subTest(ending=ending):
                self.key.write_bytes(self.public.hex().encode() + ending)
                self.assertEqual(VERIFY.read_key(self.key), self.public)

    def test_noncanonical_or_oversized_key_is_rejected(self):
        encoded = self.public.hex().encode()
        for value in (b"", encoded.upper(), b" " + encoded, encoded + b" ",
                      encoded + b"\n\n", encoded[:32] + b"\n" + encoded[32:],
                      encoded[:-1] + b"g", encoded + b"\0", b"x" * 100000):
            with self.subTest(length=len(value)):
                self.key.write_bytes(value)
                with self.assertRaises(VERIFY.VerificationError):
                    self.verify()

    @unittest.skipUnless(os.name == "posix", "POSIX FIFO and leaf-symlink handling")
    def test_all_input_types_reject_symlinks(self):
        for path in (self.archive, self.signature, self.key):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                replacement = path.with_suffix(".target")
                replacement.write_bytes(original)
                path.unlink()
                path.symlink_to(replacement)
                with self.assertRaises(VERIFY.VerificationError):
                    self.verify()
                path.unlink()
                path.write_bytes(original)
                replacement.unlink()

    @unittest.skipUnless(os.name == "posix", "POSIX special files")
    def test_fifo_is_rejected_without_waiting_for_a_writer(self):
        self.archive.unlink()
        os.mkfifo(str(self.archive))
        result = self.cli("--json")
        self.assertEqual(result.returncode, 2)
        self.assertIn("regular", json.loads(result.stdout)["error"])

    def test_directory_input_is_rejected(self):
        self.archive.unlink()
        self.archive.mkdir()
        with self.assertRaises(VERIFY.VerificationError):
            self.verify()

    def test_missing_input_is_operational_error_not_signature_rejection(self):
        self.archive.unlink()
        result = self.cli("--json")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["status"], "error")

    def test_archive_exact_limit_passes(self):
        self.assertEqual(self.verify(max_archive_bytes=len(self.original))["status"], "verified")

    def test_archive_above_limit_fails_without_publication(self):
        with self.assertRaisesRegex(VERIFY.VerificationError, "max-archive-bytes"):
            self.verify(max_archive_bytes=len(self.original) - 1, verified_copy=self.destination)
        self.assertFalse(self.destination.exists())
        self.assert_no_staging()

    def test_size_growth_after_stat_cannot_escape_limit(self):
        real_fstat = os.fstat
        def stale_size(fd):
            observed = real_fstat(fd)
            values = list(observed)
            values[6] = 0
            return os.stat_result(values)
        with self.archive.open("rb") as stream, mock.patch.object(VERIFY.os, "fstat", side_effect=stale_size):
            with self.assertRaisesRegex(VERIFY.VerificationError, "max-archive-bytes"):
                VERIFY.hash_archive(stream, 3)
            self.assertLessEqual(stream.tell(), 4)

    def test_small_reader_enforces_its_bound(self):
        self.archive.write_bytes(b"x" * 1000)
        with self.assertRaisesRegex(VERIFY.VerificationError, "66-byte"):
            VERIFY.read_small(self.archive, 66)

    def test_invalid_limits_are_rejected(self):
        for value in (0, -1, True, "100", 1.5):
            with self.subTest(value=value):
                with self.assertRaises(VERIFY.VerificationError):
                    self.verify(max_archive_bytes=value)
        for value in (0, 121, True, 1.5):
            with self.subTest(timeout=value):
                with self.assertRaises(VERIFY.VerificationError):
                    self.verify(timeout=value)

    def test_existing_file_is_never_overwritten(self):
        self.destination.write_bytes(b"keep me")
        with self.assertRaises(VERIFY.VerificationError):
            self.verify(verified_copy=self.destination)
        self.assertEqual(self.destination.read_bytes(), b"keep me")

    def test_existing_directory_is_never_replaced(self):
        self.destination.mkdir()
        (self.destination / "keep").write_text("original")
        with self.assertRaises(VERIFY.VerificationError):
            self.verify(verified_copy=self.destination)
        self.assertEqual((self.destination / "keep").read_text(), "original")

    @unittest.skipUnless(os.name == "posix", "POSIX symlink support")
    def test_dangling_destination_symlink_is_never_replaced(self):
        self.destination.symlink_to("missing")
        with self.assertRaises(VERIFY.VerificationError):
            self.verify(verified_copy=self.destination)
        self.assertEqual(os.readlink(str(self.destination)), "missing")

    def test_destination_created_during_verification_is_preserved(self):
        original_verify = VERIFY.verify_signature
        def insert_destination(openssl, key, message, signature, directory, timeout):
            result = original_verify(openssl, key, message, signature, directory, timeout)
            if message.startswith(VERIFY.DOMAIN):
                self.destination.write_bytes(b"concurrent writer")
            return result
        with mock.patch.object(VERIFY, "verify_signature", side_effect=insert_destination):
            with self.assertRaises(VERIFY.VerificationError):
                self.verify(verified_copy=self.destination)
        self.assertEqual(self.destination.read_bytes(), b"concurrent writer")
        self.assert_no_staging()

    def test_concurrent_publishers_have_exactly_one_winner(self):
        barrier = threading.Barrier(2)
        original_publish = VERIFY.publish_snapshot
        def simultaneous(snapshot, destination):
            barrier.wait(timeout=10)
            return original_publish(snapshot, destination)
        outcomes = []
        def worker():
            try:
                self.verify(verified_copy=self.destination)
                outcomes.append("published")
            except VERIFY.VerificationError:
                outcomes.append("rejected")
        with mock.patch.object(VERIFY, "publish_snapshot", side_effect=simultaneous):
            threads = [threading.Thread(target=worker) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=20)
                self.assertFalse(thread.is_alive())
        self.assertCountEqual(outcomes, ["published", "rejected"])
        self.assertEqual(self.destination.read_bytes(), self.original)
        self.assert_no_staging()

    def test_unsupported_hardlinks_do_not_fall_back_to_rename(self):
        with mock.patch.object(VERIFY.os, "link", side_effect=OSError("hard links unsupported")):
            with self.assertRaises(OSError):
                self.verify(verified_copy=self.destination)
        self.assertFalse(self.destination.exists())
        self.assert_no_staging()

    def test_failed_directory_sync_reports_already_published_verified_copy(self):
        with mock.patch.object(VERIFY, "sync_directory", side_effect=OSError("sync unavailable")):
            with self.assertRaises(VERIFY.VerificationError) as caught:
                self.verify(verified_copy=self.destination)
        self.assertEqual(caught.exception.published_copy, str(self.destination))
        self.assertFalse(caught.exception.rejected)
        self.assertEqual(self.destination.read_bytes(), self.original)
        self.assert_no_staging()

    def test_failed_snapshot_write_does_not_publish(self):
        with mock.patch.object(VERIFY, "hash_archive", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.verify(verified_copy=self.destination)
        self.assertFalse(self.destination.exists())
        self.assert_no_staging()


    def test_cleanup_failure_preserves_published_copy_in_error(self):
        real_temporary = tempfile.TemporaryDirectory
        class FailOnExit:
            def __init__(self, *args, **kwargs):
                self.inner = real_temporary(*args, **kwargs)
            def __enter__(self):
                return self.inner.__enter__()
            def __exit__(self, *args):
                self.inner.__exit__(*args)
                raise OSError("simulated cleanup failure")
        with mock.patch.object(VERIFY.tempfile, "TemporaryDirectory", FailOnExit):
            with self.assertRaises(VERIFY.VerificationError) as caught:
                self.verify(verified_copy=self.destination)
        self.assertEqual(caught.exception.published_copy, str(self.destination))
        self.assertEqual(self.destination.read_bytes(), self.original)
        self.assertFalse(caught.exception.rejected)
        self.assert_no_staging()

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor race handling")
    def test_leaf_symlink_substitution_during_open_is_rejected(self):
        real_open = os.open
        alternate = self.directory / "alternate"
        alternate.write_bytes(self.original)
        def replace_then_open(path, flags, *args, **kwargs):
            if str(path) == str(self.archive):
                self.archive.unlink()
                self.archive.symlink_to(alternate)
            return real_open(path, flags, *args, **kwargs)
        with mock.patch.object(VERIFY.os, "open", side_effect=replace_then_open):
            with self.assertRaises((OSError, VERIFY.VerificationError)):
                self.verify(verified_copy=self.destination)
        self.assertFalse(self.destination.exists())
        self.assert_no_staging()

    @unittest.skipUnless(os.name == "posix", "executable script timeout regression")
    def test_real_stalled_crypto_process_is_killed_and_reaped(self):
        pidfile = self.directory / "crypto.pid"
        executable = self.directory / "stalled-crypto"
        # This stand-in uses only stdlib modules. Avoid site/customization
        # startup hooks consuming its one-second timeout before the PID marker.
        executable.write_text(
            "#!{} -S\nimport os, time\n".format(sys.executable)
            + "with open({!r}, 'w') as out: out.write(str(os.getpid()))\n".format(str(pidfile))
            + "time.sleep(30)\n"
        )
        executable.chmod(0o700)
        with self.assertRaisesRegex(VERIFY.VerificationError, "timeout"):
            self.verify(openssl=str(executable), timeout=1)
        self.assertTrue(pidfile.exists(), "fake executable did not start")
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pidfile.read_text()), 0)

    def test_source_and_destination_cannot_be_the_same_file(self):
        with self.assertRaises(VERIFY.VerificationError):
            self.verify(verified_copy=self.archive)
        self.assertEqual(self.archive.read_bytes(), self.original)

    def test_missing_output_parent_is_not_created(self):
        destination = self.directory / "missing" / "archive"
        with self.assertRaises(OSError):
            self.verify(verified_copy=destination)
        self.assertFalse(destination.parent.exists())

    def test_openssl_timeout_is_operational_error(self):
        with mock.patch.object(VERIFY.subprocess, "run", side_effect=subprocess.TimeoutExpired("openssl", 15)):
            with self.assertRaisesRegex(VERIFY.VerificationError, "timeout"):
                self.verify()

    def test_self_test_rejects_always_successful_executable(self):
        with mock.patch.object(VERIFY, "verify_signature", return_value=True):
            with self.assertRaisesRegex(VERIFY.VerificationError, "tampered"):
                self.verify()

    def test_self_test_rejects_unavailable_crypto(self):
        with mock.patch.object(VERIFY, "verify_signature", return_value=False):
            with self.assertRaisesRegex(VERIFY.VerificationError, "self-test failed"):
                self.verify()

    def test_missing_openssl_is_operational_error(self):
        result = self.cli("--openssl", str(self.directory / "absent"), "--json")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["status"], "error")

    def test_json_success_is_single_object_with_no_secret_key_material(self):
        result = self.cli("--verified-copy", str(self.destination), "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "verified")
        self.assertEqual(result.stderr, "")
        self.assertNotIn(self.public.hex(), result.stdout)
        self.assertNotIn("PRIVATE KEY", result.stdout)

    def test_json_tamper_rejection_has_nonzero_exit(self):
        self.archive.write_bytes(b"tampered")
        result = self.cli("--json")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["status"], "rejected")
        self.assertEqual(result.stderr, "")

    def test_human_error_is_on_stderr(self):
        self.archive.write_bytes(b"tampered")
        result = self.cli()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("signature verification failed", result.stderr)

    def test_human_verification_only_warns_about_mutable_source(self):
        result = self.cli()
        self.assertEqual(result.returncode, 0)
        self.assertIn("No copy was published", result.stdout)

    def test_self_test_cli_does_not_claim_archive_verification(self):
        result = subprocess.run([sys.executable, str(SCRIPTS / "verify-offline-dist.py"),
                                 "--self-test", "--json"], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)["archive_verified"])

    def test_self_test_cannot_disguise_archive_verification(self):
        result = self.cli("--self-test", "--json")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["status"], "error")

    def test_semantic_missing_arguments_are_json_errors(self):
        result = subprocess.run([sys.executable, str(SCRIPTS / "verify-offline-dist.py"), "--json"],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["status"], "error")

    def test_paths_with_spaces_and_metacharacters_are_literal(self):
        destination = self.directory / "verified ; not-a-command $(x).tar.gz"
        result = self.cli("--verified-copy", str(destination), "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(destination.read_bytes(), self.original)

    @unittest.skipUnless(os.name == "posix", "Bash minimal-PATH regression")
    def test_bash_verifier_works_without_xxd(self):
        tools = self.directory / "minimal-path"
        tools.mkdir()
        for tool in ("openssl", "mktemp", "wc", "tr", "rm", "rmdir"):
            (tools / tool).symlink_to(shutil.which(tool))
        env = dict(os.environ, PATH=str(tools))
        self.assertIsNone(shutil.which("xxd", path=env["PATH"]))
        result = subprocess.run([shutil.which("bash"), str(SCRIPTS / "verify-offline-dist.sh"),
                                 "--archive", str(self.archive), "--signature", str(self.signature),
                                 "--trusted-public-key", str(self.key)], env=env,
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Verified distribution signature", result.stdout)

    @unittest.skipUnless(os.name == "posix", "Bash signature interoperability")
    def test_bash_and_python_both_reject_tampered_archive(self):
        self.archive.write_bytes(b"tampered")
        result = subprocess.run(["bash", str(SCRIPTS / "verify-offline-dist.sh"),
                                 "--archive", str(self.archive), "--signature", str(self.signature),
                                 "--trusted-public-key", str(self.key)], capture_output=True, text=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        with self.assertRaises(VERIFY.VerificationError):
            self.verify()

    @unittest.skipUnless(os.name == "posix", "Bash bounded-key regression")
    def test_bash_rejects_oversized_key_before_reading_into_variable(self):
        self.key.write_bytes(b"x" * 100000)
        result = subprocess.run(["bash", str(SCRIPTS / "verify-offline-dist.sh"),
                                 "--archive", str(self.archive), "--signature", str(self.signature),
                                 "--trusted-public-key", str(self.key)], capture_output=True, text=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exceeds 66 bytes", result.stderr)


if __name__ == "__main__":
    unittest.main()
