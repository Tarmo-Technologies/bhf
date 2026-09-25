#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify BHF distribution signatures without extracting or running the archive.

Use --verified-copy to hand off the exact verified bytes, published without
replacing any existing destination. Requires Python 3.8+ and an operator-trusted
OpenSSL with Ed25519 pkeyutl support. No network access or third-party Python
packages are used. This verifier and public key must be obtained independently
of the unverified distribution. See docs/verified-distribution-handoff.md.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

DOMAIN = b"BHF.DIST.TARBALL.ED25519.V1\0"
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
DEFAULT_MAX_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
DEFAULT_OPENSSL_TIMEOUT = 15

# RFC 8032 section 7.1, TEST 2: one-byte message 0x72. Public test vector,
# not a publisher identity. The private key is neither required nor embedded.
SELF_TEST_KEY = bytes.fromhex(
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
)
SELF_TEST_MESSAGE = bytes.fromhex("72")
SELF_TEST_SIGNATURE = bytes.fromhex(
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
)


class VerificationError(Exception):
    """A rejection or an operational failure, never a successful verification."""
    def __init__(self, message, *, rejected=False, published_copy=None):
        super().__init__(message)
        self.rejected = rejected
        self.published_copy = published_copy


def open_regular(path):
    """Open a stable input descriptor; reject special files and leaf symlinks.

    O_NONBLOCK prevents a POSIX FIFO substitution from hanging open. O_NOFOLLOW
    closes the POSIX leaf-symlink race. Ancestor directories and the operating
    environment remain trusted. On Windows reparse points are rejected during
    the metadata check, but this is not a Win32 handle-relative sandbox.
    """
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or getattr(before, "st_file_attributes", 0) & 0x400:
        raise VerificationError("input must be a regular, non-symlink file: {}".format(path))
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(str(path), flags)
    try:
        after = os.fstat(fd)
        if not stat.S_ISREG(after.st_mode):
            raise VerificationError("opened input is not a regular file: {}".format(path))
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise VerificationError("input changed while it was being opened: {}".format(path))
        stream = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    return stream


def read_small(path, limit):
    with open_regular(path) as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise VerificationError("input exceeds its {}-byte limit: {}".format(limit, path))
    return data


def read_key(path):
    encoded = read_small(path, 66)
    if re.fullmatch(rb"[0-9a-f]{64}(?:\r?\n)?", encoded) is None:
        raise VerificationError("trusted public key must be 64 lowercase hex characters with at most one trailing newline")
    return bytes.fromhex(encoded[:64].decode("ascii"))


def resolve_openssl(value):
    candidate = shutil.which(value)
    if candidate is None:
        raise VerificationError("OpenSSL executable not found; supply --openssl with a trusted executable path")
    return str(Path(candidate).resolve(strict=True))


def verify_signature(openssl, key, message, signature, directory, timeout):
    directory = Path(directory)
    public = directory / "public.der"
    payload = directory / "message.bin"
    sigfile = directory / "signature.bin"
    public.write_bytes(SPKI_PREFIX + key)
    payload.write_bytes(message)
    sigfile.write_bytes(signature)
    try:
        result = subprocess.run(
            [openssl, "pkeyutl", "-verify", "-pubin", "-inkey", str(public),
             "-keyform", "DER", "-rawin", "-in", str(payload), "-sigfile", str(sigfile)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise VerificationError("OpenSSL exceeded its verification timeout") from error
    return result.returncode == 0


def check_crypto(openssl, directory, timeout):
    """A valid AND a tampered public vector must behave correctly."""
    if not verify_signature(openssl, SELF_TEST_KEY, SELF_TEST_MESSAGE,
                            SELF_TEST_SIGNATURE, directory, timeout):
        raise VerificationError("OpenSSL Ed25519 known-answer self-test failed; check executable, version, and configured crypto policy")
    invalid = bytes([SELF_TEST_SIGNATURE[0] ^ 1]) + SELF_TEST_SIGNATURE[1:]
    if verify_signature(openssl, SELF_TEST_KEY, SELF_TEST_MESSAGE, invalid, directory, timeout):
        raise VerificationError("OpenSSL accepted the tampered self-test signature")


def hash_archive(stream, limit, snapshot=None):
    if os.fstat(stream.fileno()).st_size > limit:
        raise VerificationError("archive exceeds --max-archive-bytes")
    digest = hashlib.sha256()
    size = 0
    while True:
        # Read at most one byte beyond the limit, even if the file grows after
        # fstat. Never trust its initial size as the entire resource limit.
        chunk = stream.read(min(CHUNK_BYTES, limit - size + 1))
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            raise VerificationError("archive exceeds --max-archive-bytes")
        digest.update(chunk)
        if snapshot is not None:
            snapshot.write(chunk)
    if snapshot is not None:
        snapshot.flush()
        os.fsync(snapshot.fileno())
    return digest.digest(), size


def sync_directory(directory):
    if os.name != "posix":
        return "not_supported"
    fd = os.open(str(directory), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return "synced"


def publish_snapshot(snapshot, destination):
    """No check-then-rename: link creation is the atomic no-overwrite operation.

    Staging and destination are on the same filesystem. Unsupported hard links
    fail rather than falling back to a replacement operation. Retain a verified
    destination if directory synchronization subsequently fails; report it.
    """
    try:
        os.link(str(snapshot), str(destination))
    except FileExistsError as error:
        raise VerificationError("verified-copy destination already exists; it was not overwritten") from error
    try:
        return sync_directory(destination.parent)
    except OSError as error:
        raise VerificationError(
            "verified copy was published, but directory durability is uncertain: {}".format(error),
            published_copy=str(destination),
        ) from error


def verify_archive(archive, signature, trusted_public_key, *, verified_copy=None,
                   max_archive_bytes=DEFAULT_MAX_ARCHIVE_BYTES, openssl="openssl",
                   timeout=DEFAULT_OPENSSL_TIMEOUT):
    if isinstance(max_archive_bytes, bool) or not isinstance(max_archive_bytes, int) or max_archive_bytes <= 0:
        raise VerificationError("max_archive_bytes must be a positive integer")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 120:
        raise VerificationError("OpenSSL timeout must be an integer from 1 to 120 seconds")
    executable = resolve_openssl(openssl)
    key = read_key(trusted_public_key)
    signature_bytes = read_small(signature, 64)
    if len(signature_bytes) != 64:
        raise VerificationError("detached Ed25519 signature must be exactly 64 bytes")
    destination = None
    if verified_copy is not None:
        supplied = Path(verified_copy)
        destination = supplied.parent.resolve(strict=True) / supplied.name
        if not destination.parent.is_dir():
            raise VerificationError("verified-copy parent must be an existing directory")
        if os.path.lexists(str(destination)):
            raise VerificationError("verified-copy destination already exists; it was not overwritten")

    # Same-filesystem private staging permits atomic non-replacing publication.
    parent = str(destination.parent) if destination is not None else None
    published = None
    try:
        with tempfile.TemporaryDirectory(prefix="bhf-verify-", dir=parent) as temporary:
            work = Path(temporary)
            check_crypto(executable, work, timeout)
            with open_regular(archive) as source:
                if destination is None:
                    digest, size = hash_archive(source, max_archive_bytes)
                else:
                    snapshot = work / "archive.verified"
                    # Do not inherit source permissions or execute bits.
                    fd = os.open(str(snapshot), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "wb") as sink:
                        digest, size = hash_archive(source, max_archive_bytes, sink)
            if not verify_signature(executable, key, DOMAIN + digest, signature_bytes, work, timeout):
                raise VerificationError("distribution signature verification failed", rejected=True)
            durability = "not_requested"
            if destination is not None:
                try:
                    durability = publish_snapshot(snapshot, destination)
                except VerificationError as error:
                    # Preserve the publication outcome even if context-manager
                    # cleanup subsequently fails and masks the original error.
                    published = error.published_copy
                    raise
                published = str(destination)
            report = {
                "schema_version": 1,
                "status": "verified",
                "archive_sha256": digest.hex(),
                "archive_bytes": size,
                "trusted_public_key_sha256": hashlib.sha256(key).hexdigest(),
                "signature_sha256": hashlib.sha256(signature_bytes).hexdigest(),
                "signature_scheme": "BHF.DIST.TARBALL.ED25519.V1",
                "verified_copy": str(destination) if destination is not None else None,
                "publication_directory_sync": durability,
                "verification_scope": "archive_integrity_and_supplied_key_authentication_only",
            }
    except OSError as error:
        if published is not None:
            raise VerificationError(
                "verified copy was published, but completion or cleanup failed; "
                "check publication durability: {}".format(error),
                published_copy=published,
            ) from error
        raise
    return report


def _positive(value):
    if re.fullmatch(r"[0-9]{1,20}", value) is None or int(value) == 0:
        raise argparse.ArgumentTypeError("expected a positive decimal integer")
    return int(value)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--signature", type=Path)
    parser.add_argument("--trusted-public-key", type=Path)
    parser.add_argument("--verified-copy", type=Path)
    parser.add_argument("--max-archive-bytes", type=_positive, default=DEFAULT_MAX_ARCHIVE_BYTES)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--openssl-timeout", type=_positive, default=DEFAULT_OPENSSL_TIMEOUT)
    parser.add_argument("--self-test", action="store_true", help="check local crypto support without archive input")
    parser.add_argument("--json", action="store_true", help="write a machine-readable result, including operational failures")
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.openssl_timeout <= 120:
            raise VerificationError("--openssl-timeout must be from 1 to 120 seconds")
        if args.self_test:
            if any(value is not None for value in (args.archive, args.signature, args.trusted_public_key, args.verified_copy)):
                raise VerificationError("--self-test cannot be combined with archive or key options")
            executable = resolve_openssl(args.openssl)
            with tempfile.TemporaryDirectory(prefix="bhf-crypto-check-") as temporary:
                check_crypto(executable, temporary, args.openssl_timeout)
            report = {"schema_version": 1, "status": "self_test_passed",
                      "archive_verified": False, "test_vector": "RFC8032-7.1-TEST-2"}
        else:
            if any(value is None for value in (args.archive, args.signature, args.trusted_public_key)):
                raise VerificationError("--archive, --signature, and --trusted-public-key are required")
            report = verify_archive(
                args.archive, args.signature, args.trusted_public_key,
                verified_copy=args.verified_copy, max_archive_bytes=args.max_archive_bytes,
                openssl=args.openssl, timeout=args.openssl_timeout,
            )
        code = 0
    except VerificationError as error:
        code = 1 if error.rejected else 2
        report = {"schema_version": 1, "status": "rejected" if error.rejected else "error",
                  "error": str(error), "published_copy": error.published_copy}
    except OSError as error:
        code = 2
        report = {"schema_version": 1, "status": "error", "error": str(error), "published_copy": None}
    if args.json:
        print(json.dumps(report, sort_keys=True, allow_nan=False))
    elif code:
        print("verify-offline-dist.py: " + report["error"], file=sys.stderr)
    elif args.self_test:
        print("OpenSSL Ed25519 self-test passed; no archive was verified.")
    else:
        print("Verified distribution signature; SHA-256: " + report["archive_sha256"])
        if report["verified_copy"]:
            print("Verified copy: " + report["verified_copy"])
        else:
            print("No copy was published. Keep the source unchanged before use, or use --verified-copy.")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
