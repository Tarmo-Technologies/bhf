#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Sign CI-approved container archive bytes with the existing BHF dist scheme.

The expected digest must come from the trusted build job, not a file beside
an untrusted archive. This tool does not grant release or risk acceptance.
"""
import argparse
import importlib.util
import pathlib
import re
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location("offline_verify", pathlib.Path(__file__).with_name("verify-offline-dist.py"))
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=pathlib.Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--signing-key", type=pathlib.Path, required=True)
    parser.add_argument("--trusted-public-key", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch("[0-9a-f]{64}", args.expected_sha256):
        raise ValueError("invalid expected archive digest")
    signature = pathlib.Path(str(args.archive) + ".sig")
    if signature.exists():
        raise ValueError("signature already exists")
    with verify.open_regular(args.archive) as stream:
        digest, _ = verify.hash_archive(stream, 8 * 1024**3)
    if digest.hex() != args.expected_sha256:
        raise ValueError("archive differs from the trusted build job's digest")
    openssl = verify.resolve_openssl("openssl")
    with tempfile.TemporaryDirectory(prefix="bhf-container-sign-") as temporary:
        work = pathlib.Path(temporary)
        verify.check_crypto(openssl, work, 15)
        payload = work / "payload"
        payload.write_bytes(verify.DOMAIN + digest)
        signed = work / "signature"
        subprocess.run([openssl, "pkeyutl", "-sign", "-keyform", "DER", "-inkey", str(args.signing_key),
                        "-rawin", "-in", str(payload), "-out", str(signed)], check=True, timeout=15)
        # Verify against the independently supplied publisher key before
        # publishing the detached signature. A wrong key fails closed.
        verify.verify_archive(args.archive, signed, args.trusted_public_key,
                              max_archive_bytes=8 * 1024**3, openssl=openssl)
        with signature.open("xb") as output:
            output.write(signed.read_bytes())
    print(f"Signed and independently verified SHA-256 {digest.hex()}")


if __name__ == "__main__":
    main()
