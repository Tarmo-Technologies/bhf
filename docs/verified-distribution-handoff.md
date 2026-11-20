<!-- SPDX-License-Identifier: Apache-2.0 -->
# Verified Distribution Handoff

`scripts/verify-offline-dist.py` verifies the detached Ed25519 signature of a
bhf offline distribution archive and can write a separate copy of the
**exact bytes it verified**. It is a standalone Python script, not a `bhf`
subcommand. It does not extract the archive, run anything from it, or use the
network.

The release workflow runs it for the Linux installation smoke test (see
[Release controls](enterprise-release-controls.md)). It is not packed inside
the distribution archive: obtain it separately, through the same trusted
channel as the publisher's public key.

## Trust boundary

- Get this verifier and the publisher's public key through a trusted channel
  independent of the archive you are checking. A public key inside the archive
  is not a trust anchor.
- The script, the Python interpreter, the OpenSSL executable and its
  configuration, the ancestor directories and the output directory must all be
  trusted. A malicious process running as the same account can interfere
  with the check.

## Signature format

- The signature is a raw 64-byte Ed25519 signature over
  `BHF.DIST.TARBALL.ED25519.V1`, a NUL byte, and the raw 32-byte SHA-256 digest
  of the archive.
- The public-key file holds exactly 64 lowercase hex characters, optionally
  followed by one LF or CRLF. The Python verifier rejects embedded newlines,
  extra whitespace and any other size.

## Requirements and the crypto self-test

The script uses only Python's standard library and runs on Python 3.8 or
later. OpenSSL must support Ed25519 verification with `pkeyutl -rawin`. Pass
an absolute `--openssl` path when you do not control `PATH`.

```sh
python3 scripts/verify-offline-dist.py --self-test --json
```

The self-test checks a valid and a tampered public RFC 8032 test vector
against the installed OpenSSL and its configured policy. It reports
`archive_verified: false`, because it checks crypto compatibility only, not an
archive or a publisher. A local crypto policy that fails the self-test stays
as it is; the script does not change or bypass it.

## Verify and write a separate copy

Pick a trusted destination directory first. The destination file must not
exist yet, not even as a dangling symlink.

```sh
python3 scripts/verify-offline-dist.py \
  --archive incoming/bhf-release.tar.gz \
  --signature incoming/bhf-release.tar.gz.sig \
  --trusted-public-key trusted/publisher.hex \
  --verified-copy accepted/bhf-release.tar.gz \
  --max-archive-bytes 4294967296 \
  --openssl-timeout 15 \
  --json
```

Continue only when the exit code is `0` and the JSON `status` is `verified`.
Then use **`accepted/bhf-release.tar.gz`**, not the original `incoming` path.
The result gives the archive's byte count and SHA-256, fingerprints of the
public key and the signature, and the path of the copy.

How the copy is written:

1. The bytes are hashed while they are written to a private staging file on
   the output filesystem.
2. The digest is verified and the staged file is synced.
3. The copy is published with an atomic hard link, which never replaces an
   existing name, so of two concurrent publishers only the first succeeds. A
   filesystem without hard links fails with an error; there is no
   rename fallback.

The copy needs disk space for a second archive. On POSIX it has owner
read/write permission only (`0600`, subject to your umask), with no execute
bits and no permissions copied from the source, and the containing directory
is synced after publication. On other hosts, `publication_directory_sync`
reports `not_supported`. Windows filesystem and ACL behavior has not been
validated.

A directory-sync or cleanup failure after publication returns a nonzero exit
and still reports `published_copy`: the verified copy can exist even when the
command reports an error. Inspect the reported condition before deleting that
path or retrying.

The owner of the copy or an administrator can still change it after
publication. Protect the destination directory and use the copy within the
same controlled handoff. If the process is killed, a private staging
directory can remain; the script does not clean up other runs' directories.

## Verify without a copy

Without `--verified-copy`, the script authenticates the bytes it reads from
the source. This mode needs no second copy, but another process that opens
the source path later may see different bytes. The human-readable output says
so.

## Limits

| Limit | Value |
|---|---|
| Archive size | 4 GiB by default; set with `--max-archive-bytes`. Hashing streams in 1 MiB chunks and enforces the limit even if the file grows after its size was checked |
| Public-key file | At most 66 bytes |
| Signature | Exactly 64 bytes |
| Input files | Leaf symlinks and non-regular files are rejected; on POSIX the open uses no-follow and non-blocking flags against a symlink or FIFO swapped in at the leaf. Parent directories are trusted |
| OpenSSL timeout | Per OpenSSL subprocess: 15 s by default, 1–120 s allowed (`--openssl-timeout`) |

The OpenSSL timeout applies to each subprocess, not to the whole run:
filesystem reads, writes and syncs can still block. OpenSSL's stdout and
stderr are discarded, and the command is run without a shell.

## Exit codes and JSON output

| Exit | Meaning |
| --- | --- |
| 0 | `verified`, or `self_test_passed` for `--self-test` |
| 1 | The signature was rejected after the crypto self-test succeeded |
| 2 | Invalid input, missing tool, resource limit, timeout, filesystem error, or failed crypto self-test |

With `--json`, every runtime and validation outcome is one JSON object.
Malformed command-line options follow normal argparse behavior: usage text on
stderr and exit `2`. The JSON is an unsigned record of what the script
observed; it does not authenticate a separate copy of the archive.

## The Bash verifier

`scripts/verify-offline-dist.sh` checks the same signature. It builds the fixed
Ed25519 SubjectPublicKeyInfo prefix and the key bytes with Bash's builtin
`printf`, so it needs no `xxd`, and it bounds its key-file read. It verifies
only: it has none of the Python verifier's copy, descriptor, timeout or
publication handling. It strips a trailing CR/LF from the key file, within
the size bound. The change that removed its `xxd` dependency,
`eb7a787f9114e47d2bdee69de071b2b3d6cb0fc0`, also added EL7 test
prerequisites; full EL7 acceptance is a separate gate.

## What a successful check means

A successful check authenticates the bytes under the **trusted key you
supplied**. Key revocation and expiry, rollback and version policy, release
approval, vulnerability status, license compliance, extraction safety,
operational fitness and deployment authorization are separate decisions. A
signed empty file also authenticates and is still not an installable bhf
release. Keep the installer's safe extraction, the authenticated content-pack
checks, the release acceptance and the operator's approval in place.

## Tests

`scripts/ci/tests/test_distribution_verifier.py` runs in CI's
`python3 -m unittest discover -s scripts/ci/tests -v` step, which needs an
OpenSSL with Ed25519 signing and verification; a missing OpenSSL is an error.
To run only these tests:

```sh
python3 -m unittest discover -s scripts/ci/tests \
  -p test_distribution_verifier.py -v
```

The tests generate temporary Ed25519 keys and real signatures, and check:
interoperability with the Bash verifier without `xxd`, tampering, exact
resource limits, input replacement, concurrent publication, filesystem
failures, cleanup outcomes, and a stalled crypto process that is killed and
reaped. Some filesystem failures are injected; concurrent publication and
signing use the real filesystem and OpenSSL. The stalled-process fixture runs
Python with `-S`, so site-customization hooks cannot delay its startup. The
temporary private keys are neither shipped nor kept.

The tests passed on Linux with Python 3.13.5 and OpenSSL 3.5.5. Python 3.8
syntax is checked separately. Running the suite on Python 3.8, Windows and
old-glibc systems is still needed before those platforms are claimed.

## References

- bhf's signature contract: `scripts/verify-offline-dist.sh` at
  `eb7a787f9114e47d2bdee69de071b2b3d6cb0fc0`.
- RFC 8032, section 7.1, TEST 2:
  <https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1>
- RFC 8410, Ed25519 SubjectPublicKeyInfo:
  <https://www.rfc-editor.org/rfc/rfc8410.html>
- OpenSSL `pkeyutl`: <https://docs.openssl.org/3.0/man1/openssl-pkeyutl/>
