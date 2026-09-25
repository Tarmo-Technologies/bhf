<!-- SPDX-License-Identifier: Apache-2.0 -->
# Verified distribution handoff

## Purpose and trust boundary

`scripts/verify-offline-dist.py` verifies the existing BHF detached distribution
signature and can publish an independent copy of the **exact bytes verified**.
It is a standalone utility, not a new `bhf` subcommand. Neither mode extracts the
archive, executes its contents, or accesses the network.

Obtain this verifier and the publisher's public key through a trusted channel
independent of the unverified distribution. A public key inside the archive is
not a trust anchor. The script, Python interpreter, OpenSSL executable and
configuration, ancestor directories, and output directory must be trusted. This
is not a sandbox against malicious processes running as the same account.

The signature format is unchanged: a raw 64-byte Ed25519 signature over
`BHF.DIST.TARBALL.ED25519.V1`, a NUL byte, and the raw 32-byte SHA-256 archive
digest. The external public-key file must contain exactly 64 lowercase hex
characters, optionally followed by one LF or CRLF. No embedded newlines, extra
whitespace, or arbitrary key-file size is accepted by the Python verifier.

## Requirements and local crypto check

The implementation uses Python's standard library and targets Python 3.8 or
later. OpenSSL must support Ed25519 verification with `pkeyutl -rawin`; the
self-test checks the actual installed implementation and configured policy.
Use an absolute `--openssl` path when PATH is not under operator control.

```sh
python3 scripts/verify-offline-dist.py --self-test --json
```

This checks both a valid and a tampered public RFC 8032 test vector. Its result
explicitly says `archive_verified: false`. It is a compatibility check, not a
cryptographic module validation or publisher-authentication check. A failing
local crypto policy is not disabled, bypassed, or changed by the utility.

## Verify and publish a separate copy

Create or select a trusted destination directory first. The destination file
must not already exist, including as a dangling symlink.

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

Only proceed when the exit code is zero and the JSON `status` is `verified`.
Consume **`accepted/bhf-release.tar.gz`**, not the original `incoming` path.
The result includes the archive byte count and SHA-256, fingerprints of the
supplied public key and signature, and the published-copy path.

Copy mode hashes the bytes while writing a private staging file on the output
filesystem. It verifies the digest, synchronizes the staged file, and then
publishes it using atomic hard-link creation without replacing an existing
name. Concurrent publishers cannot overwrite the winner. A filesystem without
hard-link support fails explicitly; there is no ordinary-rename fallback.
This technique requires available disk space for another archive copy.

On POSIX, the copy has owner read/write permissions only (0600, subject to the
operator's umask); executable bits and source permissions are not inherited.
The containing directory is synchronized after publication. On non-POSIX hosts,
`publication_directory_sync` reports `not_supported` rather than claiming the
same durability. Windows filesystem and ACL behavior has not been validated by
this change set.

A directory-sync or cleanup failure after publication returns a nonzero result
and reports `published_copy`. The verified bytes may therefore exist even when
the overall operation reports an operational error. Do not assume every error
means nothing was created, or delete that path without inspecting the reported
condition. This is especially important for retry logic.

The independent copy is **not immutable**: its owner or an administrator can
change it after publication. Protect the destination directory and consume the
copy within the same controlled handoff. Sudden termination may leave a private
staging directory; no automatic wildcard cleanup of other runs is performed.

## Verification without copying

Omit `--verified-copy` to authenticate only the bytes read from the source.
This mode needs no second archive copy, but it cannot guarantee that the source
path will still contain those bytes when another process later opens it. The
human-readable output warns about this distinction.

## Limits, errors, and machine-readable results

The default archive limit is 4 GiB, configurable with `--max-archive-bytes`.
Hashing is streamed in 1 MiB chunks and enforces the bound even if the source
size grows after its metadata is inspected. Public keys are bounded at 66
bytes, and signatures must be exactly 64 bytes. Leaf symlinks and nonregular
input files are rejected; POSIX no-follow/nonblocking flags protect the open
against leaf symlink/FIFO substitution. Parent directories remain trusted.

Each OpenSSL subprocess has its own timeout (default 15 seconds; permitted
range 1–120 seconds). This is **not a deadline for the entire operation**:
filesystem reads, writes, and synchronization can block on the underlying
filesystem. OpenSSL stdout and stderr are discarded, and no shell is used to
construct the crypto command.

| Exit | Meaning |
| --- | --- |
| 0 | `verified`, or `self_test_passed` when explicitly running a self-test. |
| 1 | Distribution signature rejected after the crypto self-test succeeded. |
| 2 | Invalid inputs, missing tools, resource limits, timeout, filesystem error, or failed crypto self-test. |

With `--json`, runtime and semantic validation outcomes are written as one JSON
object. Syntactically invalid command-line options follow normal argparse
behavior: usage text on stderr and exit 2. A result JSON document is an
observation, not a signed attestation; its contents alone do not authenticate a
separate copy of the archive.

## Existing shell-verifier compatibility

The existing Bash verifier is unchanged by this patch. The inspected branch emits
the fixed Ed25519 SubjectPublicKeyInfo prefix and validated key bytes using
Bash's builtin `printf` instead of requiring `xxd`, and bounds its key-file read.
It remains verification-only; it does not inherit the Python verifier's copy,
descriptor, timeout, or publication guarantees. It also retains its previous
CR/LF-stripping behavior for accepted key files, subject to the new size bound.

The missing-`xxd` dependency was removed by the separate branch commit
`eb7a787f9114e47d2bdee69de071b2b3d6cb0fc0`, which also added EL7 test prerequisites.
This additive patch does not replace those changes or establish full EL7 acceptance.

## Scope of the guarantee

A successful signature check authenticates the bytes under the **supplied
trusted key**. It does not decide key revocation, expiry, rollback/version
policy, release approval, vulnerability status, license compliance, archive
extraction safety, operational suitability, or deployment authorization. Even a
signed empty file can authenticate; that does not make it an installable BHF
release. Keep the installer's safe extraction and authenticated content-pack
checks, as well as release acceptance and operator approval.

This utility is not automatically added to release bundles or release assets by
this patch. Distribute it separately through the trusted verifier channel until
the publishing workflow explicitly integrates and validates it.

## Regression validation

The new test file is under the existing CI discovery path, so the current
`python3 -m unittest discover -s scripts/ci/tests -v` step will discover it after
application. That job will now also require an OpenSSL executable with Ed25519
signing and verification support; absence is an error, not a silent skip.
The focused command is:

```sh
python3 -m unittest discover -s scripts/ci/tests \
  -p test_distribution_verifier.py -v
```

Fifty focused tests passed locally on Linux with Python 3.13.5 and OpenSSL 3.5.5,
with zero failures and zero skips. Tests generate temporary Ed25519 keys and
real signatures, check interoperability with the Bash verifier without `xxd`,
and cover tampering, exact resource limits, input replacement, concurrent
publication, filesystem failures, cleanup outcomes, and an actual stalled crypto
process that is killed and reaped. Some filesystem failures are injected;
concurrent publication and signature operations use the real filesystem and
OpenSSL. Temporary test private keys are neither shipped nor retained.

A publication-time rerun on 2026-09-25 initially found the stalled-process
fixture timing out before its Python startup marker. The fixture now uses
Python's `-S` flag to avoid unrelated site/customization startup hooks; its
one-second timeout and the production timeout behavior are unchanged. All 50
focused tests and the 8 unchanged Bash-verifier tests passed after that repair.

Python 3.8 syntax is checked separately; executing the test suite on Python 3.8,
Windows, old-glibc systems, and the complete BHF repository remains necessary
before extending those platform claims. No full workspace build or hosted CI
success is established by these focused local tests.

## Primary references

- BHF's existing signature contract: `scripts/verify-offline-dist.sh` at
  `eb7a787f9114e47d2bdee69de071b2b3d6cb0fc0`.
- RFC 8032, section 7.1 TEST 2: https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1
- RFC 8410, Ed25519 SubjectPublicKeyInfo: https://www.rfc-editor.org/rfc/rfc8410.html
- OpenSSL pkeyutl: https://docs.openssl.org/3.0/man1/openssl-pkeyutl/
