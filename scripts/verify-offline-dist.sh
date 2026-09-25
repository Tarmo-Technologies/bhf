#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ARCHIVE=""
SIGNATURE=""
TRUSTED_PUBLIC_KEY=""

usage() {
  cat <<'EOF'
Usage: verify-offline-dist.sh --archive FILE.tar.gz --signature FILE.tar.gz.sig --trusted-public-key FILE

Verify a detached BHF distribution signature with system OpenSSL before
extracting or executing any code from the archive. Obtain this verifier and
the public key through a trusted channel independent of the unverified archive.
The public-key file contains exactly 64 lowercase hex characters (plus newline).
EOF
}

die() {
  printf 'verify-offline-dist.sh: %s\n' "$*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --archive) [[ $# -ge 2 ]] || die "--archive requires a file"; ARCHIVE="$2"; shift 2 ;;
    --signature) [[ $# -ge 2 ]] || die "--signature requires a file"; SIGNATURE="$2"; shift 2 ;;
    --trusted-public-key) [[ $# -ge 2 ]] || die "--trusted-public-key requires a file"; TRUSTED_PUBLIC_KEY="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option '$1'" ;;
  esac
done

[[ -n "$ARCHIVE" && -n "$SIGNATURE" && -n "$TRUSTED_PUBLIC_KEY" ]] || die "all three file options are required"
for path in "$ARCHIVE" "$SIGNATURE" "$TRUSTED_PUBLIC_KEY"; do
  [[ -f "$path" && ! -L "$path" ]] || die "input must be a regular, non-symlink file: $path"
done
[[ "$(wc -c <"$SIGNATURE")" -eq 64 ]] || die "detached Ed25519 signature must be exactly 64 bytes"
for command in openssl xxd mktemp; do
  command -v "$command" >/dev/null 2>&1 || die "$command is required"
done

PUBLIC_HEX="$(tr -d '\r\n' <"$TRUSTED_PUBLIC_KEY")"
[[ "$PUBLIC_HEX" =~ ^[0-9a-f]{64}$ ]] || die "trusted public key must contain 64 lowercase hex characters"

VERIFY_TMP="$(mktemp -d)"
cleanup() {
  rm -f -- "$VERIFY_TMP/public.der" "$VERIFY_TMP/message.bin"
  rmdir -- "$VERIFY_TMP"
}
trap cleanup EXIT

# RFC 8410 Ed25519 SubjectPublicKeyInfo prefix followed by the raw 32-byte key.
printf '302a300506032b6570032100%s' "$PUBLIC_HEX" | xxd -r -p >"$VERIFY_TMP/public.der"
{
  printf 'BHF.DIST.TARBALL.ED25519.V1\0'
  openssl dgst -sha256 -binary "$ARCHIVE"
} >"$VERIFY_TMP/message.bin"

if ! openssl pkeyutl -verify -pubin -inkey "$VERIFY_TMP/public.der" -keyform DER \
  -rawin -in "$VERIFY_TMP/message.bin" -sigfile "$SIGNATURE" >/dev/null 2>&1; then
  die "distribution signature verification failed"
fi
printf 'Verified distribution signature: %s\n' "$ARCHIVE"
