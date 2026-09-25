#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# CI prerequisite only: build the signature-test CLI on the EL7 ABI without
# replacing system OpenSSL or changing the BHF release's linked libraries.
# Run inside the disposable EL7 CI container, not on an offline deployment.
set -euo pipefail

[[ $# -eq 1 && "$1" = /* && "$1" != / ]] || {
  echo 'usage: build-test-openssl.sh NEW_ABSOLUTE_PREFIX' >&2
  exit 2
}
prefix="$1"
[[ ! -e "$prefix" && ! -L "$prefix" ]] || {
  echo 'refusing to overwrite an existing OpenSSL test prefix' >&2
  exit 1
}
# The pinned minimal image omits Perl modules required by OpenSSL Configure.
if ! perl -MIPC::Cmd -MData::Dumper -e 1 >/dev/null 2>&1; then
  yum -y install perl-core
fi
# Source digest from the official openssl/openssl 3.5.8 release asset metadata.
version=3.5.8
digest=a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --location \
  --retry 3 --connect-timeout 30 --max-time 300 \
  "https://github.com/openssl/openssl/releases/download/openssl-${version}/openssl-${version}.tar.gz" \
  --output "$work/source.tar.gz"
printf '%s  %s\n' "$digest" "$work/source.tar.gz" | sha256sum --check --strict
# Do not execute or extract anything until its pinned digest has matched.
tar -xzf "$work/source.tar.gz" -C "$work"
(
  cd "$work/openssl-${version}"
  ./Configure linux-x86_64 no-shared no-tests \
    --prefix="$prefix" --openssldir="$prefix/ssl"
  make -j4 build_sw
  make install_sw
)
"$prefix/bin/openssl" version
# Verify the capability used by the real detached-signature tests.
"$prefix/bin/openssl" list -signature-algorithms | grep -i ed25519
