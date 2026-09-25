#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run inside the pinned manylinux2014 CI image, from the repository root.
# This provisions test tools; it is not an offline installer or FIPS build.
set -euo pipefail

: "${CARGO_HOME:?CARGO_HOME must name the isolated CI Cargo directory}"
: "${RUSTUP_HOME:?RUSTUP_HOME must name the isolated CI rustup directory}"
: "${CARGO_TARGET_DIR:?CARGO_TARGET_DIR must name the CI target directory}"
test -f crates/continuous_daemon/Cargo.toml

# manylinux's CPython and modern crypto libraries are outside the default PATH.
# The pinned image retains OpenSSL libraries but not the modern openssl CLI.
test -x /opt/python/cp311-cp311/bin/python3
export PATH="/opt/python/cp311-cp311/bin:$PATH"
yum -y install vim-common perl-core
command -v python3
python3 --version
command -v xxd
ldd --version

# Build the independent verification CLI against this old userspace. Pin the
# source bytes before extraction/build; never trust a digest downloaded at run
# time as an independent authenticity check. Official release asset:
# https://github.com/openssl/openssl/releases/tag/openssl-3.5.8
openssl_work="$(mktemp -d /tmp/bhf-ci-openssl.XXXXXXXX)"
trap 'rm -rf -- "$openssl_work"' EXIT
curl --proto '=https' --tlsv1.2 --fail --location --retry 2 --max-time 180 \
  --output "$openssl_work/openssl.tar.gz" \
  https://github.com/openssl/openssl/releases/download/openssl-3.5.8/openssl-3.5.8.tar.gz
printf '%s  %s\n' \
  a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2 \
  "$openssl_work/openssl.tar.gz" | sha256sum --check --strict -
tar -C "$openssl_work" -xzf "$openssl_work/openssl.tar.gz"
(
  cd "$openssl_work/openssl-3.5.8"
  ./Configure --prefix="$openssl_work/install" --openssldir="$openssl_work/install/ssl" no-shared
  make -j2
  make install_sw
)
export PATH="$openssl_work/install/bin:$PATH"
openssl version

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
export PATH="$CARGO_HOME/bin:$PATH"
rustc --version --verbose
cargo test --locked -p continuous_daemon --lib
cargo test --locked -p governance --lib
cargo test --locked -p bhf --test offline_dist_scripts -- --nocapture
cargo build --locked --release --workspace
scripts/check-linux-release-abi.sh "$CARGO_TARGET_DIR/release"
mkdir -p target
tar -C "$CARGO_TARGET_DIR/release" -czf target/bhf-el7-release.tar.gz \
  bhf bhf-daemon libbhf_runtrace_shim.so libbhf_cc_intercept.so
