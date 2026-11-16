#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Install the pinned cargo-nextest into $CARGO_HOME/bin (x86_64 and aarch64
# Linux runners).
set -euo pipefail
version=0.9.146
case "$(uname -sm)" in
  "Linux x86_64")
    triple=x86_64-unknown-linux-gnu
    sha256=682c21b777c333e96fd532e114d3a5a894e0729ab88d94c0a9f20f8419695428 ;;
  "Linux aarch64")
    triple=aarch64-unknown-linux-gnu
    sha256=b2e33d7c72de7ade0ff7b3a948ac37516b24f8a836b7a8870c1f634a94be9de9 ;;
  *) echo "install-nextest.sh: x86_64 or aarch64 Linux only" >&2; exit 1 ;;
esac
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
"$here/fetch.sh" \
  "https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-$version/cargo-nextest-$version-$triple.tar.gz" \
  "$sha256" "$tmp/nextest.tar.gz"
bin=${CARGO_HOME:-$HOME/.cargo}/bin
mkdir -p "$bin"
tar -xzf "$tmp/nextest.tar.gz" -C "$bin"
