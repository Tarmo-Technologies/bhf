#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Install the pinned cargo-dist (`dist`) into $CARGO_HOME/bin from its release
# tarball, checked against its SHA-256 (x86_64 Linux runners and containers).
set -euo pipefail
version=0.31.0
sha256=cd355dab0b4c02fb59038fef87655550021d07f45f1d82f947a34ef98560abb8
[ "$(uname -sm)" = "Linux x86_64" ] || { echo "install-cargo-dist.sh: x86_64 Linux only" >&2; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
"$here/fetch.sh" \
  "https://github.com/axodotdev/cargo-dist/releases/download/v$version/cargo-dist-x86_64-unknown-linux-gnu.tar.xz" \
  "$sha256" "$tmp/cargo-dist.tar.xz"
tar -xJf "$tmp/cargo-dist.tar.xz" -C "$tmp"
bin=${CARGO_HOME:-$HOME/.cargo}/bin
mkdir -p "$bin"
install -m 0755 "$tmp/cargo-dist-x86_64-unknown-linux-gnu/dist" "$bin/dist"
"$bin/dist" --version
