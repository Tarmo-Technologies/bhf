#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Install the pinned cargo-dist (`dist`) into $CARGO_HOME/bin from its release
# tarball, checked against its SHA-256 (x86_64 and aarch64 Linux runners and
# containers). The static musl build: the glibc one needs glibc 2.34, which
# the RHEL 7 containers do not have.
set -euo pipefail
version=0.31.0
case "$(uname -sm)" in
  "Linux x86_64")
    triple=x86_64-unknown-linux-musl
    sha256=1d46b93a785e8b666c0e7add581d747d53c3f29589cc3ef9aee60341ad899023 ;;
  "Linux aarch64")
    triple=aarch64-unknown-linux-musl
    sha256=2ce8104f4e10cbcb4b46eb892dd17b84237d8477f2de7aa024ce5a897447a489 ;;
  *) echo "install-cargo-dist.sh: x86_64 or aarch64 Linux only" >&2; exit 1 ;;
esac
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
"$here/fetch.sh" \
  "https://github.com/axodotdev/cargo-dist/releases/download/v$version/cargo-dist-$triple.tar.xz" \
  "$sha256" "$tmp/cargo-dist.tar.xz"
tar -xJf "$tmp/cargo-dist.tar.xz" -C "$tmp"
bin=${CARGO_HOME:-$HOME/.cargo}/bin
mkdir -p "$bin"
install -m 0755 "$tmp/cargo-dist-$triple/dist" "$bin/dist"
"$bin/dist" --version
