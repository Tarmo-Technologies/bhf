#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Install rustup from the pinned rustup-init (the one the Dockerfile uses),
# checked against its SHA-256, then a toolchain: the arguments go to
# rustup-init (x86_64 and aarch64 Linux containers).
set -euo pipefail
version=1.28.2
case "$(uname -sm)" in
  "Linux x86_64")
    triple=x86_64-unknown-linux-gnu
    sha256=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c ;;
  "Linux aarch64")
    triple=aarch64-unknown-linux-gnu
    sha256=e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c ;;
  *) echo "install-rustup.sh: x86_64 or aarch64 Linux only" >&2; exit 1 ;;
esac
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
"$here/fetch.sh" \
  "https://static.rust-lang.org/rustup/archive/$version/$triple/rustup-init" \
  "$sha256" "$tmp/rustup-init"
chmod +x "$tmp/rustup-init"
"$tmp/rustup-init" "$@"
