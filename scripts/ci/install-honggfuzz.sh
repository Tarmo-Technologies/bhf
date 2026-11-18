#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# install-honggfuzz.sh [PREFIX]: build honggfuzz 2.6 into PREFIX (default
# ~/.local/opt/honggfuzz) for `bhf fuzz --engine honggfuzz` (#295), which Ubuntu
# does not package, and print the directories to put on PATH, for
# $GITHUB_PATH: PREFIX (honggfuzz) and PREFIX/hfuzz_cc (hfuzz-clang). It builds
# in PREFIX itself, since hfuzz-clang finds libhfuzz where it was built. A
# PREFIX that already holds the build is reused. Needs libunwind-dev,
# binutils-dev and libblocksruntime-dev.
set -euo pipefail
commit=83a8415a372d84dcc69ac1e2c2f152190bcf76d1
prefix=${1:-$HOME/.local/opt/honggfuzz}
if [ ! -x "$prefix/honggfuzz" ] || [ ! -x "$prefix/hfuzz_cc/hfuzz-clang" ]; then
  rm -rf "$prefix"
  git init -q "$prefix"
  git -C "$prefix" fetch -q --depth 1 https://github.com/google/honggfuzz "$commit" >&2
  git -C "$prefix" checkout -q FETCH_HEAD
  make -C "$prefix" -j"$(nproc)" >&2
fi
"$prefix/honggfuzz" --help >/dev/null 2>&1 || true
test -x "$prefix/honggfuzz" && test -x "$prefix/hfuzz_cc/hfuzz-clang"
echo "$prefix"
echo "$prefix/hfuzz_cc"
