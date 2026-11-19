#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# install-symcc.sh [PREFIX]: build SymCC (its compiler pass and the QSYM
# backend of its runtime) at a pinned commit into PREFIX (default
# ~/.local/opt/symcc) for `bhf auto --symcc` (#324, #331), which no
# distribution packages, and print the directory to put on PATH, for
# $GITHUB_PATH: PREFIX/build, which holds `symcc` and `sym++`. SymCC is
# GPL-3.0; bhf runs it only as a subprocess, under a license profile that
# allows it. A PREFIX that already holds the build is reused. Needs git,
# cmake, ninja, a C++17 compiler, libz3-dev and the development files of an
# LLVM SymCC supports (8 to 18): LLVM_CONFIG names its llvm-config (default
# `llvm-config`), and SymCC compiles with that LLVM's clang. SYMCC_BUILD_JOBS
# caps the build's parallelism (default: every core).
set -euo pipefail
commit=522c48070bc312aeb621a631ff130ded71507d6d
prefix=${1:-$HOME/.local/opt/symcc}
llvm_config=${LLVM_CONFIG:-llvm-config}
jobs=${SYMCC_BUILD_JOBS:-$(nproc)}
if [ ! -x "$prefix/build/symcc" ] || [ ! -x "$prefix/build/sym++" ]; then
  rm -rf "$prefix"
  git init -q "$prefix/src"
  git -C "$prefix/src" fetch -q --depth 1 https://github.com/eurecom-s3/symcc "$commit" >&2
  git -C "$prefix/src" checkout -q FETCH_HEAD
  git -C "$prefix/src" submodule update -q --init --recursive >&2
  cmake -S "$prefix/src" -B "$prefix/build" -G Ninja \
    -DSYMCC_RT_BACKEND=qsym \
    -DCMAKE_BUILD_TYPE=Release \
    -DZ3_TRUST_SYSTEM_VERSION=on \
    -DLLVM_DIR="$("$llvm_config" --cmakedir)" >&2
  ninja -C "$prefix/build" -j"$jobs" >&2
fi
test -x "$prefix/build/symcc" && test -x "$prefix/build/sym++"
echo "$prefix/build"
