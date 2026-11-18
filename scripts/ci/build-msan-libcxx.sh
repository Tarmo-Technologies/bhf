#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Build libc++ and libc++abi instrumented with MemorySanitizer, from the LLVM
# release of the clang on PATH, and install them under PREFIX: the libraries
# a C++ harness's `msan` target links (BHF_MSAN_LIBCXX=PREFIX). The container
# image's msan-libcxx stage and the nightly run this. PREFIX/LLVM_VERSION
# names the release. With LICENSE_DIR, the two libraries' licenses are copied
# there. DESTDIR, when set, stages the install as make's does. Needs the
# build dependencies the image stage installs (clang and its runtime
# libraries, cmake, ninja, python3, curl, xz).
#
# Usage: build-msan-libcxx.sh PREFIX [LICENSE_DIR]
set -euo pipefail

prefix="${1:?usage: build-msan-libcxx.sh PREFIX [LICENSE_DIR]}"
licenses="${2:-}"

LLVM_VERSION=18.1.3
LLVM_SOURCE_SHA256=2929f62d69dec0379e529eb632c40e15191e36f3bd58c2cb2df0413a0dc48651

have="$(clang -dumpversion)"
if [[ "$have" != "$LLVM_VERSION" ]]; then
  echo "build-msan-libcxx.sh: clang is $have, not LLVM $LLVM_VERSION: the libraries must match the compiler that links them" >&2
  exit 1
fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
src="llvm-project-${LLVM_VERSION}.src"
curl --proto '=https' --tlsv1.2 --retry 5 --retry-all-errors --retry-delay 5 -fsSLo "$work/llvm.tar.xz" \
  "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/${src}.tar.xz"
echo "${LLVM_SOURCE_SHA256}  $work/llvm.tar.xz" | sha256sum -c -
tar -C "$work" -xJf "$work/llvm.tar.xz" "$src/runtimes" "$src/libcxx" "$src/libcxxabi" \
  "$src/libunwind" "$src/cmake" "$src/llvm/cmake" "$src/llvm/utils/llvm-lit" "$src/third-party"
cmake -G Ninja -S "$work/$src/runtimes" -B "$work/build" -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DLLVM_ENABLE_RUNTIMES='libcxx;libcxxabi' \
  -DLLVM_USE_SANITIZER=MemoryWithOrigins -DLIBCXXABI_USE_LLVM_UNWINDER=OFF \
  -DLIBCXX_INCLUDE_TESTS=OFF -DLIBCXXABI_INCLUDE_TESTS=OFF -DLIBCXX_INCLUDE_BENCHMARKS=OFF \
  -DLIBCXX_ENABLE_STATIC=OFF -DLIBCXXABI_ENABLE_STATIC=OFF -DCMAKE_INSTALL_PREFIX="$prefix"
ninja -C "$work/build" install-cxx install-cxxabi
installed="${DESTDIR:-}$prefix"
echo "$LLVM_VERSION" > "$installed/LLVM_VERSION"
if [[ -n "$licenses" ]]; then
  mkdir -p "$licenses"
  cp "$work/$src/libcxx/LICENSE.TXT" "$licenses/libcxx-LICENSE.TXT"
  cp "$work/$src/libcxxabi/LICENSE.TXT" "$licenses/libcxxabi-LICENSE.TXT"
fi
test -f "$installed/lib/libc++.so.1"
