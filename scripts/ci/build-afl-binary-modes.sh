#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Build AFL++'s QEMU and Frida modes for binaries without source, which
# Ubuntu's afl++ package leaves out, and install them under DEST:
#
#   DEST/usr/bin/afl-qemu-trace
#   DEST/usr/lib/afl/afl-frida-trace.so
#   DEST/usr/share/bhf/licenses/afl/  (licenses, UPSTREAM-SOURCES.txt)
#
# The container image's afl-binary-modes stage and the nightly run this. They
# are built from the AFL++ release that Ubuntu 24.04's package carries
# (4.09c), so afl-fuzz and both trace programs share one forkserver protocol.
# qemuafl is fetched at the commit that release pins (its own build script's
# shallow clone cannot check that commit out), and Frida's GumJS devkit is
# checked against its release digest. Needs the build dependencies the image
# stage installs (gcc, make, ninja, glib and pixman headers, python3 with
# setuptools, bison, flex, git, curl).
#
# Usage: build-afl-binary-modes.sh DEST [JOBS]
set -euo pipefail

dest="${1:?usage: build-afl-binary-modes.sh DEST [JOBS]}"
jobs="${2:-2}"

AFLPP_VERSION=4.09c
AFLPP_SOURCE_SHA256=2d3b2e4f066b1f3eda17faff147dfa3e4b16fba044257361aca51a2322c5122d
QEMUAFL_COMMIT=a1321713c7502c152dd7527555e0f8a800d55225
FRIDA_GUM_VERSION=16.0.11
FRIDA_COPYING_SHA256=5ea1544b51a28bc823b03159190d4108f9fb4f4ef912389f5137c6d295e175b2
case "$(uname -m)" in
  x86_64)
    frida_arch=x86_64
    frida_sha256=7a3c3e5cc359292454323f2c5cb6dcfa4175fd11410879c2a34108117c1afa8c
    ;;
  aarch64)
    frida_arch=arm64
    frida_sha256=4bcf99e7619cbd4f150f39c3e54d682c9a122f23595bdc95349859fa53cb7cfc
    ;;
  *) echo "build-afl-binary-modes.sh: unsupported architecture $(uname -m)" >&2; exit 2 ;;
esac

fetch() {
  curl --proto '=https' --tlsv1.2 --retry 5 --retry-all-errors --retry-delay 5 -fsSLo "$1" "$2"
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
src="$work/aflpp"

fetch "$work/aflpp.tar.gz" \
  "https://github.com/AFLplusplus/AFLplusplus/archive/refs/tags/v${AFLPP_VERSION}.tar.gz"
echo "${AFLPP_SOURCE_SHA256}  $work/aflpp.tar.gz" | sha256sum -c -
mkdir "$src"
tar -C "$src" --strip-components=1 -xzf "$work/aflpp.tar.gz"
[[ "$(cat "$src/qemu_mode/QEMUAFL_VERSION")" == "${QEMUAFL_COMMIT:0:10}" ]]

# QEMU mode: its build script checks for afl-showmap first.
make -C "$src" -j"$jobs" afl-showmap
git init -q "$src/qemu_mode/qemuafl"
git -C "$src/qemu_mode/qemuafl" fetch -q --depth 1 https://github.com/AFLplusplus/qemuafl "$QEMUAFL_COMMIT"
git -C "$src/qemu_mode/qemuafl" checkout -q FETCH_HEAD
[[ "$(git -C "$src/qemu_mode/qemuafl" rev-parse HEAD)" == "$QEMUAFL_COMMIT" ]]
(cd "$src/qemu_mode" && NO_CHECKOUT=1 JOBS="$jobs" ./build_qemu_support.sh)

# Frida mode, against the digest-checked devkit placed where its Makefile
# would download it.
devkit="frida-gumjs-devkit-${FRIDA_GUM_VERSION}-linux-${frida_arch}.tar.xz"
mkdir -p "$src/frida_mode/build/frida"
fetch "$src/frida_mode/build/frida/$devkit" \
  "https://github.com/frida/frida/releases/download/${FRIDA_GUM_VERSION}/$devkit"
echo "${frida_sha256}  $src/frida_mode/build/frida/$devkit" | sha256sum -c -
make -C "$src/frida_mode" -j"$jobs"

licenses="$dest/usr/share/bhf/licenses/afl"
mkdir -p "$dest/usr/bin" "$dest/usr/lib/afl" "$licenses"
install -m 0755 "$src/afl-qemu-trace" "$dest/usr/bin/afl-qemu-trace"
install -m 0755 "$src/afl-frida-trace.so" "$dest/usr/lib/afl/afl-frida-trace.so"
strip --strip-unneeded "$dest/usr/bin/afl-qemu-trace" "$dest/usr/lib/afl/afl-frida-trace.so"
cp "$src/LICENSE" "$licenses/AFLplusplus-LICENSE"
cp "$src/qemu_mode/qemuafl/COPYING" "$licenses/qemuafl-COPYING"
fetch "$licenses/frida-COPYING" "https://raw.githubusercontent.com/frida/frida/${FRIDA_GUM_VERSION}/COPYING"
echo "${FRIDA_COPYING_SHA256}  $licenses/frida-COPYING" | sha256sum -c -
printf '%s\n' \
  "AFLplusplus https://github.com/AFLplusplus/AFLplusplus/archive/refs/tags/v${AFLPP_VERSION}.tar.gz sha256:${AFLPP_SOURCE_SHA256}" \
  "qemuafl https://github.com/AFLplusplus/qemuafl git:${QEMUAFL_COMMIT}" \
  > "$licenses/UPSTREAM-SOURCES.txt"
echo "AFL++ ${AFLPP_VERSION} QEMU and Frida modes installed under $dest"
