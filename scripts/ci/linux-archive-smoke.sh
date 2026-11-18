#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# linux-archive-smoke.sh DISTRIB_DIR TARGET: check the CLI, daemon and both
# shim component archives of TARGET in DISTRIB_DIR against their .sha256
# sidecars, unpack them into INSTALL.md's manual layout (the shims copied
# into the CLI directory) and run the Linux release smoke on this machine:
# every artifact's libraries resolve, both programs report this checkout's
# version and commit, and `bhf auto` builds and fuzzes a C fixture with the
# runtrace shim loaded. Needs clang and make.
set -euo pipefail
[ "$#" -eq 2 ] || { echo "usage: linux-archive-smoke.sh DISTRIB_DIR TARGET" >&2; exit 2; }
distrib=$(cd "$1" && pwd)
target=$2
root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for component in bhf bhf-daemon bhf_runtrace_shim bhf_cc_intercept; do
  archive=$component-$target.tar.xz
  (cd "$distrib" && sha256sum -c "$archive.sha256")
  tar -xJf "$distrib/$archive" -C "$tmp"
done
cli=$tmp/bhf-$target
install -m 0755 "$tmp/bhf_runtrace_shim-$target/libbhf_runtrace_shim.so" "$cli/"
install -m 0755 "$tmp/bhf_cc_intercept-$target/libbhf_cc_intercept.so" "$cli/"
daemon=$tmp/bhf-daemon-$target/bhf-daemon

uname -m
clang --version
for artifact in "$cli/bhf" "$daemon" "$cli/libbhf_runtrace_shim.so" "$cli/libbhf_cc_intercept.so"; do
  ldd "$artifact"
done | tee "$tmp/ldd.txt"
if grep -q "not found" "$tmp/ldd.txt"; then exit 1; fi

version=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' "$root/Cargo.toml")
commit=$(git -C "$root" rev-parse HEAD)
"$cli/bhf" --version | tee "$tmp/bhf-version.txt"
"$daemon" --version | tee "$tmp/daemon-version.txt"
[[ $(head -n 1 "$tmp/bhf-version.txt") == "bhf v$version" ]] || {
  echo "the CLI does not report release version $version" >&2
  exit 1
}
for report in "$tmp/bhf-version.txt" "$tmp/daemon-version.txt"; do
  grep -Fxq "commit: $commit" "$report" || {
    echo "$(basename "$report" -version.txt) does not report the tested commit $commit" >&2
    exit 1
  }
done
"$daemon" --help >/dev/null

fixture=$root/tests/fixtures/engine_parity/magic_byte
"$cli/bhf" scan "$fixture" --work-dir "$tmp/scan"
"$cli/bhf" auto "$fixture" --work-dir "$tmp/plan" \
  --languages c --list-targets --no-discovery-cache
"$cli/bhf" auto "$fixture" --work-dir "$tmp/fuzz" \
  --languages c --target parse_frame --iterations 32 --single-pass \
  --sanitizers none --per-target-time 5 --no-discovery-cache
grep -Eq '"built_and_fuzzed"[[:space:]]*:[[:space:]]*1' "$tmp/fuzz/auto/run.json"
test -n "$(find "$tmp/fuzz" -name runtrace.jsonl -type f -size +0c -print -quit)"
echo "linux archive smoke: $target archives passed on $(uname -m)"
