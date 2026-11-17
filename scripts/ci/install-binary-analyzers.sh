#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# install-binary-analyzers.sh DIR: install the pinned Rizin that
# crates/cli/tests/binary_adapter_tools.rs runs `bhf binary adapter` against
# into DIR, and print the variable that names it (BHF_RIZIN) on stdout, for
# $GITHUB_ENV.
set -euo pipefail
[ "$#" -eq 1 ] || { echo "usage: install-binary-analyzers.sh DIR" >&2; exit 2; }
dir=$1
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$dir"

rizin_version=0.9.1
rizin_sha256=9102249a9f0b6319c5334a2e5cf8d9cc3f2035e1d3def027c41f6a90f647e8cf

# The static build: one tree with its libraries, no system packages.
"$here/fetch.sh" \
  "https://github.com/rizinorg/rizin/releases/download/v$rizin_version/rizin-v$rizin_version-static-x86_64.tar.xz" \
  "$rizin_sha256" "$dir/rizin.tar.xz"
mkdir -p "$dir/rizin"
tar -xJf "$dir/rizin.tar.xz" -C "$dir/rizin"
rm "$dir/rizin.tar.xz"

# It answers before the tests run; its output is the job log's, not
# $GITHUB_ENV's.
{
  "$dir/rizin/bin/rizin" -v </dev/null
} >&2

echo "BHF_RIZIN=$dir/rizin/bin/rizin"
