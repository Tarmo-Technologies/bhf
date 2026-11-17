#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# install-binary-analyzers.sh DIR: install the pinned Rizin, Ghidra and angr
# that crates/cli/tests/binary_adapter_tools.rs runs `bhf binary adapter`
# against into DIR, and print the variables that name them (BHF_RIZIN,
# BHF_GHIDRA_HEADLESS, BHF_ANGR_PYTHON) on stdout, for $GITHUB_ENV. Ghidra
# 12.2 needs a JDK 25 on PATH or in JAVA_HOME, which the workflow installs.
set -euo pipefail
[ "$#" -eq 1 ] || { echo "usage: install-binary-analyzers.sh DIR" >&2; exit 2; }
dir=$1
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$dir"

rizin_version=0.9.1
rizin_sha256=9102249a9f0b6319c5334a2e5cf8d9cc3f2035e1d3def027c41f6a90f647e8cf
ghidra_version=12.2
ghidra_build=20261016
ghidra_sha256=2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67
angr_version=10.0.7

# The static build: one tree with its libraries, no system packages.
"$here/fetch.sh" \
  "https://github.com/rizinorg/rizin/releases/download/v$rizin_version/rizin-v$rizin_version-static-x86_64.tar.xz" \
  "$rizin_sha256" "$dir/rizin.tar.xz"
mkdir -p "$dir/rizin"
tar -xJf "$dir/rizin.tar.xz" -C "$dir/rizin"
rm "$dir/rizin.tar.xz"

"$here/fetch.sh" \
  "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${ghidra_version}_build/ghidra_${ghidra_version}_PUBLIC_$ghidra_build.zip" \
  "$ghidra_sha256" "$dir/ghidra.zip"
unzip -q "$dir/ghidra.zip" -d "$dir"
rm "$dir/ghidra.zip"
headless=$dir/ghidra_${ghidra_version}_PUBLIC/support/analyzeHeadless

python3 -m venv "$dir/angr-venv"
"$dir/angr-venv/bin/pip" install --quiet --disable-pip-version-check "angr==$angr_version"

# Each answers before the tests run; their output is the job log's, not
# $GITHUB_ENV's.
{
  "$dir/rizin/bin/rizin" -v </dev/null
  test -x "$headless"
  grep "^application.version=$ghidra_version\$" "$dir/ghidra_${ghidra_version}_PUBLIC/Ghidra/application.properties"
  "$dir/angr-venv/bin/python" -c 'import angr; print("angr", angr.__version__)' 2>/dev/null
} >&2

echo "BHF_RIZIN=$dir/rizin/bin/rizin"
echo "BHF_GHIDRA_HEADLESS=$headless"
echo "BHF_ANGR_PYTHON=$dir/angr-venv/bin/python"
