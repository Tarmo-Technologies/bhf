#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# install-python2.sh [PREFIX]: build CPython 2.7.18 into PREFIX (default
# ~/.local/opt/python2.7) for the Python 2 lane's tests (#285), since Ubuntu no
# longer packages python2, and print a directory that holds only `python2` and
# `python2.7`, for $GITHUB_PATH: the build's own `python` must not shadow the
# host's Python 3. A PREFIX that already holds the build is reused.
set -euo pipefail
version=2.7.18
sha256=da3080e3b488f648a3d7a4560ddee895284c3380b11d6de75edb986526b9a814
prefix=${1:-$HOME/.local/opt/python2.7}
if [ ! -x "$prefix/bin/python2.7" ]; then
  here=$(cd "$(dirname "$0")" && pwd)
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  "$here/fetch.sh" "https://www.python.org/ftp/python/$version/Python-$version.tgz" \
    "$sha256" "$tmp/python.tgz" >&2
  tar -xzf "$tmp/python.tgz" -C "$tmp"
  if ! (cd "$tmp/Python-$version" \
        && ./configure --prefix="$prefix" >"$tmp/configure.log" 2>&1 \
        && make -j"$(nproc)" >"$tmp/make.log" 2>&1 \
        && make install >"$tmp/install.log" 2>&1); then
    tail -n 40 "$tmp"/*.log >&2
    exit 1
  fi
fi
bin=$prefix/path
mkdir -p "$bin"
ln -sf "$prefix/bin/python2.7" "$bin/python2"
ln -sf "$prefix/bin/python2.7" "$bin/python2.7"
"$bin/python2" -c 'import sys; assert sys.version_info[:2] == (2, 7)'
echo "$bin"
