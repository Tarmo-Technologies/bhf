#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# install-renode.sh DIR: install the pinned portable Renode that the live
# `renode:` transport tests (crates/target_transport/tests/live_renode.rs,
# crates/cli/tests/transport_fuzz_renode_cli.rs) run against into DIR, and
# print BHF_RENODE, its launcher, on stdout, for $GITHUB_ENV.
set -euo pipefail
[ "$#" -eq 1 ] || { echo "usage: install-renode.sh DIR" >&2; exit 2; }
dir=$1
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$dir"

renode_version=1.17.0
renode_sha256=4ba7c68b59e2447f188ef4b4b112fcccd2802582c460beedceb63b84e5605a5f

# The portable build carries its own .NET runtime: no system packages.
"$here/fetch.sh" \
  "https://github.com/renode/renode/releases/download/v$renode_version/renode-$renode_version.linux-portable.tar.gz" \
  "$renode_sha256" "$dir/renode.tar.gz"
mkdir -p "$dir/renode"
tar -xzf "$dir/renode.tar.gz" -C "$dir/renode" --strip-components=1
rm "$dir/renode.tar.gz"

# It answers before the tests run; the output is the job log's.
"$dir/renode/renode" --version </dev/null >&2

echo "BHF_RENODE=$dir/renode/renode"
