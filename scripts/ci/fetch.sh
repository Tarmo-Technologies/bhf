#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# fetch.sh URL SHA256 DEST: download URL to DEST and check its SHA-256,
# retrying transient failures (a CDN's 503 or 403). A copy already in the
# fetch cache (BHF_FETCH_CACHE, default ~/.cache/bhf-fetch) with that digest
# is used instead of the network.
set -euo pipefail
[ "$#" -eq 3 ] || { echo "usage: fetch.sh URL SHA256 DEST" >&2; exit 2; }
url=$1
sha256=$2
dest=$3
cache=${BHF_FETCH_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/bhf-fetch}
cached=$cache/$sha256
if [ -f "$cached" ] && echo "$sha256  $cached" | sha256sum --check --status -; then
  cp "$cached" "$dest"
  exit 0
fi
# --retry-all-errors (curl 7.71) also retries an HTTP 503 or 403; the
# RHEL 7 containers' curl is older and retries transient failures only.
retry=(--retry 5 --retry-delay 5)
if curl --help all 2>/dev/null | grep -q -- --retry-all-errors; then
  retry+=(--retry-all-errors)
fi
curl --proto '=https' --tlsv1.2 "${retry[@]}" -fsSLo "$dest.part" "$url"
echo "$sha256  $dest.part" | sha256sum --check --quiet - || {
  echo "fetch.sh: $url does not have SHA-256 $sha256" >&2
  rm -f "$dest.part"
  exit 1
}
mv "$dest.part" "$dest"
mkdir -p "$cache" && cp "$dest" "$cached" || true
