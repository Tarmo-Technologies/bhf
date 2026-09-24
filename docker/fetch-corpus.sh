#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Fetch the pinned sweep corpus described by a manifest TSV into $BHF_CORPUS.
# Each project is cloned at an exact revision so the sweep is reproducible.
#
# Manifest columns (tab-separated, '#' comments and blank lines ignored):
#   lang   id   git_url   rev   subpath   extra_bhf_flags
# subpath and extra_bhf_flags may be empty ("-" is also treated as empty).
#
# Env:
#   BHF_SWEEP_MANIFEST   manifest path (default: baked-in manifest)
#   BHF_CORPUS           destination dir (default: ./corpus)
set -euo pipefail
# Never block on a credential prompt for a bad/private URL — fail fast instead.
export GIT_TERMINAL_PROMPT=0

MANIFEST="${BHF_SWEEP_MANIFEST:-/usr/local/share/bhf/sweep-manifest.tsv}"
CORPUS="${BHF_CORPUS:-$PWD/corpus}"

[ -f "$MANIFEST" ] || { echo "manifest not found: $MANIFEST" >&2; exit 2; }
mkdir -p "$CORPUS"

fail=0 n=0
# Read the manifest on FD 3 so `git` in the loop body cannot consume it.
while IFS=$'\t' read -r lang id url rev subpath extra <&3 || [ -n "${lang:-}" ]; do
    case "$lang" in ''|'#'*) continue;; esac
    n=$((n+1))
    dest="$CORPUS/${lang}__${id}"
    if [ -d "$dest/.git" ]; then
        echo "[skip] $lang/$id already present"
        continue
    fi
    echo "[fetch] $lang/$id  $url @ $rev"
    rm -rf "$dest"
    # Try a cheap partial clone; fall back to a full clone if the server or rev
    # does not support fetching a single commit.
    if git clone --filter=blob:none --no-checkout "$url" "$dest" 2>/dev/null \
        || git clone --no-checkout "$url" "$dest"; then
        if ! ( cd "$dest" && git fetch --depth 1 origin "$rev" 2>/dev/null \
                && git checkout -q FETCH_HEAD 2>/dev/null ) ; then
            ( cd "$dest" && git checkout -q "$rev" )
        fi
    else
        echo "[error] clone failed: $lang/$id" >&2
        fail=$((fail+1))
        continue
    fi
    ( cd "$dest" && git rev-parse HEAD > .bhf-rev ) 2>/dev/null || true
done 3< "$MANIFEST"

echo
echo "Fetched into $CORPUS ($n projects, $fail failures)"
exit $(( fail > 0 ? 1 : 0 ))
