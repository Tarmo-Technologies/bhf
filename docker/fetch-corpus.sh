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
FILTER="${BHF_LANGS:-}"
CONTRACT="$(dirname "$(readlink -f "$0")")/sweep_contract.py"

[ -f "$MANIFEST" ] || { echo "manifest not found: $MANIFEST" >&2; exit 2; }
ROWS=$(python3 "$CONTRACT" rows "$MANIFEST")
mkdir -p "$CORPUS"

fail=0 n=0
# Read the manifest on FD 3 so `git` in the loop body cannot consume it.
while IFS=$'\t' read -r lang id url rev subpath extra <&3 || [ -n "${lang:-}" ]; do
    case "$lang" in ''|'#'*) continue;; esac
    if [ -n "$FILTER" ]; then case " $FILTER " in *" $lang "*) : ;; *) continue;; esac; fi
    n=$((n+1))
    dest="$CORPUS/${lang}__${id}"
    if [ -e "$dest" ] || [ -L "$dest" ]; then
        if python3 "$CONTRACT" checkout "$dest" "$rev" "$subpath"; then
            echo "[verified] $lang/$id matches $rev"
        else
            echo "[error] existing path is not a clean pinned checkout: $dest (left unchanged)" >&2
            fail=$((fail+1))
        fi
        continue
    fi
    echo "[fetch] $lang/$id  $url @ $rev"
    staging="$(mktemp -d "$CORPUS/.fetch-${lang}__${id}.XXXXXX")"
    # Try a cheap partial clone; fall back to a full clone if the server or rev
    # does not support fetching a single commit.
    # Separate locations for fallback: a failed clone may leave partial files.
    checkout="$staging/partial"
    if ! git clone --filter=blob:none --no-checkout "$url" "$checkout" 2>/dev/null; then
        checkout="$staging/full"
        git clone --no-checkout "$url" "$checkout" || true
    fi
    if ! { { git -C "$checkout" fetch --depth 1 origin "$rev" \
                 && git -C "$checkout" checkout -q --detach "$rev"; } \
             || git -C "$checkout" checkout -q --detach "$rev"; } \
        || ! python3 "$CONTRACT" checkout "$checkout" "$rev" "$subpath"; then
        echo "[error] fetch/checkout failed: $lang/$id (diagnostics retained at $staging)" >&2
        fail=$((fail+1))
        continue
    fi
    # Never overwrite a path created by a concurrent fetch. GNU mv -T treats
    # dest as the exact path; -n preserves it if another fetch wins the race.
    mv -T -n "$checkout" "$dest"
    if [ -e "$checkout" ]; then
        echo "[error] destination appeared concurrently: $dest; retained $staging" >&2
        fail=$((fail+1))
    else
        # A failed partial clone may remain here; retain it for diagnostics.
        rmdir "$staging" 2>/dev/null || true
    fi
done 3<<< "$ROWS"

echo
echo "Fetched into $CORPUS ($n projects, $fail failures)"
exit $(( fail > 0 ? 1 : 0 ))
