#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Fulfil the corresponding-source offer for the GPL/LGPL packages this image
# ships (WRITTEN-OFFER.md). Reads COPYLEFT-SOURCES.txt (baked into the image at
# /usr/share/bhf/licenses/) and downloads the matching Ubuntu source packages.
#
# Run it on an Ubuntu 24.04 host/container WITH network and apt (it is a
# distributor/recipient tool, not something the image runs itself). As root:
#   docker/compliance/fetch-sources.sh [COPYLEFT-SOURCES.txt] [DEST_DIR]
#
# The packages are UNMODIFIED Ubuntu 24.04 packages, so their corresponding
# source is the source Ubuntu/Canonical publishes for those exact versions.
set -euo pipefail

MANIFEST="${1:-/usr/share/bhf/licenses/COPYLEFT-SOURCES.txt}"
DEST="${2:-$PWD/corresponding-source}"

[ -f "$MANIFEST" ] || { echo "manifest not found: $MANIFEST" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root (needs apt + /etc/apt write)" >&2; exit 2; }
command -v apt-get >/dev/null || { echo "apt-get required (run on Ubuntu 24.04)" >&2; exit 2; }

# shellcheck disable=SC1091
. /etc/os-release
codename="${VERSION_CODENAME:-noble}"

# Enable deb-src for the suites this image was built from (24.04 uses deb822).
cat > /etc/apt/sources.list.d/bhf-compliance-src.sources <<EOF
Types: deb-src
URIs: http://archive.ubuntu.com/ubuntu
Suites: ${codename} ${codename}-updates ${codename}-backports ${codename}-security
Components: main universe multiverse restricted
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF

apt-get update -o APT::Update::Error-Mode=any
mkdir -p "$DEST"; cd "$DEST" || exit 1
cp "$MANIFEST" REQUESTED-SOURCES.txt

fail=0 n=0
while IFS= read -r spec; do
    case "$spec" in ''|'#'*) continue;; esac
    n=$((n + 1))
    echo "== corresponding source: $spec =="
    # Only the installed package's exact source version is corresponding-source
    # evidence. A newer version cannot silently satisfy this request.
    if ! apt-get source --download-only "$spec" 2>/dev/null; then
        echo "   ERROR: exact source unavailable: $spec" >&2
        fail=$((fail + 1))
    fi
done < "$MANIFEST"

# Components built from upstream source rather than installed from a package
# (AFL++'s QEMU mode, from qemuafl): "<name> <url> sha256:<digest>" names an
# archive and its digest, "<name> <url> git:<commit>" a commit of a repository.
UPSTREAM="${UPSTREAM_SOURCES:-$(dirname "$MANIFEST")/afl/UPSTREAM-SOURCES.txt}"
if [ -f "$UPSTREAM" ]; then
    cp "$UPSTREAM" REQUESTED-UPSTREAM-SOURCES.txt
    while read -r name url pin; do
        case "$name" in ''|'#'*) continue;; esac
        n=$((n + 1))
        echo "== upstream source: $name $pin =="
        case "$pin" in
            sha256:*)
                file="$name-$(basename "$url")"
                if ! curl --proto '=https' -fsSL --retry 5 -o "$file" "$url" \
                    || ! echo "${pin#sha256:}  $file" | sha256sum -c - >/dev/null; then
                    echo "   ERROR: exact source unavailable: $name $url" >&2
                    rm -f "$file"
                    fail=$((fail + 1))
                fi
                ;;
            git:*)
                commit="${pin#git:}"
                repo=$(mktemp -d)
                # With its submodules, which the build compiled in too.
                if git -C "$repo" init -q \
                    && git -C "$repo" fetch -q --depth 1 "$url" "$commit" \
                    && git -C "$repo" checkout -q FETCH_HEAD \
                    && [ "$(git -C "$repo" rev-parse HEAD)" = "$commit" ] \
                    && git -C "$repo" submodule -q update --init --depth 1; then
                    tar -C "$repo" --exclude=.git --transform "s|^\\.|$name-$commit|" \
                        -czf "$PWD/$name-$commit.tar.gz" .
                else
                    echo "   ERROR: exact source unavailable: $name $url $commit" >&2
                    fail=$((fail + 1))
                fi
                rm -rf "$repo"
                ;;
            *) echo "   ERROR: unknown pin $pin for $name" >&2; fail=$((fail + 1)) ;;
        esac
    done < "$UPSTREAM"
fi

echo
echo "fetched corresponding source for $((n - fail))/$n package(s) into $DEST"
if [ "$fail" -gt 0 ]; then
    echo "incomplete source archive: $fail package(s) require exact-version retrieval" >&2
    exit 1
fi
if [ "$n" -eq 0 ]; then
    echo "empty source manifest" >&2
    exit 1
fi
find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
    | sort -z | xargs -0 sha256sum > SHA256SUMS
exit 0
