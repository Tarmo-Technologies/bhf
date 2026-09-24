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
set -uo pipefail

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

apt-get update
mkdir -p "$DEST"; cd "$DEST" || exit 1

fail=0 n=0
while IFS= read -r spec; do
    case "$spec" in ''|'#'*) continue;; esac
    n=$((n + 1))
    echo "== corresponding source: $spec =="
    # Try the exact pinned version, then fall back to the package's current source
    # (an older version may have been superseded out of the archive pockets).
    if ! apt-get source --download-only "$spec" 2>/dev/null; then
        base="${spec%%=*}"
        echo "   exact version unavailable; fetching current source for $base"
        apt-get source --download-only "$base" || { echo "   WARN: no source for $base"; fail=$((fail + 1)); }
    fi
done < "$MANIFEST"

echo
echo "fetched corresponding source for $((n - fail))/$n package(s) into $DEST"
[ "$fail" -gt 0 ] && echo "note: $fail package(s) need manual retrieval (e.g. launchpad.net) if aged out of the archive"
exit 0
