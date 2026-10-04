#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build a traceable local release candidate from an exact, clean commit.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -n "$(git status --porcelain)" ]]; then
  echo 'release build requires a clean source checkout' >&2
  exit 2
fi
commit="$(git rev-parse --verify HEAD)"
version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)"
if [[ -z "$version" || ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
  echo 'could not derive release version and source commit' >&2
  exit 2
fi
source_sha="$(git archive --format=tar HEAD | sha256sum | cut -d' ' -f1)"
build_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
image="${1:-bhf:${version}}"
flavor="${2:-core}"
case "$flavor" in core|runtime|ada) ;; *) echo "unsupported image flavor: $flavor" >&2; exit 2 ;; esac
started=$SECONDS
git archive --format=tar HEAD | docker build --platform linux/amd64 --target "$flavor" -f Dockerfile -t "$image" \
  --build-arg "BHF_VERSION=$version" \
  --build-arg "VCS_REF=$commit" \
  --build-arg "BUILD_DATE=$build_date" \
  --build-arg "BHF_SOURCE_SHA256=$source_sha" -
image_id="$(docker image inspect --format '{{.Id}}' "$image")"
elapsed=$((SECONDS - started))
cat <<MANIFEST
image=$image
local_image_id=$image_id
source_commit=$commit
source_archive_sha256=$source_sha
version=$version
platform=linux/amd64
build_date=$build_date
features=default-no-llm
flavor=$flavor
build_elapsed_seconds=$elapsed
MANIFEST
