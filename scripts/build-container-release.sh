#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build a traceable local release candidate from an exact, clean commit.
set -euo pipefail
cd "$(dirname "$0")/.."
usage() {
  echo 'usage: build-container-release.sh [IMAGE] [--flavor runtime|core|ada]'
  echo 'Default: all sixteen supported languages (runtime).'
}
image=''
flavor=runtime
target=()
while (($#)); do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --flavor)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      flavor="$2"; target=(--target "$flavor"); shift 2 ;;
    --*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    *)
      if [[ -z "$image" ]]; then image="$1"
      elif [[ ${#target[@]} -eq 0 ]]; then
        # Compatibility with the original IMAGE FLAVOR invocation.
        flavor="$1"; target=(--target "$flavor")
      else usage >&2; exit 2
      fi
      shift ;;
  esac
done
case "$flavor" in core|runtime|ada) ;; *) echo "unsupported image flavor: $flavor" >&2; exit 2 ;; esac
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
image="${image:-bhf:${version}}"
started=$SECONDS
git archive --format=tar HEAD | docker build --platform linux/amd64 "${target[@]}" -f Dockerfile -t "$image" \
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
