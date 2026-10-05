#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build a traceable local release candidate from an exact, clean commit.
set -euo pipefail
cd "$(dirname "$0")/.."
usage() {
  echo 'usage: build-container-release.sh [IMAGE] [--languages LIST | --flavor runtime|core|ada] [--engines default|builtin]'
  echo 'Default: all sixteen supported languages (runtime).'
}
source scripts/language-selection.sh
image=''
languages=all
language_seen=0
flavor_seen=0
engines_seen=0
engines=default
flavor=runtime
target=()
while (($#)); do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --flavor)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      [[ "$flavor_seen" == 0 ]] || { echo 'duplicate --flavor' >&2; exit 2; }
      flavor_seen=1; flavor="$2"; target=(--target "$flavor"); shift 2 ;;
    --languages)
      [[ $# -ge 2 && "$language_seen" == 0 ]] || { usage >&2; exit 2; }
      language_seen=1; languages="$2"; shift 2 ;;
    --engines)
      [[ $# -ge 2 && "$engines_seen" == 0 ]] || { usage >&2; exit 2; }
      engines_seen=1
      engines="$2"; shift 2 ;;
    --*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    *)
      if [[ -z "$image" ]]; then image="$1"
      elif [[ ${#target[@]} -eq 0 ]]; then
        # Compatibility with the original IMAGE FLAVOR invocation.
        flavor_seen=1; flavor="$1"; target=(--target "$flavor")
      else usage >&2; exit 2
      fi
      shift ;;
  esac
done
case "$flavor" in core|runtime|ada) ;; *) echo "unsupported image flavor: $flavor" >&2; exit 2 ;; esac
[[ "$language_seen" == 0 || "$flavor_seen" == 0 ]] || { echo '--languages and --flavor are mutually exclusive' >&2; exit 2; }
case "$engines" in default|builtin) ;; *) echo 'unsupported engines; use default or builtin' >&2; exit 2 ;; esac
# Legacy Docker targets keep their historical component sets. Use --languages
# for the unified arbitrary-subset path, including explicit engine selection.
[[ "$flavor" == runtime || "$engines" == default ]] || { echo '--engines requires --languages or runtime flavor' >&2; exit 2; }
case "$flavor" in
  core) languages=c,cpp; engines=builtin ;;
  ada) languages=c,cpp,ada; engines=builtin ;;
esac
languages="$(bhf_resolve_languages "$languages")"
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
  --build-arg "BHF_LANGUAGES=$languages" \
  --build-arg "BHF_ENGINES=$engines" \
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
languages=$languages
engines=$engines
build_elapsed_seconds=$elapsed
MANIFEST
