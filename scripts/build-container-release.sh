#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build a traceable local release candidate from an exact, clean commit.
set -euo pipefail
cd "$(dirname "$0")/.."
usage() {
  echo 'usage: build-container-release.sh [IMAGE] [--languages LIST | --flavor runtime|core|ada] [--engines default|builtin] [--platform linux/amd64|linux/arm64|linux/amd64,linux/arm64] [--output FILE]'
  echo 'Default: all sixteen languages on the Docker daemon architecture.'
  echo 'Multiple platforms require --output FILE (local OCI archive); nothing is pushed.'
}
source scripts/language-selection.sh
image=''
languages=all
language_seen=0
flavor_seen=0
engines_seen=0
engines=default
flavor=runtime
platform=
output=
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
    --platform)
      [[ $# -ge 2 && -z "$platform" ]] || { usage >&2; exit 2; }
      platform="$2"; shift 2 ;;
    --output)
      [[ $# -ge 2 && -z "$output" ]] || { usage >&2; exit 2; }
      output="$2"; shift 2 ;;
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
if [[ -z "$platform" ]]; then
  platform="linux/$(docker version --format '{{.Server.Arch}}')"
fi
case "$platform" in
  linux/amd64|linux/arm64|linux/amd64,linux/arm64|linux/arm64,linux/amd64) ;;
  *) echo 'unsupported platform; use linux/amd64 and/or linux/arm64' >&2; exit 2 ;;
esac
if [[ "$platform" == *,* && -z "$output" ]]; then
  echo 'multiple platforms require --output FILE for a local OCI archive' >&2; exit 2
fi
if [[ -n "$output" ]]; then
  [[ ! -e "$output" && ! -L "$output" && "$output" != *,* ]] || { echo 'output must be a new path without commas' >&2; exit 2; }
  output="$(realpath -m -- "$output")"
  [[ -d "$(dirname "$output")" ]] || { echo 'output parent directory does not exist' >&2; exit 2; }
fi
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
build=(docker build --platform "$platform")
if [[ -n "$output" ]]; then
  build=(docker buildx build --platform "$platform" --output "type=oci,dest=$output")
fi
git archive --format=tar HEAD | "${build[@]}" "${target[@]}" -f Dockerfile -t "$image" \
  --build-arg "BHF_LANGUAGES=$languages" \
  --build-arg "BHF_ENGINES=$engines" \
  --build-arg "BHF_VERSION=$version" \
  --build-arg "VCS_REF=$commit" \
  --build-arg "BUILD_DATE=$build_date" \
  --build-arg "BHF_SOURCE_SHA256=$source_sha" -
image_id=
archive_sha=
if [[ -n "$output" ]]; then
  archive_sha="$(sha256sum "$output" | cut -d' ' -f1)"
else
  image_id="$(docker image inspect --format '{{.Id}}' "$image")"
  observed_platform="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image")"
  [[ "$observed_platform" == "$platform" ]] || { echo 'built image platform mismatch' >&2; exit 1; }
fi
elapsed=$((SECONDS - started))
cat <<MANIFEST
image=$image
local_image_id=$image_id
source_commit=$commit
source_archive_sha256=$source_sha
version=$version
platform=$platform
build_date=$build_date
features=default-no-llm
flavor=$flavor
languages=$languages
engines=$engines
build_elapsed_seconds=$elapsed
MANIFEST
if [[ -n "$output" ]]; then
  printf 'oci_archive=%s\noci_archive_sha256=%s\n' "$output" "$archive_sha"
fi
