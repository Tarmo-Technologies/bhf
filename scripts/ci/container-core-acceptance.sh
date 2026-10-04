#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build and test the exact default Dockerfile stage, retaining the image identity.
set -euo pipefail
cd "$(dirname "$0")/../.."
evidence="${BHF_CONTAINER_EVIDENCE:-container-acceptance}"
if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
  echo 'container acceptance requires a clean tracked source revision' >&2
  exit 2
fi
mkdir -p "$evidence"
commit="$(git rev-parse --verify HEAD)"
version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)"
source_sha="$(git archive --format=tar HEAD | sha256sum | cut -d' ' -f1)"
build_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
image="bhf:ci-core-${commit:0:12}"
volume="bhf-ci-work-${commit:0:12}-$$"
docker volume create "$volume" > /dev/null
trap 'docker volume rm -f "$volume" >/dev/null 2>&1 || true' EXIT

bash scripts/build-container-release.sh "$image" core > "$evidence/build.log" 2>&1 || { tail -100 "$evidence/build.log"; exit 1; }


docker image inspect "$image" > "$evidence/image-inspect.json"
image_id="$(docker image inspect --format '{{.Id}}' "$image")"
image_size="$(docker image inspect --format '{{.Size}}' "$image")"
# Observed local core build on 2026-10-04: 845,186,284 unpacked bytes.
# Leave room for reviewed security-package updates while preventing a full
# language layer from becoming the default image again.
(( image_size <= 1200000000 )) || { echo "core image exceeds 1.2 GB: $image_size" >&2; exit 1; }
compressed_size="$(docker save "$image" | gzip -1 | wc -c | tr -d ' ')"
label_version="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$image")"
label_commit="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image")"
[[ "$label_version" == "$version" && "$label_commit" == "$commit" ]]
cat > "$evidence/identity.txt" <<IDENTITY
source_commit=$commit
source_archive_sha256=$source_sha
version=$version
platform=linux/amd64
local_image_id=$image_id
unpacked_size_bytes=$image_size
gzip_docker_archive_bytes=$compressed_size
IDENTITY

run=(docker run --rm --platform linux/amd64 --network none --read-only
  --tmpfs /tmp:rw,exec,nosuid,size=1g --shm-size 2g --memory 4g --pids-limit 512
  --cap-drop ALL --cap-add SYS_PTRACE --security-opt no-new-privileges:true
  --volume "$volume:/work" --volume "$PWD/docker/fixtures/c-core:/src:ro")
"${run[@]}" "$image_id" sh -c 'test "$(id -u)" = 10001' > "$evidence/nonroot.log" 2>&1
"${run[@]}" "$image_id" --version > "$evidence/version.log" 2>&1
rg -q "$version" "$evidence/version.log" || grep -q "$version" "$evidence/version.log"
grep -Fq "$commit" "$evidence/version.log"
if "${run[@]}" "$image_id" llm --help > "$evidence/no-llm.log" 2>&1; then
  echo 'default artifact exposed the llm command' >&2
  exit 1
fi
grep -q "unrecognized subcommand 'llm'" "$evidence/no-llm.log"
"${run[@]}" "$image_id" bhf-daemon --help > "$evidence/daemon-help.log" 2>&1
grep -q 'Usage: bhf-daemon' "$evidence/daemon-help.log"
"${run[@]}" "$image_id" bhf-daemon --version > "$evidence/daemon-version.log" 2>&1
grep -q "$version" "$evidence/daemon-version.log"
grep -Fq "$commit" "$evidence/daemon-version.log"
"${run[@]}" "$image_id" auto /src --work-dir /work/run --languages c \
  --target packet_checksum --iterations 32 --single-pass --sanitizers none \
  --per-target-time 5 --no-discovery-cache > "$evidence/auto.log" 2>&1
"${run[@]}" "$image_id" /usr/bin/python3 -c 'import json; x=json.load(open("/work/run/auto/run.json")); assert not x["partial"] and x["summary"]["built_and_fuzzed"] == 1' \
  > "$evidence/result.log" 2>&1
"${run[@]}" "$image_id" sh -c 'dpkg-query -W | wc -l' > "$evidence/os-package-count.txt" 2>&1

# Reconcile the filesystem and compiled Cargo inventory; retain the DB-bound scan.
bash scripts/ci/container-runtime-acceptance.sh "$image_id" "$evidence"
bash scripts/ci/inventory-image.sh "$image_id" "$evidence"
