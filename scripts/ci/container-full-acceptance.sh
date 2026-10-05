#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Exercise the default full-language image, including Java on a read-only root.
set -euo pipefail
cd "$(dirname "$0")/../.."
evidence="${BHF_FULL_CONTAINER_EVIDENCE:-container-full-acceptance}"
if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
  echo 'full container acceptance requires a clean tracked source revision' >&2
  exit 2
fi
if [[ -d "$evidence" && -n "$(find "$evidence" -mindepth 1 -print -quit)" ]]; then
  echo "evidence directory must be empty; preserve previous results and select a new path: $evidence" >&2
  exit 2
fi
mkdir -p "$evidence"
commit="$(git rev-parse --verify HEAD)"
version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)"
source_sha="$(git archive --format=tar HEAD | sha256sum | cut -d' ' -f1)"
build_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
image="bhf:ci-full-${commit:0:12}"
volume="bhf-ci-java-${commit:0:12}-$$"
docker volume create "$volume" > /dev/null
trap 'docker volume rm -f "$volume" >/dev/null 2>&1 || true' EXIT

bash scripts/build-container-release.sh "$image" > "$evidence/build.log" 2>&1 || { tail -100 "$evidence/build.log"; exit 1; }

docker image inspect "$image" > "$evidence/image-inspect.json"
image_id="$(docker image inspect --format '{{.Id}}' "$image")"
image_size="$(docker image inspect --format '{{.Size}}' "$image")"
# Observed local full target on 2026-10-04: 3,558,046,779 bytes.
(( image_size <= 4500000000 )) || { echo "full image exceeds 4.5 GB: $image_size" >&2; exit 1; }
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
  --cap-drop ALL --security-opt no-new-privileges:true --volume "$volume:/work"
  --volume "$PWD/docker/fixtures/java-bare:/src:ro")
"${run[@]}" "$image_id" sh -c 'test "$(id -u)" = 10001 && test -r "$BHF_JVM_AGENT_JAR"' \
  > "$evidence/nonroot-java-agent.log" 2>&1
"${run[@]}" "$image_id" --version > "$evidence/version.log" 2>&1
grep -q "$version" "$evidence/version.log"
grep -Fq "$commit" "$evidence/version.log"
if "${run[@]}" "$image_id" llm --help > "$evidence/no-llm.log" 2>&1; then
  echo 'full-language artifact exposed the llm command' >&2
  exit 1
fi
grep -q "unrecognized subcommand 'llm'" "$evidence/no-llm.log"
"${run[@]}" "$image_id" auto /src --work-dir /work/java-run \
  --max-targets 1 --per-target-time 10 --iterations 32 --jobs 1 \
  > "$evidence/java-auto.log" 2>&1
"${run[@]}" "$image_id" /usr/bin/python3 -c 'import json; x=json.load(open("/work/java-run/auto/run.json")); assert not x["partial"] and x["summary"]["built_and_fuzzed"] == 1' \
  > "$evidence/result.log" 2>&1
"${run[@]}" "$image_id" sh -c 'dpkg-query -W | wc -l' \
  > "$evidence/os-package-count.txt" 2>&1
bash scripts/ci/java-offline-acceptance.sh "$image_id" "$evidence"
docker run --rm --network none --read-only --tmpfs /tmp:rw,exec,nosuid,size=1g \
  --memory 4g --pids-limit 512 --cap-drop ALL --security-opt no-new-privileges:true \
  --volume "$PWD/docker/language-smoke.sh:/language-smoke.sh:ro" \
  "$image_id" bash /language-smoke.sh > "$evidence/language-smoke.log" 2>&1

# Reconcile the filesystem and compiled Cargo inventory; retain the DB-bound scan.
bash scripts/ci/container-runtime-acceptance.sh "$image_id" "$evidence"
bash scripts/ci/inventory-image.sh "$image_id" "$evidence"
python3 scripts/ci/review-image-scan.py "$evidence"
python3 scripts/ci/container-evidence.py record "$evidence"
