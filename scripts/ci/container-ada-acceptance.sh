#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/../.."
evidence="${BHF_ADA_CONTAINER_EVIDENCE:-container-ada-acceptance}"
if [[ -d "$evidence" && -n "$(find "$evidence" -mindepth 1 -print -quit)" ]]; then
  echo "evidence directory must be empty; preserve previous results and select a new path: $evidence" >&2
  exit 2
fi
mkdir -p "$evidence"
image="bhf:ci-ada-$(git rev-parse --short=12 HEAD)"
bash scripts/build-container-release.sh "$image" ada > "$evidence/build.log" 2>&1 || { tail -100 "$evidence/build.log"; exit 1; }
image="$(docker image inspect --format '{{.Id}}' "$image")"
docker image inspect "$image" > "$evidence/image-inspect.json"
image_size="$(docker image inspect --format '{{.Size}}' "$image")"
# Observed on 2026-10-04: 1,103,129,733 bytes. Allow reviewed updates.
(( image_size <= 1500000000 )) || { echo "Ada image exceeds 1.5 GB: $image_size" >&2; exit 1; }
compressed_size="$(docker save "$image" | gzip -1 | wc -c | tr -d ' ')"
cat > "$evidence/identity.txt" <<IDENTITY
source_commit=$(git rev-parse HEAD)
local_image_id=$image
unpacked_size_bytes=$image_size
gzip_docker_archive_bytes=$compressed_size
IDENTITY
docker run --rm --network none --read-only --tmpfs /tmp:rw,exec,nosuid,size=256m \
  --memory 4g --pids-limit 512 --cap-drop ALL --security-opt no-new-privileges:true \
  "$image" sh -eu -c '
    test "$(id -u)" = 10001
    cd /tmp
    printf "%s\n" "with Ada.Text_IO; procedure Smoke is begin Ada.Text_IO.Put_Line (\"Ada ready\"); end Smoke;" > smoke.adb
    gnatmake -q smoke.adb
    ./smoke
    gprbuild --version
  ' > "$evidence/compiler-smoke.log" 2>&1
grep -q 'Ada ready' "$evidence/compiler-smoke.log"
docker run --rm --network none "$image" sh -c 'dpkg-query -W | wc -l' > "$evidence/os-package-count.txt"
bash scripts/ci/container-runtime-acceptance.sh "$image" "$evidence"
bash scripts/ci/inventory-image.sh "$image" "$evidence"
python3 scripts/ci/review-image-scan.py "$evidence"
python3 scripts/ci/container-evidence.py record "$evidence"
