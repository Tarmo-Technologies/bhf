#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/../.."
evidence="${BHF_ADA_CONTAINER_EVIDENCE:-container-ada-acceptance}"
mkdir -p "$evidence"
image="bhf:ci-ada-$(git rev-parse --short=12 HEAD)"
bash scripts/build-container-release.sh "$image" ada > "$evidence/build.log" 2>&1 || { tail -100 "$evidence/build.log"; exit 1; }
image="$(docker image inspect --format '{{.Id}}' "$image")"
docker image inspect "$image" > "$evidence/image-inspect.json"
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
bash scripts/ci/inventory-image.sh "$image" "$evidence"
