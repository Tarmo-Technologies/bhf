#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The full image's MSan libc++ (BHF_MSAN_LIBCXX) gives C++ an MSan replay: a
# planted uninitialized read is a finding that replays.
set -euo pipefail
image="${1:?usage: container-msan-cpp-acceptance.sh IMAGE EVIDENCE_DIR}"
evidence="${2:?usage: container-msan-cpp-acceptance.sh IMAGE EVIDENCE_DIR}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p "$evidence"
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,exec,nosuid,size=1g \
  --tmpfs /work:rw,exec,nosuid,uid=10001,gid=10001,size=1g \
  --shm-size 2g --memory 4g --pids-limit 512 \
  --cap-drop ALL --cap-add SYS_PTRACE --security-opt no-new-privileges:true \
  --volume "$root/docker/fixtures/cpp-msan:/src:ro" "$image" bash -eu -c '
  test -f "$BHF_MSAN_LIBCXX/lib/libc++.so.1"
  bhf auto /src --work-dir /work/run --languages cpp --per-target-time 5 --jobs 1
  finding=/work/run/results/findings/F-MSAN-0000
  python3 - "$finding" <<'\''PY'\''
import json, pathlib, sys
finding = pathlib.Path(sys.argv[1])
raw = json.loads((finding / "finding.json").read_text())
assert raw["exception"]["sanitizer"] == "msan", raw["exception"]
assert "parse_record" in raw["exception"]["stack"][0]["function"], raw["exception"]["stack"][:2]
assert "use-of-uninitialized-value" in (finding / "sanitizer.log").read_text()
PY
  bhf replay --finding "$finding" | tee /tmp/replay.txt
  grep -q "^MATCH" /tmp/replay.txt
  echo "C++ MemorySanitizer replay passed"
' > "$evidence/msan-cpp.log" 2>&1 || { tail -60 "$evidence/msan-cpp.log"; exit 1; }
