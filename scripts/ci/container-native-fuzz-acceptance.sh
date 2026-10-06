#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Exercise an owned, bounded C target under ASan/UBSan and replay a clean input.
set -euo pipefail
image="${1:?usage: container-native-fuzz-acceptance.sh IMAGE EVIDENCE_DIR}"
evidence="${2:?usage: container-native-fuzz-acceptance.sh IMAGE EVIDENCE_DIR}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
image="$(docker image inspect --format '{{.Id}}' "$image")"
architecture="$(docker image inspect --format '{{.Architecture}}' "$image")"
host_architecture="$(docker version --format '{{.Server.Arch}}')"
[[ "$architecture" == "$host_architecture" ]] || { echo 'sanitizer acceptance requires a native Docker host' >&2; exit 2; }
mkdir -p "$evidence"
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,exec,nosuid,size=1g \
  --tmpfs /work:rw,exec,nosuid,uid=10001,gid=10001,size=1g \
  --shm-size 2g --memory 4g --pids-limit 512 \
  --cap-drop ALL --cap-add SYS_PTRACE --security-opt no-new-privileges:true \
  --volume "$root/docker/fixtures/c-core:/src:ro" \
  --volume "$root/scripts/ci/container-shim-smoke.sh:/shim-smoke.sh:ro" "$image" bash -eu -c '
  bash /shim-smoke.sh
  bhf auto /src --work-dir /work/run --languages c --target packet_checksum \
    --iterations 32 --single-pass --sanitizers asan,ubsan --per-target-time 5 --jobs 1
  python3 - <<'\''PY'\''
import json, pathlib, subprocess
root = pathlib.Path("/work/run")
run = json.loads((root / "auto/run.json").read_text())
assert not run["partial"] and run["summary"]["built_and_fuzzed"] == 1, run["summary"]
targets = [t for t in run["targets"] if t["outcome"]["outcome"] == "built_and_fuzzed"]
assert len(targets) == 1 and not targets[0].get("platform_stub")
assert any(p["executions"] > 0 and p["target_entry_observed"] and p["coverage_edges"] > 0
           for p in targets[0]["outcome"]["passes"]), "no measured target entry and coverage"
findings = json.loads((root / "results/findings.json").read_text())
assert not findings["findings"], "bounded clean fixture produced findings"
# BHF native drivers accept a testcase filename for isolated replay.
# Only use BHF-generated executables in this owned fixture work directory.
binaries = [p for p in root.rglob("*") if p.is_file() and p.stat().st_mode & 0o111
            and p.read_bytes()[:4] == b"\x7fELF"]
binaries = [p for p in binaries if b"__asan_init" in p.read_bytes()
            and b"__ubsan_handle" in p.read_bytes()]
assert binaries, "no retained ASan/UBSan harness executable"
seed = pathlib.Path("/work/clean-input.bin")
seed.write_bytes(bytes(range(32)))
for binary in binaries:
    subprocess.run([str(binary), str(seed)], check=True, timeout=15)
print("Native sanitized fuzzing and clean harness replay passed")
PY
' > "$evidence/native-fuzz-replay.log" 2>&1
