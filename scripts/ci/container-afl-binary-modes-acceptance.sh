#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# AFL++'s QEMU and Frida modes in the image report coverage on an
# uninstrumented binary: `bhf binary fuzz --engine afl-qemu` and `afl-fuzz -O`
# each reach its edges, and QEMU mode finds its abort.
set -euo pipefail
image="${1:?usage: container-afl-binary-modes-acceptance.sh IMAGE EVIDENCE_DIR}"
evidence="${2:?usage: container-afl-binary-modes-acceptance.sh IMAGE EVIDENCE_DIR}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p "$evidence"
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,exec,nosuid,size=1g \
  --tmpfs /work:rw,exec,nosuid,uid=10001,gid=10001,size=1g \
  --shm-size 2g --memory 4g --pids-limit 512 \
  --cap-drop ALL --security-opt no-new-privileges:true \
  -e AFL_NO_UI=1 -e AFL_NO_AFFINITY=1 \
  --volume "$root/docker/fixtures/binary-only:/src:ro" "$image" bash -eu -c '
  test -x /usr/bin/afl-qemu-trace && test -f /usr/lib/afl/afl-frida-trace.so
  cc -O1 -o /work/gate /src/gate.c
  printf FX > /work/seed
  echo "== afl-showmap"
  for mode in -Q -O; do
    afl-showmap "$mode" -q -o "/work/map$mode" -- /work/gate < /work/seed || true
    tuples=$(wc -l < "/work/map$mode")
    echo "afl-showmap $mode: $tuples tuples"
    test "$tuples" -gt 0
  done
  echo "== QEMU mode: bhf binary fuzz --engine afl-qemu"
  bhf binary fuzz /work/gate --engine afl-qemu --seed-input AAAA --time 30 \
    --work-dir /work/qemu > /work/qemu.json
  echo "== Frida mode: afl-fuzz -O"
  mkdir -p /work/frida-in && cp /work/seed /work/frida-in/seed
  # afl-fuzz refuses the image'\''s ASAN_OPTIONS without symbolize=0.
  ASAN_OPTIONS="$ASAN_OPTIONS:symbolize=0" UBSAN_OPTIONS="$UBSAN_OPTIONS:symbolize=0" \
    afl-fuzz -O -i /work/frida-in -o /work/frida -V 20 -- /work/gate > /work/frida.log 2>&1 \
    || { tail -30 /work/frida.log; exit 1; }
  python3 - <<'\''PY'\''
import json, pathlib
def stats(path):
    rows = (line.split(":", 1) for line in pathlib.Path(path).read_text().splitlines())
    return {key.strip(): value.strip() for key, value in rows}
run = json.loads(pathlib.Path("/work/qemu.json").read_text())
assert run["engine"] == "afl-qemu", run
qemu = stats("/work/qemu/afl_qemu_out/out/default/fuzzer_stats")
frida = stats("/work/frida/default/fuzzer_stats")
print("QEMU mode:", qemu["edges_found"], "edges,", qemu["execs_done"], "executions, findings", run["findings"])
print("Frida mode:", frida["edges_found"], "edges,", frida["execs_done"], "executions,", frida["saved_crashes"], "crashes")
assert int(qemu["edges_found"]) > 0 and run["findings"], "QEMU mode found the abort with coverage"
assert int(frida["edges_found"]) > 0 and int(frida["execs_done"]) > 0, "Frida mode reports coverage"
PY
  echo "AFL++ QEMU and Frida modes passed"
' > "$evidence/afl-binary-modes.log" 2>&1 || { tail -60 "$evidence/afl-binary-modes.log"; exit 1; }
