#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# AFL++'s QEMU and Frida modes in the image report coverage on an
# uninstrumented binary: `bhf binary fuzz --engine afl-qemu` and
# `--engine afl-frida` each reach its edges and find its abort.
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
  echo "== Frida mode: bhf binary fuzz --engine afl-frida"
  bhf binary fuzz /work/gate --engine afl-frida --seed-input AAAA --time 30 \
    --work-dir /work/frida > /work/frida.json
  python3 - <<'\''PY'\''
import json, pathlib
def stats(path):
    rows = (line.split(":", 1) for line in pathlib.Path(path).read_text().splitlines())
    return {key.strip(): value.strip() for key, value in rows}
for engine, name in (("afl-qemu", "qemu"), ("afl-frida", "frida")):
    run = json.loads(pathlib.Path(f"/work/{name}.json").read_text())
    stats_file = stats(f"/work/{name}/afl_{name}_out/out/default/fuzzer_stats")
    print(engine, stats_file["edges_found"], "edges,", stats_file["execs_done"], "executions, findings", run["findings"])
    assert run["engine"] == engine and run["fidelity"]["edges_found"] > 0, run
    assert int(stats_file["edges_found"]) > 0 and run["findings"], f"{engine} found the abort with coverage"
PY
  echo "AFL++ QEMU and Frida modes passed"
' > "$evidence/afl-binary-modes.log" 2>&1 || { tail -60 "$evidence/afl-binary-modes.log"; exit 1; }
