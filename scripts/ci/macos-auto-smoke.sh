#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The macOS job's end-to-end check: `bhf auto` builds a C target natively with
# the host's clang and finds the stack overflow planted in it. No runtrace shim
# is built for macOS (it is an LD_PRELOAD library), so the run must say so: the
# fuzzed target, the campaign rollup and the finding record the shim-unavailable
# fidelity, and the finding's fuzz pass ran without the shim.
set -euo pipefail
bhf=${1:?usage: macos-auto-smoke.sh <path to bhf>}
for shim in libbhf_runtrace.so libbhf_runtrace_shim.so; do
  if [[ -e "$(dirname "$bhf")/$shim" ]]; then
    echo "macos auto smoke: $shim is beside $bhf, but no shim is built for macOS" >&2
    exit 1
  fi
done
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/src"
cat > "$tmp/src/record.c" <<'C'
#include <stddef.h>
#include <string.h>

/* A record's name is copied into a fixed buffer without a length check. */
int parse_record(const unsigned char *data, size_t len) {
    char name[8];
    if (len > 2 && data[0] == 'R') {
        memcpy(name, data + 1, len - 1);
        return name[0];
    }
    return 0;
}
C
printf 'RAAAAAAAAAAAAAAAAAAAAAAAA' > "$tmp/seed.bin"
"$bhf" auto "$tmp/src" --work-dir "$tmp/work" --languages c --per-target-time 20 \
  --jobs 1 --seed-file "$tmp/seed.bin" --no-discovery-cache
python3 - "$tmp/work" <<'PY'
import json
import pathlib
import sys

work = pathlib.Path(sys.argv[1])
run = json.loads((work / "auto/run.json").read_text())
summary = run["summary"]
assert summary["built_and_fuzzed"] == 1, summary
findings = json.loads((work / "results/findings.json").read_text())["findings"]
planted = {"BHF-201", "BHF-203"}
rules = sorted({(finding.get("rule") or {}).get("id") for finding in findings} - {None})
assert planted & set(rules), rules


def shim_unavailable(fidelity, where):
    shim = (fidelity or {}).get("runtime_shim") or {}
    assert shim.get("status") == "not_exercised", f"{where}: {fidelity}"
    assert "built for Linux only" in (shim.get("reason") or ""), f"{where}: {shim}"


fuzzed = [target for target in run["targets"] if target.get("fidelity")]
assert len(fuzzed) == 1, run["targets"]
shim_unavailable(fuzzed[0]["fidelity"], "run.json target")
shim_unavailable((summary.get("fidelity") or {}).get("dimensions"), "run.json summary")
records = [json.loads(path.read_text()) for path in (work / "results/findings").glob("*/finding.json")]
crashes = [record for record in records if record.get("rule_id") in planted]
assert crashes, [record.get("rule_id") for record in records]
for record in crashes:
    shim_unavailable(record.get("fidelity"), record.get("id"))
    assert (record.get("runtime_mode") or {}).get("shim_armed") is False, record.get("runtime_mode")
print("macos auto smoke: the planted overflow was found without the runtrace shim:", ", ".join(rules))
PY
