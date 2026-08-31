#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Ada: bhf only. No off-the-shelf fuzzer targets Ada (AFL++/libFuzzer/Jazzer/
# cargo-fuzz do not), so bhf IS the comparison. Planted magic-gated
# CONSTRAINT_ERROR (index out of range). Needs GNAT/gprbuild.
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
BHF="$ROOT/../target/debug/bhf"
BUDGET="${BUDGET:-20}"
SCRATCH="$(mktemp -d)"
RES="$ROOT/results/ada.tsv"
echo -e "tool\tharness_loc\tcrash\tttfc_s\texecs" > "$RES"
now() { date +%s.%N; }
elapsed() { echo "$(now) - $1" | bc -l; }

if ! command -v gnatmake >/dev/null 2>&1; then
  echo "SKIP: gnatmake not on PATH"; echo -e "bhf\t0\tSKIP_NO_GNAT\t-\t-" >> "$RES"; exit 0
fi
cp -r "$ROOT/targets/ada" "$SCRATCH/bhf"
s=$(now)
"$BHF" auto --per-target-time "$BUDGET" --work-dir "$SCRATCH/bhf/gw" "$SCRATCH/bhf" >"$SCRATCH/bhf.log" 2>&1 &
pid=$!; ttfc="-"; crash=0
while kill -0 "$pid" 2>/dev/null; do
  if [ "$crash" = 0 ] && compgen -G "$SCRATCH/bhf/gw/findings/*" >/dev/null 2>&1; then ttfc=$(elapsed "$s"); crash=1; fi
  sleep 0.2
done
wait "$pid" 2>/dev/null
execs=$(python3 - "$SCRATCH/bhf/gw/auto/run.json" <<'PY' 2>/dev/null
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: print(0); raise SystemExit
ex=0
for t in d.get("targets",[]):
    for p in t["outcome"].get("passes",[]): ex+=p.get("executions",0)
print(ex)
PY
)
echo -e "bhf(builtin)\t0\t$crash\t$ttfc\t${execs:-0}" >> "$RES"
echo -e "(no other fuzzer)\tN/A\tN/A\t-\t-" >> "$RES"
echo "bhf ada: crash=$crash ttfc=$ttfc"; grep -iE "built\+fuzzed|finding|failed|constraint" "$SCRATCH/bhf.log" | head -4
echo "=== RESULTS ==="; column -t -s $'\t' "$RES"
rm -rf "$SCRATCH"
