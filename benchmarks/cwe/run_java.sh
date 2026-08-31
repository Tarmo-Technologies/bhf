#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Java CWE coverage: a class with 3 bugs in 3 methods. Jazzer's single
# fuzzerTestOneInput harness reaches ONE; bhf auto-harnesses all three.
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
BHF="$ROOT/../../target/debug/bhf"
JAZZER="${JAZZER:-/opt/jazzer/jazzer}"; JAZZER_JAR="${JAZZER_JAR:-/opt/jazzer/jazzer_standalone.jar}"
BUDGET="${BUDGET:-12}"; SCRATCH="$(mktemp -d)"
RES="$ROOT/results/java_cwe.tsv"; echo -e "metric\tbhf\tJazzer" > "$RES"

cp -r "$ROOT/targets/java" "$SCRATCH/bhf"
"$BHF" auto --per-target-time "$BUDGET" --seed-dir "$ROOT/seeds_java" --work-dir "$SCRATCH/gw" "$SCRATCH/bhf" >"$SCRATCH/bhf.log" 2>&1
bhf_fns=$(python3 - "$SCRATCH/gw/findings" <<'PY'
import json,os,sys
root=sys.argv[1]; ids=set()
if os.path.isdir(root):
  for fn in os.listdir(root):
    fj=os.path.join(root,fn,"finding.json")
    if not os.path.isfile(fj): continue
    f=json.load(open(fj))
    ids.add(str(f.get("harness_id","")))   # one harness_id per fuzzed method
print(len(ids))
PY
)
echo "bhf java: distinct buggy methods found=$bhf_fns ($(grep -c 'built+fuzzed' "$SCRATCH/bhf.log") targets)"

mkdir -p "$SCRATCH/jz/classes"
jz_found=0
if javac -cp "$JAZZER_JAR" -d "$SCRATCH/jz/classes" \
     "$ROOT/targets/java/src/com/acme/MultiParser.java" "$ROOT/harnesses/MultiFuzzer.java" 2>"$SCRATCH/jz_build.log"; then
  ( cd "$SCRATCH/jz" && timeout $((BUDGET+15)) "$JAZZER" --cp=classes --target_class=MultiFuzzer -max_total_time="$BUDGET" -seed=1 >run.log 2>&1 )
  grep -qiE "Java Exception|ArrayIndexOutOfBounds|NullPointer|ArithmeticException" "$SCRATCH/jz/run.log" && jz_found=1
  { compgen -G "$SCRATCH/jz/crash-*" >/dev/null 2>&1; } && jz_found=1
else jz_found="BUILD?"; tail -4 "$SCRATCH/jz_build.log"; fi
echo "jazzer: found $jz_found bug (single harness on parsePacket only)"

echo -e "buggy methods found (of 3)\t$bhf_fns\t$jz_found" >> "$RES"
echo -e "hand-written harnesses needed\t0\t1 per method (3 for parity)" >> "$RES"
echo "=== RESULTS ==="; column -t -s $'\t' "$RES"
rm -rf "$SCRATCH"
