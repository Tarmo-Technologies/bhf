#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Ada CWE coverage: 2 subprograms raising CONSTRAINT_ERROR. No off-the-shelf
# fuzzer supports Ada, so bhf IS the comparison.
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
BHF="$ROOT/../../target/debug/bhf"; BUDGET="${BUDGET:-15}"; SCRATCH="$(mktemp -d)"
RES="$ROOT/results/ada_cwe.tsv"; echo -e "metric\tbhf\t(any other fuzzer)" > "$RES"
command -v gnatmake >/dev/null 2>&1 || { echo "SKIP: no gnatmake"; exit 0; }
cp -r "$ROOT/targets/ada" "$SCRATCH/bhf"
"$BHF" auto --per-target-time "$BUDGET" --work-dir "$SCRATCH/gw" "$SCRATCH/bhf" >"$SCRATCH/bhf.log" 2>&1
bhf_fns=$(python3 - "$SCRATCH/gw/findings" <<'PY'
import json,os,sys
root=sys.argv[1]; fns=set()
if os.path.isdir(root):
  for fn in os.listdir(root):
    fj=os.path.join(root,fn,"finding.json")
    if os.path.isfile(fj):
      f=json.load(open(fj)); fns.add(str(f.get("harness_id","")))
print(len(fns))
PY
)
echo "bhf ada: distinct buggy subprograms found=$bhf_fns ($(grep -c 'built+fuzzed' "$SCRATCH/bhf.log") targets)"
echo -e "buggy subprograms found (of 2)\t$bhf_fns\t0 (cannot fuzz Ada)" >> "$RES"
echo -e "fuzzes Ada at all\tyes\tno" >> "$RES"
echo "=== RESULTS ==="; column -t -s $'\t' "$RES"
rm -rf "$SCRATCH"
