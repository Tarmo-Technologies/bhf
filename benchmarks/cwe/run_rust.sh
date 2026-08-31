#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rust CWE coverage: a library with 3 panic-class bugs in 3 functions. cargo-fuzz's
# single fuzz_target! harness reaches ONE; bhf auto-harnesses all three.
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
BHF="$ROOT/../../target/debug/bhf"
BUDGET="${BUDGET:-12}"
SCRATCH="$(mktemp -d)"
RES="$ROOT/results/rust_cwe.tsv"
echo -e "metric\tbhf\tcargo-fuzz" > "$RES"

# bhf: auto-harness the whole lib (no fuzz/ dir), count distinct buggy functions found.
mkdir -p "$SCRATCH/bhf"; cp "$ROOT/targets/rust/Cargo.toml" "$SCRATCH/bhf/"; cp -r "$ROOT/targets/rust/src" "$SCRATCH/bhf/"
"$BHF" auto --per-target-time "$BUDGET" --seed-dir "$ROOT/seeds_rust" --work-dir "$SCRATCH/gw" "$SCRATCH/bhf" >"$SCRATCH/bhf.log" 2>&1
bhf_fns=$(python3 - "$SCRATCH/gw/findings" <<'PY'
import json,os,sys
root=sys.argv[1]; ids=set()
if os.path.isdir(root):
  for fn in os.listdir(root):
    fj=os.path.join(root,fn,"finding.json")
    if not os.path.isfile(fj): continue
    f=json.load(open(fj))
    ids.add(str(f.get("harness_id","")))   # one harness_id per fuzzed function
print(len(ids))
PY
)
bhf_targets=$(grep -cE "built\+fuzzed" "$SCRATCH/bhf.log")
echo "bhf: built+fuzzed $bhf_targets targets; distinct buggy functions found=$bhf_fns"

# cargo-fuzz: build (untimed) then run the ONE primary harness.
cp -r "$ROOT/targets/rust" "$SCRATCH/cf"
( cd "$SCRATCH/cf" && cargo +nightly fuzz build primary >"$SCRATCH/cf_build.log" 2>&1 )
cf_found=0
if [ $? -eq 0 ]; then
  ( cd "$SCRATCH/cf" && timeout $((BUDGET+30)) cargo +nightly fuzz run primary -- -max_total_time="$BUDGET" -seed=1 >"$SCRATCH/cf_run.log" 2>&1 )
  compgen -G "$SCRATCH/cf/fuzz/artifacts/primary/crash-*" >/dev/null 2>&1 && cf_found=1
else echo "cargo-fuzz build failed:"; tail -4 "$SCRATCH/cf_build.log"; cf_found="BUILD?"; fi
echo "cargo-fuzz: found $cf_found bug (single harness on parse_packet only)"

echo -e "buggy functions found (of 3)\t$bhf_fns\t$cf_found" >> "$RES"
echo -e "hand-written harnesses needed\t0\t1 per function (3 for parity)" >> "$RES"
echo -e "toolchain\tstable\tnightly" >> "$RES"
echo "=== RESULTS ==="; column -t -s $'\t' "$RES"
rm -rf "$SCRATCH"
