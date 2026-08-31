#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Resume the pinned-500 sweep: keeps every result row already written and only
# runs the projects that have none, so tuning concurrency mid-campaign costs
# nothing. Same pinned binary, so the numbers stay comparable.
cd "$(dirname "$0")" || exit 1
BHF_BIN="${BHF_BIN:-/home/ubuntu/bhf-sweep-bin/bhf}"
export BHF_BIN
"$BHF_BIN" --version >/dev/null 2>&1 || { echo "pinned binary missing: $BHF_BIN"; exit 1; }
nohup python3 -u run_sweep.py \
    --wave FULL \
    --per-lane 60 \
    --corpus-only \
    --jobs "${JOBS:-6}" \
    --campaign-time 90 \
    --per-target-time 3 \
    --max-attempts 10 \
    --max-repair-rounds 4 \
    --auto-slack 420 \
    >> /tmp/full.log 2>&1 &
echo "resumed pid $!"
