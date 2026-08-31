#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Re-measure ONLY the SLOC surface across the corpus, merging into the existing
# rows.
#
# The sweep ran before the static file-walk learned about PHP, Ruby, Lua, C#,
# COBOL and Fortran, so those six lanes' line counts were reported as almost
# nothing. Re-fuzzing 500 projects to fix a line count would be hours; a
# sloc-only pass is minutes, and --merge keeps the fuzz rows intact.
cd "$(dirname "$0")" || exit 1
BHF_BIN="${BHF_BIN:-/home/ubuntu/github/tarmo/bhf/target/release/bhf}"
export BHF_BIN
"$BHF_BIN" --version >/dev/null 2>&1 || { echo "binary missing: $BHF_BIN"; exit 1; }
nohup python3 -u run_sweep.py \
    --wave SLOC \
    --per-lane 60 \
    --corpus-only \
    --surfaces sloc \
    --merge \
    --rerun \
    --jobs "${JOBS:-6}" \
    > /tmp/sloc-refresh.log 2>&1 &
echo "sloc refresh pid $!"
