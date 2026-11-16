#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The ARM64 job's end-to-end check: `bhf auto` builds a C target natively on
# the runner and finds the stack overflow planted in it.
set -euo pipefail
bhf=${1:?usage: arm64-auto-smoke.sh <path to bhf>}
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
summary = json.loads((work / "auto/run.json").read_text())["summary"]
assert summary["built_and_fuzzed"] == 1, summary
findings = json.loads((work / "results/findings.json").read_text())["findings"]
rules = sorted({(finding.get("rule") or {}).get("id") for finding in findings} - {None})
assert {"BHF-201", "BHF-203"} & set(rules), rules
print("arm64 auto smoke: the planted overflow was found:", ", ".join(rules))
PY
