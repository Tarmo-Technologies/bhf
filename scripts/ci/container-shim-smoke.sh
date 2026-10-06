#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Verify ordinary libc calls and the C format hook in a healthy owned program.
set -euo pipefail
cat > /tmp/probe.c <<'C'
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(void) {
 const char *v = getenv("BHF_PLATFORM_SMOKE");
 if (!v || strcmp(v,"ready")) return 2;
 int fd = openat(AT_FDCWD,"/tmp/probe.txt",O_WRONLY|O_CREAT,0600);
 if (fd < 0) return 3;
 if (write(fd,"ready",5) != 5) return 4;
 close(fd);
 return printf("shim ready %d\n",1) < 0;
}
C
clang -fno-builtin /tmp/probe.c -o /tmp/probe
timeout 15s env BHF_PLATFORM_SMOKE=ready BHF_RUNTRACE_MODE=audit \
  BHF_RUNTRACE_LOG=/tmp/shim.jsonl LD_PRELOAD="$BHF_RUNTRACE_SHIM" /tmp/probe
python3 - <<'PY'
import json,pathlib
rows=[json.loads(l) for l in pathlib.Path('/tmp/shim.jsonl').read_text().splitlines()]
assert any(r.get('e')=='format' and r.get('a')=='printf' for r in rows), rows
assert pathlib.Path('/tmp/probe.txt').read_bytes()==b'ready'
print('Healthy libc lookup, file write, and C format interposition passed')
PY
