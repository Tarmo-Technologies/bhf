#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Container lifecycle and absent-assistance checks; no target project executed.
set -euo pipefail
image="${1:?usage: container-runtime-acceptance.sh IMAGE EVIDENCE_DIR}"
evidence="${2:?usage: container-runtime-acceptance.sh IMAGE EVIDENCE_DIR}"
image="$(docker image inspect --format '{{.Id}}' "$image")"
mkdir -p "$evidence"
run=(docker run --rm --network none --read-only --tmpfs /tmp:rw,exec,nosuid,size=64m
  --memory 512m --pids-limit 64 --cap-drop ALL --security-opt no-new-privileges:true)
"${run[@]}" --env OPENAI_API_KEY=acceptance-dummy --env ANTHROPIC_API_KEY=acceptance-dummy \
  "$image" sh -eu -c '
  mkdir /tmp/providers
  printf "#!/bin/sh\ntouch /tmp/provider-invoked\nexit 99\n" > /tmp/providers/codex
  chmod +x /tmp/providers/codex
  cp /tmp/providers/codex /tmp/providers/claude
  export PATH=/tmp/providers:$PATH
  bhf --help
  set +e
  bhf llm --help >/tmp/llm.log 2>&1
  status=$?
  set -e
  test "$status" = 2
  grep -q "unrecognized subcommand" /tmp/llm.log
  printf "%s\n" '\''{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'\'' | bhf-daemon --mcp
  test ! -e /tmp/provider-invoked
' > "$evidence/no-llm-environment.log" 2>&1
python3 - "$evidence/no-llm-environment.log" <<'PY'
import json, pathlib, sys
lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
reply = next(json.loads(line) for line in lines if line.startswith('{'))
names = {tool['name'] for tool in reply['result']['tools']}
assert names == {'bhf_scan', 'bhf_list_targets', 'bhf_load_findings'}, names
PY
set +e
"${run[@]}" "$image" bhf-daemon --invalid-acceptance-option > "$evidence/daemon-invalid.log" 2>&1
status=$?
set -e
[[ "$status" == 2 ]]
grep -q 'unknown option' "$evidence/daemon-invalid.log"
# Keep stdin open so the real daemon remains alive until SIGTERM arrives.
container="$(docker run -di --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true "$image" bhf-daemon)"
trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT
[[ "$(docker inspect --format '{{.State.Running}}' "$container")" == true ]]
start=$SECONDS
docker stop --time 2 "$container" > "$evidence/termination.log"
elapsed=$((SECONDS - start))
status="$(docker inspect --format '{{.State.ExitCode}}' "$container")"
printf 'elapsed_seconds=%s\nexit_code=%s\n' "$elapsed" "$status" >> "$evidence/termination.log"
[[ "$status" == 143 && "$elapsed" -le 5 ]]
