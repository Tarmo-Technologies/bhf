#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Bounded, clean BHF-owned controls; this is not upstream qualification.
# Mount fixtures at /fixtures:ro and disposable writable space at /work.
set -euo pipefail
[[ "$(id -u)" == 10001 ]]
source /usr/local/share/bhf/language-selection.sh
selected="$(bhf_resolve_languages "${1:-all}")"
source_name=source
case "${2:-}" in
  '') ;;
  --paths-with-spaces) source_name='source with spaces' ;;
  *) echo 'usage: language-auto-smoke.sh [LANGUAGES] [--paths-with-spaces]' >&2; exit 2 ;;
esac
IFS=, read -r -a languages <<< "$selected"
failed=0
for language in "${languages[@]}"; do
  stage="/work/$language"
  mkdir -p "$stage/$source_name" "$stage/cache"
  cp -R "/fixtures/$language/." "$stage/$source_name/"
  export XDG_CACHE_HOME="$stage/cache" GOCACHE="$stage/cache/go" GOMODCACHE="$stage/cache/go-mod"
  export GOENV=off GOPROXY=off GOSUMDB=off GOMAXPROCS=2 DOTNET_CLI_HOME="$stage/cache/dotnet"
  export CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS=2
  set +e
  timeout --kill-after=5s 120s bhf auto "$stage/$source_name" \
    --work-dir "$stage/run" --languages "$language" --max-targets 1 \
    --per-target-time 5 --iterations 32 --jobs 1 --single-pass --sanitizers none \
    --run-untrusted > "$stage/auto.log" 2>&1
  status=$?
  set -e
  printf '%s\n' "$status" > "$stage/exit-code"
  if ! python3 - "$stage" <<'PY'
import json, pathlib, sys
root=pathlib.Path(sys.argv[1])
assert (root/'exit-code').read_text().strip() == '0'
run=json.loads((root/'run/auto/run.json').read_text())
assert not run['partial'] and run['summary']['built_and_fuzzed'] == 1
targets=[t for t in run['targets'] if t['outcome']['outcome'] == 'built_and_fuzzed']
assert len(targets) == 1
passes=targets[0]['outcome']['passes']
assert any(p['executions'] > 0 and p['target_entry_observed'] for p in passes)
assert not targets[0].get('platform_stub')
assert not targets[0].get('stub_execution', {}).get('stub_only', False)
findings=json.loads((root/'run/results/findings.json').read_text())
assert not findings['findings']
source=root/'source'
if not source.is_dir(): source=root/'source with spaces'
original_root=pathlib.Path('/fixtures')/root.name
for original in original_root.rglob('*'):
    if original.is_file():
        staged=source/original.relative_to(original_root)
        assert staged.read_bytes() == original.read_bytes(), f'staged source changed: {original.name}'
edges=max(p['coverage_edges'] for p in passes)
print(json.dumps({'language':root.name, 'status':'passed' if edges else 'entered_without_feedback', 'target':targets[0]['name'],
                  'executions':sum(p['executions'] for p in passes),
                  'coverage_edges':edges,
                  'target_entry_observed':True}), flush=True)
assert edges > 0, 'target entered but no measured coverage feedback'
PY
  then
    echo "BHF auto control failed: $language (exit $status)" >&2
    tail -30 "$stage/auto.log" >&2
    failed=1
  fi
done
python3 - <<'PY'
import hashlib, json, pathlib
records={}
for stage in sorted(pathlib.Path('/work').iterdir()):
    if not (stage/'exit-code').is_file(): continue
    row={'exit_code':int((stage/'exit-code').read_text())}
    checkpoint=stage/'run/auto/run.json'
    if checkpoint.is_file(): row['run']=json.loads(checkpoint.read_text())
    findings=stage/'run/results/findings.json'
    if findings.is_file(): row['findings']=json.loads(findings.read_text())
    row['log_sha256']=hashlib.sha256((stage/'auto.log').read_bytes()).hexdigest()
    fixture_root=pathlib.Path('/fixtures')/stage.name
    row['fixture_hashes']={str(p.relative_to(fixture_root)):hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in fixture_root.rglob('*') if p.is_file()}
    records[stage.name]=row
print('BHF_AUTO_REPORT='+json.dumps(records, separators=(',', ':')))
PY
exit "$failed"
