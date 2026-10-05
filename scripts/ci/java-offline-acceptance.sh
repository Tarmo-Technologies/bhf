#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Explicit online dependency preparation, then disconnected compilation from
# a disposable copy. The original source remains read-only throughout.
set -euo pipefail
cd "$(dirname "$0")/../.."
image="${1:?usage: java-offline-acceptance.sh IMAGE EVIDENCE_DIR}"
evidence="${2:?usage: java-offline-acceptance.sh IMAGE EVIDENCE_DIR}"
image="$(docker image inspect --format '{{.Id}}' "$image")"
volume="bhf-java-offline-$$"
docker volume create "$volume" >/dev/null
cleanup() {
  local status=$?
  if ! retain_results; then
    echo "Result export failed; retained disposable evidence volume: $volume" >&2
    exit 1
  fi
  docker volume rm -f "$volume" >/dev/null
  exit "$status"
}
trap cleanup EXIT
mkdir -p "$evidence"
fixture="$PWD/docker/fixtures/java-offline"
run=(docker run --rm --read-only --tmpfs /tmp:rw,exec,nosuid,size=1g
  --memory 4g --pids-limit 512 --cap-drop ALL --security-opt no-new-privileges:true
  --volume "$volume:/work" --volume "$fixture:/src:ro")
retain_results() {
  # Capture existing checkpoints even when a later assertion fails. The volume
  # remains disposable; the evidence directory holds the durable JSON record.
  "${run[@]}" --network none "$image" /usr/bin/python3 -c '
import hashlib, json, pathlib
root=pathlib.Path("/work")
records={}
for name in ("no-consent", "auto-cold", "auto-warm", "auto-missing-cache"):
    base=root/name
    checkpoint=base/"auto/run.json"
    if not checkpoint.is_file(): continue
    row={"run": json.loads(checkpoint.read_text())}
    findings=base/"results/findings.json"
    if findings.is_file(): row["findings"]=json.loads(findings.read_text())
    row["hashes"]={str(p.relative_to(base)):hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in base.rglob("*") if p.is_file()}
    records[name]=row
print(json.dumps(records, indent=2))
' > "$evidence/java-auto-results.json"
}
# Only this explicit, trusted preparation phase has network access.
"${run[@]}" "$image" sh -eu -c '
  mkdir -p "/work/project with spaces" /work/cache/maven
  cp -R /src/. "/work/project with spaces/"
  cd "/work/project with spaces"
  mvn -q -B -Dmaven.repo.local=/work/cache/maven -Dmaven.test.skip=true \
    compile dependency:build-classpath -Dmdep.outputFile=/work/classpath
  rm -rf target /work/classpath
' > "$evidence/java-dependency-staging.log" 2>&1
"${run[@]}" --network none "$image" sh -eu -c '
  cd "/work/project with spaces"
  test ! -e target/classes
  mvn -q -B -o -Dmaven.repo.local=/work/cache/maven -Dmaven.test.skip=true \
    compile dependency:build-classpath -Dmdep.outputFile=/work/classpath
  java -cp "target/classes:$(cat /work/classpath)" com.tarmo.acceptance.Smoke
  test ! -e /src/target
  diff -r /src/src "/work/project with spaces/src"
' > "$evidence/java-offline-build.log" 2>&1
grep -q 'offline ready' "$evidence/java-offline-build.log"
# An empty cache must produce an error under isolation, with no successful
# fallback and no attempt to change the source checkout.
if "${run[@]}" --network none "$image" sh -eu -c '
  cd "/work/project with spaces"
  mvn -q -B -o -Dmaven.repo.local=/work/empty-cache -Dmaven.test.skip=true compile
' > "$evidence/java-missing-cache.log" 2>&1; then
  echo 'Java build unexpectedly succeeded with an empty offline cache' >&2
  exit 1
fi
grep -Eq 'offline mode|has not been downloaded|Cannot access' "$evidence/java-missing-cache.log"

# The public automatic path must independently build the dependency-bearing
# fixture. Remove the compiler-only output so it cannot stand in for this check.
"${run[@]}" --network none "$image" sh -eu -c '
  rm -rf "/work/project with spaces/target"
  export MAVEN_OPTS=-Dmaven.repo.local=/work/cache/maven
  export BHF_ACCEPTANCE_MARKER=/work/target-entered
  set +e
  bhf auto "/work/project with spaces" --work-dir /work/no-consent \
    --max-targets 1 --per-target-time 5 --iterations 32 --jobs 1
  status=$?
  set -e
  test "$status" = 1
  test ! -e "/work/project with spaces/target"
  test ! -e /work/target-entered
  python3 -c '\''import json; x=json.load(open("/work/no-consent/auto/run.json")); assert x["summary"]["built_and_fuzzed"] == 0; assert "requires --run-untrusted" in json.dumps(x)'\''
' > "$evidence/java-auto-no-consent.log" 2>&1
"${run[@]}" --network none "$image" sh -eu -c '
  export MAVEN_OPTS=-Dmaven.repo.local=/work/cache/maven
  export BHF_ACCEPTANCE_MARKER=/work/target-entered
  for state in cold warm; do
    rm -f /work/target-entered
    bhf auto "/work/project with spaces" --work-dir "/work/auto-$state" \
      --run-untrusted --max-targets 1 --per-target-time 5 --iterations 32 --jobs 1
    test "$(cat /work/target-entered)" = "checksum entered"
    python3 -c '\''import json, sys; x=json.load(open("/work/auto-"+sys.argv[1]+"/auto/run.json")); assert not x["partial"] and x["summary"]["built_and_fuzzed"] == 1; assert "checksum" in json.dumps(x)'\'' "$state"
  done
  test ! -e /src/target
  diff -r /src/src "/work/project with spaces/src"
' > "$evidence/java-auto-offline.log" 2>&1
"${run[@]}" --network none "$image" sh -eu -c '
  rm -f /work/target-entered
  export MAVEN_OPTS=-Dmaven.repo.local=/work/empty-cache
  export BHF_ACCEPTANCE_MARKER=/work/target-entered
  set +e
  bhf auto "/work/project with spaces" --work-dir /work/auto-missing-cache \
    --run-untrusted --max-targets 1 --per-target-time 5 --iterations 32 --jobs 1
  status=$?
  set -e
  test "$status" = 1
  test ! -e /work/target-entered
  python3 -c '\''import json; x=json.load(open("/work/auto-missing-cache/auto/run.json")); assert x["summary"]["built_and_fuzzed"] == 0; assert x["targets"] and all(t["outcome"]["outcome"] == "failed_build" for t in x["targets"])'\''
' > "$evidence/java-auto-missing-cache.log" 2>&1
