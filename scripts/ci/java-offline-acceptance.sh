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
trap 'docker volume rm -f "$volume" >/dev/null' EXIT
mkdir -p "$evidence"
fixture="$PWD/docker/fixtures/java-offline"
run=(docker run --rm --read-only --tmpfs /tmp:rw,exec,nosuid,size=1g
  --memory 4g --pids-limit 512 --cap-drop ALL --security-opt no-new-privileges:true
  --volume "$volume:/work" --volume "$fixture:/src:ro")
# Only this explicit, trusted preparation phase has network access.
"${run[@]}" "$image" sh -eu -c '
  mkdir -p /work/project /work/cache/maven
  cp -R /src/. /work/project/
  cd /work/project
  mvn -q -B -Dmaven.repo.local=/work/cache/maven -Dmaven.test.skip=true \
    compile dependency:build-classpath -Dmdep.outputFile=/work/classpath
  rm -rf target /work/classpath
' > "$evidence/java-dependency-staging.log" 2>&1
"${run[@]}" --network none "$image" sh -eu -c '
  cd /work/project
  test ! -e target/classes
  mvn -q -B -o -Dmaven.repo.local=/work/cache/maven -Dmaven.test.skip=true \
    compile dependency:build-classpath -Dmdep.outputFile=/work/classpath
  java -cp "target/classes:$(cat /work/classpath)" com.tarmo.acceptance.Smoke
  test ! -e /src/target
  diff -r /src/src /work/project/src
' > "$evidence/java-offline-build.log" 2>&1
grep -q 'offline ready' "$evidence/java-offline-build.log"
# An empty cache must produce an error under isolation, with no successful
# fallback and no attempt to change the source checkout.
if "${run[@]}" --network none "$image" sh -eu -c '
  cd /work/project
  mvn -q -B -o -Dmaven.repo.local=/work/empty-cache -Dmaven.test.skip=true compile
' > "$evidence/java-missing-cache.log" 2>&1; then
  echo 'Java build unexpectedly succeeded with an empty offline cache' >&2
  exit 1
fi
grep -Eq 'offline mode|has not been downloaded|Cannot access' "$evidence/java-missing-cache.log"
