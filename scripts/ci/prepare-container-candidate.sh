#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/../.."
flavor="${1:?usage: prepare-container-candidate.sh core|ada|runtime}"
case "$flavor" in
  core) evidence=container-acceptance ;;
  ada) evidence=container-ada-acceptance ;;
  runtime) evidence=container-full-acceptance ;;
  *) echo 'unsupported image flavor' >&2; exit 2 ;;
esac
python3 scripts/ci/review-image-scan.py "$evidence"
image="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[0]["Id"])' "$evidence/image-inspect.json")"
stage="$(mktemp -d)"
container="bhf-release-sources-$$"
cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$stage"
}
trap cleanup EXIT
# Controlled preparation uses network to retrieve exact source archives, with
# no source extraction or package build. Production runtime stays disconnected.
docker run --name "$container" --user 0 "$image" \
  bash /usr/share/bhf/licenses/fetch-sources.sh \
  /usr/share/bhf/licenses/COPYLEFT-SOURCES.txt /sources \
  > "$evidence/corresponding-source.log" 2>&1
docker cp "$container:/sources" "$stage/sources"
mkdir -p dist/container
python3 scripts/package-container-candidate.py --image "$image" \
  --evidence "$evidence" --sources "$stage/sources" --out dist/container \
  > "$stage/candidate-output.json"
cp "$stage/candidate-output.json" "$evidence/candidate.json"
# The last line is the machine-readable receipt; earlier output includes the
# explicit vulnerability-review decision.
tail -1 "$evidence/candidate.json"
