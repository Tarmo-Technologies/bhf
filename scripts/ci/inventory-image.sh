#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Whole-filesystem inventory reconciled with the selected compiled Cargo graph.
set -euo pipefail
image="${1:?usage: inventory-image.sh IMAGE EVIDENCE_DIR}"
evidence="${2:?usage: inventory-image.sh IMAGE EVIDENCE_DIR}"
mkdir -p "$evidence"
scanner_dir="$(mktemp -d)"
container=""
cleanup() {
  if [[ -n "$container" ]]; then docker rm "$container" >/dev/null; fi
  rm -rf "$scanner_dir"
}
trap cleanup EXIT
# Resolve once: every subsequent operation uses the immutable local image ID.
image="$(docker image inspect --format '{{.Id}}' "$image")"
flavor="$(docker image inspect --format '{{index .Config.Labels "io.tarmo.bhf.flavor"}}' "$image")"
tool_script="$(realpath "$(dirname "$0")/toolchain-image-inventory.py")"
docker run --rm --network none --read-only --memory 1g --pids-limit 128 \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --volume "$tool_script:/toolchain-inventory.py:ro" "$image" \
  /usr/bin/python3 /toolchain-inventory.py "$flavor" > "$evidence/toolchains.json"
docker image inspect "$image" > "$evidence/image-inspect.json"
container="$(docker create "$image")"
docker cp "$container:/usr/share/bhf/sbom/rust.cyclonedx.json" "$evidence/rust.cyclonedx.json"
docker cp "$container:/usr/share/bhf/sbom/build-receipt.json" "$evidence/build-receipt.json"
mkdir "$scanner_dir/binaries"
for artifact in /usr/local/bin/bhf /usr/local/bin/bhf-daemon \
                /usr/local/lib/bhf/libbhf_runtrace_shim.so /usr/local/lib/bhf/libbhf_cc_intercept.so; do
  docker cp "$container:$artifact" "$scanner_dir/binaries/"
done
fetch() {
  local name="$1" version="$2" expected="$3"
  local archive="$scanner_dir/$name.tgz"
  curl --proto '=https' --tlsv1.2 -fsSL \
    "https://github.com/anchore/${name}/releases/download/v${version}/${name}_${version}_linux_amd64.tar.gz" \
    -o "$archive"
  printf '%s  %s\n' "$expected" "$archive" | sha256sum -c -
  tar -xzf "$archive" -C "$scanner_dir" "$name"
}
fetch syft 1.46.0 d654f678b709eb53c393d38519d5ed7d2e57205529404018614cfefa0fb2b5ca
fetch grype 0.115.0 3fad92940650e514c0aa2dad83526942a055e210cec09a8a59d9c024adc2b90e
"$scanner_dir/syft" version > "$evidence/syft-version.txt"
"$scanner_dir/grype" version > "$evidence/grype-version.txt"
"$scanner_dir/syft" "docker:$image" -o "cyclonedx-json=$evidence/filesystem.cyclonedx.json"
python3 "$(dirname "$0")/merge-image-inventory.py" "$evidence" "$scanner_dir/binaries"
"$scanner_dir/grype" "sbom:$evidence/image.cyclonedx.json" -o json > "$evidence/grype.json"
python3 - "$evidence" <<'PY'
import collections, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
sbom = json.loads((root / 'image.cyclonedx.json').read_text())
scan = json.loads((root / 'grype.json').read_text())
components = collections.Counter()
for component in sbom.get('components', []):
    purl = component.get('purl', '')
    components[purl.split(':', 1)[1].split('/', 1)[0] if ':' in purl else component['type']] += 1
severities = collections.Counter(x['vulnerability']['severity'] for x in scan.get('matches', []))
summary = {
    'inventory_scope': 'filesystem catalog, compiler-verified production Cargo runtime graph, and standalone toolchain versions/file hashes',
    'components': dict(components),
    'vulnerabilities_by_severity': dict(severities),
    'database': scan.get('descriptor', {}).get('db', {}).get('status', {}),
    'disposition': 'untriaged; not a release approval',
}
(root / 'inventory-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
PY
