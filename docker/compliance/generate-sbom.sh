#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Emit a CycloneDX 1.5 SBOM of the OS package layer straight from dpkg — no
# network, no external tool, so it reproduces on an air-gapped host. This is the
# auditable image inventory for an ATO/RMF package (EO 14028). It covers the
# ~700 Ubuntu packages; bhf's OWN software composition (its Rust crates) is
# emitted separately by `bhf sbom <source-tree>` (SPDX/CycloneDX + CVE + VEX).
#
#   generate-sbom.sh [OUT_JSON]   (default: /usr/share/bhf/sbom/os.cyclonedx.json)
set -euo pipefail
OUT="${1:-/usr/share/bhf/sbom/os.cyclonedx.json}"
mkdir -p "$(dirname "$OUT")"

arch="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
. /etc/os-release 2>/dev/null || true
distro="${ID:-ubuntu}"

python3 - "$OUT" "$arch" "$distro" "${VERSION_ID:-24.04}" <<'PY'
import json, subprocess, sys, datetime
out, arch, distro, osver = sys.argv[1:5]

def license_of(pkg):
    try:
        with open(f"/usr/share/doc/{pkg}/copyright", encoding="utf-8", errors="replace") as fh:
            lics = []
            for line in fh:
                if line.startswith("License:"):
                    v = line.split(":", 1)[1].strip()
                    if v and v not in lics:
                        lics.append(v)
                    if len(lics) >= 6:
                        break
            return lics
    except OSError:
        return []

rows = subprocess.run(
    ["dpkg-query", "-W", "-f", "${Package}\t${Version}\t${source:Package}\t${source:Version}\n"],
    capture_output=True, text=True, check=True,
).stdout.splitlines()

components = []
for row in rows:
    parts = row.split("\t")
    if len(parts) < 2 or not parts[0]:
        continue
    name, ver = parts[0], parts[1]
    src = parts[2] if len(parts) > 2 and parts[2] else name
    lics = license_of(name)
    comp = {
        "type": "library",
        "name": name,
        "version": ver,
        "purl": f"pkg:deb/{distro}/{name}@{ver}?arch={arch}",
        "properties": [{"name": "syft:package:source", "value": src}],
    }
    if lics:
        comp["licenses"] = [{"license": {"name": lic}} for lic in lics]
    components.append(comp)

bom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "component": {"type": "container", "name": "bhf", "version": "0.2.32",
                      "description": f"OS package layer ({distro} {osver})"},
        "tools": [{"vendor": "Tarmo Technologies", "name": "bhf-generate-sbom"}],
    },
    "components": components,
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(bom, fh, indent=1)
print(f"generate-sbom: {len(components)} OS packages -> {out}")
PY
