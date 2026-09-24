<!-- SPDX-License-Identifier: Apache-2.0 -->
# Compliance & supply-chain artifacts for the bhf image

bhf is distributed as **source** (Apache-2.0). The project publishes **no
prebuilt images**, so it distributes no GPL/LGPL binaries and carries no
corresponding-source offer — you build the image yourself, and Ubuntu is the
distributor of the toolchain packages it pulls. These files exist so the built
image is **self-documenting** for supply-chain review / ATO, and so that anyone
who chooses to *redistribute* the built image can meet the duty they take on.

## Generated into the image at build

| Path (in image) | From | Purpose |
|---|---|---|
| `/usr/share/bhf/licenses/THIRD_PARTY_NOTICES.md` | `generate-notices.sh` | every OS package → version → source → license |
| `/usr/share/bhf/licenses/COPYLEFT-SOURCES.txt` | `generate-notices.sh` | GPL/LGPL `source=version` list |
| `/usr/share/bhf/licenses/WRITTEN-OFFER.md` | `WRITTEN-OFFER.md` | redistribution + corresponding-source notice |
| `/usr/share/bhf/licenses/fetch-sources.sh` | `fetch-sources.sh` | downloads matching Ubuntu source for the copyleft list |
| `/usr/share/bhf/sbom/os.cyclonedx.json` | `generate-sbom.sh` | CycloneDX SBOM of the OS package layer (EO 14028) |
| `/usr/share/doc/<pkg>/copyright` | apt | authoritative full per-package license text (retained) |

All generators are **offline / deterministic** (dpkg only) so they reproduce on
an air-gapped host. bhf's own software composition (its Rust crates, with CVE +
OpenVEX) comes from `bhf sbom <source-tree>` separately.

## Scripts (run outside the image build)

- `fetch-sources.sh [manifest] [dest]` — fulfils the copyleft corresponding-
  source duty (only relevant if you redistribute the built image). Run as root
  on an Ubuntu 24.04 host with network.
- `generate-sbom.sh [out.json]` / `generate-notices.sh [outdir]` — regenerate the
  SBOM / notices from any running image or host.

## See also

- Licensing summary & when the offer applies: `../../docs/site/docker.md#licensing--redistribution`
- ATO / RMF control crosswalk, vuln posture, minimal-image guidance: `../../docs/site/ato.md`

`afl++` appears in `COPYLEFT-SOURCES.txt` correctly — its Debian package ships a
GPL-3+ gcc-pass file and MPL-2.0 files, though its main body is Apache-2.0.
