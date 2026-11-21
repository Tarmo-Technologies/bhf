<!-- SPDX-License-Identifier: Apache-2.0 -->
# Compliance and supply-chain artifacts for the bhf image

bhf source is Apache-2.0. The container images also include separately licensed toolchain and runtime packages. The container release path prepares an unsigned candidate with the tested image, the matching bhf source, the exact requested Ubuntu source packages, inventories, notices and validation evidence. Signing and publication follow the release gates in [`docs/release-packaging.md`](../../docs/release-packaging.md).

The inventories, notices and source downloads here are the material for a supply-chain and redistribution review. The publisher's signature is added at the release gates above.

## Generated into the image at build

| Path (in image) | From | Purpose |
|---|---|---|
| `/usr/share/bhf/licenses/THIRD_PARTY_NOTICES.md` | `generate-notices.sh` | every OS package, with version, source and license |
| `/usr/share/bhf/licenses/COPYLEFT-SOURCES.txt` | `generate-notices.sh` | `source=version` list of the GPL/LGPL packages |
| `/usr/share/bhf/licenses/WRITTEN-OFFER.md` | `WRITTEN-OFFER.md` | redistribution and corresponding-source notice |
| `/usr/share/bhf/licenses/fetch-sources.sh` | `fetch-sources.sh` | downloads the matching Ubuntu source for the copyleft list |
| `/usr/share/bhf/sbom/os.cyclonedx.json` | `generate-sbom.sh` | CycloneDX SBOM of the OS package layer (EO 14028) |
| `/usr/share/doc/<pkg>/copyright` | apt | the full per-package license text, kept in the image |
| `/usr/share/bhf/licenses/csharp/` | .NET SDK archive | Microsoft's `LICENSE.txt` and `ThirdPartyNotices.txt` for the .NET SDK |

The .NET SDK comes from Microsoft's checksum-pinned release archive (SDK 8.0.134, runtime 8.0.34) in place of Ubuntu's `dotnet8` package, which has lagged Microsoft's security releases. It is therefore absent from the dpkg-generated notices and copyleft list; its notices are under `/usr/share/bhf/licenses/csharp/`.

`COPYLEFT-SOURCES.txt` lists `afl++` because its Debian package ships a GPL-3+ gcc-pass file and MPL-2.0 files; the main body of AFL++ is Apache-2.0.

All generators read only dpkg, so they run offline and give the same output on an air-gapped host. bhf's own software composition (its Rust crates, with CVE matching and OpenVEX) comes separately from `bhf sbom <source-tree>`.

## Scripts and data used outside the image build

- `fetch-sources.sh [COPYLEFT-SOURCES.txt] [dest]` downloads the exact Ubuntu source versions on the copyleft list, for redistribution review. Run it as root on an Ubuntu 24.04 host with network access and apt.
- `generate-sbom.sh [out.json]` and `generate-notices.sh [outdir]` regenerate the SBOM and the notices from any running image or host.
- `rust-license-overrides/` holds checksum-pinned license files for Rust crates whose published package carries none; `scripts/ci/rust-image-inventory.py` uses them when it inventories the image's Rust dependencies.

## See also

- Licensing summary and when the offer applies: [`docs/site/docker.md`](../../docs/site/docker.md#licensing-and-redistribution)
- ATO/RMF control crosswalk, vulnerability posture and minimal-image guidance: [`docs/site/ato.md`](../../docs/site/ato.md)
