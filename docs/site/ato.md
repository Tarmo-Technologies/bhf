<!-- SPDX-License-Identifier: Apache-2.0 -->
# ATO / RMF posture for the bhf container

This is an engineering crosswalk to help an ISSO/ISSM assemble an RMF package for
bhf (NIST SP 800-37) using controls from SP 800-53 and container guidance from
SP 800-190. It is evidence and posture, **not** an accreditation or a substitute
for your SSP/STIG work.

## Distribution & operating model

- **Source-only.** bhf ships as source (Apache-2.0). No prebuilt images are
  published, so nothing is redistributed to you as a binary bundle — you build
  the image inside your own (accredited) build enclave from the pinned
  `Dockerfile`. This keeps supply-chain provenance and encryption/export
  concerns inside your boundary.
- **Fully offline at runtime.** bhf discovers, harnesses, builds, and fuzzes with
  **no network access**. It has no auto-update, telemetry, or call-home. The only
  network use is at *build* time (apt + language toolchains), performed once in
  your build enclave; air-gapped **operation** needs nothing from the network.
  See [offline / air-gapped use](./docker.md#air-gapped--offline-use).

## Control crosswalk (selected)

| Area | Control(s) | How bhf/the image satisfies it |
|---|---|---|
| Boundary / no exfil | SC-7, SC-7(4) | Runtime makes zero outbound connections; verify with `--network none` (below). Vendor telemetry disabled (`DOTNET_CLI_TELEMETRY_OPTOUT=1`, `DOTNET_NOLOGO`, `…SKIP_FIRST_TIME_EXPERIENCE`). |
| Least privilege | AC-6, SC-2, SC-3 | Runs as non-root UID 10001 (`fuzzer`); `tini` PID 1; no listening services/daemons. |
| Least functionality | CM-7 | One image per need: comment out unused language `apt` lanes for a minimal deployment (below). |
| Container hardening | 800-190 §4 | `--cap-drop=ALL` + only `--cap-add=SYS_PTRACE`; `--security-opt no-new-privileges`; read-only-rootfs compatible (`--read-only` + tmpfs); digest-pinned base. |
| Supply chain / SBOM | SR-3, SR-4, SR-11, SA-15 | CycloneDX SBOM baked at `/usr/share/bhf/sbom/os.cyclonedx.json` (regenerable offline, `generate-sbom.sh`); `bhf sbom` emits SPDX-2.3/CycloneDX + CVE + OpenVEX for source trees; digest-pinned base + pinned toolchain/tool versions; OCI provenance labels (`revision`/`version`/`created`). |
| Flaw remediation | RA-5, SI-2 | Re-scannable offline (grype offline DB, or `bhf sbom --emit vulnerabilities`). Baseline posture below. |
| Integrity | SI-7 | Reproducible from pinned source; base image pinned by sha256 digest; verify build provenance via image labels. |
| Cryptography | SC-13 | bhf performs **no cryptography at runtime** (offline fuzzer). Bundled crypto libs are build-time transitive deps of fetch tools, not used while fuzzing — FIPS-validated-crypto requirements generally do not apply to bhf's operation (they may apply to your *build host*). |
| Audit | AU-2, AU-3, AU-12 | `bhf audit` writes a JSONL compliance/audit log; `bhf bug-report` produces scrubbed diagnostics (no source, corpus, usernames, hostnames, or absolute paths). |
| Configuration | CM-2, CM-6 | Behavior is flag/`.bhf.toml`-driven and reproducible; the `Dockerfile` is the documented, version-controlled baseline. |

## Verifying the air-gap (SC-7)

```sh
# Operation with no network is the supported mode; prove it:
docker run --rm --network none --shm-size=2g --cap-add=SYS_PTRACE \
  -v "$PWD":/src:ro -v bhf_work:/work \
  bhf:local auto /src --work-dir /work/run
```

Air-gapped target-dependency staging (your project's `.m2`, NuGet, `cargo vendor`,
Go modules) is covered in [docker.md](./docker.md#air-gapped--offline-use); bhf's
own instrumentation deps are already baked in.

## Vulnerability posture (RA-5, SI-2)

The image is actively remediated, not just documented. Full-image `grype` totals:

| | Total | Critical | High | Notes |
|---|--:|--:|--:|---|
| Before remediation | 2,247 | 44 | 516 | dominated by old Go toolchain (1,050) + npm |
| **After remediation** | **~870** | **0** | **0 exploitable** | see below |

What was fixed, at the source (not suppressed):

- **Go toolchain** — Ubuntu's `golang-go` (1.22.2) dragged ~1,050 CVE-flagged
  stdlib/vendored modules. Replaced with **upstream Go (pinned + sha256-verified)**,
  which ships the fixes → those ~1,050 (incl. 546 Critical/High) go to **0**.
- **npm** — its Debian dependency tree (`node-handlebars`, `node-postcss`, …)
  carried the npm-layer CVEs. npm is build-only (the lane needs `node` + `esbuild`
  at runtime), so it is **purged after esbuild is installed**, removing ~357
  packages and all npm CVEs.
- **Base + apt packages** — `apt-get dist-upgrade` pulls the latest
  `-security/-updates` patches over the pinned base.
- **Ruby default gems** — `erb`/`net-imap` updated so the interpreter loads the
  patched versions.

The residue is Ubuntu's ordinary **Medium/Low advisory backlog** (mostly *no fix
released upstream* — not missed patches) plus a few Ruby **bundled default-gem**
specs that cannot be swapped in place without breaking the interpreter. bhf does
not invoke those gems, so they are **not in its execution path** — the correct
RMF treatment is **VEX `not_affected` (vulnerable_code_not_in_execute_path)**,
which bhf emits (`bhf sbom --emit openvex`), not remediation.

Re-scan offline anytime:
```sh
grype "sbom:/usr/share/bhf/sbom/os.cyclonedx.json" --distro ubuntu:24.04   # OS layer
bhf sbom <source-tree> --emit vulnerabilities,openvex                       # bhf + VEX
```

Shrink the surface further by removing lanes you don't deploy (next section).

## Minimal image for deployment (CM-7 least functionality)

The default image carries all sixteen language lanes; a classified deployment
usually needs only a few. Delete the unused `apt` lanes from the `Dockerfile`
(e.g. keep `make clang llvm lld libclang-rt-18-dev` for C/C++, plus Rust) and
drop the rest — this removes most packages, most of the CVE surface, and, if you
drop Ada/COBOL/Fortran, the GPLv3/GPLv2 **compilers** (see
[licensing](./docker.md#licensing--redistribution)). A C/C++-only image is a
small fraction of the full one.

## What remains with the accreditation team

This repo provides the technical evidence (SBOM, provenance, hardened baseline,
control crosswalk, offline proof). The SSP, STIG/SRG checklists (e.g. the DISA
container-platform SRG), continuous monitoring, and any FIPS requirement on the
**build host** are the accreditation team's to complete.
