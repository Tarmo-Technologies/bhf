<!-- SPDX-License-Identifier: Apache-2.0 -->
# ATO / RMF posture for the bhf container

This is an engineering crosswalk to help an ISSO/ISSM assemble an RMF package for
bhf (NIST SP 800-37) using controls from SP 800-53 and container guidance from
SP 800-190. It is evidence and posture, **not** an accreditation or a substitute
for your SSP/STIG work.

## Distribution & operating model

- **Controlled builds.** Build the container from reviewed source and record the
  Dockerfile, source revision, base digest and dependency inputs. Container builds
  and the separate CLI release/distribution workflow are different artifacts;
  do not assume that every BHF distribution is source-only.
- **Offline operation must be enforced.** Stage the required tools, target
  dependencies and advisory databases before disconnecting. Use `--network none`
  for the container and equivalent host controls. Target build scripts and
  explicitly selected network/LLM integrations need separate review; an offline
  usage pattern is not a universal proof that every command can never connect.
  See [offline / air-gapped use](./docker.md#air-gapped--offline-use).

## Control crosswalk (selected)

These are candidate evidence sources and deployment controls, not a statement
that a repository or container automatically satisfies the listed controls.

| Area | Control(s) | Evidence or deployment condition to verify |
|---|---|---|
| Boundary / no exfil | SC-7, SC-7(4) | Enforce the network boundary with `--network none` (below); verify the selected workflows and mounts. Vendor telemetry disabled (`DOTNET_CLI_TELEMETRY_OPTOUT=1`, `DOTNET_NOLOGO`, `…SKIP_FIRST_TIME_EXPERIENCE`). |
| Least privilege | AC-6, SC-2, SC-3 | Runs as non-root UID 10001 (`fuzzer`); `tini` PID 1; no listening services/daemons. |
| Least functionality | CM-7 | Named core, Ada, and full-language targets; select only the required tooling (below). |
| Container hardening | 800-190 §4 | `--cap-drop=ALL` + only `--cap-add=SYS_PTRACE`; `--security-opt no-new-privileges`; read-only-rootfs compatible (`--read-only` + tmpfs); digest-pinned base. |
| Supply chain / SBOM | SR-3, SR-4, SR-11, SA-15 | OS inventory at `/usr/share/bhf/sbom/os.cyclonedx.json`; build-time Cargo inventory and binary receipt; reconciled final-image scan in acceptance evidence; `bhf sbom` emits SPDX-2.3/CycloneDX + CVE + OpenVEX for source trees; digest-pinned base + pinned toolchain/tool versions; OCI provenance labels (`revision`/`version`/`created`). |
| Flaw remediation | RA-5, SI-2 | Re-scannable offline (grype offline DB, or `bhf sbom --emit vulnerabilities`). Baseline posture below. |
| Integrity | SI-7 | Record source/base/dependency digests and verify artifact integrity. Version pins or OCI labels alone do not prove reproducible builds or authenticated provenance. |
| Cryptography | SC-13 | BHF uses hashing and signature verification for integrity/update workflows. Identify the actual module, mode and authorization boundary; no FIPS validation or exemption is established here. |
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

Retain the whole-image inventory, scan database identity, raw matches, and a
reviewed disposition for the exact shipped image. The baked OS inventory covers
only dpkg packages. Container acceptance reconciles a filesystem scan with the
selected compiled Cargo dependency graph and verifies the shipped binary hashes.
Build-toolchain caches are included in the filesystem scan.

The local October 4 observations are recorded in
[the validation report](https://github.com/Tarmo-Technologies/bhf/blob/04a54c4a2f922fb943e8a7f5ded9ef35e6fc38de/docs/validation/2026-10-04-rtos-container-local.md). Those
working-tree scans are historical evidence and do not approve a later release.
A match may need distro backport analysis; absence from a runtime path is not
sufficient to dismiss an installed vulnerable component. Automatic matches stay
under investigation until evidence supports a reviewed disposition. See
[inventory assurance and review gates](./inventory-assurance.md).

## Minimal image for deployment (CM-7 least functionality)

Use the named `core` target for C/C++, `ada` for core plus GNAT/GPRbuild, and
`runtime` for the full-language toolchain image. The default Docker
build includes all sixteen supported languages through `runtime`; smaller images
require explicit selection. All three exclude optional LLM code. Use the documented
hardened Compose override and stage project dependencies before disconnecting.
Each supported deployment needs execution evidence for its selected language
and source/cache mounts; a Java smoke does not validate every full-image lane.

## What remains with the accreditation team

This repo provides tooling and candidate evidence, not an authorization decision.
The team must validate the exact deployment artifact and operating boundary,
retain provenance and review records, and complete the SSP, applicable STIG/SRG
checklists, continuous monitoring and cryptographic requirements. Offline
operation and generated VEX files do not establish accreditation.
