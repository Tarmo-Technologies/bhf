<!-- SPDX-License-Identifier: Apache-2.0 -->
# ATO / RMF posture for the bhf container

This page maps the bhf container to NIST controls, for an ISSO or ISSM who
assembles an RMF package for bhf (NIST SP 800-37). It uses controls from
SP 800-53 and container guidance from SP 800-190. Each row names the
evidence bhf provides and the deployment condition you verify. Your SSP and
STIG work stays with your accreditation team (see the last section).

## Distribution and operating model

- **Controlled builds.** Build the container from reviewed source and record
  the Dockerfile, source revision, base image digest and dependency inputs.
  The container image and the CLI release packages
  ([Release Packaging](release-packaging.md)) are separate artifacts with
  separate build workflows.
- **Offline operation.** Stage the tools, target dependencies and advisory
  databases you need before you disconnect. Run the container with
  `--network none` and apply equivalent controls on the host. Target build
  scripts and any network or model integration you enable can open
  connections, so review them separately. See
  [offline / air-gapped use](./docker.md#air-gapped-and-offline-use).

## Control crosswalk (selected)

Each row lists evidence sources and deployment controls to verify for your
deployment.

| Area | Control(s) | Evidence or deployment condition to verify |
|---|---|---|
| Boundary / no exfiltration | SC-7, SC-7(4) | Enforce the network boundary with `--network none` (below); verify the workflows and mounts you use. The image sets `DOTNET_CLI_TELEMETRY_OPTOUT=1`, `DOTNET_NOLOGO=1` and `DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1`. |
| Least privilege | AC-6, SC-2, SC-3 | Runs as the non-root user `fuzzer` (UID 10001); `tini` is PID 1; no service listens on a port. |
| Least functionality | CM-7 | Named `core`, `ada` and full-language (`runtime`) build targets; select only the tooling you need (below). |
| Container hardening | 800-190 §4 | `--cap-drop=ALL` plus only `--cap-add=SYS_PTRACE`; `--security-opt no-new-privileges`; runs with a read-only root filesystem (`--read-only` plus a tmpfs, as `docker/compose.hardened.yaml` sets); digest-pinned base image. |
| Supply chain / SBOM | SR-3, SR-4, SR-11, SA-15 | OS inventory at `/usr/share/bhf/sbom/os.cyclonedx.json`; build-time Cargo inventory and binary receipt; a reconciled final-image scan in the acceptance evidence; `bhf sbom` emits SPDX 2.3 or CycloneDX, CVE matches and OpenVEX for source trees; digest-pinned base and pinned toolchain and tool versions; OCI provenance labels (`revision`, `version`, `created`). |
| Flaw remediation | RA-5, SI-2 | Re-scan offline with an offline grype database or `bhf sbom --emit vulnerabilities`. See the baseline posture below. |
| Integrity | SI-7 | Record source, base and dependency digests and verify artifact integrity. Reproducible builds and authenticated provenance need that recorded evidence in addition to version pins and OCI labels. |
| Cryptography | SC-13 | bhf uses hashing and signature verification for integrity and update workflows. Identify the actual module, mode and authorization boundary for your package; bhf carries no FIPS validation or exemption. |
| Audit | AU-2, AU-3, AU-12 | `bhf audit` writes a JSONL compliance and audit log; `bhf bug-report` writes scrubbed diagnostics with no source, corpus, usernames, hostnames or absolute paths. |
| Configuration | CM-2, CM-6 | Behaviour is set by flags and `.bhf.toml` and is reproducible; the version-controlled `Dockerfile` is the documented baseline. |

## Verifying the air gap (SC-7)

Run bhf with no network:

```sh
docker run --rm --network none --shm-size=2g --cap-add=SYS_PTRACE \
  -v "$PWD":/src:ro -v bhf_work:/work \
  bhf:local auto /src --work-dir /work/run
```

The image already contains bhf's own instrumentation dependencies. To stage
your project's dependencies (`.m2`, NuGet, `cargo vendor`, Go modules) for an
air-gapped run, see [docker.md](./docker.md#air-gapped-and-offline-use).

## Vulnerability posture (RA-5, SI-2)

Retain the whole-image inventory, the scan database identity, the raw
matches and a reviewed disposition for the exact image you ship. The baked
OS inventory lists dpkg packages. Container acceptance reconciles a
filesystem scan, which includes the build-toolchain caches, with the
compiled Cargo dependency graph, and verifies the hashes of the shipped
binaries.

The local scans of October 4, 2026 are recorded in
[the validation report](../validation/2026-10-04-rtos-container-local.md).
They describe that working tree; each release needs its own scan. A match
can need distro backport analysis. An installed vulnerable component counts
even when it sits outside the runtime path. A match stays under
investigation until evidence supports a reviewed disposition. See
[inventory assurance and review gates](./inventory-assurance.md).

## Minimal image for deployment (CM-7 least functionality)

| Build target | Contents |
|---|---|
| `core` | C and C++ |
| `ada` | `core` plus GNAT and GPRbuild |
| `runtime` | the full-language toolchains, all sixteen languages |

The default Docker build (`production`) builds on `runtime`; a smaller image
needs an explicit `--target`. None of the three includes the optional `llm`
feature. Use the hardened Compose override (`docker/compose.hardened.yaml`)
and stage project dependencies before you disconnect. Keep execution
evidence for each language and each source and cache mount your deployment
uses; a smoke test of one lane covers that lane.

## What remains with the accreditation team

bhf provides the tooling and the evidence listed above. Your accreditation
team makes the authorization decision. The team validates the exact
deployment artifact and operating boundary, retains provenance and review
records, and completes the SSP, the applicable STIG and SRG checklists,
continuous monitoring and the cryptographic requirements. Offline operation
and generated VEX files are inputs to that work.
