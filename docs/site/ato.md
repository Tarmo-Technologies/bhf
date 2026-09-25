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
| Least functionality | CM-7 | One image per need: comment out unused language `apt` lanes for a minimal deployment (below). |
| Container hardening | 800-190 §4 | `--cap-drop=ALL` + only `--cap-add=SYS_PTRACE`; `--security-opt no-new-privileges`; read-only-rootfs compatible (`--read-only` + tmpfs); digest-pinned base. |
| Supply chain / SBOM | SR-3, SR-4, SR-11, SA-15 | CycloneDX SBOM baked at `/usr/share/bhf/sbom/os.cyclonedx.json` (regenerable offline, `generate-sbom.sh`); `bhf sbom` emits SPDX-2.3/CycloneDX + CVE + OpenVEX for source trees; digest-pinned base + pinned toolchain/tool versions; OCI provenance labels (`revision`/`version`/`created`). |
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

The figures below are a historical remediation record, not a current vulnerability
assessment of an immutable image digest. Re-scan the exact deployment artifact
and retain the database version before relying on them. The earlier "0 exploitable"
claim is not established by component inventory or missing execution observations.

Previously reported full-image `grype` totals:

| | Total | Critical | High | Notes |
|---|--:|--:|--:|---|
| Before remediation | 2,247 | 44 | 516 | dominated by old Go toolchain (1,050) + npm |
| Previously reported after remediation | ~870 | 0 | Exploitability not established | Historical counts; reassess the exact artifact |

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

The earlier explanation characterized remaining matches as a Medium/Low backlog
and unused bundled gems. Those observations are not sufficient to establish
non-impact or prescribe a `not_affected` VEX disposition. As corrected on
2026-09-25, BHF leaves automatic matches `under_investigation` until
vulnerability-specific evidence supports a reviewed decision. See
[inventory assurance and review gates](../inventory-assurance.md). Historical
scan counts do not establish current remediation or authorization status.

Re-scan offline anytime:
```sh
grype "sbom:/usr/share/bhf/sbom/os.cyclonedx.json" --distro ubuntu:24.04   # OS layer
bhf sbom <source-tree> --vuln-db <offline-db.json> --emit vulnerabilities,openvex,vex-review
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

This repo provides tooling and candidate evidence, not an authorization decision.
The team must validate the exact deployment artifact and operating boundary,
retain provenance and review records, and complete the SSP, applicable STIG/SRG
checklists, continuous monitoring and cryptographic requirements. Offline
operation and generated VEX files do not establish accreditation.
