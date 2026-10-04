<!-- SPDX-License-Identifier: Apache-2.0 -->
# Local RTOS and container validation — October 4, 2026

This is local development evidence from an uncommitted working tree based on
`2e9ea97def2a71e66bf00b5d50d4c5f5a9112bd6`. It is **not** an exact-commit
release receipt, hosted CI result, physical-board validation, or vulnerability
exception approval.

## FreeRTOS reference profile

`BHF_RTOS_LIVE=1 cargo test --locked -p target_transport --test live_rtos -- --nocapture`
passed both real-QEMU tests: pinned FreeRTOS kernel boot/snapshot and
clean/default/HardFault/clean task-aware input drive. The classified fault was
`CpuException` and the final clean run had no inherited fault.

`BHF_RTOS_CLI=1 cargo test --locked -p bhf --test transport_fuzz_qemu_cli
cli_freertos_clean_fault_clean -- --nocapture` passed clean → fault → clean,
retained the fault finding, and returned `MATCH` from `bhf replay` against a
fresh guest. `scripts/hil-emu.sh` passed RV-1 through RV-4 locally with these
tests included. Hosted HIL-emu results and physical-board behavior remain
separate evidence.

## Docker targets

The default `core` target built as `linux/amd64`. The current local build was
`sha256:623fc11ade8026e308a2abf502734b2d6fa37eef015f61904026dee3f1e0b9a2`,
845,191,884 unpacked bytes. That image ran the C
`parse_frame` fixture as UID 10001 under `--network none --read-only`, a writable
`/tmp` tmpfs and `/work` volume, 4 GB memory and 512 PIDs. It built and fuzzed
one target for 32 executions with 10 observed edges. The default image rejects
`bhf llm` and reports version `0.2.34`.

The explicit full-language `runtime` target built as `linux/amd64`, local image
`sha256:3000733cbb599777084100168053f5c8761f39cfdac4c56ef95490a32555dac5`,
3,558,046,779 unpacked bytes. Its immutable JVM agent was readable as UID
10001 under a read-only root. The bare `java_fuzz` fixture built and fuzzed
under `--network none`, retaining a planted BHF-201 finding. A staged
Maven/Gradle dependency-bearing fixture has **not** passed this profile.

The checked-in CI now builds both targets and runs the C and bare-Java smoke
commands, but no hosted results are asserted here. The Compose default service
set contains only `bhf`; the `validation` profile adds `sweep`.

## Provisional inventory and scan

Local Syft 1.46.0 inventoried both images and Grype 0.115.0 scanned those
inventories using DB built `2026-10-04T08:11:47Z` (schema `v6.1.10`). The core
inventory found 187 Debian packages and no recognized compiled Rust packages;
its scan reported 547 matches: 422 Medium, 119 Low, 6 Negligible. The full
inventory found 359 Debian packages plus Maven, NuGet, gem, npm, and Go
components; its scan reported 1,025 matches: 12 High, 852 Medium, 151 Low,
10 Negligible. High matches included distro-provided setuptools, wheel,
commons-io, plexus-utils, rexml, webrick, net-imap, and node-undici packages.
These are untriaged observations, not accepted exceptions. The scan inventory
did not recover the compiled BHF Rust dependency graph, so it is not yet a
complete release SBOM. The exact image identity, complete feature-aware
inventory, disposition, and authenticated digest must be reconciled before
publication.
