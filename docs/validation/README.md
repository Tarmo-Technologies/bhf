<!-- SPDX-License-Identifier: Apache-2.0 -->

# Validation records

Each page here records a validation campaign or re-run: what was run, on
which commit or release, and what it found. The pages are dated and describe bhf as it was
on that date; the [user guides](../site/index.md) describe current
behaviour. The four `*-2026-09-25.json` files in this directory are
machine-readable test records from 2026-09-25;
[Scheduler reliability](../scheduler-reliability.md) and the
[portability repair record](../portability-hardening-2026-09-25.md) cite
two of them.

## Real code and legacy builds

| Record | What it records |
|---|---|
| [Real codebases, 2026-05-12](2026-05-12-real-codebases.md) | Ada and IDL discovery, instrumentation and fake CORBA generation on five public repositories |
| [Broken builds in real code, 2026-06-08](2026-06-08-real-code-broken-builds.md) | `scripts/validation/real-code-matrix.py`: build recovery on real projects with broken builds |
| [Defense-domain recovery, 2026-06-15](2026-06-15-dod-domain-recovery.md) | Offline runs on flight software, crypto, radio and radar DSP codebases |
| [Legacy breakage matrix, 2026-07-19](2026-07-19-legacy-breakage-matrix.md) | Thirteen scenarios that delete a required source, header or Ada child-unit body |
| [Expanded legacy breakage matrix, 2026-07-19](2026-07-19-expanded-legacy-breakage-matrix.md) | 53 pinned legacy C, C++, Ada and mixed projects, unmodified and damaged |
| [Legacy C, C++ and Ada offline, 2026-07-19](2026-07-19-legacy-c-cpp-ada-offline.md) | 37 repositories cloned online, then run with no network |
| [Post-update sweep, 2026-07-21](2026-07-21-major-updates-sweep.md) | 53 projects after the RHEL 7 and C/C++ driver changes |
| [Zero-fuzz remediation, 2026-07-23](2026-07-23-zero-fuzz-remediation.md) | The checklist of fixes for a legacy Ada/C/C++ sweep that fuzzed no target, with each item's status and proof |
| [Memory scaling, 2026-07-20](2026-07-20-memory-scaling-benchmarks.md) | Indexing, static analysis and fuzzing memory on trees up to Linux's 26.5M lines |
| [Fuzzer research and dogfood, 2026-07-01](2026-07-01-fuzzer-research-dogfood.md) | A review of the fuzzing ecosystem and a broad run of bhf on real projects |

## Static rules

| Record | What it records |
|---|---|
| [BHF-512 framework raw-HTML sweep, 2026-07-07](2026-07-07-bhf512-framework-html-sweep.md) | The JavaScript raw-HTML sink rules over 50 projects |
| [BHF-544 log injection, 2026-07-07](2026-07-07-bhf544-log-injection-sweep.md) | The CWE-117 log-injection taint rule |
| [BHF-545 GraphQL injection, 2026-07-08](2026-07-08-bhf545-graphql-injection-sweep.md) | The Python CWE-943 GraphQL-injection rule |
| [Next.js generated-bundle pruning, 2026-07-08](2026-07-08-nextjs-static-scan-generated-pruning.md) | The fix for the `next` static-scan timeout |

## Platforms, packages and containers

| Record | What it records |
|---|---|
| [RHEL 9 on Proxmox, 2026-07-20](2026-07-20-rhel9-proxmox.md) | A glibc mismatch in the Ubuntu-built binary, then a source build, the offline package and its installer on RHEL 9 |
| [RHEL 7 on Proxmox, 2026-07-21](2026-07-21-rhel7-proxmox.md) | The release binaries and the C/C++ lane on CentOS 7.9 |
| [Linux and Windows platform matrix, 2026-07-21](2026-07-21-current-platform-matrix.md) | Current RHEL, Ubuntu LTS, Windows and Windows Server versions |
| [Docker sweep, 2026-09-24](2026-09-24-docker-sweep.md) | The production image over 32 projects, two per language |
| [RTOS and container, local, 2026-10-04](2026-10-04-rtos-container-local.md) | The FreeRTOS reference profile on QEMU and the `core` image under `--network none`, from a local tree |
| [Language-selection images, 2026-10-05](2026-10-05-language-selection-results.md) | Container images built with a subset of languages |
| [Windows installer, 2026-10-05](2026-10-05-windows-installer-results.md) | The CLI and daemon installers on three Windows guests |
| [0.3.0 qualification checkpoint, 2026-10-05](2026-10-05-qualification-checkpoint.md) | The packaged install-and-run workflows and a 100-project campaign |
| [LLM and MCP, 2026-07-20](2026-07-20-llm-mcp-validation.md) | The optional LLM assistance and the MCP service |

## Embedded and full-system emulation

| Record | What it records |
|---|---|
| [Emulator in the loop, live QEMU, 2026-09-27](2026-09-27-hil-emu-live-qemu.md) | `scripts/hil-emu.sh` with every tool required |
| [Reference agent on FreeRTOS, 2026-11-18](2026-11-18-freertos-agent.md) | `c_runtime/bhf_agent.c` as a FreeRTOS task under QEMU |
| [Reference agent on Zephyr, 2026-11-18](2026-11-18-zephyr-agent.md) | The same agent on Zephyr v3.7.0 under QEMU |
| [Full-system persistent loop, 2026-11-19](2026-11-19-fullsystem-persistent-loop.md) | `reset=persistent` on the `qemu-system:` lane |
| [Full-system fast snapshot, 2026-11-19](2026-11-19-fullsystem-fast-snapshot.md) | `reset=fast`, the dirty-page snapshot |

## Re-runs of measured gaps

Each of these re-runs, by name, the targets of one class in
[Measured gaps](../expected-gaps.md) from the 2026-07-28 sweep, except the
zoxide record, which re-runs one row of the harness-parity audit.

| Record | What it records |
|---|---|
| [Go lane re-sweep, 2026-11-16](2026-11-16-go-resweep.md) | The 40 Go projects of the sweep at the same commits |
| [Go targets outside a module (Go-3), 2026-11-16](2026-11-16-go3-loose-packages.md) | Go targets with no `go.mod` |
| [Java collection parameters (Java-1), 2026-11-16](2026-11-16-java1-collections.md) | Java parameters of collection types |
| [Rust-1 and Rust-4, 2026-11-17](2026-11-17-rust-trait-and-param-classes.md) | Rust parameters with no byte decoder, and static methods of another crate's trait |
| [zoxide in-crate parity, 2026-11-17](2026-11-17-zoxide-incrate-parity.md) | The zoxide harness-parity row with the in-crate Rust lane |
| [Ada-3 withed projects, 2026-11-18](2026-11-18-ada3-withed-projects.md) | Ada units that "cannot belong to several projects" |
| [Ada-4 vendored runtime, 2026-11-18](2026-11-18-ada4-vendored-runtime.md) | GNAT predefined units that "depend on" themselves |
| [C-3 K&R C, 2026-11-18](2026-11-18-c3-knr.md) | Old-style C definitions |
| [JS-2 browser globals, 2026-11-18](2026-11-18-js2-browser-globals.md) | JavaScript and TypeScript targets that use `window` and other browser globals |
| [Py-2 receivers, 2026-11-18](2026-11-18-py2-receivers.md) | Python methods whose class `__init__` takes arguments |
