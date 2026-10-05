<!-- SPDX-License-Identifier: Apache-2.0 -->

# BHF v0.2.35 release candidate

Unpublished. Exact-revision CI, image acceptance, scan review, and protected
publisher signing determine release eligibility; this heading is not approval.

- Default CLI/daemon exclude LLM connectivity, with explicit opt-in builds.
- The default container includes all sixteen supported languages without LLM
  integration. `--languages` explicitly narrows a run; `--flavor core` or
  `--flavor ada` selects a smaller image. Validation sweeps require explicit startup.
- Read-only, non-root, disconnected acceptance covers the selected profile.
  Java's agent is prebuilt; project builds require consent and staged caches.
- Binary/source/image identity, compiler-backed Cargo inventory, whole-image
  scanning, corresponding sources, and an authenticated offline handoff now have
  a common release path. Failed or stale acceptance evidence blocks packaging.
- See [deployment support boundaries](docs/site/docker.md) for the exact limits
  of Windows collectors, private Rust, RTOS emulation, and physical hardware.

## Previous release: v0.2.34

Released 2026-10-01.

This release teaches `bhf binary scan` to look inside Debian packages, makes the
`afl-qemu` binary-fuzz engine honor its timeout and expose a memory limit, and
adds AFL++ binary-only (QEMU/Frida) modes to `bhf fuzz`. There are no breaking
changes; every existing invocation behaves as before.

## `binary scan` recurses into `.deb` packages and tar archives

A Debian `.deb` is an `ar` archive whose payload lives in a compressed
`data.tar.*` member. `bhf binary scan` recognized the outer `ar` container but
never decoded that member, so scanning a `.deb` that contained one ELF reported
`0 files inventoried`.

The scan now decompresses `data.tar.*` / `control.tar.*` members — gzip, xz, and
zstd — walks the tar, and inventories each contained binary with
nested-container provenance recorded in its path, for example
`pkg.deb!data.tar.zst!usr/bin/foo` (the containing archive is its
`container_path`, the in-tar path its `member_name`). The decoders are pure Rust
(`flate2`'s `rust_backend`, `lzma-rs`, `ruzstd`), so no external `tar` / `dpkg`
is required and the RHEL 7, Windows MSVC, and cross build matrices stay free of a
C toolchain. Decompression is size-capped (`--max-bytes`, otherwise 1 GiB) and
nesting is depth-bounded, so a decompression or recursion bomb is skipped rather
than exhausting memory, and tar entry paths are used only as in-memory labels
(nothing is written to disk, so there is no path-traversal surface).

## `binary fuzz --engine afl-qemu`: real timeout, child memory limit

`bhf binary fuzz --engine afl-qemu` documented `--timeout-ms` as the
per-execution timeout but never passed it to `afl-fuzz`, so the mutation
campaign auto-calibrated its own timeout while only the crash-replay oracle
honored the flag. `--timeout-ms` is now threaded to `afl-fuzz` as `-t`, so the
campaign and the replay oracle share one policy.

A new `--mem-mb <MiB|none>` flag sets the AFL child memory limit (`afl-fuzz -m`).
It defaults to `none` because QEMU mode maps a large virtual address space and a
tight cap aborts the campaign before a testcase is preserved. Both effective
limits are recorded in the run-provenance JSON.

## `bhf fuzz --engine afl++`: QEMU/Frida binary-only modes

`bhf fuzz --engine afl++` could only drive a compile-time-instrumented harness,
so a stripped, source-less library the harness `dlopen`s got no coverage. Three
new flags expose AFL++'s binary-only execution:

- `--afl-mode native|qemu|frida` — `native` (default) keeps compile-time
  instrumentation byte-for-byte; `qemu` runs the target under AFL++ QEMU mode
  (`afl-fuzz -Q`) and `frida` under Frida mode (`-O`), adding coverage inside the
  dependency without rebuilding it.
- `--afl-path DIR` — point at an AFL++ install that is not on `PATH`; sets
  `AFL_PATH` and locates `afl-fuzz`, so QEMU/Frida mode finds `afl-qemu-trace` /
  `afl-frida-trace.so`.
- `--afl-inst-range RANGE` (repeatable) — scope binary-only instrumentation to a
  module or address range, joined into `AFL_QEMU_INST_RANGES` /
  `AFL_FRIDA_INST_RANGES`.

The effective mode, path, and ranges are recorded in `run.json`. All three
commands' new flags are now in the CLI reference (`docs/site/cli.md`).

## Maintenance

- The `bhf_runtrace_shim` LD_PRELOAD interposer compiles under rustc 1.99, which
  made `invalid_runtime_symbol_definitions` deny-by-default and flagged the
  shim's standard fixed-arity `open(path, flags, mode_t)` override.
- The `bhf PR` dogfood gate now treats "no auto-harnessable changed targets" as a
  pass instead of a tool/setup failure (a real build/link/runtime failure, panic,
  or confirmed finding still fails).
- The `cargo-minor-and-patch` dependency group was bumped (including `thiserror`
  2.0.21).

## Upgrading

No configuration change is required.
