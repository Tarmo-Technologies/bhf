<!-- SPDX-License-Identifier: Apache-2.0 -->

# BHF v0.3.0

Released 2026-10-05.

- The default CLI and daemon builds leave out LLM connectivity; build with the `llm` feature to include it.
- Native and container installers share language names, aliases, and dependency selection. `all` selects sixteen languages; an empty language selection or combining `all` with named languages is rejected before installation.
- Windows C/C++ default runs locate Clang's ASan DLL automatically. The driver reports unhandled exceptions and lets exceptions handled by ASan or the target continue.
- When every attempted fuzz pass fails, `auto` keeps the runtime error in `auto/run.json`. A run with no successful target and no finding exits nonzero.
- Persistent-harness waits and RedQueen setup honor the fuzz-pass budget. Timeout cleanup terminates the harness process group, so a descendant cannot hold an output pipe open and stall the campaign after its deadline.
- README and CLI help show a one-target first run, compiler prerequisites, and the findings and blocked-target reports. Offline installation verifies the complete archive before extraction and needs an operator trust policy (`install.sh --trust-policy`, see [INSTALL.md](INSTALL.md)).
- `bhf auto` keeps at most 64 MiB of corpus per target (`--max-corpus-mb`) and stops starting targets when the work directory reaches 4 GiB (`--max-work-dir-mb`). `bhf clean <work-dir> --compact` keeps findings and replay evidence. `--resume` reuses completed targets when the source, build context, and harness options are unchanged.
- The default container includes all sixteen supported languages without LLM integration. `--languages` narrows a run; `--flavor core` or `--flavor ada` selects a smaller image. Validation sweeps start only under the `validation` Compose profile.
- Each container profile passes its acceptance run as non-root, on a read-only filesystem, with no network. The Java coverage agent ships prebuilt; Maven, Gradle, Cargo and MSBuild project builds need `--run-untrusted` and use staged dependency caches.
- One release path produces the binary, source and image identity records, a compiler-backed Cargo inventory, a whole-image scan, the corresponding sources, and an authenticated offline handoff. Packaging stops when acceptance evidence has failed or is stale.
- The release campaign over 100 projects measured 98 on the original release candidate; the two that timed out were measured by reruns after the fix. [`evidence/v0.3.0/README.md`](evidence/v0.3.0/README.md) describes the evidence archive.
- [Running bhf in Docker](docs/site/docker.md) lists the deployment profiles and the tested limits of Windows collectors, private Rust, RTOS emulation, and physical hardware.

## Previous release: v0.2.34

Released 2026-10-01.

This release teaches `bhf binary scan` to look inside Debian packages, makes the `afl-qemu` binary-fuzz engine honor its timeout and expose a memory limit, and adds AFL++ binary-only (QEMU/Frida) modes to `bhf fuzz`. Existing invocations behave as before.

### `binary scan` recurses into `.deb` packages and tar archives

A Debian `.deb` is an `ar` archive whose payload lives in a compressed `data.tar.*` member. `bhf binary scan` recognized the outer `ar` container but never decoded that member, so scanning a `.deb` that contained one ELF reported `0 files inventoried`.

The scan now decompresses `data.tar.*` / `control.tar.*` members (gzip, xz, and zstd), walks the tar, and inventories each contained binary with nested-container provenance recorded in its path, for example `pkg.deb!data.tar.zst!usr/bin/foo` (the containing archive is its `container_path`, the in-tar path its `member_name`). The decoders are pure Rust (`flate2`'s `rust_backend`, `lzma-rs`, `ruzstd`), so no external `tar` / `dpkg` is required and the RHEL 7, Windows MSVC, and cross build matrices stay free of a C toolchain. Decompression is size-capped (`--max-bytes`, otherwise 1 GiB) and nesting is depth-bounded, so a decompression or recursion bomb is skipped instead of exhausting memory. Tar entry paths are used only as in-memory labels; nothing is written to disk.

### `binary fuzz --engine afl-qemu`: real timeout, child memory limit

`bhf binary fuzz --engine afl-qemu` documented `--timeout-ms` as the per-execution timeout but never passed it to `afl-fuzz`, so the mutation campaign auto-calibrated its own timeout while only the crash-replay oracle honored the flag. `--timeout-ms` is now threaded to `afl-fuzz` as `-t`, so the campaign and the replay oracle share one policy.

A new `--mem-mb <MiB|none>` flag sets the AFL child memory limit (`afl-fuzz -m`). It defaults to `none` because QEMU mode maps a large virtual address space and a tight cap aborts the campaign before a testcase is preserved. Both effective limits are recorded in the run-provenance JSON.

### `bhf fuzz --engine afl++`: QEMU/Frida binary-only modes

`bhf fuzz --engine afl++` could only drive a compile-time-instrumented harness, so a stripped, source-less library the harness `dlopen`s got no coverage. Three new flags expose AFL++'s binary-only execution:

- `--afl-mode native|qemu|frida` — `native` (default) keeps compile-time instrumentation byte-for-byte; `qemu` runs the target under AFL++ QEMU mode (`afl-fuzz -Q`) and `frida` under Frida mode (`-O`), adding coverage inside the dependency without rebuilding it.
- `--afl-path DIR` — point at an AFL++ install that is not on `PATH`; sets `AFL_PATH` and locates `afl-fuzz`, so QEMU/Frida mode finds `afl-qemu-trace` / `afl-frida-trace.so`.
- `--afl-inst-range RANGE` (repeatable) — scope binary-only instrumentation to a module or address range, joined into `AFL_QEMU_INST_RANGES` / `AFL_FRIDA_INST_RANGES`.

The effective mode, path, and ranges are recorded in `run.json`. The [CLI reference](docs/site/cli.md) lists the new flags of all three commands.

### Maintenance

- The `bhf_runtrace_shim` LD_PRELOAD interposer compiles under rustc 1.99, which made `invalid_runtime_symbol_definitions` deny-by-default and flagged the shim's standard fixed-arity `open(path, flags, mode_t)` override.
- The `bhf PR` dogfood workflow passes when a change has no auto-harnessable targets. A build, link or runtime failure, a panic, or a confirmed finding still fails it.
- The `cargo-minor-and-patch` dependency group was bumped (including `thiserror` 2.0.21).

### Upgrading

No configuration change is required.
