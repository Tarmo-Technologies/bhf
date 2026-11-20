<!-- SPDX-License-Identifier: Apache-2.0 -->
# Portability and daemon-framing repair (2026-09-25)

Base: `30ee685cfe94138dd6d3626d3dee09b24796589f` on `rtos-radar-fuzzing`. The machine-readable record of the test runs is [validation/portability-2026-09-25.json](validation/portability-2026-09-25.json).

## Installer: no-clobber publish on old glibc

On Linux, `publish_pack_stage` (`crates/governance/src/lib.rs`) calls `SYS_renameat2` through `libc::syscall` instead of glibc's `renameat2` wrapper, which glibc 2.17 (RHEL 7) lacks. It keeps `RENAME_NOREPLACE` and returns the operating system's error. When the kernel or filesystem does not support the call, publication fails; there is no fallback to an ordinary rename or a check-then-overwrite. Publication on other platforms is unchanged.

Tests call the publication helper itself and cover: a complete publication; an existing empty directory (its inode is kept); a nonempty directory; a file; a dangling symlink at the destination; an absent source; a path with a NUL byte; and two publishers racing, of which exactly one wins.

The `rhel7-build` CI job runs `cargo test --locked -p governance --lib` in a manylinux2014 container (glibc 2.17) before its offline-distribution and release build steps. The container uses the hosted runner's kernel.

## Daemon framing

The daemon's frame reader rejects a duplicate `Content-Length` header (header names compare case-insensitively) and a non-decimal length. Tests cover a body exactly at the limit, a body one byte over, duplicate headers, and malformed lengths.

The compact-error regression test now sends a path-independent request whose serialized body fits the 512-byte test limit on every platform; the earlier version embedded a temporary file path that could exceed it on Windows. The test checks that the ordinary response does not fit and that the compact error and the next frame are handled. The 512-byte test limit and the production limits are unchanged.

## Test runs

Actions run `36192874457` (setup revision `0f4a3043f0aef6b98c63c4660d1627e08289449b`) applied the edits to the exact original Git blobs and ran:

| Environment | Suites | Result |
| --- | --- | --- |
| Ubuntu 24.04 | Governance, daemon, CI policy / Bash behavior / workflow contracts | Passed |
| Windows Server 2022 | Governance, daemon, platform-neutral CI acceptance policy | Passed |
| EL7-compatible container, glibc 2.17 | Governance | Passed |

The Linux and Windows test counts differ because some tests, including the Linux publication tests, are platform-gated. The Linux CI Bash and mock suite runs only on Ubuntu, as in the production CI policy jobs. The Linux and Windows source patches were identical after newline normalization, and the downloaded artifact ZIPs matched GitHub's reported SHA-256 digests (the JSON record lists them).

The tested edits are Git tree `1f0b542592abe021ffb5cb04c832391e73e20c8f` in commit `22467267adeb99c6c69867bdef8dcac5c8bb77b2`.

## Reproduce

On a supported Rust host:

```sh
cargo test --locked -p governance --lib
cargo test --locked -p bhf-daemon --lib
```

[CI acceptance](ci-acceptance.md) documents the CI policy test commands and the Linux shell-fixture scope.
