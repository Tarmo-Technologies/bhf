<!-- SPDX-License-Identifier: Apache-2.0 -->
# Ada-4 vendored-runtime re-run, 2026-11-18

This record re-runs, by name, every Ada target that the 2026-07-28 campaign
sweep (`results-0728`) failed to build because a GNAT predefined unit "depends
on itself". That is the Ada-4 class of [expected-gaps.md](../expected-gaps.md).
The project is re-run at the commit that sweep measured. The bhf under test is
a release build of the wave-12 branch, which leaves the GNAT predefined units
to the compiler's runtime (#356).

The rows are under `benchmarks/campaign-2026-07-25/`:

| Directory | What it is |
|---|---|
| `results-0728/` | Before: the 2026-07-28 sweep |
| `results-1118-ada4/` | After: the 9 targets, in 1 project |

## Reproduce

```sh
cd benchmarks/campaign-2026-07-25
BHF_BIN=<bhf> python3 go1_rerun.py results-0728 results-1118-ada4 \
  --lang ada --class Ada-4
```

The July rows record an Ada target's failed build without its reason, so the
script gives each one the cause most of its row's failed builds have, from
the row's blocker histogram. In this row that is the Ada-4 diagnostic for all
9.

## Before and after

All 9 are in Lucretia/bare_bones, a freestanding x86 kernel that vendors its
own GNAT runtime (`System`, `Ada`, `Interfaces` and their children, built for
no operating system). The July rows count `Vga_Console.Put`'s two overloads
as two targets; the re-run attempts the name once, so the table counts
subprograms.

| | Before | After |
|---|---:|---:|
| Subprograms re-run | 8 | 8 |
| Failed build: a predefined unit depends on itself | 8 | 0 |
| Built and fuzzed | 0 | 7 |
| Built, the target not reached | 0 | 1 |

`Vga_Console.Put` builds and runs, but no input reached it: its harness
rejected every input it decoded.

The run reported 7 findings, all from the kernel's own hardware access run
as a host process: `Crash` dereferences the `System.Address` it is given, the
multiboot accessors read the structures at the addresses the boot loader
hands over, and the console writes the VGA text buffer at its fixed address.
On the board these are valid; on the host they are an `access check failed`
(1) and a `STORAGE_ERROR` for an erroneous memory access (6).

## What it took

bhf staged an instrumented copy of every Ada unit in the tree, the vendored
runtime included. gprbuild compiled those copies in place of the host
compiler's runtime, whose other units they do not match, and stopped at
`predefined unit depends on itself` (or at an `s-stalib.adb` that "must be
compiled"). A unit named `Ada`, `System`, `Interfaces` or `GNAT`, or a child
of one, by its declaration or by GNAT's file-name convention for them
(`a-`, `s-`, `i-` and `g-` prefixes, and `interfac.ads`), is now left
unstaged, and the log says so: here, 30 units. The build uses the host
compiler's runtime, as a host build of the project would.
