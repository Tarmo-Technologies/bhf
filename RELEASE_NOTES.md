<!-- SPDX-License-Identifier: Apache-2.0 -->

# BHF v0.2.32 release notes

Released 2026-09-14.

**This is a security release. Upgrade if you run bhf against code you do not
control.** 0.2.31 had two separate ways for a scanned tree to execute commands on
the host running `bhf auto` — both in default mode, with no opt-in flag required and
no error surfaced. The run exits 0, prints a normal summary, and reports 0 findings.

There are no behavioral changes beyond the fixes. Well-formed build configuration
from every affected source is honored exactly as before.

## The trust boundary

`bhf auto` reads two files straight out of the scanned tree, by design and without
any flag: an auto-loaded `.bhf.toml`, and the project's own `compile_commands.json`.
Both vulnerabilities live there. They are different defects with different fixes,
and **neither fix closes the other**.

## 1. Command injection into the generated Makefile

GHSA-725h-95qg-44fv · CWE-78

Values from those files were interpolated into the harness Makefile unescaped, and
`make` hands its recipes to `/bin/sh`.

| | Source | Sink |
|---|---|---|
| V1 | `.bhf.toml` `cxx-std` | `CXX_STD ?=` → `-std=$(CXX_STD)` |
| V2 | `compile_commands.json` `-std=` | `CXX_STD ?=` → `-std=$(CXX_STD)` |
| V3 | `compile_commands.json` compiler | `CXX =` — heads every recipe line |

V1 is the reported vector. V2 and V3 were found while remediating it. **V2 needs no
`.bhf.toml` at all** — an ordinary compile database is enough — so a fix aimed only
at the reported vector would have left an equivalent primitive in place.

### Root cause

One pattern, not three bugs. `split_{c,cpp}_build_context_flags` pull values back
out of the internal `@bhf-build-context-*` pseudo-flags and interpolate them with no
escaping, while validation only ever inspected the **prefixed** form — where the
single-quote relaxation that exists for legitimate CMake defines
(`-DLLAMA_VERSIONS=>=3`) makes `@bhf-...=c++17; id` look acceptable.

The `-std=` path compounds it: `encoded_flags` deliberately *removes* the flag from
`compile_flags` so it can drive the Makefile's single `CXX_STD` knob — which also
removes it from `escape_makefile_recipe_flag`, the function that would have quoted
it.

### The fix

Validation moved to the emission boundary, where every producer converges.

- **C++ standard** — a closed set: `c++`/`gnu++` plus a two-to-three character
  alphanumeric version beginning with a digit. Accepts every real selector including
  the draft forms `c++0x`, `c++1y`, `c++2a`; admits no separator. The previous check
  tested only the `c++` prefix, which `c++17; id` satisfies.
- **`CC` / `CXX`** — held to the strict bare-token rule. The quoting relaxation for
  compile flags must not reach a value that heads a recipe.
- **Build-context metadata** — `BUILD_CONTEXT_PROVENANCE` and friends are
  neutralised. Not an active vector, but written as `NAME = <value>`, where a
  newline would end the assignment and let the remainder parse as Makefile source.
- **Ada `.gpr` projects** — the same treatment adapted to GPR syntax. A `.gpr` is
  not a shell, so spaces and parentheses stay legal — a Windows source directory
  needs them — and only a quote, newline, or control character is refused.

## 2. Execution of an untrusted compiler from the scanned tree

CWE-829 · reported against the retired `govfuzz` project as GHSA-2352-w7c6-wr67

bhf executes the compiler named by the tree's compile database — as `$(CC)`/`$(CXX)`
under make, in the standalone-header preflight, and in the libstdc++ probe. The only
check was that the token's file name **contained** `clang`, or equalled `gcc`/`g++`.
The path was never verified to be a real toolchain.

A tree that ships an executable beside its sources and points the database at it ran
its own program on the host. Because the shim can exec the real compiler after its
payload, the build succeeds and the run looks entirely normal.

**No metacharacter is involved.** `./evilclang` is a well-formed path containing
nothing a shell acts on, so every rule added for the injection class above passes it
through untouched. Four deliveries were confirmed, including a tree binary named
**exactly** `clang`, which defeats any name-based check.

### The fix

The compile database may influence *which* compiler is used, never *where it comes
from*:

- the leaf must be a real driver name, matched exactly after stripping a version
  suffix (`gcc-12`) and a target-triple prefix (`aarch64-linux-gnu-gcc`).
- a **bare name** is left as written — it carries no directory, so the operator's
  PATH decides, and the generated Makefile stays readable for a hand rebuild.
- an **absolute path outside the scanned tree** is honored, so a cross or custom
  toolchain (`/opt/toolchain/bin/g++-12`) keeps working. That is ordinary for the
  hard-to-build trees bhf targets, and the operator installed it.
- a **relative path**, or an absolute path **inside the tree**, is refused. `auto`
  publishes the canonical sweep root, and the working directory is always treated as
  untrusted, covering `cd repo && bhf auto .`.

## Both fixes: what a rejected value does

It falls back to the built-in default rather than failing the run. The tree's build
system is untrusted input, not an operator instruction, and a project whose compile
database carries a malformed dialect should still get fuzzed. A malformed
`--cxx-std` still errors, because that file claims to configure the run and a silent
downgrade would hide it.

## Diagnostics

**A killed Rust harness build is no longer reported as a compile error.** cargo's
stderr classifier falls back to the tail of the output, reached only when there is
no error line at all — precisely what a build killed by a signal leaves behind. It
reported whichever crate happened to be compiling, naming a crate that had not
failed and could not be reproduced. Progress lines no longer stand in for a
diagnosis, the exit status (including the signal) is reported, and the raw stderr —
previously discarded at both cargo failure sites — is persisted to
`<work>/harnesses/<id>/cargo-build-stderr.log`.

**ThreadSanitizer no longer reports a harness race-free when it saw a race it could
not place.** A report whose frames carry no `file:line` is unreadable, not evidence
of a scaffolding race, and was dropped without being counted. It is now surfaced as
`unattributed`. A report that *does* resolve to only the bhf driver or a system
library is still dropped, as intended.

## Dependencies

`rustls` moves to 0.23.45 for RUSTSEC-2026-0285, reaching the tree through `ureq` <-
`llm_harness_gen`. rustls 0.23.42 accepted TLS 1.3 handshake messages sent at the
wrong encryption level when they followed a key-changing message in the same record,
contrary to RFC 8446 §5.1. The handshake transcript remains authenticated, so this
is not a handshake-forgery primitive.

## Upgrading

No configuration change is required.

If you cannot upgrade immediately, remove `.bhf.toml` and `compile_commands.json`
from a tree before scanning it. Neither is a substitute for upgrading — other build
files feed the same context recovery.

## Credit

GHSA-725h-95qg-44fv was reported privately through GitHub Security Advisories with a
complete reproducer and an accurate root-cause analysis; V2 and V3 were identified
during remediation. The untrusted-compiler defect was reported against `govfuzz`,
also with a complete reproducer.
