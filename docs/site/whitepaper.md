<!-- SPDX-License-Identifier: Apache-2.0 -->
# One fuzzer for the whole codebase

### A white paper on bhf: automated, multi-language fuzzing for legacy and mission-critical software

---

## Summary

Fuzzing finds memory-safety and logic bugs, and adopting it takes work: a
person writes a harness for every entry point, gets the project building
under an instrumented toolchain, and repeats both for the next language. For
a legacy C, C++ and Ada estate (radar, avionics, RTOS, defence) that work
often stops the effort. For Ada, the established option is GNATfuzz, a
commercial tool that needs a buildable GNAT project.

**bhf automates that work.** Point it at a source tree and it discovers the
fuzzable entry points, generates typed harnesses, recovers the build when
there is none, and fuzzes across **sixteen languages: Ada, C, C++, Rust,
Java, Python, Perl, Go, COBOL, Fortran, C#, JavaScript, TypeScript, Ruby, Lua
and PHP**. It uses its built-in engine, or drives AFL++ on native C, C++,
COBOL, Fortran, Rust and Ada targets.

Head-to-head against the most-used fuzzer for C, Rust, Java and Ada, bhf
found the same planted bugs as each specialist tool with **no** hand-written
harness code (against 5 to 13 lines per target). It also fuzzed a target
with **no working build**, harnessed **185 targets of the miniz library from
one command**, and was the one tool in the group that fuzzes Ada.

The full numbers and a reproducible benchmark suite are in the
[comparison](comparison.md).

---

## The problem: setup cost

A fuzzer has two parts. The **engine**, the mutation strategy and coverage
feedback, is mature in AFL++, libFuzzer, LibAFL and Jazzer. The **plumbing**
is what a person does to point that engine at code:

1. **Write a harness** for each function to fuzz: decode raw bytes into the
   function's typed arguments, construct any receiver object, and call it.
2. **Get a working, instrumented build**: the right sanitizer-coverage
   flags, a nightly toolchain for some ecosystems, a `fuzz/` crate for
   others.
3. **Repeat** for each entry point and each language.

On a new service that is an afternoon's work. On a 30-year-old radar
codebase with hundreds of parsers across C, C++ and Ada, often without a
build that runs on a modern Linux host and sometimes buildable only with a
vendor RTOS toolchain, the plumbing is the obstacle, not the engine.

For **Ada**, the language of much safety-critical avionics and defence
code, AFL++ has no Ada front end and there is no libFuzzer or Jazzer;
GNATfuzz needs a GNAT Pro licence and a project that builds.

---

## The bhf approach: automate the plumbing

bhf automates all three steps in sixteen languages.

**Discovery.** It parses the whole tree and ranks fuzzable subprograms by
attacker reachability: parsers that take a byte channel score highest, and
getters and internal helpers rank lower, so the most exposed surface is
fuzzed first. One command found **185** fuzz targets in the miniz library.
See [Target Ranking](target-ranking.md).

**Typed harness generation.** For each target, bhf generates the harness a
person would have written. It decodes fuzz bytes into the real parameter
types and **constructs receiver objects** for instance methods, for example
a C++ class through a supported constructor or factory. You write no
`LLVMFuzzerTestOneInput`, `fuzz_target!` or `fuzzerTestOneInput`.

**Build recovery.** Legacy code rarely comes with a working build. With
`--probe-build`, bhf recovers the compile context (include paths, defines,
generated headers) from CMake, Meson, Make and autotools, Ninja or Visual
Studio projects. For any other build, such as Bazel, SCons, a bare
`build.sh` or a vendor RTOS build, `--build-command` runs it and intercepts
the actual compiler invocations to learn the flags. Both run the project's
own build scripts, so they are opt-in. When there is no build at all, bhf
synthesises one and repairs the gaps. RTOS application code that only a
Wind River, Green Hills or QNX toolchain can compile is fuzzed
**stub-isolated** on the host: bhf fakes the platform headers (`vxWorks.h`,
`INTEGRITY.h`, `sys/neutrino.h`) so the algorithmic code builds and fuzzes
with sanitizers.

**Engine choice.** The built-in engine is coverage-guided, with
cmplog/RedQueen comparison solving *on by default*. In the benchmark it
solved magic-byte, length and input-to-state gates from a cold start with
no configuration. `bhf auto --engine afl++` drives AFL++ instead, and
`bhf fuzz --engine` can also drive libFuzzer, honggfuzz and WinAFL.

**Sixteen languages, one engine.** Ada, C and C++ use typed direct
generators and the deepest build-repair loop. Rust and Java use native and
JVM builders. Python, Perl, JavaScript, TypeScript, Ruby, Lua and PHP use
persistent interpreter drivers, and Go, COBOL, Fortran and C# use their own
compiled or runtime paths. The `LD_PRELOAD` behavioural and taint layer runs
on the native Ada, C, C++, Rust, Go, COBOL and Fortran harnesses and in the
Python, Perl, Ruby, Lua and PHP interpreters. Java, C#, JavaScript and
TypeScript use their own coverage and crash or exception signals. See
[Vulnerability Coverage](vulnerability-coverage.md).

---

## The evidence

bhf ran against the most-used fuzzer for C, Rust, Java and Ada on identical
planted-bug targets: a parser with a bug reachable only past a gate, so the
engine's feedback has to work. The competitors ran in their **best**
configuration (AFL++ with a CMPLOG binary, libFuzzer with value profile).
The method and every raw number are in the [comparison](comparison.md). The
main results:

- **No harness code.** bhf needs **0 lines** of hand-written harness in each
  measured language. The alternatives need 5 to 13 lines *per target*:
  libFuzzer 6, AFL++ 13, cargo-fuzz 5, Jazzer 5.
- **Same bugs.** On every target, bhf found the planted bug the specialist
  tool found. Its built-in engine solved all three C gate classes from a
  cold start, including the input-to-state gate that needs cmplog, for which
  AFL++ needed a separate `-c` build and libFuzzer needed
  `-use_value_profile`.
- **Time to first crash from source.** From raw source to first crash,
  including discovery, build and fuzzing, bhf took **1.2 to 2.6 s**. The
  specialists' fuzz-only times were 0.5 to 1.9 s, starting from a pre-built
  harness that a person had already written.
- **Targets per command.** One `bhf auto` run harnessed **185** miniz
  targets. Writing those by hand is about 1,100 to 2,400 lines of harness
  code.
- **No working build needed.** bhf fuzzed code with **no working build**;
  each competitor needs one.
- **Ada.** bhf discovered an Ada subprogram, decoded its `String`
  parameter, built the GNAT harness and found a `CONSTRAINT_ERROR` with no
  options beyond the time budget. It was the one tool in the comparison that
  fuzzes Ada.

| | bhf | best alternative |
|---|---|---|
| Hand-written harness per target | **0 lines** | 5 to 13 lines |
| Languages | **16** (C, Rust, Java and Ada measured here) | one each |
| Targets per command | **all (185 on miniz)** | one |
| Fuzzes with no working build | **yes** | no |
| Fuzzes Ada | **yes** | no |
| Finds the planted bug | **yes, in each measured language** | yes |

---

## Where it matters: legacy, defence, RTOS

bhf targets legacy Ada, C and C++ code, including projects built for RTOS
platforms such as VxWorks, Green Hills INTEGRITY and QNX that a Linux lab
host cannot run directly. Its build recovery, vendor-toolchain interception
and RTOS platform stubs cut the manual work of making a host-side fuzz
target. It runs offline, treats scanned trees and child-process output as
untrusted, and writes JSON, SARIF, JUnit, Markdown and CSV reports.

---

## Measured scope

On the C, Rust, Java and Ada fixtures measured here, bhf found the same
planted bugs as AFL++, libFuzzer, cargo-fuzz and Jazzer without a
hand-written harness, and it was the one tool that exercised the Ada
target. The results hold for the pinned fixtures and budgets in the
[comparison](comparison.md). For bhf's engine against AFL++, libFuzzer and
honggfuzz on identical targets, see the
[Engine Benchmark](engine-parity-benchmark.md).

---

*Reproduce every figure with the scripts in
[benchmarks/](../../benchmarks/README.md). Measurements used
clang/libFuzzer 18, AFL++, cargo-fuzz 0.13 (Rust nightly), Jazzer and
GNAT/gprbuild on 6 vCPUs and 13 GB of RAM.*
