<!-- SPDX-License-Identifier: Apache-2.0 -->

# C and C++ Fuzzing

bhf finds C and C++ functions, generates direct-call and lifecycle-sequence
harnesses for them, builds the harnesses with sanitizers and coverage, and
fuzzes them through the same reporting pipeline as `bhf auto`.

## Quick Start

To sweep a whole source tree:

```sh
bhf auto path/to/src --work-dir bhf_work --per-target-time 60
```

To work on one C++ function by hand:

```sh
bhf list targets path/to/src --top 20
bhf generate-harness path/to/src/parser.cpp \
  --target Parser::parse \
  --output bhf_work/harnesses
bhf build bhf_work --harness H-CPP000A
bhf fuzz bhf_work --harness H-CPP000A --iterations 1000 --seed-input smoke
```

Use the harness id that `generate-harness` prints. `bhf list targets` and
`bhf auto` give stable ids starting `H-C` for C and `H-X` for C++.
`bhf generate-harness` without `--id` names the harness `H-C` or `H-CPP`
followed by the target's line number as four hex digits (`H-CPP000A` for a
function on line 10). Generate into `<work>/harnesses/`, where `bhf auto` puts
its harnesses; `bhf explain` and `bhf capsule` read harnesses from there.

`bhf fuzz` prints a progress line on stderr 2 s into the run, then at
doubling intervals up to every 30 s (`--quiet` turns them off), and its JSON
summary on stdout at the end.

To write the harness yourself, wrap an existing `LLVMFuzzerTestOneInput`, or
edit a generated harness, see [Custom C and C++ Harnesses](custom-harness.md).

## Prerequisites

- `make`
- `clang` for C harnesses and `clang++` for C++ harnesses, or another
  compiler named with `CC`/`CXX` or `--cc`/`--cxx`
- a working C++ standard library for C++ harnesses
- sanitizer support for `-fsanitize=address,undefined` and
  `-fsanitize-coverage=trace-pc-guard,trace-cmp`; the libFuzzer runtime
  (`-fsanitize=fuzzer`) only for the optional `make libfuzzer` build
- `afl-fuzz` and `afl-clang-fast` / `afl-clang-fast++`, only for AFL++
- on Linux, for runtime virtualisation, the runtrace shim
  `libbhf_runtrace_shim.so` (the build also stages a copy named
  `libbhf_runtrace.so` beside the `bhf` binary, which `bhf auto` prefers)

## Builds

Generated C/C++ harnesses are Makefile-based. Each Makefile target builds one
binary:

| Make target | Binary | Built by |
|---|---|---|
| `make` (default) | `main`: bhf's own driver (a framed fork server and a SanitizerCoverage runtime), with ASan and UBSan | `bhf build`, `bhf auto` |
| `make libfuzzer` | `main_libfuzzer`, for libFuzzer and other fuzzers (see the harness's `PORTABILITY.md`) | by hand |
| `make afl` | `main_afl`, for `bhf fuzz --engine afl++` | `bhf build --c-engine afl++`, `bhf auto --engine afl++` |
| `make afl_cmplog` | `main_afl_cmplog`, the same build under `AFL_LLVM_CMPLOG=1` | `bhf build --c-engine afl++`, `bhf auto --engine afl++` |
| `make symcc` | `main_symcc`, built with SymCC | `bhf auto --symcc` |

`main` is not a libFuzzer binary; `make libfuzzer` builds one.

**AFL++.** afl-fuzz runs with `-c main_afl_cmplog -l 2AT`, AFL++'s
input-to-state stage over the comparison operands it logs, which solves magic
values and checksums that no dictionary holds. When the CmpLog binary is
missing (its build failed, or it is older than `main_afl`), afl-fuzz runs
without `-c`, and bhf says so. `main_afl` has no bhf driver, so the
comparison evidence of an AFL++ finding (`finding.json` `gates`) is recorded
by replaying its input through the `main` beside it, which is built from the
same harness source.

**SymCC.** `make symcc` builds `main_symcc` with SymCC's `symcc` (C) or
`sym++` (C++): the harness and bhf's driver, without sanitizers or edge
coverage, under SymCC's own instrumentation. SymCC solves the branch
conditions of the input it runs and writes one input per branch it can flip
into `SYMCC_OUTPUT_DIR`. `bhf auto --symcc` builds it when the license
profile permits SymCC (see [Licensing](licensing.md)), at the language
standard `main` was built with (a `C_STD` dialect such as `gnu89` included),
with each compile-database unit compiled by SymCC as well. sym++ uses the
system C++ library (`SYMCC_REGULAR_LIBCXX=1`) unless `SYMCC_LIBCXX_PATH`
names a SymCC-instrumented libc++.

### Compilers and flags

When make's built-in compiler defaults are still `cc` and `g++`, the
generated Makefile and `bhf build` use `clang` and `clang++`. `CC`/`CXX`,
`--cc`/`--cxx`, or `[toolchain] cc`/`cxx` in a config file choose another
compiler, and the Makefile picks its instrumentation from the compiler that
actually runs:

- clang gets `trace-pc-guard,trace-cmp` coverage and the `function`/`vptr`
  UBSan subtractions;
- gcc (native or cross-prefixed, `.exe` included) gets `trace-pc,trace-cmp`
  and statically linked sanitizer runtimes.

bhf's own flags for the `main` build (optimization, debug info, sanitizers and
coverage) are the Makefile's `BHF_CFLAGS`/`BHF_CXXFLAGS`. A `CFLAGS` or
`CXXFLAGS` in the environment (a development shell or an SDK's setup script
often exports them) or on make's command line comes after them, so it adds
flags (a later `-O2` wins over bhf's `-O1`) and coverage and the sanitizers
stay. `--cflags`/`--cxxflags` (`toolchain.cflags`) are appended as well, and
their defines and include directories also reach bhf's driver object and the
other lanes. A hand-run `make BHF_CFLAGS=...` replaces bhf's flags.

The environment's `CFLAGS`/`CXXFLAGS` are written for your compiler (or the
host's), so they follow bhf's flags only in builds that use it: your
compilers, bhf's default clang, the gcc retry and a `--target-triple` sweep
you set up. They are left out, with a note, of a build whose compiler bhf
picked in place of yours: a platform guard's cross lane (a host-only
`-march=native` would fail the aarch64 build), and clang after your compiler
fails the `--sanitizers` check.

A compile database's compiler is only the Makefile's default `CC`/`CXX`; it
never overrides the compiler bhf or you select. `--sanitizers` keeps the
selected compiler when it builds a program with the requested sanitizers
whose runtime starts on this host (bhf links and runs a probe with `CC`, and
with `CXX` for a C++ harness); otherwise it says which compiler it uses
instead and why (see [Sanitizers](sanitizers.md)). A C translation unit of a
C++ harness is compiled with `CC` and takes flags spelled for `CC`'s family,
then `CFLAGS`. `--cflags` also reach bhf's driver object (without `-std=` and
`-Werror`; a C++ harness's driver takes `--cxxflags` too), so an
ABI-selecting flag such as `-m32` applies to the whole link. `CC=clang` in
the environment is bhf's own default, so `bhf auto` still retries a target
clang rejects with gcc, which it does not do for a compiler you chose.

### Fuzzing build mode

Every lane compiles the target with
`-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1`, OSS-Fuzz's convention, which
AFL++'s compiler wrappers also follow. A project tests this macro to skip
checksum and signature checks or to make randomness repeatable in a fuzz
build, so the builtin, coverage, MemorySanitizer, ThreadSanitizer,
differential and AFL++ lanes all fuzz the same program, and a reproducer
capsule rebuilds it the same way.

A finding past such a check may not reproduce in a production build. Each
fuzzed target's `fidelity.fuzzing_build_mode` in `run.json` (and each
finding's) says `on` or `off`. When a finding's crash path gets past a check
under `#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` in the same function,
or runs code under `#ifdef`, its `fuzzing_build_mode_note` (shown in
`results/findings.json` and INDEX.md) reads `reachable only with the check
under ... at <file>:<line> disabled`. `--no-fuzzing-build-mode` (on `bhf
auto` and `bhf build`) or `BHF_FUZZING_BUILD_MODE=0` builds without the macro,
and `make BHF_FUZZING_BUILD_MODE_FLAGS=` drops it from one hand-run build.

### Rebuild stamps

The `main` binaries depend on a toolchain stamp (`bhf_toolchain.stamp`), and
the MemorySanitizer, ThreadSanitizer, coverage and differential lanes on a
lane stamp of their own (`bhf_lanes.stamp`). Changing a compiler or its flags
in the same harness directory therefore relinks instead of linking stale
objects, and building a lane leaves the `main` stamp alone.

bhf's driver objects depend on a stamp of the compilers and flags they are
built with (`bhf_driver.stamp`). A dialect rung (`C_STD`/`CXX_STD`), a repair
round or a compatibility flag relinks the harness with the same driver
object; a new compiler, target, toolchain define or include directory, or
driver flag rebuilds it. A lane links `bhf_driver.o` itself when its driver
compile would be the same command as the main driver's: its compiler is `CC`
(`CXX` for C++) and no toolchain target, toolchain driver flags, or toolchain
defines and include directories apply (`--target`, `--cflags`, `--define`,
`--toolchain-include`). Otherwise it links a driver object built by its own
compiler.

## Discovery

`bhf scan`, `bhf list targets` and `bhf auto` read these files. By default
`auto` also skips non-library directories such as `tests/`, `tools/` and
`vendor/` (the full set, and `--include-dir`, are in [Auto:
Discovery](auto.md#discovery)), and `list targets` marks the rows it skips.

| File kind | Handling |
|---|---|
| `.c` | C parser |
| `.h` | C or C++ parser, selected from function counts and C++ markers |
| `.cpp`, `.cc`, `.cxx`, `.C` | C++ parser |
| `.hpp`, `.hh`, `.hxx` | C++ parser |

C/C++ ranking reads the signature. Byte buffers, string-like parameters,
pointer-plus-length pairs, parser-like names, error-code returns and few
parameters score higher. A call-graph pass then moves up entry-point functions
that call many other functions in the tree. [Target Ranking](target-ranking.md)
gives the weights.

`bhf auto --preprocess auto|always|never` controls the CPP-lite preprocessor
that discovery runs. `auto` (the default) preprocesses a file only when it has
a project macro context (a compile database's `-D` flags) and five or more
conditional directives; `always` preprocesses every C/C++ file, and `never`
parses the raw source. Preprocessing resolves `#ifdef`, `#ifndef`, `#if`,
`#elif` and `#else` branches, so a function compiled under the active
configuration is found and one compiled out is not, and a line map keeps
reported locations pointing at the original source.

An `#if` or `#elif` expression is evaluated as C evaluates it: integer
constants (decimal, octal, hex, binary, with `u`/`l` suffixes and `'`
separators), character constants, `defined`, every arithmetic, shift,
comparison, bitwise and logical operator, and `?:`. Object-like macros from the
file and the compile database expand; an identifier no macro defines is 0, and
an empty macro (`-DFLAG`) is 1. CPP-lite does not follow `#include` into
headers, so a macro a header defines reads as 0, and it does not expand
function-like macros. When an expression uses one, or anything else it cannot
evaluate, discovery keeps every branch of that `#if` chain and prints
`bhf auto: note: <file>: #if expression not evaluated at line N, every branch
kept: ...`. A function the compiler drops may then be listed (and fail to
build), and every function the compiler builds is still listed.

## Harness Generation

`bhf generate-harness` needs `--target` for a C or C++ source; it does not
pick a best target for these languages. For C++, each of these spellings
selects `widgets::Codec::decode`:

| Spelling | Example |
|---|---|
| Bare name | `decode` |
| Qualified suffix | `Codec::decode` |
| Fully qualified, as `bhf list targets` prints it | `widgets::Codec::decode` |
| Any of those with a parameter list | `Codec::decode(const unsigned char *, size_t)` |

An exact spelling wins over a suffix: a suffix is tried only when no
definition has exactly that name, so `Codec::decode` names a global `Codec`
even when `widgets::Codec` also exists. A leading `::` (`::Codec::decode`)
names the global namespace only. When a spelling matches several
definitions, bhf picks the first, prints all of them, and `--target-line N`
selects one. A spelling that matches nothing fails with the closest
definitions in the file. `bhf auto --target` accepts the same spellings.

### Generation flags

| Flag | Purpose |
|---|---|
| `--target <NAME>` | The function to harness, spelled as above. Required for C and C++ |
| `--target-line <N>` | Pick the definition at this 1-based line when several match |
| `--kind <direct\|sequence>` | `direct` (default) calls the target once; `sequence` drives a bounded operation loop (see [Supported C Parameter Shapes](#supported-c-parameter-shapes)) |
| `--output <DIR>` | Output directory (default `generated_harnesses`); the harness goes in `<DIR>/<id>/` |
| `--id <ID>` | Set the harness id, useful when overloads or line-based ids collide |
| `--extra-source <PATH>` | Add another C/C++ source file to the generated Makefile (repeatable) |
| `--extra-include <DIR>` | Add an include directory (repeatable) |
| `--cleanup <EXPR>` | Code to run after the target call; `R` names the return value (`--cleanup "if (R) json_value_free(R)"`). Replaces the built-in cleanup detection (cJSON, libxml2, parson, expat, ...) |
| `--template-instantiate <TYPES>` | Type arguments for a C++ function template whose call sites show no instantiation, comma-separated in parameter order (`int,std::string`) |
| `--max-decode-depth <N>` | Nesting depth of typed decoders (default 4); deeper fields stay zero |
| `--max-array-elems <N>` | Elements decoded per fixed array (default 64); a larger array fuzzes a `0..cap` fill count |
| `--max-decl-bytes <BYTES>` | Size ceiling of one parameter's decoder (default 65536); a larger one rejects the parameter |
| `--container-size-max <N>` / `--array-max-size <N>` / `--bitset-max-size <N>` | C++ bounds: a dynamic container's element count (default 16), the largest `std::array<T, N>` with `T` of unknown size (default 4096), the largest `std::bitset<N>` decoded bit by bit (default 4096) |

### Build defines without a compile database

A compile database (a checked-in `compile_commands.json`, or the one
`--probe-build` records by running the project's build) gives each file its
exact flags. Without one, bhf reads the nearest `CMakeLists.txt`, else
`Makefile`, without running it, and gives a C harness the `-D` and `-U`
defines it finds:

- **CMake:** `add_definitions`, `add_compile_definitions`, and the
  `target_compile_definitions` of the target that owns the file. Another
  target's defines are never combined with them.
- **Makefile:** `CPPFLAGS`, `CFLAGS`, `DEFS` and `DEFINES` assignments.

A define whose value only the build could compute (`-DVERSION=$(VERSION)`,
a generator expression) is left out. The harness Makefile records
`BUILD_CONTEXT_PROVENANCE = cmake_statically_recovered` (or
`makefile_statically_recovered`). Code behind `#ifdef ENABLE_TLV`, when the
build turns `ENABLE_TLV` on, is then compiled and fuzzed. When a harness still
needed made-up headers or macro values, the "Fabricated build context"
section of `run.md` names `--probe-build`.

### Paths with spaces and special characters

Source, include, extra-source, runtime and compiler paths may contain spaces,
parentheses, apostrophes, ampersands and the characters `* ? [ ] { } ~ !`.
The generated Makefile double-quotes such paths in recipes and never uses them
as make prerequisites, so a tree under `/home/Dana Smith/...`,
`/srv/R&D/...` or `C:/Program Files (x86)/...` builds like any other. A
compile flag the recipe shell would act on is single-quoted whole, with an
apostrophe written `'\''` (`'-I/home/Dana'\''s tree/include'`), so it
reaches the compiler as the one argument it was. That includes a quoted
string-macro define from the compile database (`-DNAME="value with
spaces"`): the compiler receives its double quotes, so the macro is a string
literal, and nothing inside the quotes is run as a command. A
`--differential` compiler given as a path with spaces is double-quoted like
the other paths.

Some characters no quoting makes safe, and bhf refuses them before
generation, naming the character:

- in a path: `$`, `#`, a backtick, a double quote, a backslash, `;`, `|`,
  `<` or `>`;
- in a compile flag: `$`, `#` or a control character, which `make` acts on
  before the shell sees the recipe (`#` ends the make variable the flag is
  assigned to);
- in the `[toolchain]` flags and defines (`--cflags`, `--define`, ...): only
  `$` or a control character, since they reach `make` through the
  environment, where `#` starts no comment.

On Windows, where `\` separates path components, `%` is refused instead of
the backslash, and `^` is quoted like `&`; see [Windows](windows.md) for how
flags are quoted there. In `bhf auto` such a target's outcome is
`unsafe_build_path` (counted as `summary.unsafe_build_path` in `run.json`, and
filed as an `unsafe-build-path` row in `bug-report.md`). Rename or move the
path; `--force` does not change the outcome.

### Compile databases

bhf detects sibling headers such as `parser.hpp`, local quoted includes,
nearby `include/` or `inc/` directories, and an existing
`compile_commands.json`. The database is searched in place and in the
conventional out-of-source build directories (`build/`, `builddir/`,
`cmake-build-debug/`, `cmake-build-release/`, `out/`) at every ancestor of
the source, so a database someone hands you is used without running any
build. Database entries contribute include paths, forced include files,
defines and undefines, `-std=...` and `-pthread` to the generated Makefile. A
forced include (`-include FILE`, `-imacros FILE`) is made absolute only when
the file exists relative to the entry's `directory`; otherwise it is kept as
written, so `-include iostream` still finds the system header through the
include search path.

A database written by an MSVC build (`cl.exe` or `clang-cl` rows, with `/I`,
`/D`, `/U`, `/FI`, `/std:c11`, `/J`, `/Zp4`, `/Zc:wchar_t-`, `/external:I`)
is read the same way. Each option with build semantics becomes its clang
spelling, backslash separators become `/`, and the rest (`/O2`, `/Zi`, `/MD`,
`/EHsc`, `/W4`, `/Fo...`, precompiled-header switches) is left out and named
in the Makefile's `BUILD_CONTEXT_DROPPED`. A `command` string is split by the
Windows command-line rules. The harness is still built with bhf's compiler
choice (clang, or cl with `--cc cl`), not the row's `cl.exe`.

### Visual Studio solutions

A tree with a `.sln`, `.slnx` or `.vcxproj` and no compile database or
CMake/Meson build is imported by default. Off Windows, this happens only when
the solution is the tree's only build description: a tree that also has a
Makefile, autotools inputs (`configure.ac`, `Makefile.am`), Ninja, SCons or
Bazel files, at its root or on the way to the solution, follows that build
unless `--msbuild-solution` names the solution.

The import reads the files and runs nothing. It takes the solution's
directory as `$(SolutionDir)`, follows each project's local `<Import>`s and
property sheets, evaluates `Condition=` for one configuration (the first
listed for x64, or `--msbuild-config Release|x64`), resolves `$(...)` from the
solution, the project files and the environment, and reads each `ClCompile`
item's include directories, defines, undefines, forced includes,
`LanguageStandard`, `AdditionalOptions`, `CharacterSet` (`UNICODE`/`_UNICODE`
or `_MBCS`) and `ExcludedFromBuild`. It prints the solution and configuration
it read. With several solutions it takes the shallowest (then the first by
path); `--msbuild-solution` picks another (relative to the scanned tree; a
solution outside it is imported too, and a missing file is an error).

A `$(...)` with no value leaves its include directory or define out, and the
run names it. MSBuild reads environment variables as properties, so setting
`MYSDK` supplies `$(MYSDK)`. The database is written to
`<work>/auto/msbuild/compile_commands.json`, never into the tree. On Windows,
each row also carries the import libraries (`ws2_32.lib`, found in `LIB`) its
own project links, which reach only that project's harnesses.
`--no-msbuild-import` turns the import off. MSBuild itself evaluates each
project (`msbuild -getItem:ClCompile`), when it is installed, only with
`--msbuild-evaluate`, `--probe-build` or `--run-untrusted`, since evaluation
runs the projects' property functions. See [Windows](windows.md) for the
Windows specifics.

### Fabricated build context

When the build context still leaves a header, a macro value or a type
undefined, the repair loop writes a placeholder (an empty header,
`#define NAME 0`, `typedef void *T`) so the target compiles. Code compiled
against a placeholder can take paths the real build never takes, so a finding
from it may be false or may need an input the real build rejects. The same
holds for a header found by its file name outside the scanned tree: a run on
a subdirectory of a checkout reads headers from the whole checkout, so in a
monorepo the header can be another project's, with that project's
definitions. A header from the scanned tree wins over such a header, and a
directory named with `--extra-include` is never counted.

Each such finding says so:

- its `finding.json` has `build.fidelity` (`{level: "reduced", context,
  fabricated: [{kind, name, value}]}`, with `kind` one of `macro`, `header`,
  `type` or `include_dir`) and an `actionability.confidence` of `low`;
- its normalized record has low confidence, with a note in INDEX.md, the
  `build_fidelity` column of `findings.csv`, and `bhf explain`;
- `run.json` lists the target's `build_fidelity` and counts such targets in
  `summary.fabricated_build_context`, and the console summary and `run.md`
  list them too.

Supply the real context (a compile database, `--extra-include`, `--define`)
and run again. A type the sources use without including its header (`cerr`
without `<iostream>`, a `uint32_t` without `<stdint.h>`, or a project type
the target's includes lead to one header for) is resolved by including that
real header. That is not a fabrication: the build keeps full fidelity, the
repair record in `run.json` carries `resolved_header`, and `run.json`
`targets[].real_headers_included` and `run.md` list it as `type cerr: real
header included (<iostream>)`.

### Link and compile hints from `bhf build`

`bhf build` compiles exactly the sources the Makefile lists; it has no repair
loop. When the link fails on symbols defined elsewhere in the tree, it prints
the defining files, the `--extra-source` flags to regenerate with, and an
`AUTO_EXTRA_SOURCES=... bhf build ...` command that needs no regeneration. It
looks for definitions around the target (the enclosing checkout, or the
project around a `src/` or `lib/` directory) and in the directories of the
harness's other inputs: every source its Makefile compiles, every include
directory it searches, and the `--extra-source`, `--extra-include` and
`--source-root` paths `generation-metadata.json` records. A harness kept
beside its library outside a checkout (`harness/` and `lib/`) therefore finds
the definition too.

It also suggests:

- `AUTO_EXTRA_INCLUDES='-include iostream'` for standard streams used without
  their header;
- for standard-library names that a pre-standard header writes without
  `std::` (`string`, `map`, `list`), relying on a `using namespace std;` in
  the sources that include it, a prelude header with their headers and
  `using std::` declarations (`<harness dir>/std_prelude.h`), which it writes,
  and the `-include` command for it (see [Custom
  harnesses](custom-harness.md#headers-that-rely-on-using-namespace-std)). A
  later build adds the new names it reports to that file and keeps the other
  lines. `bhf auto` writes the same prelude itself when a harness build fails
  on such names, force-includes it into every translation unit of that
  harness, and builds again (see [Auto: Repair
  Synthesis](auto.md#repair-synthesis));
- `-fms-extensions` (clang++) or `-fpermissive` (g++) for a member declared
  with an extra class qualification (`int Widget::name();` inside class
  `Widget`), which only MSVC accepts.

Each suggested command keeps the build variables you already set, and when
several apply, a last line combines them. `bhf auto` adds the compatibility
flag itself when a target needs it (`-fms-extensions` for clang++,
`-fpermissive` for g++), through the work dir's `cxx_compat.mk`, which every
harness Makefile includes, and keeps it only when the retry removes the
error. It prints `bhf auto: <id>: building with -fms-extensions (clang) /
-fpermissive (gcc) ...`, records the flag among the target's repairs
(`compiler_compat` in `run.json` and the harness's `result.json`) and in its
build recipe (`compat_flags`), and a capsule of the target applies it in the
spelling of the compiler that rebuilds it.

Extra build input comes from the environment: `AUTO_EXTRA_SOURCES` (sources),
`AUTO_EXTRA_INCLUDES` (any compile flags: `-I`, `-D`, `-include`,
`-fms-extensions`), `AUTO_EXTRA_LDFLAGS` (link flags) and `CXX_STD`/`C_STD`
(language standard). `CFLAGS`/`CXXFLAGS` are appended too, but only to the
`main` build; `AUTO_EXTRA_INCLUDES` reaches every lane.

### Recovering a compile database

When no database exists, `--probe-build` runs the project's own build offline
and captures the real compile flags. It detects and drives CMake
(`-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`), Meson (`meson setup`), MSBuild (the
Visual Studio import above, evaluated by MSBuild when it is installed), Make
and autotools (a compiler-interposing `CC`/`CXX` wrapper), standalone Ninja
(`ninja -t compdb`), and, under compiler interception, Bazel
(`bazel build //...`) and SCons (`scons`).

For any other build (a custom `build.sh`, Waf, a vendor RTOS build),
`--build-command "<cmd>"` runs that exact command under two interceptors that
record every compile into one `compile_commands.json`:

- a compiler shim placed first on `PATH`, which catches `cc`, `gcc`, `clang`,
  MSVC's `cl` and `clang-cl`, the vendor compilers common in radar and RTOS
  work (Wind River Diab `dcc`/`dplus`, Green Hills `ccarm`/`cxarm`, QNX
  `qcc`/`q++`, Keil/IAR, TI), and cross-prefixed GNU and LLVM toolchains
  started by name (on Windows the shims are executables, and an MSBuild build
  is captured through its CL task; see [Windows](windows.md));
- an `LD_PRELOAD` shim (`libbhf_cc_intercept.so`) that hooks the `exec*` and
  `posix_spawn*` families, so a compiler started by absolute path (a
  hard-coded vendor toolchain, a Bazel toolchain) or through `posix_spawn`
  (ninja and cmake drivers) is captured too.

Records are de-duplicated by translation unit, so a compile both interceptors
see is recorded once. `--probe-build` and `--build-command` both run the
project's build, which is untrusted code, so they run under bhf's sandbox
(bwrap or firejail) when one is installed.

### RTOS and vendor platforms

A Linux lab host cannot run a VxWorks, Green Hills INTEGRITY or QNX image, so
bhf fuzzes RTOS application code (parsers, protocol handlers, radar signal
processing) stub-isolated on the host: it fakes the platform headers and
builds the algorithmic code with sanitizers. When a host build hits a missing
RTOS header (`vxWorks.h`, `taskLib.h`, `semLib.h`, `msgQLib.h`,
`INTEGRITY.h`, `sys/neutrino.h`), the repair loop fills it with the
platform's types and constants (`STATUS`, `SEM_ID`, `OK`/`ERROR`, INTEGRITY
`Error`/`Value`, QNX kernel calls) instead of an empty placeholder. The
synthesized headers are searched with `-idirafter`, so the angled `<...>`
includes resolve without shadowing a real system header. Code guarded by
`#ifdef __vxworks`, `__INTEGRITY` or `__QNX__` is detected and the guard is
defined, so that branch compiles. Findings from a stub-isolated build are
marked reduced-fidelity: the platform behavior is faked, and the fuzzing
exercises the portable logic.

### `static` functions

For a C direct harness (manual or `auto`) whose target is a `static` function
defined in a `.c` file, and a C++ direct harness whose target is a `static`
free function defined in a `.cpp` file, bhf includes that source file into
`main.c` or `main.cpp` and leaves it out of the Makefile's separate source
list. The internal-linkage function is then callable from the harness, and
targets with external linkage build as before.

## How Inputs Become Arguments

A generated C or C++ harness decodes each fuzz input into the target's
arguments. A few rules decide what a parameter can receive:

- **Buffer and length pairs.** A byte pointer followed by an integer is bound
  to the input as a `(Data, Size)` pair only when the integer is named like a
  length. An output buffer is paired with its capacity (by value or by
  pointer) under the same rule. Names are read word by word (`dataLen` is
  `data` + `len`, `num_bytes` is `num` + `bytes`). A length-shaped word is
  `len`, `length`, `size`, `sz`, `siz`, `count`, `cnt`, `cap`, `capacity` or
  `bytes`, or a word ending in one (`srclen`, `bufsize`, `bufsz`, `bufsiz`,
  `nbytes`, `linecount`). So are `num` (`num_items`, `numBytes`), `n` and
  `nr` on their own or ahead of a plural (`nBytes`, `n_items`, `nr_pages`),
  `n` or `num` ahead of an element noun (`nElem`, `nMemb`, `nItem`, `nTok`,
  `nEntry`, `num_rec`, `nChar`, `nByte`), `number of` ahead of a plural
  (`numberOfElements`, `number_of_bytes`), the run-together counts
  `nmemb`/`nitems`/`nelem`, OpenSSL's `inl`/`outl`, `argc`, `avail`,
  `remaining`, the Win32 `cb`/`cch` prefixes (`cbData`, `pcbData`,
  `cchName`) and the bare `cb`, `cch`, `pcb` and `pcch`. A callback named `cb`
  never pairs, since its type is not a length type. A trailing digit is
  ignored (`len1`, `size_2`). A count marker inside another word does not
  count (`account`, `caps`, `silent`, `enum`), and neither does a name whose
  last word is `id`, `flags`, `mode`, `type`, `kind`, `line`, `bit` or
  `status` (`account_id`, `count_mode`). Offset-,
  index- and position-shaped names (`offset`, `off`, `pos`, `index`, `idx`,
  `start`, `begin`, `skip`, `bit_index`) never pair with a buffer, as a length
  or as a capacity. They are decoded as ordinary values, and the buffer gets
  its own heap copy of the input, so ASan sees its real size. In C, a header
  that omits parameter names (`arg1`, `arg2`) still pairs a binary pointer
  with the integer after it.
- **Typedefs.** In both C and C++, typedefs are resolved on both sides,
  typedef chains included (`const u8_t *` / `const BYTE *` buffers, `UINT` /
  `DWORD` / `u32_t` lengths). A buffer spelled through a pointer typedef
  (`LPCBYTE`, `PBYTE`, `typedef const u8_t *cu8_ptr`) pairs too, and the
  Win32 ones (`PBYTE`, `LPBYTE`, `PUCHAR`, `PCBYTE`, `LPCBYTE`, `PCUCHAR`) do
  without a typedef in the scanned tree. The typedef hides whether the bytes
  are const, so that buffer is always a heap copy of the input, and its
  length is the copy's size. Without a length partner it is decoded like a
  read-only byte pointer (below): a NUL-terminated heap copy. A scalar or
  byte-pointer typedef that the target's own `.c` declares is resolved too,
  whatever its name (`uchar` and `DWORD` included). The harness spells it as
  the type it aliases, in the target's prototype and in the `.c`'s
  function-pointer typedefs it copies, so it does not need to include the
  `.c`. A struct or enum typedef that only the `.c` declares stays opaque, and
  so does a name the `.c` also `#define`s or declares only in a preprocessor
  branch that does not also hold the target (a typedef under `#if 0` is
  ignored).
- **Unsigned integers.** Unsigned parameters, struct fields and output-pointer
  values cover their full range, `size_t` included, so values with the top
  bit set (`0x80000000`..`0xffffffff`, wrap-around sizes, bit masks) are
  reachable. Values named like a length, size or count stay bounded, since a
  huge length produces only allocation failures: a `size_t` or `z_size_t`
  length stays in `0..=65536`, and any other unsigned length in
  `0..=0x7fffffff`. Each value consumes the same number of input bytes either
  way.

### Decoding layout

A generated harness reads the testcase through one cursor, starting at byte 0,
and decodes the parameters in declaration order. Every multi-byte value is
little-endian. A read past the end of the input yields zero bytes, so a short
input still calls the target, with zeros and empty strings in the parameters
it did not reach. The per-type rules are:

| Parameter | Input bytes | Value |
|---|---|---|
| `bool`, `_Bool` | 1 | the low bit of the byte |
| `char`, `signed char`, `int8_t`, `unsigned char`, `uint8_t` | 1 | the byte |
| `short`, `int16_t` | 4 | a 32-bit read, truncated to 16 bits |
| `unsigned short`, `uint16_t` | 4 | a 32-bit read modulo 65536 |
| `int`, `int32_t` | 4 | a 32-bit read |
| `unsigned`, `uint32_t` | 4 | a 32-bit read; named like a length: modulo 2^31 |
| `long`, `long long`, `int64_t` | 8 | a 64-bit read |
| `unsigned long`, `uint64_t` | 8 | a 64-bit read; named like a length: modulo 2^31 |
| `size_t`, `z_size_t` | 8 | a 64-bit read; named like a length: modulo 65537 |
| `float`, `double` | 4, 8 | the integer read, converted to the floating type |
| enum with N named members | 4 | a 32-bit read modulo N picks the member, in declaration order |
| enum with no named members | 4 | a 32-bit read modulo 256 |
| `channels`, `req_comps` and other channel counts | 4 | a 32-bit read modulo 9 |
| integer named `flags`, `flag`, `flg`, `cflags`, `eflags`, `mode`, `modes`, `options`, `option`, `opts` or ending in `_flags`, `_flag`, `_mode`, `_options`, `_opts`, or whose type is named `flag`, `flags` or ends in `_flag`, `_flags`, `_flag_t`, `_flags_t` | 0 | pinned to 0, the default mode: such a value selects a variant or a dispatch, and a fuzzed one trips reserved bits no real caller sets |
| `const char *` | 2 + L | a 16-bit length prefix, then L bytes (at most 4096 and at most what is left) in a heap copy of L + 1 bytes ending in NUL |
| `char *` (writable), or a `char` typedef such as `CHAR *` | up to 4096 | a fixed 4097-byte heap buffer holding the next 4096 bytes (or what is left), no prefix |
| `fmt`, `format` and the last `char *` of a variadic function | 2 + L | as `const char *`, with every `%` replaced by a space |
| `const wchar_t *` | 2 + L wide characters | a 16-bit prefix counting wide characters (4 bytes each on Linux), at most 2048 |
| `const char **` with a count | 8, then strings | a count modulo 17, then that many length-prefixed strings of at most 256 bytes |
| `T *items` with a count | 8, then elements | a count modulo 65 sizes a zeroed array of that many elements, then each element by its own rule |
| struct or union | its fields' bytes | each field by its own rule, in declaration order, nested up to 4 deep; arrays fill at most 64 elements. A field that is itself `const` is decoded only in the heap storage of a C typed array's elements or of the struct a C pointer parameter points to (and what those point to); elsewhere (a by-value local, C++) it stays zero and reads no bytes, as a `const` bit-field and a `const` function pointer declared inline always do. A C++ `static` data member is not a field |
| pointer to a scalar or enum | the scalar's bytes | the address of a local holding the decoded value |
| C++ `T &` | `T`'s bytes | a local decoded as `T`, passed by reference |
| C++ `std::string`, `std::string_view` | 2 + L | as `const char *` |
| C++ `std::vector<T>` and other sequences | 8, then elements | a count modulo 17, then each element (a byte vector or span takes the remaining input, below) |

Length-named and offset-named parameters are the ones described above. Some
parameters read no cursor bytes and take the rest of the input instead.
Within one call they are decoded after every cursor parameter of that call,
whatever their position in the signature, and they take the bytes the cursor
left (the *remaining input*). For the target call of a direct harness with no
cursor parameter, that is the whole testcase:

- a byte buffer paired with a length-named integer: a read-only buffer is a
  view of the remaining input and its length is the remaining size; a
  writable one is a heap copy of it (at most 1 MiB) and its length is the
  copy's size;
- a read-only byte pointer with no length partner (`const uint8_t *`,
  `const unsigned char *` or a typedef of one): a NUL-terminated heap copy of
  the remaining input, `max(remaining + 1, 8)` bytes, zero-filled past it. It
  is a copy, not a view of the fuzz input, so ASan reports overflows against
  that allocation;
- `const void *` with no partner: a view of the remaining input; `void *`: a
  heap copy;
- a writable byte pointer with no partner (`unsigned char *`, `uint8_t *`,
  or an element type spelled through a typedef such as `u8_t *`, `BYTE *` or
  `std::uint8_t *`): a heap copy of the remaining input with 64 KiB of
  headroom;
- C++ byte vectors and spans (`std::vector<uint8_t>`,
  `std::span<const uint8_t>`): a copy or view of the remaining input;
- `FILE *`: `fmemopen` over a copy of the remaining input (on Windows, which
  has no `fmemopen`, a temporary file holding it, deleted on close);
- the path parameter of a file loader (`load_file(const char *path)`): the
  remaining input written to a temporary file;
- a read-only pointer to a record bhf cannot construct: a view of the
  remaining input.

bhf's driver passes each input in a heap allocation of exactly its size (one
byte for an empty input), in the fuzz loop and on replay, as libFuzzer does.
A read one past a view of the input is a heap overflow the sanitizer reports.
The AFL++ lane copies each input out of AFL++'s testcase buffer, which is
larger than the input, into such an allocation too, so the same read is the
same `heap-buffer-overflow` there.

So for `f(const uint8_t *data, uint32_t a, uint32_t b)`, `a` is bytes 0-3,
`b` bytes 4-7 and `data` the bytes from 8 on. For
`g(const char *buf, size_t len, int depth)`, `depth` is bytes 0-3 and the pair
the rest; with `int flags` in place of `depth`, `flags` is pinned to 0 and the
pair is the whole input. No input byte feeds two parameters of one call. A
seed (a sample file of the buffer's format) is therefore also given behind as
many zero bytes as the fixed-width parameters before the buffer take, 8 for
`f`, so the buffer starts with it (see [Seeds](auto.md#seeds)).

A call that takes several such buffers (two lone buffers, two pairs, a pair
and a `FILE *`) gives each its own bytes. After the cursor parameters, every
one but the last, in parameter order, takes 4 bytes of little-endian length
L, then the next `min(L, bytes left)` bytes, in a heap copy of its own, freed
after the call. A buffer paired with a length gets exactly those bytes (one
byte when empty), and their count as its length. So does a `FILE *` or a file
path, whose end the callee sees. A buffer with no length partner keeps the
allocation it would get alone, as large as the whole input: those bytes,
then zeros. A function that reads it for as many bytes as another argument
says (`memcmp(a, b, n)`) stays inside it. The last buffer takes the
remaining input as above. So for `h(const uint8_t *a, size_t alen, const
uint8_t *b, size_t blen, int x)`, bytes 0-3 are `x`, bytes 4-7 the length of
`a`, the next that many bytes `a` (and `alen` their count), and the rest `b`,
with `blen` its size. A parameter that only takes the input's size (an
output buffer's capacity) reads no bytes and follows the last buffer. A
`void *` ahead of a `(data, len)` pair (a context pointer) is such a lone
buffer, so `data` starts after the 4-byte length of its slice. A seed is
therefore also given behind 4 zero bytes, which leave the context empty.

A parameter named like one of the harness's own locals (`Data`, `Size`,
`Cur`, `R`, or a name starting `_bhf_` or `bhf_`) is declared in `main.c` /
`main.cpp` as `bhf_arg_<name>`; it is passed by position, and the trace, the
layout and `bhf decode-args` show its declared name.

**Explicit buffer lengths.** The remaining input has no length of its own: a
buffer without a length parameter is as long as the input lets it be. Set
`BHF_BUFFER_LEN_DIMENSION=1` when generating the harness (`bhf
generate-harness` or `bhf auto`) to give it one. A buffer with no length
partner then gets exactly its bytes in a heap copy of that size (one byte
when empty), with no NUL terminator and no 8-byte floor, whether it is a
read-only byte pointer, a `void *` or a `const void *` view, so the sanitizer
sees the shorter buffer. A writable byte pointer keeps its 64 KiB of headroom
for the callee's writes. A buffer before the call's last one gets its slice,
as above, without the input-sized allocation, and the call's last buffer
takes a sized slice too, after the cursor parameters and the other buffers (4
more bytes, a little-endian length clamped to the bytes left, then that many
bytes). An empty buffer's one byte is zeroed and addressable, so a read of
byte 0 of an empty buffer is not reported.

The setting is off by default, because a buffer shorter than the input can
make a function with an implicit length contract read past it, a crash the
harness caused. The harness records it only where it gave a buffer a length
(`buffer_len_dimension` in `arg-layout.json` and `generation-metadata.json`,
and `with an explicit buffer length` after the format stamp in the source); a
harness whose buffers all have a length partner decodes the same with it on
and records nothing.

**Receivers and sequences.** A C++ method's receiver is decoded after the
target's own cursor parameters. A default-constructible class takes no input
bytes; otherwise its constructor or factory arguments are decoded next, by the
same rules. A mined protocol then decodes each step's arguments before that
step's call. A lifecycle loop reads one byte for the number of steps (modulo
the step count plus one), then, for each step, one selector byte (modulo the
step count) and that step's arguments. The target's whole-input parameters
come last, right before the target call, so they take only bytes the
constructor, the factory and the loop did not read. Constructor, factory and
step arguments that use the whole input take the input remaining when that
call is decoded (after the target's cursor parameters), which a later call can
read again. A mined protocol step that the project's own tests bind to the
input keeps the whole input.

A C sequence harness keeps its operation program in a control block at the
end of the input (`sequence-layout.json` gives its length) and decodes the
calls' arguments from the front. A call's whole-input parameters take the
argument bytes the cursor left when the call is decoded, never the control
block. Only a call that runs once before anything read the cursor (the
constructor, a configuration call, the first protocol call) and reads no
cursor bytes itself keeps the whole input.

### Seeing the decoded arguments

A generated harness prints the value of every parameter it decoded when
`BHF_TRACE_ARGS=1` is set, one `BHF_ARG` line per parameter on stderr after
decoding and before the call:

```sh
BHF_TRACE_ARGS=1 bhf_work/harnesses/<id>/main bhf_work/results/findings/<ID>/testcase.bin
BHF_ARG {"call":"target","i":1,"role":"param","name":"width","type":"unsigned int","decoder":"bhf_i32()","span":[0,4],"value":"640"}
```

Each line carries the call (`target`, `receiver` for a C++ receiver's
constructor arguments and the receiver object, or the name of another function
the harness calls), the parameter index, name and type, how it was decoded,
`span` (the `[start, end)` bytes of the testcase it came from), and its value.
A pointer carries `ptr` (its address), `alloc_size` (the heap allocation, from
AddressSanitizer), `len` (the content length) and `preview_hex` (at most 32
leading bytes, never raw text). An output or in-out parameter (a non-const
reference, a pointer to scalar storage, a writable string) has `"role":"out"`
and a second line with `"phase":"after"` and its value after the call. Without
the variable a harness prints nothing.

When the fuzz loop records a new C/C++ crash (builtin engine, fork server or
AFL++), it re-runs the testcase once with the trace on. `decoded.json`
(`schema_version` `bhf.decoded.v1`) then holds every traced value in
`arguments` (a length-prefixed string also gets `length_prefix`, the 16-bit
prefix its bytes ask for, next to the `len` the harness took) and their byte
ranges in `provenance`, or `arguments_unavailable` with the reason.
`finding.json` gains `decoded_args`, the target call's arguments with
`name`, `type`, `role`, `value` or `len`, `span`, `preview_hex` and
`after_call_value`.

When a heap access hits a region a traced buffer starts (`basis`
`region_start`) or points into (`region_interior`, for a view that starts
after the bytes other parameters took), `exception.access.parameter` names
that parameter and the access offset from its pointer. The trace is a second
run of the testcase, so the parameter is matched against that run's own
report of the access when it is the finding's fault (the same crash frame,
else the same reported location or faulting instruction, and the same
direction, width and region); on Windows, AddressSanitizer places each run's
heap elsewhere. For a wild access with no region, it names the nearest traced
pointer below the faulting address (`nearest_pointer`).

`bhf replay --show-args` re-runs the harness with the trace and prints the
arguments as a table. `bhf explain` shows the same table under HARNESS
ARGUMENTS, and `bhf cartography` labels each byte with the parameter it was
decoded into. In `bhf explain`'s table, an argument whose bytes a recorded
comparison read is tagged `[compared at <file>:<line>]` (or the comparison's
address when it could not be symbolized). The length of a `(buffer, length)`
pair holds the input's size, not input bytes, and is never tagged; its buffer
is. Evidence recorded on `min_testcase.bin` is related to the parameters
through `arg-layout.json` decoded over that file. The results `findings.json`
carries the accessed parameter as `fuzz.access.parameter`, and
`findings.csv` the arguments (`arguments`) and that parameter
(`access_parameter`).

Harnesses generated before the trace existed print nothing: regenerate them,
or read the arguments under a debugger. A passthrough harness, which hands
the input straight to the project's own `LLVMFuzzerTestOneInput`, decodes no
parameters, and `--show-args`, `decode-args` and `decoded.json` say so.
`bhf report --backfill` records the decoded arguments of a finding that has
no `decoded.json` (one migrated from an earlier release) when its harness has
the trace.

### Decoding a testcase without running it

Generation also writes `arg-layout.json` beside `main.c` / `main.cpp`
(`schema_version` `bhf.arg-layout.v1`, recorded as `arg_layout` in
`generation-metadata.json`): the decode steps in the order the harness runs
them. Each parameter step gives:

- its `call`, `index`, `name`, `type` and `order`;
- where its bytes come from (`input`: `cursor`, `remainder`, `whole_input` or
  `none`);
- the decoder kind (`decoder`: `scalar`, `bounded_int`, `enum_member`,
  `length_prefixed_string`, `capacity_string`, `rest_view`, `input_buffer`,
  `input_length`, `input_end` (the `end` of a `[begin, end)` pair, one past
  the buffer's bytes), `input_stream`, `input_file`, `fixed` or `other`) and
  its `primitive` (`bhf_i32`, `bhf_c_string`, ...);
- `width`, `endianness`, `value_kind`, bounds (`lo`, `hi`), enum `members`,
  `length_prefix_bytes` and `max_len`;
- whether a buffer is `copied`, whether the value is a C string read up to its
  first NUL (`nul_terminated`), the constant a `fixed` parameter is given
  (`fixed_value`), and the other half of a pair (`paired_with`);
- `static_decode` with a `note` when its value cannot be computed from the
  description.

A `remainder` step marks where a call's whole-input parameters take the bytes
the cursor left (`sized` with the explicit buffer-length setting), and an
`opaque` step marks a lifecycle loop, whose input use is known only at run
time. In a call with several buffers, each buffer but the last follows a
`sized` `remainder` step of its own, after the cursor steps: its 4-byte
length, then its bytes.

`bhf decode-args` maps a testcase to the value of each parameter:

```sh
bhf decode-args --finding F-0003-9c1d22e0            # its testcase.bin and harness
bhf decode-args crash.bin --harness bhf_work/harnesses/H-C0001
bhf decode-args --finding F-0003-9c1d22e0 --static --json
```

With a built harness that has the argument trace, it runs the harness once
with `BHF_TRACE_ARGS=1` and shows its `BHF_ARG` values. Without one (a work
dir copied without binaries, a cross-compiled harness), or with `--static`,
it replays `arg-layout.json` over the testcase:

- scalars (and C++ references to them, which the harness decodes as their
  referent), bounded integers, enums, length-prefixed and capacity strings,
  and remainder, whole-input and paired buffers are decoded as `bhf_decode.h`
  decodes them. A C string's length and preview stop at its first NUL byte,
  as the target reads it and the trace prints it; its span covers every byte
  it was decoded from;
- a parameter the harness sets to a constant (`fixed_value` in the layout)
  shows that constant;
- every other parameter, and every parameter decoded after a step the layout
  cannot replay, is listed under `not decoded statically` with the reason. A
  struct decoded field by field keeps the count of bytes it reads, so
  decoding continues after it; a lifecycle loop or a wide string does not.

A sequence harness picks its calls from its control block, so its layout is
not replayed. `--json` prints one `bhf.decode-args.v1` document (`source`
`harness_trace` or `arg_layout`, `arguments`, `not_decoded`, `notes`). A
finding recorded with a different harness input format than the layout gets
a note, since its bytes decode differently.

### Reading arguments in a debugger

`bhf replay --debugger` runs the testcase under gdb or lldb (cdb on Windows)
in batch mode. It breaks at the target function the generation metadata
names, prints `info args` and `bt full` there, then continues to the crash
and prints `bt full` again. It sets
`ASAN_OPTIONS=handle_segv=0:abort_on_error=1:detect_leaks=0`, so the debugger
sees the fault, and applies the replay's runtime mode, injected variables and
runtrace shim, so a crash that depends on them happens there too (see
[CLI](cli.md#replaying-a-finding)). The debugger session runs the harness
outside the replay's sandbox.

To do the same by hand: harnesses are built with `-O1 -g`, so gdb can show the
target's arguments:

```sh
gdb -q -batch -ex 'set debuginfod enabled off' -ex 'break <target>' -ex run -ex 'info args' \
    --args bhf_work/harnesses/<id>/main bhf_work/results/findings/<ID>/testcase.bin
```

- A reference parameter prints with `p offset`, not `p *offset`.
- A buffer's allocation size is
  `call (unsigned long)__sanitizer_get_allocated_size(buffer)`.
- For a SEGV, run with `ASAN_OPTIONS=handle_segv=0` and `-ex run -ex 'bt 4'`:
  gdb stops on the signal with the arguments in the backtrace.
- For another ASan report, use `-ex 'break __asan::ReportGenericError' -ex
  run -ex 'frame 2' -ex 'info args'` (frame 1 is `__asan_report_load*`).
- For UBSan, run with
  `UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_stacktrace=1` and
  `-ex run -ex bt`, or break on the check's handler
  (`__ubsan_handle_mul_overflow`) and use `frame 1`.
- At `-O1` a local can print `<optimized out>`: break at the target's entry,
  where the arguments are live, or rebuild a copy of the harness with
  `make -B main CFLAGS=-O0` (`CXXFLAGS=-O0` for C++), which comes after bhf's
  `-O1` and keeps the sanitizers.

### Harness format version

Whenever a change makes the same input bytes decode to different argument
values, the harness format version goes up. Each harness records it as
`harness_format_version` in `generation-metadata.json`, and the top of the
generated `main.c` / `main.cpp` shows it (`bhf harness format 4`). The
current C/C++ format is 4. A harness with no recorded version is format 1.

| Format | What changed |
|---|---|
| 2 | An unsigned input with its top bit set, or a `size_t` not named like a length, decodes to a different value. `(buffer, integer)` pairs whose integer is not named like a length are no longer bound to the input length or to an output buffer's capacity |
| 3 | The layout above: a call's whole-input parameters take the bytes its cursor parameters left, instead of the whole input again, and a C++ method's whole-input target parameters come after its receiver's arguments. A call that mixes the two kinds (`f(data, a, b)`) decodes differently; under format 2, `data` was the whole input and also overlapped `a` and `b`. A direct harness whose target call has only cursor parameters, or only whole-input ones, decodes as before, except that a C++ receiver's constructor, factory and step arguments and a sequence harness's operations take the bytes the cursor left instead of the whole input. Ada harnesses stay at format 2, since their decoding did not change |
| 4 | Every buffer of a call that takes several gets its own bytes (each but the last a sized slice, above) instead of the same remaining input, and every `(buffer, length)` pair of a call is bound, not only the first. The counts named `nElem`, `numberOfElements` or a bare `cb` pair. A lone pointer-typedef buffer (`LPCBYTE`), and a lone writable byte pointer whose element type is a typedef or `std::uint8_t` (`u8_t *`, `BYTE *`), get a heap copy of the input instead of one byte. A writable pointer to a `char` typedef (`CHAR *`) decodes as the writable `char *` above instead of one byte. A parameter named like a harness local is renamed. The scalar typedefs a C target declares in its own `.c` are resolved. C++ sizes a typed array to its element count as the C lane does, and both lanes decode each element of such an array from the input. Any other harness decodes its inputs as format 3 did |

Corpora from an older format still run, but their inputs can exercise
different values. Re-run the corpus and re-triage the findings recorded
against an older harness rather than comparing them directly. A harness
generated with `BHF_BUFFER_LEN_DIMENSION=1` decodes the same format
differently again, so a finding also records `buffer_len_dimension` when the
harness that found it had it on, and the notes below also flag a finding
replayed against a harness generated with the other setting.

bhf tracks the format in these places:

- `bhf generate-harness` (and so `bhf auto`) prints a warning when it
  regenerates a harness directory whose recorded format differs from the one
  it writes, and `bhf replay` prints a note when the harness it replays
  against was generated with another format.
- Each new finding records the format of the harness that found it as
  `harness.format_version` (and `harness.buffer_len_dimension`) in
  `finding.json`, with the older top-level `harness_format_version` kept for
  earlier readers. The same is written to the harness's corpus metadata
  (`corpus/<id>/metadata.json`, `bhf.corpus-metadata.v1`). Every fuzz pass
  writes it too, whether or not it found anything: a corpus the pass creates
  gets it before its first input, and every corpus gets it at the end of the
  pass.
- `bhf auto` notes when a corpus was recorded against another format than the
  harness it fuzzes, and when a corpus holds inputs but no metadata (one an
  earlier release left, kept with `--reuse-legacy-corpus`): such a corpus was
  recorded before formats were stamped, so its inputs are format 2 or earlier.
- `bhf replay`, `bhf minimize`, `bhf decode-args` and `bhf capsule` read the
  finding's format from `harness` first, then the top-level key, then the
  harness directory's metadata, and compare it with the harness they run.
  When they differ, replay says so in a `note` (also in `--json` `notes`),
  minimize on stderr, and capsule in a warning and as `harness_format_note`
  in the capsule's `manifest.json` (with `harness_format_version` and
  `finding_harness_format_version`).

A finding that records no format came from a format 2 or earlier harness, so
it is flagged against a format 3 or later harness. Such a finding replays as
recorded against a harness of its own format. Against a regenerated harness,
its testcase decodes into other arguments, so fuzz the regenerated harness
again rather than comparing the two.

## Supported C Parameter Shapes

The C emitter supports:

- scalar integer and length-like types, including common zlib/miniz aliases;
- `const char *`, `char *`, standalone read-only byte pointers as a
  NUL-terminated heap copy of the fuzz input (see [Decoding
  layout](#decoding-layout)),
  and byte pointer plus adjacent length pairs, including typedef aliases such
  as `const mz_uint8 *`;
- standalone `const void *` as a borrowed fuzz-input view and standalone
  `void *` as a heap-owned mutable copy of the current fuzz input;
- output byte buffer plus adjacent output-length pointer or scalar-capacity
  pairs;
- enums, structs by value, structs by pointer, fixed arrays, and first-decodable
  union members when the source or included headers expose type definitions;
- pointer-to-scalar and pointer-to-enum output parameters, including typedef
  aliases, plus `time_t`/`MZ_TIME_T` scalar pointer aliases;
- top-level `void **` output slots as stack-backed nullable pointer slots;
- typedef function-pointer callback parameters via a generated no-op trampoline
  that matches the typedef signature;
- `FILE *` and miniz-style `MZ_FILE *` macro aliases, backed by `fmemopen`
  over the current fuzz input and closed after the target call.

**Lifecycle APIs.** For an API whose functions take a `struct T *` handle as
their first parameter, `--kind sequence` and `bhf auto` drive a bounded
operation loop between init and end helpers from the same source file. If
those init and end helpers are `static`, bhf includes the defining `.c` file
into `main.c` and leaves it out of separate linking. Other `static`
operations on the same handle are left out of the loop unless one of them is
the selected target.

## Supported C++ Parameter Shapes

The C++ emitter supports:

- scalar C-like types handled by the C decoder, including `bool`, plus
  `std::size_t` and 8-/16-/32-/64-bit `std::uint*_t` / `std::int*_t`
  C++ aliases;
- visible C++ enums and `enum class` parameters, with scoped alternatives
  emitted as `Enum::Member` or `namespace::Enum::Member` so generated
  harnesses compile, including source-only namespaced implementation files
  whose decoded parameter types are only visible after including the source;
- `const char *` / byte pointer plus adjacent length;
- mutable output-looking byte/void pointer plus output-length pointer or scalar
  capacity pairs, followed by input pointer/length pairs;
- `std::string`, `std::string_view`;
- `std::vector<uint8_t>`, `std::vector<std::uint8_t>`,
  `std::vector<unsigned char>`, `std::vector<char>`, `std::vector<std::byte>`;
- `std::vector<std::string>` plus `std::vector<T>` for supported owned C++
  value decoders, including visible aggregate element types;
- `std::deque<T>`, `std::list<T>`, and `std::forward_list<T>` for supported
  owned C++ value decoders, including visible aggregate element types;
- `std::set<T>` and `std::map<K, V>` for supported owned C++ value decoders;
- `std::unordered_set<T>` and `std::unordered_map<K, V>` for supported owned
  C++ value decoders;
- `std::map<K, V>` and `std::unordered_map<K, V>` with supported scalar/string
  keys and visible aggregate mapped values;
- `std::array<BYTE, N>` for byte element types and `N <= 4096`, plus
  `std::array<T, N>` for supported owned C++ value decoders, including visible
  aggregate element types;
- `std::bitset<N>` for `N <= 4096`, filled from input-controlled boolean bits;
- `std::optional<std::string>` plus `std::optional<T>` for supported owned
  C++ value decoders such as standard scalar aliases, byte containers, and
  visible aggregate types;
- `std::pair<T, U>` when both fields have supported owned C++ value decoders,
  including visible aggregate fields;
- `std::tuple<T...>` when every element has a supported owned C++ value
  decoder, including visible aggregate elements;
- `std::variant<T...>` when every alternative has a supported owned C++
  value decoder, including `std::monostate` and visible aggregate
  alternatives;
- `std::unique_ptr<T>` and `std::shared_ptr<T>` when `T` has a supported owned
  C++ value decoder, including visible aggregate pointee types;
- `std::filesystem::path`;
- common `std::chrono` duration aliases (`nanoseconds`, `microseconds`,
  `milliseconds`, `seconds`, `minutes`, and `hours`) from bounded integer
  values;
- `std::span` of byte-like element types and visible aggregate element types,
  using C++20 when needed;
- `FILE *` parameters backed by `fmemopen` over the current fuzz input and
  closed after the target call;
- typedef function-pointer callback parameters via a generated no-op trampoline
  that matches the typedef signature;
- `std::function<signature>` callback parameters via a generated no-op lambda
  for direct and lifecycle-step harness calls;
- simple aggregate `struct` / public-field `class` parameters by value or
  reference when the source or included headers expose their definitions;
  scalar, enum, fixed-array, and nested visible aggregate fields reuse the
  recursive C type decoder. For source-only C++ implementations without a
  project header, the harness includes the implementation file when needed to
  make those visible aggregate definitions available.

**Member functions.** When a qualified target looks like
`namespace::Class::method`, the harness creates a receiver and calls the
method on it, using a default constructor or a supported public constructor
with parameters. With `--kind sequence`, and in `bhf auto` when same-class
setup methods are visible, the harness runs a bounded sequence of those
methods before the target call. Which methods it picks is decided from names
and signatures, and methods known to be `private` or `protected` are skipped.
A class whose only known constructors are not public is not harnessed, and
the reason suggests a wrapper or factory. So is an abstract class, one that
declares a pure-virtual member directly (`virtual ... = 0;`). When the state
transitions that matter sit behind non-public helpers, add a public test
wrapper.

## Findings

C/C++ findings come from sanitizer reports and runtime-audit evidence. The
builtin engine keeps the `main` binary running as a fork server, feeds it
inputs over a framed protocol, and parses the sanitizer report of an input
that crashes. AFL++ mode runs `afl-fuzz` against the staged `main_afl`
sanitizer binary, then replays the crash files through that binary to write
normalized findings. An input afl-fuzz saved as a hang (past its 1 s `-t`) is
re-run through `main_afl` with twice that time; one that hangs again is a
BHF-230 finding with the stack it was looping in, and the run summary's
`hangs` counts it as a builtin pass's would.

The AFL++ session is kept in `afl_out/<harness>/out` between runs, and
afl-fuzz resumes it (`AFL_AUTORESUME`) with its queue, coverage map and
stats. Seeds the session was not given before (a builtin pass's corpus, new
`--seed-file`s) are added to its queue, and the crashes and hangs of the
session a resume moved aside are collected with this run's. After each run,
the queue is copied into the bhf corpus (`corpus/<harness>/queue`, counted in
`corpus_persisted`), so the builtin engine and `bhf corpus` start from what
AFL++ found. A session afl-fuzz cannot resume is started over, once, and bhf
says so. `bhf clean` removes `afl_out`. `bhf fuzz --engine afl++ --workers N`
runs a `-M main` instance and N-1 `-S` instances in the one output directory,
synced as AFL++ syncs them (see `--workers` in the [CLI reference](cli.md)).

afl-fuzz normally binds itself to a free CPU core. bhf changes that in two
cases, and the run summary (`fuzz_runs/<harness>-latest.json`) records the
reason in `afl.no_affinity`:

- bhf runs on only some of the host's CPUs, for example under
  `taskset -c 3`. bhf sets `AFL_NO_AFFINITY=1` so afl-fuzz stays on those
  CPUs instead of moving to one outside them (`pinned`).
- Other CPU-locked processes, such as other fuzzers on a busy host, hold
  every core. afl-fuzz refuses to start with `No more free CPU cores`. bhf
  says so on stderr and runs that instance again once with
  `AFL_NO_AFFINITY=1` (`no_free_core`).

`requested` means `AFL_NO_AFFINITY` was already set in the environment. The
field is absent when afl-fuzz bound a core itself.

When every afl-fuzz instance of a pass has exited, bhf kills any `main_afl`
or `main_afl_cmplog` process still running. afl-fuzz leaves the persistent
child of its CmpLog fork server stopped when it exits. Left running, that
child would hold the session's lock, so the next run could not resume the
session, and it would keep its CPU core bound.

### Uncaught C++ exceptions

A C++ harness calls the target inside `try`/`catch` when the build enables
exceptions (under `-fno-exceptions` it runs unguarded). An exception that
leaves the target is an uncaught-exception finding, BHF-231 (CWE-248, low
severity), named by the exception's demangled type and its `what()`: a
program that calls the target the way the harness does would terminate on it,
as it would on `std::out_of_range` from `vector::at` or
`std::invalid_argument` from `stoi` on unvalidated input.

An exception type the API throws on purpose, to report bad input to callers
that catch it, is not a finding once you list it as expected:
`bhf auto --cxx-expected-exception json::parse_error` (repeatable, `*` for
every type; config key `cxx-expected-exception`;
`BHF_CXX_EXPECTED_EXCEPTIONS` for `bhf fuzz`). The harness then treats that
input as rejected. An exception that escapes a `noexcept` function is always a
finding: `std::terminate` ends the process before any `catch`, and bhf reads
the C++ runtime's own message (`terminate called after throwing an instance
of ...`, or libc++abi's `terminating due to uncaught exception of type ...`).

### Runtime oracles

When `bhf auto` runs a harness with the runtrace shim, the builtin engine also
checks each input against executable oracles. They turn these observations
into `classification: "oracle_hit"` findings that carry the oracle name, the
API and the runtime evidence:

- **Path traversal.** A file API receives a path with a parent-directory
  segment such as `../secret`.
- **Network egress.** A destination is observed through `connect` or resolver
  audit events.
- **Sensitive environment.** A secret-like environment variable name is read
  through `getenv` or `secure_getenv`; the value is never recorded.
- **Command injection (BHF-304).** A shell command string reaches `system` or
  `popen`, contains command-injection metacharacters, and is fuzz-controlled:
  input bytes appear in the command on one execution, and it never runs
  without them, as the taint-confirmed BHF-431 check decides at the end of the
  run. A constant command, whatever shell syntax it holds, is only noted.
- **Format string.** A format string reaches `printf`, `fprintf`, `dprintf`,
  `sprintf` or `snprintf` when it is not a literal in the program's read-only
  data, the whole format (at least 4 bytes) occurs verbatim in the current
  input, and it contains a conversion marker. A sanitizer crash inside such a
  call (a `%n` write, a `%s` read of a garbage argument) is the same bug: when
  the faulting frames are the printf family's own and the call's format
  argument is not a string literal, or the format-string oracle fired for the
  harness, the crash is reported as BHF-408 (CWE-134, with the crash's own CWE
  second) at the call, in one finding group with the oracle and format-string
  capability findings.
- **Leaked descriptors.** An audited file descriptor is opened and not closed
  before the harness execution exits.
- **File deletion (BHF-414, `file-deletion-runtime`).** A successful
  `unlink`, `unlinkat` or `remove` with a parent-directory path.
- **Native assertions (BHF-415, `native-assertion-contract`).** A C/C++
  assertion failure, with the expression and source location.
- **Path-controlled open (BHF-405, `path-controlled-open-runtime`).** `open`,
  `openat` or `fopen` reached by a fuzz-controlled path, with a `taint_path`
  source-to-sink string (`fuzz_input[offset..] → open(path)`). The shim stamps
  byte-origin taint on each path event, and bhf confirms the finding across
  executions: a path is reported only if it carried taint on at least one
  execution and was never opened untainted during the run, which filters out
  program constants the auto-dictionary copies back into inputs.

Like the other runtime findings, these records are stamped
`confirmation: "runtime"`, which sets them apart from static-scan candidates.
Ada runtime instrumentation feeds handled `Constraint_Error` range and index
check events, `Storage_Error`, `Tasking_Error` and user-defined exception
events into the same oracle SDK, as `ada-runtime-constraint-check` (BHF-102),
`ada-runtime-storage-error` (BHF-103), `ada-runtime-tasking-error` (BHF-104)
and `ada-runtime-user-exception` (BHF-105) findings.

These oracles need the runtrace shim. It is not loaded for cross-compiled
targets fuzzed under qemu-user, for Windows binaries run under wine, or for
RTOS stub-isolated builds, so those targets get sanitizer and crash findings
only.

### Differential and metamorphic checks

`bhf differential` replays one input directory through two harness binaries
and writes BHF-301 output-divergence findings, stamped with the
`differential-output-runtime` oracle, when stdout, exit status or timeout
behavior differs. `bhf fuzz --differential-harness <PATH>` does the same
inside the builtin engine's loop: every input runs through both builds (a
second build of the harness, such as the `main_diff` that
`make diff DIFF_CC=gcc` builds), which are compared on how each run ended
and on what it observed, the target's return value and anything it hands
`bhf_diff_observe(ptr, len)`, so mutation searches for inputs on which the
builds disagree.

`bhf differential` also runs single-harness metamorphic checks with
`--harness` and `--metamorphic-transform`, one or several of
`append-newline`, `trailing-whitespace`, `reorder-json-keys` and
`utf8-bom`. It compares the original and transformed runs and writes BHF-307
`metamorphic-relation-runtime` findings when the relation the transform
declares is violated: the same output for the first three, the same exit
status for `utf8-bom`. See [Differential fuzzing](../differential-fuzzing.md)
for the details.

Ada-only artifacts (swallowed-exception breadcrumbs, Ada handler paths,
generated `repro.adb` files) do not apply to C/C++ targets: a report writes
`repro.adb` only into an Ada finding, and removes one an earlier release
wrote into another finding. `bhf explain` leaves the files bhf's driver opens
to feed each input (`<work>/fuzz_inputs`, `<work>/fuzz_scratch`) out of a
finding's FAKED ENVIRONMENT section.

### Reproducing a finding offline

A C or C++ crash finding can be packaged into a capsule that rebuilds and
replays it without the work dir:

```sh
bhf capsule --work-dir bhf_work --finding-id <ID>     # package it
bhf verify-poc bhf_work/capsules/capsule_<ID>          # rebuild and replay it on another host
bhf cartography --work-dir bhf_work --finding-id <ID>  # which input bytes steer it
```

A C capsule rebuilds with `clang` (or `$CC`), a C++ one with `clang++` (or
`$CXX`). It holds the harness driver, the target sources and the headers they
include in their original layout, the repair stubs (with their absolute
`#include`s made relative to the capsule), and what `bhf auto` or `bhf build`
recorded for the build: the language standard, the extra sources, the
`AUTO_EXTRA_*` and `[toolchain]` flags and the compatibility flags.
`bhf capsule` refuses, with the reason, a harness that cannot rebuild
offline. `bhf verify-poc` compares the replay with the finding's rule, kind
and sink or site, as `bhf replay` does.
`python3 bhf_work/results/findings/<ID>/replay.py` replays a finding against
the work dir's own harness binary. See [CLI](cli.md) for the full behavior.

## Generated Dictionaries

C and C++ harness generation writes `dictionary.txt` beside `main.c` or
`main.cpp` when the source or its included headers expose reusable tokens:
enum members, object-like string and integer `#define` constants, string
literals, and switch `case` labels, inline labels included. C++ sources and
headers are mined with the C++ parser, so scoped `enum class` members appear
both as leaf tokens and as qualified `Enum::Member` tokens. A
`# from <file>:<line>` comment above each token names up to three places it
was found, so `# from widget.c:12, include/widget.h:3` points at the
comparison or constant it came from. The comparison constants the engine
observes at run time go to `learned_dictionary.txt` beside it (see
[CLI](cli.md)).

The builtin engine loads the dictionary automatically, for token insertion
and for structure-aware input synthesis; AFL++ mode passes the same
dictionary with `-x`. `bhf fuzz --structured-inputs <MODE>` chooses the
synthesis:

| Mode | Synthesis |
|---|---|
| `auto` (default) | all of the modes below; the dictionary-based ones need a mined dictionary, and `recursive` runs without one |
| `off` | none |
| `record` | TLV-style records |
| `json` | JSON objects and arrays |
| `xml` | XML elements |
| `kv` | newline-delimited key/value lines |
| `url` | URL-encoded query strings |
| `multipart` | multipart/form-data bodies |
| `csv` | CSV and table rows |
| `http` | raw HTTP requests |
| `ini` | INI sections and keys |
| `toml` | TOML tables and keys |
| `yaml` | YAML sections and keys |
| `recursive` | recursively nested grammar inputs: balanced delimiter pairs nested deep, for recursive-descent parsers |

## Current Limits

- The C++ parser is based on tree-sitter, and its handling of templates,
  overloads, macros, nested namespaces, operators, and declarations hidden by
  build-system conditionals is heuristic. It records plain class and struct
  member access for methods and constructors; declarations generated by
  macros can need a wrapper.
- Complex object graphs, custom allocators, ownership-bearing
  pointer-to-pointer APIs other than nullable `void **` output slots,
  callbacks that must have side effects, unsupported constructors,
  non-aggregate C++ class inputs, and virtual dispatch usually need a
  hand-written wrapper. See [Custom C and C++ Harnesses](custom-harness.md)
  for writing one and running it through `bhf build`, `bhf fuzz` and the
  triage commands.
- bhf reads an existing `compile_commands.json`; `--probe-build` recovers one
  from CMake, Meson, MSBuild, Make and autotools, Ninja, Bazel and SCons; and
  `--build-command` recovers one from any other build by compiler
  interception. Interception records the per-file compile flags (`-I`, `-D`,
  `-std`, forced includes), not the full build graph. It captures compilers
  started by name, by absolute path or through `posix_spawn`, except a
  statically linked compiler started by absolute path, which `LD_PRELOAD`
  does not reach.
- C/C++ direct harnesses are instrumented with
  `-fsanitize-coverage=trace-pc-guard,trace-cmp` and bhf's SanitizerCoverage
  runtime: edge presence, AFL hit-count buckets, comparison progress with
  `--comparison-progress` (alias `--cmp-progress`), cmplog/RedQueen capture,
  and value-profile dictionary mining.
