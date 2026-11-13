<!-- SPDX-License-Identifier: Apache-2.0 -->

# C and C++ Fuzzing

BHF can discover C and C++ functions, generate direct-call harnesses, build
them with sanitizer instrumentation, and fuzz them through the same reporting
pipeline used by `bhf auto`. The C/C++ lane is a first-class part of the
government legacy fuzzing mission; current parity work is focused on build
context ingestion and C++ lifecycle harnesses.

## Quick Start

For a full source-tree sweep:

```sh
bhf auto path/to/src --work-dir bhf_work --per-target-time 60
```

For manual control against one C++ function:

```sh
bhf list targets path/to/src --top 20
bhf generate-harness path/to/src/parser.cpp \
  --target Parser::parse \
  --output bhf_work/harnesses
bhf build bhf_work --harness H-CPP000A
bhf fuzz bhf_work --harness H-CPP000A --iterations 1000 --seed-input smoke
```

Use the actual harness id printed by `generate-harness` or by
`list-targets`. Stable ids from `list-targets` and `auto` use `H-C...` for C
and `H-X...` for C++; standalone manual generation defaults to `H-C<line>` or
`H-CPP<line>` unless `--id` is supplied. Generate into `<work>/harnesses/`,
where `bhf auto` puts its harnesses; `bhf explain` and `bhf capsule` read
harnesses from there.

To write the harness yourself, wrap an existing `LLVMFuzzerTestOneInput`, or
edit a generated one, see [Custom C and C++ Harnesses](../custom-harness/).

## Prerequisites

- `make`
- `clang` for C harnesses and `clang++` for C++ harnesses
- a working C++ standard library for C++ harnesses
- sanitizer support for `-fsanitize=address,undefined` and
  `-fsanitize-coverage=trace-pc-guard,trace-cmp`; the libFuzzer runtime
  (`-fsanitize=fuzzer`) only for the optional `make libfuzzer` export
- `afl-fuzz` plus `afl-clang-fast` / `afl-clang-fast++` only when using AFL++
- `libbhf_runtrace_shim.so` on Linux when runtime virtualisation is desired
  (the build also stages a `libbhf_runtrace.so` copy beside the `bhf`
  binary, which the auto loop prefers)

Generated C/C++ harnesses are Makefile-based. The default build target creates
`main`: bhf's own driver (a framed fork server plus a SanitizerCoverage
runtime), built with ASan and UBSan. It is not a libFuzzer binary;
`make libfuzzer` builds one for other fuzzers (see the harness's
`PORTABILITY.md`). `bhf build --c-engine afl++` runs `make afl` and stages
`main_afl` for `bhf fuzz --engine afl++`.
When make's built-in compiler defaults are still `cc` / `g++`, the generated
Makefile and `bhf build` prefer `clang` / `clang++`. `CC`/`CXX` (or `--cc`/`--cxx`,
or `[toolchain] cc`/`cxx` in a config file) choose another compiler, and the
Makefile picks its instrumentation from the compiler that actually runs: clang
gets `trace-pc-guard,trace-cmp` coverage and the `function`/`vptr` UBSan
subtractions, gcc (native or cross-prefixed, `.exe` included) gets
`trace-pc,trace-cmp` and statically linked sanitizer runtimes. Setting
`CFLAGS`/`CXXFLAGS` still replaces bhf's flags entirely; use `--cflags` /
`--cxxflags` (`toolchain.cflags`) to APPEND flags and keep coverage and ASan.
Every object depends on a toolchain stamp, so changing the compiler or its flags
in the same harness directory rebuilds instead of linking stale objects. A
compile database's compiler is only the Makefile's default `CC`/`CXX`; it never
overrides the compiler bhf or the operator selects. `--sanitizers` keeps the
selected compiler when it can build the requested sanitizers and otherwise
says which compiler it uses instead. A C translation unit of a C++ harness is
compiled with `CC` and takes flags spelled for `CC`'s family (with `CFLAGS`
when the two compilers are of different families and `CFLAGS` is set).
`--cflags` also reach bhf's driver object (without `-std=` and `-Werror`; a
C++ harness's driver takes `--cxxflags` too), so an ABI-selecting flag such as
`-m32` applies to the whole link. `CC=clang` in the environment is bhf's own
default: `bhf auto` still retries a target clang rejects with gcc, which it
does not do for a compiler the operator chose.

## Discovery

`scan`, `list-targets`, and `auto` consider these files:

| File kind | Handling |
|---|---|
| `.c` | C parser |
| `.h` | C or C++ parser, selected from function counts and C++ markers |
| `.cpp`, `.cc`, `.cxx`, `.C` | C++ parser |
| `.hpp`, `.hh`, `.hxx` | C++ parser |

C/C++ ranking is signature-based. Byte buffers, string-like parameters,
pointer-plus-length pairs, parser-oriented names, error-code returns, and small
arity score higher. Ranking also applies a call-graph rerank that boosts
orchestrator/entry-point functions calling many other in-tree functions, on top
of the signature heuristics.

`bhf auto` accepts `--preprocess auto|always|never` to control the built-in
CPP-lite preprocessor used for discovery: `auto` (the default) preprocesses only
files with heavy conditional compilation, `always` forces it on every C/C++
file, and `never` parses raw source. Preprocessing resolves `#ifdef`/`#if`
branches so conditionally compiled functions are not missed, and a line map
keeps reported locations pointing at the original source.

## Harness Generation

C and C++ manual harness generation requires `--target`; there is no implicit
"best target" selection for these languages. For C++, these spellings select
`widgets::Codec::decode`:

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

Useful flags:

| Flag | Purpose |
|---|---|
| `--extra-source <PATH>` | Add another C/C++ source file to the generated Makefile |
| `--extra-include <DIR>` | Add an include directory |
| `--cleanup <EXPR>` | Run cleanup after the target call; `R` names the return value |
| `--id <ID>` | Pick a stable harness id, useful when overloads or line ids collide |
| `--max-decode-depth <N>` | Cap typed-decoder nesting depth (default 4); deeper fields are left zeroed |
| `--max-array-elems <N>` | Cap synthesized fixed-array elements (default 64); larger arrays fuzz a `0..cap` fill count |
| `--max-decl-bytes <BYTES>` | Cap aggregate size for inline struct/union synthesis (default 64 KiB); larger types are rejected |

Source, include, extra-source, runtime and compiler paths may contain spaces,
parentheses, apostrophes, ampersands and the characters `* ? [ ] { } ~ !`. The
generated Makefile double-quotes such paths in recipes and never uses them as
make prerequisites, so a tree under `/home/Dana Smith/...`, `/srv/R&D/...` or
`C:/Program Files (x86)/...` builds like any other. A compile flag the
recipe shell would act on is single-quoted whole, with an apostrophe written
`'\''` (`'-I/home/Dana'\''s tree/include'`), so it reaches the compiler as the
one argument it was. That includes a quoted string-macro define from the
compile database (`-DNAME="value with spaces"`): the compiler receives its
double quotes, so the macro is a string literal, and nothing inside the quotes
is ever run as a command. A `--differential` compiler given as a path with
spaces is double-quoted like the other paths. A path with a character no
quoting can make safe is refused before generation, and the message names the
character: `$`, `#`, a backtick, a double quote, a backslash, `;`, `|`, `<` or
`>`. A compile flag is refused only for `$`, `#` or a control character, which
`make` acts on before the shell sees the recipe (`#` ends the make variable
the flag is assigned to). The `[toolchain]` flags and defines (`--cflags`,
`--define`, ...) reach `make` through the environment, where `#` starts no
comment, so they may hold one; they are refused only for `$` or a control
character, and the message names it. On Windows, where `\` separates path
components, `%` is refused instead of the backslash, and `^` is quoted like
`&`; see [Windows](windows.md) for how flags are quoted there. In `bhf auto`
such a target's outcome is `unsafe_build_path` (counted as
`summary.unsafe_build_path` in `run.json`, and filed as an `unsafe-build-path`
row in `bug-report.md`): rename or move the path; `--force` cannot help.

BHF auto-detects sibling headers such as `parser.hpp`, local quoted
includes, nearby `include/` or `inc/` directories, and a pre-existing
`compile_commands.json`. The database is searched in place and in the
conventional out-of-source build directories (`build/`, `builddir/`,
`cmake-build-debug/`, `cmake-build-release/`, `out/`) at every ancestor of the
source, so a database an integrator hands over is consumed with **no build
execution**. Compile database entries contribute include paths, forced include
files, defines/undefines, `-std=...`, and `-pthread` flags to the generated
Makefile. A forced include (`-include FILE`, `-imacros FILE`) is made absolute
only when the file exists relative to the entry's `directory`; otherwise it is
kept as written, so `-include iostream` still finds the system header through
the include search path.

A database written by an MSVC build (`cl.exe` or `clang-cl` rows, with `/I`,
`/D`, `/U`, `/FI`, `/std:c11`, `/J`, `/Zp4`, `/Zc:wchar_t-`, `/external:I`)
is read the same way: each option with build semantics becomes its clang
spelling, backslash separators become `/`, and the rest (`/O2`, `/Zi`, `/MD`,
`/EHsc`, `/W4`, `/Fo...`, precompiled-header switches) is left out and named
in the Makefile's `BUILD_CONTEXT_DROPPED`. A `command` string is split by the
Windows command-line rules. The harness is still built by bhf's compiler
choice (clang, or cl with `--cc cl`), not by the row's `cl.exe`.

**Visual Studio solutions.** A tree with a `.sln`, `.slnx` or `.vcxproj` and
no compile database or CMake/Meson build is imported by default (off Windows,
only when the solution is the tree's only build description: a tree that also
has a Makefile, autotools inputs such as `configure.ac`/`Makefile.am`, Ninja,
SCons or Bazel files, at its root or on the way to the solution, follows that
build unless `--msbuild-solution` names the solution). The import
reads the files and runs nothing: it takes the solution's directory as
`$(SolutionDir)`, follows the project's local `<Import>`s and property sheets,
evaluates `Condition=` for one configuration (the first listed for x64, or
`--msbuild-config Release|x64`), resolves `$(...)` from the solution, the
project files and the environment, and reads each `ClCompile` item's include
dirs, defines, undefines, forced includes, `LanguageStandard`,
`AdditionalOptions`, `CharacterSet` (`UNICODE`/`_UNICODE` or `_MBCS`) and
`ExcludedFromBuild`. It prints the solution and configuration it read; with
several solutions it takes the shallowest (then by path), and
`--msbuild-solution` picks another (relative to the scanned tree; a solution
outside it is imported too, and a missing file is an error). A `$(...)` with
no value here leaves its
include dir or define out, and the run names it (MSBuild reads environment
variables as properties, so setting `MYSDK` supplies `$(MYSDK)`). The database
is written to `<work>/auto/msbuild/compile_commands.json`, never into the
tree. On Windows each row also carries the import libraries (`ws2_32.lib`,
found in `LIB`) its own project links, which reach only that project's
harnesses. `--no-msbuild-import` turns it off. The default import is this
static reading; MSBuild itself evaluates each project
(`msbuild -getItem:ClCompile`) when it is installed only with
`--msbuild-evaluate`, `--probe-build` or `--run-untrusted`, since evaluation
runs the project's property functions. See [windows.md](windows.md) for
Windows specifics.

**Fabricated build context.** When the build context still leaves a header,
a macro value or a type undefined, the repair loop writes a placeholder
(an empty header, `#define NAME 0`, `typedef void *T`) so the target
compiles. Code compiled against a placeholder can take paths the real build
never does, so such a finding may be false or need an input the real build
rejects. Each one says so: its `finding.json` has `build.fidelity`
(`{level: "reduced", context, fabricated: [{kind, name, value}]}`), its
normalized record is low confidence with a caveat in INDEX.md, findings.csv's
`build_fidelity` column and `bhf explain`, and `run.json` lists the target's
`build_fidelity` and counts the targets in `summary.fabricated_build_context`.
The console summary and `run.md` list them too. Supply the real context (a
compile database, `--extra-include`, `--define`) and re-run. A type the
sources use without including its header (`cerr` without `<iostream>`, a
`uint32_t` without `<stdint.h>`, or a project type the target's includes
lead to one header for) is resolved by including that real header, which is
no fabrication: the build keeps full fidelity, the repair record in
`run.json` carries `resolved_header`, and `run.json`
`targets[].real_headers_included` and `run.md` list it as
`type cerr: real header included (<iostream>)`.

`bhf build` compiles exactly the sources the Makefile lists; it has no repair
loop. When the link fails on symbols defined elsewhere in the tree, it prints
the defining files with the `--extra-source` flags to regenerate with and an
`AUTO_EXTRA_SOURCES=... bhf build ...` command that needs no regeneration.
It looks for them around the target (the enclosing checkout, or the project
around a `src/`/`lib/` directory) and in the directories of the harness's
other inputs: every source its Makefile compiles, every include dir it
searches, and the `--extra-source`/`--extra-include`/`--source-root` paths
`generation-metadata.json` records, so a harness kept beside its library
outside a checkout (`harness/` + `lib/`) finds the definer too. It
also suggests `AUTO_EXTRA_INCLUDES='-include iostream'` for standard streams
used without their header, and `-fms-extensions` (clang++) or `-fpermissive`
(g++) for a member declared with an extra class qualification
(`int Widget::name();` inside class `Widget`), which only MSVC accepts. Each
suggested command keeps the build variables you already set, and when several
apply a last line combines them. `bhf auto` adds that flag itself when a
target needs it (`-fms-extensions` for clang++, `-fpermissive` for g++,
through the work dir's `cxx_compat.mk`, which every harness Makefile includes,
kept only when the retry removes the error), says so (`bhf auto: <id>:
building with -fms-extensions (clang) / -fpermissive (gcc) ...`), records it
among the target's repairs (`compiler_compat` in `run.json` and the harness's
`result.json`) and in its build recipe (`compat_flags`), and a capsule of the
target applies it in the spelling of the compiler that rebuilds it. Extra
build input comes from the environment:
`AUTO_EXTRA_SOURCES` (sources), `AUTO_EXTRA_INCLUDES` (any compile flags:
`-I`, `-D`, `-include`, `-fms-extensions`), `AUTO_EXTRA_LDFLAGS` (link flags)
and `CXX_STD`/`C_STD` (language standard). Do not use `CXXFLAGS`/`CFLAGS` for
this: they replace the sanitizer and coverage flags.

To *recover* a database when none exists, `--probe-build` runs the project's own
build offline and captures the real compile flags. It detects and drives CMake
(`-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`), Meson (`meson setup`), MSBuild
(the Visual Studio import above, evaluated by MSBuild when it is installed),
Make/autotools (a compiler-interposing `CC`/`CXX` wrapper),
standalone Ninja (`ninja -t compdb`), and — under compiler interception — Bazel
(`bazel build //...`) and SCons (`scons`).

For any *other* build — a custom `build.sh`, Waf, a vendor RTOS build, or a
build named anything — `--build-command "<cmd>"` runs that exact command under
two complementary interceptors that record every compile into one
`compile_commands.json`:

- a front-of-`PATH` compiler shim that catches `cc`/`gcc`/`clang`, MSVC's
  `cl`/`clang-cl`, and the named vendor compilers common in radar/RTOS work
  (Wind River Diab `dcc`/`dplus`, Green Hills `ccarm`/`cxarm`, QNX `qcc`/`q++`,
  Keil/IAR, TI) plus cross-prefixed GNU/LLVM toolchains invoked *by name*
  (on Windows the shims are executables, and an MSBuild build is captured
  through its CL task, see [windows.md](windows.md)); and
- an `LD_PRELOAD` exec-interposing shim (`libbhf_cc_intercept.so`) that hooks
  the `exec*`/`posix_spawn*` family, so a compiler invoked **by absolute path**
  (a hard-coded vendor toolchain, a Bazel toolchain) or via `posix_spawn`
  (ninja/cmake drivers) is captured too.

Records are processed for duplicates by translation unit, so the two interceptors never
double-count. Both `--probe-build` and `--build-command` execute the project's
untrusted build, so they run under bhf's sandbox (bwrap/firejail) when one is
available.

### RTOS and vendor platforms

A Linux lab host cannot run a VxWorks, Green Hills INTEGRITY, or QNX image, so
bhf fuzzes RTOS application code (parsers, protocol handlers, radar signal
processing) **stub-isolated** on the host: it fakes the platform headers and
builds the algorithmic code with sanitizers. When a host build hits a missing
RTOS header — `vxWorks.h`, `taskLib.h`, `semLib.h`, `msgQLib.h`, `INTEGRITY.h`,
`sys/neutrino.h` — the repair loop fills it with a real type surface (`STATUS`,
`SEM_ID`, `OK`/`ERROR`, INTEGRITY `Error`/`Value`, QNX kernel calls) instead of
an empty placeholder, and the synthesized headers are searched with
`-idirafter` so the angled `<...>` includes resolve without shadowing a genuine
system header. Code guarded by `#ifdef __vxworks` / `__INTEGRITY` / `__QNX__`
is detected and the guard is defined so the otherwise-invisible branch compiles.
Findings from a stub-isolated build are flagged **reduced-fidelity**: the
platform behavior is faked, so only the portable logic is exercised.

For manual and auto C direct harnesses targeting a `static` function defined in
a `.c` file, and C++ direct harnesses targeting a `static` free function defined
in a `.cpp` file, BHF includes that source file into `main.c` or `main.cpp`
and omits it from the separate Makefile source list. This keeps
internal-linkage helpers callable from the generated harness without changing
normal external-linkage targets.

The real-code validation lane covers cJSON and tinyxml2 snapshots. It builds
generated harnesses through `bhf build`, then removes their public headers
in copied workspaces and asserts `bhf auto` reports the missing headers in
`needed_for_build.synthesized_headers`.

## How Inputs Become Arguments

A generated C or C++ harness decodes each fuzz input into the target's
arguments. A few rules decide what a parameter can receive:

- **Buffer and length pairs.** A byte pointer followed by an integer is bound
  to the whole input, `(Data, Size)`, only when the integer is named like a
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
  never pairs: its type is not a length type. A trailing digit is ignored
  (`len1`, `size_2`). A count marker
  inside another word does not count (`account`, `caps`, `silent`, `enum`),
  and neither does a name whose last word is `id`, `flags`, `mode`, `type`,
  `kind`, `line`, `bit` or `status` (`account_id`, `count_mode`). Offset-,
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
  read-only byte pointer (below): a NUL-terminated heap copy.
- **Unsigned integers.** Unsigned parameters, struct fields and output-pointer
  values cover their full range, `size_t` included, so values with the top
  bit set (`0x80000000`..`0xffffffff`, wrap-around sizes, bit masks) are
  reachable. Values named like a length, size or count stay bounded: a
  `size_t` or `z_size_t` length stays in `0..=65536`, and any other unsigned
  length stays in `0..=0x7fffffff`. A huge length only produces allocation
  failures. Each value consumes the same number of input bytes either way.

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
| `const char *` | 2 + L | a 16-bit length prefix, then L bytes (at most 4096 and at most what is left) in a heap copy of L + 1 bytes ending in NUL |
| `char *` (writable) | up to 4096 | a fixed 4097-byte heap buffer holding the next 4096 bytes (or what is left), no prefix |
| `fmt`, `format` and the last `char *` of a variadic function | 2 + L | as `const char *`, with every `%` replaced by a space |
| `const wchar_t *` | 2 + L wide characters | a 16-bit prefix counting wide characters (4 bytes each on Linux), at most 2048 |
| `const char **` with a count | 8, then strings | a count modulo 17, then that many length-prefixed strings of at most 256 bytes |
| `T *items` with a count | 8 | a count modulo 65 sizes a zeroed array of that many elements |
| struct or union | its fields' bytes | each field by its own rule, in declaration order, nested up to 4 deep; arrays fill at most 64 elements |
| pointer to a scalar or enum | the scalar's bytes | the address of a local holding the decoded value |
| C++ `T &` | `T`'s bytes | a local decoded as `T`, passed by reference |
| C++ `std::string`, `std::string_view` | 2 + L | as `const char *` |
| C++ `std::vector<T>` and other sequences | 8, then elements | a count modulo 17, then each element (a byte vector or span is the whole input, below) |

The length-named, offset-named and channel-count names are the ones listed
above. Some parameters read no cursor bytes and are fed from the input as a
whole. Within one call they are decoded after every cursor parameter of that
call, whatever their position in the signature, and they take the bytes the
cursor left (the *remaining input*). For the target call of a direct harness
with no cursor parameter, that is the whole testcase:

- a byte buffer paired with a length-named integer: a read-only buffer is a
  view of the remaining input and its length is the remaining size; a
  writable one is a heap copy of it (at most 1 MiB) and its length is the
  copy's size;
- a read-only byte pointer with no length partner (`const uint8_t *`,
  `const unsigned char *` or a typedef of one): a NUL-terminated heap copy of the
  remaining input, `max(remaining + 1, 8)` bytes, zero-filled past it. It is a
  copy, not a view of the fuzz input, so ASan reports overflows against that
  allocation;
- `const void *` with no partner: a view of the remaining input; `void *`: a
  heap copy;
- a writable byte pointer with no partner (`unsigned char *`, `uint8_t *`): a
  heap copy of the remaining input with 64 KiB of zeroed headroom;
- C++ byte vectors and spans (`std::vector<uint8_t>`,
  `std::span<const uint8_t>`): a copy or view of the remaining input;
- `FILE *`: `fmemopen` over a copy of the remaining input (on Windows, which
  has no `fmemopen`, a temporary file holding it, deleted on close);
- the path parameter of a file loader (`load_file(const char *path)`): the
  remaining input written to a temporary file;
- a read-only pointer to a record bhf cannot construct: a view of the
  remaining input.

So for `f(const uint8_t *data, uint32_t a, uint32_t b)`, `a` is bytes 0-3, `b`
bytes 4-7 and `data` the bytes from 8 on, and for
`g(const char *buf, size_t len, int flags)`, `flags` is bytes 0-3 and the pair
the rest. No input byte feeds two parameters of one call. A seed (a sample
file of the buffer's format) is therefore also given behind as many zero
bytes as the fixed-width parameters before the buffer take, 8 for `f`, so the
buffer starts with it (see [Seeds](auto.md#seeds)).

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

The remaining input has no length of its own: a buffer without a length
parameter is as long as the input lets it be. Set
`BHF_BUFFER_LEN_DIMENSION=1` when generating the harness (`bhf generate-harness`
or `bhf auto`) to give it one. A buffer with no length partner then gets
exactly its bytes in a heap copy of that size (a `const void *` view
included, so the sanitizer sees the shorter buffer): one before the call's
last buffer gets its slice, above, without the input-sized allocation, and
the call's last buffer takes a sized slice too, after the cursor parameters
and the other buffers (4 more bytes, a little-endian length clamped to the
bytes left, then that many bytes). It is off by default: a buffer shorter
than the input can make a function with an implicit length contract read
past it, a crash the harness made. The harness records it only where it
gave a buffer a length (`buffer_len_dimension` in `arg-layout.json` and
`generation-metadata.json`, and `with an explicit buffer length` after the
format stamp in the source); a harness whose buffers all have a length
partner decodes the same with it on and records nothing.

A C++ method's receiver is decoded after the target's own cursor parameters. A
default-constructible class takes no input bytes; otherwise its constructor or
factory arguments are decoded next, by the same rules. A mined protocol then
decodes each step's arguments before that step's call. A lifecycle loop reads
one byte for the number of steps (modulo the step count plus one), then for
each step one selector byte (modulo the step count) and that step's
arguments. The target's whole-input parameters come last, right before the
target call, so they take only bytes the constructor, the factory and the
loop did not read. Constructor, factory and step arguments that use the whole
input take the input remaining when that call is decoded (after the target's
cursor parameters), which a later call can read again. A mined protocol step
bound to the input by the project's own tests keeps the whole input. A C
sequence harness keeps its operation program in a control block at the end of
the input (`sequence-layout.json` gives its length) and decodes the calls'
arguments from the front. A call's whole-input parameters take the argument
bytes the cursor left when the call is decoded, never the control block. Only
a call that runs once before anything read the cursor (the constructor, a
configuration call, the first protocol call) and reads no cursor bytes itself
keeps the whole input.

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

When the fuzz loop records a new C/C++ crash (builtin engine, fork-server or
AFL++), it re-runs the testcase once with the trace on. `decoded.json`
(`schema_version` `bhf.decoded.v1`) then holds every traced value in
`arguments` (a length-prefixed string also gets `length_prefix`, the 16-bit
prefix its bytes ask for, next to the `len` the harness took) and their byte
ranges in `provenance`, or `arguments_unavailable` with the reason. `finding.json` gains `decoded_args`, the target call's
arguments with `name`, `type`, `role`, `value` or `len`, `span`, `preview_hex`
and `after_call_value`. When a heap access hits a region a traced buffer
starts (`basis` `region_start`) or points into (`region_interior`, for a view
that starts after the bytes other parameters took), `exception.access.parameter`
names that parameter and the access offset from its pointer. For a wild access
with no region it names the nearest traced pointer below the faulting address
(`nearest_pointer`). `bhf replay --show-args` re-runs the harness with the trace
and prints the arguments as a table. `bhf explain` shows the same table under
HARNESS ARGUMENTS, and `bhf cartography` labels each byte with the parameter
it was decoded into. Harnesses generated before the trace existed print
nothing: regenerate them, or read the arguments under a debugger. A
passthrough harness, which hands the input straight to the project's own
`LLVMFuzzerTestOneInput`, decodes no parameters, and `--show-args`,
`decode-args` and `decoded.json` say so. `bhf report --backfill` records the
decoded arguments of a finding that has no `decoded.json` (one migrated from
an earlier release) when its harness has the trace. In
`bhf explain`'s HARNESS ARGUMENTS table, an argument whose bytes a recorded
comparison read is tagged `[compared at <file>:<line>]` (or the comparison's
address when it could not be symbolized). The length of a `(buffer, length)`
pair holds the input's size, not input bytes, and is never tagged; its buffer
is. Evidence recorded on
`min_testcase.bin` is related to the parameters through `arg-layout.json`
decoded over that file. The results `findings.json` carries the accessed
parameter as `fuzz.access.parameter`, and `findings.csv` the arguments
(`arguments`) and that parameter (`access_parameter`).

### Decoding a testcase without running it

Generation also writes `arg-layout.json` beside `main.c` / `main.cpp`
(`schema_version` `bhf.arg-layout.v1`, recorded as `arg_layout` in
`generation-metadata.json`): the decode steps in the order the harness runs
them. Each parameter step gives its `call`, `index`, `name`, `type` and
`order`, where its bytes come from (`input`: `cursor`, `remainder`,
`whole_input` or `none`), the decoder kind (`decoder`: `scalar`,
`bounded_int`, `enum_member`, `length_prefixed_string`, `capacity_string`,
`rest_view`, `input_buffer`, `input_length`, `input_end` (the `end` of a
`[begin, end)` pair, one past the buffer's bytes), `input_stream`,
`input_file`, `fixed` or `other`), its `primitive` (`bhf_i32`, `bhf_c_string`, ...),
`width`, `endianness`, `value_kind`, bounds (`lo`, `hi`), enum `members`,
`length_prefix_bytes` and `max_len`, whether a buffer is `copied`, whether
the value is a C string read up to its first NUL (`nul_terminated`), the
constant a `fixed` parameter is given (`fixed_value`), the
other half of a pair (`paired_with`), and `static_decode` with a `note` when
its value cannot be computed from the description. A `remainder` step marks
where a call's whole-input parameters take the bytes the cursor left (`sized`
with the explicit buffer-length dimension), and an `opaque` step a lifecycle
loop, whose input use is known only at run time. In a call with several
buffers, each buffer but the last follows a `sized` `remainder` step of its
own, after the cursor steps: its 4-byte length, then its bytes.

`bhf decode-args` maps a testcase to the value of each parameter:

```sh
bhf decode-args --finding F-0003-9c1d22e0            # its testcase.bin and harness
bhf decode-args crash.bin --harness bhf_work/harnesses/H-C0001
bhf decode-args --finding F-0003-9c1d22e0 --static --json
```

With a built harness that has the argument trace it runs it once with
`BHF_TRACE_ARGS=1` and shows its `BHF_ARG` values. Without one (a work dir
copied without binaries, a cross-compiled harness) or with `--static`, it
replays `arg-layout.json` over the testcase: scalars (and C++ references to
them, which the harness decodes as their referent), bounded integers,
enums, length-prefixed and capacity strings, and remainder, whole-input and
paired buffers are decoded as `bhf_decode.h` decodes them (a C string's
length and preview stop at its first NUL byte, as the target reads it and
the trace prints it; its span covers every byte it was decoded from), a
parameter the harness sets to a constant (`fixed_value` in the layout) shows
that constant, and every other
parameter, and every one decoded after a step the layout cannot replay (a
struct decoded field by field keeps the count of bytes it reads; a lifecycle
loop or a wide string does not), is listed under `not decoded statically`
with the reason. A sequence harness picks its calls from its control block,
so its layout is not replayed. `--json` prints one `bhf.decode-args.v1`
document (`source` `harness_trace` or `arg_layout`, `arguments`,
`not_decoded`, `notes`). A finding recorded with another harness input
format than the layout gets a note, since its bytes decode differently.

### Reading arguments in a debugger

`bhf replay --debugger` does this for you: it runs the testcase under gdb or
lldb (cdb on Windows) in batch mode, breaks at the target function the
generation metadata names, prints `info args` and `bt full` there, then
continues to the crash and prints `bt full` again, with
`ASAN_OPTIONS=handle_segv=0:abort_on_error=1:detect_leaks=0` so the debugger
sees the fault and with the replay's runtime mode, injected variables and
runtrace shim, so a crash that depends on them happens there too (see
[CLI](cli.md#replaying-a-finding)). The session runs the harness outside the
replay's sandbox. By hand, harnesses
are built with `-O1 -g`, so gdb can show the target's arguments:

```sh
gdb -q -batch -ex 'set debuginfod enabled off' -ex 'break <target>' -ex run -ex 'info args' \
    --args bhf_work/harnesses/<id>/main bhf_work/results/findings/<ID>/testcase.bin
```

- A reference parameter prints with `p offset`, not `p *offset`.
- A buffer's allocation size is
  `call (unsigned long)__sanitizer_get_allocated_size(buffer)`.
- For a SEGV, run with `ASAN_OPTIONS=handle_segv=0` and `-ex run -ex 'bt 4'`:
  gdb stops on the signal with the arguments in the backtrace.
- For another ASan report, `-ex 'break __asan::ReportGenericError' -ex run
  -ex 'frame 2' -ex 'info args'` (frame 1 is `__asan_report_load*`).
- For UBSan, run with
  `UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_stacktrace=1` and
  `-ex run -ex bt`, or break on the check's handler
  (`__ubsan_handle_mul_overflow`) and use `frame 1`.
- At `-O1` a local can print `<optimized out>`: break at the target's entry,
  where the arguments are live, or rebuild a copy of the harness with
  `make -B main CFLAGS='-O0 -g -fsanitize=address,undefined'`
  (`CXXFLAGS='-O0 -g -std=$(CXX_STD) -fsanitize=address,undefined'` for C++).

### Harness format version

Whenever a change makes the same input bytes decode to different argument
values, the harness format version is bumped. Each harness records it as
`harness_format_version` in `generation-metadata.json`. It also appears at the
top of the generated `main.c` / `main.cpp` (`bhf harness format 4`). A harness
with no recorded version is format 1.

Format 2 changed two things. An unsigned input with its top bit set, or a
`size_t` that is not named like a length, now decodes to a different value.
And `(buffer, integer)` pairs whose integer is not named like a length are no
longer bound to the input length or to an output buffer's capacity. Corpora
from format 1 still run, but their inputs can exercise different values.
Re-run the corpus and re-triage findings recorded against a format 1 harness.
Do not compare them directly.

Format 3 is the layout above: a call's whole-input parameters take the bytes
its cursor parameters left, instead of the whole input again, and a C++
method's whole-input target parameters come after its receiver's arguments.
A testcase of a call that mixes the two kinds (`f(data, a, b)`) decodes
differently: under format 2, `data` was the whole input and also overlapped
`a` and `b`. A direct harness whose target call has only cursor parameters, or
only whole-input ones, decodes as before, except that a C++ receiver's
constructor, factory and step arguments and a sequence harness's operations
now take the bytes the cursor left instead of the whole input. Ada harnesses
keep format 2: their decoding did not change.

Format 4 gives every buffer of a call that takes several its own bytes (each
but the last a sized slice, above) instead of the same remaining input, and
binds every `(buffer, length)` pair of a call, not only the first. It also
pairs the counts named `nElem`, `numberOfElements` or a bare `cb`, gives a
lone pointer-typedef buffer (`LPCBYTE`) a heap copy of the input instead of
one byte, and renames a parameter named like a harness local. A testcase of
a call with any of these shapes decodes differently under format 3; any
other harness decodes its inputs as format 3 did.

A harness generated with `BHF_BUFFER_LEN_DIMENSION=1` decodes the same
format differently again, so a finding also records `buffer_len_dimension`
when the harness that found it had it on, and the notes below also flag a
finding replayed against a harness generated with the other setting.

`bhf generate-harness` (and so `bhf auto`) prints a warning when it regenerates
a harness directory whose recorded format differs from the one it writes.
`bhf replay` prints a note when the harness it replays against was generated
with another format. Each new finding records the format of the harness that
found it, as `harness.format_version` (and `harness.buffer_len_dimension`) in
`finding.json`, with the older top-level `harness_format_version` kept for
earlier readers, and writes the same to the harness's corpus metadata
(`corpus/<id>/metadata.json`, `bhf.corpus-metadata.v1`). Every fuzz pass
writes it too, whether or not it found anything: a corpus the pass creates
gets it before its first input, and every corpus at the end of the pass.
`bhf auto` notes when a corpus was recorded against another format than the
harness it fuzzes, and when a corpus holds inputs but no metadata (one an
earlier release left, kept with `--reuse-legacy-corpus`): it was recorded
before formats were stamped, so its inputs are format 2 or earlier.
`bhf replay`, `bhf minimize`, `bhf decode-args` and `bhf capsule` read the
finding's format from `harness` first, then the top-level key, then the
harness dir's metadata. They compare it with the harness they run, and when
they differ say so: replay as a `note` (also in `--json` `notes`), minimize
on stderr, and capsule as a warning and as `harness_format_note` in the
capsule's `manifest.json` (with `harness_format_version` and
`finding_harness_format_version`). A finding that records no format came from
a format 2 or earlier harness, so it is flagged against a format 3 or later
harness. Such a finding replays as recorded against a harness of its own format; against
a regenerated harness its testcase decodes into other arguments, so fuzz the
regenerated harness again rather than comparing the two.

## Supported C Parameter Shapes

The C emitter supports:

- scalar integer and length-like types, including common zlib/miniz aliases;
- `const char *`, `char *`, standalone immutable byte pointers as a
  NUL-terminated heap copy of the fuzz input (see the decoding layout above),
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

For first-parameter `struct T *` lifecycle APIs, `--kind sequence` and
`bhf auto` can drive a bounded operation loop with same-source init/end
helpers. If those lifecycle boundary helpers are `static`, BHF includes the
defining `.c` file into `main.c` and omits it from separate linking. Other
static same-handle operation helpers are still excluded unless they are the
selected target.

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
  using C++20 when needed.
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

Member-function support is heuristic. If a qualified target looks like
`namespace::Class::method`, the harness creates a receiver and calls the
method. It can use default constructors or supported public parameterized
constructors. `--kind sequence`, and `bhf auto` when same-class setup
methods are visible, emits a bounded method-sequence harness before the target
call. Sequence setup selection skips methods known to be `private` or
`protected`; classes whose only known constructors are non-public are blocked
with wrapper/factory guidance instead of emitting an invalid receiver
construction. Abstract classes — those that declare a pure-virtual member
directly (`virtual ... = 0;`) — cannot be instantiated as receivers either,
and are skipped with the same factory/wrapper guidance. Add a public test
wrapper when important state transitions are intentionally hidden behind
non-public helpers.

## Findings

C/C++ findings come from sanitizer reports and runtime-audit evidence. The
built-in BHF engine invokes libFuzzer-style `main` binaries one input at a
time and parses sanitizer stderr. AFL++ mode runs `afl-fuzz` against the staged
`main_afl` sanitizer binary, then replays crash artifacts through that binary to
emit normalized findings.

When `bhf auto` runs with the runtrace shim, the built-in engine also
evaluates executable oracle hits per input. The current executable oracles
promote file APIs that receive paths with a parent-directory segment such as
`../secret`, and network egress destinations observed through connect or
resolver audit events, and secret-like environment variable names observed
through redacted `getenv` or `secure_getenv` audit events, into
`classification: "oracle_hit"` findings carrying the oracle name, API, and
runtime evidence without recording the environment value. Shell command strings
observed through `system` or `popen` are promoted when they contain
command-injection
metacharacters. Printf-style format strings observed through `printf`,
`fprintf`, `dprintf`, `sprintf`, or `snprintf` are promoted when the format
bytes match the current fuzz input and contain a conversion marker. The same
per-input runtrace stream now reports audited file descriptors that are opened
and not closed before the harness execution exits. Successful `unlink`,
`unlinkat`, or `remove` calls with parent-directory paths promote to
`file-deletion-runtime` BHF-414 findings. Native C/C++ assertion failures
observed through the runtrace shim promote to `native-assertion-contract`
BHF-415 findings with expression and source evidence. File-open calls
(`open`, `openat`, `fopen`) reached by a fuzz-controlled path promote to
`path-controlled-open-runtime` BHF-405 findings carrying a `taint_path`
source→sink string (`fuzz_input[offset..] → open(path)`). The shim stamps
byte-origin taint on each path event, and the CLI confirms the finding by
cross-execution matching: a path is reported only if it carried taint on at
least one execution and was never opened untainted across the run, which
suppresses program constants the auto-dictionary echoes back into inputs. Like
the other runtime promotions, the resulting record is stamped
`confirmation: "runtime"`, distinguishing it from a static-scan candidate. Ada
runtime instrumentation can feed
handled `Constraint_Error` range/index check events, `Storage_Error`,
`Tasking_Error`, and user-defined exception events into the same SDK; those
become `ada-runtime-constraint-check` BHF-102, `ada-runtime-storage-error`
BHF-103, `ada-runtime-tasking-error` BHF-104, or `ada-runtime-user-exception`
BHF-105 oracle findings.

The runtrace shim is native-only. The behavioral and taint oracles above
(BHF-405 path-controlled open, the command-injection and sensitive-environment
promotions, BHF-414 file-deletion, and the other runtime promotions) are not
armed for cross-compiled targets fuzzed under qemu-user or Windows binaries run
under wine. RTOS stub-isolated builds are likewise compiled without the shim, so
they do not carry these oracles either.

For cross-implementation checks, `bhf differential` replays the same input
directory through two harness binaries and emits BHF-301 output-divergence
findings stamped with the `differential-output-runtime` oracle when stdout,
exit status, or timeout behavior differs.
The same command supports single-harness metamorphic checks with `--harness`
and `--metamorphic-transform append-newline`; BHF compares original versus
transformed execution and emits BHF-307 `metamorphic-relation-runtime` findings
when the relation is violated.

Ada-only findings such as swallowed exception breadcrumbs, Ada handler paths,
and generated `repro.adb` files do not apply to C/C++ targets.

### Reproducing a finding offline

Every C and C++ crash finding can be handed off without the work dir:

```sh
bhf capsule --work-dir bhf_work --finding-id <ID>     # package it
bhf verify-poc bhf_work/capsules/capsule_<ID>          # rebuild + replay it anywhere
bhf cartography --work-dir bhf_work --finding-id <ID>  # which input bytes steer it
```

A C capsule rebuilds with `clang` (or `$CC`), a C++ one with `clang++` (or
`$CXX`), from the harness driver, the target sources and the headers they
include in their original layout, the repair stubs (their absolute
`#include`s made relative to the capsule), and what `bhf auto` or `bhf build`
recorded for the build: the language standard, the extra sources, the
`AUTO_EXTRA_*` and `[toolchain]` flags and the compatibility flags.
`bhf verify-poc` compares the replay with the finding's rule, kind and sink
or site, as `bhf replay` does. `python3
bhf_work/results/findings/<ID>/replay.py` replays a finding against the work
dir's own harness binary. See [CLI](cli.md) for the full behavior.

## Generated Dictionaries

C and C++ harness generation writes `dictionary.txt` beside `main.c` or
`main.cpp` when source or included headers expose reusable tokens. The
dictionary mines enum members, object-like string/integer `#define` constants,
string literals, and switch `case` labels, including inline labels. C++ source
and header mining uses the C++ parser, so scoped `enum class` members are
included both as leaf tokens and qualified `Enum::Member` tokens. The built-in
engine loads that dictionary automatically for token
insertion plus record/TLV-, JSON-, XML element-, key/value-, URL-encoded
query-string, multipart/form-data, CSV/table-row, raw HTTP request, INI
section/key, TOML table/key, and YAML section/key input synthesis. AFL++ mode
passes the same dictionary with `-x`. A `# from <file>:<line>` comment above
each token names up to three places it was found, so `# from widget.c:12,
include/widget.h:3` points at the comparison or constant it came from. The
comparison constants the engine observes at runtime go to
`learned_dictionary.txt` beside it (see [CLI](cli.md)).

Use `bhf fuzz --structured-inputs off` to disable the built-in
structured synthesis for a target, `--structured-inputs record` for only the
TLV-style record mutator, `--structured-inputs json` for only JSON-shaped
object/array synthesis, `--structured-inputs xml` for only XML element
synthesis, `--structured-inputs kv` for only newline-delimited key/value
synthesis, `--structured-inputs url` for only URL-encoded query-string
synthesis, `--structured-inputs multipart` for only multipart/form-data
synthesis, `--structured-inputs csv` for only CSV/table-row synthesis, or
`--structured-inputs http` for only raw HTTP request synthesis, or
`--structured-inputs ini` for only INI section/key synthesis, or
`--structured-inputs toml` for only TOML table/key synthesis, or
`--structured-inputs yaml` for only YAML section/key synthesis, or
`--structured-inputs recursive` for only recursively-nested grammar synthesis
(balanced delimiter pairs nested to depth, to stress recursive-descent parsers).
`auto` is the default and enables all structured mutators; the dictionary-backed
ones additionally require a mined dictionary, while the recursive nesting mutator
runs even without one.

## Current Limits

- C++ parser support is tree-sitter-based and heuristic around templates,
  overloads, macros, nested namespaces, operators, and declarations hidden by
  build-system conditionals. It records straightforward class/struct member
  access for methods and constructors, but macro-generated declarations may
  still need wrappers.
- Complex object graphs, custom allocators, ownership-bearing pointer-to-pointer
  APIs beyond nullable `void **` output slots, callbacks that require semantic
  side effects, unsupported constructors, non-aggregate C++ class inputs, and
  virtual dispatch usually need a hand-written wrapper. See
  [Custom C and C++ Harnesses](../custom-harness/) for writing one and
  running it through `bhf build`, `bhf fuzz` and the triage commands.
- Build-system ingestion consumes a pre-existing `compile_commands.json`;
  `--probe-build` recovers one from CMake, Meson, MSBuild, Make/autotools,
  Ninja, Bazel, and SCons; and `--build-command` recovers one from any other
  build via compiler interception. Interception captures the per-file compile
  flags (`-I`/`-D`/`-std`/force-includes), not the full build graph. Compilers
  invoked by name *or* by absolute path *or* via `posix_spawn` are all captured;
  a statically-linked compiler (which ignores `LD_PRELOAD`) invoked by absolute
  path is the remaining blind spot.
- C/C++ direct harnesses are instrumented with
  `-fsanitize-coverage=trace-pc-guard,trace-cmp` and a built-in SanitizerCoverage
  runtime (edge presence, AFL hit-count buckets, opt-in comparison-progress via
  `--comparison-progress` (alias `--cmp-progress`), cmplog/RedQueen capture, and
  value-profile dictionary mining); IDE and daemon
  parity with the Ada lane is still partial.

For those reasons, C/C++ support is practical for direct-call byte-oriented
targets today, with object-heavy and dependency-heavy C++ parity tracked as
active product work.
