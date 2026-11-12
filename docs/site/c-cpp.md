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
Makefile and `bhf build` prefer `clang` / `clang++`. The generated sanitizer
and coverage flags are clang's unless the harness was generated from a gcc
compile database, so leave `CC`/`CXX` unset or point them at clang; a
`CXX=g++` build of a clang Makefile fails on unrecognized options.

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
parentheses, apostrophes and the characters `* ? [ ] { } ~ !`. The generated
Makefile double-quotes such paths in recipes and never uses them as make
prerequisites, so a tree under `/home/Dana Smith/...` or
`C:/Program Files (x86)/...` builds like any other. Compile-database flags
that name such paths are quoted too: single-quoted, or double-quoted when they
contain an apostrophe (`-I/home/Dana's tree/include`). A `--differential`
compiler given as a path with spaces is quoted the same way. A path or flag
with a character no quoting can make safe is refused before generation, and
the message names the character: `$`, `#`, a backtick, a double quote, a
backslash, `;`, `|`, `&`, `<` or `>`. On Windows, where `\` separates path
components, `%` and `^` are refused instead of the backslash.

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

`bhf build` compiles exactly the sources the Makefile lists; it has no repair
loop. When the link fails on symbols defined elsewhere in the tree, it prints
the defining files with the `--extra-source` flags to regenerate with and an
`AUTO_EXTRA_SOURCES=... bhf build ...` command that needs no regeneration. It
also suggests `AUTO_EXTRA_INCLUDES='-include iostream'` for standard streams
used without their header, and `-fms-extensions` (clang++) or `-fpermissive`
(g++) for a member declared with an extra class qualification
(`int Widget::name();` inside class `Widget`), which only MSVC accepts. Each
suggested command keeps the build variables you already set, and when several
apply a last line combines them. `bhf auto` reports the same extra
qualification with the flag to set but does not add it itself. Extra build
input comes from the environment:
`AUTO_EXTRA_SOURCES` (sources), `AUTO_EXTRA_INCLUDES` (any compile flags:
`-I`, `-D`, `-include`, `-fms-extensions`), `AUTO_EXTRA_LDFLAGS` (link flags)
and `CXX_STD`/`C_STD` (language standard). Do not use `CXXFLAGS`/`CFLAGS` for
this: they replace the sanitizer and coverage flags.

To *recover* a database when none exists, `--probe-build` runs the project's own
build offline and captures the real compile flags. It detects and drives CMake
(`-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`), Meson (`meson setup`), MSBuild
(Visual Studio `.vcxproj` parse), Make/autotools (a compiler-interposing `CC`/`CXX` wrapper),
standalone Ninja (`ninja -t compdb`), and — under compiler interception — Bazel
(`bazel build //...`) and SCons (`scons`).

For any *other* build — a custom `build.sh`, Waf, a vendor RTOS build, or a
build named anything — `--build-command "<cmd>"` runs that exact command under
two complementary interceptors that record every compile into one
`compile_commands.json`:

- a front-of-`PATH` compiler shim that catches `cc`/`gcc`/`clang` and the named
  vendor compilers common in radar/RTOS work (Wind River Diab `dcc`/`dplus`,
  Green Hills `ccarm`/`cxarm`, QNX `qcc`/`q++`, Keil/IAR, TI) plus cross-prefixed
  GNU/LLVM toolchains invoked *by name*; and
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
  the run-together counts `nmemb`/`nitems`/`nelem`, OpenSSL's `inl`/`outl`,
  `argc`, `avail`, `remaining`, and the Win32 `cb`/`cch` prefixes (`cbData`,
  `pcbData`, `cchName`). A trailing digit is ignored (`len1`, `size_2`). A count marker
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
  (`LPCBYTE`, `PBYTE`, `typedef const u8_t *cu8_ptr`) pairs too. The typedef
  hides whether the bytes are const, so that buffer is always a heap copy of
  the input, and its length is the copy's size.
- **Unsigned integers.** Unsigned parameters, struct fields and output-pointer
  values cover their full range, `size_t` included, so values with the top
  bit set (`0x80000000`..`0xffffffff`, wrap-around sizes, bit masks) are
  reachable. Values named like a length, size or count stay bounded: a
  `size_t` or `z_size_t` length stays in `0..=65536`, and any other unsigned
  length stays in `0..=0x7fffffff`. A huge length only produces allocation
  failures. Each value consumes the same number of input bytes either way.

### Harness format version

Whenever a change makes the same input bytes decode to different argument
values, the harness format version is bumped. Each harness records it as
`harness_format_version` in `generation-metadata.json`. It also appears at the
top of the generated `main.c` / `main.cpp` (`bhf harness format 2`). A harness
with no recorded version is format 1.

Format 2 changed two things. An unsigned input with its top bit set, or a
`size_t` that is not named like a length, now decodes to a different value.
And `(buffer, integer)` pairs whose integer is not named like a length are no
longer bound to the input length or to an output buffer's capacity. Corpora
from format 1 still run, but their inputs can exercise different values.
Re-run the corpus and re-triage findings recorded against a format 1 harness.
Do not compare them directly.

`bhf generate-harness` (and so `bhf auto`) prints a warning when it regenerates
a harness directory whose recorded format differs from the one it writes.
`bhf replay` prints a note when the harness it replays against was generated
with another format. The finding still replays against that harness as built,
but a regenerated harness decodes its testcase differently.

## Supported C Parameter Shapes

The C emitter supports:

- scalar integer and length-like types, including common zlib/miniz aliases;
- `const char *`, `char *`, standalone immutable byte pointers as borrowed
  fuzz-input views, and byte pointer plus adjacent length pairs, including
  typedef aliases such as `const mz_uint8 *`;
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
include in their original layout, the repair stubs, and the language standard
and extra sources bhf recorded for the build. `python3
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
passes the same dictionary with `-x`.

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
