<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

## Unreleased

### Fixed
- The explicit buffer-length dimension (`BHF_BUFFER_LEN_DIMENSION=1`) is
  recorded only for a harness it gave a buffer a length: the source stamp,
  `arg-layout.json` and `generation-metadata.json` `buffer_len_dimension`,
  and so the finding and corpus format, no longer claim it for a harness
  whose buffers all have a length partner, which decodes the same with it
  on. Under the dimension a call's length-less buffers, its last one and a
  `const void *` view included, take a heap copy of exactly their bytes, so
  the sanitizer sees the shorter buffer; without it they stay as large as
  the input.
- Every fuzz pass records its harness's input format in the corpus metadata
  (`corpus/<id>/metadata.json`), whether or not it found anything: a corpus
  the pass creates gets it before its first input, and every corpus at the
  end of the pass. `bhf auto` notes a corpus that holds inputs but no
  metadata (an earlier release's, kept with `--reuse-legacy-corpus`) as
  recorded before formats were stamped, format 2 or earlier, instead of
  saying nothing.
- `bhf decode-args --static` decodes a C++ reference to a scalar
  (`unsigned short &offset`, `const unsigned int &mask`) as the scalar it
  refers to, as the harness does, instead of listing it under "not decoded
  statically". `arg-layout.json` describes it like the plain scalar
  (`value_kind`, `static_decode`), so explain's argument evidence covers it
  too.
- C and C++ harnesses bind more lengths to their buffers, so correct code no
  longer reports an overflow the harness made: counts spelled `n` or `num`
  ahead of an element noun (`nElem`, `nMemb`, `nItem`, `nTok`, `numEntry`),
  `number of` ahead of a plural (`numberOfElements`, `number_of_bytes`), and
  the bare Win32 `cb`/`cch` (`const BYTE *pb, DWORD cb`) now pair. A callback
  named `cb` still never pairs, and Hungarian integers (`nValue`, `nIndex`,
  `nMode`) are still ordinary values.
- The `end` of a `[begin, end)` pointer pair is traced and decoded as
  pointing at no bytes: `BHF_TRACE_ARGS=1` gives it length 0 instead of
  reading past the pair's buffer (which aborted a traced run once the pair
  took a buffer of its own), and `arg-layout.json` describes it with the new
  `input_end` decoder, so `bhf decode-args --static` agrees.
- A byte buffer spelled through a pointer typedef (`LPCBYTE`, `PCBYTE`,
  `PCUCHAR`, or a project's `typedef const BYTE *bytes_t`) with no length
  partner is a heap copy of the input, as a spelled `const unsigned char *`
  is, instead of one byte of storage the callee read past; with a count it
  pairs in both lanes without a typedef in the scanned tree.
- A target parameter named like one of the harness's own locals (`Data`,
  `Size`, `Cur`, `R`, a `_bhf_` or `bhf_` name) gets a local of its own
  (`bhf_arg_<name>`). Such a harness used to initialise the parameter from
  itself (and crash on every input) or fail to build. The trace, the layout
  and `decode-args` keep the declared name.
- Every buffer of a call that takes several gets bytes of its own: each but
  the last takes a sized slice of the input (a 4-byte length, then that many
  bytes, in a heap copy of its own), and the last the bytes the cursor left.
  A buffer with a length (or a `FILE *`) gets exactly the slice's bytes; one
  without keeps an allocation as large as the input, the slice's bytes then
  zeros, so a function reading it for another argument's length
  (`memcmp(a, b, n)`) stays inside it. Only the first `(buffer, length)` pair
  of a call used to be bound: a second pair's length was decoded on its own
  and could exceed its buffer, and two buffers got the same bytes.
  `arg-layout.json` gives each slice a sized `remainder` step, so
  `bhf decode-args --static` decodes these calls exactly.
- `bhf replay` no longer reports MATCH, stamps `last_seen` or records a
  reproduction in `results/` for a replay that could not compare where the
  crash happened. An unsymbolized report (frames that name only a module
  offset) is `UNVERIFIED recorded=<rule> actual=<rule> not_compared=sink`
  with exit code 4 (`"verdict": "unverified"` in `--json`). When the harness
  is the recorded build (its sha256 is `build.binary.sha256`), replay
  symbolizes such a report itself with `llvm-symbolizer` or `addr2line` and
  compares again. A finding that records no crash location (no frames, sink,
  site or pc) matches only the recorded build. Fuzz, replay and minimization
  children put `symbolize=1` after an inherited `ASAN_OPTIONS`/`UBSAN_OPTIONS`.
- A fatal signal without a sanitizer report records its signal
  (`exception.signal`, and as `exception.check`), and replay compares it: an
  abort finding replayed against a harness that dies of an illegal
  instruction is `MISMATCH ... differs=signal`. The recorded faulting pc
  offset is compared against the recorded build. Minimization of a C/C++
  finding keeps a reduction only when it is the recorded crash (same rule,
  kind, signal, and sink, site or pc), so an abort is no longer minimized into
  an input that crashes with another signal somewhere else.
- The unsymbolized-replay note names its cause: a fatal signal that printed no
  sanitizer report, a stripped harness binary, or an inherited `symbolize=0`,
  before the symbolizer advice.
- A replay or minimization timeout kills the harness's whole process group,
  so a launcher whose child keeps running no longer hangs `bhf replay`, and
  output a leftover process holds is waited for at most 2 s. The event-log
  (Ada) replay and minimization now time out after 10 s too.
- The "could not auto-resolve the harness" error names each directory it
  searched once (`looked in <dirs> for main, main_afl, main.exe or
  main_afl.exe`) and no longer searches `results/` or `results/findings/` as
  work dirs.
- An I/O or JSON error in the event-log replay names the file (finding.json,
  testcase.bin, the event log, decoded.json or the harness) instead of
  `I/O error during replay`.
- Crashes with no frames and no source position, such as the raw SIGSEGVs of
  a cross sweep's harnesses, are no longer one root-cause group for the whole
  work dir. Their key hashes the rule, kind, check name and the harness that
  found them (its id and target function), so two harnesses' crashes are two
  groups (`results/INDEX.md`, `explain`). bhf's driver, in a build without a
  sanitizer runtime, prints `bhf: fatal signal <SIG> pc=0x... addr=0x...
  exe_offset=0x...` before the signal kills the harness; the offset of the
  faulting instruction in the executable is recorded as
  `exception.pc_offset` and separates two crash sites of one harness.
- The generated `replay.py` merges bhf's sanitizer keys into an inherited
  `ASAN_OPTIONS`/`UBSAN_OPTIONS` instead of keeping the inherited value as it
  was: `UBSAN_OPTIONS` always gets `print_stacktrace=1:report_error_type=1:
  halt_on_error=1` and `ASAN_OPTIONS` `abort_on_error=1:halt_on_error=1` (plus
  `detect_leaks=1` for a leak finding), so `UBSAN_OPTIONS=suppressions=...`
  no longer turns a UBSan finding into a frameless report and `exit status: 0`.
  The script exits with the harness's status, 128 plus the signal for a
  harness killed by one.
- A C or C++ capsule's `build.sh` picks the sanitizer flags of the compiler that
  runs it (gcc has no `function` UBSan check and links its runtimes
  statically), as the harness Makefile does, and a capsule of a harness bhf
  built with gcc rebuilds with gcc: the default compiler is read off the
  harness binary when `$CC`/`$CXX` is not set (manifest `build_recipe`
  `compiler`, `compiler_family`, `compiler_source`). A launcher in front of the
  compiler (`CXX="ccache clang++"`) works for the capsule's include scan and
  for `build.sh`, and a compiler path with spaces stays one word. The C++
  standard-library fallback also works on libc++ hosts: it takes the
  compiler's libc++ (`-stdlib=libc++`) or an installed libc++ header dir when
  no libstdc++ works. It adds no libstdc++ search dir to a compiler that
  links libc++ (its driver passes `-lc++`), and still adds one to a compiler
  that links libstdc++ but cannot find it, on a host that also has libc++.
- `bhf env-capsule` records and replays a finding's world under the shim mode
  it fired in (`rng` or `fuzz_driven`, from `finding.json`
  `runtime_mode.pass`) with the environment variables the fuzz loop injected,
  so a crash found in bhf's RNG pass, or by a harness that does not hand its
  input to the shim, can be captured. Without `--finding-id` it applies the
  same exit rule as `bhf capsule` (one shared rule): it counts findings with no
  faked-environment crash as skipped, and when it captures nothing it says so
  and exits non-zero.
- Dictionary tokens holding CR, LF, TAB or another control byte are written
  as `\xNN` in `dictionary.txt`, `learned_dictionary.txt` and the IDL and Go
  lanes' dictionaries. AFL++ dropped a `\r`/`\n`/`\t` line with "Invalid
  escaping" and libFuzzer rejected the whole file.
- The coverage label of a fuzz run (`run.json` `coverage.source`) names the
  instrumentation the harness binary carries: `sancov-trace-pc` when GCC's
  debug information records code compiled with `trace-pc`,
  `sancov-trace-pc-guard` for clang's guards, `go-cover` for the Go lane, and
  `edge-bitmap` when the binary shows none (a build made without coverage
  included; the driver's coverage hook alone does not count), instead of
  `sancov-trace-pc-guard` for every edge map. The same label is in `run.json`
  `targets[].outcome.passes[].coverage_instrumentation`, in `finding.json`
  `build.binary.coverage_instrumentation` and in the report's coverage figure.
- Comparison evidence for a finding of a cross-built harness is recorded under
  the emulator the harness was fuzzed with (recorded beside it), instead of a
  native replay that could not run it. Cross builds without a sanitizer runtime
  link the driver's `memcmp`/`bcmp`/`str*cmp` wrappers (`-Wl,--wrap=`), so
  string and buffer gates reach the comparison log and the evidence there too,
  and comparison sites of 32-bit and big-endian ELF harnesses are symbolized.
- With a GCC toolchain, a build probe builds the project's archives with that
  GCC and GCC-spelled sanitizer and coverage flags (and no-op coverage hooks
  for the programs the probe build links of its own, kept at a path without
  spaces so a tree under a spaced path still configures), so they link into
  the GCC-built harnesses instead of clang-built AddressSanitizer archives. A
  toolchain that builds for another target leaves the host probe with clang.
- The Visual Studio project import reads a solution the way MSBuild would for
  one configuration: `$(SolutionDir)` is the solution's directory, local
  `<Import>`s and property sheets are followed, `Condition=` is evaluated for
  the chosen `Configuration|Platform` (the first listed for x64, or
  `--msbuild-config`) instead of taking every configuration's defines at once,
  `$(...)` resolves from the project files and the environment (a token left
  without a value is named on the console), and each `ClCompile` item's forced
  includes, undefines, language standard, `AdditionalOptions`, `CharacterSet`
  and `ExcludedFromBuild` apply. `\` in project paths is read as a separator
  on every host, so a solution analysed on Linux no longer yields include dirs
  the recipe guard refuses. With several solutions the choice is
  deterministic (shallowest, then by path) and printed; `.slnx` and
  single-quoted `Include=` are read too.
- A `compile_commands.json` written by an MSVC build (`cl.exe`, `clang-cl`)
  contributes its include dirs, defines, forced includes and language
  standard: cl options (`/I`, `/D`, `/U`, `/FI`, `/std:`, `/J`, `/Zp`,
  `/external:I`) are translated, the rest is named in
  `BUILD_CONTEXT_DROPPED`, and a `command` string is split by the Windows
  rules. The harness is still built by bhf's compiler choice. A launcher name
  (`ccache.exe`) is recognised with its `.exe` suffix and either separator.
- The C sequence-harness template's Windows crash handler is the chained
  unhandled-exception filter, as in the direct templates: a first-chance
  vectored handler turned exceptions AddressSanitizer handles itself into
  crashes.
- Windows reproducers start from a plain shell: after a harness build the
  sanitizer runtime DLL of the toolchain that built it is linked next to
  `main.exe` and its directories are recorded in `bhf-runtime-path.txt`,
  which `replay.py` puts on `PATH`. `results/INDEX.md` names `python` (not
  `python3`) on Windows, and `bhf explain` prints the `PATH` line for a direct
  run.
- A harness refused because its build context supplied a path or flag no
  recipe quoting can contain is reported as a failed build of the build
  context, not as an unsupported parameter type.
- A sanitizer stack frame whose source path contains spaces
  (`C:\Users\...\My Projects\...`) keeps the path whole, so the frame's
  function, `explain`'s sink and the call-frame chain no longer absorb part of
  the path.
- Unresolved symbols reported by the MSVC linkers (`LNK2019`/`LNK2001`,
  `lld-link: undefined symbol`, including lld-link's unquoted C++ signatures
  and `__declspec(dllimport)` names) are classified like GNU ld's, so the
  repair loop stubs them on Windows.
- `bhf explain` no longer presents dictionary substring matches as gates the
  engine solved. Its comparison evidence is recorded while the finding's own
  input runs: an input span counts only when a comparison operand equals its
  bytes and a replay with those bytes changed shows the operand change with
  them (for inputs of up to 32 bytes, flipping each byte also finds operands
  computed from them, such as a folded range check, and an operand that
  differs between two replays of the unchanged input, such as a process id or
  a clock reading, is not counted). Comparisons the harness makes while
  decoding the input are not the target's: the driver discards those made
  before the target is entered, and later ones in harness code are dropped
  when `llvm-symbolizer` locates them. Without evidence it says so and why
  (empty input, no instrumented comparison in the target, harness without a
  recording driver, computed operands not searched in an input over 32 bytes,
  ...) instead of "not gated". Dictionary tokens found in the input are
  listed only as labelled substring matches (3 bytes or more, at most 3
  occurrences). explain shows `min_testcase.bin` when there is one and names
  the file it shows, and notes when the input is a built-in starting input or
  a byte-identical copy of a listed seed.
- explain reads `dictionary.txt` with the engine's AFL parser: tokens
  containing `=` are no longer dropped, and `\r` is a carriage return.
- C/C++ dictionary mining skips `#include "..."` paths.
- `FAKED ENVIRONMENT` in explain says where its events come from: the replay of
  the finding's own input when the runtrace shim was loaded for it, else the
  harness's last fuzz pass (labelled as covering all of its inputs), and
  "environment not observed (runtrace shim not loaded)" when the shim was not
  loaded, instead of claiming no resources were touched.
- explain's reachability line says what the verdict rests on. A verdict
  inferred from the entry's signature reads "the signature of the entry ...
  matches an input-taking shape, so likely reachable from input; not proven",
  and an entry with no recorded
  reachability reads "not assessed" rather than attacker-reachable.
- Runtime cmplog (`BHF_CMPLOG`) produces records for sanitized C/C++ harnesses.
  The sanitizer defines `strcmp`, `memcmp` and `bcmp` in the executable, so the
  runtrace shim's hooks never ran; bhf's driver now writes the same records
  from the sanitizer's comparison hooks, which also cover `bcmp` and the
  `strcasecmp` family.
- The runtrace shim records `fopen` and `fopen64`, also in AddressSanitizer
  harnesses: its `dlsym` hook answers `dlsym(RTLD_NEXT, "fopen")` from an
  earlier object with the shim's hook, as `RTLD_NEXT` means, instead of
  resolving from the shim itself and skipping it.
- docs/site/c-cpp.md described a lone read-only byte pointer as a borrowed
  view of the fuzz input. The harness passes a NUL-terminated heap copy of the
  input, `max(Size + 1, 8)` bytes.
- Generated C/C++ Makefiles choose their coverage and sanitizer flags from the
  compiler that actually runs, at build time: `CC=gcc`/`CXX=g++`, a
  cross-prefixed gcc (from `CC`, a compile database or a build capture) and
  `.exe` driver names get GCC-spelled flags (`trace-pc,trace-cmp`, no
  `function`/`vptr` UBSan checks, statically linked sanitizer runtimes so the
  runtrace shim does not abort them) instead of failing on clang-only
  options. A compile database's compiler is only the Makefile default: the
  per-translation-unit object rules use `$(CC)`/`$(CXX)`, so an override or a
  retry reaches every unit.
- Objects are rebuilt when the compiler or its flags change in the same harness
  directory: every object and binary depends on a toolchain stamp (compiler,
  family and flags). A gcc retry, a cross build or a new `CC` between runs no
  longer links objects from the previous compiler ("file in wrong format").
  The MemorySanitizer, ThreadSanitizer, coverage and differential lanes link a
  driver object from their own compiler.
- `bhf build --target`/`--toolchain` apply to C/C++ harnesses (they select
  `<prefix>-gcc`/`<prefix>-g++`, or `--target=` for clang) instead of being
  ignored, and `--runtime`, `--probe-backend` and the `--ada-*` flags are
  refused for a C/C++ harness with the flags that do apply.
- The generated Ada project no longer writes a tool prefix as
  `Toolchain_Name`, which gprconfig cannot match; the prefix becomes the
  `Target` when none is given, and a gprconfig compiler name (`GNAT`) is still
  written as `Toolchain_Name`. A prefixed toolchain without a prefixed gprbuild
  uses the multi-target `gprbuild`, and the compiler canary prefers
  `<prefix>-gnatmake`, which takes compile switches directly.
- `bhf auto --sanitizers` keeps an operator's `CC`/`CXX` when they can build
  the requested sanitizers, with flags in their spelling; otherwise it says it
  uses clang and why. The gcc retry no longer replaces an operator's compiler
  and only swaps the compilers, keeping `trace-cmp` and the dialect ladder;
  `CC=clang` in the environment is bhf's own default and keeps the retry.
- A C translation unit of a C++ harness takes flags for its own compiler's
  family, so `CC=gcc` beside `clang++` no longer gets clang-only options, and
  toolchain C/C++ flags reach bhf's driver object (without `-std=`/`-Werror`),
  so an ABI-selecting flag such as `-m32` applies to the whole link.
- Relative paths in a `bhf auto` config file (`--config` or an auto-loaded
  `.bhf.toml`) resolve against the file's directory, not the working
  directory.
- `bhf auto --help` and the docs no longer claim every flag is a config key;
  they list the accepted keys, and a test keeps the list in step with the flags.
- C++ `--target` accepts a trailing qualified suffix, in `generate-harness`
  and `bhf auto`: `Class::method` selects `ns::Class::method`, with or without
  the parameter list. An exact spelling still wins: the suffix match applies
  only when no target has exactly that name, so `Class::method` keeps naming a
  global `Class` when a namespaced one also exists. A leading `::` names the
  global namespace only. `bhf auto --target` used to match only the full
  name, the name without its parameter list, or the bare name, so a value
  that matched nothing before can now select targets. When a suffix matches
  several functions, `generate-harness` lists every match and picks the first,
  as for overloads (`--target-line` picks one); `bhf auto` keeps them all. A
  target that matches nothing lists the closest definitions (and, in
  `generate-harness`, the accepted spellings). `generate-harness --help` now
  says `--target` is required for C and C++.
- `bhf build` reports the C/C++ harness lookup error (an unknown `--harness`,
  or several harnesses and no `--harness`, with the ids it found) instead of
  falling through to the Ada layout check ("missing src_instrumented"). It
  also accepts a harness directory or `<work>/harnesses` as its argument and
  prints the equivalent `bhf build <work> --harness <id>` command.
- A failed C/C++ `bhf build` explains itself: it names the in-tree sources
  that define the undefined symbols, with the `--extra-source` flags and an
  `AUTO_EXTRA_SOURCES=... bhf build ...` command that adds them, and suggests
  `-include iostream` for standard streams used without their header, `-l`
  flags for system libraries, and `-fms-extensions` (clang++) or
  `-fpermissive` (g++) for a member declared with an extra class
  qualification. Each suggested command keeps the `AUTO_EXTRA_SOURCES`,
  `AUTO_EXTRA_INCLUDES`, `AUTO_EXTRA_LDFLAGS`, `CXX_STD` and `C_STD` values
  the build ran with, and when several suggestions apply a last line combines
  them into one command. The make output still streams while the build runs.
- Standard stream names used without their header (`cerr`, `cout`, `cin`,
  `clog`, `endl`, their `std::` forms, and `std::basic_istream<char>`-style
  incomplete types) are classified as a missing standard type instead of an
  unrecognised build error. `bhf auto` force-includes the header, and waits
  for that repair before it drops a recovered source that fails this way. The
  manipulators `ends`, `flush` and `ws` map to `<iostream>` only when written
  `std::`-qualified, so a project type with one of those names still gets the
  usual placeholder.
- A member declared with an extra class qualification (`int Widget::name();`
  inside class `Widget`) is classified as its own build error
  (`extra_qualification` in `run.json`) instead of an unrecognised one. `bhf
  auto` reports the declaration's location and the flag that relaxes the
  check: `AUTO_EXTRA_INCLUDES=-fms-extensions` for clang++ or
  `AUTO_EXTRA_INCLUDES=-fpermissive` for g++, set in the environment. It does
  not add the flag itself.
- A compile-database `-include`/`-imacros` operand is made absolute only when
  the file exists relative to the entry's directory. `-include iostream` no
  longer becomes a missing `<dir>/iostream`.
- `bhf auto` keeps a project fuzz driver (`LLVMFuzzerTestOneInput`) that
  `--target`, `--target-file` or `--harness-id` selects, even when the tree has
  other targets, and otherwise prints a note naming the drivers it skipped.
  The discovery cache's semantic version is bumped, so an existing cache is
  recomputed once.
- `make libfuzzer` works for a harness around the project's own
  `LLVMFuzzerTestOneInput`: it links the project sources directly, and no
  `bhf_libfuzzer.c` shim (a second `LLVMFuzzerTestOneInput`) is written. The
  `PORTABILITY.md` honggfuzz recipe builds `main.cpp` with `hfuzz-clang++` for
  C++ harnesses, and passes `-DBHF_EXTERNAL_DRIVER` for the shim builds.
- `bhf auto` seeds are byte-exact. Mined seeds, `--seed-file`, `--seed-dir` and
  corpus entries reseeded into later passes or the AFL++ stage used to pass
  through a UTF-8 conversion that replaced every invalid byte with `EF BF BD`,
  so binary formats were fuzzed from mangled inputs. Corpora in work dirs from
  earlier releases can still hold such entries; the first `bhf auto` run of
  this release in such a work dir sets its corpus aside (see below).
- The `bhf auto` AFL++ stage cut every seed to 4096 bytes. It now uses the run's
  resolved `--max-len`; a fixed `--max-len` below AFL++'s 1 MiB default is also
  passed to afl-fuzz as `-G` when its `-h` lists that option (AFL++ 4.00c or
  newer). An older afl-fuzz gets only the capped seeds, and stderr says so.
- Seed mining no longer takes build and IDE artifacts (`.vcxproj`, `.sln`,
  `.filters`, `.user`, `.suo`, `.props`, `.pdb`, `.dll`, `.lib`, `.obj`, `.ilk`,
  `.exp`, ...) from test-data directories. Pass such files with `--seed-dir`
  when the target parses them.
- `bhf fuzz --workers N` and `--sanitizers a,b` on a `bhf auto` work dir found no
  harness: workers got only `build/<id>/`, while auto keeps the binary in
  `harnesses/<id>/`. The parent now resolves the harness as a single run does
  and makes each worker's harness dirs (`build/`, `harnesses/`, `auto/`,
  `generated_harnesses/`) exact copies of its own. A worker copy of a dir the
  parent no longer has is removed and one that differs is copied again, so a
  worker never runs a harness left by an earlier campaign; symlinked files are
  copied as files. A campaign without a built harness fails up front with exit 3.
- A multi-worker campaign in which every worker failed exited 0 with 0 findings.
  It now exits non-zero (the workers' shared exit code, else 1) and prints each
  failing worker's stderr tail. Workers stopped at the time limit after
  recording findings are not failures: that campaign keeps its exit code and
  stderr says they were stopped (stopped workers that recorded nothing exit 1).
  Worker stderr goes to `worker-<id>-N/worker-stderr.log` instead of an
  undrained pipe (a chatty worker no longer blocks), and the campaign summary
  gains additive `per_worker[].stderr_log`, `stderr_tail`,
  `stopped_at_deadline` and `new_findings` fields.
- A duplicate a multi-worker campaign left in a worker dir was merged back into
  `results/findings` by a later campaign once the finding it duplicated had
  been removed, so a finding triaged away (or one from a harness build that no
  longer exists) came back. The merge now marks duplicates
  (`merged-duplicate`), and a marked duplicate whose finding is gone is dropped
  before the next campaign starts. The campaign summary gains an additive
  `dropped_duplicates` count and the merge report a `dropped` count.
- `bhf fuzz` dropped a crash matching a finding already recorded for the harness
  without a trace. The run JSON gains additive `duplicates_of_existing` (finding
  ids) and `duplicate_crashes_of_existing` fields, and stderr gets a note.
- A harness reported at most one stackless UBSan finding per rule for its
  whole run; distinct sites were dropped as duplicates. The builtin loop,
  AFL++ crash ingestion and the cross-pass pre-seed now key on the site and
  check, and a dedupe key is used up only once its finding is written, so a
  first hit that does not reproduce no longer hides a later one.
- Crashes inside `memcmp`/`bcmp` and other interceptors no longer share one
  root-cause key across unrelated callers.
- A crash the fork-server missed and the fresh re-run caught now gets its
  `sanitizer.log`.
- UBSan findings can be minimized: the minimizer's child now halts on the
  first UBSan report like the fuzz child, instead of seeing a clean exit.
- `bhf explain` and the finding explanation and fix guidance no longer print
  an empty function name for a report with no stack. They name the reported
  location; explain also names the harness target and prints the sanitizer's
  report line.
- `results/` stacks no longer list glibc frames (`csu/`, `sysdeps/`,
  `assert/`, `signal/`): a relative frame path that names no file under the
  source root is not a project frame, and relative paths are resolved before
  the under-the-root test. glibc abort, signal and `assert()` frames are also
  root-cause noise, so assertion failures in unrelated code no longer share a
  key.
- UBSan reports at the same line and column of same-named files in different
  directories are no longer one finding.
- An ASan address description with a distance, size or offset too large for
  a signed offset leaves `exception.access.region.offset` unset instead of
  overflowing.
- UBSan NULL and index reports no longer read "Incorrect Calculation": a
  UBSan finding is classified by its check before any message needle.
- Classification ignores the source path in a report: a directory named
  `zoom`, `timeout` or `division_by_zero` no longer turns a finding into an
  out-of-memory, hang or divide-by-zero finding.
- A SEGV's direction is ASan's READ/WRITE token. An unknown direction, or a
  non-canonical high address, is CWE-119 instead of an assumed write
  (CWE-787).
- C/C++ harnesses: a typedef'd byte buffer or length (`const u8_t *`,
  `const BYTE *`, `LPCBYTE`, `UINT`, `DWORD`) now pairs as `(Data, Size)` in
  the C++ lane too, so the length can no longer overrun the buffer. A buffer
  spelled through a pointer typedef gets a heap copy whose size is its length.
  An integer after a buffer is bound to the input length, or to an output
  buffer's capacity, only when its name is length-shaped. Names are matched
  word by word, so common abbreviations (`sz`, `bufsiz`, `bytes`, `cnt`,
  OpenSSL `inl`, Win32 `cb`/`cch` counts) pair, while `account_id`, `caps` or
  `flags` do not. Offset-, index- and position-named parameters are never
  bound to a buffer's size, in both lanes. Previously
  `f(const unsigned char *src, unsigned offset, unsigned size)` received
  `offset = Size`, and `f(unsigned char *dst, unsigned offset, unsigned n)`
  received `offset` = the buffer's capacity, so every access started past the
  end.
- C/C++ harnesses: unsigned parameters, struct fields and output values,
  `size_t` included, decode across their full range. Before, values of 2^31
  and above (65537 and above for `size_t`) were unreachable. Length-, size-
  and count-named values stay bounded.
- C/C++ harnesses build from paths that contain spaces, parentheses,
  apostrophes or `* ? [ ] { } ~ !`. This covers the source tree, include dirs,
  the work dir, the runtime dir, the compiler, `--extra-include`/`--extra-source`
  and `--differential` compiler paths. Such paths are double-quoted in
  generated Makefiles, per-translation-unit object rules and the
  `AUTO_EXTRA_INCLUDES`/`AUTO_EXTRA_SOURCES` variables, and they never become
  make prerequisites. Compile-database flags naming them are quoted too
  (double-quoted when they contain an apostrophe), and `bhf capsule` quotes
  copied source names in `build.sh`. Before, every target under such a path
  was refused, a spaced `--extra-include` was split into two arguments, and a
  capsule of a source file named with a space did not rebuild. Characters no
  quoting can make safe (`$`, `#`, backtick, `"`, `\`, `;`, `|`, `&`, `<`,
  `>`) are still refused. The message now names the character, and the
  next-steps advice lists these refusals separately and no longer suggests
  `--force` for them. `bug-report.md` tags them as a path problem rather than a
  missing type, although `run.json` still records them under the
  `unsupported_params` outcome.
- `bhf capsule`, `bhf verify-poc`, `bhf cartography` and `bhf env-capsule`
  work on C++ harnesses and on harnesses made with `generate-harness --id
  <name>`. They kept only `H-C*` harness ids and dropped every other finding
  under one message ("no reproducible C crash findings ... need a runtime
  finding with a testcase.bin"). The harness's language now comes from its
  `generation-metadata.json` (else the id prefix), and the harness is looked
  up in `harnesses/`, `auto/`, `generated_harnesses/` and `build/`. Any other
  finding is refused with its own reason (unknown id, not a runtime crash, no
  harness, no input, unsupported language, harness not built) and, when there
  is one, a command that reproduces it: `python3 <finding>/replay.py`, or the
  built harness run on the input with sanitizer options.
- The four commands exit non-zero when a requested `--finding-id` is refused,
  fails, or (capsule, env-capsule) did not reproduce, and when a run without
  `--finding-id` writes nothing although the work dir has runtime findings.
  `capsule` exited 0 having packaged nothing, and `cartography` exited 0 on a
  refused id. env-capsule reports refusals before it looks for the runtrace
  shim, so its message no longer depends on how bhf was installed.
- `bhf capsule` and `bhf env-capsule` build each capsule in a scratch dir and
  move it into place when complete. A refused or failed run no longer leaves
  an empty `capsules/` dir or a capsule skeleton without `manifest.json`.
- A capsule rebuilds from what the harness was built with: the compiler's own
  dependency list decides which headers ship, and they keep their path relative
  to the project tree, so `#include "sub/x.h"` and `-iquote`/`-idirafter`/
  `-include` roots resolve. Headers were flattened by basename, and only `-I`
  roots were copied. The language standard and extra sources and include dirs
  recorded in `harnesses/<id>/coverage-build-recipe.json`, per-translation-unit
  compile-database objects, the force-included repair headers and the work
  dir's `c_compat.mk` flags are applied; all were ignored.
- `bhf capsule` ships the finding's `min_testcase.bin` when it reproduces (else
  `testcase.bin`), still as `input/testcase.bin`, and prints and records which
  one shipped. It always shipped `testcase.bin` while calling it minimized.
- `bhf cartography` maps a SEGV by its faulting address. A wild-pointer report
  has no region-relative offset, so every byte that kept the crash was
  "don't care" and the crash was called `gated_crash`. Where address-space
  randomization cannot be turned off (a container's default seccomp profile
  refuses `personality(2)`), it prints a warning that those bytes cannot be
  attributed and suggests `--security-opt seccomp=unconfined`.
- `bhf cartography` and `bhf env-capsule` work with a relative `--work-dir`,
  including the default `bhf_work`. The replays run in the harness's own dir,
  where the relative binary and input paths did not resolve, so every finding
  was reported as producing no AddressSanitizer report or as not crashing.
- `bhf env-capsule` ships the first input that crashes under the recorded
  environment (`min_testcase.bin`, then `testcase.bin`, then the input that
  crashed while recording). It shipped `min_testcase.bin` without checking it,
  so a capsule whose minimized input did not replay was marked not reproduced.
- When the compiler cannot list a build's includes, a capsule also ships the
  project headers the sources' `#include` lines reach, so a header outside the
  include roots (`#include "../common/defs.h"`) is no longer left out. A C++
  capsule recovers the installed libstdc++ headers and library when `clang++`
  cannot find them itself, as bhf's own C++ builds do, both when it is packaged
  and in its `build.sh`. A failed rebuild is reported by the compiler's first
  `error:` line rather than its `N error(s) generated.` tally.
- `bhf verify-poc` on a path that does not exist says so and names the
  `bhf capsule` command that writes it, instead of a format error.
- `bhf explain` prints `bhf capsule` / `bhf verify-poc` under REPRODUCE OFFLINE
  only for findings capsule can package. For any other it says why and prints
  `python3 <finding>/replay.py` or the harness command; for an AddressSanitizer
  crash cartography can map it adds `bhf cartography`.
- The harness command that `bhf explain` and the capsule refusals print runs
  the built harness with the sanitizer options `bhf replay` uses, from the same
  builder: `ASAN_OPTIONS` `abort_on_error=1:halt_on_error=1` (plus
  `detect_leaks=1` for a leak finding) and `UBSAN_OPTIONS` also
  `print_stacktrace=1:report_error_type=1`, merged after your own values. It
  printed fixed options without `halt_on_error`, the UBSan check name or leak
  detection, so it did not reproduce the way a replay does.
- `bhf explain` quotes the work dir and capsule path in its `bhf capsule` and
  `bhf verify-poc` lines, so a path with spaces pastes as one argument, and on
  Windows the capsule refusals name `python` for a finding's `replay.py`.
- The clang-cl harness lane (`--cc clang-cl`) builds again: bhf's cl front
  end handed clang-cl the coverage flags in cl's `/fsanitize-coverage=`
  spelling, which clang-cl reads as file names, so every harness build failed.
  It now passes clang's own `-fsanitize-coverage=` to clang-cl.
- `bhf replay` reported `MATCH` whenever the rule matched, so a crash of the
  same class at another site, or in another harness, was confirmed and stamped
  into `finding.json` as a reproduction. A C/C++ replay now matches on rule,
  kind and sink (the top project frame, function and `file:line`), or on the
  reported site for a finding recorded without frames. `MISMATCH` gains a
  `differs=` field and a line naming what differed; a hang is
  `actual=<timeout>`. `last_seen` is stamped only on a full match. The fuzz
  loop's fresh-process confirmation of a crash uses the same comparison. A
  replayed report that names no function and no source position (an
  unsymbolized one) is not taken for another crash site: the location is
  marked as not compared and replay says so. Replay puts the same LLVM
  toolchain on `PATH` that `bhf auto` gives its fuzz children (the RHEL 7 LLVM
  Toolset when the base `clang` lacks SanitizerCoverage), so its reports are
  symbolized as theirs were.
- `bhf replay` and `bhf minimize` ran C/C++ harnesses without the fuzz child's
  `ASAN_OPTIONS`; they now use the same options (`abort_on_error=1`,
  `halt_on_error=1`, and `detect_leaks=1` for a leak finding) plus the UBSan
  options.
- `bhf replay` and `bhf minimize` failed with "I/O error during replay" on a
  harness `bhf build` staged alone into `build/<id>/main` (including the
  auto-resolved `fixture_path` of every finding `bhf fuzz` recorded for it):
  they looked for `main.c`/`main.cpp` only beside the binary and treated it as
  an Ada harness. `bhf fuzz`, `bhf replay` and `bhf minimize` now share one
  protocol detector. It searches every harness dir of the work dir
  (`generated_harnesses/`, `harnesses/`, `auto/`, `build/`), scans the whole
  binary for bhf's driver strings, recognises a `-fsanitize=fuzzer` binary by
  its runtime, and honours a declared input mode. An Ada harness, which also
  reads `BHF_FRAMED`, is recognised by the string GNAT's binder puts in every
  Ada main, whichever probe backend it was built with. An Ada-path failure
  names its cause and how the protocol was chosen. For a binary staged alone,
  the input-format note reads `generation-metadata.json` from the harness dir
  the detector found its driver source in.
- `bhf fuzz` ran a hand-compiled libFuzzer binary at `build/<id>/main` on
  stdin, so libFuzzer ran its own loop and the seed was recorded as the
  testcase of crashes it found. It is now run on one input file per process,
  and `bhf fuzz` notes that it runs without coverage guidance and how to wrap it
  with `bhf generate-harness --target LLVMFuzzerTestOneInput`.
- A `bhf.project.v1` `builtin` target with a prebuilt bhf harness validated as
  framed but fuzzed without the framed protocol or coverage. `bhf project run`
  now writes the target's input mode to `build/<id>/harness-protocol.json`,
  which the fuzz lane, replay and minimize use.
- A copied or moved work dir replayed and minimized against the original's
  harness binaries, because `finding.json` held an absolute `fixture_path`
  that replay, auto's minimization and `replay.py` tried first. New findings
  record `fixture_path` relative to the work dir when the harness is inside it,
  and every reader resolves it in the work dir holding the finding, never
  relative to the current directory; an absolute value from an earlier release
  is mapped into that work dir by its
  `harnesses|auto|generated_harnesses|build/<id>/` tail, and is used as
  recorded only when the work dir has no harness for the finding's
  `harness_id`. `replay.py` also looks under `build/<id>/`.
- `bhf replay` rewrote `finding.json` after a match without rebuilding
  `results/`, leaving the `results/findings.json` evidence hashes and
  `results/attestation.json` stale. It now rebuilds the index when the work
  dir has one, for every kind of finding (harness, binary, session, collector
  and transport).
- `bhf replay` panicked on a `build.binary.sha256` in `finding.json` that is
  not ASCII.
- Migrating a bhf 0.2.x work dir deleted `FINDINGS.md`, `findings.csv`,
  `auto/findings.csv` and each finding's `replay.py`, and said only that
  `findings/` moved. They are now kept under `results/legacy/` with a
  `migration.json` record, and the migration prints what it moved and kept,
  that migrated findings lack `sanitizer.log` until backfilled, what happens to
  the corpus, and that the migration is one-way.
- `bhf auto` on a work dir from an earlier release kept reseeding its old
  corpus queue, including seeds the old seed encoding damaged. On its first run
  in a work dir migrated from 0.2.x, or one an earlier `bhf auto` wrote
  (including a 0.2.x work dir an earlier release already migrated), it moves
  `corpus/` to `corpus-legacy/` (kept, not reseeded) and records the decision
  in `auto/legacy-corpus.json`; `--reuse-legacy-corpus` keeps reseeding it.
  Every `bhf auto` run now writes that record before anything else (a new work
  dir is recorded as `fresh`), which is how a later run or `bhf report` tells
  this release's work dirs from earlier ones.

### Changed
- The C/C++ harness input format is now version 4: a call with several
  buffers, a count named as above, a pointer-typedef buffer or a parameter
  named like a harness local decodes differently from format 3. Regenerate
  such a harness and re-run its corpus. Findings, corpora and capsules
  recorded against format 3 are flagged by `bhf replay`, `bhf minimize`,
  `bhf decode-args` and `bhf capsule` as before; a harness whose calls have
  none of these shapes decodes its inputs as format 3 did.
- `bhf replay` has a new exit code, 4, for an `UNVERIFIED` replay; scripts
  that treated every non-zero, non-3 code as an error should treat 4 as "not
  reproduced".
- The signature and root-cause key of a fatal signal without a sanitizer
  report hash the signal, so BHF-210 finding IDs change.
- The root-cause key (`cluster_key_full`) of a crash without frames or a
  source position now hashes the harness that found it, and the signature
  (the finding ID suffix) of a fatal signal the driver printed a pc for hashes
  that pc. A work dir from an earlier release may record such a crash once
  more; start from a fresh work dir to compare groups.
- A target refused because a source path, include dir or compile flag holds a
  character no quoting makes safe in a build recipe now has its own outcome,
  `unsafe_build_path`, in `run.json` (and `summary.unsafe_build_path`, the
  terminal label and the blocker histogram), and its own `unsafe-build-path`
  category in `bug-report.json`/`bug-report.md`, instead of
  `unsupported_params` / `unsupported-type`. Tooling that grouped these refusals
  under `unsupported_params` should also read the new outcome.
- Target ranking (`bhf auto` discovery and `bhf list targets`) reads C and C++
  parameter types through the file's typedefs and those of the project headers
  it includes, and through the built-in Windows and stdint spellings. A byte
  buffer spelled through a typedef (`const u8_t *data`, `u8_t const *`) is
  recognised as an input buffer, a typedef'd integer (`u32_t len`, `DWORD`)
  as the integer it aliases, and a typedef'd byte as a stream decoder's
  byte. Targets taking such parameters now rank as input-taking functions and
  record `input_reachability: attacker_reachable` where they were
  `reachability_unproven`, so their rank and reported reachability change.
- `run.json` `coverage.source` values changed meaning (see Fixed): consumers
  that matched `sancov-trace-pc-guard` for every edge map should accept
  `sancov-trace-pc`, `go-cover` and `edge-bitmap`. Additive fields:
  `passes[].coverage_instrumentation`, `finding.json`
  `build.binary.coverage_instrumentation` and `gate_capture.runner`, and a
  `bhf_runner.json` (`bhf.harness_runner.v1`) beside each cross-built harness.
- `findings.json` gains an optional `reproduce.build.fidelity`, present only
  for a finding built with fabricated inputs (both schemas describe it), and
  `findings.csv` a trailing `build_fidelity` column; readers that address
  columns by position keep working.
- Visual Studio solutions, projects and property sheets are build-context
  files: editing one makes `--resume` re-attempt the targets it affects (a
  work dir from an earlier release re-attempts once).
- A heap overflow of a buffer the generated harness sized itself, for a pointer
  parameter it passes without a length, is `lab_only` and reads as
  "precondition-dependent": whether a real caller can pass a buffer that short
  is the entry's contract, which bhf cannot see. This covers decoded C strings
  and input copies whose allocating statement in the harness source has no
  length companion; a buffer passed with its length (a `(buf, len)` pair, an
  output buffer with its capacity) keeps the entry's verdict.
- `bhf.findings.v1` gains four optional `fuzz` keys, written for every fuzz
  finding: `access` (the sanitizer-reported memory access, without its raw
  address), `input_to_state` (the comparison evidence; `null` when no capture
  ran or it could not run), `input_to_state_input` (the file its offsets
  index, `min_testcase.bin` or `testcase.bin`) and `arguments` (the harness's
  decoded arguments, when traced), plus the `runtrace` evidence role.
  Documents written before them still validate against the new schema; a
  strict validator holding the previous schema rejects the new keys.
  `findings.csv` appends the columns `access`, `access_size`, `region_size`,
  `region_offset`, `input_to_state` and `input_to_state_input` after
  `evidence_dir`.
- Harness `dictionary.txt` files start with a comment saying their tokens are
  mined from source, and mark the raw-byte encodings of each integer literal.
- C/C++ harnesses no longer feed the same input bytes to two parameters of one
  call. A call's whole-input parameters (a byte buffer without a length
  parameter, a `(buffer, length)` pair, `const void *`/`void *`, `FILE *`, a
  loader's temp-file path) are decoded after its cursor parameters and take
  the bytes those left, in both the C and the C++ lane. Before,
  `f(const uint8_t *data, uint32_t a, uint32_t b)` read `a` and `b` from bytes
  0-7, which were also the first bytes of `data`, so mutating one mutated the
  other. A C++ method's whole-input target parameters are decoded after its
  receiver's constructor or factory arguments and lifecycle loop. A C++
  receiver's constructor, factory and step arguments and the calls of a C
  sequence harness that run after other decoding take the bytes the cursor
  left, and a sequence-harness call never takes the operation-program block at
  the end of the input. A direct harness's target call with only one kind of
  parameter decodes as before.
- The harness input format is now version 3, and each new finding records the
  format of the harness that found it (additive `harness_format_version` in
  `finding.json`). `bhf replay` (a `note`, also in `--json` `notes`), `bhf
  minimize` (stderr) and `bhf capsule` (a warning, and `harness_format_note`,
  `harness_format_version` and `finding_harness_format_version` in
  `manifest.json`) flag a finding recorded against another format than the
  harness they run, including findings that record none, which come from a
  format 2 or earlier harness. Regenerate a harness to move to format 3, then
  re-run its corpus: inputs recorded against format 2 decode differently
  where a call mixes whole-input and cursor parameters. Ada harnesses, whose
  decoding did not change, keep format 2. The opt-in buffer-length dimension
  is part of the format: findings from a harness generated with it record an
  additive `buffer_len_dimension: true`, and a finding replayed, minimized or
  packaged against a harness generated with the other setting is flagged the
  same way.
- The foreign-guard qemu-user lane of `bhf auto` builds with GCC's
  `trace-pc,trace-cmp` coverage when the cross compiler accepts it, so emulated
  arch targets are fuzzed coverage-guided instead of blind.
- A failed C++ build caused by a member declared with its own class's
  qualification is retried with `-fms-extensions` (clang) or `-fpermissive`
  (gcc) from a new work-dir `cxx_compat.mk`, spliced into every C++ Makefile
  lane and object rule; the fragment is kept only when that error disappears.
- Toolchain changes are announced: the compilers a `[toolchain]` or `--cc`
  selects, the environment values they replace, and the compiler a
  `--sanitizers` build falls back to.
- `bhf auto --seed-dir` reads a directory's files in name order.
- Sanitizer finding signatures, IDs and root-cause keys changed. UBSan runs
  with `print_stacktrace=1` and `report_error_type=1` during fuzzing,
  minimization, `bhf replay` and in `replay.py`, so UBSan findings now carry a
  stack. The signature hashes only the crash stack (not the allocation or free
  stack), plus UBSan's check name and, for UBSan or stackless reports, the
  reported site: the last two components of the reported path with its line
  and column (`a/util.c:3:5`). Root-cause keys also hash the rule, kind and
  check, skip libc and interceptor frames, and key UBSan reports on their
  site. Existing findings are not rewritten; compare runs in a fresh work dir.
  See docs/site/sanitizers.md.
- `bhf explain` explains each root-cause group (findings sharing a
  `cluster_key_full`, such as one site reached through several harnesses)
  once, by its first finding, and lists the group's other findings with their
  harnesses. Every block names its harness and, when the sanitizer recorded
  one, the memory access: direction, width, the region it hit and where that
  region was allocated or freed. `--all-members` explains every finding as
  before.
- UBSan findings report under a rule, CWE, explanation and fix hint per
  check instead of BHF-210 / "Incorrect Calculation (CWE-682)": for example
  missing return is BHF-214 / CWE-758 and an invalid shift BHF-215 /
  CWE-1335. Only signed and unsigned integer overflow share a rule
  (BHF-205). UBSan index reports move from BHF-201 to BHF-220, division by
  zero from BHF-205 to BHF-222, and insufficient object size from BHF-201 to
  BHF-227. An ASan SEGV outside the first memory page reports under BHF-223
  instead of the NULL-dereference rule BHF-206. `bhf replay` still matches
  findings recorded under the earlier rules.
- SARIF result `properties.cwe` is the finding's computed CWE rather than the
  rule's catalog CWE; `properties.cwe_top_25` is set only when the two agree.
- Generated C/C++ harnesses are now input format 2. The version is recorded as
  `harness_format_version` in `generation-metadata.json` (an additive field) and
  at the top of `main.c` / `main.cpp`. Inputs whose unsigned values have the
  top bit set, non-length `size_t` values, and pairs whose integer is not
  length-named decode differently than under format 1. `bhf generate-harness`
  warns when it regenerates a harness of another format, and `bhf replay`
  notes when it replays against one. Re-run existing corpora and re-triage
  findings recorded against older harnesses.
- Ada static rules run on a statement and scope model instead of line
  matching. BHF-409 now reports only Unchecked_Conversion to an access type
  (and Address_To_Access_Conversions), BHF-410 a double free through an alias,
  BHF-411 a task writing unprotected package state, and BHF-412 a spawn of a
  non-constant program or shell command. Plain instantiations, tasking
  constructs and constant spawns are no longer findings. BHF-402 ignores case
  statements, `Finalize` handlers and cleanup-only guards. The Ada BHF-405 line
  heuristic is removed (the taint engine still reports Ada file-open sinks).
  Test trees, GNAT binder output and predefined-hierarchy runtime units are
  not scanned. CWE mappings: BHF-409 CWE-704 -> CWE-843, BHF-411
  CWE-362 -> CWE-567 (Base entries).
- Capsule layout and `build.sh`: `sources/` keeps the project's directory
  layout (it was flat), the driver is `harness/main.c` or `harness/main.cpp`,
  and `build.sh` compiles like the harness Makefile's `main` rule (section
  garbage collection, `-D_GNU_SOURCE -D_DEFAULT_SOURCE`, `CXX=${CXX:-clang++}`
  for C++). `manifest.json` stays `bhf.capsule/v1`: `lang` is `c` or `cpp`, and
  `language`, `toolchain`, `input_source`, `input_minimized`, `build_recipe`
  and `rebuilt` are additive. A manifest without `lang` is read as C.
- `byte-control.json` (`bhf.byte-control/v1`) gains additive fields `input`,
  `crash.fault_address` and `crash.fault_address_stable`, the byte classes
  `controls_address` and `unknown`, and the primitive kinds
  `controlled_address_read`, `controlled_address_write`,
  `controlled_address_access`, `unattributed_crash` and `uncontrolled_crash`
  (a crash no input byte gates was `gated_crash`). Cartography perturbs the
  minimized input when it reproduces, and replays with address-space
  randomization off. The env-capsule manifest gains `lang` and `input_source`.
  The capsule manifest's `build_recipe` gains `stdlib_include_fallback`.
- `bhf replay` prints a summary under the `MATCH`/`MISMATCH` line: the
  compared fields, the replayed crash (rule, kind, sink, top frames, memory
  access and allocation site), the exit status or signal and duration, the
  harness (protocol, and whether its sha256 matches the recorded build) and
  the testcase size and sha256. Binary, session, collector and transport
  findings get the same summary for what their replay compares (a binary
  target's exit status and sanitizer report, the session oracle verdict, the
  collector oracle signature, the transport fault identity), and an Ada replay
  shows the harness exit status and duration. The first line is unchanged, so
  scripts that look for it keep working; a collector replay's attributing
  event and process tree now follow it instead of preceding it.
- `fixture_path` in new `finding.json` records is relative to the work dir
  when the harness is inside it (an absolute path otherwise). Readers accept
  both forms.

### Added
- A seed reaches the buffer of a C/C++ harness that decodes fixed-width
  scalars before it: `bhf auto` (for its mined and `--seed-file`/`--seed-dir`
  seeds, in the builtin and AFL++ stages) and `bhf fuzz` (for
  `--seed-file`/`--seed-input`) also give each seed behind as many zero bytes
  as those scalars take, from the harness's `arg-layout.json`, plus 4 for the
  length of each other buffer's slice ahead of it (a context pointer before a
  `(data, len)` pair), which a zero leaves empty. The seed itself is still
  given byte for byte. A multi-worker `bhf fuzz` makes the prefixed seeds
  once, and its workers prefix none of the seeds they are handed.
  `auto/seeds.json` lists the prefixed seeds under an additive
  `layout_variants` (`harness_id`, `layout_prefix`, `sha256`).
- `bhf capsule`, `bhf verify-poc` and `bhf env-capsule` support every harness
  language bhf generates, through per-language lanes: Ada, Rust, Go, Java, C#,
  Python, JavaScript, TypeScript, Ruby, Perl, PHP, Lua, COBOL and Fortran, as
  well as C and C++. A capsule ships what its lane's rebuild needs (for Ada the
  generated `bhf_build.gpr`, the runtime project and sources, the instrumented
  sources, the harness, the stub packages and the operator projects it extends
  or `with`s; for Rust, Go and C# the dependencies vendored from the local
  cargo, module or NuGet cache; for an interpreted lane the launcher, bhf's
  driver and the scanned tree), relocates every path the build and launch
  files name into the capsule, and rebuilds offline in a clean copy. The
  rebuilt PoC is replayed with the input protocol the shared detector reads
  off it (the Ada stdin event-log protocol for a GNAT binary), and the lane's
  crash oracle names what fired (an unhandled Ada exception, a runtime's
  `== bhf <lang> finding:` report, a panic, libcob's runtime check, a
  sanitizer report). The manifest records the programs the rebuild needs and
  their versions (`requires`), the protocol (`protocol`, `run`) and the lane's
  build facts (for Ada the target, runtime, switches and GNAT/gprbuild
  versions); `verify-poc` checks them first and names each missing program
  and the variable that overrides it. A program build.sh finds under several
  names (`lua`, `lua5.4`, `lua5.3`, `luajit`) records the others
  (`requires[].alternatives`), and any of them meets it. An Ada capsule whose
  rebuilt PoC raises a different exception than the finding recorded is not
  counted as reproducing (manifest `finding_signature`, `reproduced: false`,
  `reproduced_other_crash: true`), and `verify-poc` checks the replay against
  the finding's exception (`MISMATCH` otherwise). A harness a lane cannot
  rebuild offline is refused with the reason: a dependency not in the local
  cache, an Ada project file outside the scanned tree, a harness built for
  another target, a Java target built by Maven or Gradle, a build file
  build.sh renders that still names the work dir or the scanned tree after
  relocation. A text file a relocated capsule ships unchanged but that names
  them is reported in a warning. env-capsule takes the native lanes (C, C++, Ada, Rust, COBOL,
  Fortran) and refuses a statically linked harness (Go) or one that runs in a
  language runtime, with that reason; cartography stays C/C++. `bhf explain`
  offers capsule and verify-poc for the findings whose lane and harness layout
  capsule takes; capsule checks dependencies and the size of what it ships
  when it packages, so it can still refuse one of them, and says why. The new
  manifest fields are additive; capsules written before them still verify.
- The Fortran lane records how each Fortran object of a harness link was
  compiled (`harnesses/<id>/fortran-build.json`), which a capsule uses to
  rebuild them from source.
- `bhf replay` writes `<finding>/replay.log` on every run, match or not: the
  verdict, what ran, the exit status, the harness's raw stderr and stdout
  (each bounded to its first 256 KiB and last 768 KiB, the cut marked) and any
  debugger transcript. The summary names it (`log`; `replay_log` in `--json`).
  It is not an evidence file, and results/ is now rebuilt after a mismatch too,
  so the attestation covers it.
- New findings record the generated harness's input format as
  `harness.format_version` (and `harness.buffer_len_dimension`) in
  `finding.json`, next to the top-level `harness_format_version` kept for
  earlier readers, and in the harness's corpus metadata
  (`corpus/<id>/metadata.json`, `bhf.corpus-metadata.v1`). `bhf replay`,
  `bhf minimize`, `bhf decode-args` and `bhf capsule` read the format from the
  finding's `harness` first, then the top-level key, then the harness dir, and
  `bhf auto` notes a corpus recorded against another format than its harness.
- `arg-layout.json` beside each generated C/C++ harness (`bhf.arg-layout.v1`,
  named as `arg_layout` in `generation-metadata.json`): the static decode
  layout of the harness's arguments, in the order the harness decodes them.
  Each parameter records its order, input source (cursor, remainder, whole
  input), decoder kind and primitive, width, endianness, bounds, enum
  members, length-prefix size, buffer copy or view and pairing, whether the
  value is a C string read up to its first NUL (`nul_terminated`) and the
  constant a `fixed` parameter is given (`fixed_value`); it also marks
  where a call's whole-input parameters take the remaining bytes and any
  lifecycle loop. `generation-metadata.json` also records `target_function`.
- `bhf decode-args`: maps a testcase (or `--finding <id>`) to the value each
  harness parameter receives, through the harness's argument trace when its
  binary runs, else (or with `--static`) by replaying `arg-layout.json` for
  scalars, bounded integers, enums, length-prefixed strings, constants and
  remainder, whole-input and paired buffers, naming each parameter it cannot
  decode statically and why. Both sources measure a C string up to its first
  NUL byte. Text table, or `--json` (`bhf.decode-args.v1`).
- `bhf replay --debugger [gdb|lldb|cdb]` re-runs the testcase under a batch
  debugger: it breaks at the harness's target function, prints its arguments
  and full stack, continues to the crash and prints the stack again, with
  AddressSanitizer's signal handling off so the debugger sees a SEGV. The
  harness gets the replay's runtime mode and injected variables, and the
  runtrace shim is preloaded into the harness only. lldb prints the crash
  site through on-crash (`-k`) commands and stops a sanitizer report at the
  sanitizer's report function. The session runs without a sandbox, so it is
  refused with `--sandbox firejail|bubblewrap` or `--sandbox-strict`. It
  says what to install when no debugger is found.
- `bhf explain` tags each harness argument whose input bytes a recorded
  comparison read with the comparison's site (`[compared at bits.c:12]`).
- `findings.csv` appends `arguments` (`name=value;...`, buffers as
  `len N hex <first 8 bytes>`, bounded) and `access_parameter`; results
  `findings.json` carries `exception.access.parameter` as
  `fuzz.access.parameter` (`{name, offset, basis}`, null when unknown), and
  INDEX.md names it on the memory-access line. Both are additive.
- Each token in a harness's `dictionary.txt` is preceded by a
  `# from <file>:<line>` comment naming up to three places in the target source
  and its headers where it was found (C, C++, Ada and the managed lanes), so a
  token can be traced to the comparison or constant it came from. The file
  stays a valid AFL dictionary.
- `learned_dictionary.txt` beside a harness's `dictionary.txt`: after each
  `bhf auto` fuzz pass that recorded comparison operands (`cmplog.jsonl`), bhf
  writes them there, deduplicated and bounded (at most 256 tokens of at most
  64 bytes, this run's first, then an earlier run's), under a header saying
  they were observed at runtime. `bhf fuzz` and later `bhf auto` runs load it
  after `dictionary.txt`, each token once, and AFL++ mode passes it with `-x`.
- Windows: Visual Studio and Windows SDK discovery. Without `INCLUDE`/`LIB`
  (no Developer shell), bhf finds the newest instance with the C++ toolset
  through `vswhere`, applies the environment its `VsDevCmd.bat` sets, and
  caches only what VsDevCmd changed (its variables and the `PATH` directories
  it added, per instance, version and architecture under
  `%LOCALAPPDATA%\bhf\vs-env`), which later runs apply onto their own
  environment. It uses a clang on `PATH`, the standalone LLVM, or Visual Studio's bundled
  clang, and GNU make from its usual install locations. Each command prints
  what it used; `run.json` records it as `build_environment` and `--dry-run`
  shows it. `--no-vs-env` (or `BHF_NO_VS_ENV=1`) and `--vs-arch` control it.
- An MSVC `cl.exe` harness lane: `--cc cl` (or `clang-cl`, or
  `[toolchain] cc = "cl"`) builds the C/C++ harnesses with Visual Studio's
  compiler through `bhf-cl`, a front end that runs cl with the equivalent of
  the generated Makefiles' command lines, `/fsanitize=address`, and MSVC's
  SanitizerCoverage (`inline-8bit-counters`, `edge`, `trace-cmp`,
  `trace-div`). The C driver folds inline 8-bit counters into its edge and
  hit-count maps after each input and implements the division hooks. cl's
  diagnostics gain their clang spelling for the repair loop, and weak repair
  stubs become MSVC alternate names. The Makefiles recognise the `msvc`
  family. The front end is installed in the user's own cache directory and an
  existing one is reused only when its bytes are this `bhf`'s.
- The Visual Studio project import runs by default when a tree has a
  solution or project and no compile database or CMake/Meson build. Off
  Windows it does so only when the solution is the tree's only build
  description: a Makefile, autotools inputs (`configure.ac`, `Makefile.am`,
  `autogen.sh`), Ninja, SCons or Bazel files at the root or on the way to the
  solution mean that build is followed, unless `--msbuild-solution` names the
  solution. It runs nothing and writes its database to `<work>/auto/msbuild/`.
  On Windows each row carries the import libraries its own project links
  (`bhf_link_libraries`): only libraries found in a `LIB` directory reach that
  project's harnesses (`BUILD_CONTEXT_LDFLAGS`, now also in the C
  Makefiles), and the rest (the solution's own outputs, third-party
  libraries, paths, C runtime libraries) is named and left out. The project
  reader is bounded (file size, nesting depth, expanded value length and a
  per-project expansion budget), so a hostile project file cannot hang or
  exhaust bhf. The default import is the static reading on every host:
  MSBuild itself evaluates each project (`msbuild -getItem:ClCompile`) when it
  is installed only with `--msbuild-evaluate` (config key `msbuild-evaluate`,
  explicit `--config` only), `--probe-build` or `--run-untrusted`, because
  evaluation runs the projects' property functions. New flags:
  `--msbuild-solution` (relative to the scanned tree; a solution outside the
  tree is imported, and a missing file is an error), `--msbuild-config`,
  `--no-msbuild-import`, `--msbuild-evaluate`.
- `--build-command` on Windows captures the cl invocations of an MSBuild
  build: the command runs through `cmd.exe`, compilers on `PATH` get
  executable shims, and MSBuild's CL task is pointed at the `cl.exe` shim
  through `CLToolPath`/`CLToolExe`. Response files are expanded, and a cl run
  that compiles several sources yields one database row per source.
- Findings from a harness that compiled only with headers, macro values or
  types bhf fabricated for missing build context are marked: `finding.json`
  gets `build.fidelity` (`{level, context, fabricated: [{kind, name, value}]}`),
  the normalized finding is low confidence with a caveat in INDEX.md and
  `bhf explain`, and `run.json` lists the target's `build_fidelity` and counts
  them in `summary.fabricated_build_context`; the console summary and `run.md`
  list them too.
- Comparison evidence per finding: `bhf auto` (after minimization) and
  `bhf report --backfill` replay each runtime finding's preferred input with
  the C/C++ driver's comparison capture (`BHF_CMP_EVIDENCE`) and store the
  result in `finding.json` as `gates` and `gate_capture`, with the runtrace
  events of that replay in the finding's `runtrace.jsonl`. It reaches
  `findings.json` (`fuzz.input_to_state`, with the file its offsets index in
  `fuzz.input_to_state_input`), `findings.csv`, `INDEX.md` and SARIF (the
  `bhfInputToState` and `bhfInputToStateInput` properties and a related
  location per comparison site). Under AddressSanitizer `memcmp`/`bcmp`
  evidence carries no source position, as the interceptor reports itself as
  the call site. `finding.json` `runtime_mode.shim_armed` records whether the runtrace
  shim was loaded for the fuzz pass.
- `bhf.findings.v1` `fuzz.access` and the CSV access columns carry the memory
  access the sanitizer reported.
- `BHF_BUFFER_LEN_DIMENSION=1`, set when a C/C++ harness is generated, gives a
  byte buffer without a length parameter an explicit length: 4 more input
  bytes after the call's cursor parameters, then that many bytes. It is off by
  default, because a buffer shorter than the input can make a function with an
  implicit length contract overflow it. The choice is recorded as an additive
  `buffer_len_dimension` in `generation-metadata.json`.
- Generated C and C++ harnesses print each decoded parameter when run with
  `BHF_TRACE_ARGS=1`: one `BHF_ARG {json}` line per parameter on stderr, after
  decoding and before the call, with its name, type, decoder, the testcase
  bytes it came from (`span`) and its value. Buffers and strings carry their
  address, AddressSanitizer allocation size, length and a hex preview of at
  most 32 bytes. Output and in-out parameters (non-const references, pointers
  to scalar storage, writable strings) get a second line with their value
  after the call. A C++ receiver's constructor arguments and the receiver
  object are traced too, as are the arguments of sequence-harness operations
  and C++ lifecycle and protocol steps. Without the variable nothing is
  printed. The trace helpers are in the new `c_runtime/bhf_trace.h`, which the
  generated sources include. Harnesses generated by earlier releases have no
  trace.
- When the fuzz loop records a new C/C++ crash (builtin engine, persistent
  fork-server or AFL++ ingestion) it re-runs the testcase once with the trace
  on, bounded by the per-input timeout (5 to 30 s). `decoded.json` gains a
  `schema_version` (`bhf.decoded.v1`) and, besides the existing raw-bytes
  entry, `arguments` (every traced value) with per-argument `provenance`
  byte ranges, or `arguments_unavailable` with the reason. `finding.json`
  gains an additive `decoded_args` array (`name`, `type`, `role`, `value`,
  `len`, `span`, `preview_hex`, `after_call_value`) for the target call and
  the receiver, and `exception.access.parameter` names the parameter whose
  traced buffer starts the region a heap access hit (`basis`
  `region_start`) or points into it (`region_interior`, with the offset from
  that pointer), or for a wild access the nearest traced pointer below the
  faulting address (`nearest_pointer`).
- `bhf replay --show-args` replays with the trace and prints the decoded
  arguments as a table, and the parameter the access hit; with `--json` they
  are `arguments`. `bhf explain` shows the table in a HARNESS ARGUMENTS
  section and names the accessed parameter under its `Access` line, and
  `bhf cartography` labels each byte with the parameter it was decoded into
  (`params` in `byte-control.json`, `parameters` listing their spans).
- docs/site/c-cpp.md documents the decoding layout: cursor order, widths,
  endianness, bounds, length prefixes, which parameters use the whole input,
  receivers, constructors and lifecycle loops, the argument trace, and a gdb
  recipe for reading arguments from harnesses built before it.
- A `[toolchain]` table, shared by `bhf auto --config` and the new
  `bhf build --config`, with matching flags: `cc`, `cxx`, `cflags`, `cxxflags`,
  `ldflags` (appended to bhf's instrumentation), `defines`, `include-dirs`,
  `target`, `sysroot`, `runner`, `runner-args`, and `[toolchain.ada]` `prefix`,
  `gprbuild`, `gnat`, `target`, `runtime`, `switches`, `probe-backend`. It is
  validated before anything builds and, from an auto-loaded `.bhf.toml`, ignored
  with a note. `bhf auto` gains `--cc`, `--cxx`, `--cflags`, `--cxxflags`,
  `--ldflags`, `--define`, `--toolchain-include`, `--sysroot`,
  `--target-triple`, `--runner`, `--runner-arg`, `--ada-prefix`,
  `--ada-target`, `--ada-runtime`, `--ada-gprbuild`, `--ada-gnat`,
  `--ada-switch` and `--probe-backend`; `bhf build` gains the C/C++ ones plus
  `--ada-gprbuild`, `--ada-gnat` and `--ada-switch`.
- Whole-sweep cross mode: with a `[toolchain] runner` (`--runner`) and a
  C/C++ toolchain that builds for another target (`target`, or a cross `cc`),
  every C/C++ candidate is built for the target with coverage and fuzzed under
  the runner. A runner for a foreign `[toolchain.ada] target` alone runs only
  the Ada harnesses (with that target's qemu-user `-L` directory) and leaves the
  C/C++ candidates native. A foreign target or C/C++ compiler (also from
  `CC`/`CXX`) without a runner, and a runner with nothing foreign to run, are
  refused before anything builds. The archives a build probe (`--probe-build`,
  `--build-command`, `--run-untrusted`) builds for the host, in its probe
  directory or (a plain Makefile) in the tree, are rebuilt for the target
  member by member from the captured compile commands and linked into the
  cross-built harnesses; members of the same name from different translation
  units are told apart by the objects the build left, and an archive that
  cannot be rebuilt is named with the reason. An archive already built for the
  target is linked as it is, and a project archive is linked into a cross build
  only when its objects are for the target's architecture.
- `[cross.<guard>]` config tables (explicit `--config` only) override the
  compiler (`cc`, `cxx`), `target`, `sysroot`, `runner` and `runner-args` of a
  guard-driven cross lane (`mingw`, `aarch64`, `armhf`, `ppc64le`, `ppc64`,
  `ppc`, `mipsel`, `mips`, `sparc64`) instead of the built-in table. They are
  validated before anything builds, and bhf prints what each selects. A lane's
  sysroot reaches every compile and link, bhf's driver object included, and a
  clang `cc` gets `--target=<triple>`; they replace a `[toolchain]` sysroot or
  target for the lane's candidates.
- More `bhf auto` config keys: `extra-source`, `seed-file`, `seed-dir`,
  `sanitizers`, `engine`, `languages`, `project`, `ada-deps`, `passes`, and
  `probe-build` (explicit `--config` only).
- docs/site/custom-harness.md: writing an `LLVMFuzzerTestOneInput` entry
  point and wrapping it with `generate-harness`, editing a generated
  `bhf_run_one`, building with `AUTO_EXTRA_SOURCES`/`AUTO_EXTRA_INCLUDES`/
  `CXX_STD`, fuzzing from byte-exact `--seed-file` seeds, triage, the
  binary-only route, and what to avoid. The C/C++ and CLI pages now generate
  manual harnesses into `<work>/harnesses/`.
- `auto/seeds.json` lists every seed a `bhf auto` run used (path, source
  `user`/`mined`, size, bytes used, sha256), and `run.json` gains an additive
  `seeds` summary that points to it. `-v` prints the list. A run that stops
  before resolving seeds removes a list left by an earlier run in the work dir.
- `bhf auto --no-seed-mining` and the config key `seed-mining = false` turn off
  seeding from the tree's own test data.
- `finding.json` `exception` carries the sanitizer's structured evidence:
  `location`, UBSan `check`, and ASan `access` (direction, size, address and
  hint, region kind/size/offset, allocation and free stacks). The fuzz run
  summary (`fuzz_runs/<harness>-latest.json`) `duplicate_sanitizer_hits`
  counts later crashes folded into an already-reported root cause, and
  `unreproduced_sanitizer_hits` the crashes of a root cause that never
  reproduced in a fresh process. All are additive.
- Rules BHF-213 (undefined behavior), BHF-214 (missing return), BHF-215
  (invalid shift), BHF-216 (unreachable reached), BHF-217 (invalid bool/enum
  load), BHF-218 (out-of-range floating-point conversion), BHF-219 (pointer
  overflow), BHF-220 (array index out of bounds), BHF-221 (type mismatch),
  BHF-222 (division by zero), BHF-223 (SEGV on a non-null address), BHF-224
  (invalid variable-length array size), BHF-225 (value-changing implicit
  integer conversion), BHF-226 (misaligned access), BHF-227 (access to an
  undersized object) and BHF-228 (invalid builtin argument).
- Ada rules BHF-564 (index/range checks suppressed), BHF-565 (overflow check
  suppressed), BHF-566 (local `'Unchecked_Access` escapes), BHF-567 (address
  overlay), BHF-568 (unsafe C function imported), BHF-569 (secret logged),
  BHF-570 (exception escapes a C export), BHF-571 (raise out of `Finalize`), and
  Ada coverage for BHF-419, 422, 428, 436, 437 and 550. See
  `docs/designs/2026-10-16-ada-static-rules.md`.
- `bhf replay --json` prints the result as one `bhf.replay.v1` document for
  every kind of finding (a non-harness finding's document carries `lane` and
  `details`, and `harness` only when a binary ran), and `--show-output` also
  prints the harness's raw output.
- `bhf report --backfill` replays each C/C++ sanitizer finding without a
  `sanitizer.log` (such as findings migrated from a 0.2.x work dir) against its
  harness and, when the replay is the recorded crash, adds `sanitizer.log`, the
  crash frames, the reported location, check and memory access, and a refreshed
  sink and explanation to the finding (id and signature unchanged, a `history`
  entry recorded). Findings whose harness is gone, that now crash elsewhere,
  or whose replay is unsymbolized, are listed and left as they were. It runs
  with the LLVM toolchain `bhf auto` uses on `PATH`.
- `results/INDEX.md`, `bhf report` and the end of each producer run warn when a
  work dir from an earlier release (migrated from 0.2.x, with a set-aside or
  reused earlier corpus, or with `bhf auto` state and no
  `auto/legacy-corpus.json`) holds testcases or corpus entries with several
  `EF BF BD` sequences, which earlier seed encoding produced from binary seeds.
  A work dir this release's `bhf auto` started is never flagged, even when the
  run stopped before writing `auto/seeds.json`. `results::RebuildSummary`
  gains a `damaged_inputs` field.
- docs/finding-report-fields.md describes upgrading a 0.2.x work dir.
- A C or C++ capsule ships `build.ps1`, a Windows build that needs no POSIX
  shell, and on Windows `bhf capsule` and `bhf verify-poc` rebuild with it.
  It builds the way the harness Makefile builds there, linking bhf's driver
  (the capsule now also ships `runtime/bhf_driver.c`), with the compiler
  family recorded for the harness (`bhf_toolchain.stamp`; for the MSVC lane,
  the compiler bhf's cl front end ran, now recorded in
  `coverage-build-recipe.json` as `msvc_compiler`): cl with
  `/fsanitize=address` and cl's SanitizerCoverage flags (linking
  `libsancov.lib`) as the bhf-cl front end spells them, with bhf's weak repair
  stubs compiled from MSVC copies; clang-cl; or clang targeting MSVC.
  `$CC`/`$CXX` names another compiler. Outside a Developer shell the script
  takes the environment cl and clang-cl read from Visual Studio, and it
  copies the sanitizer
  runtime DLL next to `poc.exe`. The manifest gains `build_windows`,
  `run_windows`, `requires_windows` and `build_recipe` `windows_compiler`,
  `windows_compiler_dialect` and `windows_compiler_source` (all additive).
  Before, a capsule rebuilt only through `sh build.sh`, with clang-style
  `-fsanitize` flags even for a cl-built harness, and its `./poc` did not run
  on Windows. A rebuild that fails is reported by MSVC's `error C2065:` /
  `error LNK2019:` line as well as by an `error:` line.

## 0.3.0 - 2026-10-05

### Breaking
- Default CLI and daemon artifacts omit LLM integrations; build with the explicit
  `llm` feature to include them. The default container includes all sixteen
  supported languages; reduced `core` and `ada` images require explicit selection.
  `--languages` limits a run only when supplied. Validation sweep startup
  requires the `validation` Compose profile.
- Maven/Gradle, Cargo, and MSBuild project execution requires `--run-untrusted`;
  dependency resolution uses staged caches. Disconnected deployment additionally
  requires operating-system network isolation.
- All findings, indexes and native reports live under `<work-dir>/results/`. `FINDINGS.md`,
  `findings.csv` and `auto/findings.csv` at the work-dir top, `auto/attestation.json`, and
  `reports/run-last.*` (written by `ci --sarif`) are gone. Use `results/INDEX.md`,
  `results/findings.{json,csv,sarif}` and `results/attestation.json`.
- `findings.csv` has a new, single column set (see docs/finding-report-fields.md). The
  per-harness stub columns moved to `auto/run.json` `targets[]`; `--static-dynamic` is a no-op.
- `static-scan` and `sbom` default to `<work-dir>/results/{static,sbom}`; `--out` still
  writes elsewhere (and then does not update `results/`).
- `differential --out` is now `--work-dir` (alias kept); findings are `F-DIFF-NNNN`.
- `bhf report` with no flags rebuilds `bhf_work/results/`; `--findings/--out` keep the old behaviour.
- Severity is unified: impact, then record severity, then rule default; `--force` stub
  findings are floored to low on disk. `ci --fail-on` uses the same resolver. A finding with
  no impact, severity, or rule (the resolver's `medium` default) now trips `--fail-on
  medium`/`low` instead of being bucketed `unknown`, which is fail-closed; an unreadable
  record is still counted as `unknown`.
- Tools that read `bhf_work/findings.csv` or `bhf_work/findings/` directly must switch to
  `results/findings.json` (schema in `schemas/`, reference fixture in `tests/fixtures/golden_results/`).

### Added
- **Coverage-guided relational policy fuzzing** (`bhf relational`): run one generated
  testcase across several named launch/session **profiles** (differing in runner, args,
  environment, declared target allowlist and secret references) and evaluate declarative
  relational **predicates** (`status_relation`, `subset`/allowlist, `equal`, `differ`, and
  an `external` comparator decided by a trusted out-of-process extension) over each
  profile's observed behaviour, catching both
  unexpected *divergence* and unexpected *equivalence* against an explicit policy — an
  authorization bug class a crash-only or single-harness output-diff oracle cannot see,
  because the offending runs can exit `0` with byte-identical stdout (#61). The campaign
  retains inputs that reach new code in any profile, a new semantic observation
  (postcondition / runtime-oracle result), a new cross-profile outcome vector, or a new
  effect-event shape, and emits a finding per violated relation: `BHF-308`
  (unexpected authorization, CWE-863), `BHF-309` (allowlist escape, CWE-862), `BHF-310`
  (unexpected equivalence, CWE-285), `BHF-311` (unexpected divergence, CWE-754) and
  `BHF-312` (external-comparator violation, CWE-285). An `external` predicate names a
  trusted `bhf.extension-manifest.v1` comparator by path (explicit load is the trust
  boundary); the driver spawns + negotiates it and drives `oracle.evaluate` (#57's
  `bhf.extension.v1`) over the secret-redacted cross-profile observation bundle, mapping
  `ok → compliant`, `finding → violation` (carrying the comparator's signature,
  classification and executable/config-hash + protocol-version provenance into the
  relational finding) and `unsupported`/bounded-infrastructure → `policy_unknown` — never a
  fabricated verdict, and kept distinct from setup/auth/missing-observation outcomes. Each
  profile runs with a **distinct** coverage-shm file, runtime-trace log and scratch dir, so
  one profile's coverage or effect events can never contaminate another's, and per-case
  novelty is bucketed per profile. Effect events come from the runtime-trace collector,
  with the platform-neutral `bhf.collector-event.v1` source feeding the same seam where it
  is active. Secret references (`lab:` prefix) are resolved locally and in-process only and
  redacted out of every finding and replay bundle — only the stable reference id survives.
  New `bhf relational run` (campaign), `bhf relational replay` (re-run every required
  profile and re-confirm the relation) and `bhf relational minimize` (shrink the testcase
  and reduce the required profile set) subcommands; the policy is a TOML file
  (`bhf.relational.v1`). Findings persist through the unified `results/` layout
  (`results/findings/F-REL-*`) so importers / SARIF / vulnerability-management tools read
  them with the same reader as every other finding kind.
- Versioned **out-of-process extension protocol** (`bhf.extension.v1`): bhf can start an
  explicitly-trusted extension executable, negotiate a protocol version + capabilities
  before any work, and drive length-framed JSON request/response envelopes that each
  carry campaign/worker/testcase identity (#57). The shipped capability is
  `oracle.evaluate`: a private semantic oracle can judge whether a **clean-exiting**
  input violates a contract a crash-only fuzzer cannot see, becoming a stable,
  replayable `extension_oracle` finding (`confirmation: "extension"`). New `bhf extension
  validate` (spawn + negotiate, print protocol/caps/hashes) and `bhf extension evaluate`
  (drive one input, emit a finding + run provenance) subcommands, plus `bhf fuzz
  --extension <manifest>` which drives the retained corpus through the oracle after the
  run (not in the hot mutation loop) and attaches an additive `extension` block to the
  run summary. Every extension crash, per-call timeout, oversized/malformed response,
  mismatched case identity, or `unsupported` reply is a **bounded infrastructure result**
  that can never masquerade as a target vulnerability; findings and run metadata record
  the extension executable/config SHA-256, negotiated capabilities, protocol version, and
  restart/loss events. The manifest (`bhf.extension-manifest.v1`, TOML) is only ever
  loaded through an explicit `--manifest` path — that is the trust boundary; there is no
  auto-discovery. The wire contract is externally implementable (JSON Schemas in
  `schemas/`, operator docs in `docs/extension-protocol.md`, and a dependency-free Python
  reference extension), so an out-of-tree extension in any language interoperates with
  the host. The **full capability set** is now implemented: `codec.decode` /
  `codec.encode` / `codec.repair` (decode a raw frame to a structured value, encode it
  back, and repair computed fields like length/CRC after a mutation), `mutator.mutate`
  (reproducible structure-aware mutation), `scenario.next` / `scenario.observe-response`
  (drive a multi-message session, binding a response-derived handle/nonce into a later
  message), and `lifecycle.setup` / `lifecycle.reset` / `lifecycle.teardown` (per-case
  state with a fresh temp root between cases). A new `bhf extension session` composes
  them end to end against a target (a mutated frame is codec-repaired before it reaches
  the target; the OPEN handle is bound into the WRITE; a clean-exit escape is a finding),
  and `bhf fuzz --extension` repairs a recognized retained frame before the oracle sees
  it. A `bhf.project.v1` profile can declare the extension inline via an `[[extension]]`
  section, which `bhf project run` materializes as a trusted `bhf.extension-manifest.v1`
  and loads. Capability negotiation advertises the whole set, and an extension that
  declares only a subset still works; CBOR wire encoding remains an optional,
  negotiated-but-unused format (the host speaks JSON only). The minimal reproduction (a
  toy `[u16 length][payload][u32 crc]` protocol with `OPEN`/`WRITE`) is implemented once
  outside the tree in the Python reference extension, which is now also exercised by a
  release-build integration test (not just the debug run). The reference extension's
  `codec.decode`/`codec.repair` reject any input that is not a recognized toy frame, so an
  unrecognized raw corpus entry is evaluated **verbatim** instead of being rebuilt — the
  host stays codec-agnostic over arbitrary corpora. A crash/timeout whose restart-time
  re-handshake fails (restart budget exhausted) is now classified as a bounded
  infrastructure result — `EXIT_INFRA` (4) with run provenance (loss recorded) — rather
  than a usage error with no provenance. New `bhf extension minimize` delta-debugs an
  emitted extension-oracle finding by re-driving `oracle.evaluate`, accepting a candidate
  only when it reproduces the **same stable signature**, so a finding is emitted, replayed,
  and minimized with an unchanged signature (#57).
- `bhf fuzz` / `bhf binary-fuzz` gain a platform-neutral **runtime-event collector**
  (`--collector <auto|none|PATH>`, `--collector-window-ms <MS>`) that observes the
  process, filesystem, and module-load effects a target performs even when it exits
  cleanly (#60). Observed effects are attributed to the testcase's descendant process
  tree within a bounded post-exit window and fed through the shared bug-oracle
  registry, so a controlled process execution, a path escaping the allowed root, or a
  controlled library load becomes a `binary_semantic` finding with no crash. The
  contract is a versioned JSONL wire format (`bhf.collector-event.v1`, JSON Schema in
  `schemas/`) that an out-of-repo provider can target: `--collector auto` selects the
  built-in provider for the platform — on Windows the native `bhf-collector-win` ETW
  provider, which starts the NT Kernel Logger real-time session and decodes live
  `EVENT_RECORD`s for the process / file-I/O / image-load kernel providers (complete
  pointer-size- and version-aware MOF decode: `CreateProcess*`/descendants,
  file create/open/write/rename/delete with resolved paths, `LoadLibrary*`/image-load);
  on Linux the in-process `LD_PRELOAD` runtrace adapter, a collector-shaped view over
  the same shim events that leaves `--runtime-oracles` unchanged. On Linux the adapter
  reuses the fuzz loop's shim log, so `bhf fuzz --collector auto` with the shim not armed
  (the default `--runtime-oracles off`) records a degraded, *not-observed* run rather
  than claiming a clean assurance over coverage it never had, and the adapter confirms a
  sink only through the SAME cross-execution matching / constant-suppression the
  runtime oracles use — never from a single run's taint. A PATH runs an
  external sidecar, and `none` (default) leaves behaviour unchanged. The Windows decode
  logic is unit-tested on every platform against synthetic ETW-shaped records (including
  version-guarded v2/v3 `FileIo_Create` payloads); the live
  ETW run is validated on the Windows CI runner (`BHF_WIN_LIVE=1`). Findings store their raw collector
  session as evidence so `bhf replay` reproduces the semantic finding deterministically
  and a reviewer can audit the attribution; collection loss, unsupported APIs, or a
  permission denial are recorded as fidelity limitations and refuse a false "clean"
  assurance. Provenance records the backend name/version/hash, process-tree scope,
  observation window, the backend's *declared* supported event classes kept distinct
  from the classes actually *observed* this run, and fidelity, for importers /
  SARIF / vulnerability-management tools. (#60)
- `bhf fuzz --protocol-profile <PATH>` drives a response-dependent, multi-message
  **protocol session** (HDF-7): a versioned profile (`bhf.protocol.v1`, TOML)
  declares typed messages, computed length/CRC/offset/TLV fields, response
  captures and back-references, legal message ordering, session reset, and a
  clean-exit oracle. Mutation edits field values and sequence structure, a repair
  pass recomputes derived fields and re-resolves references before send, and
  scheduling reports code-coverage novelty and protocol-state/transition novelty
  separately. `--session-transport tcp:HOST:PORT`, `--session-reset`, and
  `--max-session-messages` control the live TCP backend; a finding carries a
  `session.json` artifact, and `bhf replay`/`bhf minimize` re-drive and shrink it
  against a fresh reset. The run and finding record the profile hash and
  transport/reset fidelity, for importers / SARIF / vulnerability-management
  tools. (#58)
- `results/findings.json` (`bhf.findings.v1`) with JSON Schemas in `schemas/`.
- Per-finding `sanitizer.log`, harness sha256 + GNU build-id, `created_at`/`last_seen`,
  `history[]`, and a minimized reproducer for each root-cause group (`--no-minimize`).
- SBOM vulnerability matches appear as `sca` findings.
- Portable harness export: each generated C/C++/Rust/Ada harness dir now carries a
  `Mayhemfile` and a `PORTABILITY.md` with exact commands for Mayhem, libFuzzer, AFL++,
  and honggfuzz. C/C++ gain a `make libfuzzer` target; Rust gains a `build-libfuzzer.sh`
  (a separate instrumented build, since libFuzzer cannot consume bhf's trace-pc-guard
  staticlib); both use a generated `bhf_libfuzzer.c` shim. `BHF_CRASH_ON_FINDING=1` makes an
  Ada finding abort the process (SIGABRT) so a crash-keying external engine detects it.
- `bhf binary fuzz` can express a manually authored binary-only harness that needs
  an emulator/loader and fixed arguments: `--runner <PROG>` (e.g. `wine`,
  `qemu-x86_64`) with repeatable `--runner-arg`, and repeatable `--target-arg`
  (a `@@` token marks the input-file position, else file-mode input is appended).
  The runner, target args, and full argv are recorded in the finding so
  `bhf replay`/`bhf minimize` reproduce the launch. `--runner` is builtin-engine
  only; `--target-arg` applies to the afl-qemu engine too (#47).
- `--runtime-oracles auto|on|off` on `bhf fuzz` and `bhf binary fuzz` loads the
  runtrace sink oracles via the `LD_PRELOAD` shim, so a clean-exit semantic
  violation (fuzz-controlled command execution, path escape, dlopen, network
  egress, SQL) becomes a finding even when the target exits zero — not just a
  crash. `bhf fuzz` reuses the builtin loop's existing oracle + cross-execution
  taint machinery (previously reachable only through `bhf auto`); `bhf binary
  fuzz` publishes each input to the shim through an inherited fd so a black-box
  target gets byte-origin taint, emits `binary_semantic` findings, and replays
  them by re-confirming the oracle. Off by default (opt-in); Linux-only (#59).
- `bhf binary fuzz` user-defined postcondition oracles with per-case fixture
  hooks: `--setup-command` / `--oracle-command` / `--reset-command`. Each case
  runs in a fresh `BHF_CASE_DIR` (passed to the hooks and the target); the oracle
  gets the target status + stderr and signals clean (exit 0) / finding (exit 1,
  first stdout line = signature) / infrastructure error (any other exit). A
  violation becomes a `binary_postcondition` finding (BHF-502) even on a clean
  target exit, and `bhf replay`/`minimize` re-evaluate the oracle rather than a
  crash signature — expressing application-specific security policy the built-in
  sink oracles cannot (#55).
- `bhf project <validate|list|run>`: a versioned, explicitly-loaded external
  project/target-profile manifest (`bhf.project.v1`, TOML) kept outside the bhf
  source tree. One manifest composes a private harness (source or prebuilt
  binary) with its corpora, layered dictionaries (merged in declared order, not
  first-match), grammar, and per-target launch settings under stable target ids.
  `validate` resolves and hashes every asset and type-checks each target (missing
  assets, duplicate ids, unsupported schema/bhf version, invalid relative paths,
  unsafe secret interpolation) without running a campaign or the build command;
  `run` materializes an isolated work dir and reuses the existing
  `builtin`/`afl++` (`fuzz`) and `binary` (`binary fuzz`) engines, records
  provenance (`results/project.json`: project id/version/schema, manifest
  SHA-256, resolved+redacted launch, and every asset's SHA-256), and stamps a
  `project-provenance.json` sidecar onto each finding and the native run-summary
  dir so findings/replay/minimization retain project/target identity. Paths
  resolve relative to the manifest dir (`--allow-external-paths` to opt out of
  the `..`/absolute guard); `${env:NAME}`/`${secret:NAME}` env handles resolve at
  launch with only the handle recorded in provenance. Explicit `--manifest` is
  the trust boundary (no auto-discovery; `--skip-build` reuses a prebuilt
  binary). A target composes the engines' launch features: `runner` /
  `runner-args` / `target-args` (with `arguments` as an alias) launch a binary
  target under a runner/emulator with fixed `@@`-marked argv (#47, binary engine
  only); `runtime-oracles` (`auto`/`on`/`off`) arms the clean-exit sink oracles
  on both lanes (#59); and a `[target.postcondition]` with required
  `oracle-command` plus optional `setup-command`/`reset-command` runs a
  user-defined security postcondition around each testcase (#55, binary builtin
  engine). Malformed compositions fail closed at `validate` (an unknown field, a
  `runner-args` without `runner`, a `target-args`/`arguments` conflict, a
  postcondition with no oracle, an invalid `runtime-oracles` mode, or a
  binary-only wrapper on a native target) (#56).

### Changed
- With no `--findings`/`--out`, `bhf report` rebuilds `bhf_work/results/`. `--junit`/
  `--baseline`/`--model` write to `results/report/` (with the `bhf.report.v2` snapshot).
  `export` bundles `results/`. `clean --findings` removes `results/`, and `clean --reports`
  removes `results/report/`.

### Fixed
- **Fuzz-pass deadlines now cover persistent execution and RedQueen setup**: a
  persistent harness could continue fixed-length waits after its pass budget,
  while descendants that inherited captured pipes could keep cleanup blocked
  after the parent was killed. Persistent waits now inherit the effective pass
  timeout, RedQueen setup stops at the pass deadline, and timeout/error cleanup
  terminates the complete harness process group.
- **Protocol-session replay/minimize honor the recorded oracle** (`bhf replay`/`bhf minimize`,
  #58): under a multi-oracle profile (`[[oracle]]` is a list) a session recorded for oracle
  `O1` could be "reproduced" — or minimized — via a *different* oracle `O2` firing, falsely
  confirming `O1` and letting delta-debugging shrink away the very structure `O1` depends on.
  Replay and minimize now require the re-driven session to fire the SAME recorded oracle (by
  name and `rule_id`), not merely *some* finding.
- **Explicit enum wire width + overflow guard** (`bhf.protocol.v1`, #58): an `enum` field (and
  response capture) may now set an explicit `width = "u8"|"u16"|"u32"`; when absent the width is
  still inferred from the largest variant code, but an enum that must occupy a wider wire field
  than its codes imply no longer under-sizes and shifts the fields after it. A variant code that
  exceeds the resolved width now errors with `ValueTooWide` at encode time (mirroring the integer
  arm) instead of silently truncating.
- **Extension re-handshake failure no longer leaks children** (`bhf extension`/`bhf fuzz
  --extension`, #57): a supervised extension whose restart-time re-handshake fails persistently
  now ends the pass after a single failed respawn instead of re-attempting one for every
  remaining restart slot, and the host reaps every spawned child. Previously each failed
  re-handshake dropped its freshly-spawned child's session via `?` without killing/reaping it
  (`std::process::Child` neither kills nor waits on drop), leaking up to `max_restarts` zombie
  processes across the evaluate loop. A failed respawn/re-handshake is now terminal (at most one
  extra child), and a `Session` reaps its child on drop on every path. The bounded outcome is
  unchanged: `EXIT_INFRA` (4) with `extension.json` provenance for `evaluate`/`session`, and the
  fuzz pass still ends cleanly without a target finding.
- **Extension teardown cannot hang on a double-forked grandchild** (`bhf extension`/`bhf fuzz
  --extension`, #57 follow-up): the `Session` drop that reaps the child now waits for its
  stdout frame-reader thread only up to a short bound before detaching it. If the extension
  double-forked a grandchild that inherited the child's stdout (fd 1), that grandchild keeps the
  pipe's write-end open after the direct child is killed+reaped, so the reader's blocking `read`
  never sees EOF; the previous unconditional `join()` on drop would then block teardown/restart
  forever. The child is still killed+reaped (no zombie) and the normal path still joins the
  reader cleanly at EOF — only a reader left blocked on a grandchild-held pipe is abandoned. The
  bounded outcome (`EXIT_INFRA` (4) with `extension.json`) is unchanged.
- **Relational executor robustness** (`bhf relational`, #61): the per-profile spawn now
  feeds stdin and drains stdout/stderr on dedicated threads concurrently with the wait
  loop, so a target that streams more than a pipe buffer of output — or never reads its
  stdin — no longer deadlocks the parent until `--timeout-secs`; the timeout/kill behaviour
  is unchanged. Each per-(profile,case) scratch dir (`input.bin` + `cov.shm` +
  `runtrace.jsonl` + `collector.jsonl`) is now removed as soon as its run returns (via an
  RAII guard), and the campaign/replay/minimize scratch roots are removed on any exit
  including a propagated error, so a long or interrupted campaign no longer accumulates or
  leaks scratch. Retention now also folds in a **new semantic observation** (postcondition /
  runtime-oracle result), matching the documented behaviour.
- **Secret redaction in binary-lane findings** (`bhf project run`, #56): a resolved
  `${secret:NAME}` / `${env:NAME}` env value no longer leaks in plaintext into
  `results/findings/<id>/finding.json` (nor anything `bhf replay`/`minimize` reads back).
  The spawned target still receives the real resolved value, but the finding records only
  the handle; `bhf replay`/`minimize` re-resolve it from the environment (the same
  `BHF_SECRET_<NAME>` mechanism `project run` uses), erroring if it is unset rather than
  reproducing with a missing secret. Standalone `bhf binary fuzz` env is unchanged
  (recorded verbatim; it has no secret handles).
- `F-TSAN`, `F-MEM`, `F-JSINK`, `F-EXT` and `F-DIFF` findings were missing from the auto index.
- `bhf report` with default flags after `bhf auto` found nothing.
- `replay.py` harness discovery looked in the pre-`harnesses/` location.

## 0.2.34 - 2026-10-01

`bhf binary scan` now recurses into Debian `.deb` packages and tar archives.
Previously a `.deb` was recognized as an `ar` container but its compressed
`data.tar.*` member was never decoded, so a package holding one ELF reported
`0 files inventoried`. The scan now decompresses `data.tar.*` / `control.tar.*`
members — gzip, xz, and zstd via pure-Rust decoders (`flate2`, `lzma-rs`,
`ruzstd`), so no external `tar`/`dpkg` is needed and the RHEL 7 / Windows MSVC /
cross build matrices stay C-toolchain-free — walks the tar, and inventories each
contained binary with nested-container provenance in its path (e.g.
`pkg.deb!data.tar.zst!usr/bin/foo`). Decompression is size-capped (`--max-bytes`,
else 1 GiB) and nesting is depth-bounded, so a decompression or recursion bomb is
skipped rather than exhausting memory. (#43)

`bhf binary fuzz --engine afl-qemu` now applies `--timeout-ms` to the mutation
campaign. It documented `--timeout-ms` as the per-execution timeout but never
passed it to `afl-fuzz`, so the campaign auto-calibrated its own timeout while
only the crash-replay oracle honored the flag; it is now threaded through as
`afl-fuzz -t` so both use one policy. A new `--mem-mb <MiB|none>` flag sets the
AFL child memory limit (`afl-fuzz -m`); it defaults to `none` because QEMU mode
maps a large virtual address space and a tight cap aborts the campaign. Both
effective limits are recorded in the run-provenance JSON. (#44)

`bhf fuzz --engine afl++` gains AFL++ binary-only modes so a stripped,
source-less dependency the harness loads can still be covered. `--afl-mode
native|qemu|frida` selects compile-time instrumentation (the default,
byte-for-byte unchanged), QEMU mode (`afl-fuzz -Q`), or Frida mode (`-O`);
`--afl-path DIR` points at a non-`PATH` AFL++ install (sets `AFL_PATH`, locates
`afl-fuzz`); and the repeatable `--afl-inst-range` scopes instrumentation to a
module or address range via `AFL_QEMU_INST_RANGES` / `AFL_FRIDA_INST_RANGES`. The
effective mode, path, and ranges are recorded in `run.json`. (#45)

All three are documented in the CLI reference (`docs/site/cli.md`); `--help`
already carried the flags.

Maintenance: the `bhf_runtrace_shim` LD_PRELOAD interposer now compiles under
rustc 1.99 (which made `invalid_runtime_symbol_definitions` deny-by-default); the
`bhf PR` dogfood gate treats "no auto-harnessable changed targets" as a pass
rather than a tool/setup failure; and the `cargo-minor-and-patch` dependency
group was bumped (including `thiserror` 2.0.21).

## 0.2.33 - 2026-09-28

The built-in `bhf fuzz` engine now arms its in-campaign input-to-state feedback
by default. Previously only `bhf auto` wired the RedQueen cmplog (`BHF_CMP_SHM`,
#400) and value-profile (`BHF_VP_SHM`, #398) shared-memory channels; the raw
`fuzz` command ran blind against integer / magic-value comparison gates and
could clear them only by chance (~2^-32). `prepare()` now arms both for
builtin/BhfFramed harnesses, with `BHF_DISABLE_REDQUEEN=1` as the kill-switch,
at no throughput cost on the exploration path (60.3k/s armed vs 60.6k/s off on a
non-crashing target). On the `redqueen_int` engine-parity fixture this moves the
built-in engine from 0/10 to 10/10 (0.43s median time-to-first-crash), matching
the AFL++ cmplog and libFuzzer value-profile lanes; BHF now solves all four
parity cases. A regression test drives the `bhf fuzz` path cold (the prior gate
only exercised `bhf auto`, which is why the gap went unnoticed).

Documentation: a new **On-Target & Embedded** guide documents the RTOS / radar /
firmware lane end to end — cross-build and probe backends, the three
`--target-transport` backends (on-device agent, gdb-remote debug probe, and
full-system `qemu-system` snapshot) with the coverage-map spec, the `--deadline`
timing oracle (BHF-555), big-endian fidelity, HIL boards, and the
emulator-in-the-loop validation lane. `--deadline`, `--target-transport`, and
`--transport-coverage-map` are now documented in the CLI reference (previously
`--help` only). The emulator lane — RV-1 (big-endian ppc64), RV-2 (live qemu-arm
gdbstub), RV-3 (`qemu-system` Cortex-M snapshot + planted fault) — was validated
live on QEMU 8.2.2, and the RTOS roadmap's status was reconciled to match.

## 0.2.32 - 2026-09-14

**Security release. Two separate ways a scanned tree could execute commands on the
host running `bhf auto`, both in default mode with no opt-in flag and no error
surfaced.** Anyone running 0.2.31 against code they do not control should upgrade. A
tree delivered for assurance review, fuzzed in CI, or cloned from a public
repository carried the payload into whatever host held the secrets.

Both live in the same trust boundary — the two files `bhf auto` reads straight out
of the scanned tree by design, an auto-loaded `.bhf.toml` and the project's own
`compile_commands.json` — but they are different defects with different fixes, and
neither fix closes the other.

**Command injection into the generated Makefile (GHSA-725h-95qg-44fv, CWE-78).**
Values from both files were interpolated into the harness Makefile unescaped, and
`make` hands those recipes to `/bin/sh`. Three sinks: `cxx-std` from `.bhf.toml` and
a `-std=` recovered from the compile database both reach `CXX_STD ?= <value>`, which
expands into `-std=$(CXX_STD)`; the compile database's compiler reaches `CXX =`,
which heads every recipe line. The reported vector was the first. The second needs
no `.bhf.toml` at all, so fixing only what was reported would have left an
equivalent primitive in place.

The root cause was one pattern rather than three bugs. `split_cpp_build_context_flags` and `split_c_compile_context`
pull values back out of the internal `@bhf-build-context-*` pseudo-flags and
interpolate them with no escaping, while validation only ever inspected the
*prefixed* form — where the single-quote relaxation that exists for legitimate CMake
defines (`-DLLAMA_VERSIONS=>=3`) makes `@bhf-...=c++17; id` look acceptable. The
`-std=` case compounds it: `encoded_flags` deliberately *removes* the flag from
`compile_flags` so it can drive the single `CXX_STD` knob, which also removes it
from the function that would have quoted it.

Validation now happens at the emission boundary, where every producer converges.
`--cxx-std` and any recovered dialect are held to a closed set (`c++`/`gnu++` plus a
two-to-three character alphanumeric version starting with a digit) that accepts
`c++17`, `gnu++20` and the draft forms `c++0x` / `c++2a` while admitting no
separator — the previous check tested only the `c++` prefix, which `c++17; id`
satisfies. `CC`/`CXX` are held to the strict bare-token rule. The `BUILD_CONTEXT_*`
metadata is neutralised: not an active vector, but written as `NAME = <value>` where
a newline would end the assignment and let the remainder parse as Makefile source.
Ada `.gpr` projects get the same treatment adapted to their syntax — GPR is not a
shell, so spaces and parentheses stay legal and only a quote, newline, or control
character is refused.

**Execution of an untrusted compiler from the scanned tree (CWE-829).** Separate
from the above and not closed by it. bhf executes the compiler named by the tree's
`compile_commands.json` — as `$(CC)`/`$(CXX)` under make, in the standalone-header
preflight, and in the libstdc++ probe. The only check was that the token's file name
*contained* `clang`, or equalled `gcc`/`g++`. The path was never verified to be a
real toolchain. A tree that ships an executable beside its sources and points the
database at it therefore ran its own program on the host. No metacharacter is
involved — `./evilclang` is a well-formed path — so every rule added for the
injection class passes it through untouched.

The compile database may now influence *which* compiler is used, never *where it
comes from*. The leaf must be a real driver name, matched exactly after stripping a
version suffix (`gcc-12`) and a target-triple prefix (`aarch64-linux-gnu-gcc`). A
bare name is left as written, since it carries no directory and the operator's PATH
decides. An absolute path outside the scanned tree is honored, so a cross or custom
toolchain keeps working. A relative path, or an absolute path inside the tree, is
refused; `auto` publishes the canonical sweep root for this, and the working
directory is always treated as untrusted, covering `cd repo && bhf auto .`.

Across both fixes, a rejected value falls back to the built-in default rather than
failing the run: the tree's build system is untrusted input, not an operator
instruction, and a project whose compile database carries a malformed dialect should
still get fuzzed. A malformed `--cxx-std` still errors, because that file claims to
configure the run and a silent downgrade would hide it. Well-formed values from
every affected source are honored exactly as before.

**A killed Rust harness build is no longer reported as a compile error.** `classify`
falls back to the tail of cargo's stderr, which is reached only when there is no
error line at all — precisely what a build killed by a signal leaves behind. It
reported whichever crate happened to be compiling, naming a crate that had not
failed. The raw stderr was also discarded at both cargo failure sites, so any
failure the classifier did not recognise was undebuggable. The stderr is now
persisted to `<work>/harnesses/<id>/cargo-build-stderr.log`, progress lines never
stand in for a diagnosis, and the exit status — including the signal — is reported.

**ThreadSanitizer no longer reports a harness race-free when it saw a race it could
not place.** A report whose frames carry no `file:line` is unreadable, not evidence
of a scaffolding race, and was being dropped without being counted anywhere. It is
now surfaced as `unattributed`. A report that *does* resolve to only the bhf driver
or a system library is still dropped, as intended.

Also in this release: `rustls` moves to 0.23.45 for RUSTSEC-2026-0285, which reaches
the tree through `ureq` <- `llm_harness_gen`. rustls 0.23.42 accepted TLS 1.3
handshake messages sent at the wrong encryption level when they followed a
key-changing message in the same record. The handshake transcript stays
authenticated, so this is not a handshake-forgery primitive.

## 0.2.31 - 2026-08-15

**Large auto campaigns are now bounded, compactable, and findings-first.** The
reported 40+ GiB work directory from v0.2.27 was reproducible from retained Rust
Cargo `target/` trees: one real candidate consumed about 589 MiB, multiplied once
per attempted harness. The build now removes those intermediates on every return
path after the final replay binary has consumed them, startup compacts legacy
trees, and `bhf clean <work> --compact` reclaims caches/scratch without
deleting findings, reports, corpora, checkpoints, generated source, or replay
binaries. `--max-work-dir-mb` defaults to a 4096 MiB allocated-size admission
ceiling (`0` disables), while `--max-corpus-mb` defaults to 64 MiB per target for
both active and persisted coverage corpora. Finding testcases are never evicted.

Findings now lead every handoff: `<work>/FINDINGS.md` is impact ordered and carries
evidence, remediation, and replay commands; root `<work>/findings.csv` is the
grouped machine index; full evidence remains in `<work>/findings/`; and the old
`auto/findings.csv` path is kept as an identical compatibility alias. The terminal
and `run.md` point there before campaign coverage and blockers.

**A pinned 200-project, all-language audit closed expert-harness setup gaps with
measured controls.** The durable run completed 200/200 rows, proved entry for 118
selected calls, and covered 105 project bodies. Focused final-binary Go and C++
reruns produce an explicitly labeled 113/200 cross-run composite. The independent
expert set entered and covered 16/16 endpoints; exact normalized semantic target
selection rose from 6/16 to 13/16. The generators now checkpoint immediately
before calls; rank identifier tokens rather than substrings; materialize file
operands for JavaScript/Ruby/COBOL; await JavaScript promises; mine Go feeder →
terminal sequences; construct typed PHP object graphs; support common C++ member
templates/defaults; emit Fortran character-array descriptors; isolate C# target
IL; and retry exact-package Go coverage before black-box fallback.

The checked-in benchmark pins every repository/revision and includes one expert
driver per language plus durable runners and comparison scripts. Its residual
report names the remaining manual-harness territory: private Rust in-crate
targets, full generated/platform build graphs, framework hosts and unavailable
packages, coupled scientific array shapes, and general multi-step resource
protocols.

## 0.2.30 - 2026-07-31

**A freshly built executable is no longer a coin flip to launch.** The kernel
refuses to `exec` a file that is still open for writing anywhere (`ETXTBSY`), and
bhf's whole shape is build-then-run: a harness build followed immediately by a
fuzz or replay of the binary it just produced. In a multi-threaded process a child
forked by one thread inherits a write descriptor another thread has not closed yet,
so the window is real but microseconds wide — it surfaces only under load, as an
intermittent failure that reads like a broken harness rather than a race.

0.2.27 fixed this for `replay` alone. Two other paths were still exposed and both
were failing in CI:

  * the multicore worker spawn — `worker 0 failed to spawn: Text file busy`, which
    had been misattributed to an unrelated dependency bump;
  * the ThreadSanitizer and MemorySanitizer corpus replays, which `make` a
    sanitizer binary and exec it immediately. There the failure was SILENT: the
    spawn error was indistinguishable from a completed run, so the replay reported
    zero findings — a clean bill of health for a binary that never started. The
    TSan case was diagnosed from its CI timing: the test failed in 0.69s, where the
    timeout path it was first attributed to would have taken 150s.

The retry now lives at the single spawn every bounded subprocess goes through, so
harness builds, replays, fuzz children and the multicore workers are all covered
rather than three call sites being patched one incident at a time. `WouldBlock`
(`EAGAIN`) is retried alongside it, for a loaded box briefly out of process slots.

**A ThreadSanitizer replay run that never completed is now reported as UNMEASURED
rather than counted as clean.** `run_tsan_replay` returns findings AND the number of
corpus inputs whose run never finished, and `auto` prints the latter, saying those
inputs are not clean. A timed-out child arrives as an ordinary non-success exit —
`output_with_timeout` kills it and discards the `timed_out` flag — so the replay had
no way to tell "ran, no race" from "never ran"; `output_with_timeout_flagged` exposes
it. This is the same false-clean class as `stub_only` (#417) and `built_not_entered`
(#95).

**The C# lane reports itself accurately, and tells an offline host what it needs.**
The preflight banner resolved `sharpfuzz` on PATH only while the build also accepts
the default dotnet global-tools location, so a host that had run
`dotnet tool install --global` — which writes to `~/.dotnet/tools`, not on PATH —
was told "C# MISSING sharpfuzz" and then built and fuzzed the lane anyway. Both now
share one resolver, which also gained the Windows path
(`%USERPROFILE%\.dotnet\tools\sharpfuzz.exe`) it never had. The install hint named
a command that needs the network, on the hosts least able to run it, and omitted
NuGet entirely — yet the generated harness references SharpFuzz 2.3.0 plus every
`PackageReference` copied from the target csproj, so an offline host with both tools
staged passed preflight and then failed EVERY target at restore. The hint now names
the offline path and `NUGET_PACKAGES`.

## 0.2.29 - 2026-07-31

**`auto` now shows where the run is, and lets you steer it without killing it.**
The sweep printed one line per target — position, name, outcome — which answers
"what is happening" but not "how far along is this", "is it yielding anything",
or "which of the two `--force` phases am I in". On a 26k-candidate tree the
position counter is also the wrong progress signal: with `--max-targets 50` the
run ends at 50 *fuzzed*, and `[213/26409]` says nothing about that.

A terminal run now keeps a status block pinned below the scrolling results,
carrying the constraint that will actually end the run (with an ETA derived from
the binding one — success rate under a cap, attempt rate otherwise, never past a
`--campaign-time` deadline), a live yield tally with the most common blocker, host
CPU/RSS against the run's own budget, and one line per in-flight target showing
its stage, execs/s, edges, and how long since it last found anything. `--force`
phase 2 is named in the block rather than only in a banner that has scrolled away.

**The run is also steerable from the keyboard.** Every one of these previously
meant killing the sweep and restarting with different flags, discarding every
completed target:

* `q` stops cleanly — no new targets start, in-flight ones finish and are
  persisted, and the report and summary are written. Ctrl-C's outcome (a run
  killed mid-sweep) was previously the only way to stop early. A forced phase 2 is
  skipped rather than started after a stop request.
* `p` pauses and resumes, for when the box is needed elsewhere.
* `+` / `-` retune `--jobs`, clamped to 1..cores.
* `]` / `[` retune `--max-targets`, never below what has already fuzzed. An
  uncapped run can be capped down but not raised — it is already unlimited, and
  inventing a ceiling would silently restrict it.
* `>` / `<` retune `--per-target-time`, applied from the next target (the running
  one keeps its planned pass cascade). Refused when a `--campaign-time` split owns
  the budget rather than fighting it.
* `f` adds or drops the forced phase 2 — decided at the phase boundary, so it
  works on a run that never passed `--force`.
* `v` toggles per-target detail.

Nothing baked into discovery or a harness build (`--sanitizers`, `--cxx-std`,
`--build-command`) is adjustable: changing those mid-sweep would make targets
within one report incomparable.

None of it requires knowing the keys in advance. The legend is a permanent line
of the block and picks one of three widths so a narrow terminal shortens it
instead of cutting it off mid-list — a truncated legend hides that the remaining
keys exist at all. `?` expands it in place into what each key does and what each
value currently is; any key that does something dismisses it again. The block is
also now capped to the terminal height, reporting what it hid: a block taller
than the screen cannot be erased correctly, because the cursor cannot walk up
past the top.

The parallel sweep gained live per-target progress in the process: it previously
ran with no progress sink at all, because concurrent rewrites of a single terminal
line corrupt the display. Each worker now owns a dashboard slot instead. Piped and
CI output is unchanged; `--verbose` adds a run-level heartbeat every 30 s.

Ctrl-C behaviour is untouched — the key reader disables line buffering and echo
but leaves `ISIG` on.

Two smaller corrections fell out of the same work. Every `eprintln!` in the crate
now routes through the run's console (`bhfeprintln!`): a bare write landing inside
the sticky region desynchronised the erase, which wiped the message and stranded
block fragments in the scrollback — observed in a real sweep, not theorised. And
the console summary and `run.md` no longer report the shortfall left by an
operator stop as "dropped by cap", which blamed flags the operator may never have
passed.

## 0.2.28 - 2026-07-30

**BHF-440 no longer reports bhf deleting its own temp input as a target
vulnerability.** Reported from the field: bhf claimed attacker input could
delete a file via a function whose only call is `statvfs` — a read-only stat that
cannot appear in BHF-440's API list at all. The finding showed api `unlink`, path
`/tmp/bhf_in032dWa`, taint `fuzz_input[2..] -> unlink(path)`.

That file is bhf's own: `bhf_make_tempfile()` materialises the fuzz bytes at
`/tmp/bhf_inXXXXXX` so a `const char *path` parameter can be supplied at all, then
bhf removes it. The shim saw the unlink, the path really was input-derived,
and the oracle billed it to whatever target was under test.

A gap rather than a bad heuristic: `is_bhf_owned_resource` already knew these
paths — its comment names `bhf_make_tempfile()` — but had exactly one call site,
the resource-leak oracle. The sink oracles were added later and never consulted
it, and a `ConfirmedSink` carries no frame, so unlike the crash path (which
suppresses "no target frame" as a harness fault) nothing could tell target from
scaffolding.

Scope was set by measurement: a first attempt suppressed any filesystem sink
resolving inside the work dir and immediately failed
`auto_confirms_path_controlled_open_bhf405`, because a target OPENING an
attacker-named file relative to its CWD is a real BHF-405 and the fuzz child's CWD
is inside the work dir. Narrowed to DESTRUCTIVE sinks on bhf's own `/tmp/bhf_*`
artifacts only — a target deleting a file in its own scratch directory still
reports, and so does any traversal.

## 0.2.27 - 2026-07-30

- **`replay` no longer fails intermittently on a freshly built harness.** The
  kernel refuses to `exec` a file that is still open for writing anywhere, so
  building a harness and immediately replaying it races the writer's descriptor
  closing. Both spawn paths now retry that (`ExecutableFileBusy`) and a transient
  fork failure on a loaded box (`WouldBlock`), matched on `ErrorKind` so it
  compiles on every target.

- **The failure says why.** `failed to start harness <path>` kept its cause in the
  `#[source]` chain, and the top-level `error:` line is all a CI log shows — so it
  could not be told apart from a missing file or a permissions problem. The errno
  is in the message now. That ambiguity is why the first two attempts at this fix
  patched the wrong spawn sites, in the wrong crate.

Stated plainly: the retry is a well-founded mitigation, not a confirmed fix — the
errno was never visible, which the second change makes impossible next time.

## 0.2.26 - 2026-07-29

`static-scan` is **13.6x faster on Java** with byte-identical output, and every
per-lane toolchain spawn is now bounded.

| tree | lane | before | after |
|---|---|---:|---:|
| elasticsearch (4.99M SLOC) | Java | 616.6s | **45.4s** (13.6x) |
| kubernetes | Go | 59.2s | **15.4s** (3.8x) |
| Proton | C/C++ | 10.6s | 10.4s |

8.1k -> 110k SLOC/s on Java, memory unchanged or slightly lower.

**The harness came first.** `scripts/validation/finding-parity.py` captures a
normalised digest of a scan — findings as a MULTISET of `rule:path:line:slug`
(several findings legitimately share a site, so set semantics would hide a change
in how many), totals per rule, severity and CWE, and `analysis_gaps` by reason —
and fails on any difference. The gaps matter most: they are where the engine
admits it stopped, so exploring LESS shows up as MORE gaps even when the finding
count holds. Speed is easy to measure and easy to fool yourself about; losing a
finding looks exactly like a faster scan. Every number above is parity-gated, on
Java, Go and C/C++.

**The 0.2.25 write-up blamed the wrong pass** — it named the interprocedural taint
worklist, from reading the code. Measurement put 24 of a 28-second Java scan in
`annotate_reachability`, the call-graph BFS that LABELS findings, and 1.3s in
taint. Both real causes were there:

- **`reachable` was a `BTreeSet<FunctionKey>`, and a key holds a `PathBuf`.** Every
  probe cost ~17 comparisons of long path strings, and the BFS probes once per
  candidate target per call site. It is membership-only and never iterated, so it
  is now a hash set — 3.1x on its own, and it helped Go as much as Java.
- **Each call site walked EVERY function in the tree sharing that name**, and that
  list grows with the tree: the actual source of the O(n^1.6). A name whose whole
  candidate set is already reachable can never contribute again, whichever subset
  the preference rules would pick, so such names are retired. The reachable set
  only grows, so saturation is monotonic and cannot go stale. A further 2.7x, and
  the BFS went 79.1s -> 2.0s on the full tree.

`call_targets` also stopped allocating a `String` per lookup and cloning the whole
candidate list — kept because it is strictly better, though on its own it was
worth only 1.03x.

**Per-lane toolchain spawns are bounded**, the same class as the gprbuild spawn
that ate a campaign and orphaned for 39 hours — found by auditing for it rather
than waiting for it to bite again. C# `have()`/`dotnet --list-sdks`, Java
`javac -version`, JS `node --version` and `node -c <module>` (a real 120s budget,
since it reads user JavaScript), Go `go mod tidy` and `go env GOVERSION`, and the
Rust `cargo +nightly` probe all previously ran with no timeout and no process
group.

Left alone deliberately: the per-file rule packs (23.9s, already parallel at
cores-1) and the taint worklist (16.0s, single-threaded for a mono-language tree
because `scan_taint_project` parallelizes across LANGUAGES). That worklist shares
mutable state and is the pass that can silently change findings, so it needs a
real decomposition rather than a `par_iter` swap.

## 0.2.25 - 2026-07-29

Documentation release on top of 0.2.24, which carried the performance work.

- `docs/expected-gaps.md` now records the one measured performance outlier left
  after the timeout sweep, with its root causes rather than just its symptom:
  `static-scan`'s interprocedural taint pass runs at **8.1k SLOC/s on Java**
  against **924k SLOC/s on C**, and scales at about **O(n^1.6)** (1,050 Java files
  in 2.5s, 4,912 in 30.4s, extrapolating to the 616s measured over elasticsearch's
  31,243). `scan_taint_project` parallelizes across LANGUAGES rather than within
  one, so a single-language tree runs the whole phase on one core; and the
  worklist revisits a function once per distinct taint signature.

## 0.2.24 - 2026-07-29

Performance and robustness release. **Every project that timed out in the
500-project sweep now completes**, and two long-standing process bugs are gone.

Validated on a 16-lane sweep (`benchmarks/campaign-2026-07-25/results-0729/`, 48
projects, 3 per lane): **zero problems — no timeouts, no crashes** — 1,676
targets attempted, 568 fuzzed (33.9%), 121 findings.

**The eight timeouts.** Measured under the real sweep invocation
(`--campaign-time 240`, 510s outer): Proton 449s, sumatrapdf 457s, emscripten
406s, serenity 351s, envoy 366s, rocksdb 361s, whisper.cpp 325s, gnat-llvm 244s.

Four causes, all found by measuring — the first two guesses were wrong and
changed nothing, so the stage timings that found them stay behind
`BHF_PROFILE`:

- **A header classifier that parsed each file twice.** `classify_c_header`
  counted C functions *and* C++ functions to pick a language, then the real parse
  ran a third time: **33 seconds** on simdjson's 187k-line amalgamated header
  before any real work. The cheap predicates already in the same `||` chain now
  answer first.
- **A per-target rescan of the whole source.** Two loop-invariant guards sat
  inside the per-target loop behind a lazy `.or_else`: 7,264 targets × 7.7 MB ≈
  **56 GB of scanning**, 83 of 99 seconds.
- **A per-target linear scan in `list targets`**, allocating a name string per
  comparison — ~74M times on one file.
- **Single-threaded parsing.** Both discovery surfaces ran on one core while the
  static scan had used a worker pool for ages. Now `cores - 1` with the 256 MiB
  stacks discovery already needed, and byte-identical output (entries are visited
  in sorted order and `par_iter().collect()` preserves it).

`list targets`: simdjson 900s TIMEOUT → 143s, Proton 888s → 475s, sumatrapdf
305s → 118s.

**No phase is unbudgeted any more.** Discovery is deliberately not billed to
`--campaign-time`, but unbilled is not unbounded — Proton indexed for 447s
against a declared 240s campaign and was killed having fuzzed nothing. Discovery,
its C++ member-access pass, and the **declaration index (173s, the largest phase
of all)** now honour one deadline for the phase, degrade to a clearly-labelled
PARTIAL result, and say what they skipped. `BHF_DISCOVERY_TIME` overrides.
The in-flight grace scales with the campaign instead of being a flat two minutes,
and no single subprocess may take more than a quarter of it.

**Two process bugs, both observed on real runs:**

- **Orphaned compilers outlived bhf indefinitely.** `compiler_adapter` ran
  gprbuild with a plain `Command::output()` — no timeout, no process group, no
  `PR_SET_PDEATHSIG` — so a killed run left `gprbuild`/`gcc`/`gnat1` with PPID 1.
  Processes were found still burning CPU **39 hours** after their sweep, stealing
  time from every run since. That is also why gnat-llvm timed out on a 4 MB tree:
  one generated harness sent `gnat1` into a spin and nothing stopped it. Verified
  zero orphans after a run that previously left them.

- **Target code ran in the caller's working directory.** An empty file named
  `AAAAAA` — a fuzz input used as a filename — appeared in a source checkout.
  Three paths that execute the built harness set no working directory, so writes
  landed wherever bhf was invoked from, very often the tree being scanned.
  They now run beside the harness binary, under the work dir.

**`--resume` is reliable instead of "works the second time".** Two independent
causes:

- Per-target `result.json` records live in `harnesses/`, which was treated as
  regenerable — so any refresh (a work dir from a different build, say) deleted
  every record. `--resume` then honestly reported "no completed targets" and
  re-ran everything; that run wrote fresh records, so the *next* resume worked. A
  refresh now clears build products and keeps records. Records from a different
  build are kept where they FUZZED and re-attempted otherwise, so a stale "no"
  cannot cap what the new binary reaches.

- Resume treated "discovery cache hit" as proof the tree was unchanged. It is
  not: fuzzing executes the target, and a target that writes or rewrites a
  source-extension file — codegen, compilers — changes the digest the next run
  compares against, so a run can invalidate its own fingerprint. Resume is now
  decided **per source file**: a target is stale only when its own file moved.
  The per-file hashes are a by-product of the fingerprint walk that already ran,
  so this adds no extra walk and no extra reads; only the verdict is kept.

## 0.2.23 - 2026-07-28

Follow-up to 0.2.22, from a second full 500-project sweep (`results-0728/`: 482
measured, **1,212,086 targets discovered, 3,638 attempted, 1,069 built+fuzzed —
29.4%**, 366 findings, all 16 lanes).

> **Corrected 2026-08-25.** Those totals roll up every row file in
> `results-0728/`, including 27 for repositories the lane check later replaced
> from the ranked pool. Scored over the pinned `corpus.tsv` the run is 457
> measured, 1,182,129 discovered, 3,449 attempted, 984 built+fuzzed — 28.5%,
> 329 findings. The defects described below are unaffected.

The headline defect is a crash, not a gap. **carbon-language/carbon-lang was
SIGKILLed during discovery in BOTH `list targets` and `auto`** — bhf
produced no target list at all, which is worse than any residual blocker,
because a hard kill leaves nothing to act on and is indistinguishable from a
hang.

- **Recursive C/C++ types no longer explode type resolution.** Resolving one
  1205-line header from carbon-lang's `toolchain/sem_ir` took **13.0 GiB and
  88 seconds**. `MAX_RESOLVE_DEPTH` bounds recursion DEPTH but not BREADTH: a
  struct with F fields expands F subtrees, each expanding F more, so a
  self-referential type unrolled to the 16-deep limit materializes on the order
  of F^16 field vectors.

  Two changes, both needed. Resolved shapes are memoized on (spelling, depth) —
  keying on depth as well as spelling keeps results byte-identical to the
  uncached walk, including the `Opaque` truncation at the limit. That halved the
  time but not the memory, because a cache hit still CLONES the subtree:
  memoization avoids recomputation, not materialization. So resolution now also
  stops at a cycle — a type that transitively contains itself resolves to
  `Opaque` at the point of recurrence instead of unrolling. Nothing is lost: a
  decoder cannot build an infinitely nested value, so the unroll and the
  `Opaque` are equally undrivable, but the shape is now the size of the type
  rather than exponential in the depth limit.

  carbon-lang, whole tree: **12.9 GiB and SIGKILLed with no output → 52 MiB,
  exit 0, 5,092 targets listed and 4,040 fuzzable**. The single header: 13.0 GiB
  / 88s → **77 MiB / 1.2s**. The same fix took `simdjson` from a 900-second
  `list targets` timeout to completing in 481s with 14,690 targets.

- **Discovery degrades under memory pressure instead of being OOM-killed.** The
  static scan already survived these trees by stopping at an RSS ceiling;
  discovery had no memory bound at all. Both discovery surfaces now share that
  watchdog and report a PARTIAL target list rather than dying silently.
  `list targets` parses five lanes itself and defers the other eleven to `auto`,
  so guarding only the shared walk would have left C++ — carbon-lang's own
  language — unguarded. Honest note: this guard did **not** save carbon-lang on
  its own, because a single file crossed the ceiling and blew past it between
  two 500ms samples; the type-resolution fix above is the real one. This is the
  backstop for trees that grow past memory gradually.

- **A C++ target in a header that cannot compile standalone is now driven
  through its owner translation unit.** `blocked_by_non_self_contained_header`
  was the largest C++ residual class in the sweep (49 targets, plus 10 in C).
  Such a header routinely compiles as part of the `.cpp` that owns it — the same
  move the C lane already makes for a static target or a private handle, one
  step further out. A candidate is adopted only when it PREFLIGHT-COMPILES, so a
  wrong guess is rejected rather than baked in, and a header no translation unit
  can make compile is still rejected.

- **A repair no longer breaks the code it was meant to unblock.** The loop
  answered an undeclared identifier with `#define ScannerLimit …`, which is
  force-included ahead of every translation unit and rewrote the enumerator's
  own definition — `enum : size_t { ScannerLimit = 4 }` became
  `enum : size_t { 1 = 4 }`, "expected identifier", in a source that compiled
  fine before. Same hazard as the existing tree-function and tree-type vetoes,
  one construct over, and it now gets the same veto and the same
  reserved-identifier escape hatch.

- **An opaque C handle whose struct is defined in the target's own translation
  unit is now drivable** rather than reported as incomplete.

`docs/expected-gaps.md` is re-measured against this sweep.

## 0.2.22 - 2026-07-28

Correctness release. Nineteen defects, found by re-running the full 500-project
sweep and then by reading what the sweep could not explain — plus the three CI
workflows that had been failing unattended while Actions was assumed dead.

Two of these are the kind that hide in plain sight: **no Ada target could be
built on GNAT 11 at all**, and **`list targets` was blind to 11 of the 16
supported languages**. Both had been true for a long time and neither showed up
as an error anyone read.

Found by re-running the full 500-project sweep (`benchmarks/campaign-2026-07-25`,
`results-0727/`: 463 measured, 1.1M targets discovered, 3,594 attempted, 1,057
built+fuzzed, 354 findings).

- **A cyclic construction recipe no longer eats 12 GiB during discovery.** The
  sweep lost 22 projects to `exit=-9` — SIGKILL, no timeout, 44 to 250 seconds
  in, before a target was ever attempted. It was bhf's own memory: one
  `bhf auto` on simdjson, alone on an idle box, peaks at **12.4 GiB and is
  OOM-killed**, where `list targets` over the same 39 MB tree uses 225 MiB. The
  C++ parameter decoder's recipe block documented an invariant — recipes exist
  only for a target's DIRECT parameters, so a constructor's arguments are always
  directly decodable — that the producer graph had since made false. That graph
  resolves what a chosen constructor's arguments need, to a fixed point, and is
  explicitly cyclic (`A(B)`, `B(A)`); the consumer following those recipes had no
  bound. It now carries the chain of keys it is expanding and treats a repeat as
  "not decodable", the same clean skip the parameter got before recipes existed.
  Depth is not what is cut: a three-deep acyclic chain still resolves.

- **POSIX and GLib integer aliases are scalars, not opaque handles.** `pid_t` is
  an int, but the typedef chases into glibc's `__pid_t`, which is not in the
  scanned tree — so fastfetch's `ffProcessGetInfoLinux(pid_t pid, …)` skipped
  with "opaque type 'pid_t' … needs lifecycle support (Phase C)", and HandBrake's
  `ghb_do_scan(…, gboolean force)` said the same about GLib's `gboolean`. This is
  the situation the existing BSD and Win32 blocks already answer. `pthread_t`,
  `sem_t` and `gpointer` are deliberately excluded: they are integer- or
  pointer-shaped but name a live kernel object, and decoding one from fuzz bytes
  hands the target a fabricated handle. `gchar *` joins `char *` as a C string.
  Measured on fastfetch: 1 → 3 built+fuzzed.

  The scalar table also used to win over the tree unconditionally — the same
  hazard as the Win32 header pack redefining a Linux driver's own `CHAR`. A
  project that declares its own `key_t` struct would have had an int cast to it.
  A tree declaration that resolves to something real now wins.

- **A `java.io.File` parameter is a byte channel.** `parse(File)` is the classic
  Java entry point (`ImageIO.read(File)`, `new ZipFile(File)`) and every one of
  them skipped as an unsupported type, because the harness could only hand a
  target bytes it held in memory. It now writes the input to one temp file per
  process, truncated per iteration, and passes its `File`, `Path`, `URI` or
  `URL`. Output sinks (`OutputStream`, `Writer`, `PrintWriter`, `PrintStream`,
  `StringBuilder`) and `ClassLoader` also stopped blocking targets. Collections
  and fuzz-parsed URIs are still refused, with reasons.

- **`list targets` covers all sixteen lanes, not the five it was written for.**
  The command had its own five-variant language enum — Ada, C, C++, Java, Rust —
  written when there were five lanes and never revisited, so on a Go, Python,
  JS/TS, C#, Ruby, PHP, Perl, Lua, Fortran or COBOL tree it printed nothing at
  all. Across the sweep it listed 2.0M targets and every one was in those five,
  while `auto` discovered targets in all sixteen. The eleven are now deferred to
  `auto`'s discovery rather than given a second parser here, gated on a cheap
  extension scan so a C/C++/Ada/Java/Rust-only tree pays what it always did.

- **A JS/TS harness that cannot be prepared says so** (58 targets). The harness
  built — module loads, export resolves — and then died constructing the receiver
  for a `Class#method`, because the class wants an environment that is not here
  (gstack's `BrowseClient` looks for a live daemon port). The engine recorded a
  harness that ran zero inputs and the run said `built, no fuzz pass ran`, naming
  nothing. A third build gate now runs the launcher in a LOAD-ONLY mode and takes
  the driver's own error as the skip reason. Load-only rather than "run one
  input" because a finding halts the driver with a nonzero exit — gating on that
  would have skipped exactly the targets that crash.

- **Discovery on an amalgamated single header finishes.** simdjson's
  `singleheader/` took over 1500 seconds and was still going, where `list
  targets` over the same two files takes 145 — so the whole difference was work
  `auto` adds. Two loop-invariant computations were being redone inside
  per-function loops, and profiling named them (the obvious-looking quadratic was
  not the cost): `recipe_mining::for_source` handed back a CLONE of the whole
  recipe map on every cache hit — **133 of the preflight's 137 seconds** on one
  2,863-function file — and `cpp_class_is_default_constructible` re-parsed the
  entire include closure per opaque parameter, which its caller had already
  parsed once. The preflight on simdjson.h (10,894 functions) went from never
  finishing to **9.5 s**, and the whole directory from >1500 s to **218 s**.

- **A Go target under `internal/` is reachable** (8 targets, 3 repos). Go decides
  "outside the internal tree" from the IMPORT PATH, so a harness module named
  `bhfharness` was outside every project — and `internal/` is where a great
  deal of real Go code lives. The harness now declares itself a child of the
  module under test, satisfying the rule the way the project's own packages do.

- **A language PREVIEW feature is not an unbuildable tree** (11 targets, RxJava
  and spring-framework). javac refuses `var _ = …` — preview on 21, standard from
  22 — and names the flag it wants. It is asked for once now and carried through:
  javac refuses to READ preview class files without it, and so does the JVM that
  loads them.

- **The C# harness no longer duplicates attributes the target declares** (17
  targets, 4 Windows projects). The SDK synthesizes `[assembly: AssemblyTitle]`
  by default and a classic project keeps its own `Properties/AssemblyInfo.cs`
  declaring the same, so compiling those sources in gave `error CS0579`.

- **A `path =` in another table no longer answers for `[lib]`** (8 targets, fd).
  fd declares `[[bin]] path = "src/main.rs"`, so the binary-only crate's
  synthesized `[lib]` went out with no path of its own and cargo refused the
  manifest. Cargo's `error:` line is also a BANNER when it wraps — the diagnosis
  is in the `Caused by:` block, which is now carried.

- **A staged Ada C stub takes the header it includes with it** (12 targets, 2
  projects). `auto_stubs.c` opens with `#include "auto_types.h"`, and a quoted
  include resolves against the including file's own directory — so mirroring only
  the `.c` into the Ada source dir left the header behind and every staged stub
  died on `fatal error: auto_types.h: No such file or directory`. Measured on
  tsoding/eepers: 0 built+fuzzed and 5 failed builds, now 4 and 1.

- **The underscore is not part of the decoration-macro convention.** The ALL-CAPS
  visibility-macro rule anchored on one (`_API`, `_EXPORT`), so it missed JNI's
  `JNIEXPORT jint JNICALL …` — every Android or Java native library — and
  `JNIEXPORT` reached the harness as a type it could not construct offline.

- **A Go `/vN` module is required at `vN`, not `v0`.** The harness `go.mod`
  hardcoded `require <module> v0.0.0-incompatible`, which semantic import
  versioning makes illegal for a path ending `/vN` (N ≥ 2): Go rejects the file
  with `go: errors parsing go.mod` before any build, so every target in the
  project failed. 51 targets across 9 of the sweep's 40 Go repos — caddy,
  cli/cli, alist, etcd, moby, traefik, bubbletea, 3x-ui, CLIProxyAPI. `/v1` and
  unsuffixed paths keep the v0 spelling, which is what Go wants for a module that
  has not adopted the suffix.

  What this buys is that the REAL blocker becomes visible; it is not a fuzz-count
  claim. Measured on bubbletea, 7 targets moved off `failed_build` and the
  manufactured error is gone — and what they hit next is that the module wants a
  newer Go than the host has, which is an environment limit bhf reports
  honestly and cannot fix. Do not restate this as +51 fuzzed targets.

- **A line the interpreter echoed is not the diagnosis.** Node opens every
  module-load failure by echoing the failing statement from its own internals and
  underlining it with a caret; `throw error;` contains "error", so it won the
  first-line-containing-that-word match and **77 targets reported a line of
  Node's source, and nothing else, as their entire reason**. An echoed line (one
  followed by a caret underline) is now ineligible, and a line that NAMES a
  diagnostic is preferred over one that merely contains the word. Python, Lua,
  Perl and Ruby resolve to exactly the line they did before.

- **No Ada target could be built on GNAT 11 at all.** The harness build passed
  `-gnat2022` unconditionally, as "the latest supported standard, which accepts
  older code too". That switch arrived in GNAT 12; on GNAT 11 — Ubuntu 22.04's
  default and that of still-supported RHEL 9 derivatives — `gnat1` answers
  `invalid switch: -gnat2022` and the build dies before reading a line of Ada.
  The standard is now probed and lowered to `-gnat2012` when the compiler lacks
  the switch.

- **A compile flag that needs quoting is quoted, not refused.** A CMake
  version-comparison define is legitimate and its `>` would redirect if emitted
  bare into the recipe — `-DLLAMA_VERSIONS=>=3` (gpt4all),
  `-D_LIBCPP_HARDENING_MODE=..._DEBUG>` (btop) — which cost every target in both
  projects. The relaxation is for FLAGS only: a source path is also a make target
  and an include name lands in an `#include "..."` line, so both stay strict, and
  `$`, a single quote and a newline are still refused outright.

- **A non-code import no longer fails the whole TypeScript transpile.** esbuild
  has no loader for `import logo from "./logo.png"` or `"./Comp.vue"` and fails
  the entire bundle, skipping the target even though the fuzzed function never
  touches the asset (`.png` 5, `.svg` 5, `.yaml` 5, `.vue` 3).

- **A Go `context.Context` parameter is call context, not a refusal.** It carries
  no fuzz input, and one such parameter made the whole target undrivable. The
  harness passes `context.Background()` — never nil, which would panic the moment
  the callee touched `Done()`.

- **Two ways the blocker histogram destroyed its own key.** A path in the MIDDLE
  of a diagnostic was per-instance noise that never grouped — 176 of 1109
  distinct rows, 456 targets, were one-off rows for that alone; a rooted or
  extension-bearing path token now collapses to `PATH`, while prose keeps its
  slashes. And an apostrophe inside a word is a contraction, not a delimiter:
  Perl's most common failure opens "Can't locate Foo.pm in @INC", and reading
  that apostrophe as a quote destroyed the message on the lane where it fires
  most. GNAT's `Foo'` form and Ada attributes are unaffected.

## 0.2.21 - 2026-07-27

Reach release: the targets `--force` was supposed to rescue and did not.

- **`--force` now works outside C/C++/Ada.** The forced sweep's residual
  blockers showed 116 Go targets and 31 C# targets ending `unsupported_params`
  however hard you forced them — Go's undrivable count was identical between the
  forced and unforced arms, because nothing attempted it. Both lanes now have
  the C-family's best-effort driver:
  - **Go** drives an undrivable parameter as its type's zero value, qualifying
    the spelling into the harness package, and calls a method on an addressable
    zero receiver (not a nil pointer, which would panic on first field access).
    An unexported, generic, variadic, or inline-literal type is still refused
    rather than guessed.
  - **C#** allocates a receiver whose type has no accessible parameterless
    constructor without running one, via the runtime's own
    `GetUninitializedObject`, resolved by reflection so the shim compiles on any
    target framework. An abstract type or interface is still refused.
  - A target built on a fabricated value is recorded as such, so the report
    floors its findings to Low with the forced caveat and counts it separately —
    a forced nil-map panic never reads as a confirmed defect.

- **A function returning a struct by value can be stubbed.** Twenty raylib
  symbols in one clay harness stubbed fine and one did not, because it returns
  an aggregate by value and the stub generator had no way to name the type. It
  now constructs a zeroed return value where the type is complete (the
  header-backed path), which is exactly as neutral as the `return 0;` its
  siblings get. clay: 3 of 6 attempted targets fuzzed, now 4.

- **A configure-style `#error` guard no longer ends the build.** Sweeping what
  `--force` still cannot build, ten of 104 sampled unbuilt harnesses died on a
  header's own `#error` — libssh's "no strtoull function found", ImageMagick's
  "you should set MAGICKCORE_QUANTUM_DEPTH" — where nothing is missing from the
  tree at all and a real `./configure` would have defined the macro the guard
  tests. BHF now reads the conditional that owns the `#error` and defines
  that macro, with the value the guard itself requires — preferring the outermost
  feature-test wrapper, so libssh's guard defines `HAVE_STRTOULL` and leaves the
  real libc function alone rather than taking the inner branch and aliasing
  `strtoull` to a symbol this host lacks. Undecidable guards (a comparison, a
  compound condition, an error that fires *because* a macro is defined) are
  refused rather than guessed. Measured on the two corpus projects that carry the
  class: the guard errors are gone from every build log and more targets reach
  the report-only floor (WindTerm 3 → 6, ImageMagick 1 → 4); neither converts a
  target to fuzzing inside a 90-second campaign, because what remains behind them
  is a different class.

- **`findings.csv` columns line up again.** The optional `scan_type`/`forced`
  columns are written before the stub-accounting block but their names were
  appended after it, so under `--force` or `--static-dynamic` every stub column
  carried its left neighbour's value and `forced` read out `linked_real`. With
  neither flag the header is unchanged.

- **A libc function is never defined away.** btop's build died inside glibc —
  `/usr/include/unistd.h:1091: error: expected identifier or '('` on its own
  declaration of `syscall` — because a vendored header calls `syscall()` from a
  `static inline` without including `<unistd.h>`, and the undeclared-call repair
  answered with `#define syscall`. That define is force-included ahead of every
  translation unit, so it erased the declaration too, in a file no repair can
  reach. Such names now route to their declaring header (`#include <unistd.h>`),
  and the neutral-macro fallback refuses outright for anything the C runtime
  owns. btop: 4 of 10 attempted targets built+fuzzed → 5, and zero unbuilt
  harnesses in the sweep.

- **A C++ free function no header declares gets declared.** The forward-
  declaration gate was "does the target have any includes at all", but a
  header-less `.cpp` still pulls in whatever headers the file includes — none of
  which need declare the target. The harness then called a name nothing had
  declared. It now searches those headers for an actual declarator, and strips
  export/constant-evaluation decoration macros (`JNIEXPORT jstring`,
  `utf8_constexpr14_impl int`) from the declaration it emits, so it cannot
  manufacture an `unknown type name` the target never had.

- **`--force` no longer empties the missing-dependency manifest.** Forcing
  degrades a residual failed build to a report-only static scan — the right
  floor — but a report-only outcome carries no diagnostics for the manifest to
  mine, and the degradation replaced them with a bare COUNT of residual errors.
  The dependency evidence went with them, so the run that most needs the manifest
  produced none: tmux, whose every target embeds libevent's `struct event` by
  value, reported "4 still blocking" unforced and **"No external dependencies
  were missing — the tree built against its own sources"** forced. The forced
  degradation now carries the unresolved type names across, and a regression test
  pins that forcing can never empty the manifest.

- **Macro templates and macro invocations are no longer discovered as targets.**
  Two shapes parse as function definitions but are not functions:
  - A body inside a backslash-continued `#define` — BSD `<sys/tree.h>`'s
    `RB_GENERATE_INSERT(name, type, field, cmp, attr)` defines a whole function
    whose return type is `attr struct type *`, where `attr`/`type`/`name` are
    macro PARAMETERS. The harness emitted `attr struct type * R = ...`, which
    clang rejects with "cannot combine with previous 'type-name' declaration
    specifier" and no repair can fix, because nothing is missing. tmux's
    compat/tree.h alone produced seven such dead targets — seven slots in the
    ranked cap that real functions should have had.
  - A multi-segment ALL-CAPS invocation at file scope — Linux's
    `TRACE_EVENT(mcu_cmd_info, TP_PROTO(...), ...)`, which parses as a function
    whose parameter *types* are the macro's arguments. Single-word ALL-CAPS names
    are kept, because BLAS/LAPACK really do export `DGEMM`.

  On lede this removed 139 pseudo-targets from the ranked list and gave the slots
  back to real functions.

- **The synthesized Win32 pack no longer redefines the tree's own typedefs.**
  Win32-style scalar names are not exclusive to Windows: lede's MediaTek mt7603
  Linux driver declares its own `typedef signed char CHAR;` and `union
  _LARGE_INTEGER`. BHF force-included its `windows.h` placeholder over them
  and produced `typedef redefinition with different types ('signed char' vs
  'char')` — its own error. When the tree defines the name, the ordinary type
  repairs run instead.

- **A CamelCase export macro no longer leaks into the generated C harness.**
  `strip_type_decoration` recognised the ALL-CAPS convention (`WREN_API`,
  `STBIDEF`) but not the CamelCase one, so ImageMagick's `ModuleExport size_t f()`
  reached the harness as `extern ModuleExport size_t f(...)`: "unknown type name
  'ModuleExport'" plus an `expected ';'` cascade, on a line BHF wrote itself.
  The same shape was fixed for C++ above; this is its C twin.

- **Getting started.** `docs/recommended-sweep.md` gives the one command to
  start from and what every flag buys; `bhf auto --help` prints the same
  command, and a distribution ships it as `RECOMMENDED-SWEEP.md`.

- **Tooling.** `benchmarks/campaign-2026-07-25/residual_errors.py` sweeps the
  corpus forced and histograms the actual compiler errors behind every harness
  that did not fuzz — the worklist that produced the `#error`-guard fix. It only
  counts harnesses BHF gave up on: the repair loop reaches the link stage
  with symbols still undefined on its way to resolving them, so harvesting every
  harness (the first cut) ranked the loop working as designed as the largest
  defect class.

## 0.2.20 - 2026-07-24

- **More real legacy Ada/C/C++ targets reach the fuzzer.** A focused audit of
  the offline Ada/C/C++ fuzzing path fixed a set of defects, each of which
  silently prevented a class of real targets from being fuzzed:
  - Library-, aggregate-, and abstract-governed Ada projects now build. The
    synthesized build project no longer *extends* a library project (which GNAT
    rejects without `Library_Dir`, and which can't carry the harness main) or an
    aggregate (which can't be extended) — it builds a standalone project over the
    instrumented source overlay instead. Validated in a 20-project sweep against
    real library-project repos (AdaYaml, Ada-Crypto-Library, ada-toml).
  - GCC-instrumented C/C++ harnesses now record coverage. The coverage/cmplog
    shared-memory maps are opened unconditionally in the driver, not only on the
    clang `trace-pc-guard` path — a GCC (`trace-pc`) build previously left them
    NULL and fuzzed blind.
  - The framed fork-server no longer desyncs or deadlocks on inputs larger than
    the harness's 1 MiB buffer: the engine clamps each frame to that buffer.
  - UBSan-class faults (signed overflow, out-of-bounds index, shift, null deref)
    are detected on the default run — the builtin fuzz child now arms
    `UBSAN_OPTIONS`/`ASAN_OPTIONS` halt-on-error, matching the AFL path.
  - A translation unit that mixes old-style K&R and ANSI-prototyped functions
    keeps its ANSI parsers (the real targets), which were previously dropped;
    `list`/`scan` recover the correct K&R signatures too.
  - C++ rvalue-reference parameters (`T&&`) are moved into the call instead of
    being passed as an uncompilable lvalue.
  - `@response-file` compile-database arguments are expanded, preserving the
    `-I`/`-D` context they carried instead of dropping it.

- **Fuzz outcomes.** An `--engine afl++` run that executed zero inputs is
  recorded as built, not fuzzed. A native target that was entered and executed
  but produced zero coverage edges is flagged as having fuzzed blind. A legacy
  C++ target whose older-dialect build ties the default's error count now adopts
  the repairable older-dialect errors and converges instead of failing outright.

- **Dependencies.** Upgraded the Tera template engine to 2.x (with the
  corresponding harness-template syntax update) and refreshed the Cargo
  minor/patch set and pinned GitHub Actions.

## 0.2.19 - 2026-07-23

- **Legacy Ada/C/C++ zero-fuzz remediation.** Forty-seven discovery,
  ranking, generation, build-recovery, and execution-accounting issues found in
  a top-500 legacy-code sweep were investigated and covered by focused and
  end-to-end regressions. Fixes include exact Ada overload identity and
  dependency closure, merged reopened IDL modules, checked-in CORBA servants,
  C++ default/lifecycle construction, neutral `CORBA::Environment` handling,
  namespace-safe type resolution, legacy header preprocessing, and exact
  per-translation-unit compile contexts for original and repair-added sources.
  Directly included C++ implementation files are de-duplicated from that object
  graph, and generated C/C++ Makefiles explicitly select the complete build as
  their default goal. C++ standalone-header preflights now share the harness's
  standard-library path recovery and essential defensive prelude. Ada projects
  with obsolete runtime imports are overlaid without inheriting those imports,
  and generic-local result types are qualified through the generated instance.

- **Target execution and fallback evidence.** Successful campaigns now
  prove entry into the selected project endpoint rather than counting driver
  execution alone. Generation fallback chains, repairs, terminal stages, cache
  provenance, and stable structured failure categories survive into per-target
  checkpoints and final reports.

- **Durable and safe campaign resume.** `auto --resume` reloads atomically
  checkpointed completed targets from an unchanged campaign and retries only
  unfinished targets. Regenerable state is refreshed on normal reruns and
  incompatible upgrades while corpora and findings are preserved. The README
  now documents reboot/power-loss recovery and the target-level resume boundary.

- **Compact scrubbed bug reports.** The release includes
  `bhf-bug-report`, which creates one size-capped support report from a
  running or completed auto work directory. It reports structured decision,
  build, repair, and execution facts without source, harness or corpus content,
  paths, filenames, or project identifiers.

- **Full distribution is a permanent release artifact.** Every tagged release
  builds, installs, smokes, and publishes the all-in-one Linux
  `bhf-dist-<version>-x86_64-unknown-linux-gnu.tar.gz` with `install.sh`.
  The bundle now always contains `INSTALL.md`, `LICENSE`, `README.md`, and
  `RELEASE_NOTES.md`, enforced by packaging regressions and release-workflow
  archive checks.

## 0.2.18 - 2026-07-21

- **Restored all-in-one Linux installer bundle.** The release now publishes
  `bhf-dist-v0.2.18-x86_64-unknown-linux-gnu.tar.gz` with a bundled
  `install.sh`, CLI, daemon, both Linux preload shims, harness runtimes, signed
  content, and smoke fixture. The release workflow builds this bundle from the
  EL7-baseline artifacts and exercises an extracted install before publication.
  Separate component archives remain available for manual layouts; every one
  now includes `INSTALL.md` with exact checksum, extraction, co-location,
  optional-daemon, and environment-override commands.

- **Exact CLI archive validation.** The Linux and Windows release gates now
  select the exact `bhf` CLI archive instead of allowing the similarly
  named daemon archive to win an order-dependent wildcard match. This release
  completes publication of the self-contained harness-runtime packaging added
  in v0.2.17; the v0.2.17 tag did not publish after its gate correctly rejected
  the mistakenly selected daemon archive.

- **Task-based release asset guide.** The README, install, Windows, offline,
  and release-packaging guides now say exactly when to use the CLI, daemon,
  runtrace shim, compiler-interception shim, source archive, manifests, and
  checksum files. They distinguish installer-based and manual/archive installs,
  explain the effect of omitting optional components, and give an exact offline
  download pattern that cannot accidentally select the similarly named daemon.

- **ThreadSanitizer replay reliability.** Corpus replay now gives explicit TSan
  shadow-memory mapping failures a larger harness-wide bounded retry budget and
  retries transient unsymbolized reports, avoiding missed BHF-556 findings under
  parallel sanitizer load without multiplying the bound across every corpus
  input. The live-runtime E2E also rechecks TSan availability at the point of
  failure instead of treating an ASLR/runtime outage as a bhf defect.

- **Clear RHEL 7 installation prerequisites.** The README now includes a
  copy-paste EL7 quick install. The v0.2.18 Unix CLI installer detects RHEL /
  CentOS 7 and explains that it installs only the CLI, prints the exact RHSCL
  LLVM 7 packages, and links the separate runtrace and compiler-interception
  shim installers instead of leaving a fresh host with an unexplained toolchain
  failure.

- **Current platform matrix.** Release compatibility now extends through RHEL
  10 and Ubuntu 26.04 LTS, while retaining RHEL 7/8/9 and Ubuntu 22.04/24.04.
  Native Windows coverage spans Windows 11 Enterprise 25H2, Windows 11
  Enterprise LTSC 2024 (24H2 codebase), and Windows Server 2019/2022/2025. CI
  exercises release binaries through scan, target discovery, native C harness
  compilation, and fuzzing instead of checking only startup.

- **Working Linux shim installers.** The v0.2.18 runtrace and compiler-
  interception shell installer assets were repaired in place after clean-host
  validation exposed cargo-dist 0.31 applying `chmod` to the final library path
  before moving the library out of its temporary directory. The release
  workflow now patches and gates both generated library installers so the
  failure cannot recur. Every Unix installer now also checks for the `xz`
  helper up front, and the RHEL setup commands install it explicitly; this
  replaces an opaque extraction failure on minimal RHEL images.

- **Platform installer and prerequisite diagnostics.** The v0.2.18 CLI and
  daemon PowerShell installer assets were updated in place so `irm ... | iex`
  also works in a non-interactive Windows Server 2019 OpenSSH session. Missing
  Windows C/C++ tools now recommend LLVM, VS 2022 Build Tools/Windows SDK, and
  GNU make instead of incorrectly printing an Ubuntu `apt-get` command. Linux
  C/C++ diagnostics now distinguish the RHEL 7 LLVM Toolset, RHEL 8+ `dnf`, and
  Ubuntu `apt-get` paths.

## 0.2.17 - 2026-07-21

- **Self-contained release harness runtimes.** Supersedes v0.2.16: the
  published CLI archives now carry all eleven language-runtime trees needed to
  generate and compile C/C++, Ada, Rust, Java, Python, Perl, C#, JavaScript /
  TypeScript, Ruby, Lua, PHP, COBOL, Fortran, and Go harnesses. Installer-only
  deployments securely materialize the same sources from the CLI's embedded
  copy, so a release binary never depends on the GitHub runner checkout path.
  Linux and Windows release jobs now inspect their completed archives and fail
  if any runtime is missing.

## 0.2.16 - 2026-07-21

- **Windows, Ubuntu, and RHEL release artifacts.** Releases now publish the
  `bhf` CLI and daemon for both `x86_64-pc-windows-msvc` and
  `x86_64-unknown-linux-gnu`, with native PowerShell and Unix shell installers.
  Windows Server 2022 CI tests and smokes the Windows executables. The Linux
  artifact is built at the GLIBC 2.17 baseline for Ubuntu and RHEL 7 through 9;
  Linux-only runtime and compiler-interception shims remain separate Linux
  assets.

- **Windows cargo-dist packaging.** The Linux-only runtrace shim now skips its
  GNU C hook compilation and linker version script when cargo-dist assembles a
  Windows release. Windows CI explicitly builds the shim package to keep this
  release-only path covered.

- **Native Windows C harness linking.** Generated harnesses and the external
  driver no longer emit competing COFF weak defaults for the Linux-only
  runtrace input hook. This fixes the `LNK1227` failure that previously stopped
  an otherwise valid MSVC/Clang harness before fuzzing.

- **UTF-8-safe C++ type qualification.** The C++ decoder no longer slices
  through a multibyte character when fuzzed or recovered type text places a
  non-ASCII scalar immediately before an identifier. This fixes the BHF-210
  panic found by the repository's self-fuzzing PR gate.

- **Offline sanitizer replay reliability.** Capsule verification and direct
  sanitizer integration runners no longer inherit a distro-configured remote
  `DEBUGINFOD_URLS`. This prevents `llvm-symbolizer` from hanging indefinitely
  when the network or debuginfod service is unavailable; the ASan pool bridge
  regression also has a hard timeout.

- **RHEL 7 through RHEL 9 support and release compatibility.** GNU/Linux release
  artifacts now build in a pinned manylinux2014 / CentOS 7 userspace and pass an
  automated GLIBC 2.17 ABI plus preload-export gate instead of inheriting the
  newer Ubuntu runner ABI. The binary distribution installer auto-detects
  `dnf`/`yum`, maps selected lanes to RHEL package names, and installs available
  dependencies even when an optional supplemental package is absent. Dedicated
  RHEL-compatible CI and Proxmox validation cover the release build, package
  install, signed content, bundled C smoke target, and a real miniz run.

- **TypeScript fuzzing lane.** `bhf auto --languages typescript` discovers
  exported functions and public class methods in `.ts`/`.tsx` source (the
  name-extracting parser strips type annotations; interfaces, type aliases, and
  `private`/`protected`/`abstract` members are excluded), transpiles the target to
  CommonJS with esbuild, and fuzzes it with the same warm-Node framed driver, V8
  block coverage, dictionary, and command-injection detector as the JavaScript
  lane. Node + esbuild required (`npm i -g esbuild`); absent either, the lane skips
  cleanly. `.d.ts` declaration files are not fuzzed.

- **Self-fuzz dogfood CI.** A nightly `dogfood` workflow runs `bhf auto` on
  bhf's own C runtime decoders (the untrusted-input parsers every harness
  links), uploads SARIF + findings, and fails on a fuzz-confirmed crash — bhf
  fuzzing itself.

- **JS/TS runtime-load check.** A module that passes `node -c` (syntax) but whose
  `require('...')` cannot resolve at runtime — an npm dependency not installed
  (e.g. `qs` → `side-channel`) — previously built a harness that died at startup and
  fuzzed 0 inputs while being reported as "built". It now skips cleanly with an
  actionable reason (`… requires an npm dependency that is not installed; run
  npm install`). Applies to the transpiled TypeScript output too.

- **JavaScript/TypeScript prototype-pollution detector (BHF-509 / CWE-1321).** The
  top JS injection class. The driver snapshots `Object.prototype`/`Array.prototype`
  and, after an input carrying a `__proto__`/`constructor`/`prototype` vector,
  reports a new own-property that appeared on them; complete `{"__proto__":{…}}`
  payloads are seeded into the dictionary so an unsafe `JSON.parse`+merge is
  reachable end-to-end. Verified: a recursive-merge vuln is found (BHF-509) while a
  benign `JSON.parse` (which never pollutes) is not — 0 false positives.

- **JavaScript command-injection detector (BHF-431 / CWE-78).** The JS lane runs
  without the LD_PRELOAD shim (managed runtime), so — like Jazzer.js's bug detectors
  — the driver hooks `child_process.exec`/`execSync` in JS and reports a
  taint-confirmed command injection when a shell-metacharacter-bearing substring of
  the fuzz input reaches the command (the input controls shell *syntax*, not just
  data). The command is never executed (a benign stub is returned). Verified:
  `execSync('convert ' + input)` is caught while a fixed command with metachar-laden
  input is not — 0 false positives.

- **Wider fuzzable surface for the C# and JavaScript lanes.** The C# lane now
  fuzzes methods with a `bool` sibling (driven to `false`) and drives an
  `offset`/`index`/`start` integer to `0` (not the buffer length, which threw), so
  `Parse(string, bool)` and `Read(byte[], int offset, int count)` shapes are covered.
  The JavaScript lane now discovers **static** methods of exported classes
  (`Class.parse`-style, no construction needed) in addition to instance methods.

- **Coverage depth for the C# and JavaScript lanes.** Three improvements from a
  post-merge dogfood sweep: (1) both lanes now **mine a magic-value dictionary**
  from the target's string/integer literals — the managed/interpreted drivers carry
  no CmpLog, so a single multi-byte comparison gate (`if (s == "OPENSESAME")`) was
  previously uncrackable; with the dictionary it is found (the libFuzzer-autodict /
  Jazzer-value-profile lever the other managed lanes already had). (2) The
  **JavaScript lane discovers public methods of exported classes** (`Class#method`),
  not just free functions — the driver `new`s a no-arg-constructible class and calls
  the method, covering class-based libraries. (3) The **JavaScript lane no longer
  runs under the LD_PRELOAD runtrace shim** (like the JVM/.NET lanes): Node's
  `stat()`→`open()` on every `require` is the same TOCTOU pattern that false-positived
  on the .NET host, so it is excluded.

- **JavaScript / Node.js fuzzing lane.** `bhf auto --languages javascript`
  discovers exported functions (CommonJS + ESM) taking a `Buffer`/`string`, and
  fuzzes them coverage-guided on bhf's own fork-server engine driving one warm
  Node process — no Jazzer.js, no jsfuzz, no libFuzzer, no `fuzz(data)` to
  hand-write. Coverage is **real V8 precise block coverage** (the inspector
  Profiler, no Babel/Istanbul source rewrite) folded per input — keyed on `(script,
  block span, taken/not-taken)` — into bhf's cumulative `BHF_COV_SHM` edge
  bitmap, so the engine gets genuine branch feedback. An uncaught exception that is
  not input rejection hard-halts (exit 86) and maps to a BHF rule + CWE (stack
  overflow → BHF-207/CWE-674, resource `RangeError`/OOM → BHF-209, `ReferenceError` /
  assertion / explicit `throw` → BHF-210). `TypeError` (and `SyntaxError`/`URIError`/
  validating `RangeError`) are treated as input rejection — the untyped-lane policy
  the Python lane uses — since bhf synthesizes only the first argument; a
  first-argument name filter also keeps internal array/options helpers out of the
  fuzz set. Validated on a 30-project / 2,018-file campaign (express, lodash, axios,
  moment, validator.js, node-semver, marked, joi, …): 0 panics, 531 fuzzable
  functions discovered, 0 false positives; end-to-end it finds an
  uncontrolled-recursion crash with the V8 stack. The driver uses only Node
  built-ins (`inspector`, `fs`) — nothing linked into bhf. See
  [docs/site/javascript.md](docs/site/javascript.md).

- **C# / .NET fuzzing lane.** `bhf auto --languages csharp` discovers `public`
  methods taking a `byte[]`/`string`/`Stream`, builds the target with `dotnet`
  through a project reference, instruments its IL with
  [SharpFuzz](https://github.com/Metalnem/sharpfuzz) (`sharpfuzz <dll>`), and fuzzes
  it coverage-guided on bhf's own fork-server engine — no AFL, no libFuzzer, no
  `Fuzzer.Run` to hand-write. The driver `mmap`s bhf's `BHF_COV_SHM` edge
  bitmap (64 KB = the AFL map size SharpFuzz targets) into
  `SharpFuzz.Common.Trace.SharedMem`, so the instrumented target writes coverage
  straight into bhf's cumulative map, and speaks the framed fork-server protocol
  to keep **one warm CLR** alive across all inputs. An uncaught exception that is not
  input rejection is a finding (exit 86), mapped to a BHF rule + CWE by type (index
  OOB → BHF-201/CWE-125, null-deref → BHF-206/CWE-476, arithmetic → BHF-205, OOM →
  BHF-209, stack overflow → BHF-207, else BHF-210). Input-rejection exceptions
  (`ArgumentException`, `FormatException`, …) and the target namespace's own
  exceptions are suppressed. Like the JVM lane, it runs without the LD_PRELOAD shim
  (the .NET host's own startup I/O would otherwise trip the TOCTOU/open oracles).
  The target project reference is pinned to the best framework the installed SDK
  supports, so a library that multi-targets a newer preview TFM still builds.
  Validated on a 25-project / 69,608-file campaign (dotnet/runtime, roslyn, EF Core,
  Newtonsoft.Json, MessagePack, YamlDotNet, ImageSharp, …): 0 panics, 3,113 fuzzable
  methods discovered; end-to-end at ~6,900 exec/s on a warm CLR with real edge
  coverage and 0 shim false positives. SharpFuzz/SharpFuzz.Common are Apache-2.0 and
  link into the user harness, never into bhf. See
  [docs/site/csharp.md](docs/site/csharp.md).

- **Fortran fuzzing lane.** `bhf auto --languages fortran` discovers Fortran
  `subroutine`/`function` procedures with a `character` (byte-buffer) argument,
  compiles them with `gfortran -fsanitize=address
  -fsanitize-coverage=trace-pc,trace-cmp`, and fuzzes them coverage-guided on the C
  fork-server engine. AddressSanitizer is the memory oracle — a Fortran array/
  substring out-of-bounds is reported directly as a crash with the exact
  `.f90:line` and CWE (heap → CWE-122/787). The glue calls the routine via the
  gfortran C ABI (args by reference, a hidden length per character argument) with
  the primary buffer heap-allocated to the input size so a real OOB lands in ASan's
  redzone. Validated on a 20-project / 40,367-file campaign: 0 panics, 13,406
  fuzzable procedures discovered, 6,500+ exec/s, 0 false positives. See
  [docs/site/fortran.md](docs/site/fortran.md). libgfortran (LGPLv3 + GCC RLE) links
  into the user harness like the C runtime; gfortran is a subprocess only.

- **COBOL fuzzing lane — the first turnkey COBOL fuzzer.** `bhf auto
  --languages cobol` discovers COBOL programs (`PROGRAM-ID` with a fuzzable
  `LINKAGE` `PIC X` operand), translates them to C with GnuCOBOL (`cobc -C
  -debug -fec=all`; free/fixed format detected, copybook `-I` dirs collected),
  generates a driver that drives the full `USING` operand list (primary buffer +
  length + zeroed rest), and fuzzes on the C fork-server path (edge coverage,
  CmpLog, ASan). Two crash oracles — ASan for raw memory corruption and libcob
  `-fec=all` for COBOL-semantic violations — with each crash attributed to its
  `.cob:line` and CWE (out-of-bounds ref-mod → CWE-125, zero-divide → CWE-369,
  size overflow → CWE-190). The taint-confirmed sink oracles (command/SQL/path
  injection, CWE-78/89/22) apply too. Validated on a 23-project / 2925-file
  campaign: 0 panics, 30/38 build+fuzz, 0 false positives, 2 real
  command-injection findings. cobc is GPLv3 (subprocess-only); libcob is LGPLv3
  and links into the user harness like the GNAT runtime. See
  [docs/site/cobol.md](docs/site/cobol.md).

- **PR-native CI + GitHub Action.** New `bhf ci --changed-since <ref>` mode
  scopes a run to only the files a pull request changes (merge-base aware,
  reusing the discovery cache), with `--sarif` output, a compact `--ci-json`
  result, and a `--pr-gate {confirmed,all,never}` policy that by default fails
  only on a fuzz-confirmed finding. A composite action
  (`.github/actions/bhf-pr`) makes it one `uses:` line: it resolves the PR
  base, installs bhf, runs the scoped fuzz, uploads SARIF for inline
  code-scanning annotations, and posts a sticky PR summary comment. See
  [docs/site/ci.md](docs/site/ci.md). The git-diff helpers are factored into a
  shared module reused by `list-targets --changed-since`; non-scoped `ci`
  behavior is unchanged.
- **Two-compiler differential fuzzing in `auto`.** New `bhf auto
  --differential clang:gcc` rebuilds each C/C++ harness under both compilers via
  a portable `make diff` target and replays the fuzz corpus through both, flagging
  any input on which their exit/crash behavior diverges — a codegen- or
  UB-dependent bug one compiler exposes and the other hides — as a BHF-301 finding
  in the normal report. Comparison is on exit status (bhf harnesses suppress
  target stdout); a failed second-compiler build logs and skips. The standalone
  `bhf differential` subcommand (arbitrary two-harness / metamorphic) is
  unchanged.

## v0.2.15 - 2026-07-10

- **First public release.** Hardened for public distribution: Dependabot version
  updates, GitHub Actions pinned to commit SHAs, least-privilege workflow
  permissions, and a security review that fixed a SQL-shim out-of-bounds read
  (counted `mysql_real_query`/`sqlite3_prepare*` buffers), an Ada-stub path
  traversal from untrusted compiler diagnostics, signal-unsafe shim locking, and
  two resource-exhaustion caps (IDL parser recursion, event-log allocation).
- **Cross-language static coverage sweep** closing per-language gaps found vs
  semgrep/gosec/spotbugs/cppcheck: `BHF-551` Java JNDI injection (Log4Shell class,
  CWE-917; non-literal `Context.lookup`), `BHF-552` Rust unsafe `transmute`
  (CWE-843), `BHF-553` Rust `unwrap()`/`expect()` panic in library code (CWE-248,
  scoped to fallible boundaries to stay precise), `BHF-554` C/C++ printf
  argument-type mismatch (CWE-686, high-confidence literal cases only). Broadened
  `BHF-429` hardcoded-secret detection with a generic `NAME = "secret"` assignment
  pattern (language-agnostic, placeholder-guarded) and `BHF-422` weak-crypto to
  cover DES/3DES/RC4/ECB/Blowfish/MD4 across C/Go/Rust/Python/Java (new Rust
  detector). All cross-checked against the competitor and verified 0 false
  positives on the 14-repo comparison corpus.
- **Static C/C++ matched the measured defect-class set.** Added the two bug classes cppcheck
  caught and bhf missed, as precise per-function intraprocedural scanners:
  `BHF-549` dangling-lifetime return (returning the address/reference of a local;
  CWE-562) and `BHF-550` resource leak (an allocation/handle never freed, closed,
  returned, or escaped; CWE-401/772). Cross-checked against cppcheck's
  `returnDanglingLifetime`/`memleak` — bhf fires on the same real defects with
  0 false positives on the corpus.

- **Measured tool comparison + static/SBOM/SLOC improvements** (see
  `docs/site/comparison-2026-07.md`). New static rules: `BHF-546` Python
  `try/except/pass` swallowed exception (CWE-703), `BHF-547` unbounded
  `scanf`/`getwd` reads (CWE-120/676), `BHF-548` cleartext `ws://` transport
  (CWE-319). Every static finding now carries its CWE and a `remediation` line in
  the JSON, Markdown, and SARIF (`help`/`helpUri`) outputs.
- **SBOM: lockfile ingestion + SPDX.** Reads `uv.lock` (and the existing
  lockfiles) for pinned/transitive components so CVE matching works; adds an
  SPDX-2.3 JSON emitter (`--format spdx-json`) alongside CycloneDX/VEX.
- **`bhf sloc <PATH>...`** — a standalone, rayon-parallel SLOC counter (no SAST
  scan) that counts one or more roots in a single invocation; fastest and closest
  to cloc on the pinned comparison repositories.
- **`auto --force` (alias `--force-fuzz`)** — force-fuzz mode: attempt every
  discovered C/C++/Ada function even when a parameter can't be driven or a
  type/symbol is undefined. Bypasses the pre-build skip gates, synthesizes
  best-effort drivers for opaque/function-pointer/unknown params, applies
  universal compiler-diagnostic-driven stubbing until the harness builds, and
  never hard-fails (a still-unbuildable target degrades to a report-only static
  scan). Findings from a forced/stub-heavy build are floored to Low confidence
  with a `forced` note and counted separately, since a forced crash may be a stub
  artifact rather than a real defect.
- **Win32/MFC + qualified-call recovery (no flag)** — the repair loop injects the
  synthesized `windows.h` typedefs (`BOOL`/`DWORD`/`PUCHAR`/…) for stray Win32
  names so such targets build+fuzz with real semantics; the C/C++ decoder drives
  Win32 pointer typedefs; and a namespaced free function gets a forward
  declaration even when an unrelated header (e.g. `StdAfx.h`) is auto-included,
  fixing `use of undeclared identifier`.
- **`findings.csv` overhaul** — weakness-describing messages, bare CWE numbers, a
  `remediation` column (replacing the meaningless `fix_location`), `source` +
  `data_flow` (source→sink from taint traces), an `entity` column (tainted
  variable/sink), blank `member_finding_ids` for singleton issues, and relative
  report-only (`F-RO-*`) paths.
- **`--static-dynamic`** adds a `scan_type` column to `findings.csv`
  (`static-dynamic` for a static-scan result, `dynamic` for a fuzzed result).
- Renamed the user-facing `report-only` outcome to `static-only`.

## v0.2.14 - 2026-07-08

- Added a `--sloc <FILE>` flag to `bhf static-scan` and `bhf auto` that
  writes an accurate per-language SLOC breakdown (LANGUAGE, FILES, TOTAL,
  COMMENTS, BLANKS, SLOC). Comment counting is language-aware (Ada `--`, C-family
  `//`/`/* */`, hash comments, Perl POD, Python docstrings) via the same stripper
  the rule engine uses, and the same dependency/build-tree pruning as the scan
  applies, so vendored/`node_modules`/`.venv` code is excluded. A `.json`
  extension emits JSON; anything else emits an aligned text table.

## v0.2.13 - 2026-07-08

- Added a Python static rule (`BHF-545`, CWE-943) that flags a GraphQL operation
  document parsed via `gql()` from a dynamically-built string carrying GraphQL
  operation syntax. A literal document with request data bound through
  `variable_values` is the safe form and does not fire, mirroring the SQL rule.
- Fixed `bhf auto --external-tools` so the flag activates the external
  analyzers on its own: it now defaults to the `external-tools` license profile
  instead of the no-op `strict-permissive`, matching `static-scan --external-tools`
  (an explicit `BHF_PROFILE` still wins). Previously the flag silently ran no
  analyzers unless `BHF_PROFILE=external-tools` was also set.
- Expanded framework raw-HTML XSS coverage (`BHF-512`) across Vue, Svelte, and
  Angular sinks, and stopped the static scanner from analyzing generated
  `compiled/` bundles (e.g. Next.js build output).
- Reworked the README for an outward-facing audience: dropped the internal Status
  section, added a concise "What it does" overview, and documented `auto --static`
  and `--external-tools` usage.

## v0.2.12 - 2026-07-07

- Added Python static rules for unsafe `tarfile` extraction without a safe filter
  (`BHF-542`, CWE-22), Flask/Jinja request-data-as-template-source injection
  (`BHF-543`, CWE-1336), and tainted values reaching a logging sink without CR/LF
  neutralization (`BHF-544`, CWE-117).

## v0.2.11 - 2026-07-07

- Degrade C/C++ targets that reference an unsuppliable external class to a
  report-only static scan instead of a bare failed build: a placeholdered
  external class (e.g. MFC `CString`) whose rebuild fails with scalar-used-as-
  class errors, and a forward-declared type whose definition is not visible to
  the generated harness translation unit, now both fall back to "fuzz the
  source" with CWE-tagged findings.
- Overhauled `findings.csv` for static findings: added `rule_id` and a
  human-readable `message` column so a row says what the issue is, not just a
  CWE; blanked the redundant `harness_id` for static rows; surfaced the
  emit-time confidence instead of a flattened report-time value; and populated
  `sink_function` with the enclosing function name rather than the file name.
- Extended SBOM cataloging to list external COTS/OSS/GOTS software traced from
  C/C++ `#include` directives and Ada `with` clauses even without a dependency
  manifest, while excluding the project's own headers/packages and system or
  toolchain headers. `--sbom` now explains an empty result.
- Annotated the `auto` bug report so known, working-as-intended limitations
  (opaque-handle lifecycle skips, classes with no public constructor/factory)
  are tagged and not mistaken for reportable bugs.
- Made the SBOM golden test version-agnostic so it no longer breaks on each
  release version bump.

## v0.2.10 - 2026-07-07

- Re-cut the v0.2.9 release after GitHub rejected Artifact Attestations for the
  private Tarmo-Technologies organization/repository plan.
- Disabled GitHub Artifact Attestations in the generated release workflow and
  updated release documentation to describe checksum verification plus signed
  content-pack verification as the supported release integrity path.

## v0.2.9 - 2026-07-07

- Re-cut the v0.2.8 static-analysis release payload with the generated release
  matrix limited to the smoke-tested `x86_64-unknown-linux-gnu` target.
- Documented the supported binary release target and the Linux-only runtime
  preload package constraint.
- Guarded a Linux-only fuzz-runner `prctl` call so non-Linux source builds do
  not fail on that symbol.

## v0.2.8 - 2026-07-07

- Expanded `bhf static-scan` with broad framework, JavaScript, container,
  GitHub Actions, Django, Electron, and Qt WebEngine rule coverage.
- Added Qt WebEngine hardening detections for sandboxing, mixed content, local
  file/remote URL access, plugins, clipboard access, geolocation, unknown URL
  schemes, DNS prefetch, WebRTC local IP exposure, screen capture, canvas
  readback, and hyperlink auditing.
- Added Django deployment hardening detections for HTTPS redirect defaults,
  HSTS, proxy HTTPS state, referrer policy, nosniff, host allowlists,
  CSRF/session cookies, frame options, request-size limits, debug mode, and
  weak password hashers.
- Improved static-analysis release documentation, benchmark coverage for the
  Django HTTPS redirect rule, and release-flow guidance for `dist` tag planning.

## v0.2.7 - 2026-07-02

- Added `auto --static` whole-tree static scanning alongside fuzzing.
- Mapped static findings into sink/fix location reporting.
