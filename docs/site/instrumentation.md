<!-- SPDX-License-Identifier: Apache-2.0 -->

# Instrumentation

Each of bhf's sixteen fuzzing lanes gets coverage feedback from a mechanism
suited to its language:

| Lanes | Coverage mechanism |
|---|---|
| Ada | source probe events plus compiler `trace-pc` edge coverage |
| C, C++, Rust | compiler SanitizerCoverage edge and compare feedback |
| Java | bhf's ASM bytecode agent |
| Python, Perl, Ruby, Lua | interpreter tracing into the shared edge map |
| Go | `go build -cover -covermode=atomic` block sets, with a black-box fallback |
| COBOL, Fortran | the C fork-server path with compiler edge and compare coverage |
| C# | SharpFuzz IL instrumentation bridged into bhf's map |
| JavaScript, TypeScript | V8 precise block coverage from a warm Node process |
| PHP | `pcov` line coverage when available, with a black-box fallback |

Only the Ada lane rewrites the target source for bhf probe events. Every
available coverage channel feeds the built-in engine's corpus decisions. A
lane whose instrumenter is unavailable uses the fallback described in its
section below, and reports no coverage it did not measure.

## Ada source instrumentation

bhf rewrites Ada source so the fuzz harness can report testcase boundaries,
breadcrumbs, exception-handler transitions and result classes.

### Event model

The generated harness starts each testcase, feeds the decoded inputs to the
target subprogram, and records the path through selected source spans. A
top-level catch in the harness records unhandled exceptions. Explicit
swallowed-exception signals are kept as findings when the target handles an
error without reporting it to the runner.

### Ada probe backends

The instrumented API is the same for every probe backend:

- `host_file` writes events to a host-visible event stream.
- `memory_buffer` stores events in an exported ring buffer.
- `semihosting` calls a target-provided write hook.
- `stub` keeps the result status without trace output.

The generated instrumentation therefore does not depend on the runner chosen
for a target.

### Edge coverage

An Ada harness is also compiled with `-fsanitize-coverage=trace-pc` against
the AdaFuzz `__sanitizer_cov_trace_pc` runtime (`ada_runtime/adafuzz_cov.c`).
GNAT/GCC rejects the C/C++ lane's `trace-pc-guard`, so the Ada lane uses the
parameterless `trace-pc` variant. It feeds the same edge bitmap the engine
uses for corpus guidance, and a bounded persisted corpus. Ada coverage is
edge presence only; the hit-count-bucket and comparison-progress channels
below belong to the C, C++ and Rust lanes. A target whose toolchain rejects
`trace-pc`, or that is built uninstrumented, falls back to event-log and
signature feedback.

## C/C++ coverage instrumentation

C/C++ harnesses are instrumented at compile time, not by source rewriting.
The generated Makefile compiles each driver with
`-fsanitize-coverage=trace-pc-guard,trace-cmp`, and the harness carries bhf's
own SanitizerCoverage runtime; no LLVM, libFuzzer or sanitizer-fuzzer runtime
is linked. The runtime exposes four coverage-feedback channels, each a
separate `MAP_SHARED` region the engine reads once per execution:

- **Edge presence**: `trace-pc-guard` sets one bit per instrumented edge in a
  cumulative bitmap (`BHF_COV_SHM`); the engine reads the popcount to detect
  new edges.
- **Hit-count buckets**: a parallel byte map (`BHF_COV_CNT_SHM`)
  saturating-increments each edge's per-execution hit count, bucketed
  AFL-style (`1, 2, 3, 4-7, 8-15, …`), so a deeper loop or recursion counts
  as new coverage even on known edges.
- **Comparison progress** (opt-in): a per-site byte map
  (`BHF_CMP_PROGRESS_SHM`) records the longest leading-byte prefix an input
  matched at each compare site. This laf-intel-style gradient rewards getting
  one more byte of a multi-byte gate right. Enable it with
  `bhf auto --comparison-progress`; it is inert when the variable is unset.
- **Stack depth**: an 8-byte word (`BHF_STACK_DEPTH_SHM`) holds the deepest
  stack the execution reached, measured from the frame of the call into the
  target. An input that recursed a quarter deeper than every input before it
  is kept even when it ran no new edge, and the repeat-token mutator doubles
  the longest run of a nesting opener (`[`, `{`, `(`, `<`) in it. Hit-count
  buckets stop growing at 128 hits; this channel does not, so an unbounded
  recursion reaches the end of the stack and is reported as a BHF-207 stack
  overflow. `BHF_DISABLE_STACK_DEPTH=1` turns it off.

The same `trace-cmp` callbacks also feed RedQueen/cmplog input-to-state
operand capture and value-profile dictionary mining. See
[libFuzzer feature parity](libfuzzer-parity.md) for how these map to
libFuzzer options.

### Comparison evidence

The callbacks and the sanitizer's `__sanitizer_weak_hook_{memcmp,strcmp,...}`
hooks also record comparison evidence for one finding. When
`BHF_CMP_EVIDENCE` names a file, the driver writes every comparison of the
run to it: integer compares and switch cases, `memcmp`/`bcmp` and the
`str*cmp` family, with both operands, whether they were equal, and the call
site. Unlike the cmplog ring, it keeps satisfied comparisons and zero
operands. Comparisons the harness makes before it enters the target (its own
decoding of the input) are discarded when it calls `bhf_target_enter`, so
they cannot use up the 8192 records a run keeps. Calls from outside the
executable are left out.

Under AddressSanitizer the `memcmp`/`bcmp` interceptor reports a position
inside itself as the call site. For buffer and string comparisons the driver
therefore also records the return addresses of the four frames above that
position (glibc's `backtrace()`; record format version 2). When the evidence
is read, the first of those frames that is not in the sanitizer runtime is
the comparison's site. The gate then names the target's call line, a
`memcmp` in harness code is left out like any harness comparison, and a call
whose caller is in a shared library is dropped. When no frame resolves, the
gate says its site is not attributable (sanitizer interceptor) instead of
naming the interceptor's address. bhf sets the variable only for the replays
that record a finding's evidence; a fuzz campaign never sets it, so each
callback costs one pointer test.

## Rust coverage instrumentation

Rust harnesses are instrumented by the compiler, not by source rewriting. The
target crate and harness are built as a `staticlib` with `cargo +nightly`,
under `RUSTFLAGS` that arm SanitizerCoverage (`-Cpasses=sancov-module`,
`-Cllvm-args=-sanitizer-coverage-trace-pc-guard`,
`-Cllvm-args=-sanitizer-coverage-trace-compares`) and ASan
(`-Zsanitizer=address`). The resulting `.a` is linked with `clang` against
the shared C fork-server driver, which is compiled with the matching
`-fsanitize=address -fsanitize-coverage=trace-pc-guard,trace-cmp` and carries
the same SanitizerCoverage runtime as the C/C++ lane. A Rust harness
therefore has the same coverage-feedback channels as a C/C++ one, and feeds
the same RedQueen/cmplog operand capture and value-profile mining.

## Java instrumentation (ASM bytecode agent)

Java harnesses are instrumented by bhf's own JVM bytecode coverage agent,
which does for the JVM what SanitizerCoverage does for native code. The
harness runs under `java -javaagent:bhf-jvm-agent.jar ...`, and the agent
instruments the target's classes at load time. It inserts a stack-neutral
probe (`LDC <blockId>; INVOKESTATIC Coverage.recordEdge(I)V`) at method entry
and at the start of each basic block. The probe records AFL-style edges
(block transitions, `idx = prev ^ block`) into the file-backed `BHF_COV_SHM`
map, with a per-edge byte counter that saturates at 255. The built-in engine
reads that map as it reads a C or Rust SanitizerCoverage binary's, so Java
targets get the same coverage-guided passes. The Java lane uses this single
edge map.

## Python instrumentation (interpreter tracer)

The Python lane instruments the CPython interpreter at run time, not the
source or a compiler. The generated driver runs under a persistent CPython
held open by the framed fork-server protocol. Coverage is collected by
`sys.monitoring` (Python 3.12 and later) or a `sys.settrace` fallback, whose
edge counters are written into the same file-backed `BHF_COV_SHM` map the
engine reads for every other lane. The LD_PRELOAD runtrace shim is loaded
into the interpreter and records from target entry on, so the lane reports
the shim's sink findings (an input-controlled path reaching `open`, a command
reaching a shell) beside exceptions. Python uses this single edge map.

## Perl instrumentation (interpreter tracer)

Perl harnesses are also instrumented at the interpreter level. The harness
runs under `perl -d:BhfCov`, whose `DB::DB` hook records per-statement edge
coverage into the shared `BHF_COV_SHM` map. The `perl -d` debugger path makes
this the slowest of the tracer lanes. As with Python, the runtrace shim is
loaded into `perl` from target entry on, so the lane has the shim's sink
oracles. Perl uses this single edge map.

## Go instrumentation

Go harnesses are compiled. The generated `main` imports the target package
through a module `replace`, decodes the input by Go type, and is built with
`go build` into a native framed fork-server binary that turns panics into
findings. The runtrace shim runs natively for this lane. Go coverage is
normally collected with `go build -cover -covermode=atomic`. Before each
input the driver clears the counters; afterwards it reads the executed-block
set with `runtime/coverage.WriteCounters` and folds stable block ids into
`BHF_COV_SHM`. Counter values are ignored, so one execution maps to one edge
set. If the coverage build fails or the counter encoding is not recognized,
bhf retries the target in black-box mode rather than dropping it or reading
invalid data as coverage.

## COBOL, Fortran, C#, JavaScript, Ruby, Lua and PHP

COBOL is translated by GnuCOBOL to C on the C driver path and gets edge
coverage, CmpLog/RedQueen, and sanitizer and libcob runtime checks. Fortran
compiles with gfortran ASan plus `trace-pc`/`trace-cmp` into the C
fork-server path. See the [COBOL](cobol.md) and [Fortran](fortran.md) lane
guides.

C# uses SharpFuzz to rewrite the target's IL, then bridges its 64 KiB edge
bitmap into `BHF_COV_SHM` while one warm CLR serves framed inputs.
JavaScript and TypeScript use the Node inspector's V8 precise block coverage
in one warm Node process. See the [C#](csharp.md) and
[JavaScript/TypeScript](javascript.md) guides.

Ruby uses `TracePoint`, Lua uses `debug.sethook`, and PHP uses `pcov` when
the extension is available; each feeds per-line or edge ids into the shared
map from a persistent interpreter. PHP falls back to black-box execution when
`pcov` is not available. These interpreter lanes do not use compiler
SanitizerCoverage. As with Python and Perl, the runtrace shim is loaded into
the interpreter from target entry on, so they have the shim's sink oracles.
