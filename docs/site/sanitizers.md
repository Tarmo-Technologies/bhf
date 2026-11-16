<!-- SPDX-License-Identifier: Apache-2.0 -->

# Sanitizers

`bhf auto` and `bhf fuzz` arm the C/C++ sanitizer matrix via
`--sanitizers`. By default a native C/C++ harness builds with `-fsanitize=address,undefined`
(ASan + UBSan) plus the engine's coverage instrumentation. This page covers the
controls that make sanitizers usable on shared-memory / custom-allocator / RTOS
code, where stock ASan tends to drown a run in false positives.

`--sanitizers` governs the C/C++ matrix only. Ada uses source instrumentation
rather than LLVM sanitizers; Rust always builds with ASan + sancov via hardcoded
flags (not tunable through `--sanitizers`); Java runs in the JVM under bhf's
own bytecode coverage agent, where LLVM sanitizers do not apply; Python, Perl,
Ruby, Lua, and PHP use interpreter coverage plus exception/error oracles; C#
uses SharpFuzz IL coverage; JavaScript/TypeScript use V8 block coverage; and Go
uses atomic compiler coverage with a safe black-box fallback. COBOL and Fortran
have lane-owned ASan/coverage builds. None of those settings are selected by
the C/C++ `--sanitizers` matrix.

## `--sanitizers <set | none>`

- `--sanitizers asan,ubsan,lsan` — arm exactly this set. `asan,ubsan,lsan` are
  mutually compatible; `msan` and `tsan` are exclusive with those and each other
  (run them as separate campaigns).
- `--sanitizers none` — build each native C/C++ harness with the engine's
  coverage instrumentation but **no `-fsanitize=`** at all. You get
  coverage-guided, **crash-only** fuzzing (SIGSEGV / SIGABRT still caught) with
  **zero ASan/UBSan false positives**. This is the escape hatch for code that
  FP-storms under ASan — shared memory, custom allocators, partially instrumented
  RTOS builds — without paying the qemu-user cross-compile tax. `none` is
  standalone; combining it with a real sanitizer is rejected.

With an operator's compiler (`CC`/`CXX`, `--cc`/`--cxx`, `[toolchain]`),
`--sanitizers` first links a trivial program with the requested sanitizers and
runs it: with `CC` for every harness, and with `CXX` (as C++) for a C++
harness. A compiler that cannot link it (gcc has no MemorySanitizer), or whose
runtime links but aborts before `main` on this host (GCC's ThreadSanitizer
under a kernel with high-entropy ASLR prints `FATAL: ThreadSanitizer:
unexpected memory mapping`), is not kept, and bhf says so, naming the variable,
the compiler and the runtime's message. A failing `CC` sends the C and C++
harnesses to clang/clang++; a failing `CXX` sends the C++ harnesses to clang++
and leaves `CC` building their C units. A C-only sweep never runs `CXX`. The
environment's `CFLAGS` (for `CC`) and `CXXFLAGS` (for `CXX`) are written for
the compiler bhf left, so they stay out of the clang builds, and the note says
so when they are set.

A SIGABRT accompanied by a recognizable assertion or panic diagnostic remains an
input rejection. A silent SIGABRT is saved as a crash because there is no evidence
that the target intentionally rejected the input. A run whose sanitizer runtime
could not start (that `FATAL` line, an AddressSanitizer shadow-mapping failure,
a runtime that is not first in the library list) is never a finding. The first
fuzz pass that sees it ends the target with an error naming the line and the
compiler the harness was built with, and no further pass runs. The target's
outcome is `sanitizer_runtime_unavailable` (`summary.sanitizer_runtime_unavailable`
in `run.json`, "not fuzzed (sanitizer runtime cannot start on this host)" in the
summary): an environment problem, which is not filed in the bug report and is
tried again by `--resume`. Build with a compiler whose runtime starts on the
host (clang), or pick the sanitizers with `--sanitizers`, which runs the check
above first.

`--sanitizers` is inert on every lane except native C/C++. Ada uses source
instrumentation; Rust always applies ASan + sancov through lane-owned
`RUSTFLAGS`; Java and the managed/interpreted lanes use their coverage and
exception mechanisms; Go recovers panics and uses atomic compiler coverage;
COBOL and Fortran own their native build flags. Cross/emulated builds drop host
sanitizers because ASan's shadow memory does not survive qemu-user/wine. See
[Instrumentation](./instrumentation.md) for the complete sixteen-lane feedback
matrix and fallback behavior.

## Tuning, not disabling: `<SAN>_OPTIONS` passthrough

To tame the false-positive storm without giving up detection entirely, set the
sanitizer's own runtime options in the environment. bhf **merges** your
inherited `<SAN>_OPTIONS` with the keys it requires (`abort_on_error`,
`halt_on_error`, `detect_leaks`) — your keys are kept, bhf's go last so they
win (you cannot accidentally disable `abort_on_error`, which is what turns a
sanitizer report into a saved finding; a child run under qemu-user gets
`abort_on_error=0` instead, see below). `UBSAN_OPTIONS` also always gets
`print_stacktrace=1` and `report_error_type=1`, during fuzzing, minimization,
`bhf replay` and in the generated `replay.py`. Minimization, `bhf replay`,
`bhf report --backfill` and the `replay.py` reproducer run C/C++ harnesses
with the same `ASAN_OPTIONS` and `UBSAN_OPTIONS` keys as a fuzz child
(`abort_on_error=1:halt_on_error=1:symbolize=1`, so an inherited value cannot
turn a report into a clean exit; a leak finding also gets `detect_leaks=1`,
and leak detection is never turned off: nothing sets `detect_leaks=0`).
`symbolize=1` goes after an inherited value, so an inherited `symbolize=0`
cannot erase the frames a replay compares. The inherited value itself is
passed through as it is, a quoted value or a drive path with a `:` in it
included, and bhf's keys follow it. `replay.py` exits with the harness's
status, 128 plus the signal for a harness killed by one.
UBSan then prints the stack of
each report and names the failed check (`missing-return`,
`invalid-shift-exponent`, ...) on its `SUMMARY:` line. Each sanitizer is merged independently, so
per-sanitizer suppressions land in the right variable:

```sh
ASAN_OPTIONS=verify_asan_link_order=0:detect_container_overflow=0:detect_odr_violation=0:allocator_may_return_null=1:suppressions=$PWD/asan.supp \
LSAN_OPTIONS=suppressions=$PWD/lsan.supp \
bhf auto path/to/src --sanitizers asan,ubsan,lsan
```

Common RTOS / partial-build false-positive killers:

- `verify_asan_link_order=0` — vendor libs not built with ASan.
- `detect_container_overflow=0` — partial instrumentation across the
  instrumented/uninstrumented boundary.
- `detect_odr_violation=0` — duplicate symbols in large firmware builds.
- `detect_stack_use_after_return=0` — RTOS cooperative context switches confuse
  ASan's fake stack.
- `suppressions=<file>` — silence a specific known-benign report.

Under qemu-user, a guest abort makes the emulator dump its own address space,
which takes minutes. A child that runs under an emulator (`--qemu-user`, or
the emulator recorded beside a cross-built harness in `bhf_runner.json`)
therefore does not abort on a report and runs with core dumps off: the
sanitizer still exits non-zero after its report, and that exit is classified
as the crash. A minimization, replay or comparison-capture child gets
`abort_on_error=0` in place of `abort_on_error=1`, so each of bhf's keys
appears once in its options and in the direct harness command `bhf explain`
prints. A fuzz child under an emulator gets `abort_on_error=0` appended after
the options it runs with (which can also come from `--sanitizers` and
`--env`); the last value wins.
The generated `replay.py` does the same whenever it runs the harness under a
runner (its embedded `RUNNER`, the `bhf_runner.json` beside the harness, or a
non-empty `BHF_REPLAY_RUNNER`); a native run keeps `abort_on_error=1`.

## How a sanitizer report is classified

Each UBSan check kind has its own rule, CWE, explanation and fix hint; only
signed and unsigned integer overflow share one rule, BHF-205. The
kind comes from UBSan's check name on its `SUMMARY:` line when it printed one,
else from the report text after `runtime error:`. Classification reads these
structured fields and the text after the source location only, so a path such
as `src/zoom/` or `src/timeout/` never changes it.

| UBSan check | Kind | Rule | CWE |
|---|---|---|---|
| `signed-integer-overflow`, `unsigned-integer-overflow` | `signed-integer-overflow`, `unsigned-integer-overflow` | BHF-205 | CWE-190 |
| `null-pointer-use`, `invalid-null-argument`, `invalid-null-return`, `nullptr-with-offset` | `null-pointer-dereference` | BHF-206 | CWE-476 |
| `out-of-bounds-index` | `out-of-bounds-access` | BHF-220 | CWE-129 (+ CWE-125, CWE-787) |
| `non-positive-vla-index` | `invalid-vla-bound` | BHF-224 | CWE-129 |
| `integer-divide-by-zero`, `float-divide-by-zero` | `division-by-zero` | BHF-222 | CWE-369 |
| `invalid-shift-exponent`, `invalid-shift-base` | `invalid-shift` | BHF-215 | CWE-1335 |
| `missing-return` | `missing-return` | BHF-214 | CWE-758 |
| `unreachable-call` | `unreachable` | BHF-216 | CWE-758 |
| `invalid-bool-load`, `invalid-enum-load` | `invalid-value-load` | BHF-217 | CWE-758 |
| `float-cast-overflow` | `float-cast-overflow` | BHF-218 | CWE-681 |
| `implicit-*-truncation`, `implicit-integer-sign-change` | `implicit-conversion` | BHF-225 | CWE-681 (+ CWE-197) |
| `pointer-overflow`, `nullptr-after-nonzero-offset` | `pointer-overflow` | BHF-219 | CWE-823 (+ CWE-119) |
| `function-type-mismatch`, `dynamic-type-mismatch`, `cfi-bad-type` | `type-mismatch` | BHF-221 | CWE-843 |
| `insufficient-object-size` | `insufficient-object-size` | BHF-227 | CWE-125 / CWE-787 / CWE-119 |
| `misaligned-pointer-use`, `alignment-assumption` | `misaligned-access` | BHF-226 | CWE-758 |
| `invalid-builtin-use` | `invalid-builtin-use` | BHF-228 | CWE-758 |
| any other | `undefined-behavior` | BHF-213 | CWE-758 |

In a gcc build with both ASan and UBSan, gcc's `object-size` check (BHF-227)
guards the same access as ASan's own check and fires first, so a heap or stack
overflow first comes out as BHF-227. clang's check does the same for a member
access through a heap block smaller than its struct. bhf then re-runs that
input with the check suppressed: when ASan reports the same access, the
finding is ASan's (BHF-201, BHF-203), as with clang. When ASan stays silent the
BHF-227 finding stands: the check also sees memory ASan does not track, such
as a chunk of a pool allocator declared `alloc_size`, so the gcc lanes keep it
on. A replay of either kind on the gcc binary, which reports BHF-227, is the
same crash.

This second opinion applies to the builtin engine's crashes and to those an
AFL++ pass finds. It runs once per root cause: the first hit of a BHF-227
report is re-run, within the per-input timeout and what is left of the pass's
time, and later hits of it, in this pass or a later one over the same work
dir, count against the finding without another re-run. The finding's
`finding.json` says which report it carries and why:

```json
"sanitizer_second_opinion": {
  "check": "object-size",
  "used": "asan",
  "reason": "UBSan's object-size check reported this access before ASan; with the check suppressed, AddressSanitizer reported heap-buffer-overflow at the same sink",
  "replaced_cluster_key": "..."
}
```

`used` is `ubsan` when the BHF-227 report stands, and `reason` then says why:
the re-run reported no error, reported something else, reached its time limit,
or was skipped because the pass's time had run out. `results/findings.json`
carries `{check, used, reason}` as `fuzz.sanitizer_second_opinion`.

Each AddressSanitizer report kind has its own rule too. The kind is read
from the report's `ERROR:` line; a class ASan names with a phrase there
(`out of memory`, `calloc parameters overflow`) takes the name its
`SUMMARY:` line gives it (`out-of-memory`, `calloc-overflow`).

| ASan report kind | Rule | CWE |
|---|---|---|
| `heap-buffer-overflow`, `global-buffer-overflow`, `container-overflow`, `intra-object-overflow`, `use-after-poison`, `negative-size-param` | BHF-201 | CWE-122 / CWE-125 / CWE-787 |
| `heap-use-after-free` | BHF-202 | CWE-416 |
| `stack-buffer-overflow`, `stack-buffer-underflow`, `dynamic-stack-buffer-overflow` | BHF-203 | CWE-121 |
| `double-free`, `attempting free on address which was not malloc()-ed`, `alloc-dealloc-mismatch`, `new-delete-type-mismatch` | BHF-204 | CWE-415 |
| `SEGV` (Windows: `access-violation`, `in-page-error`) | BHF-206 / BHF-223 (below) | CWE-476 / CWE-125 / CWE-787 / CWE-119 |
| `stack-overflow` (unbounded recursion) | BHF-207 | CWE-674 |
| `out-of-memory`, `allocation-size-too-big`, `calloc-overflow`, `reallocarray-overflow`, `pvalloc-overflow`, `rss-limit-exceeded` | BHF-209 | CWE-789 |
| `stack-use-after-return`, `stack-use-after-scope` | BHF-211 | CWE-562 / CWE-825 |
| `FPE` (Windows: `int-divide-by-zero`, `flt-divide-by-zero`) | BHF-222 | CWE-369 |
| `memcpy-param-overlap`, `strcpy-param-overlap` and the other `*-param-overlap` copies | BHF-229 | CWE-475 |
| `BUS`, `ILL`, `ABRT`, `TRAP` (Windows: `illegal-instruction`, `breakpoint`, ...) and any other kind | BHF-210 | CWE-119 |

A kind bhf has no rule for, including one a newer compiler-rt adds, is a
reachable crash (BHF-210), never a heap overflow.

An ASan SEGV in the first memory page (ASan's "zero page" hint, or an address
below `0x1000`) is a NULL dereference, BHF-206 / CWE-476. Any other SEGV is a
wild or corrupted pointer, BHF-223: CWE-125 for a READ, CWE-787 for a WRITE,
and CWE-119 when ASan reports no direction or the address is a non-canonical
"high value address", for which ASan prints READ whatever the access was. The
direction is ASan's `READ`/`WRITE` token, recorded as
`exception.access.direction`. On Windows, ASan names the fault by its
exception instead (`access-violation on unknown address`, or `in-page-error`
for a mapped page that could not be read in); bhf treats both as a SEGV, with
the same rules and CWEs.

The SARIF result's `properties.cwe` is the finding's CWE (the first of
`properties.cwes`); the rule entry keeps its catalog CWE. `bhf replay` still
matches findings recorded under the rules earlier releases used for these
reports. Those releases classified a UBSan report by its text alone: integer
overflow, division by zero and any "cannot be represented in type" report
(a left shift included) were BHF-205, the load, store, member-access,
reference-binding and NULL-argument or NULL-return reports BHF-206, an array
index BHF-201, and every other check (a member call on NULL included)
BHF-210. Every ASan SEGV was BHF-206, and every other ASan kind without
its own rule above (a Windows access violation or in-page error, a stack
overflow, an arithmetic exception or other deadly signal, an overlapping
copy, a refused allocation, `unknown-crash`, ...) BHF-201. They also took
the kind from the first word of the `ERROR:` line (`out` for `out of
memory`, `memcpy-param-overlap:` with its colon), which replay accepts too.
In `results/`, SARIF, the report JSON and `bhf explain`, such a finding is
grouped by the key this release gives its stored report, so it shares a
root-cause group with the same crash found now; `finding.json` is not
rewritten.

## How a sanitizer finding is identified

Each sanitizer crash becomes one finding per root cause per harness, not one
per crashing input.

- **Signature and finding ID.** The signature hashes the rule, the crash kind,
  UBSan's check name, the crash-stack function names and, for a UBSan report
  or any report printed without a stack, the reported site
  (`<dir>/<file>:<line>:<col>`, the last two components of the reported path,
  so `src/a/util.c` and `src/b/util.c` are different sites wherever the tree
  is checked out; a bare file name takes its directory from the top crash
  frame naming the same file). A fatal signal with no sanitizer report has no
  stack; its site is the faulting instruction's offset in the executable,
  when bhf's driver printed one (see below). The `F-NNNN-<sig8>` suffix is
  its first 8 hex digits. The allocation and free stacks are not hashed.
- **Root-cause key** (`cluster_key_full`, the `group` in `results/`). The
  rule, kind and check name plus the first three project frames. libc,
  sanitizer-runtime and interceptor frames (`__memcmp_avx2_movbe`,
  `MemcmpInterceptorCommon`, `bcmp`, glibc component sources such as
  `sysdeps/`, `csu/`, `assert/` and `signal/`) are skipped, so the key starts
  at the project code that made the call. So are C++ standard-library frames
  (`std::` and `__gnu_cxx::` functions, and any frame in a standard-library
  header under `include/c++/` or MSVC's `VC/Tools/MSVC/.../include/`; a
  Rust `std::` frame is dropped by the same rule): two
  out-of-bounds reads through `std::unique_ptr::get` in two project functions
  are two groups. A crash with no other frame keeps its standard-library
  frames. A UBSan report keys on its site and
  the function it is in: the same site reached from several harnesses is one
  group, two sites are two groups. A crash with neither a project frame nor a
  source site keys on its rule, kind, check name, the faulting pc offset when
  there is one, and the harness that found it (its id and the function it
  calls): frame-less crashes of two harnesses are two groups, and two crash
  sites of one harness are two groups when the driver printed their pc. Its
  `cluster_fallback` is `true`. Releases up to 0.3.0 keyed such a crash on
  its signature, then only the rule and kind, so every frame-less finding of
  a rule was one group, and so was every frame-less crash with no sanitizer
  report of a kind: a fatal signal (which 0.2.x named `ASAN_FATAL_SIGNAL` and
  tagged `asan`), a transport-reported fault or a transport deadline.
  Findings in a work dir from those releases are grouped by the key this
  release gives their stored report (its message, `location`, `check` or
  signal, and any frames `bhf report --backfill` added; a crash with no
  sanitizer report is keyed with no sanitizer, as it is now) in `results/`,
  SARIF, the report JSON and `bhf explain`; `finding.json` is not
  rewritten.
- **Per-run dedup.** The fuzz loop, AFL++ crash ingestion and the pre-seed from
  findings an earlier pass wrote all use the root-cause key. A key is used up
  only when its finding is written: a first hit that does not reproduce in a
  fresh process does not hide a later hit of the same root cause. After three
  failed confirmations the key is given up and later hits are no longer
  re-run. Later hits of a reported root cause are counted per key in
  `duplicate_sanitizer_hits` of the harness's
  `fuzz_runs/<harness>-latest.json`; hits of a root cause that never
  reproduced (failed confirmations and the hits after it was given up) are
  counted separately, in `unreproduced_sanitizer_hits`.

`finding.json` keeps the sanitizer's structured evidence under `exception`:

| Field | Contents |
|---|---|
| `stack` | the crash stack only (at most 16 frames) |
| `location` | `{file, line, column}` the report names (UBSan's `file:line:col: runtime error:` prefix, ASan's `SUMMARY:` location) |
| `check` | UBSan's check name from its `SUMMARY:` line |
| `access` | ASan's access: `direction` (`read`/`write`/`unknown`), `size`, `address`, `address_hint` (`zero-page`, `high-value-address`), `region` (`kind` `heap`/`stack`/`global`, `size`, `offset` from the object's start, `relation` `after`/`before`/`inside`, `distance`, `variable`, `frame_offset`), `alloc_stack`, `free_stack` |

When the persistent fork-server misses a crash that the fresh-process re-run
catches, that run's stderr is the finding's `sanitizer.log`.

The fork-server runs every input it keeps in its corpus once more in a fresh
process, to catch crashes the warm process hides. These re-runs happen on a
background thread, so the fuzz loop does not wait for a process start on a
loaded host. Where a re-run runs, and at what priority, depends on the CPUs
bhf may use (its affinity and CPU quota) and on `--deadline`:

| Usable CPUs | `--deadline` | Re-runs run | Their priority |
|---|---|---|---|
| 2 or more | either | on a background thread | lower: nice +10 on Linux, below-normal on Windows (back to normal once the loop stops); normal for a re-run that starts in the pass's drain window or after the loop stops |
| 1 | not set | on a background thread | the loop's own |
| 1 | set | inline, as the loop's own step | the loop's own |

At a lower priority a re-run takes a CPU only when the loop leaves one idle.
On one CPU a lowered re-run would never finish under load, so it keeps the
loop's priority, and with `--deadline` it runs inline, so a response time is
never judged while it competes with the loop.

- **Deadline re-check.** A response-deadline (BHF-555) report from a
  background re-run is re-checked inline, at the loop's priority, whatever the
  CPU count. Like every BHF-555 report, it then becomes a finding only when
  two of three fresh re-runs overrun the deadline too.
- **Isolation.** Each re-run starts in an empty working directory of its own,
  with `TMPDIR` (`TMP` and `TEMP` on Windows) pointing there, so a target that
  keeps files in its working directory never shares them with the fork-server.
- **Findings.** A crash a re-run finds goes through the same dedup and
  verification and becomes a finding. The input then stops being a mutation
  base and is never saved in the corpus queue.
- **The queue.** An input reaches `corpus/<harness>/queue/` only once its
  re-run has come back clean. Until then it is only a mutation base in memory.
- **Bounds.** At most 32 re-runs (64 MiB of inputs) are outstanding; beyond
  that the loop waits for the oldest.
- **End of a pass.** In the drain window at the end of `--time` (a quarter
  of it, but at least 5 s, and all of a shorter pass) the loop stops issuing
  inputs once the outstanding re-runs, at the time re-runs have taken so far,
  need what is left; a re-run still going at `--time` is stopped. A re-run
  that starts in that window does not run at a lower priority: the pass may
  be about to wait for it. A pass without `--time` waits for every
  re-run. A pass that stopped at its finding count does not wait, and a crash
  a re-run reports after that count is reached is kept for the next pass
  instead of reported.
- **Unchecked inputs.** Inputs a pass could not check are counted in
  `fresh_reruns.unchecked` of `fuzz_runs/<harness>-latest.json` and kept in
  `corpus/<harness>/unchecked/`, beside the queue (up to 128 of them; `bhf
  auto` keeps `corpus/` between runs). The next fork-server pass on that work
  dir re-runs them first: a clean one joins the queue and a crashing one is
  reported. A `--workers` campaign hands them to its workers and collects what
  the workers leave unchecked back there, never into its queue.
- **Seeds.** A seed a fork-server pass never got to run is not added to the
  queue by that pass.
- **The empty input** always runs in a fresh process; bhf runs it once per
  pass and reuses the result.

A harness built without a sanitizer runtime (a cross build run under its
emulator, or a native build without sanitizers) prints nothing of its
own when a fatal signal kills it. bhf's driver then writes one line to stderr
before the signal kills the process as before:

```text
bhf: fatal signal SIGSEGV pc=0x55d0c1a2b3c4 addr=0x0 exe_offset=0x13c4
```

`exe_offset` is the faulting instruction's file address in the executable
(the same in every run, so `addr2line -e main 0x13c4` names the line); it is
missing when the pc is in a shared library. `addr` is printed for a fault the
kernel raised. The handler covers SIGSEGV, SIGBUS, SIGILL, SIGFPE and SIGTRAP,
and is installed only when no sanitizer runtime is linked and nothing else
handles the signal. The offset is recorded as `exception.pc_offset`.

## Hangs

An execution of the builtin engine that runs past `--timeout` is killed, and
its input is run once more in a fresh process with twice the timeout. If it
hangs again, it is a hang finding, BHF-230 (CWE-835); if the re-run finishes,
it was one slow execution and is only counted. Before killing a re-run that
hangs, bhf sends it SIGABRT with `handle_abort=1` added to the sanitizer
options, so a sanitizer runtime prints the stack the target was looping in.
The finding's stack starts at the first frame below the coverage or
comparison callback the signal interrupted, and two inputs that loop in the
same functions are one finding. Without a sanitizer runtime (or on Windows)
the finding has no stack, and the pass's hangs are one finding.

A pass re-runs at most four hangs, and none it has less time left for than
the re-run needs. `fuzz_runs/<harness>-latest.json` counts them under
`hangs`:

```json
"hangs": { "timeout_ms": 200, "observed": 2, "confirmed": 2, "cleared": 0, "not_rerun": 0 }
```

`observed` executions were killed at the timeout, `confirmed` hung again
(each is a finding, or a later hit of one), `cleared` finished when re-run,
and `not_rerun` were past the four re-runs or the pass's time. With
`--deadline`, an execution that overruns it is a response-deadline finding
(BHF-555) instead.

## Custom allocators: the ASan poison bridge

Legacy / RTOS C rarely uses `malloc`; it carves a static `uint8_t pool[N]` and
hands out sub-regions from a custom allocator. ASan only tracks redzones around
its **own** allocations, so an overflow that stays inside the static pool (past
the logical allocation, but within the backing array) is a silent **false
negative**.

`c_runtime/bhf_asan.h` bridges a custom pool to ASan's manual poisoning
interface so those overflows become findings. Three calls, each a no-op when the
translation unit is not built with ASan (so the same source still compiles under
`--sanitizers none`, on the cross path, and in a normal build):

```c
#include "bhf_asan.h"

static unsigned char pool[4096];

void allocator_init(void) {
    bhf_asan_pool_init(pool, sizeof pool);   /* poison the whole pool once */
}

void *my_alloc(size_t n) {
    void *p = bump_from(pool, n);
    bhf_asan_on_alloc(p, n);                  /* unpoison the live slice */
    return p;
}

void my_free(void *p, size_t n) {
    bhf_asan_on_free(p, n);                   /* optional: re-arm UAF detection */
    /* ... return to pool ... */
}
```

After init + on-alloc, a read or write that runs off the end of an allocation
into still-poisoned pool memory is reported as a use-after-poison /
heap-buffer-overflow — the same coverage you would get from a malloc-based target.
Align pool sub-allocations to 8 bytes for exact detection (ASan's shadow
granularity is one byte per eight).

## Cooperative context switches: fiber annotations

RTOS cooperative schedulers switch stacks themselves (ucontext, custom
setjmp/longjmp, task switch). ASan's `detect_stack_use_after_return` fake stack
assumes one linear stack, so a switch can produce bogus `stack-use-after-return`
reports. Two options:

- **Blunt:** run with `ASAN_OPTIONS=detect_stack_use_after_return=0` (preserved by
  the env merge above). You lose use-after-return detection everywhere.
- **Accurate:** bracket each switch with `c_runtime/bhf_asan_fiber.h` so ASan
  follows it and keeps the check on. Describe each fiber (including the initial
  one) with a `bhf_fiber_t` holding its stack region, then:

```c
#include "bhf_asan_fiber.h"

bhf_fiber_t main_fiber = {0};                       /* learned on first entry */
bhf_fiber_t co_fiber = BHF_FIBER_INIT(co_stack, sizeof co_stack);

/* main, switching to the coroutine */
bhf_fiber_before_switch(&main_fiber, &co_fiber);
swapcontext(&main_uc, &co_uc);
bhf_fiber_after_switch(&main_fiber, &co_fiber);

/* coroutine entry/resume — captures main's real stack region into main_fiber */
bhf_fiber_after_switch(&co_fiber, &main_fiber);
...
bhf_fiber_before_switch(&co_fiber, &main_fiber);    /* NULL `from` when exiting */
swapcontext(&co_uc, &main_uc);
```

The calls are no-ops without ASan, so the same source still builds under
`--sanitizers none`, on the cross path, and normally.

## The ThreadSanitizer corpus replay

Unless `--sanitizers` leaves `tsan` out, `bhf auto` builds each C harness's
TSan variant (`make tsan`) and replays the saved corpus through it. A data
race whose report names a frame in the target's own source becomes a BHF-556
(CWE-362) finding.
The run summary says what the replay could not conclude:

- **unmeasured:** inputs whose TSan run never completed (a timeout, or a
  start that failed on every retry), inputs that hung under the MSan replay,
  and the rest of a corpus whose replay reached the harness's budget. They are
  not race-free, only unexamined.
- **unattributed:** races TSan reported with no symbolized frame. They are real
  but unlocated. Install `llvm-symbolizer` or keep debug info to locate them.
- **run again:** inputs whose first run exited cleanly with no report. Each such
  input is run once more before it counts as race-free, and the summary gives
  the number of races only that second run showed. TSan can miss a race on any
  single run. It checks and updates an address's shadow memory in a step that
  is not atomic, so two threads that first touch an address at the same moment
  can both miss the other's access. A race on either side of a
  `pthread_create` went unreported on about one run in twenty, and the second
  run brings that to about one in four hundred. The extra run uses the same
  per-run timeout and timeout budget as every other replay run. If it does not
  finish, the input keeps the clean result of its first run.

### Bounds of the MSan and TSan replays

Each replayed input runs for at most `--timeout`, or 30 s, whichever is less.
A run past it is a hang under that sanitizer: it is not run again, and the
replay that comes next (TSan, after MSan) skips that input. A harness's replay
stops when it has taken the harness's `--per-target-time`. Every run is a line
of `auto/sanitizer-replay.jsonl`: the sanitizer, harness, input, `elapsed_ms`,
`timeout_ms` and the outcome (`completed`, `timeout`, `spawn_failed` or
`skipped_known_hang`).

## When to use which

- **Default sweep:** omit `--sanitizers` — ASan + UBSan is the right baseline.
- **FP storm you want gone:** `--sanitizers none` (lose sub-crash detection, keep
  coverage + crashes), or keep ASan and tame it with `ASAN_OPTIONS` above.
- **Custom static-pool allocator:** keep ASan and wire `bhf_asan.h` so
  intra-pool overflows are caught.
- **Leaks:** `--sanitizers asan,ubsan,lsan`. **Uninitialized reads / races:**
  `--sanitizers msan` or `tsan` as separate campaigns.
