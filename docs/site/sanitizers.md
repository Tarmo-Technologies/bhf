<!-- SPDX-License-Identifier: Apache-2.0 -->

# Sanitizers

A native C or C++ harness is built with `-fsanitize=address,undefined` (AddressSanitizer and UndefinedBehaviorSanitizer, ASan and UBSan below) and the engine's coverage instrumentation. `--sanitizers` on `bhf auto` and `bhf fuzz` selects another set. This page covers:

- choosing the sanitizers, or building without them for code that produces many ASan false positives (shared memory, custom allocators, RTOS builds);
- tuning them through `<SAN>_OPTIONS`;
- how a sanitizer report becomes a finding, and how findings are grouped;
- hangs;
- custom allocators and cooperative context switches;
- the MemorySanitizer, ThreadSanitizer, control-flow integrity and RealtimeSanitizer replays that `bhf auto` runs after fuzzing.

`--sanitizers` applies to native C/C++ harnesses only. The other lanes use their own instrumentation, which `--sanitizers` does not change:

| Lane | Error detection |
|---|---|
| Ada | source instrumentation |
| Rust | ASan and SanitizerCoverage, always, through lane-owned `RUSTFLAGS` |
| Java | bhf's bytecode coverage agent in the JVM |
| Python, Perl, Ruby, Lua, PHP | interpreter coverage, exception and error oracles |
| C# | SharpFuzz IL coverage |
| JavaScript, TypeScript | V8 block coverage |
| Go | atomic compiler coverage and recovered panics, with a black-box fallback |
| COBOL, Fortran | lane-owned ASan and coverage builds |

A cross-compiled harness that runs under qemu-user or wine is built without host sanitizers, because ASan's shadow memory does not work under those emulators. [Instrumentation](instrumentation.md) has the per-lane feedback matrix and its fallbacks.

## Platform availability

| Native host | Fuzzed C/C++ build | Post-fuzz replay lanes |
|---|---|---|
| Linux | ASan, UBSan and LSan; HWASan on AArch64; MSan or TSan as a separate selection | MSan and TSan by default; CFI and RealtimeSanitizer when selected |
| Windows with clang | ASan and UBSan | None: LLVM does not ship Windows runtimes for LSan, MSan, TSan or RealtimeSanitizer, and bhf's full CFI lane is not compatible with the Microsoft ABI |
| Windows with `cl` or `clang-cl` | ASan only | None |

On native Windows the default clang harness uses ASan and UBSan together, with the same coverage and CmpLog instrumentation and the same finding evidence as on Linux. `--sanitizers asan`, `ubsan` and `asan,ubsan` are accepted. bhf refuses `lsan`, `msan`, `tsan`, `hwasan`, `cfi` and `realtime` before discovery instead of attempting builds whose runtime does not exist or reporting those classes as measured. Use a Linux host when those lanes are required. The `cl` and `clang-cl` lanes remain ASan-only because Microsoft's compiler interface provides no UBSan mode.

## `--sanitizers <set | none>`

| Value | Effect |
|---|---|
| `asan`, `ubsan`, `lsan` | AddressSanitizer, UndefinedBehaviorSanitizer, LeakSanitizer. They combine with each other. |
| `msan`, `tsan` | MemorySanitizer, ThreadSanitizer. Each needs a build of its own and combines with no other sanitizer: run it as a separate campaign. |
| `hwasan` | HWAddressSanitizer in place of ASan, on an AArch64 host only. See [HWASan on AArch64](#hwasan-on-aarch64). |
| `cfi` | `bhf auto` only. Replays the corpus through a control-flow integrity build after fuzzing; it is never part of the fuzzed build. See [The control-flow integrity replay](#the-control-flow-integrity-replay). |
| `realtime` (or `rtsan`) | `bhf auto` only. Replays the corpus through a RealtimeSanitizer build. See [The RealtimeSanitizer replay](#the-realtimesanitizer-replay). |
| `none` | Builds each native C/C++ harness with coverage instrumentation and no `-fsanitize=` flag. It cannot be combined with another value. |

The values are comma-separated (`--sanitizers asan,ubsan,lsan`). `address`, `undefined`, `leak`, `memory`, `thread` and `hwaddress` are accepted as aliases.

`--sanitizers none` gives coverage-guided fuzzing that finds crashes (SIGSEGV, SIGABRT and the other fatal signals) and produces no ASan or UBSan report, so none of their false positives either. Use it for code that produces many false positives under ASan: shared memory, custom allocators, partially instrumented RTOS builds.

Without `--sanitizers`, `bhf auto` also replays each corpus through MemorySanitizer and ThreadSanitizer builds after fuzzing on hosts where those runtimes exist (see [The MemorySanitizer replay](#the-memorysanitizer-replay) and [The ThreadSanitizer replay](#the-threadsanitizer-replay)). Native Windows skips both and records their bug classes as unobservable. With `--sanitizers`, supported hosts run those replays only for `msan` or `tsan` in the set; `none` runs neither.

With an operator's compiler (`CC`/`CXX`, `--cc`/`--cxx`, `[toolchain]`), `--sanitizers` first links a trivial program with the requested sanitizers and runs it: with `CC` for every harness, and with `CXX` (as C++) for a C++ harness. A compiler that cannot link it (gcc has no MemorySanitizer), or whose runtime links but aborts before `main` on this host (GCC's ThreadSanitizer under a kernel with high-entropy ASLR prints `FATAL: ThreadSanitizer: unexpected memory mapping`), is replaced, and bhf prints a note naming the variable, the compiler and the runtime's message. A failing `CC` sends the C and C++ harnesses to clang/clang++; a failing `CXX` sends the C++ harnesses to clang++ and leaves `CC` building their C units. A C-only sweep never runs `CXX`. The environment's `CFLAGS` (for `CC`) and `CXXFLAGS` (for `CXX`) are written for the compiler bhf replaced, so they stay out of the clang builds, and the note says so when they are set.

A SIGABRT with a recognizable assertion or panic message counts as the target rejecting the input. A SIGABRT with no such message is saved as a crash.

A run whose sanitizer runtime could not start (that `FATAL` line, an AddressSanitizer shadow-mapping failure, a runtime that is not first in the library list) is never a finding. The first fuzz pass that sees it ends the target with an error naming the line and the compiler the harness was built with, and no further pass runs. The target's outcome is `sanitizer_runtime_unavailable` (`summary.sanitizer_runtime_unavailable` in `run.json`, "Not fuzzed (sanitizer runtime cannot start on this host)" in the summary). bhf treats it as an environment problem: it is left out of the bug report and tried again by `--resume`. Build with a compiler whose runtime starts on the host (clang), or pick the sanitizers with `--sanitizers`, which runs the check above first.

## Tuning sanitizers with `<SAN>_OPTIONS`

To cut false positives and keep detection on, set the sanitizer's own runtime options in the environment. bhf **merges** your inherited `<SAN>_OPTIONS` with the keys it requires (`abort_on_error`, `halt_on_error`, `detect_leaks`). Your keys are kept and bhf's go last, so bhf's win: `halt_on_error=1` stops the run at the first report, so a UBSan or LSan report is a saved crash rather than a printed warning. A child that runs under an emulator gets `abort_on_error=0` (see below).

The builtin engine's own executions also append `symbolize=0:abort_on_error=0`: the sanitizer exits non-zero after its report, and bhf re-runs each new crash symbolized in a fresh process with the replay keys below. That report becomes the finding. `BHF_IN_LOOP_SYMBOLIZE=1` symbolizes in the loop instead (see the [CLI reference](cli.md)).

Minimization, `bhf replay`, `bhf report --backfill` and the generated `replay.py` run C/C++ harnesses with these `ASAN_OPTIONS` and `UBSAN_OPTIONS` keys:

- `abort_on_error=1:halt_on_error=1:symbolize=1`, after the inherited value, so an inherited value cannot turn a report into a clean exit, and an inherited `symbolize=0` cannot erase the frames a replay compares;
- `detect_leaks=1` for a leak finding (bhf never sets `detect_leaks=0`);
- for UBSan, also `print_stacktrace=1` and `report_error_type=1`, so UBSan prints the stack of each report and names the failed check (`missing-return`, `invalid-shift-exponent`, ...) on its `SUMMARY:` line.

The inherited value is passed through unchanged, including a quoted value or a drive path with a `:` in it, and bhf's keys follow it. `replay.py` exits with the harness's exit status, or 128 plus the signal number for a harness killed by a signal.

Each sanitizer's variable is merged separately, so per-sanitizer suppressions land in the right variable:

```sh
ASAN_OPTIONS=verify_asan_link_order=0:detect_container_overflow=0:detect_odr_violation=0:allocator_may_return_null=1:suppressions=$PWD/asan.supp \
LSAN_OPTIONS=suppressions=$PWD/lsan.supp \
bhf auto path/to/src --sanitizers asan,ubsan,lsan
```

`ASAN_OPTIONS` keys that remove common false positives in RTOS and partially instrumented builds:

| Key | Use it when |
|---|---|
| `verify_asan_link_order=0` | vendor libraries are not built with ASan |
| `detect_container_overflow=0` | instrumented and uninstrumented code share containers |
| `detect_odr_violation=0` | a large firmware build has duplicate symbols |
| `detect_stack_use_after_return=0` | RTOS cooperative context switches confuse ASan's fake stack |
| `suppressions=<file>` | one known-benign report should be silenced |

Under qemu-user, a guest abort makes the emulator dump its own address space, which takes minutes. A child that runs under an emulator (`--qemu-user`, or the emulator recorded beside a cross-built harness in `bhf_runner.json`) therefore does not abort on a report and runs with core dumps off. The sanitizer still exits non-zero after its report, and bhf classifies that exit as the crash. A minimization, replay or comparison-capture child gets `abort_on_error=0` in place of `abort_on_error=1`, so each of bhf's keys appears once in its options and in the direct harness command `bhf explain` prints. A fuzz child under an emulator gets `abort_on_error=0` appended after the options it runs with (which can also come from `--sanitizers` and `--env`); the last value wins. The generated `replay.py` does the same whenever it runs the harness under a runner (its embedded `RUNNER`, the `bhf_runner.json` beside the harness, or a non-empty `BHF_REPLAY_RUNNER`); a native run keeps `abort_on_error=1`.

## How a sanitizer report is classified

Each UBSan check kind has its own rule, CWE, explanation and fix hint; only signed and unsigned integer overflow share one rule, BHF-205. The kind comes from UBSan's check name on its `SUMMARY:` line when it printed one, else from the report text after `runtime error:`. Classification reads these structured fields and the text after the source location only, so a path such as `src/zoom/` or `src/timeout/` never changes it.

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

In a gcc build with both ASan and UBSan, gcc's `object-size` check (BHF-227) guards the same access as ASan's own check and fires first, so a heap or stack overflow first comes out as BHF-227. clang's check does the same for a member access through a heap block smaller than its struct. bhf then re-runs that input with the check suppressed: when ASan reports the same access, the finding is ASan's (BHF-201, BHF-203), as with clang. When ASan stays silent the BHF-227 finding stands: the check also sees memory ASan does not track, such as a chunk of a pool allocator declared `alloc_size`, so the gcc lanes keep it on. A replay of either kind on the gcc binary, which reports BHF-227, is the same crash.

This second opinion applies to the builtin engine's crashes and to those an AFL++ pass finds. It runs once per root cause: the first hit of a BHF-227 report is re-run, within the per-input timeout and what is left of the pass's time, and later hits of it, in this pass or a later one over the same work dir, count against the finding without another re-run. The finding's `finding.json` says which report it carries and why:

```json
"sanitizer_second_opinion": {
  "check": "object-size",
  "used": "asan",
  "reason": "UBSan's object-size check reported this access before ASan; with the check suppressed, AddressSanitizer reported heap-buffer-overflow at the same sink",
  "replaced_cluster_key": "..."
}
```

`used` is `ubsan` when the BHF-227 report stands, and `reason` then says why: the re-run reported no error, reported something else, reached its time limit, or was skipped because the pass's time had run out. `results/findings.json` carries `{check, used, reason}` as `fuzz.sanitizer_second_opinion`.

Each AddressSanitizer report kind has its own rule too. The kind is read from the report's `ERROR:` line; a class ASan names with a phrase there (`out of memory`, `calloc parameters overflow`) takes the name its `SUMMARY:` line gives it (`out-of-memory`, `calloc-overflow`).

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

A kind bhf has no rule for, including one a newer compiler-rt adds, is a reachable crash (BHF-210), never a heap overflow.

An ASan SEGV in the first memory page (ASan's "zero page" hint, or an address below `0x1000`) is a NULL dereference, BHF-206 / CWE-476. Any other SEGV is a wild or corrupted pointer, BHF-223: CWE-125 for a READ, CWE-787 for a WRITE, and CWE-119 when ASan reports no direction or the address is a non-canonical "high value address", for which ASan prints READ whatever the access was. The direction is ASan's `READ`/`WRITE` token, recorded as `exception.access.direction`. On Windows, ASan names the fault by its exception instead (`access-violation on unknown address`, or `in-page-error` for a mapped page that could not be read in); bhf treats both as a SEGV, with the same rules and CWEs.

The SARIF result's `properties.cwe` is the finding's CWE (the first of `properties.cwes`); the rule entry keeps its catalog CWE.

### Findings recorded by earlier releases

`bhf replay` matches findings recorded under the rules earlier releases used for these reports. Those releases classified a UBSan report by its text alone: integer overflow, division by zero and any "cannot be represented in type" report (a left shift included) were BHF-205, the load, store, member-access, reference-binding and NULL-argument or NULL-return reports BHF-206, an array index BHF-201, and every other check (a member call on NULL included) BHF-210. Every ASan SEGV was BHF-206, and every other ASan kind without its own rule above (a Windows access violation or in-page error, a stack overflow, an arithmetic exception or other deadly signal, an overlapping copy, a refused allocation, `unknown-crash`, ...) BHF-201. They also took the kind from the first word of the `ERROR:` line (`out` for `out of memory`, `memcpy-param-overlap:` with its colon), which replay accepts too. In `results/`, SARIF, the report JSON and `bhf explain`, such a finding is grouped by the key this release gives its stored report, so it shares a root-cause group with the same crash found now; `finding.json` is not rewritten.

## How a sanitizer finding is identified

Each sanitizer crash becomes one finding per root cause per harness, not one per crashing input.

- **Signature and finding ID.** The signature hashes the rule, the crash kind, UBSan's check name, the crash-stack function names and, for a UBSan report or any report printed without a stack, the reported site (`<dir>/<file>:<line>:<col>`, the last two components of the reported path, so `src/a/util.c` and `src/b/util.c` are different sites wherever the tree is checked out; a bare file name takes its directory from the top crash frame naming the same file). A fatal signal with no sanitizer report has no stack; its site is the faulting instruction's offset in the executable, when bhf's driver printed one (see below). The `F-NNNN-<sig8>` suffix is its first 8 hex digits. The allocation and free stacks are not hashed.
- **Root-cause key** (`cluster_key_full`, the `group` in `results/`). The rule, kind and check name plus the first three project frames. libc, sanitizer-runtime and interceptor frames (`__memcmp_avx2_movbe`, `MemcmpInterceptorCommon`, `bcmp`, glibc component sources such as `sysdeps/`, `csu/`, `assert/` and `signal/`) are skipped, so the key starts at the project code that made the call. So are C++ standard-library frames (`std::` and `__gnu_cxx::` functions, and any frame in a standard-library header under `include/c++/` or MSVC's `VC/Tools/MSVC/.../include/`; a Rust `std::` frame is dropped by the same rule): two out-of-bounds reads through `std::unique_ptr::get` in two project functions are two groups. A crash with no other frame keeps its standard-library frames. A UBSan report keys on its site and the function it is in: the same site reached from several harnesses is one group, two sites are two groups. A crash with neither a project frame nor a source site keys on its rule, kind, check name, the faulting pc offset when there is one, and the harness that found it (its id and the function it calls): frame-less crashes of two harnesses are two groups, and two crash sites of one harness are two groups when the driver printed their pc. Its `cluster_fallback` is `true`.
- **Per-run dedup.** The fuzz loop, AFL++ crash ingestion and the pre-seed from findings an earlier pass wrote all use the root-cause key. A key is used up only when its finding is written: a first hit that does not reproduce in a fresh process does not hide a later hit of the same root cause. After three failed confirmations the key is given up and later hits are no longer re-run. Later hits of a reported root cause are counted per key in `duplicate_sanitizer_hits` of the harness's `fuzz_runs/<harness>-latest.json`; hits of a root cause that never reproduced (failed confirmations and the hits after it was given up) are counted separately, in `unreproduced_sanitizer_hits`.

Releases up to 0.3.0 keyed a frame-less crash on its signature, then only on the rule and kind. Every frame-less finding of a rule was then one group, and so was every frame-less crash of a kind with no sanitizer report: a fatal signal (which 0.2.x named `ASAN_FATAL_SIGNAL` and tagged `asan`), a transport-reported fault or a transport deadline. Findings in a work dir from those releases are grouped by the key this release gives their stored report (its message, `location`, `check` or signal, and any frames `bhf report --backfill` added; a crash with no sanitizer report is keyed with no sanitizer, as it is now) in `results/`, SARIF, the report JSON and `bhf explain`. `finding.json` is not rewritten.

`finding.json` keeps the sanitizer's structured evidence under `exception`:

| Field | Contents |
|---|---|
| `stack` | the crash stack only (at most 16 frames) |
| `location` | `{file, line, column}` the report names (UBSan's `file:line:col: runtime error:` prefix, ASan's `SUMMARY:` location) |
| `check` | UBSan's check name from its `SUMMARY:` line |
| `access` | ASan's access: `direction` (`read`/`write`/`unknown`), `size`, `address`, `address_hint` (`zero-page`, `high-value-address`), `region` (`kind` `heap`/`stack`/`global`, `size`, `offset` from the object's start, `relation` `after`/`before`/`inside`, `distance`, `variable`, `frame_offset`), `alloc_stack`, `free_stack` |

### Fresh-process re-runs of kept inputs

The builtin engine runs a C/C++ harness in a fork-server: a persistent process that runs input after input. State that process keeps from earlier inputs can hide a crash, so the fork-server runs every input it keeps in its corpus once more in a fresh process. When the fresh-process re-run catches a crash the fork-server missed, that run's stderr is the finding's `sanitizer.log`.

These re-runs happen on a background thread, so the fuzz loop does not wait for a process start on a loaded host. Where a re-run runs, and at what priority, depends on the CPUs bhf may use (its affinity and CPU quota) and on `--deadline`:

| Usable CPUs | `--deadline` | Re-runs run | Their priority |
|---|---|---|---|
| 2 or more | either | on a background thread | lower: nice +10 on Linux, below-normal on Windows (back to normal once the loop stops); normal for a re-run that starts in the pass's drain window or after the loop stops |
| 1 | not set | on a background thread | the loop's own |
| 1 | set | inline, as the loop's own step | the loop's own |

At a lower priority a re-run takes a CPU only when the loop leaves one idle. On one CPU a lowered re-run would never finish under load, so it keeps the loop's priority, and with `--deadline` it runs inline, so a response time is never judged while it competes with the loop.

- **Deadline re-check.** A response-deadline (BHF-555) report from a background re-run is re-checked inline, at the loop's priority, whatever the CPU count. Like every BHF-555 report, it then becomes a finding only when two of three fresh re-runs overrun the deadline too.
- **Isolation.** Each re-run starts in an empty working directory of its own, with `TMPDIR` (`TMP` and `TEMP` on Windows) pointing there, so a target that keeps files in its working directory never shares them with the fork-server.
- **Findings.** A crash a re-run finds goes through the same dedup and verification and becomes a finding. The input then stops being a mutation base and is never saved in the corpus queue.
- **The queue.** An input reaches `corpus/<harness>/queue/` only once its re-run has come back clean. Until then it is only a mutation base in memory.
- **Bounds.** At most 32 re-runs (64 MiB of inputs) are outstanding; beyond that the loop waits for the oldest.
- **End of a pass.** In the drain window at the end of `--time` (a quarter of it, but at least 5 s, and all of a shorter pass) the loop stops issuing inputs once the outstanding re-runs, at the time re-runs have taken so far, need what is left; a re-run still going at `--time` is stopped. A re-run that starts in that window does not run at a lower priority: the pass may be about to wait for it. A pass without `--time` waits for every re-run. A pass that stopped at its finding count does not wait, and a crash a re-run reports after that count is reached is kept for the next pass instead of reported.
- **Unchecked inputs.** Inputs a pass could not check are counted in `fresh_reruns.unchecked` of `fuzz_runs/<harness>-latest.json` and kept in `corpus/<harness>/unchecked/`, beside the queue (up to 128 of them; `bhf auto` keeps `corpus/` between runs). The next fork-server pass on that work dir re-runs them first: a clean one joins the queue and a crashing one is reported. A `--workers` campaign hands them to its workers and collects what the workers leave unchecked back there, never into its queue.
- **Seeds.** A seed a fork-server pass never got to run is not added to the queue by that pass.
- **The empty input** always runs in a fresh process; bhf runs it once per pass and reuses the result.

### Crashes without a sanitizer report

A harness built without a sanitizer runtime (a cross build run under its emulator, or a native build with `--sanitizers none`) prints nothing of its own when a fatal signal kills it. bhf's driver then writes one line to stderr before the signal ends the process:

```text
bhf: fatal signal SIGSEGV pc=0x55d0c1a2b3c4 addr=0x0 exe_offset=0x13c4
```

`exe_offset` is the faulting instruction's file address in the executable (the same in every run, so `addr2line -e main 0x13c4` names the line); it is missing when the pc is in a shared library. `addr` is printed for a fault the kernel raised. The handler covers SIGSEGV, SIGBUS, SIGILL, SIGFPE and SIGTRAP, and is installed only when no sanitizer runtime is linked and nothing else handles the signal. The offset is recorded as `exception.pc_offset`.

## Hangs

An execution of the builtin engine that runs past `--timeout` is killed, and its input is run once more in a fresh process with twice the timeout. If it hangs again, it is a hang finding, BHF-230 (CWE-835); if the re-run finishes, it was one slow execution and is only counted. Before killing a re-run that hangs, bhf sends it SIGABRT with `handle_abort=1` added to the sanitizer options, so a sanitizer runtime prints the stack the target was looping in. The finding's stack starts at the first frame below the coverage or comparison callback the signal interrupted, and two inputs that loop in the same functions are one finding.

An interpreter answers no signal while its target loops, so in the interpreted lanes the re-run's driver keeps the time instead: bhf sets `BHF_HANG_REPORT_MS` to the re-run's limit and lets it run up to half that again (at most 2s) past it, and when the limit passes the driver prints the frames its target is running (`== bhf hang: <lane>`, then `== bhf frame: <function> @ <file>:<line>` lines) and halts. The Python driver uses a SIGALRM timer, Ruby and the JVM a watchdog thread, Perl a SIGALRM handler, PHP an async `pcntl` SIGALRM (whole seconds; without the `pcntl` extension the hang has no stack), Lua a count hook on the run's CPU time, and Node a worker thread that pauses the main thread through the inspector. A Go target's runtime answers SIGABRT with its goroutine dump, whose target frames make the stack. The Lua re-run runs without the coverage line hook, whose cost can make a deep recursion outlast the timeout: an input that, given the time, crashes instead (that recursion overflowing the stack) is reported as that crash. Without a sanitizer runtime, a driver that reports, or a goroutine dump (a native target on Windows, say), the finding has no stack, and the pass's hangs are one finding.

A pass re-runs at most four hangs, and none it has less time left for than the re-run needs. `fuzz_runs/<harness>-latest.json` counts them under `hangs`:

```json
"hangs": { "timeout_ms": 200, "observed": 2, "confirmed": 2, "cleared": 0, "not_rerun": 0 }
```

`observed` executions were killed at the timeout, `confirmed` hung again (each is a finding, or a later hit of one), `cleared` finished when re-run, and `not_rerun` were past the four re-runs or the pass's time. With `--deadline`, an execution that overruns it is a response-deadline finding (BHF-555) instead.

## Custom allocators: the ASan poison bridge

RTOS and other embedded C code often allocates from a static `uint8_t pool[N]` through a custom allocator instead of `malloc`. ASan tracks redzones around its **own** allocations only, so an overflow that stays inside the static pool (past the logical allocation, but within the backing array) goes unreported.

`c_runtime/bhf_asan.h` connects a custom pool to ASan's manual poisoning interface so those overflows become findings. It has three calls. Each is a no-op when the translation unit is not built with ASan, so the same source still compiles under `--sanitizers none`, on the cross path, and in a normal build:

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

After `bhf_asan_pool_init` and `bhf_asan_on_alloc`, a read or write that runs off the end of an allocation into still-poisoned pool memory is reported as `use-after-poison` (BHF-201), as an overflow of a `malloc` block would be. Align pool sub-allocations to 8 bytes for exact detection: ASan's shadow memory has one byte per eight bytes of memory.

## Cooperative context switches: fiber annotations

RTOS cooperative schedulers switch stacks themselves (ucontext, custom setjmp/longjmp, a task switch). ASan's `detect_stack_use_after_return` fake stack assumes one linear stack, so a switch can produce false `stack-use-after-return` reports. There are two ways to handle it:

- **Turn the check off:** run with `ASAN_OPTIONS=detect_stack_use_after_return=0`, which the option merge above keeps. Use-after-return detection is then off everywhere.
- **Annotate the switches:** bracket each switch with the calls in `c_runtime/bhf_asan_fiber.h`, so ASan follows it and keeps the check on. Describe each fiber (including the initial one) with a `bhf_fiber_t` holding its stack region, then:

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

The calls are no-ops without ASan, so the same source still builds under `--sanitizers none`, on the cross path, and normally.

## HWASan on AArch64

On an AArch64 host, `--sanitizers hwasan` (or `hwaddress`) builds the fuzzed harness with `-fsanitize=hwaddress` in place of ASan. HWAddressSanitizer keeps a random tag in each pointer's top byte, which AArch64 ignores on every load and store, and the same tag for each 16 bytes of the memory it points to. An access through a pointer whose tag does not match its memory's is a report: heap and stack overflows, use after free and invalid frees, as ASan finds them, with less memory (a tag per 16 bytes, no redzones or quarantine). It carries LeakSanitizer, as ASan does, and combines with `ubsan`.

A report becomes a finding under the rule ASan gives the same bug (BHF-201 for a heap overflow, BHF-202 use after free, BHF-203 a stack overflow, BHF-204 an invalid free), its exception named `HWASAN_<KIND>`. HWASan's `ERROR:` line says only `tag-mismatch`, so the kind is the first specific `Cause:` its report gives. Its options are `HWASAN_OPTIONS`, which bhf merges as it does `ASAN_OPTIONS`.

`hwasan` is refused beside `asan`, which finds the same bugs another way, and on any host other than AArch64. An x86-64 CPU does not ignore a pointer's top byte, so the build fails or the runtime does not start, and bhf says so before building. A HWASan build also needs a Linux kernel with the tagged-address ABI (5.4 or newer).

## The MemorySanitizer replay

MemorySanitizer (MSan) cannot share a build with ASan. Unless `--sanitizers` leaves `msan` out, `bhf auto` therefore builds a separate MSan variant of each C and C++ harness (`make msan`) after the fuzz passes and replays the saved corpus through it. A read of uninitialized memory whose report's faulting frame is in the target's own source becomes a BHF-212 (CWE-457) finding; reports in bhf's driver, the C runtime or a system library are dropped. A C++ harness needs an MSan-instrumented libc++: see [C++ under the MSan replay](#c-under-the-msan-replay).

### C++ under the MSan replay

MemorySanitizer reports a read of memory never written only when every function that touched that memory is instrumented, the C++ standard library included. A C++ harness's `make msan` therefore builds against an MSan-instrumented libc++ and libc++abi: `BHF_MSAN_LIBCXX` names their install prefix (`include/c++/v1`, `lib`). The full image builds them from the LLVM release of its clang and sets `BHF_MSAN_LIBCXX=/opt/msan-libcxx`. Elsewhere, build them once with the LLVM runtimes build:

```sh
cmake -G Ninja -S llvm-project/runtimes -B msan-build \
  -DLLVM_ENABLE_RUNTIMES='libcxx;libcxxabi' -DLLVM_USE_SANITIZER=MemoryWithOrigins \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/opt/msan-libcxx
ninja -C msan-build install-cxx install-cxxabi
export BHF_MSAN_LIBCXX=/opt/msan-libcxx
```

Use the LLVM release of the clang that builds the harnesses. Without `BHF_MSAN_LIBCXX` a C++ harness's `make msan` stops with that message, the replay skips it, and the run lists uninitialized reads as unobservable in C++.

On a kernel with 32 bits of mmap randomization, an MSan process sometimes lands in an address-space layout that clashes with its shadow memory and re-runs itself with randomization off; a container's default seccomp profile refuses that (`MemorySanitizer: CHECK failed: msan_linux.cpp ... ADDR_NO_RANDOMIZE`). The process stopped before it ran the input, so bhf runs it again, up to 8 times.

## The ThreadSanitizer replay

Unless `--sanitizers` leaves `tsan` out, `bhf auto` builds each C harness's ThreadSanitizer (TSan) variant (`make tsan`) and replays the saved corpus through it. The C++ harnesses have no TSan build. A race shows up only when the target starts threads while it handles one input. A data race whose report names a frame in the target's own source becomes a BHF-556 (CWE-362) finding. The run summary says what the replay could not conclude:

- **unmeasured:** inputs whose TSan run never completed (a timeout, or a start that failed on every retry), inputs that hung under the MSan replay, and the rest of a corpus whose replay reached the harness's budget. bhf counts them as unexamined, not as race-free.
- **unattributed:** races TSan reported with no symbolized frame, so no source location. Install `llvm-symbolizer` or keep debug info to locate them.
- **run again:** inputs whose first run exited cleanly with no report. Each such input runs once more before it counts as race-free, and the summary gives the number of races only that second run showed. TSan checks and updates an address's shadow memory in a step that is not atomic, so two threads that first touch an address at the same moment can both miss the other's access. In bhf's test of two unsynchronized writes on either side of a `pthread_create`, one run missed the race about one time in twenty; a second, independent run lowers that to about one in four hundred. The extra run uses the same per-run timeout and timeout budget as every other replay run. If it does not finish, the input keeps the clean result of its first run.

## The control-flow integrity replay

`bhf auto --sanitizers ...,cfi` replays each C/C++ harness's corpus through a control-flow integrity build (`make cfi`, `main_cfi`: clang `-fsanitize=cfi -flto -fvisibility=hidden`). It finds type errors the fuzzed build does not report: a cast to the wrong class (`static_cast<Circle *>` of a `Square`), a virtual call through an object of another type, and a call through a function pointer of the wrong type. The fuzzed build keeps UBSan's `function` and `vptr` checks off, so this replay is where bhf observes type confusion. CFI needs whole-program LTO, a link the fuzzed build does not do, so it runs as a replay of its own build after the fuzz passes, and `bhf fuzz` refuses `--sanitizers cfi`.

Its checks report through the UBSan runtime, and a report becomes a finding under the rule its check maps to: BHF-221, type confusion (CWE-843), at the cast or call, with the CFI build as the fixture `bhf replay` runs. The build needs clang and an LTO linker (lld, or binutils with LLVM's gold plugin). A harness whose CFI build fails is named in the run's output, and its corpus is counted as unmeasured for type confusion.

## The RealtimeSanitizer replay

`bhf auto --sanitizers ...,realtime` (or `rtsan`) checks code that must not block: an interrupt handler, or the body of an RTOS task, that allocates, takes a lock, sleeps or makes a system call on its real-time path (CWE-1322). Such a call is valid C and only misses a deadline, so the other sanitizers do not report it.

The lane marks each nonblocking target's harness, so the target runs between `__rtsan_realtime_enter()` and `__rtsan_realtime_exit()`. `--nonblocking` names the targets (repeat it to name several):

| Value | Marks |
|---|---|
| `entry-points` (the default) | interrupt handlers: a name ending in `_IRQHandler`, `IRQHandler`, `_Handler`, `_isr` or `_irq_handler`, or starting with `isr_`; and task or thread bodies: a function returning `void` whose name contains `task` or `thread` and that takes one `void *` (FreeRTOS), one `ULONG` (ThreadX) or three `void *` (Zephyr) |
| `all` | every target |
| any other value | the target of that name |

After the fuzz passes, each marked C/C++ harness is built with `-fsanitize=realtime` (`make rtsan`, `main_rtsan`) and replays its corpus. A real-time unsafe call becomes a BHF-232 finding at the target's frame that made it, with the RTSan build as the fixture `bhf replay` runs. The lane needs clang 20 or newer, which it finds as `clang-22`, `clang-21`, `clang-20` or `clang`. Without one, the run says so and skips the lane. A harness whose RTSan build fails is named in the run's output, and its corpus is counted as unmeasured for real-time safety. `--nonblocking` without the `realtime` lane is an error, and `bhf fuzz` refuses `--sanitizers realtime`, as it does `cfi`.

## Bounds of the MSan, TSan, CFI and RealtimeSanitizer replays

Each replayed input runs for at most `--timeout`, or 30 s, whichever is less. A run past it is a hang under that sanitizer: it is not run again, and the replay that comes next (TSan, after MSan) skips that input. A harness's replay stops when it has taken the harness's `--per-target-time`. Every run is a line of `auto/sanitizer-replay.jsonl`: the sanitizer, harness, input, `elapsed_ms`, `timeout_ms` and the outcome (`completed`, `timeout`, `spawn_failed` or `skipped_known_hang`).

## Bug classes a run could not observe

`run.json`'s `summary.unobservable_classes` and the run report's "Bug classes this run could not observe" list each bug class that no lane of the run detects in the C/C++ targets it fuzzed, the languages it went unobserved in, and what would observe it:

| Class | Unobserved without |
|---|---|
| memory errors | ASan |
| undefined behavior | UBSan |
| leaks | LSan or ASan |
| uninitialized reads | the MSan replay (in C++, with an MSan-instrumented libc++) |
| data races | the TSan replay (C only) |
| type confusion | the CFI replay |
| real-time unsafe calls | the RealtimeSanitizer replay |

For a class listed there, the absence of findings says nothing about the target.

## When to use which

| Goal | Use |
|---|---|
| A default sweep | Omit `--sanitizers`: ASan and UBSan in the fuzzed build, and, in `bhf auto`, the MSan and TSan replays. |
| Fewer false positives | Keep ASan and set `ASAN_OPTIONS` ([above](#tuning-sanitizers-with-san_options)), or use `--sanitizers none` for coverage-guided, crash-only fuzzing. |
| A custom static-pool allocator | Keep ASan and call the `bhf_asan.h` hooks, so overflows inside the pool are reported. |
| Leaks | `--sanitizers asan,ubsan,lsan` |
| Fuzzing under MSan or TSan | `--sanitizers msan` or `--sanitizers tsan`, each as a separate campaign |
| C++ type confusion and bad indirect calls | Add `cfi` to `bhf auto --sanitizers`. |
| Interrupt handlers and RTOS tasks that must not block | Add `realtime`, and name the targets with `--nonblocking` when the default entry-point match misses them. |
