<!-- SPDX-License-Identifier: Apache-2.0 -->

# libFuzzer feature parity (built-in engine)

bhf's built-in engine is coverage-guided and runs offline without the libFuzzer in-process runtime. C/C++ harnesses are compiled with the system clang's sanitizer instrumentation (SanitizerCoverage for coverage, ASan for memory errors), and bhf supplies its own mutator and coverage feedback. This page maps the libFuzzer options you know from `clang -fsanitize=fuzzer` to their bhf equivalents. Options are `bhf fuzz` flags unless marked `auto`.

## Flag mapping

| libFuzzer | bhf | Notes |
|---|---|---|
| `-max_len=N` | `--max-len N` | Maximum generated input length. Default 4096. |
| `-len_control=N` | `--len-control N` | Adaptive length growth: the effective mutation length starts small and doubles toward `--max-len` after `N` executions without a new corpus signature. `0` disables it. Default 100. |
| `-timeout=N` | `--timeout 10s` | Per-input timeout for C/C++ harnesses (default 10s). The slow input is killed, and one that hangs again at twice the timeout is a hang finding (BHF-230), as libFuzzer saves a `timeout-` unit. Separate from `--time`, the whole-campaign budget. The Ada lane bounds runaway inputs with CPU rlimits. |
| `-rss_limit_mb=N` | `--rss-limit-mb N` | Per-input RSS ceiling. RSS is polled from `/proc/<pid>/statm`, and a breach is reported as an out-of-memory finding. For `bhf fuzz`, `0` (the default) disables it. `bhf auto` defaults to a quarter of available host or cgroup memory, clamped to 512–8192 MiB. bhf polls RSS instead of setting an `RLIMIT_AS` cap, which would break ASan's large virtual-address reservation. |
| `-print_final_stats=1` | `--print-final-stats` | End-of-run summary: executions, exec/s, new and duplicate corpus signatures, findings, elapsed time. |
| `-runs=N` | `--iterations N` | Execution cap. Defaults to 256 when neither `--iterations` nor `--time` is given. |
| `-max_total_time=N` | `--time 30s`; `auto --per-target-time N` | `--time` is the whole budget of one manual `fuzz` run. Under `bhf auto`, `--per-target-time` (default 60 s) is each target's total fuzz wall-clock time, split evenly across the three passes (empty, rng, fuzz-driven) under one shared deadline, so a target takes about this long whatever the pass count. AFL++'s `-V` is the same knob. |
| stop on first crash | `auto --per-target-finding-count 1` | Stops a target as soon as it has produced N distinct crash signatures (checked mid-pass; the remaining passes are skipped), or when its `--per-target-time` is spent. Unset (the default), every finding within the budget is collected. |
| (whole-run cap) | `auto --campaign-time S` [+ `--min-target-time M`] | Wall-clock cap across all targets. With `--min-target-time`, the budget is split evenly across targets with a per-target floor instead. |
| `-jobs=N` / `-workers=N` / `-fork=N` | `--workers N\|auto`; `auto --workers-per-target N` | Multicore campaign. Per-input length, timeout and RSS limits are passed to every worker, and the workers share new corpus entries as they run (every `BHF_SYNC_INTERVAL_MS`). `bhf auto --workers-per-target N` runs each target's built-in passes this way and merges the workers' queues into the target's corpus. |
| `-dict=FILE` | `--dict FILE` | An AFL/libFuzzer dictionary (`name="token"` lines, `\xNN` escapes) whose tokens the mutator splices into inputs, on top of the harness's own `dictionary.txt`. bhf also mines a dictionary from string and byte literals and from recovered comparison operands (`--cmplog-log`). |
| `-use_value_profile=1` | cmplog / RedQueen (`--cmplog-log`) | See [Value profile compared with cmplog (RedQueen)](#value-profile-compared-with-cmplog-redqueen). |
| `inline-8bit-counters` / AFL `COUNT` buckets | always on (C/C++ driver) | Edge hit counts are bucketed (`1, 2, 3, 4-7, 8-15, …`), so a deeper loop or recursion is new coverage, beyond edge presence. |
| `-fsanitize-coverage=stack-depth` (libFuzzer's stack-depth feature) | always on (C/C++ driver) | An input that recurses deeper than every one before it is kept on the same edges, and a mutator doubles its run of a nesting opener, so unbounded recursion reaches a BHF-207 stack overflow. `BHF_DISABLE_STACK_DEPTH=1` turns it off. |
| laf-intel comparison split | `auto --comparison-progress` | Opt-in leading-byte-match gradient on multi-byte gates; a `bhf auto` flag. See below. |
| `-merge=1` | `bhf corpus merge` (duplicates by content) / `bhf corpus minimize --harness` (coverage-minimal) | `merge` removes duplicates by content. `minimize` replays each input in a fresh process with the harness's coverage map, and keeps only the inputs that reach an edge no earlier input did (in every lane whose driver writes the map: C, C++, Python and the other bhf-built lanes) or that add a new event-log signature (Ada). A map whose edges differ between two runs of one input is not used. For a harness that records neither, every input is copied through and the command exits `2`. |
| `-minimize_crash=1` | `bhf minimize` | Shrinks a crashing input by binary search while keeping the finding. |
| `-seed_inputs` / corpus dir | `--seed-input` / `--seed-file`; `auto --seed-file` / `--seed-dir` | Seed corpus. |
| `-detect_leaks=1` | `--sanitizers lsan` | Part of the sanitizer matrix (asan, msan, ubsan, tsan, lsan) for native C/C++ harnesses; every other lane has its own instrumentation. Cross-compiled and emulated targets run without host sanitizers (ASan's shadow memory does not survive qemu-user or wine), so the matrix does not apply and the run uses its portable feedback path. |

## Coverage granularity

The C/C++ driver tracks four coverage channels: edge presence (`trace-pc-guard`), AFL-style logarithmic hit-count buckets (the equivalent of libFuzzer's `inline-8bit-counters`), the opt-in laf-intel comparison-progress gradient (`--comparison-progress`), and the deepest stack an execution reached (libFuzzer's stack-depth feature). An input is kept in the corpus if it advances any of the four.

The Ada lane is coverage-guided too. An instrumented Ada harness is compiled with `-fsanitize-coverage=trace-pc` (GNAT/GCC rejects `trace-pc-guard`), which feeds the same edge bitmap and a bounded persisted corpus. The source is rewritten with breadcrumb probes at exception handlers and `raise` statements, which feed an exception-signature signal alongside edge presence. Ada coverage is edge presence only; the hit-count-bucket and comparison-progress channels belong to the C, C++ and Rust lanes. After the sweep, `bhf auto` replays an Ada harness's corpus and reports the lines and subprograms its edges reached, in the format of the C/C++ report (`results/coverage/<id>/`, see [Auto](auto.md)). A `trace-pc` edge is placed on its Ada line with `addr2line`, and on the original source's line through the instrumented copy's line map.

## Rust and Java coverage

Rust and Java targets use the same built-in engine and corpus handling. Rust harnesses are built as SanitizerCoverage+ASan static libraries linked to the same C fork-server driver, so they get the same coverage channels as C/C++. Java bytecode is instrumented by bhf's own ASM agent, which feeds edge coverage into the same engine; the Java lane has the edge map only.

## Value profile compared with cmplog (RedQueen)

libFuzzer's `-use_value_profile` turns each comparison into an approximate coverage signal: an input that brings a comparison's operands closer is rewarded even when it never satisfies the branch, which helps the mutator climb past multi-byte comparisons and checksums.

bhf reaches the same goal through cmplog/RedQueen rather than a distance signal. Comparison operands are captured two ways and fed to the mutator:

- **String and buffer gates** (`memcmp`, `strcmp`, `strncmp`, …): the generated driver defines the ASan `__sanitizer_weak_hook_*` family, which ASan's interceptors call with both operands (no libFuzzer runtime needed). The LD_PRELOAD runtrace shim records the same under `BHF_CMPLOG=1`, in the harness's own processes only (`BHF_TARGET_EXE`), not in a shell the harness runs. When the driver's site-tagged records are present, the shim's untagged ones add no dictionary tokens.
- **Scalar and character gates** (`*c == '{'`, integer `==`, `switch`): the driver is compiled with `-fsanitize-coverage=trace-cmp`, and its `trace_cmp*` and `trace_switch` callbacks record the integer operand pairs.

Both feed a per-execution operand ring (`BHF_CMP_SHM`). The engine arms capture for the one corpus entry it is about to mutate, runs it once, and turns the operands it observed into mutations two ways:

- a **dictionary insert** of each operand (position-independent), and
- an **offset-aware RedQueen splice** that replaces `operand_a` with `operand_b` at the exact offset `operand_a` appears in that input (input-to-state).

Capturing operands per input (against the entry being mutated, not a global pre-mined pool) lets the splice find `operand_a` at the offset the parser compared it, so one mutation passes one gate. Before capturing, the entry is colorized: its coverage-irrelevant bytes are randomized to near-unique values while its edge footprint is preserved, so single-byte and short operands splice at the right offset instead of at every occurrence of a common byte.

This is operand-level feedback rather than gradient-level feedback. Instead of nudging an input toward a comparison value over many generations, bhf injects the observed value directly. That clears the magic-byte, header, keyword and checksum cases libFuzzer's value profile targets, often in a single mutation. Where a gradient still helps, the opt-in `--comparison-progress` flag adds a laf-intel-style channel on the C/C++ driver: the driver records, per compare site, the longest leading-byte prefix an input matched, and the engine rewards an input that matches one more byte of a multi-byte gate.

That leaves transformed comparisons, where the magic value is a function of the input that never appears verbatim as an operand (`crc32(buf) == K`, `a == (b ^ K)` where the compiler folds the operand into a derived form, length or hash arithmetic). Neither input-to-state splicing nor leading-byte comparison progress can synthesize those. For C/C++, `bhf auto --symcc` adds a hybrid concolic loop. Each harness also builds with SymCC (`main_symcc`). When a built-in pass's corpus stops growing, its newest entries run through SymCC, which solves the branch conditions they reached and writes an input for each branch it can flip. Those inputs run next in the pass and stay in the corpus when they add coverage, as AFL++'s SymCC custom mutator and LibAFL's concolic stage feed theirs. SymCC is GPL-3.0 and runs only as a subprocess, under a license profile that permits it (see [Licensing](licensing.md)).
