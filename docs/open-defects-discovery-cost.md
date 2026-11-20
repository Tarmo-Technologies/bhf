<!-- SPDX-License-Identifier: Apache-2.0 -->
# Discovery cost: what a huge C++ file cost, and what fixed it

All measurements here come from the 2026-07-27 re-run of the 500-project sweep (`benchmarks/campaign-2026-07-25`, `results-0727/`). Both defects in this class are fixed. The page keeps the measurements because the method that isolated them applies to the next instance.

---

## Context: how the class was found

The sweep's `--problems` list showed 22 projects ending `exit=-9` with `timed_out=False` (SIGKILL with no timeout, 44 to 250 seconds in) and 14 more ending at the 510-second campaign ceiling. All but three were C++.

In the sweep harness `exit=-9` has two causes: `timed_out=True` is the harness's own kill, and `timed_out=False` is the kernel. The cgroup counter `/sys/fs/cgroup/user.slice/memory.events` confirmed the kernel (`oom_kill 46`). The kernel log was not readable on that host; on a host without `dmesg`, use the cgroup counter.

The kills were not caused by running six projects at once on a 13 GB host. One run alone on an idle host reproduced the memory use:

```
bhf auto simdjson            (39 MB tree, alone, idle box)  12.4 GiB  OOM-killed
bhf list targets simdjson                                    225 MiB  ok
bhf static-scan simdjson                                      70 MiB  ok
```

**Measure one run alone before blaming the runner.**

---

## 1. A cyclic construction recipe recursed forever (fixed)

### Root cause

`crates/harness_gen/src/cpp_decoders.rs`, in the class-construction recipe block, relied on this invariant in a comment:

> The recipe is only registered for the target's DIRECT opaque-class parameters, so a constructor's argument types are always directly decodable — the recursive arg decode below terminates immediately.

The producer graph (`resolve_cpp_parameter_constructions` in `crates/cli/src/generate_harness.rs`) made that false. It resolves what a chosen constructor's own arguments need, to a fixed point; its own comment says the graph is cyclic (`A(B)`, `B(A)`) and that `MAX_PRODUCER_DEPTH` makes it terminate. The consumer had no such bound, so following one recipe into the next never returned and allocated a decode statement per frame.

### Fix

The decoder now carries the chain of class keys it is expanding. A key already on the chain means the recipe needs a value it is still producing, so that parameter falls through to the ordinary opaque skip. The cut is on cycles, not depth: a three-deep acyclic chain still resolves, and a type reached twice by different paths is not a cycle. The test `a_cyclic_construction_recipe_terminates_instead_of_recursing` pins both.

### How it was isolated

The bisect alone was misleading, so the steps are worth reusing:

1. A stage bisect (`list targets` against `auto --list-targets` against `static-scan`) put the cost inside `auto`'s discovery.
2. A directory bisect showed `include/` and `src/` together blowing up while each alone used 20 MiB, a cross-file signature; a file bisect then named `src/generic/stage2/tape_builder.h`. **Both results were the last straw, not the cause**: the file was fine on its own, and the "culprit" pair did not reproduce in isolation.
3. RSS probes printed before each stage, then before each file, then inside the per-function loop, found it. Print the probe *before* the work: the offending call never returns, so a probe after it prints nothing.

The trigger was `stage2(dom::document &_doc)` in `simdjson/src/rvv-vls.cpp`, the first function in that tree whose parameter resolved a non-empty recipe set.

---

## 2. The preflight recomputed per function what it had already computed (fixed)

### Symptom

With the memory fixed, simdjson still could not be swept, because discovery did not finish. The cost was in one directory:

```
list targets   simdjson/singleheader/  (7.7 MB simdjson.h + 2.7 MB simdjson.cpp)   145 s
auto           simdjson/singleheader/                                            > 1500 s (killed)
auto           simdjson minus singleheader/                                         59 s
```

`list targets` and `auto` parse the same files, so the difference was work that `auto` adds.

### Root cause

Two loop-invariant computations ran inside per-function loops. Profiling found them; the first guess, `find_cpp_factory_for_class` scanning every function, looked quadratic but was not the cost.

- **97% was `recipe_mining::for_source`.** The recipes are cached by project root, but a cache hit returned a clone of the whole map, one entry per constructible class in the project. Called once per function, that took 133 of the preflight's 137 seconds on the 2,863-function `simdjson.cpp`. The map is now shared through an `Arc` and fetched once, outside the loop.
- **The rest was `cpp_class_is_default_constructible` re-parsing the closure.** It took the include-closure texts and ran `collect_cpp_class_info_for_harness` on them per call, inside a per-parameter loop whose caller had already computed that result: 7.7 MB of C++ re-parsed per opaque parameter. It now takes the class info the caller collected, which gives the same answer.

### Measured

| | before | after |
|---|---:|---:|
| preflight, `simdjson.cpp` (2,863 fns) | 137 s | 3.9 s |
| preflight, `simdjson.h` (10,894 fns) | never finished | 9.5 s |
| `auto --list-targets`, whole `singleheader/` | >1500 s (killed) | **218 s**, 250 MB |

The remaining time is mostly the tree-sitter parse of the 7.7 MB header.

### Alternatives not taken

The preflight is advisory: its only effect is `KNOWN_UNBUILDABLE_SIGNATURE_DEMOTION`, a rank demotion for signatures that harness generation would refuse anyway. Capping it by function count, with a logged skip, was the cheap alternative. Once the real cost was measured the cap was unnecessary, and it would have reported functions as checked that were not.

Do not handle a future instance by excluding amalgamated headers from discovery. sqlite's `sqlite3.c` and simdjson's `simdjson.h` are what many projects ship, and `dedup_amalgamated_single_header` keeps their targets from being counted twice instead of dropping them.

---

## Re-measuring

Run one `bhf` alone on an idle host and record the peak RSS of its whole process tree, for example by polling `/proc/<pid>/statm` for `bhf` and its children.

To find the stage, run these three over the same tree. Their cost should be within an order of magnitude of each other; when `auto` is far above the others, the extra is work only `auto` does.

```sh
bhf list targets <tree> --format json --top 5
bhf static-scan  <tree> --out /tmp/s
bhf auto         <tree> --work-dir /tmp/w --list-targets
```

`--list-targets` returns right after discovery and ranking, so it measures discovery without build or fuzz time.
