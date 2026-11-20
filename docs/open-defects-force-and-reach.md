<!-- SPDX-License-Identifier: Apache-2.0 -->
# `--force` reach: what was fixed, and what bhf still cannot fuzz

These results come from running `bhf auto --force` over 126 real projects and reading the residual blockers. Each item gives the symptom, the root cause, the change, how to verify it, and, where it matters, the explanations that were ruled out.

Read [How `--force` works now](#how---force-works-now) first: several items below depend on it.

---

## How `--force` works now

`--force` used to apply to the whole sweep. Over the 126 corpus projects that had at least one undrivable target, that cost 13 fuzzed targets (214 to 201) and gained one fuzz finding. A forced attempt takes about 36% longer (7.8 s to 10.6 s), so within a fixed `--campaign-time` fewer candidates were attempted. `git/git` went from 10 attempted and 5 fuzzed to 1 attempted and 0 fuzzed.

It now runs in two phases:

1. Phase 1 is always unforced, identical to a run without the flag, so work spent forcing one target cannot starve a target that would have fuzzed.
2. Phase 2 retries, forced, only the targets phase 1 could not fuzz.
3. The forced outcome is kept for every retried target. Because phase 1's fuzzed targets are never retried, `--force` cannot lower the fuzzed count.

On the same corpus the fuzzed count went from 211 to 221 (+10): C +7, Go +3, Rust +1, C# 0, C++ −1. The noise floor is ±3 (re-running the unforced arm alone gave 214 and 211), so only the C and Go changes are above noise.

`--resume --force` over a finished campaign keeps every target that already fuzzed and sends only the rest to phase 2, skipping phase 1 for them because their unforced result is already on disk.

**Keep phase 1 separate from phase 2.** Folding them back into one forced pass is the regression the +10 is measured against.

---

## 1. `--force` could not stub a function returning a struct by value (fixed)

### Symptom

A link error survived `--force`, which stubs whatever the compiler reports undefined. On `nicbarker/clay`:

```
Clay_Raylib_Initialize -> failed_build
  {"kind": "undefined_symbol", "name": "LoadShaderFromMemory"}
```

### Root cause

Twenty other raylib symbols in the same harness were stubbed into `repairs/auto_stubs.c` (all `weak`). The one that stayed undefined differed in its return type:

```c
/* clay/renderers/raylib/raylib.h:1052 */
RLAPI Shader LoadShaderFromMemory(const char *vsCode, const char *fsCode);
```

The others return `void` or scalars. `stub_body_for_return_type` returns a `&'static str`, so it cannot name a type; it declined and emitted no repair, and the link stayed broken.

### Fix

`stub_aggregate_value_return_body` (`crates/c_stub_gen/src/lib.rs`) builds the value: `<Type> _bhf_ret = {0}; return _bhf_ret;`. In C, `{0}` zero-initializes any complete aggregate without `<string.h>`, and zero is the neutral value every other stub returns.

It is used only on the header-backed path, where the stub translation unit includes the declaration's own header, so the type is complete. In the isolated translation unit (which sees only `auto_types.h`), a definition with an incomplete result type is invalid C whatever its body (C11 6.9.1p3), so bhf still refuses there; `isolated_stub_still_refuses_an_aggregate_return` pins that.

### Ruled out

- **The repair budget.** `--max-repair-rounds 30` behaved the same as `4` and printed no "repair cap reached". The planner returned no repair; it did not run out of rounds.
- **The `main` and libc refusal guards** in the `UndefinedSymbol` arm of `plan_repair_forced_with_source_policy`: the symbol is neither.

### Verify

```sh
git clone --depth 1 https://github.com/nicbarker/clay
bhf auto clay --work-dir wk --per-target-time 1 --single-pass --jobs 1 \
  --max-attempts 6 --max-repair-rounds 6 --force
```

Measured: built and fuzzed went from 3 of 6 attempted to 4, with `Clay_Raylib_Initialize` among them and no `{"kind":"undefined_symbol","name":"LoadShaderFromMemory"}`.

---

## 2. Targets that end `unbuildable after N repair rounds`

### Symptom

Across the 126-project forced arm, 297 targets end with a `report_only` blocker reading `forced: unbuildable after N repair round(s) (N residual build error(s) the diagnostic-driven stubbing could not resolve)`. By lane: c 125, cpp 76, go 47, csharp 25, rust 24.

This is a class: whatever the repair loop could not fix. The blocker histogram normalizes text for grouping and does not show causes; those are in each harness's `repairs/*_build_output.log`.

### The enumeration

`benchmarks/campaign-2026-07-25/residual_errors.py` sweeps the corpus forced, collects the `error:` lines from every harness BHF gave up on, and deletes each clone and work dir right away, so peak disk use is one project.

Filter on the outcome before reading the logs. The first version of the script read a `status` key that `result.json` does not have (the outcome is nested), so it collected every harness with an error in its last build log, including ones that ended `built_and_fuzzed`. The repair loop reaches the link stage with symbols still undefined on its way to resolving them, so a successful C harness often leaves `undefined reference to …` behind. That pushed "undefined reference" and "linker command failed" to the top, although all four btop exemplars had ended `built_and_fuzzed` with `retries=1, repairs=[add_source]`.

Filtered to terminal outcomes, over 55 unbuilt harnesses in 26 C and C++ projects:

```
   17  [c:11 cpp:6]  unknown type name '<id>'
   15  [cpp:8 c:7]   use of undeclared identifier '<id>'
    8  [c:5 cpp:3]   expected expression
    8  [c:5 cpp:3]   undefined reference to '<id>' / linker command failed
    7  [c:5 cpp:2]   field has incomplete type '<id>'
    7  [c:7]         cannot combine with previous '<id>' declaration specifier
    5  [c:3 cpp:2]   redefinition of '<id>'
```

`--report <jsonl>` builds the histogram from an existing capture without sweeping. The normalized text is for grouping; open an exemplar's raw log, which the capture keeps as the first six verbatim lines per harness.

### Fixed: the configure-style `#error` guard

Ten of the 104 harnesses in the first capture stopped at a header's own `#error`, with nothing missing from the tree:

```
/libssh/include/libssh/priv.h:45:4:   error: "no strtoull function found"
/libssh/include/libssh/priv.h:198:4:  error: "Your system must provide a __func__ macro"
/MagickCore/magick-config.h:70:3:     error: "you should set MAGICKCORE_QUANTUM_DEPTH"
```

A real `./configure` would have defined the macro the guard tests. No header, type or symbol repair applies, so those targets used up every repair round and ended report-only. `ConfigGuardError` now classifies the diagnostic (both gcc's `error: #error "..."` and clang's `error: "..."`), and the planner finds the conditional that owns the `#error` and defines the macro that makes that branch dead, with the value the guard requires. The outermost negative feature-test wrapper wins over the innermost branch: libssh nests the chain inside `#if !defined(HAVE_STRTOULL)`, and taking the inner branch would define `HAVE___STRTOULL`, which aliases `strtoull` to a symbol this host lacks and trades one `#error` for an undefined reference. A guard bhf cannot decide is refused.

Measured with `config_guard_ab.sh` (two pinned binaries, the two corpus projects with this class): the guard diagnostics are gone from every build log, and report-only targets rise (WindTerm 3 to 6, ImageMagick 1 to 4), so more targets reach the static-only floor. Within a 90-second campaign neither project gains a fuzzed target: behind the guard is a different class (absent crypto libraries in WindTerm, a missing generated `magick-baseconfig.h` in ImageMagick).

WindTerm's later `unknown type name 'bignum'` and `'MD5CTX'` errors come from `#ifdef HAVE_LIBGCRYPT` / `HAVE_LIBCRYPTO` blocks over absent libraries, a missing dependency, not the guard.

### Fixed from the exemplars

Reading the exemplars found five more defects, four of them in bhf:

- **`--force` emptied the missing-dependency manifest.** The forced degradation to report-only replaced the diagnostics with a count, and a report-only outcome has no `last_errors` for the manifest to read. tmux reported "4 still blocking" unforced and "No external dependencies were missing" forced. The unresolved type names now carry across the degradation; `auto_force_keeps_manifest.rs` pins it.
- **Macro templates discovered as targets.** BSD `<sys/tree.h>`'s `RB_GENERATE_INSERT` defines a function body inside a continued `#define`, where `attr`, `type` and `name` are macro parameters. This was seven dead targets in tmux, each ending `cannot combine with previous 'type-name' declaration specifier`: the whole of that histogram row.
- **Macro invocations discovered as targets**, such as Linux's `TRACE_EVENT(...)` (two in lede). With the item above, 139 pseudo-targets left the ranked list.
- **The Win32 pack redefined the tree's own typedefs.** lede's MediaTek Linux driver defines `CHAR` and `_LARGE_INTEGER`, and the force-included pack redefined them. That was the whole `redefinition of` / `typedef redefinition` row.
- **A CamelCase export macro leaked into the generated C harness** (ImageMagick's `ModuleExport` at `main.c:49`), the C counterpart of the C++ decoration leak fixed in 0.2.21. It also caused the follow-on `expected ';' after top level declarator` rows.

### What is left

Most of the remaining `unknown type name` and `use of undeclared identifier` rows are types behind absent third-party SDKs: libssh's `MD5CTX`, `SHACTX` and `bignum` behind `HAVE_LIBGCRYPT`, Qt's `QRect` (QtScrcpy `H-X0038`), protobuf's `Message`, JNI, libevent, and Win32's `LONG`, `UINT32` and `HRESULT`. Those are missing dependencies: the fix is to provide them, and the missing-dependency manifest now lists them under `--force` too.

To find the next class, re-run the capture (about an hour for 53 projects), fix the largest class, measure again, and repeat. The capture is not committed, because it measures one binary at one moment and a stale copy makes a fixed class look open.

---

## 3. `--force` outside C, C++ and Ada: Go and C# done, Rust open

### Symptom

`unsupported_params` survived forcing on three lanes. From the forced arm's residual blockers:

| Lane | Targets | Shape |
|---|---:|---|
| Go | 116 | 58 undrivable parameter types, 23 methods, plus Go-version and no-`go.mod` |
| Rust | 64 | 37 no byte decoder, 16 target kind, 11 private-module trait impl |
| C# | 31 | Receivers that cannot be constructed (instance method, no usable constructor) |

Go's undrivable count was the same, 219, in both arms: nothing attempted it.

### Go and C#: done

Both lanes now have a counterpart of the C family's `best_effort_param_emission` (`crates/harness_gen/src/c_generate.rs`): a driver that compiles, without aiming for correct values.

- **Go** (`crates/cli/src/auto/go_build.rs`): an undrivable parameter becomes its type's zero value. Every Go type has one, so the only thing that can fail is naming the type from the harness package. An exported target type gains the `tgt.` qualifier; a predeclared name, or a qualifier into a package the harness already imports, is kept; an unexported, generic, variadic or inline-literal spelling is refused. A method is called on a zero receiver with `(&recv).M(...)`, which works for pointer and value receivers. A nil `*T` is not used, because it panics as soon as the method touches a field, and that panic would come from bhf, not the target.
- **C#** (`crates/cli/src/auto/csharp_build.rs`): a receiver type whose only constructors take parameters or are private is allocated without running one, through the runtime's `GetUninitializedObject`, resolved by reflection so the shim compiles on any target framework (the method moved namespace in .NET 5). An abstract type or interface is still refused: there is no instance to allocate.

A fabricated value can panic by itself, so a target built this way records a `ForcedSyntheticParams` repair that names what was synthesized. The report floors its findings to Low with the forced note in `fidelity.caveats` and counts it in `summary.forced`, as for a stub-only C build. **Keep that coupling**: without it a forced nil-map panic would read as a confirmed CWE-476.

### Rust: open

The three Rust shapes are separate problems:

- **"no byte decoder for T" (37)** follows from the type system. Rust has no universal zero value, and `T::default()` compiles only if `T: Default`, which codegen cannot test without type resolution. Emitting it anyway trades a clean skip for a `failed_build` and a wasted build; measure before treating that as an improvement.
- **Target kind (16)** and **private-module trait impl (11)** are separate known gaps, not parameter problems.

### Go environment blockers

"no `go.mod`" and "requires go >= X" are toolchain problems that `--force` cannot change. They are counted in the 116 above; subtract them before you state a target number.

---

## Re-measuring

The scripts live in `benchmarks/campaign-2026-07-25/`. Set `BHF_BIN` (for `launch_force_ab3.sh` and `run_sweep.py`), or `BEFORE` and `AFTER` (for `config_guard_ab.sh`), to the pinned binaries you are comparing.

```sh
# The forced arm, limited to the projects a force flag can move.
sh launch_force_ab3.sh                       # writes results-force3/
python3 force_delta.py --baseline results-plain2 --forced results-force3

# What the forced arm could not build, by compiler diagnostic.
python3 residual_errors.py --lanes c,cpp --limit 40 --out residual-c-cpp.jsonl
python3 residual_errors.py --report residual-c-cpp.jsonl

# A/B a fix whose class is already identified, on the projects that have it.
sh config_guard_ab.sh
```

`force_delta.py` separates real fuzz reach from stub-only reach, and fuzz findings from static findings. Report deltas from that split: `summary.findings` counts report-only static findings together with runtime crashes, and the total made the global-force arm look like "+376 findings" when its fuzz findings had not changed.

### Measurement rules

- **Run both A/B arms on the same binary.** Copy it out of `target/release/` and pass it explicitly; a sweep pointed at `target/release/bhf` while you rebuild changes binary mid-sweep.
- **Tell binaries apart by checksum.** Builds from the same commit report the same `bhf --version`.
- **Match the measurement to the claim.** A whole-corpus A/B takes an hour and has a ±3 noise floor. For a class as narrow as the `#error` guard, running the projects that show it under two pinned binaries answers the question in minutes.
- **`--repos <file>`** limits a wave to the projects a flag can move (126 of 226 here). Do not combine it with `--corpus-only`, which drops pool replacements and shrinks the set to 124.
- **`--results-dir`** keeps an A/B from overwriting its baseline.
- **Do not edit source while `cargo test --workspace` runs**: the transient compile error shows up as a test failure.
- **Use `--no-fail-fast`**, or the suite stops at the first failing binary and under-reports the failures.

---

## The phase merge rule

An earlier version of the two-phase merge kept phase 1's outcome unless forcing fuzzed the target, on the grounds that a forced `report_only` says less than an unforced `failed_build` that names a real error. That suppressed the result the operator asked for and broke two tested contracts (`force_bypasses_cpp_only_class_pre_skip_gate` and `unbuildable_target_degrades_to_report_only_under_force`). The targeted force tests passed; only the full suite caught it. Phase 2 now prints its own blocker histogram, which keeps the diagnostics visible.
