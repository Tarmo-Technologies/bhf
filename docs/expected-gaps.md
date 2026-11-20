<!-- SPDX-License-Identifier: Apache-2.0 -->
# Measured Gaps: Targets bhf Does Not Fuzz Yet

This page lists each class of target that bhf skipped or failed to fuzz in the
500-project sweep, with its size, its cause and a verdict. It was first sized
from `benchmarks/campaign-2026-07-25/results-0727/` (439 projects measured,
3,420 targets attempted, 983 built and fuzzed).

**Re-measured 2026-07-28** over a full 500-project sweep
(`results-0728/`: 457 projects measured, 1,182,129 targets discovered, 3,449
attempted, **984 built and fuzzed, 28.5%**, 329 findings, all 16 lanes). The
class shape below is unchanged; see [What the 2026-07-28 sweep
changed](#what-the-2026-07-28-sweep-changed) for what it added and closed.

Both figures are scored over the 500 repositories pinned in `corpus.tsv`, the
basis [`docs/site/sweep-500.md`](site/sweep-500.md) publishes. A bare
`aggregate.py` over those directories also rolls up rows for repositories the
lane check later replaced, which reads higher (482 projects and 29.4% for
`results-0728/`); the
[campaign README](../benchmarks/campaign-2026-07-25/README.md) explains the
difference.

Counts are targets, from the sweep's residual-blocker histogram. They were
produced by the binary from **before** the 2026-07-27 fixes. A class fixed
since is marked **[FIXED]**, and its count is what it cost before the fix.
The other entries keep the classification recorded in that sweep.

Each class carries a verdict:

- **GAP**: a limitation in bhf, fixable in bhf. These make up the work list.
- **DEPENDENCY**: the code needed is not in the tree. bhf names it in the
  missing-dependency manifest; installing the dependency fixes it.
- **ENVIRONMENT**: a fact about the host's toolchain, such as a compiler
  version or an SDK ceiling.
- **BY DESIGN**: bhf refuses the target on purpose, and the reason is stated.

---

## The shape of the loss

Of 3,594 attempted targets, 2,537 did not fuzz (1,057 fuzzed, 29.4%: the
all-rows basis described above). Approximately:

| | targets | share |
|---|---:|---:|
| DEPENDENCY — a package/header/SDK that is not in the tree | ~1,050 | 41% |
| GAP — bhf cannot drive or build it yet | ~1,180 | 47% |
| ENVIRONMENT — toolchain version, SDK ceiling | ~110 | 4% |
| BY DESIGN — legacy dialect, report-only | ~45 | 2% |
| Fixed since this measurement | ~150 | 6% |

**The largest fixable group is undrivable parameters, ahead of failed
builds.**

---

## C

### C-1. Opaque type needs lifecycle support — 86 — **[PARTLY FIXED]**

The biggest single C gap. Sub-shapes:

| | count | what it is |
|---|---:|---|
| `opaque type X for parameter X` | 31 | a by-value type the tree never defines |
| `opaque type X for pointer parameter X` | 28 | pointer to same |
| `opaque handle X … incomplete in the harness's included headers` | 13 | **the full definition IS in the tree, in a non-included `.c`** |
| `pointer parameter X … not safely drivable after struct synthesis` | 7 | synthesis produced something unsafe to point at |
| `decoder … exceeds 65536 bytes after struct synthesis` | 6 | a legitimately huge aggregate |

The 13 "incomplete in the harness's included headers" cases look the most
tractable. The refusal message ("its full definition is visible only in a
non-included source") describes the tree; bhf does not hold that definition
at that point. The harness's `type_defs` are the included headers plus the
tree-wide flat-POD fallback, never the target `.c`'s own body
(`header_complete_aggregate_spellings`), so the complete struct is not in the
registry when bhf refuses.

Copying the private struct into the harness translation unit is the fix:
completing an incomplete type is legal C, and the layout matches because the
text is the project's own. It needs the tree-wide struct definitions passed
down to the decoder first, which is a feature in its own right.

`git`'s `struct repository`, timescaledb's `CompressionSettings` and antirez/ds4's
`ds4_session` are the worked examples.

**Partly fixed since.** A handle whose full definition is in the target's
**own** `.c` (antirez/ds4's `struct ds4_session`, at ds4.c:47656 beside the
target) is now completed through the whole-TU `#include` of that source, when
the headers do not define it and the tree has no constructor that returns
one (`generate_harness.rs`, the private-handle path). A definition in a
**different** non-included `.c` still needs the tree-wide plumbing above.

### C-2. `missing header` (26) / `missing type` (31) / `undeclared function` (20) — **mostly DEPENDENCY**

These remain after the repair loop gives up. Spot-reading them in the
previous campaign found mostly absent SDKs: libevent, Qt, protobuf, JNI,
Win32. The manifest reports them. A minority are bhf's own; read their
exemplars' build logs to find them.

### C-3. K&R C — 21 — **[FIXED]**

A K&R definition is now fuzzed through the prototype its parameter
declarations give, each parameter at its promoted type (#283). Re-running the
sweep's 20 C-3 targets left none report-only as K&R C. Only 6 were K&R
definitions: 2 built and fuzzed, 1 built without an input reaching the target,
2 stop at zlib's `#define local static` (#415) and 1 is compiled out. The other
14 were ANSI C that the July extractor misread, and now stop where other C
targets stop. See [the re-run](validation/2026-11-18-c3-knr.md).

### C-4. `build abandoned after N repair rounds: --campaign-time exhausted` — 10 — **ENVIRONMENT**

The campaign budget ran out during build repair, and bhf reports it as a
cut-off. Raise `--campaign-time`.

---

## C++

### C++-1. `blocked_by_non_self_contained_header` — 49 report-only + 10 in C — **[FIXED]**

A header that cannot be included by an independent translation unit. The
unforced default refused these without trying (`--force` already bypassed the
gate: clay went 0 → 3 fuzzed that way). It now falls back to the header's
owner translation unit, adopted only when it preflight-compiles; see [What the
2026-07-28 sweep changed](#what-the-2026-07-28-sweep-changed).

### C++-2. Unconstructible class — 30 — **GAP**

"no public default constructor, no supported public constructor, and no
factory". The producer graph resolves constructor arguments to a fixed point
already; these are what it still cannot reach.

### C++-3. No byte-buffer decoder — 33 — **GAP**

The auto-harness drives scalars, strings and visible aggregates. What is left is
templates, non-visible aggregates and library types.

### C++-4. Return type undefined in the scanned tree — 16 — **DEPENDENCY**

An external SDK or framework type (MFC, a vendor CORBA IDL). bhf reports
these targets and does not fuzz them.

### C++-5. Member of a class defined only in a `.cpp` — 4 — **GAP**

Same shape as C-1's "definition is in a non-included source", in C++.

### C++-6. `compile flag contains a shell/make metacharacter` — 6 — **[FIXED]**

A flag that is safe once single-quoted is now quoted rather than refused (an
apostrophe in it is written `'\''`); `$`, `#` and a newline are still refused,
and paths/include names stay strict.

### C++-7. `linker command failed` — 10 — **GAP or DEPENDENCY**, unsplit

Needs the exemplars read. Terminal link failures after repair.

---

## Ada

### Ada-1. `1 undefined symbol(s) after repair` — 33 — **GAP**

The largest Ada class. The repair loop stubs Ada units and C symbols but ends
with one symbol unresolved.

### Ada-2. `missing Ada symbol` — 19 — **GAP**

### Ada-3. `unit X cannot belong to several projects` — 9 — **[FIXED]**

BHF's own project synthesis, not the target's. Reproduced on
mk270/whitakers-words, where each of `commands.gpr`, `words_engine.gpr`,
`support_utils.gpr` and `latin_utils.gpr` owns its `src/<name>` directory and
`with`s the next. bhf staged instrumented copies of the target's closure,
units of the withed projects included, and built with a project extending the
target's own, so `support_utils.uniques_package` had two owners: the copy and
`support_utils`. (`extends all` does not fix it; that was tested.)

The units of the projects the governing one `with`s are now left to those
projects, uninstrumented, and copies an earlier target staged of them are
removed (#287). `"src/" & project'Name` is evaluated, so the project that owns
the target's source governs its build, and a library project's build stands
alone. Re-running the sweep's 10 Ada-3 targets (8 subprograms) built and
fuzzed 7 and left none on this reason. The eighth now stops in its own
harness, which gives a record's string and enumeration components integer
literals (#418). See [the re-run](validation/2026-11-18-ada3-withed-projects.md).

### Ada-4. `predefined unit depends on itself` — 9 — **[FIXED]**

Same family: a staged copy of a predefined unit shadowed the real one. A tree
that vendors its own GNAT runtime (`Ada`, `System`, `Interfaces`, `GNAT` and
their children) had those units staged and compiled in place of the host
compiler's, which they do not match. They are now left to the compiler's
runtime (#356). Re-running the sweep's 9 Ada-4 targets (8 subprograms, all in
one freestanding kernel) built all 8 and fuzzed 7; the eighth builds, but no
input reached it. See
[the re-run](validation/2026-11-18-ada4-vendored-runtime.md).

### Ada-5. `named type X is not declared in the parsed source set` — ~10 — **GAP**

`Char_Array`, `Lsp.Json_Streams.Json_Stream`, `St7735r_Bitmap_Buffer`. A type
whose declaration is outside the parsed set and which has no synthesizable
constructor.

### Ada-6. `blocked_by_generic` — 1 — **GAP**

A generic subprogram with a parameter that has no default.

---

## Go

### Go-1. Undrivable parameter type — 58 — **GAP**

`*protocol.RequestHeader`, `*pflag.FlagSet`, `DecodeOptions`, `context.Context`,
`*zap.Logger`. Under `--force` these become zero values; unforced they skip.
**`context.Context` is [FIXED]**: it is call context, not fuzz input, and now
decodes to `context.Background()` (never nil, which would panic the callee). The
rest are genuine project/library types.

The [2026-11-16 re-sweep](validation/2026-11-16-go-resweep.md) re-ran by name
the 59 targets the July sweep skipped here: 7 now build and fuzz (on Go 1.27.4;
6 of them need a newer `go` than 1.22.2), and 52 remain.
- 24 take a pointer to a struct.
- 15 take a named type of another package.
- 8 take a named type of their own package.
- 5 take a map or a slice of a non-byte type.

Several of the named types are a basic type underneath (`type DeviceID
[32]byte`), which decoding through the underlying type would drive.

### Go-2. Method needs a receiver — 24 — **[FIXED]** for a sibling constructor

Said "pass `--force`", whose zero receiver (taken by address so `(&r).M()` is
valid for both value and pointer receivers) still works. A REAL receiver from
a sibling `func NewT() *T` is now attempted unforced, which is what a human
would write: `go_parser::GoFunc` records its return type (`returns`), and the
Go lane finds the package's constructor for the receiver type
(`find_go_constructor`). For `func NewParser() *Parser` beside
`func (p *Parser) Parse(data []byte) int`, `bhf auto` without `--force` builds
and fuzzes `Parse`. A receiver with no such constructor still skips unforced.

### Go-3. `not inside a Go module (no go.mod)` — 17 — **[FIXED]**

A package outside every Go module: a GOPATH-era tree, or a dir of `.go` files
run with `go run`. The harness imports its target through a module `replace`,
which needs a dir with a `go.mod`. bhf now copies the package into the harness
dir with a `go.mod` of its own; the scanned tree is not written to.
- A `package main` is renamed in the copy, so it can be imported.
- A dir of `go run` scripts, each with its own `main`, is no package at all,
  so only the target's file is copied.
- `//line` directives keep a finding on the project's file and line.

The [2026-11-16 re-run](validation/2026-11-16-go3-loose-packages.md) of the 17
targets by name: 15 build and fuzz. The other 2 are SWIG bindings and fail
for want of `swig` (ENVIRONMENT). The copy is one dir: a GOPATH tree's other
packages, imported by their GOPATH paths, are resolved as modules, and a build
fails when no module provides them.

### Go-4. `requires go >= X` — 135 of 261 on Go 1.22.2 — **ENVIRONMENT**

Under `GOTOOLCHAIN=local`. There is already an overlay that lowers the directive
and retries; these are the ones where that is not enough: a dependency needs
`go >= 1.23` to `go >= 1.26.4`. The
[2026-11-16 re-sweep](validation/2026-11-16-go-resweep.md) measured 135 of the
261 attempted targets here on the host's Go 1.22.2, and none on Go 1.27.4, where
146 built and fuzzed against 26. A current `go` on `PATH` is the fix.

### Go-5. A package `init` panics on this Go release — 1 — **ENVIRONMENT**

v2ray-core's `qtls-go1-15` dependency panics in its `init`
(`qtls.ClientSessionState doesn't match`) on any Go but the release it was
written for, so the harness dies before `main` on every input. The
[2026-11-16 re-sweep](validation/2026-11-16-go-resweep.md) counted it as a
finding. The build now starts each Go harness once without an input, and a
failure there is reported as `built_not_entered` (`target_environment`),
naming the package and the panic, with no finding (#398). The Go release the
project supports is the fix.

### Go-6. A `Must` function's documented panic — 9 findings — **[FIXED]**

terraform's `MustParseHash`, `MustParseVersion` and `MustParseProviderPart`,
etcd's `MustUnmarshalMessage`, headscale's `MustParseNodeID`, multica's
`MustParseUUID`, and gin's `LoadHTMLGlob` through `template.Must`. Each of
these panics on input it rejects, by contract; the caller promises valid
input, usually a constant. This is the Go analogue of Rust-3. In the
[2026-11-16 re-sweep](validation/2026-11-16-go-resweep.md) all 9 were
reported as findings. When the fuzz target is a `Must` function, the
generated harness now treats a panic that a `Must` function raises as a
rejected input, and it does the same for `template.Must`'s panic under any
target. The ranking puts `MustX` below its `X` (#399). A runtime fault in a
`Must` function's own body is still a finding. So is the panic of a target
that is not a `Must` function and passes its input to one
(`regexp.MustCompile(filter)`), marked `lab_only` (`must_panic`).

---

## Rust

### Rust-1. No native byte decoder — 42 — **partly [FIXED]**

Measured (#338, [the rerun](validation/2026-11-17-rust-trait-and-param-classes.md)).
An owned parameter of a crate type with a `Default` impl or derive that the
lane can reach is built from `T::default()`. That moved RecordFlux's
`Identifier::new(&str, Location)` from a skip to built and fuzzed, and no
target to a failed build. `Option<T>` of a decodable `T` and `i128`/`u128`
decode too. Of the 42:
- 5 build and fuzz;
- 20 are in-crate setups the lane (#244) cannot complete;
- 3 fail their build;
- 12 have no decoder still: references to project types, raw pointers,
  engine handles (`v8::PinScope`), `&Path`, and the `bytes` crate's `Bytes`.

### Rust-2. Private-module trait-impl method — 17 — **[FIXED]**

The in-crate lane calls a static trait-impl method by UFCS with a
`crate`-rooted trait path (a trait of the crate, private modules included) or
a std conversion trait (`FromStr`, `TryFrom<&[u8]>`, `TryFrom<&str>`), and
imports the trait of an instance method. A static method of another crate's
trait was Rust-4, fixed since.

### Rust-3. `unsafe fn` with a caller-upheld precondition — 16 — **BY DESIGN**

Fuzz bytes would violate the caller's contract, so a crash would come from the
harness, not the target. bhf refuses these.

### Rust-4. Static method of a non-in-crate trait impl — 11 — **[FIXED]**

A dependency's trait is resolved through the impl file's `use` declarations
or its full spelling, and the harness crate depends on the trait's crate
with the target's spec (#338). `From<&[u8]>`/`From<&str>` join the standard
conversions. In [the rerun](validation/2026-11-17-rust-trait-and-param-classes.md):
- 7 of meilisearch's 9 `BytesDecode` codecs resolve. They failed to link,
  with undefined monomorphized generics, until the Rust lane stopped using
  crate-local ThinLTO (#409). Rerun with that change, all seven link
  ([2026-11-20](validation/2026-11-20-rust-generic-link.md));
- 2 are impls on a generic type, which need a type argument;
- one is a `Default::default`, which takes no input;
- one was not discovered.

The last three refusals now say what they are.

---

## Java

### Java-1. Unsupported parameter type — 75 — **partly GAP, partly DEPENDENCY**

`Context` (15, Android, not resolvable offline), `RequestHttp<…>` (6, generic),
`ListNode`/`TreeNode` (4, project types), `Map<String,Object>` (3),
`File`/`Writer` **[FIXED]**.

**JDK collections are [FIXED]** (#236). The harness declared locals with `var`,
which infers the wrong element type for a collection built from the input. A
collection local is now declared with its parsed type and filled with decoded
elements: `List<String>`, `Map<String, Object>`, sets, sorted maps, nested
collections, wildcards, `int[]`. A `List` of a project type takes default
instances of it, when the type has a no-arg constructor, factory or constant.

The [2026-11-16 re-run](validation/2026-11-16-java1-collections.md) of the 57
targets `results-0728` skipped here, by name: 7 now pass the parameter they were
skipped on, and none builds. Five need the project's Maven or Gradle build, which
fails, one fails javac on the tree, and one stops at its next parameter. Of the
50 unchanged, 19 take an Android type and 29 a project or dependency type with
nothing to construct it from. A bare type variable `T` (2) is still unresolved.

### Java-2. Instance method, no no-arg constructor — 12 — **GAP**

The builder/factory receiver synthesis (#459) covers some; these are the rest.

### Java-3. Constructor of an abstract class/interface — 8 — **BY DESIGN**

### Java-4. Maven `DependencyResolutionException` — 20 — **DEPENDENCY**

Maven cannot resolve the project's dependencies offline.

---

## C#

### C#-1. Unconstructible receiver — 26 — **[PARTLY FIXED]**

`GetUninitializedObject` covers the forced path. Unforced, an instance method
whose type has no accessible parameterless constructor still skips.

### C#-2. Abstract/interface receiver — 13 — **BY DESIGN**

No instance to allocate by any route.

### C#-3. `CS0246: type or namespace not found` — 32 — **DEPENDENCY**

### C#-4. `NETSDK1045` / `NU1010` — 15 — **ENVIRONMENT**

SDK ceiling and central package management.

---

## Python

### Py-1. `ModuleNotFoundError` — 266 — **DEPENDENCY**

The largest single class in the sweep. The manifest names each missing
package; `bhf auto --install-deps` installs it with `pip3` where the network
allows.

### Py-2. Instance method needs constructor arguments — 25 — **[FIXED]**

The receiver is built from its `__init__` arguments, each decoded from the
input as a method parameter of that annotation or name is (#286). Re-running
the sweep's 21 Py-2 targets built and fuzzed 6 and left none on this reason.
10 now stop at a dependency the project needs and is not installed, 3 at a
constructor argument bhf cannot build, and 2 elsewhere. See
[the re-run](validation/2026-11-18-py2-receivers.md).

### Py-3. `type X is not subscriptable` — 10 — **DEPENDENCY**

The project's own module fails to import because it subscripts a class that
is not generic in the installed library version (spec-kit's `Choice[...]`).
bhf reports it as "not loadable (skipped cleanly)" with the interpreter's
message.

### Py-4. Python 2 — 20 — **BY DESIGN**

---

## JavaScript / TypeScript

### JS-1. Missing npm package — ~225 — **DEPENDENCY**

### JS-2. Browser globals: `window is not defined` (23), `navigator is not defined` (5) — **[FIXED]**

A DOM-targeting module loaded under bare Node. The driver now stands in for
the browser globals Node lacks when a module needs them (#288), and each
finding of such a target names them in its `fidelity_caveat`, since a finding
may depend on the stand-ins. Re-running the sweep's 37 JS-2 targets (29
JavaScript, 8 TypeScript) built and fuzzed 23 and left none on a missing
browser global; the other 14 stop at the next precondition (an extension API,
exports that are not functions, a JSX sample without React). See
[the re-run](validation/2026-11-18-js2-browser-globals.md).

### TS-1. `No loader is configured for ".png"/".svg"/".yaml"/".vue"` — 18 — **[FIXED]**

The transpile now declares loaders for the usual non-code assets: inert text for
markup and config, a data URL for binaries.

### JS-3. Unconstructible receiver — 58 — **[FIXED]**

### JS-4. A host or browser API the driver does not stand in for — 6 findings — **ENVIRONMENT**

`ReferenceError: FileReader is not defined` (three), `app is not defined`,
`store is not defined` and `Javy is not defined`, in the
[2026-11-16 re-sweep](validation/2026-11-16-go-resweep.md). These are a
browser's API and names that an embedding host defines. Each call stopped at
the missing name, so every input reported it as a finding. Before fuzzing,
the build now runs each target on the fuzz passes' starting inputs (the
run's seed inputs included) and on inputs built from the literals in its
source file; [JavaScript](site/javascript.md#browser-globals) lists them.
When every one stops at the same undefined global, thrown at the same place,
the target is reported as `built_not_entered` (`target_environment`), naming
the global, with no finding (#398). When any of them gets past it, the
`ReferenceError` is still a finding. The gap that remains: an undefined
global behind a check that none of those inputs passes, such as a format the
literals do not spell, is also reported as the target's environment. A seed
file with an input that passes the check gets the target fuzzed.

---

## Ruby / PHP / Lua / Perl

Mostly **DEPENDENCY** (missing gems, Composer `vendor/`, luarocks, CPAN):
about 140 targets. The rest are load-time preconditions in the target
(`private method called`, `Trait not found`, `attempt to index a nil value`):
the project needs an environment to load. bhf skips each and names the
precondition.

---

## Fortran

### For-1. `Cannot open module file` / `Cannot open included file` — ~10 — **DEPENDENCY**

`stdlib_kinds.mod`, `fpm_environment.mod`, `SIZE`. A Fortran `.mod` is a build
artifact, so an unbuilt dependency has none.

### For-2. Unresolved external symbols — 3 — **DEPENDENCY**

---

## What the 2026-07-28 sweep changed

The re-run was measured on a binary pinned before that day's fixes, so it is a
clean read of the previous release.

**Found and fixed: a crash in discovery.** `carbon-language/carbon-lang` was
SIGKILLed (`exit -9`) during discovery in both `list targets` and `auto`, and
bhf produced no target list. A hard kill leaves nothing to act on and looks
like a hang.

Root cause was in type resolution, not discovery. `MAX_RESOLVE_DEPTH` bounds
recursion depth but not breadth, so a self-referential C++ type unrolled to the
16-deep limit materialized on the order of F^16 field vectors. One 1205-line
header cost **13.0 GiB and 88s**. Fixed by memoizing on (spelling, depth) and
stopping at a cycle: a type that transitively contains itself now resolves to
`Opaque` at the recurrence rather than unrolling, which loses nothing because a
decoder cannot build an infinitely nested value either way.

| carbon-lang | before | after |
|---|---:|---:|
| whole tree, `list targets` | SIGKILL at 12.9 GiB, 0 targets | exit 0, **52 MiB**, 5,092 targets |
| whole tree, `auto` | SIGKILL, 0 targets | 4,040 fuzzable targets |
| the single header | 13.0 GiB / 88s | **77 MiB / 1.2s** |

The same fix took `simdjson` from a 900s `list targets` timeout to completing in
481s with 14,690 targets. Seven other C/C++ projects still time out
(`sumatrapdf`, `Proton`, `emscripten`, `serenity`, `rocksdb`, `envoy`,
`whisper.cpp`) because of their tree size, a separate cause.

Discovery also gained the RSS ceiling the static scan already had, on both
surfaces: `list targets` parses five lanes itself and defers eleven, and a
guard on the shared walk alone would miss C++. Past the ceiling, discovery
returns a partial target list and says so. For carbon-lang, one file crossed
the ceiling between two 500 ms samples, so the type-resolution fix is what
resolved it; the guard covers trees whose memory use grows gradually.

**Closed since the measurement.** `blocked_by_non_self_contained_header`
(49 C++ targets, the largest C++ residual class) now falls back to the header's
owner translation unit, adopted only when it preflight-compiles. A repair that
`#define`s over an enumerator the project itself defines, turning
`enum { X = 4 }` into `enum { 1 = 4 }` and breaking a source that compiled, is
now vetoed, as repairs over tree functions and types already were.

**Still open.** Most of what remains is missing modules and packages
(Python 273, TypeScript 174, JavaScript 95, Ruby 42, Lua 39, PHP 36). These
are DEPENDENCY: the missing-dependency manifest names each one. The largest
GAP classes are undrivable parameters and unconstructible receivers, as
ranked below.

---

## Performance: the static scanner

`static-scan` was the last measured outlier after the timeout sweep, and it is
now **13.6x faster on Java** with byte-identical output.

| tree | lane | before | after |
|---|---|---:|---:|
| elasticsearch (4.99M SLOC) | Java | 616.6 s | **45.4 s** (13.6x) |
| kubernetes | Go | 59.2 s | **15.4 s** (3.8x) |
| Proton | C/C++ | 10.6 s | 10.4 s (unchanged) |

Java went from 8.1k to 110k SLOC/s. Every number above passed
`scripts/validation/finding-parity.py`: identical findings and identical
`analysis_gaps`, per rule, severity and CWE. A lost finding looks like a
faster scan, and a scan that explores less reports more gaps even when the
finding count holds, so the parity check is the gate for every speed-up.

Profiling put 24 s of a 28 s Java scan in `annotate_reachability`, the
call-graph BFS that labels findings, and 1.3 s in the interprocedural taint
worklist. Both causes were in that BFS:

- **`reachable` was a `BTreeSet<FunctionKey>`, and a key holds a `PathBuf`.** Every
  probe cost ~17 comparisons of long path strings, and the BFS probes once per
  candidate target per call site. It is membership-only, never iterated, so it is
  now a hash set: **3.1x** on its own, and it helped Go as much as Java.
- **Each call site walked EVERY function in the tree sharing that name**, and that
  list grows with the tree, which is the source of the O(n^1.6). A name whose whole
  candidate set is already reachable can never contribute again, whichever subset
  the preference rules pick, so such names are retired. The reachable set only
  grows, so that is monotonic and cannot go stale: a further **2.7x**, and the BFS
  went from 79.1 s to 2.0 s on the full tree.

**The residual is lane-specific, and it is the Java call graph.** Measured phase
shares on comparable trees:

| lane | per-file | taint | reachability |
|---|---:|---:|---:|
| Go (kubernetes) | 15.3 s | **2.1 s** | 1.9 s |
| C++ (Proton) | 13.0 s | **0.04 s** | 0.09 s |
| Python (django) | 5.1 s | **0.6 s** | 0.3 s |
| Java (elasticsearch) | 23.5 s | **15.9 s** | 4.2 s |

Measuring the call graph itself says what the cause is
(`BHF_PROFILE=1` prints these):

| lane | call sites | edges walked | fan-out |
|---|---:|---:|---:|
| Java (elasticsearch) | 175,297 | 436,984 | **2.49** |
| Go (kubernetes) | 17,690 | 14,112 | **0.80** |

The counts are taken after self-calls and duplicates are dropped, so they are
the edges the taint pass walks.

**Java carries roughly 3.1x the edges per call site that Go does.** Calls are
`obj.method(...)`, and the index keys on name plus arity, so `get()` resolves to
every zero-argument `get` in the tree. Each spurious edge is both extra taint
work and a spurious flow, which is why elasticsearch also emits 43,660
`unresolved_project_local_call` gaps for the names that match nothing at all.

This is one defect with two symptoms. A receiver-type-aware index would make
the lane faster and more precise: narrowing the edges toward Go's ratio of
about 1:1 removes work and spurious flows together.

**Enabling the C++ receiver path for Java would break taint propagation.** The
machinery looks one language gate away:

    if language == "cpp" {
        for (name, type_name) in cpp_local_object_declarations(&line.text) { ... }
    }

`cpp_member_targets` resolves `ReceiverType::member` against `by_name` with
no inheritance walk. When the method is declared on a base class or
interface, the lookup misses and returns no targets. Java dispatch is
virtual and elasticsearch is interface-heavy, so most call sites would
resolve to nothing, turning the 2.49 over-approximation into a near-total
under-approximation. The result would look like a large speed-up with fewer
findings, which is also what a real precision gain looks like. Build an
inheritance-aware index first (declared type, then supertypes, then the
declaring class), and treat the resulting finding delta as the deliverable.

The narrowing needs each Java type's supertypes from the parser. The order
of work is:

1. ~~`java_parser`: extract `extends` / `implements` per type.~~ **DONE** —
   `JavaTypeModel::supertypes` carries them (leaf-reduced, so `java.io.Closeable`
   is usable as an index key). Nothing consumes it yet, so behaviour is
   unchanged. A class exposes `superclass` and `interfaces` as named
   tree-sitter fields, but an interface's own `extends` list is an unnamed
   child node: a field-only lookup returns nothing for
   `interface A extends B, C`, which is the case that matters most.
2. `static_analysis`: resolve a member against the closure rather than the
   declared type alone. **The closure itself is DONE**:
   `java_parser::supertype_closure`, transitive and cycle-safe, unit-tested and
   not yet consumed. What remains in this step is wiring Java type models into
   `static_analysis` (it does not consume them today) and tracking Java local
   declarations so a receiver's declared type is known at the call site.
3. Gate it opt-in, measure the finding delta with `finding-parity.py`, and review
   what disappears BEFORE it becomes the default.

This is a precision change: `finding-parity.py` will show findings change,
most likely fewer as spurious flows disappear, and each disappearance needs
review.

The rest of the taint time is inherent work. Two further optimisations of
the taint worklist measured no gain:

- Hashing its membership sets (`enqueued`, `fn_states`, `truncated`), the change
  that was worth 3.1x in the reachability BFS, moved nothing. The BFS probed once
  per candidate per LINE; the worklist probes once per enqueue and per pop, orders
  of magnitude fewer, so long-path comparisons never dominated here. The
  change is kept for consistency and marked as a no-op in the code.
- Making the per-line arity resolution allocation-free took the phase from 15.9 s
  to 16.9 s: avoiding the two intermediate `Vec`s meant walking the candidate list
  up to three times instead of once. Reverted.

The remaining 16.0 s is the per-line call resolution itself: candidate
extraction, call-shape gating and arity matching. The remaining structural
lever is running it on more than one core. `scan_taint_project` parallelizes
across languages, so a single-language tree uses one core. Parallelizing
within a language means splitting the shared mutable state (`enqueued`,
`fn_states`, `truncated`, the findings sink) of the one pass that can change
findings, a redesign gated on `finding-parity.py`.

Per-file rule packs (23.6 s) are already parallel at cores-1.

---

## Ranked work list

By fixable targets, highest first:

1. **C opaque-type lifecycle** (C-1; 86, less the own-TU handles now
   completed): a definition in another non-included `.c` needs the
   tree-wide struct definitions plumbed to the decoder.
2. **C++ unconstructible class** (C++-2; 30) + no-decoder (C++-3; 33).
3. **Ada link/symbol residue** (Ada-1, Ada-2; 52).
4. **Go undrivable parameters** (Go-1; 58 before `context.Context` was
   fixed): the rest are project and library types (`*zap.Logger`,
   `*pflag.FlagSet`).
5. **Rust project-type and handle parameters** (Rust-1; 12 of 42 left).
6. **Java project-type parameters** (Java-1; 29 of the 57 that `results-0728`
   left): a project or dependency type with no no-arg constructor, factory or
   constant to build it from. JDK collections are decoded since #236.
7. **C# unforced receiver** (C#-1; 26).

Closed since the list was first ranked, and dropped from it: the C++
non-self-contained header (C++-1), the Go receiver with a sibling
constructor (Go-2), `context.Context` (Go-1), the TS asset loaders (TS-1),
the C++ compile-flag quoting (C++-6), private-module trait-impl methods
(Rust-2), the JS browser globals (JS-2), the Python receiver with
constructor arguments (Py-2) and the Rust staticlib link of large
workspaces (#409).

## Method

Work this list from exemplars' raw build logs, not from the histogram alone.
The histogram normalizes messages for grouping and says nothing about cause,
and an obvious-looking diagnosis can be wrong.
`benchmarks/campaign-2026-07-25/residual_errors.py` collects those logs.
