<!-- SPDX-License-Identifier: Apache-2.0 -->
# bhf vs the field: a measured comparison

This page compares **bhf** with the most widely used fuzzer for C, Rust, Java
and Ada, on identical planted-bug targets. It then describes how the C++,
Python, Perl and Go lanes apply the same workflow. bhf fuzzes sixteen
languages; this benchmark suite has measured targets for these four.

The scripts under [benchmarks/](../../benchmarks/README.md) produce every
measured number here, and the results are recorded in
`benchmarks/results/*.tsv`. See [Methodology](#methodology) for the rules and
[Reproduce](#reproduce) to run it yourself.

## Measured results

| | **bhf** | libFuzzer | AFL++ | cargo-fuzz | Jazzer | GNATfuzz (not measured) |
|---|---|---|---|---|---|---|
| Languages measured here | **C, Rust, Java, Ada** | C | C | Rust | Java | Ada |
| Hand-written harness per target | **0 lines** | 6 lines | 13 lines | 5 lines | 5 lines | 0 (generates one per subprogram) |
| Fuzzes **Ada** | **yes** | no | no | no | no | yes |
| Targets fuzzed per command | **all** (185 on miniz) | 1 | 1 | 1 | 1 | 1 subprogram |
| Needs a working build | **no** (recovers a partial build and stubs what is missing) | yes | yes | yes | yes | yes (a buildable GNAT project) |
| Needs a nightly or special toolchain | Rust lane only: nightly | no | no | yes (nightly) | no | commercial (GNAT Pro) |
| Finds the planted bug | **yes** (all four languages) | yes | yes | yes | yes | not measured |
| Engines it runs | built-in; `bhf fuzz --engine` also drives AFL++, libFuzzer, honggfuzz and WinAFL | its own | its own | libFuzzer | its own, built on libFuzzer | AFL++, libFuzzer, SymCC |

GNATfuzz, AdaCore's commercial Ada fuzzer, is listed from its
documentation. It needs a licence, so it has no measured column. AFL++'s
GCC plugin can also instrument code GNAT compiles, given a hand-written
harness.

On these targets bhf needed no hand-written harness code, fuzzed every
target of a tree in one command, fuzzed the Ada target, and worked without
an existing build. Each tool found the planted bug in the target it ran.

## How bhf reduces setup

A fuzzer has two parts: an **engine** (mutation and coverage feedback) and
the **harness and build plumbing** a person writes to point that engine at
code. The plumbing is a hand-written harness per entry point, a working
build, a fuzz-target crate and a coverage-instrumented toolchain.

bhf does the plumbing. It discovers fuzzable entry points across a whole
tree, **generates the typed harness**, recovers the build when there is
none, and fuzzes. The built-in coverage-guided engine runs with cmplog
(RedQueen-style comparison solving) on by default in `bhf auto`; `bhf fuzz
--engine` can drive AFL++, libFuzzer, honggfuzz or WinAFL instead. On the
planted-bug targets below, bhf found the same bugs as the dedicated fuzzers
with no hand-written harness.

## Results by language

The target in each language is a parser with a bug reachable only past a
gate, the standard shape of a fuzzing benchmark, so the engine needs its
coverage feedback to reach it. `harness` is the number of lines of
fuzz-harness code a person writes first. `TTFC` (time to first crash) for
bhf is **end-to-end**: raw source, discovery, build, crash. For the other
tools it is **fuzz-only**, on a pre-built, hand-written harness; their
harness-writing time is not counted.

### C: vs libFuzzer and AFL++

There are three gate classes: a 32-bit magic, a length field, and an
input-to-state (length-derived) magic that needs cmplog/RedQueen. The
competitors run in their **best** configuration: AFL++ with a CMPLOG binary
(`-c`), libFuzzer with `-use_value_profile=1`.

| target (gate) | tool | harness | finds bug | TTFC | execs-to-crash |
|---|---|---|---|---|---|
| magic (32-bit) | libFuzzer | 6 | yes | 0.49 s | 382 |
| | AFL++ | 13 | yes | <1 s | 2187 |
| | **bhf (builtin)** | **0** | **yes** | 1.21 s* | 361 |
| length field | libFuzzer | 6 | yes | 0.66 s | 2 |
| | AFL++ | 13 | yes | <1 s | 40 |
| | **bhf (builtin)** | **0** | **yes** | 1.21 s* | 70 |
| input-to-state | libFuzzer | 6 | yes | 0.64 s | 22 430 |
| | AFL++ (cmplog) | 13 | yes | <1 s | 1 575 |
| | **bhf (builtin)** | **0** | **yes** | 1.21 s* | 409 |

\* End-to-end, including bhf's build of the harness it generated. The
competitors' times exclude the build and the hand-written harness they
need.

A bare in-process fuzzer with a pre-built harness reaches its first crash
sooner in fuzz-only time; that is the job libFuzzer and AFL++ are built
for. bhf's built-in engine solves **all three gate classes from a cold
start**, including the input-to-state gate, with cmplog on by default and no
`-c` build or extra flags, in 1.21 s end-to-end **with no harness**.

`benchmarks/results/c.tsv` also records `bhf auto --engine afl++` on the
same targets: it found the magic bug and did not find the length-field or
input-to-state bugs within the run's budget. The built-in engine is the
default and is what the table shows. A LibAFL engine (`bhf fuzz --engine
libafl`) is available in a bhf built with the `libafl-engine` Cargo
feature; the release binaries leave it out.

### Rust: vs cargo-fuzz

| tool | harness | finds bug | TTFC |
|---|---|---|---|
| cargo-fuzz | 5 (+ `fuzz/` crate) | yes | 0.98 s (fuzz-only) |
| **bhf** | **0** | **yes** | 1.61 s (end-to-end) |

Both build the target with a nightly Rust toolchain. cargo-fuzz also needs a
`fuzz/` crate and a `fuzz_target!` harness per target. bhf fuzzes the
library as it is, with no harness.

### Java: vs Jazzer

bhf fuzzes Java with its **own JVM bytecode coverage agent** (ASM
instrumentation and a persistent fork-server driver), the same built-in
engine architecture as the C, C++, Ada and Rust lanes. Standalone Jazzer
runs a harness you write; bhf generates its own.

| tool | harness | finds bug | TTFC |
|---|---|---|---|
| Jazzer (standalone) | 5 (`fuzzerTestOneInput`) | yes | 1.85 s (fuzz-only) |
| **bhf** | **0** | **yes** | 2.62 s (end-to-end) |

bhf discovers the method, **synthesises the receiver object** and drives a generated harness through its own JVM agent, with no `fuzzerTestOneInput` and no classpath wiring. `benchmarks/run_java.sh` labels the bhf run `bhf(builtin)`; the row recorded in `benchmarks/results/java.tsv` predates that label and reads `bhf(jazzer)`.

### Ada: vs GNATfuzz and AFL++

Among the fuzzers measured here, bhf is the one that fuzzes Ada. Two other
tools can:

- **GNATfuzz** (AdaCore, commercial, part of GNAT Pro) generates a harness
  for each subprogram of a GNAT project that builds, and fuzzes it with
  AFL++, libFuzzer or SymCC. It needs that buildable project and a licence.
- **AFL++**'s GCC plugin instruments code GNAT compiles, given a harness and
  a build written by hand.

bhf needs no buildable project (it recovers the build, or stubs what is
missing), harnesses every subprogram of a tree in one command, is open
source, and fuzzes Ada beside the fifteen other languages with one engine.

| tool | harness | finds bug | TTFC |
|---|---|---|---|
| libFuzzer, AFL++ (clang, as run here), cargo-fuzz, Jazzer | n/a | **do not fuzz Ada** | n/a |
| **bhf** | **0** | **yes** (`CONSTRAINT_ERROR`) | 1.41 s (end-to-end) |

bhf discovered `Parse_Frame`, decoded fuzz bytes into its `String`
parameter, built the GNAT harness and found the planted
`CONSTRAINT_ERROR`, with no options beyond `--per-target-time`.

### C++: class-aware harnessing

The C/C++ *engine* comparison is the C table above (identical clang
instrumentation). For C++, bhf also harnesses **class methods**. On the C++
service fixture in `tests/fixtures/government_legacy_patterns/cpp/`, bhf
ranks `Gov::TelemetryService::Submit` as attacker-reachable and
**synthesises the receiver object** to call it. With libFuzzer or AFL++, a
person writes a harness that constructs the object and calls the method.

### Python, Perl and Go: the same workflow

bhf also fuzzes **Python**, **Perl** and **Go**, each driven by its
built-in engine over the framed fork-server protocol rather than Atheris,
`go test -fuzz` or libFuzzer. As in every lane, the harness count a person
writes is **0**. bhf discovers the entry points, generates the typed driver,
checks that it loads (`py_compile` and an import smoke test for Python,
`perl -c` and `require` for Perl, `go build` for Go) and fuzzes it.

- **Receivers.** For Python and Perl instance methods, bhf synthesises a
  no-argument receiver where one exists. For a Go method it takes the
  receiver from a no-argument constructor in the same file; with `--force`
  it calls the method on a zero-valued receiver.
- **Coverage.** Python edges come from `sys.monitoring` (Python 3.12 and
  later) or `sys.settrace`, and Perl edges from a `-d:BhfCov` (`DB::DB`)
  tracer, both into the same shared coverage map the C, C++, Ada and Rust
  engines use. Go builds with `-cover -covermode=atomic`, clears the
  counters for each input, and folds the executed blocks into the shared
  edge map. If the coverage build fails or the counter format is not
  recognised, the Go target is fuzzed in black-box mode.
- **Oracles.** The Python and Perl interpreters load the `LD_PRELOAD`
  shim's behavioural and taint sink oracles, which record from the first
  call into the target, so a path or command the input controls is
  reported beside exceptions. Go harnesses are native binaries and load
  the shim directly. The Go harness recovers panics into CWE-mapped
  findings.

Findings in all three lanes carry CWEs and cluster by crash site, as in the
C, C++, Ada, Rust and Java lanes.

## Coverage per command

A fuzzer that needs one harness per entry point scales with the people who
write them. bhf covers a library with one command:

| library | targets bhf harnessed (one command, 0 harnesses) | equivalent hand-written harness code |
|---|---|---|
| miniz (a zlib-class C library) | **185** | about 1,100 to 2,400 lines (185 × 6 to 13) |

## Methodology

- **Targets** (`benchmarks/targets/<lang>/`) have a uniform entry point and
  a gate-guarded planted bug, so finding it requires coverage feedback. The
  C and Rust targets gate on a 32-bit magic or an input-to-state magic; the
  Java and Ada targets gate on a single byte or character. Both tools in
  each language run the same target.
- **Configuration.** Each competitor runs in its best documented
  configuration (AFL++ CMPLOG `-c`, libFuzzer `-use_value_profile=1`). The
  seed is a benign 8-byte input that trips no gate. bhf runs with no flags
  except `--per-target-time`.
- **TTFC.** bhf's time is end-to-end and *includes* the build of the
  harness it generated. The competitors' time is fuzz-only, on a pre-built,
  hand-written harness, and leaves out the time a person spends writing the
  5 to 13 lines.
- **Engine selection.** The tables show bhf's built-in engine, the default.
  Every competitor found its bug, so the comparison measures setup work as
  well as the engine result.

## Reproduce

```sh
cargo build --workspace
BUDGET=15 bash benchmarks/run_c.sh     # -> benchmarks/results/c.tsv
bash benchmarks/run_rust.sh            # -> benchmarks/results/rust.tsv
bash benchmarks/run_java.sh            # -> benchmarks/results/java.tsv
bash benchmarks/run_ada.sh             # -> benchmarks/results/ada.tsv
```

The scripts run the debug build at `target/debug/bhf`. Toolchains:
clang/libFuzzer 18, AFL++ (`afl-clang-fast`, `afl-fuzz`), cargo-fuzz 0.13
on Rust nightly, Jazzer (standalone) on JDK 17 or later, GNAT and
gprbuild. The recorded runs used 6 vCPUs and 13 GB of RAM.
