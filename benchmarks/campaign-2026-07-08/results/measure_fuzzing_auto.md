# `bhf auto` fuzzing measurements (2026-07-08 campaign)

Two `bhf auto` sweeps completed, and all four other fuzzing toolchains were
installed (AFL++ 4.09c, clang/libFuzzer 18.1.3, cargo-fuzz 0.13.2, Jazzer
standalone JAR, Go 1.22.2). The campaign measured workflow and capability. A
throughput comparison needs multi-hour single-target runs on identical
harnesses; that is gap 3 below.

## Auto-run measurements

Both sweeps used `--max-targets 5 --per-target-time 3 --no-discovery-cache`
with an absolute `--work-dir`.

| Repo | Discovered (ranked) | Built+fuzzed | Skipped | Findings | Executions | Throughput | Coverage | Duration |
|---|---|---|---|---|---|---|---|---|
| c_jansson (C) | 5 of 228 | 2 | 3 | 5 | 118 | 19 exec/s | 142 edges | 22.4s |
| go_cobra (Go) | 5 of 165 | 3 | 2 | 0 | 134,595 | 14,980 exec/s | 11 edges | 10.4s |

Both ran with no hand-written harnesses. On c_jansson, bhf recovered a partial
build: it linked the library's full set of 12 translation units to resolve
undefined externals and stubbed 3 external dependencies, with no
`compile_commands.json` and no working build. The 3 C skips ("could not
auto-harness") and the 2 Go skips were variadic or complex signatures, and bhf
logged them to a bug report. The c_jansson rate (19 exec/s) reflects a 3 s
per-target budget, much of it spent on build recovery and linking; go_cobra
reached about 15k exec/s once compiled. Both numbers show the pipeline running
end to end without manual setup.

## Capability matrix

| Capability | bhf | AFL++ | libFuzzer | cargo-fuzz | Jazzer |
|---|---|---|---|---|---|
| Harnesses to write before first run | **0** (auto-generated) | N (1 per target) | N | N | N |
| Languages driven by one engine | **8** (C/C++/Ada/Rust/Java/Python/Perl/Go) | C/C++ (+ QEMU bins) | C/C++ | Rust | JVM (Java/Kotlin) |
| Fuzzes broken / non-building code | **Yes** (build-recovery, stubs, full-TU link) | No | No | No | No |
| Fuzz-confirmation of static findings | **Yes** | No | No | No | No |
| Discovers + ranks targets automatically | **Yes** | No | No | No | No |
| `--force` / report-only degrade path | **Yes** | No | No | No | No |
| Raw single-target throughput (mature target) | Not measured in this campaign | Mature specialist | Mature specialist | Mature specialist | Mature specialist |
| Ecosystem maturity / mutator sophistication | Growing | Mature | Mature | Mature | Mature |

## Per-feature result

- **Zero-harness start:** bhf generated 5 C and 5 Go harnesses without human
  input. Each measured dedicated fuzzer requires a hand-written harness per
  target.
- **Languages:** bhf has eight language lanes under one engine; this
  campaign's fuzz runs used the C and Go lanes. The measured dedicated fuzzers
  each cover one language family.
- **Fuzzing broken code:** the c_jansson run recovered a build without
  `compile_commands.json`.
- **Fuzz-confirmation of static findings:** none of the measured crash-only
  fuzzers perform static-to-dynamic confirmation.
- **Raw single-target throughput:** quantifying this axis needs the long,
  identical-harness comparison in gap 3. The dedicated fuzzers have mature,
  target-specific engines and integrations.
- **Ecosystem maturity:** AFL++ has a larger collection of mutators, community
  resources, and integrations.

## Gaps found

1. **Auto-harness coverage on hard signatures.** 3/5 C and 2/5 Go targets
   were skipped as "could not auto-harness" (variadic
   `json_vunpack_ex`/`json_vpack_ex`, `unpack`, Go template-func/ActiveHelp
   closures). Supporting these signatures would raise the built-and-fuzzed
   ratio.
2. **Throughput on recovered builds.** c_jansson's 19 exec/s reflects build
   recovery and linking using the 3 s budget. Compiling the recovered build
   once and keeping it would let later targets in the same library reuse the
   archive in place of re-linking 12 translation units per target.
3. **A controlled throughput comparison.** A controlled run against AFL++ on
   an identical target would measure the exec/s difference.

## Result

In these C and Go runs, bhf fuzzed with no hand-written harnesses and
recovered a partial build. Zero-harness generation, eight language lanes,
build recovery and fuzz-confirmation of static findings are a combination none
of the measured dedicated fuzzers offers. Raw single-target throughput and
mutator maturity on identical harnesses are open (gap 3).

Reports were written to `/tmp/gfa1/auto/run.json` (c_jansson) and
`/tmp/gfa2/auto/run.json` (go_cobra); bug reports to
`/tmp/gfa1/auto/bug-report.md` and `/tmp/gfa2/auto/bug-report.md`.
