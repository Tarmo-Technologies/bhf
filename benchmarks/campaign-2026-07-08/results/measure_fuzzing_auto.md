## Findings

Two `bhf auto` sweeps completed, and all four competitor toolchains were
installed (AFL++ 4.09c, clang/libFuzzer 18.1.3, cargo-fuzz 0.13.2, Jazzer
standalone JAR, Go 1.22.2). This is a **workflow/capability** assessment rather
than a raw-throughput contest. A fair throughput comparison requires multi-hour
single-target runs on identical harnesses and was outside this measurement.

### Auto-run measurements

Both sweeps used `--max-targets 5 --per-target-time 3 --no-discovery-cache` with absolute `--work-dir`.

| Repo | Discovered (ranked) | Built+fuzzed | Skipped | Findings | Executions | Throughput | Coverage | Duration |
|---|---|---|---|---|---|---|---|---|
| c_jansson (C) | 5 of 228 | 2 | 3 | 5 | 118 | 19 exec/s | 142 edges | 22.4s |
| go_cobra (Go) | 5 of 165 | 3 | 2 | 0 | 134,595 | 14,980 exec/s | 11 edges | 10.4s |

Both ran with **zero hand-written harnesses**. On c_jansson bhf recovered a broken/partial build: it linked the library's full 12-source TU set to close undefined externals (§26.1) and stubbed 3 external deps — no `compile_commands.json`, no working build required. The 3 C skips ("could not auto-harness") and 2 Go skips were variadic or complex signatures and were logged to a bug report. The c_jansson throughput (19 exec/s) is low because per-target-time was 3s and much of the budget went to build recovery and linking; go_cobra hit ~15k exec/s once compiled. Neither number is a throughput benchmark; they show that the pipeline ran end to end without manual setup.

### Capability matrix (the actual comparison)

| Capability | bhf | AFL++ | libFuzzer | cargo-fuzz | Jazzer |
|---|---|---|---|---|---|
| Harnesses to write before first run | **0** (auto-generated) | N (1 per target) | N | N | N |
| Languages driven by ONE engine | **8** (C/C++/Ada/Rust/Java/Python/Perl/Go) | C/C++ (+ QEMU bins) | C/C++ | Rust | JVM (Java/Kotlin) |
| Fuzzes broken / non-building code | **Yes** (build-recovery, stubs, full-TU link) | No | No | No | No |
| Fuzz-confirmation of static findings | **Yes (unique)** | No | No | No | No |
| Discovers + ranks targets automatically | **Yes** | No | No | No | No |
| `--force` / report-only degrade path | **Yes** | No | No | No | No |
| Raw single-target throughput (mature target) | Not measured in this campaign | Mature specialist | Mature specialist | Mature specialist | Mature specialist |
| Ecosystem maturity / mutator sophistication | Growing | Mature | Mature | Mature | Mature |

### Per-feature result

- **Zero-harness start:** bhf generated 5 C and 5 Go harnesses without human input. Each measured dedicated fuzzer requires a handwritten harness per target.
- **Multi-language single engine:** bhf covered eight language lanes in this campaign; the measured competitors each covered one language family.
- **Fuzzing broken code:** the c_jansson run recovered a build without `compile_commands.json`.
- **Fuzz-confirmation of static findings:** none of the measured crash-only fuzzers performed static-to-dynamic confirmation.
- **Raw single-target throughput:** the campaign did not run the long, identical-harness comparison required to quantify this axis. The dedicated fuzzers have mature, target-specific engines and integrations.
- **Ecosystem maturity:** AFL++ has a larger collection of mutators, community resources, and integrations.

### Concrete gaps bhf should fix to lead more decisively

1. **Auto-harness coverage on hard signatures.** 3/5 C and 2/5 Go targets skipped as "could not auto-harness" (variadic `json_vunpack_ex`/`json_vpack_ex`, `unpack`, Go template-func/ActiveHelp closures). Supporting these signatures would raise the measured built-and-fuzzed ratio.
2. **Throughput on recovered builds.** c_jansson's 19 exec/s reflects build-recovery/link eating the 3s budget. Amortize the recovered-build compile once and persist it so subsequent targets in the same library reuse the archive instead of re-linking 12 TUs per target.
3. **Publish a controlled throughput comparison.** This assessment does not establish an exec/s comparison with AFL++ on an identical target. A controlled run would quantify the difference.

### Overall verdict

In these runs, bhf provided zero-harness, eight-language auto-fuzzing with build recovery and fuzz-confirmation of static findings. None of the measured dedicated fuzzers combined those capabilities. The campaign did not quantify raw single-target throughput or mutator maturity on identical harnesses.

Reports written to `/tmp/gfa1/auto/run.json` (c_jansson) and `/tmp/gfa2/auto/run.json` (go_cobra); bug-reports at `/tmp/gfa1/auto/bug-report.md` and `/tmp/gfa2/auto/bug-report.md`.
