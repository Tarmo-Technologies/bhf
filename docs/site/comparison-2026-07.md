<!-- SPDX-License-Identifier: Apache-2.0 -->
# bhf measured against selected tools (2026-07)

This July 2026 campaign ran bhf and selected single-purpose tools, feature by feature, on a 14-repository corpus in C, C++, Rust, Go, Python, Java, Perl and JavaScript: zlib, jansson, nlohmann/json, fmt, ripgrep, semver, gin, cobra, click, requests, commons-lang, gson, mojo and express. Every number below comes from running the tools on this corpus. Where a dedicated tool led on its axis, the table gives its number.

The gaps the campaign found led to these additions, with before and after numbers in each section:

- SBOM lockfile ingestion and an SPDX emitter.
- A per-finding CWE and remediation text in every report format.
- New detection classes for Python, C/C++, Perl, Java and Rust.
- A dedicated `bhf sloc` command.

**Scope.** bhf combines an offline fuzzer, a static analyzer and an SBOM tool. This campaign measures breadth and the fuzz-confirmation of static findings. For bhf's engine against AFL++, libFuzzer and honggfuzz on identical targets, see the [Engine Benchmark](engine-parity-benchmark.md).

---

## Scorecard

| Feature | Result | Deciding number |
|---|---|---|
| Multi-language auto-fuzzing with no hand-written harness | only measured tool | 0 harnesses, against one per target for every measured fuzzer; 16 languages today (8 in this corpus) on the built-in engine; builds and fuzzes code whose full build fails, by recovering a partial build and stubbing missing symbols |
| Fuzz-confirmation of static findings | only measured tool | no other measured tool ran static-to-dynamic confirmation |
| Static analysis, Go | most findings with signal | go_gin: bhf 14 taint findings, gosec 0 (it could not build the repo), semgrep 20 (mostly CI configuration findings) |
| Static analysis, Java | only measured tool on these classes | deserialization sinks and JNDI injection (Log4Shell, BHF-551, CWE-917) |
| Static analysis, Rust | measured rule gaps closed | added unsafe `transmute` (BHF-552) and `unwrap()`/`expect()` panic in a library (BHF-553), with 0 hits on the corpus's clean code, alongside the existing `build.rs` taint rule |
| Static analysis, Python | from behind to level | py_click 0 → 14 findings after BHF-546 (`try/except/pass`, CWE-703), 0 false positives |
| Static analysis, C/C++ | missing classes added | cppcheck's 465 to 1711 raw items are about 90% style and information; bhf adds taint-to-sink paths and a CWE per finding. Added BHF-547 (`scanf`, `getwd`), BHF-549 (dangling-lifetime return, CWE-562) and BHF-550 (resource leak, CWE-401), which fire on the same defects as cppcheck's `returnDanglingLifetime` and `memleak` with 0 false positives on the corpus. BHF-554 (printf argument-type mismatch, CWE-686) now covers the fourth class |
| SBOM component discovery | most components found | py_click 30 → 94 components through `uv.lock`, the same transitive depth as syft; more than syft on npm and cargo in this corpus |
| SBOM CVE matching | versions now pinned | lockfiles now give pinned versions, which an offline CVE database can match; before, manifest parsing gave `version: null` and 0 matches |
| Report content | broadest measured combination | SARIF codeFlows, fuzz-confirmation provenance, reachability, root-cause clustering and VEX in one report |
| Report formats | three measured gaps closed | per-finding CWE in every format, remediation text with SARIF `help`/`helpUri`, an SPDX 2.3 emitter |
| SLOC | closest to cloc, fastest timed | 1.3% mean deviation from cloc, against about 20% for scc and tokei; the release build of `bhf sloc` had the lowest time on all 3 timed repos (cpp_json: bhf 13 ms, tokei 16, scc 23) and ran 40 to 120 times faster than cloc |

---

## 1. SLOC counting: accuracy and speed

bhf was compared to cloc, scc and tokei, with cloc as the accuracy reference.

**Mean absolute deviation from cloc:** bhf **1.3%**, scc 19.7%, tokei 23.6%.

scc and tokei deviate by about 20% on average because they count Perl POD and Python docstrings as code (perl_mojo: about 25,600 lines for scc and tokei against about 10,500 for bhf and cloc; py_requests: about 9,300 against about 7,600). They also classify C/C++ headers differently. bhf strips comments per language with the same engine its security rules use. The chart is `benchmarks/campaign-2026-07-08/charts/sloc_accuracy.png`.

**Speed.** The first measurement timed `bhf static-scan --sloc`, which counts lines as a side output of a full static-analysis parse and ran about 150 times slower than tokei. Two changes followed: a dedicated `bhf sloc <PATH>...` command that skips the rule engine, and a parallel count over a rayon thread pool. Release build, best of 3 runs per repo, in milliseconds:

| repo | tokei | scc | cloc | **bhf** |
|---|--:|--:|--:|--:|
| cpp_json (about 110k lines) | 16 | 23 | 521 | **13** |
| commons-lang | 25 | 18 | 898 | **10** |
| ripgrep | 9 | 8 | 722 | **6** |

`bhf sloc` had the lowest time on each timed repo and ran 40 to 120 times faster than cloc. It counts in parallel and counts only the languages bhf supports. The chart is `benchmarks/campaign-2026-07-08/charts/sloc_speed.png`.

## 2. Static analysis: precision and new classes

The tools compared were cppcheck 2.13, flawfinder 2.0.20, semgrep 1.168, bandit, gosec, clippy and perlcritic.

**Finding volume.** cppcheck reports 465 to 1711 raw items on the C and C++ repos. On cpp_json its 1711 items are **35** error or warning, 272 style, 103 performance and **1298** informational. flawfinder's 161 to 296 hits come from lexical matching with no flow analysis and no ranking. bhf's 37 to 141 findings each carry a security type, a CWE and a confidence score, and fuzzing can confirm them.

**Where bhf led:**

- Go: go_gin 14 findings against gosec 0. gosec could not build the repo under its installed Go version; bhf's static analysis does not need the project to build.
- Java: deserialization sinks that no other measured tool flagged.

**Classes added after the campaign:**

- **BHF-546** (Python `try/except/pass`, CWE-703): py_click went from **0 to 14** findings, each a real swallowed exception in the source, with **0 false positives**. bandit caught this class and bhf did not. bhf does not copy bandit's B603, which flags every `subprocess` call; BHF-404 flags `os.system` and `shell=True`.
- **BHF-547** (unbounded `scanf`, `fscanf` or `sscanf` with a widthless `%s` or `%[`, and `getwd`; CWE-120, CWE-676): cppcheck and semgrep flagged this class, and bhf had recorded it as an analysis gap. A width-bounded `%31s` does not fire (0 false positives on the corpus).
- **BHF-549** (dangling-lifetime return, CWE-562) and **BHF-550** (resource leak, CWE-401 and CWE-772): the two C/C++ classes cppcheck caught and bhf missed. Both are per-function, intraprocedural scanners next to the existing use-after-free and uninitialized-read analyses. They fire on the same lines as cppcheck's `returnDanglingLifetime` and `memleak`. Tuning removed 4 false positives found on the corpus (a stored-offset return, and a local array copied into a `std::string` return); after it, the rules fire **0 times** on the corpus's library code. On this corpus, bhf now reports the measured cppcheck defect classes with fewer non-security items.
- **BHF-548** (cleartext `ws://` transport, CWE-319): the one class where semgrep found more than bhf on real Perl code. The rule matches `ws://` only, because `http://` also appears in XML namespaces.

BHF-547 and BHF-548 fire 0 times on the corpus's clean code and only on unsafe constructs. BHF-546 added 23 findings across the two Python repos, with no false positives.

## 3. SBOM and SCA: components and CVE matching

bhf was compared to syft (components) and grype (CVEs).

**Before:** bhf tied syft on Go (42 and 42) and Maven (21 and 21) and found more on npm (45 to 0) and cargo (6 to 0; syft needs a lockfile). It found fewer on py_click (30 to 81), where syft read the lockfile for transitive dependencies. bhf matched **0 CVEs** on every repo, because manifest parsing produced `version: null` and a null version cannot match a CVE range.

**Added after the campaign:**

- **Lockfile ingestion**, including `uv.lock`, which py_click uses: py_click went from **30 to 94 components, 92 with pinned versions** (19 had a null version before), the same transitive depth as syft. Pinned versions let an offline CVE database match them. The campaign host had no CVE database, so matches appear when you supply a feed.
- **SPDX 2.3 JSON** (`bhf sbom --format spdx-json` writes `sbom.spdx.json`): bhf previously wrote CycloneDX and VEX; syft led on SPDX, the format procurement rules ask for most often. bhf now writes CycloneDX, SPDX and VEX.

## 4. Fuzzing and `auto`: workflow capabilities

Capabilities compared with AFL++, libFuzzer, cargo-fuzz and Jazzer, plus real `bhf auto` sweeps:

| Capability | bhf | AFL++ | libFuzzer | cargo-fuzz | Jazzer |
|---|:-:|:-:|:-:|:-:|:-:|
| Harnesses required to start | **0** | 1 per target | 1 per target | 1 per target | 1 per target |
| Languages driven by one engine | **16** today (8 in this campaign) | C/C++ | C/C++ | Rust | JVM |
| Fuzzes code whose full build fails | **yes** | no | no | no | no |
| Recovers build context without `compile_commands.json` | **yes** | no | no | n/a | n/a |
| Fuzz-confirmation of static findings | **yes** | no | no | no | no |
| Fuzzes a function with undrivable parameters (`--force`) | **yes** | no | no | no | no |
| Offline / air-gapped | **yes** | yes | yes | partial | partial |

A real `auto` sweep on c_jansson recovered a partial build with no `compile_commands.json`: it linked a 12-file translation-unit set and stubbed 3 dependencies. No measured competitor configuration provides this workflow.

The workflow measurements cover automatic setup, build recovery and confirmation. The [Engine Benchmark](engine-parity-benchmark.md) compares fuzzing engines on identical targets.

## 5. Reporting: formats and evidence

bhf was the only measured tool that combined SARIF codeFlows (source-to-sink dataflow), fuzz-confirmation provenance, static reachability verdicts, root-cause clustering (one row per issue) and OpenVEX. Three gaps where a competitor led were closed:

- **Per-finding CWE** in the primary `static-report.json`, the Markdown table and SARIF. It was in the SARIF tags and CSV only; go_gin went from **0 to 14** findings with a CWE.
- **Remediation text and SARIF `help`/`helpUri`** on every finding. semgrep and bandit had this and bhf had none; go_gin went from **0 to 14** findings with remediation.
- **SPDX 2.3** SBOM output (see §3).

bhf writes JSON, SARIF 2.1.0, JUnit, CSV, Markdown, CycloneDX, SPDX and OpenVEX, the most formats in this comparison.

## 6. Scope of the results

The corpus holds 14 repositories in 8 languages. SLOC speed was timed on 3 of them. The detection-class and reporting results hold for the tool versions and configurations listed here, on this corpus.

In this campaign bhf ran offline and covered static analysis, SBOM generation and fuzz-confirmation in one tool.

---

*Reproduction:* [benchmarks/campaign-2026-07-08/](../../benchmarks/campaign-2026-07-08/README.md) holds the corpus list, the per-tool measurements (`results/`) and the charts (`charts/`). `results/synthesis.md` records the scorecard before the additions.
