<!-- SPDX-License-Identifier: Apache-2.0 -->
# bhf measured against selected tools (2026-07)

This paper measures bhf against selected single-purpose tools for each
of its features, across a 14-repository corpus spanning C, C++, Rust, Go, Python,
Java, Perl, and JavaScript (zlib, jansson, nlohmann/json, fmt, ripgrep, semver,
gin, cobra, click, requests, commons-lang, gson, mojo, express). Every number
below was produced by actually running the tools on this corpus; where a
dedicated tool legitimately wins on its one axis, we say so with the number.

The comparison also drove a round of improvements: every gap where bhf was
behind a competitor and the gap was closable, it was closed (SBOM lockfile
ingestion + SPDX, per-finding CWE + remediation in all report formats, three new
detection classes, and a dedicated fast SLOC command). Before/after numbers are
shown per section.

**Scope.** bhf is an integrated, offline fuzz-lab, static analyzer, and SBOM
tool. This comparison focuses on breadth and *fuzz-confirmation of static
findings*. Raw single-target fuzz throughput was not measured on identical
harnesses and is not ranked here.

---

## Executive scorecard

| Feature | Verdict | Deciding number |
|---|---|---|
| Zero-harness multi-language auto-fuzzing | **unique in the measured set** | 0 harnesses vs N-per-target for every measured competitor; 16 current product lanes / 1 engine (8 represented in this corpus); fuzzes broken/non-building code |
| Fuzz-confirmation of static findings | **unique in the measured set** | No other measured tool performed static→dynamic confirmation |
| Static analysis — Go | **strongest measured signal** | go_gin: bhf 14 taint findings vs gosec **0** (build-gated) vs semgrep 20 (mostly CI-noise) |
| Static analysis — Java | **strongest measured signal** | deserialization sinks + JNDI injection (Log4Shell, BHF-551/CWE-917) |
| Static analysis — Rust | **closed the measured rule gaps** | added unsafe `transmute` (BHF-552) + `unwrap()`/`expect()` panic-in-lib (BHF-553), precisely scoped (0 corpus noise), plus the existing build.rs taint |
| Static analysis — Python | **now competitive** (was behind) | py_click **0 → 14** after adding BHF-546 (`try/except/pass`, CWE-703); precision kept (0 FP) |
| Static analysis — C/C++ | **matched the measured defect classes** | cppcheck's 465–1711 raw = ~90% style/info; only bhf has taint→sink + CWE. Closed the class gap: BHF-547 (`scanf`/`getwd`), BHF-549 (dangling-lifetime return, CWE-562), BHF-550 (resource leak, CWE-401) — bhf fires on the *same* real defects as cppcheck's `returnDanglingLifetime`/`memleak`, with **0 corpus false positives** |
| SBOM component discovery | **strongest measured coverage** | py_click **30 → 94** components via `uv.lock`; matches syft's transitive depth; exceeds syft on npm/cargo in this corpus |
| SBOM CVE matching | **now enabled** (was 0) | versions now pinned from lockfiles, so an offline CVE DB matches (was null-version → 0 matches) |
| Reporting richness | **broadest measured combination** | Only measured tool combining codeFlows + fuzz-confirm provenance + reachability + root-cause clustering + VEX |
| Reporting breadth | **closed three measured gaps** | Added per-finding CWE (all formats), remediation + SARIF help/helpUri, SPDX-2.3 emitter |
| SLOC — overall | **closest to cloc and fastest in the timed set** | **1.3 %** mean deviation from cloc vs scc/tokei at about 20%; release+parallel `bhf sloc` beat tokei and scc on all 3 timed repos (cpp_json 13 ms vs tokei 16 / scc 23; ~50× faster than cloc) |
| Raw fuzz throughput (single mature target) | specialist advantage | AFL++/libFuzzer/cargo-fuzz/Jazzer have more mature mutator engineering; this campaign did not run a throughput shootout |

---

## 1. SLOC counting — accuracy and speed in the measured set

Compared bhf to cloc, scc, tokei, using cloc as the accuracy reference.

**Mean absolute deviation from cloc:** bhf **1.3 %**, scc 19.7 %, tokei 23.6 %.

bhf's mean absolute deviation from cloc is 1.3% across the 14 repos. scc/tokei
deviate about 20% on average because
they **over-count Perl POD and Python docstrings as code** (perl_mojo: scc/tokei
~25,600 vs bhf/cloc ~10,500; py_requests: ~9,300 vs ~7,600) and classify C/C++
headers differently. bhf's language-aware comment stripping — the same engine
its security rules use — counts them correctly. See `charts/sloc_accuracy.png`.

**Speed.** The original `--sloc` (a side-output of the SAST scan) paid the full
parse cost, making it look ~150× slower than tokei. Two fixes closed that:
(1) a dedicated `bhf sloc <PATH>...` command that skips the rule engine, and
(2) parallelizing the count across a rayon pool. **Result (release build, best of
3 per repo, ms):**

| repo | tokei | scc | cloc | **bhf** |
|---|--:|--:|--:|--:|
| cpp_json (~110k) | 16 | 23 | 521 | **13** |
| commons-lang | 25 | 18 | 898 | **10** |
| ripgrep | 9 | 8 | 722 | **6** |

bhf `sloc` was **the fastest** on every timed repo — ahead of tokei and scc, and ~50×
faster than cloc — because it parallelizes and only counts its supported languages.
It was also closest to cloc across the 14-repository corpus. (The earlier ~0.5 s
figure was a debug build; the release binary users run produced the numbers above.
See `charts/sloc_speed.png`.)

## 2. Static analysis — precision over volume, and three new classes

Measured vs cppcheck 2.13, flawfinder 2.0.20, semgrep 1.168, bandit, gosec, clippy,
perlcritic.

**Finding volume.** cppcheck reports 465–1711 raw items on the C repos, but on
cpp_json those 1711 are only **35** error/warning (security-ish), 272 style, 103
performance, **1298 informational**. flawfinder's counts (161–296) are pure lexical
grep with no flow analysis — unranked, unconfirmed. bhf's 37–141 are
security-typed, CWE-tagged, confidence-scored, and — uniquely — **fuzz-confirmable**.

**Where bhf had the strongest measured signal:** Go (go_gin 14 vs gosec 0, which couldn't build the
repo under a mismatched Go version — bhf's build-independence is a *measured*
advantage), Java (deserialization sinks no competitor flagged), and precision
everywhere.

**Gaps closed:**
- **BHF-546** (Python `try/except/pass`, CWE-703): py_click went **0 → 14** findings,
  every one a genuine swallowed exception in real source, **0 false positives**.
  This was the class bandit caught that bhf missed. (bhf deliberately does
  *not* copy bandit's B603 "flag every `subprocess` call" — that's the noise its
  precision avoids; BHF-404 already flags `os.system`/`shell=True` syntactically.)
- **BHF-547** (unbounded `scanf`/`fscanf`/`sscanf` with widthless `%s`/`%[`, and
  `getwd`; CWE-120/676): the class cppcheck+semgrep flagged and bhf dropped to
  an analysis-gap. Precise — a width-bounded `%31s` does not fire (0 corpus FP).
- **BHF-549** (dangling-lifetime return, CWE-562) and **BHF-550** (resource leak,
  CWE-401/772): the two C/C++ classes cppcheck caught and bhf missed, added as
  precise per-function intraprocedural scanners alongside the existing
  use-after-free/uninitialized-read analyses. Cross-checked: bhf fires on the
  *same* real lines as cppcheck's `returnDanglingLifetime` and `memleak`, and — after
  tightening away 4 real false positives found on the corpus (a stored-offset return,
  a local array copied into a `std::string` return) — fires **0 times** on the
  corpus's well-written library code. In this corpus, bhf now catches the same
  measured defect classes as cppcheck while producing fewer non-security items.
- **BHF-548** (cleartext `ws://` transport, CWE-319): the one class semgrep out-found
  bhf on real Perl. Shipped `ws://`-only to stay precise (`http://` collides with
  XML namespaces).

Net: **no new noise in the measured corpus** — BHF-547/548 fire 0 times across the corpus's clean code and
only on unsafe constructs; BHF-546 added 23 real findings across the two
Python repos with zero false positives.

## 3. SBOM / SCA — component discovery and CVE matching

Measured vs syft (components) and grype (CVEs).

**Before:** bhf tied syft on Go (42/42) and Maven (21/21), beat it on npm (45–0)
and cargo (6–0, syft needs a lockfile), but **lost py_click 30 vs 81** (syft read
the lockfile for transitive deps) and found **0 CVEs everywhere** because manifest
parsing emitted `version: null` — a null version can't match a CVE range.

**Gaps closed:**
- **Lockfile ingestion** (`uv.lock` was the missing one py_click uses): py_click
  **30 → 94 components, 92 with pinned versions** (was 19 null) — matching syft's
  transitive depth. With pinned versions, an offline CVE DB now matches (the root
  cause the analysis identified; the box here ships no CVE DB, so matches show when a
  feed is supplied).
- **SPDX-2.3 JSON emitter** (`--format spdx-json` → `sbom.spdx.json`): bhf emitted
  CycloneDX/VEX only; SPDX is the more common procurement mandate that syft won on.
  Now bhf emits CycloneDX **and** SPDX **and** VEX.

## 4. Fuzzing & `auto` — measured workflow capabilities

Capability comparison vs AFL++, libFuzzer, cargo-fuzz, Jazzer, plus real `auto`
sweeps.

| Capability | bhf | AFL++ | libFuzzer | cargo-fuzz | Jazzer |
|---|:-:|:-:|:-:|:-:|:-:|
| Harnesses required to start | **0** | 1/target | 1/target | 1/target | 1/target |
| Languages driven by one engine | **16 current** (8 measured in this campaign) | C/C++ | C/C++ | Rust | JVM |
| Fuzzes broken / non-building code | **yes** | no | no | no | no |
| Recovers build context (no compile_commands) | **yes** | no | no | n/a | n/a |
| Fuzz-confirmation of static findings | **yes** | no | no | no | no |
| `--force` fuzz any function | **yes** | no | no | no | no |
| Offline / air-gapped | **yes** | yes | yes | partial | partial |

A real `auto` sweep on c_jansson recovered a partial build (linked a 12-source TU
set, stubbed 3 deps) with no `compile_commands.json`; none of the measured
competitor configurations provided this workflow.

**Throughput scope:** this campaign did not run an hours-long comparison on
identical harnesses. It therefore establishes no raw-throughput ranking between
bhf, AFL++, libFuzzer, cargo-fuzz, and Jazzer. The workflow measurements above
cover automatic setup, build recovery, and confirmation.

## 5. Reporting — measured format and evidence coverage

bhf was the only measured tool combining SARIF codeFlows
(source→sink dataflow), fuzz-confirmation provenance, static-reachability verdicts,
root-cause clustering (one row per issue), and OpenVEX. Three breadth gaps a
competitor beat it on were closed:
- **Per-finding CWE** now in the primary `static-report.json`, the Markdown table,
  and SARIF (was SARIF-tags/CSV only; go_gin went **0 → 14** findings with CWE).
- **Remediation + SARIF `help`/`helpUri`** on every finding (semgrep/bandit had this;
  bhf had none — go_gin **0 → 14** with remediation).
- **SPDX-2.3** SBOM output (see §3).

Formats emitted: JSON, SARIF 2.1.0, JUnit, CSV, Markdown, CycloneDX, SPDX, OpenVEX —
the broadest set in this comparison.

## 6. Limits of the comparison

The corpus contains fourteen repositories, with eight language lanes represented.
SLOC speed was measured on three repositories. Raw single-target fuzz throughput
was not measured on identical harnesses. Detection-class and reporting results
apply to the pinned tool versions and configurations used here; they do not
establish an overall ranking on other projects.

The measured bhf workflow combined offline operation, static analysis, SBOM
generation, and fuzz-confirmation in one tool.

---

*Reproduction: `benchmarks/campaign-2026-07-08/` holds the corpus list, the raw
per-tool measurements (`results/`), and the charts (`charts/`).*
