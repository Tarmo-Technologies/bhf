# 2026-07-08 campaign: scorecard and gap list

This page records bhf 0.2.14 as measured on 2026-07-08 and 2026-07-09 against
the tools in the [campaign README](../README.md). Later releases added some
items from the gap list, such as the `bhf sloc` command (item 9) and the
`spdx-json` SBOM output, `bhf sbom --emit spdx-json` (item 7).

## Summary

| Feature area | Verdict | Deciding number |
|---|---|---|
| **Multi-lang auto-fuzzing (zero-harness)** | Only measured tool with it | 0 harnesses vs N for every other tool; 8 language lanes / 1 engine (the fuzz runs used C and Go); fuzzes broken/non-building code (c_jansson recovered build, no `compile_commands.json`) |
| **Fuzz-confirmation of static findings** | Only measured tool with it | Only measured tool doing static-to-dynamic confirmation |
| **Static C/C++** | Higher precision, behind on volume and classes | cppcheck raw 465–1711 vs bhf 37–141, but ~90% of cppcheck is style/info; bhf is the only measured tool with taint-to-sink + CWE. Behind on scanf/gets, printf-arg-type, dangling-lifetime, resource-leak classes |
| **Static Go** | Strongest measured signal | Only tool producing findings on both repos: go_gin bhf 14 vs gosec **0** (build-gated fail) vs semgrep 20 Go-code results (17 of them one style rule). go_cobra bhf 14 ≥ gosec 11 |
| **Static Java** | Strongest measured signal | bhf 5 (3× deserialization) vs semgrep 2 (both CI-configuration warnings); only measured tool surfacing `ObjectInputStream` sinks |
| **Static Rust** | Strong security signal, behind on raw count | Only measured tool catching the build.rs command-injection taint (1–0); semgrep 20 vs bhf 13, with all 20 semgrep results action-pin warnings |
| **Static Python** | **Mixed / behind** | py_requests bhf **leads** (14 HIGH taint vs bandit 0 substantive); py_click bhf **behind** (0 findings vs bandit 23 substantive, semgrep 3) |
| **Static Perl** | Behind on count, higher-severity findings | perlcritic 221 > semgrep 31 > bhf 18; bhf's 18 are eval/shell/weak-crypto findings, and it misses the insecure-websocket class |
| **SBOM component discovery** | Mixed by ecosystem | Ties syft on go (42/42, 7/7) and maven (21/21, 8/8); exceeds syft 45–0 (npm) and 6–0 (cargo); trails on py_click, 30 vs 81 (transitive) |
| **SBOM CVE matching** | **Behind** | grype 11 (py_click) + 1 (java_gson) vs bhf **0 everywhere**: null versions from manifests cannot match CVE ranges |
| **Report content** | Broadest measured combination | Only measured tool with codeFlows + fuzz-confirm provenance + reachability verdict + root-cause clustering + VEX combined |
| **Report formats** | Competitive, 3 gaps | No SPDX (syft leads), no per-finding CWE in primary JSON (bandit leads), no remediation text (semgrep/bandit lead) |
| **SLOC counting** | Behind on speed, close to cloc | tokei/scc ~0.1s vs bhf **16.5s (~150×)**; counts align with cloc and avoid the measured Perl and docstring overcounts |

## Gap list, by impact

### P0: structural gaps that decide a whole feature area

1. **SBOM CVE matching: bhf finds 0 CVEs everywhere; grype finds 11
   (py_click) + 1 (java_gson).** The measured cause is missing versions: bhf
   parses `pyproject.toml`/`pom.xml` with `version: null`, and a null version
   cannot match a CVE range. **Proposed: ingest lockfiles**: `uv.lock`,
   `poetry.lock`, pinned `requirements.txt`,
   `package-lock.json`/`pnpm-lock.yaml`, `Cargo.lock`, and Maven transitive
   resolution. Lockfiles carry both the
   pinned versions for the CVE gap and the transitive closure for the Python
   depth gap (81 against 30). The campaign ranks this fix first.

2. **Static Python on py_click found nothing: bhf 0, bandit 23 substantive,
   semgrep 3.** On a 17.8k-SLOC repository with no taint-reachable sink, bhf
   reports nothing (24 `unresolved_project_local_call` gaps, 0 findings).
   **Proposed: non-taint syntactic Python rules** for the classes bandit's
   B603/B607/B110/B311 catch: `subprocess` partial-path/`shell=` execution
   (CWE-78/426), `try/except/pass` swallowing (CWE-703), and non-crypto
   `random.*` in a security context (CWE-330). Why the weak-PRNG rule
   (BHF-428) did not fire on py_click's 3 `random` sites is open; untested
   possible causes are a strict context gate or a Python lane not wired to
   BHF-428.

3. **Go findings have an empty CWE field.** Every BHF-405/404/426/427/436/472
   finding in both Go reports shipped `cwe=` blank, while gosec ships
   `G304`/`G302` and semgrep ships CWE metadata, so SARIF and compliance
   consumers get no CWE mapping. **Proposed: populate** BHF-405 as
   CWE-22/73, BHF-404 as CWE-78, BHF-426 as CWE-295, BHF-427 as CWE-918, and
   BHF-436 as CWE-789. Item 6 covers the same defect at the schema level.

### P1: detection classes other tools catch on real code

4. **C/C++ bug classes cppcheck catches and bhf drops:**
   - A `scanf`/`gets`-family unbounded read becomes an `analysis_gap` in place
     of a finding. Both semgrep (`insecure-use-scanf-fn`) and cppcheck flag
     it; bhf emits **0**. Proposed: a lexical/AST rule (CWE-120/CWE-676).
   - `printf`/format **argument-type** mismatch (`invalidPrintfArgType`, 8 in
     zlib). bhf has CWE-134 for an untrusted *format*, and no argument-type
     checker.
   - Dangling-lifetime returns (`returnDanglingLifetime`,
     `returnTempReference`, `autoVariables`, CWE-562).
   - Resource leak (`fopen`/`malloc` without close/free, CWE-772); the
     file-open sink already tracked for BHF-405 could be reused.

5. **Insecure-transport and insecure-websocket rule (all lanes).** semgrep's
   `detect-insecure-websocket` (`ws://` against `wss://`) and cleartext-URL
   detection is the one class where semgrep found more than bhf on Perl code
   (perl_mojo). Proposed: a cleartext/insecure-transport-scheme rule
   (CWE-319) across lanes.

### P2: reporting and output parity (low cost)

6. **Per-finding CWE missing from the primary static JSON and Markdown**
   (present only in SARIF tags and the auto CSV). Bandit puts `issue_cwe` on
   every JSON finding. Proposed: a top-level `cwe` field in the static-scan
   finding schema and a CWE column in the Markdown table. This also fixes the
   Go empty-CWE gap (item 3) at the schema level.

7. **No SPDX SBOM.** syft emits SPDX-2.3 JSON and tag-value; bhf emitted
   CycloneDX/VEX only. SPDX is the more common procurement requirement.
   Proposed: `spdx-json` and `spdx-tag-value` emitters.

8. **No remediation or help text.** bhf emitted no `help`, `helpUri` or fix
   text; semgrep (`help`+`helpUri`) and bandit (`more_info`) both do. This is
   the one report-content axis where bhf had nothing. Proposed: per-rule
   `help`+`helpUri` in SARIF and a `remediation` field on JSON findings.

### P3: speed and breadth

9. **SLOC is ~150× slower than tokei (16.5s against 0.09s).** Proposed: a
   standalone `bhf sloc <path>` or `--sloc-only` fast path that skips the
   SAST parse and counts several roots in one invocation, removing the
   full-scan cost from SLOC counting. Secondary: an optional
   `c_header`/`cpp_header` split for like-for-like comparison.

10. **Auto-harness coverage on hard signatures.** 3/5 C + 2/5 Go targets were
    skipped as "could not auto-harness" (variadic
    `json_vpack_ex`/`json_vunpack_ex`, Go template-func/ActiveHelp closures).
    Supporting these signatures would raise the built-and-fuzzed ratio.
    Secondary: cache the recovered-build archive so per-target re-linking of
    12 translation units does not use up the fuzz budget (c_jansson measured
    19 exec/s).

11. **Rust code-rule breadth.** Outside the build.rs taint finding, bhf had
    few Rust code rules, and 12 of its 13 Rust findings on rust_semver were
    GitHub Actions findings. Candidates: unsafe-usage context and
    panic-in-lib.

## Measurement scope

**Where bhf led the selected tools in this measurement:**

- **Zero-harness multi-language fuzzing.** 0 harnesses against N per target
  for AFL++/libFuzzer/cargo-fuzz/Jazzer; 8 language lanes under one engine
  against 1–2 each (the fuzz runs used C and Go); and it fuzzed
  **broken/non-building code** (c_jansson: recovered a partial build, linked
  the 12-source TU set, stubbed 3 dependencies, no `compile_commands.json`).
- **Fuzz-confirmation of static findings.** None of the other measured tools
  performed static-to-dynamic confirmation.
- **Static analysis, fuzzing, SBOM, SLOC and reporting in one offline tool.**
  Build independence was measured: gosec returned **0** on go_gin because it
  could not build under Go 1.22 when the repository requires 1.25, and bhf
  returned 14 taint findings without a build.
- **Report content**: the only measured tool combining codeFlows dataflow,
  fuzz-confirm provenance, reachability verdicts, root-cause clustering, and
  VEX.
- **Accuracy details**: SLOC counts closer to cloc than scc's and tokei's
  (their Perl ~2.5× overcount and docstring counting); bhf reads npm and
  cargo manifests that syft needs a lockfile to see (45–0, 6–0).

**Where dedicated single-purpose tools led in this measurement:**

- **Raw SLOC speed**: tokei and scc were about 150 times faster (0.09s
  against 16.5s). They are purpose-built line counters; bhf counted as a side
  effect of a full tree-sitter SAST parse.
- **CVE matching at measurement time**: grype+syft reported 11 + 1 CVEs
  against 0 because they read pinned lockfiles (see P0 item 1).
- **Python breadth on repositories without a taint-reachable sink** (bandit),
  **Perl style and volume** (perlcritic), and **remediation text**
  (semgrep/bandit).

**Not measured:** raw fuzz throughput on a mature single target, which needs
an hours-long, identical-harness comparison. The specialist fuzzers have
mature mutator engineering and integrations.

**Measured result:** bhf led the selected tools on zero-setup multi-language
fuzzing, fuzz-confirmation, the integrated offline workflow, and combined
report content. Dedicated tools led on SLOC counting speed, CVE matching, and
several detection classes. The listed gaps were candidates for follow-up. The
results describe this 14-repository corpus.
