# Executive summary

| Feature area | Verdict | Deciding number |
|---|---|---|
| **Multi-lang auto-fuzzing (zero-harness)** | Unique in the measured set | 0 harnesses vs N for every competitor; 8 langs / 1 engine; fuzzes broken/non-building code (c_jansson recovered build, no `compile_commands.json`) |
| **Fuzz-confirmation of static findings** | Unique in the measured set | Only measured tool doing static→dynamic confirmation |
| **Static C/C++** | Higher precision, behind on volume and classes | cppcheck raw 465–1711 vs bhf 37–141, but ~90% of cppcheck is style/info; bhf is the only measured tool with taint→sink + CWE. Loses on scanf/gets, printf-arg-type, dangling-lifetime, resource-leak classes |
| **Static Go** | Strongest measured signal | Only tool producing signal on both repos: go_gin bhf 14 vs gosec **0** (build-gated fail) vs semgrep 20 (mostly CI-noise). go_cobra bhf 14 ≥ gosec 11 |
| **Static Java** | Strongest measured signal | bhf 5 (3× deserialization) vs semgrep 2 (both CI-noise); only measured tool surfacing `ObjectInputStream` sinks |
| **Static Rust** | Strong security signal, behind on raw count | Only measured tool catching build.rs command-injection taint (1–0); semgrep 20 vs bhf 13 but all 20 semgrep = action-pin spam |
| **Static Python** | **Mixed / behind** | py_requests bhf **wins** (14 HIGH taint vs bandit 0 substantive); py_click bhf **loses** (0 findings vs bandit 23 substantive, semgrep 3) |
| **Static Perl** | Behind on count, higher-severity findings | perlcritic 221 > semgrep 31 > bhf 18; bhf's 18 are eval/shell/weak-crypto findings, but it misses the insecure-websocket class |
| **SBOM component discovery** | Mixed by ecosystem | Ties syft on go (42/42, 7/7) and maven (21/21, 8/8); exceeds syft 45–0 (npm) and 6–0 (cargo); trails on py_click, 30 vs 81 (transitive) |
| **SBOM CVE correlation** | **Behind** | grype 11 (py_click) + 1 (java_gson) vs bhf **0 everywhere** — null versions from manifests can't match CVE ranges |
| **Reporting richness** | Broadest measured combination | Only measured tool with codeFlows + fuzz-confirm provenance + reachability verdict + root-cause clustering + VEX combined |
| **Reporting breadth** | Competitive, 3 fixable gaps | No SPDX (syft wins), no per-finding CWE in primary JSON (bandit wins), no remediation text (semgrep/bandit win) |
| **SLOC counting** | Behind on speed, close to cloc | tokei/scc ~0.1s vs bhf **16.5s (~150×)**; counts align with cloc and avoid the measured Perl and docstring overcounts |

---

# GAP LIST (prioritized by impact)

### P0 — Structural gaps that flip a whole feature from "behind" to "leading"

1. **SBOM CVE correlation: bhf finds 0 CVEs everywhere; grype finds 11 (py_click) + 1 (java_gson).**
   Root cause is measured, not the DB: bhf parses `pyproject.toml`/`pom.xml` with `version: null`; a null version can't match a CVE range. **Fix: ingest lockfiles** — `uv.lock`, `poetry.lock`, pinned `requirements.txt`, `package-lock.json`/`pnpm-lock.yaml`, `Cargo.lock`, maven transitive resolution. This single fix closes **both** the CVE gap (pinned versions) **and** the Python transitive-depth gap (81 vs 30). Highest-leverage item in the whole campaign.

2. **Static Python py_click zero-finding miss: bhf 0 vs bandit 23 substantive vs semgrep 3.**
   On a 17.8k-SLOC repo with no taint-reachable sink, bhf goes silent (24 `unresolved_project_local_call` gaps, 0 findings). **Fix: add non-taint syntactic Python rules** for the classes bandit's B603/B607/B110/B311 catch — `subprocess` partial-path/`shell=` exec (CWE-78/426), `try/except/pass` swallowing (CWE-703), non-crypto `random.*` in security context (CWE-330). Also verify why the existing weak-PRNG rule (BHF-428) didn't fire on py_click's 3 `random` sites — likely context-gate too strict or Python lane not wired to BHF-428.

3. **Go findings have empty CWE field.** Every BHF-405/404/426/427/436/472 finding in both Go reports shipped `cwe=` blank while gosec ships `G304`/`G302` and semgrep ships CWE metadata. This undercuts an otherwise-winning result for SARIF/compliance consumers. **Fix: populate** BHF-405→CWE-22/73, BHF-404→CWE-78, BHF-426→CWE-295, BHF-427→CWE-918, BHF-436→CWE-789. (Note: this is a broader defect — see #6.)

### P1 — Missing detection classes competitors catch on real code

4. **C/C++ missing bug classes cppcheck catches and bhf drops:**
   - `scanf`/`gets`-family unbounded read is dropped to an `analysis_gap`, not a finding — both semgrep (`insecure-use-scanf-fn`) and cppcheck flag it; bhf emits **0**. Add lexical/AST rule (CWE-120/CWE-676).
   - `printf`/format **argument-type** mismatch (`invalidPrintfArgType`, 8 in zlib) — bhf has CWE-134 for untrusted *format* but no arg-type checker.
   - Dangling-lifetime returns (`returnDanglingLifetime`/`returnTempReference`/`autoVariables`, CWE-562).
   - Resource leak (`fopen`/`malloc` without close/free, CWE-772) — reuse the file-open sink already tracked for BHF-405.

5. **Insecure-transport / insecure-websocket rule (all lanes).** semgrep's `detect-insecure-websocket` (ws:// vs wss://) + cleartext-URL is the one class semgrep out-finds bhf on real Perl code (perl_mojo). Add a cleartext/insecure-transport-scheme rule (CWE-319) across lanes.

### P2 — Reporting/output parity (cheap, high perceived value)

6. **Per-finding CWE missing from primary static JSON + Markdown** (present only in SARIF tags + auto CSV). Bandit puts `issue_cwe` on every JSON finding. Add a top-level `cwe` field to the static-scan finding schema and a CWE column to the MD table. This also fixes the Go empty-CWE gap (#3) at the schema level.

7. **No SPDX SBOM.** syft emits SPDX-2.3 JSON + tag-value; bhf emits CycloneDX/VEX only. SPDX is the more common procurement mandate. Add `spdx-json` + `spdx-tag-value` emitters.

8. **No remediation/help text.** bhf emits zero `help`/`helpUri`/fix text; semgrep (help+helpUri) and bandit (more_info) both do. This is the one richness axis where bhf is flatly behind. Add per-rule `help`+`helpUri` to SARIF and a `remediation` field to JSON findings.

### P3 — Speed / breadth polish

9. **SLOC is ~150× slower than tokei (16.5s vs 0.09s).** Offer a standalone `bhf sloc <path>` / `--sloc-only` fast path that skips the SAST parse and supports whole-corpus multi-root in one invocation. Won't beat purpose-built counters on speed, but removes the "accurate-but-unusably-slow" penalty. Secondary: emit optional `c_header`/`cpp_header` split for apples-to-apples comparison.

10. **Auto-harness coverage on hard signatures.** 3/5 C + 2/5 Go targets skipped as "could not auto-harness" (variadic `json_vpack_ex`/`json_vunpack_ex`, Go template-func/ActiveHelp closures). Supporting these signatures would raise the measured built-and-fuzzed ratio. Secondary: cache the recovered-build archive so per-target re-linking of 12 translation units does not consume the fuzz budget (c_jansson measured 19 exec/s).

11. **Rust code-rule breadth.** Outside the build.rs taint finding, bhf has near-zero Rust *code* rules and pads its Rust count with GH-Actions findings. Add unsafe-usage-context, panic-in-lib, etc.

---

# Measurement scope

**Where bhf led the selected tools in this measurement:**
- **Zero-harness multi-language fuzzing.** 0 harnesses vs N-per-target for AFL++/libFuzzer/cargo-fuzz/Jazzer; 8 languages under one engine vs 1–2 each; and it fuzzed **broken/non-building code** (c_jansson: recovered a partial build, linked 12-source TU set, stubbed 3 deps, no `compile_commands.json`).
- **Fuzz-confirmation of static findings.** None of the other measured tools performed static-to-dynamic confirmation.
- **Integrated static + dynamic + SBOM + SLOC + reporting** in one offline/air-gapped tool. The build-independence is a *measured* advantage, not a marketing claim: gosec returned literally **0** on go_gin because it couldn't build under Go 1.22 while the repo demands 1.25; bhf's 14 taint findings didn't care.
- **Reporting richness**: the only measured tool combining codeFlows dataflow, fuzz-confirm provenance, reachability verdicts, root-cause clustering, and VEX.
- **Correctness sub-wins**: cleaner SLOC than scc/tokei (Perl ~2.5× overcount, docstring miscounting); reads npm/cargo manifests syft needs a lockfile to see (45–0, 6–0).

**Where dedicated single-purpose tools won in this measurement:**
- **Raw SLOC speed**: tokei/scc are ~150× faster (0.09s vs 16.5s). They always will be — they're purpose-built line counters; bhf counts as a side-effect of a full tree-sitter SAST parse.
- **Raw fuzz throughput on a mature single target**: this was **not** quantified with an hours-long, identical-harness comparison. The specialist tools have mature mutator engineering and integrations; the campaign does not rank their throughput against bhf.
- **CVE correlation at measurement time**: grype+syft reported 11 + 1 CVEs versus 0 because they read pinned lockfiles (see P0 item 1).
- **Python breadth on non-taint-reachable repos** (bandit), **Perl style/volume** (perlcritic), and **remediation text** (semgrep/bandit) are real, current deficits.

**Measured result:** bhf led the selected tools on zero-setup multi-language
fuzzing, fuzz-confirmation, integrated offline workflow, and combined report
content. Dedicated tools led on raw counting and fuzzing speed, CVE correlation,
and several detection classes. The listed gaps were candidates for follow-up;
this 14-repository campaign does not establish an overall product ranking.
