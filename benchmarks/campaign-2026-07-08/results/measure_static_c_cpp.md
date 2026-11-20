# C/C++ static scan: bhf, cppcheck, flawfinder and semgrep (2026-07-08 campaign)

Measured 2026-07-09 on the campaign host. Tools: cppcheck 2.13.0, flawfinder 2.0.20, semgrep 1.168.0, bhf `target/debug/bhf`. Corpus: `benchmarks/campaign-2026-07-08/corpus/{c_zlib,c_jansson,cpp_json,cpp_fmt}`.

The measurement found gaps in bhf's C lane. bhf treated `scanf` as an unresolved-call analysis gap where semgrep and cppcheck flagged `scanf` and format-string cases. cppcheck also found dangling-lifetime returns, argument-type mismatches, and resource leaks that bhf's heuristic lane missed at the time.

## Metrics table (finding counts)

| Repo | bhf | cppcheck (raw `wc -l`) | cppcheck (real `<error>`) | flawfinder (task cmd `grep -c ':'`) | flawfinder (real hits) | semgrep (`results`) |
|---|---|---|---|---|---|---|
| c_zlib | 141 | 477 | 465 | 342 | 296 | 28 |
| c_jansson | 34 | 878 | 270 | 129 | 123 | 9 |
| cpp_json | 37 | 5360 | 1711 | 166 | 161 | 4 |
| cpp_fmt | 42 | 2834 | 859 | 232 | 227 | 7 |

Notes on the raw counts:

- **cppcheck's raw `wc -l` count includes `information` and `checkers-report` lines.** The distinct `<error>` elements are fewer, and most of those are not security results: on cpp_json, the 1711 errors are **35** `error`+`warning` (security-relevant), 272 style, 103 performance and 1298 informational. On c_zlib, the 465 are 25 security, 204 style and 234 informational. cppcheck's memory-safety results are a small fraction of its raw count.
- **flawfinder's `grep -c ':'` also counts header and footer lines**; the `[level]` hit lines are 296/123/161/227. flawfinder is a lexical match on every `strcpy`/`memcpy`/`sprintf` token, with no flow analysis, so its hits are unranked and unconfirmed.
- An earlier concurrent cppcheck run reported c_zlib=130 errors; that run was CPU-contended and timed out mid-scan. The clean 300 s re-run gives **465**, the number in the table.

## What each tool finds (classes)

- **bhf**: security-typed findings with CWE, severity, confidence, remediation and dataflow. The clustered CWE distribution (issues view): CWE-120 unbounded copy, CWE-22 path traversal (BHF-405 path-controlled open, 39 in zlib), CWE-134 format string, CWE-190 integer overflow, CWE-457 uninitialized use, CWE-787 out-of-bounds write, CWE-494 unpinned CI action, CWE-829/415/362. Every finding carries `analysis.path.predicates` (guard conditions), an `evidence` snippet, `actionability.verdict`, and `analysis_gaps` for unresolved interprocedural calls. Its taint and behavioral findings are fuzz-confirmable and CWE-tagged; the compared configurations did not provide an equivalent taint-to-sink path.
- **cppcheck**: a flow-sensitive C/C++ engine. Its security-relevant `error`/`warning` results in zlib: `uninitvar`, `returnDanglingLifetime`, `returnTempReference`, `autoVariables` (returns the address of a local), `resourceLeak`, `invalidPrintfArgType`, `nullPointer`, `ctuOneDefinitionRuleViolation`. A low count, in **memory-safety classes bhf's heuristic lane did not emit** (dangling lifetime, printf argument-type mismatch, resource leak).
- **flawfinder**: lexical matching, with high volume, no flow analysis and no confirmation.
- **semgrep `--config=auto`**: on C/C++ almost all results were YAML and CI configuration rules, `github-actions-mutable-action-tag` (26/7/2/0) and `dependabot-missing-cooldown`. The C-code rules that fired were `insecure-use-scanf-fn` (2, c_zlib) and Python rules that misfired on cpp_json (`direct-use-of-jinja2`). Beyond `insecure-use-scanf-fn`, no C/C++ memory-safety rule fired in this configuration.

## Result

cppcheck and flawfinder produced larger raw counts, dominated by style, informational, or lexical results. In the measured configurations, bhf alone emitted path-traversal and command-taint findings with dataflow predicates, CWE mapping, remediation, and fuzz-confirmability. cppcheck also found defect classes that bhf lacked, listed below.

## Gaps found

1. **`scanf`/`gets`-family unbounded reads became an `analysis_gap` in place of a finding.** In c_zlib, both semgrep (`insecure-use-scanf-fn`) and cppcheck flag `scanf("%1s",answer)` at `contrib/minizip/miniunz.c:392` and `minizip.c:343`. bhf recorded these two as `unresolved_project_local_call` gaps (`scanf` callee) and emitted **0** scanf findings. Proposed: a lexical/AST rule (CWE-120/CWE-676) for unbounded `scanf`/`gets` reads, so the gap becomes a finding. Both other tools flag this class.
2. **printf/format argument-type mismatch (`invalidPrintfArgType`, 8 in zlib) and dangling-lifetime returns (`returnDanglingLifetime`, `returnTempReference`, `autoVariables`) are cppcheck-only classes.** bhf has format-string (CWE-134) for an *untrusted* format argument, and no printf argument-type checker or return-of-local/temp-reference (CWE-562) rule. Adding these would cover the classes where cppcheck found defects bhf did not.
3. **Resource leak (CWE-772) on `fopen`/`malloc` without a matching close/free.** cppcheck's `resourceLeak` fires in zlib; bhf had no leak rule in the C lane. A heuristic could reuse the file-open sink bhf already tracks for BHF-405.

Artifacts: bhf reports at `/tmp/bhf_{repo}/static-report.json`; cppcheck XML at `/tmp/ccz.xml` (zlib) and `/tmp/cc_{jansson,cpp_json,cpp_fmt}.xml`; semgrep JSON at `/tmp/sg_{repo}.json`.
