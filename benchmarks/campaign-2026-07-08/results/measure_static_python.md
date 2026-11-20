# Python static scan: bhf, bandit and semgrep (2026-07-08 campaign)

Measured 2026-07-09 on the pinned repositories. All three tools ran on both
repositories without errors or timeouts.

## Raw finding counts

| Repo (SLOC) | Tool | Total | Severity mix | Categories (rule → count) |
|---|---|---|---|---|
| **py_click** (17,818) | bandit | **1325** | 1322 LOW / 3 MED | B101 assert 1292, B603 subprocess 10, B404 8, B110 try-except-pass 7, B311 rand 3, B108 tmp 3, B606/B607 1 |
| | semgrep (--config=auto) | **3** | 1 MED/1 ERR/1 WARN | uv-missing-dependency-cooldown 1, python36-Popen1 1, dangerous-globals-use 1 |
| | **bhf** | **0** | — | (24 analysis gaps: `unresolved_project_local_call`) |
| **py_requests** (7,575) | bandit | **708** | 581 LOW / 127 MED | B101 assert 579, B113 request-without-timeout 120, B301 pickle 7, B403 1, B105 hardcoded-pw 1 |
| | semgrep (--config=auto) | **3** | 3 WARN | insecure-hash-sha1 2, non-literal-import 1 |
| | **bhf** | **14** | 14 HIGH | BHF-421 unsafe-deserialization 7, BHF-426 TLS-verify-disabled 4, BHF-427 SSRF (taint) 3 |

## Substantive findings after filtering

Most of bandit's results are in test files. After excluding test files and
`assert_used` (B101), bandit has **23 substantive findings in py_click and 0
in py_requests**:

- **py_click**: 1290 of 1325 findings (97%) are in test files; 1292 are bare
  `assert`.
- **py_requests**: 692 of 708 (98%) are in test files, and **every non-test
  finding is an assert or a missing timeout**, so 0 substantive non-test
  findings remain after filtering.

Bandit's much larger raw count consists mostly of `assert` in tests plus
`requests(...)` without a `timeout=`. Semgrep's auto ruleset reported three
findings per repository.

## bhf results

- **Taint-traced, HIGH-severity classes** that the other tools did not report
  on py_requests: BHF-421 unsafe deserialization (pickle/marshal/yaml,
  CWE-502), BHF-426 TLS certificate/hostname verification disabled (CWE-295),
  and BHF-427 SSRF through a tainted URL reaching an outbound HTTP request
  (CWE-918). Each has a full `taint_trace` (assignment, project-local calls,
  sink) from the `bhf.static.taint.v1` engine. Bandit reports B301 (pickle
  import and use, no dataflow) and reports neither SSRF nor disabled TLS
  verification as taint findings. Semgrep's auto config reported none of the
  three classes on py_requests.
- **Deduplicated output**: 14 findings, all HIGH, with no test-file asserts.
  Bandit's 708 (py_requests) and 1325 (py_click) need manual filtering down to
  0 and 23.
- bhf writes SARIF, JSON and Markdown with a baseline diff
  (`new`/`unchanged`/`resolved`), and records 24 (py_click) and 36
  (py_requests) unresolved project-local calls in `analysis_gaps`.

## Result

The result was mixed. bhf produced the high-severity taint findings measured
on py_requests; bandit had the larger raw count on both repositories.

- **py_requests:** bhf reported 14 high-severity taint findings (SSRF,
  deserialization, and TLS); bandit had no substantive non-test findings, and
  semgrep reported three SHA-1/import findings.
- **py_click:** bhf reported no findings; semgrep reported three, and bandit had
  23 substantive findings covering subprocess use, swallowed exceptions, and
  weak random-number generation. bhf also emitted 24
  `unresolved_project_local_call` gaps.

## Gaps found

1. **py_click returned zero findings**, which makes it the priority.
   Proposed: non-taint syntactic rules for the classes bandit caught and bhf
   had no equivalent for: `subprocess` partial-path execution and `shell=`
   review (B603/B607, CWE-78/426), `try/except/pass` swallowing (B110,
   CWE-703), and non-crypto `random.*` in a security context (B311, CWE-330).
   bhf has a weak-PRNG rule (BHF-428); why it did not fire on py_click's 3
   `random` sites is open. Untested possible causes: a context gate that is
   too strict, or a Python lane not wired to BHF-428.
2. **`unresolved_project_local_call` gaps** (24 in click, 36 in requests):
   each is an intra-project call the taint engine could not resolve, so the
   taint lane stopped there. Better Python declaration indexing and call
   resolution would let the taint lane follow those calls toward their
   sinks.

On py_requests, bhf's taint analysis found 14 high-severity findings. On
py_click, bhf's Python rules at the time found none of the classes bandit
reported.
