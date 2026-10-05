All numbers below were measured on the pinned repositories.

## Python SAST comparison: bhf vs bandit vs semgrep

All three tools ran cleanly on both repos (no errors, no timeouts). Numbers are real, measured 2026-07-09.

### Raw finding counts

| Repo (SLOC) | Tool | Total | Severity mix | Categories (rule → count) |
|---|---|---|---|---|
| **py_click** (17,818) | bandit | **1325** | 1322 LOW / 3 MED | B101 assert 1292, B603 subprocess 10, B404 8, B110 try-except-pass 7, B311 rand 3, B108 tmp 3, B606/B607 1 |
| | semgrep (--config=auto) | **3** | 1 MED/1 ERR/1 WARN | uv-missing-dependency-cooldown 1, python36-Popen1 1, dangerous-globals-use 1 |
| | **bhf** | **0** | — | (24 analysis gaps: `unresolved_project_local_call`) |
| **py_requests** (7,575) | bandit | **708** | 581 LOW / 127 MED | B101 assert 579, B113 request-without-timeout 120, B301 pickle 7, B403 1, B105 hardcoded-pw 1 |
| | semgrep (--config=auto) | **3** | 3 WARN | insecure-hash-sha1 2, non-literal-import 1 |
| | **bhf** | **14** | 14 HIGH | BHF-421 unsafe-deserialization 7, BHF-426 TLS-verify-disabled 4, BHF-427 SSRF (taint) 3 |

### Signal quality (the raw counts are misleading)

Bandit's totals are dominated by test-file noise. After excluding test files and `assert_used` (B101), the substantive bandit signal is **23 findings in py_click, 0 in py_requests**:
- **py_click**: 1290 of 1325 findings (97%) are in test files; 1292 are bare `assert`.
- **py_requests**: 692 of 708 (98%) are in test files; **every non-test finding is an assert or timeout** — 0 substantive non-test findings after filtering.

Bandit's much larger raw count consists mostly of `assert` in tests plus
`requests(...)` without a `timeout=`. Semgrep's auto ruleset reported three
findings per repository.

### bhf-specific results

- **Taint-traced, HIGH-severity vuln classes** none of the others surfaced on py_requests: BHF-421 unsafe deserialization (pickle/marshal/yaml, CWE-502), BHF-426 TLS cert/hostname verification disabled (CWE-295), BHF-427 SSRF via tainted URL reaching an outbound HTTP request (CWE-918) — with a full `taint_trace` (assignment → project-local calls → sink), engine `bhf.static.taint.v1`. Bandit reports B301 (pickle *import/usage*, no dataflow) but never reaches SSRF or TLS-verify-disabled as taint findings. Semgrep's auto config missed all three classes on py_requests.
- **Deduped, non-noisy output**: 14 findings all HIGH, no test-assert flood — vs bandit's 708/1325 that a human must triage down to ~0–23.
- Emits SARIF/JSON/Markdown with baseline-diff (`new`/`unchanged`/`resolved`) and records 24/36 unresolved project-local calls in `analysis_gaps`.

### Verdict

The result was mixed: bhf did not lead by raw count, but it produced the
high-severity taint findings measured on py_requests.

- **py_requests:** bhf reported 14 high-severity taint findings (SSRF,
  deserialization, and TLS); bandit had no substantive non-test findings, and
  semgrep reported three SHA-1/import findings.
- **py_click:** bhf reported no findings; semgrep reported three, and bandit had
  23 substantive findings covering subprocess use, swallowed exceptions, and
  weak random-number generation. bhf also emitted 24
  `unresolved_project_local_call` gaps.

### Concrete gaps

1. **py_click zero-finding miss** is the priority: add non-taint syntactic rules for the classes bandit caught and bhf has no equivalent for — `subprocess` without `shell=` review / partial-path exec (B603/B607, CWE-78/426), `try/except/pass` swallowing (B110, CWE-703), and non-crypto `random.*` used in a security context (B311, CWE-330). bhf already ships a weak-PRNG rule (BHF-428) per memory — verify why it didn't fire on py_click's 3 `random` sites (likely context-gate too strict, or Python lane not wired to BHF-428).
2. **Resolve `unresolved_project_local_call` gaps** (24 in click, 36 in requests): bhf's taint engine is dropping intra-project call edges it can't resolve, which both suppresses findings and inflates the gap count. Improving the Python decl-index / call resolution would let the taint lane reach sinks it currently can't, directly converting gaps into findings.

The py_requests result demonstrates bhf's taint analysis. The py_click result
shows that the measured Python rule coverage was incomplete.
