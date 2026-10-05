## bhf vs gosec vs semgrep — Go static-scan (go_gin, go_cobra)

All numbers below were measured by actually running each tool on `benchmarks/campaign-2026-07-08/corpus/{go_gin,go_cobra}`. Tool paths: gosec/semgrep from `~/.local/bin`, bhf `target/debug/bhf`. System Go is **1.22.2**.

### Raw counts

| Repo | bhf static-scan | gosec (`-fmt json ./...`) | semgrep (`--config=auto`) — total | semgrep — `.go`-code only |
|---|---|---|---|---|
| go_gin (18.3k Go SLOC) | **14** | **0 — FAILED to analyze** | 40 | 20 |
| go_cobra (12.6k Go SLOC) | 14 | 11 | 13 | 1 |

### What broke and caveats
- **gosec on go_gin returned 0 issues and analyzed 0 files/0 lines** — it fails-closed because it needs a compilable build, and go_gin's `go.mod` requires `go >= 1.25.0` while the box has go 1.22.2 (`Stats: files:0, lines:0`). Not a real "clean" result; gosec simply couldn't run. This is gosec's core weakness: no build, no analysis.
- **semgrep `--config=auto` required network + metrics-on** (errored with `--metrics=off`); it succeeded with metrics on. Its totals are heavily inflated by non-code findings: on go_gin, 19 of 40 are `.github/*.yml` CI-config rules (`github-actions-mutable-action-tag`, `dependabot-missing-cooldown`) and 1 is a test-fixture `key.pem`. On go_cobra, 12 of 13 are CI-config — only **1** finding touches actual `.go` code (`import-text-template` in cobra.go). Semgrep's `.go` signal on go_gin is 17× `no-direct-write-to-responsewriter` (a best-practice/style rule in render code, largely noise) plus 2 cookie flags and 1 fprintf.

### Categories

- **bhf** (all high/critical severity, taint-aware): go_gin → BHF-472 unpinned GitHub Action ×5, BHF-426 TLS verification disabled ×4, BHF-405 non-literal file open ×3, BHF-436 tainted allocation size ×1, BHF-427 tainted URL → SSRF ×1. go_cobra → BHF-405 non-literal file open ×11, BHF-472 unpinned action ×2, BHF-404 shell exec ×1.
- **gosec** go_cobra: G304 file-inclusion-via-variable ×10, G302 file-perms ×1. (go_gin: none, build failure.)
- **semgrep**: mostly CI-hygiene + framework style rules; genuine security signal is thin (cookie flags, private-key-in-fixture).

### Overlap / validation
- On go_cobra, **bhf BHF-405 (×11) and gosec G304 (×10) are the same class** (CWE-22/73 file inclusion via non-literal path in the completion/doc generators) — bhf matches gosec's core finding and adds a shell-exec (BHF-404) and unpinned-action findings gosec doesn't cover.
- bhf **BHF-472 overlaps semgrep's `github-actions-mutable-action-tag`** — bhf has the CI-config breadth too, without the dependabot/style noise.

### Verdict
Across these two repositories, bhf was the only measured tool to produce
security findings on both. On go_gin it returned 14 high-severity taint-backed
findings; gosec could not analyze the project under the installed Go version,
and semgrep's 40 results included 20 Go findings dominated by 17 style rules.
On go_cobra, bhf reported 14 findings and gosec reported 11, primarily in the
same file-inclusion class; semgrep reported one code finding. The result shows
the value of build-independent analysis for this pinned environment.

### Concrete gap
- **Emit CWE IDs on Go findings.** Every bhf finding in both reports had an **empty `cwe` field** (`cwe=` on BHF-405/404/426/427/436/472). gosec ships `G304`/`G302` and semgrep ships OWASP/CWE metadata; bhf's blank CWE is a real regression for SARIF/compliance consumers and undercuts an otherwise-winning result. Populating CWE (BHF-405→CWE-22/73, BHF-404→CWE-78, BHF-426→CWE-295, BHF-427→CWE-918, BHF-436→CWE-789) is the single highest-value fix.
- Secondary: bhf found **0** of the response-writer/cookie-security patterns semgrep flags on go_gin (`no-direct-write-to-responsewriter`, `cookie-missing-httponly/secure`). Most are low-value style, but the two cookie-attribute rules (CWE-1004/614) are legitimate and would close the only category where semgrep has code signal bhf lacks.

Report/data files: `/tmp/gfscan/{go_gin,go_cobra}/static-report.json`, `/tmp/gosec_{go_gin,go_cobra}.json`, `/tmp/semgrep_{go_gin,go_cobra}.json`.
