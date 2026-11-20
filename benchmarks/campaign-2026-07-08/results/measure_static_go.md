# Go static scan: bhf, gosec and semgrep (2026-07-08 campaign)

All numbers were measured by running each tool on
`benchmarks/campaign-2026-07-08/corpus/{go_gin,go_cobra}`. Tool paths:
gosec and semgrep from `~/.local/bin`, bhf `target/debug/bhf`. The system Go
is **1.22.2**.

## Raw counts

| Repo | bhf static-scan | gosec (`-fmt json ./...`) | semgrep (`--config=auto`) — total | semgrep — `.go`-code only |
|---|---|---|---|---|
| go_gin (18.3k Go SLOC) | **14** | **0 — FAILED to analyze** | 40 | 20 |
| go_cobra (12.6k Go SLOC) | 14 | 11 | 13 | 1 |

## Tool failures and non-code results

- **gosec on go_gin returned 0 issues and analyzed 0 files and 0 lines.**
  gosec needs a compilable build, and go_gin's `go.mod` requires
  `go >= 1.25.0` while the host had Go 1.22.2 (`Stats: files:0, lines:0`).
  The 0 is a failed analysis: gosec did not run on the code.
- **semgrep `--config=auto` required network access and metrics on** (it
  errored with `--metrics=off`) and succeeded with metrics on. Most of its
  results are non-code findings: on go_gin, 19 of 40 are `.github/*.yml`
  CI-configuration rules (`github-actions-mutable-action-tag`,
  `dependabot-missing-cooldown`) and 1 is a test-fixture `key.pem`. On
  go_cobra, 12 of 13 are CI configuration, and **1** finding touches `.go`
  code (`import-text-template` in cobra.go). semgrep's `.go` results on
  go_gin are 17× `no-direct-write-to-responsewriter` (a best-practice rule,
  here in render code), 2 cookie flags and 1 fprintf.

## Categories

- **bhf** (all high or critical severity, taint-aware): go_gin: BHF-472
  unpinned GitHub Action ×5, BHF-426 TLS verification disabled ×4, BHF-405
  non-literal file open ×3, BHF-436 tainted allocation size ×1, BHF-427
  tainted URL to SSRF ×1. go_cobra: BHF-405 non-literal file open ×11, BHF-472
  unpinned action ×2, BHF-404 shell exec ×1.
- **gosec** go_cobra: G304 file-inclusion-via-variable ×10, G302 file
  permissions ×1. go_gin: none, because the build failed.
- **semgrep**: mostly CI-hygiene and framework style rules; its
  security-relevant results were the cookie flags and the private key in a
  fixture.

## Overlap

- On go_cobra, **bhf's BHF-405 (×11) and gosec's G304 (×10) are the same
  class** (CWE-22/73 file inclusion through a non-literal path in the
  completion and doc generators). bhf matches gosec's main finding and adds a
  shell exec (BHF-404) and unpinned-action findings that gosec does not
  report.
- bhf's **BHF-472 overlaps semgrep's `github-actions-mutable-action-tag`**;
  bhf reports the unpinned-action class without the dependabot and style
  rules.

## Result

Across these two repositories, bhf was the only measured tool to produce
security findings on both. On go_gin it returned 14 high-severity taint-backed
findings; gosec could not analyze the project under the installed Go version,
and semgrep's 40 results included 20 Go findings, 17 of them one style rule.
On go_cobra, bhf reported 14 findings and gosec 11, mostly in the same
file-inclusion class; semgrep reported one code finding. In this pinned
environment, bhf's analysis ran without a build and gosec's did not.

## Gaps found

- **Emit CWE IDs on Go findings.** Every bhf finding in both reports had an
  **empty `cwe` field** (`cwe=` on BHF-405/404/426/427/436/472). gosec ships
  `G304`/`G302` and semgrep ships OWASP/CWE metadata; a blank CWE leaves SARIF
  and compliance consumers without the mapping. Proposed: BHF-405 to
  CWE-22/73, BHF-404 to CWE-78, BHF-426 to CWE-295, BHF-427 to CWE-918, and
  BHF-436 to CWE-789. The campaign ranked this the highest-value Go fix.
- Secondary: bhf found **0** of the response-writer and cookie-security
  patterns semgrep flags on go_gin (`no-direct-write-to-responsewriter`,
  `cookie-missing-httponly/secure`). The two cookie-attribute rules
  (CWE-1004/614) are the one category where semgrep had code findings that
  bhf lacked.

Report and data files: `/tmp/gfscan/{go_gin,go_cobra}/static-report.json`,
`/tmp/gosec_{go_gin,go_cobra}.json`, `/tmp/semgrep_{go_gin,go_cobra}.json`.
