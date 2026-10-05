Real measured data collected:
- bhf: JSON/SARIF-2.1.0/Markdown (static-scan); auto adds CSV+JUnit; SBOM = CycloneDX+OpenVEX+CSV, NO SPDX
- Static JSON/MD findings lack CWE field (CWE only in SARIF tags + auto CSV)
- SARIF has codeFlows (dataflow) — semgrep SARIF does NOT
- syft: SPDX-2.3 (23 pkgs) + CycloneDX
- bandit: JSON with issue_cwe + more_info(remediation)
- semgrep: SARIF-2.1.0 with helpUri+help+OWASP tags, no codeFlows, 3 results
- cppcheck: XML/plist only, 402 errors on cpp_json

---

## bhf reporting vs competitors — measured comparison (2026-07-09)

The measurement ran `bhf static-scan benchmarks/campaign-2026-07-08/corpus/py_requests --out /tmp/rep --sarif` (14 findings: 7×BHF-421 deser/CWE-502, 4×BHF-426 TLS/CWE-295, 3×BHF-427 SSRF/CWE-918), inspected `/tmp/rep/static-report.{json,sarif,md}`, an auto `findings.csv`, and `bhf sbom` output, and then ran each competitor on the same corpus.

### What bhf actually emits
- **static-scan**: JSON (`bhf.static.v1`), SARIF **2.1.0** (`$schema` verified, driver `BHF 0.2.14`), Markdown. **No CSV, no JUnit from static-scan.**
- **auto**: adds `findings.csv` (19 columns incl. `cwe`, `sink_file/line/function`, `confirmation`, `confidence`, `verdict`, `member_finding_ids` = one-row-per-root-cause clustering) and JUnit.
- **sbom**: `cyclonedx.json`, `openvex.json`, `cyclonedx-vex`, `sbom.json`, `sbom.csv`, `vulnerabilities.json/csv`. **No SPDX.**

### Per-finding richness (measured against the JSON/SARIF)
- **Source→sink dataflow**: bhf SARIF carries **`codeFlows`** and a full `analysis.trace` (assignment→assignment→sink with snippets, `interprocedural_depth`, `tainted_parameters`, `complete_trace`, `confidence_reason`). Semgrep SARIF on the same repository has **no codeFlows**.
- **Confidence + actionability**: every finding has `confidence` + `analysis.actionability.verdict` (`likely_reachable`) + `reachability`. Semgrep encodes confidence only as a tag; bandit has `issue_confidence`.
- **CWE**: present in bhf SARIF rule `tags` (CWE-918/502/295) and in the auto CSV `cwe` column — **but the static JSON and Markdown per-finding records have NO `cwe` field** (confirmed: `cwe in finding? False`). Bandit puts `issue_cwe` on every JSON finding; semgrep puts CWE in rule tags. **Gap: bhf's primary static JSON/MD lacks per-finding CWE.**
- **Remediation**: **bhf emits none** — no `help`/`helpUri`/fix text anywhere. Semgrep SARIF has both `help` and `helpUri` per rule; bandit has `more_info` links. **This is bhf's weakest richness axis.**
- **Fuzz-confirmation provenance**: bhf emitted a `confirmation` column and FuzzReached SBOM evidence; the compared outputs had no equivalent.
- **Clustering to one-row-per-root-cause**: bhf CSV `member_finding_ids`; competitors emit one row per hit.

### Measured metrics table

| Feature / repo | bhf | semgrep | bandit | cppcheck | syft | Measured result |
|---|---|---|---|---|---|---|
| SARIF 2.1.0 | ✅ | ✅ | ❌ | ❌ (2.13: XML/plist only) | n/a | Tie w/ semgrep |
| JSON | ✅ | ✅ | ✅ | ❌ | ✅ | Tie |
| Markdown | ✅ | ❌ | ❌ | ❌ | ❌ | bhf only |
| CSV | ✅ (auto+sbom) | ❌ | ❌ | ❌ | ❌ (purls-ish) | bhf only |
| JUnit | ✅ (auto) | ✅ (`--junit-xml`) | ❌ | ❌ | ❌ | Tie |
| XML | ❌ | ❌ | ✅ (txt/xml) | ✅ | ✅ (cyclonedx-xml) | cppcheck/syft win |
| SBOM CycloneDX | ✅ | ❌ | ❌ | ❌ | ✅ | Tie w/ syft |
| SBOM **SPDX** | ❌ | ❌ | ❌ | ❌ | ✅ **SPDX-2.3** | **syft wins — bhf gap** |
| VEX (OpenVEX/CDX-VEX) | ✅ | ❌ | ❌ | ❌ | ❌ | bhf only |
| Source→sink dataflow (codeFlows) | ✅ | ❌ | ❌ | ❌ | n/a | bhf only |
| Per-finding CWE in primary JSON | ❌ (SARIF/CSV only) | ⚠️ rule tag | ✅ every finding | ⚠️ | n/a | **bandit wins on JSON** |
| Remediation / help text | ❌ | ✅ help+helpUri | ✅ more_info | ⚠️ | n/a | **semgrep/bandit win** |
| Confidence + reachability verdict | ✅ rich | ⚠️ tag | ⚠️ field | ❌ | n/a | bhf had the richest measured fields |
| Fuzz-confirmation provenance | ✅ | ❌ | ❌ | ❌ | ❌ | bhf only |
| Root-cause clustering | ✅ | ❌ | ❌ | ❌ | ❌ | bhf only |

### Per-repo finding counts (real, measured)
| Repo | bhf static | semgrep (auto) | bandit | cppcheck |
|---|---|---|---|---|
| py_requests | 14 | 3 | 16 | — |
| py_click | 0 | — | — | — |
| go_gin | 14 | — | — | — |
| rust_semver | 13 | — | — | — |
| java_gson | 5 | — | — | — |
| cpp_json | — | — | — | 402 |

(cppcheck's 402 is mostly style/warning noise on 422 files, not security; bandit's 16 vs bhf's 14 on py_requests are near-parity but bhf's carry dataflow traces bandit lacks.)

### Verdict
In this measured set, bhf produced the richest combined report and comparable
format breadth. No compared tool combined codeFlows dataflow, fuzz-confirmation
provenance, actionability and reachability verdicts, root-cause clustering, and
VEX. Three concrete output gaps remained at the time of measurement.

### Concrete gaps
1. **SPDX SBOM (highest priority).** syft emits SPDX-2.3 JSON + tag-value; `bhf sbom --emit` has no `spdx`/`spdx-json` option (confirmed "NO SPDX FILE"). SPDX is the more common procurement/compliance mandate than CycloneDX. Add `spdx-json` + `spdx-tag-value` emitters.
2. **Per-finding CWE in the primary static JSON + Markdown.** CWE lives only in SARIF `tags` and the auto CSV — the flagship `static-report.json` finding object and the MD table have no CWE column (bandit beats bhf here). Add a top-level `cwe` field to the static-scan finding schema and a CWE column to the MD table.
3. **Remediation / fix guidance.** bhf emits zero `help`/`helpUri`/fix text; semgrep and bandit both do. Add per-rule `help`+`helpUri` to SARIF rules and a `remediation` field to JSON findings.

Relevant paths: `/tmp/rep/static-report.{json,sarif,md}`, `/tmp/gfsbom/` (CycloneDX/VEX, no SPDX), `/tmp/syft.spdx.json`, `/tmp/bandit.json`, `/tmp/semgrep.sarif`, `/tmp/cppcheck.xml`.
