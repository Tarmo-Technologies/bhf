# Report formats and content (2026-07-08 campaign)

Measured 2026-07-09. The outputs at a glance:

- bhf: JSON, SARIF 2.1.0 and Markdown from `static-scan`; `auto` adds CSV and JUnit; the SBOM is CycloneDX, OpenVEX and CSV, with no SPDX.
- bhf's static JSON and Markdown findings have no CWE field; CWE is in the SARIF tags and the auto CSV only.
- bhf's SARIF has `codeFlows` (dataflow); semgrep's SARIF has none.
- syft: SPDX-2.3 (23 packages) and CycloneDX.
- bandit: JSON with `issue_cwe` and `more_info` (remediation links).
- semgrep: SARIF 2.1.0 with `helpUri`, `help` and OWASP tags, no `codeFlows`, 3 results.
- cppcheck: XML/plist only, 402 errors on cpp_json.

## Method

The measurement ran `bhf static-scan benchmarks/campaign-2026-07-08/corpus/py_requests --out /tmp/rep --sarif` (14 findings: 7×BHF-421 deserialization/CWE-502, 4×BHF-426 TLS/CWE-295, 3×BHF-427 SSRF/CWE-918). It inspected `/tmp/rep/static-report.{json,sarif,md}`, an auto `findings.csv`, and `bhf sbom` output, and then ran each other tool on the same corpus.

## What bhf emits

- **static-scan**: JSON (`bhf.static.v1`), SARIF **2.1.0** (`$schema` verified, driver `BHF 0.2.14`), Markdown. static-scan writes no CSV and no JUnit.
- **auto**: adds `findings.csv` (19 columns, including `cwe`, `sink_file/line/function`, `confirmation`, `confidence`, `verdict`, and `member_finding_ids`, which clusters one row per root cause) and JUnit.
- **sbom**: `cyclonedx.json`, `openvex.json`, `cyclonedx-vex`, `sbom.json`, `sbom.csv`, `vulnerabilities.json/csv`. No SPDX.

## Per-finding content (measured against the JSON and SARIF)

- **Source-to-sink dataflow**: bhf's SARIF carries **`codeFlows`** and a full `analysis.trace` (assignment, assignment, sink, with snippets, `interprocedural_depth`, `tainted_parameters`, `complete_trace`, `confidence_reason`). Semgrep's SARIF on the same repository has no `codeFlows`.
- **Confidence and actionability**: every finding has `confidence`, `analysis.actionability.verdict` (`likely_reachable`) and `reachability`. Semgrep encodes confidence only as a tag; bandit has `issue_confidence`.
- **CWE**: present in bhf's SARIF rule `tags` (CWE-918/502/295) and in the auto CSV `cwe` column. The static JSON and Markdown per-finding records have no `cwe` field (checked: `cwe in finding? False`). Bandit puts `issue_cwe` on every JSON finding; semgrep puts CWE in rule tags. Gap: bhf's primary static JSON and Markdown lack a per-finding CWE.
- **Remediation**: bhf emitted no `help`, `helpUri` or fix text. Semgrep's SARIF has `help` and `helpUri` per rule; bandit has `more_info` links. This was bhf's weakest content axis.
- **Fuzz-confirmation provenance**: bhf emitted a `confirmation` column and FuzzReached SBOM evidence; the compared outputs had no equivalent.
- **One row per root cause**: bhf's CSV has `member_finding_ids`; the other tools emit one row per hit.

## Measured metrics

| Feature / repo | bhf | semgrep | bandit | cppcheck | syft | Measured result |
|---|---|---|---|---|---|---|
| SARIF 2.1.0 | Yes | Yes | No | No (2.13: XML/plist only) | n/a | Tie with semgrep |
| JSON | Yes | Yes | Yes | No | Yes | Tie |
| Markdown | Yes | No | No | No | No | bhf only |
| CSV | Yes (auto+sbom) | No | No | No | No (purls-ish) | bhf only |
| JUnit | Yes (auto) | Yes (`--junit-xml`) | No | No | No | Tie |
| XML | No | No | Yes (txt/xml) | Yes | Yes (cyclonedx-xml) | cppcheck/syft lead |
| SBOM CycloneDX | Yes | No | No | No | Yes | Tie with syft |
| SBOM **SPDX** | No | No | No | No | Yes, **SPDX-2.3** | **syft leads; bhf gap** |
| VEX (OpenVEX/CDX-VEX) | Yes | No | No | No | No | bhf only |
| Source-to-sink dataflow (codeFlows) | Yes | No | No | No | n/a | bhf only |
| Per-finding CWE in primary JSON | No (SARIF/CSV only) | Partial (rule tag) | Yes, every finding | Partial | n/a | **bandit leads on JSON** |
| Remediation / help text | No | Yes (help+helpUri) | Yes (more_info) | Partial | n/a | **semgrep/bandit lead** |
| Confidence + reachability verdict | Yes, detailed | Partial (tag) | Partial (field) | No | n/a | bhf had the most measured fields |
| Fuzz-confirmation provenance | Yes | No | No | No | No | bhf only |
| Root-cause clustering | Yes | No | No | No | No | bhf only |

## Per-repo finding counts

| Repo | bhf static | semgrep (auto) | bandit | cppcheck |
|---|---|---|---|---|
| py_requests | 14 | 3 | 16 | — |
| py_click | 0 | — | — | — |
| go_gin | 14 | — | — | — |
| rust_semver | 13 | — | — | — |
| java_gson | 5 | — | — | — |
| cpp_json | — | — | — | 402 |

cppcheck's 402 on 422 files are mostly style and warning results rather than security findings. On py_requests, bandit's 16 and bhf's 14 are close in count; bhf's carry dataflow traces and bandit's do not.

## Result

In this measured set, bhf produced the most detailed combined report and comparable format breadth. No compared tool combined `codeFlows` dataflow, fuzz-confirmation provenance, actionability and reachability verdicts, root-cause clustering, and VEX. Three output gaps remained at the time of measurement.

## Gaps found

1. **SPDX SBOM (highest priority).** syft emits SPDX-2.3 JSON and tag-value; `bhf sbom --emit` had no `spdx`/`spdx-json` option (checked: no SPDX file). SPDX is a more common procurement and compliance requirement than CycloneDX. Proposed: `spdx-json` and `spdx-tag-value` emitters.
2. **Per-finding CWE in the primary static JSON and Markdown.** CWE lives only in the SARIF `tags` and the auto CSV; the `static-report.json` finding object and the Markdown table have no CWE column, where bandit has one. Proposed: a top-level `cwe` field in the static-scan finding schema and a CWE column in the Markdown table.
3. **Remediation and fix guidance.** bhf emitted no `help`, `helpUri` or fix text; semgrep and bandit both do. Proposed: per-rule `help` and `helpUri` in the SARIF rules and a `remediation` field on JSON findings.

Relevant paths: `/tmp/rep/static-report.{json,sarif,md}`, `/tmp/gfsbom/` (CycloneDX/VEX, no SPDX), `/tmp/syft.spdx.json`, `/tmp/bandit.json`, `/tmp/semgrep.sarif`, `/tmp/cppcheck.xml`.
