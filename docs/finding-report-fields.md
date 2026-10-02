<!-- SPDX-License-Identifier: Apache-2.0 -->

# bhf results reference

Every command that produces or changes findings writes into one self-contained
directory, `<work-dir>/results/` (default `bhf_work/results/`), and rebuilds its
index when it finishes. This doc describes that layout, the `bhf.findings.v1` /
`bhf.finding.v1` contracts, the CSV columns, and what changed from bhf ≤ 0.2.x.

## Layout

| Path | What it is |
|---|---|
| `results/INDEX.md` | Start here: summary, then every finding grouped by root cause |
| `results/findings.json` | Everything, machine-readable (`bhf.findings.v1`). Normative schema: `schemas/bhf.findings.v1.schema.json` |
| `results/findings.csv` | One row per finding — see [findings.csv](#findingscsv) |
| `results/findings.sarif` | SARIF 2.1.0, one run, every finding kind except `sca` |
| `results/manifest.json` | `bhf.results-manifest.v1`: tool, source, full producer history |
| `results/attestation.json` | in-toto Statement v1 over every file under `results/` |
| `results/findings/<ID>/` | Evidence for findings that have files: `finding.json`, `testcase.bin`, `min_testcase.bin` (when minimized), `sanitizer.log`, `decoded.json`, `replay.py` / `repro.adb` |
| `results/static/` | Native `static-scan` output (`static-report.{json,md,sarif}`) |
| `results/sbom/` | Native `sbom` output (`cyclonedx.json`, `sbom.spdx.json`, `openvex.json`, `vulnerabilities.json`, ...) |

`static-scan` (`S-*`) and SCA (`F-SCA-*`) findings carry no evidence
directory — their evidence (a location, or a component) is inline in
`findings.json`. The static findings `auto` writes as directories
(`F-STATIC-*`, `F-RO-*`, `F-EXT-*`) keep them, same as any dynamic finding.

### ID family → `kind`

| IDs | `kind` |
|---|---|
| `F-NNNN-<sig8>` | `fuzz` (sanitizer crash, unhandled exception, or oracle hit during fuzzing) |
| `F-MSAN-*`, `F-TSAN-*`, `F-MEM-*`, `F-JSINK-*`, `F-CAP-*` | `runtime` (replay/profiling passes over the corpus) |
| `F-DIFF-*` | `differential` |
| `BF-*` | `binary` |
| `F-STATIC-*`, `F-RO-*`, `F-EXT-*`, `S-*` | `static` |
| `F-SCA-*` | `sca` |

`bhf report` rebuilds `results/` on demand. A work dir from bhf ≤ 0.2.x (with
`findings/` at the top) is migrated into the `results/` layout automatically
the first time any command opens it; see [Migration from 0.2.x](#migration-from-02x).

## `findings.json` (`bhf.findings.v1`)

`schemas/bhf.findings.v1.schema.json` is the normative definition; this is a
field summary. `findings.json` always starts with `schema_version`, then
`generated_at`, `tool`, so an importer can detect the format from the first
few bytes. Every key is present (`null` where a value does not apply — never
omitted), and unknown keys are rejected.

Document-level fields: `schema_version`, `generated_at`, `tool` (`{name,
version, build}`), `source` (`{root, vcs}`), `producers[]` (the last 50
producer-history entries; `manifest.json` keeps the last 1000), `counts`
(`{total, by_kind, by_severity, by_confirmation}`), `findings[]`, `groups[]`
(`{key, representative, members}`), and `errors[]` (`{path, reason}` for
records that failed to load — a bad record never aborts the rebuild).

### Finding fields

| Field | Type | Notes |
|---|---|---|
| `id` | string | unique within `results/` |
| `kind` | enum | `fuzz`, `runtime`, `static`, `binary`, `differential`, `sca` |
| `producer` | string | command that wrote it, inferred from the ID family |
| `rule` | `{id, slug, name}`, each nullable | `id` is `BHF-NNNN`, the static rule id, or `null` when no catalog rule matches |
| `title` | string | one line, for lists |
| `message` | string | tool message (addresses stripped) |
| `explanation` | string \| null | plain-English summary |
| `severity` | enum | `critical`/`high`/`medium`/`low`/`info` — see [Severity](#severity) |
| `impact` | enum \| null | raw `actionability.impact` |
| `confidence` | `{level, score}` | level from `high`/`medium`/`low`/`unknown`; score 0–1 or null |
| `cwe` | int[] | at least one |
| `confirmation` | `{level, detail}` | see [Confirmation levels](#confirmation-levels) |
| `verdict` | enum \| null | `real_reachable`, `likely_reachable`, `lab_only`, `blocked`, `unknown` |
| `location` | `{file, line, column, function}` \| null | repo-relative POSIX path, 1-based |
| `fix_location` | same shape \| null | the single best place to start a fix |
| `stack` | `[{function, file, line}]` | project frames only, at most 32 |
| `trace` | `[{file, line, function, note}]` | static data-flow trace; empty for other kinds |
| `fingerprint` | `{primary, signature}` | `primary` is the stable cross-run identity |
| `group` | string \| null | root-cause group key |
| `occurrences` | int | members in the group this finding represents |
| `first_seen`, `last_seen` | RFC 3339 \| null | `last_seen` updates when a later run reproduces the same `fingerprint.primary` |
| `reachability` | object \| null | entry path for fuzz; fuzz reachability for SCA |
| `fidelity` | `{stubs_used, forced, caveats[]}` | `forced` when the target ran forced-and-stub-heavy under `--force` |
| `remediation` | string \| null | |
| `patch_hints` | `[{title, guidance}]` | advisory, not a literal diff |
| `reproduce` | `{harness_id, command, build}` \| null | `build`: `{sanitizers[], binary_sha256, build_id}`; `command` is relative to `results/` |
| `evidence` | `{dir, files[]}` \| null | each file: `{role, path, sha256, size}` — roles: `finding`, `testcase`, `testcase_minimized`, `sanitizer_log`, `decoded`, `replay_script`, `repro_ada`, `byte_control` |
| `fuzz` | `{exception, classification, harness_id, dialect, oracle}` \| null | `exception`: `{name, message, sanitizer}` |
| `static` | `{engine, precision, snippet, baseline_status, triage_state}` \| null | |
| `sca` | object \| null | `{vuln_id, aliases[], component, fixed_versions[], cvss, kev, references[], match_confidence, matching_method, vex}` |
| `binary` | `{sha256, build_id, arch, crash}` \| null | |
| `raw_ref` | string \| null | path of the source record, relative to `results/` |

### Severity

One `severity` per finding, chosen by the first rule that applies:

1. `impact` (`actionability.impact`), unless it is `unknown`.
2. The record's own `severity` (static, binary, SCA).
3. The rule catalog's `default_severity`.
4. `medium`.

A finding with `fidelity.forced: true` is floored to `low`. `ci --fail-on`
gating, SARIF `level`, CSV and `INDEX.md` ordering all read this resolved
`severity`, not the raw `impact`.

### Confirmation levels

`confirmation.level` is a normalized evidence strength; bhf owns these
semantics so importers don't have to re-derive them from raw fields. The
first row that matches wins:

| Level | Rule |
|---|---|
| `capability` | classification `capability` |
| `intended_rejection` | classification `intended_rejection` |
| `crash_lead` | prosthetics/stubs were used, or a sanitizer/unhandled crash with low confidence |
| `runtime_oracle` | classification `oracle_hit`, confirmation `runtime`, or a differential divergence |
| `sanitizer_crash` | sanitizer or unhandled crash |
| `static_confirmed` | static finding confirmed by a fuzz run (`fuzz_confirmed` / `fuzz_exercised`) |
| `static` | static finding, otherwise |
| `advisory` | SCA match |

`confirmation.detail` keeps the raw `confirmation` string the record carried.

## `finding.json` (`bhf.finding.v1`)

Every per-finding evidence record (`results/findings/<ID>/finding.json`)
carries the envelope below, in addition to its producer-specific fields
(documented inline above per block — `fuzz`, `static`, `sca`, `binary`):

| Field | Meaning |
|---|---|
| `schema_version` | `"bhf.finding.v1"` |
| `finding_kind` | one of the `kind` values above (not called `kind`: binary-fuzz records already use `kind: "binary_crash"`) |
| `created_at` | RFC 3339, set when the finding was first emitted |
| `last_seen` | RFC 3339, updated when a later run reproduces the same `fingerprint.primary` |
| `forced` | `true` when the finding came from a forced/stub-heavy build under `--force` |
| `history[]` | `{at, command, fields[]}` — one entry per enrichment pass (`minimize`, `cartography`, `confirm`, fidelity) that edited this record in place |
| `minimization_skipped` | `true` when `auto`'s minimization pass ran out of budget before reaching this finding's group |

## Producer history

Every command that writes into `results/` appends one entry to
`manifest.json` `producers[]`: `{command, argv, started_at, finished_at,
status, exit_code, findings_total}`. `manifest.json` keeps the last 1000
entries; `findings.json` `producers[]` shows only the most recent 50 of
those.

Children spawned by multicore fuzz workers and the continuous daemon's job
workers run with the hidden env var `BHF_RESULTS_DEFER=1`, which skips their
own per-job rebuild and producer record entirely — the parent process (the
multicore coordinator, or the daemon's results-refresh thread) merges their
findings and owns the single record for the batch.

## `findings.csv`

One row per finding. Columns, from `CSV_HEADER`:

```
id,kind,severity,confidence,confirmation,rule_id,cwe,title,file,line,function,group,occurrences,verdict,vuln_id,purl,first_seen,evidence_dir
```

`cwe` is written `CWE-120`; multiple values are `;`-separated.

## Migration from 0.2.x

bhf 0.3.0 unified every command's output under `results/`. If you have tooling
reading the old layout directly:

- `FINDINGS.md`, `findings.csv` / `auto/findings.csv` at the work-dir top,
  `auto/attestation.json`, and `reports/run-last.*` are gone. Use
  `results/INDEX.md`, `results/findings.{json,csv,sarif}`, and
  `results/attestation.json`.
- The per-finding writeup used to live in `run.md`; it no longer does.
  `run.md`/`run.json` keep campaign mechanics only (targets built/fuzzed/
  skipped, missing build deps) — read findings from `results/` instead.
- `findings.csv` has the single column set above. The per-harness stub
  accounting (`stub_total`, `stub_blind`, `stub_declared`, `linked_real`) moved
  to `auto/run.json` `targets[]`; `--static-dynamic` is a no-op.
- `runtime_mode` is not written anywhere in the new contract.
- An old-layout work dir (`<work>/findings/` at the top) is migrated
  automatically — `findings/` is renamed to `results/findings/`, the legacy
  index files are deleted, and `results/` is rebuilt — the first time any
  command opens it. `replay`, `minimize`, `capsule`, and `--resume` keep
  working against a migrated work dir.
- Tools that read `bhf_work/findings.csv` or `bhf_work/findings/` directly
  must switch to `results/findings.json` (schema in `schemas/`, reference
  fixture in `tests/fixtures/golden_results/`).

## Quick reading guide

- **Distinct bugs?** count unique `fingerprint.primary` (or `group`).
- **Is it real / worth triaging?** `confirmation.level` of `sanitizer_crash` or
  stronger, plus `verdict` of `likely_reachable`/`real_reachable`. Treat
  `impact: info` and `confirmation.level: intended_rejection` as non-defects.
- **How bad?** `severity` + `cwe`.
- **Where to fix?** `location` (where it faults) and `fix_location` (where to
  start) — read `explanation` + `patch_hints` first.
- **Reproduce?** `evidence.files[role=replay_script]`, or
  `bhf replay --finding <id>`.
