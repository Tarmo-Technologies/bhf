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
| `results/legacy/` | Only in a work dir migrated from bhf ≤ 0.2.x: the old `FINDINGS.md`, `findings.csv`, `auto/findings.csv` and `findings/<ID>/replay.py`, and `migration.json` (what was moved, when) |
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
omitted), and unknown keys are rejected. Keys added to v1 after its first
release (`fuzz.access`, `fuzz.input_to_state`, `fuzz.input_to_state_input`,
`fuzz.arguments`, the `runtrace` evidence role) are optional in the schema, so documents written
before them still validate; bhf always writes them. A validator holding the
older schema rejects them.

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
| `stack` | `[{function, file, line}]` | project frames only, at most 32; frames under the source root, and with no root known, frames outside toolchain, harness and libc component paths. A relative frame path that names no file under the source root (glibc's `assert/assert.c`, `csu/libc-start.c`) is not a project frame |
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
| `evidence` | `{dir, files[]}` \| null | each file: `{role, path, sha256, size}` — roles: `finding`, `testcase`, `testcase_minimized`, `sanitizer_log`, `decoded`, `replay_script`, `repro_ada`, `byte_control`, `runtrace` (the runtrace events of the replay that recorded the comparison evidence) |
| `fuzz` | `{exception, classification, harness_id, dialect, oracle, access, input_to_state, arguments}` \| null | `exception`: `{name, message, sanitizer}`; see [Fuzz block](#fuzz-block) |
| `static` | `{engine, precision, snippet, baseline_status, triage_state}` \| null | |
| `sca` | object \| null | `{vuln_id, aliases[], component, fixed_versions[], cvss, kev, references[], match_confidence, matching_method, vex}` |
| `binary` | `{sha256, build_id, arch, crash}` \| null | |
| `raw_ref` | string \| null | path of the source record, relative to `results/` |

### Fuzz block

| Field | Type | Notes |
|---|---|---|
| `access` | object \| null | the memory access the sanitizer reported: `{direction, size, address_hint, region, alloc_stack[], free_stack[]}`. `direction` is `read`, `write` or `unknown`; `region` is `{kind, size, offset, relation, distance, variable, frame_offset}` (`kind` `heap`, `stack` or `global`; `offset` negative before the object, `>= size` past it). The raw address is left out (it differs run to run); the stacks keep project and harness frames only, at most 8 |
| `input_to_state` | array \| null | comparison evidence recorded while this finding's input ran (from `finding.json` `gates`); `null` when no capture ran or it could not run (`gate_capture.status` `unavailable`), `[]` when one ran and no input bytes fed a comparison. Each entry: `{offset, len, operand_hex, compared_with_hex, cmp_kind, site, site_location, relation, operands_equal}`. `relation` is `equal` (the operand bytes are the input bytes), `byte_swapped` (the same, read big-endian) or `derived` (the operand is computed from those bytes and changed when they did); `site` is the comparison's offset in the harness executable, `site_location` its source position when it could be symbolized (never for `memcmp`/`bcmp` under AddressSanitizer, whose interceptor reports itself as the site) |
| `input_to_state_input` | string \| null | the finding file whose bytes the `input_to_state` offsets index: `min_testcase.bin` or `testcase.bin` (`finding.json` `gate_capture.input`); `null` when no capture named it |
| `arguments` | array \| null | the values the harness decoded from the input and passed to the target (`finding.json` `decoded_args`), when traced: `{name, type, value, len, span, preview_hex, role, after_call_value}`; `span` is `[start, end)` in the testcase, `role` `param`, `receiver` or `out` |

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
| `gates` | comparison evidence for the input named in `gate_capture.input`: each input span (`offset`, `len`) whose bytes reached a comparison, with `operand_hex`, `compared_with_hex`, `cmp_kind`, `site`, `location` (`{file, line, function}` or `null`), `relation` and `operands_equal`. Written by `bhf auto` after minimization and by `bhf report --backfill`. An operand counts only when its bytes occur in the input and a replay with those bytes changed shows it change with them (`derived`: flipping a byte changed it, and two replays of the unchanged input agreed on it, so a process id or clock reading does not count). Comparisons the harness makes before entering the target are left out, and so are later ones whose site symbolizes to harness code (this needs `llvm-symbolizer`) |
| `gate_capture` | how `gates` was recorded: `{input, input_len, status, reason, comparisons, truncated, unconfirmed, runs, shim_armed}`. `status` is `recorded`, `no_input_comparisons`, `no_comparisons` (no instrumented comparison was recorded in the target; uninstrumented code such as a prebuilt library is not observed) or `unavailable` (the capture could not run; with `reason`); `unconfirmed` counts operands whose bytes occur in the input but that did not follow a change of them; `shim_armed` says the replay ran with the runtrace shim, whose events for this one input are in the finding's `runtrace.jsonl` |
| `runtime_mode` | `{pass, env_injected, shim_armed}` stamped by `auto` on each finding: the fuzz pass, the environment it injected, and whether the runtrace shim was loaded for it |

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
id,kind,severity,confidence,confirmation,rule_id,cwe,title,file,line,function,group,occurrences,verdict,vuln_id,purl,first_seen,evidence_dir,access,access_size,region_size,region_offset,input_to_state,input_to_state_input
```

`cwe` is written `CWE-120`; multiple values are `;`-separated. The columns
after `evidence_dir` were added later, at the end, so readers that address
columns by position keep working: `access` is the access direction,
`access_size` its width, `region_size` and `region_offset` the object it hit,
`input_to_state` lists the comparison evidence as
`offset:len:cmp_kind:operand_hex`, `;`-separated, and `input_to_state_input`
names the file those offsets index.

SARIF results carry the comparison evidence as the `bhfInputToState` property
(the `finding.json` `gates` entries), the file its offsets index as
`bhfInputToStateInput`, and each comparison site with a source position as a
related location. A capture that could not run adds neither property.

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
  index files and reproducer scripts are kept under `results/legacy/`, and
  `results/` is rebuilt — the first time any command opens it, including
  commands that only read (`explain`, `report`). The command prints what it
  moved and kept. `replay`, `minimize`, `capsule`, and `--resume` keep working
  against a migrated work dir. See
  [Upgrading a 0.2.x work dir](#upgrading-a-02x-work-dir).
- Tools that read `bhf_work/findings.csv` or `bhf_work/findings/` directly
  must switch to `results/findings.json` (schema in `schemas/`, reference
  fixture in `tests/fixtures/golden_results/`).


### Upgrading a 0.2.x work dir

The migration is one-way: once a current bhf opens a 0.2.x work dir, bhf 0.2.x
can no longer read it (`cannot read <wd>/findings`). Keep a copy first
(`cp -a bhf_work bhf_work.0.2`). The copy replays its own harnesses: recorded
harness paths are resolved in the work dir that holds the finding.

What a migrated work dir has, and what it does not:

- The findings keep their ids and the evidence 0.2.x recorded. They have no
  `sanitizer.log`, crash frames for UBSan reports, or minimized inputs.
  Re-running `bhf auto` over the source tree into the same work dir minimizes
  the representative of each finding group that has no minimized input (within
  its time budget; `bhf minimize <finding>` does the rest), but it adds no
  `sanitizer.log` or frames: a crash that matches a migrated finding is a
  duplicate. Run `bhf report --backfill --work-dir <wd>` to replay each one
  against its harness and add `sanitizer.log`, frames and the memory access
  where the harness still exists and still reports the same crash. A replay
  that comes back unsymbolized is skipped; put `llvm-symbolizer` on `PATH` (or
  set `ASAN_SYMBOLIZER_PATH`) and run it again.
- `results/legacy/` keeps the old `FINDINGS.md`, `findings.csv`,
  `auto/findings.csv` and `replay.py` scripts; `results/INDEX.md` and
  `results/findings.{json,csv,sarif}` replace them, and each finding gets a
  current `replay.py`.
- The corpus may hold seeds damaged by the seed encoding of earlier releases
  (every byte that was not valid UTF-8 became `EF BF BD`). The first `bhf auto`
  run of this release sets `corpus/` aside as `corpus-legacy/` instead of
  reseeding it, unless you pass `--reuse-legacy-corpus`. It does the same in a
  0.2.x work dir an earlier release already migrated, and in any work dir an
  earlier `bhf auto` wrote: it recognises them by their auto state
  (`auto/run.json`, `auto/work-state.json`) without the
  `auto/legacy-corpus.json` record every run of this release writes first.
  `results/INDEX.md` and `bhf report` warn about testcases and corpus entries
  that look damaged this way.

For results comparable with a fresh install, run `bhf auto` into a new work
dir. Read each finding's `sanitizer.log` where it has one, otherwise run its
`replay.py` (or `bhf replay --finding <id>`), which prints the sanitizer report.

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
- **Which input bytes matter?** `fuzz.input_to_state`: the spans that reached a
  comparison while the finding's input ran. `dictionary.txt` in the harness dir
  is mined from source when the harness is generated; a token of it that occurs
  in an input is not evidence that any comparison read it.
- **How sure is `likely_reachable`?** For C/C++ it is usually inferred from the
  entry's signature (an input-taking shape, such as a byte-buffer parameter or
  a parser taking a byte); `bhf explain` says what
  each verdict rests on. A heap overflow of a buffer the generated harness sized
  for a pointer parameter it passes without a length is `lab_only`
  (precondition-dependent); one passed with its length, such as the buffer of a
  `(buf, len)` pair, keeps the entry's verdict.
