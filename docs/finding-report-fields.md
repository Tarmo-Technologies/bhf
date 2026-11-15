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
| `results/findings/<ID>/` | Evidence for findings that have files: `finding.json`, `testcase.bin`, `min_testcase.bin` (when minimized), `sanitizer.log`, `decoded.json`, `replay.py` / `repro.adb`; plus `replay.log`, the raw output of `bhf replay`, and `replay-other-harness.log`, that of a `bhf replay` of another harness than the finding's own that did not `MATCH` (both covered by `attestation.json`, neither an evidence role) |
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
release (`fuzz.access`, `fuzz.access.parameter`, `fuzz.input_to_state`,
`fuzz.input_to_state_input`, `fuzz.input_to_state_status`,
`fuzz.input_to_state_reason`, `fuzz.input_to_state_search`, `fuzz.arguments`,
`verdict_reason`, `fuzz.access.allocated_by_harness`, the `runtrace`
evidence role)
are optional in the schema, so documents written
before them still validate; bhf always writes them. A validator holding the
older schema rejects them. `reproduce.build.fidelity` is optional the same
way, but written only for a finding whose harness build used fabricated
inputs (below).

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
| `verdict_reason` | enum \| null | why `verdict` is `lab_only` or `blocked`, `null` for the others: `stubbed_value` (the crash needed a value a build-recovery stub, mock or fake supplied), `missing_resource` (`blocked`: the run lacked a resource), `allocator_only_leak` (a leak report with only allocator frames), `contract_assertion` (a contract assertion the harness cannot satisfy), `short_slice_precondition` (a fixed-width read of a slice shorter than documented), `harness_cleanup` (a fault in the harness's own cleanup), `must_panic` (a function that panics by design), `enum_domain_precondition` (an assertion on an enum value outside its domain), `harness_sized_buffer` (an overflow of a buffer bhf's harness sized for a pointer parameter it passes without a length), `entry_not_input` (the entry's signature does not take input) |
| `location` | `{file, line, column, function}` \| null | repo-relative POSIX path, 1-based |
| `fix_location` | same shape \| null | the single best place to start a fix |
| `stack` | `[{function, file, line}]` | project frames only, at most 32; frames under the source root, and with no root known, frames outside toolchain, harness and libc component paths. A relative frame path that names no file under the source root (glibc's `assert/assert.c`, `csu/libc-start.c`) is not a project frame |
| `trace` | `[{file, line, function, note}]` | static data-flow trace; empty for other kinds |
| `fingerprint` | `{primary, signature}` | `primary` is the stable cross-run identity |
| `group` | string \| null | root-cause group key |
| `occurrences` | int | members in the group this finding represents |
| `first_seen`, `last_seen` | RFC 3339 \| null | `last_seen` updates when a later run reproduces the same `fingerprint.primary` |
| `reachability` | object \| null | entry path for fuzz; fuzz reachability for SCA. Its `attacker_reachable` is the entry's signature verdict, so it can be `true` while the finding's `verdict` is `lab_only` for the reason in `verdict_reason` (such as `harness_sized_buffer`) |
| `fidelity` | `{stubs_used, forced, caveats[]}` | `forced` when the target ran forced-and-stub-heavy under `--force` |
| `remediation` | string \| null | |
| `patch_hints` | `[{title, guidance}]` | advisory, not a literal diff |
| `reproduce` | `{harness_id, command, build}` \| null | `build`: `{sanitizers[], binary_sha256, build_id}`, plus `fidelity` when the harness compiled only after bhf supplied inputs the build context lacked; `command` is relative to `results/` |
| `reproduce.build.fidelity` | `{level, context, fabricated[]}` (optional) | `level` is `reduced`; `context` is where the build context came from (`none`, `exact_tu_compile_database`, ...); each `fabricated` entry is `{kind, name, value}` with `kind` `macro`, `header`, `type`, or `include_dir` (a dir of real headers found by file name outside the scanned tree, which may be another project's). Such a finding's `confidence.level` is `low` and `fidelity.caveats` names what was fabricated: code compiled against a placeholder macro value or header can take paths the real build never does, so the finding may be false or not reproduce against the real build |
| `evidence` | `{dir, files[]}` \| null | each file: `{role, path, sha256, size}` — roles: `finding`, `testcase`, `testcase_minimized`, `sanitizer_log`, `decoded`, `replay_script`, `repro_ada`, `byte_control`, `runtrace` (the runtrace events of the replay that recorded the comparison evidence) |
| `fuzz` | `{exception, classification, harness_id, dialect, oracle, access, input_to_state, input_to_state_input, input_to_state_status, input_to_state_reason, input_to_state_search, arguments, sanitizer_second_opinion, lineage}` \| null | `exception`: `{name, message, sanitizer}`; see [Fuzz block](#fuzz-block) |
| `static` | `{engine, precision, snippet, baseline_status, triage_state}` \| null | |
| `sca` | object \| null | `{vuln_id, aliases[], component, fixed_versions[], cvss, kev, references[], match_confidence, matching_method, vex}` |
| `binary` | `{sha256, build_id, arch, crash}` \| null | |
| `raw_ref` | string \| null | path of the source record, relative to `results/` |

### Fuzz block

| Field | Type | Notes |
|---|---|---|
| `access` | object \| null | the memory access the sanitizer reported: `{direction, size, address_hint, region, alloc_stack[], free_stack[], parameter, allocated_by_harness}`. `direction` is `read`, `write` or `unknown`; `region` is `{kind, size, offset, relation, distance, variable, frame_offset}` (`kind` `heap`, `stack` or `global`; `offset` negative before the object, `>= size` past it). `parameter` is the harness parameter whose buffer the access hit, `{name, offset, basis}`, from `finding.json` `exception.access.parameter` when the argument trace named one, else `null`: `basis` `region_start` (the parameter's pointer is the region start; `offset` is the access's offset in it), `region_interior` (the pointer points into the region; `offset` is from the pointer) or `nearest_pointer` (no region was reported; `offset` is the faulting address minus the closest traced pointer below it). The raw address is left out (it differs run to run); the stacks keep the project's frames only, filtered as `stack` is (no allocator, libc, sanitizer, bhf harness or driver frames, no `_start`, paths relative to the source root and none outside it), at most 8. `allocated_by_harness` is `true` when bhf's generated harness allocated the buffer (a decoded C string, a copy of the input it sized), whose frames `alloc_stack` leaves out, so the overflow may depend on a precondition the harness could not see (see `verdict_reason`); `false` for a project allocation or the fuzz driver's copy of the input; `null` when no allocation stack was recorded |
| `input_to_state` | array \| null | comparison evidence recorded while this finding's input ran (from `finding.json` `gates`); `null` when no capture ran or it could not run (`gate_capture.status` `unavailable`), `[]` when one ran and no input bytes fed a comparison. Each entry: `{offset, len, operand_hex, compared_with_hex, cmp_kind, site, site_location, relation, operands_equal}`. `relation` is `equal` (the operand bytes are the input bytes), `byte_swapped` (the same, read big-endian) or `derived` (the operand is computed from those bytes and changed when they did); `site` is the comparison's offset in the harness executable, `site_location` its source position when it could be symbolized. Under AddressSanitizer the `memcmp`/`bcmp` interceptor reports itself as the site; the driver also records the frames above it, and the site is the first of them that is not the sanitizer runtime (the target's call), or the interceptor's own address, with no `site_location`, when none resolves (`finding.json` `gates[].site_unattributable`) |
| `input_to_state_input` | string \| null | the finding file whose bytes the `input_to_state` offsets index: `min_testcase.bin` or `testcase.bin` (`finding.json` `gate_capture.input`); `null` when no capture named it |
| `input_to_state_status` | string \| null | what the capture found (`finding.json` `gate_capture.status`): `recorded`, `no_input_comparisons` (comparisons ran but no input bytes fed one), `no_comparisons` or `unavailable` (the capture could not run); `null` when no capture ran |
| `input_to_state_reason` | string \| null | why the capture recorded no evidence (`gate_capture.reason`), when it recorded none: the empty input, no instrumented comparison, the harness not found, what the search left out, ... |
| `input_to_state_search` | `{state, searched_bytes, input_len}` \| null | how far the search for operands computed from input bytes (range checks such as `width - 1 > 31`) got (`gate_capture.derived_search`, `searched_bytes`): `state` `done`, `partial` (its replay budget ran out) or `too_long` (an input over 1 MiB, not searched); `null` when that search did not run or the capture predates it |
| `arguments` | array \| null | the values the harness decoded from the input and passed to the target (`finding.json` `decoded_args`), when traced: `{name, type, value, len, span, preview_hex, role, after_call_value}`; `span` is `[start, end)` in the testcase, `role` `param`, `receiver` or `out` |
| `sanitizer_second_opinion` | `{check, used, reason}` \| null | for a finding whose first report was UBSan's insufficient-object-size (BHF-227), which fires before ASan on the same access: bhf re-ran the input once with that check suppressed (`check` `object-size`). `used` is `asan` when AddressSanitizer then reported the same sink and access direction, and the finding carries ASan's report (its rule, kind and `sanitizer.log`); `ubsan` when the first report stands. `reason` says what the re-run showed (ASan's report, no error, another report, its time limit) or why it did not run (the pass's time had run out). From `finding.json` `sanitizer_second_opinion`, which with `used` `asan` also keeps `replaced_cluster_key`, the `cluster_key_full` of the UBSan report replaced, so a later pass counts a hit of it against this finding. `null` for every other finding; absent in documents written before it |
| `lineage` | object \| null | what the finding's input (`testcase.bin`) descends from in the fuzz queue (`finding.json` `lineage`): `{origin, root_sha256, root_path, layout_prefix, depth, parent_sha256, donor_sha256, reason}`. `origin` is `mined_seed`, `user_seed`, `seed` (a start input no seed list names), `corpus` (a reseeded queue entry whose own ancestry was not recorded), `generated` (no seed) or `unknown`; `depth` counts mutation generations from the root (`0`: the input is the root); `root_path` is relative to the source root when under it; `reason` says why the lineage is unknown (an AFL++ crash, an ancestor with no record) or stops at a corpus entry. `null` for findings saved before lineage was kept and from lanes that keep none |

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
| `gate_capture` | how `gates` was recorded: `{input, input_len, status, reason, comparisons, truncated, unconfirmed, runs, shim_armed, runner, served_resources, harness}`. `status` is `recorded`, `no_input_comparisons`, `no_comparisons` (the target made no comparison the driver recorded on this input; the reason gives the counts it left out) or `unavailable` (the capture could not run; with `reason`); `unconfirmed` counts operands whose bytes occur in the input but that did not follow a change of them; `shim_armed` says the replay ran with the runtrace shim, whose events for this one input are in the finding's `runtrace.jsonl`; `runner` names the emulator the capture replayed a harness built for another platform under (`qemu-aarch64`), and is absent for a native replay; `served_resources` lists the faked resources the shim served bytes to while the input replayed and crashed (`[]` when none), and is absent when the shim was not loaded for the replay, the replay did not crash (a sanitizer or runtime report; a fatal signal alone does not count, as for env-capsule), or the capture predates it; `harness` names the binary the capture replayed in place of the one the finding was fuzzed with (`main`, the driver build beside an AFL++ finding's `main_afl`, which has no bhf driver), and is absent otherwise, including for an `unavailable` capture, which replayed nothing. `reason` for an `unavailable` capture says why a harness cannot record comparisons: an AFL++ build with no driver build beside it, a lane whose harnesses do not link bhf's driver (only the C, C++, Rust, Fortran and COBOL lanes link it), a Rust, Fortran or COBOL binary built without it (by an earlier bhf or some other way; re-run `bhf auto`), or a C/C++ harness an earlier bhf generated (rebuild it), built some other way, or not generated by bhf |
| `build` | how the harness was built: `binary` is `{sha256, build_id, coverage_instrumentation}` for the harness binary that produced the finding, where `coverage_instrumentation` is the instrumentation that fed its edge map as the binary shows it (`sancov-trace-pc-guard` for clang's guards, `sancov-trace-pc` for a translation unit compiled with GCC's `-fsanitize-coverage=trace-pc`, `go-cover`), and is absent when the binary does not show one (no coverage, stripped or compressed debug information); `sandbox` is the sandbox the run used |
| `runtime_mode` | `{pass, env_injected, shim_armed}` stamped by `auto` on each finding: the fuzz pass, the environment it injected, and whether the runtrace shim was loaded for it (the pass's runtrace log holds, within its first 64 KiB, the `shim_loaded` line the shim writes when it first opens the log) |

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
id,kind,severity,confidence,confirmation,rule_id,cwe,title,file,line,function,group,occurrences,verdict,vuln_id,purl,first_seen,evidence_dir,access,access_size,region_size,region_offset,input_to_state,input_to_state_input,arguments,access_parameter,build_fidelity,input_to_state_status,verdict_reason,alloc_by_harness
```

`cwe` is written `CWE-120`; multiple values are `;`-separated. The columns
after `evidence_dir` were added later, at the end, so readers that address
columns by position keep working: `access` is the access direction,
`access_size` its width, `region_size` and `region_offset` the object it hit,
`input_to_state` lists the comparison evidence as
`offset:len:cmp_kind:operand_hex`, `;`-separated, `input_to_state_input`
names the file those offsets index, `arguments` summarises `fuzz.arguments`,
`access_parameter` names `fuzz.access.parameter`, and `build_fidelity` reads
`reduced: macro NAME=VALUE, header NAME, ...` for a finding whose harness was
built with fabricated inputs (empty otherwise), `input_to_state_status` is
`fuzz.input_to_state_status` (why `input_to_state` is empty is in
`findings.json` and `INDEX.md`), `verdict_reason` is the finding's
`verdict_reason` (empty when there is none), and `alloc_by_harness` is
`fuzz.access.allocated_by_harness` (`true`, `false`, or empty when not
known). `arguments` is
`name=value` per argument, `;`-separated: a buffer or string reads
`len <N>`, followed by `hex <first 8 bytes>` when a preview was traced
(`data=len 50718 hex 68baa77e0f010203...`), an output whose value changed
reads `<before>-><after>`, a `;` inside a name or value is written `,`, and
the cell stops at 200 characters with `...`.

SARIF results carry the actionability verdict as `actionabilityVerdict` and
its reason as `actionabilityVerdictReason` (`null` unless the verdict is
`lab_only` or `blocked`). They carry the comparison evidence as the `bhfInputToState` property
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
  automatically the first time any command opens it, including commands that
  only read (`explain`, `capsule`): `findings/` is renamed to
  `results/findings/` and the legacy index files and reproducer scripts are
  kept under `results/legacy/`. The command prints what it moved and kept.
  A read-only command does not rebuild `results/`; `bhf report` or the next
  `bhf auto` (or any other command that records findings) does, and `bhf
  explain`'s migration message ends with the `bhf report --work-dir <W>`
  command to run. `replay`, `minimize`, `capsule`, and `--resume` keep working
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
- Earlier releases gave a sanitizer crash with no frames, and a crash with no
  sanitizer report and no frames (a fatal signal, `FATAL_SIGNAL` or, in
  0.2.x, `ASAN_FATAL_SIGNAL` tagged `asan`; a transport-reported fault,
  `TARGET_*`; a transport deadline, `TRANSPORT_DEADLINE_EXCEEDED`), one
  root-cause key per rule and kind, so frame-less UBSan findings at unrelated
  sites, and fatal signals of unrelated harnesses, shared one group.
  `results/` (the `group` and `occurrences` columns, `fingerprint.primary`,
  the `INDEX.md` group count), `findings.sarif`, the report JSON
  (`cluster_key_full`, `cluster_fallback`) and `bhf explain` key such a
  finding as this release does: on the site and check its stored report
  names, or, with no site, its rule, kind, check (a crash's signal) and
  harness. `finding.json` keeps the key it was written with.
- Where that key names a site (a UBSan finding's location), the report JSON
  gives the finding `cluster_fallback: false`, so `bhf report --baseline` and
  `--triage` match it on its `cluster_key_full` instead of its signature and
  its `bhf-issue-v1` key changes. A baseline saved before the upgrade then
  shows such an issue as new and the old one as unobserved, and a triage
  decision recorded for the old key no longer applies: save the baseline
  again and re-check those decisions after opening a work dir from 0.3.0 or
  earlier.
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
  is mined from source when the harness is generated (each token's
  `# from <file>:<line>` comment says where); a token of it that occurs in an
  input is not evidence that any comparison read it. `learned_dictionary.txt`
  beside it holds the comparison constants the engine observed at runtime while
  fuzzing that harness (from `cmplog.jsonl`, across passes and runs, at most 256
  tokens: operands that met more distinct values at a comparison site than
  any of the inputs compared with them did); they were compared during some
  run, not necessarily this finding's. The runtrace shim's own comparisons (its
  checks of the paths and names the target used) are never among them.
- **How sure is `likely_reachable`?** For C/C++ it is usually inferred from the
  entry's signature (an input-taking shape, such as a byte-buffer parameter or
  a parser taking a byte, with typedefs such as `const u8_t *` read through the
  source's and its headers' declarations, and pointer typedefs to bytes such as
  `LPCBYTE` or `typedef const octet_t *rbuf_t` read as the pointer they are);
  `finding.json` `input_reachability_basis` records the rule, the parameter and
  its type as spelled and resolved (`{rule, param, spelled_type,
  resolved_type, typedefs_resolved}`, plus `via` for a
  `call_graph_provenance` entry: the registrar it is passed to, the receive
  call its body makes, or `volatile_pointer`), `findings.json` carries it as
  `reachability.reachability_basis`, and `bhf explain` says what each verdict
  rests on. A finding whose input is empty or all zero bytes, or whose method
  ran on an object bhf's harness constructed, carries a caveat that real
  callers may never produce that state (`fidelity.caveats`, the INDEX.md
  `Caveat:` line, and beside the verdict in `bhf explain`). A heap overflow of a buffer the generated harness sized
  for a pointer parameter it passes without a length is `lab_only`
  (precondition-dependent); one passed with its length, such as the buffer of a
  `(buf, len)` pair, keeps the entry's verdict.
