<!-- SPDX-License-Identifier: Apache-2.0 -->
# Container Validation Sweep

The container sweep runs `bhf auto` inside the Docker image over a pinned corpus of 32 public projects, two per language across 16 languages, and writes a pass/fail report. It checks that each language lane builds, harnesses and fuzzes real code in the image. The scripts and the manifest are in [`docker/`](../docker/README.md): `sweep-manifest.tsv` (the corpus), `fetch-corpus.sh` (`bhf-fetch-corpus`), `bhf-sweep.sh` (`bhf-sweep`) and `sweep_contract.py` (the checks below).

Status: the strict Linux image gate passed on the image built from the current code (evidence below). The qualification gates listed under [Open gates](#open-gates) are tracked separately.

## What the gate checks

- **Image build.** Every required setup step, including compilation, package installation and the dependency caches, fails the image build when it fails. No step ends in `|| true`.
- **Selection.** A sweep with no selected project fails. `BHF_LANGS` with an unknown language fails.
- **Per-project result.** Each project's status comes from its versioned `auto/run.json`, not from the human-readable summary. A row is `PASS` only when bhf built, harnessed and fuzzed at least one non-stub target of that project. `STUB-ONLY`, `NO-TARGETS`, `NOT-ENTERED`, missing, error and timeout rows fail the gate. The sweep exits `0` only when every selected project passes.
- **Manifest.** The manifest is validated before anything is written: six TSV columns, safe project identifiers and source subpaths, no duplicates, a full 40-character commit SHA and a valid repository URL per row.
- **Results directory.** The sweep refuses a nonempty results directory, so a rerun never deletes earlier evidence. Pick a fresh directory or volume for each run.
- **Fetch.** An existing clone must be at the full pinned commit, with no modified, untracked or ignored files. A failed or new download leaves existing paths in place.

The report records the edge count of every row, so a `PASS` campaign that reached zero edges is visible in it and needs its own coverage review.

Build recovery executes code from the target project. Run the sweep only on these public pinned projects, inside the disposable container. Keep earlier `bhf:local` images and sweep volumes; write new evidence to a new directory or volume.

## Evidence: current-code image, 2026-09-25 UTC

| Item | Value |
|---|---|
| Source archive | `/tmp/bhf-enterprise-container.CRwioX/source-wave4-pugixml-lifetime.tar` |
| Archive SHA-256 | `f6048b57c11bd611d941d1f75972cc29eeaa4d30bde353199fdd7bf318677838` |
| Image tag | `bhf:enterprise-20260924-wave4-pugixml-lifetime` |
| Image ID | `sha256:140318d01e3b52fd82ea1cf00fff99a2c1b3895c76d900b528574c5cf275247c` |
| Baseline revision (label) | `5528a41df1968e7ec7efb843b9dac12cbe377c8c` |
| Created (label) | `2026-09-25T03:30:57Z` |
| Build log | `/tmp/bhf-enterprise-wave4-pugixml-lifetime-build.log` |
| Tool versions | `/tmp/bhf-enterprise-wave4-tool-versions.log`: Clang 18.1.3, Go 1.27.1, .NET 8.0.131, JDK 21, Python 3.12.3, Rust nightly 1.100.0 |

The image labels record the source archive hash, so the image identifies the exact input it was built from. Edits made to this page after the build are not part of that archive.

### Sweep setup

- Fresh volume `bhf_enterprise_20260924_wave4_full32_clean`, with the public corpus copied in. `bhf-fetch-corpus` verified all 32 pinned checkouts before the sweep.
- `--network none`.
- One target per project, five seconds per target, a 120-second cap per project.
- `CARGO_NET_OFFLINE=true` with a staged Cargo cache.
- `NUGET_PACKAGES` set to a staged NuGet cache, and a `NuGet.Config` whose only package source was that cache.

No source checkout or package download happened during the run.

### Result

The strict report is `/work/results/sweep-report.tsv` in that volume; stdout is in `/tmp/bhf-enterprise-wave4-full32-sweep.log`. It returned **32 PASS** across 16 languages, with no stub-only, no-target, missing, error or timeout rows.

An earlier current-code image without staged target packages passed 29 of 32 projects in bounded split runs: Rust CSV could not fetch `memchr` and `itoa`, and the C# projects Sprache and Superpower could not restore their NuGet graphs. With staged dependencies, all three passed on that image. For an offline build, stage each target's own third-party dependencies in a local cache; bhf's bundled packages cover its instrumentation.

### Defects the sweep found and how they were fixed

- **Pugixml double free in a generated harness.** The first image found three ASan double frees in one generated Pugixml sequence harness. `load_buffer_inplace_own` takes ownership of its buffer, and the harness freed it again after the call. The generator now leaves that allocation to Pugixml, and for the borrowing `load_buffer_inplace` variant it frees the buffer after the document reset. The corrected sweep reported 562 Pugixml edges and no findings. Each of the three old testcases exited `0` against the corrected harness (`/tmp/bhf-enterprise-wave4-pugixml-replay.log`).
- **Zero-edge lanes (fixed 2026-09-24).** Lua lunajson and both PHP projects reached zero edges, each from a target-selection or discovery defect. Re-verified on the pinned corpora with the release binary, PHP 8.3.6 and Lua 5.4:

  | Project | Edges before → after | Fix |
  |---|---|---|
  | symfony-yaml | 0 → 1230 | exception-setter demotion |
  | php-parser | 0 → 174 | string-input first-parameter affinity |
  | lunajson | 0 → 162 | discovery of factory fields in a module's `return {…}` |

  [`DEVELOPMENT_PLAN.md`](../DEVELOPMENT_PLAN.md) has the per-lane root causes and regression tests.
- **COBOL finding count (fixed 2026-09-24).** Each COBOL campaign reported one pass-level finding ID while its `findings/` directory and CSV were empty. COBOL crash attribution deletes a finding it proves to be a harness artifact (an empty-input dynamic `CALL` to an unlinked sibling program), but the deletion did not reach the in-memory pass records behind the headline count. `report::reconcile_pass_findings_with_disk` now drops every pass finding ID whose `finding.json` a later step removed, so `summary.findings`, `run.json`, `run.md`, `findings.csv` and `FINDINGS.md` agree. Re-verified on the pinned carddemo corpus with the release binary: `CSUTLDTC` reports `summary.findings = 0` and an empty `findings/`. The sweep volumes above were produced before this fix.

Go fastjson recorded one `MustParse` panic on empty input, with the `lab_only` actionability verdict (see [`docs/finding-report-fields.md`](finding-report-fields.md)).

## Open gates

These are separate qualification gates:

- native Windows and RHEL qualification;
- long-running service soak tests;
- a representative multi-trial comparison against AFL++ and libFuzzer (see [Engine benchmark](enterprise-engine-benchmark.md));
- a Mayhem comparison, which needs a licensed Mayhem environment.
