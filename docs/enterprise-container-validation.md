<!-- SPDX-License-Identifier: Apache-2.0 -->
# Enterprise container validation

Status: strict Linux image gate passed on the corrected current-code image;
broader enterprise qualification remains open.

Confirmed defects in the baseline validation infrastructure:

1. Docker build chains ended in `|| true`, masking compilation, package installation
   and dependency-cache failures. Required setup must fail the image build.
2. The sweep exited successfully for empty selections, stub-only execution and
   projects without fuzzable targets. A successful matrix must include at least
   one selected project and real target-entry evidence for every project.
3. Human-readable summary parsing could mistake a zero stub counter for a stub
   outcome. The versioned JSON report is the validation contract instead.
4. Reruns deleted prior project results, and unchecked manifest identifiers could
   escape the result directory. Validate the manifest before mutation, and refuse
   nonempty result directories instead of deleting evidence.
5. Fetching skipped existing clones without checking their revision. Existing
   clones must match the full pinned commit and have no modified/extra inputs;
   failed/new downloads must not remove preexisting paths.

Acceptance: fixture-based negative tests, current-source image build, all 32 pinned
projects across 16 languages attempted, source/image/toolchain identity recorded,
and every missing/partial/unentered/stub-only/timeout result fails the gate. A PASS
means observed execution of at least one non-stub target, not complete API coverage,
meaningful feedback in every language, or proof of competitive fuzzing quality.
Zero-feedback campaigns remain visible and require separate coverage evaluation.

Do not overwrite historical `bhf:local` image or sweep volumes. Keep new evidence
in a unique directory/volume. Build recovery executes target-controlled code;
only run these public pinned fixtures inside the disposable container.

## Current-code evidence — 2026-09-25 UTC

The source archive
`/tmp/bhf-enterprise-container.CRwioX/source-wave4-pugixml-lifetime.tar` hashes
to `f6048b57c11bd611d941d1f75972cc29eeaa4d30bde353199fdd7bf318677838`.
It built `bhf:enterprise-20260924-wave4-pugixml-lifetime`, image ID
`sha256:140318d01e3b52fd82ea1cf00fff99a2c1b3895c76d900b528574c5cf275247c`.
Labels record the source archive hash, baseline revision
`5528a41df1968e7ec7efb843b9dac12cbe377c8c`, and creation time
`2026-09-25T03:30:57Z`. Build log:
`/tmp/bhf-enterprise-wave4-pugixml-lifetime-build.log`. Tool versions are in
`/tmp/bhf-enterprise-wave4-tool-versions.log` (among them Clang 18.1.3, Go
1.27.1, .NET 8.0.131, JDK 21, Python 3.12.3, and runtime Rust nightly
1.100.0). Later edits to this evidence document are not included in the build
archive; the image identifies its actual build input, not the whole later
documentation worktree.

The original public corpus was copied into the fresh volume
`bhf_enterprise_20260924_wave4_full32_clean`. `bhf-fetch-corpus` verified all
32 pinned checkouts with zero failures before the sweep. The run used
`--network none`, one target per project, five seconds per target, a
120-second campaign cap per project, `CARGO_NET_OFFLINE=true`, a staged Cargo
cache, `NUGET_PACKAGES` pointing to a staged NuGet cache, and a `NuGet.Config`
whose only package source was that local cache. No source checkout or package
download occurred during the run. The single uninterrupted strict report is
`/work/results/sweep-report.tsv` in that volume; stdout is
`/tmp/bhf-enterprise-wave4-full32-sweep.log`. It returned **32 PASS, zero
stub-only, no-target, missing, error, or timeout rows** across 16 languages.

An earlier current-code image without staged target packages returned 29/32
in bounded split runs: Rust CSV could not obtain `memchr`/`itoa`, while C#
Sprache and Superpower could not restore their NuGet graphs. Staged dependency
retries made all three pass on that image. The separate full run above is the
stronger image-level evidence, but its dependency cache is part of the stated
offline test setup. BHF's bundled instrumentation packages alone are not a
claim that arbitrary third-party applications build in an air gap.

The first image also found three ASan double frees in one generated Pugixml
sequence harness. `load_buffer_inplace_own` owns its buffer, but the harness
freed it after the call. The generator now leaves that allocation to Pugixml
and defers cleanup for the borrowed `load_buffer_inplace` variant until after
document reset. The corrected full sweep reported 562 Pugixml edges and zero
findings; each of the three old testcase files exited 0 when replayed against
the corrected harness (`/tmp/bhf-enterprise-wave4-pugixml-replay.log`).

The strict PASS means at least one non-stub target was entered and fuzzed. It
does not prove coverage quality or complete API breadth. The wave4 sweep showed
three zero-edge lanes — Lua lunajson and both PHP projects — each a distinct
target-selection/discovery defect, **all fixed (2026-09-24)** and re-verified on
the pinned corpora with the release binary + PHP 8.3.6 / lua5.4: symfony-yaml
`0 → 1230` edges (exception-setter demotion), php-parser `0 → 174` (string-input
first-parameter affinity), lunajson `0 → 162` (module `return {…}` factory-field
discovery). See `DEVELOPMENT_PLAN.md` for per-lane root causes and regressions.
Go fastjson saved one
`MustParse` panic on empty input with a `lab_only` actionability verdict; it
is not a confirmed target security defect. Each COBOL campaign reported one
pass-level finding ID, while its top-level `findings/` directory and CSV were
empty. **This count/evidence mismatch is fixed (2026-09-24):** COBOL crash
attribution deletes a finding it proves a harness artifact (an empty-input
dynamic `CALL` to an unlinked sibling program), but that removal did not reach
the in-memory pass records feeding the headline count. `report::
reconcile_pass_findings_with_disk` now drops any pass finding id whose
`finding.json` a post-pass removed, so `summary.findings`, `run.json`, `run.md`,
`findings.csv` and `FINDINGS.md` all agree. Re-verified on the pinned carddemo
corpus with the release binary: `CSUTLDTC` reports `summary.findings = 0` and an
empty `findings/`. The wave4 volumes above predate the fix. Native Windows/RHEL
qualification,
long-running service soaks, and a representative multi-trial AFL++/libFuzzer
comparison are separate gates; a Mayhem comparison is unavailable without a
licensed environment.
