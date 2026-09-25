<!-- SPDX-License-Identifier: Apache-2.0 -->
# BHF enterprise-readiness plan and model handoff

## Current state — read first

The user **resumed development on 2026-09-24** with the instruction to pick up
from this plan. The earlier pause and handoff remain historical context.
Production credentials, publication, deployment, and external infrastructure
changes still require separate direction under [Authorization.md](Authorization.md).

Repository: `/home/ubuntu/github/tarmo/bhf`; branch: `dockerize`; baseline:
`5528a41df1968e7ec7efb843b9dac12cbe377c8c`; workspace version: `0.2.32`.
There are extensive **uncommitted changes and new files**. Preserve them. Do not
reset, clean, discard, or blindly replace the worktree. The two interrupted CLI
workstreams now compile and pass focused tests at the checkpoint below; this is
not a final-tree certification. No delegated agent was restarted.

The unchanged objective is a production-ready, enterprise-level BHF with
credible capability and effectiveness comparable to AFL++ and Mayhem. This has
**not** been achieved or verified. Small passing tests, an image build, and
feature counts do not establish that conclusion.

Read [Authorization.md](Authorization.md) for the user's approved development
scope. Model selection/delegation is for cost, specialization, and independent
review, not to bypass safeguards. Tests should use authorized local fixtures,
isolated public-source checkouts, and temporary keys. Document any unavailable
validation rather than conceal it or relabel it as passed.

## Complete plan index

This file controls current status and sequencing. Linked documents contain the
detailed designs, failure fixtures, contracts, and historical evidence. Older
phrases such as “active,” “next wave,” or “implementation complete” in those
documents are not instructions to resume and are not final-tree certification.

| Document | Purpose |
|---|---|
| [Enterprise readiness program](docs/enterprise-readiness-program.md) | Full acceptance matrix: security, services, engines, breadth, scale, access, platforms, supported surface |
| [Production readiness review](docs/production-readiness-review.md) | Initial audit, implemented corrections, historical broad-test record, remaining release gates |
| [Release review](docs/review-release-ci.md) | Installer, packaging, MSRV, CI and documentation findings |
| [Daemon/editor review](docs/review-daemon-editors.md) | Initial trust-boundary and editor lifecycle findings |
| [Feature review](docs/review-feature-completeness.md) | Optional-engine limits, cleanup/replay issues, feature and efficiency backlog |
| [Pack authentication](docs/enterprise-pack-authentication.md) | Signature byte contracts, trust/rotation, whole-archive bootstrap, installer and release gaps |
| [Daemon reliability](docs/enterprise-daemon-reliability.md) | Bounded response/findings loading, editor deadlines, process ownership and implemented tests |
| [Service soak plan](docs/enterprise-service-soak-plan.md) | Durability, backpressure, whole shutdown, tenant boundary, failure-injection and soak specifications |
| [Harness protocol](docs/enterprise-harness-protocol.md) | Confirmed manual C workflow defect, protocol resolution design and integration acceptance |
| [Go harness gap plan](docs/enterprise-harness-gap-plan.md) | Plain-data-only decoding scope, structural eligibility and reachability tests |
| [Engine benchmark plan](docs/enterprise-engine-benchmark.md) | Runner, diagnostic-only evidence, controlled real-code comparison methodology |
| [Container validation](docs/enterprise-container-validation.md) | Strict sweep/fetch contracts and current-image sixteen-language validation |
| [Measured language gaps](docs/expected-gaps.md) | Per-language exemplars, residual categories, historical counts, scanner performance and ranked work |

## Worktree status and evidence boundaries

The table below records executions before resumption. The newer checkpoint
follows it; neither is a production-readiness certification.

| Workstream | Implemented or in progress | Evidence and limits |
|---|---|---|
| Initial review | Cleanup/capsule path checks, temporary-file handling, honest unsupported Nyx path, installer staging, version stamps, docs/MSRV/editor corrections | Broad initial suite: 5,541 passed, 2 failed, 4 ignored; the two stale release assertions were corrected and their entire 11-test target passed. The whole suite was not repeated afterward. |
| Authenticated distributions | Ring Ed25519 packs; key-ID-bound metadata; external trust policy; streamed hashing; detached tar signature; independent OpenSSL verifier; seed-member checks; protected signing workflow | Owner reported governance 68/68, distribution 26/26, pack CLI 1/1, enterprise CLI 11/11. Actual protected workflow/public release not run. Mutable-source and installation lifecycle gaps remain. |
| Daemon/report/editor | Bounded serialization including large IDs; descriptor-based bounded finding reads; no auxiliary testcase reads; GNAT deadline; process-tree shutdown | Daemon 24/24, report 71/71, GNAT 18/18. Native Windows and stronger ancestor-race confinement remain unverified. |
| Scheduler | Unique IDs, atomic persistence, Unix directory sync, corrupt/duplicate snapshot rejection, positive-budget rounding and scheduler deadline | Latest slice 22/22; strict scoped Clippy passed. Queue/history/startup memory and whole webhook/DNS shutdown remain unbounded. Zero budget still means unlimited. |
| Manual C protocol/coverage | Was interrupted in `crates/cli/src/fuzz.rs` and new `crates/cli/tests/manual_c_protocol_cli.rs` | The historical resolver tests did not establish the real workflow; see the resumed checkpoint below. |
| Go data-only harnesses | Was interrupted in `crates/cli/src/auto/go_build.rs` and `crates/go_parser/src/lib.rs` | Earlier intermediate compile errors are superseded by the resumed checkpoint below. The 58-target sweep remains unrun. |
| Comparison runner | Common callbacks, version/hash capture, trial records, independent replay, censoring distinctions; scratch layout workaround removed | No valid completed three-engine comparison. Existing `smoke-*.json` files are diagnostic, even those named `smoke-valid-*`. |
| Container validation | Required build steps fail closed; JSON-based real-entry sweep gate; safe manifests; evidence preservation; pinned clean checkout checks | Python contracts 11/11; wave1 image built successfully. No new 32-project fuzz sweep was started. Wave1 predates subsequent Rust changes. |

Dependency policy passed all four categories with the added crypto/report
dependencies at its recorded checkpoint. Rust 1.88 compatibility, the 41-page
docs build, and editor/optional-feature results in the initial review are useful
historical evidence, not substitutes for testing the final tree. The SPDX
manifest was regenerated for the current added files at the checkpoint below.

## Resumed checkpoint — 2026-09-24

P0's source-stability gate is met for the current worktree: `cargo check
--workspace --all-targets` passed after both interrupted changes. Focused
results: `cargo test -p go_parser` (8/8), `cargo test -p bhf --lib
auto::go_build::tests` (25/25), `cargo test -p bhf --test auto_go_lane`
(4/4), `cargo test -p bhf --test manual_c_protocol_cli` (1/1, including
framed and no-fork execution), `cargo test -p bhf --lib protocol_resolution`
(2/2), `cargo test -p bhf --lib libfuzzer` (8/8), and `python3 -B -m
unittest discover -s benchmarks/engine-comparison -p test_runner.py` (4/4).
`cargo fmt --all`, `git diff --check`, SPDX manifest generation, and
`cargo run -p spdx_check -- check` passed. Later full-workspace attempts
exposed three additional integration issues, detailed below.

The SPDX manifest generator initially swept ignored benchmark run directories
and made the manifest depend on local evidence files. It now excludes
`benchmarks/engine-comparison/results`, while still checking benchmark source;
`cargo test -p spdx_check` passed 11/11 and the manifest was regenerated.

Source checkpoint: baseline commit `5528a41`; SHA-256 of `git diff --binary`
over `fuzz.rs`, `auto/attempt.rs`, `auto/go_build.rs`, `auto_go_lane.rs`,
`auto_go_force.rs`, `m19_signed_releases.rs`, `go_parser/src/lib.rs`,
`tests/fixtures/go_force/forcelib/forcelib.go`, and `THIRD_PARTY.md` is
`f5398e8ae9f9e5574bd16a6cfafcef68157989b3159118be3409a3a86120bdf2`.
The new `manual_c_protocol_cli.rs` separately hashes to
`dc6363f20a63260aa36ca28dcbfcfc54150042d8261f2e83bcee438545a0d59c`.
The latest rebuilt `target/release/bhf` hashes to
`ed2445aa911e348bc6c333a8a04e3b7ebdc954a5ef6a1518bd07b961025e9997`.
The earlier three-engine smoke used the prior release binary hash
`bd423b188edfc73829725a0dbaac0c0cd9b42e1952e29ea10b51a0ae4a696edf`;
the later Go coverage fix does not change that historical result. These hashes
identify local source and binaries; there is no commit or release artifact.

P1's documented manual C generate → build → fuzz path now selects
`bhf_framed`, creates a temporary coverage map when needed, and reports a
planted ASan heap overflow with nonzero edge feedback. The regression also
found and fixed a second defect: after a framed child died, fresh-process
replay sent raw stdin to a driver that accepts a filename in that mode, so
the target was never called. The no-fork regression exercises the same path.
The broader C++ amalgamation suite found another protocol-classification
regression: the state-masked crash recheck was guarded by the external
libFuzzer classification, which is false for the framed driver. It now uses
the framed-driver guard; the full C++ test target passed 5/5 and independently
replayed the saved ASan crash.
The release binary was rebuilt. BHF-only smoke evidence is in
`benchmarks/engine-comparison/results/smoke-p1-20260924-01.json`; its saved
crash replayed under the independent ASan oracle.

P2's narrow Go data-only path now puts complete JSON examples into the initial
seed pool for both `auto` and `fuzz`, uses declared JSON field names, rejects
method-bearing types and unsupported tags, and selects the target from its
actual source file. A real `auto` fixture proved nested pointer, slice, and map
fields reached a planted target branch without `--force`. A pinned frp revision
(`5c6d761c1287e6153f07b824fb6d71b96ee598fe`) exposed another issue:
`-coverpkg` included the target but omitted the generated main package, leaving
Go's `runtime/coverage` counter mode invalid. Including both packages changed
the same selected `DecodeProxyConfigurerJSON` target from a historical type skip
to a real, unforced five-second run with target entry and 21 coverage edges
(69,009 executions, no finding). Raw logs and work are under
`/tmp/bhf-p2-frp-auto-coverage-20260924.log` and
`/tmp/bhf-p2-frp-work-coverage-20260924/`; the earlier blind run is preserved
under `/tmp/bhf-p2-frp-work-20260924/`. The existing Go lane integration now
asserts positive runtime edges, not only metadata. The broader Go force test
revealed that a raw `[]byte` argument followed by a JSON data-only argument
needs two separately decoded input fields: the first is length-prefixed raw
bytes, and the remainder is a JSON document. The generator now writes paired
seeds, allowing `Render` to run unforced while the method `Feed` still needs a
synthetic receiver. Go builder tests passed 25/25, Go force 2/2, and Go lane
4/4. Rebuilding the release binary and repeating the same pinned frp target
with the paired-input path produced target entry, 27 coverage edges, 58,833
executions, no finding, no forced repairs, and no blocking dependencies in five
seconds. Evidence: `/tmp/bhf-p2-frp-auto-mixed-20260924.log` and
`/tmp/bhf-p2-frp-work-mixed-20260924/`. Go's historical 58-target
skip bucket was **not** fully re-swept; custom constructors, lifecycle types,
deeper parser reach, and the broader per-language backlog remain open. Strict Clippy was
attempted but stopped on `manual_is_multiple_of` in `cmplog`, then
`too_many_arguments` and `redundant_closure` in `governance` with the first
lint allowed. This is not a passing strict-Clippy gate.

The pinned AFL++ 5.03c LLVM instrumentation build completed locally with
`CXXFLAGS='-O3 -funroll-loops -fPIC
--gcc-install-dir=/usr/lib/gcc/x86_64-linux-gnu/13'`; log:
`/tmp/bhf-afl503c.NoHEOu/build-cxxflags.log`. A one-trial, five-second
three-engine smoke is preserved in
`benchmarks/engine-comparison/results/smoke-p1-three-engine-20260924-01.json`.
BHF and AFL++ saved independently replayed crashes within budget (first
observed at 0.63s and 0.18s). libFuzzer's saved crash was first observed at
8.56s and is explicitly `out_of_budget_crash`, not a solve. The runner now
records BHF's run-summary protocol and coverage and separates post-budget
artifacts from confirmed in-budget solves. This toy single trial establishes
runner operation, **not** AFL++ or Mayhem parity.

The first broad workspace run reached the CLI library and failed its license
audit because `THIRD_PARTY.md` omitted the new direct `ring` dependency; two
other tests then failed because their shared lock was poisoned. The matrix now
records `ring` as Apache-2.0 AND ISC, the direct audit passes (203 reachable,
163 third-party, 26 direct third-party packages), and all three tests passed
on rerun. Later workspace runs exposed the framed fresh-recheck issue above,
then stale Go force expectations, then one stale release-workflow assertion.
The release assertion now checks the plan-provided `RELEASE_TAG` and sanitized
artifact version; `cargo test -p bhf --test m19_signed_releases` passed 11/11.
The latest workspace run passed the 1,696-test CLI library and every test
target through `m19_signed_releases` except that now-corrected assertion.
After its fix, all 21 remaining CLI integration binaries passed individually,
`cargo test --workspace --exclude bhf -- --test-threads=2` passed, and
`cargo test -p bhf --doc` passed. Thus the workspace test targets were covered
by segmented passing runs, but there is no single uninterrupted green
`cargo test --workspace` result. Logs include
`/tmp/bhf-resumed-workspace-tests-go-final-20260924.log`,
`/tmp/bhf-remaining-cli-tests-20260924.log`, and
`/tmp/bhf-other-workspace-tests-20260924.log`. Final `cargo check --workspace
--all-targets`, `cargo fmt --all -- --check`, `git diff --check`, and SPDX
check passed.

## Continued local hardening — 2026-09-24

P3 pack installation now copies the initially verified manifest and payloads
into an owned temporary directory under the installation parent, verifies the
staged pack again, requires its identity/signature/items to match the initial
verification, writes the receipt there, and publishes the directory with
Linux no-clobber `renameat2`. Pack verification and copying have 64 MiB
manifest, 10,000-item, 2 GiB per-item, and 20 GiB aggregate limits. The seed
installer reads the archive from the verified installed pack copy, copies it
into one owned snapshot (2 GiB cap), and uses that exact file for member
validation and extraction. Tests include
deterministic source mutation before/after snapshot, a pre-existing symlink
destination, simultaneous installers, a compressed-size rejection, and the
signed offline package flow, plus bundle-source mutation after installation.
`cargo test -p governance --lib` passed 72/72,
`cargo test -p bhf --test pack_auth_cli` passed 1/1, and the complete
`offline_dist_scripts` target passed 29/29 after the mutation and dry-run
regressions. These are local Linux results;
source/destination ancestor substitution, non-Linux publish semantics,
interruption recovery, and uncompressed seed-extraction disk limits remain to
be resolved. Explicit `--no-content` extraction is unauthenticated by design.
See [pack authentication](docs/enterprise-pack-authentication.md).

P4 scheduler startup now reads at most a configured snapshot-byte cap plus one
and enforces configured record, history, and waiting-queue caps. Submission
returns a capacity error before consuming an ID or modifying disk; a paginated
listing API bounds each page. Defaults are 64 MiB snapshot, 64 KiB record,
10,000 retained jobs, 1,024 queued jobs, 1,000 jobs per page, and 64 worker
threads. A zero poll interval is rejected. Focused
tests passed 28/28 after adding an overall socket deadline and 64 KiB webhook
response cap, including trickle/large-body/success loopback fixtures;
`cargo check --workspace --all-targets` passed. Persistence still
rewrites all bounded history under a mutex, and DNS/shutdown cancellation,
retention/export, restart-orphan, and scale-soak gates remain open. See
[service soak plan](docs/enterprise-service-soak-plan.md).

The user confirmed no licensed Mayhem environment or native Windows/RHEL
test runners are available for this work. Continue local implementation and
validation; report those qualification gates as unavailable, never passed.

The first attempt at one uninterrupted `cargo test --workspace
-- --test-threads=2` exhausted the local filesystem while linking. After
deleting only disposable Rust incremental cache and rerunning with one Cargo
build job, the suite passed the CLI library and 130 earlier target binaries,
then `build_recovery_scenarios` failed one of 12 Ada scenarios with zero built
targets. The exact Ada fixture built and fuzzed when reproduced directly; its
focused rerun passed, and the whole `build_recovery` target passed 9/9 with
one test thread. All later CLI integration binaries passed serially, as did
`cargo test --workspace --exclude bhf -- --test-threads=1`. Logs:
`/tmp/bhf-final-workspace-tests-20260924.log` (disk failure),
`/tmp/bhf-final-workspace-tests-serial-20260924.log` (Ada scenario failure),
`/tmp/bhf-build-recovery-rerun-20260924.log`,
`/tmp/bhf-final-cli-remainder-20260924.log`, and
`/tmp/bhf-final-other-workspace-20260924.log`. The Ada result is a local
flakiness signal under the broader run, not a proven production fix. There
is still no uninterrupted green full-workspace run on this final tree.

P6 now has a **current-code Linux container gate**. The first current-source
image (`bhf:enterprise-20260924-wave2-current`, ID `e6a79fb735e2...`) passed
29/32 pinned projects with network disabled and no additional target-package
cache. Rust CSV needed its public Cargo dependencies, and C# Sprache and
Superpower needed NuGet packages and an offline source configuration. After
staging those dependencies, separate bounded retries passed all three, so
32/32 projects passed on that image across split/retry runs. This distinction
matters: BHF's own preloaded instrumentation dependencies do not make every
application buildable offline.

The wave2 Pugixml run reported three ASan double frees from one generated
sequence harness. Investigation found that the harness freed the buffer after
`pugi::xml_document::load_buffer_inplace_own`, even though Pugixml owns it.
The generator no longer frees ownership-taking buffers and
defers cleanup of buffers borrowed by `load_buffer_inplace` until after document
reset. A generated-code regression covers lifecycle, protocol, and shared
target-parameter cleanup emissions. Harness-generator library tests passed
604/604 and snapshots 44/44. On the corrected image, Pugixml passed with 562
edges and zero findings;
all three old testcases independently replayed against the new harness with
exit code 0. This establishes those three reports were harness-origin, not
Pugixml defects.

The corrected image `bhf:enterprise-20260924-wave4-pugixml-lifetime` has ID
`sha256:140318d01e3b52fd82ea1cf00fff99a2c1b3895c76d900b528574c5cf275247c`.
Its build source archive is
`/tmp/bhf-enterprise-container.CRwioX/source-wave4-pugixml-lifetime.tar`
(SHA-256 `f6048b57c11bd611d941d1f75972cc29eeaa4d30bde353199fdd7bf318677838`);
the image records that hash, baseline revision, and creation time in labels.
The original pinned corpus was recopied and verified clean: 32 projects,
zero checkout failures. A **single uninterrupted strict sweep** on this image
with `--network none`, one target/project, five seconds/target, 120-second
campaign cap, `CARGO_NET_OFFLINE=true`, staged Cargo/NuGet caches, and an
explicit local NuGet feed returned `PASS=32`, `STUB-ONLY=0`, `NO-TARGETS=0`,
`MISSING=0`, `ERROR=0`. The report and full artifacts are in Docker volume
`bhf_enterprise_20260924_wave4_full32_clean` under `/work/results`; stdout is
`/tmp/bhf-enterprise-wave4-full32-sweep.log`. The same image and run are
described in [container validation](docs/enterprise-container-validation.md).

This gate proves at least one non-stub target entry for each project. It does
**not** prove API breadth, competitive effectiveness, or nonzero feedback in
every lane. The wave4 sweep reported three zero-edge lanes; re-examined against
the evidence they are three DIFFERENT defects, not one "entered but no feedback"
class:

- **php/symfony-yaml — target selection (fixed 2026-09-24).** The sweep read
  `unsupported_params`, not entry: BHF picked
  `ParseException#setParsedFile`, a setter on an *exception* class, over
  `Yaml::parse`. Cause: the dynamic-lane name scorer matched the `parse` action
  stem inside the setter's object noun (`set` + **Parsed**File), tying the setter
  at the top with the real parse entries; the single-target sweep then took the
  alphabetically-first (the exception setter), whose receiver constructor needs
  an argument. Fix: `name_semantics::is_accessor_or_mutator` demotes any method
  whose LEADING token is `set`/`get`/`is`/`has`/`with` below every normal target
  (`discovery::dynamic_target_score`). Verified on the pinned corpus with the
  release binary + PHP 8.3.6: the top targets are now `Inline::parse` /
  `parseScalar` / `evaluateBinaryScalar`, all `entered=true` with **1223–1230
  edges** (was 0). Regressions:
  `name_semantics::tests::accessors_and_mutators_detected_by_leading_token_only`
  and `discovery::tests::exception_class_setter_ranks_below_real_parse_entries`.
- **php/php-parser — entry fixed 2026-09-24; ranking follow-up noted.** The
  wave4 pick `ConstExprEvaluator#evaluateSilently(Expr $expr)` was
  `built_not_entered` because its first parameter is an AST **object**, not a
  string: fuzz bytes cannot synthesize a valid `Expr`, so the harness bailed
  before the endpoint. Fix: `php::first_param_fuzz_affinity` ranks a first
  parameter that IS the byte channel (`string`/`mixed`) above one needing object
  synthesis (`discovery::dynamic_target_score` PHP arm). Verified on the pinned
  corpus + PHP 8.3.6: the lane now enters and produces coverage —
  `Lexer#tokenize` 174 edges, `JsonDecoder#decode` 48, all `entered=true` (was
  0/built_not_entered). Regression:
  `php::tests::first_param_affinity_prefers_byte_channels_over_object_synthesis`.
  Follow-up: the deterministic #1 pick `Internal\TokenPolyfill::tokenize` still
  records ~0 edges because on PHP 8+ it delegates to the native `PhpToken`
  tokenizer (a C path pcov cannot see) — an `Internal`-namespace demotion would
  route the single-target sweep to `Lexer#tokenize`. Tracked, not yet applied.
- **lua/lunajson — fixed 2026-09-24 (0 → 162 edges).** `target_entry_observed=
  true` over ~38k execs with 0 edges because the picked targets were non-fuzzable:
  `decoder.lua#fixedtonumber` is `local fixedtonumber = tonumber` (a C-function
  alias — executes zero Lua lines, so the line-hook correctly records nothing) and
  `encoder.lua#__index` is a metamethod. The real entry `decode` is a **runtime
  closure** — `src/lunajson.lua` ends with `return { decode = newdecoder(), ... }`,
  with no static `function decode`, so the `function`-header scan missed it
  (json-lua works because it defines plain `json.decode`/`parse` → 131 edges).
  Fix: `lua::parse_module_table_fields` discovers the public fields of a
  module-level `return { ... }` table whose value is a factory call
  (`decode = newdecoder()`) or an inline `function`; the harness already calls
  `dofile(module)['field'](data)`. Metamethods (`__*`) are also now demoted across
  every dynamic lane. Verified with lua5.4 on the pinned corpus: `decode` is the
  top pick, `entered=true`, **162 edges** (was 0). Regressions:
  `lua::tests::module_return_table_factory_fields_are_discovered` and
  `nested_return_table_inside_function_is_not_a_module_surface`. (The remaining
  `fixedtonumber` helper still records 0 as a C-alias — correct behavior, and no
  longer the selected target.)

Go fastjson saved one `MustParse` empty-input panic marked
`lab_only`; the two COBOL campaigns each reported one pass-level finding ID
but their top-level evidence directories/CSV contain no finding record.

**COBOL count reconciliation — fixed 2026-09-24.** Root cause: COBOL crash
attribution (`crate::auto::cobol_oracle::run_cobol_attribution`) deletes the
`findings/<id>/` bundle of a crash it proves a harness artifact — the empty
input drives `CSUTLDTC` into a dynamic `CALL` to a sibling program that is not
linked into the single-program harness (`libcob: module 'X' not found`). That
removal reached the disk-derived outputs (`findings.csv`, `FINDINGS.md`) but
not the in-memory pass records that feed `summary.findings`, `run.json` and
`run.md`, so the headline count reported a finding with no evidence bundle (the
identical id `F-0000-46760087` in both projects — the shared empty-input hash).
Fix: `report::reconcile_pass_findings_with_disk` retains only pass finding ids
whose `finding.json` still exists, called after every post-pass and before
`write_reports`. Verified end-to-end on the pinned carddemo corpus with the
release binary (GnuCOBOL 3.1.2 / clang 18.1.3): `CSUTLDTC` now reports
`reconciled 1 finding id`, `summary.findings = 0`, empty `findings/`, and
0 CSV rows — all four surfaces agree. Regression:
`report::tests::phantom_finding_removed_by_post_pass_is_reconciled_out_of_count`.
The stale wave4 volumes predate the fix; a fresh COBOL sweep now reads 0. The
remaining zero-edge lanes (below) are unchanged. The final
native Windows/RHEL matrix, sustained service/failure soaks, real-code
comparative study, licensed Mayhem comparison, and release/security audit
remain open. The user confirmed no Mayhem environment or native Windows/RHEL
runners are available; those gates are unavailable, not passed.

## Consolidated gate status (2026-09-25)

Verified this session on this Linux host (release binary; GnuCOBOL 3.1.2, clang
18.1.3, PHP 8.3.6, lua5.4, AFL++ 5.03c). "Verified" = tests pass and, where a
lane was fixed, re-run on the pinned corpus.

| Item | Status | Evidence |
|---|---|---|
| COBOL finding-count reconciliation | **DONE** | carddemo `findings 1→0`, all surfaces agree; `report::reconcile_pass_findings_with_disk` + regression test |
| Zero edges — php/symfony-yaml | **DONE** | `0→1230` edges; accessor/exception-setter demotion + 2 regressions |
| Zero edges — php/php-parser | **DONE** | `0→174` edges; first-param fuzz-affinity + regression (follow-up: Internal-namespace demotion noted) |
| Zero edges — lua/lunajson | **DONE** | `0→162` edges; module `return{}` factory-field discovery + 2 regressions |
| Installation security (P3) | **Implemented + verified** | 113 tests green (72 governance + pack_auth + 11 signed-release + 29 offline-dist): signing, key custody, downgrade/tamper/revocation, external trust, offline install. Remainder: distribution-packaging integration (packaging plumbing) |
| Service durability (P4) | **Core implemented + verified** | 52 tests green (bhf-daemon 24 + continuous_daemon 28): bounded queue (1024) + 64 MiB snapshot cap, deterministic `Capacity` backpressure, crash recovery, persistence atomicity, webhook deadline/response cap, owned process-tree shutdown. Remainder: sustained scale-soak with measured RSS/latency thresholds (operational); native Windows process-tree runner (**unavailable**) |
| Comparative baseline (P5) | **First step done; study open** | Three-engine smoke exists (`benchmarks/engine-comparison/results/smoke-p1-three-engine-…`); AFL++ 5.03c builds. Remainder: real-code multi-trial FuzzBench study (large, operational); fresh libFuzzer arm needs `libstdc++-dev` (**no root here**); Mayhem (**unavailable — no license**) |
| Release / security audit | **CI tested** | `m19_signed_releases` (11) + `m19_full_ci_matrix` green; full external audit is operational |

Full regression: `cargo test -p bhf --lib` → **1701 passed / 0 failed**; plus
governance 72, bhf-daemon 24, continuous_daemon 28, target_rank 141, and the
pack/offline/signed-release integration suites.

**Genuinely blocked in this environment (cannot be passed here, only documented):**
licensed Mayhem comparison, native Windows/RHEL matrix, and a fresh libFuzzer
benchmark arm (needs root to install `libstdc++-dev`). The large open studies
(FuzzBench real-code comparison, sustained multiworker soak) are operational and
must run in a dedicated long-running environment; producing toy stand-ins for
them is explicitly disallowed by the P5 exit gate below.

## Execution plan (resumed)

### P0 — Recover a stable, reviewable source checkpoint

1. Read this handoff and the relevant detailed plans; inspect `git status`,
   diffs, recent test artifacts and actual process state. Do not restart a
   previously launched process solely because its observation timed out.
2. Finish the two interrupted CLI workstreams below in isolated file ownership.
   Do not run competing builds while another agent is halfway through a
   multi-file Rust edit. Treat old compile diagnostics as clues, not as proof
   the same error remains.
3. Compile/check the combined workspace and run focused regressions. Repair
   actual failures without deleting assertions, disabling gates, or treating
   skipped external-tool tests as executed validation.
4. Record a source snapshot/hash and exact test commands. Keep implementation
   patches separate from benchmark infrastructure and evidence changes.

Exit gate: a coherent compiling worktree, both interrupted tasks resolved or
explicitly held as unfinished, and reproducible focused test results.

### P1 — Correct the documented generate/build/fuzz workflow

Files: `crates/cli/src/fuzz.rs`,
`crates/cli/tests/manual_c_protocol_cli.rs`; detailed protocol plan above.

- Finish one consistent protocol resolver for sibling-source, split
  generated/build, automatic and script layouts; retain real external
  libFuzzer and stdin support. Strong framed markers must take precedence over
  merely finding a C source file.
- Use that classification consistently for persistent execution, coverage,
  per-input dispatch, replay, filtering and summaries. Keep source/launcher
  inspection bounded and do not read an entire binary as UTF-8.
- Finish the temporary 64 KiB coverage-map provision for standalone builtin
  framed harnesses that lack a caller-supplied map. Review ownership, cleanup,
  child lifetime and preservation of caller-supplied/automatic maps.
- Exercise the actual public generate-harness → build → fuzz commands. Verify
  real entry, correct protocol, nonzero feedback and a reproducible known
  fixture result. Include no-forkserver/fallback/replay cases and retain genuine
  libFuzzer regression coverage.
- Rebuild the release binary before benchmarking. Do not hide the production
  defect by copying marker sources into benchmark scratch layouts.

Exit gate: the real manual and automatic workflows work, not just resolver
unit tests, and the benchmark uses an unmodified documented workflow.

### P2 — Finish Go data-only input construction, then measured lane gaps

- Review the interrupted parser and builder diff before extending it. Eligibility
  must be proven from declarations, not inferred from an exported type name.
- Permit only supported plain-data shapes. Reject unknown/imported opaque
  types, private fields, interfaces, synchronization/resource handles, unsafe
  state and lifecycle-dependent objects without explicit supported construction.
- Review custom decoding hooks, including JSON and text unmarshaling, receiver
  methods, aliases, embedded fields, recursive shapes and package identity.
  A standard JSON decoder can invoke target-defined hooks; it is not by itself
  proof that construction is side-effect-free.
- Preserve existing supported types, clean skips and explicit `--force`
  semantics. Provide valid structured starting inputs and prove that bytes
  populate fields and reach target logic. Adding a dictionary alone is not
  proof that a campaign starts or progresses with valid structured inputs.
- Test nested structures, pointers, collections, null/missing/malformed fields,
  hook/opaque-type rejection and attribution of harness-versus-target failures.
  Re-run real exemplars and report the actual resolved subset, not “58 fixed.”

Then work the complete per-language backlog from `docs/expected-gaps.md`, using
current logs before each fix. Historical priority buckets include C opaque
lifecycle (86), Java generic/collection parameters, C++ non-self-contained
headers (49 report-only), Go parameter/receiver/module gaps, Rust decoders (42)
and trait resolution, C++ class construction/decoders, Ada symbols/GPR structure,
Python/C# receivers, and JS browser environments. Some historical items are
already marked fixed; do not reimplement them from an old ranked list.

Exit gate per change: representative before/after real-entry and coverage
evidence, no new harness-origin false findings, and honest residual categories.
Keep dependency/environment/design limits distinct from implementation gaps.

### P3 — Close artifact and installation security gaps

- Independently review exact signed bytes, key-ID binding, key parsing,
  duplicate/unknown fields, policy downgrade, revocation and rotation behavior.
  Retain RFC-vector and OpenSSL verification tests; use vetted crypto only.
- Close verify-then-copy races: copy/hash from stable opened inputs into an
  owned staging snapshot and publish only the verified bytes. Prevent destination
  symlink/ancestor substitution under the declared deployment threat model.
- Give pack/archive operations explicit input, output, count, time and disk
  budgets. Streaming hashes solve memory growth, not mutable-input authenticity
  or unlimited disk consumption.
- Make seed validation and extraction operate on the same controlled archive
  snapshot. Preserve regular-file/directory-only rules and outside sentinels.
- Test installation interruption between renames, simultaneous installers,
  partial command-link updates, staging collisions, rollback and receipt paths.
  Preserve recoverable previous installations and never silently remove data.
- Validate trust bootstrap before executing bundled code. The verifier and
  public key must come from an independent trusted channel; a bundled policy
  cannot establish publisher trust.
- Review all examples for changed defaults: authenticated packaging and external
  install policy are the normal path; legacy integrity-only mode must remain
  explicitly selected and described as unauthenticated.

Exit gate: bounded, authenticated, recoverable installation under injected
failures, plus independently reviewed key custody/rotation/revocation procedures.

### P4 — Complete service durability, scale and deployment boundaries

Use the precise fixtures in `docs/enterprise-service-soak-plan.md`.

- Add bounded queue/history and startup loading, deterministic backpressure,
  bounded/paginated listing, and persistence that does not rewrite unbounded
  history under a global mutex. Specify retention/export before deleting data.
- Add an overall webhook deadline and response-byte cap, bounded/cancellable
  resolution, shutdown cancellation, and a whole-scheduler shutdown bound.
  Do not replace a blocked resolver with indefinitely accumulating threads.
- Exercise disk errors, restart, concurrent producers, malformed snapshots,
  numeric limits, acknowledged-ID survival and crash-time orphan reconciliation.
  Retain at-least-once semantics unless stronger guarantees are actually proved.
- Validate Windows process-tree and filesystem behavior natively; Linux tests
  cannot prove those paths. Include escaped descendants and blocked pipes in
  the documented isolation/lifecycle model.
- Define the actual shared-service boundary. Shipped stdio/MCP interfaces are
  same-user interfaces, not a remotely authenticated multi-tenant service.
  Scheduler submission lacks tenant identity; JSON-RPC tokens are not an OS
  sandbox. Require protected workspace handles or OS-level tenant isolation,
  authenticated front ends and audited role enforcement where shared operation
  is supported.
- Run sustained multiworker and restart/failure soaks. Predeclare thresholds
  for RSS/disk/child count, acknowledgement survival, shutdown time, and p95/p99
  submit/list latency. Preserve measurements and every failure.

Exit gate: tested bounded operation, recoverable state and a truthful deployment
threat model, not merely additional configuration switches.

### P5 — Produce a credible comparative effectiveness baseline

- First obtain a valid small three-engine run after P1; then use multiple
  independent trials and representative real-code families with common harness
  semantics and independent replay/coverage measurement.
- Pin current tool/source versions and hashes. Keep identical base seeds,
  input limits, resource budgets and sanitizer policy; document native guidance
  differences such as BHF source dictionaries, AFL++ CMPLOG and libFuzzer value
  profiling. Do not call native execution counters equivalent.
- Separate build/setup cost, campaign time and artifact-observation overhead.
  Enforce/report effective time budgets; account for sanitizer symbolization
  delays. Crashes observed outside budget must not silently become in-budget
  successes. Preserve failed builds, tool errors and unconfirmed artifacts
  separately from valid right-censored no-result trials.
- Confirm saved results through a common independent oracle, deduplicate bugs,
  measure common coverage, and publish raw rows plus reproducible analysis and
  uncertainty. Pre-register targets/trials/budgets rather than hand-pick only
  favorable results. Use FuzzBench methodology for the real-code study.
- Compare expert harnesses with generated harnesses: coverage/reach, setup effort,
  reproducibility and false-result rate matter alongside mutation throughput.
- A direct Mayhem comparison requires a licensed, authorized version/account
  and equivalent integration/budget. No such run exists. Record missing product
  capabilities explicitly; do not infer parity from documentation or redefine
  missing functionality out of scope merely to obtain a green gate.

Current AFL++ preparation: official v5.03c resolves to
`dbaf11913c1b2702dee5b4d3dcfffd52f1defe50`. The local 4.09c smoke is historical.
The pinned source under `/tmp/bhf-afl503c.NoHEOu/src` now builds its LLVM
instrumentation with the GCC 13 selection in `CXXFLAGS`; no system toolchain
installation occurred. This only supports the diagnostic smoke above.

Exit gate: repeatable real-code evidence strong enough for the specific claims
made. Toy regression results do not establish enterprise superiority.

### P6 — Validate current artifacts across languages and platforms

- Freeze/capture a coherent source snapshot after relevant changes. Build a new
  tagged image with source-archive hash, revision, timestamp and tool versions.
- Run all 32 pinned projects across 16 languages with the strict JSON/real-entry
  sweep. Use fresh result directories; verify clean pinned sources. Preserve
  failures and zero-feedback lanes, especially previously observed PHP/Lua
  cases. A PASS establishes some real entry, not complete API coverage.
- Verify offline operation with explicitly staged target dependencies and
  network disabled. Do not mistake preloaded instrumentation dependencies for
  all third-party application dependencies being available offline.
- Run final-tree workspace, optional-feature, editor, docs, SPDX/license,
  minimum-Rust and artifact installation gates. Exercise native Windows and
  RHEL/Ubuntu ABI matrices on these exact changes.
- Review every public command and advertised feature against implementation.
  Nyx snapshot support remains unimplemented; its typed unsupported result is
  not an implementation. Optional library adapters are not CLI integrations
  merely because their crates compile.
- Profile scanner/storage costs before optimizing repeated traversals. Check
  CPU/RSS/disk limits, corpus exchange, cancellation/resume, replay/minimization,
  and long-running diagnostics. The Nyx software-replay temporary stdout file
  still needs a disk-growth budget despite bounded returned memory.

Exit gate: release-artifact and final-source evidence matches the supported
surface, with no skipped/missing lane presented as validated.

### P7 — Release operations and final completion audit

- Review `.github/workflows/release.yml` trust boundaries. Administrators must
  protect release tags and the `production-release` environment and provision
  the signing secret/public variables through approved channels. A hostile
  workflow on an unprotected tag must not gain the signing key.
- Confirm private keys are outside all uploads/logs, PRs cannot use the signing
  environment, signed-job failure prevents publication, and the receiver can
  verify the complete artifact independently before extraction/execution.
- Review key recovery, revocation delivery, rollback policy, artifact provenance,
  supported upgrades, operational runbooks, audit retention and dependency/CVE
  feed coverage. An empty vulnerability database is not evidence of no known
  vulnerabilities; inventory-only and assessed states must remain distinct.
- Obtain explicit direction before using production credentials, publishing,
  deploying or changing external infrastructure. None occurred in this work.
- Audit every acceptance-matrix row against current authoritative evidence.
  Retain all unmet implementation and evidence gates. Do not mark complete on
  intent, historical green tests or lack of an obvious failure.

## Suggested task split for the next model

Use small, file-owned tasks and independent review. Lower-cost models can handle
mechanical docs/CI consistency, bounded script tests, fixture creation and result
aggregation. Protocol, parser semantics, concurrency/durability and trust-boundary
changes need a capable coding model and a separate review. Model identity does
not change authorization or safety requirements.

Recommended order: finish P2 eligibility and real-project validation → P3/P4
bounded slices → real-code P5 study → P6 current-image matrix → real-code and
soak qualification → P7 final audit. Release security and service work can run in
parallel when file ownership is disjoint. Keep one integration owner; serialize
shared Cargo builds and reserve quiet CPU for comparative trials.

## Evidence and environment inventory

These local artifacts are temporary and must be checked for existence on resume.
They are not committed release evidence and must not be deleted or overwritten
casually.

- `/tmp/bhf-enterprise-container.CRwioX/source-wave1.tar`: SHA-256
  `03fd68b1842172efd97a07a5ee83235d81d03cc642540cc88e0a8b055dc5e1f2`.
- Image `bhf:enterprise-20260924-wave1`: ID
  `sha256:c93dac8a0eabde82c4031db3b87bb482dc487ee56f7f02b02bc4379a974affdc`;
  successfully built from wave1, **not** from the paused current tree.
- `/tmp/bhf-enterprise-container.CRwioX/source-wave2.tar`: SHA-256
  `ed9b3a71ace2e8468ad0a23d518d1a15f29638ebbbe3af788dc067687f59f442`;
  snapshot only, no wave2 image built. It predates the newest scheduler, protocol,
  Go and subsequent release-hardening edits.
- `/tmp/bhf-enterprise-container.CRwioX/source-wave4-pugixml-lifetime.tar`:
  SHA-256 `f6048b57c11bd611d941d1f75972cc29eeaa4d30bde353199fdd7bf318677838`;
  build snapshot for the current-image strict sweep. Image
  `bhf:enterprise-20260924-wave4-pugixml-lifetime` has ID
  `sha256:140318d01e3b52fd82ea1cf00fff99a2c1b3895c76d900b528574c5cf275247c`.
  Documentation edits recording the results followed this build; do not call
  the archive a byte-for-byte snapshot of the later documentation worktree.
- Docker volume `bhf_enterprise_20260924_wave4_full32_clean`: clean pinned
  corpus and one uninterrupted 32/32 strict sweep. Logs:
  `/tmp/bhf-enterprise-wave4-full32-sweep.log`,
  `/tmp/bhf-enterprise-wave4-clean-corpus-verify.log`,
  `/tmp/bhf-enterprise-wave4-pugixml-replay.log`, and
  `/tmp/bhf-enterprise-wave4-tool-versions.log`.
- The same directory contains `build-wave1.log`, `cargo-deny.log`, corpus fetch
  and verification logs. Initial reuse of historical partial clones failed;
  fresh fetching succeeded, then verification reported 32 projects/0 failures.
- Volume `bhf_enterprise_20260924_wave1`: fresh pinned corpus at `/work/corpus`;
  no new matrix fuzz run started. Historical `bhf_sweep_work` and `bhf:local`
  were left intact.
- `/tmp/bhf-e3-engine-parity.log` and `/tmp/bhf-e3-redqueen-cmplog.log`: bounded
  BHF-only diagnostic gate results. Benchmark `results/*-runs/` trees are ignored
  generated evidence; small JSON files remain visible but are not valid parity
  evidence.
- `/tmp/bhf-afl503c.NoHEOu/`: pinned comparator source, historical failed logs,
  and successful `build-cxxflags.log`; no system installation performed.
- Initial broad-test log: `/tmp/bhf-production-final-tests.log`; Rust 1.88
  isolated target: `/tmp/bhf-msrv188-target.T8lYox`.
- Last disk observation after the full sweep: roughly 20 GiB free of 387 GiB.
  Avoid duplicate large builds, indiscriminate cleanup, and pruning unrelated
  Docker data. Resource availability must be rechecked before the next campaign.

The historical handoff preserved interrupted implementation. The resumed
checkpoint above records subsequent fixes and validation without altering the
earlier evidence files.
