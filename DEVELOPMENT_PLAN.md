<!-- SPDX-License-Identifier: Apache-2.0 -->
# BHF enterprise-readiness plan

This page tracks the status and order of the enterprise-readiness work: the phases P0 to P7 below, what each one has delivered, and what is still open. The goal is a production-ready BHF whose capability and effectiveness hold up against AFL++ and Mayhem. No comparative study has measured that yet (see [P5](#p5-comparative-effectiveness-baseline)).

The status below was recorded on 2026-09-25 at workspace version `0.2.32` (baseline commit `5528a41df1968e7ec7efb843b9dac12cbe377c8c`), with [later changes](#changes-since-2026-09-25) listed after it. Use a recorded test result as evidence for that tree only; re-run the gates on the tree you release.

## Plan index

| Document | Purpose |
|---|---|
| [Enterprise readiness program](docs/enterprise-readiness-program.md) | Full acceptance matrix: security, services, engines, breadth, scale, access, platforms, supported surface |
| [Production readiness review](docs/production-readiness-review.md) | Initial audit, corrections, broad-test record, remaining release gates |
| [Release and CI fixes](docs/review-release-ci.md) | Installer, packaging, minimum Rust, CI and documentation defects |
| [Daemon and editor hardening](docs/review-daemon-editors.md) | Trust-boundary and editor lifecycle defects |
| [Feature review](docs/review-feature-completeness.md) | Optional-engine limits, cleanup and replay issues, feature and efficiency backlog |
| [Pack authentication](docs/enterprise-pack-authentication.md) | Signature formats, trust and rotation, whole-archive signature, installer limits |
| [Daemon reliability](docs/enterprise-daemon-reliability.md) | Bounded responses and finding loading, editor deadlines, process ownership |
| [Service soak plan](docs/enterprise-service-soak-plan.md) | Durability, backpressure, shutdown, tenant boundary, failure-injection and soak plan |
| [Scheduler reliability](docs/scheduler-reliability.md) | Storage ownership, fail-closed persistence, health and shutdown APIs |
| [Harness protocol](docs/enterprise-harness-protocol.md) | How the builtin engine picks a harness's input protocol, and the manual C workflow defect |
| [Typed Go data parameters](docs/enterprise-harness-gap-plan.md) | Plain-data Go parameter decoding, eligibility rules and acceptance tests |
| [Engine benchmark plan](docs/enterprise-engine-benchmark.md) | Comparison runner, diagnostic evidence, real-code comparison method |
| [Container validation](docs/enterprise-container-validation.md) | Sweep and fetch contracts, sixteen-language image validation |
| [Measured language gaps](docs/expected-gaps.md) | Per-language exemplars, residual categories, counts, ranked work |

Older wording in those documents such as "active", "next wave" or "implementation complete" describes the state when each was written; this page holds the current status.

## Gate status (2026-09-25)

Recorded on a Linux host with the release binary, GnuCOBOL 3.1.2, clang 18.1.3, PHP 8.3.6, Lua 5.4 and AFL++ 5.03c. "Done" means the tests pass and, where a lane was fixed, the lane was re-run on the pinned corpus.

| Item | Status | Evidence |
|---|---|---|
| COBOL finding-count reconciliation | Done | carddemo findings 1 → 0, all report surfaces agree; `report::reconcile_pass_findings_with_disk` and its regression test |
| Zero edges, php/symfony-yaml | Done | 0 → 1230 edges; accessor and exception-setter demotion, two regression tests |
| Zero edges, php/php-parser | Done | 0 → 174 edges; first-parameter fuzz affinity, one regression test (a ranking follow-up is open, below) |
| Zero edges, lua/lunajson | Done | 0 → 162 edges; discovery of factory fields in a module's `return {}` table, two regression tests |
| Installation security (P3) | Implemented and tested | Governance, `pack_auth_cli`, `m19_signed_releases` and `offline_dist_scripts` tests: signing, key handling, downgrade, tamper and revocation, external trust policy, offline install |
| Service durability (P4) | Core implemented and tested | `bhf-daemon` and `continuous_daemon` tests: bounded queue (1,024) and 64 MiB snapshot cap, `Capacity` backpressure, crash recovery, atomic persistence, webhook deadline and response cap, process-tree shutdown. Open: a sustained scale soak with RSS and latency thresholds, and native Windows process-tree tests |
| Comparative baseline (P5) | First step done; study open | A three-engine smoke (`benchmarks/engine-comparison/results/smoke-p1-three-engine-20260924-01.json`); AFL++ 5.03c builds. Open: a multi-trial real-code study, a fresh libFuzzer arm, a Mayhem comparison |
| Release and security audit | CI-tested | `m19_signed_releases` and `m19_full_ci_matrix` pass; an external audit is open |

`cargo test -p bhf --lib` passed with no failures, as did the governance, `bhf-daemon`, `continuous_daemon` and `target_rank` suites and the pack, offline-distribution and signed-release integration suites. The workspace test targets passed in segmented runs; no single uninterrupted `cargo test --workspace` run passed on that tree.

Three qualification gates had no environment and are open: a licensed Mayhem comparison, a native Windows and RHEL test matrix, and a fresh libFuzzer benchmark arm (it needs `libstdc++-dev` installed with root). The real-code comparison study and the sustained multi-worker soak need a dedicated long-running environment; P5's exit gate does not accept small stand-in runs for them.

### Changes since 2026-09-25

- **Typed Go data parameters:** the 2026-11-16 [Go re-sweep](docs/validation/2026-11-16-go-resweep.md) re-ran the 59 targets skipped as Go-1; 7 now build and fuzz and 52 still skip.
- **Scheduler:** jobs record their tenant and workspace, tenants see only their workspace's jobs, and a job left `Running` by a crashed scheduler is marked `Failed` on restart, with its leftover process stopped on Linux (#385). Webhook DNS resolution has a deadline and scheduler shutdown is bounded (#272). See [Scheduler reliability](docs/scheduler-reliability.md).
- **Daemon tenant paths** are pinned with `openat2` on Linux; see [Daemon](docs/site/daemon.md#security-modes).

## Fixes recorded during this work

### Lane fixes from the container sweep

The 32-project container sweep on image `bhf:enterprise-20260924-wave4-pugixml-lifetime` reported three lanes with zero coverage edges. They were three different defects:

- **php/symfony-yaml: target selection.** BHF picked `ParseException#setParsedFile`, a setter on an exception class, over `Yaml::parse`. The dynamic-lane name scorer matched the `parse` action stem inside the setter's noun (`set` + **Parsed**File), tying it with the real parse entries, and the single-target sweep took the alphabetically first one, whose receiver constructor needs an argument. `is_accessor_or_mutator` (`crates/target_rank/src/name_semantics.rs`) now demotes any method whose leading token is `set`, `get`, `is`, `has` or `with` below every normal target (`discovery::dynamic_target_score`). On the pinned corpus with PHP 8.3.6 the top targets are now `Inline::parse`, `parseScalar` and `evaluateBinaryScalar`, all entered, with 1223 to 1230 edges. Regression tests: `accessors_and_mutators_detected_by_leading_token_only` and `exception_class_setter_ranks_below_real_parse_entries`.
- **php/php-parser: entry.** The pick `ConstExprEvaluator#evaluateSilently(Expr $expr)` was `built_not_entered` because its first parameter is an AST object that fuzz bytes cannot produce. `php::first_param_fuzz_affinity` now ranks a first parameter that is the byte channel (`string`, `mixed`) above one that needs object synthesis. The lane now enters and gains coverage: `Lexer#tokenize` 174 edges, `JsonDecoder#decode` 48. Regression test: `first_param_affinity_prefers_byte_channels_over_object_synthesis`. Open: the top pick `Internal\TokenPolyfill::tokenize` still records about 0 edges, because on PHP 8 it delegates to the native `PhpToken` tokenizer, which pcov cannot see; demoting the `Internal` namespace would route the single-target sweep to `Lexer#tokenize`.
- **lua/lunajson: discovery.** The picked targets ran no Lua lines: `decoder.lua#fixedtonumber` is `local fixedtonumber = tonumber` (an alias of a C function) and `encoder.lua#__index` is a metamethod. The real entry, `decode`, is a runtime closure: `src/lunajson.lua` ends with `return { decode = newdecoder(), ... }` and has no static `function decode`. `lua::parse_module_table_fields` now discovers the public fields of a module-level `return { ... }` table whose value is a factory call or an inline `function`, and metamethods (`__*`) are demoted in every dynamic lane. `decode` is now the top pick, entered, with 162 edges. Regression tests: `module_return_table_factory_fields_are_discovered` and `nested_return_table_inside_function_is_not_a_module_surface`.

### COBOL finding count

COBOL crash attribution (`cobol_oracle::run_cobol_attribution`) deletes the `findings/<id>/` bundle of a crash it proves to be a harness artifact: the empty input drove `CSUTLDTC` into a dynamic `CALL` to a sibling program not linked into the single-program harness (`libcob: module 'X' not found`). The deletion reached `findings.csv` and `FINDINGS.md` but not the in-memory pass records behind `summary.findings`, `run.json` and `run.md`, so the headline count showed a finding with no evidence. `reconcile_pass_findings_with_disk` now keeps only pass finding IDs whose `finding.json` still exists, after every post-pass and before the reports are written. On the pinned carddemo corpus, `CSUTLDTC` reports `reconciled 1 finding id` and every surface reads 0. Regression test: `phantom_finding_removed_by_post_pass_is_reconciled_out_of_count`.

### Pugixml double free from the generated harness

The wave2 Pugixml run reported three ASan double frees from one generated sequence harness. The harness freed its buffer after `pugi::xml_document::load_buffer_inplace_own`, which takes ownership of it. The generator no longer frees buffers whose ownership the callee takes, and frees buffers lent to `load_buffer_inplace` only after the document is reset. A generated-code regression covers lifecycle, protocol and shared target-parameter cleanup. On the corrected image Pugixml ran with 562 edges and no findings, and the three old testcases replayed against the new harness with exit code 0: the reports came from the harness, not Pugixml.

### Container gate

On image `bhf:enterprise-20260924-wave4-pugixml-lifetime` (`sha256:140318d01e3b52fd82ea1cf00fff99a2c1b3895c76d900b528574c5cf275247c`, built from a source archive with SHA-256 `f6048b57c11bd611d941d1f75972cc29eeaa4d30bde353199fdd7bf318677838`, recorded in the image labels), one uninterrupted strict sweep of the 32 pinned projects with `--network none`, one target per project, five seconds per target, a 120-second campaign cap, `CARGO_NET_OFFLINE=true`, staged Cargo and NuGet caches and a local NuGet feed returned `PASS=32`, `STUB-ONLY=0`, `NO-TARGETS=0`, `MISSING=0`, `ERROR=0`. A pass means at least one non-stub target was entered in each project. On the earlier wave2 image, Rust CSV and C# Sprache and Superpower passed only after their Cargo and NuGet dependencies were staged: BHF's preloaded instrumentation dependencies do not make every application buildable offline. [Container validation](docs/enterprise-container-validation.md) describes the sweep.

### Manual C protocol (P1)

The documented manual C `generate-harness`, `build`, `fuzz` path now selects `bhf_framed`, creates a temporary coverage map when the caller supplies none, and reports a planted ASan heap overflow with nonzero edge feedback. After a framed child died, fresh-process replay used to send raw stdin to a driver that takes a file name in that mode, so the target was never called; that is fixed and covered with and without the fork server. The C++ amalgamation suite found that the state-masked crash recheck was guarded by the external libFuzzer classification, which a framed driver does not have; it now uses the framed-driver guard. See [Harness protocol](docs/enterprise-harness-protocol.md).

### Go data-only parameters (P2)

`auto` and `fuzz` seed complete JSON examples, use declared JSON field names, reject method-bearing types and unsupported tags, and select the target from its own source file. A pinned frp target changed from a type skip to an unforced run with coverage. See [Typed Go data parameters](docs/enterprise-harness-gap-plan.md).

### Other changes

- The SPDX manifest generator excludes `benchmarks/engine-comparison/results`, so the manifest no longer depends on local evidence files, and still checks benchmark source.
- The license audit failed while `THIRD_PARTY.md` lacked the new direct `ring` dependency; the matrix now lists it as `Apache-2.0 AND ISC`.
- The pinned AFL++ 5.03c (`dbaf11913c1b2702dee5b4d3dcfffd52f1defe50`) LLVM instrumentation builds with `CXXFLAGS='-O3 -funroll-loops -fPIC --gcc-install-dir=/usr/lib/gcc/x86_64-linux-gnu/13'`. In the one-trial, five-second three-engine smoke, BHF and AFL++ saved crashes that replayed independently within budget (first seen at 0.63 s and 0.18 s); libFuzzer's crash was first seen at 8.56 s and is recorded as `out_of_budget_crash`. The runner records BHF's run-summary protocol and coverage and separates post-budget artifacts from in-budget solves. This smoke checks the runner.
- Strict Clippy stopped on `manual_is_multiple_of` in `cmplog`, then on `too_many_arguments` and `redundant_closure` in `governance`; it was not a passing gate on that tree.
- A full-workspace test run once failed one of 12 Ada build-recovery scenarios with zero built targets; the fixture built and fuzzed when run directly and the `build_recovery` target passed with one test thread. Treat it as a possible flake under load.

## Execution plan

### P0: Stable source checkpoint (done)

Two interrupted CLI workstreams (the manual C protocol in `crates/cli/src/fuzz.rs` and Go data-only harnesses in `crates/cli/src/auto/go_build.rs` and `crates/go_parser/src/lib.rs`) were finished, `cargo check --workspace --all-targets` passed, and focused tests passed.

### P1: Correct the documented generate, build, fuzz workflow (done)

One protocol resolver serves sibling-source, split generated/build, automatic and script layouts, keeps external libFuzzer and stdin support, and gives a framed marker priority over the mere presence of C source. The same classification drives persistent execution, coverage, per-input dispatch, replay, filtering and summaries. Exit gate: the real manual and automatic workflows work, and the benchmark uses the unmodified documented workflow.

### P2: Go data-only construction, then measured lane gaps

Eligibility is proven from declarations: only plain-data shapes, and no opaque or imported types, private fields, interfaces, synchronization or resource handles, unsafe state, lifecycle-dependent objects or custom `UnmarshalJSON`/`UnmarshalText` hooks. Tests cover nested structures, pointers, collections, null, missing and malformed fields, rejection of hooks and opaque types, and harness-versus-target attribution.

Then work the per-language backlog in [expected-gaps.md](docs/expected-gaps.md) from current logs: C opaque lifecycle, Java generic and collection parameters, C++ non-self-contained headers, Go parameter, receiver and module gaps, Rust decoders and trait resolution, C++ class construction, Ada symbols and GPR structure, Python and C# receivers, and JavaScript browser environments. Some of these are already fixed there; check before starting one.

Exit gate per change: before-and-after evidence of real entry and coverage, no new false findings that come from the harness, and residual categories that separate dependency, environment and design limits from implementation gaps.

### P3: Artifact and installation security

Signed bytes, key-ID binding, key parsing, duplicate and unknown fields, policy downgrade, revocation and rotation are implemented and tested with the RFC 8032 vector and OpenSSL. Installation copies into an owned stage, verifies the staged bytes, and publishes with a no-clobber rename on Linux; seed validation and extraction use one controlled snapshot.

Open: substitution of source or destination ancestor directories, non-Linux publish behavior, recovery from an interruption between renames, and disk limits for uncompressed seed extraction. `--no-content` extraction is unauthenticated.

Exit gate: bounded, authenticated, recoverable installation under injected failures, plus reviewed key custody, rotation and revocation procedures. See [Pack authentication](docs/enterprise-pack-authentication.md).

### P4: Service durability, scale and deployment boundaries

Bounded queue, history and startup loading, `Capacity` backpressure, paginated listing, webhook deadlines and response caps, bounded shutdown, tenant-scoped jobs and orphan reconciliation are implemented.

Open: persistence still rewrites the whole bounded history under one mutex; there is no retention or export policy; Windows process-tree and filesystem behavior need native tests; jobs run as the daemon's OS user, so shared operation needs OS or container isolation per tenant; and the sustained multi-worker and restart soak has not run. Set thresholds for RSS, disk, child count, acknowledgement survival, shutdown time and p95/p99 submit and list latency before it runs.

Exit gate: tested bounded operation, recoverable state, and a deployment threat model that matches the code. The fixtures are in the [service soak plan](docs/enterprise-service-soak-plan.md).

### P5: Comparative effectiveness baseline

- Run multiple independent trials on representative real-code families with common harness semantics and independent replay and coverage measurement, following the FuzzBench method.
- Pin tool and source versions and hashes. Keep base seeds, input limits, resource budgets and sanitizer policy identical, and document native guidance differences (BHF source dictionaries, AFL++ CMPLOG, libFuzzer value profiling). Native execution counters are not comparable across engines.
- Separate build and setup cost, campaign time and artifact-observation overhead, and report effective time budgets, including sanitizer symbolization delay. A crash seen after the budget is not an in-budget solve. Keep failed builds, tool errors and unconfirmed artifacts apart from valid right-censored trials.
- Confirm saved results through one independent oracle, deduplicate bugs, measure common coverage, and publish raw rows with a reproducible analysis and its uncertainty. Fix targets, trials and budgets before the runs.
- Compare expert harnesses with generated ones on coverage and reach, setup effort, reproducibility and false-result rate, as well as throughput.
- A Mayhem comparison needs a licensed version and account with equivalent integration and budget. Record any capability Mayhem has that BHF lacks.

Exit gate: repeatable real-code evidence strong enough for each specific claim made. See the [engine benchmark plan](docs/enterprise-engine-benchmark.md).

### P6: Validate current artifacts across languages and platforms

- Build a tagged image from a captured source snapshot, with the source archive hash, revision, timestamp and tool versions in its labels.
- Run the 32 pinned projects in 16 languages with the strict real-entry sweep in fresh result directories on verified clean sources. Keep failures and zero-feedback lanes.
- Check offline operation with explicitly staged target dependencies and the network disabled.
- Run the final-tree workspace, optional-feature, editor, docs, SPDX and license, minimum-Rust and artifact-installation gates, and the native Windows and RHEL/Ubuntu ABI matrices, on the exact release tree.
- Review every public command and advertised feature against the implementation. An optional library adapter counts as a CLI integration only when a command uses it.
- Profile scanner and storage costs before optimizing repeated traversals, and check CPU, RSS and disk limits, corpus exchange, cancellation and resume, replay and minimization, and long-running diagnostics.

Exit gate: release-artifact and final-source evidence matches the supported surface, and no skipped or missing lane is reported as validated.

### P7: Release operations and final audit

- Review the trust boundaries of `.github/workflows/release.yml`. Administrators protect release tags and the `production-release` environment and provision the signing secret and public variables; a workflow on an unprotected tag must not reach the signing key.
- Confirm that private keys stay out of every upload and log, that pull requests cannot use the signing environment, that a failed signing job stops publication, and that a receiver can verify the complete artifact before extracting or running it.
- Review key recovery, revocation delivery, rollback policy, artifact provenance, supported upgrades, operational runbooks, audit retention and CVE feed coverage. An empty vulnerability database is not evidence of no known vulnerabilities; keep inventory-only and assessed states distinct.
- Audit every row of the acceptance matrix against current evidence, and keep every unmet gate open.

## Evidence kept outside the repository

The 2026-09-24 and 2026-09-25 runs kept their logs, source archives, Docker volumes and images on the build host; they are not in the repository. The container images and archives are identified by these values:

| Artifact | Identity |
|---|---|
| Source archive `source-wave1.tar` | SHA-256 `03fd68b1842172efd97a07a5ee83235d81d03cc642540cc88e0a8b055dc5e1f2` |
| Image `bhf:enterprise-20260924-wave1` | `sha256:c93dac8a0eabde82c4031db3b87bb482dc487ee56f7f02b02bc4379a974affdc` |
| Source archive `source-wave2.tar` (no image built) | SHA-256 `ed9b3a71ace2e8468ad0a23d518d1a15f29638ebbbe3af788dc067687f59f442` |
| Source archive `source-wave4-pugixml-lifetime.tar` | SHA-256 `f6048b57c11bd611d941d1f75972cc29eeaa4d30bde353199fdd7bf318677838` |
| Image `bhf:enterprise-20260924-wave4-pugixml-lifetime` | `sha256:140318d01e3b52fd82ea1cf00fff99a2c1b3895c76d900b528574c5cf275247c` |
| Docker volume `bhf_enterprise_20260924_wave4_full32_clean` | The clean pinned corpus and the 32/32 strict sweep |

The benchmark `results/*-runs/` trees are generated and ignored by git. The small JSON files in `benchmarks/engine-comparison/results/` are diagnostic smoke records, including those named `smoke-valid-*`, and are not parity evidence.
