<!-- SPDX-License-Identifier: Apache-2.0 -->
# Contractor qualification checkpoint

Decision: **NOT_READY**. This record distinguishes executed packaging/functional
checks from the requested third-party vulnerability-discovery campaign, which
is not executed in this work. No release or publisher signature has been made.

Live baseline: PR #91 remains open at
`37582ed1849d18b11e5d6438b049ee6ed5034b69`; main is
`2e9ea97def2a71e66bf00b5d50d4c5f5a9112bd6`. Version remains 0.2.35.
Latest published release is 0.2.34; prior releases are preserved.
Read-only protection lookup: strict `CI acceptance`, admin enforcement enabled,
force pushes/deletions disabled. No required-review entry appeared in the
protection response. The listed Copilot ruleset is disabled; no settings changed.
PR #91 had no submitted reviews. Earlier-head CI is not acceptance of this work.

Available local runner: 6 CPUs, 13 GiB RAM, 8 GiB swap, 179 GiB free disk;
Docker 29.1.3, unprivileged workload support. No new paid resources authorized.
Build concurrency: one image, two Cargo jobs. Functional containers: disconnected,
read-only root, at most 4 GiB RAM, 512 PIDs, two CPUs, disposable work/tmp space.
No external projects or credentials are mounted into these functional checks.

## Audit to action

| Area | Action and evidence status |
|---|---|
| Language selection | Shared resolver implemented. The exact `12d6066` default, sixteen singleton, and three mixed images passed construction, selection receipt, exclusion, and lifecycle checks. |
| Native installation | Shared resolver, pre-side-effect rejection, dry-run dependency closure, and authenticated install/tamper/upgrade/rollback tests passed 30/30. A fresh exact-head Linux bundle also passed signed archive verification, installation, and its C target-entry smoke. The disposable OS matrix remains a release gate. |
| Default no AI | Selected CLI/daemon compiled graph excludes `llm_harness_gen`; all twenty images passed dummy-provider and command/MCP exposure controls. |
| Functional controls | All sixteen BHF-owned clean controls entered non-stub targets through public `bhf auto`, executed inputs, produced measured feedback, and emitted valid JSON. Dependency-bearing Java controls also passed. |
| Artifact sizes | Exact local configuration IDs and unpacked bytes recorded for twenty images. The exact-head default image's compressed Docker archive and complete review archive are also recorded. Compressed and largest-layer comparison remains incomplete across every subset. |
| Inventory and signing | Independent verifier tests passed 8/8. Exact-head inventory, scan, acceptance record, BHF source, and all 108 requested Ubuntu source packages are in an unsigned review archive. The scan has zero policy blockers and 829 residual matches requiring review; no publisher key creation or release publication occurred. |
| 100 upstream projects | No frozen verified 100-project manifest or scored trials produced. Unrun; no success rate claimed. |
| Release support | Sixteen-language target-entry and an exact-head unsigned redistribution archive passed. The 100-project qualification, complete native/platform install matrix, redistribution review, protected human risk review, and publisher-authenticated handoff remain blockers. |
| Optional limits | Physical boards, arbitrary RTOS fidelity, Windows ETW and broad private-resource Rust remain scoped capability limitations. |

The 100-project qualification budget is up to 50 CPU-hours of requested target
execution alone (100 × 3 × 5 × 120 seconds), before preparation and builds.
Nothing in this checkpoint claims that compiler smoke or a short owned fixture
satisfies that preset. No failed project is removed from a scored denominator.

## Resumed packaging and owned-control work

The interrupted `ccdb343` matrix was continued from a detached checkout of that
exact source, preserving its first four rows and interrupted Java log. It
completed all twenty selections: nineteen compiler/lifecycle rows passed; the
Ruby-only build failed because the patched zlib gem needed development headers.
This older matrix did not include the stronger automatic controls added below.

The native installer regression expected the removed `none` language selector.
Its assertion and the packaged help were brought into agreement with the
nonempty-selection contract; all thirty installer tests passed, including
temporary-key authenticated installation, tamper rejection, upgrade preservation,
and rollback. Provider opt-in mocks passed 19/19. CI policy/inventory/resumption
tests passed 239/239; independent offline verifier tests passed 8/8. The selected
default CLI/daemon graph excludes `llm_harness_gen`.

The dependency-bearing BHF-owned Java control now uses public `bhf auto` on a
disposable source copy with spaces in its path, staged Maven dependencies,
network disabled, and a read-only root/original checkout. Cold and warm runs
each produced one entered target, 96 executions, 57 measured edges, and no
findings. An independent marker in the owned target confirms body entry.
Missing consent and an empty offline cache both produced zero entered targets
and exit status 1. Original source integrity was checked. JSON checkpoints and
artifact hashes survive disposable-volume cleanup even on assertion failure.

Additional clean packet/checksum fixtures exercise all sixteen lanes through
`bhf auto`; they are fixtures, not upstream-project slots. Initial runs exposed
Go replacement-path quoting on spaced paths and missing PHP `pcov` feedback.
The Go correction passed its 25 builder tests and all four integration tests,
including real target coverage with spaced source/work directories. The Ruby
dependency closure and PHP coverage extension were corrected and passed in the
final selected images. The first scalar-only Fortran fixture was ineligible by
design. Its character-input replacement entered successfully, and the initial
failure remains in local evidence. C/C++ spaced paths remain explicitly
unsupported by strict Makefile input validation. Ordinary-path controls passed
for those lanes.

The matrix now supports source/hash-checked resumption, preserves interrupted
attempt logs, checks ecosystem exclusions, and can require owned automatic
controls. An explicitly requested workflow matrix gates candidate packaging.
The exact `12d6066662daa68cbe242919d311f663d90ea0bf` matrix then passed all
twenty rows: the all-language default, each of sixteen singleton selections,
and Java/Python, C/C++/Ada, and JavaScript/TypeScript mixes. Source archive
SHA-256 was `2f6ff150ec95613cc31527dbbf3427c6d55f4e4fe8f969ce6fda37394479e2a0`.
Every row passed build, non-root disconnected/read-only runtime, termination,
malformed-option, dummy-provider/no-LLM, toolchain receipt/exclusion, and owned
automatic controls. The matrix checkpoint hashes to
`aa83811a4e6bb652b4a9b703aada7ede8ac3a96f98f3b0b74258efcc6d1e9711`.

The final default image is
`sha256:a3565b7e4c3c74754ab19068b565d254723e5da0f671bc06dfe6b73dd981f5f8`
at 3,647,380,700 unpacked bytes. Singleton images range from 1,053,558,558
bytes (Perl) to 2,096,099,063 bytes (Rust), showing real toolchain exclusion
rather than inheritance from the full image. The all-language owned-control
JSON hashes to `f916723ad99fe00c7e6c000197f29f29f1e49d0f9bd2db89d6c182b441f4256a`.
Each language entered exactly one clean target for 32 executions. Measured edge
counts were Ada 107, C 6, C++ 18, Rust 27, Java 17, Python 2, Perl 7, Go 14,
COBOL 37, Fortran 151, C# 5, JavaScript 3, TypeScript 10, Ruby 1, Lua 4,
and PHP 4. All produced zero findings, as expected for these clean controls.
These are functionality checks, not the 100-project qualification sweep.

Exact-head CI on PR #92 passed its acceptance gate at `12d6066`, including
Rust 1.88, build/test, core and default container jobs, RHEL 7/8/9/10,
Ubuntu 22.04/24.04/26.04, Windows build and Server 2025 compatibility,
license audit, SBOM, docs, and the hermetic target-entry gate.

At documentation head `b1b9bec379d430cb3f672401f2a234d11528fadf`, a clean
locked release workspace build was packaged into a 17,109,697-byte offline
Linux bundle with a disposable BHF-generated PKCS#8 v2 test key. The complete
archive was independently verified into a private copy before extraction. The
bundle installer then authenticated its content pack, installed the CLI,
daemon, bug-report tool, and both Linux shims into a clean prefix, and passed
its bundled C target-entry smoke: one target built and fuzzed, eight executions,
six edges, and zero findings. The development binary reported
`bhf 0.2.34-60-gb1b9bec` and commit `b1b9bec`; a version tag was not present.
The archive SHA-256 is
`d360dad713fd2c97b75cbda7bac6b8891395f3f3353c42b46b74f5b07c4d83e1`,
and the 64-byte detached signature's SHA-256 is
`62a0ddd35591c86ca6c1c7581670f447bd00544b06cc39990a34eb057f828936`.
The disposable private key was deleted after the receipts were captured. This
single-host test does not replace installation on every supported OS or
publisher signing.

Whole-image inventory of the older all-language image
`sha256:6f7c175dff3751da9c7195219f5810481dfacd0fb13ca1c254ed47fa70cc78d4`
used checksum-verified Syft 1.46.0 and Grype 0.115.0 with a valid database built
2026-10-04T08:11:47Z. Its policy result was
`REQUIRES_PROTECTED_REVIEW: 0 blockers, 829 residual matches` (678 Medium,
141 Low, 10 Negligible). Residual matches are untriaged; no risk was accepted.
The exact final image used the same checksum-verified Syft 1.46.0 and Grype
0.115.0 database. It contained two additional Debian components from the PHP
coverage correction and had the same 829 residual matches with zero policy
blockers. Its CycloneDX inventory hashes to
`1ed6d80f0ba2de4d9729bc9251f4025a8bce3473161b2e90e0afc60bcf665926`;
the complete Grype JSON hashes to
`e27bd156a317f7432fe4c623bb0b3b8d92377fc27247ce17b6ace15beb496794`.
Residual matches remain untriaged and require protected human review. Global
Rust formatting also reports pre-existing differences outside the
changed files; changed Rust files pass their scoped formatting check.

The documentation head
`27fa1bb85b9c0e4550c4617c340d01eaaf2ff5d6` was then built as a fresh
all-language default image and passed the full container acceptance path. The
image configuration digest is
`sha256:0f87da0b4aad41751e22cb37d2491fecb2d7e0b0a501baca3d48cea84f364114`,
with 3,647,380,699 unpacked bytes and a 1,392,718,906-byte gzip Docker archive.
Its source archive hashes to
`e3205d3c318ecc9949c0706a2d709abaa5bfe27f600d2cbf98b0caa5f9c0f226`.
The sealed acceptance record is `PASS`; inventory reconciliation, isolated
runtime controls, dependency-bearing Java, and all-language toolchain smoke
completed. The current scan again records zero blockers and 829 residual
matches. The scan JSON hashes to
`bd74b591849f445ee7f3b36b2d132c3301b8fb4cc09c807cc0180d654c1f5549`.

The matching unsigned redistribution candidate contains the saved tested
image, exact BHF source archive, 108 requested Ubuntu source packages across
335 corresponding-source files, license and Rust notice material, inventories,
the complete scan, and sealed acceptance logs. All downloaded-source checksums
and the candidate checksum passed. The archive has 374 members, with 370 files
bound into its release manifest; it is 2,263,872,500 bytes and hashes to
`b40b890b9ec208bff185aaa03d2b401b016682468f64629af3ea5e73c9e097f9`.
Its manifest state is `requires_detached_signature`. These materials make the
candidate reviewable; they do not complete license review, accept residual
vulnerability risk, or authenticate a publisher.

Raw execution evidence is retained locally under
`/tmp/bhf-qualification-20261005`; this is a workspace location, not a contractor
download link. The 100-project sweep, actual native package installation on every
supported OS, redistribution and residual-risk review, and
publisher-authenticated handoff remain unrun or incomplete. Decision remains
**NOT_READY**.

The compact matrix identities, sizes, per-language owned-control measurements,
and scan hashes are in the
[language-selection results](2026-10-05-language-selection-results.md).
