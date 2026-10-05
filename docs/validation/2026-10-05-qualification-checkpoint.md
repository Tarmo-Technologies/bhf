<!-- SPDX-License-Identifier: Apache-2.0 -->
# Contractor qualification checkpoint

Decision: **NOT_READY**. This record distinguishes executed packaging/functional
checks from the requested third-party vulnerability-discovery campaign, which
is not executed in this work. No release or publisher signature has been made.

Live baseline: PR #91 remains open at
`37582ed1849d18b11e5d6438b049ee6ed5034b69`; main is
`2e9ea97def2a71e66bf00b5d50d4c5f5a9112bd6`. The release candidate is now
version 0.3.0.
Latest published release is 0.2.34; prior releases are preserved.
The final customer-command check exposed a Windows default-run failure after
the earlier sanitizer-disabled smoke passed. The first failure was the missing
Clang ASan DLL search path. After resolving it, the driver's first-chance
exception handler still terminated valid sanitized inputs. A corrected driver
completed 64 executions with 11 coverage edges on Server 2019 and detected the
owned fixture's intentional out-of-bounds write. This is a diagnostic build,
not final packaged release acceptance. The shared Windows CI smoke now uses
the README command with default sanitizers and requires executions, coverage,
and the documented output files. Fresh packaged acceptance remains pending.
The exception-filter fix also covers the embedded C/C++ driver templates.
When every attempted fuzz pass fails, `auto` now records the last runtime
error instead of a build-only success. A run with no other successful target
therefore exits nonzero and keeps the error in `auto/run.json`.

The EL7 generated installer now installs successfully past its glibc check;
the following archive identity check incorrectly counted a license directory
named `bhf` as a second executable. That check now counts regular files only
and still rejects missing or duplicate executables. Its three regression tests
and the full 242-test CI policy suite pass locally.
Read-only protection lookup: strict `CI acceptance`, admin enforcement enabled,
force pushes/deletions disabled. No required-review entry appeared in the
protection response. The listed Copilot ruleset is disabled; no settings changed.
PR #91 had no submitted reviews. Earlier-head CI is not acceptance of this work.

Local runner at the initial checkpoint: 6 CPUs, 13 GiB RAM, 8 GiB swap,
179 GiB free disk;
Docker 29.1.3, unprivileged workload support. No new paid resources authorized.
Build concurrency: one image, two Cargo jobs. Functional containers: disconnected,
read-only root, at most 4 GiB RAM, 512 PIDs, two CPUs, disposable work/tmp space.
No external projects or credentials are mounted into these functional checks.

## Audit to action

| Area | Action and evidence status |
|---|---|
| Language selection | Shared resolver implemented. The exact `12d6066` default, sixteen singleton, and three mixed images passed construction, selection receipt, exclusion, and lifecycle checks. |
| Native installation | Shared resolver, pre-side-effect rejection, dry-run dependency closure, and authenticated install/tamper/upgrade/rollback tests passed 30/30. Final CI and actual packaged customer-command checks passed after correcting the installer and Windows default-run defects. The final Linux bundle passed authenticated installation with its smoke enabled, default C execution, and resume. The final Windows component archives passed default sanitized C execution on all three retained guests and clean C++ execution on Server 2019. |
| Default no AI | Selected CLI/daemon compiled graph excludes `llm_harness_gen`; all twenty images passed dummy-provider and command/MCP exposure controls. |
| Functional controls | All sixteen BHF-owned clean controls entered non-stub targets through public `bhf auto`, executed inputs, produced measured feedback, and emitted valid JSON. Dependency-bearing Java controls also passed. |
| Artifact sizes | Exact local configuration IDs and unpacked bytes recorded for twenty images. The exact-head default image's compressed Docker archive and complete review archive are also recorded. Compressed and largest-layer comparison remains incomplete across every subset. |
| Inventory and signing | Independent verifier tests passed 8/8. Exact-head inventory, scan, acceptance record, BHF source, and all 108 requested Ubuntu source packages are in an unsigned review archive. The scan has zero policy blockers and 829 residual matches requiring review; no publisher key creation or release publication occurred. |
| 100 upstream projects | No frozen verified 100-project manifest or scored trials produced. Unrun; no success rate claimed. |
| Release support | Final installer CI, sixteen-language target-entry, default container execution, authenticated Linux customer installation/resume, retained Windows default component execution, and source-bound unsigned archive validation passed. The 100-project qualification, redistribution review, and publisher-authenticated handoff remain incomplete. The user excluded protected human approval from this execution; no protected workflow setting or review decision was changed. |
| Optional limits | Physical boards, arbitrary RTOS fidelity, Windows ETW and broad private-resource Rust remain scoped capability limitations. |

The 100-project qualification budget is up to 50 CPU-hours of requested target
execution alone (100 × 3 × 5 × 120 seconds), before preparation and builds.
Nothing in this checkpoint claims that compiler smoke or a short owned fixture
satisfies that preset. No failed project is removed from a scored denominator.
An audit covering September 28 through October 5 found no completed run:
repository history contains no new campaign results, the local sweep workspaces
were last updated in July or August, and the hosted workflows in that period do
not run 100 projects. The older July corpus and results therefore do not satisfy
the one-week requirement.

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

The documentation and release-document contract review was pushed as
`e95d2d08048e77db72dc95436853d251ffaae1de`. Repository-wide Markdown scans
identified and removed first-person drafting residue and unsupported overall
rankings; dated benchmark conclusions were scoped to their pinned corpora.
Local site/link generation, SPDX validation, 239 CI policy tests, and 16
documentation/release-contract tests passed. Hosted full CI run `37266433513`
then passed for this commit, including the complete platform and container
matrix. Separate docs, license, SBOM, dogfood, and hermetic target-entry jobs
also passed. The public comparison's final accuracy pass additionally removed
an unmeasured raw-throughput ranking and distinguished average SLOC deviation
from per-repository deviation.

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

The EL7-baseline binaries retained by exact implementation-head CI run
`37254610365` were also packaged from the clean `12d6066` source with a new
disposable BHF-generated key. The complete 16,856,154-byte archive was verified
into a private copy before extraction. Its SHA-256 is
`bb0fe1f0525ef8f99c7158c491f34433eebe43924b4e5165593466a3643f4750`,
and its 64-byte detached signature hashes to
`d7870cdd48515b73c8db1c807015f163e3e8faee2e2b183b004d9b5980f0f84f`.
The real bundle installer authenticated and installed the Python selection on
the pinned CentOS 7 ABI image, AlmaLinux 8.10, 9.8, and 10.2, and Ubuntu 22.04,
24.04, and 26.04. Every row loaded the CLI, daemon, and two shims without a
missing library and reported `bhf 0.2.35`. Network, system-package installation,
rustup, symlink creation, and the bundled C smoke were disabled for this matrix;
it establishes archive authentication, installation, and binary compatibility.
Separate exact-head jobs and the all-language container matrix cover toolchains
and target entry. Hosted CI also extracted and exercised the native Windows
archive on Server 2022 and 2025. The disposable matrix key was deleted.

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

For the retained `27fa1bb` candidate, a local reviewer handoff under
`/tmp/bhf-qualification-20261005/reviewer-handoff-27fa1bb` contains every one
of the 829 residual matches in `residual-findings.csv`, plus
`package-summary.csv` and `review-summary.json`. The matches span 115
package/version pairs and 175 unique vulnerability IDs. All match decisions
remain `under_investigation`; grouping does not remove rows or accept risk.
The complete CSV hashes to
`1f350bd4bda4fe9ba8d992ace126599195a964a82cf7333a6e58d7f7c468c528`,
and the package summary hashes to
`633e5049c968780437225494a3cd700189a593609e62d33976b7875066eab0a2`.
These convenience files describe the earlier retained candidate, not a release
rebuilt from the documentation-review commit.

Raw execution evidence is retained locally under
`/tmp/bhf-qualification-20261005`; this is a workspace location, not a contractor
download link. Final generated-installer CI and customer-path checks passed. The
100-project sweep, redistribution and residual-risk review, and
publisher-authenticated handoff remain unrun or incomplete. Decision remains
**NOT_READY**. Protected human approval is outside this execution at the user's
request; it has not been recorded as granted.

## Proxmox and installer follow-up

Proxmox SSH aliases now select the existing key for `proxmox`, `10.100.0.1`,
`ms01`, and `192.168.48.22`. Each alias checks the existing trusted host record
for `10.100.0.1`. Direct IP and hostname authentication passed. The retained
Windows Server 2019, Windows 11 25H2, and Windows 11 LTSC 2024 guests then passed
actual generated component installation and native C execution. Their source
identity, artifact hashes, scoped results, and VM cleanup are recorded in the
[Windows installer results](2026-10-05-windows-installer-results.md).

The new CI installer checks exposed three issues: the host-owned checkout was
not trusted inside the EL7 build container; Python inherited incompatible
PowerShell 7 module paths when launching Windows PowerShell 5.1; and global
cargo-dist installer generation incorrectly advertised glibc 2.31 instead of
the ABI-checked 2.17 baseline. The fixes trust only the container checkout,
clear inherited module paths in the child test environment, and explicitly
declare the Linux target's validated glibc floor. Release builds also retain
the exact source commit in their CLI and daemon version output.

A fresh all-language image at
`86bea93c73d513ec59d5021bb7f08670ed11c242` passed sealed container acceptance.
Its configuration digest is
`sha256:b9754f624ad042c76d8c46cc50d2aa1a4185038354e7602c17a4583121e532db`;
its scan hashes to
`2a9012e9deefda15416c0d6dbb036f10cc405cd7a6d1f29fe3b2ee6b41e0cf41`
and again records zero policy blockers and 829 residual matches. The matching
unsigned archive contains the tested image, exact BHF source, the same 108
requested Ubuntu source packages, inventories, notices, and sealed evidence.
The packager rechecked the downloaded-source checksums and exact installed
source-version requests before reusing those files. The archive is
2,263,880,329 bytes and hashes to
`b5ba99e4baf0ec59c718220b1f63e637607142989320c61c53e8642770b9c83b`.
It represents that source snapshot, before the final glibc metadata correction
and documentation update; it remains unsigned.

The retained `27fa1bb` redistribution review files now also include 64 packaged
toolchain notice texts and their hashes. That JSON hashes to
`972081931f44f337c02bbfbc14cc7cf3cb66ee7dcfb67557bfa9ba4ee1cc26f2`.
Literal component-name references were found for 105 of the 1,549 records with
missing scanner license metadata. These are unreviewed text pointers, not
license assignments. The matching `dotnet8` corresponding-source request is
present. This material does not complete redistribution review.

PR #91's cancelled dogfood check was rerun and passed. Its other checks remain
successful; the PR is still open. No merge, version tag, publisher signature,
or new GitHub release has been made.

The customer documentation pass corrected a failing full-bundle command:
README and the site installation guide now pass the required external trust
policy and verify the detached archive signature before extraction. The offline
update example uses the same procedure. README and the two main help screens
begin with a serial, one-target run and identify the results and skipped-target
reports. Language defaults and the distinct `auto`/standalone `fuzz` corpus
budgets were reconciled with the implementation. All 166 Markdown documents
were rescanned for drafting residue and vague promotional language. Site/link
generation, SPDX validation, 239 CI policy tests, existing help contracts, and
13 release/document contract tests passed locally. The final packaged customer
workflow still needs execution against the rebuilt artifacts.

The compact matrix identities, sizes, per-language owned-control measurements,
and scan hashes are in the
[language-selection results](2026-10-05-language-selection-results.md).

## Final packaged customer-workflow validation

Customer workflow decision: **PASS** for branch source
`d3509e35766c56a377f6735bfd5a5b228492c5c4`. Hosted CI run
`37321367468` passed every required check, including all supported Linux
compatibility jobs and Windows Server 2022/2025. The native artifacts report
CI merge source `d1bd11b74f690bbe70e8ccf61b0a223cbd65e63c`; its tracked tree
is identical to the branch source. These source identities are preserved;
subsequent documentation-only commits are not represented by these artifacts.

The actual EL7 CI binaries were packaged with a disposable test key. The
independent Python verifier authenticated a private copy before extraction.
The extracted installer ran with its smoke enabled, an external test policy,
a new prefix, and no package-manager, Rust, or symlink changes. The installed
CLI then ran the README command with default sanitizers against a clean owned
C fixture: one non-stub target, 103,814 executions, eight measured edges,
zero findings, and both documented report paths. Repeating that command with
`--resume` reloaded one completed target and reran zero targets. The private
key was deleted. This proves the authentication workflow with a test identity;
it does not authenticate a publisher.

The 16,850,074-byte Linux bundle hashes to
`7d6c731b7af92beb41e8d207376a558c0ea62776e025f8e5999fe6173efa4e25`.
Its receipt hashes to
`e78da0cbdc999da858d9e60b7b8bffedc2b8a15b4795bbbabc9655b639aa4d46`.
Raw evidence is under
`/tmp/bhf-qualification-20261005/customer-native-d3509e3`.

The final default container is
`sha256:ae789a83a8140534bfbeb65e540ca7f8e2fc21c3b1cbdd7e9ef78d3ab64199bb`.
Its full acceptance record hashes to
`b2bed9d2fdb60d81a91afc93e53757be9c681ee1949ff2e9eb132f20c2537d9e`.
A disconnected, read-only, non-root run of the README default command completed
97,688 executions and eight measured edges on a clean owned C target, with zero
findings. All sixteen owned language controls also passed: each entered one
non-stub target, executed 32 inputs, measured positive coverage, and produced
zero findings. Those bounded controls used `--sanitizers none` and are separate
from the default C check. Their combined JSON hashes to
`9941f8b18d8f6079d22e26e7337851b0926f4db14bdbce3d0cd897186b6dec46`.

The final unsigned container archive contains the tested image, exact BHF source,
all 108 matching Ubuntu source-package requests, and sealed inventory/scan data.
It is 2,263,886,372 bytes and hashes to
`eb61458454348a1f64e7c31c0a2b696328bdff1d0230c348aa30daa37907cb1b`.
An independent streaming read checked all 370 manifest files against their
hashes and matched the source/image identity. The scan still has zero policy
blockers and 829 residual matches under investigation. No risk acceptance or
publisher signature is implied.

The documentation-complete `f46f885671b0e8f700cdb26671202c552905492d`
revision was then rebuilt and rechecked. Hosted CI run `37326679648` passed all
required jobs. The final EL7 artifact ZIP hashes to
`093b2ff1b0b54916dc0287515b0089966b706caa7392c854dbe5081044de0dfa`;
the binaries report CI merge source
`647c82ab71896b0336e2f7b67b4984201cd9a299`. Its authenticated test bundle
completed the installer smoke, README default run, and explicit resume path:
105,105 executions, eight measured edges, zero findings, one completed target
reloaded, and zero rerun. The disposable signing key was deleted.

The corresponding final container image is
`sha256:13f1c6667acdf12f7ac97903b652dcce9bba0566080406008c8bbac454bb7583`.
Its unsigned 2,263,879,480-byte archive hashes to
`e3683f8043cb3a4c772339d58e3169319cb284cf6bb68c291e5785042c434483`.
An independent streaming read matched all 370 manifest files, the exact source
commit, and the image digest. A fresh disconnected, read-only, non-root README
run completed 94,424 executions with eight measured edges and zero findings.
These retained artifacts are version 0.2.35. The requested 0.3.0 version-only
candidate must pass its own exact-revision CI and artifact checks before release.

Final retained Windows component/default C checks passed on Server 2019,
Windows 11 25H2, and Windows 11 LTSC 2024, detecting the owned fixture's
intentional ASan stack-buffer-overflow. A clean default C++ run on Server 2019
completed 30,507 executions and 38 measured edges with zero findings. See
[the Windows evidence record](2026-10-05-windows-installer-results.md).
All three guests were shut down and their original boot orders restored.
Horizon remained running.

The final documentation review checked README/install steps against the actual
installer, source, and packaged command output. All 41 public command-help
interfaces returned valid help. The documentation site/link build, SPDX check,
242 CI policy tests, real all-inputs-rejected regression, and 12 help-related
 unit tests passed. A style-marker scan covered 183 tracked documentation files
with no drafting or AI-phrase matches. The release checklist now assigns bundle
creation/signing to the actual protected job and requires archive authentication
before extraction. The unavailable dedicated documentation-review skill was
replaced by direct source, command, and evidence review.

The download examples now target the 0.3.0 candidate instead of the previous
published release. The documentation contract checks those examples against
the workspace release version. All 13 release-document/manifest contract tests
pass. The candidate remains unpublished until the release process completes.

The retained 100-project requirement remains unrun; customer functionality
checks do not satisfy that scored qualification. Its status is kept separate
from the passed functional checks. Protected human approval remains excluded
from this execution, with no workflow setting or review decision changed.
