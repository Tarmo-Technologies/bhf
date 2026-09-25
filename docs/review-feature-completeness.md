<!-- SPDX-License-Identifier: Apache-2.0 -->
# Feature completeness review

This is a scoped review of the current feature promises, the documented residual
gaps, and optional fuzz-engine adapters. It is not a claim that every roadmap
item or every target in the supported languages is complete. The roadmap itself
marks §24 as continuing work, while `docs/expected-gaps.md` distinguishes BHF
gaps from absent dependencies, environment limits, and intentional refusals.

## Prioritized follow-up handoff

| Priority | Work item | Evidence | Acceptance | Economical assignment | Status |
|---|---|---|---|---|---|
| P1 | Complete real Nyx execution or keep it explicitly unsupported. The `nyx-engine` feature previously reached `unreachable!()` even though `NyxError::NotImplemented` exists. | `crates/fuzz_engine/nyx_adapter/src/lib.rs`; `crates/fuzz_engine/nyx_adapter/Cargo.toml`; `docs/site/cli.md` says Nyx is not CLI-reachable. | Feature-enabled call returns typed `NotImplemented`; later real backend needs integration coverage against Nyx/QEMU and documented host prerequisites. | Small fix: fast coding model. Real backend: specialist Rust/virtualization engineer; estimate separately. | Panic fixed; backend remains open. |
| P1 | Prevent the software replay adapter from deadlocking on verbose children and guarantee temporary input cleanup. | Pipe buffering could report a false hang; timestamp-derived input names were predictable. | Large-stdout fixture passes; secure temporary input is removed; in-memory capture is capped at 1 MiB. | Fast coding model; small isolated Rust change. | Fixed and tested. |
| P1 | Prevent cleanup and compaction from traversing symlinked workdir descendants. | `crates/cli/src/auto/storage.rs` and `crates/cli/src/clean.rs` previously followed symlinked ancestors while finding nested caches or `auto/findings.csv`. | Temporary-directory tests preserve sentinels behind symlinked ancestors. Cache compaction, explicit work-root aliases, and leaf-symlink unlinking remain covered. | Fast coding model; isolated filesystem boundary fix. | Fixed and tested. |
| P1 | Isolate filesystem-sensitive tests from global `/tmp` state. | `crates/cli/src/auto/report.rs::failed_build_records_unresolved_configure_header_with_remediation` used `/tmp` as a project root, allowing unrelated fixtures to change output. | The test owns a temporary project root for the whole assertion. | Fast coding model; small test-only change. | Fixed and tested. |
| P1 | Refresh `bhf --version` when the current branch ref moves and support Git worktrees. | `crates/cli/build.rs` watched hardcoded `.git/HEAD`, tags, and packed refs but not the loose branch ref; `.git` can also be a file in worktrees. | Build script watches HEAD, active symbolic ref, packed refs, and tags using `git rev-parse --git-path`; rebuilt `bhf --version` reports the current commit. | Fast coding model; small build-script change. | Fixed and rebuilt: version reports `g5528a41-dirty`. |
| P2 | Preserve the deliberate engine boundary in user-facing docs and expose adapter maturity clearly to library consumers. | `docs/site/cli.md` documents that only builtin/AFL++ are accepted; Nyx, LibAFL, and libFuzzer adapters are not integrated into `bhf fuzz`. Nyx software replay has no coverage feedback (`coverage_edges` is empty). | Adapter docs identify software replay as process replay, not snapshot restore or coverage-guided fuzzing; CLI lists only implemented engines. | Fast coding model; doc-only. | CLI boundary documented; review records adapter limit. |
| P2 | Continue resolving high-count, confirmed target-driving gaps rather than treating language count as parity. | `docs/expected-gaps.md`: C opaque types (86), C++ non-self-contained headers (49 report-only), Go undrivable types (58), Rust no native byte decoder (42). | Each fix has representative fixtures and moves the correct outcomes to built-and-fuzzed while preserving dependency/environment/design classifications. | Assign to lane owners; fast model for bounded cases, specialist Rust/C++ model for semantic/codegen changes. | Open; separate lane work. |
| P3 | Keep roadmap completion claims scoped to dated milestones and documented behavior. | `ROADMAP.md` says §0/M0–M19/§25 are delivered while explicitly leaving §24 continuous improvement. | Claims reference implemented workflows and residual gaps; no blanket all-features-complete wording. | Maintainer/editor; small review. | Open review recommendation. |

## Scope classification

Intentional limits include: the manual command lane differences recorded in
`ROADMAP.md`'s implementation snapshot; no real ORB requirement; unavailable
third-party engine adapters through the CLI; Ada 83 report-only behavior; and
toolchain/dependency absence. These are support boundaries, not missing promised
behavior, as long as current docs remain explicit.

Promised behavior should be considered missing when an advertised lane cannot
execute its documented workflow or reports success without the stated result.
The `nyx-engine` panic was a defect for consumers who enabled that exposed
feature and now returns `NotImplemented`. The software replay backend is a
limited adapter scaffold: it launches
a target with a file path, has no snapshot restore and no coverage feedback, so
it must not be represented as production Nyx fuzzing. Its stdout is captured in
a temporary file to avoid pipe deadlocks; the in-memory result is capped at 1 MiB,
while the temporary file can still grow until the target exits or times out.

The largest remaining product gaps are target-class limitations, not the count
of language labels: the residual sweep inventory in `docs/expected-gaps.md`
contains both actionable harness/build gaps and honest dependency/environment
refusals. Its verdict labels should be preserved when promoting items into work.

## Cleanup boundary policy

For `bhf clean` and automatic cache compaction, the user-selected work directory
is the explicit trust root and may itself be a symlink alias. No descendant
directory is followed while locating nested owned artifacts. A symlink at the
artifact leaf is unlinked as a leaf; its target is left untouched. This keeps
explicit work-root aliases usable while preventing a nested `auto/` or harness
symlink from redirecting deletion outside that root.

These checks cover static symlink layouts. They do not make path-based deletion
race-free against a concurrent process swapping an ancestor after metadata
validation; that stronger guarantee would require directory-handle-relative
operations.

## Validation completed

- `cargo test -p fuzz_engine_nyx_adapter --locked` — 6 passed.
- `cargo test -p fuzz_engine_nyx_adapter --features nyx-engine` — 3 passed.
- `cargo test -p bhf --lib clean::tests` — 7 passed.
- `cargo test -p bhf --lib auto::storage::tests` — 4 passed.
- `cargo test -p bhf --lib auto::report::tests::failed_build_records_unresolved_configure_header_with_remediation` — 1 passed.
- `cargo build -p bhf --locked` — passed; `target/debug/bhf --version` reported
  `bhf 0.2.32-15-g5528a41-dirty`, matching `git rev-parse --short HEAD` (`5528a41`).
- `git diff --check` — passed.
