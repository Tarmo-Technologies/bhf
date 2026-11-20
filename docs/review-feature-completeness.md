<!-- SPDX-License-Identifier: Apache-2.0 -->
# Feature Completeness Review, 2026-09-24

This review covered the feature promises in the documentation, the documented
residual gaps and the optional fuzz-engine adapters, at baseline `5528a41`.
It is part of the [Production readiness review](production-readiness-review.md).
[`ROADMAP.md`](../ROADMAP.md) §24 lists the continuing work, and
[Measured gaps](expected-gaps.md) separates bhf's own gaps from missing
dependencies, environment limits and deliberate refusals.

## Follow-up items

| Priority | Work item | Evidence | Acceptance | Status |
|---|---|---|---|---|
| P1 | Real Nyx execution, or Nyx kept explicitly unsupported. The `nyx-engine` feature reached `unreachable!()` although `NyxError::NotImplemented` existed. | `crates/fuzz_engine/nyx_adapter/` (since removed) | A feature-enabled call returns the typed `NotImplemented`; a real backend would need integration tests against Nyx/QEMU and documented host prerequisites | The panic was fixed. Nyx was later retired in favor of the full-system transport, and the crate removed |
| P1 | The software replay adapter deadlocked on verbose children and used predictable input names | Pipe buffering could report a false hang; input names derived from timestamps | A large-stdout fixture passes; the secure temporary input is removed; in-memory capture is capped at 1 MiB | Fixed and tested (adapter since removed with the Nyx crate) |
| P1 | Cleanup and compaction followed symlinked work-directory descendants | `crates/cli/src/auto/storage.rs` and `crates/cli/src/clean.rs` followed symlinked ancestors while finding nested caches or `auto/findings.csv` | Temporary-directory tests keep sentinels behind symlinked ancestors; cache compaction, explicit work-root aliases and leaf-symlink unlinking stay covered | Fixed and tested |
| P1 | A filesystem-sensitive test depended on global `/tmp` state | `crates/cli/src/auto/report.rs::failed_build_records_unresolved_configure_header_with_remediation` used `/tmp` as a project root | The test owns a temporary project root for the whole assertion | Fixed and tested |
| P1 | `bhf --version` did not refresh when the branch ref moved, and Git worktrees were not handled | `crates/cli/build.rs` watched `.git/HEAD`, tags and packed refs but not the loose branch ref; in a worktree `.git` is a file | The build script watches HEAD, the active symbolic ref, packed refs and tags through `git rev-parse --git-path`; a rebuilt `bhf --version` reports the current commit | Fixed; the rebuilt binary reported `g5528a41-dirty` |
| P2 | State the engine boundary in the user documentation and the maturity of each adapter for library users | At the time, `bhf fuzz` accepted the builtin engine and AFL++ only, and the Nyx software replay had no coverage feedback (`coverage_edges` empty) | Adapter docs describe software replay as process replay without snapshot restore or coverage guidance; the CLI lists only implemented engines | Done. `bhf fuzz --engine` now also takes `libfuzzer`, `honggfuzz`, `winafl` (native Windows) and `libafl` (a build with the `libafl-engine` feature); see [libFuzzer adapter](libfuzzer-adapter.md) |
| P2 | Keep closing the confirmed high-count target-driving gaps | [Measured gaps](expected-gaps.md): C opaque types (86), C++ non-self-contained headers (49 report-only), Go undrivable types (58), Rust without a native byte decoder (42) | Each fix has representative fixtures and moves the right outcomes to built-and-fuzzed, keeping the dependency, environment and by-design classifications | Ongoing lane work; the C++ headers class is fixed since |
| P3 | Keep roadmap completion claims tied to dated milestones and documented behavior | `ROADMAP.md` lists §0, M0–M19 and §25 as delivered and §24 as continuing | Claims reference implemented workflows and residual gaps | Open |

## Scope classification

These are support boundaries, documented as such:

- the differences between the manual command lanes recorded in `ROADMAP.md`'s
  implementation snapshot;
- CORBA targets are fuzzed without a real ORB;
- third-party engine adapters that the CLI does not offer;
- Ada 83 targets, which are reported and not fuzzed;
- missing toolchains and dependencies.

A promised behavior counts as missing when an advertised lane cannot run its
documented workflow, or reports success without the stated result. The
`nyx-engine` panic was such a defect for anyone who enabled that feature. The
software replay backend launched a target with a file path, with no snapshot
restore and no coverage feedback. It captured stdout in a temporary file to
avoid pipe deadlocks; the in-memory result was capped at 1 MiB, while the
temporary file could grow until the target exited or timed out.

The largest remaining product gaps are target classes. The residual sweep
inventory in [Measured gaps](expected-gaps.md) holds both actionable harness
and build gaps and dependency or environment refusals; keep its verdict labels
when an item becomes work.

## Cleanup boundary policy

For `bhf clean` and automatic cache compaction, the work directory you select
is the trust root, and it may itself be a symlink. No descendant directory is
followed while bhf locates nested artifacts it owns. A symlink at the artifact
leaf is unlinked as a leaf, and its target is left alone. Work-root aliases
therefore keep working, and a nested `auto/` or harness symlink cannot
redirect a deletion outside the root.

These checks cover symlink layouts that exist before the command runs. A
concurrent process that swaps an ancestor after the metadata check is outside
them; closing that race needs directory-handle-relative operations.

## Validation

- `cargo test -p fuzz_engine_nyx_adapter --locked` and
  `cargo test -p fuzz_engine_nyx_adapter --features nyx-engine`: passed (the
  crate has since been removed).
- `cargo test -p bhf --lib clean::tests`: passed.
- `cargo test -p bhf --lib auto::storage::tests`: passed.
- `cargo test -p bhf --lib auto::report::tests::failed_build_records_unresolved_configure_header_with_remediation`:
  passed.
- `cargo build -p bhf --locked`: passed; `target/debug/bhf --version` reported
  `bhf 0.2.32-15-g5528a41-dirty`, matching `git rev-parse --short HEAD`
  (`5528a41`).
- `git diff --check`: passed.
