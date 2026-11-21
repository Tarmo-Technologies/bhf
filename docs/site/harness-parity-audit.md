<!-- SPDX-License-Identifier: Apache-2.0 -->

# 200-project expert harness parity audit

This audit measures bhf's generated harnesses against real, independently written expert fuzz drivers. It pins 200 projects across all sixteen supported languages (12 or 13 per language). Each run allows the normal backfill of up to ten candidate targets and requires an exact checkpoint just before the selected call, which proves the target was entered. A separate expert set holds one reviewed driver per language at the same project revision. `BHF_BLIND_EXPERT_HARNESSES=1` hides each repository's own fuzz drivers from automatic selection, so they cannot steer bhf's choice.

## Measured result

The durable 200-project rerun completed every row with no interrupted or negative-exit record. In it, 118 selected calls were entered and 105 produced dynamic project coverage, up from 93 body-covered projects in the first pass.

Focused reruns on the final binary then fixed a Go coverage-scope defect (Go body coverage went from 3 to 10 of 13 projects) and a C++ MSBuild context defect. With those two lanes' rerun results substituted into the durable run, the composite is 113/200 body-covered projects. A single run of all 200 projects on one binary gives a single-run figure; the command is in `benchmarks/harness-parity-200/FINDINGS.md`.

Against the expert set, which has one project per language, the final binary entered and dynamically covered the selected endpoint in 16 of 16 projects. bhf selected the same normalized entry point as the expert in 13 of 16 languages, up from 6 of 16 before the audit. The three differences:

- **Rust, zoxide.** The expert calls a private in-package database method that a separate public harness crate cannot reach. The in-crate lane (`bhf auto --rust-private`) now reaches it. In the [rerun on 2026-11-17](../validation/2026-11-17-zoxide-incrate-parity.md), bhf picks the private `Database::deserialize` and, run at the expert's endpoint, drives `Database::open_dir` with its database file.
- **COBOL, webbol.** bhf and the expert pick two different deep surfaces that both work. bhf supports both the file-resource setup and the target entry the expert's choice needs.
- **PHP, Monolog.** bhf and the expert pick different formatters that both work. bhf constructs the typed `LogRecord` object the expert's choice needs.

The blind 30-project C and C++ line comparison ([benchmarks/harness-parity-20/](../../benchmarks/harness-parity-20/ANALYSIS.md)) measures native coverage depth. All 30 pairs were comparable; 19 had no expert-only implementation lines, and 25 had seven or fewer. bhf's harnesses covered 50,340 implementation lines against 48,742 for the experts, with 123 expert-only lines in total. Line counts and entry-point equality are reported separately, because each measures something the other does not.

## Expert techniques bhf now automates

| Technique | Automatic behaviour |
|---|---|
| Execution proof | Every lane checkpoints immediately before the selected call; a run that only decodes or sets up is demoted. |
| Semantic selection | Identifier-token scoring ranks public parsers, decoders, whole-artifact entry points and stateful surfaces first, and ranks debug, report and inspection helpers down. |
| File-backed input | JavaScript, Ruby and COBOL write the fuzz bytes to a file for path and file operands and remove it after the call. JavaScript awaits a returned promise before cleanup. |
| Stateful APIs | Go mines a bounded one-input feeder plus a zero-argument terminal call, including Cobra's `SetArgs` then `Execute`. |
| Typed objects | PHP resolves imports and recursively constructs bounded scalar, array, enum, date and constructor graphs. |
| C++ templates and defaults | Public member templates, defaulted parameters, common rvalue byte strings and default-template aliases produce legal calls. |
| ABI-specific arrays | Fortran assumed-shape character arrays receive the required descriptor and the full input extent. |
| Managed instrumentation | C# compiles project code into a separate target library and instruments only project IL. |
| Coverage fallback | When a module-wide Go coverage build fails, Go retries instrumentation for the selected package before it falls back to black-box fuzzing. |
| Build context | Static MSBuild paths keep resolved project properties and drop unresolved configuration variables rather than inventing include paths. |

## Remaining expert-parity gaps

1. **Build-graph fidelity.** In some large Ada, C++, C#, Fortran, Java and Rust projects, generated files, feature flags, platform SDKs or the full project build graph keep a reduced source closure from building.
2. **Framework bootstrapping.** Missing packages, and code that needs a browser, Neovim, Android or Windows host, account for several unbuilt rows. The audit counts these separately from generator defects.
3. **Structured scientific data.** Fortran scientific APIs need coherent, bounded vectors and matrices with coupled dimensions, leading dimensions and alias and intent constraints. The lane drives character control inputs.
4. **General state and resource sequences.** The Go feeder-then-terminal rule covers one pattern. Mining constructor, setter or feed, parse or execute, and cleanup sequences across the native and managed lanes is open.

The reproducibility kit is in [benchmarks/harness-parity-200/](../../benchmarks/harness-parity-200/README.md): pinned project manifests, one expert harness per language, durable and resumable runners, comparison scripts and the residual classification. The audit records discovery, build, target entry, dynamic body coverage and exact semantic selection as separate results, so a shallow or setup-only run never counts as a covered target.
