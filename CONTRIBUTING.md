<!-- SPDX-License-Identifier: Apache-2.0 -->
# Contributing to bhf

This guide covers how to build, test, and submit changes. By contributing you
agree that your contributions are licensed under the project's
[Apache-2.0](./LICENSE) license.

## Development setup

bhf is a Rust workspace of about 60 crates under `crates/`. You need Rust 1.88
or newer (`rust-toolchain.toml` pins the version CI uses), plus a **nightly**
toolchain for the Rust fuzzing lane's sanitizer build. Each language lane also
needs its own toolchain: GNAT and GPRbuild for Ada, `clang` and `make` for
C/C++, a JDK for Java, `python3`, `perl` or `go` for those lanes. See
[From source](./README.md#from-source) and the per-language guides
under [`docs/site/`](./docs/site/index.md); install only the lanes you work on.

A test that needs a missing toolchain skips itself, so a run on a partial
toolchain covers only the lanes you have installed. With `BHF_REQUIRE_TOOLS=1`
a test fails instead of skipping when a tool it needs is missing (a compiler,
GNAT, a JDK, node, ...) or when the runtrace shim is not built beside the
`bhf` under test (`cargo build -p bhf_runtrace_shim`). The nightly integration
suite sets it. Every tool check in `crates/cli/tests/` goes through
`support::require_tool` (`crates/cli/tests/support/mod.rs`).

```sh
cargo build --workspace     # also produces libbhf_runtrace_shim.so next to the binaries
cargo test  --workspace     # full suite
cargo test -p c_parser      # a single crate
cargo test -p bhf --test auto_attempt name_substring   # a single test
```

## Before you open a PR

Run these first:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets    # a deny-level lint fails CI
cargo run -p spdx_check -- generate       # update SPDX/manifest.json after adding/removing files
```

CI runs clippy on Linux and Windows; the Windows job also fails on any
warning (`-D warnings`). The License Audit workflow runs `cargo deny check`,
`spdx_check -- check`, and `spdx_check -- generate` followed by a diff of
`SPDX/manifest.json`.

- **SPDX header on every new file.** Source files start with
  `// SPDX-License-Identifier: Apache-2.0` (or the language's comment form);
  `docs/` and root Markdown use `<!-- SPDX-License-Identifier: Apache-2.0 -->`.
  After adding or removing any tracked file, re-run `spdx_check -- generate`.
  The License Audit workflow fails on a file missing from
  `SPDX/manifest.json`; [SPDX/README.md](./SPDX/README.md) lists which files
  it audits.
- **Dependencies are license-gated.** The permissive core profile may link only
  Apache-2.0, MIT or BSD code. A new dependency needs an entry in the ROADMAP
  dependency matrix (§1.2) and in `deny.toml` in the same change; `cargo deny`
  and the License Audit workflow enforce this.
- **Codegen changes need a fixture.** Anything emitted into a user's workspace
  (harness source, `.gpr`, Makefiles, stubs) needs a fixture under
  `examples/` or `tests/fixtures/` that shows the emitted source compiles.
- **Write regression tests.** New behavior and bug fixes get a test that
  checks the behavior, not a rubber-stamp assertion.

## Conventions

- Library crates test in-file (`#[cfg(test)]` at the bottom of `src/lib.rs`);
  CLI integration tests live in `crates/cli/tests/` and run the binary or call
  `auto` internals against `tests/fixtures/`. The Ada scanner's acceptance
  corpus has its own layout rules in
  [crates/ada_parser/tests/golden/README.md](./crates/ada_parser/tests/golden/README.md).
- Tests write scratch files under a directory that removes itself, never a
  `temp_dir().join(format!("bhf-..."))` built by hand. Use
  `TestDir::new("name")` from `crates/cli/src/test_support.rs` in the `bhf`
  crate (an integration test includes it with
  `#[path = "../src/test_support.rs"] mod test_support;`), or `tempfile` in
  the other crates. A failing test then leaves nothing behind. Set
  `BHF_KEEP_TEST_DIRS=1` to keep a `TestDir` for inspection; its path is
  printed when the test ends.
- `ROADMAP.md` is the engineering source of truth (dependency matrix,
  milestone criteria); user-facing behavior docs live in
  [`docs/site/`](./docs/site/index.md). Update both when behavior changes. A
  README or docs page that disagrees with the code is a bug.
- Treat all scanned trees, manifests, corpus files, and child-process output
  as **untrusted input**. bhf's threat model is analyzing code you do not
  trust.

## Reporting bugs and security issues

Functional bugs: open a GitHub issue with a minimal reproducer. Security
issues: report them privately as described in [SECURITY.md](./SECURITY.md),
not in a public issue.
