<!-- SPDX-License-Identifier: Apache-2.0 -->

# SPDX Manifest

`manifest.json` lists every auditable file in the repository with the SPDX license identifier found in its first ten lines. Auditable files are the Rust, C, Ada (`.ada`, `.adb`, `.ads`, `.gpr`), TOML, YAML and Tera sources, the Markdown files under `docs/` and `SPDX/`, and `THIRD_PARTY.md`. The scan skips `vendor/`, `Cargo.lock`, `.git/` and generated output such as `target/`, `bhf_work/`, `dist/` and `benchmarks/engine-comparison/results/`.

Run these from the repository root:

| Command | Effect |
|---|---|
| `cargo run -p spdx_check -- check` | Prints each auditable file that has no SPDX identifier and exits non-zero if there is one. |
| `cargo run -p spdx_check -- generate` | Rewrites `SPDX/manifest.json`. It fails on the first auditable file without an identifier. |
