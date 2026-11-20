<!-- SPDX-License-Identifier: Apache-2.0 -->

# Architecture

BHF is an offline fuzzing toolchain for sixteen languages: Ada, C, C++, Rust,
Java, Python, Perl, Go, COBOL, Fortran, C#, JavaScript, TypeScript, Ruby, Lua
and PHP. It targets the legacy and mission-critical code common in government
systems.

The code bhf links is Apache-2.0, MIT or BSD licensed; it never links GPL or
LGPL libraries. bhf runs external tools such as FSF GNAT, GPRbuild, clang,
clang++ and AFL++ as separate processes. Two optional crates build only when
you enable their Cargo feature: `fuzz_engine/libafl_adapter` (feature
`libafl-engine`) and `llm_harness_gen` (feature `llm`). The default build and
the release binaries leave both out.

## Pipeline

1. **Parse** the sources of all sixteen languages with permissively licensed
   parser front ends.
2. **Rank** fuzz targets from subprograms, exception handlers, type
   information and call relationships. See [Target Ranking](target-ranking.md).
3. **Generate** direct-call harnesses and partial-build projects around the
   selected targets, and stub missing headers, types and undefined symbols.
4. **Instrument** the harness build for coverage. For Ada, `bhf instrument`
   also rewrites the source with probe breadcrumbs and testcase boundaries.
5. **Build and run** harnesses on the host, cross-compiled, or under
   qemu-user, optionally inside a sandbox.
6. **Virtualise the runtime** with an `LD_PRELOAD` shim that fakes missing
   files, sockets, environment variables and `dlopen` chains so the harness
   reaches the target code. The shim and its behavioural and taint oracles
   run on native C, C++, Ada, Rust, Go, COBOL and Fortran harnesses, and in
   the Python, Perl, Ruby, Lua and PHP interpreters, where it records from
   the first call into the target. Java, C#, JavaScript and TypeScript use
   their own runtime's coverage and crash signals, and cross-compiled or
   emulated runs (qemu-user, wine) run without the shim. See
   [Runtime Virtualisation](runtime-virtualisation.md).
7. **Normalize findings** into JSON, Markdown, SARIF, JUnit XML, CSV and the
   responses the IDE daemon serves.

`bhf auto` runs steps 1 to 7 in one command. It harnesses and builds Ada, C
and C++ targets inside an iterative repair loop that reads compiler
diagnostics and fixes the build. It prebuilds Rust and Java targets before
that loop, without diagnostic-driven repair, and then fuzzes them the same
way.

The other lanes replace the repair loop with a compile, import or
interpreter smoke test, then run under a persistent interpreter or as a
native binary:

| Lane | Smoke test and runtime |
|---|---|
| Python | `py_compile` |
| Perl | `perl -c` |
| Go | `go build` |
| COBOL | GnuCOBOL `cobc` |
| Fortran | `gfortran` |
| C# | `dotnet` with SharpFuzz |
| JavaScript, TypeScript | a warm Node process; TypeScript compiled with esbuild |
| Ruby, Lua, PHP | their own interpreters |

By default every lane runs bhf's built-in coverage-guided engine over its
framed fork-server protocol. `--engine afl++` drives AFL++ instead for C,
C++, COBOL, Fortran, Rust and Ada targets, and `--engine winafl` drives
WinAFL for C and C++ on native Windows (see `bhf auto --help`).

The individual subcommands expose the pipeline steps for manual use. Their
language scopes differ:

| Command | Languages |
|---|---|
| `bhf scan`, `bhf generate-harness` | Ada, C, C++ |
| `bhf list targets` | Ada, C, C++, Java, Rust |
| `bhf auto` | all sixteen |

Each command's `--help` output is the exact current contract.

## Crate Boundaries

Parsers and rankers:

- `crates/ada_parser`: Ada syntax and source ranges.
- `crates/c_parser`: C syntax, functions, declarations.
- `crates/cpp_parser`: C++ syntax, functions, declarations.
- `crates/{go,java,perl,python,rust}_parser`: front ends for the Go, Java,
  Perl, Python and Rust lanes. The other lanes discover targets with
  tree-sitter or lane-specific parsing in the CLI lane builders.
- `crates/idl_parser`: a CORBA IDL subset.
- `crates/target_rank`: scores candidate fuzz entry points in the supported
  languages.

Harness and project synthesis:

- `crates/harness_gen`: emits Ada, C, C++, Java and Rust harnesses plus
  build-local support files. The other lanes emit their harnesses from the
  CLI lane builders
  (`crates/cli/src/auto/{python,perl,go,cobol,fortran,csharp,js,ruby,lua,php}_build.rs`)
  against the matching `*_runtime/` decode runtimes; Go decodes inline.
- `crates/project_synth`: Ada partial-build `.gpr` generation.
- `crates/stub_gen`: Ada package, identifier and visibility stubs.
- `crates/c_stub_gen`: C placeholder headers, typedef placeholders, and
  declared and blind function stubs.
- `crates/probe_gnat_actions`: opt-in GNAT compiler-action probes.

Build, fuzz and replay:

- `crates/build_classifier`: maps gcc, clang, ld and GNAT diagnostics to the
  `BuildErrorKind` enum that drives repair planning.
- `crates/compiler_adapter`: discovers and invokes the toolchains you have
  installed.
- `crates/instrumenter`: rewrites Ada source for probe events.
- `crates/fuzz_engine/builtin`: the built-in deterministic engine.
- `crates/multicore_fuzz`: runs one target's campaign on several cores.
- `crates/bhf_runtrace_shim`: the `LD_PRELOAD` shim (`libbhf_runtrace_shim.so`)
  that records and fakes the runtime environment around a fuzz target, on
  the lanes listed in step 6 of the pipeline.
- `crates/cmplog`: comparison logs (CmpLog, RedQueen style) turned into
  fuzzing dictionaries.
- `crates/replay_min`: replay and delta-debugging minimization.
- `crates/rehost`: runs an unmodified Cortex-M firmware image from its reset
  vector in bhf's own ARMv7-M Thumb-2 interpreter. The image is an ELF, or a
  raw image at a base address. Each input reaches the firmware through a
  fixed buffer in its memory or through its peripheral reads. Peripheral
  windows come from a CMSIS-SVD file (`svd.rs`, its own XML reader), and
  each register has an MMIO model: passthrough from the input, a constant,
  or a bit-extract. bhf infers the bit-extract model for status-register
  polling loops by probing a recorded trace of the reads. The interpreter
  raises the interrupts the firmware enables on a schedule the input chooses
  (`nvic.rs`) and counts the basic blocks it enters in a 64 KiB edge map.
  `bhf binary rehost` (`crates/cli/src/binary_rehost.rs`) fuzzes with it and
  writes each fault as a finding that `bhf replay` reproduces.

Output and policy:

- `crates/report`: JSON, Markdown, SARIF, JUnit and CSV emitters.
- `crates/results`: the `<work>/results/` directory and its
  `bhf.findings.v1` contract.
- `crates/confidence_model`: calibrated finding confidence.
- `crates/finding_rules`: the finding-class registry (BHF-101 to BHF-571,
  plus BHF-668, covering logic, memory, injection and static classes; list
  them with `bhf rules list`) and the executable-oracle registry that emits
  runtime-confirmed hits (`confirmation: "runtime"`) during fuzzing.
- `crates/static_analysis`: the rules behind `bhf static-scan`.
- `crates/sbom_ingest`: evidence-graded SBOM component ingestion for
  `bhf sbom`.
- `crates/binary_analysis`: offline binary inventory for `bhf binary scan`.
- `crates/governance`: policy, audit log and air-gapped update packs.
- `crates/license_policy`: profile-driven probe and dependency gates.
- `crates/spdx_check`: SPDX metadata audit.

IDE and orchestration:

- `crates/daemon` (binary `bhf-daemon`): a JSON-RPC service for editor
  clients, and a separate read-only MCP stdio mode that returns bounded,
  deterministic evidence. See [Daemon](daemon.md).
- `crates/extension_host`: the host side of the `bhf.extension.v1`
  out-of-process extension protocol. See
  [Extension Protocol](extension-protocol.md).
- `crates/llm_harness_gen` (Cargo feature `llm`): provider-neutral prompt
  preparation, Ada, C and C++ harness-candidate preflight, memory-aware
  capture, and bounded adapters for hosted and OpenAI-compatible model
  providers. Model output is advisory and stays outside the deterministic
  pipeline above. See [LLM and MCP](llm.md).
- `crates/cli`: the `bhf` command-line entry point. Its `auto` module drives
  the full sweep; a build with the `llm` feature adds the `bhf llm` command
  group.

## Docs Site

The Markdown sources live in `docs/site`. `scripts/docs/build-site.py`
renders them to static HTML, which you can build and read offline:

```sh
python3 scripts/docs/build-site.py --out target/docs-site
```

Every heading, `#` to `######`, gets the anchor GitHub gives it, so a link to `auto.md#needed_for_build` works on the site as it does on GitHub. The build fails on a relative link to a Markdown file that does not exist, and on a link to a heading that the target page, or the same page, does not have. A link to a repository file the site does not publish points to that file on GitHub. The build writes canonical links, `sitemap.xml` and a `Sitemap:` line in `robots.txt` only for the host you pass with `--base-url`; the default is no host.

The `Docs Site` workflow builds the site and uploads it as a GitHub Pages
artifact on every push to `main` and every pull request. Its deploy job runs
only when the repository variable `BHF_PAGES_ENABLED` is `true`. Pages is not
enabled for the repository and no domain points at the site, so no public
host serves it.
