<!-- SPDX-License-Identifier: Apache-2.0 -->

# Differential Fuzzing

BHF ships a `bhf differential` subcommand: it replays each input
through two already-built harness executables (or one harness under a metamorphic
transform) and flags behavioural divergences. It is language-agnostic — the
executables can come from any of the sixteen current lanes as long as they obey
the normal one-input harness contract; the language is fixed by the target
source, not by this tool.

Automated comparison *across Ada compilers* — toolchain discovery and
multi-compiler matrix orchestration — remains a v1.1+ research boundary.
BHF does not bundle compilers and does not depend on proprietary or
copyleft-linked compiler libraries in the strict-permissive core profile.

Run it over a directory of inputs:

```sh
# two compilers / two harness builds
bhf differential --harness-a ./harness_a --harness-b ./harness_b \
  --inputs ./corpus --work-dir ./bhf_work

# one harness, metamorphic transforms
bhf differential --harness ./harness \
  --metamorphic-transform append-newline,reorder-json-keys,utf8-bom \
  --inputs ./corpus --work-dir ./bhf_work
```

The CLI compares observable behaviour — stdout bytes and exit code/timeout —
and emits findings on divergence:

- `BHF-301` (differential output divergence) when two harnesses disagree on the
  same input;
- `BHF-307` (metamorphic relation violation) when one harness breaks the
  relation a metamorphic transform declares between an input and its variant.

Each transform declares the relation its variant must keep:

| Transform | Variant | Relation |
| --- | --- | --- |
| `append-newline` | a `\n` after the input | same output: stdout bytes and exit status |
| `trailing-whitespace` | a space and a tab at the end of every line, before its `\r\n` or `\n` | same output |
| `reorder-json-keys` | every JSON object's members in reverse order, every other byte (whitespace, separators, values' spelling) kept | same output |
| `utf8-bom` | a UTF-8 byte order mark (`EF BB BF`) before the input | same exit status; stdout may differ, as a parser that echoes its input echoes the mark |

`--metamorphic-transform` takes several, comma-separated or the flag repeated;
each is applied to every input, the input itself runs once, and each variant
is checked against its own relation. A finding's `metamorphic` block names its
`transform` and `relation`, and the variant is `testcase_transformed.bin`.
A transform that does not apply to an input (no JSON text or no object with two
members for `reorder-json-keys`, a byte order mark already there for
`utf8-bom`) leaves it out, and the summary line counts the variants left out.

Each divergence is written to `<work-dir>/results/findings/F-DIFF-NNNN/` as a
JSON finding with stdout/exit-code previews and oracle metadata, and
`results/` is rebuilt (`--timeout-secs` bounds each side, default 5). A rerun
on the same work dir adds the next free `F-DIFF-` ids and never overwrites
earlier findings. `--out DIR` is a deprecated spelling of `--work-dir DIR`.

The internal `replay_min` library offers a narrower, signature-based path for
control-flow diagnostics:

- each side is tagged with a `CompilerIdentity`;
- `replay_min::run_differential_harnesses` executes the same input through both
  harness runners;
- event streams are reduced to BHF exception signatures;
- differing signature sets produce a serializable `DifferentialMismatch` that
  carries both compiler identities and both signature lists.

The comparison itself is language- and compiler-agnostic; what limits *Ada
compiler* matrices specifically is which compilers users can install and
license:

| Pair | Boundary | Status |
| --- | --- | --- |
| FSF GNAT version A vs FSF GNAT version B | external user-installed subprocesses | Feasible for validation and nightly matrices. |
| FSF GNAT vs AdaCore GNAT Pro | user/customer environment only | Product can compare outputs, but cannot require or redistribute GNAT Pro. |
| FSF GNAT vs another open Ada frontend | external subprocesses | Deferred until another frontend can compile generated harnesses. |
| Compiler libraries or front-end APIs linked into BHF | not allowed in core | Keep behind research-lab boundaries if ever explored. |

The subcommand intentionally starts from built harnesses. Toolchain discovery,
multi-compiler project synthesis, and automated matrix orchestration can layer on
top without changing the comparison contract.
