<!-- SPDX-License-Identifier: Apache-2.0 -->

# Differential Fuzzing

BHF ships a `bhf differential` subcommand: it replays each input
through two already-built harness executables (or one harness under a metamorphic
transform) and flags behavioural divergences. Inside a fuzz campaign, `bhf fuzz
--differential-harness` runs every input through two builds and makes their
disagreement a finding ([In the fuzz loop](#in-the-fuzz-loop)). It is language-agnostic — the
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

## In the fuzz loop

`bhf fuzz --differential-harness <PATH>` makes divergence a finding of the
builtin engine's own campaign rather than of a replay afterwards: every input
the loop runs (each seed and mutant) runs through the fuzzed harness and
through a second build of it, so the search reaches inputs the primary
build's corpus never would.

```sh
# the same harness built twice: the fuzzed build and gcc's
make -C bhf_work/harnesses/H-X diff DIFF_CC=gcc
bhf fuzz bhf_work --harness H-X --time 5m   --differential-harness bhf_work/harnesses/H-X/main_diff
```

The second build is any executable linked with bhf's driver
(`c_runtime/bhf_driver.c`): another compiler, other flags or defines, or
another version of the target. It runs on a fork-server of its own, with its
own coverage maps; an input that grows either build's coverage is kept, so
the campaign explores both. Its persistent process stays in step with the
fuzzed build's, so that a target that keeps state from one input to the next
(a counter, a cache, an allocator) holds the same state in both when they are
compared: it also runs every input the fuzzed build's process runs outside the
comparison (the CmpLog and colorization probes, the calibration re-runs of a
new corpus entry), and when either process dies (a crash, a hang) or is
restarted, both start over. The two runs of an input are compared on:

- how each ended: clean, rejected (a non-zero exit), crashed (a sanitizer
  report or fatal signal) or hung;
- for two clean runs, what each observed: a hash the driver keeps of the bytes
  the target hands `bhf_diff_observe(ptr, len)`, of the target's return value
  in a bhf-generated harness (an integer, character, enum, boolean or floating
  value; a pointer only as null or not, since two builds' addresses differ;
  a struct not at all), and of `bhf_run_one`'s return value.

A target observes what it computed (a decoded value, a canonical form, a
serialized output) with the driver's hook, declared weak where the target is
also built without bhf's driver:

```c
extern void bhf_diff_observe(const void *data, size_t len) __attribute__((weak));
/* ... */
if (bhf_diff_observe) bhf_diff_observe(out, out_len);
```

An input on which the builds disagree is re-run in a fresh process of each,
with twice the per-input timeout, so that a build that is only slower than
`--timeout` (an `-O0` or MemorySanitizer build) is not taken to hang: the rule
the fuzzed build's own hangs follow. When they disagree there, each is re-run
once more, and the disagreement holds only when each build does what it did
the first time: a build whose observation changes from one process to the
next (it observes an address, the time or a random value) is
nondeterministic, not divergent. A disagreement that holds is a BHF-301
finding through the usual fuzz findings pipeline (`classification:
oracle_hit`, oracle `differential-output-runtime`, whose `stdout_equal`
evidence here stands for the observations), one per kind of disagreement (the
observations, or each pair of outcomes and crash kinds, against one second
build), at most 16 per run. A later run on the work dir that finds a kind of
disagreement already recorded for the harness does not record it again: it
lists that finding in the run summary's `duplicates_of_existing`, as it does a
crash it found before. The finding's `differential` block records `mode:
in_loop`, both builds (`harness_a`, `harness_b`), `divergence` (`outcome` or
`observation`), each build's `outcome_a`/`outcome_b` and
`observation_a`/`observation_b` (`{hash, observations}`, or `null` for a run
that did not return), `report_a`/`report_b` (`{kind, rule_id}`) for a build
that crashed, whose sanitizer report is the finding's `sanitizer.log`,
`confirmed: fresh_process`, and `timeout_ms`, the timeout the fresh-process
runs had.

The run summary's `differential` block gives the second build (`harness`),
its `executions`, the `divergences` seen in the loop, and what became of
each: `confirmed` (it held in fresh processes), `unconfirmed` (the builds
agreed there: the difference depended on what ran before), `nondeterministic`
(a build disagreed with itself) or `not_rerun` (its kind of disagreement was
recorded already, the run has its 16 findings, or four re-runs of that kind
did not hold, past which a kind is only counted); the four add up to
`divergences`. `findings` counts the BHF-301 findings recorded.

`bhf replay` of an in-loop divergence runs its input through both builds, each
in a fresh process with the finding's `timeout_ms`, and reports `MATCH` (exit
`0`) when they disagree the way the finding records and each run ends as
recorded, and `MISMATCH` (exit `3`) with what differs otherwise. The replay
summary's `lane` is `differential`, with both builds and what each did. When
the second build is no longer at `harness_b`, the replay cannot tell and
reports `UNVERIFIED` (exit `4`), naming the missing build. `--harness` names
the fuzzed build; the second build is always the one the finding records.

The second build runs only in the builtin engine's single-worker loop:
`--differential-harness` with another `--engine`, `--workers`, a sanitizer
matrix, `--target-transport` or `--protocol-profile` is refused (exit `2`), as
is a fuzzed harness that does not speak bhf's framed protocol (exit `3`).

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
