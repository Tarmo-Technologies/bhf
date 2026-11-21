<!-- SPDX-License-Identifier: Apache-2.0 -->

# Differential Fuzzing

Differential fuzzing runs the same input through two builds of a target, or through one build with a transformed copy of the input, and reports the inputs on which the results disagree. bhf does this in two places:

- `bhf differential` replays a directory of inputs through two built executables, or through one executable under metamorphic transforms.
- `bhf fuzz --differential-harness` runs every input of a fuzz campaign through a second build ([In the fuzz loop](#in-the-fuzz-loop)).

You build each side yourself, with whatever compiler, flags or target version you want to compare. bhf takes the built executables; it does not install or select compilers.

## Replaying a corpus: `bhf differential`

```sh
# two builds of one harness
bhf differential --harness-a ./harness_a --harness-b ./harness_b \
  --inputs ./corpus --work-dir ./bhf_work

# one harness, metamorphic transforms
bhf differential --harness ./harness \
  --metamorphic-transform append-newline,reorder-json-keys,utf8-bom \
  --inputs ./corpus --work-dir ./bhf_work
```

Each executable receives the input file's path as `argv[1]`, with an empty stdin, so it can be a harness from any language lane. bhf compares the stdout bytes and the exit status (or timeout) of the two runs and records:

- `BHF-301` (output divergence) when two harnesses disagree on the same input;
- `BHF-307` (metamorphic relation violation) when one harness breaks the relation a transform declares between an input and its variant.

| Option | Default | Meaning |
|---|---|---|
| `--harness-a`, `--harness-b` | none | The two executables to compare |
| `--harness` | none | The one executable for metamorphic mode |
| `--metamorphic-transform` | none | Transforms to apply; comma-separated or repeated |
| `--inputs` | required | Directory of input files |
| `--work-dir` | `bhf_work` | Where findings are written |
| `--timeout-secs` | `5` | Timeout for each side of each input |

`--out DIR` is a deprecated spelling of `--work-dir DIR`.

### Metamorphic transforms

Each transform declares the relation its variant must keep:

| Transform | Variant | Relation |
| --- | --- | --- |
| `append-newline` | a `\n` after the input | same output: stdout bytes and exit status |
| `trailing-whitespace` | a space and a tab at the end of every line, before its `\r\n` or `\n` | same output |
| `reorder-json-keys` | every JSON object's members in reverse order, every other byte (whitespace, separators, the spelling of values) kept | same output |
| `utf8-bom` | a UTF-8 byte order mark (`EF BB BF`) before the input | same exit status; stdout may differ, because a parser that echoes its input echoes the mark |

The original input runs once, and each selected transform is applied to it and checked against its own relation. A transform skips an input it does not apply to: `reorder-json-keys` needs JSON text with an object of two or more members, and `utf8-bom` needs an input without a byte order mark. The summary line counts the skipped variants.

### Output

Each divergence becomes a JSON finding in `<work-dir>/results/findings/F-DIFF-NNNN/`, with previews of both sides' stdout and exit codes and the oracle metadata. bhf then rebuilds `results/`. A rerun on the same work directory takes the next free `F-DIFF-` ids and keeps earlier findings. In metamorphic mode, the finding's `metamorphic` block names the `transform` and the `relation`, and the variant input is saved as `testcase_transformed.bin`.

## In the fuzz loop

`bhf fuzz --differential-harness <PATH>` makes divergence a finding of the builtin engine's own campaign. Every input the loop runs, seeds and mutants, runs through the fuzzed harness and through the second build. The search can therefore reach inputs that a replay of the primary build's corpus would miss.

```sh
# build the same harness a second time with gcc, then fuzz both
make -C bhf_work/harnesses/H-X diff DIFF_CC=gcc
bhf fuzz bhf_work --harness H-X --time 5m \
  --differential-harness bhf_work/harnesses/H-X/main_diff
```

The second build is any executable linked with bhf's driver (`c_runtime/bhf_driver.c`): another compiler, other flags or defines, or another version of the target. It runs on its own fork server with its own coverage maps. An input that grows either build's coverage is kept, so the campaign explores both.

The second build's process stays in step with the fuzzed build's, so that a target that keeps state between inputs (a counter, a cache, an allocator) holds the same state in both when they are compared. It also runs the inputs the fuzzed build runs outside the comparison (the CmpLog and colorization probes, the calibration re-runs of a new corpus entry). When either process dies (a crash, a hang) or is restarted, both start over.

### What is compared

- How each run ended: clean, rejected (a non-zero exit), crashed (a sanitizer report or fatal signal) or hung.
- For two clean runs, what each observed. The driver keeps a hash of:
  - the bytes the target passes to `bhf_diff_observe(ptr, len)`;
  - the target's return value in a bhf-generated harness (an integer, character, enum, boolean or floating value; a pointer only as null or non-null, because two builds' addresses differ; a struct is not compared);
  - `bhf_run_one`'s return value.

A target reports what it computed (a decoded value, a canonical form, a serialized output) through the driver's hook. Declare the hook weak when the target is also built without bhf's driver:

```c
extern void bhf_diff_observe(const void *data, size_t len) __attribute__((weak));
/* ... */
if (bhf_diff_observe) bhf_diff_observe(out, out_len);
```

### Confirming a divergence

1. An input on which the builds disagree is re-run in a fresh process of each build, with twice the per-input `--timeout`. A build that is only slower than `--timeout` (an `-O0` or MemorySanitizer build) is therefore not reported as a hang. The fuzzed build's own hangs follow the same rule.
2. When they still disagree, each build runs the input once more. The disagreement holds only when each build repeats what it did the first time. A build whose observation changes from one process to the next (it observes an address, the time or a random value) is counted as nondeterministic.

A disagreement that holds is a `BHF-301` finding in the usual fuzz findings pipeline (`classification: oracle_hit`, oracle `differential-output-runtime`; its `stdout_equal` evidence stands for the observations). bhf records one finding per kind of disagreement (the observations, or each pair of outcomes and crash kinds, against one second build), up to 16 per run. A later run on the same work directory that finds a kind already recorded for the harness lists the existing finding in the run summary's `duplicates_of_existing`, as it does for a crash found before.

The finding's `differential` block records:

| Field | Meaning |
|---|---|
| `mode` | `in_loop` |
| `harness_a`, `harness_b` | The fuzzed build and the second build |
| `divergence` | `outcome` or `observation` |
| `outcome_a`, `outcome_b` | How each build's run ended |
| `observation_a`, `observation_b` | `{hash, observations}`, or `null` for a run that did not return |
| `report_a`, `report_b` | `{kind, rule_id}` for a build that crashed; its sanitizer report is the finding's `sanitizer.log` |
| `confirmed` | `fresh_process` |
| `timeout_ms` | The timeout the fresh-process runs used |

The run summary's `differential` block gives the second build (`harness`), its `executions`, the `divergences` seen in the loop, and the `findings` recorded. Each divergence is counted in exactly one of:

| Counter | Meaning |
|---|---|
| `confirmed` | It held in fresh processes |
| `unconfirmed` | The builds agreed in fresh processes; the difference depended on what ran before |
| `nondeterministic` | A build disagreed with itself |
| `not_rerun` | Its kind was already recorded, the run already has 16 findings, or four re-runs of that kind failed to hold (later ones of that kind are only counted) |

### Replaying an in-loop finding

`bhf replay` of an in-loop divergence runs the input through both builds, each in a fresh process with the finding's `timeout_ms`. It reports:

| Verdict | Exit | When |
|---|---|---|
| `MATCH` | `0` | The builds disagree the way the finding records and each run ends as recorded |
| `MISMATCH` | `3` | Anything differs; the output says what |
| `UNVERIFIED` | `4` | The second build is no longer at `harness_b`; the output names the missing build |

The replay summary's `lane` is `differential`, with both builds and what each did. `--harness` names the fuzzed build; the second build is always the one the finding records.

### Requirements

The second build runs in the builtin engine's single-worker loop. `bhf fuzz --differential-harness` exits with code `2` when combined with another `--engine`, `--workers`, a sanitizer matrix (several `--sanitizers`), `--target-transport` or `--protocol-profile`. It exits with code `3` when the fuzzed harness does not speak bhf's framed protocol, that is, when it is not linked with `c_runtime/bhf_driver.c`.

## Comparing Ada compilers

The comparison works the same for any language and compiler. For Ada, each compiler is a user-installed subprocess, and bhf's strict-permissive core profile links no Ada compiler library. You can compare:

- two FSF GNAT versions, by building the harness once with each;
- FSF GNAT against AdaCore GNAT Pro, where you hold a GNAT Pro installation (bhf does not ship or require it);
- any other Ada compiler that can build bhf's generated harness.

## The `replay_min` library

The `replay_min` crate offers a signature-based comparison for control-flow diagnostics:

- each side is tagged with a `CompilerIdentity`;
- `replay_min::run_differential_harnesses` runs the same input through both harness runners;
- each event stream is reduced to bhf exception signatures;
- differing signature sets produce a serializable `DifferentialMismatch` that carries both compiler identities and both signature lists.
