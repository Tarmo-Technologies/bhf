<!-- SPDX-License-Identifier: Apache-2.0 -->
# Run bhf on every pull request

For BHF distribution validation, the explicitly dispatched **Container release
candidate** workflow has a `language_matrix` option. It runs the all-language,
sixteen single-language, and three mixed-image construction matrix with benign
BHF-owned `bhf auto` controls. Requested matrix failures block candidate packaging;
short functional controls do not establish upstream qualification. See the
[Docker selection guide](docker.md#installation-selection-versus-run-selection)
for local execution, evidence retention, and resumption.

`bhf ci` fuzzes only the code a pull request changes and reports the results
where reviewers already are: inline annotations on the changed lines and a single
summary comment. The GitHub Action wraps it so the whole thing is one `uses:` line
with no config file.

## Quick start

Copy this to `.github/workflows/bhf-pr.yml`:

```yaml
name: bhf PR
on: pull_request
permissions:
  contents: read
  pull-requests: write   # sticky summary comment
  security-events: write # SARIF upload → code-scanning annotations
jobs:
  bhf:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # required so merge-base against the PR base resolves
      - uses: Tarmo-Technologies/bhf/.github/actions/bhf-pr@main
        with:
          path: .
          campaign-time: "180"
```

On the next PR you get: the run scoped to the diff, SARIF uploaded to the
code-scanning tab (inline annotations in the **Files changed** tab), a sticky
summary comment, and a check that fails only when the PR introduces a
fuzz-confirmed finding.

## What the action does

1. **Resolves the base ref** — the PR base commit (via `merge-base`, so a branch
   behind its base does not re-fuzz the base's own changes), or the repo default
   branch on `push`. Override with `base-ref`.
2. **Installs bhf** — downloads the release binary for the runner, falling
   back to a source build.
3. **Runs `bhf ci --changed-since <base>`** — discovery still walks the tree,
   but only the changed files' targets are built and fuzzed, and the discovery
   cache is reused across runs so repeat PR runs are fast.
4. **Uploads SARIF** to code-scanning for inline annotations.
5. **Posts a sticky summary comment** (one comment, updated in place), which
   links `results/INDEX.md` for the full findings index.
6. **Enforces the gate** — see below.

With `corpus-cache` on (the default), the action restores the newest cache of
the PR's branch, else of its base branch, into the work dir before the run: the
corpus each harness grew (`corpus/`), the discovery cache, and the findings
the last run stored, which `bhf ci` replays first as
[regressions](#regression-replay). The log and the job summary say how many
inputs and findings were restored. It saves them after the run, whatever the
verdict, under a key of its own (a cache key cannot be overwritten), so each
run continues the last one.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `mode` | `pr` | `pr` \| `batch` \| `prune` \| `coverage` — see [Modes](#modes). |
| `path` | `.` | Source root to scan. |
| `base-ref` | *(auto)* | Git ref to diff against. Default: PR base / default branch. |
| `languages` | *(all)* | Comma list to restrict any of the sixteen lanes (`ada,c,cpp,rust,java,python,perl,go,cobol,fortran,csharp,javascript,typescript,ruby,lua,php`). |
| `campaign-time` | `180` | Whole-run wall-clock budget (seconds). |
| `per-target-time` | `30` | Per-target fuzz budget (seconds). |
| `pr-gate` | `confirmed` | `confirmed` \| `all` \| `never` — when to fail the check. |
| `comment` | `true` | Post/update the sticky PR summary comment. |
| `upload-sarif` | `true` | Upload SARIF to the code-scanning tab. |
| `version` | `latest` | bhf release tag to install. |
| `build-from-source` | `false` | Install from source (`cargo install --git`) instead. |
| `corpus-cache` | `true` | Restore the work dir's corpus, discovery cache and stored findings from the Actions cache before the run, and save them after it. |
| `corpus-dir` | `$RUNNER_TEMP/bhf_work` | The work dir bhf runs in and the cache keeps. |

## Modes

| Mode | What it runs |
|---|---|
| `pr` (default) | `bhf ci --changed-since <base>`: the changed code's targets, with the gate. |
| `batch` | `bhf ci` over the whole tree, with the gate: every target's corpus grows. |
| `prune` | A one-second `bhf auto` builds the harnesses again, then `bhf corpus minimize` keeps the inputs of each corpus that add coverage. The log and the job summary give the counts before and after. |
| `coverage` | `bhf auto` for `per-target-time`, which replays each corpus through a source-coverage build: the run's line coverage in the job summary, and `results/coverage/` uploaded as an artifact. |

`batch`, `prune` and `coverage` belong on a schedule. They share the corpus
cache with the PR runs, so the corpus a PR check restores is the one the
scheduled runs grew and pruned. `.github/workflows/bhf-scheduled.example.yml`
runs the three in turn each week, and any one by hand.

## Gate policy

`pr-gate` decides when the check fails:

| Value | Fails the PR when… |
|---|---|
| `confirmed` (default) | a **fuzz-confirmed** finding (actionability verdict `real` or `likely`) is present in the changed code. |
| `all` | any finding is present (including static-only / low-confidence). |
| `never` | never — annotate-only mode. |

The default is deliberately quiet: a static-only or lab-only signal annotates the
PR but does not block it, so the gate flags introduced defects rather than
pre-existing noise.

## Regression replay

Before a run is judged, `bhf ci` replays the findings an earlier run stored
against this run's build of their harness: a finding that still reproduces
fails the gate (unless `pr-gate` is `never`), and one that no longer does is
reported fixed and passes. They are a work dir's `regressions/` directory and
each `--regressions <DIR>` (a directory of finding directories, as
`results/findings/` holds them).

A work dir restored from a CI cache still holds its last run's findings in
`results/findings/`. They move to `regressions/` before the run, one per root
cause, so they are checked as regressions instead of being counted again as
this run's findings. Their minimized inputs (`min_testcase.bin`, else
`testcase.bin`) also seed the run, so the engines run them first. The summary
gives the counts, and `--ci-json` has `regressions` with the ids that
`reproduced`, were `fixed`, or could not be replayed (`unverified`).

## Requirements

- **`fetch-depth: 0`** on `actions/checkout` — a shallow clone has no merge-base
  and the action will error rather than silently fuzzing the whole tree.
- **Code-scanning** for inline annotations: free on public repositories; private
  repositories need GitHub Advanced Security. Without it, set `upload-sarif:
  false` and rely on the summary comment (the SARIF file is still produced).
- **Permissions**: `pull-requests: write` (comment) and `security-events: write`
  (SARIF). `contents: read` is enough for the checkout.
- **Toolchains**: the runner needs the compiler for each language you fuzz (e.g.
  `clang`/`make` for C/C++). Missing toolchains skip that lane rather than failing.

## Make it a required check

In **Settings → Branches → Branch protection**, add the `bhf` job as a
required status check so a PR cannot merge while it introduces a confirmed finding.

## Using the CLI directly (non-GitHub CI)

The Action is a thin wrapper; the CLI works in any CI:

```sh
bhf ci . \
  --changed-since origin/main \
  --campaign-time 180 \
  --sarif bhf.sarif \
  --ci-json bhf-ci.json \
  --pr-gate confirmed \
  --work-dir "$RUNNER_TEMP/bhf_work"
```

- `--changed-since <ref>` scopes to the diff (`<merge-base>..HEAD`).
- `--changed-paths-from <file>` uses a precomputed newline-separated file list
  instead of asking git.
- `--sarif <path>` copies `results/findings.sarif` (SARIF 2.1.0) to `<path>`.
  Every result carries a location, since code scanning drops one without: a
  finding with no crash frame (a format-string, memory-limit or deadline
  oracle) points at the fuzzed function's line, or at the source root when
  that is unknown. `--ci-json <path>` writes a compact machine-readable result (counts by
  severity/verdict, confirmed count, scoped file count, and the
  [regression replay](#regression-replay)'s ids) for your own reporting.
- `--regressions <DIR>` replays the stored findings in `<DIR>` as well as the
  work dir's own (repeatable).
- Exit code is `0` unless the gate fails.

## LLM and agent use in CI

BHF does not require or call an LLM in CI. Keep PR gates deterministic:
gate on BHF exit status, actionability, replay, and SARIF/JSON fields—not on
a model's wording or severity guess. `bhf llm prompt` can render a bounded,
provider-free triage prompt as a separate artifact; `llm assist` makes a remote
or local provider request and should remain a non-gating, explicitly configured
step.

If a CI agent summarizes findings, give it the normalized finding and bounded
run metadata rather than the checkout or full logs. Review artifacts for target
credentials and private source before sending them to a cloud or authenticated
CLI provider, inject provider keys through the CI secret store, and do not write
key values into arguments, workflow YAML, caches, or uploaded prompts. See
[LLM Assistance](./llm.md) for the exact provider and MCP boundaries.

## Scope of a passing check

A diff-scoped run fuzzes only the changed files' targets under a bounded time
budget. A green check means "no confirmed finding was introduced in the changed
code within the budget" — **not** that the code is safe. Raise `campaign-time` for
deeper runs, and run a full `bhf auto` sweep periodically (e.g. nightly)
alongside the per-PR gate.

## Future work

Baseline delta (fuzz the base ref and the head ref, then report only *newly
introduced* findings) is planned. Today, diff-scoping already restricts findings
to changed code, which covers the common case.
