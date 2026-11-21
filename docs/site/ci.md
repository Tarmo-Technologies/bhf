<!-- SPDX-License-Identifier: Apache-2.0 -->
# Run bhf on every pull request

`bhf ci` runs the `bhf auto` pipeline for a CI job. With `--changed-since` it builds and fuzzes only the targets in the files a pull request changes. It writes SARIF for inline annotations on the changed lines and a Markdown summary, and its exit code is the gate. The bhf GitHub Action wraps it in one `uses:` step with no config file.

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

The same workflow is in `.github/workflows/bhf-pr.example.yml`. On the next pull request you get:

- a run scoped to the diff;
- SARIF uploaded to the code-scanning tab, which shows inline annotations in the **Files changed** tab;
- a sticky summary comment;
- a check that fails when the pull request introduces a fuzz-confirmed finding.

## What the action does

1. **Resolves the base ref**: the `base-ref` input, else the PR base commit, else `origin/<default branch>` on `push`. `bhf ci` diffs from the merge-base of that ref and `HEAD`, so a branch behind its base does not re-fuzz the base's own changes.
2. **Installs bhf**: runs the release installer for the `version` tag, and falls back to `cargo install --git` when no release is found or the installer fails.
3. **Runs `bhf ci --changed-since <base>`**: discovery walks the whole tree, but only the changed files' targets are built and fuzzed. The discovery cache is reused across runs.
4. **Uploads SARIF** to code scanning for inline annotations.
5. **Posts a sticky summary comment** (one comment, updated in place) that links `results/INDEX.md`, the full findings index.
6. **Enforces the gate** (see [Gate policy](#gate-policy)).

With `corpus-cache` on (the default), the action restores the newest cache of the PR's branch, else of its base branch, into the work dir before the run. The cache holds the corpus each harness grew (`corpus/`), the discovery cache, and the findings the last run stored, which `bhf ci` replays first as [regressions](#regression-replay). The log and the job summary give the number of inputs and findings restored. After the run the action saves the cache under a new key, whatever the verdict, because a cache key cannot be overwritten. Each run continues the last one.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `mode` | `pr` | `pr` \| `batch` \| `prune` \| `coverage`; see [Modes](#modes). |
| `path` | `.` | Source root to scan. |
| `base-ref` | *(auto)* | Git ref to diff against. Default: the PR base, or the default branch on `push`. |
| `languages` | *(all)* | Comma list restricting the run to some of the sixteen lanes (`ada,c,cpp,rust,java,python,perl,go,cobol,fortran,csharp,javascript,typescript,ruby,lua,php`). |
| `campaign-time` | `180` | Whole-run wall-clock budget (seconds). |
| `per-target-time` | `30` | Per-target fuzz budget (seconds). |
| `pr-gate` | `confirmed` | `confirmed` \| `all` \| `never`: when to fail the check. |
| `comment` | `true` | Post or update the sticky PR summary comment. |
| `upload-sarif` | `true` | Upload SARIF to the code-scanning tab. |
| `version` | `latest` | bhf release tag to install. |
| `build-from-source` | `false` | Install from source (`cargo install --git`) instead. |
| `corpus-cache` | `true` | Restore the work dir's corpus, discovery cache and stored findings from the Actions cache before the run, and save them after it. |
| `corpus-dir` | `$RUNNER_TEMP/bhf_work` | The work dir bhf runs in and the cache keeps. |

The action's outputs are `exit-code` (the `bhf ci` exit code: `0` pass, `1` gate failed) and `ci-json` (the path of the `--ci-json` result).

## Modes

| Mode | What it runs |
|---|---|
| `pr` (default) | `bhf ci --changed-since <base>`: the changed code's targets, with the gate. |
| `batch` | `bhf ci` over the whole tree, with the gate: every target's corpus grows. |
| `prune` | A one-second `bhf auto` rebuilds the harnesses, then `bhf corpus minimize` keeps the inputs of each corpus that add coverage. The log and the job summary give the counts before and after. |
| `coverage` | `bhf auto` for `per-target-time`, which replays each corpus through a source-coverage build. The run's line coverage goes to the job summary, and `results/coverage/` is uploaded as an artifact. |

Run `batch`, `prune` and `coverage` on a schedule. They share the corpus cache with the PR runs, so the corpus a PR check restores is the one the scheduled runs grew and pruned. `.github/workflows/bhf-scheduled.example.yml` runs the three in turn each week, and any one of them by hand.

## Gate policy

`pr-gate` decides when the check fails:

| Value | Fails the PR when… |
|---|---|
| `confirmed` (default) | a **fuzz-confirmed** finding (actionability verdict `real` or `likely`) is present in the changed code. |
| `all` | any finding is present, including static-only and low-confidence ones. |
| `never` | never: the run only annotates. |

With the default, a static-only or lab-only finding annotates the PR without failing the check.

When the changed code has no target bhf can harness, the check passes and the job summary says nothing was fuzzed. When targets were discovered but none was built and fuzzed, the check passes with a warning saying so. A `bhf ci` that errors before it produces a result (a tool or setup failure) fails the check, and the action prints the work dir's diagnostics in the log.

## Regression replay

Before a run is judged, `bhf ci` replays the findings an earlier run stored against this run's build of their harness. A finding that still reproduces fails the gate, unless `pr-gate` is `never`; one that no longer reproduces is reported fixed and passes. The stored findings come from the work dir's `regressions/` directory and from each `--regressions <DIR>` (a directory of finding directories, laid out as `results/findings/` holds them).

A work dir restored from a CI cache still holds its last run's findings in `results/findings/`. Before the run they move to `regressions/`, one per root cause, so they are checked as regressions instead of being counted again as this run's findings. Their minimized inputs (`min_testcase.bin`, else `testcase.bin`) also seed the run, so the engines run them first. The summary gives the counts, and the `--ci-json` result has a `regressions` object listing the ids that `reproduced`, were `fixed`, or could not be replayed (`unverified`).

## Requirements

- **`fetch-depth: 0`** on `actions/checkout`. A shallow clone lacks the base commit, so `bhf ci` cannot compute the changed files and exits `1`.
- **Code scanning** for inline annotations. It is free on public repositories; private repositories need GitHub Advanced Security. Without it, set `upload-sarif: false` and use the summary comment (bhf still writes the SARIF file).
- **Permissions**: `pull-requests: write` (comment) and `security-events: write` (SARIF). `contents: read` is enough for the checkout.
- **Toolchains**: the runner needs the compiler or interpreter for each language you fuzz (for example `clang` and `make` for C/C++). A lane whose toolchain is missing is skipped, and the run summary names it.

## Make it a required check

In **Settings → Branches → Branch protection**, add the `bhf` job as a required status check. A PR that introduces a confirmed finding then cannot merge.

## Use the CLI directly (other CI systems)

The CLI runs in any CI:

```sh
bhf ci . \
  --changed-since origin/main \
  --campaign-time 180 \
  --sarif bhf.sarif \
  --ci-json bhf-ci.json \
  --pr-gate confirmed \
  --work-dir "$RUNNER_TEMP/bhf_work"
```

| Option | Effect |
|---|---|
| `--changed-since <ref>` | Scope the run to the diff `<merge-base>..HEAD`. |
| `--changed-paths-from <file>` | Read a newline-separated changed-file list from a file instead of asking git. Overrides `--changed-since`. |
| `--sarif <path>` | Write the run's SARIF 2.1.0 report to `<path>`. Every result carries a location, because code scanning drops one without: a finding with no crash frame (a format-string, memory-limit or deadline oracle) points at the fuzzed function's line, or at the source root when that is unknown. |
| `--ci-json <path>` | Write a compact JSON result: counts by severity and verdict, the confirmed count, the scoped file count, the exit code, the [regression replay](#regression-replay) ids and each gate's result (`gates`). |
| `--regressions <DIR>` | Replay the stored findings in `<DIR>` as well as the work dir's own. Repeatable. |
| `--gitlab-sast <path>` | Write a [GitLab SAST report](#gitlab-ci) of the run's findings. |
| `--pr-gate <policy>` | `confirmed`, `all` or `never`, as for the action. The CLI default is `off`, which gates on `--fail-on` (severity threshold, default `any`) or `--fail-on-actionability`. |
| `--summary-file <path>` | Append the Markdown summary here. Default: the file `GITHUB_STEP_SUMMARY` names. |
| `--policy <file>` | Gate on a policy-as-code file (`bhf policy validate` checks one) as well. Its `ci` section (`fail_on_severity`, `require_artifacts`, `require_runner_plan`, `require_full_runner_assignment`) is one more gate beside `--pr-gate`, `--fail-on-actionability`, the regression replay and a `--fail-on` the command line gives; its `fail_on_severity` takes the place of the default `--fail-on any`. |

The CLI's `--per-target-time` default is 60 seconds; the action passes 30. `bhf ci` exits `0` when every gate it applied passes and `1` when one fails or when the run errors; the summary names each gate's result. Run `bhf ci --help` for the full option list.

## GitLab CI

`ci/gitlab/bhf.gitlab-ci.yml` is a GitLab CI template that does what the action does. Include it and name a bhf image (built from bhf's Dockerfile and pushed to your registry; see [Docker](docker.md)):

```yaml
include:
  - remote: "https://raw.githubusercontent.com/Tarmo-Technologies/bhf/main/ci/gitlab/bhf.gitlab-ci.yml"
variables:
  BHF_IMAGE: registry.example.com/tools/bhf:latest
```

In a merge request pipeline its `bhf` job runs `bhf ci --changed-since` the target branch, gated by `BHF_PR_GATE`. It writes `gl-sast-report.json`, which `artifacts:reports:sast` hands to the merge request's security widget. The job caches the corpus, the discovery cache and the stored findings, keyed by branch with the default branch as the fallback, so each pipeline continues the corpus and replays the findings as [regressions](#regression-replay). A scheduled pipeline sweeps the whole tree (`BHF_MODE=batch`) without gating. `BHF_PATH`, `BHF_LANGUAGES`, `BHF_CAMPAIGN_TIME` and `BHF_PER_TARGET_TIME` correspond to the action's inputs.

The report uses GitLab's SAST format 15.2.1. Each finding with a source location is one vulnerability. Its primary identifier is the bhf rule, followed by its CWEs; its location is the finding's file and line; its severity is the finding's; its id is the finding's fingerprint, which is stable across pipelines. `bhf ci --gitlab-sast <PATH>` writes the report for a run, and `bhf report --gitlab-sast` writes it to `results/gl-sast-report.json` from a work dir.

## Models and agents in CI

bhf needs no model in CI and makes no model request there. Gate on bhf's exit status, actionability, replay results and the SARIF or JSON fields, which are deterministic. `bhf llm prompt` (in a build with the `llm` feature, see [LLM Assistance](llm.md)) renders a bounded triage prompt as a separate artifact. `bhf llm assist` sends a request to a remote or local provider; keep it a non-gating, explicitly configured step.

If a CI agent summarizes findings, give it the normalized finding and bounded run metadata, not the checkout or full logs. Before sending artifacts to a cloud or authenticated-CLI provider, review them for target credentials and private source. Inject provider keys through the CI secret store, and keep key values out of arguments, workflow YAML, caches and uploaded prompts. See [LLM Assistance](llm.md) for the provider and MCP boundaries.

## What a passing check covers

A diff-scoped run fuzzes the changed files' targets within a time budget. A green check means no confirmed finding appeared in the changed code within that budget. `bhf ci` reports every finding in those targets, including one the base branch already had; it does not fuzz the base ref to subtract them. Raise `campaign-time` for deeper runs, and run a full `bhf auto` sweep on a schedule (for example nightly) beside the per-PR gate.
