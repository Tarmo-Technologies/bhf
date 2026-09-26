<!-- SPDX-License-Identifier: Apache-2.0 -->
# Campaign comparison and carried-forward triage

`bhf report` can compare its current results with a saved native BHF report,
retain operator decisions, and produce a standalone HTML view that works offline.
This is a reporting feature: it does not execute targets, rerun findings, suppress
raw results, or add a release gate.

## Compare two campaigns

First save a baseline report using the normal command:

```sh
bhf report --findings work-before/findings --out reports-before --run before
```

The command prints `REPORT ... json=<path>`. Use that native JSON file as the
baseline for a later report (replace `BASELINE_JSON` with the printed path):

```sh
bhf report --findings work-after/findings --out reports-after --run after \
  --baseline BASELINE_JSON --sarif --csv --junit
```

Alongside the unchanged native JSON/Markdown and any requested SARIF/CSV/JUnit
files, the command writes three comparison files using the current report stem:

- `<stem>.comparison.json`: structured counts, issue identities, before/after
  severity and member IDs, triage decisions, warnings, and unmatched triage keys.
- `<stem>.comparison.md`: a concise comparison table.
- `<stem>.comparison.html`: an offline, expandable issue view with no JavaScript,
  external resources, server, browser storage, or uploaded data.

`COMPARISON <path>` lines identify these outputs. Open the HTML file directly in
a browser. Report content can contain sensitive project identifiers and triage
notes; offline rendering is not permission to distribute it externally.

## What changes mean

`new` means an issue identity occurs only in the current report. `persistent`
means it occurs in both. `not_observed` means it occurs only in the baseline.
**Not observed does not mean fixed, unreachable, or unaffected.** Campaigns can
have different coverage, budgets, configurations, and source versions. This
feature does not prove scope equivalence or validate raw finding truth.

Counts are per comparison identity, not per raw crash. Each entry retains the
sorted member finding IDs from both reports so duplicate occurrences are not
lost. Known severities are ranked critical, high, medium, low, info; informational
and note normalize to info. An unknown severity is not silently converted into a
low rank. Incomparable changes are flagged for review rather than presented as a
proven improvement.

The highest known severity among grouped members is used, unless a member has
unknown severity, in which case the group remains unknown. `severity_increased`
is null when the comparison cannot rank both sides. Its summary count includes
only proven rank increases.

## Identity and its limits

A versioned SHA-256 key is computed from the strongest available matching signal
plus rule ID, classification, and logical target name. A full, non-fallback
cluster key is preferred; otherwise the exact recorded signature is used. The
algorithm never assumes that equal run-local finding IDs identify the same issue.
Without a full cluster key or signature, entries are deliberately kept separate
across the two runs and cannot carry triage decisions. Those limitations are
included in the outputs.

These keys identify matching recorded evidence, not a mathematically proven
shared root cause. Changing the rule, classification, target name, signature, or
clustering algorithm can produce a new key and stale decisions. There is no
fuzzy matching across renamed symbols or changed signatures. Different or
missing source roots generate an explicit warning; the operator must confirm
that reports and triage belong to the intended project.

The input format is `bhf.report.v2`; arbitrary SARIF or other scanner JSON is not
accepted as a baseline by this version. Existing formats remain available as
ordinary exports, and their schemas and grouping are unchanged.

## Carry manual decisions

Keep a project-specific, version-controlled triage file with schema
`bhf.triage.v1`. Copy an actual `issue_key` from the comparison JSON; the literal
placeholder below must be replaced before use:

```json
{
  "schema_version": "bhf.triage.v1",
  "decisions": [
    {
      "issue_key": "COPY_ACTUAL_COMPARISON_ISSUE_KEY_HERE",
      "status": "investigating",
      "owner": "software-assurance-team",
      "reason": "Review tracked in internal ticket 42."
    }
  ]
}
```

Then add `--triage project-triage.json` to the command with `--baseline`.
Supported statuses are `open`, `investigating`, `accepted_risk`, `false_positive`,
and `fixed`. Each entry requires a unique valid key, a nonempty owner, and a
nonempty reason. Unknown fields and statuses are rejected instead of silently
ignored. The triage input is never rewritten by the command.

An observed issue with an operator `fixed` decision is displayed as `reopened`;
the original decision remains in the evidence. Open/investigating issues remain
in the review queue. A severity increase or incomparable severity change also
requires review even when an accepted-risk or false-positive decision exists.
Unchanged accepted-risk/false-positive decisions are carried forward without a
new review requirement. None of these statuses deletes or suppresses the native
finding, changes VEX, alters actionability, or makes the comparison process exit
with failure merely because issues exist.

Decisions that do not match either report, including unsafe run-local fallback
keys, appear in `unmatched_triage_keys`. They are not treated as successful
suppressions. Decisions are operator input, not authenticated approval; maintain
review history and access controls around the triage file externally.

## Compatibility and failure behavior

Existing `bhf report` calls without `--baseline` behave as before. The baseline
and optional triage are validated before current output generation. A rolling
baseline may use the same path as the current native JSON: the baseline is read
before the existing writer replaces that path. Preserve separate baseline files
when historical source artifacts are required.

Each input is limited to 64 MiB, with at most 100,000 findings/decisions. Report
finding counts, unique nonempty IDs, and the required schema are checked.
Special files and leaf symlinks are rejected; Unix reads additionally use
non-following, nonblocking opens. This is not a sandbox against someone who
controls parent directories or the report-generation workspace.

The three comparison files are individually atomically replaced; the set is not
transactional. A write error can leave a partial set, and ordinary reports may
already have been generated before a comparison-output error. Only consume a
new set after the command exits successfully. The JSON is the authoritative
comparison observation. HTML and Markdown escape supplied content; the HTML
uses a restrictive content security policy and no active report links.

## Tests

```sh
cargo test --locked -p bhf --lib report::comparison
cargo test --locked -p bhf --test report_comparison_cli
```

There are 26 model/renderer/file tests (one Unix-only) and 10 native CLI tests.
CLI tests generate real reports from inert local fixture records; they do not
run a fuzzing target or reproduce a vulnerability. The focused workflow runs on
Ubuntu and Windows separately from the long workspace suite. Its existence does
not assert that either platform test has passed; use the actual run for the
published revision. Full workspace and embedded-platform qualification remain
separate from this reporting feature.
