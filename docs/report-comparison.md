<!-- SPDX-License-Identifier: Apache-2.0 -->
# Campaign Comparison and Carried-Forward Triage

`bhf report --baseline` compares the current results with a saved native bhf
report, carries your triage decisions forward, and writes a standalone HTML
view that works offline. The comparison works on saved reports: it reads the
two reports and the triage file and writes new files next to the current
report. It runs no target and leaves the findings themselves unchanged.

## Compare two campaigns

First save a baseline report:

```sh
bhf report --findings work-before/results/findings --out reports-before --run before
```

The command prints `REPORT run=... findings=... json=<path> markdown=<path>`.
Pass that native JSON file as the baseline of a later report (replace
`BASELINE_JSON` with the printed path):

```sh
bhf report --findings work-after/results/findings --out reports-after --run after \
  --baseline BASELINE_JSON --sarif --csv --junit
```

In work-directory mode, `bhf report --work-dir <work> --baseline BASELINE_JSON`
writes the same files under `<work>/results/report/`.

Next to the native JSON and Markdown and any SARIF, CSV or JUnit file you
asked for, the command writes three comparison files named after the current
report:

| File | Contents |
|---|---|
| `<stem>.comparison.json` | Counts, issue identities, severity and member IDs before and after, triage decisions, warnings and unmatched triage keys. This file is the authoritative comparison. |
| `<stem>.comparison.md` | A short comparison table |
| `<stem>.comparison.html` | An expandable issue view for a browser, with no JavaScript, external resources, server, browser storage or uploads |

The command prints a `COMPARISON <path>` line for each file. Open the HTML file
directly in a browser. The files can contain sensitive project identifiers and
triage notes, so handle them like the reports they come from.

## What the states mean

| State | Meaning |
|---|---|
| `new` | The issue identity occurs only in the current report |
| `persistent` | It occurs in both reports |
| `not_observed` | It occurs only in the baseline |

`not_observed` records only that the current report has no matching issue.
Two campaigns can differ in coverage, budget, configuration and source
version, so an issue that was not observed may still be present.

Counts are per comparison identity, not per raw crash. Each entry keeps the
sorted member finding IDs from both reports, so duplicates stay visible.

Severity:

- Known severities rank `critical`, `high`, `medium`, `low`, `info`;
  `informational` and `note` normalize to `info`.
- A group takes the highest known severity among its members. If any member's
  severity is unknown, the group's severity is unknown.
- `severity_increased` is `null` when the two sides cannot both be ranked, and
  its summary count includes only proven rank increases.
- A change that cannot be ranked is flagged for review.

## Issue identity

Each issue gets a versioned SHA-256 key made from the strongest matching
signal available, plus the rule ID, the classification and the logical target
name:

1. a full, non-fallback cluster key when there is one;
2. otherwise the exact recorded signature.

Run-local finding IDs are never used to match issues across reports. An entry
with neither a full cluster key nor a signature is kept separate in each run
and cannot carry a triage decision; the outputs list these entries.

Two entries share a key when their recorded evidence matches; the key says
nothing about a shared root cause. Changing the rule, classification, target
name, signature or clustering algorithm produces a new key, and decisions
under the old key go stale. Renamed symbols and changed signatures are not
matched approximately. When the two reports have different or missing source
roots, the comparison prints a warning; confirm that the reports and the
triage file belong to the same project.

The baseline must be a `bhf.report.v2` report; SARIF and other scanners' JSON
cannot be a baseline. bhf's other export formats are unchanged, in schema and
grouping.

## Carry decisions forward

Keep a project-specific, version-controlled triage file with the schema
`bhf.triage.v1`. Copy a real `issue_key` from the comparison JSON in place of
the placeholder:

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

Then add `--triage project-triage.json` to the command that has `--baseline`
(`--triage` requires `--baseline`).

- Statuses: `open`, `investigating`, `accepted_risk`, `false_positive`,
  `fixed`.
- Each entry needs a unique valid key, a nonempty `owner` and a nonempty
  `reason`. Unknown fields and unknown statuses are errors.
- bhf never rewrites the triage file.

How decisions apply:

| Situation | Result |
|---|---|
| An issue marked `fixed` is observed again | Shown as `reopened`; the original decision stays in the evidence |
| `open` or `investigating` | Stays in the review queue |
| `accepted_risk` or `false_positive`, severity unchanged | Carried forward with no new review |
| `accepted_risk` or `false_positive`, severity increased or not comparable | Needs review again |
| A decision whose key matches neither report, including an unsafe run-local fallback key | Listed in `unmatched_triage_keys` |

Decisions leave the native findings, VEX and actionability unchanged, and the
existence of issues does not change the command's exit status. A decision is
operator input with no authentication; keep review history and access control
for the triage file in your own version control.

## Compatibility and failure behavior

- `bhf report` without `--baseline` behaves as before.
- The baseline and the triage file are validated before any current output is
  written. A rolling baseline can use the same path as the current native
  JSON, because the baseline is read before the writer replaces that path.
  Keep separate baseline files when you need the history.
- Each input is limited to 64 MiB and 100,000 findings or decisions. Finding
  counts, unique nonempty IDs and the schema are checked.
- Special files and leaf symlinks are rejected. On Unix, reads use
  non-following, non-blocking opens. These checks assume that the parent
  directories and the report workspace are trusted.
- Each of the three comparison files is replaced atomically, but the set is
  not written as one transaction. A write error can leave a partial set, and
  the ordinary reports may already be written when a comparison output fails.
  Use a new set only after the command exits successfully.
- The HTML and Markdown escape all supplied content. The HTML has a
  restrictive content security policy and no active links.

## Tests

```sh
cargo test --locked -p bhf --lib report::comparison
cargo test --locked -p bhf --test report_comparison_cli
```

The library tests cover the model, the renderers and the file handling (one
test is Unix-only). The CLI tests generate real reports from inert local
fixture records. The `report-comparison` workflow runs these tests on Ubuntu
and Windows, separately from the workspace suite; check its run for the
revision you use.
