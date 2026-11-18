#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run bhf for the bhf-pr action: `bhf ci` scoped to the PR's changes, in a
# work dir a cache may have restored (#317).
#
# Inputs (environment): INPUT_PATH, INPUT_LANGUAGES, INPUT_CAMPAIGN_TIME,
# INPUT_PER_TARGET_TIME, INPUT_PR_GATE, BASE_REF, BHF_WORK_DIR, and
# RUNNER_TEMP, GITHUB_OUTPUT and GITHUB_STEP_SUMMARY as Actions sets them.
# Outputs: exit, sarif, ci_json and has_sarif in GITHUB_OUTPUT.
set -uo pipefail

work="${BHF_WORK_DIR:?BHF_WORK_DIR is the work dir}"
sarif="$RUNNER_TEMP/bhf.sarif"
ci_json="$RUNNER_TEMP/bhf-ci.json"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"

# What a cache restored: the corpus each harness grew, and the findings the
# last run stored, which `bhf ci` replays as regressions.
inputs=0
corpora=0
shopt -s nullglob
for queue in "$work"/corpus/*/queue; do
  files=("$queue"/*)
  if (( ${#files[@]} > 0 )); then
    inputs=$((inputs + ${#files[@]}))
    corpora=$((corpora + 1))
  fi
done
stored=("$work"/regressions/*/ "$work"/results/findings/*/)
shopt -u nullglob
if (( inputs > 0 || ${#stored[@]} > 0 )); then
  echo "bhf: restored corpus: $inputs input(s) in $corpora harness corpora, ${#stored[@]} stored finding(s)"
  echo "> **bhf**: restored corpus: $inputs input(s) in $corpora harness corpora, ${#stored[@]} stored finding(s)." >> "$summary"
else
  echo "bhf: no restored corpus; this run starts from the seeds"
fi

if ! bhf ci --help 2>/dev/null | grep -q -- '--changed-since'; then
  echo "::error title=bhf::the installed bhf does not support 'ci --changed-since' — pin 'version:' to a release that ships it, or set 'build-from-source: true'"
  exit 1
fi
lang_arg=()
if [[ -n "${INPUT_LANGUAGES:-}" ]]; then
  lang_arg=(--languages "$INPUT_LANGUAGES")
fi
# The work dir lives outside the checkout so discovery never scans it.
bhf ci "${INPUT_PATH:-.}" \
  --changed-since "${BASE_REF:?BASE_REF is the ref to diff against}" \
  --campaign-time "${INPUT_CAMPAIGN_TIME:-180}" \
  --per-target-time "${INPUT_PER_TARGET_TIME:-30}" \
  "${lang_arg[@]}" \
  --pr-gate "${INPUT_PR_GATE:-confirmed}" \
  --sarif "$sarif" \
  --ci-json "$ci_json" \
  --work-dir "$work"
code=$?
echo "exit=$code" >> "$GITHUB_OUTPUT"
echo "sarif=$sarif" >> "$GITHUB_OUTPUT"
echo "ci_json=$ci_json" >> "$GITHUB_OUTPUT"
if [[ -f "$sarif" ]]; then echo "has_sarif=true" >> "$GITHUB_OUTPUT"; fi
echo "bhf ci finished with exit code $code"
exit 0
