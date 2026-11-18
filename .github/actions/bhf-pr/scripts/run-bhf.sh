#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run bhf for the bhf-pr action, in a work dir a cache may have restored
# (#317), in one of its modes (#319):
#   pr        `bhf ci` scoped to the PR's changes (the default);
#   batch     `bhf ci` over the whole tree, growing every target's corpus;
#   prune     rebuild the harnesses and shrink each corpus to the inputs that
#             add coverage (`bhf corpus minimize`);
#   coverage  fuzz briefly from the corpus and report the line coverage it
#             reaches (`results/coverage/`).
#
# Inputs (environment): INPUT_MODE, INPUT_PATH, INPUT_LANGUAGES,
# INPUT_CAMPAIGN_TIME, INPUT_PER_TARGET_TIME, INPUT_PR_GATE, BASE_REF (pr),
# BHF_WORK_DIR, and RUNNER_TEMP, GITHUB_OUTPUT and GITHUB_STEP_SUMMARY as
# Actions sets them. Outputs: mode and exit, and sarif, ci_json and has_sarif
# (pr, batch) or coverage_dir (coverage), in GITHUB_OUTPUT.
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

mode="${INPUT_MODE:-pr}"
echo "mode=$mode" >> "$GITHUB_OUTPUT"
lang_arg=()
if [[ -n "${INPUT_LANGUAGES:-}" ]]; then
  lang_arg=(--languages "$INPUT_LANGUAGES")
fi
path="${INPUT_PATH:-.}"

# `bhf ci`, scoped to the PR's changes or over the whole tree, with the gate.
# The work dir lives outside the checkout so discovery never scans it.
run_ci() {
  if ! bhf ci --help 2>/dev/null | grep -q -- '--changed-since'; then
    echo "::error title=bhf::the installed bhf does not support 'ci --changed-since' — pin 'version:' to a release that ships it, or set 'build-from-source: true'"
    exit 1
  fi
  bhf ci "$path" \
    "$@" \
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
}

# The harness binary of harness `id`: its own build, or an Ada harness's.
harness_binary() {
  local id="$1" candidate
  for candidate in "$work/harnesses/$id/main" "$work/harnesses/$id/main.exe" \
    "$work/build/$id/obj/main" "$work/build/$id/obj/main.exe"; do
    if [[ -f "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

case "$mode" in
  pr)
    run_ci --changed-since "${BASE_REF:?BASE_REF is the ref to diff against}"
    ;;
  batch)
    run_ci
    ;;
  prune)
    # A brief run builds each harness again from this tree; its corpus is
    # then replayed, keeping each input that adds coverage.
    bhf auto "$path" --work-dir "$work" --per-target-time 1 "${lang_arg[@]}" >/dev/null
    before=0
    after=0
    shopt -s nullglob
    for queue in "$work"/corpus/*/queue; do
      id="$(basename "$(dirname "$queue")")"
      inputs=("$queue"/*)
      (( ${#inputs[@]} > 0 )) || continue
      if ! harness="$(harness_binary "$id")"; then
        echo "bhf: prune: $id has no harness binary; its corpus is kept as it is"
        continue
      fi
      rm -rf "$queue.min"
      if bhf corpus minimize --harness "$harness" --in "$queue" --out "$queue.min" >/dev/null \
        && kept=("$queue.min"/*) && (( ${#kept[@]} > 0 )); then
        echo "bhf: prune: $id: ${#inputs[@]} input(s) -> ${#kept[@]}"
        before=$((before + ${#inputs[@]}))
        after=$((after + ${#kept[@]}))
        rm -rf "$queue"
        mv "$queue.min" "$queue"
      else
        echo "bhf: prune: $id: minimizing failed; its corpus is kept as it is"
        rm -rf "$queue.min"
      fi
    done
    shopt -u nullglob
    echo "bhf: pruned the corpus from $before to $after input(s)"
    echo "> **bhf**: pruned the corpus from $before to $after input(s)." >> "$summary"
    echo "exit=0" >> "$GITHUB_OUTPUT"
    ;;
  coverage)
    # The corpus replays through a source-coverage build of each harness at
    # the end of the run, which writes results/coverage/<id>/.
    log="$RUNNER_TEMP/bhf-coverage.log"
    bhf auto "$path" --work-dir "$work" --per-target-time "${INPUT_PER_TARGET_TIME:-30}" \
      "${lang_arg[@]}" 2> "$log" >/dev/null
    line="$(grep -m1 'line coverage' "$log" | sed 's/^bhf auto: //')"
    echo "bhf: ${line:-no line coverage was measured}"
    echo "> **bhf**: ${line:-no line coverage was measured}." >> "$summary"
    echo "coverage_dir=$work/results/coverage" >> "$GITHUB_OUTPUT"
    echo "exit=0" >> "$GITHUB_OUTPUT"
    ;;
  *)
    echo "::error title=bhf::unknown mode '$mode' (expected pr, batch, prune or coverage)"
    exit 1
    ;;
esac
exit 0
