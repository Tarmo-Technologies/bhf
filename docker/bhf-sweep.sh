#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Run bhf auto across the pinned sweep corpus and emit a pass/fail report.
# Proves each language lane can build, harness, and fuzz inside the container.
#
# Usage:  bhf-sweep [--fetch] [manifest.tsv]
#   --fetch        fetch/refresh the corpus first (needs network)
#
# Env (all optional):
#   BHF_CORPUS            corpus dir            (default: ./corpus)
#   BHF_SWEEP_RESULTS     results/report dir    (default: ./results)
#   BHF_SWEEP_MANIFEST    manifest TSV          (default: baked-in)
#   BHF_PER_TARGET_TIME   fuzz secs per target  (default: 20)
#   BHF_MAX_TARGETS       targets per project   (default: 3)
#   BHF_CAMPAIGN_TIME     hard cap per project  (default: 240)
#   BHF_JOBS              concurrent targets    (default: 1)
#   BHF_LANGS             space list to filter  (default: all)
set -euo pipefail
set -f

FETCH=0
[ "${1:-}" = "--fetch" ] && { FETCH=1; shift; }

MANIFEST="${1:-${BHF_SWEEP_MANIFEST:-/usr/local/share/bhf/sweep-manifest.tsv}}"
CORPUS="${BHF_CORPUS:-$PWD/corpus}"
RESULTS="${BHF_SWEEP_RESULTS:-$PWD/results}"
PTT="${BHF_PER_TARGET_TIME:-20}"
MAXT="${BHF_MAX_TARGETS:-3}"
CAMP="${BHF_CAMPAIGN_TIME:-240}"
JOBS="${BHF_JOBS:-1}"
FILTER="${BHF_LANGS:-}"
CONTRACT="$(dirname "$(readlink -f "$0")")/sweep_contract.py"

[ -f "$MANIFEST" ] || { echo "manifest not found: $MANIFEST" >&2; exit 2; }
ROWS=$(python3 "$CONTRACT" rows "$MANIFEST")
for value in "$PTT" "$MAXT" "$CAMP" "$JOBS"; do
    [[ "$value" =~ ^[1-9][0-9]{0,7}$ ]] || { echo "budgets must be positive bounded integers" >&2; exit 2; }
done
python3 "$CONTRACT" prepare "$RESULTS"
REPORT_MD="$RESULTS/sweep-report.md"
REPORT_TSV="$RESULTS/sweep-report.tsv"

if [ "$FETCH" = 1 ]; then
    BHF_SWEEP_MANIFEST="$MANIFEST" BHF_CORPUS="$CORPUS" bhf-fetch-corpus
fi

started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
{
    echo "# BHF containerised sweep"
    echo
    echo "- started: \`$started\`"
    echo "- image bhf: \`$(bhf --version 2>/dev/null | head -1)\`"
    echo "- budget: per-target ${PTT}s · max-targets ${MAXT} · campaign ${CAMP}s · jobs ${JOBS}"
    echo
    echo "| lang | project | status | targets fuzzed | execs | edges | findings | secs |"
    echo "|------|---------|--------|---------------:|------:|------:|---------:|-----:|"
} > "$REPORT_MD"
: > "$REPORT_TSV"

# outcome tallies
declare -i n_pass=0 n_stub=0 n_notargets=0 n_error=0 n_missing=0 n_selected=0

run_one() {
    local lang="$1" id="$2" subpath="$3" extra="$4" revision="$5"
    local src="$CORPUS/${lang}__${id}"
    [ -n "$subpath" ] && [ "$subpath" != "-" ] && src="$src/$subpath"
    local wd="$RESULTS/${lang}__${id}"
    local status execs edges finds targets secs
    execs=0; edges=0; finds=0; targets=0

    if ! python3 "$CONTRACT" checkout "$CORPUS/${lang}__${id}" "$revision" "$subpath"; then
        status="MISSING"; n_missing+=1
        printf '%s\t%s\t%s\t0\t0\t0\t0\t0\n' "$lang" "$id" "$status" >> "$REPORT_TSV"
        printf '| %s | %s | ⚠ %s | 0 | 0 | 0 | 0 | 0 |\n' "$lang" "$id" "$status" >> "$REPORT_MD"
        echo "[$lang/$id] MISSING ($src)"
        return
    fi

    mkdir "$wd"
    [ "$extra" = "-" ] && extra=""
    local t0 t1; t0=$(date +%s)
    # Build recovery executes the tree's own build system to recover real compile
    # flags. That is arbitrary code execution by design — which is exactly why the
    # sweep runs inside the container. --force fuzzes what phase 1 could not build.
    # NB: </dev/null keeps bhf and any build subprocess from consuming the manifest
    # that the outer loop reads (the loop uses FD 3, but this is belt-and-suspenders).
    # shellcheck disable=SC2086
    local rc=0
    timeout --kill-after=10 $((CAMP + 600)) bhf --profile external-tools auto "$src" \
        --work-dir "$wd" \
        --jobs "$JOBS" \
        --per-target-time "$PTT" \
        --max-targets "$MAXT" \
        --campaign-time "$CAMP" \
        --unsafe-search-and-run-build-commands \
        --force \
        $extra > "$wd/sweep-stdout.log" 2>&1 </dev/null || rc=$?
    t1=$(date +%s); secs=$((t1 - t0))

    local stats report_status="ERROR(no-valid-report)"
    if stats=$(python3 "$CONTRACT" stats "$wd/auto/run.json"); then
        IFS=$'\t' read -r report_status targets execs edges finds <<< "$stats"
    fi

    if [ "$rc" -eq 124 ]; then
        status="TIMEOUT"; n_error+=1
    elif [ "$rc" -ne 0 ]; then
        status="ERROR($rc)"; n_error+=1
    else
        status="$report_status"
        case "$status" in
            PASS) n_pass+=1;;
            STUB-ONLY) n_stub+=1;;
            NO-TARGETS|NOT-ENTERED) n_notargets+=1;;
            *) n_error+=1;;
        esac
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$lang" "$id" "$status" "${targets:-0}" "${execs:-0}" "${edges:-0}" "${finds:-0}" "$secs" >> "$REPORT_TSV"
    printf '| %s | %s | %s | %s | %s | %s | %s | %s |\n' \
        "$lang" "$id" "$status" "${targets:-0}" "${execs:-0}" "${edges:-0}" "${finds:-0}" "$secs" >> "$REPORT_MD"
    echo "[$lang/$id] $status  execs=${execs:-0} edges=${edges:-0} finds=${finds:-0} ${secs}s"
}

# Read the manifest on FD 3 so a subprocess in the loop body that reads stdin
# (bhf, or a build-recovery tool) cannot swallow the remaining manifest lines.
while IFS=$'\t' read -r lang id url rev subpath extra <&3 || [ -n "${lang:-}" ]; do
    case "$lang" in ''|'#'*) continue;; esac
    if [ -n "$FILTER" ]; then case " $FILTER " in *" $lang "*) : ;; *) continue;; esac; fi
    n_selected+=1
    run_one "$lang" "$id" "${subpath:-}" "${extra:-}" "$rev"
done 3<<< "$ROWS"

{
    echo
    echo "## Totals"
    echo
    echo "- PASS (built+harnessed+fuzzed): **$n_pass**"
    echo "- STUB-ONLY (fuzzed synthetic stub, needs review): $n_stub"
    echo "- NO-TARGETS (no fuzzable entry found): $n_notargets"
    echo "- MISSING (corpus not fetched): $n_missing"
    echo "- ERROR / TIMEOUT: $n_error"
    echo "- Edges: sum of per-target peak feedback counters; not a global edge union."
    echo "- Findings: per-pass observations on entered real targets, not unique bugs."
    echo
    echo "- finished: \`$(date -u +%Y-%m-%dT%H:%M:%SZ)\`"
} >> "$REPORT_MD"

echo
echo "==================== SWEEP TOTALS ===================="
echo "PASS=$n_pass STUB-ONLY=$n_stub NO-TARGETS=$n_notargets MISSING=$n_missing ERROR=$n_error"
echo "report: $REPORT_MD"
echo "====================================================="

# Every selected project needs positive real-target execution evidence.
[ "$n_selected" -gt 0 ] && [ "$n_pass" -eq "$n_selected" ]
