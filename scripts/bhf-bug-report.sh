#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

usage() {
  printf '%s\n' \
    'Usage: bhf-bug-report WORK_DIR [OUTPUT_FILE]' \
    '' \
    'Create one compact scrubbed report from a running or completed bhf auto work directory.' \
    'No source, harness code, corpus data, paths, file names, targets, variables, types, units,' \
    'symbols, or macros are included. Default output: ./bhf-support-report.txt'
}

case "${1:-}" in
  -h|--help)
    usage
    exit 0
    ;;
  '')
    usage >&2
    exit 2
    ;;
esac

work_dir=$1
output_file=${2:-bhf-support-report.txt}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)

bhf_bin=
for candidate in "$script_dir/bhf" "$script_dir/../bhf"; do
  if [ -x "$candidate" ]; then
    bhf_bin=$candidate
    break
  fi
done
if [ -z "$bhf_bin" ]; then
  bhf_bin=$(command -v bhf 2>/dev/null || true)
fi
if [ -z "$bhf_bin" ]; then
  printf '%s\n' 'bhf-bug-report: could not find the bhf executable' >&2
  exit 2
fi

exec "$bhf_bin" bug-report "$work_dir" --output "$output_file" --stdout \
  --examples 6 --max-bytes 4000
