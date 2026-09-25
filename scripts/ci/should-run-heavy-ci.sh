#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Unknown/empty comparisons must run full CI. Keep exemptions narrow: Markdown
# under a crate, fixture, or benchmark may be compiled with include_str!, parsed
# as a test input, or used as an acceptance contract.
if (( $# == 0 )); then
  echo true
  exit 0
fi

for path in "$@"; do
  case "$path" in
    crates/* | tests/* | benchmarks/* | vendor/* | .github/workflows/* | .github/actions/*)
      echo true
      exit 0
      ;;
    docs/*.md | docs/*.rst | docs/*.txt | docs/*.png | docs/*.jpg | docs/*.jpeg | docs/*.svg | docs/*.webp | docs/*.css | docs/*.html | scripts/docs/* | LICENSE | NOTICE | .github/ISSUE_TEMPLATE/* | .github/PULL_REQUEST_TEMPLATE*)
      ;;
    *.md)
      # Only repository-root Markdown is unconditionally documentation.
      if [[ "$path" == */* ]]; then
        echo true
        exit 0
      fi
      ;;
    *)
      echo true
      exit 0
      ;;
  esac
done

echo false
