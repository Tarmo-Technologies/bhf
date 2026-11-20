#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Copy bhf's user documentation from a source checkout into a distribution
# directory. Paths keep their repository layout (README.md beside docs/,
# examples/ and schemas/), so the relative links in README.md, INSTALL.md and
# docs/ resolve inside the extracted package, and inside an install prefix
# that install.sh lays out the same way. scripts/package-offline-dist.sh runs
# this for the full Linux bundle; scripts/check-doc-links.py checks the result.

set -euo pipefail

# The files README.md and the documentation index link, the license notices
# a binary distribution carries, and the plan and benchmark write-ups the
# guides cite.
DIST_DOC_FILES=(
  README.md
  INSTALL.md
  RELEASE_NOTES.md
  CHANGELOG.md
  LICENSE
  NOTICE
  THIRD_PARTY.md
  SECURITY.md
  CONTRIBUTING.md
  CODE_OF_CONDUCT.md
  ROADMAP.md
  DEVELOPMENT_PLAN.md
  docker/README.md
  docker/compliance/README.md
  docker/compliance/WRITTEN-OFFER.md
  evidence/v0.3.0/README.md
  c_runtime/zephyr/README.md
  crates/target_transport/tests/freertos/README.md
  crates/ada_parser/tests/golden/README.md
  SPDX/README.md
)
# Every Markdown write-up under benchmarks/ (READMEs, analyses and results),
# without the scripts and raw data beside them.
DIST_DOC_TREES=(
  benchmarks
)
# The user guides and reference pages (docs/), the example projects the
# guides cite (examples/), and the JSON schemas of bhf's output (schemas/).
DIST_DOC_DIRS=(
  docs
  examples
  schemas
)

usage() {
  cat <<'EOF'
Usage: scripts/stage-dist-docs.sh SOURCE_ROOT DEST_DIR

Copy the user documentation of the bhf checkout at SOURCE_ROOT into DEST_DIR,
keeping the repository layout: README.md, INSTALL.md, RELEASE_NOTES.md,
CHANGELOG.md, the license notices, docs/, examples/, schemas/, every
Markdown page under benchmarks/, and the READMEs that the guides link under
docker/, evidence/, c_runtime/, crates/ and SPDX/. Existing copies of docs/,
examples/, schemas/ and benchmarks/ in DEST_DIR are replaced.
EOF
}

die() {
  printf 'stage-dist-docs.sh: %s\n' "$*" >&2
  exit 1
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac
[[ $# -eq 2 ]] || { usage >&2; exit 2; }
SOURCE_ROOT=$1
DEST_DIR=$2
[[ -d "$SOURCE_ROOT" ]] || die "source root is not a directory: $SOURCE_ROOT"
[[ -d "$SOURCE_ROOT/docs/site" ]] || die "not a bhf checkout (no docs/site): $SOURCE_ROOT"

mkdir -p "$DEST_DIR"
for path in "${DIST_DOC_FILES[@]}"; do
  [[ -f "$SOURCE_ROOT/$path" && ! -L "$SOURCE_ROOT/$path" ]] \
    || die "missing documentation file: $SOURCE_ROOT/$path"
  mkdir -p "$(dirname "$DEST_DIR/$path")"
  cp "$SOURCE_ROOT/$path" "$DEST_DIR/$path"
done
for tree in "${DIST_DOC_TREES[@]}"; do
  [[ -d "$SOURCE_ROOT/$tree" && ! -L "$SOURCE_ROOT/$tree" ]] \
    || die "missing documentation directory: $SOURCE_ROOT/$tree"
  rm -rf "${DEST_DIR:?}/$tree"
  while IFS= read -r -d '' page; do
    path=${page#"$SOURCE_ROOT"/}
    mkdir -p "$(dirname "$DEST_DIR/$path")"
    cp "$page" "$DEST_DIR/$path"
  done < <(find "$SOURCE_ROOT/$tree" -type f -name '*.md' -print0)
done
for dir in "${DIST_DOC_DIRS[@]}"; do
  [[ -d "$SOURCE_ROOT/$dir" && ! -L "$SOURCE_ROOT/$dir" ]] \
    || die "missing documentation directory: $SOURCE_ROOT/$dir"
  rm -rf "${DEST_DIR:?}/$dir"
  cp -R "$SOURCE_ROOT/$dir" "$DEST_DIR/$dir"
done
