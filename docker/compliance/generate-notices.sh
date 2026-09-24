#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Generate third-party license notices and the copyleft source-obligation list
# from the installed dpkg set. Runs at IMAGE BUILD TIME (as root) after every apt
# install, so it reflects exactly what the image ships. Output:
#   <OUT>/THIRD_PARTY_NOTICES.md  — every package, version, source, license(s)
#   <OUT>/COPYLEFT-SOURCES.txt    — `source=version` for GPL/LGPL packages only
#
# The authoritative full license text for each package stays in the image at
# /usr/share/doc/<pkg>/copyright (never deleted). bhf itself is Apache-2.0.
set -uo pipefail

OUT="${1:-/usr/share/bhf/licenses}"
mkdir -p "$OUT"
NOTICES="$OUT/THIRD_PARTY_NOTICES.md"
COPYLEFT="$OUT/COPYLEFT-SOURCES.txt"

{
    echo "# Third-party notices — Debian/Ubuntu userland in this image"
    echo
    echo "Generated at image build from \`dpkg\` and \`/usr/share/doc/<pkg>/copyright\`."
    echo "The **authoritative** full license text for every package is retained in the"
    echo "image at \`/usr/share/doc/<pkg>/copyright\`."
    echo
    echo "This image is a **mere aggregation** of independent programs. bhf itself is"
    echo "Apache-2.0 and invokes the toolchain packages as separate subprocesses; it"
    echo "does not link them. Some packages below are GPL/LGPL — see WRITTEN-OFFER.md"
    echo "and COPYLEFT-SOURCES.txt for the corresponding-source offer."
    echo
    echo "Non-dpkg components, all permissive: Rust toolchain (Apache-2.0 OR MIT),"
    echo "esbuild (MIT), SharpFuzz + dnlib (MIT), ASM/asm-tree (BSD-3-Clause),"
    echo "bhf (Apache-2.0)."
    echo
    echo "| Package | Version | Source | Declared license(s) |"
    echo "|---|---|---|---|"
} > "$NOTICES"
: > "$COPYLEFT"

# ${source:Package}/${source:Version} give the SOURCE package + its version, which
# is what `apt-get source pkg=version` needs to fetch the exact corresponding code.
dpkg-query -W -f '${Package}\t${Version}\t${source:Package}\t${source:Version}\n' 2>/dev/null \
    | sort | while IFS=$'\t' read -r pkg ver srcpkg srcver; do
    [ -z "$srcpkg" ] && srcpkg="$pkg"
    [ -z "$srcver" ] && srcver="$ver"
    cp="/usr/share/doc/$pkg/copyright"
    lic="(see /usr/share/doc/$pkg/copyright)"
    if [ -f "$cp" ]; then
        found=$(grep -oiE '^License: .+' "$cp" 2>/dev/null | sed 's/^License: //I' \
            | sort -u | paste -sd', ' - | cut -c1-90)
        [ -n "$found" ] && lic="$found"
        # Source obligation. For a machine-readable (DEP-5) copyright, trust its
        # `License:` fields — this avoids false-flagging a permissive package
        # (e.g. afl++/Apache-2.0) whose license TEXT merely mentions GPL for
        # compatibility. For a free-text copyright with no `License:` field, fall
        # back to a reference to the common GPL/LGPL license text.
        if grep -qiE '^License:' "$cp" 2>/dev/null; then
            grep -qiE '^License:[[:space:]]*L?GPL' "$cp" 2>/dev/null \
                && echo "$srcpkg=$srcver" >> "$COPYLEFT"
        elif grep -qE '/usr/share/common-licenses/(GPL|LGPL)' "$cp" 2>/dev/null; then
            echo "$srcpkg=$srcver" >> "$COPYLEFT"
        fi
    fi
    printf '| %s | %s | %s | %s |\n' "$pkg" "$ver" "$srcpkg" "$lic" >> "$NOTICES"
done

sort -u -o "$COPYLEFT" "$COPYLEFT"
echo "generate-notices: $(($(wc -l < "$NOTICES") - 12)) packages -> $NOTICES"
echo "generate-notices: $(wc -l < "$COPYLEFT") copyleft source package(s) -> $COPYLEFT"
