#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Build bhf's native JVM coverage agent + fork-server driver into a single
# self-contained jar: com.bhf.{Coverage,CoverageAgent,Driver} shaded together
# with ASM (BSD-3-Clause, strict-permissive clean). The jar is BOTH the
# `-javaagent` (Premain-Class) AND the driver main class (`java -cp <jar>
# com.bhf.Driver`).
#
# ASM is fetched from Maven Central into a cache on first build (no repo binary),
# retrying transient failures, and every copy, pre-staged, cached or fetched, must
# have the SHA-256 pinned below. For air-gapped builds, pre-stage the two jars
# into $BHF_JVM_CACHE or $ASM_JAR_DIR (the bhf offline-deps workflow handles
# this). Downloads and the jar are written beside their place and renamed into
# it, so concurrent first builds never read a partial file.
#
# Usage: build-agent.sh [OUT_JAR]
#   OUT_JAR defaults to $BHF_JVM_CACHE/bhf-jvm-agent.jar.
# Prints the absolute path of the built jar on success.
set -eu

ASM_VERSION="9.7"
ASM_CORE_SHA256="adf46d5e34940bdf148ecdd26a9ee8eea94496a72034ff7141066b3eea5c4e9d"
ASM_TREE_SHA256="62f4b3bc436045c1acb5c3ba2d8ec556ec3369093d7f5d06c747eb04b56d52b1"
HERE=$(cd "$(dirname "$0")" && pwd)
SRC="$HERE/src"
CACHE="${BHF_JVM_CACHE:-$HOME/.cache/bhf/jvm}"
OUT="${1:-$CACHE/bhf-jvm-agent.jar}"
mkdir -p "$CACHE"

JAVAC="${JAVAC:-javac}"
JAR="${JAR:-jar}"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# Locate (or fetch) the two ASM jars we need: core + tree API, each with its
# pinned SHA-256.
fetch_asm() {
  name="$1"
  want="$2"
  # Prefer a pre-staged copy (offline), then the cache, then Maven Central.
  for dir in "${ASM_JAR_DIR:-}" "$CACHE"; do
    if [ -n "$dir" ] && [ -f "$dir/$name" ]; then
      got=$(sha256_of "$dir/$name")
      if [ "$got" = "$want" ]; then
        echo "$dir/$name"
        return 0
      fi
      echo "build-agent.sh: $dir/$name has SHA-256 $got, not ASM $ASM_VERSION's $want" >&2
      return 1
    fi
  done
  url="https://repo1.maven.org/maven2/org/ow2/asm/${name%-"$ASM_VERSION".jar}/$ASM_VERSION/$name"
  part="$CACHE/$name.part.$$"
  if command -v curl >/dev/null 2>&1; then
    # --retry-all-errors (curl 7.71) also retries an HTTP 429 or 503.
    retry="--retry 6 --retry-delay 5"
    if curl --help all 2>/dev/null | grep -q -- --retry-all-errors; then
      retry="$retry --retry-all-errors"
    fi
    # shellcheck disable=SC2086
    curl --proto '=https' -fsSL $retry "$url" -o "$part" || { rm -f "$part"; return 1; }
  elif command -v wget >/dev/null 2>&1; then
    wget -q --tries=6 --waitretry=5 "$url" -O "$part" || { rm -f "$part"; return 1; }
  else
    echo "build-agent.sh: need curl or wget to fetch $name (or pre-stage it in \$ASM_JAR_DIR)" >&2
    return 1
  fi
  got=$(sha256_of "$part")
  if [ "$got" != "$want" ]; then
    rm -f "$part"
    echo "build-agent.sh: $url has SHA-256 $got, not ASM $ASM_VERSION's $want" >&2
    return 1
  fi
  mv -f "$part" "$CACHE/$name"
  echo "$CACHE/$name"
}

ASM_CORE=$(fetch_asm "asm-$ASM_VERSION.jar" "$ASM_CORE_SHA256")
ASM_TREE=$(fetch_asm "asm-tree-$ASM_VERSION.jar" "$ASM_TREE_SHA256")

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
CLASSES="$WORK/classes"
mkdir -p "$CLASSES"

# Shade ASM classes in first, then overlay our compiled classes. Drop ASM's
# module-info + META-INF: a stray module-info.class in the javac output dir would
# flip javac into module mode and hide the classpath ("module not found").
(cd "$CLASSES" && "$JAR" xf "$ASM_CORE" && "$JAR" xf "$ASM_TREE")
rm -rf "$CLASSES/META-INF"
find "$CLASSES" -name "module-info.class" -delete

"$JAVAC" -cp "$ASM_CORE:$ASM_TREE" -d "$CLASSES" \
  "$SRC/com/bhf/Cmplog.java" \
  "$SRC/com/bhf/Coverage.java" \
  "$SRC/com/bhf/CoverageAgent.java" \
  "$SRC/com/bhf/Driver.java" \
  "$SRC/com/bhf/BhfData.java" \
  "$SRC/com/bhf/Sink.java"

MANIFEST="$WORK/MANIFEST.MF"
cat > "$MANIFEST" <<EOF
Manifest-Version: 1.0
Premain-Class: com.bhf.CoverageAgent
Agent-Class: com.bhf.CoverageAgent
Can-Retransform-Classes: true
Main-Class: com.bhf.Driver
EOF

mkdir -p "$(dirname "$OUT")"
"$JAR" cfm "$OUT.part.$$" "$MANIFEST" -C "$CLASSES" .
mv -f "$OUT.part.$$" "$OUT"
echo "$OUT"
