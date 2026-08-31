#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Build bhf's native JVM coverage agent + fork-server driver into a single
# self-contained jar: com.bhf.{Coverage,CoverageAgent,Driver} shaded together
# with ASM (BSD-3-Clause, strict-permissive clean). The jar is BOTH the
# `-javaagent` (Premain-Class) AND the driver main class (`java -cp <jar>
# com.bhf.Driver`).
#
# ASM is fetched from Maven Central into a cache on first build (no repo binary).
# For air-gapped builds, pre-stage the two jars into $BHF_JVM_CACHE or
# $ASM_JAR_DIR (the bhf offline-deps workflow handles this).
#
# Usage: build-agent.sh [OUT_JAR]
#   OUT_JAR defaults to $BHF_JVM_CACHE/bhf-jvm-agent.jar.
# Prints the absolute path of the built jar on success.
set -eu

ASM_VERSION="9.7"
HERE=$(cd "$(dirname "$0")" && pwd)
SRC="$HERE/src"
CACHE="${BHF_JVM_CACHE:-$HOME/.cache/bhf/jvm}"
OUT="${1:-$CACHE/bhf-jvm-agent.jar}"
mkdir -p "$CACHE"

JAVAC="${JAVAC:-javac}"
JAR="${JAR:-jar}"

# Locate (or fetch) the two ASM jars we need: core + tree API.
fetch_asm() {
  name="$1"
  # Prefer a pre-staged copy (offline), then the cache, then Maven Central.
  for dir in "${ASM_JAR_DIR:-}" "$CACHE"; do
    [ -n "$dir" ] && [ -f "$dir/$name" ] && { echo "$dir/$name"; return 0; }
  done
  url="https://repo1.maven.org/maven2/org/ow2/asm/${name%-$ASM_VERSION.jar}/$ASM_VERSION/$name"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$CACHE/$name"
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$url" -O "$CACHE/$name"
  else
    echo "build-agent.sh: need curl or wget to fetch $name (or pre-stage it in \$ASM_JAR_DIR)" >&2
    return 1
  fi
  echo "$CACHE/$name"
}

ASM_CORE=$(fetch_asm "asm-$ASM_VERSION.jar")
ASM_TREE=$(fetch_asm "asm-tree-$ASM_VERSION.jar")

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
"$JAR" cfm "$OUT" "$MANIFEST" -C "$CLASSES" .
echo "$OUT"
