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
# retrying transient failures. A fetched or cached jar must have the SHA-256
# pinned below; a cached one that does not is fetched again. ASM_JAR_DIR names
# jars the operator vouches for, used as they are: a distribution's own build of
# ASM 9.7 (Debian's libasm-java, as the container image uses) is not
# byte-identical to Maven Central's. For air-gapped builds, pre-stage Maven
# Central's two jars into $BHF_JVM_CACHE, or any build of them into
# $ASM_JAR_DIR (the bhf offline-deps workflow handles this). Downloads and the
# jar are written beside their place and renamed into it, so concurrent first
# builds never read a partial file.
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

# Locate (or fetch) the two ASM jars we need: core + tree API. A fetched or
# cached one must have its pinned SHA-256.
fetch_asm() {
  name="$1"
  want="$2"
  # Prefer the operator's pre-staged copy, then the cache, then Maven Central.
  if [ -n "${ASM_JAR_DIR:-}" ] && [ -f "$ASM_JAR_DIR/$name" ]; then
    echo "$ASM_JAR_DIR/$name"
    return 0
  fi
  if [ -f "$CACHE/$name" ]; then
    if [ "$(sha256_of "$CACHE/$name")" = "$want" ]; then
      echo "$CACHE/$name"
      return 0
    fi
    # Not the jar this script fetched: a partial or altered file.
    rm -f "$CACHE/$name"
  fi
  # Maven Central, then Google's mirror of it: Central's CDN has answered
  # some networks with errors for an hour at a time. The pinned digest below
  # holds the jar to the same bytes whichever one serves it.
  path="org/ow2/asm/${name%-"$ASM_VERSION".jar}/$ASM_VERSION/$name"
  part="$CACHE/$name.part.$$"
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    echo "build-agent.sh: need curl or wget to fetch $name (or pre-stage it in \$ASM_JAR_DIR)" >&2
    return 1
  fi
  fetched=""
  for base in https://repo1.maven.org/maven2 https://maven-central.storage-download.googleapis.com/maven2; do
    url="$base/$path"
    if command -v curl >/dev/null 2>&1; then
      # --retry-all-errors (curl 7.71) also retries an HTTP 429 or 503.
      retry="--retry 6 --retry-delay 5"
      if curl --help all 2>/dev/null | grep -q -- --retry-all-errors; then
        retry="$retry --retry-all-errors"
      fi
      # shellcheck disable=SC2086
      curl --proto '=https' -fsSL $retry "$url" -o "$part" && fetched=1 && break
    else
      wget -q --tries=6 --waitretry=5 "$url" -O "$part" && fetched=1 && break
    fi
    rm -f "$part"
  done
  [ -n "$fetched" ] || return 1
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
