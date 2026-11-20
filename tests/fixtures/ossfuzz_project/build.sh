#!/bin/bash -eu
# SPDX-License-Identifier: Apache-2.0
#
# The OSS-Fuzz build script of a small record parser, written the way an
# OSS-Fuzz project's build.sh is: it runs from the checkout ($SRC/<project>),
# builds with $CC/$CXX and $CFLAGS/$CXXFLAGS, links every fuzz target with
# $LIB_FUZZING_ENGINE (and with $CXX, C targets included), keeps objects in
# $WORK and leaves the fuzz targets in $OUT.

$CC $CFLAGS -Isrc -c src/record.c -o "$WORK/record.o"

$CXX $CXXFLAGS -Isrc fuzz/parse_record_fuzzer.cc "$WORK/record.o" \
    -o "$OUT/parse_record_fuzzer" $LIB_FUZZING_ENGINE

$CC $CFLAGS -Isrc -c fuzz/checksum_fuzzer.c -o "$WORK/checksum_fuzzer.o"
$CXX $CXXFLAGS "$WORK/checksum_fuzzer.o" "$WORK/record.o" \
    -o "$OUT/checksum_fuzzer" $LIB_FUZZING_ENGINE

# Not a fuzz target: a tool built beside them.
$CC $CFLAGS -Isrc tools/record_tool.c "$WORK/record.o" -o "$OUT/record_tool"

# The seed corpus, dictionaries and options OSS-Fuzz takes from beside a fuzz
# target in $OUT. The corpus keeps a regression input for the overflow.
zip -q -j "$OUT/parse_record_fuzzer_seed_corpus.zip" fuzz/corpus/parse_record/*
cp fuzz/parse_record_fuzzer.dict fuzz/parse_record_fuzzer.options fuzz/record.dict "$OUT/"
