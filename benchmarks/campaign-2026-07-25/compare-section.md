<!-- SPDX-License-Identifier: Apache-2.0 -->
# bhf against the usual tool for each job

Measured on twelve projects from the 500-project sweep, cloned once and read
by every tool. `compare.py` produced the numbers; the raw values are in
`compare-sloc.json`, `compare-sbom.json` and `compare-static.json` in this
directory.

## Line counting, against cloc (the reference) and tokei

| Project | bhf | cloc | tokei | bhf time | cloc time |
|---|---:|---:|---:|---:|---:|
| cJSON | 18,740 | 25,437 | 13,597 | 0.55s | 1.21s |
| jansson | 14,765 | 17,511 | 18,271 | 0.02s | 0.32s |
| leveldb | 21,289 | 23,026 | 22,008 | 0.03s | 0.36s |
| tinyxml2 | 7,552 | 27,943 | 26,717 | 0.02s | 0.56s |
| mkcert | 1,212 | 1,359 | 1,136 | 0.01s | 0.28s |
| gson | 38,061 | 41,438 | 40,108 | 0.03s | 0.94s |
| inspect.lua | 39 | 1,079 | 809 | 0.01s | 0.32s |
| MySQLTuner-perl | 14,425 | 38,995 | 20,334 | 0.02s | 0.66s |
| monolog | 333 | 19,007 | 17,233 | 0.01s | 0.93s |
| requests | 7,944 | 12,470 | 12,012 | 0.02s | 0.61s |
| tmuxinator | 1,342 | 7,123 | 5,174 | 0.01s | 0.35s |
| fd | 6,779 | 8,570 | 7,525 | 0.01s | 0.37s |

Total wall time: bhf 0.74s, cloc 6.91s, about 9x faster. bhf prunes vendored
trees, `node_modules`, `.venv` and test directories, so it counts the code it
would fuzz and its totals are lower than cloc's. This comparison exposed six
languages the counter did not recognise (PHP, Ruby, Lua, C#, COBOL, Fortran);
the numbers above are from after that fix.

## SBOM, against syft

| Project | bhf components | syft components | bhf time | syft time |
|---|---:|---:|---:|---:|
| cJSON | 2 | 4 | 2.58s | 40.8s |
| jansson | 4 | 4 | 2.05s | 41.36s |
| leveldb | 6 | 1 | 1.62s | 21.44s |
| tinyxml2 | 3 | 4 | 0.68s | 51.15s |
| mkcert | 6 | 11 | 0.11s | 30.25s |
| gson | 22 | 42 | 1.34s | 33.07s |
| inspect.lua | 0 | 12 | 0.35s | 12.11s |
| MySQLTuner-perl | 185 | 21 | 1.45s | 15.16s |
| monolog | 19 | 12 | 0.33s | 13.44s |
| requests | 21 | 22 | 0.51s | 47.25s |
| tmuxinator | 0 | 4 | 0.51s | 18.72s |
| fd | 130 | 137 | 0.9s | 24.51s |

Total wall time: bhf 12.43s, syft 349.26s, about 28x faster. The counts differ
in both directions: bhf reads declared manifests and grades each component's
evidence, and syft also fingerprints vendored binaries. This comparison found
a gemspec parser that required parentheses, so every gemspec-driven Ruby
project reported zero components; the numbers above are from after that fix.

## Static analysis, against cppcheck, flawfinder, gosec and bandit

| Project | Lane | bhf | time | cppcheck, gosec or bandit | time | flawfinder | time |
|---|---|---:|---:|---:|---:|---:|---:|
| cJSON | c | 40 | 2.79s | cppcheck 223 | 740.23s | 112 | 0.34s |
| jansson | c | 34 | 0.29s | cppcheck 88 | 47.24s | 123 | 0.31s |
| leveldb | cpp | 22 | 0.42s | cppcheck 78 | 4.56s | 147 | 0.37s |
| tinyxml2 | cpp | 10 | 0.92s | cppcheck 49 | 20.94s | 71 | 0.13s |
| mkcert | go | 10 | 0.02s | gosec 19 | 1.18s | — | — |
| gson | java | 5 | 0.49s | — | — | — | — |
| inspect.lua | lua | 2 | 0.01s | — | — | — | — |
| MySQLTuner-perl | perl | 6 | 0.21s | — | — | — | — |
| monolog | php | 0 | 0.08s | — | — | — | — |
| requests | python | 23 | 0.17s | bandit 708 | 1.48s | — | — |
| tmuxinator | ruby | 5 | 0.03s | — | — | — | — |
| fd | rust | 7 | 0.07s | — | — | — | — |

bhf runs 9x to 265x faster than cppcheck, gosec and bandit (cJSON: 2.8s
against cppcheck's 740s). flawfinder, a lexical scanner, is faster than bhf on
three of the four C and C++ projects. bhf reports
fewer findings than any of them, for example 23 against bandit's 708 on
requests: its rules favour precision, and an earlier campaign measured their
false-positive rate ([`docs/site/sast-comparison.md`](../../docs/site/sast-comparison.md)).
`static-scan` has no rules specific to PHP, Ruby, Lua, C#, COBOL or Fortran.

`compare.py` runs no other static analyser on the Java, Lua, Perl, PHP, Ruby
and Rust projects, so those rows show bhf's count only.
