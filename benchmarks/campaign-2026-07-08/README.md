<!-- SPDX-License-Identifier: Apache-2.0 -->
# bhf comparison campaign (2026-07-08)

Measurements of bhf 0.2.14 (the version its SARIF output records) against
other tools for each feature, on a 14-repository corpus in C, C++, Rust, Go,
Python, Java, Perl and JavaScript.
The corpus was cloned locally and is not checked in. The other tools were
cloc, scc and tokei (SLOC); cppcheck, flawfinder, semgrep, bandit, gosec,
clippy and perlcritic (static analysis); syft and grype (SBOM); AFL++,
libFuzzer and cargo-fuzz (fuzzing).

| Path | Contents |
|---|---|
| [`results/synthesis.md`](results/synthesis.md) | Summary table for every feature area and the gap list |
| [`results/measure_sloc.md`](results/measure_sloc.md) | SLOC counts and speed |
| [`results/measure_static_c_cpp.md`](results/measure_static_c_cpp.md), [`_go`](results/measure_static_go.md), [`_python`](results/measure_static_python.md), [`_rust_java_perl`](results/measure_static_rust_java_perl.md) | Static analysis per language group |
| [`results/measure_sbom.md`](results/measure_sbom.md) | SBOM components and CVE matching |
| [`results/measure_fuzzing_auto.md`](results/measure_fuzzing_auto.md) | `bhf auto` fuzzing runs |
| [`results/measure_reporting.md`](results/measure_reporting.md) | Report formats and content |
| `results/*.csv` | Raw SLOC numbers |
| `charts/` | Figures |
| `static-out/` | bhf `static-scan` output for three of the repositories |

## SLOC accuracy against cloc

Mean absolute deviation from cloc over the 13 repositories in
`results/sloc_final.csv`, counting each repository's primary language: **bhf
1.3%**, scc 19.7%, tokei 23.6%. scc and tokei classify Mojolicious `.pod` and
`.t` files as Raku, count Python docstrings as code, and split C++ headers
from sources differently. `results/measure_sloc.md` repeats the comparison
with headers summed. See `charts/sloc_accuracy.png`.
