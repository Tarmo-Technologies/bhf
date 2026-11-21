<!-- SPDX-License-Identifier: Apache-2.0 -->
# Static-scanner precision benchmark

Measures the **precision, recall and false positives** of bhf's static rules, per rule and per language, against a labelled corpus. A rule change that adds a false positive or loses a detection fails the test.

## Layout

- `corpus/<lang>/`: labelled source for Ada, C, C++, Go, Java, Perl, Python and Rust. Each line where a finding is expected carries an inline annotation `EXPECT BHF-NNN` in that language's comment syntax; every other line must stay clean. The `safe*` and `fp_guards*` files hold most of the hard negatives: safe API variants that must not fire, such as parameterized queries, literal-only `eval`, `yaml.safe_load`, bounded copies, block `eval {}` and an API name inside a string.
- `results.tsv`: the scored result per language and per rule, rewritten by each run.

## Running

```sh
cargo test -p static_analysis --test precision_benchmark -- --nocapture
```

The runner (`crates/static_analysis/tests/precision_benchmark.rs`) scans the corpus, matches each finding to the `EXPECT` labels, counts true positives, false positives and false negatives, and writes `results.tsv`. It asserts overall precision of at least 0.90 and a recall of 1.0, so every rule still fires on its labelled lines. The checked-in result is 114 true positives, 0 false positives and 0 false negatives.

## Corpus

The corpus is written for bhf and is license-clean. It is small and each case targets one rule or one false-positive pattern, so the numbers measure precision and recall on this curated set. Extending it with a permissively licensed subset of NIST Juliet and real-world positives and negatives is planned.
