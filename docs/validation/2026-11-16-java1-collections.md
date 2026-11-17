<!-- SPDX-License-Identifier: Apache-2.0 -->
# Java collection parameters (Java-1), 2026-11-16

This re-runs, by name, every Java target the 2026-07-28 campaign sweep
(`results-0728`) skipped as Java-1, `parameter #N has an unsupported type`. It
backs the Java-1 entry of [expected-gaps.md](../expected-gaps.md). Each project is
cloned at the commit that sweep measured. The bhf under test is a release build
of the wave-8 branch (`bhf 0.3.0-dev`).

The harness declared every local with `var`. For a collection built from the
input, `var` infers the wrong element type, so a `List<String>` or
`Map<String, Object>` parameter was unsupported. A collection local is now
declared with its parsed type, spelled fully qualified, and filled with a fuzzed
number of decoded elements. A `java.util.Random` parameter is now seeded from
the input.

The rows are under `benchmarks/campaign-2026-07-25/`:

| Directory | What it is |
|---|---|
| `results-1116-java1/` | The 57 targets, under the sweep's flags |
| `results-1116-java1-untrusted/` | The three projects whose targets now reach their Maven or Gradle build, re-run with `--run-untrusted` |

## Reproduce

```sh
cd benchmarks/campaign-2026-07-25
BHF_BIN=<bhf> python3 go1_rerun.py results-0728 results-1116-java1 \
  --lang java --class Java-1 --all-lanes --jobs 2
BHF_BIN=<bhf> python3 go1_rerun.py results-0728 results-1116-java1-untrusted \
  --lang java --class Java-1 --all-lanes --jobs 3 --run-untrusted \
  --only java__jeecgboot__JeecgBoot.json --only java__lysine-dev__retrofit.json \
  --only java__zxing__zxing.json
```

## Result

| | Before | After | After, `--run-untrusted` |
|---|---:|---:|---:|
| Java-1 targets | 57 | | |
| Built and fuzzed | 0 | 0 | 0 |
| Still Java-1, on the same parameter | 57 | 50 | 50 |
| Still Java-1, on the next parameter | | 1 | 1 |
| Stopped at the project's Maven or Gradle build, which needs consent | | 5 | |
| Failed build | | 1 | 6 |

The `--run-untrusted` column re-ran only the three projects with a target at
the consent gate; the other rows are carried over.

**None of the 57 builds and fuzzes.** Collections were a small part of the
class. The seven targets the change moved:

| Target | Parameter | Now |
|---|---|---|
| JeecgBoot `parseTemplate`, `parseTemplateContent` (3) | `Map<String, Object>` | Needs the Maven build, which fails to resolve the parent POM |
| zxing `ExpandedProductParsedResult` | `Map<String,String>` | Needs the Maven build, which finds no plugin for a prefix; the Android integration module does not compile |
| retrofit `create` | `Random` | Needs the Gradle build; javac on the tree finds a duplicate class (`src/main/java16` multi-release sources) |
| hello-algorithm `FindNumbersWithSum` | `int[]` | javac on the tree finds a duplicate class `Solution` (many exercise dirs, one default package) |
| proleap-cobol-parser `CobolCompilationUnitVisitorImpl` | `List<String>` | Its next parameter, ANTLR's `CommonTokenStream`, is unsupported |

Under the sweep's flags, bhf does not run a project's own build, and five of
these targets stop there. With `--run-untrusted`, each of those builds fails
for a reason in the project or its dependencies.

The 50 that did not move:

| Parameter type | Targets |
|---|---:|
| An Android framework type (`Context`, `AssetManager`), not resolvable offline | 19 |
| A project type with no no-arg constructor, factory or constant (`ListNode`, `SVWindow`, `Tree`, an interface such as `FileWriterAction`) | 17 |
| A generic project interface (`RequestHttp<CloseableHttpClient, HttpHost>`) | 3 |
| A `List` of such a project type (`List<BarEntry>`, `List<CobolExpression>`) | 4 |
| A dependency's type (`ObjectMapper`, `ObjectProvider<…>`, `TypeReference<T>`) | 5 |
| A bare type variable `T` | 2 |

## The fixture

`tests/fixtures/java_generics/` has one target per collection shape: a
`List<String>`, a `Map<String, Object>`, an `int[]`, a `Set<Integer>`, a
`SortedMap<String, byte[]>`, a `List<Set<Integer>>` and a
`Collection<? extends CharSequence>`. `crates/cli/tests/auto_java_generics.rs`
checks that each one builds and fuzzes, and that the planted
ArrayIndexOutOfBoundsException behind `widths(List<String>)` is found.
