<!-- SPDX-License-Identifier: Apache-2.0 -->
# BHF-545 GraphQL-Injection Sweep - 2026-07-08

This memo records the validation for `BHF-545` (CWE-943 GraphQL injection), a
Python static rule that flags a GraphQL operation document parsed via `gql()`
from a dynamically-built string.

## Rule shape

`BHF-545` fires only when all three hold on a line:

- a `gql(` parser call (word-boundary matched, not inside a string literal),
- dynamic-string evidence (`+` concatenation, an f-string, or `.format(`), and
- GraphQL operation syntax (`query`/`mutation`/`subscription`).

A literal operation document with request data bound through `variable_values`
is the safe form and does not fire. This mirrors the SQL rule (`BHF-419`): the
sink requires concat/format evidence, so a parameterized/variable-bound query is
clean.

## Sweep

- Branch: `sast-graphql-hardening-2026-07-08`
- Scanner: `target/debug/bhf static-scan <repo>`
- Corpus: three real GraphQL Python projects.

| Repo | Total findings | BHF-545 total | BHF-545 outside tests |
|---|--:|--:|--:|
| `graphql-python/gql` | ~2.9k | 71 | 0 |
| `strawberry-graphql/strawberry` | 8 | 0 | 0 |
| `graphql-python/graphene` | 5 | 0 | 0 |

The two server frameworks (strawberry, graphene) build schemas rather than
client-side operation strings, so they produce zero `BHF-545` noise — the rule is
scoped to the `gql()` client pattern.

All 71 `gql` reports are in that library's own test suite, in the shape
`gql(subscription_str.format(count=count))` — a genuine dynamic operation
document. Whether the interpolated value is attacker-controlled is a taint
question the syntactic rule does not resolve, exactly as with `BHF-419`; the
library source itself produced no reports.

## Unit coverage

`python_rule_pack_flags_dynamic_graphql_documents` asserts three positive shapes
(concat, f-string, `.format`) and a negative block covering: a literal document
bound with `variable_values`, `gql(CONST)`, a dynamic SQL `execute` on the same
tree (fires `BHF-419`, not `BHF-545`), and a `gql(` needle that appears only inside
a string literal.

## Commands

```sh
cargo fmt --check
cargo test -p finding_rules -p static_analysis --quiet
cargo test -p static_analysis --test precision_benchmark
cargo build -p bhf --quiet
cargo run -p spdx_check -- check
```
