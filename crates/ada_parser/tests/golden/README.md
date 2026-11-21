<!-- SPDX-License-Identifier: Apache-2.0 -->

# Golden Ada Corpus

Synthetic Ada fixtures for the Ada scanner's acceptance test (`crates/ada_parser/tests/golden.rs`). Every fixture is written for this corpus; third-party Ada source does not belong here.

## Layout

Each fixture lives at:

```text
<dialect>/<scenario>/{src.adb|src.ads,manifest.toml}
```

The dialect directories are `ada95`, `ada2005`, `ada2012` and `ada2022`. Use `src.adb` for bodies and subunits and `src.ads` for specs. If both exist, the harness scans `src.adb`.

## Manifest

`manifest.toml` holds the ground truth, counted by reading the Ada source:

```toml
description = "Short fixture purpose"
dialect_hint = "ada_2012"

[expected]
ada_standard = "ada_2012"
unit_kind = "body"
subprograms = 1
handlers = 0
raises = 0
types = 0
use_clauses = 0
with_clauses = []
pragmas = ["ada_2012"]

[expected.names]
subprograms = ["run"]
handler_choices = []
type_kinds = []
```

`dialect_hint` is optional. Leave it out when the fixture exercises dialect detection from pragmas or heuristics.

A non-empty list under `[expected.names]` is an allow-list: every name the extractor reports in that category must appear in it. An empty list is not checked.

## Adding a fixture

1. Create a scenario directory under the oldest dialect the fixture needs.
2. Add a small synthetic Ada source file with an Apache-2.0 SPDX header.
3. Add `manifest.toml` with an Apache-2.0 SPDX header.
4. Set the expected counts from the source, not from the extractor's output.
5. Run:

```bash
cargo test -p ada_parser --test golden -- --nocapture
cargo run -p spdx_check -- check
```

If a fixture exposes an extractor bug, first write a failing focused test in the extractor or reconcile module, then fix the extractor. Keep the manifest counts true to the source; lower one only when an open issue documents the bug as out of scope.

## Acceptance

The golden harness requires at least 50 fixtures and these aggregate thresholds:

- subprograms: extracted / expected >= 0.95
- handlers + raises: extracted / expected >= 0.99

It also fails on any extracted name missing from a manifest allow-list.
