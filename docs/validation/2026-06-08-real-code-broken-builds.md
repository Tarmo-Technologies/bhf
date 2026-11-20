<!-- SPDX-License-Identifier: Apache-2.0 -->

# Real-Code Broken-Build Validation - 2026-06-08

Workspace: `/tmp/bhf-real-code-validation`

Runner:

```sh
python3 scripts/validation/real-code-matrix.py \
  --workspace /tmp/bhf-real-code-validation \
  --json-out /tmp/bhf-real-code-validation/result.json \
  --json
```

Offline rerun:

```sh
python3 scripts/validation/real-code-matrix.py \
  --workspace /tmp/bhf-real-code-validation \
  --offline \
  --json-out /tmp/bhf-real-code-validation/offline-result.json \
  --json
```

## Pinned Repositories

| Repository | Commit | Language | Purpose |
|---|---:|---|---|
| `DaveGamble/cJSON` | `fb16e5cf358798aabb049655975cde8427101056` | C | Real CMake `compile_commands.json`, C89 flags, generated harness build, missing-header breakage. |
| `leethomason/tinyxml2` | `8224e427b655b83dae5e2298f1e6919523a78737` | C++ | Real CMake `compile_commands.json`, C++ generated harness build, missing-header breakage. |
| `yaml/AdaYaml` | `7fde22a1a564bbece3e97430f469717ac46e5842` | Ada | Real Ada scan, target-ranking scale, project-imported generated GPR build. |
| `stcarrez/ada-util` | `3f4f187deeec2a4164c19a03a04c0a79962ff61f` | Ada | Real Ada target discovery, instrumentation, project-imported generated GPR, and host toolchain incompatibility classification. |

## Results

Both online and offline runs completed with:

```json
{
  "repositories": 4,
  "checks": 10,
  "scenarios": 3,
  "passed": 11,
  "failed": 0,
  "known_gaps": 0,
  "toolchain_gaps": 2
}
```

Strict checks that passed:

- `cJSON`: `list-targets` returned 10 targets; generated harness for
  `cJSON_ParseWithLength` built through `bhf build`.
- `cJSON` broken copy: removing `cJSON.h` made `bhf auto` fail the target
  build and report `needed_for_build.synthesized_headers = cJSON.h`.
- `tinyxml2`: `list-targets` returned 10 targets; generated harness for
  `Parse` built through `bhf build`.
- `tinyxml2` broken copy: removing `tinyxml2.h` made `bhf auto` fail both
  matching parser targets and report
  `needed_for_build.synthesized_headers = tinyxml2.h`.
- `AdaYaml`: `list-targets` returned 10 targets; `scan` found 1300 targets;
  generated harness GPR for `Yaml.Dom.Loading.From_String` built with
  `gprbuild` through the real `yaml.gpr`/`Parser_Tools` project graph.
- `ada-util`: `list-targets` returned 10 targets; instrumentation of
  `src/base/dates/util-dates-iso8601.adb` wrote `breadcrumbs.json`.

Toolchain gaps:

- `ada-util` generated GPR build for `Util.Dates.ISO8601.Value` now imports
  the real `utilada_base.gpr`, preserving project `Naming` choices instead of
  flattening source directories into the harness project. On this validation
  host, the imported project selects `util-dates-to_ada_time_64.adb`, which
  calls `Ada.Calendar.Conversions.To_Duration_64` and `To_Ada_Time_64`.
  GNAT 13 lacks those APIs, so the runner classifies the result as a host
  toolchain gap. The manifest
  (`tests/fixtures/real_code_validation/manifest.toml`) declares this gap as
  a check and as a scenario, so `toolchain_gaps` counts it twice.

## Issue Found And Fixed

The cJSON compile database preserves `-std=c89`. That exposed a BHF runtime
compatibility bug: `c_runtime/bhf_decode.h` used C99 `inline` and C99-style
loop declarations. The runtime header and smoke test were updated so generated
C harnesses can compile under real C89 project flags.

The AdaYaml GPR build exposed two Ada parity gaps that were also fixed:

- `generate-harness --project` now imports the real GPR project; the
  harness GPR no longer claims the project's source directories as its own.
  This preserves the project's `Naming`, external variables and library
  settings, and avoids "unit belongs to several projects" failures.
- Return types from package specs and child-package parent specs are resolved
  to qualified Ada names, so generated harnesses emit declarations such as
  `Yaml.Dom.Document_Reference` instead of non-visible short names.

## Current Readiness Signal

On these four repositories, target discovery and generated-harness builds
work for C, C++, and Ada. The C and C++ runs also exercise compile-database
ingestion and broken-header `needed_for_build` reporting. The Ada runs
exercise real GPR project imports and generated GPR builds; ada-util is
reported as a host compiler/runtime mismatch on this host (GNAT 13), counted
under `toolchain_gaps`, with `known_gaps` at 0.
