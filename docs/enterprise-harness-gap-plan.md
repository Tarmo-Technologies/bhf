<!-- SPDX-License-Identifier: Apache-2.0 -->
# Typed Go data parameters

`bhf auto` and `bhf fuzz` drive a Go target whose parameters are plain data:
exported, package-local structs built from scalars, strings, pointers,
slices, arrays and string-keyed maps. The generated harness decodes the fuzz
input into a typed local with the standard-library JSON decoder and calls the
target, with no `--force`. This page describes the eligibility rules, the
evidence, and the acceptance tests. The `Go-1` class in
[expected-gaps.md](expected-gaps.md) tracks the Go targets bhf still skips for
an unsupported parameter type.

## How it works

- bhf parses the package-local struct declarations and accepts a parameter
  only when every reachable field is proven plain data (rules below).
- `auto` and `fuzz` seed complete JSON documents as starting inputs, so the
  first executions reach the target's parser logic instead of failing to
  decode.
- A target that takes `[]byte` followed by a JSON data argument gets two input
  fields: a length-prefixed raw field and a trailing JSON document. Paired
  starting seeds fill both.
- A Go parser of the shape `Unmarshal(in []byte, out interface{})` (or `any`)
  is driven with a fresh `*interface{}` as the output argument.
- For any other nameable type, `--force` declares a zero value (`var z T`,
  through `harness_visible_go_type()` in `crates/cli/src/auto/go_build.rs`)
  and does not fill it from the fuzz input. Without `--force`, such a target
  is skipped with `unsupported Go parameter type`.

The code is in `decode_for_type()`, `generate_call()` and
`is_plain_json_parameter()` in `crates/cli/src/auto/go_build.rs`.

## Eligibility rules

bhf builds a JSON-backed value only when the parsed declarations show that
every reachable field is plain data:

- the parameter and every nested named type can be named in the generated
  harness, and their declarations and field types are parsed;
- every reachable field is exported; one unsupported field rejects the whole
  type, so no field is silently left out;
- leaves are scalar and string types, and compositions are pointers, slices,
  arrays and string-keyed maps of allowed types;
- interfaces, channels, functions, unexported or embedded fields, custom
  `UnmarshalJSON` or `UnmarshalText` hooks, `unsafe.Pointer`, synchronization
  primitives, handles, readers and writers, loggers, clients, file
  descriptors, and types whose declaration cannot be read are rejected;
- bhf never calls a guessed `New*`, `Open*`, `Connect*` or other constructor.

## Evidence

- A local `auto` fixture reached a planted branch through nested pointer,
  slice, map and tagged fields.
- At frp revision `5c6d761c1287e6153f07b824fb6d71b96ee598fe`, bhf built and
  entered `DecodeProxyConfigurerJSON` without `--force`. This run also found a
  Go coverage defect: `-coverpkg` left out the generated harness module, so
  `runtime/coverage.WriteCounters` ran in an invalid mode. With both the
  target package and the harness module in `-coverpkg`, a five-second run
  recorded 21 coverage edges and 69,009 executions, with no finding. With the
  two-field `[]byte` plus JSON layout, the same target recorded 27 edges and
  58,833 executions in five seconds, with no finding and no forced repair.
  The raw logs of these two runs are not in the repository; the 2026-11-16
  re-run built and fuzzed the same target at the same revision
  (`benchmarks/campaign-2026-07-25/results-1116-go1-go1.27/go__fatedier__frp.json`).
- The [Go re-sweep](validation/2026-11-16-go-resweep.md) of 2026-11-16 re-ran
  the 59 targets the 2026-07-28 sweep skipped as Go-1: 7 now build and fuzz
  and 52 still skip.

## Representative targets

These are skip decisions recorded by the 2026-07-28 sweep
(`benchmarks/campaign-2026-07-25/results-0728/`):

| Project | Parameter | Fits the rules |
|---|---|---|
| XTLS/Xray-core | `*protocol.RequestHeader` (`go__XTLS__Xray-core.json`) | Data-shaped; depends on its declaration. |
| frp | `DecodeOptions` (`go__fatedier__frp.json`) | Data-shaped; depends on its declaration. |
| Cobra | `*pflag.FlagSet` (`go__spf13__cobra.json`) | No: a lifecycle handle. |
| etcd | `*zap.Logger` (`go__etcd-io__etcd.json`) | No: a lifecycle handle. |

`FlagSet` and `Logger` are excluded because their invariants are defined by
their APIs and lifecycles; a zero value or synthesized fields can produce
crashes that come from the harness, not the target. Receiver construction
(Go-2) and the no-`go.mod` lane (Go-3) are separate classes in
[expected-gaps.md](expected-gaps.md).

## Acceptance tests

1. A package-local fixture target takes an exported nested data struct, has
   a parser-like validation branch, and is generated in normal (not
   `--force`) mode. The generated harness compiles and a valid JSON seed
   reaches an observable branch or reachability oracle.
2. Mutated valid JSON reaches a planted, deterministic finding in that
   fixture; malformed JSON is rejected as input and is not reported as a
   harness crash.
3. A pointer field and a collection or map field are populated; `null`,
   empty, absent and malformed fields have documented behavior.
4. A custom `UnmarshalJSON` implementation, a private field, an interface, a
   `*zap.Logger`-like lifecycle type and a `*pflag.FlagSet`-like handle are
   skipped in normal mode (unit tests
   `data_struct_decoder_rejects_private_state_custom_json_and_unknown_handles`
   and `data_decoder_allows_only_plain_recursively_proven_field_types`).
   `--force` keeps its zero-value behavior without changing finding
   classification.
5. The Go-1 sweep is re-run with before/after residual histograms,
   build/fuzz counts, findings, and an audit for crashes that originate in
   the harness; the result reports the resolved count measured.
   **Done 2026-11-16** ([Go re-sweep](validation/2026-11-16-go-resweep.md)):
   7 of the 59 resolved and 52 still skip. The audit found no crash in
   generated harness code and two input-independent causes of false findings
   (#398, #399).
