<!-- SPDX-License-Identifier: Apache-2.0 -->
# Next harness-driving gap: typed Go data parameters

Resumed checkpoint, 2026-09-24: a narrow data-only implementation now parses
package-local struct declarations, rejects private fields, embedded fields,
method-bearing and opaque types, and seeds complete JSON documents in both
`auto` and `fuzz`. A real `auto` fixture reached a planted branch through
nested pointer, slice, map and tagged fields. This does not resolve the
historical 58-target bucket: its full before/after sweep and harness-origin
finding audit have not been run. The remaining acceptance tests below still apply.

A targeted public-source check at frp revision
`5c6d761c1287e6153f07b824fb6d71b96ee598fe` built and entered
`DecodeProxyConfigurerJSON` without `--force`. It first exposed a separate Go
coverage defect: `-coverpkg` excluded the generated harness module, leaving
`runtime/coverage.WriteCounters` in an invalid mode. After including both the
target package and harness module, the same five-second target run recorded
21 coverage edges, 69,009 executions and no finding. That is one resolved
historical skip with measured feedback; it is not a full 58-target re-sweep or
proof of deep parser-state coverage. Raw current-run evidence is at
`/tmp/bhf-p2-frp-work-coverage-20260924/` in the validation environment.
The subsequent full-workspace test sweep found that targets taking `[]byte`
followed by a JSON data argument need separate input fields: a length-prefixed
raw field and a trailing JSON document. Paired starting seeds now populate
both fields; a Go force fixture passed 2/2 while confirming only its method
receiver still needs `--force`. The same pinned frp target repeated with this
layout entered unforced, recorded 27 edges and 58,833 executions in five
seconds, and reported no finding or forced repair. Its log is
`/tmp/bhf-p2-frp-auto-mixed-20260924.log`. Parser depth beyond that measured
feedback remains unverified.

## Scope recommendation

The sweep records 58 Go targets skipped for unsupported parameter types
(`docs/expected-gaps.md`, Go-1). This is a heterogeneous bucket, not a single
58-target fix. The recommended first feature slice is only *plain data* Go
parameters whose local type declaration can be inspected and whose values can
be constructed without invoking target code: exported structs composed of
supported scalars, strings, pointers, slices, arrays, and maps. Decode input
into a typed local via a standard-library JSON decoder, then call the discovered
target. Do not claim support for all Go structs, interfaces, or dependency
types.

This is distinct from the existing `--force` fallback in
`crates/cli/src/auto/go_build.rs`: force currently declares a zero value for a
nameable type. That may compile but usually does not make attacker-controlled
bytes reach fields or exercise parser logic. The proposed normal path must only
be enabled when static evidence establishes a safe, data-only shape.

## Evidence and representative targets

The reported sweep failures are real skip decisions, not failed builds:

- XTLS/v2ray has `*protocol.RequestHeader` targets in
  `benchmarks/campaign-2026-07-25/results-0728/go__XTLS__Xray-core.json`.
- frp has repeated `DecodeOptions` targets in
  `.../go__fatedier__frp.json`.
- Cobra has `*pflag.FlagSet` in `.../go__spf13__cobra.json`.
- etcd has `*zap.Logger` in `.../go__etcd-io__etcd.json`.

The first two are plausible data-shaped cases, subject to declaration
inspection. `FlagSet` and `Logger` are deliberately excluded from this first
slice: their invariants and behavior are lifecycle/API-defined, and a zero
value or arbitrary field synthesis can create harness-origin crashes or
side-effects. The 58 count therefore remains a measured upper bound; only
re-running the sweep can show the actual effect of the narrower feature.

The implementation boundary is visible in `decode_for_type()` and
`generate_call()` in `crates/cli/src/auto/go_build.rs`. Today unknown types
cleanly produce `unsupported Go parameter type` in normal mode. `--force`
uses `harness_visible_go_type()` and `var z T`; it does not populate data from
the fuzz input.

## Static eligibility contract

Only synthesize JSON-backed values when parsed declarations prove every
reachable field is safe plain data. Specifically:

- the parameter and all nested named types are nameable in the generated
  harness, and parser metadata confirms their declarations and field types;
- every reachable field is exported (or otherwise addressable by the
  generated code); unsupported fields reject the whole type rather than being
  silently omitted;
- recursively allowed leaves are a bounded set of scalar/string types and
  pointer/slice/array/map compositions of allowed data types;
- reject interfaces, channels, functions, unexported fields, custom
  unmarshaler hooks, `unsafe.Pointer`, synchronization primitives, handles,
  readers/writers, loggers, clients, file descriptors, and types whose
  declaration cannot be inspected;
- never call a guessed `New*`, `Open*`, `Connect*`, or other constructor. A
  future explicit user-provided constructor can be a separate opt-in feature.

Plain JSON decoding is not enough by itself: the engine must provide or receive
valid structured starting inputs that reach the target's parser logic. Keep
binary-only mutation as-is and add structured seeds through an explicit
dictionary/corpus initialization path; do not report an unsupported parameter
as supported just because `json.Unmarshal` compiles.

## Acceptance tests

Before implementation is considered complete, add a local fixture and tests
that establish all of the following:

1. A package-local fixture target takes an exported nested data struct, has a
   parser-like validation branch, and is generated in normal (not `--force`)
   mode. The generated harness compiles and a valid JSON seed reaches an
   observable branch/reachability oracle.
2. Mutated valid JSON can exercise a planted, deterministic safe finding in
   that fixture; malformed JSON is rejected/ignored as input and is not
   misclassified as a harness crash.
3. A pointer field and a collection/map field are populated; `null`, empty,
   absent, and malformed-field cases have intentional documented semantics.
4. A custom `UnmarshalJSON` implementation, private field, interface,
   `*zap.Logger`-like lifecycle type, and `*pflag.FlagSet`-like handle remain
   cleanly skipped in normal mode. `--force` retains its existing documented
   best-effort zero-value behavior without changing finding classification.
5. The unsupported 58-target Go sweep is re-run with before/after residual
   histograms, build/fuzz counts, findings, and any new harness-origin crash
   audit. Report the actual resolved count rather than assigning all 58 to this
   feature.

## Non-goals

This slice does not add universal Go reflection, infer constructors, initialize
dependency-managed resources, synthesize private fields with `unsafe`, or
promise all Go parser-like inputs can be represented as JSON. It does not
address Go receiver construction (Go-2) or the no-`go.mod` lane (Go-3).

**Recommended next wave:** implement only after reviewing the real declarations
for the XTLS/v2ray and frp exemplars, and after the engine comparison smoke
runner has a valid baseline. The static parser's ability to prove field
eligibility is a prerequisite; if that evidence is not available, keep the
existing safe skip rather than guessing from exported type names.
