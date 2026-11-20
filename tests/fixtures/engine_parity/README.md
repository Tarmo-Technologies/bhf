<!-- SPDX-License-Identifier: Apache-2.0 -->
# Engine-parity benchmark fixtures

Planted-bug C harnesses, one per gated-parser gap class, each crashing **only** past its gate. The sweep test runs bhf's built-in engine on each one **cold** (with no trigger seed) and records time to first crash (TTFC) and executions.

| Fixture | Gate | Crash |
|---|---|---|
| `magic_byte/` | `buf[0]==0x55 && buf[1]==0x55` then length byte in {0,1,2} | stack OOB write (st24-style) |
| `const_gate/` | first 4 bytes == `0xDEADBEEF` | OOB write |
| `len_field/` | 1-byte length field > 8 | OOB read |

Run the sweep with:

```sh
cargo test -p bhf --test engine_parity -- --ignored --nocapture
```

It needs clang with libFuzzer and `make`, prints a TTFC table and asserts that the engine solves each fixture cold. `BHF_PARITY_SECS` sets the budget per fixture (default 8 seconds). The comparison against AFL++, libFuzzer and honggfuzz on these fixtures is in [`docs/site/engine-parity-benchmark.md`](../../../docs/site/engine-parity-benchmark.md).

## RedQueen discriminator

`redqueen_int/` is a separate fixture for the input-to-state (cmplog) mutator. Its crash sits behind an **integer** comparison against a magic value derived from the input's length. The engine reaches it by capturing the comparison operand with SanitizerCoverage trace-cmp and splicing it into the input at the offset it was compared; the shim's memory and string compare hooks, the static dictionary and blind or structured mutation do not reach it. `redqueen_cmplog.rs` asserts that the engine solves it cold with per-input capture on, and does not solve it in the same budget with capture disabled (`BHF_DISABLE_REDQUEEN=1`, the dictionary-only path):

```sh
cargo test -p bhf --test redqueen_cmplog -- --ignored --nocapture
```

## Stack depth

`stack_depth/` is a bracket parser that recurses once per `[` with no depth limit, and every depth runs the same edges. `stack_depth_novelty.rs` checks that the engine, which counts stack depth as progress, keeps the deeper inputs and exhausts the stack (a BHF-207 finding).

## Status (2026-06-21)

The engine solves all three gap classes cold. The generated `dictionary.txt` carries the magic bytes, and generated C direct harnesses run under a persistent fork-server driver, which raises throughput from tens of executions per second to tens of thousands. That throughput lets dictionary insertion pass each gate without a trigger seed.
