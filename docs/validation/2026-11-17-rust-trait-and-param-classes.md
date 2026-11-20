<!-- SPDX-License-Identifier: Apache-2.0 -->
# Rust-1 and Rust-4 reruns, 2026-11-17

[expected-gaps.md](../expected-gaps.md) lists two Rust classes from the
2026-07-28 corpus run (`benchmarks/campaign-2026-07-25/results-0728`):
- Rust-1: a parameter with no byte decoder, 42 targets;
- Rust-4: a static method of a trait impl whose trait is not the crate's
  own, 11 targets.

This record reruns both classes by name with `go1_rerun.py --lang rust`, on
the corpus checkouts pinned to the 0728 commits. The rows are in
`benchmarks/campaign-2026-07-25/results-1117-*`.

## Rust-4

A static method of a trait impl (`fn bytes_decode(bytes: &[u8])` of
`impl BytesDecode for Codec`) can only be called by UFCS,
`<Codec as Trait>::bytes_decode(..)`. The lane resolved the trait only among
the crate's own traits and `FromStr`/`TryFrom`. It now resolves a
dependency's trait:
- through the `use` declarations of the impl's file (`use heed::{BytesDecode,
  BytesEncode}`), or the trait's full spelling;
- for a dependency the target crate declares. That includes one inherited
  from its workspace, whose spec the harness crate copies.

`From<&[u8]>` and `From<&str>` join the standard conversions. The fixture
`tests/fixtures/rust_ext_trait` covers each form
(`crates/cli/tests/auto_rust_external_trait.rs`).

`results-1117-rust4`, with that change:

| Project | Targets | Now |
|---|---:|---|
| meilisearch | 9 | 7 resolve and are attempted; 2 are impls on a generic type |
| worldmonitor | 1 | `Default::default`, which takes no input |
| Kong | 1 | not discovered in this run (the ranking cap) |

The two generic impls are `impl<'a, C> BytesDecode<'a> for
FieldDocIdFacetCodec<C>` and one in `heed_codec/facet/mod.rs`. A harness
cannot choose the type argument. Their refusal now says so, as does the
`Default::default` one ("takes no input; nothing to fuzz"); both had been
reported as an outside trait.

The seven meilisearch decoders got past resolution and then hit, in turn:
1. The checkout had not been fetched, and the harness builds offline: "no
   matching package named `heed`". Fetching it is environment setup.
2. meilisearch's `bbqueue` is a git dependency with no rev, which the
   harness crate cannot resolve offline on its own. The harness crate's
   `Cargo.lock` now starts as the target's (its workspace's, else its own),
   which pins it and the versions the target was built with.
3. The staticlib then fails to link, with undefined monomorphized generics
   from dependencies (`core::slice::sort::...<i_overlay::...>`). That is a
   build class of its own, tracked in #409.

A decoder in meilisearch's `meilitool` crate, whose dependency graph is
smaller, built and fuzzed. Each milli harness compiles the crate's ~400
dependencies under ASan from scratch, so a full meilisearch rerun exceeds
the sweep's 1,800 s per-project cap. Recording the codecs' outcomes is part
of #409: [2026-11-20](2026-11-20-rust-generic-link.md) has the link fix and
a rerun of all 26 codec targets.

## Rust-1

expected-gaps.md said of building a parameter from `T::default()`: "measure
before assuming that is an improvement". It was measured. An owned parameter
of a crate type with a `Default` impl or derive that the lane can reach is
built from `T::default()`, as a `&T` parameter already was.

The first rerun ran it as an opt-in experiment. One target of the 42 changed:
RecordFlux's `Identifier::new(identifier: &str, location: Location)`. Its
build then stopped at `no matching package named annotate-snippets`. The
checkout pins Rust 1.77, whose `cargo fetch` filled a different registry
index cache than the nightly cargo the harness builds with. Fetched with the
nightly cargo, the target built, fuzzed and was entered, so the change is
kept, ungated.

The same project's other targets take `Option<String>` and `i128`. `Option<T>`
of a decodable `T` (a flag byte, then `T`) and `i128`/`u128` (16 bytes) now
decode. `Option<PathBuf>` does not: a path from fuzz bytes would point the
target at arbitrary files. The fixture `tests/fixtures/rust_default_params`
has one target of each kind with a planted bug, and each is found
(`crates/cli/tests/auto_rust_default_params.rs`).

| Rerun | Built and fuzzed | No decoder | Unsupported setup | Failed build |
|---|---:|---:|---:|---:|
| `results-1117-rust1`, before these changes | 4 | 13 | 20 | 3 |
| `results-1117-rust1-final`, with them | 5 | 12 | 20 | 3 |

These are the 42 targets' 40 rows. The 20 unsupported setups are targets
the in-crate lane (#244) admits but cannot set up; in 0728 all 42 were
Rust-1. The 12 left have no decoder:
- references to project types (`&Ty`, `&ProgramABI`);
- raw pointers (`*const c_void`);
- engine handles (`&mut v8::PinScope`, `Arc<AuthManager>`);
- `&Path`, and the `bytes` crate's `Bytes` (3).

A possible next step, untested: decode `Bytes` from a `Vec<u8>` once the
harness crate depends on `bytes`, as it now depends on a trait's crate.

## Reproduce

```sh
cargo build --release -p bhf -p bhf_runtrace_shim
cd benchmarks/campaign-2026-07-25
# The harness builds offline: fetch each checkout with the nightly cargo the
# lane uses, which a pinned rust-toolchain would otherwise override.
(cd /path/to/corpus/ada/AdaCore__RecordFlux && cargo +nightly fetch)
BHF_BIN=../../target/release/bhf python3 go1_rerun.py results-0728 OUT \
  --lang rust --class Rust-1 --all-lanes --run-untrusted --jobs 2
BHF_BIN=../../target/release/bhf python3 go1_rerun.py results-0728 OUT \
  --lang rust --class Rust-4 --all-lanes --run-untrusted --jobs 2
```
