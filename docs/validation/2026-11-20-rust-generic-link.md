<!-- SPDX-License-Identifier: Apache-2.0 -->
# Rust harnesses over dependency generics, 2026-11-20

Issue #409. The [2026-11-17 rerun](2026-11-17-rust-trait-and-param-classes.md)
left seven of meilisearch's heed codec decoders (`BytesDecode::bytes_decode`)
failing at the same step. Each harness crate built, and then clang could not
link its staticlib with bhf's driver. The undefined symbols were instances of
core's generics for a dependency's own types, such as
`core::slice::sort::stable::drift::sort::<i_overlay::bind::segment::IdSegment, ...>`.

## Cause

`nm` on the staticlib shows the instance defined as a local symbol (`t`) in
one of `i_overlay`'s object files and undefined (`U`) in two others. The
issue suggested rustc's generic sharing (`-Zshare-generics`) as the cause,
but switching it off does not fix the link. The failure needs three things
at once:
- SanitizerCoverage's trace-pc-guard instrumentation;
- ASan;
- the ThinLTO rustc runs across a crate's codegen units when it optimizes.

The harness crate builds at `opt-level = 1`, so that ThinLTO pass runs, and
it made the instance local to one codegen unit while another still called it.

Measured with rustc 1.98.0-nightly (485ec3fbc 2026-06-10, LLVM 22.1.6), at
`opt-level = 1` unless a row says otherwise. The first column is a harness
staticlib that calls `i_overlay` 2.0.5's float overlay, `i_overlay` being
the crate in the reported failure. The second is the fixture below.

| `RUSTFLAGS` | `i_overlay` harness | fixture |
|---|---|---|
| bhf's flags before the fix (trace-pc-guard, trace-compares, ASan) | 18 undefined references | 27 undefined references |
| the same, plus `-Zshare-generics=n` | 20 undefined references | not run |
| ASan alone | links and runs | not run |
| the sancov flags alone | links and runs | not run |
| bhf's flags at `opt-level = 0` | links and runs | not run |
| bhf's flags, plus `-Ccodegen-units=1` | links and runs | not run |
| bhf's flags, plus `-Clto=off` | links and runs | links and runs |
| the libFuzzer flag set (inline-8bit-counters, pc-table) | links and runs | links and runs |

The fixture needs the generic layer to fail. With the dependency calling
`sort_by` directly instead of through another crate's generic method, the
same flags link.

## Change

bhf's Rust flags gain `-Clto=off`. The external and in-crate Rust builds,
`build-afl.sh` and a capsule's rebuild all use them. The capsule had its own
copy of the flags; it now takes the lane's and records them in its
manifest's `build_recipe.rustflags`. The libFuzzer build script keeps its
flags, which link either way.

The fixture `tests/fixtures/rust_generic_dep` has a target crate (`app`)
whose dependency (`shapes`) sorts its own type, from three modules, through
a generic method of a third crate (`keysort`).
`crates/cli/tests/auto_rust_generic_dep.rs` runs `bhf auto` on it. Before the
change the target ended as `failed_build`, with `undefined_symbol` errors for
`drift::sort::<Segment, ...>`. After it, the target builds and fuzzes, and the
planted out-of-bounds index is found.

## meilisearch

`bhf auto --target bytes_decode` finds 25 candidates in `crates/milli` at
b884653f and one more, `UuidCodec`, in `crates/index-scheduler`. All 26
were rerun with a debug build of bhf that includes the change. The seven
decoders that the 2026-11-17 rerun left failing at the link are among them.
None of the 26 fails at the link:
- 22 build;
- 3 are refused as impls on a generic type, which need a type argument
  (`FieldDocIdFacetCodec<C>`, `FacetGroupKeyCodec<T>`, `SynonymsKeyCodec<S>`);
- `EmbedderInfoCodec` in `vector/db.rs` fails to compile, not to link. The
  struct is private to its module, so the external harness crate cannot
  name it (`E0603`).

Each harness compiles milli's ~400 dependencies with ASan. Built from
scratch for every harness, as bhf does, that took 15 to 20 minutes per
harness on the shared 6-core host. The first three candidates ran that way.
For the other 23, each harness's `rust_harness` directory was a symlink to a
directory whose `target` pointed at one shared cargo target directory. The
dependencies then compiled once, and each later harness built in about a
minute. bhf's build commands and flags were unchanged.
`BHF_KEEP_BUILD_ARTIFACTS=1` stopped bhf from removing the links after each
build. Each `bhf auto` call was capped at 570 s, and the next one continued
it with `--resume`.

| Codec | Source (`crates/milli/src/heed_codec/`) | `--per-target-time` | `bhf auto` | `bhf fuzz` on the built harness, 90 s |
|---|---|---:|---|---|
| `BEU16StrCodec` | `beu16_str_codec.rs` | 20 | built, not entered | 22 executions; `split_at` panic |
| `BEU32StrCodec` | `beu32_str_codec.rs` | 20 | built, not entered | 1,762 executions, 51 edges; `split_at` panic |
| `BytesRefCodec` | `byte_slice_ref.rs` | 20 | 15,055 executions, 35 edges | not run |
| `FacetGroupValueCodec` | `facet/mod.rs:108` | 90 | 1 execution, 22 edges; index panic | not run |
| `FacetGroupLazyValueCodec` | `facet/mod.rs:120` | 90 | built, not entered | 69,364 executions, 40 edges; index panic |
| `OrderedF64Codec` | `facet/ordered_f64_codec.rs` | 90 | built, not entered | 78,728 executions, 46 edges |
| `FieldIdWordCountCodec` | `field_id_word_count_codec.rs` | 90 | built, not entered | 90,450 executions, 64 edges |
| `U8StrStrCodec` | `str_str_u8_codec.rs:14` | 90 | built, not entered | 100,504 executions, 55 edges |
| `UncheckedU8StrStrCodec` | `str_str_u8_codec.rs:41` | 90 | built, not entered | 88,818 executions, 47 edges |
| `VersionCodec` | `version.rs` | 90 | built, not entered | 54,902 executions, 50 edges |
| `UuidCodec` | `crates/index-scheduler/src/uuid_codec.rs` | 90 | 20,144 executions, 43 edges | not run |
| `FstSetCodec`, `ObkvCodec`, `StrBEU32Codec`, `StrBEU16Codec`, `StrRefCodec` and the six roaring bitmap codecs | `fst_set_codec.rs`, `obkv_codec.rs`, `str_beu32_codec.rs`, `str_ref.rs`, `roaring_bitmap/`, `roaring_bitmap_length/` | 30 | built, not entered | not run |
| `FieldDocIdFacetCodec<C>`, `FacetGroupKeyCodec<T>`, `SynonymsKeyCodec<S>` | `facet/field_doc_id_facet_codec.rs`, `facet/mod.rs:85`, `synonyms_key_codec.rs` | 30 | refused: generic type | not run |
| `EmbedderInfoCodec` | `crates/milli/src/vector/db.rs` | 30 | failed to compile: private struct (`E0603`) | not run |

The findings are panics on short input. `bytes.split_at(2)` (or
`split_at(4)`) in the two string codecs panics with `mid > len` when the
input is shorter than the integer prefix. The two facet group value codecs
read `bytes[0]`, which panics on an empty input.

"Built, not entered" means the harness got no execution within a pass,
whose budget is a third of `--per-target-time`. Under `bhf fuzz`, the eight
such harnesses run there made their first execution 22 to 40 s after the
start. The six in the 90 s rows then ran at about 400 to 1,000 executions a
second. Run directly on one input, the `FacetGroupLazyValueCodec` harness
takes 0.2 s. Two stack samples of the debug bhf, taken 7 s and 13 s into a
`bhf fuzz` run of the `OrderedF64Codec` harness, were both in
`protocol_detect::scan_markers`. That function reads the whole harness
binary, about 1 GB with debug information, looking for runtime markers.
`BytesRefCodec` was entered within its first 6 s pass; why it started
sooner was not measured, nor was a release build of bhf.

## Reproduce

```sh
cargo test -p bhf --test auto_rust_generic_dep
cargo build -p bhf
target/debug/bhf auto --run-untrusted --target bytes_decode --jobs 1 \
  --per-target-time 90 --max-work-dir-mb 0 \
  /path/to/corpus/rust/meilisearch__meilisearch/crates/milli --work-dir WORK
target/debug/bhf fuzz --harness HARNESS_ID --time 90s WORK
```
