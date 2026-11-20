<!-- SPDX-License-Identifier: Apache-2.0 -->
# Zoxide harness-parity row with the in-crate lane, 2026-11-17

The expert harness for zoxide
(`benchmarks/harness-parity-200/expert/rust/zoxide_db.rs`) runs inside the
crate, materializes a database file and calls `Database::open_dir`, which lives
in the private `db` module. In the 2026-10-03 audit, auto could reach only
zoxide's public surface from a separate crate, so this was the one expert
setup capability auto lacked (see
[FINDINGS.md](../../benchmarks/harness-parity-200/FINDINGS.md)). This record
reruns the row with the in-crate lane (`--rust-private`), on zoxide at the
pinned `cf086b057dfcc7c306450c70829b2788a3e64219`.

The binary is a release build of the wave-9 branch with this change's code,
`bhf v0.3.0-dev+fb6f2da9`, SHA-256
`6338815f1c315af52f94a467188cc3e1e4d10f10dab9034aa768fb98a8fe2db0`. Both rows
record it. The artifacts are in
`benchmarks/harness-parity-200/rows-2026-11-17-zoxide/`.

## Reproduce

```sh
cargo build --release -p bhf -p bhf_runtrace_shim
# The in-crate build runs Cargo offline: fetch zoxide's dependencies first,
# in the checkout run.py keeps under <out>/sources/.
(cd <out>/sources/rust__ajeetdsouza__zoxide && cargo fetch)
python3 benchmarks/harness-parity-200/run.py --only ajeetdsouza/zoxide \
  --keep-sources --output <out> \
  --bhf-arg=--rust-private --bhf-arg=--run-untrusted
python3 benchmarks/harness-parity-200/run.py --only ajeetdsouza/zoxide \
  --keep-sources --output <out-open_dir> --seconds 30 \
  --bhf-arg=--rust-private --bhf-arg=--run-untrusted \
  --bhf-arg=--target --bhf-arg=open_dir
```

`--bhf-arg` passes an argument to every `bhf auto` the runner starts, and the
row records them. Before the `cargo fetch`, the in-crate build stopped at
`no matching package named askama found`.

## Result

| Row | Endpoint | Target entry | Body edges | Executions |
|---|---|---|---:|---:|
| Auto's own choice (`auto.json`) | `Database::deserialize(&[u8])`, private, in `src/db/mod.rs` | checkpoint | 754 | 29,456 |
| The expert's endpoint (`open_dir.json`, `--target open_dir`) | `Database::open_dir(impl AsRef<Path>)`, in the private `db` module | checkpoint | 961 | 86,076 |

Both rows build, fuzz and enter the endpoint, and its body is covered. Neither
has a finding.

Left to choose, auto ranks the byte decoder `deserialize` above the
directory opener `open_dir`, so the two rows' endpoints differ. The difference
is now a ranking choice, as in the COBOL and PHP rows: run with
`--target open_dir`, auto drives the expert's endpoint with the expert's
setup.

### The resource

`resource_recipe.json` is the recipe the lane recorded beside the harness:
`crate::db::Database::open_dir` is a directory opener, and each input is a
temporary directory seeded with `db.zo` as the file. That directory is under
the runner's per-harness scratch directory, which the runner sweeps after each
run.

The campaign's runtrace skips opens inside bhf's own work directory, where the
resource lives, so that bhf's own instrumentation files do not trip the
oracles. It does log the cleanup of each case's `db.zo`: 92,370 unlinks over
the run. `replay-runtrace.jsonl` is one corpus input (1,796 bytes) replayed
through the harness under the runtrace shim, with its scratch directory
outside the work directory. It records:
1. the case's directory created;
2. `db.zo` opened, as the harness writes the input into it;
3. `db.zo` opened again, as `open_dir` reads it;
4. the directory removed.

The target-entry checkpoint reads `01`.

## What the rerun fixed

- Auto's top-ranked zoxide endpoint, `Database::deserialize`, did not compile
  (E0624, `associated function deserialize is private`). The lane declared
  its harness module at the crate root. A private associated function is
  visible only inside its module and the module's descendants, so the
  harness module is now declared beside the file that defines the target. A
  new fixture, `rust_incrate_private_assoc` (`Store::decode` in
  `src/store/mod.rs`), covers it.
- The first `open_dir` run reported a BHF-416 (insecure permissions) for the
  harness's own `mkdir(<case dir>, 0777)`. The umask makes that directory
  `0755`, and the shim now tests the mode a directory was created with
  (#407).
