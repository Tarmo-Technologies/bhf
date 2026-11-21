<!-- SPDX-License-Identifier: Apache-2.0 -->
# Go lane re-sweep, 2026-11-16

This record re-runs the Go lane of the 2026-07-28 campaign sweep (`results-0728`): the same 40 Go projects, each cloned at the commit that sweep measured. It is acceptance test 5 of the [enterprise harness gap plan](../enterprise-harness-gap-plan.md), and it backs the Go rows of [expected-gaps.md](../expected-gaps.md). The bhf under test is a release build of the wave-6 branch (`bhf 0.3.0-dev`).

The rows are under `benchmarks/campaign-2026-07-25/`:

| Directory | What it is |
|---|---|
| `results-0728/` | Before: the 2026-07-28 sweep |
| `results-1116-go/` | After, on the sweep host's Go 1.22.2 |
| `results-1116-go-go1.27/` | After, on Go 1.27.4 |
| `results-1116-go1/` | The 59 targets `results-0728` skipped as Go-1, re-run by name, on Go 1.22.2 |
| `results-1116-go1-go1.27/` | The same 59, on Go 1.27.4 |

## Reproduce

```sh
cd benchmarks/campaign-2026-07-25
# The sweep, at the commits results-0728 measured (--pin):
BHF_BIN=<bhf> python3 run_sweep.py --wave FULL --per-lane 60 --corpus-only --only go \
  --jobs 2 --campaign-time 90 --per-target-time 3 --max-attempts 10 \
  --max-repair-rounds 4 --auto-slack 420 --results-dir <out> --pin results-0728 --rerun
# The 0728 Go-1 targets by name:
BHF_BIN=<bhf> python3 go1_rerun.py results-0728 <out-go1>
# The class histogram, before and after:
python3 go_resweep_compare.py results-0728 <out>
```

The Go 1.27.4 runs put that toolchain first on `PATH` with `GOTOOLCHAIN=local`.

## Residual histogram

Counted over the targets in `.go` sources, in the classes `expected-gaps.md` uses. Each project attempts its ten top-ranked targets (`--max-attempts 10`).

| Class | Before | After, Go 1.22.2 | After, Go 1.27.4 |
|---|---:|---:|---:|
| Go targets attempted | 256 | 261 | 253 |
| Built and fuzzed | 34 | 26 | 146 |
| Go-4: a module needs a newer `go` (environment) | 122 | 135 | 0 |
| Go-1: undrivable parameter type | 59 | 47 | 46 |
| Go-2: method needs a receiver | 23 | 17 | 17 |
| Go-2: receiver type unexported or generic | 0 | 10 | 10 |
| Failed build | 8 | 15 | 22 |
| Go-3: no `go.mod` | 10 | 10 | 10 |
| Built, target not entered | 0 | 1 | 2 |
| Findings, all lanes | 17 | 24 | 40 |

Four differences between the columns shape these numbers:

- **The toolchain decides most of it.** On Go 1.22.2, half the attempted targets stop at Go-4: a dependency needs `go >= 1.23` to `go >= 1.26.4`, and `GOTOOLCHAIN=local` refuses to fetch one. The before run had the same limitation (122). On Go 1.27.4 none do, and 146 targets build and fuzz.
- **The ten targets per project changed.** Ranking changed between the runs, and the Go-2 work made methods targets, so the before run and the Go 1.22.2 run attempted only 162 targets in common. Of those, 13 changed class:
  - 7 Go-2 receivers, which the after run reports with a more precise reason (unexported or generic receiver type);
  - 3 Go-1 targets that now pass the parameter check and stop at Go-4;
  - 1 Go-2 target that now fails its build;
  - v2ray's `DecodeJSONConfig`, now `built_not_entered`: its harness ran 305 inputs and none reached the target, which the before run did not check.
- **The same run varies.** Two runs on Go 1.22.2 at the same commits gave 22 and 26 built-and-fuzzed targets, and 9 and 15 failed builds, from timeouts and module-fetch failures.
- **Failed builds have no cause in these rows.** The sweep read a failed build's cause from `reason`, but bhf records it as `last_errors`. `run_sweep.py` now reads it, for the next run.

## Go-1: the resolved count

The histogram cannot say how many Go-1 targets are now drivable, because most of the 59 were not among the ten targets attempted again. `go1_rerun.py` re-runs exactly those 59 by name (`bhf auto --target`), at the same commits:

| Outcome now | Go 1.22.2 | Go 1.27.4 |
|---|---:|---:|
| Built and fuzzed | 1 | 7 |
| Past the parameter check, but a module needs a newer `go` | 6 | 0 |
| Still Go-1 | 52 | 52 |

**7 of the 59 resolved**: they pass the parameter check and fuzz on a current toolchain. They are frp's four `Decode*JSON` functions, Xray-core's `DecodePunchPacket`, headscale's `ParseIPSet` and multica's `BuildMultiThreadCommentReplyInstructions`. None found a bug in its budget.

The 52 that remain are split by parameter type:

| Parameter type | Targets |
|---|---:|
| A pointer to a struct (`*pflag.FlagSet`, `*zap.Logger`, `*gorm.DB`, `*tar.Reader`) | 24 |
| A named type from another package (`protocol.DeviceID`, `fuzzy.Source`, `http.Header`) | 15 |
| A named type of the same package (`Delimiter`, `ObjectID`, `Type`) | 8 |
| A map or slice of a non-byte type (`map[string]any`, `[]*store.KVPair`) | 5 |

Several of the named types are a basic type underneath (`type DeviceID [32]byte`, `type Attribute int`). Decoding a named type through its underlying type is the next Go-1 item.

## Findings and the harness-origin crash audit

`run_sweep.py` read each finding from `<work>/findings`, a layout bhf no longer writes, so no sweep before this one recorded what its findings were. It now reads `results/findings`, and records each finding's rule, crash frames and message. The before run's 17 findings cannot be audited.

The run summaries' finding counts (the table's last row) disagree with the finding directories in four projects; moby's summary counts 4 and its directory holds 1, and go-ethereum's counts 0 and holds 1. The audit below is of the directories: 23 on Go 1.22.2, 40 on Go 1.27.4.

On Go 1.22.2, 2 of the 23 findings are from Go harnesses, both in v2ray-core:

- `Go panic: qtls.ClientSessionState doesn't match`, raised in `qtls-go1-15.init.0`. A dependency's package `init` refuses the running Go version, before any input runs. This is environment-origin (#398).
- `crypto/hmac: hash generation function does not produce unique values`, from `vmess/aead.KDF`. Go 1.21 and later reject the hash constructor v2ray-core passes. This is a defect in the target under a current Go, but no input causes it.

The other 21 are in the projects' C, JavaScript, TypeScript and Python code. Six JS/TS findings are harness gaps: `ReferenceError: FileReader is not defined` (three), `app is not defined`, `store is not defined` and `Javy is not defined` name browser or host APIs the Node harness does not provide (#398).

On Go 1.27.4, 19 of the 40 findings are from Go harnesses:

| Kind | Findings | Origin |
|---|---:|---|
| A `Must*` function's documented panic: terraform `MustParseHash` (2), `MustParseVersion` (2), `MustParseProviderPart`; etcd `MustUnmarshalMessage`; headscale `MustParseNodeID`; multica `MustParseUUID`; gin `LoadHTMLGlob` through `template.Must` | 9 | Harness: the function panics on bad input by contract (#399) |
| v2ray-core's `qtls` package `init` | 1 | Environment (#398) |
| v2ray-core's `crypto/hmac` constructor | 1 | Target, under a current Go, independent of the input |
| An index, slice or nil fault, or a library panic, in a parser: Xray-core `encryption.DecodeHeader`, terraform `stackaddrs.ParseAbsComponentInstanceOnly`, lazygit `patch.Parse` and `oscommands`, lazydocker `commands` (2, one through `mgutz/str.ToArgv`), fzf `tui.HexToColor`, CLIProxyAPI `misc.antigravityBaseUserAgent` | 8 | Candidates for the target; not yet triaged against each project's callers |

So 11 of the 19 are not findings a user should act on. Both causes are now issues: #398 for a failure every input hits before the target, and #399 for a `Must*` contract panic. No crash is in generated harness code: every top frame is the project's or a dependency's. None comes from a zero-valued receiver either, since the sweep does not pass `--force`.
