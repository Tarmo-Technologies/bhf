<!-- SPDX-License-Identifier: Apache-2.0 -->
# Go targets outside a module (Go-3), 2026-11-16

This record re-runs, by name, every Go target the 2026-07-28 campaign sweep
(`results-0728`) skipped as Go-3, `target is not inside a Go module (no go.mod
found)`. It backs the Go-3 entry of [expected-gaps.md](../expected-gaps.md).
Each project is cloned at the commit that sweep measured. The bhf under test is
a release build of the wave-8 branch (`bhf 0.3.0-dev`), on the sweep host's
Go 1.22.2.

The harness imports its target through a module `replace`, which needs a
directory holding a `go.mod`, so a target outside every module was skipped.
bhf now copies the target's package into the harness directory (`bhf_target/`)
with a `go.mod` of its own:
- a `package main` is renamed in the copy, so it can be imported;
- from a directory of `go run` scripts, each with its own `main`, only the
  target's file is copied;
- each copied file opens with a `//line` directive, so a finding names the
  project's file and line.

The rows are in `benchmarks/campaign-2026-07-25/results-1116-go3/`.

## Reproduce

```sh
cd benchmarks/campaign-2026-07-25
BHF_BIN=<bhf> python3 go1_rerun.py results-0728 results-1116-go3 --class Go-3 --all-lanes
```

`--all-lanes` reads every lane's rows. Three of the four projects were in the
sweep for another language and hold Go code too, so a Go-lane-only count
(the [Go re-sweep](2026-11-16-go-resweep.md) counted 10) misses them.

## Result

| Project (sweep lane) | Target | Before | After |
|---|---|---:|---:|
| astaxie/build-web-application-with-golang (go) | `FixHeader`, `RemoveFooterLink` in `build.go` and `build_new.go` | 10 skipped | 10 built and fuzzed |
| hashicorp/vagrant (ruby) | `Asset`, `AssetDir`, `AssetInfo`, `MustAsset` in `locales.go` | 4 skipped | 4 built and fuzzed |
| xmake-io/xmake (lua) | `Add` in `add.go` | 1 skipped | 1 built and fuzzed |
| xiaojieonly/Ehviewer_CN_SXJ (c) | `WebPGetInfo`, `Wrapped_WebPGetInfo` in `libwebp.go` | 2 skipped | 2 failed builds |
| **Total** | | **17 skipped, 0 built** | **15 built and fuzzed, 2 failed builds** |

- **astaxie** is a book. Each language directory holds one or more
  `package main` programs, run one at a time with `go run build.go`. In `zh/`
  and `zh-tw/`, the three programs each declare `main`, and two of them
  declare `FixHeader`, so together they do not form one package. By name, bhf
  now finds these functions in 14 places, more than the 10 the capped sweep
  attempted, and all 14 build and fuzz. While the copy still took every file
  of such a directory, 8 of the 14 failed to build on the second declaration
  of `main`.
- **vagrant**'s `locales.go` is a go-bindata asset file. The Ruby project
  has no Go module.
- **xmake**'s `add.go` is the library package of an example Go project, with
  no module.
- **Ehviewer**'s `libwebp.go` is a SWIG binding: `libwebp.swig` is in the
  same directory, and `go build` runs `swig` on it (`exec: "swig": executable
  file not found in $PATH`). This host has no `swig`, so this is ENVIRONMENT.

## Findings

One, in vagrant: `MustAsset` panics `asset: Asset(): Asset  not found` for
a name that is not an asset. A `Must*` function panics on bad input by
contract, so a user does not need to act on it (#399).
