<!-- SPDX-License-Identifier: Apache-2.0 -->
# Py-2 receiver re-run, 2026-11-18

This record re-runs, by name, every Python target that the 2026-07-28
campaign sweep (`results-0728`) skipped because its class's `__init__` takes
arguments:
`only no-arg-constructible receivers are supported`. That is the Py-2 class of
[expected-gaps.md](../expected-gaps.md). Each project is re-run at the commit
that sweep measured. The bhf under test is a release build of the wave-11
branch, which builds the receiver from its decoded `__init__` arguments (#286).

The rows are under `benchmarks/campaign-2026-07-25/`:

| Directory | What it is |
|---|---|
| `results-0728/` | Before: the 2026-07-28 sweep |
| `results-1118-py2/` | After: the 21 targets, in 11 projects |

## Reproduce

```sh
cd benchmarks/campaign-2026-07-25
BHF_BIN=<bhf> python3 go1_rerun.py results-0728 results-1118-py2 \
  --lang python --class Py-2 --all-lanes
```

`--all-lanes` reads every lane's rows: half of these targets are in projects
the sweep chose for another language (pix2pix's data loaders, xmake's
generator, caffe's Python bindings).

## Before and after

| | Before | After |
|---|---:|---:|
| Py-2 targets re-run | 21 | 21 |
| Skipped: the receiver needs constructor arguments | 21 | 0 |
| Built and fuzzed | 0 | 6 |
| Not loadable: a module the project needs is not installed | 0 | 10 |
| Not loadable: tabs and spaces mixed in its indentation (`TabError`) | 0 | 1 |
| A constructor argument of a type bhf cannot build | 0 | 3 |
| Not discovered | 0 | 1 |

Built and fuzzed: pix2pix's `cityscapes.load_image` and `load_label`,
xmake's `XmakeGenerator.filename`, system-design-primer's `HashTable.set`,
the skills repository's `ReviewHandler.log_message` (a `Path` argument) and
browser-use's `FileSystem.read_file` (`str | Path`).

What stops the rest:

- **A missing dependency** (10): `werkzeug` for flask (4), `bubus` for
  browser-use (2), the compiled `caffe._caffe` (2), `colour` for manim and
  `mrjob` for system-design-primer. With the receiver built, these targets
  reach the import that the July sweep never got to. They need that
  dependency installed.
- **A constructor argument bhf cannot build** (3): an object of the
  project's own class (manim's `scene: Scene`, flask's `app: App`), and
  markitdown's `client: Any`. bhf builds scalars, `str`, `bytes`,
  containers, streams, paths and unions with one of those.
- AdaCore/aws's `aws.py` mixes tabs and spaces in its indentation, which
  Python 3 refuses (`TabError`).
- Kong's `Plugin.access` is in `spec/fixtures/`, which discovery has skipped
  by default since the July sweep.

## What it took

Building the receiver from its decoded arguments reached 4 of the 21. Two
more changes brought it to 6:

- **Unions and paths.** `str | Path` and `str | os.PathLike[str]` are decoded
  as their first member bhf can build, and a `Path` annotation as a
  `pathlib.Path` of decoded text. This also fixes a method parameter
  annotated `Optional[str]`, which got raw bytes.
- **A late import is the environment.** pix2pix's `cityscapes.__init__`
  imports a `labels` helper module that is not installed. The driver
  reported its `ModuleNotFoundError` as a finding of the target. An
  `ImportError` is now an environment rejection, as an `OSError` is.

The re-run reported no findings.
