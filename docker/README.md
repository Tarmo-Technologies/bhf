<!-- SPDX-License-Identifier: Apache-2.0 -->
# `docker/`: container assets for bhf

The image is built from the `Dockerfile` at the repository root.
This directory holds what goes into the image, the Compose files and the
validation sweep. The full guide is
[`docs/site/docker.md`](../docs/site/docker.md).

| File | Role |
|---|---|
| `../Dockerfile` | Multi-stage image. The default target carries bhf and the toolchains for all sixteen languages, AFL++, Rust nightly and SharpFuzz, and runs as the non-root user `fuzzer` under `tini`. `--target core` builds a C/C++-only image, `--target ada` adds GNAT and GPRbuild to it, and `--target validation` adds the sweep below. |
| `../.dockerignore` | Limits the build context to the Rust workspace and the runtime source trees. |
| `toolchain-platform.sh` | Checksum-pinned Go, Node.js and rustup archives for Linux x86-64 and ARM64. |
| `python-build-tools.txt` | Hash-pinned pip, setuptools, wheel and packaging for the full image. |
| `entrypoint.sh` | Dispatches `docker run IMAGE ...` to `bhf`, `bhf-daemon`, `bhf-sweep`, `bhf-fetch-corpus` or a shell; any other first word is a `bhf` subcommand. |
| `compose.yaml` | `docker compose` services with only the runtime grants fuzzing needs (`SYS_PTRACE`, `shm_size`); the `validation` profile builds and runs the sweep. |
| `compose.hardened.yaml` | An overlay for `compose.yaml`; stage the project's dependencies before using it. |
| `sweep-manifest.tsv` | The 32-project validation corpus: two small, SHA-pinned, real projects per language. |
| `fetch-corpus.sh` | Clones the manifest's projects at their pinned revisions (`bhf-fetch-corpus` in the image). |
| `bhf-sweep.sh` | Runs `bhf auto` across the corpus and writes a pass/fail report (`bhf-sweep` in the image). |
| `sweep_contract.py`, `test_sweep_contract.py` | Checks shared by the sweep and the corpus fetcher, and their tests (`python3 -m unittest discover -s docker -p 'test_*.py'`). |
| `language-smoke.sh`, `language-auto-smoke.sh`, `fixtures/` | Compiler and runtime checks for every language in the image, and small bhf-owned `bhf auto` controls. |
| [`compliance/`](compliance/README.md) | License notices, the OS-layer SBOM and the corresponding-source tools. |

## Quick start

```sh
# build the default image (from the repository root)
docker build -t bhf:local -f Dockerfile .

# fuzz your own tree
docker run --rm --shm-size=2g --cap-add=SYS_PTRACE \
  -v "$PWD":/src:ro -v bhf_work:/work \
  bhf:local auto /src --work-dir /work/run --per-target-time 60

# build the validation image and run the 32-project sweep (needs network)
docker build --target validation -t bhf:full-local -f Dockerfile .
docker run --rm --shm-size=2g --cap-add=SYS_PTRACE -v bhf_work:/work \
  bhf:full-local bhf-sweep --fetch
```

`docker compose -f docker/compose.yaml --profile validation run --rm sweep`
builds and runs the same sweep through Compose.

## Runtime privileges

Fuzzing needs two grants: `--cap-add=SYS_PTRACE` (LeakSanitizer and ASan
stop-the-world) and `--shm-size=2g` (coverage bitmaps and cmplog shared
memory). The container runs as UID 10001 and keeps the default seccomp
profile; under `compose.yaml` it also gets `cap_drop: ALL` and
`no-new-privileges`. The guide has the read-only root filesystem recipe and
the resource and troubleshooting notes.
