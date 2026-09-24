<!-- SPDX-License-Identifier: Apache-2.0 -->
# `docker/` — container assets for bhf

The image itself is built from the repo-root [`Dockerfile`](../Dockerfile). This
directory holds everything that goes *into* the image plus the convenience
compose file. Full usage guide: **[docs/site/docker.md](../docs/site/docker.md)**.

| File | Role |
|---|---|
| `../Dockerfile` | Multi-stage, hardened image: builds bhf, installs all 16 language toolchains + AFL++ + Rust nightly + SharpFuzz, runs as non-root `fuzzer` under `tini`. |
| `../.dockerignore` | Keeps the build context to the Rust workspace + runtime source trees. |
| `entrypoint.sh` | Dispatches `docker run IMAGE …` to `bhf` / `bhf-daemon` / `bhf-sweep` / a shell. |
| `sweep-manifest.tsv` | The 32-project validation corpus — 2 small, SHA-pinned, real projects per language. |
| `fetch-corpus.sh` | Clones the manifest's projects at their pinned revisions (`bhf-fetch-corpus`). |
| `bhf-sweep.sh` | Runs `bhf auto` across the corpus and writes a pass/fail report (`bhf-sweep`). |
| `compose.yaml` | `docker compose` with exactly the fuzzing runtime grants (`SYS_PTRACE`, `shm_size`) and nothing else. |

## Quick start

```sh
# build
docker build -t bhf:local -f Dockerfile .            # from the repo root

# fuzz your own tree
docker run --rm --shm-size=2g --cap-add=SYS_PTRACE \
  -v "$PWD":/src:ro -v bhf_work:/work \
  bhf:local auto /src --work-dir /work/run --per-target-time 60

# run the reproducible 32-project validation sweep
docker run --rm --shm-size=2g --cap-add=SYS_PTRACE -v bhf_work:/work \
  bhf:local bhf-sweep --fetch
```

## Runtime privileges, briefly

Fuzzing needs two grants and no more: `--cap-add=SYS_PTRACE` (LeakSanitizer /
ASan stop-the-world) and `--shm-size=2g` (coverage bitmaps + cmplog shm). The
container runs as UID 10001, keeps the default seccomp profile, and under
`compose.yaml` also `cap_drop: ALL` + `no-new-privileges`. See the guide for the
read-only-rootfs recipe and the resource/troubleshooting notes.
