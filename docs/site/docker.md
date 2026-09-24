<!-- SPDX-License-Identifier: Apache-2.0 -->
# Running bhf in Docker

The container carries the CLI, the daemon, both Linux shims, and every one of
the sixteen language toolchains bhf can build, harness, and fuzz — plus AFL++
and a Rust nightly for the Rust sanitizer lane. It runs as an unprivileged user
under `tini`, and grants fuzzing the two extra runtime privileges it needs and
nothing more.

## Build

```sh
# from the repo root
docker build -t bhf:local -f Dockerfile .
# or
docker compose -f docker/compose.yaml build
```

The build is multi-stage: a builder compiles the Rust workspace against Ubuntu
24.04 glibc (so the preload shims match the runtime), and the runtime image
installs the toolchains. The final image is large (all sixteen lanes + .NET SDK
+ JDK/Maven/Gradle); scope it down by deleting unused `apt` lanes from the
`Dockerfile` if you only fuzz a few languages — an absent toolchain simply skips.

## Run

```sh
docker run --rm \
  --shm-size=2g \
  --cap-add=SYS_PTRACE \
  -v "$PWD":/src:ro \
  -v bhf_work:/work \
  bhf:local auto /src --work-dir /work/run --per-target-time 30
```

Anything after the image name is passed to `bhf` (the entrypoint also accepts
`bhf`, `bhf-daemon`, `bhf-sweep`, `bash`). Read `/work/run/FINDINGS.md` first.

## Why fuzzing needs those two flags

A fuzzer needs a little more than a hardened default container gives it. Grant
exactly this, no more:

| Flag | Why | Symptom if missing |
|---|---|---|
| `--cap-add=SYS_PTRACE` | LeakSanitizer / ASan stop-the-world at process exit | `LeakSanitizer has encountered a fatal error` / degraded ASan reports |
| `--shm-size=2g` | Coverage bitmaps and cmplog shared-memory maps | slow/again-and-again restarts, cmplog disabled, OOM on `/dev/shm` |

Everything else stays locked down: the image runs as UID 10001 (`fuzzer`), keeps
the default seccomp profile, and under `docker/compose.yaml` also runs with
`cap_drop: ALL` (then re-adds only `SYS_PTRACE`) and `no-new-privileges`. bhf
already exports `AFL_SKIP_CPUFREQ=1` and
`AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1` so the AFL lane does not depend on the
host's (non-namespaced) `kernel.core_pattern` or CPU governor.

For a read-only root filesystem:

```sh
docker run --rm --read-only \
  --tmpfs /tmp:exec --shm-size=2g --cap-add=SYS_PTRACE \
  -v bhf_work:/work -v "$PWD":/src:ro \
  bhf:local auto /src --work-dir /work/run
```

`/tmp` needs `exec` because some lanes compile and run harnesses staged there.

## Resources

bhf scales its memory budgets to the cgroup limit, so a `--memory` cap is
honoured. Budget at least `jobs × rss-limit-mb` for fuzz children plus headroom
for discovery, compilers, and reports. On a memory-capped container prefer a
serial sweep (`--jobs 1`) and set `--rss-limit-mb` explicitly. See
[Resource Requirements](../../README.md#resource-requirements).

## The 32-project sweep

The image bakes a reproducible validation sweep: two small, pinned, real
projects per language (32 total). It proves every lane can build, harness, and
fuzz inside the container.

```sh
docker run --rm --shm-size=2g --cap-add=SYS_PTRACE \
  -v bhf_work:/work \
  bhf:local bhf-sweep --fetch          # --fetch clones the pinned corpus first
```

Outputs land under `/work/results/`: `sweep-report.md`, `sweep-report.tsv`, and
a per-project work dir. Tune the budget with `BHF_PER_TARGET_TIME`,
`BHF_MAX_TARGETS`, `BHF_CAMPAIGN_TIME`, `BHF_JOBS`, and filter languages with
`BHF_LANGS="c cpp rust"`. The corpus manifest is
`/usr/local/share/bhf/sweep-manifest.tsv`; override with `BHF_SWEEP_MANIFEST`.

## Troubleshooting

- **`LeakSanitizer has encountered a fatal error`** — add `--cap-add=SYS_PTRACE`,
  or export `ASAN_OPTIONS=detect_leaks=0` if you do not need leak detection.
- **cmplog/coverage errors, `/dev/shm` full** — raise `--shm-size`.
- **Killed / OOM under `--memory`** — lower `--jobs` and `--rss-limit-mb`, or
  raise the cap. bhf records an analysis gap when it hits the RSS ceiling.
- **A language target is skipped** — that toolchain is not installed in your
  scoped image, or the project has no fuzzable entry point in that language.
