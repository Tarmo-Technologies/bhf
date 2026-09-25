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
installs the toolchains. The runtime carries all sixteen lanes + .NET 8 SDK +
a headless JDK + Maven; scope it down further by deleting unused `apt` lanes from
the `Dockerfile` if you only fuzz a few languages — an absent toolchain simply
skips. The Java lane uses Maven + `javac`; **Gradle is intentionally omitted** to
keep the image small (it pulls a large GUI-adjacent dependency tree). Add
`gradle` back to the `Dockerfile` if you need Gradle-project build recovery.

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

## Air-gapped / offline use

The image is built so that **bhf's own instrumentation dependencies are staged at
build time** — no lane reaches the internet to fuzz on a disconnected host:

- **Java** — the JVM coverage agent shades ASM. `build-agent.sh` would otherwise
  fetch `asm`/`asm-tree` from Maven Central; the image installs them
  (`libasm-java` → `/usr/share/java`) and sets `ASM_JAR_DIR=/usr/share/java`, so
  the agent builds offline.
- **C#** — the harness references `SharpFuzz`; the image primes the default NuGet
  cache with it at build time.

What the image **cannot** stage for you is your *target project's own* build
dependencies. Air-gapped fuzzing of a real project means bringing those across
the gap, exactly as you already do to build the project by hand:

| Lane | Stage on the host (mount into the container) |
|---|---|
| Java (Maven) | your `~/.m2` repository; run `mvn -o` |
| Java (Gradle) | your Gradle cache (and add `gradle` to the image) |
| C# | the target's NuGet packages into `NUGET_PACKAGES` (SharpFuzz is already cached) |
| Rust | `cargo vendor` output + a `.cargo/config.toml` pointing at it |
| Go | a vendored module tree or a populated `GOMODCACHE` |
| Node/TS | the target's `node_modules` |

With those staged, run with `--network none` to prove the run is truly offline:

```sh
docker run --rm --network none --shm-size=2g --cap-add=SYS_PTRACE \
  -v "$PWD":/src:ro -v "$HOME/.m2":/home/fuzzer/.m2 -v bhf_work:/work \
  bhf:local auto /src --work-dir /work/run --build-command "mvn -o -B clean compile"
```

## Using a compile_commands.json

For C/C++, a `compile_commands.json` (clang compilation database) gives bhf the
real translation-unit flags. bhf uses it automatically — you do **not** need
`--probe-build` when you already have one:

- Put it in the **project root** or a **`build/` subdirectory**. A symlink at
  either location is followed. bhf discovers it and builds each harness with the
  recorded flags.
- `--probe-build` is only for *regenerating* a database by running the project's
  own build; it writes to `<tree>/.bhf-build/compile_commands.json`. If you place
  your own database there and regeneration then fails (e.g. offline), bhf now
  **keeps and uses your database** instead of discarding it — but the simplest
  path is to drop it in the project root and run without `--probe-build`.

## The 32-project sweep

The image bakes a reproducible validation sweep: two small, pinned, real
projects per language (32 total). A passing sweep demonstrates observed entry
into at least one non-stub target in every selected project. It does not prove
complete API coverage, useful coverage feedback in every lane, or competitive
fuzzing effectiveness.

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
Results must be a new or empty directory: reruns refuse to overwrite evidence.
Choose a new `BHF_SWEEP_RESULTS` for each run. Empty selections, partial or
malformed JSON reports, missing/dirty/unpinned checkouts, stub-only campaigns,
unentered targets and timeouts fail the gate. The machine-readable `auto/run.json`
is authoritative, not text-summary keyword matching. Reported edges sum each
entered target's peak counter (not a global union); findings count per-pass
observations, not unique bugs. Zero feedback remains visible in the report.

Corpus fetching verifies existing clones against the full manifest commit and
rejects modified or extra inputs rather than deleting them. Build recovery may
modify a checkout, so repeated validation may require a fresh `BHF_CORPUS` as
well. Custom manifests require six tab-separated columns, unique safe identifiers,
full lowercase commit hashes and relative in-tree source paths; use `-` for
unused source paths or flags. These checks do not sandbox target build commands:
run untrusted projects only inside an appropriately isolated container.

## Licensing & redistribution

The image **aggregates independent programs** on one medium. bhf itself is
Apache-2.0 and runs the bundled toolchains as **subprocesses** — it does not link
their GPL code, so aggregating them does not place bhf under the GPL (mere
aggregation, GPLv2 §2 / GPLv3 §5). AFL++ is predominantly Apache-2.0.

bhf is distributed as **source** and publishes **no prebuilt images**, so the
project distributes no GPL/LGPL binaries and owes no corresponding-source offer —
you build the image, and Ubuntu is the distributor of the packages it pulls.
The duty only arises **if you choose to redistribute the built image** (push it
to a registry, ship a `docker save` tarball): then you make the GPL/LGPL
corresponding source available (the GNU compilers/tools, OpenJDK, glibc, AFL++'s
gcc-pass file). The image is built to make that turnkey — under
`/usr/share/bhf/licenses/` (and an SBOM under `/usr/share/bhf/sbom/`):

| File | Purpose |
|---|---|
| `THIRD_PARTY_NOTICES.md` | every package → version → source → declared license(s) |
| `COPYLEFT-SOURCES.txt` | `source=version` for just the GPL/LGPL packages |
| `WRITTEN-OFFER.md` | the written offer — **add your contact before distributing** |
| `fetch-sources.sh` | downloads the matching Ubuntu source for those packages |

Full per-package license text is retained at `/usr/share/doc/<pkg>/copyright`.
To fulfil the offer:

```sh
docker run --rm --user 0 -v "$PWD/corresponding-source":/out bhf:local \
  bash /usr/share/bhf/licenses/fetch-sources.sh \
       /usr/share/bhf/licenses/COPYLEFT-SOURCES.txt /out
```

To shed the GPLv3/GPLv2 **compilers**, drop the Ada, COBOL, and Fortran `apt`
lanes from the `Dockerfile` (you keep clang for C/C++); `make`/`glibc` remain.
See `docker/compliance/README.md`.

**Deploying to accredited/classified environments?** See
[ATO / RMF posture](./ato.md) — control crosswalk (800-53/800-190), the air-gap
proof, the honest vulnerability posture (scan the OS layer + bhf, not the
build-toolchain caches), and how to build a minimal least-functionality image.

## Troubleshooting

- **`LeakSanitizer has encountered a fatal error`** — add `--cap-add=SYS_PTRACE`,
  or export `ASAN_OPTIONS=detect_leaks=0` if you do not need leak detection.
- **cmplog/coverage errors, `/dev/shm` full** — raise `--shm-size`.
- **Killed / OOM under `--memory`** — lower `--jobs` and `--rss-limit-mb`, or
  raise the cap. bhf records an analysis gap when it hits the RSS ceiling.
- **A language target is skipped** — that toolchain is not installed in your
  scoped image, or the project has no fuzzable entry point in that language.
