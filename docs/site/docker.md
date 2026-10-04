<!-- SPDX-License-Identifier: Apache-2.0 -->
# Running bhf in Docker

The default `core` image carries the CLI, daemon, Linux shims, and C/C++ build
and fuzz tools. The opt-in `runtime` image adds the full language toolchains,
AFL++, and Rust nightly. Both build the production binaries without the optional
`llm` Cargo feature. Each runs as an unprivileged user
under `tini`, and grants fuzzing the two extra runtime privileges it needs and
nothing more.

## Build

```sh
# from the repo root
docker build -t bhf:local -f Dockerfile .
# full-language image (explicit):
docker build --target runtime -t bhf:full-local -f Dockerfile .
# selected Ada tooling on top of core:
docker build --target ada -t bhf:ada-local -f Dockerfile .
# or build the core image through Compose:
docker compose -f docker/compose.yaml build
# Explicit validation only:
docker compose -f docker/compose.yaml --profile validation run --rm sweep
# From a clean commit, stamp a local release candidate with version and source:
scripts/build-container-release.sh bhf:release-candidate
```

The image currently supports `linux/amd64` only, matching its checksum-pinned
Go archive. The release script refuses dirty checkouts and supplies the same
version and commit to the binary and image metadata. The build context comes
from `git archive HEAD`, excluding untracked and ignored local files. An optional
second argument selects `core`, `ada`, or `runtime`. Its `local_image_id` identifies
the local image configuration, and is distinct from a registry manifest digest.

The builder compiles only the release binaries and Linux shims against Ubuntu
24.04 glibc. The default final stage inherits `core`, with C/C++ tools. The named
`runtime` target carries all sixteen lanes + .NET 8 SDK + a headless JDK + Maven.
Gradle is omitted from the full image; add it to that stage for Gradle-project
build recovery. The full language validation sweep uses `runtime` explicitly.

| Profile | Included build tools | Executed acceptance |
|---|---|---|
| `core` (default) | C/C++ with Clang/LLVM | Non-root, read-only, disconnected C fixture in the actual image |
| `ada` (explicit) | Core plus GNAT/GPRbuild | Non-root, read-only, disconnected Ada compiler smoke; broader project acceptance remains project-specific |
| `runtime` (explicit) | All sixteen language toolchains except Gradle project recovery | Bare Java and staged Maven fixture under a read-only, disconnected profile; other lanes need separate hardened-profile evidence |
| FreeRTOS reference | Separate pinned kernel, ARM GCC, QEMU | Cooperative task/queue image, clean → fault → clean, retained finding and replay; no physical-board claim |

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

In the full-language `runtime` image, the JVM coverage-agent JAR is prebuilt
into an immutable image path. Java
projects with Maven or Gradle build files still need a writable, disposable
source staging copy because those tools write build outputs into their module.
Mount that copy at `/src` for the Java project path. A bare `javac` project can
use a read-only `/src` mount.

For a read-only root filesystem and a bare source fixture:

```sh
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,exec,nosuid,size=1g --shm-size=2g \
  --memory=4g --pids-limit=512 --cap-drop=ALL --cap-add=SYS_PTRACE \
  --security-opt no-new-privileges:true \
  -v bhf_work:/work -v "$PWD":/src:ro \
  bhf:local auto /src --work-dir /work/run --jobs 1
```

`/tmp` needs `exec` because some lanes compile and run harnesses staged there.
The 4 GB / 512-process envelope was exercised with the small C acceptance
fixture; size these limits for the target project before using this profile.

The equivalent supported Compose override is:

```sh
docker compose -f docker/compose.yaml -f docker/compose.hardened.yaml \
  run --rm -v "$PWD":/src:ro bhf --help
```

It isolates networking, makes the root read-only, supplies `/tmp`, and routes
language caches to `/work/cache`. Maven/Gradle source staging remains explicit:
copy the project into disposable writable storage and mount that copy at `/src`.
Populate its dependency cache during a separately authorized preparation step.
`scripts/ci/java-offline-acceptance.sh` checks successful staged Maven compilation,
unchanged original source, and a failing empty-cache build under network isolation.

## Release inventory and build inputs

The Ubuntu repositories use a dated snapshot. Builder Rust, runtime nightly,
rustup, Go, esbuild, and selected Ruby gems have explicit versions; downloaded
rustup and Go archives have checksum checks. Refresh pins through a reviewed
build and scan. Package versions and ecosystem inventory are retained for each
image, including dependencies supplied by package managers.

`scripts/ci/inventory-image.sh IMAGE EVIDENCE_DIR` scans the immutable local image
ID. It verifies the shipped binary hashes against the compiler receipt, then
merges the filesystem inventory with the selected normal Cargo dependency graph.
Build scripts and proc macros are recorded separately in `build-receipt.json`.
The OS-only inventory remains labeled `os.cyclonedx.json`. Scanner versions and
the vulnerability database identity accompany the scan; a successful inventory
command alone is not a vulnerability disposition or publication approval.

## Resources

bhf scales its memory budgets to the cgroup limit, so a `--memory` cap is
honoured. Budget at least `jobs × rss-limit-mb` for fuzz children plus headroom
for discovery, compilers, and reports. On a memory-capped container prefer a
serial sweep (`--jobs 1`) and set `--rss-limit-mb` explicitly. See
[Resource Requirements](../../README.md#resource-requirements).

## Air-gapped / offline use

The full-language image stages **bhf's own instrumentation dependencies at build time**.
Target build tools can still try the network; use `--network none` with staged
project dependencies to enforce disconnected execution:

- **Java** — the JVM coverage agent is built into the image with the packaged
  ASM jars. `BHF_JVM_AGENT_JAR` points at that immutable artifact, so first use
  does not need a writable home cache. Target project dependencies still need
  staging.
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
  bhf:full-local auto /src --work-dir /work/run --run-untrusted
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

The full-language image bakes a reproducible validation sweep: two small, pinned, real
projects per language (32 total). A passing sweep demonstrates observed entry
into at least one non-stub target in every selected project. It does not prove
complete API coverage, useful coverage feedback in every lane, or competitive
fuzzing effectiveness.

```sh
docker run --rm --shm-size=2g --cap-add=SYS_PTRACE \
  -v bhf_work:/work \
  bhf:full-local bhf-sweep --fetch          # --fetch clones the pinned corpus first
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
evidence limits and the control crosswalk. Inventory and scan the entire shipped
image, including toolchain caches; authorization remains deployment-specific.

## Troubleshooting

- **`LeakSanitizer has encountered a fatal error`** — add `--cap-add=SYS_PTRACE`,
  or export `ASAN_OPTIONS=detect_leaks=0` if you do not need leak detection.
- **cmplog/coverage errors, `/dev/shm` full** — raise `--shm-size`.
- **Killed / OOM under `--memory`** — lower `--jobs` and `--rss-limit-mb`, or
  raise the cap. bhf records an analysis gap when it hits the RSS ceiling.
- **A language target is skipped** — that toolchain is not installed in your
  scoped image, or the project has no fuzzable entry point in that language.
