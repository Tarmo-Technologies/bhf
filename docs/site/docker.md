<!-- SPDX-License-Identifier: Apache-2.0 -->
# Running bhf in Docker

The default image includes all sixteen supported language toolchains, the CLI,
daemon, Linux shims, AFL++, and Rust nightly. Smaller `core` and `ada` images
require explicit selection. All build the production binaries without the optional
`llm` Cargo feature. Each runs as an unprivileged user
under `tini`, and grants fuzzing the two extra runtime privileges it needs and
nothing more.

## Build

```sh
# from the repo root
docker build -t bhf:local -f Dockerfile .
# smaller C/C++ image (explicit):
docker build --target core -t bhf:core-local -f Dockerfile .
# selected Ada tooling on top of core:
docker build --target ada -t bhf:ada-local -f Dockerfile .
# or build the default all-language image through Compose:
docker compose -f docker/compose.yaml build
# Explicit validation only:
docker compose -f docker/compose.yaml --profile validation run --rm sweep
# From a clean commit, stamp a local release candidate with version and source:
scripts/build-container-release.sh bhf:release-candidate
# Smaller release candidate (explicit):
scripts/build-container-release.sh bhf:core-candidate --flavor core
```

The image currently supports `linux/amd64` only, matching its checksum-pinned
Go archive. The release script refuses dirty checkouts and supplies the same
version and commit to the binary and image metadata. The build context comes
from `git archive HEAD`, excluding untracked and ignored local files. The optional
`--flavor core|ada|runtime` flag selects a toolchain profile; the default is all
languages (`runtime`). The legacy second positional flavor remains accepted. Its `local_image_id` identifies
the local image configuration, and is distinct from a registry manifest digest.

The builder compiles only the release binaries and Linux shims against Ubuntu
24.04 glibc. The default final stage inherits `runtime`, which carries all sixteen
languages, including .NET 8 SDK, a headless JDK, and Maven.
Gradle is omitted from the full image; add it to that stage for Gradle-project
build recovery. The validation helpers use the explicit `validation` target.

| Profile | Included build tools | Executed acceptance |
|---|---|---|
| `core` (explicit) | C/C++ with Clang/LLVM | Non-root, read-only, disconnected C fixture in the actual image |
| `ada` (explicit) | Core plus GNAT/GPRbuild | Non-root, read-only, disconnected Ada compiler smoke; broader project acceptance remains project-specific |
| `runtime` / `production` (default) | All sixteen language toolchains except Gradle project recovery | Bare Java, staged offline Maven, and benign compiler/runtime startup for all sixteen languages under isolation; project-specific dependencies still require staging |
| FreeRTOS reference | Separate pinned kernel, ARM GCC, QEMU | Cooperative task/queue image, clean → fault → clean, retained finding and replay; no physical-board claim |

The release support boundary is host-native operation in the tested deployment
profiles. Windows native artifact checks do not establish retained-target replay
under a ready live ETW observer. Rust private/resource-backed placement remains
experimental, and repeated-trial comparative effectiveness is not established.
The FreeRTOS reference does not validate Samsung Android devices, arbitrary RTOS
images, peripherals, or physical boards. Those need separate device-specific
qualification; an attached Android phone is not evidence for this profile.

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

### Selecting languages

With no `--languages` flag, discovery considers all sixteen supported languages:
Ada, C, C++, Rust, Java, Python, Perl, Go, COBOL, Fortran, C#, JavaScript,
TypeScript, Ruby, Lua, and PHP. To deliberately restrict a run, use, for example,
`auto /src --languages java,python`. The CLI reports how many candidates that
filter excludes. Selecting a smaller image does not silently change discovery.

Toolchain availability is not proof that every target was fuzzed. Check the
per-language counts, skipped targets, build failures, and target-entry results.
Project build consent (`--run-untrusted`) and staged project dependencies still
apply. Unsupported targets and denied builds are incomplete work.

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

Standalone Node, esbuild, Go, rustup, and each installed Rust component also
have explicit version and file-hash inventories; filesystem discovery alone
does not reliably identify these prebuilt tools.

The Ubuntu repositories use a dated snapshot. Builder Rust, runtime nightly,
rustup, Go, Node, Maven, esbuild, Python build tools, and selected Ruby gems have explicit versions; downloaded
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

Java Maven/Gradle, Rust Cargo, and C# MSBuild project builds require
`--run-untrusted`. Cargo uses `--offline`; Maven/Gradle use their offline flags;
NuGet resolves against the staged package cache and a local empty feed. Missing
dependencies fail with build diagnostics. Denied project execution is reported
as unsupported, never as successful assurance. These flags do not constrain
network calls made by project scripts: use the isolated deployment profile.
Direct compiler/interpreter invocation and target execution remain part of
`auto` without this flag. C/C++ and Ada project probes also require this consent.
Stage dependency-bearing sources in a disposable writable copy as described
above, including projects whose MSBuild targets write next to their sources.

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

Container candidates retain the installed OS package notices, selected Rust
crate license texts, and upstream tool licenses. The candidate packager includes
exact Ubuntu source archives from `COPYLEFT-SOURCES.txt`, their checksums, and the
BHF source archive containing the build instructions. Source retrieval fails if
any exact requested version is unavailable; it does not substitute a newer
version. The generated OS notices and inventory do not cover every ecosystem by
themselves.

`WRITTEN-OFFER.md` is informational material, not a completed publisher offer.
Redistribution review must account for all bundled components and modifications.
The signed candidate includes source material rather than relying on a blank
contact field. [ATO / RMF posture](./ato.md) is supporting deployment evidence.

## Authenticated offline container handoff

The `Container release candidate` workflow runs full CI at the exact source
revision, builds and tests the chosen image, reconciles its inventory, and checks
the scan. Critical/High findings, unknown severity, fixable Medium findings, and
invalid/stale databases block packaging for signing. Other matches remain
explicitly `under_investigation` in the review record; none are automatically
marked unaffected.

The unsigned archive includes `image.docker.tar`, `release-manifest.json`, source
archives, binary hashes, SBOMs, scan/database details, and acceptance logs. It uses
the tested local image configuration digest. A registry manifest digest is not
claimed for this offline format.

Publisher signing requires the matching version tag and approval in the existing
`production-release` environment. The reviewer accepts or rejects the exact
candidate and residual findings. A detached signature authenticates the entire
container archive using the existing BHF distribution signature scheme; the
independent verifier checks it before the archive is extracted or loaded.
Obtain the verifier and publisher public key through an independently trusted
channel, as described in [verified distribution handoff](https://github.com/Tarmo-Technologies/bhf/blob/main/docs/verified-distribution-handoff.md).

```sh
python3 scripts/verify-offline-dist.py \
  --archive bhf-container-VERSION-core-COMMIT.tar.gz \
  --signature bhf-container-VERSION-core-COMMIT.tar.gz.sig \
  --trusted-public-key /trusted/publisher.hex \
  --max-archive-bytes 8589934592 \
  --verified-copy /safe/verified-container.tar.gz
```

After successful verification, extract the verified copy, load its
`image.docker.tar` with `docker load`, and use the image ID recorded in
`release-manifest.json`. These archives are separate from native binary bundles
and receive their own signatures.

## Troubleshooting

- **`LeakSanitizer has encountered a fatal error`** — add `--cap-add=SYS_PTRACE`,
  or export `ASAN_OPTIONS=detect_leaks=0` if you do not need leak detection.
- **cmplog/coverage errors, `/dev/shm` full** — raise `--shm-size`.
- **Killed / OOM under `--memory`** — lower `--jobs` and `--rss-limit-mb`, or
  raise the cap. bhf records an analysis gap when it hits the RSS ceiling.
- **A language target is skipped** — that toolchain is not installed in your
  scoped image, or the project has no fuzzable entry point in that language.

### Installation selection versus run selection

The default image and native installer select all sixteen languages; the default
CLI and daemon exclude LLM provider features. `bhf auto --languages` only filters
a run. To omit toolchains and their caches from the image construction path:

```sh
scripts/build-container-release.sh bhf:all-local
scripts/build-container-release.sh bhf:java-python --languages java,python
scripts/build-container-release.sh bhf:embedded-host --languages c,cpp,ada
scripts/build-container-release.sh bhf:rust-only --languages rust
# Explicitly omit the optional AFL++ installation:
scripts/build-container-release.sh bhf:java-python-builtin --languages java,python --engines builtin
BHF_LANGUAGES=java,python BHF_ENGINES=builtin docker compose -f docker/compose.yaml build bhf
```

Builds require a clean checkout. Selections are nonempty, case insensitive,
deduplicated, and order independent, using the same aliases as `auto`.
`all` must appear alone; empty fields, `none`, unknown names, repeated selection
options, and combining `--languages` with `--flavor` are errors. Legacy
`--flavor core` and `--flavor ada` retain their previous component sets; use
`--languages` for arbitrary subsets. `--engines` applies to the new selection
path or `runtime`. Compiled parsers remain in the binary, and unfiltered discovery
continues to consider every language. A toolchain selection is not proof that a
language passed end-to-end qualification.

Python remains a shared operational dependency. Rust, Go, Ada, COBOL and Fortran
retain native linking/instrumentation tools. TypeScript includes Node and esbuild;
JavaScript includes Node. AFL++ (the default optional engine) can pull native
compiler dependencies even for a managed-language selection. System tools may
transitively bring Perl or runtime libraries. These dependencies are intentional;
this option does not promise the absence of every executable associated with an
excluded language. No subset inherits and then strips an all-language image.
The common Rust/C toolchains in the **BHF compiler builder stage** build BHF
itself and are distinct from customer toolchains in the shipping image.

Ruby includes the zlib development headers required to build its pinned native
gem. PHP includes `pcov` for measured target coverage; a PHP interpreter without
that extension can enter a target while reporting zero coverage feedback.

The selected canonical list is stored in
`/usr/local/share/bhf/selected-languages.txt`, with engines in
`selected-engines.txt`. Missing project dependencies still require separately
prepared caches; the image does not download project code at startup. Validation
helpers now require the explicit `validation` Docker target/Compose profile.

For an extracted native bundle, use its packaged installer:

```sh
./install.sh --non-interactive --no-content --languages java,python
```

Native selection controls new dependency installation, never removes existing
host tools, and retains all compiled parsers. `--extras none --no-smoke` omits
optional build-recovery packages and the installer's C smoke prerequisites.
`--no-system-packages --no-rustup` uses operator-prepared toolchains. Native
C#/TypeScript prerequisites remain explicit warnings when unavailable; a
successful installation alone does not establish runtime availability.

Executed evidence and outstanding qualification blockers are tracked in the
[qualification checkpoint](https://github.com/Tarmo-Technologies/bhf/blob/hardening/language-subset-qualification/docs/validation/2026-10-05-qualification-checkpoint.md).

The explicitly dispatched **Container release candidate** workflow offers a
`language_matrix` option. It constructs the default, every single-language
selection, and three mixed selections, then exercises compiler startup, excluded
ecosystems, daemon lifecycle, and clean BHF-owned target-entry/coverage controls
through `bhf auto`. A requested matrix failure blocks candidate packaging.
These short controls establish functionality, not upstream-project qualification.

The same matrix can run locally from a clean checkout. Keep evidence outside the
checkout; resume checks the exact commit, source-archive hash, selection order,
control settings, and completed evidence hashes before starting the next row:

```sh
python3 scripts/ci/container-selection-matrix.py --evidence /tmp/bhf-selection --auto
python3 scripts/ci/container-selection-matrix.py --evidence /tmp/bhf-selection --resume
```

Interrupted attempts retain their logs in separate directories. Failed rows stay
failed in a resumed matrix; start a new evidence directory after a source fix.
The owned controls use ordinary source paths by default. Their optional
`--paths-with-spaces` mode records broader path compatibility separately:
C/C++ Makefile generation currently rejects these paths. It must not be
represented as validated support.
