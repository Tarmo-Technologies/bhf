<!-- SPDX-License-Identifier: Apache-2.0 -->
# Running bhf in Docker

The default image carries the toolchains for all sixteen languages, the CLI,
the daemon, the Linux shims, AFL++ and Rust nightly. The `core` and `ada`
targets build smaller images. Images run as an unprivileged user under `tini`
and are built without the optional `llm` Cargo feature.

## Build

```sh
# from the repo root
docker build -t bhf:local -f Dockerfile .
# smaller C/C++ image:
docker build --target core -t bhf:core-local -f Dockerfile .
# core plus GNAT/GPRbuild:
docker build --target ada -t bhf:ada-local -f Dockerfile .
# or build the default all-language image (bhf:local) through Compose:
docker compose -f docker/compose.yaml build
# build the validation image (bhf:full-local) and run the 32-project sweep:
docker compose -f docker/compose.yaml --profile validation run --rm sweep
# from a clean commit, stamp a local release candidate with version and source:
scripts/build-container-release.sh bhf:release-candidate
# smaller release candidate:
scripts/build-container-release.sh bhf:core-candidate --flavor core
```

The Dockerfile supports Linux x86-64 (`linux/amd64`) and ARM64
(`linux/arm64`) with architecture-specific, checksum-verified toolchains.
Builds, Compose included, use the Docker daemon's architecture by default.

```sh
# Build a specific architecture locally:
scripts/build-container-release.sh bhf:arm64 --platform linux/arm64
# Create an isolated Buildx builder, then export both variants locally:
docker buildx create --name bhf-multiarch --driver docker-container
BUILDX_BUILDER=bhf-multiarch scripts/build-container-release.sh bhf:multiarch \
  --platform linux/amd64,linux/arm64 --output /tmp/bhf-multiarch.oci.tar
```

The multi-platform export needs a Buildx builder with native build nodes or
emulation for both architectures. Emulation is fine for build checks, but it
can change sanitizer behaviour and fuzzing speed. The release workflow, run
by hand for a release, runs a native fuzzing validation on an x86-64 runner
and on an ARM64 runner before it keeps the candidate for each architecture.
CI also builds and tests every change natively on ARM64 (the `arm64-build`
job): the workspace and the runtrace shim, the tests outside bhf's heavy
integration suites, and a `bhf auto` run that finds a planted overflow.

The release script refuses a dirty checkout and stamps the same version and
commit into the binary and the image metadata. Its build context comes from
`git archive HEAD`, so untracked and ignored local files are left out. The
optional `--flavor core|ada|runtime` flag selects a toolchain profile; the
default is all languages (`runtime`). The script reports `local_image_id`,
the local image configuration ID, which is not a registry manifest digest.

## What the images contain

The builder stage compiles the release binaries and Linux shims against
Ubuntu 24.04 glibc. The default final stage inherits `runtime`, which carries
all sixteen languages, including the .NET 8 SDK, a headless JDK and Maven.
Gradle is not in the image; add it to that stage for Gradle-project build
recovery.

With C++ selected, the image also carries libc++ and libc++abi built with
MemorySanitizer in `/opt/msan-libcxx` (`BHF_MSAN_LIBCXX`), which the C++ MSan
replay builds against (see
[Sanitizers](sanitizers.md#c-under-the-msan-replay)). They add about 14 MB.

With the default engines, the image carries AFL++'s QEMU and Frida modes for
binaries without source, which Ubuntu's `afl++` package leaves out:

- `/usr/bin/afl-qemu-trace`, which `bhf binary fuzz --engine afl-qemu` and
  `afl-fuzz -Q` run;
- `/usr/lib/afl/afl-frida-trace.so`, for `afl-fuzz -O` and
  `bhf fuzz --afl-mode frida`.

They are built from the AFL++ release the package carries (4.09c), with the
qemuafl commit that release pins and a digest-checked Frida GumJS devkit, so
`afl-fuzz` and both trace programs share one fork-server protocol. With the
GLib runtime the QEMU mode loads, they add about 17 MB. The container
acceptance runs each mode on an uninstrumented binary and checks that it
reports coverage. qemuafl is GPL-2.0: `fetch-sources.sh` also downloads the
sources listed in `/usr/share/bhf/licenses/afl/UPSTREAM-SOURCES.txt`.

| Profile | Build tools | Acceptance run in the image |
|---|---|---|
| `core` | C/C++ with Clang/LLVM | Non-root, read-only, disconnected C fixture |
| `ada` | Core plus GNAT/GPRbuild | Non-root, read-only, disconnected Ada compiler smoke test |
| `runtime` / `production` (default) | All sixteen language toolchains; no Gradle | Bare Java, staged offline Maven, and compiler/runtime startup for all sixteen languages under isolation |

Project-specific dependencies still need staging in every profile (see
[Air-gapped and offline use](#air-gapped-and-offline-use)). For embedded
targets, including the FreeRTOS reference under QEMU, see
[On-Target & Embedded](on-target-fuzzing.md).

## Run

```sh
docker run --rm \
  --shm-size=2g \
  --cap-add=SYS_PTRACE \
  -v "$PWD":/src:ro \
  -v bhf_work:/work \
  bhf:local auto /src --work-dir /work/run --per-target-time 30
```

Anything after the image name is passed to `bhf`. The entrypoint also
accepts `bhf`, `bhf-daemon`, `bhf-sweep` (validation image), `sh` and `bash`
as the first word. Read `/work/run/results/INDEX.md` first.

### Windows and macOS hosts

Run these Linux images with Docker Desktop in Linux-container mode on
Windows, or with Docker Desktop on macOS. x86-64 machines use `linux/amd64`;
Apple Silicon uses `linux/arm64`. Bind-mount a source directory and keep
results in a Docker volume as shown above. In Windows PowerShell, use
`${PWD}` for the source path and put the command on one line instead of using
shell `\` continuations.

The container uses Linux toolchains and Linux runtime behaviour on every
host. Windows-specific APIs and MSVC builds need the
[native Windows release](windows.md). Cross-compiled and emulated targets
need their own toolchains and runners (see
[Cross-Compilation](cross-compilation.md)).

### Selecting languages

With no `--languages` flag, discovery considers all sixteen supported
languages: Ada, C, C++, Rust, Java, Python, Perl, Go, COBOL, Fortran, C#,
JavaScript, TypeScript, Ruby, Lua and PHP. To restrict a run, pass for
example `auto /src --languages java,python`; the CLI reports how many
candidates the filter excludes. Discovery is the same in every image: a
smaller image changes which toolchains are present, not which languages are
discovered.

To see what was fuzzed, read the per-language counts, skipped targets, build
failures and target-entry results in `auto/summary.txt`. Project build
consent (`--run-untrusted`) and staged project dependencies apply as on any
host; an unsupported target or a denied build is reported as not fuzzed.

## Container permissions

A fuzzer needs two grants beyond a hardened default container:

| Flag | Why | Symptom if missing |
|---|---|---|
| `--cap-add=SYS_PTRACE` | LeakSanitizer and ASan stop the world at process exit | `LeakSanitizer has encountered a fatal error`, or degraded ASan reports |
| `--shm-size=2g` | Coverage bitmaps and cmplog shared-memory maps | repeated restarts, cmplog disabled, or `/dev/shm` running out of space |

Everything else stays locked down. The image runs as UID 10001 (`fuzzer`)
and keeps the default seccomp profile. Under `docker/compose.yaml` it also
runs with `cap_drop: ALL` (re-adding only `SYS_PTRACE`) and
`no-new-privileges`. bhf exports `AFL_SKIP_CPUFREQ=1` and
`AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1`, so the AFL++ engine does not
depend on the host's `kernel.core_pattern` (which is not namespaced) or CPU
governor.

In the full-language `runtime` image, the JVM coverage-agent JAR is prebuilt
into an immutable image path. Maven and Gradle write build outputs into the
project's modules, so a Java project with Maven or Gradle build files needs a
writable, disposable copy of the source: mount that copy at `/src`. A bare
`javac` project can use a read-only `/src` mount.

For a read-only root filesystem and a bare source fixture:

```sh
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,exec,nosuid,size=1g --shm-size=2g \
  --memory=4g --pids-limit=512 --cap-drop=ALL --cap-add=SYS_PTRACE \
  --security-opt no-new-privileges:true \
  -v bhf_work:/work -v "$PWD":/src:ro \
  bhf:local auto /src --work-dir /work/run --jobs 1
```

`/tmp` needs `exec` because some lanes compile and run harnesses staged
there. The 4 GB and 512-process limits were sized for the small C acceptance
fixture; size them for your target project.

The equivalent Compose override is:

```sh
docker compose -f docker/compose.yaml -f docker/compose.hardened.yaml \
  run --rm -v "$PWD":/src:ro bhf --help
```

It disables networking, makes the root filesystem read-only, supplies `/tmp`
and routes language caches to `/work/cache`. Maven and Gradle source staging
stays explicit: copy the project into disposable writable storage, mount
that copy at `/src`, and populate its dependency cache in a separately
authorized preparation step. `scripts/ci/java-offline-acceptance.sh` checks
that a staged Maven project compiles, that the original source is unchanged,
and that a build with an empty cache fails under network isolation.

## Release inventory and build inputs

The Ubuntu repositories come from a dated snapshot. Builder Rust, runtime
nightly, rustup, Go, Node, Maven, esbuild, Python build tools and selected
Ruby gems have explicit versions, and the downloaded rustup and Go archives
are checksum-checked. Standalone Node, esbuild, Go, rustup and each installed
Rust component also have explicit version and file-hash inventories, because
a filesystem scan does not identify these prebuilt tools reliably. Package
versions and the ecosystem inventory, including dependencies supplied by
package managers, are kept for each image. Refresh the pins through a reviewed
build and scan.

`scripts/ci/inventory-image.sh IMAGE EVIDENCE_DIR` scans the immutable local
image ID. It checks the shipped binary hashes against the compiler receipt,
then merges the filesystem inventory with the selected normal Cargo
dependency graph. Build scripts and proc macros are recorded separately in
`build-receipt.json`. The OS-only inventory is `os.cyclonedx.json`. Scanner
versions and the vulnerability database identity are recorded with the scan.

## Resources

bhf scales its memory budgets to the cgroup limit, so it honours a
`--memory` cap. Budget at least `jobs × rss-limit-mb` for fuzz children, plus
headroom for discovery, compilers and reports. In a memory-capped container,
prefer a serial sweep (`--jobs 1`) and set `--rss-limit-mb` explicitly. See
[Resource Requirements](../../README.md#resource-requirements).

## Air-gapped and offline use

The full-language image stages bhf's own instrumentation dependencies at
build time:

- **Java**: the JVM coverage agent is built into the image with the packaged
  ASM jars. `BHF_JVM_AGENT_JAR` points at that immutable artifact, so first
  use needs no writable home cache.
- **C#**: the harness references `SharpFuzz`, and the image primes the
  default NuGet cache with it at build time.

Your target project's own build dependencies are not in the image. To fuzz a
real project offline, bring those across the gap, as you would to build the
project by hand:

| Lane | Stage on the host (mount into the container) |
|---|---|
| Java (Maven) | your `~/.m2` repository; run `mvn -o` |
| Java (Gradle) | your Gradle cache (and add `gradle` to the image) |
| C# | the target's NuGet packages, in `NUGET_PACKAGES` (SharpFuzz is already cached) |
| Rust | `cargo vendor` output and a `.cargo/config.toml` pointing at it |
| Go | a vendored module tree or a populated `GOMODCACHE` |
| Node/TS | the target's `node_modules` |

Java Maven/Gradle, Rust Cargo and C# MSBuild project builds need
`--run-untrusted`, and so do the C/C++ and Ada project build probes. Cargo
runs with `--offline`, Maven and Gradle with their offline flags, and NuGet
resolves against the staged package cache and a local empty feed. A missing
dependency fails the build with its diagnostics. A denied project build is
reported as unsupported. These flags do not stop network calls made by
project scripts; use the isolated profile (`--network none`) for that. Without
`--run-untrusted`, `auto` still runs compilers and interpreters directly, and
runs the target. Stage dependency-bearing sources in a disposable writable
copy as described above, including projects whose MSBuild targets write next
to their sources.

With the dependencies staged, run with `--network none` so the run is
disconnected:

```sh
docker run --rm --network none --shm-size=2g --cap-add=SYS_PTRACE \
  -v "$PWD":/src:ro -v "$HOME/.m2":/home/fuzzer/.m2 -v bhf_work:/work \
  bhf:local auto /src --work-dir /work/run --run-untrusted
```

## Using a compile_commands.json

For C/C++, a `compile_commands.json` (clang compilation database) gives bhf
the real translation-unit flags, and bhf uses one without `--probe-build`:

- Put it in the project root or a `build/` subdirectory (a symlink at either
  place is followed). bhf finds it and builds each harness with the recorded
  flags.
- `--probe-build` regenerates a database by running the project's own build.
  It builds outside the tree, in `<work>/probe/<tree>-<hash>/` (CMake and
  Meson with their build directory there, Make and an intercepted
  `--build-command` in a copy of the tree there), so a read-only `/src` mount
  works. It writes `<work>/probe/<tree>-<hash>/.bhf-build/compile_commands.json`.
  If you place your own database at `<tree>/.bhf-build/compile_commands.json`
  and regeneration fails (for example offline), bhf keeps and uses your
  database. A probe that yields no database says why (for Make: it ran no
  compiler).

See [C and C++: compile databases](c-cpp.md#compile-databases) for the full
search order.

## The 32-project sweep

The validation image (the `validation` Docker target, or Compose's
`validation` profile, tagged `bhf:full-local`) carries a reproducible
validation sweep: two small, pinned, real projects per language, 32 in all.
A passing sweep shows bhf entering at least one non-stub target in every
selected project.

```sh
docker run --rm --shm-size=2g --cap-add=SYS_PTRACE \
  -v bhf_work:/work \
  bhf:full-local bhf-sweep --fetch          # --fetch clones the pinned corpus first
```

Results land under `/work/results/`: `sweep-report.md`, `sweep-report.tsv`
and a work dir per project. These environment variables tune the sweep:

| Variable | Default | Meaning |
|---|---|---|
| `BHF_PER_TARGET_TIME` | `20` | Fuzz seconds per target |
| `BHF_MAX_TARGETS` | `3` | Targets per project |
| `BHF_CAMPAIGN_TIME` | `240` | Budget per project (seconds) |
| `BHF_JOBS` | `1` | Concurrent targets |
| `BHF_LANGS` | all | Space-separated language filter, such as `"c cpp rust"` |
| `BHF_SWEEP_MANIFEST` | `/usr/local/share/bhf/sweep-manifest.tsv` | The corpus manifest |
| `BHF_SWEEP_RESULTS` | `./results` | Results directory |
| `BHF_CORPUS` | `./corpus` | Corpus directory |

The results directory must be new or empty, because a rerun never overwrites
evidence: choose a new `BHF_SWEEP_RESULTS` for each run. The gate fails on an
empty selection, a partial or malformed JSON report, a missing, dirty or
unpinned checkout, a stub-only campaign, an unentered target or a timeout. The
gate reads the machine-readable `auto/run.json`, not the text summary.
Reported edges sum each entered target's peak counter (not a global union),
and findings count per-pass observations, not unique bugs. A project with
zero coverage feedback shows as zero in the report.

Corpus fetching checks existing clones against the full manifest commit and
rejects modified or extra inputs rather than deleting them. Build recovery
may modify a checkout, so a repeated validation may need a fresh `BHF_CORPUS`
as well. A custom manifest needs six tab-separated columns, unique safe
identifiers, full lowercase commit hashes and relative in-tree source paths;
use `-` for an unused source path or flag. These checks do not sandbox target
build commands: run untrusted projects only inside an isolated container.

## Licensing and redistribution

The image aggregates independent programs on one medium. bhf itself is
Apache-2.0 and runs the bundled toolchains as subprocesses. It does not link
their GPL code, so aggregating them does not place bhf under the GPL (mere
aggregation, GPLv2 §2 / GPLv3 §5). AFL++ is predominantly Apache-2.0.

Container candidates keep the installed OS package notices, selected Rust
crate license texts and upstream tool licenses. The candidate packager adds
the exact Ubuntu source archives listed in `COPYLEFT-SOURCES.txt`, their
checksums, and the bhf source archive containing the build instructions.
Source retrieval fails if an exact requested version is unavailable, and
never substitutes a newer version. The generated OS notices and inventory
cover OS packages; the release review accounts for the other ecosystems. The
.NET SDK comes from Microsoft's checksum-pinned release archive (8.0.134),
because Ubuntu noble's package has lagged its security releases; its license
and third-party notices are in `/usr/share/bhf/licenses/csharp/`.

[docker/compliance/WRITTEN-OFFER.md](../../docker/compliance/WRITTEN-OFFER.md)
lists the redistribution material a candidate carries. A distributor who
relies on a written offer instead of shipping the included source material
prepares and reviews its own. Redistribution review covers every bundled
component and modification. See [ATO / RMF posture](ato.md) for deployment
evidence.

## Authenticated offline container handoff

The `Container release candidate` workflow runs full CI at the exact source
revision, builds and tests the chosen image, reconciles its inventory and
checks the scan. Critical or High findings, unknown severity, fixable Medium
findings and invalid or stale databases block packaging for signing. Other
matches are recorded as `under_investigation` in the review record; none is
marked unaffected automatically.

The unsigned archive holds `image.docker.tar`, `release-manifest.json`, source
archives, binary hashes, SBOMs, scan and database details, and acceptance
logs. It records the tested local image configuration digest; this offline
format has no registry manifest digest.

Publisher signing needs the matching version tag and approval in the
`production-release` environment. The reviewer accepts or rejects the exact
candidate and its residual findings. A detached signature authenticates the
whole container archive with bhf's distribution signature scheme, and the
independent verifier checks it before the archive is extracted or loaded.
Obtain the verifier and the publisher public key through an independently
trusted channel, as described in
[verified distribution handoff](../verified-distribution-handoff.md).

```sh
python3 scripts/verify-offline-dist.py \
  --archive bhf-container-VERSION-core-COMMIT.tar.gz \
  --signature bhf-container-VERSION-core-COMMIT.tar.gz.sig \
  --trusted-public-key /trusted/publisher.hex \
  --max-archive-bytes 8589934592 \
  --verified-copy /safe/verified-container.tar.gz
```

After verification, extract the verified copy, load its `image.docker.tar`
with `docker load`, and use the image ID recorded in `release-manifest.json`.
These archives are separate from the native binary bundles and have their own
signatures.

## Troubleshooting

- **`LeakSanitizer has encountered a fatal error`**: add
  `--cap-add=SYS_PTRACE`, or export `ASAN_OPTIONS=detect_leaks=0` if you do
  not need leak detection.
- **cmplog or coverage errors, `/dev/shm` full**: raise `--shm-size`.
- **Killed or OOM under `--memory`**: lower `--jobs` and `--rss-limit-mb`, or
  raise the cap. bhf records an analysis gap when it hits the RSS ceiling.
- **A language's targets are skipped**: that toolchain is not in your image,
  or the project has no fuzzable entry point in that language.
- **`MemorySanitizer: CHECK failed: msan_linux.cpp ... ADDR_NO_RANDOMIZE`**:
  the host kernel randomizes mmap with 32 bits, and the default seccomp
  profile refuses MSan's re-run with randomization off. bhf retries such a
  run up to 8 times. To fix it at the source, set
  `sysctl vm.mmap_rnd_bits=28` on the host.
- **`bhf cartography` warns that address-space randomization cannot be turned
  off**: the default seccomp profile refuses `personality(2)`, so the bytes
  that set a SEGV's faulting address show as `unknown`. Add
  `--security-opt seccomp=unconfined` to the cartography run if you need
  them. Overflows mapped by their region-relative offset work either way.

## Installation selection versus run selection

The default image and the native installer select all sixteen languages,
and the default CLI and daemon are built without the LLM provider features.
`bhf auto --languages` only filters a run. To leave toolchains and their
caches out of an image, select languages when you build it:

```sh
scripts/build-container-release.sh bhf:all-local
scripts/build-container-release.sh bhf:java-python --languages java,python
scripts/build-container-release.sh bhf:embedded-host --languages c,cpp,ada
scripts/build-container-release.sh bhf:rust-only --languages rust
# Leave out the optional AFL++ installation:
scripts/build-container-release.sh bhf:java-python-builtin --languages java,python --engines builtin
BHF_LANGUAGES=java,python BHF_ENGINES=builtin docker compose -f docker/compose.yaml build bhf
```

Builds need a clean checkout. Selections must be nonempty; they are case
insensitive, deduplicated and order independent, and use the same aliases as
`auto`. `all` must appear alone. Empty fields, `none`, unknown names,
repeated selection options, and `--languages` combined with `--flavor` are
errors. `--flavor core` and `--flavor ada` keep their component sets; use
`--languages` for any other subset. `--engines` applies to a `--languages`
selection or to `runtime`. Every image keeps all compiled parsers, and
unfiltered discovery still considers every language.

What a selection keeps:

- Python is a shared operational dependency of every image.
- Rust, Go, Ada, COBOL and Fortran keep their native linking and
  instrumentation tools.
- TypeScript includes Node and esbuild; JavaScript includes Node.
- AFL++ (the default optional engine) can pull in native compiler
  dependencies even for a managed-language selection, and system tools may
  bring in Perl or runtime libraries.
- Ruby includes the zlib development headers its pinned native gem needs.
- PHP includes `pcov` for measured target coverage; a PHP interpreter without
  that extension enters a target but reports zero coverage feedback.

Each subset is built from its own selection, never by stripping the
all-language image. The Rust/C toolchains in the bhf compiler builder stage
build bhf itself and are separate from the target toolchains in the shipping
image.

The selected list is stored in `/usr/local/share/bhf/selected-languages.txt`,
and the engines in `selected-engines.txt`. Missing project dependencies still
need separately prepared caches; the image downloads no project code at
startup. The validation helpers need the `validation` Docker target or
Compose profile.

For an extracted native bundle, select languages with its packaged
installer:

```sh
./install.sh --non-interactive --no-content --languages java,python
```

A native selection controls which new dependencies are installed; it never
removes existing host tools, and it keeps all compiled parsers.
`--extras none --no-smoke` leaves out the optional build-recovery packages
and the installer's C smoke-test prerequisites. `--no-system-packages
--no-rustup` uses operator-prepared toolchains. Native C# and TypeScript
prerequisites print a warning when unavailable; check that the toolchains run
after the installation.

The executed evidence and the open qualification blockers are tracked in the
[qualification checkpoint](../validation/2026-10-05-qualification-checkpoint.md).

### The language selection matrix

The `Container release candidate` workflow, dispatched by hand, has a
`language_matrix` option. It builds the default image, every single-language
selection and three mixed selections, then checks compiler startup, the
excluded ecosystems, the daemon lifecycle, and target-entry and coverage on
bhf's own control targets through `bhf auto`. A failed matrix row blocks
candidate packaging. These short controls check that each selection works;
qualification on upstream projects is separate.

The same matrix runs locally from a clean checkout. Keep the evidence outside
the checkout. `--resume` checks the exact commit, source-archive hash,
selection order, control settings and completed evidence hashes before
starting the next row:

```sh
python3 scripts/ci/container-selection-matrix.py --evidence /tmp/bhf-selection --auto
python3 scripts/ci/container-selection-matrix.py --evidence /tmp/bhf-selection --resume
```

An interrupted attempt keeps its logs in a separate directory. A failed row
stays failed in a resumed matrix; start a new evidence directory after a
source fix. The control targets use ordinary source paths by default. The
optional `--paths-with-spaces` mode records path compatibility separately;
C/C++ Makefile generation rejects paths with spaces.
