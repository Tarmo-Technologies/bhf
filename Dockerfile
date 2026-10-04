# SPDX-License-Identifier: Apache-2.0
# syntax=docker/dockerfile:1.7
#
# BHF — Build Harness Fuzz — core default and full-language targets.
#
# Multi-stage:
#   1. builder  : compiles the release binaries (CLI, daemon, both Linux shims)
#                 against Ubuntu 24.04 glibc so the shims match the runtime.
#   2. runtime  : explicit full-language target, Ubuntu 24.04 carrying every one of the sixteen language
#                 toolchains bhf can build/harness/fuzz, plus AFL++ and a Rust
#                 nightly for the Rust sanitizer lane. Runs as a non-root user
#                 under tini. bhf's own instrumentation deps
#                 (the JVM coverage agent's ASM jars, the C# SharpFuzz package)
#                 are staged at build time; target-project dependencies are a
#                 separate staging responsibility.
#   3. core     : final/default C/C++ build-and-fuzz target without the other
#                 language toolchains or validation sweep helpers.
#
# Fuzzing needs a few runtime privileges the image cannot grant itself; grant
# them at `docker run` time (see docker/compose.yaml and docs/site/docker.md):
#   --cap-add=SYS_PTRACE     LeakSanitizer / ASan stop-the-world
#   --shm-size=2g            coverage bitmaps + cmplog shared memory
#   -v bhf_work:/work        persist findings, corpora, replay binaries

# Bootstrap HTTPS from an exact, checksum-verified Ubuntu CA package. This
# avoids a mutable apt install before selecting the reviewed archive snapshot.
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 AS certificates
ADD --checksum=sha256:6bac2a01979e210d9eac1d4d56747ec709ea60654744d66705dc3c36e7629e50 https://archive.ubuntu.com/ubuntu/pool/main/c/ca-certificates/ca-certificates_20260601~24.04.1_all.deb /tmp/ca.deb
RUN dpkg-deb -x /tmp/ca.deb /tmp/ca \
    && mkdir /certificates \
    && cat /tmp/ca/usr/share/ca-certificates/mozilla/*.crt > /certificates/ca-certificates.crt

FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 AS ubuntu-pinned
COPY --from=certificates /certificates/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ARG UBUNTU_SNAPSHOT=20261004T000000Z
RUN printf 'APT::Snapshot "%s";\nAPT::Update::Error-Mode "any";\n' "${UBUNTU_SNAPSHOT}" > /etc/apt/apt.conf.d/50snapshot
LABEL io.tarmo.bhf.ubuntu-snapshot="${UBUNTU_SNAPSHOT}"

########################################  builder  ########################################
FROM ubuntu-pinned AS builder
ARG TARGETPLATFORM
RUN test "${TARGETPLATFORM}" = linux/amd64

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Toolchain to compile bhf and its C-runtime bits (the shims are Rust cdylibs,
# but build.rs steps and the C runtime driver want a working C toolchain).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl build-essential make clang llvm lld pkg-config git python3 \
    && rm -rf /var/lib/apt/lists/*

# Pin the reviewed builder Rust version.
RUN curl --proto '=https' --tlsv1.2 -fsSLo /tmp/rustup-init https://static.rust-lang.org/rustup/archive/1.28.2/x86_64-unknown-linux-gnu/rustup-init \
    && echo '20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c  /tmp/rustup-init' | sha256sum -c - \
    && chmod +x /tmp/rustup-init \
    && /tmp/rustup-init -y --profile minimal --default-toolchain 1.99.0 \
    && rm /tmp/rustup-init \
    && rustc --version && cargo --version

WORKDIR /src
COPY . .
ARG CARGO_BUILD_JOBS=2
ARG VCS_REF=unknown
ARG BHF_SOURCE_SHA256=unknown

# Build the release packages. Cache the registry and target dir across rebuilds,
# then lift just the artifacts out of the cache mount into a real layer.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    mkdir -p /out \
    && BHF_RELEASE_VERSION=1 BHF_VCS_REF="${VCS_REF}" cargo build --locked --release -p bhf -p bhf-daemon -p bhf_runtrace_shim -p bhf_cc_intercept --jobs "${CARGO_BUILD_JOBS}" --message-format=json > /out/cargo-messages.jsonl \
    && cp target/release/bhf            /out/bhf \
    && cp target/release/bhf-daemon     /out/bhf-daemon \
    && cp target/release/libbhf_runtrace_shim.so /out/libbhf_runtrace_shim.so \
    && cp target/release/libbhf_cc_intercept.so  /out/libbhf_cc_intercept.so \
    && strip /out/bhf /out/bhf-daemon /out/*.so \
    && python3 scripts/ci/rust-image-inventory.py --artifacts /out --messages /out/cargo-messages.jsonl \
         --commit "${VCS_REF}" --source-sha "${BHF_SOURCE_SHA256}"

########################################  runtime  ########################################
FROM ubuntu-pinned AS runtime
ARG TARGETPLATFORM
RUN test "${TARGETPLATFORM}" = linux/amd64

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# --- Base utilities + the sixteen language toolchains -----------------------
# C/C++ (clang/llvm/make) is mandatory; the rest install cleanly and a target
# whose toolchain is absent simply skips, so this image covers every lane.
# NB: the JDK is headless (no AWT/X11 -> no mesa/second-LLVM pull) and Gradle is
# omitted (Maven + javac cover the Java lane; a Gradle project's build recovery
# is the one lane feature traded for a much smaller image). See docs/site/docker.md.
# `dist-upgrade` applies security/updates packages from the dated snapshot.
# Refresh the snapshot in reviewed releases and retain the new scan disposition.
# Go comes from the pinned upstream archive below.
RUN apt-get update && apt-get -y dist-upgrade && apt-get install -y --no-install-recommends \
        # base / runtime plumbing
        ca-certificates curl xz-utils file git tini locales \
        # C / C++  (required build+fuzz lane)
        make clang llvm lld libclang-rt-18-dev \
        # Ada
        gnat gprbuild \
        # Java  (headless JDK + Maven; libasm-java provides asm-9.7 + asm-tree-9.7
        # at /usr/share/java for the offline JVM coverage-agent build — see ASM_JAR_DIR)
        default-jdk-headless maven libasm-java \
        # Python  (3.12 -> sys.monitoring coverage)
        python3 python3-dev python3-venv python3-pip \
        # Perl
        perl \
        # Fortran
        gfortran \
        # COBOL  (GnuCOBOL cobc)
        gnucobol \
        # JavaScript / TypeScript  (node runtime; npm is build-only, purged below)
        nodejs \
        # Ruby
        ruby ruby-dev \
        # Lua
        lua5.4 liblua5.4-dev \
        # PHP
        php-cli \
        # C#  (.NET 8 SDK from the Ubuntu archive)
        dotnet-sdk-8.0 \
        # AFL++ engine (optional C/C++ adapter)
        afl++ \
    && rm -rf /var/lib/apt/lists/* \
    && locale-gen C.UTF-8

# Go from upstream (pinned + checksum-verified).
ARG GO_VERSION=1.27.1
ARG GO_SHA256=63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445
RUN curl --proto '=https' --tlsv1.2 -fsSLo /tmp/go.tgz \
        "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
    && echo "${GO_SHA256}  /tmp/go.tgz" | sha256sum -c - \
    && tar -C /usr/local -xzf /tmp/go.tgz \
    && rm -f /tmp/go.tgz \
    && /usr/local/go/bin/go version

# TypeScript bundler for the JS/TS lane (pinned). npm is BUILD-ONLY: install
# esbuild into /usr/local (survives npm removal), then purge npm and its
# now-orphaned node-* deps. The final-image scan determines remaining exposure.
# bhf's JS/TS lane needs only `node` + `esbuild` at runtime.
RUN apt-get update && apt-get install -y --no-install-recommends npm \
    && npm install -g --prefix /usr/local --no-fund --no-audit esbuild@0.28.2 \
    && npm cache clean --force \
    && apt-get purge -y npm && apt-get autoremove -y --purge \
    && rm -rf /var/lib/apt/lists/* /root/.npm \
    && esbuild --version && node --version

# Ruby ships default gems that carry advisories (erb, net-imap, zlib). Update them
# so the interpreter loads the patched versions, and for `erb` (self-contained,
# pure-Ruby, the only High) remove the superseded bundled copy so nothing — runtime
# or scanner — sees the old version. bhf's Ruby lane fuzzes target code and does not
# invoke these gems, so any residual is not in its execution path (see ato.md).
RUN set -eu; gem install --no-document erb:6.0.7 net-imap:0.6.7 zlib:3.2.3; \
    rubylib="$(ruby -e 'puts RbConfig::CONFIG["rubylibdir"]')"; \
    defdir="$(ruby -e 'require "rubygems"; puts Gem.default_specifications_dir')"; \
    rm -f "$rubylib/erb.rb" "$defdir"/erb-*.gemspec; rm -rf "$rubylib/erb" /root/.local/share/gem /root/.gem; \
    ruby -e 'require "erb"; require "json"; require "net/imap"; require "zlib"; abort("erb not patched") unless Gem::Version.new(ERB.version) >= Gem::Version.new("6")' \
    && echo "erb runtime $(ruby -e 'require "erb"; puts ERB.version')"

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1

# --- C# instrumentation CLI (SharpFuzz) into a shared tools path ------------
RUN dotnet tool install --tool-path /usr/local/dotnet-tools --version 2.3.0 SharpFuzz.CommandLine \
    && chmod -R a+rX /usr/local/dotnet-tools

# --- License compliance: third-party notices + GPL/LGPL corresponding-source offer ---
# BHF's own license is Apache-2.0; bundled packages retain their own terms.
# These generated notices cover OS packages. Per-package full license
# text stays in /usr/share/doc/*/copyright. See docs/site/docker.md#licensing.
COPY docker/compliance/ /usr/local/share/bhf/compliance/
ARG BHF_VERSION=0.2.34
RUN bash /usr/local/share/bhf/compliance/generate-notices.sh /usr/share/bhf/licenses \
    && bash /usr/local/share/bhf/compliance/generate-sbom.sh /usr/share/bhf/sbom/os.cyclonedx.json \
    && install -m 0644 /usr/local/share/bhf/compliance/WRITTEN-OFFER.md /usr/share/bhf/licenses/ \
    && install -m 0644 /usr/local/share/bhf/compliance/README.md        /usr/share/bhf/licenses/ \
    && install -m 0755 /usr/local/share/bhf/compliance/fetch-sources.sh /usr/share/bhf/licenses/

# --- bhf binaries + Linux shims from the builder ---------------------------
COPY --from=builder /out/bhf            /usr/local/bin/bhf
COPY --from=builder /out/bhf-daemon     /usr/local/bin/bhf-daemon
COPY --from=builder /out/libbhf_runtrace_shim.so /usr/local/lib/bhf/libbhf_runtrace_shim.so
COPY --from=builder /out/libbhf_cc_intercept.so  /usr/local/lib/bhf/libbhf_cc_intercept.so
COPY --from=builder /out/inventory/ /usr/share/bhf/sbom/

# --- Air-gap: stage bhf's own instrumentation dependencies -----------------
# Java: build-agent.sh needs asm + asm-tree to shade into the JVM coverage agent.
# It fetches them from Maven Central unless ASM_JAR_DIR/BHF_JVM_CACHE has them.
# The maven/JDK packages already ship /usr/share/java/asm-9.7.jar + asm-tree-9.7.jar,
# so pointing bhf there makes the Java lane build its agent fully offline.
ENV ASM_JAR_DIR=/usr/share/java
COPY java_runtime/ /usr/local/share/bhf/java_runtime/
RUN mkdir -p /usr/local/share/bhf/jvm /tmp/bhf-jvm-cache \
    && BHF_JVM_CACHE=/tmp/bhf-jvm-cache \
       sh /usr/local/share/bhf/java_runtime/build-agent.sh /usr/local/share/bhf/jvm/bhf-jvm-agent.jar \
    && rm -rf /tmp/bhf-jvm-cache
ENV BHF_JVM_AGENT_JAR=/usr/local/share/bhf/jvm/bhf-jvm-agent.jar

# Runtime env: shim paths, per-user Rust toolchain, C# tools + NuGet cache.
ENV BHF_RUNTRACE_SHIM=/usr/local/lib/bhf/libbhf_runtrace_shim.so \
    BHF_CC_INTERCEPT=/usr/local/lib/bhf/libbhf_cc_intercept.so \
    RUSTUP_HOME=/home/fuzzer/.rustup \
    CARGO_HOME=/home/fuzzer/.cargo \
    PATH=/home/fuzzer/.cargo/bin:/usr/local/go/bin:/usr/local/dotnet-tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Sanitizer defaults tuned for containerised fuzzing. bhf sets the AFL/ASan
# keys it strictly needs per-invocation; these are safe process-wide defaults.
ENV ASAN_OPTIONS=abort_on_error=1:handle_abort=1:allocator_may_return_null=1 \
    UBSAN_OPTIONS=abort_on_error=1 \
    AFL_SKIP_CPUFREQ=1 \
    AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

# Go build defaults for generated harnesses: -mod=mod lets `go build` add the
# target's transitive requires/sums into the harness module, and GOTOOLCHAIN=local
# pins the installed toolchain so a target's `go`/`toolchain` directive never
# triggers a surprise toolchain download mid-build.
ENV GOFLAGS=-mod=mod \
    GOTOOLCHAIN=local

# --- Non-root user -----------------------------------------------------------
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin fuzzer \
    && mkdir -p /work && chown fuzzer:fuzzer /work

COPY --chown=root:root docker/entrypoint.sh /usr/local/bin/bhf-entrypoint
COPY --chown=root:root docker/bhf-sweep.sh  /usr/local/bin/bhf-sweep
COPY --chown=root:root docker/fetch-corpus.sh /usr/local/bin/bhf-fetch-corpus
COPY --chown=root:root docker/sweep-manifest.tsv /usr/local/share/bhf/sweep-manifest.tsv
COPY --chown=root:root docker/sweep_contract.py /usr/local/bin/sweep_contract.py
RUN chmod 0755 /usr/local/bin/bhf-entrypoint /usr/local/bin/bhf-sweep /usr/local/bin/bhf-fetch-corpus

# Everything below runs AS the unprivileged fuzzer so the Rust toolchain and the
# NuGet cache land in $HOME already owned by fuzzer — no `chown -R` over a large
# tree, which would otherwise duplicate ~900 MB of toolchain into its own layer.
USER fuzzer
WORKDIR /home/fuzzer

# Rust nightly for the sanitizer/coverage lane. The image sets an explicit dated
# channel so bhf's Rust lane probes the preinstalled toolchain rather than a
# rolling `cargo +nightly` (crates/cli/src/auto/rust_build.rs). rust-src is NOT
# added: bhf instruments via SanitizerCoverage flags, not -Zbuild-std.
ENV BHF_RUST_NIGHTLY=nightly-2026-06-10
RUN curl --proto '=https' --tlsv1.2 -fsSLo /tmp/rustup-init https://static.rust-lang.org/rustup/archive/1.28.2/x86_64-unknown-linux-gnu/rustup-init \
    && echo '20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c  /tmp/rustup-init' | sha256sum -c - \
    && chmod +x /tmp/rustup-init \
    && /tmp/rustup-init -y --profile minimal --default-toolchain nightly-2026-06-10 \
    && rm /tmp/rustup-init \
    && rustup component add --toolchain nightly-2026-06-10 llvm-tools-preview \
    && rustc +nightly-2026-06-10 --version

# C# air-gap: prime the fuzzer's default NuGet cache with SharpFuzz 2.3.0 (bhf's
# own instrumentation dependency) plus the SDK build packages a net8.0 harness
# restore pulls, so a self-contained C# target builds offline. A target with its
# OWN NuGet PackageReferences still needs those staged into NUGET_PACKAGES by the
# operator (see docs/site/docker.md), exactly like a Maven target's ~/.m2.
RUN set -eux; d="$(mktemp -d)"; cd "$d"; \
    printf '%s' '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework><LangVersion>latest</LangVersion></PropertyGroup><ItemGroup><PackageReference Include="SharpFuzz" Version="2.3.0" /></ItemGroup></Project>' > warm.csproj; \
    echo 'class P{static void Main(){}}' > Program.cs; \
    dotnet build -c Release -v quiet; \
    cd /; rm -rf "$d"

WORKDIR /work
ENV BHF_SWEEP_MANIFEST=/usr/local/share/bhf/sweep-manifest.tsv

# Build metadata (pass with --build-arg for reproducible provenance):
#   docker build --build-arg VCS_REF=$(git rev-parse HEAD) \
#                --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) ...
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG BHF_SOURCE_SHA256=unknown
LABEL org.opencontainers.image.title="bhf" \
      org.opencontainers.image.description="BHF full-language tooling; project dependencies require explicit offline staging" \
      org.opencontainers.image.source="https://github.com/Tarmo-Technologies/bhf" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Tarmo Technologies" \
      org.opencontainers.image.version="${BHF_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}"
LABEL io.tarmo.bhf.source-archive-sha256="${BHF_SOURCE_SHA256}" io.tarmo.bhf.flavor="runtime"

ENTRYPOINT ["/usr/bin/tini","--","/usr/local/bin/bhf-entrypoint"]
CMD ["--help"]

########################################  core  ########################################
# Default distribution: C/C++ build-and-fuzz tools, deterministic CLI/daemon,
# and Linux shims. The full sixteen-language environment remains available as
# `docker build --target runtime ...` (the validation Compose profile uses it).
FROM ubuntu-pinned AS core
ARG TARGETPLATFORM
RUN test "${TARGETPLATFORM}" = linux/amd64
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8 LC_ALL=C.UTF-8
RUN apt-get update && apt-get -y dist-upgrade && apt-get install -y --no-install-recommends \
      ca-certificates clang llvm lld libclang-rt-18-dev make git file tini python3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/bhf /usr/local/bin/bhf
COPY --from=builder /out/bhf-daemon /usr/local/bin/bhf-daemon
COPY --from=builder /out/libbhf_runtrace_shim.so /usr/local/lib/bhf/libbhf_runtrace_shim.so
COPY --from=builder /out/libbhf_cc_intercept.so /usr/local/lib/bhf/libbhf_cc_intercept.so
COPY --from=builder /out/inventory/ /usr/share/bhf/sbom/
COPY docker/compliance/ /usr/local/share/bhf/compliance/
ARG BHF_VERSION=0.2.34
RUN bash /usr/local/share/bhf/compliance/generate-notices.sh /usr/share/bhf/licenses \
    && bash /usr/local/share/bhf/compliance/generate-sbom.sh /usr/share/bhf/sbom/os.cyclonedx.json \
    && install -m 0644 /usr/local/share/bhf/compliance/WRITTEN-OFFER.md /usr/share/bhf/licenses/ \
    && install -m 0644 /usr/local/share/bhf/compliance/README.md /usr/share/bhf/licenses/ \
    && install -m 0755 /usr/local/share/bhf/compliance/fetch-sources.sh /usr/share/bhf/licenses/
COPY --chown=root:root docker/entrypoint.sh /usr/local/bin/bhf-entrypoint
RUN chmod 0755 /usr/local/bin/bhf-entrypoint \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin fuzzer \
    && mkdir -p /work && chown fuzzer:fuzzer /work
ENV BHF_RUNTRACE_SHIM=/usr/local/lib/bhf/libbhf_runtrace_shim.so \
    BHF_CC_INTERCEPT=/usr/local/lib/bhf/libbhf_cc_intercept.so \
    ASAN_OPTIONS=abort_on_error=1:handle_abort=1:allocator_may_return_null=1 \
    UBSAN_OPTIONS=abort_on_error=1 \
    AFL_SKIP_CPUFREQ=1 \
    AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
USER fuzzer
WORKDIR /work
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG BHF_SOURCE_SHA256=unknown
LABEL org.opencontainers.image.title="bhf" \
      org.opencontainers.image.description="BHF core C/C++ build-and-fuzz image" \
      org.opencontainers.image.source="https://github.com/Tarmo-Technologies/bhf" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Tarmo Technologies" \
      org.opencontainers.image.version="${BHF_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      io.tarmo.bhf.source-archive-sha256="${BHF_SOURCE_SHA256}" \
      io.tarmo.bhf.flavor="core"
ENTRYPOINT ["/usr/bin/tini","--","/usr/local/bin/bhf-entrypoint"]
CMD ["--help"]

########################################  ada  ########################################
FROM core AS ada
USER root
RUN apt-get update && apt-get install -y --no-install-recommends gnat gprbuild \
    && rm -rf /var/lib/apt/lists/* \
    && bash /usr/local/share/bhf/compliance/generate-notices.sh /usr/share/bhf/licenses \
    && bash /usr/local/share/bhf/compliance/generate-sbom.sh /usr/share/bhf/sbom/os.cyclonedx.json
LABEL io.tarmo.bhf.flavor="ada"
USER fuzzer

# Keep the default build identical to core, despite optional stages above.
FROM core AS production
