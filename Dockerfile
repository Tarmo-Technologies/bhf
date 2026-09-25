# SPDX-License-Identifier: Apache-2.0
# syntax=docker/dockerfile:1.7
#
# BHF — Build Harness Fuzz — production container.
#
# Multi-stage:
#   1. builder  : compiles the Rust workspace (CLI, daemon, both Linux shims)
#                 against Ubuntu 24.04 glibc so the shims match the runtime.
#   2. runtime  : Ubuntu 24.04 carrying every one of the sixteen language
#                 toolchains bhf can build/harness/fuzz, plus AFL++ and a Rust
#                 nightly for the Rust sanitizer lane. Runs as a non-root user
#                 under tini. Air-gap ready: bhf's own instrumentation deps
#                 (the JVM coverage agent's ASM jars, the C# SharpFuzz package)
#                 are staged at build time so no lane reaches the network to fuzz.
#
# Fuzzing needs a few runtime privileges the image cannot grant itself; grant
# them at `docker run` time (see docker/compose.yaml and docs/site/docker.md):
#   --cap-add=SYS_PTRACE     LeakSanitizer / ASan stop-the-world
#   --shm-size=2g            coverage bitmaps + cmplog shared memory
#   -v bhf_work:/work        persist findings, corpora, replay binaries

########################################  builder  ########################################
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Toolchain to compile bhf and its C-runtime bits (the shims are Rust cdylibs,
# but build.rs steps and the C runtime driver want a working C toolchain).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl build-essential make clang llvm lld pkg-config git \
    && rm -rf /var/lib/apt/lists/*

# Pin Rust to the channel the workspace declares (rust-toolchain.toml -> stable).
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain stable \
    && rustc --version && cargo --version

WORKDIR /src
COPY . .
ARG CARGO_BUILD_JOBS=2

# Build the whole workspace. Cache the registry and target dir across rebuilds,
# then lift just the artifacts out of the cache mount into a real layer.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --locked --release --workspace --jobs "${CARGO_BUILD_JOBS}" \
    && mkdir -p /out \
    && cp target/release/bhf            /out/bhf \
    && cp target/release/bhf-daemon     /out/bhf-daemon \
    && cp target/release/libbhf_runtrace_shim.so /out/libbhf_runtrace_shim.so \
    && cp target/release/libbhf_cc_intercept.so  /out/libbhf_cc_intercept.so \
    && strip /out/bhf /out/bhf-daemon /out/*.so

########################################  runtime  ########################################
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# --- Base utilities + the sixteen language toolchains -----------------------
# C/C++ (clang/llvm/make) is mandatory; the rest install cleanly and a target
# whose toolchain is absent simply skips, so this image covers every lane.
# NB: the JDK is headless (no AWT/X11 -> no mesa/second-LLVM pull) and Gradle is
# omitted (Maven + javac cover the Java lane; a Gradle project's build recovery
# is the one lane feature traded for a much smaller image). See docs/site/docker.md.
# `dist-upgrade` first pulls the latest -security/-updates patches over the pinned
# base layer (CVE remediation, RA-5/SI-2). Go is installed from the upstream
# tarball below, NOT `golang-go` — Ubuntu's Go lags and drags ~1000 CVE-flagged
# stdlib/vendored modules; upstream Go ships the fixes.
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
        nodejs npm \
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

# Go from upstream (pinned + checksum-verified) — current stdlib, CVEs fixed.
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
# now-orphaned node-* deps — which carry the only npm-layer CVEs (handlebars,
# nanoid/postcss, …). bhf's JS/TS lane needs only `node` + `esbuild` at runtime.
RUN npm install -g --prefix /usr/local --no-fund --no-audit esbuild@0.28.2 \
    && npm cache clean --force \
    && apt-get purge -y npm && apt-get autoremove -y --purge \
    && rm -rf /var/lib/apt/lists/* /root/.npm \
    && esbuild --version && node --version

# Ruby ships default gems that carry advisories (erb, net-imap, zlib). Update them
# so the interpreter loads the patched versions, and for `erb` (self-contained,
# pure-Ruby, the only High) remove the superseded bundled copy so nothing — runtime
# or scanner — sees the old version. bhf's Ruby lane fuzzes target code and does not
# invoke these gems, so any residual is not in its execution path (see ato.md).
RUN set -eu; gem update --no-document erb net-imap zlib; \
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
# The image aggregates (does not link) these programs; bhf stays Apache-2.0. The
# only duty redistribution creates is source availability for the GPL/LGPL
# packages — captured here from the exact installed set. Per-package full license
# text stays in /usr/share/doc/*/copyright. See docs/site/docker.md#licensing.
COPY docker/compliance/ /usr/local/share/bhf/compliance/
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

# --- Air-gap: stage bhf's own instrumentation dependencies -----------------
# Java: build-agent.sh needs asm + asm-tree to shade into the JVM coverage agent.
# It fetches them from Maven Central unless ASM_JAR_DIR/BHF_JVM_CACHE has them.
# The maven/JDK packages already ship /usr/share/java/asm-9.7.jar + asm-tree-9.7.jar,
# so pointing bhf there makes the Java lane build its agent fully offline.
ENV ASM_JAR_DIR=/usr/share/java

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

# Rust nightly for the sanitizer/coverage lane. Kept as the ROLLING `nightly`
# channel on purpose — bhf's Rust lane probes the plain `cargo +nightly`
# (crates/cli/src/auto/rust_build.rs) with no dated fallback. rust-src is NOT
# added: bhf instruments via SanitizerCoverage flags, not -Zbuild-std.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain nightly \
    && rustup component add --toolchain nightly llvm-tools-preview \
    && rustc +nightly --version

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
ARG BHF_VERSION=0.2.32
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG BHF_SOURCE_SHA256=unknown
LABEL org.opencontainers.image.title="bhf" \
      org.opencontainers.image.description="BHF (Build Harness Fuzz) — offline sixteen-language automated fuzzer and harness generator" \
      org.opencontainers.image.source="https://github.com/Tarmo-Technologies/bhf" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Tarmo Technologies" \
      org.opencontainers.image.version="${BHF_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}"
LABEL io.tarmo.bhf.source-archive-sha256="${BHF_SOURCE_SHA256}"

HEALTHCHECK --interval=1m --timeout=10s --retries=3 CMD ["bhf","--version"]

ENTRYPOINT ["/usr/bin/tini","--","/usr/local/bin/bhf-entrypoint"]
CMD ["--help"]
