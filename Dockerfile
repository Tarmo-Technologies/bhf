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
#                 under tini.
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

# Build the whole workspace. Cache the registry and target dir across rebuilds,
# then lift just the artifacts out of the cache mount into a real layer.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --workspace \
    && mkdir -p /out \
    && cp target/release/bhf            /out/bhf \
    && cp target/release/bhf-daemon     /out/bhf-daemon \
    && cp target/release/libbhf_runtrace_shim.so /out/libbhf_runtrace_shim.so \
    && cp target/release/libbhf_cc_intercept.so  /out/libbhf_cc_intercept.so \
    && strip /out/bhf /out/bhf-daemon /out/*.so || true

########################################  runtime  ########################################
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# --- Base utilities + the sixteen language toolchains -----------------------
# C/C++ (clang/llvm/make) is mandatory; the rest install cleanly and a target
# whose toolchain is absent simply skips, so this image covers every lane.
RUN apt-get update && apt-get install -y --no-install-recommends \
        # base / runtime plumbing
        ca-certificates curl xz-utils file git tini locales \
        # C / C++  (required build+fuzz lane)
        make clang llvm lld libclang-rt-18-dev \
        # Ada
        gnat gprbuild \
        # Java  (JDK + Maven + Gradle build recovery)
        default-jdk maven gradle \
        # Python  (3.12 -> sys.monitoring coverage)
        python3 python3-dev python3-venv python3-pip \
        # Perl
        perl \
        # Go
        golang-go \
        # Fortran
        gfortran \
        # COBOL  (GnuCOBOL cobc)
        gnucobol \
        # JavaScript / TypeScript  (TS via esbuild, installed below)
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
    && locale-gen C.UTF-8 || true

# TypeScript bundler used by the JS/TS lane (pinned for reproducibility).
RUN npm install -g --no-fund --no-audit esbuild@0.28.2 \
    && npm cache clean --force || true

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
    PATH=/usr/local/cargo/bin:/usr/local/dotnet-tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# --- Rust nightly for the Rust sanitizer/coverage fuzzing lane -------------
# bhf instruments target Rust code with -Zsanitizer + SanitizerCoverage, which
# needs nightly plus rust-src and llvm-tools. The bhf binary itself is already
# compiled in the builder stage; this toolchain is only for building targets.
# NB: kept as the rolling `nightly` channel on purpose — bhf's Rust lane probes
# the plain `cargo +nightly` (crates/cli/src/auto/rust_build.rs) with no dated
# fallback, so a date-pinned toolchain alone would make it skip the lane.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain nightly \
    && rustup component add --toolchain nightly rust-src llvm-tools-preview \
    && rustc +nightly --version

# --- C# instrumentation CLI (SharpFuzz) into a shared tools path ------------
RUN dotnet tool install --tool-path /usr/local/dotnet-tools --version 2.3.0 SharpFuzz.CommandLine \
    && chmod -R a+rX /usr/local/dotnet-tools

# --- bhf binaries + Linux shims from the builder ---------------------------
COPY --from=builder /out/bhf            /usr/local/bin/bhf
COPY --from=builder /out/bhf-daemon     /usr/local/bin/bhf-daemon
COPY --from=builder /out/libbhf_runtrace_shim.so /usr/local/lib/bhf/libbhf_runtrace_shim.so
COPY --from=builder /out/libbhf_cc_intercept.so  /usr/local/lib/bhf/libbhf_cc_intercept.so

ENV BHF_RUNTRACE_SHIM=/usr/local/lib/bhf/libbhf_runtrace_shim.so \
    BHF_CC_INTERCEPT=/usr/local/lib/bhf/libbhf_cc_intercept.so

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

# --- Non-root user + writable caches ---------------------------------------
# The Rust/dotnet lanes update their caches while building targets, so the
# unprivileged fuzzer must own the shared toolchain caches (not world-writable).
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin fuzzer \
    && mkdir -p /work \
    && chown -R fuzzer:fuzzer /work /usr/local/cargo /usr/local/rustup

COPY --chown=root:root docker/entrypoint.sh /usr/local/bin/bhf-entrypoint
COPY --chown=root:root docker/bhf-sweep.sh  /usr/local/bin/bhf-sweep
COPY --chown=root:root docker/fetch-corpus.sh /usr/local/bin/bhf-fetch-corpus
COPY --chown=root:root docker/sweep-manifest.tsv /usr/local/share/bhf/sweep-manifest.tsv
RUN chmod 0755 /usr/local/bin/bhf-entrypoint /usr/local/bin/bhf-sweep /usr/local/bin/bhf-fetch-corpus

USER fuzzer
WORKDIR /work
ENV BHF_SWEEP_MANIFEST=/usr/local/share/bhf/sweep-manifest.tsv

# Build metadata (pass with --build-arg for reproducible provenance):
#   docker build --build-arg VCS_REF=$(git rev-parse HEAD) \
#                --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) ...
ARG BHF_VERSION=0.2.32
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="bhf" \
      org.opencontainers.image.description="BHF (Build Harness Fuzz) — offline sixteen-language automated fuzzer and harness generator" \
      org.opencontainers.image.source="https://github.com/Tarmo-Technologies/bhf" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Tarmo Technologies" \
      org.opencontainers.image.version="${BHF_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}"

HEALTHCHECK --interval=1m --timeout=10s --retries=3 CMD ["bhf","--version"]

ENTRYPOINT ["/usr/bin/tini","--","/usr/local/bin/bhf-entrypoint"]
CMD ["--help"]
