# SPDX-License-Identifier: Apache-2.0
# syntax=docker/dockerfile:1.7
#
# BHF — Build Harness Fuzz — all-language default and selected-language targets.
#
# Multi-stage:
#   1. builder  : compiles the release binaries (CLI, daemon, both Linux shims)
#                 against Ubuntu 24.04 glibc so the shims match the runtime.
#   2. runtime  : default full-language target, Ubuntu 24.04 carrying every one of the sixteen language
#                 toolchains bhf can build/harness/fuzz, plus AFL++ and a Rust
#                 nightly for the Rust sanitizer lane. Runs as a non-root user
#                 under tini. bhf's own instrumentation deps
#                 (the JVM coverage agent's ASM jars, the C# SharpFuzz package)
#                 are staged at build time; target-project dependencies are a
#                 separate staging responsibility.
#   3. core     : explicit C/C++ build-and-fuzz target without the other
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
ARG TARGETARCH
COPY docker/toolchain-platform.sh /usr/local/share/bhf/toolchain-platform.sh
ARG UBUNTU_SNAPSHOT=20261004T000000Z
RUN printf 'APT::Snapshot "%s";\nAPT::Update::Error-Mode "any";\n' "${UBUNTU_SNAPSHOT}" > /etc/apt/apt.conf.d/50snapshot
# Ubuntu ports sources do not opt into APT's snapshot selector. Use an
# explicit snapshot URL on ARM64 and avoid filtering it a second time.
RUN if [ "$TARGETARCH" = arm64 ]; then \
      printf 'APT::Update::Error-Mode "any";\n' > /etc/apt/apt.conf.d/50snapshot; \
      printf 'Types: deb\nURIs: https://snapshot.ubuntu.com/ubuntu/%s/\nSuites: noble noble-updates noble-backports noble-security\nComponents: main restricted universe multiverse\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n' "$UBUNTU_SNAPSHOT" > /etc/apt/sources.list.d/ubuntu.sources; \
    fi
LABEL io.tarmo.bhf.ubuntu-snapshot="${UBUNTU_SNAPSHOT}"

# Prepare the supported JS/TS tools without shipping npm's dependency tree.
FROM ubuntu-pinned AS javascript-tools
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG BHF_LANGUAGES=all
COPY scripts/language-selection.sh /selection.sh
RUN source /usr/local/share/bhf/toolchain-platform.sh; bhf_toolchain_platform "$TARGETARCH"; \
    source /selection.sh; languages="$(bhf_resolve_languages "$BHF_LANGUAGES")" || exit; \
    mkdir -p /out/usr/local/bin /out/usr/share/bhf/licenses/javascript; \
    if bhf_has_language "$languages" javascript || bhf_has_language "$languages" typescript; then \
      apt-get update && apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
      && curl --proto '=https' --tlsv1.2 -fsSLo /tmp/node.tar.xz "https://nodejs.org/dist/v24.21.0/node-v24.21.0-linux-${BHF_NODE_ARCH}.tar.xz" \
      && echo "${BHF_NODE_SHA256}  /tmp/node.tar.xz" | sha256sum -c - \
      && mkdir -p /opt/node && tar -xJf /tmp/node.tar.xz --strip-components=1 -C /opt/node \
      && cp /opt/node/bin/node /out/usr/local/bin/node \
      && cp /opt/node/LICENSE /out/usr/share/bhf/licenses/javascript/node-LICENSE \
      && /out/usr/local/bin/node --version || exit; \
      if bhf_has_language "$languages" typescript; then \
        PATH=/opt/node/bin:$PATH npm install -g --prefix /opt/esbuild --no-fund --no-audit esbuild@0.28.2 \
        && cp /opt/esbuild/lib/node_modules/esbuild/bin/esbuild /out/usr/local/bin/esbuild \
        && cp /opt/esbuild/lib/node_modules/esbuild/LICENSE.md /out/usr/share/bhf/licenses/javascript/esbuild-LICENSE.md \
        && /out/usr/local/bin/esbuild --version || exit; \
      fi; \
    fi

########################################  builder  ########################################
FROM ubuntu-pinned AS builder
ARG TARGETPLATFORM
RUN case "${TARGETPLATFORM}" in linux/amd64|linux/arm64) ;; *) echo "unsupported platform: ${TARGETPLATFORM}" >&2; exit 2 ;; esac

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_TOOLCHAIN=1.99.0 \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Toolchain to compile bhf and its C-runtime bits (the shims are Rust cdylibs,
# but build.rs steps and the C runtime driver want a working C toolchain).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl build-essential make clang llvm lld pkg-config git python3 \
    && rm -rf /var/lib/apt/lists/*

# Pin the reviewed builder Rust version.
RUN . /usr/local/share/bhf/toolchain-platform.sh; bhf_toolchain_platform "$TARGETARCH"; \
    curl --proto '=https' --tlsv1.2 -fsSLo /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/1.28.2/${BHF_RUST_HOST}/rustup-init" \
    && echo "${BHF_RUSTUP_SHA256}  /tmp/rustup-init" | sha256sum -c - \
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
    --mount=type=cache,id=bhf-target-${TARGETARCH},target=/src/target,sharing=locked \
    . /usr/local/share/bhf/toolchain-platform.sh \
    && bhf_toolchain_platform "$TARGETARCH" \
    && mkdir -p /out \
    && BHF_RELEASE_VERSION=1 BHF_VCS_REF="${VCS_REF}" cargo build --locked --release -p bhf -p bhf-daemon -p bhf_runtrace_shim -p bhf_cc_intercept --jobs "${CARGO_BUILD_JOBS}" --message-format=json-render-diagnostics > /out/cargo-messages.jsonl \
    && cp target/release/bhf            /out/bhf \
    && cp target/release/bhf-daemon     /out/bhf-daemon \
    && cp target/release/libbhf_runtrace_shim.so /out/libbhf_runtrace_shim.so \
    && cp target/release/libbhf_cc_intercept.so  /out/libbhf_cc_intercept.so \
    && strip /out/bhf /out/bhf-daemon /out/*.so \
    && python3 scripts/ci/rust-image-inventory.py --artifacts /out --messages /out/cargo-messages.jsonl \
         --commit "${VCS_REF}" --source-sha "${BHF_SOURCE_SHA256}" --target "${BHF_RUST_HOST}"

########################################  runtime  ########################################
FROM ubuntu-pinned AS runtime
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG BHF_LANGUAGES=all
ARG BHF_ENGINES=default
COPY scripts/language-selection.sh /usr/local/share/bhf/language-selection.sh
ARG TARGETPLATFORM
RUN case "${TARGETPLATFORM}" in linux/amd64|linux/arm64) ;; *) echo "unsupported platform: ${TARGETPLATFORM}" >&2; exit 2 ;; esac

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Operational Python is shared by inventory and diagnostics. Native linking
# tools are selected by the shared closure; no all-language parent is used.
RUN source /usr/local/share/bhf/language-selection.sh; \
    languages="$(bhf_resolve_languages "$BHF_LANGUAGES")" || exit; \
    case "$BHF_ENGINES" in default|builtin) ;; *) echo 'invalid BHF_ENGINES' >&2; exit 2 ;; esac; \
    mapfile -t packages < <(bhf_language_packages container "$languages"); \
    if [[ "$BHF_ENGINES" == default ]]; then packages+=(afl++); fi; \
    apt-get update && apt-get -y dist-upgrade && apt-get install -y --no-install-recommends \
      ca-certificates curl xz-utils file git tini locales python3 "${packages[@]}" \
    && rm -rf /var/lib/apt/lists/* && locale-gen C.UTF-8 \
    && printf '%s\n' "$languages" > /usr/local/share/bhf/selected-languages.txt \
    && printf '%s\n' "$BHF_ENGINES" > /usr/local/share/bhf/selected-engines.txt

# Go from upstream (pinned + checksum-verified).
ARG GO_VERSION=1.27.1
RUN source /usr/local/share/bhf/language-selection.sh; \
    languages="$(cat /usr/local/share/bhf/selected-languages.txt)"; \
    if bhf_has_language "$languages" go; then \
    source /usr/local/share/bhf/toolchain-platform.sh; bhf_toolchain_platform "$TARGETARCH"; \
    curl --proto '=https' --tlsv1.2 -fsSLo /tmp/go.tgz \
        "https://go.dev/dl/go${GO_VERSION}.linux-${BHF_GO_ARCH}.tar.gz" \
    && echo "${BHF_GO_SHA256}  /tmp/go.tgz" | sha256sum -c - \
    && tar -C /usr/local -xzf /tmp/go.tgz \
    && rm -f /tmp/go.tgz \
    && /usr/local/go/bin/go version ; \
    fi

COPY --from=javascript-tools /out/ /

# Maven's upstream distribution retains its bundled licenses and has newer
# dependencies than the archived Ubuntu Maven package.
RUN source /usr/local/share/bhf/language-selection.sh; \
    languages="$(cat /usr/local/share/bhf/selected-languages.txt)"; \
    if bhf_has_language "$languages" java; then \
    curl --proto '=https' --tlsv1.2 -fsSLo /tmp/maven.tgz https://archive.apache.org/dist/maven/maven-3/3.10.0/binaries/apache-maven-3.10.0-bin.tar.gz \
    && echo '908b1501bfb420bf7c8affb855534a9c407fd6099367bfb9f2f2dcb8e9799102bffb84518cde74c679bd76870247c6528683abdd620581bffa90f95d92d175aa  /tmp/maven.tgz' | sha512sum -c - \
    && mkdir /opt/maven && tar -xzf /tmp/maven.tgz --strip-components=1 -C /opt/maven \
    && ln -s /opt/maven/bin/mvn /usr/local/bin/mvn && rm /tmp/maven.tgz \
    && mvn --version ; \
    fi

COPY docker/python-build-tools.txt /usr/local/share/bhf/python-build-tools.txt
RUN source /usr/local/share/bhf/language-selection.sh; \
    languages="$(cat /usr/local/share/bhf/selected-languages.txt)"; \
    if bhf_has_language "$languages" python; then \
    python3 -m pip install --break-system-packages --ignore-installed --no-cache-dir --no-deps --require-hashes \
      -r /usr/local/share/bhf/python-build-tools.txt \
    && rm -rf /usr/lib/python3/dist-packages/pip* \
              /usr/lib/python3/dist-packages/setuptools* /usr/lib/python3/dist-packages/pkg_resources* \
              /usr/lib/python3/dist-packages/wheel* /usr/lib/python3/dist-packages/packaging* \
    && python3 -m pip --version \
    && python3 -c 'import setuptools, wheel, packaging; assert setuptools.__version__ == "84.0.0"; assert wheel.__version__ == "0.48.0"' ; \
    fi

# Pin reviewed Ruby component versions and remove superseded installed copies,
# including default-gem files and specifications. Keep the patched components
# usable by the interpreter and retain their licenses and source in the image.
RUN source /usr/local/share/bhf/language-selection.sh; \
    languages="$(cat /usr/local/share/bhf/selected-languages.txt)"; \
    if bhf_has_language "$languages" ruby; then \
    set -eu; gem install --no-document erb:6.0.7 net-imap:0.6.7 zlib:3.2.3 rexml:3.4.4 webrick:1.9.2 cgi:0.5.2 resolv:0.7.2; \
    gem uninstall --install-dir /usr/lib/ruby/gems/3.2.0 --ignore-dependencies --executables net-imap -v 0.3.4.1; \
    gem uninstall --install-dir /usr/lib/ruby/gems/3.2.0 --ignore-dependencies --executables rexml -v 3.2.5; \
    gem uninstall --install-dir /usr/share/rubygems-integration/all --ignore-dependencies --executables webrick -v 1.8.1; \
    rubylib="$(ruby -e 'puts RbConfig::CONFIG["rubylibdir"]')"; \
    rubyarch="$(ruby -e 'puts RbConfig::CONFIG["archdir"]')"; \
    defdir="$(ruby -e 'require "rubygems"; puts Gem.default_specifications_dir')"; \
    rm -f "$rubylib/erb.rb" "$defdir"/erb-*.gemspec; rm -rf "$rubylib/erb" /root/.local/share/gem /root/.gem; \
    rm -f "$rubylib/cgi.rb" "$rubylib/resolv.rb" "$rubyarch/zlib.so" \
          "$defdir"/cgi-*.gemspec "$defdir"/resolv-*.gemspec "$defdir"/zlib-*.gemspec; \
    rm -rf "$rubylib/cgi" "$rubyarch/cgi" /usr/lib/ruby/gems/3.2.0/gems/cgi-0.3.6 \
           /usr/lib/ruby/gems/3.2.0/gems/resolv-0.2.2 /usr/lib/ruby/gems/3.2.0/gems/zlib-3.0.0; \
    ruby -e 'require "erb"; require "json"; require "net/imap"; require "zlib"; abort("erb not patched") unless Gem::Version.new(ERB.version) >= Gem::Version.new("6")' \
    && ruby -e 'require "cgi"; require "resolv"; require "zlib"; {"cgi"=>"0.5.2", "resolv"=>"0.7.2", "zlib"=>"3.2.3"}.each { |n,v| abort("incorrect loaded gem: " + n) unless Gem.loaded_specs[n].version.to_s == v }' \
    && echo "erb runtime $(ruby -e 'require "erb"; puts ERB.version')" ; \
    fi

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1

# --- C# instrumentation CLI (SharpFuzz) into a shared tools path ------------
RUN source /usr/local/share/bhf/language-selection.sh; \
    languages="$(cat /usr/local/share/bhf/selected-languages.txt)"; \
    if bhf_has_language "$languages" csharp; then \
    dotnet tool install --tool-path /usr/local/dotnet-tools --version 2.3.0 SharpFuzz.CommandLine \
    && chmod -R a+rX /usr/local/dotnet-tools ; \
    fi

# --- License compliance: third-party notices + GPL/LGPL corresponding-source offer ---
# BHF's own license is Apache-2.0; bundled packages retain their own terms.
# These generated notices cover OS packages. Per-package full license
# text stays in /usr/share/doc/*/copyright. See docs/site/docker.md#licensing.
COPY docker/compliance/ /usr/local/share/bhf/compliance/
ARG BHF_VERSION=0.0.0-local
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
RUN source /usr/local/share/bhf/language-selection.sh; \
    languages="$(cat /usr/local/share/bhf/selected-languages.txt)"; \
    if bhf_has_language "$languages" java; then \
    mkdir -p /usr/local/share/bhf/jvm /tmp/bhf-jvm-cache \
    && BHF_JVM_CACHE=/tmp/bhf-jvm-cache \
       sh /usr/local/share/bhf/java_runtime/build-agent.sh /usr/local/share/bhf/jvm/bhf-jvm-agent.jar \
    && rm -rf /tmp/bhf-jvm-cache ; \
    fi
ENV BHF_JVM_AGENT_JAR=/usr/local/share/bhf/jvm/bhf-jvm-agent.jar

# Runtime env: shim paths, per-user Rust toolchain, C# tools + NuGet cache.
ENV BHF_RUNTRACE_SHIM=/usr/local/lib/bhf/libbhf_runtrace_shim.so \
    BHF_CC_INTERCEPT=/usr/local/lib/bhf/libbhf_cc_intercept.so \
    RUSTUP_HOME=/home/fuzzer/.rustup \
    CARGO_HOME=/home/fuzzer/.cargo \
    PATH=/home/fuzzer/.cargo/bin:/usr/local/go/bin:/usr/local/dotnet-tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Sanitizer defaults tuned for containerized fuzzing. bhf sets the AFL/ASan
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
RUN chmod 0755 /usr/local/bin/bhf-entrypoint

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
RUN source /usr/local/share/bhf/language-selection.sh; \
    languages="$(cat /usr/local/share/bhf/selected-languages.txt)"; \
    if bhf_has_language "$languages" rust; then \
    source /usr/local/share/bhf/toolchain-platform.sh; bhf_toolchain_platform "$TARGETARCH"; \
    curl --proto '=https' --tlsv1.2 -fsSLo /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/1.28.2/${BHF_RUST_HOST}/rustup-init" \
    && echo "${BHF_RUSTUP_SHA256}  /tmp/rustup-init" | sha256sum -c - \
    && chmod +x /tmp/rustup-init \
    && /tmp/rustup-init -y --profile minimal --default-toolchain nightly-2026-06-10 \
    && rm /tmp/rustup-init \
    && rustup component add --toolchain nightly-2026-06-10 llvm-tools-preview \
    && rustc +nightly-2026-06-10 --version ; \
    fi

# C# air-gap: prime the fuzzer's default NuGet cache with SharpFuzz 2.3.0 (bhf's
# own instrumentation dependency) plus the SDK build packages a net8.0 harness
# restore pulls, so a self-contained C# target builds offline. A target with its
# OWN NuGet PackageReferences still needs those staged into NUGET_PACKAGES by the
# operator (see docs/site/docker.md), exactly like a Maven target's ~/.m2.
RUN source /usr/local/share/bhf/language-selection.sh; \
    languages="$(cat /usr/local/share/bhf/selected-languages.txt)"; \
    if bhf_has_language "$languages" csharp; then \
    set -eux; d="$(mktemp -d)"; cd "$d"; \
    printf '%s' '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework><LangVersion>latest</LangVersion></PropertyGroup><ItemGroup><PackageReference Include="SharpFuzz" Version="2.3.0" /></ItemGroup></Project>' > warm.csproj; \
    echo 'class P{static void Main(){}}' > Program.cs; \
    dotnet build -c Release -v quiet; \
    cd /; rm -rf "$d" ; \
    fi

WORKDIR /work
ENV BHF_SWEEP_MANIFEST=/usr/local/share/bhf/sweep-manifest.tsv \
    NUGET_PACKAGES=/home/fuzzer/.nuget/packages

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
LABEL io.tarmo.bhf.source-archive-sha256="${BHF_SOURCE_SHA256}" io.tarmo.bhf.flavor="runtime" \
      io.tarmo.bhf.languages="${BHF_LANGUAGES}" io.tarmo.bhf.engines="${BHF_ENGINES}"

ENTRYPOINT ["/usr/bin/tini","--","/usr/local/bin/bhf-entrypoint"]
CMD ["--help"]

########################################  core  ########################################
# Legacy explicit profile: C/C++ tools, deterministic CLI/daemon,
# and Linux shims. The full sixteen-language environment remains available as
# `docker build --target runtime ...` (the validation Compose profile uses it).
FROM ubuntu-pinned AS core
ARG TARGETPLATFORM
RUN case "${TARGETPLATFORM}" in linux/amd64|linux/arm64) ;; *) echo "unsupported platform: ${TARGETPLATFORM}" >&2; exit 2 ;; esac
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
ARG BHF_VERSION=0.0.0-local
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

# Validation helpers are an explicit component; never fetched/executed by default.
FROM runtime AS validation
USER root
COPY docker/bhf-sweep.sh /usr/local/bin/bhf-sweep
COPY docker/fetch-corpus.sh /usr/local/bin/bhf-fetch-corpus
COPY docker/sweep-manifest.tsv /usr/local/share/bhf/sweep-manifest.tsv
COPY docker/sweep_contract.py /usr/local/bin/sweep_contract.py
RUN chmod 0755 /usr/local/bin/bhf-sweep /usr/local/bin/bhf-fetch-corpus
USER fuzzer

# Include every supported language unless a smaller selection is explicit.
FROM runtime AS production
