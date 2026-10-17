#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Reviewed upstream archives for each supported Linux container architecture.
# Source this file and call bhf_toolchain_platform with Docker's TARGETARCH.
bhf_toolchain_platform() {
    case "$1" in
        amd64)
            BHF_RUST_HOST=x86_64-unknown-linux-gnu
            BHF_NODE_ARCH=x64
            BHF_RUSTUP_SHA256=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c
            BHF_NODE_SHA256=fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6
            BHF_GO_SHA256=ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5
            BHF_DOTNET_ARCH=x64
            BHF_DOTNET_SHA512=07c007fe88c04a2e8330a97c32de5a1bbbfab719dd6fae29d225e1a5f0cbb3fa0a9c0b9987a4b71c698686cfa9e76d01b0f4d84a67e08290d8600397f6cef3d9
            ;;
        arm64)
            BHF_RUST_HOST=aarch64-unknown-linux-gnu
            BHF_NODE_ARCH=arm64
            BHF_RUSTUP_SHA256=e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c
            BHF_NODE_SHA256=6ad1325edbdb5649c379b75a237147a666c95d4f9ae8d340fef2d1575d289ad2
            BHF_GO_SHA256=94f3e30b8e374bc285e7dadc11e0865726b9bc6e85b841ccceaabc0214c6b7c8
            BHF_DOTNET_ARCH=arm64
            BHF_DOTNET_SHA512=2fd63aaee1d8d2573dd33093f3b250ba06417237f5f6eab5bed95de35593805db20ffba90970bbebaaaeb5ce30a6ffaf4f5640f0911865ee25622830c57e2274
            ;;
        *) echo "unsupported container architecture: $1 (use amd64 or arm64)" >&2; return 2 ;;
    esac
    BHF_GO_ARCH="$1"
    export BHF_RUST_HOST BHF_NODE_ARCH BHF_GO_ARCH BHF_DOTNET_ARCH
    export BHF_RUSTUP_SHA256 BHF_NODE_SHA256 BHF_GO_SHA256 BHF_DOTNET_SHA512
}
