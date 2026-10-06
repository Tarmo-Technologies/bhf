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
            BHF_GO_SHA256=63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445
            ;;
        arm64)
            BHF_RUST_HOST=aarch64-unknown-linux-gnu
            BHF_NODE_ARCH=arm64
            BHF_RUSTUP_SHA256=e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c
            BHF_NODE_SHA256=6ad1325edbdb5649c379b75a237147a666c95d4f9ae8d340fef2d1575d289ad2
            BHF_GO_SHA256=3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec
            ;;
        *) echo "unsupported container architecture: $1 (use amd64 or arm64)" >&2; return 2 ;;
    esac
    BHF_GO_ARCH="$1"
    export BHF_RUST_HOST BHF_NODE_ARCH BHF_GO_ARCH
    export BHF_RUSTUP_SHA256 BHF_NODE_SHA256 BHF_GO_SHA256
}
