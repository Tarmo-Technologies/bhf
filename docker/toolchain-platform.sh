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
            BHF_NODE_SHA256=4f2b175a6d53a5c617a80dba2676238a0688cef28c6da4eba35c7d844e66fcfb
            BHF_GO_SHA256=7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840
            BHF_DOTNET_ARCH=x64
            BHF_DOTNET_SHA512=a7e10581123a8fc79bfa807f20cddec4ab1d190b1f7ee64dc690d0358cd3515d33462e54e109b5b9f55f6fbb75d16a54d01d7d35d25465f97765b86c48d79796
            ;;
        arm64)
            BHF_RUST_HOST=aarch64-unknown-linux-gnu
            BHF_NODE_ARCH=arm64
            BHF_RUSTUP_SHA256=e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c
            BHF_NODE_SHA256=6e51a2ada00f0011cc266f65d98922b403d7ad88f809ca2aa615a5fe1ce6e86c
            BHF_GO_SHA256=3392582988a273a87ab5043ee1b2c9c17a2c3c00580bf9326c47a2e0aaaeac92
            BHF_DOTNET_ARCH=arm64
            BHF_DOTNET_SHA512=a2598dbd6b207eaaed8bb1f4a546f3f405285606ba2301c6ee75b9dda08e0789bee51a20a3bb94d87f7a6e191e7e0b4932589df4d6c91709485932a75bf9fa66
            ;;
        *) echo "unsupported container architecture: $1 (use amd64 or arm64)" >&2; return 2 ;;
    esac
    BHF_GO_ARCH="$1"
    export BHF_RUST_HOST BHF_NODE_ARCH BHF_GO_ARCH BHF_DOTNET_ARCH
    export BHF_RUSTUP_SHA256 BHF_NODE_SHA256 BHF_GO_SHA256 BHF_DOTNET_SHA512
}
