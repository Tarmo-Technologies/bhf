#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# hil-emu.sh — the emulator-in-the-loop validation lane that CANNOT silently skip.
#
# It runs the REAL (live-QEMU) transport validations for the RTOS/radar / HDF-1 /
# HDF-4 work:
#
#   RV-1  big_endian_input_reaches_a_native_endian_branch_only_on_the_target
#         (cross-endian fidelity: same bytes hit a native-endian branch only on
#          the big-endian ppc64 target under qemu-ppc64)
#   RV-2  live_gdb            — the real RSP client against a real qemu-arm gdbstub
#   RV-3  live_fullsystem     — FullSystemTransport end-to-end on emulated Cortex-M
#                               (qemu-system-arm mps2-an385: savevm/loadvm snapshot
#                                reset + coverage-ring readback + planted fault)
#
# Unlike the default `cargo test` (which self-skips when the emulator/cross
# toolchains are absent), this lane first HARD-FAILS if any required tool is
# missing, then runs the gated tests with BHF_HIL_REQUIRE=1 so they cannot skip.
#
# Usage:  scripts/hil-emu.sh
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# Map each required tool to the Debian/Ubuntu package that provides it, for the
# hard-fail install hint.
declare -A tool_pkg=(
  [qemu-arm]="qemu-user"
  [qemu-ppc64]="qemu-user"
  [qemu-system-arm]="qemu-system-arm"
  [qemu-img]="qemu-utils"
  [arm-none-eabi-gcc]="gcc-arm-none-eabi"
  [arm-linux-gnueabihf-gcc]="gcc-arm-linux-gnueabihf"
  [powerpc64-linux-gnu-gcc]="gcc-powerpc64-linux-gnu"
  [nm]="binutils"
  [cc]="build-essential"
)

required_tools=(
  qemu-arm qemu-ppc64 qemu-system-arm qemu-img
  arm-none-eabi-gcc arm-linux-gnueabihf-gcc powerpc64-linux-gnu-gcc
  nm cc
)

missing=()
missing_pkgs=()
for tool in "${required_tools[@]}"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing+=("$tool")
    missing_pkgs+=("${tool_pkg[$tool]:-$tool}")
  fi
done

if (( ${#missing[@]} > 0 )); then
  # De-duplicate the package list.
  readarray -t uniq_pkgs < <(printf '%s\n' "${missing_pkgs[@]}" | sort -u)
  echo "ERROR: hil-emu requires these tools, which are not on PATH:" >&2
  printf '  - %s\n' "${missing[@]}" >&2
  echo >&2
  echo "Install them (Debian/Ubuntu):" >&2
  echo "  sudo apt-get update && sudo apt-get install -y ${uniq_pkgs[*]}" >&2
  exit 1
fi

echo "== hil-emu: all required qemu + cross toolchains present =="
for tool in "${required_tools[@]}"; do
  printf '  %-26s %s\n' "$tool" "$(command -v "$tool")"
done
echo

# ---------------------------------------------------------------------------
# RV-1 — cross-endian fidelity. Runs in the `bhf` crate. With the ppc64 cross
# gcc + qemu-ppc64 present it MUST execute the gated ppc64 path; treat a
# "skipping qemu-ppc64 run" line as a failure of this lane.
# ---------------------------------------------------------------------------
echo "== RV-1: big_endian_input_reaches_a_native_endian_branch_only_on_the_target =="
rv1_log="$(mktemp)"
trap 'rm -f "$rv1_log"' EXIT
cargo test -p bhf --lib \
  big_endian_input_reaches_a_native_endian_branch_only_on_the_target \
  -- --nocapture 2>&1 | tee "$rv1_log"
if grep -q "skipping qemu-ppc64 run" "$rv1_log"; then
  echo "ERROR: RV-1 skipped its qemu-ppc64 path although the toolchain is present." >&2
  exit 1
fi
echo

# ---------------------------------------------------------------------------
# RV-2 + RV-3 — the live transport tests. BHF_HIL_REQUIRE=1 turns any missing
# tool into a hard failure, so these cannot self-skip in this lane.
# ---------------------------------------------------------------------------
echo "== RV-2: live_gdb (real qemu-arm gdbstub) =="
BHF_HIL_REQUIRE=1 cargo test -p target_transport --test live_gdb -- --nocapture
echo

echo "== RV-3: live_fullsystem (qemu-system-arm mps2-an385 snapshot) =="
BHF_HIL_REQUIRE=1 cargo test -p target_transport --test live_fullsystem -- --nocapture
echo

echo "== hil-emu: RV-1, RV-2, RV-3 all executed the REAL live path and passed =="
