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
#                                reset + coverage-ring readback + planted fault,
#                                the reset=persistent loop, the reset=fast
#                                dirty-page snapshot (cc builds its QEMU
#                                plugin), and their ignored benchmarks against
#                                a loadvm per input, which run nightly and by
#                                hand, not on a pull request or a push)
#   RV-4  the pinned FreeRTOS task/queue profile and the FreeRTOS agent task
#   RV-5  the reference agent's Zephyr sample (west + ZEPHYR_BASE, from
#         scripts/ci/install-zephyr.sh)
#   RV-6  the board lane from a board profile (#293): hil_board against a
#         qemu-system-arm stand-in, and the reference agent on a pty over the
#         profile's serial lane
#   RV-7  the Renode transport (#340): live_renode and the shipped CLI against
#         the pinned Renode BHF_RENODE names (scripts/ci/install-renode.sh)
#   RV-8  the kernel guest lane (#350, #378, #379): bhf kernel run, fuzz
#         (coverage, and the planted KASAN bug as a finding) and replay
#         against the KCOV/KASAN guest kernel and widget module
#         BHF_KERNEL_IMAGE and BHF_KERNEL_MODULE name
#         (scripts/ci/build-kcov-guest-kernel.sh)
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
  [git]="git"
)

required_tools=(
  qemu-arm qemu-ppc64 qemu-system-arm qemu-img
  arm-none-eabi-gcc arm-linux-gnueabihf-gcc powerpc64-linux-gnu-gcc
  nm cc git
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

if ! printf '#include <stdlib.h>\n#include <string.h>\n' | arm-none-eabi-gcc -E -x c - >/dev/null 2>&1; then
  echo 'ERROR: ARM bare-metal C headers missing; install libnewlib-dev and libnewlib-arm-none-eabi.' >&2
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
cargo test --locked -p bhf --lib \
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
BHF_HIL_REQUIRE=1 cargo test --locked -p target_transport --test live_gdb -- --nocapture
echo

echo "== RV-3: live_fullsystem (qemu-system-arm mps2-an385 snapshot) =="
BHF_HIL_REQUIRE=1 cargo test --locked -p target_transport --test live_fullsystem -- --nocapture
# The benchmarks are nightly checks (#346, #347): the schedule, a manual
# dispatch and a local run take them; a pull request or a push does not wait
# on a shared runner's timing.
rv3_benchmark_runs() {
  case "${GITHUB_EVENT_NAME:-}" in
    pull_request | push) return 1 ;;
    *) return 0 ;;
  esac
}
if rv3_benchmark_runs; then
  echo "== RV-3 benchmarks against a loadvm per input: reset=persistent (needs 3x the runs), reset=fast (needs a fifth of the reset latency) =="
  BHF_HIL_REQUIRE=1 cargo test --locked -p target_transport --test live_fullsystem -- \
    --ignored --nocapture
else
  echo "== RV-3 benchmarks: not run on ${GITHUB_EVENT_NAME} (they run nightly) =="
fi
echo

echo "== RV-4: pinned FreeRTOS task/queue transport and CLI replay =="
kernel_dir="$(mktemp -d)"
trap 'rm -f "$rv1_log"; rm -rf "$kernel_dir"' EXIT
git -C "$kernel_dir" init -q
git -C "$kernel_dir" fetch -q --depth 1 https://github.com/FreeRTOS/FreeRTOS-Kernel \
  8be86d4a24fd4091f8f4192018423ab590f408db
git -C "$kernel_dir" checkout -q FETCH_HEAD
BHF_RTOS_KERNEL="$kernel_dir" BHF_RTOS_LIVE=1 cargo test --locked \
  -p target_transport --test live_rtos -- --nocapture
BHF_RTOS_KERNEL="$kernel_dir" BHF_RTOS_CLI=1 cargo test --locked \
  -p bhf --test transport_fuzz_qemu_cli cli_freertos_ -- --nocapture
BHF_RTOS_KERNEL="$kernel_dir" BHF_RTOS_CLI=1 cargo test --locked \
  -p bhf --test transport_freertos_agent_cli -- --nocapture
echo

echo "== RV-5: the reference agent's Zephyr sample, CLI finding and replay =="
command -v west >/dev/null && [ -n "${ZEPHYR_BASE:-}" ] || {
  echo "ERROR: RV-5 needs west and ZEPHYR_BASE (scripts/ci/install-zephyr.sh)" >&2
  exit 1
}
BHF_ZEPHYR_CLI=1 cargo test --locked -p bhf --test transport_zephyr_agent_cli -- --nocapture
echo

echo "== RV-6: the board lane from a board profile: QEMU stand-in, agent on a pty =="
BHF_HIL_REQUIRE=1 cargo test --locked -p target_transport --test hil_board -- --nocapture
BHF_REQUIRE_TOOLS=1 cargo test --locked -p bhf --test transport_agent_serial_cli -- --nocapture
echo

echo "== RV-7: the Renode transport, library and CLI (Save/Load snapshot reset) =="
[ -n "${BHF_RENODE:-}" ] && [ -x "$BHF_RENODE" ] || command -v renode >/dev/null || {
  echo "ERROR: RV-7 needs Renode: set BHF_RENODE (scripts/ci/install-renode.sh)" >&2
  exit 1
}
BHF_REQUIRE_TOOLS=1 cargo test --locked -p target_transport --test live_renode -- --nocapture
BHF_REQUIRE_TOOLS=1 BHF_RENODE_CLI=1 cargo test --locked \
  -p bhf --test transport_fuzz_renode_cli -- --nocapture
echo

echo "== RV-8: a Linux kernel in a qemu-system guest, with KCOV coverage =="
[ -f "${BHF_KERNEL_IMAGE:-}" ] && [ -f "${BHF_KERNEL_MODULE:-}" ] && command -v qemu-system-x86_64 >/dev/null || {
  echo "ERROR: RV-8 needs qemu-system-x86_64 and BHF_KERNEL_IMAGE and BHF_KERNEL_MODULE (scripts/ci/build-kcov-guest-kernel.sh)" >&2
  exit 1
}
BHF_REQUIRE_TOOLS=1 BHF_KERNEL_GUEST=1 cargo test --locked \
  -p bhf --test kernel_guest_cli -- --nocapture
echo

echo "== hil-emu: RV-1 through RV-8 executed the REAL live paths and passed =="
