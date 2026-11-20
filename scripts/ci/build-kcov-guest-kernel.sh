#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# build-kcov-guest-kernel.sh OUT: build the guest kernel the `bhf kernel fuzz`
# guest tests boot (crates/cli/tests/kernel_guest_cli.rs) into OUT, and print
# BHF_KERNEL_IMAGE and BHF_KERNEL_MODULE on stdout, for $GITHUB_ENV.
#
# The kernel is a pinned kernel.org release, x86_64 defconfig plus
# kvm_guest.config, with KCOV (and its comparison mode), KASAN, debugfs and
# DWARF debug info, KASLR off (the edge ids are PCs), and the subsystems a
# guest without devices never loads (DRM, sound, wireless, USB) left out to
# keep the build small. The module is the widget driver fixture
# (tests/fixtures/kernel_widget/linux), whose ioctl has a planted
# slab-out-of-bounds write, built against that tree.
#
# OUT gets bzImage and widget.ko; the build tree (OUT/linux-VERSION, several
# GB) is deleted afterwards unless KEEP_TREE=1. JOBS sets make's -j (default:
# the CPUs online). A tree already configured is built on, so an interrupted
# run picks up where it stopped, and an OUT this recipe already built (its
# OUT/recipe.sha256 names this script and the fixture) is used as it is.
# Needs gcc, make, flex, bison, bc, the libelf and OpenSSL headers
# (Debian/Ubuntu: build-essential flex bison bc libelf-dev libssl-dev);
# HOSTCFLAGS and HOSTLDFLAGS are passed to make when set, for headers and
# libraries outside the system paths.
set -euo pipefail
[ "$#" -eq 1 ] || { echo "usage: build-kcov-guest-kernel.sh OUT" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
mkdir -p "$1"
out=$(cd "$1" && pwd)
jobs=${JOBS:-$(getconf _NPROCESSORS_ONLN)}

version=6.12.118
sha256=08308460320e852ac0745b2be3c7ae1cd81bdad713506ed7d817ba1ec9e1a5a5
tree=$out/linux-$version
recipe=$(cat "$0" "$root/tests/fixtures/kernel_widget/linux/drivers/misc/widget.c" \
  "$root/tests/fixtures/kernel_widget/linux/include/uapi/linux/widget.h" | sha256sum | cut -d' ' -f1)

if [ -f "$out/bzImage" ] && [ -f "$out/widget.ko" ] && [ "$(cat "$out/recipe.sha256" 2>/dev/null)" = "$recipe" ]; then
  echo "BHF_KERNEL_IMAGE=$out/bzImage"
  echo "BHF_KERNEL_MODULE=$out/widget.ko"
  exit 0
fi
rm -f "$out/recipe.sha256"

for tool in gcc make flex bison bc perl xz; do
  command -v "$tool" >/dev/null || { echo "build-kcov-guest-kernel.sh: $tool is not installed" >&2; exit 1; }
done

make_args=(-C "$tree" -j"$jobs")
[ -n "${HOSTCFLAGS:-}" ] && make_args+=("HOSTCFLAGS=$HOSTCFLAGS")
[ -n "${HOSTLDFLAGS:-}" ] && make_args+=("HOSTLDFLAGS=$HOSTLDFLAGS")

if [ ! -f "$tree/.config" ]; then
  "$here/fetch.sh" \
    "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$version.tar.xz" \
    "$sha256" "$out/linux-$version.tar.xz"
  rm -rf "$tree"
  tar -xJf "$out/linux-$version.tar.xz" -C "$out"
  rm "$out/linux-$version.tar.xz"
  cat > "$tree/kernel/configs/bhf_kcov_guest.config" <<'EOF'
# The guest bhf kernel fuzz boots: KCOV coverage for the executor, KASAN
# reports for the findings, and stable PCs.
CONFIG_KCOV=y
CONFIG_KCOV_INSTRUMENT_ALL=y
CONFIG_KCOV_ENABLE_COMPARISONS=y
CONFIG_DEBUG_FS=y
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KASAN_INLINE=y
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
CONFIG_MODULES=y
CONFIG_MODULE_UNLOAD=y
CONFIG_DEVTMPFS=y
CONFIG_BLK_DEV_INITRD=y
CONFIG_VIRTIO_CONSOLE=y
# CONFIG_RANDOMIZE_BASE is not set
# CONFIG_DRM is not set
# CONFIG_SOUND is not set
# CONFIG_WIRELESS is not set
# CONFIG_WLAN is not set
# CONFIG_USB_SUPPORT is not set
EOF
  make "${make_args[@]}" defconfig >&2
  make "${make_args[@]}" kvm_guest.config >&2
  make "${make_args[@]}" bhf_kcov_guest.config >&2
fi

# Every option the guest relies on must have survived the merge.
for option in CONFIG_KCOV CONFIG_KCOV_ENABLE_COMPARISONS CONFIG_KASAN CONFIG_DEBUG_INFO \
              CONFIG_DEBUG_FS CONFIG_VIRTIO_CONSOLE CONFIG_DEVTMPFS CONFIG_MODULES; do
  grep -qx "$option=y" "$tree/.config" || {
    echo "build-kcov-guest-kernel.sh: $option is not set in $tree/.config" >&2
    exit 1
  }
done

make "${make_args[@]}" bzImage modules >&2

module=$out/widget-module
rm -rf "$module"
mkdir -p "$module"
cp "$root/tests/fixtures/kernel_widget/linux/drivers/misc/widget.c" "$module/widget.c"
cat > "$module/Kbuild" <<EOF
obj-m := widget.o
ccflags-y := -I$root/tests/fixtures/kernel_widget/linux/include
EOF
make "${make_args[@]}" M="$module" modules >&2

cp "$tree/arch/x86/boot/bzImage" "$out/bzImage"
cp "$module/widget.ko" "$out/widget.ko"
rm -rf "$module"
echo "$recipe" > "$out/recipe.sha256"
if [ "${KEEP_TREE:-0}" != 1 ]; then
  rm -rf "$tree"
fi

echo "BHF_KERNEL_IMAGE=$out/bzImage"
echo "BHF_KERNEL_MODULE=$out/widget.ko"
