#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Rebuild the fixture firmware images from their C sources. The images are
# committed so the tests need no cross compiler; run this after changing a
# source, with the GNU Arm Embedded toolchain (arm-none-eabi-gcc) on PATH.
set -eu
cd "$(dirname "$0")"
CFLAGS="-mcpu=cortex-m4 -mthumb -mfloat-abi=soft -O2 -g0 -ffreestanding -nostdlib -fno-builtin"
LDFLAGS="-T link.ld -Wl,--build-id=none -Wl,--no-warn-rwx-segments -Wl,-z,max-page-size=16"
for image in magic faults; do
    arm-none-eabi-gcc $CFLAGS $LDFLAGS -o "$image.elf" startup.c "$image.c" -lgcc
    arm-none-eabi-objcopy -O binary "$image.elf" "$image.bin"
done
