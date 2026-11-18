#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# install-zephyr.sh [DIR]: a Zephyr v3.7.0 tree with its CMSIS module, and
# west in DIR/.venv (default ~/.local/opt/zephyrproject), for the Zephyr agent
# sample (#291). Prints the environment the sample's build needs as
# NAME=VALUE lines, for $GITHUB_ENV: ZEPHYR_BASE, and the gnuarmemb toolchain
# variant over the host's arm-none-eabi-gcc. Put DIR/.venv/bin on PATH for
# west. A DIR that already holds the tree is reused.
set -euo pipefail
version=v3.7.0
dir=${1:-$HOME/.local/opt/zephyrproject}
venv=$dir/.venv
mkdir -p "$dir"
if [ ! -x "$venv/bin/west" ]; then
  python3 -m venv "$venv"
  "$venv/bin/pip" install --quiet west==1.5.0 >&2
fi
if [ ! -f "$dir/zephyr/VERSION" ]; then
  "$venv/bin/west" init -m https://github.com/zephyrproject-rtos/zephyr \
    --mr "$version" --clone-opt=--depth=1 "$dir/manifest-tmp" >&2
  # west init wants an empty directory: move its workspace into DIR.
  mv "$dir/manifest-tmp/.west" "$dir/manifest-tmp/zephyr" "$dir/"
  rmdir "$dir/manifest-tmp"
  (cd "$dir" && "$venv/bin/west" update --narrow -o=--depth=1 cmsis >&2)
fi
"$venv/bin/pip" install --quiet -r "$dir/zephyr/scripts/requirements-base.txt" >&2
gcc=$(command -v arm-none-eabi-gcc)
echo "ZEPHYR_BASE=$dir/zephyr"
echo "ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb"
echo "GNUARMEMB_TOOLCHAIN_PATH=$(dirname "$(dirname "$gcc")")"
