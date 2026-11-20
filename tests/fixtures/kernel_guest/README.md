<!-- SPDX-License-Identifier: Apache-2.0 -->

# Kernel guest replies

`replies/` holds what bhf's executor (`c_runtime/kernel_executor.c`) sent
back for four programs, recorded in the guest `bhf kernel run` boots: the
kernel and `widget.ko` that `scripts/ci/build-kcov-guest-kernel.sh` builds
(Linux 6.12.118, KCOV and KASAN), under QEMU 8.2.2 with tcg, one boot, in
this order. Each `NAME.prog` is the program, in the executor's format, and
`NAME.reply` the REPLY message's payload (no header).

| Name | Program |
|---|---|
| `xfer-slot1` | open `/dev/widget`; `WIDGET_IOC_XFER` with slot 1 |
| `xfer-slot1-again` | the same program again |
| `xfer-slot7` | the same with slot 7, which the driver refuses (`EINVAL`) |
| `get-stats` | open `/dev/widget`; `WIDGET_IOC_GET_STATS` into an out buffer |

The kernel ran without KASLR (`nokaslr`): its PCs are its link-time
addresses, and the module's are where it loaded on that boot.
