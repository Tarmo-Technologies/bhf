<!-- SPDX-License-Identifier: Apache-2.0 -->

# Kernel guest replies

`replies/` holds what bhf's in-guest executor ([`c_runtime/kernel_executor.c`](../../../c_runtime/kernel_executor.c)) sent back for four programs, recorded in one boot in the order of the table below. The guest is the one `bhf kernel run` starts, with the kernel and `widget.ko` that `scripts/ci/build-kcov-guest-kernel.sh` builds (Linux 6.12.118, KCOV and KASAN), under QEMU 8.2.2 with TCG. Each `NAME.prog` is the program in the executor's format, and `NAME.reply` is the REPLY message's payload without its header.

| Name | Program |
|---|---|
| `xfer-slot1` | open `/dev/widget`; `WIDGET_IOC_XFER` with slot 1 |
| `xfer-slot1-again` | the same program again |
| `xfer-slot7` | the same with slot 7, which the driver refuses (`EINVAL`) |
| `get-stats` | open `/dev/widget`; `WIDGET_IOC_GET_STATS` into an out buffer |

The kernel ran without KASLR (`nokaslr`): its PCs are its link-time addresses, and the module's are where it loaded on that boot.

# Kernel guest console logs

`console/` holds the serial console of guests that `bhf kernel run` booted, as the parser of `bhf kernel fuzz` reads them. Each log runs from the executor's `ready` line to the guest's end; the boot messages before `ready` are cut.

| Log | Kernel | What ran |
|---|---|---|
| `kasan-slab-out-of-bounds.log` | the KASAN kernel, `widget.ko` | `WIDGET_IOC_XFER` with slot 4 (the widget driver fixture's planted bug) |
| `kasan-slab-use-after-free.log` | the KASAN kernel, `bugs.ko` | `BUGS_UAF` |
| `kasan-double-free.log` | the KASAN kernel, `bugs.ko` | `BUGS_DOUBLE_FREE` |
| `kasan-null-ptr-deref.log` | the KASAN kernel, `bugs.ko` | `BUGS_NULL` (a general protection fault on the shadow address) |
| `warning.log` | the KASAN kernel, `bugs.ko` | `BUGS_WARN` |
| `null-ptr-deref.log` | the KCSAN kernel, `bugs.ko`, `kunit.enable=0` | `BUGS_NULL` (a page fault) |
| `kcsan-data-race.log` | the KCSAN kernel | nothing: KCSAN's own KUnit test (`CONFIG_KCSAN_KUNIT_TEST`) races at boot, from its first test thread on |

The KASAN kernel is the one `scripts/ci/build-kcov-guest-kernel.sh` builds. The KCSAN kernel is the same release with the same recipe, KASAN off and `CONFIG_KCSAN`, `CONFIG_KUNIT` and `CONFIG_KCSAN_KUNIT_TEST` on. `console/bugs.c` is the module whose ioctl commands trigger the bugs. It is built against each kernel with `-fmacro-prefix-map`, so its WARNING names `drivers/misc/bugs.c`. Every guest booted with `panic_on_warn=1`, so each log ends at the panic its report caused.
