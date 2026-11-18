/* SPDX-License-Identifier: Apache-2.0 */
/* Host stand-in (see kernel.h) for Zephyr's fatal-error interface. */
#ifndef BHF_ZEPHYR_HOST_FATAL_H
#define BHF_ZEPHYR_HOST_FATAL_H

#define K_ERR_CPU_EXCEPTION 0

struct arch_esf;
void k_sys_fatal_error_handler(unsigned int reason, const struct arch_esf *esf);
__attribute__((noreturn)) void k_fatal_halt(unsigned int reason);

#endif
