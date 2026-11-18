// SPDX-License-Identifier: Apache-2.0

/* Edge-coverage runtime for the Ada lane (#412).
 *
 * GNAT/GCC does NOT support `-fsanitize-coverage=trace-pc-guard` (the flag the
 * C/C++ driver uses); GCC 13.x rejects it with "valid arguments are: trace-cmp
 * trace-pc". The Ada target+harness are therefore instrumented with
 * `-fsanitize-coverage=trace-pc`, which emits a call to the parameterless
 * `__sanitizer_cov_trace_pc(void)` at every instrumented edge. This file DEFINES
 * that callback (plus a constructor that maps the BHF_COV_SHM bitmap) so the
 * built-in engine gets per-edge feedback exactly like the C/C++ driver does.
 *
 * It is compiled by the AdaFuzz runtime project WITHOUT any
 * `-fsanitize-coverage` flag (`-g` only) so it is itself uninstrumented — if it
 * were instrumented, `__sanitizer_cov_trace_pc` would call into itself and
 * recurse. The unresolved `__sanitizer_cov_trace_pc` symbol referenced by the
 * instrumented Ada + binder objects pulls this archive member into the link.
 *
 * Bitmap indexing mirrors the C/C++ driver's BHF_COV_BITS-sized MAP_SHARED
 * map (crates/cli/src/fuzz.rs:CoverageTracker and direct_harness.c.tera) so the
 * engine reader is unchanged: one byte per (hashed) edge, BHF_COV_BITS bytes
 * total. trace-pc has no guard pointer, so the return-address PC is hashed into
 * the bitmap instead.
 *
 * With BHF_COV_PCS=<file> (the coverage replay's, #310), each edge's PC is also
 * appended to that file the first time this process reaches it, as a hex offset
 * from the image's start, so the host can place it on an Ada line.
 *
 * In the AFL++ build (#304), which links AFL++'s runtime, each edge also goes
 * to AFL++'s map: the edge from the previous PC, as AFL's classic
 * instrumentation counts it, on one of a table of guards AFL++'s runtime
 * numbers like its own. The runtime's functions are weak references, null in
 * every other build.
 */

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/* MUST match BHF_COV_BITS in crates/cli/src/fuzz.rs and
 * direct_harness.c.tera — the engine maps the same file at this size. */
#define BHF_COV_BITS (1u << 16)

#if defined(__has_attribute)
#if __has_attribute(no_sanitize)
#define ADAFUZZ_NOCOV __attribute__((no_sanitize("coverage")))
#endif
#endif
#ifndef ADAFUZZ_NOCOV
#define ADAFUZZ_NOCOV
#endif

static unsigned char *adafuzz_cov_map = 0;

extern void __sanitizer_cov_trace_pc_guard(uint32_t *guard) __attribute__((weak));
extern void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop)
    __attribute__((weak));
#define ADAFUZZ_AFL_GUARDS 4096u
static uint32_t adafuzz_afl_guards[ADAFUZZ_AFL_GUARDS];
static uintptr_t adafuzz_afl_prev_pc;

__attribute__((constructor)) ADAFUZZ_NOCOV static void adafuzz_afl_guards_init(void) {
    if (__sanitizer_cov_trace_pc_guard_init) {
        __sanitizer_cov_trace_pc_guard_init(adafuzz_afl_guards,
                                            adafuzz_afl_guards + ADAFUZZ_AFL_GUARDS);
    }
}

/* The BHF_COV_PCS recorder: its file, and the PCs this process wrote. */
#define ADAFUZZ_PCS_SLOTS (1u << 16)
static int adafuzz_pcs_fd = -1;
static uintptr_t adafuzz_pcs_seen[ADAFUZZ_PCS_SLOTS];
#if defined(__ELF__)
extern char __executable_start __attribute__((weak));
#endif

/* Map (or create+size) the BHF_COV_SHM edge bitmap once at process start.
 * MAP_SHARED so coverage accumulates across the persistent fork-server process
 * and any per-spawn children, and so the engine reading the same file sees it.
 * No-op when BHF_COV_SHM is unset (a plain run with no engine). */
ADAFUZZ_NOCOV __attribute__((constructor)) static void adafuzz_cov_open(void) {
    const char *pcs = getenv("BHF_COV_PCS");
    if (pcs && *pcs) {
        adafuzz_pcs_fd = open(pcs, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    }
    const char *p = getenv("BHF_COV_SHM");
    if (!p || !*p) {
        return;
    }
    int fd = open(p, O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        return;
    }
    if (ftruncate(fd, BHF_COV_BITS) == 0) {
        void *m =
            mmap(0, BHF_COV_BITS, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (m != MAP_FAILED) {
            adafuzz_cov_map = (unsigned char *)m;
        }
    }
    close(fd);
}

/* trace-pc edge callback. GCC emits a parameterless call here at each edge; the
 * return address identifies the edge. Fold it into the bitmap with the same
 * scramble libFuzzer/AFL use for PC-table-less coverage so adjacent edges spread
 * across buckets. No-op until the bitmap is mapped. */
/* Append `pc`'s offset to the BHF_COV_PCS file once per process: an open-
 * addressed set of the PCs written; a full set writes the rest every time,
 * which the host's reader dedups. */
ADAFUZZ_NOCOV static void adafuzz_pcs_record(uintptr_t pc) {
    static const char hex[] = "0123456789abcdef";
    uintptr_t base = 0;
    uintptr_t offset;
    unsigned slot, probe;
    char line[2 * sizeof(uintptr_t) + 1];
    int len = 0, shift;
#if defined(__ELF__)
    if (&__executable_start) base = (uintptr_t)&__executable_start;
#endif
    slot = (unsigned)((pc ^ (pc >> 7)) & (ADAFUZZ_PCS_SLOTS - 1));
    for (probe = 0; probe < 64; probe++) {
        unsigned at = (slot + probe) & (ADAFUZZ_PCS_SLOTS - 1);
        if (adafuzz_pcs_seen[at] == pc) return;
        if (adafuzz_pcs_seen[at] == 0) {
            adafuzz_pcs_seen[at] = pc;
            break;
        }
    }
    offset = pc - base;
    for (shift = (int)(sizeof(uintptr_t) * 8) - 4; shift >= 0; shift -= 4) {
        unsigned digit = (unsigned)((offset >> shift) & 15u);
        if (len == 0 && digit == 0 && shift > 0) continue;
        line[len++] = hex[digit];
    }
    line[len++] = '\n';
    (void)!write(adafuzz_pcs_fd, line, (size_t)len);
}

ADAFUZZ_NOCOV void __sanitizer_cov_trace_pc(void) {
    uintptr_t pc = (uintptr_t)__builtin_return_address(0);
    if (__sanitizer_cov_trace_pc_guard) {
        __sanitizer_cov_trace_pc_guard(
            &adafuzz_afl_guards[(pc ^ adafuzz_afl_prev_pc) % ADAFUZZ_AFL_GUARDS]);
        adafuzz_afl_prev_pc = pc >> 1;
    }
    if (adafuzz_pcs_fd >= 0) {
        adafuzz_pcs_record(pc);
    }
    if (!adafuzz_cov_map) {
        return;
    }
    adafuzz_cov_map[(pc ^ (pc >> 3)) & (BHF_COV_BITS - 1)] = 1;
}

/* Portability (#64): force a process crash an EXTERNAL fuzzer (Mayhem
 * base-executable, AFL) detects as a fault. A plain abort() is not enough: the
 * GNAT runtime installs a SIGABRT handler that converts the signal into a
 * catchable Ada exception, which the harness's top-level `when others` handler
 * then swallows. Resetting SIGABRT to its default disposition first means abort()
 * terminates the process with SIGABRT (signal 6) instead. Called from
 * AdaFuzz.Probe.On_Top_Level_Catch only when BHF_CRASH_ON_FINDING is set. */
ADAFUZZ_NOCOV void adafuzz_crash_now(void) {
    signal(SIGABRT, SIG_DFL);
    abort();
}
