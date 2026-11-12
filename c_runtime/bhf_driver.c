/* SPDX-License-Identifier: Apache-2.0 */
/*
 * bhf native fork-server driver + edge-coverage / cmplog / value-profile
 * runtime, factored so a NON-C harness (a Rust staticlib exporting
 * `bhf_run_one`) can link the SAME persistent driver the C harness uses.
 *
 * This is a self-contained copy of the language-agnostic driver+runtime from
 * `harness_gen/src/templates/direct_harness.c.tera` (the default, non-AFL block):
 * it provides `main` (the persistent framed fork-server loop the builtin engine
 * drives via BHF_FRAMED, plus an argv[1]-file per-spawn isolation path), the
 * SanitizerCoverage trace-pc-guard edge bitmap (BHF_COV_SHM), AFL-style
 * hit-count buckets (BHF_COV_CNT_SHM), the laf-intel comparison-progress map
 * (BHF_CMP_PROGRESS_SHM), the RedQueen/cmplog operand ring (BHF_CMP_SHM),
 * and the value-profile dictionary log (BHF_VP_SHM). It declares — but does
 * NOT define — `bhf_run_one`, which the linked Rust staticlib provides.
 *
 * The marker string `BHF_FRAMED` below is what the engine greps for in the
 * sibling source to decide a harness speaks the persistent fork-server protocol;
 * `rust_generate` copies this file to `main.c` beside the binary so the engine
 * drives the Rust harness exactly like a C driver harness (fork-server, coverage,
 * cmplog, value-profile — all the native machinery, no third-party fuzzer).
 *
 * Keep the SHM layouts (sizes, per-edge/site/record bytes) in lock-step with
 * direct_harness.c.tera and the readers in crates/cli/src/fuzz.rs.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
/* Windows (mingw-w64) has no <unistd.h>/<sys/mman.h>. The shared coverage/cmplog
 * maps use Win32 file mapping; the framed-protocol pipe I/O uses the _-prefixed
 * CRT calls + _setmode for binary mode; windows.h supplies the unhandled
 * exception filter used by unsanitized builds (no ASan on mingw). */
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#define BHF_DEVNULL "NUL"
#define bhf_read _read
#define bhf_write _write
#define bhf_dup _dup
#define bhf_dup2 _dup2
#define bhf_close _close
#define bhf_open _open
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#define BHF_DEVNULL "/dev/null"
#define bhf_read read
#define bhf_write write
#define bhf_dup dup
#define bhf_dup2 dup2
#define bhf_close close
#define bhf_open open
#endif

/* MSVC (`cl.exe`, the MSVC harness lane): no GNU attributes or builtins.
 * `_ReturnAddress` is the intrinsic for `__builtin_return_address(0)`, and a
 * callback MSVC's `libsancov.lib` looks up at start-up must be exported from
 * the executable for it to be found. */
#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>
#pragma intrinsic(_ReturnAddress)
#define BHF_MSVC 1
#define BHF_RA _ReturnAddress()
#define BHF_MEMCPY memcpy
#define BHF_EXPORT __declspec(dllexport)
#else
#define BHF_RA __builtin_return_address(0)
#define BHF_MEMCPY __builtin_memcpy
#define BHF_EXPORT
#endif

/* The Rust staticlib defines this; the driver only calls it. */
extern int bhf_run_one(const uint8_t *Data, size_t Size);
#if defined(BHF_MSVC)
/* MSVC has no weak symbols: an alternate name supplies the no-op default
 * when the harness does not define LLVMFuzzerInitialize. */
int bhf_no_fuzzer_initialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    return 0;
}
#pragma comment(linker, "/alternatename:LLVMFuzzerInitialize=bhf_no_fuzzer_initialize")
extern int LLVMFuzzerInitialize(int *argc, char ***argv);
#define BHF_FUZZER_INITIALIZE(argc, argv) LLVMFuzzerInitialize((argc), (argv))
#else
extern int LLVMFuzzerInitialize(int *argc, char ***argv) __attribute__((weak));
#define BHF_FUZZER_INITIALIZE(argc, argv) \
    do { if (LLVMFuzzerInitialize) LLVMFuzzerInitialize((argc), (argv)); } while (0)
#endif

/* Republish the fuzz input to the runtrace shim so fuzz-driven mode can route
 * the current iteration's bytes into fake fds / sockets / dlopen stubs. The
 * shim is Linux-only. COFF gives separate __attribute__((weak)) references
 * different fallback symbols in each translation unit, and link.exe rejects
 * those defaults with LNK1227 when this driver is linked to a generated
 * harness, so Windows must not emit the weak reference at all. */
#if defined(_WIN32)
#define BHF_PUBLISH_INPUT(data, size) ((void)0)
#else
extern void bhf_shim_set_fuzz_input(const uint8_t *data, size_t size) __attribute__((weak));
#define BHF_PUBLISH_INPUT(data, size) do { \
    if (bhf_shim_set_fuzz_input) bhf_shim_set_fuzz_input((data), (size)); \
} while (0)
#endif

/* The coverage/cmplog runtime functions must NOT be instrumented themselves: a
 * compare inside a trace-cmp callback would re-enter it and recurse forever, and
 * self-edges would pollute the bitmap. GCC (incl. mingw) spells the opt-out
 * `no_sanitize_coverage`; clang spells it `no_sanitize("coverage")`. */
#if defined(__has_attribute)
#if defined(__clang__) && __has_attribute(no_sanitize)
#define BHF_NOCOV __attribute__((no_sanitize("coverage")))
#elif __has_attribute(no_sanitize_coverage)
#define BHF_NOCOV __attribute__((no_sanitize_coverage))
#elif __has_attribute(no_sanitize)
#define BHF_NOCOV __attribute__((no_sanitize("coverage")))
#endif
#endif
#ifndef BHF_NOCOV
#define BHF_NOCOV
#endif

/* Map a shared, file-backed region of `size` bytes at `path`, or 0 on failure.
 * Both platforms back the map with a real file so the engine (a separate
 * process on the host; under wine the host sees the same file) reads the same
 * bytes. POSIX: open+ftruncate+mmap(MAP_SHARED). Windows: CreateFileMapping +
 * MapViewOfFile, which writes through to the backing file. */
BHF_NOCOV static void *bhf_map_shared(const char *path, size_t size) {
#ifdef _WIN32
    HANDLE fh = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) return NULL;
    HANDLE mh = CreateFileMappingA(fh, NULL, PAGE_READWRITE,
                                   (DWORD)(((uint64_t)size) >> 32),
                                   (DWORD)(size & 0xffffffffu), NULL);
    CloseHandle(fh); /* the mapping object keeps the file alive */
    if (!mh) return NULL;
    /* Keep `mh` open for the process lifetime: the view stays valid and the OS
     * reclaims both at exit. */
    return MapViewOfFile(mh, FILE_MAP_ALL_ACCESS, 0, 0, size);
#else
    int fd = bhf_open(path, O_RDWR | O_CREAT, 0600);
    if (fd < 0) return NULL;
    void *p = NULL;
    if (ftruncate(fd, (off_t)size) == 0) {
        void *m = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (m != MAP_FAILED) p = m;
    }
    bhf_close(fd);
    return p;
#endif
}

#ifdef _WIN32
/* Report only unhandled exceptions. First-chance exceptions can be handled by
 * the target or by ASan (including its shadow-memory allocation), so treating
 * them as crashes makes a valid sanitized harness reject every input. Chain
 * the previous unhandled filter so ASan retains its diagnostics, then provide
 * a distinctive exit instead of a debugger dialog for unsanitized builds. */
#define BHF_WIN_CRASH_EXIT 0x39
static LPTOP_LEVEL_EXCEPTION_FILTER bhf_win_previous_filter;
BHF_NOCOV static LONG WINAPI bhf_win_unhandled(EXCEPTION_POINTERS *info) {
    if (bhf_win_previous_filter) {
        LONG handled = bhf_win_previous_filter(info);
        if (handled == EXCEPTION_CONTINUE_EXECUTION) return handled;
    }
    DWORD code = info->ExceptionRecord->ExceptionCode;
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_STACK_OVERFLOW:
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
    case EXCEPTION_DATATYPE_MISALIGNMENT:
        fprintf(stderr, "BHF_CRASH code=0x%lx\n", (unsigned long)code);
        fflush(stderr);
        TerminateProcess(GetCurrentProcess(), BHF_WIN_CRASH_EXIT);
        return EXCEPTION_CONTINUE_SEARCH; /* unreachable */
    default:
        return EXCEPTION_CONTINUE_SEARCH;
    }
}
BHF_NOCOV static void bhf_win_install_crash_handler(void) {
    bhf_win_previous_filter = SetUnhandledExceptionFilter(bhf_win_unhandled);
}
#endif

/* Edge-coverage bitmap (#385): one presence bit per instrumented edge in a
 * MAP_SHARED region named by BHF_COV_SHM, so coverage accumulates across
 * per-spawn children and within the persistent process. No-op when unset. */
#define BHF_COV_BITS (1u << 16)
static unsigned char *bhf_cov_map = 0;
static uint32_t bhf_cov_next = 0;
BHF_NOCOV static void bhf_cov_open(void) {
    if (bhf_cov_map) return;
    const char *p = getenv("BHF_COV_SHM");
    if (!p || !*p) return;
    void *m = bhf_map_shared(p, BHF_COV_BITS);
    if (m) bhf_cov_map = (unsigned char *)m;
}

/* Comparison evidence (BHF_CMP_EVIDENCE): when the variable names a file, every
 * comparison the instrumented code makes is appended to a MAP_SHARED record
 * array in it -- satisfied ones and zero operands included, unlike the cmplog
 * ring below, which keeps only what the mutator can use. `bhf` sets it for the
 * single replays that record which input bytes reach which comparison of one
 * finding's input; a fuzz campaign never sets it, so every callback pays one
 * NULL test. Layout MUST match crates/cli/src/gate_evidence.rs:
 *   header  [u32 magic "BHFE"][u32 version][u32 count][u32 flags]
 *           flags bit0: the target was entered; bit1: records were dropped
 *           (the target's, or the harness's when it never marked entry)
 *   record  [u8 kind][u8 len_a][u8 len_b][u8 flags][u32 site][u32 size]
 *           [u8 a[OPMAX]][u8 b[OPMAX]]
 *           flags bit0: after target entry; bit1: a is a compile-time
 *           constant; bit2: b is; bit3: the operands compared equal
 * `site` is the caller's return address relative to the executable's start
 * (ELF), so the reader can symbolize it against the harness binary. Calls
 * from outside the executable (libc, the runtrace shim, libstdc++) are not
 * recorded: they are not the target's own comparisons. One exception: the
 * AddressSanitizer memcmp/bcmp interceptor hands its hook a pc inside the
 * interceptor itself, so every memcmp/bcmp call shares that one site in the
 * executable, wherever it was made. */
#define BHF_EV_MAGIC 0x45464842u
#define BHF_EV_VERSION 1u
#define BHF_EV_CAP 8192u
#define BHF_EV_OPMAX 32u
#define BHF_EV_HDR 16u
#define BHF_EV_REC (12u + 2u * BHF_EV_OPMAX)
#define BHF_EV_BYTES (BHF_EV_HDR + BHF_EV_CAP * BHF_EV_REC)
#define BHF_EV_INT 1u
#define BHF_EV_SWITCH 2u
#define BHF_EV_FLOAT 3u
#define BHF_EV_DOUBLE 4u
#define BHF_EV_MEMCMP 5u
#define BHF_EV_STRNCMP 6u
#define BHF_EV_STRCMP 7u
#define BHF_EV_STRNCASECMP 8u
#define BHF_EV_STRCASECMP 9u
#define BHF_EV_CONST_A 2u
#define BHF_EV_CONST_B 4u
static unsigned char *bhf_ev_map = 0;
static unsigned char bhf_ev_entered = 0;
/* The runtrace shim says when the calling thread is inside one of its hooks:
 * its own string and buffer compares reach the sanitizer's comparison hooks
 * too, and are not the target's. Not on Windows (see BHF_PUBLISH_INPUT). */
#if defined(_WIN32)
#define BHF_IN_SHIM() 0
#else
extern int bhf_shim_in_hook(void) __attribute__((weak));
#define BHF_IN_SHIM() (bhf_shim_in_hook && bhf_shim_in_hook())
#endif
#if defined(__ELF__)
extern char __executable_start[] __attribute__((weak));
extern char etext[] __attribute__((weak));
#endif
BHF_NOCOV static void bhf_ev_put32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)v;
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16);
    p[3] = (unsigned char)(v >> 24);
}
BHF_NOCOV static uint32_t bhf_ev_get32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
BHF_NOCOV static void bhf_ev_open(void) {
    const char *p;
    void *m;
    if (bhf_ev_map) return;
    p = getenv("BHF_CMP_EVIDENCE");
    if (!p || !*p) return;
    m = bhf_map_shared(p, BHF_EV_BYTES);
    if (!m) return;
    bhf_ev_map = (unsigned char *)m;
    bhf_ev_put32(bhf_ev_map, BHF_EV_MAGIC);
    bhf_ev_put32(bhf_ev_map + 4, BHF_EV_VERSION);
}
/* The caller's offset in the executable, or 0 when it lies outside it. */
BHF_NOCOV static int bhf_ev_site(const void *pc, uint32_t *site) {
    uintptr_t at = (uintptr_t)pc;
#if defined(__ELF__)
    if (__executable_start && etext) {
        if (at < (uintptr_t)__executable_start || at >= (uintptr_t)etext) return 0;
        *site = (uint32_t)(at - (uintptr_t)__executable_start);
        return 1;
    }
#endif
    *site = (uint32_t)(at - (uintptr_t)&bhf_ev_open);
    return 1;
}
BHF_NOCOV static void bhf_ev_push(unsigned kind, unsigned flags, const void *pc,
                                  const unsigned char *a, unsigned la,
                                  const unsigned char *b, unsigned lb, uint32_t size) {
    unsigned char *m = bhf_ev_map, *r;
    uint32_t count, site, i;
    if (!m || !bhf_ev_site(pc, &site)) return;
    count = bhf_ev_get32(m + 8);
    if (count >= BHF_EV_CAP) {
        m[12] |= 2u;
        return;
    }
    if (la > BHF_EV_OPMAX) la = BHF_EV_OPMAX;
    if (lb > BHF_EV_OPMAX) lb = BHF_EV_OPMAX;
    r = m + BHF_EV_HDR + count * BHF_EV_REC;
    r[0] = (unsigned char)kind;
    r[1] = (unsigned char)la;
    r[2] = (unsigned char)lb;
    r[3] = (unsigned char)(flags | (bhf_ev_entered ? 1u : 0u));
    bhf_ev_put32(r + 4, site);
    bhf_ev_put32(r + 8, size);
    for (i = 0; i < la; i++) r[12 + i] = a[i];
    for (i = 0; i < lb; i++) r[12 + BHF_EV_OPMAX + i] = b[i];
    bhf_ev_put32(m + 8, count + 1);
}
BHF_NOCOV static void bhf_ev_int(unsigned kind, uint64_t a, uint64_t b, unsigned width,
                                 unsigned flags, const void *pc) {
    unsigned char ab[8], bb[8];
    unsigned i;
    if (!bhf_ev_map) return;
    if (width > 8) width = 8;
    for (i = 0; i < width; i++) {
        ab[i] = (unsigned char)(a >> (8 * i));
        bb[i] = (unsigned char)(b >> (8 * i));
    }
    bhf_ev_push(kind, flags | (a == b ? 8u : 0u), pc, ab, width, bb, width, width);
}
BHF_NOCOV static unsigned bhf_ev_len(const unsigned char *s, unsigned max, int stop_at_nul) {
    unsigned i = 0;
    if (!stop_at_nul) return max;
    while (i < max && s[i]) i++;
    return i;
}
BHF_NOCOV static void bhf_ev_buf(unsigned kind, const void *pc, const void *s1, const void *s2,
                                 size_t n, int stop_at_nul, int result) {
    const unsigned char *a = (const unsigned char *)s1, *b = (const unsigned char *)s2;
    unsigned cap;
    if (!bhf_ev_map || !a || !b || BHF_IN_SHIM()) return;
    cap = n > BHF_EV_OPMAX ? BHF_EV_OPMAX : (unsigned)n;
    bhf_ev_push(kind, result == 0 ? 8u : 0u, pc, a, bhf_ev_len(a, cap, stop_at_nul), b,
                bhf_ev_len(b, cap, stop_at_nul), n > 0xffffffffu ? 0xffffffffu : (uint32_t)n);
}

/* Runtime cmplog (BHF_CMPLOG=1) for sanitized harnesses. The sanitizer runtime
 * defines strcmp/strncmp/memcmp/bcmp in the executable itself, so the runtrace
 * shim's LD_PRELOAD hooks for them never run; its interceptors call the weak
 * hooks below instead. They append the shim's `{"e":"cmplog",...}` line to
 * BHF_RUNTRACE_LOG, which `bhf auto` folds into the next pass's dictionary.
 * Each distinct operand pair is written once per process, and at most
 * BHF_CMPLOG_MAX_BYTES in all. */
#define BHF_CMPLOG_OPMAX 32u
#define BHF_CMPLOG_MAX_BYTES (1u << 20)
static int bhf_cmplog_fd = -2;
static uint32_t bhf_cmplog_written = 0;
static uint64_t bhf_cmplog_seen[4096];
BHF_NOCOV static void bhf_cmplog_open(void) {
#ifdef _WIN32
    bhf_cmplog_fd = -1;
#else
    const char *on, *path;
    if (bhf_cmplog_fd != -2) return;
    bhf_cmplog_fd = -1;
    on = getenv("BHF_CMPLOG");
    path = getenv("BHF_RUNTRACE_LOG");
    /* No strcmp here: under ASan it would call this driver's own weak hook. */
    if (!on || on[0] != '1' || on[1] != 0 || !path || !*path) return;
    bhf_cmplog_fd = bhf_open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
#endif
}
BHF_NOCOV static void bhf_cmplog_line(const char *kind, const unsigned char *a, unsigned la,
                                      const unsigned char *b, unsigned lb) {
    static const char hex[] = "0123456789abcdef";
    char line[64 + 4 * BHF_CMPLOG_OPMAX];
    unsigned len = 0, i, k;
    uint64_t h = 1469598103934665603ull;
    const char *p;
    if (bhf_cmplog_fd == -2) bhf_cmplog_open();
    if (bhf_cmplog_fd < 0 || (la == 0 && lb == 0)) return;
    if (la > BHF_CMPLOG_OPMAX) la = BHF_CMPLOG_OPMAX;
    if (lb > BHF_CMPLOG_OPMAX) lb = BHF_CMPLOG_OPMAX;
    for (p = kind; *p; p++) { h ^= (unsigned char)*p; h *= 1099511628211ull; }
    for (i = 0; i < la; i++) { h ^= a[i]; h *= 1099511628211ull; }
    h ^= 0xffu; h *= 1099511628211ull;
    for (i = 0; i < lb; i++) { h ^= b[i]; h *= 1099511628211ull; }
    if (h == 0) h = 1;
    if (bhf_cmplog_seen[h & 4095u] == h) return;
    bhf_cmplog_seen[h & 4095u] = h;
#define BHF_CL_PUT(s) for (p = (s); *p; p++) line[len++] = *p
    BHF_CL_PUT("{\"e\":\"cmplog\",\"k\":\"");
    BHF_CL_PUT(kind);
    BHF_CL_PUT("\",\"a\":\"");
    for (k = 0; k < la; k++) { line[len++] = hex[a[k] >> 4]; line[len++] = hex[a[k] & 15]; }
    BHF_CL_PUT("\",\"b\":\"");
    for (k = 0; k < lb; k++) { line[len++] = hex[b[k] >> 4]; line[len++] = hex[b[k] & 15]; }
    BHF_CL_PUT("\"}\n");
#undef BHF_CL_PUT
    if (bhf_cmplog_written + len > BHF_CMPLOG_MAX_BYTES) return;
    bhf_cmplog_written += len;
    if (bhf_write(bhf_cmplog_fd, line, len) < 0) return;
}
BHF_NOCOV static void bhf_cmplog_buf(const char *kind, const void *pc, const void *s1,
                                     const void *s2, size_t n, int stop_at_nul) {
    const unsigned char *a = (const unsigned char *)s1, *b = (const unsigned char *)s2;
    unsigned cap;
    uint32_t site;
    if (bhf_cmplog_fd == -1 || !a || !b) return;
    /* Only the program's own compares: not libc's or a preloaded library's,
     * and not the runtrace shim's from inside its hooks. */
    if (!bhf_ev_site(pc, &site) || BHF_IN_SHIM()) return;
    cap = n > BHF_CMPLOG_OPMAX ? BHF_CMPLOG_OPMAX : (unsigned)n;
    bhf_cmplog_line(kind, a, bhf_ev_len(a, cap, stop_at_nul), b, bhf_ev_len(b, cap, stop_at_nul));
}

/* One-byte, cumulative proof that generated harness code crossed the boundary
 * immediately before the selected project target.  This is deliberately
 * separate from edge coverage: a driver/fork-server can execute and collect
 * its own edges without ever entering the endpoint. */
static unsigned char *bhf_target_map = 0;
BHF_NOCOV void bhf_target_enter(void) {
    /* Comparison evidence: the records so far are the harness's own decoding
     * of the input, which the reader leaves out once the target was entered.
     * Discard them at the first entry so a harness that compares every input
     * byte cannot use up the capacity the target's comparisons need. */
    if (bhf_ev_map && !bhf_ev_entered) {
        bhf_ev_put32(bhf_ev_map + 8, 0);
        bhf_ev_map[12] = (unsigned char)(bhf_ev_map[12] & ~2u);
    }
    bhf_ev_entered = 1;
    if (bhf_ev_map) bhf_ev_map[12] |= 1u;
    if (!bhf_target_map) {
        const char *p = getenv("BHF_TARGET_ENTRY_SHM");
        if (p && *p) {
            void *m = bhf_map_shared(p, 1);
            if (m) bhf_target_map = (unsigned char *)m;
        }
    }
    if (bhf_target_map) bhf_target_map[0] = 1;
}
/* AFL-style per-exec hit-count buckets (#420): a SECOND map, BHF_COV_CNT_SHM,
 * same size, one byte per edge; trace-pc-guard saturating-increments it so the
 * engine can bucket loop/recursion depth. No-op when unset. */
static unsigned char *bhf_cov_cnt_map = 0;
BHF_NOCOV static void bhf_cov_cnt_open(void) {
    if (bhf_cov_cnt_map) return;
    const char *p = getenv("BHF_COV_CNT_SHM");
    if (!p || !*p) return;
    void *m = bhf_map_shared(p, BHF_COV_BITS);
    if (m) bhf_cov_cnt_map = (unsigned char *)m;
}
/* laf-intel comparison-progress (#421): a THIRD map, BHF_CMP_PROGRESS_SHM,
 * one byte per hashed compare site recording the MAX leading-byte match this
 * exec, so the engine can reward an input one byte closer to a multi-byte gate.
 * No-op when unset. */
#define BHF_CMPP_BITS (1u << 16)
static unsigned char *bhf_cmpp_map = 0;
BHF_NOCOV static void bhf_cmpp_open(void) {
    if (bhf_cmpp_map) return;
    const char *p = getenv("BHF_CMP_PROGRESS_SHM");
    if (!p || !*p) return;
    void *m = bhf_map_shared(p, BHF_CMPP_BITS);
    if (m) bhf_cmpp_map = (unsigned char *)m;
}
BHF_NOCOV static unsigned bhf_cmpp_slot(const void *ra) {
    uintptr_t rel = (uintptr_t)ra - (uintptr_t)&bhf_cmpp_open;
    return (unsigned)(rel * 2654435761u) & (BHF_CMPP_BITS - 1);
}
BHF_NOCOV static void bhf_cmpp_int(uint64_t a, uint64_t b, unsigned width, const void *ra) {
    unsigned m, i, slot;
    unsigned char p;
    if (!bhf_cmpp_map || a == b) return;
    if (width > 8) width = 8;
    m = 0;
    for (i = 0; i < width; i++) {
        if (((a >> (8 * i)) & 0xff) == ((b >> (8 * i)) & 0xff)) m++;
        else break;
    }
    if (m == 0) return;
    p = (unsigned char)(m > 7 ? 7 : m);
    slot = bhf_cmpp_slot(ra);
    if (bhf_cmpp_map[slot] < p) bhf_cmpp_map[slot] = p;
}
BHF_NOCOV static void bhf_cmpp_buf(const unsigned char *s1, const unsigned char *s2,
                                           unsigned n, int result, const void *pc) {
    unsigned m = 0, slot;
    unsigned char p;
    if (!bhf_cmpp_map || result == 0) return;
    if (n > 8u) n = 8u;
    while (m < n && s1[m] == s2[m]) m++;
    if (m == 0) return;
    p = (unsigned char)(m > 7 ? 7 : m);
    slot = bhf_cmpp_slot(pc);
    if (bhf_cmpp_map[slot] < p) bhf_cmpp_map[slot] = p;
}

/* RedQueen/cmplog operand ring (#400) in BHF_CMP_SHM. Layout MUST match
 * CmpShmReader in crates/cli/src/fuzz.rs:
 *   [u32 armed][u32 count] then BHF_CMP_CAP records of
 *   [u8 len_a][u8 len_b][u8 a[OPMAX]][u8 b[OPMAX]]. */
#define BHF_CMP_CAP 2048u
#define BHF_CMP_OPMAX 32u
#define BHF_CMP_REC (2u + 2u * BHF_CMP_OPMAX)
#define BHF_CMP_BYTES (8u + BHF_CMP_CAP * BHF_CMP_REC)
static unsigned char *bhf_cmp_map = 0;
BHF_NOCOV static void bhf_cmp_open(void) {
    const char *p;
    if (bhf_cmp_map) return;
    p = getenv("BHF_CMP_SHM");
    if (!p || !*p) return;
    void *m = bhf_map_shared(p, BHF_CMP_BYTES);
    if (m) bhf_cmp_map = (unsigned char *)m;
}
BHF_NOCOV static int bhf_cmp_armed(void) {
    unsigned char *m = bhf_cmp_map;
    if (!m) return 0;
    return m[0] | m[1] | m[2] | m[3];
}
BHF_NOCOV static void bhf_cmp_push(const unsigned char *a, unsigned la,
                                           const unsigned char *b, unsigned lb) {
    unsigned char *m = bhf_cmp_map;
    unsigned count, off, i;
    if (!m) return;
    if (la > BHF_CMP_OPMAX) la = BHF_CMP_OPMAX;
    if (lb > BHF_CMP_OPMAX) lb = BHF_CMP_OPMAX;
    count = (unsigned)m[4] | ((unsigned)m[5] << 8) | ((unsigned)m[6] << 16) | ((unsigned)m[7] << 24);
    if (count >= BHF_CMP_CAP) return;
    off = 8u + count * BHF_CMP_REC;
    m[off] = (unsigned char)la;
    m[off + 1] = (unsigned char)lb;
    for (i = 0; i < la; i++) m[off + 2u + i] = a[i];
    for (i = 0; i < lb; i++) m[off + 2u + BHF_CMP_OPMAX + i] = b[i];
    count++;
    m[4] = (unsigned char)count;
    m[5] = (unsigned char)(count >> 8);
    m[6] = (unsigned char)(count >> 16);
    m[7] = (unsigned char)(count >> 24);
}
BHF_NOCOV static void bhf_cmp_int(uint64_t a, uint64_t b, unsigned width) {
    unsigned char ab[8], bb[8];
    unsigned i;
    if (!bhf_cmp_armed()) return;
    if (a == b || a == 0 || b == 0) return;
    if (width > 8) width = 8;
    for (i = 0; i < width; i++) {
        ab[i] = (unsigned char)(a >> (8 * i));
        bb[i] = (unsigned char)(b >> (8 * i));
    }
    bhf_cmp_push(ab, width, bb, width);
}
BHF_NOCOV static unsigned bhf_cmp_copy(unsigned char *dst, const unsigned char *src,
                                               unsigned maxlen, int stop_at_nul) {
    unsigned i;
    for (i = 0; i < maxlen; i++) {
        unsigned char c = src[i];
        if (stop_at_nul && c == 0) break;
        dst[i] = c;
    }
    return i;
}
BHF_NOCOV static void bhf_cmp_buf(const unsigned char *s1, const unsigned char *s2,
                                          unsigned n, int stop_at_nul, int result) {
    unsigned char a[BHF_CMP_OPMAX], b[BHF_CMP_OPMAX];
    unsigned la, lb;
    if (!bhf_cmp_armed() || result == 0) return;
    if (n > BHF_CMP_OPMAX) n = BHF_CMP_OPMAX;
    la = bhf_cmp_copy(a, s1, n, stop_at_nul);
    lb = bhf_cmp_copy(b, s2, n, stop_at_nul);
    if (la == 0 && lb == 0) return;
    bhf_cmp_push(a, la, b, lb);
}

/* Value-profile token log (#398) in BHF_VP_SHM:
 * [u32 cursor][ {u8 len}{len bytes} ... ], deduped in-process. */
#define BHF_VP_BYTES (1u << 16)
static unsigned char *bhf_vp_map = 0;
static unsigned char bhf_vp_seen1[256];
static uint64_t bhf_vp_seenN[4096];
BHF_NOCOV static void bhf_vp_open(void) {
    if (bhf_vp_map) return;
    const char *p = getenv("BHF_VP_SHM");
    if (!p || !*p) return;
    void *m = bhf_map_shared(p, BHF_VP_BYTES);
    if (m) bhf_vp_map = (unsigned char *)m;
}
BHF_NOCOV static void bhf_vp_add(const unsigned char *data, unsigned len) {
    if (!bhf_vp_map || len == 0 || len > 8) return;
    unsigned z = 1;
    for (unsigned i = 0; i < len; i++) if (data[i]) { z = 0; break; }
    if (z) return;
    if (len == 1) {
        if (bhf_vp_seen1[data[0]]) return;
        bhf_vp_seen1[data[0]] = 1;
    } else {
        uint64_t h = 1469598103934665603ull;
        for (unsigned i = 0; i < len; i++) { h ^= data[i]; h *= 1099511628211ull; }
        h ^= len;
        uint64_t slot = h & 4095u;
        if (bhf_vp_seenN[slot] == h) return;
        bhf_vp_seenN[slot] = h;
    }
    uint32_t *cursor = (uint32_t *)bhf_vp_map;
    uint32_t c = *cursor;
    if ((size_t)c + 1u + len + 4u > BHF_VP_BYTES) return;
    unsigned char *w = bhf_vp_map + 4 + c;
    w[0] = (unsigned char)len;
    for (unsigned i = 0; i < len; i++) w[1 + i] = data[i];
    *cursor = c + 1 + len;
}

/* Inline 8-bit counters (`-fsanitize-coverage=inline-8bit-counters`, the form
 * MSVC implements): the instrumented code increments one byte per edge itself,
 * and the counters are folded into the same edge and hit-count maps after each
 * input, then cleared. Each instrumented module registers its counter array
 * once, at start-up. */
#define BHF_C8_MAX_MODULES 16
static unsigned char *bhf_c8_start[BHF_C8_MAX_MODULES];
static unsigned char *bhf_c8_stop[BHF_C8_MAX_MODULES];
static uint32_t bhf_c8_base[BHF_C8_MAX_MODULES];
static unsigned bhf_c8_modules = 0;
BHF_NOCOV BHF_EXPORT void __sanitizer_cov_8bit_counters_init(unsigned char *start, unsigned char *stop) {
    unsigned i;
    if (start == stop) return;
    for (i = 0; i < bhf_c8_modules; i++)
        if (bhf_c8_start[i] == start) return;
    if (bhf_c8_modules == BHF_C8_MAX_MODULES) return;
    bhf_c8_start[bhf_c8_modules] = start;
    bhf_c8_stop[bhf_c8_modules] = stop;
    bhf_c8_base[bhf_c8_modules] = bhf_cov_next;
    bhf_cov_next += (uint32_t)(stop - start);
    bhf_c8_modules++;
    bhf_cov_open();
    bhf_cov_cnt_open();
    bhf_cmp_open();
    bhf_cmpp_open();
    bhf_ev_open();
}
BHF_NOCOV static void bhf_c8_flush(void) {
    unsigned module;
    for (module = 0; module < bhf_c8_modules; module++) {
        unsigned char *p = bhf_c8_start[module];
        uint32_t edge = bhf_c8_base[module];
        for (; p < bhf_c8_stop[module]; p++) {
            unsigned char hits = *p;
            uint32_t slot;
            edge++;
            if (!hits) continue;
            *p = 0;
            slot = edge & (BHF_COV_BITS - 1);
            if (bhf_cov_map) bhf_cov_map[slot] = 1;
            if (bhf_cov_cnt_map) {
                unsigned total = (unsigned)bhf_cov_cnt_map[slot] + hits;
                bhf_cov_cnt_map[slot] = (unsigned char)(total > 255 ? 255 : total);
            }
        }
    }
}

BHF_NOCOV void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    if (start == stop || *start) return;
    for (uint32_t *x = start; x < stop; x++) *x = ++bhf_cov_next;
    bhf_cov_open();
    bhf_cov_cnt_open();
    bhf_cmp_open();
    bhf_cmpp_open();
    bhf_ev_open();
}
BHF_NOCOV void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    if (!*guard || !bhf_cov_map) return;
    bhf_cov_map[*guard & (BHF_COV_BITS - 1)] = 1;
    if (bhf_cov_cnt_map && bhf_cov_cnt_map[*guard & (BHF_COV_BITS - 1)] != 255)
        bhf_cov_cnt_map[*guard & (BHF_COV_BITS - 1)]++;
}
/* GCC has no `trace-pc-guard`; GCC-family builds instrument with
 * `-fsanitize-coverage=trace-pc`, which calls this guard-less hook at each edge.
 * Hash the return address into the SAME bitmap the guard path fills so the
 * engine's coverage reader stays platform-agnostic. */
BHF_NOCOV void __sanitizer_cov_trace_pc(void) {
    if (!bhf_cov_map) return;
    uintptr_t pc = (uintptr_t)BHF_RA;
    uint32_t h = ((uint32_t)(pc * 2654435761u) >> 4) & (BHF_COV_BITS - 1);
    bhf_cov_map[h] = 1;
    if (bhf_cov_cnt_map && bhf_cov_cnt_map[h] != 255)
        bhf_cov_cnt_map[h]++;
}
BHF_NOCOV void __sanitizer_cov_trace_cmp1(uint8_t a, uint8_t b) { bhf_ev_int(BHF_EV_INT, a, b, 1, 0, BHF_RA); bhf_cmp_int(a, b, 1); bhf_cmpp_int(a, b, 1, BHF_RA); }
BHF_NOCOV void __sanitizer_cov_trace_cmp2(uint16_t a, uint16_t b) { bhf_ev_int(BHF_EV_INT, a, b, 2, 0, BHF_RA); bhf_cmp_int(a, b, 2); bhf_cmpp_int(a, b, 2, BHF_RA); }
BHF_NOCOV void __sanitizer_cov_trace_cmp4(uint32_t a, uint32_t b) { bhf_ev_int(BHF_EV_INT, a, b, 4, 0, BHF_RA); bhf_cmp_int(a, b, 4); bhf_cmpp_int(a, b, 4, BHF_RA); }
BHF_NOCOV void __sanitizer_cov_trace_cmp8(uint64_t a, uint64_t b) { bhf_ev_int(BHF_EV_INT, a, b, 8, 0, BHF_RA); bhf_cmp_int(a, b, 8); bhf_cmpp_int(a, b, 8, BHF_RA); }
/* Float/double comparison hooks (Fortran numeric code + float-heavy C/C++ emit
 * these under trace-cmp; missing them fails the link). Feed the bit patterns to
 * the same cmplog so a magic float/double constant stays learnable. */
BHF_NOCOV void __sanitizer_cov_trace_cmpf(float a, float b) { uint32_t ua, ub; BHF_MEMCPY(&ua, &a, 4); BHF_MEMCPY(&ub, &b, 4); bhf_ev_int(BHF_EV_FLOAT, ua, ub, 4, 0, BHF_RA); bhf_cmp_int(ua, ub, 4); bhf_cmpp_int(ua, ub, 4, BHF_RA); }
BHF_NOCOV void __sanitizer_cov_trace_cmpd(double a, double b) { uint64_t ua, ub; BHF_MEMCPY(&ua, &a, 8); BHF_MEMCPY(&ub, &b, 8); bhf_ev_int(BHF_EV_DOUBLE, ua, ub, 8, 0, BHF_RA); bhf_cmp_int(ua, ub, 8); bhf_cmpp_int(ua, ub, 8, BHF_RA); }
/* In a const_cmp callback the FIRST argument is the compile-time constant. */
BHF_NOCOV void __sanitizer_cov_trace_const_cmp1(uint8_t a, uint8_t b) { bhf_ev_int(BHF_EV_INT, a, b, 1, BHF_EV_CONST_A, BHF_RA); bhf_vp_add(&a, 1); bhf_vp_add(&b, 1); bhf_cmp_int(a, b, 1); bhf_cmpp_int(a, b, 1, BHF_RA); }
BHF_NOCOV void __sanitizer_cov_trace_const_cmp2(uint16_t a, uint16_t b) { bhf_ev_int(BHF_EV_INT, a, b, 2, BHF_EV_CONST_A, BHF_RA); bhf_vp_add((unsigned char *)&a, 2); bhf_vp_add((unsigned char *)&b, 2); bhf_cmp_int(a, b, 2); bhf_cmpp_int(a, b, 2, BHF_RA); }
BHF_NOCOV void __sanitizer_cov_trace_const_cmp4(uint32_t a, uint32_t b) { bhf_ev_int(BHF_EV_INT, a, b, 4, BHF_EV_CONST_A, BHF_RA); bhf_vp_add((unsigned char *)&a, 4); bhf_vp_add((unsigned char *)&b, 4); bhf_cmp_int(a, b, 4); bhf_cmpp_int(a, b, 4, BHF_RA); }
BHF_NOCOV void __sanitizer_cov_trace_const_cmp8(uint64_t a, uint64_t b) { bhf_ev_int(BHF_EV_INT, a, b, 8, BHF_EV_CONST_A, BHF_RA); bhf_vp_add((unsigned char *)&a, 8); bhf_vp_add((unsigned char *)&b, 8); bhf_cmp_int(a, b, 8); bhf_cmpp_int(a, b, 8, BHF_RA); }
BHF_NOCOV void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases) {
    uint64_t n = cases[0], bits = cases[1];
    unsigned len = (unsigned)(bits / 8);
    uint64_t i;
    if (len < 1) len = 1;
    if (len > 8) len = 8;
    for (i = 0; i < n; i++) {
        uint64_t cv = cases[2 + i];
        bhf_vp_add((unsigned char *)&cv, len);
    }
    if (bhf_ev_map) {
        for (i = 0; i < n && i < 64; i++)
            bhf_ev_int(BHF_EV_SWITCH, val, cases[2 + i], len, BHF_EV_CONST_B, BHF_RA);
    }
    if (bhf_cmp_armed()) {
        for (i = 0; i < n && i < 64; i++) bhf_cmp_int(val, cases[2 + i], len);
    }
}
/* Division hooks (`trace-div`): a divisor the input controls is compared with
 * zero, which is what makes a division-by-zero reachable. */
BHF_NOCOV void __sanitizer_cov_trace_div4(uint32_t val) { bhf_ev_int(BHF_EV_INT, val, 0, 4, BHF_EV_CONST_B, BHF_RA); bhf_cmpp_int(val, 0, 4, BHF_RA); }
BHF_NOCOV void __sanitizer_cov_trace_div8(uint64_t val) { bhf_ev_int(BHF_EV_INT, val, 0, 8, BHF_EV_CONST_B, BHF_RA); bhf_cmpp_int(val, 0, 8, BHF_RA); }
/* ASan's str/mem-cmp interceptors call these weak hooks (even without libFuzzer
 * linked), feeding multi-byte string/buffer gates into the RedQueen ring, the
 * runtime cmplog and comparison evidence. memcmp's hook also covers bcmp, which
 * clang emits for `memcmp(...) == 0`: ASan routes both through it. */
BHF_NOCOV void __sanitizer_weak_hook_memcmp(void *pc, const void *s1, const void *s2, size_t n, int result) {
    bhf_ev_buf(BHF_EV_MEMCMP, pc, s1, s2, n, 0, result);
    bhf_cmplog_buf("memcmp", pc, s1, s2, n, 0);
    bhf_cmp_buf((const unsigned char *)s1, (const unsigned char *)s2, (unsigned)n, 0, result);
    bhf_cmpp_buf((const unsigned char *)s1, (const unsigned char *)s2, (unsigned)n, result, pc);
}
BHF_NOCOV void __sanitizer_weak_hook_strncmp(void *pc, const char *s1, const char *s2, size_t n, int result) {
    bhf_ev_buf(BHF_EV_STRNCMP, pc, s1, s2, n, 1, result);
    bhf_cmplog_buf("strncmp", pc, s1, s2, n, 1);
    bhf_cmp_buf((const unsigned char *)s1, (const unsigned char *)s2, (unsigned)n, 1, result);
    bhf_cmpp_buf((const unsigned char *)s1, (const unsigned char *)s2, (unsigned)n, result, pc);
}
BHF_NOCOV void __sanitizer_weak_hook_strcmp(void *pc, const char *s1, const char *s2, int result) {
    bhf_ev_buf(BHF_EV_STRCMP, pc, s1, s2, BHF_EV_OPMAX, 1, result);
    bhf_cmplog_buf("strcmp", pc, s1, s2, BHF_CMPLOG_OPMAX, 1);
    bhf_cmp_buf((const unsigned char *)s1, (const unsigned char *)s2, BHF_CMP_OPMAX, 1, result);
    bhf_cmpp_buf((const unsigned char *)s1, (const unsigned char *)s2, BHF_CMP_OPMAX, result, pc);
}
BHF_NOCOV void __sanitizer_weak_hook_strncasecmp(void *pc, const char *s1, const char *s2, size_t n, int result) {
    bhf_ev_buf(BHF_EV_STRNCASECMP, pc, s1, s2, n, 1, result);
    bhf_cmplog_buf("strncasecmp", pc, s1, s2, n, 1);
    bhf_cmp_buf((const unsigned char *)s1, (const unsigned char *)s2, (unsigned)n, 1, result);
    bhf_cmpp_buf((const unsigned char *)s1, (const unsigned char *)s2, (unsigned)n, result, pc);
}
BHF_NOCOV void __sanitizer_weak_hook_strcasecmp(void *pc, const char *s1, const char *s2, int result) {
    bhf_ev_buf(BHF_EV_STRCASECMP, pc, s1, s2, BHF_EV_OPMAX, 1, result);
    bhf_cmplog_buf("strcasecmp", pc, s1, s2, BHF_CMPLOG_OPMAX, 1);
    bhf_cmp_buf((const unsigned char *)s1, (const unsigned char *)s2, BHF_CMP_OPMAX, 1, result);
    bhf_cmpp_buf((const unsigned char *)s1, (const unsigned char *)s2, BHF_CMP_OPMAX, result, pc);
}

/* The same hooks for a build without a sanitizer runtime, such as a cross
 * build run under an emulator: no interceptor calls the hooks above there, so
 * bhf links that harness with `-Wl,--wrap=<name>` for each function below. The
 * linker then sends the program's own calls here; each one forwards to the real
 * function and hands the hook its operands and result. In every other build the
 * wrappers are unused and their `__real_` references stay unresolved, hence
 * weak. */
#if defined(__ELF__) && !defined(_WIN32)
extern int __real_memcmp(const void *, const void *, size_t) __attribute__((weak));
extern int __real_bcmp(const void *, const void *, size_t) __attribute__((weak));
extern int __real_strcmp(const char *, const char *) __attribute__((weak));
extern int __real_strncmp(const char *, const char *, size_t) __attribute__((weak));
extern int __real_strcasecmp(const char *, const char *) __attribute__((weak));
extern int __real_strncasecmp(const char *, const char *, size_t) __attribute__((weak));
BHF_NOCOV int __wrap_memcmp(const void *s1, const void *s2, size_t n) {
    int result = __real_memcmp(s1, s2, n);
    __sanitizer_weak_hook_memcmp(__builtin_return_address(0), s1, s2, n, result);
    return result;
}
BHF_NOCOV int __wrap_bcmp(const void *s1, const void *s2, size_t n) {
    int result = __real_bcmp(s1, s2, n);
    __sanitizer_weak_hook_memcmp(__builtin_return_address(0), s1, s2, n, result);
    return result;
}
BHF_NOCOV int __wrap_strcmp(const char *s1, const char *s2) {
    int result = __real_strcmp(s1, s2);
    __sanitizer_weak_hook_strcmp(__builtin_return_address(0), s1, s2, result);
    return result;
}
BHF_NOCOV int __wrap_strncmp(const char *s1, const char *s2, size_t n) {
    int result = __real_strncmp(s1, s2, n);
    __sanitizer_weak_hook_strncmp(__builtin_return_address(0), s1, s2, n, result);
    return result;
}
BHF_NOCOV int __wrap_strcasecmp(const char *s1, const char *s2) {
    int result = __real_strcasecmp(s1, s2);
    __sanitizer_weak_hook_strcasecmp(__builtin_return_address(0), s1, s2, result);
    return result;
}
BHF_NOCOV int __wrap_strncasecmp(const char *s1, const char *s2, size_t n) {
    int result = __real_strncasecmp(s1, s2, n);
    __sanitizer_weak_hook_strncasecmp(__builtin_return_address(0), s1, s2, n, result);
    return result;
}
#endif

BHF_NOCOV static void bhf_run_one_bytes(const uint8_t *data, size_t size) {
    BHF_PUBLISH_INPUT(data, size);
    bhf_run_one(data, size);
    bhf_c8_flush();
}
static void bhf_run_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    if (n < 0) n = 0;
    rewind(f);
    /* Match the persistent path: over-allocate and NUL-terminate so a harness
     * that deliberately feeds a C-string API cannot read beyond an exact-size
     * replay allocation. */
    uint8_t *b = (uint8_t *)malloc((size_t)(n ? n : 1) + 1);
    if (!b) { fclose(f); return; }
    size_t r = fread(b, 1, (size_t)n, f);
    b[r] = 0;
    fclose(f);
    bhf_run_one_bytes(b, r);
    free(b);
}
static int bhf_read_n(int fd, void *buf, size_t n) {
    size_t got = 0;
    unsigned char *b = (unsigned char *)buf;
    while (got < n) {
        int r = (int)bhf_read(fd, b + got, (unsigned)(n - got));
        if (r <= 0) return 0;
        got += (size_t)r;
    }
    return 1;
}
int main(int argc, char **argv) {
    BHF_FUZZER_INITIALIZE(&argc, &argv);
#ifdef _WIN32
    /* Install the crash handler that makes a fault a detectable exit under wine. */
    bhf_win_install_crash_handler();
#endif
    /* GCC-family builds (and Windows) instrument with `-fsanitize-coverage=trace-pc`,
     * which — unlike clang's `trace-pc-guard` — has NO guard-init callback to open
     * the coverage/cmplog SHM maps. Open them here for every platform. The opens are
     * idempotent (`if (bhf_cov_map) return;`), so this is a no-op on the clang
     * path where `__sanitizer_cov_trace_pc_guard_init` already opened them before
     * main(). Without this, a GCC-built harness leaves the maps NULL and every
     * `__sanitizer_cov_trace_pc` edge callback early-returns — the whole run
     * silently degrades to black-box (zero-coverage) fuzzing. */
    bhf_cov_open();
    bhf_cov_cnt_open();
    bhf_cmpp_open();
    bhf_cmp_open();
    bhf_vp_open();
    bhf_ev_open();
    bhf_cmplog_open();
    /* Persistent fork-server framed protocol (BHF_FRAMED=1): write a ready
     * byte, then loop reading {u32 LE length, bytes} and replying one sync byte
     * per input. #427: redirect the target's stdout to /dev/null and write sync
     * bytes to the saved control fd so target output can't deadlock the pipe. */
    if (getenv("BHF_FRAMED")) {
        int bhf_ctrl_fd = bhf_dup(1);
        int bhf_devnull;
        unsigned char ready = 1;
        if (bhf_ctrl_fd < 0) return 1;
#ifdef _WIN32
        /* Binary mode: stop the CRT translating CRLF / treating 0x1A as EOF in
         * the framed {u32 len, bytes} protocol on stdin and the control fd. */
        _setmode(0, _O_BINARY);
        _setmode(bhf_ctrl_fd, _O_BINARY);
#endif
        bhf_devnull = bhf_open(BHF_DEVNULL, O_WRONLY);
        if (bhf_devnull >= 0) {
            bhf_dup2(bhf_devnull, 1);
            if (bhf_devnull != 1) bhf_close(bhf_devnull);
        }
        if (bhf_write(bhf_ctrl_fd, &ready, 1) != 1) return 1;
        size_t cap = 1u << 20;
        uint8_t *buf = (uint8_t *)malloc(cap);
        if (!buf) return 1;
        for (;;) {
            uint32_t len;
            if (!bhf_read_n(0, &len, 4)) break;
            if ((size_t)len > cap) len = (uint32_t)cap;
            if (len && !bhf_read_n(0, buf, len)) break;
            bhf_run_one_bytes(buf, len);
            unsigned char sync = 1;
            if (bhf_write(bhf_ctrl_fd, &sync, 1) != 1) break;
        }
        free(buf);
        return 0;
    }
    if (argc < 2) return 0;
    bhf_run_file(argv[1]);
    return 0;
}
