/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Edge coverage for a service a `bhf fuzz` session campaign starts with
 * `--session-server-cmd` (#363). Build the service with SanitizerCoverage
 * and link this file:
 *
 *   clang -fsanitize=address -fsanitize-coverage=trace-pc-guard \
 *     service.c path/to/bhf/c_runtime/bhf_service_cov.c -o service
 *
 * (GCC: -fsanitize-coverage=trace-pc). bhf sets BHF_COV_SHM for the service
 * to a file it maps: one byte per edge, set when the edge runs, the layout
 * bhf_driver.c's harnesses use. After each session bhf reads the edges the
 * service has reached, and keeps a session that reached new code. Without
 * BHF_COV_SHM, or run outside bhf, every callback returns at once.
 *
 * This file has no main(): it is linked into a program that has one.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

#if defined(__clang__) || defined(__GNUC__)
#define BHF_SVC_NOCOV __attribute__((no_sanitize("coverage"))) __attribute__((used))
#else
#define BHF_SVC_NOCOV
#endif

#define BHF_SVC_COV_BYTES (1u << 16)

static unsigned char *bhf_svc_map = 0;
static int bhf_svc_tried = 0;
static uint32_t bhf_svc_next = 0;

BHF_SVC_NOCOV static void bhf_svc_open(void) {
    const char *path;
    if (bhf_svc_tried) return;
    bhf_svc_tried = 1;
    path = getenv("BHF_COV_SHM");
    if (!path || !*path) return;
#ifdef _WIN32
    {
        HANDLE file = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                  OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        HANDLE mapping;
        if (file == INVALID_HANDLE_VALUE) return;
        mapping = CreateFileMappingA(file, NULL, PAGE_READWRITE, 0, BHF_SVC_COV_BYTES, NULL);
        CloseHandle(file);
        if (!mapping) return;
        bhf_svc_map = (unsigned char *)MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0,
                                                     BHF_SVC_COV_BYTES);
    }
#else
    {
        int fd = open(path, O_RDWR | O_CLOEXEC);
        void *map;
        if (fd < 0) return;
        map = mmap(0, BHF_SVC_COV_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        close(fd);
        if (map != MAP_FAILED) bhf_svc_map = (unsigned char *)map;
    }
#endif
}

BHF_SVC_NOCOV void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    uint32_t *guard;
    if (start == stop || *start) return;
    for (guard = start; guard < stop; guard++) *guard = ++bhf_svc_next;
    bhf_svc_open();
}

BHF_SVC_NOCOV void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    if (!*guard || !bhf_svc_map) return;
    bhf_svc_map[*guard & (BHF_SVC_COV_BYTES - 1)] = 1;
}

/* GCC's -fsanitize-coverage=trace-pc: no guards, so hash the return address
 * into the same map, as bhf_driver.c does. */
BHF_SVC_NOCOV void __sanitizer_cov_trace_pc(void) {
    uintptr_t pc;
    if (!bhf_svc_tried) bhf_svc_open();
    if (!bhf_svc_map) return;
    pc = (uintptr_t)__builtin_return_address(0);
    bhf_svc_map[((uint32_t)(pc * 2654435761u) >> 4) & (BHF_SVC_COV_BYTES - 1)] = 1;
}
