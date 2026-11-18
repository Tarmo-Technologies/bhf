/* SPDX-License-Identifier: Apache-2.0 */
/*
 * bhf reference target-side agent (#289); the protocol and the API are in
 * bhf_agent.h. Freestanding C99: build it without SanitizerCoverage (the agent
 * is not code under test) and link it with the code under test, which is.
 */
#include "bhf_agent.h"

#ifndef BHF_AGENT_NO_SETJMP
#include <setjmp.h>
#endif

#if defined(__clang__)
#define BHF_AGENT_NOCOV __attribute__((no_sanitize("coverage")))
#elif defined(__GNUC__) && __GNUC__ >= 12
#define BHF_AGENT_NOCOV __attribute__((no_sanitize_coverage))
#else
#define BHF_AGENT_NOCOV
#endif

/* The edges seen in the running input, as a bitmap of guard ids modulo its
 * size: an edge is recorded once per input. */
#ifndef BHF_AGENT_SEEN_BITS
#define BHF_AGENT_SEEN_BITS (1u << 16)
#endif

static const bhf_agent_config *bhf_cfg;
static uint8_t bhf_seen[BHF_AGENT_SEEN_BITS / 8u];
static size_t bhf_n_edges;
static volatile int bhf_running;

static volatile int bhf_faulted;
static uint32_t bhf_fault_kind;
static uint64_t bhf_fault_addr;
static char bhf_fault_detail[BHF_AGENT_DETAIL_MAX];
static uint32_t bhf_fault_detail_len;

#ifndef BHF_AGENT_NO_SETJMP
static jmp_buf bhf_resume;
#endif

BHF_AGENT_NOCOV static void bhf_put_u32(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
}

BHF_AGENT_NOCOV static uint32_t bhf_get_u32(const uint8_t *in) {
    return (uint32_t)in[0] | ((uint32_t)in[1] << 8) | ((uint32_t)in[2] << 16) |
           ((uint32_t)in[3] << 24);
}

BHF_AGENT_NOCOV static int bhf_write_u32(uint32_t value) {
    uint8_t word[4];
    bhf_put_u32(word, value);
    return bhf_cfg->write(bhf_cfg->io_ctx, word, sizeof word);
}

BHF_AGENT_NOCOV void bhf_agent_init(const bhf_agent_config *config) {
    size_t i;
    bhf_cfg = config;
    for (i = 0; i < sizeof bhf_seen; i++) bhf_seen[i] = 0;
    bhf_n_edges = 0;
    bhf_running = 0;
    bhf_faulted = 0;
}

BHF_AGENT_NOCOV void bhf_agent_edge(uint32_t id) {
    uint32_t bit = id % BHF_AGENT_SEEN_BITS;
    uint8_t mask = (uint8_t)(1u << (bit & 7u));
    if (!bhf_running || (bhf_seen[bit >> 3] & mask)) return;
    bhf_seen[bit >> 3] |= mask;
    if (bhf_n_edges < bhf_cfg->edge_cap) bhf_cfg->edges[bhf_n_edges++] = id;
}

BHF_AGENT_NOCOV void bhf_agent_fault(uint32_t kind, uint64_t addr, const char *detail) {
    uint32_t len = 0;
    if (!bhf_running) return;
    bhf_running = 0;
    bhf_fault_kind = kind;
    bhf_fault_addr = addr;
    while (detail && detail[len] && len < BHF_AGENT_DETAIL_MAX) {
        bhf_fault_detail[len] = detail[len];
        len++;
    }
    bhf_fault_detail_len = len;
    bhf_faulted = 1;
#ifndef BHF_AGENT_NO_SETJMP
    longjmp(bhf_resume, 1);
#endif
}

/* Forget the running input's edges for the next one. */
BHF_AGENT_NOCOV static void bhf_reset_edges(void) {
    size_t i;
    for (i = 0; i < bhf_n_edges; i++) {
        uint32_t bit = bhf_cfg->edges[i] % BHF_AGENT_SEEN_BITS;
        bhf_seen[bit >> 3] &= (uint8_t)~(1u << (bit & 7u));
    }
    bhf_n_edges = 0;
}

/* Read and drop `len` input bytes the agent will not run. */
BHF_AGENT_NOCOV static int bhf_drain(uint32_t len) {
    uint8_t scratch[64];
    while (len > 0) {
        uint32_t chunk = len < sizeof scratch ? len : (uint32_t)sizeof scratch;
        if (bhf_cfg->read(bhf_cfg->io_ctx, scratch, chunk) != 0) return -1;
        len -= chunk;
    }
    return 0;
}

BHF_AGENT_NOCOV static int bhf_reply(uint32_t status) {
    uint8_t chunk[4 * 64];
    size_t i = 0;
    if (bhf_write_u32(status) != 0 || bhf_write_u32((uint32_t)bhf_n_edges) != 0) return -1;
    while (i < bhf_n_edges) {
        size_t n = 0;
        while (i < bhf_n_edges && n < sizeof chunk) {
            bhf_put_u32(chunk + n, bhf_cfg->edges[i++]);
            n += 4;
        }
        if (bhf_cfg->write(bhf_cfg->io_ctx, chunk, n) != 0) return -1;
    }
    if (!bhf_faulted) return bhf_write_u32(0);
    {
        uint8_t head[4 + 4 + 8 + 4];
        bhf_put_u32(head, 1);
        bhf_put_u32(head + 4, bhf_fault_kind);
        bhf_put_u32(head + 8, (uint32_t)bhf_fault_addr);
        bhf_put_u32(head + 12, (uint32_t)(bhf_fault_addr >> 32));
        bhf_put_u32(head + 16, bhf_fault_detail_len);
        if (bhf_cfg->write(bhf_cfg->io_ctx, head, sizeof head) != 0) return -1;
        if (bhf_fault_detail_len > 0 &&
            bhf_cfg->write(bhf_cfg->io_ctx, (const uint8_t *)bhf_fault_detail,
                           bhf_fault_detail_len) != 0)
            return -1;
    }
    return 0;
}

BHF_AGENT_NOCOV int bhf_agent_serve_one(void) {
    uint8_t word[4];
    uint32_t len;
    uint32_t status = BHF_AGENT_STATUS_OK;
    if (bhf_cfg->read(bhf_cfg->io_ctx, word, sizeof word) != 0) return -1;
    len = bhf_get_u32(word);
    bhf_reset_edges();
    bhf_faulted = 0;
    if (len > bhf_cfg->input_cap) {
        /* Refused: read past it, so the next frame is where the host sends it. */
        if (bhf_drain(len) != 0) return -1;
        return bhf_reply(BHF_AGENT_STATUS_REFUSED);
    }
    if (len > 0 && bhf_cfg->read(bhf_cfg->io_ctx, bhf_cfg->input, len) != 0) return -1;
#ifndef BHF_AGENT_NO_SETJMP
    if (setjmp(bhf_resume) == 0) {
        bhf_running = 1;
        (void)bhf_cfg->entry(bhf_cfg->input, len);
        bhf_running = 0;
    }
#else
    bhf_running = 1;
    (void)bhf_cfg->entry(bhf_cfg->input, len);
    bhf_running = 0;
#endif
    if (bhf_faulted) status = BHF_AGENT_STATUS_CRASH;
    return bhf_reply(status);
}

BHF_AGENT_NOCOV int bhf_agent_report_fault(void) {
    if (!bhf_faulted) return 0;
    if (bhf_reply(BHF_AGENT_STATUS_CRASH) != 0) return -1;
    bhf_faulted = 0;
    return 0;
}

BHF_AGENT_NOCOV void bhf_agent_serve(void) {
    while (bhf_agent_serve_one() == 0) {
    }
}

#ifndef BHF_AGENT_NO_SANCOV
/* SanitizerCoverage's trace-pc-guard callbacks: number the guards, and record
 * each one the running input reaches. */
BHF_AGENT_NOCOV void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    static uint32_t next;
    uint32_t *guard;
    if (start == stop || *start) return;
    for (guard = start; guard < stop; guard++) *guard = ++next;
}

BHF_AGENT_NOCOV void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    if (*guard && bhf_running) bhf_agent_edge(*guard);
}

/* GCC's -fsanitize-coverage=trace-pc, which has no guards: the edge is the
 * address the callback returns to, a block of the code under test. */
BHF_AGENT_NOCOV void __sanitizer_cov_trace_pc(void) {
    if (bhf_running) bhf_agent_edge((uint32_t)(uintptr_t)__builtin_return_address(0));
}
#endif
