/* SPDX-License-Identifier: Apache-2.0 */
/*
 * bhf reference target-side agent (#289): the target half of
 * `bhf fuzz --target-transport agent:tcp:HOST:PORT` and `agent:serial:PATH`.
 *
 * Freestanding C99: no heap, no libc beyond <stddef.h>/<stdint.h> (and
 * <setjmp.h> for resuming after a fault, unless BHF_AGENT_NO_SETJMP). The
 * board supplies byte I/O over its UART, socket or debug channel, the buffers,
 * and the function under test; the agent runs one input per round trip:
 *
 *   host -> target:  {u32 le len}{len input bytes}
 *   target -> host:  {u32 le status}
 *                    {u32 le n_edges}{n_edges * u32 le edge}
 *                    {u32 le fault_present}
 *                    if fault_present == 1:
 *                        {u32 le kind}{u64 le addr}{u32 le detail_len}{detail}
 *
 * status: 0 ok, 1 crash, 2 timeout, 3 refused (the input is longer than the
 * agent's input buffer: it is read and dropped, not run). Fault kinds are
 * BHF_AGENT_FAULT_*. Edges are the SanitizerCoverage guards the input reached:
 * build the code under test with -fsanitize-coverage=trace-pc-guard and this
 * file provides the callbacks (define BHF_AGENT_NO_SANCOV to provide your own
 * and call bhf_agent_edge()).
 *
 * A fault handler (a HardFault vector, a POSIX signal handler) calls
 * bhf_agent_fault(): the agent reports the fault for the input that was
 * running and goes on with the next one (it longjmps out of the handler; on
 * a target where that is not safe, reset instead and report the fault from
 * the record a reset keeps).
 */
#ifndef BHF_AGENT_H
#define BHF_AGENT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status words. */
#define BHF_AGENT_STATUS_OK 0u
#define BHF_AGENT_STATUS_CRASH 1u
#define BHF_AGENT_STATUS_TIMEOUT 2u
#define BHF_AGENT_STATUS_REFUSED 3u

/* Fault kinds, as the host decodes them. */
#define BHF_AGENT_FAULT_CPU_EXCEPTION 0u
#define BHF_AGENT_FAULT_MEMORY_PROTECTION 1u
#define BHF_AGENT_FAULT_WATCHDOG 2u
#define BHF_AGENT_FAULT_ASSERTION 3u
#define BHF_AGENT_FAULT_STACK_OVERFLOW 4u
#define BHF_AGENT_FAULT_TIMEOUT 5u

/* The longest fault detail the agent keeps. */
#define BHF_AGENT_DETAIL_MAX 96u

/* Read exactly `n` bytes into `buf`; 0 on success, nonzero when the link is
 * gone. */
typedef int (*bhf_agent_read_fn)(void *ctx, uint8_t *buf, size_t n);
/* Write exactly `n` bytes; 0 on success. */
typedef int (*bhf_agent_write_fn)(void *ctx, const uint8_t *buf, size_t n);
/* The function under test, as libFuzzer's LLVMFuzzerTestOneInput. */
typedef int (*bhf_agent_entry_fn)(const uint8_t *data, size_t size);

typedef struct bhf_agent_config {
    bhf_agent_read_fn read;
    bhf_agent_write_fn write;
    void *io_ctx;
    bhf_agent_entry_fn entry;
    /* The input buffer: an input longer than `input_cap` is refused. */
    uint8_t *input;
    size_t input_cap;
    /* The edges one input reached; past `edge_cap` they are dropped. */
    uint32_t *edges;
    size_t edge_cap;
} bhf_agent_config;

/* Start the agent with `config` (kept by pointer: it must outlive the
 * agent). */
void bhf_agent_init(const bhf_agent_config *config);

/* Serve one input: read its frame, run it, reply. 0 after a reply, nonzero
 * when the link is gone. */
int bhf_agent_serve_one(void);

/* Serve inputs until the link is gone. */
void bhf_agent_serve(void);

/* Record that the running input reached edge `id` (the SanitizerCoverage
 * callbacks call it). */
void bhf_agent_edge(uint32_t id);

/* From a fault handler: report fault `kind` at `addr` with `detail` for the
 * running input, and resume the agent loop. Does not return while an input
 * runs; returns at once otherwise. */
void bhf_agent_fault(uint32_t kind, uint64_t addr, const char *detail);

#ifdef __cplusplus
}
#endif

#endif /* BHF_AGENT_H */
