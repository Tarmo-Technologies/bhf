/* SPDX-License-Identifier: Apache-2.0 */
/*
 * bhf reference agent on Zephyr (#291): the agent of bhf_agent.c, built with
 * BHF_AGENT_NO_SETJMP, served on a UART in its own thread. Zephyr's
 * fatal-error path ends a thread that faults, so the fault handler records
 * the fault for the running input, the thread that started the agent sends
 * its reply, and a new agent thread serves the next input.
 */
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/fatal.h>
#include <zephyr/kernel.h>

#include "bhf_agent.h"
#include "bhf_agent_zephyr.h"

static const struct device *const bhf_uart = DEVICE_DT_GET(DT_CHOSEN(bhf_agent_uart));

static uint8_t bhf_input[CONFIG_BHF_AGENT_INPUT_SIZE];
static uint32_t bhf_edges[CONFIG_BHF_AGENT_EDGE_CAP];
static bhf_agent_config bhf_config;

K_THREAD_STACK_DEFINE(bhf_agent_stack, CONFIG_BHF_AGENT_STACK_SIZE);
static struct k_thread bhf_agent_thread;
/* Given by the fatal-error handler when a fault ends the agent thread. */
static K_SEM_DEFINE(bhf_agent_faulted, 0, 1);

static int bhf_uart_read(void *ctx, uint8_t *buf, size_t n) {
    size_t i;
    (void)ctx;
    for (i = 0; i < n; i++) {
        unsigned char c;
        while (uart_poll_in(bhf_uart, &c) != 0) {
            k_yield();
        }
        buf[i] = c;
    }
    return 0;
}

static int bhf_uart_write(void *ctx, const uint8_t *buf, size_t n) {
    size_t i;
    (void)ctx;
    for (i = 0; i < n; i++) {
        uart_poll_out(bhf_uart, buf[i]);
    }
    return 0;
}

static void bhf_agent_main(void *a, void *b, void *c) {
    (void)a;
    (void)b;
    (void)c;
    bhf_agent_serve();
}

/* Zephyr's handler for every fatal error. One in the agent thread is the
 * running input's: record it and return, and Zephyr ends the thread. Any
 * other halts, as Zephyr's default handler does. */
void k_sys_fatal_error_handler(unsigned int reason, const struct arch_esf *esf) {
    if (k_current_get() == &bhf_agent_thread) {
        uint64_t pc = 0;
#if defined(CONFIG_ARM)
        if (esf != NULL) {
            pc = esf->basic.pc;
        }
#else
        (void)esf;
#endif
        bhf_agent_fault(BHF_AGENT_FAULT_CPU_EXCEPTION, pc, "Zephyr fatal error");
        k_sem_give(&bhf_agent_faulted);
        return;
    }
    (void)esf;
    k_fatal_halt(reason);
}

void bhf_agent_zephyr_run(bhf_agent_entry_fn entry) {
    if (!device_is_ready(bhf_uart)) {
        return;
    }
    bhf_config.read = bhf_uart_read;
    bhf_config.write = bhf_uart_write;
    bhf_config.io_ctx = NULL;
    bhf_config.entry = entry;
    bhf_config.input = bhf_input;
    bhf_config.input_cap = sizeof bhf_input;
    bhf_config.edges = bhf_edges;
    bhf_config.edge_cap = sizeof bhf_edges / sizeof bhf_edges[0];
    bhf_agent_init(&bhf_config);
    for (;;) {
        k_thread_create(&bhf_agent_thread, bhf_agent_stack,
                        K_THREAD_STACK_SIZEOF(bhf_agent_stack), bhf_agent_main, NULL, NULL,
                        NULL, CONFIG_BHF_AGENT_PRIORITY, 0, K_NO_WAIT);
        k_sem_take(&bhf_agent_faulted, K_FOREVER);
        k_thread_join(&bhf_agent_thread, K_FOREVER);
        (void)bhf_agent_report_fault();
    }
}
