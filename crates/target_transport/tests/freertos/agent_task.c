/* SPDX-License-Identifier: Apache-2.0 */
/*
 * The reference target-side agent (c_runtime/bhf_agent.c) as a FreeRTOS task
 * on mps2-an385 (#290). It serves the agent protocol over UART0, which
 * `qemu-system-arm -serial tcp::PORT,server` makes a socket for
 * `bhf fuzz --target-transport agent:tcp:127.0.0.1:PORT`. A HardFault in the
 * code under test is reported for the input that raised it, and the task
 * goes on with the next input: the handler returns from the exception into
 * bhf_fault_recover, which reports it from the task.
 */
#include <setjmp.h>
#include <stdint.h>

#include "FreeRTOS.h"
#include "task.h"

#include "bhf_agent.h"

/* CMSDK APB UART0. */
#define UART0_DATA (*(volatile uint32_t *)0x40004000u)
#define UART0_STATE (*(volatile uint32_t *)0x40004004u)
#define UART0_CTRL (*(volatile uint32_t *)0x40004008u)
#define UART0_BAUDDIV (*(volatile uint32_t *)0x40004010u)
#define UART_STATE_TX_FULL 1u
#define UART_STATE_RX_FULL 2u

/* System control block fault status. */
#define SCB_CFSR (*(volatile uint32_t *)0xE000ED28u)
#define SCB_HFSR (*(volatile uint32_t *)0xE000ED2Cu)

#define AGENT_INPUT_CAP 256u
#define AGENT_EDGE_CAP 512u

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static uint8_t agent_input[AGENT_INPUT_CAP];
static uint32_t agent_edges[AGENT_EDGE_CAP];
static volatile uint32_t fault_pc;

static int uart_read(void *ctx, uint8_t *buf, size_t n) {
    (void)ctx;
    while (n--) {
        while (!(UART0_STATE & UART_STATE_RX_FULL)) {
        }
        *buf++ = (uint8_t)UART0_DATA;
    }
    return 0;
}

static int uart_write(void *ctx, const uint8_t *buf, size_t n) {
    (void)ctx;
    while (n--) {
        while (UART0_STATE & UART_STATE_TX_FULL) {
        }
        UART0_DATA = *buf++;
    }
    return 0;
}

/* The agent's setjmp/longjmp, for an image without a C library: the
 * callee-saved registers, the stack pointer and the return address. */
__attribute__((naked)) int setjmp(jmp_buf env) {
    (void)env;
    __asm volatile(
        "mov ip, sp\n"
        "stmia r0!, {r4-r11, ip, lr}\n"
        "movs r0, #0\n"
        "bx lr\n");
}

__attribute__((naked, noreturn)) void longjmp(jmp_buf env, int value) {
    (void)env;
    (void)value;
    __asm volatile(
        "ldmia r0!, {r4-r11, ip, lr}\n"
        "mov sp, ip\n"
        "movs r0, r1\n"
        "it eq\n"
        "moveq r0, #1\n"
        "bx lr\n");
}

/* Thread mode again, on the agent task's stack: report the fault. */
void bhf_fault_recover(void) {
    bhf_agent_fault(BHF_AGENT_FAULT_CPU_EXCEPTION, fault_pc, "HardFault");
    for (;;) {
    }
}

/* From HardFault_Handler with the exception frame: return from the exception
 * into bhf_fault_recover instead of the faulting instruction. */
void bhf_hardfault(uint32_t *frame) {
    fault_pc = frame[6];
    SCB_CFSR = SCB_CFSR; /* write-one-to-clear */
    SCB_HFSR = SCB_HFSR;
    frame[6] = (uint32_t)(uintptr_t)bhf_fault_recover;
    frame[7] = 0x01000000u; /* xPSR: Thumb */
}

__attribute__((naked)) void HardFault_Handler(void) {
    __asm volatile(
        "tst lr, #4\n"
        "ite eq\n"
        "mrseq r0, msp\n"
        "mrsne r0, psp\n"
        "push {lr}\n"
        "bl bhf_hardfault\n"
        "pop {pc}\n");
}

static void agent_task(void *arg) {
    static bhf_agent_config config;
    (void)arg;
    config.read = uart_read;
    config.write = uart_write;
    config.io_ctx = 0;
    config.entry = LLVMFuzzerTestOneInput;
    config.input = agent_input;
    config.input_cap = AGENT_INPUT_CAP;
    config.edges = agent_edges;
    config.edge_cap = AGENT_EDGE_CAP;
    bhf_agent_init(&config);
    for (;;) {
        (void)bhf_agent_serve_one();
    }
}

int main(void) {
    UART0_BAUDDIV = 16u;
    UART0_CTRL = 3u; /* TX and RX enable */
    xTaskCreate(agent_task, "bhf-agent", 512, NULL, 1, NULL);
    vTaskStartScheduler();
    for (;;) {
    }
}

/* The FreeRTOS hooks the configuration asks for. */
void vApplicationMallocFailedHook(void) {
    for (;;) {
    }
}
void vApplicationStackOverflowHook(TaskHandle_t task, char *name) {
    (void)task;
    (void)name;
    for (;;) {
    }
}
