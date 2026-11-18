/* SPDX-License-Identifier: Apache-2.0 */
/*
 * The host side of the Zephyr stand-in (see zephyr/kernel.h), and the agent's
 * main: serve on a loopback port, printed on stdout, with Zephyr's
 * fatal-error path played by a SIGSEGV handler: it calls the glue's
 * k_sys_fatal_error_handler and, as Zephyr aborts a faulting thread, ends
 * the thread.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/fatal.h>
#include <zephyr/kernel.h>

#include "bhf_agent_zephyr.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

struct device bhf_zephyr_host_uart = {-1, -1};
static __thread struct k_thread *bhf_host_current;

static void *bhf_host_trampoline(void *arg) {
    struct k_thread *thread = arg;
    bhf_host_current = thread;
    thread->entry(thread->p1, thread->p2, thread->p3);
    return NULL;
}

k_tid_t k_thread_create(struct k_thread *thread, k_thread_stack_t *stack, size_t stack_size,
                        k_thread_entry_t entry, void *p1, void *p2, void *p3, int prio,
                        uint32_t options, k_timeout_t delay) {
    (void)stack;
    (void)stack_size;
    (void)prio;
    (void)options;
    (void)delay;
    thread->entry = entry;
    thread->p1 = p1;
    thread->p2 = p2;
    thread->p3 = p3;
    if (pthread_create(&thread->tid, NULL, bhf_host_trampoline, thread) != 0) abort();
    return thread;
}

int k_thread_join(struct k_thread *thread, k_timeout_t timeout) {
    (void)timeout;
    return pthread_join(thread->tid, NULL);
}

k_tid_t k_current_get(void) { return bhf_host_current; }

void k_yield(void) { sched_yield(); }

void bhf_zephyr_host_sem_init(struct k_sem *sem, unsigned int initial) {
    if (pipe(sem->fds) != 0) abort();
    while (initial-- > 0) k_sem_give(sem);
}

void k_sem_give(struct k_sem *sem) {
    char token = 1;
    if (write(sem->fds[1], &token, 1) != 1) abort();
}

int k_sem_take(struct k_sem *sem, k_timeout_t timeout) {
    char token;
    (void)timeout;
    while (read(sem->fds[0], &token, 1) != 1) {
        if (errno != EINTR) abort();
    }
    return 0;
}

bool device_is_ready(const struct device *dev) { return dev->listener >= 0; }

int uart_poll_in(const struct device *dev, unsigned char *c) {
    struct device *uart = (struct device *)dev;
    ssize_t got;
    if (uart->link < 0) {
        uart->link = accept4(uart->listener, NULL, NULL, SOCK_NONBLOCK);
        if (uart->link < 0) {
            usleep(100);
            return -1;
        }
    }
    got = recv(uart->link, c, 1, MSG_DONTWAIT);
    if (got == 1) return 0;
    if (got == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
        close(uart->link);
        uart->link = -1;
    }
    usleep(100);
    return -1;
}

void uart_poll_out(const struct device *dev, unsigned char c) {
    if (dev->link >= 0) (void)send(dev->link, &c, 1, MSG_NOSIGNAL);
}

void k_fatal_halt(unsigned int reason) {
    (void)reason;
    abort();
}

static void bhf_host_fault(int sig) {
    (void)sig;
    k_sys_fatal_error_handler(K_ERR_CPU_EXCEPTION, NULL);
    pthread_exit(NULL);
}

int main(int argc, char **argv) {
    struct sockaddr_in addr;
    socklen_t len = sizeof addr;
    struct sigaction action;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(argc > 1 ? (uint16_t)atoi(argv[1]) : 0);
    bhf_zephyr_host_uart.listener = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (bhf_zephyr_host_uart.listener < 0 ||
        bind(bhf_zephyr_host_uart.listener, (struct sockaddr *)&addr, sizeof addr) != 0 ||
        listen(bhf_zephyr_host_uart.listener, 1) != 0 ||
        getsockname(bhf_zephyr_host_uart.listener, (struct sockaddr *)&addr, &len) != 0)
        return 1;
    memset(&action, 0, sizeof action);
    action.sa_handler = bhf_host_fault;
    sigemptyset(&action.sa_mask);
    sigaction(SIGSEGV, &action, NULL);
    printf("%u\n", (unsigned)ntohs(addr.sin_port));
    fflush(stdout);
    bhf_agent_zephyr_run(LLVMFuzzerTestOneInput);
    return 1;
}
