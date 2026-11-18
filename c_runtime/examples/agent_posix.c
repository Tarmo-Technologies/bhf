/* SPDX-License-Identifier: Apache-2.0 */
/*
 * The bhf reference agent on a POSIX host (#289), for `bhf fuzz
 * --target-transport agent:tcp:127.0.0.1:PORT`: it listens on 127.0.0.1:PORT
 * (0 picks one, printed on stdout), serves each connection until the host
 * closes it, and reports a SIGSEGV, SIGBUS, SIGFPE, SIGILL or SIGABRT as the
 * running input's fault. Link it with bhf_agent.c and the code under test,
 * which defines LLVMFuzzerTestOneInput and is built with
 * -fsanitize-coverage=trace-pc-guard:
 *
 *   cc -c bhf_agent.c && cc -c examples/agent_posix.c -I.
 *   clang -fsanitize-coverage=trace-pc-guard -c target.c
 *   cc -o agent agent_posix.o bhf_agent.o target.o
 *
 * With `--pty` it serves a pseudo-terminal instead (#293), standing in for a
 * board's UART: it prints the terminal's path, for `bhf fuzz
 * --target-transport agent:serial:PATH`, and serves each time the host opens
 * it.
 *
 * On a board, the same loop runs over the UART with read/write callbacks of
 * its own and a fault vector that calls bhf_agent_fault().
 */
#define _XOPEN_SOURCE 700
#include "bhf_agent.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef AGENT_INPUT_CAP
#define AGENT_INPUT_CAP 4096
#endif
#ifndef AGENT_EDGE_CAP
#define AGENT_EDGE_CAP 65536
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static uint8_t input[AGENT_INPUT_CAP];
static uint32_t edges[AGENT_EDGE_CAP];

static int sock_read(void *ctx, uint8_t *buf, size_t n) {
    int fd = *(int *)ctx;
    while (n > 0) {
        ssize_t got = read(fd, buf, n);
        if (got <= 0) return -1;
        buf += got;
        n -= (size_t)got;
    }
    return 0;
}

static int sock_write(void *ctx, const uint8_t *buf, size_t n) {
    int fd = *(int *)ctx;
    while (n > 0) {
        ssize_t put = write(fd, buf, n);
        if (put <= 0) return -1;
        buf += put;
        n -= (size_t)put;
    }
    return 0;
}

static void on_fault(int sig, siginfo_t *info, void *uctx) {
    uint32_t kind = BHF_AGENT_FAULT_CPU_EXCEPTION;
    const char *name = "signal";
    (void)uctx;
    switch (sig) {
    case SIGSEGV: kind = BHF_AGENT_FAULT_MEMORY_PROTECTION; name = "SIGSEGV"; break;
    case SIGBUS: kind = BHF_AGENT_FAULT_MEMORY_PROTECTION; name = "SIGBUS"; break;
    case SIGFPE: name = "SIGFPE"; break;
    case SIGILL: name = "SIGILL"; break;
    case SIGABRT: kind = BHF_AGENT_FAULT_ASSERTION; name = "SIGABRT"; break;
    default: break;
    }
    bhf_agent_fault(kind, (uint64_t)(uintptr_t)info->si_addr, name);
    /* No input was running: the agent itself faulted. */
    _exit(70);
}

static void configure(bhf_agent_config *config, int *fd) {
    config->read = sock_read;
    config->write = sock_write;
    config->io_ctx = fd;
    config->entry = LLVMFuzzerTestOneInput;
    config->input = input;
    config->input_cap = sizeof input;
    config->edges = edges;
    config->edge_cap = AGENT_EDGE_CAP;
}

/* Serve a pseudo-terminal's master end. Until the host opens the terminal,
 * and after it closes it, a read fails: wait and serve again. */
static int serve_pty(void) {
    static const struct timespec wait = {0, 10 * 1000 * 1000};
    bhf_agent_config config;
    int fd = posix_openpt(O_RDWR | O_NOCTTY);
    if (fd < 0 || grantpt(fd) != 0 || unlockpt(fd) != 0) {
        perror("agent_posix: pty");
        return 1;
    }
    printf("%s\n", ptsname(fd));
    fflush(stdout);
    for (;;) {
        configure(&config, &fd);
        bhf_agent_init(&config);
        bhf_agent_serve();
        nanosleep(&wait, NULL);
    }
}

int main(int argc, char **argv) {
    static const int sigs[] = {SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT};
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof addr;
    struct sigaction action;
    bhf_agent_config config;
    int listener, one = 1;
    size_t i;

    memset(&action, 0, sizeof action);
    action.sa_sigaction = on_fault;
    /* The handler longjmps back into the agent loop: leave the signal
     * unblocked for the next input's fault. */
    action.sa_flags = SA_SIGINFO | SA_NODEFER;
    for (i = 0; i < sizeof sigs / sizeof sigs[0]; i++) sigaction(sigs[i], &action, NULL);
    signal(SIGPIPE, SIG_IGN);
    if (argc > 1 && strcmp(argv[1], "--pty") == 0) return serve_pty();

    listener = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)(argc > 1 ? atoi(argv[1]) : 0));
    if (bind(listener, (struct sockaddr *)&addr, sizeof addr) != 0 || listen(listener, 4) != 0) {
        perror("agent_posix: listen");
        return 1;
    }
    getsockname(listener, (struct sockaddr *)&addr, &addr_len);
    printf("%u\n", (unsigned)ntohs(addr.sin_port));
    fflush(stdout);

    for (;;) {
        int fd = accept(listener, NULL, NULL);
        if (fd < 0) continue;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        configure(&config, &fd);
        bhf_agent_init(&config);
        bhf_agent_serve();
        close(fd);
    }
}
