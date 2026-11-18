/* SPDX-License-Identifier: Apache-2.0 */
/* A host stand-in for the Zephyr kernel API c_runtime/zephyr/bhf_agent_zephyr.c
 * uses (#291), so the glue builds and runs on the host loopback: threads are
 * pthreads, a semaphore is a pipe (its give is safe in a signal handler, as
 * Zephyr's is in a fault), and zephyr_host.c plays the fatal-error path. */
#ifndef BHF_ZEPHYR_HOST_KERNEL_H
#define BHF_ZEPHYR_HOST_KERNEL_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    int forever;
} k_timeout_t;
#define K_FOREVER ((k_timeout_t){1})
#define K_NO_WAIT ((k_timeout_t){0})

typedef void (*k_thread_entry_t)(void *, void *, void *);

struct k_thread {
    pthread_t tid;
    k_thread_entry_t entry;
    void *p1, *p2, *p3;
};
typedef struct k_thread *k_tid_t;

typedef char k_thread_stack_t;
#define K_THREAD_STACK_DEFINE(name, size) k_thread_stack_t name[size]
#define K_THREAD_STACK_SIZEOF(name) sizeof(name)

k_tid_t k_thread_create(struct k_thread *thread, k_thread_stack_t *stack, size_t stack_size,
                        k_thread_entry_t entry, void *p1, void *p2, void *p3, int prio,
                        uint32_t options, k_timeout_t delay);
int k_thread_join(struct k_thread *thread, k_timeout_t timeout);
k_tid_t k_current_get(void);
void k_yield(void);

struct k_sem {
    int fds[2];
};
void bhf_zephyr_host_sem_init(struct k_sem *sem, unsigned int initial);
#define K_SEM_DEFINE(name, initial, limit)                                                 \
    struct k_sem name;                                                                     \
    __attribute__((constructor)) static void name##_bhf_host_init(void) {                  \
        bhf_zephyr_host_sem_init(&name, (initial));                                        \
    }
void k_sem_give(struct k_sem *sem);
int k_sem_take(struct k_sem *sem, k_timeout_t timeout);

#endif
