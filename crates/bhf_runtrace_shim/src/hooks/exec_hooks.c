// SPDX-License-Identifier: Apache-2.0

/* execl, execlp and execle take their arguments as a variadic list, which the
 * Rust hooks cannot define. These collect the list into an argv and hand it
 * to execv, execvp or execve: the next definition of those is this library's
 * own Rust hook, which records the exec and calls libc's. Perl runs a shell
 * command (`system("cmd > file")`) through execl("/bin/sh", "sh", "-c", ...),
 * so without them the command-injection sink never saw it (#300). */
#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <unistd.h>

#define BHF_HOOK __attribute__((used, externally_visible, visibility("default")))
#define BHF_EXEC_MAX_ARGS 4096

/* Referenced from Rust so the linker keeps this object (see proc.rs). */
void bhf_exec_hook_anchor(void) {}

/* Collect `first` and the arguments after it, up to the NULL that ends them,
 * into `argv`; leaves `ap` after the NULL. 0, or -1 with E2BIG. */
static int bhf_collect_args(const char *first, va_list *ap, const char **argv) {
    size_t count = 0;
    for (const char *arg = first; arg != NULL; arg = va_arg(*ap, const char *)) {
        if (count == BHF_EXEC_MAX_ARGS) {
            errno = E2BIG;
            return -1;
        }
        argv[count++] = arg;
    }
    argv[count] = NULL;
    return 0;
}

BHF_HOOK int execl(const char *path, const char *arg, ...) {
    const char *argv[BHF_EXEC_MAX_ARGS + 1];
    va_list ap;
    va_start(ap, arg);
    int collected = bhf_collect_args(arg, &ap, argv);
    va_end(ap);
    if (collected != 0) return -1;
    return execv(path, (char *const *)argv);
}

BHF_HOOK int execlp(const char *file, const char *arg, ...) {
    const char *argv[BHF_EXEC_MAX_ARGS + 1];
    va_list ap;
    va_start(ap, arg);
    int collected = bhf_collect_args(arg, &ap, argv);
    va_end(ap);
    if (collected != 0) return -1;
    return execvp(file, (char *const *)argv);
}

BHF_HOOK int execle(const char *path, const char *arg, ...) {
    const char *argv[BHF_EXEC_MAX_ARGS + 1];
    va_list ap;
    va_start(ap, arg);
    int collected = bhf_collect_args(arg, &ap, argv);
    char *const *envp = collected == 0 ? va_arg(ap, char *const *) : NULL;
    va_end(ap);
    if (collected != 0) return -1;
    return execve(path, (char *const *)argv, envp);
}
