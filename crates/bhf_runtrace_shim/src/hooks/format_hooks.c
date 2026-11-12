// SPDX-License-Identifier: Apache-2.0

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

extern void bhf_runtrace_log_format(const char *api, const char *format);

#define BHF_HOOK __attribute__((used, externally_visible, visibility("default")))

void bhf_format_hook_anchor(void) {}

static void bhf_log_format_preserving_errno(const char *api, const char *format) {
    int saved_errno = errno;
    bhf_runtrace_log_format(api, format);
    errno = saved_errno;
}

BHF_HOOK int printf(const char *format, ...) {
    bhf_log_format_preserving_errno("printf", format);
    va_list ap;
    va_start(ap, format);
    int result = vprintf(format, ap);
    va_end(ap);
    return result;
}

BHF_HOOK int fprintf(FILE *stream, const char *format, ...) {
    bhf_log_format_preserving_errno("fprintf", format);
    va_list ap;
    va_start(ap, format);
    int result = vfprintf(stream, format, ap);
    va_end(ap);
    return result;
}

BHF_HOOK int dprintf(int fd, const char *format, ...) {
    bhf_log_format_preserving_errno("dprintf", format);
    va_list ap;
    va_start(ap, format);
    int result = vdprintf(fd, format, ap);
    va_end(ap);
    return result;
}

BHF_HOOK int sprintf(char *str, const char *format, ...) {
    bhf_log_format_preserving_errno("sprintf", format);
    va_list ap;
    va_start(ap, format);
    int result = vsprintf(str, format, ap);
    va_end(ap);
    return result;
}

BHF_HOOK int snprintf(char *str, size_t size, const char *format, ...) {
    bhf_log_format_preserving_errno("snprintf", format);
    va_list ap;
    va_start(ap, format);
    int result = vsnprintf(str, size, format, ap);
    va_end(ap);
    return result;
}

/* dlsym(RTLD_NEXT, ...) searches the objects loaded after its CALLER, and
 * glibc's dlsym reads the caller from its return address. A sanitizer runtime
 * resolves the real functions behind its interceptors this way. The hook
 * needs the caller's address, which only C can read portably, and a lookup it
 * does not answer itself goes to the real dlsym as a tail call, so the real
 * one sees the original caller: forwarded with an ordinary call, the lookup
 * would start after this library and skip its hooks (fopen, dlopen, memcmp,
 * ...), or find a later-loaded sanitizer runtime's own interceptor. build.rs
 * compiles this file optimized for compilers without musttail. */
extern void *bhf_shim_dlsym(void *handle, const char *symbol, const void *caller);
extern void *bhf_shim_real_dlsym(void);

#if defined(__has_attribute)
#if __has_attribute(musttail)
#define BHF_MUSTTAIL __attribute__((musttail))
#endif
#endif
#ifndef BHF_MUSTTAIL
#define BHF_MUSTTAIL
#endif

typedef void *(*bhf_dlsym_fn)(void *, const char *);

BHF_HOOK void *dlsym(void *handle, const char *symbol) {
    void *answer = bhf_shim_dlsym(handle, symbol, __builtin_return_address(0));
    bhf_dlsym_fn real;
    if (answer != (void *)~(size_t)0) return answer;
    real = (bhf_dlsym_fn)bhf_shim_real_dlsym();
    if (!real) return NULL;
    BHF_MUSTTAIL return real(handle, symbol);
}

BHF_HOOK void *bhf_format_hook_symbols[] = {
    (void *)&printf,
    (void *)&fprintf,
    (void *)&dprintf,
    (void *)&sprintf,
    (void *)&snprintf,
    (void *)&dlsym,
};
