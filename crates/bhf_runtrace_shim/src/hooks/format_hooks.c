// SPDX-License-Identifier: Apache-2.0

#define _GNU_SOURCE
/* This file defines the fortified `__*_chk` entry points itself; the
 * compiler's default `_FORTIFY_SOURCE` would wrap the plain names in inline
 * redirects to them. */
#undef _FORTIFY_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

extern void bhf_runtrace_log_format(const char *api, const char *format);
/* The next definition of `symbol` after this library (libc's), resolved from
 * Rust so the lookup never goes through this library's own `dlsym` hook. */
extern void *bhf_shim_resolve_next(const char *symbol);

#define BHF_HOOK __attribute__((used, externally_visible, visibility("default")))
#define BHF_INNER __attribute__((noinline, visibility("hidden")))

void bhf_format_hook_anchor(void) {}

static void bhf_log_format_preserving_errno(const char *api, const char *format) {
    int saved_errno = errno;
    bhf_runtrace_log_format(api, format);
    errno = saved_errno;
}

/* The real libc function behind a hook, resolved once. Forwarding through a
 * plain call would bind to this library's own export of the same name (and
 * log twice) or to a sanitizer's interceptor in the executable. */
#define BHF_REAL(type, name)                                                  \
    static type real_##name;                                                  \
    type real = __atomic_load_n(&real_##name, __ATOMIC_RELAXED);             \
    if (!real) {                                                              \
        real = (type)bhf_shim_resolve_next(#name);                            \
        __atomic_store_n(&real_##name, real, __ATOMIC_RELAXED);              \
    }                                                                         \
    if (!real) {                                                              \
        errno = ENOSYS;                                                       \
        return -1;                                                            \
    }

typedef int (*bhf_vprintf_fn)(const char *, va_list);
typedef int (*bhf_vfprintf_fn)(FILE *, const char *, va_list);
typedef int (*bhf_vsprintf_fn)(char *, const char *, va_list);
typedef int (*bhf_vsnprintf_fn)(char *, size_t, const char *, va_list);
typedef int (*bhf_vdprintf_fn)(int, const char *, va_list);
typedef int (*bhf_vasprintf_fn)(char **, const char *, va_list);
typedef int (*bhf_vprintf_chk_fn)(int, const char *, va_list);
typedef int (*bhf_vfprintf_chk_fn)(FILE *, int, const char *, va_list);
typedef int (*bhf_vsprintf_chk_fn)(char *, int, size_t, const char *, va_list);
typedef int (*bhf_vsnprintf_chk_fn)(char *, size_t, int, size_t, const char *, va_list);
typedef int (*bhf_vdprintf_chk_fn)(int, int, const char *, va_list);
typedef int (*bhf_vasprintf_chk_fn)(char **, int, const char *, va_list);

/* Every hook below logs the format under the name of the variadic API the
 * program called: `vprintf` and `__printf_chk` as `printf`, `vsnprintf` as
 * `snprintf`, and so on. A sanitizer runtime defines `printf` in the
 * executable and forwards it to the `vprintf` it finds next, which is this
 * library's, so one format bug is named the same whether the call reached the
 * shim directly, through an interceptor, or through a fortified build's
 * `__printf_chk`.
 *
 * The `va_list` hooks are also what `dlsym(RTLD_NEXT, ...)` hands a
 * sanitizer runtime (`bhf_format_next_hook`): the hidden `bhf_hook_*`
 * definitions, whose addresses are this library's own, unlike the exported,
 * preemptible names. */

BHF_INNER int bhf_hook_vprintf(const char *format, va_list ap) {
    BHF_REAL(bhf_vprintf_fn, vprintf)
    bhf_log_format_preserving_errno("printf", format);
    return real(format, ap);
}

BHF_INNER int bhf_hook_vfprintf(FILE *stream, const char *format, va_list ap) {
    BHF_REAL(bhf_vfprintf_fn, vfprintf)
    bhf_log_format_preserving_errno("fprintf", format);
    return real(stream, format, ap);
}

BHF_INNER int bhf_hook_vsprintf(char *str, const char *format, va_list ap) {
    BHF_REAL(bhf_vsprintf_fn, vsprintf)
    bhf_log_format_preserving_errno("sprintf", format);
    return real(str, format, ap);
}

BHF_INNER int bhf_hook_vsnprintf(char *str, size_t size, const char *format, va_list ap) {
    BHF_REAL(bhf_vsnprintf_fn, vsnprintf)
    bhf_log_format_preserving_errno("snprintf", format);
    return real(str, size, format, ap);
}

BHF_INNER int bhf_hook_vdprintf(int fd, const char *format, va_list ap) {
    BHF_REAL(bhf_vdprintf_fn, vdprintf)
    bhf_log_format_preserving_errno("dprintf", format);
    return real(fd, format, ap);
}

BHF_INNER int bhf_hook_vasprintf(char **strp, const char *format, va_list ap) {
    BHF_REAL(bhf_vasprintf_fn, vasprintf)
    bhf_log_format_preserving_errno("asprintf", format);
    return real(strp, format, ap);
}

BHF_INNER int bhf_hook_vprintf_chk(int flag, const char *format, va_list ap) {
    BHF_REAL(bhf_vprintf_chk_fn, __vprintf_chk)
    bhf_log_format_preserving_errno("printf", format);
    return real(flag, format, ap);
}

BHF_INNER int bhf_hook_vfprintf_chk(FILE *stream, int flag, const char *format, va_list ap) {
    BHF_REAL(bhf_vfprintf_chk_fn, __vfprintf_chk)
    bhf_log_format_preserving_errno("fprintf", format);
    return real(stream, flag, format, ap);
}

BHF_INNER int bhf_hook_vsprintf_chk(char *str, int flag, size_t slen, const char *format,
                                    va_list ap) {
    BHF_REAL(bhf_vsprintf_chk_fn, __vsprintf_chk)
    bhf_log_format_preserving_errno("sprintf", format);
    return real(str, flag, slen, format, ap);
}

BHF_INNER int bhf_hook_vsnprintf_chk(char *str, size_t maxlen, int flag, size_t slen,
                                     const char *format, va_list ap) {
    BHF_REAL(bhf_vsnprintf_chk_fn, __vsnprintf_chk)
    bhf_log_format_preserving_errno("snprintf", format);
    return real(str, maxlen, flag, slen, format, ap);
}

BHF_INNER int bhf_hook_vdprintf_chk(int fd, int flag, const char *format, va_list ap) {
    BHF_REAL(bhf_vdprintf_chk_fn, __vdprintf_chk)
    bhf_log_format_preserving_errno("dprintf", format);
    return real(fd, flag, format, ap);
}

BHF_INNER int bhf_hook_vasprintf_chk(char **strp, int flag, const char *format, va_list ap) {
    BHF_REAL(bhf_vasprintf_chk_fn, __vasprintf_chk)
    bhf_log_format_preserving_errno("asprintf", format);
    return real(strp, flag, format, ap);
}

/* The exported names. Each `va_list` export is a thin call to its hidden
 * hook; each variadic one packs its arguments and calls the hook of its
 * `va_list` counterpart, so every format is logged exactly once. */

BHF_HOOK int vprintf(const char *format, va_list ap) {
    return bhf_hook_vprintf(format, ap);
}

BHF_HOOK int vfprintf(FILE *stream, const char *format, va_list ap) {
    return bhf_hook_vfprintf(stream, format, ap);
}

BHF_HOOK int vsprintf(char *str, const char *format, va_list ap) {
    return bhf_hook_vsprintf(str, format, ap);
}

BHF_HOOK int vsnprintf(char *str, size_t size, const char *format, va_list ap) {
    return bhf_hook_vsnprintf(str, size, format, ap);
}

BHF_HOOK int vdprintf(int fd, const char *format, va_list ap) {
    return bhf_hook_vdprintf(fd, format, ap);
}

BHF_HOOK int vasprintf(char **strp, const char *format, va_list ap) {
    return bhf_hook_vasprintf(strp, format, ap);
}

BHF_HOOK int __vprintf_chk(int flag, const char *format, va_list ap) {
    return bhf_hook_vprintf_chk(flag, format, ap);
}

BHF_HOOK int __vfprintf_chk(FILE *stream, int flag, const char *format, va_list ap) {
    return bhf_hook_vfprintf_chk(stream, flag, format, ap);
}

BHF_HOOK int __vsprintf_chk(char *str, int flag, size_t slen, const char *format, va_list ap) {
    return bhf_hook_vsprintf_chk(str, flag, slen, format, ap);
}

BHF_HOOK int __vsnprintf_chk(char *str, size_t maxlen, int flag, size_t slen,
                             const char *format, va_list ap) {
    return bhf_hook_vsnprintf_chk(str, maxlen, flag, slen, format, ap);
}

BHF_HOOK int __vdprintf_chk(int fd, int flag, const char *format, va_list ap) {
    return bhf_hook_vdprintf_chk(fd, flag, format, ap);
}

BHF_HOOK int __vasprintf_chk(char **strp, int flag, const char *format, va_list ap) {
    return bhf_hook_vasprintf_chk(strp, flag, format, ap);
}

#define BHF_VARIADIC(call)    \
    va_list ap;               \
    va_start(ap, format);     \
    int result = call;        \
    va_end(ap);               \
    return result;

BHF_HOOK int printf(const char *format, ...) {
    BHF_VARIADIC(bhf_hook_vprintf(format, ap))
}

BHF_HOOK int fprintf(FILE *stream, const char *format, ...) {
    BHF_VARIADIC(bhf_hook_vfprintf(stream, format, ap))
}

BHF_HOOK int dprintf(int fd, const char *format, ...) {
    BHF_VARIADIC(bhf_hook_vdprintf(fd, format, ap))
}

BHF_HOOK int sprintf(char *str, const char *format, ...) {
    BHF_VARIADIC(bhf_hook_vsprintf(str, format, ap))
}

BHF_HOOK int snprintf(char *str, size_t size, const char *format, ...) {
    BHF_VARIADIC(bhf_hook_vsnprintf(str, size, format, ap))
}

BHF_HOOK int asprintf(char **strp, const char *format, ...) {
    BHF_VARIADIC(bhf_hook_vasprintf(strp, format, ap))
}

BHF_HOOK int __printf_chk(int flag, const char *format, ...) {
    BHF_VARIADIC(bhf_hook_vprintf_chk(flag, format, ap))
}

BHF_HOOK int __fprintf_chk(FILE *stream, int flag, const char *format, ...) {
    BHF_VARIADIC(bhf_hook_vfprintf_chk(stream, flag, format, ap))
}

BHF_HOOK int __sprintf_chk(char *str, int flag, size_t slen, const char *format, ...) {
    BHF_VARIADIC(bhf_hook_vsprintf_chk(str, flag, slen, format, ap))
}

BHF_HOOK int __snprintf_chk(char *str, size_t maxlen, int flag, size_t slen,
                            const char *format, ...) {
    BHF_VARIADIC(bhf_hook_vsnprintf_chk(str, maxlen, flag, slen, format, ap))
}

BHF_HOOK int __dprintf_chk(int fd, int flag, const char *format, ...) {
    BHF_VARIADIC(bhf_hook_vdprintf_chk(fd, flag, format, ap))
}

BHF_HOOK int __asprintf_chk(char **strp, int flag, const char *format, ...) {
    BHF_VARIADIC(bhf_hook_vasprintf_chk(strp, flag, format, ap))
}

/* This library's `va_list` hook for `name`, for a `dlsym(RTLD_NEXT, name)`
 * from an object loaded before it (a sanitizer runtime resolving the real
 * function behind its interceptor); NULL for any other name. */
void *bhf_format_next_hook(const char *name) {
    static const struct {
        const char *name;
        void *hook;
    } hooks[] = {
        {"vprintf", (void *)&bhf_hook_vprintf},
        {"vfprintf", (void *)&bhf_hook_vfprintf},
        {"vsprintf", (void *)&bhf_hook_vsprintf},
        {"vsnprintf", (void *)&bhf_hook_vsnprintf},
        {"vdprintf", (void *)&bhf_hook_vdprintf},
        {"vasprintf", (void *)&bhf_hook_vasprintf},
        {"__vprintf_chk", (void *)&bhf_hook_vprintf_chk},
        {"__vfprintf_chk", (void *)&bhf_hook_vfprintf_chk},
        {"__vsprintf_chk", (void *)&bhf_hook_vsprintf_chk},
        {"__vsnprintf_chk", (void *)&bhf_hook_vsnprintf_chk},
        {"__vdprintf_chk", (void *)&bhf_hook_vdprintf_chk},
        {"__vasprintf_chk", (void *)&bhf_hook_vasprintf_chk},
    };
    size_t i;
    if (!name) return NULL;
    for (i = 0; i < sizeof hooks / sizeof hooks[0]; i++) {
        const char *a = hooks[i].name;
        const char *b = name;
        while (*a && *a == *b) {
            a++;
            b++;
        }
        if (*a == *b) return hooks[i].hook;
    }
    return NULL;
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
    (void *)&asprintf,
    (void *)&vprintf,
    (void *)&vfprintf,
    (void *)&vsprintf,
    (void *)&vsnprintf,
    (void *)&vdprintf,
    (void *)&vasprintf,
    (void *)&__printf_chk,
    (void *)&__fprintf_chk,
    (void *)&__sprintf_chk,
    (void *)&__snprintf_chk,
    (void *)&__dprintf_chk,
    (void *)&__asprintf_chk,
    (void *)&__vprintf_chk,
    (void *)&__vfprintf_chk,
    (void *)&__vsprintf_chk,
    (void *)&__vsnprintf_chk,
    (void *)&__vdprintf_chk,
    (void *)&__vasprintf_chk,
    (void *)&dlsym,
};
