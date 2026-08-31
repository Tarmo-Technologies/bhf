// SPDX-License-Identifier: Apache-2.0

#define _GNU_SOURCE
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

BHF_HOOK void *bhf_format_hook_symbols[] = {
    (void *)&printf,
    (void *)&fprintf,
    (void *)&dprintf,
    (void *)&sprintf,
    (void *)&snprintf,
};
