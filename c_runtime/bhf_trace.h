/* SPDX-License-Identifier: Apache-2.0 */
#ifndef BHF_TRACE_H
#define BHF_TRACE_H

/* Argument trace for generated harnesses.
 *
 * Run a generated harness with BHF_TRACE_ARGS=1 and it prints one line per
 * decoded parameter to stderr, after the parameters are decoded and before
 * the call:
 *
 *     BHF_ARG {"call":"target","i":1,"role":"param","name":"width",
 *              "type":"uint32_t","decoder":"bhf_i32()","span":[4,8],
 *              "value":"15"}
 *
 * An output or in-out parameter (a non-const reference, a pointer to scalar
 * storage, a writable string) gets a second line after the call, with
 * "phase":"after" and its new value. Buffers carry their address ("ptr"),
 * the allocation size the address sanitizer reports ("alloc_size"), their
 * content length ("len") and at most BHF_TRACE_PREVIEW leading bytes as hex
 * ("preview_hex"); input bytes are never printed raw, so a testcase cannot
 * forge a sanitizer report line. "span" is the [start, end) byte range of
 * the testcase the parameter was decoded from.
 *
 * Without the variable the harness prints nothing: the check is one cached
 * getenv per process. The tracer reads only memory it knows is valid (the
 * testcase, a live heap allocation, or memory the address sanitizer reports
 * as addressable), so tracing never adds a crash of its own.
 *
 * Strict C89 (-std=c89 -pedantic-errors) clean, like bhf_decode.h. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bhf_decode.h"

#define BHF_TRACE_LINE_MAX 2048
#define BHF_TRACE_PREVIEW 32
/* Longest C string the tracer measures. */
#define BHF_TRACE_STRING_MAX ((size_t)1 << 16)
/* No content length known for a buffer. */
#define BHF_TRACE_NO_LEN ((size_t)-1)
/* The pointer holds scalar storage the harness owns: print its pointee. */
#define BHF_TRACE_DEREF 1
/* The pointer is a NUL-terminated string the harness built. */
#define BHF_TRACE_NUL 2

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define BHF_TRACE_ASAN 1
#endif
#endif
#if !defined(BHF_TRACE_ASAN) && defined(__SANITIZE_ADDRESS__) && !defined(_MSC_VER)
#define BHF_TRACE_ASAN 1
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef BHF_TRACE_ASAN
size_t __sanitizer_get_allocated_size(const volatile void *p);
int __sanitizer_get_ownership(const volatile void *p);
void *__asan_region_is_poisoned(void *beg, size_t size);
#endif

typedef struct bhf_trace_line {
    char buf[BHF_TRACE_LINE_MAX];
    size_t len;
    int full;
} bhf_trace_line;

/* One line is built at a time; harnesses decode on one thread. */
static inline bhf_trace_line *bhf_tl(void) {
    static bhf_trace_line line;
    return &line;
}

static inline int bhf_trace_on(void) {
    static int on = -1;
    if (on < 0) {
        const char *v = getenv("BHF_TRACE_ARGS");
        on = (v && v[0] && !(v[0] == '0' && v[1] == '\0')) ? 1 : 0;
    }
    return on;
}

static inline void bhf_tl_raw(const char *s, size_t n) {
    bhf_trace_line *l = bhf_tl();
    /* Keep room for the closing "}\n". */
    if (l->full || n > BHF_TRACE_LINE_MAX - 3 - l->len) {
        l->full = 1;
        return;
    }
    memcpy(l->buf + l->len, s, n);
    l->len += n;
}

static inline void bhf_tl_str(const char *s) {
    bhf_tl_raw(s, strlen(s));
}

static inline void bhf_tl_digits(uint64_t v) {
    char tmp[24];
    char out[24];
    size_t n = 0;
    size_t i;
    do {
        tmp[n++] = (char)('0' + (int)(v % 10u));
        v /= 10u;
    } while (v != 0u && n < sizeof tmp);
    for (i = 0; i < n; ++i) {
        out[i] = tmp[n - 1 - i];
    }
    bhf_tl_raw(out, n);
}

static inline void bhf_tl_hex_digits(uint64_t v) {
    static const char hex[] = "0123456789abcdef";
    char tmp[18];
    char out[18];
    size_t n = 0;
    size_t i;
    do {
        tmp[n++] = hex[(size_t)(v & 0xfu)];
        v >>= 4;
    } while (v != 0u && n < 16);
    for (i = 0; i < n; ++i) {
        out[i] = tmp[n - 1 - i];
    }
    bhf_tl_raw("0x", 2);
    bhf_tl_raw(out, n);
}

/* Start a line. `head` is the generator's JSON object prefix without its
 * closing brace: {"call":...,"name":...,"type":... */
static inline void bhf_tl_begin(const char *head) {
    bhf_trace_line *l = bhf_tl();
    l->len = 0;
    l->full = 0;
    bhf_tl_str("BHF_ARG ");
    bhf_tl_str(head);
}

static inline void bhf_tl_end(void) {
    bhf_trace_line *l = bhf_tl();
    if (l->full) {
        static const char cut[] = "BHF_ARG {\"truncated\":true}\n";
        fwrite(cut, 1, sizeof cut - 1, stderr);
    } else {
        l->buf[l->len++] = '}';
        l->buf[l->len++] = '\n';
        fwrite(l->buf, 1, l->len, stderr);
    }
    fflush(stderr);
}

static inline void bhf_tl_number(const char *key, uint64_t v) {
    bhf_tl_str(",\"");
    bhf_tl_str(key);
    bhf_tl_str("\":");
    bhf_tl_digits(v);
}

static inline void bhf_tl_span(size_t lo, size_t hi) {
    bhf_tl_str(",\"span\":[");
    bhf_tl_digits((uint64_t)lo);
    bhf_tl_raw(",", 1);
    bhf_tl_digits((uint64_t)(hi < lo ? lo : hi));
    bhf_tl_raw("]", 1);
}

static inline void bhf_tl_hex(const char *key, const unsigned char *p, size_t n) {
    static const char hex[] = "0123456789abcdef";
    char pair[2];
    size_t i;
    bhf_tl_str(",\"");
    bhf_tl_str(key);
    bhf_tl_str("\":\"");
    for (i = 0; i < n; ++i) {
        pair[0] = hex[(p[i] >> 4) & 0xf];
        pair[1] = hex[p[i] & 0xf];
        bhf_tl_raw(pair, 2);
    }
    bhf_tl_raw("\"", 1);
}

/* ---- values ------------------------------------------------------------ */

static inline void bhf_tr_u64(uint64_t v) {
    bhf_tl_str(",\"value\":\"");
    bhf_tl_digits(v);
    bhf_tl_raw("\"", 1);
}

static inline void bhf_tr_i64(int64_t v) {
    bhf_tl_str(",\"value\":\"");
    if (v < 0) {
        bhf_tl_raw("-", 1);
        bhf_tl_digits((uint64_t)0 - (uint64_t)v);
    } else {
        bhf_tl_digits((uint64_t)v);
    }
    bhf_tl_raw("\"", 1);
}

static inline void bhf_tr_bool(int v) {
    bhf_tl_str(v ? ",\"value\":\"true\"" : ",\"value\":\"false\"");
}

static inline void bhf_tr_f64(double v) {
    char tmp[64];
    char *p;
    sprintf(tmp, "%.17g", v);
    /* Locale decimal commas and anything else unexpected stay JSON-safe. */
    for (p = tmp; *p; ++p) {
        if (*p == '"' || *p == '\\' || (unsigned char)*p < 0x20) {
            *p = '?';
        }
    }
    bhf_tl_str(",\"value\":\"");
    bhf_tl_str(tmp);
    bhf_tl_raw("\"", 1);
}

/* An address as the value (a pointer slot after the call, a function). */
static inline void bhf_tr_addr_value(const void *p) {
    if (!p) {
        bhf_tl_str(",\"value\":\"NULL\"");
        return;
    }
    bhf_tl_str(",\"value\":\"");
    bhf_tl_hex_digits((uint64_t)(size_t)p);
    bhf_tl_raw("\"", 1);
}

static inline void bhf_tr_fnptr(int set) {
    bhf_tl_str(set ? ",\"value\":\"<function>\"" : ",\"value\":\"NULL\"");
}

static inline void bhf_tr_untraced(void) {
    bhf_tl_str(",\"traced\":false");
}

/* How many bytes at `p` the tracer may read, at most `want`. `*alloc` is set to
 * the heap allocation size when the sanitizer runtime knows it. */
static inline size_t bhf_tr_readable(const void *p, size_t want, const uint8_t *data,
                                     size_t size, size_t *alloc, int *alloc_known) {
    size_t a = (size_t)p;
    *alloc = 0;
    *alloc_known = 0;
    if (!p || want == 0) return 0;
    if (data && a >= (size_t)data && a - (size_t)data < size) {
        size_t left = size - (a - (size_t)data);
        return left < want ? left : want;
    }
#ifdef BHF_TRACE_ASAN
    if (__sanitizer_get_ownership(p)) {
        size_t n = __sanitizer_get_allocated_size(p);
        *alloc = n;
        *alloc_known = 1;
        return n < want ? n : want;
    }
    {
        void *bad = __asan_region_is_poisoned((void *)a, want);
        if (!bad) return want;
        return (size_t)bad > a ? (size_t)bad - a : 0;
    }
#else
    return 0;
#endif
}

/* Whether `p` is the end of the span [data, data + size): one past its last
 * byte, as the `end` of a `[begin, end)` pair is. It points at none of the
 * span's bytes, and past a buffer of exactly those bytes, so it is traced as
 * empty without reading it. */
static inline int bhf_tr_at_span_end(const void *p, const uint8_t *data, size_t size) {
    return p && data && (size_t)p == (size_t)data + size;
}

static inline void bhf_tr_preview(const void *p, size_t n) {
    unsigned char tmp[BHF_TRACE_PREVIEW];
    if (n > BHF_TRACE_PREVIEW) n = BHF_TRACE_PREVIEW;
    if (n > 0) {
        memcpy(tmp, p, n);
    }
    bhf_tl_hex("preview_hex", tmp, n);
}

/* A pointer argument: its address, allocation size, content length and a
 * bounded preview. `known_len` is the decoder's own content length, or
 * BHF_TRACE_NO_LEN. */
static inline void bhf_tr_ptr(const void *p, const uint8_t *data, size_t size,
                              size_t known_len, int flags) {
    size_t alloc;
    int alloc_known;
    size_t readable;
    size_t shown;
    (void)flags;
    if (!p) {
        bhf_tl_str(",\"ptr\":\"NULL\"");
        return;
    }
    bhf_tl_str(",\"ptr\":\"");
    bhf_tl_hex_digits((uint64_t)(size_t)p);
    bhf_tl_raw("\"", 1);
    if (bhf_tr_at_span_end(p, data, size)) {
        bhf_tl_number("len", 0);
        bhf_tr_preview(p, 0);
        return;
    }
    readable = bhf_tr_readable(p, BHF_TRACE_PREVIEW, data, size, &alloc, &alloc_known);
    if (alloc_known) {
        bhf_tl_number("alloc_size", (uint64_t)alloc);
    }
    if (known_len != BHF_TRACE_NO_LEN) {
        bhf_tl_number("len", (uint64_t)known_len);
    }
    shown = readable;
    if (known_len != BHF_TRACE_NO_LEN && known_len < shown) shown = known_len;
    if (readable > 0 || known_len == 0) {
        bhf_tr_preview(p, shown);
    }
}

/* A NUL-terminated string argument. */
static inline void bhf_tr_str(const char *s, const uint8_t *data, size_t size,
                              size_t known_len, int flags) {
    size_t alloc;
    int alloc_known;
    size_t readable;
    size_t len;
    if (!s) {
        bhf_tl_str(",\"ptr\":\"NULL\"");
        return;
    }
    bhf_tl_str(",\"ptr\":\"");
    bhf_tl_hex_digits((uint64_t)(size_t)s);
    bhf_tl_raw("\"", 1);
    if (bhf_tr_at_span_end(s, data, size)) {
        bhf_tl_number("len", 0);
        bhf_tr_preview(s, 0);
        return;
    }
    readable = bhf_tr_readable(s, BHF_TRACE_STRING_MAX, data, size, &alloc, &alloc_known);
    if (alloc_known) {
        bhf_tl_number("alloc_size", (uint64_t)alloc);
    }
    if (readable > 0) {
        const void *nul = memchr(s, 0, readable);
        len = nul ? (size_t)((const char *)nul - s) : readable;
    } else if (flags & BHF_TRACE_NUL) {
        len = strlen(s);
    } else {
        len = known_len;
    }
    if (len == BHF_TRACE_NO_LEN) return;
    bhf_tl_number("len", (uint64_t)len);
    bhf_tr_preview(s, len);
}

/* An aggregate passed by value: its size and leading object bytes. */
static inline void bhf_tr_obj(const void *obj, size_t n) {
    bhf_tl_number("len", (uint64_t)n);
    bhf_tr_preview(obj, n);
}

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* C++: one entry point for any argument type, chosen at compile time. */
#if __cplusplus >= 201103L || (defined(_MSVC_LANG) && _MSVC_LANG >= 201103L)
#include <type_traits>

/* Whether a type's object bytes are its value. std::is_trivially_copyable is
 * missing from libstdc++ before GCC 5 (which clang may build against), so use
 * the compiler builtin where there is one. */
#if defined(__clang__) && defined(__has_feature)
#if __has_feature(is_trivially_copyable)
#define BHF_TRACE_TRIVIAL(T) __is_trivially_copyable(T)
#endif
#endif
#if !defined(BHF_TRACE_TRIVIAL) && defined(__GNUC__) && !defined(__clang__) && __GNUC__ < 5
#define BHF_TRACE_TRIVIAL(T) __has_trivial_copy(T)
#endif
#ifndef BHF_TRACE_TRIVIAL
#define BHF_TRACE_TRIVIAL(T) std::is_trivially_copyable<T>::value
#endif

namespace bhf_trace_detail {

template <typename T> struct is_text_char
    : std::integral_constant<bool, std::is_same<typename std::remove_cv<T>::type, char>::value> {};

template <typename T> struct trivial : std::integral_constant<bool, BHF_TRACE_TRIVIAL(T)> {};

/* A pointer to an object (or void), not to a function. */
template <typename P> struct is_data_pointer
    : std::integral_constant<bool, std::is_pointer<P>::value &&
                                       !std::is_function<typename std::remove_pointer<P>::type>::value> {};

/* Any object pointer, const or volatile qualified or not, as `const void *`. */
template <typename T>
inline const void *address(T *p) {
    return static_cast<const void *>(const_cast<const typename std::remove_cv<T>::type *>(p));
}

template <typename T>
inline void arithmetic(const T &v, std::true_type /* bool */) {
    bhf_tr_bool(v ? 1 : 0);
}

template <typename T>
inline void arithmetic(const T &v, std::false_type) {
    if (std::is_floating_point<T>::value) {
        bhf_tr_f64(static_cast<double>(v));
    } else if (std::is_signed<T>::value) {
        bhf_tr_i64(static_cast<int64_t>(v));
    } else {
        bhf_tr_u64(static_cast<uint64_t>(v));
    }
}

template <typename T>
inline void scalar(const T &v, std::true_type /* arithmetic */) {
    arithmetic(v, std::integral_constant<bool, std::is_same<T, bool>::value>());
}

template <typename T>
inline void scalar(const T &v, std::false_type /* enum */) {
    typedef typename std::underlying_type<T>::type U;
    arithmetic(static_cast<U>(v), std::integral_constant<bool, std::is_same<U, bool>::value>());
}

/* An arithmetic or enum value of any cv-qualification. */
template <typename T>
inline void unqualified_scalar(const T &v) {
    typedef typename std::remove_cv<T>::type U;
    const U copy = v;
    scalar(copy, std::integral_constant<bool, std::is_arithmetic<U>::value>());
}

/* The generator sets BHF_TRACE_DEREF only for a pointer to storage it owns. */
template <typename T>
inline void pointee(const T *p, int flags, std::true_type /* arithmetic or enum */) {
    if ((flags & BHF_TRACE_DEREF) && p) {
        unqualified_scalar(*p);
    }
}

template <typename T>
inline void pointee(const T *, int, std::false_type) {}

template <typename T>
inline void pointer(const T *p, const uint8_t *data, size_t size, size_t len, int flags,
                    std::true_type /* char */) {
    bhf_tr_str(static_cast<const char *>(address(p)), data, size, len, flags);
}

template <typename T>
inline void pointer(const T *p, const uint8_t *data, size_t size, size_t len, int flags,
                    std::false_type) {
    bhf_tr_ptr(address(p), data, size, len, flags);
    pointee(p, flags,
            std::integral_constant<bool, std::is_arithmetic<T>::value || std::is_enum<T>::value>());
}

/* A contiguous container: data() returns a pointer to complete objects and
 * size() converts to size_t. */
template <typename C>
inline auto container(const C &c, int) -> typename std::enable_if<
    is_data_pointer<decltype(c.data())>::value &&
        std::is_object<typename std::remove_pointer<decltype(c.data())>::type>::value &&
        (sizeof(*c.data()) > 0) && std::is_convertible<decltype(c.size()), size_t>::value>::type {
    typedef typename std::remove_cv<
        typename std::remove_pointer<decltype(c.data())>::type>::type E;
    size_t n = static_cast<size_t>(c.size());
    bhf_tl_number("len", static_cast<uint64_t>(n));
    if (n > 0 && trivial<E>::value) {
        size_t bytes = n * sizeof(E);
        bhf_tr_preview(address(c.data()), bytes);
    }
}

/* A smart pointer: get() returns an object pointer. */
template <typename C>
inline auto container(const C &c, long) ->
    typename std::enable_if<is_data_pointer<decltype(c.get())>::value>::type {
    const void *p = address(c.get());
    if (p) {
        bhf_tl_str(",\"ptr\":\"");
        bhf_tl_hex_digits(static_cast<uint64_t>(reinterpret_cast<size_t>(p)));
        bhf_tl_raw("\"", 1);
    } else {
        bhf_tl_str(",\"ptr\":\"NULL\"");
    }
}

/* Its object bytes, by address even when the class overloads `&`. */
template <typename C>
inline void object(const C &c, std::true_type /* trivially copyable */) {
    bhf_tr_obj(address(&reinterpret_cast<const volatile char &>(c)), sizeof(C));
}

template <typename C>
inline void object(const C &, std::false_type) {
    bhf_tr_untraced();
}

template <typename C>
inline void container(const C &c, ...) {
    object(c, trivial<C>());
}

template <typename T>
inline void value(const T &v, const uint8_t *, size_t, size_t, int,
                  std::integral_constant<int, 0> /* arithmetic or enum */) {
    unqualified_scalar(v);
}

template <typename T>
inline void value(const T &v, const uint8_t *data, size_t size, size_t len, int flags,
                  std::integral_constant<int, 1> /* object pointer */) {
    typedef typename std::remove_pointer<typename std::remove_cv<T>::type>::type P;
    pointer(v, data, size, len, flags, is_text_char<P>());
}

template <typename T>
inline void value(const T &v, const uint8_t *, size_t, size_t, int,
                  std::integral_constant<int, 2> /* function pointer */) {
    bhf_tr_fnptr(v != 0);
}

template <typename T>
inline void value(const T &v, const uint8_t *, size_t, size_t, int,
                  std::integral_constant<int, 3> /* class, array, other */) {
    container(v, 0);
}

template <typename T>
inline void value(const T &, const uint8_t *, size_t, size_t, int,
                  std::integral_constant<int, 4> /* nullptr, member pointer */) {
    bhf_tr_untraced();
}

template <typename T> struct kind {
    typedef typename std::remove_cv<T>::type U;
    static const int value =
        (std::is_arithmetic<U>::value || std::is_enum<U>::value)
            ? 0
            : (std::is_pointer<U>::value &&
               std::is_function<typename std::remove_pointer<U>::type>::value)
                  ? 2
                  : std::is_pointer<U>::value
                        ? 1
                        : (std::is_member_pointer<U>::value ||
                           std::is_same<U, decltype(nullptr)>::value)
                              ? 4
                              : 3;
};

} // namespace bhf_trace_detail

template <typename T>
inline void bhf_trace_value(const T &v, const uint8_t *data, size_t size, size_t len, int flags) {
    bhf_trace_detail::value(v, data, size, len, flags,
                            std::integral_constant<int, bhf_trace_detail::kind<T>::value>());
}
#else
/* Before C++11 every argument is shown as its object bytes. */
template <typename T>
inline void bhf_trace_value(const T &v, const uint8_t *, size_t, size_t, int) {
    bhf_tr_obj((const void *)&reinterpret_cast<const volatile char &>(v), sizeof(T));
}
#endif
#endif /* __cplusplus */

#endif /* BHF_TRACE_H */
