// SPDX-License-Identifier: Apache-2.0

/* A bracket parser whose recursion has no depth limit (#220). Each level
 * keeps a 4 KiB scratch frame, so about two thousand open brackets exhaust an
 * 8 MiB stack. Every depth runs the same edges: only a fuzzer that counts
 * stack depth as progress keeps the deeper inputs that get there. */
#include <stddef.h>

static int parse(const unsigned char *p, size_t n, size_t *i) {
    volatile unsigned char scratch[4096];
    int sum = 0;
    while (*i < n) {
        unsigned char c = p[(*i)++];
        scratch[c] = c;
        if (c == '[')
            sum += parse(p, n, i) + scratch['['];
        else if (c == ']')
            return sum;
        else
            sum += c & 1;
    }
    return sum;
}

int stack_depth(const unsigned char *data, size_t len) {
    size_t i = 0;
    return parse(data, len, &i);
}
