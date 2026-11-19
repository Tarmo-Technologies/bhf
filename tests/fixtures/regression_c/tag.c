/* SPDX-License-Identifier: Apache-2.0 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Planted: a tag longer than four bytes overflows `tag`. */
int parse_tag(const uint8_t *data, size_t len) {
    char tag[4];
    if (len > 0 && data[0] == 'T') {
        memcpy(tag, data, len);
        return tag[0];
    }
    return 0;
}
