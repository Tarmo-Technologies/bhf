// SPDX-License-Identifier: Apache-2.0
// zlib trade-study adapter (#370): decompress the input as a zlib stream
// into a fixed 64 KiB buffer with uncompress2.
#include <stddef.h>

#include "zlib.h"

int target_one_input(const unsigned char *data, size_t size) {
    static unsigned char out[1 << 16];
    uLongf out_len = sizeof out;
    uLong in_len = (uLong)size;
    (void)uncompress2(out, &out_len, data, &in_len);
    return 0;
}
