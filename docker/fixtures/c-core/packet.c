// SPDX-License-Identifier: Apache-2.0
#include <stddef.h>
#include <stdint.h>

/* Benign container build/entry smoke: all accesses are bounded by length. */
unsigned int packet_checksum(const uint8_t *data, size_t length) {
    unsigned int sum = 0;
    for (size_t i = 0; i < length; ++i) {
        sum = (sum + data[i]) & 0xffffu;
    }
    return sum;
}
